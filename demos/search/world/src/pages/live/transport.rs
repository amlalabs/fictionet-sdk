//! Cancellable, bounded public-web I/O owned by a Live session.

use super::*;
use fictionet_extras::models::UpstreamPhase;
use std::net::IpAddr;

struct Runtime(Option<tokio::runtime::Runtime>);
impl Drop for Runtime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

pub(super) struct Transport {
    runtime: Runtime,
    loopback: bool,
    processing: Arc<tokio::sync::Semaphore>,
}
impl Transport {
    pub(super) fn new() -> Result<Self, String> {
        Self::build(false)
    }
    #[cfg(test)]
    pub(super) fn loopback() -> Result<Self, String> {
        Self::build(true)
    }
    fn build(loopback: bool) -> Result<Self, String> {
        Ok(Self {
            runtime: Runtime(Some(
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .enable_all()
                    .build()
                    .map_err(|_| "Live transport could not start")?,
            )),
            loopback,
            processing: Arc::new(tokio::sync::Semaphore::new(1)),
        })
    }
    pub(super) fn spawn(&self, work: impl std::future::Future<Output = ()> + Send + 'static) {
        self.runtime.0.as_ref().unwrap().spawn(work);
    }
    // CPU work owns a permit until it finishes even if its caller is cancelled.
    // Bounded input and one worker keep revoked sessions from accumulating parsers.
    pub(super) async fn process<T: Send + 'static>(
        &self,
        cx: &Cx,
        lifetime: &Lifetime,
        work: impl FnOnce() -> Result<T, String> + Send + 'static,
    ) -> Result<T, String> {
        let mut stopped = lifetime.stop.subscribe();
        if *stopped.borrow() || cx.is_cancelled() {
            return Err("Live session stopped".into());
        }
        let task = async {
            let permit = self
                .processing
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| "Live processing stopped")?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                work()
            })
            .await
            .map_err(|_| "Live processing worker stopped")?
        };
        tokio::select! {
            biased;
            _ = stopped.changed() => Err("Live session stopped".into()),
            _ = cx.cancelled() => Err("Live run stopped".into()),
            result = tokio::time::timeout(Duration::from_secs(10), task) => {
                result.map_err(|_| "Live processing timed out")?
            }
        }
    }
    fn permits(&self, ip: IpAddr) -> bool {
        if self.loopback {
            return ip.is_loopback();
        }
        match ip {
            IpAddr::V4(ip) => {
                let [a, b, c, _] = ip.octets();
                !ip.is_private()
                    && !ip.is_loopback()
                    && !ip.is_link_local()
                    && !ip.is_documentation()
                    && !ip.is_broadcast()
                    && !matches!(a, 0 | 224..=255)
                    && !(a == 100 && (64..=127).contains(&b))
                    && !(a == 192 && b == 0 && c == 0)
                    && !(a == 192 && b == 88 && c == 99)
                    && !(a == 198 && matches!(b, 18 | 19))
            }
            IpAddr::V6(ip) => {
                if let Some(ip) = ip.to_ipv4_mapped() {
                    return self.permits(ip.into());
                }
                let [a, b, ..] = ip.segments();
                (a & 0xe000) == 0x2000
                    && !(a == 0x2001 && (b < 0x200 || b == 0xdb8))
                    && a != 0x2002
                    && !(a == 0x3fff && b < 0x1000)
            }
        }
    }
    pub(super) async fn request(
        &self,
        cx: &Cx,
        lifetime: &Lifetime,
        observer: Option<Arc<capture::Observer>>,
        url: &str,
        search: Option<(&Key, &Value)>,
    ) -> Result<warc::Response, String> {
        struct Attempt {
            cx: Cx,
            observer: Arc<capture::Observer>,
            event: capture::Event,
        }
        impl Drop for Attempt {
            fn drop(&mut self) {
                (self.observer)(&self.cx, &self.event);
            }
        }
        let url = url::Url::parse(url).map_err(|_| "Invalid Live URL")?;
        let mut destination = url.clone();
        let _ = destination.set_username("");
        let _ = destination.set_password(None);
        destination.set_query(None);
        destination.set_fragment(None);
        let event = capture::Event {
            attempt: cx.random_u64(),
            url: destination,
            method: if search.is_some() {
                http::Method::POST
            } else {
                http::Method::GET
            },
            purpose: if search.is_some() {
                capture::Purpose::Search
            } else {
                capture::Purpose::Capture
            },
            phase: UpstreamPhase::Attempt,
            status: None,
        };
        // No attempt is published after a lifetime has been revoked.
        if lifetime.cancelled() || cx.is_cancelled() {
            return Err("Live session stopped".into());
        }
        let mut attempt = observer.map(|observer| {
            observer(cx, &event);
            Attempt {
                cx: cx.clone(),
                observer,
                event: capture::Event {
                    phase: UpstreamPhase::Cancelled,
                    ..event
                },
            }
        });
        let work = async {
            if !matches!(url.scheme(), "http" | "https")
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err("Live URL is not a public HTTP destination".to_owned());
            }
            let host = url.host_str().ok_or("Missing Live host")?;
            let port = url.port_or_known_default().ok_or("Missing Live port")?;
            let addresses: Vec<_> = tokio::net::lookup_host((host.trim_matches(['[', ']']), port))
                .await
                .map_err(|_| "Live DNS lookup failed")?
                .collect();
            if addresses.is_empty() || addresses.iter().any(|address| !self.permits(address.ip())) {
                return Err("Live destination is outside the capture network".into());
            }
            let host_time = {
                let mut hosts = lifetime.hosts.lock().await;
                hosts
                    .entry(host.to_owned())
                    .or_insert_with(|| {
                        Arc::new(tokio::sync::Mutex::new(tokio::time::Instant::now()))
                    })
                    .clone()
            };
            let mut next = host_time.lock().await;
            tokio::time::sleep_until(*next).await;
            let client = reqwest::Client::builder()
                .user_agent(capture::BROWSER)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .resolve_to_addrs(host, &addresses)
                .build()
                .map_err(|_| "Live client failed")?;
            let request = if let Some((key, body)) = search {
                client
                    .post(url)
                    .header("x-api-key", key.value())
                    .header("content-type", "application/json")
                    .body(body.to_string())
            } else {
                client.get(url).header("accept-encoding", "identity")
            };
            let response = request.send().await;
            *next = tokio::time::Instant::now()
                + Duration::from_millis(if search.is_some() { 250 } else { 500 });
            drop(next);
            let mut response = response.map_err(|_| "Live request failed")?;
            if let Some(attempt) = &mut attempt {
                attempt.event.phase = UpstreamPhase::Response;
                attempt.event.status = Some(response.status());
            }
            let status = response.status();
            let headers = response.headers().clone();
            let parse = search.is_some()
                || headers
                    .get(http::header::CONTENT_TYPE)
                    .is_some_and(|value| {
                        value.as_bytes().starts_with(b"text/html")
                            || value.as_bytes().starts_with(b"text/css")
                    });
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| "Live response failed")? {
                if body.len() + chunk.len() > 32 * 1024 * 1024 {
                    return Err("Live response exceeds capture size limit".into());
                }
                body.extend_from_slice(&chunk);
            }
            self.process(cx, lifetime, move || {
                let mut response = warc::Response {
                    status,
                    headers,
                    body: body.into(),
                };
                // Archive a decoded representation once. Replay and previews cannot
                // expand a compressed body again or bypass the retained-byte budget.
                response.body = response
                    .decoded_with_limit(if parse {
                        capture::PARSE_BYTES
                    } else {
                        warc::Response::DECODED_BYTES
                    })
                    .map_err(|error| error.to_string())?
                    .into();
                response.headers.remove(http::header::CONTENT_ENCODING);
                response
                    .headers
                    .insert(http::header::CONTENT_LENGTH, response.body.len().into());
                Ok(response)
            })
            .await
        };
        let mut stopped = lifetime.stop.subscribe();
        if *stopped.borrow() {
            return Err("Live session stopped".into());
        }
        tokio::select! {
            biased;
            _ = stopped.changed() => Err("Live session stopped".into()),
            _ = cx.cancelled() => Err("Live run stopped".into()),
            result = tokio::time::timeout(Duration::from_secs(20), work) => {
                let result = result.map_err(|_| "Live request timed out".to_owned()).and_then(|r| r);
                if result.is_err() && let Some(attempt) = &mut attempt && attempt.event.phase == UpstreamPhase::Cancelled {
                    attempt.event.phase = UpstreamPhase::Failed;
                }
                result
            }
        }
    }
}

#[cfg(test)]
mod tests;
