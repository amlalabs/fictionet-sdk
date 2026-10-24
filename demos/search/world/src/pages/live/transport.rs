//! Cancellable public-web I/O owned by a Live session.

use super::*;
use fictionet_extras::models::UpstreamPhase;

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
    processing: Arc<tokio::sync::Semaphore>,
}
impl Transport {
    pub(super) fn new() -> Result<Self, String> {
        Ok(Self {
            runtime: Runtime(Some(
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .enable_all()
                    .build()
                    .map_err(|_| "Live transport could not start")?,
            )),
            processing: Arc::new(tokio::sync::Semaphore::new(1)),
        })
    }
    pub(super) fn spawn(&self, work: impl std::future::Future<Output = ()> + Send + 'static) {
        self.runtime.0.as_ref().unwrap().spawn(work);
    }
    // CPU work owns a permit until it finishes even if its caller is cancelled.
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
            result = task => result,
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
            let client = capture::client(&url).await.map_err(|e| e.to_string())?;
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
            let response = response
                .map_err(|error| format!("Live request failed: {:?}", error.without_url()))?;
            if let Some(attempt) = &mut attempt {
                attempt.event.phase = UpstreamPhase::Response;
                attempt.event.status = Some(response.status());
            }
            let mut response = capture::receive(response)
                .await
                .map_err(|e| e.to_string())?;
            self.process(cx, lifetime, move || {
                // Store a decoded representation for both replay and discovery.
                response.body = response
                    .decoded()
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
            result = work => {
                if result.is_err() && let Some(attempt) = &mut attempt && attempt.event.phase == UpstreamPhase::Cancelled {
                    attempt.event.phase = UpstreamPhase::Failed;
                }
                result
            }
        }
    }
}
