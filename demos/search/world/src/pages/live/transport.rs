//! Cancellable public-web I/O owned by a Live session.

use super::*;
use fictionet_extras::models::UpstreamPhase;
use std::io;

struct Runtime(Option<tokio::runtime::Runtime>);
impl Drop for Runtime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

/// What one host request is for.
#[derive(Clone, Copy)]
pub(in crate::pages) enum Ask<'a> {
    /// Query the search provider with this key and body.
    Search(&'a Key, &'a Value),
    /// Copy a page or dependency for Live replay, as this client (by its
    /// User-Agent) would get it, or as the default browser. A dependency
    /// names the page it belongs to.
    Copy {
        user_agent: Option<&'a http::HeaderValue>,
        page: Option<&'a url::Url>,
    },
    /// Copy a package index or file the copied web lacks.
    Package,
    /// Send a git client's request to its real host as it was made.
    Git(&'a GitRequest),
}

/// A git client's request to a repository the copied web lacks. Its answer
/// depends on the method, the body and the protocol headers, so it is sent
/// each time, never kept.
pub(in crate::pages) struct GitRequest {
    pub method: http::Method,
    pub headers: http::HeaderMap,
    pub body: Vec<u8>,
}

impl GitRequest {
    /// The request as the guest's git client made it, with the headers the
    /// smart HTTP protocol reads.
    pub(in crate::pages) fn of(parts: &http::request::Parts, body: &[u8]) -> Self {
        let mut headers = http::HeaderMap::new();
        for name in [
            http::header::CONTENT_TYPE,
            http::header::ACCEPT,
            http::header::CONTENT_ENCODING,
            http::header::HeaderName::from_static("git-protocol"),
        ] {
            if let Some(value) = parts.headers.get(&name) {
                headers.insert(name, value.clone());
            }
        }
        Self {
            method: parts.method.clone(),
            headers,
            body: body.to_vec(),
        }
    }
}

pub(in crate::pages) struct Transport {
    runtime: Runtime,
    clients: capture::Pool,
}
impl Transport {
    pub(in crate::pages) fn new() -> Result<Self, String> {
        Ok(Self {
            clients: capture::Pool::default(),
            runtime: Runtime(Some(
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .enable_all()
                    .build()
                    .map_err(|_| "Live transport could not start")?,
            )),
        })
    }
    pub(in crate::pages) fn spawn(
        &self,
        work: impl std::future::Future<Output = ()> + Send + 'static,
    ) {
        self.runtime.0.as_ref().unwrap().spawn(work);
    }
    pub(in crate::pages) async fn process<T: Send + 'static>(
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
            tokio::task::spawn_blocking(work)
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

    pub(in crate::pages) async fn request(
        &self,
        cx: &Cx,
        lifetime: &Lifetime,
        observer: Option<Arc<capture::Observer>>,
        url: &str,
        ask: Ask<'_>,
    ) -> io::Result<warc::Response> {
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
        let url = url::Url::parse(url)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid Live URL"))?;
        let mut destination = url.clone();
        let _ = destination.set_username("");
        let _ = destination.set_password(None);
        destination.set_query(None);
        destination.set_fragment(None);
        let event = capture::Event {
            attempt: cx.random_u64(),
            url: destination,
            method: match ask {
                Ask::Search(..) => http::Method::POST,
                Ask::Copy { .. } | Ask::Package => http::Method::GET,
                Ask::Git(git) => git.method.clone(),
            },
            purpose: match ask {
                Ask::Search(..) => capture::Purpose::Search,
                Ask::Copy { .. } => capture::Purpose::Capture,
                Ask::Package | Ask::Git(_) => capture::Purpose::Package,
            },
            phase: UpstreamPhase::Attempt,
            status: None,
            page: match ask {
                Ask::Copy { page, .. } => page.cloned(),
                _ => None,
            },
        };
        // No attempt is published after a lifetime has been revoked.
        if lifetime.cancelled() || cx.is_cancelled() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Live session stopped",
            ));
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
            let client = self.clients.client(&url).await?;
            let request = match ask {
                Ask::Search(key, body) => client
                    .post(url)
                    .header("x-api-key", key.value())
                    .header("content-type", "application/json")
                    .body(body.to_string()),
                Ask::Copy {
                    user_agent: Some(user_agent),
                    ..
                } => client
                    .get(url)
                    .header("accept-encoding", "identity")
                    .header(http::header::USER_AGENT, user_agent),
                Ask::Copy {
                    user_agent: None, ..
                }
                | Ask::Package => client.get(url).header("accept-encoding", "identity"),
                Ask::Git(git) => client
                    .request(git.method.clone(), url)
                    .headers(git.headers.clone())
                    .header("accept-encoding", "identity")
                    .body(git.body.clone()),
            };
            let response = request.send().await;
            // The innermost cause is the real error: a name that does not
            // resolve, a refused connection, a certificate it would not accept.
            let response = response.map_err(|error| {
                let mut cause: &dyn std::error::Error = &error;
                while let Some(source) = cause.source() {
                    cause = source;
                }
                io::Error::other(cause.to_string())
            })?;
            if let Some(attempt) = &mut attempt {
                attempt.event.phase = UpstreamPhase::Response;
                attempt.event.status = Some(response.status());
            }
            let mut response = capture::receive(response).await?;
            self.process(cx, lifetime, move || {
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
            .map_err(io::Error::other)
        };
        let mut stopped = lifetime.stop.subscribe();
        if *stopped.borrow() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Live session stopped",
            ));
        }
        tokio::select! {
            biased;
            _ = stopped.changed() => Err(io::Error::new(io::ErrorKind::Interrupted, "Live session stopped")),
            _ = cx.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "Live run stopped")),
            result = work => {
                if result.is_err() && let Some(attempt) = &mut attempt && attempt.event.phase == UpstreamPhase::Cancelled {
                    attempt.event.phase = UpstreamPhase::Failed;
                }
                result
            }
        }
    }
}
