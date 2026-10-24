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
    /// Copy a page or dependency for Live replay.
    Copy,
    /// Read the public original of a page the world writes.
    Original,
    /// Ask the search provider for the text it holds of an original that
    /// cannot be read directly, with this key and body.
    Contents(&'a Key, &'a Value),
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
                Ask::Search(..) | Ask::Contents(..) => http::Method::POST,
                Ask::Copy | Ask::Original => http::Method::GET,
            },
            purpose: match ask {
                Ask::Search(..) => capture::Purpose::Search,
                Ask::Copy => capture::Purpose::Capture,
                Ask::Original | Ask::Contents(..) => capture::Purpose::Original,
            },
            phase: UpstreamPhase::Attempt,
            status: None,
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
                Ask::Search(key, body) | Ask::Contents(key, body) => client
                    .post(url)
                    .header("x-api-key", key.value())
                    .header("content-type", "application/json")
                    .body(body.to_string()),
                Ask::Copy | Ask::Original => client.get(url).header("accept-encoding", "identity"),
            };
            let response = request.send().await;
            let response = response.map_err(|error| {
                io::Error::other(format!("Live request failed: {:?}", error.without_url()))
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
