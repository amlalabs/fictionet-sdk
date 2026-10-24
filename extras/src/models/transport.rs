//! Shared provider transport lifecycle for host and guest requests.
use super::*;

/// The outcome of one attempt to contact a provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamPhase {
    /// Entering the host transport.
    Attempt,
    /// The provider sent HTTP response headers.
    Response,
    /// The connection failed before a response arrived.
    Failed,
    /// The request was dropped before a response arrived.
    Cancelled,
}

/// A credential-free event for one correlated provider request.
#[derive(Clone, Debug)]
pub struct UpstreamEvent {
    /// Run-local correlation handle, shared by all events of this attempt.
    pub attempt: u64,
    /// The HTTP method.
    pub method: http::Method,
    /// The path, excluding any credential-bearing query.
    pub path: http::uri::PathAndQuery,
    /// Attempt or terminal outcome.
    pub phase: UpstreamPhase,
    /// A real provider status, only when response headers arrived.
    pub status: Option<http::StatusCode>,
}

/// Receives transport events without credentials, bodies or raw diagnostics.
pub type UpstreamObserver = dyn Fn(&Cx, &UpstreamEvent) + Send + Sync;

struct Attempt {
    cx: Cx,
    observer: Arc<UpstreamObserver>,
    event: UpstreamEvent,
}
impl Attempt {
    fn finish(&mut self, phase: UpstreamPhase, status: Option<http::StatusCode>) {
        self.event.phase = phase;
        self.event.status = status;
        (self.observer)(&self.cx, &self.event);
    }
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if self.event.phase == UpstreamPhase::Attempt {
            self.finish(UpstreamPhase::Cancelled, None);
        }
    }
}

pub(super) async fn forward(
    cx: &Cx,
    forward: &web::Forward,
    observer: Option<&Arc<UpstreamObserver>>,
    request: Request<Body>,
) -> fictionet::Result<Response<Body>> {
    let mut attempt = observer.map(|observer| {
        let event = UpstreamEvent {
            attempt: cx.random_u64(),
            method: request.method().clone(),
            path: request.uri().path().parse().expect("HTTP path"),
            phase: UpstreamPhase::Attempt,
            status: None,
        };
        observer(cx, &event);
        Attempt {
            cx: cx.clone(),
            observer: observer.clone(),
            event,
        }
    });
    let result = forward.clone().call(request).await;
    if let Some(attempt) = &mut attempt {
        match &result {
            Ok(response) => attempt.finish(UpstreamPhase::Response, Some(response.status())),
            Err(_) => attempt.finish(UpstreamPhase::Failed, None),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Failed;
    impl web::Upstream for Failed {
        fn request(self: Arc<Self>, _: Request<Body>) -> web::UpstreamFuture {
            Box::pin(async { Err(Error::msg("private transport diagnostic")) })
        }
    }
    struct Pending;
    impl web::Upstream for Pending {
        fn request(self: Arc<Self>, _: Request<Body>) -> web::UpstreamFuture {
            Box::pin(std::future::pending())
        }
    }
    #[test]
    fn failures_and_cancellation_finish_their_own_attempts() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(5),
            |cx| async move {
                let events = Arc::new(Mutex::new(Vec::new()));
                let seen = events.clone();
                let observer: Arc<UpstreamObserver> =
                    Arc::new(move |_, event| seen.lock().unwrap().push(event.clone()));
                let failed =
                    web::forward(&cx, "https://api.anthropic.com".parse()?, Arc::new(Failed))?;
                let request = || {
                    Request::post("/v1/messages?token=private")
                        .body(Body::empty())
                        .unwrap()
                };
                assert!(
                    forward(&cx, &failed, Some(&observer), request())
                        .await
                        .is_err()
                );
                let pending =
                    web::forward(&cx, "https://api.anthropic.com".parse()?, Arc::new(Pending))?;
                let mut work = Box::pin(forward(&cx, &pending, Some(&observer), request()));
                std::future::poll_fn(|task| {
                    assert!(work.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                })
                .await;
                drop(work);
                let events = events.lock().unwrap();
                assert_eq!(
                    events.iter().map(|e| e.phase).collect::<Vec<_>>(),
                    [
                        UpstreamPhase::Attempt,
                        UpstreamPhase::Failed,
                        UpstreamPhase::Attempt,
                        UpstreamPhase::Cancelled
                    ]
                );
                assert_eq!(events[0].attempt, events[1].attempt);
                assert_eq!(events[2].attempt, events[3].attempt);
                assert_ne!(events[0].attempt, events[2].attempt);
                assert!(
                    events
                        .iter()
                        .all(|e| e.status.is_none() && e.path.as_str() == "/v1/messages")
                );
                Ok(())
            },
        ))
        .unwrap();
    }
}
