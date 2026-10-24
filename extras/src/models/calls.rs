//! Logical inference calls, shared by HTTP and WebSocket adapters.
use super::*;

/// The state of a logical inference call, independent of its transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallPhase {
    /// Request admitted to the model adapter.
    Connecting,
    /// Receiving a nonstreaming response.
    Receiving,
    /// Receiving an event stream.
    Streaming,
    /// The response body was fully consumed.
    Complete,
    /// The transport or response was interrupted.
    Interrupted,
}

/// Per-call tools and lifecycle destination, supplied by the world.
pub struct Call {
    /// The engine attributed to this inference call.
    pub engine: Arc<dyn Engine>,
    /// Receives lifecycle transitions and actual response statuses.
    pub observe: Arc<dyn Fn(CallPhase, Option<http::StatusCode>) + Send + Sync>,
}
/// Creates one call context per HTTP request or WebSocket response creation.
pub type CallObserver = dyn Fn(&Cx, &http::Method, &http::uri::PathAndQuery) -> Call + Send + Sync;

impl Model {
    /// Observes logical calls rather than connection handshakes or splice turns.
    pub fn observe_calls(mut self, observer: Arc<CallObserver>) -> Self {
        self.calls = Some(observer);
        self
    }

    pub(super) async fn send_observed(
        mut self,
        request: Request<Body>,
    ) -> fictionet::Result<Response<Body>> {
        let Some(observer) = &self.calls else {
            return self.send(request).await;
        };
        let path = request
            .uri()
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/"));
        let call = observer(&self.cx, request.method(), &path);
        let mut body = CallBody {
            inner: Body::empty(),
            call,
            status: None,
            done: false,
        };
        (body.call.observe)(CallPhase::Connecting, None);
        self.engine = Some(body.call.engine.clone());
        match self.send(request).await {
            Ok(response) => {
                body.status = Some(response.status());
                let phase = if response
                    .headers()
                    .get(http::header::CONTENT_TYPE)
                    .is_some_and(|v| v.as_bytes().starts_with(b"text/event-stream"))
                {
                    CallPhase::Streaming
                } else {
                    CallPhase::Receiving
                };
                (body.call.observe)(phase, body.status);
                Ok(response.map(|inner| {
                    body.inner = inner;
                    Body::new(body)
                }))
            }
            Err(error) => {
                body.finish(CallPhase::Interrupted);
                Err(error)
            }
        }
    }
}

struct CallBody {
    inner: Body,
    call: Call,
    status: Option<http::StatusCode>,
    done: bool,
}
impl http_body::Body for CallBody {
    type Data = Bytes;
    type Error = Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Error>>> {
        let result = Pin::new(&mut self.inner).poll_frame(cx);
        match &result {
            Poll::Ready(None) => self.finish(CallPhase::Complete),
            Poll::Ready(Some(Err(_))) => self.finish(CallPhase::Interrupted),
            _ => {}
        }
        result
    }
    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}
impl CallBody {
    fn finish(&mut self, phase: CallPhase) {
        if !self.done {
            self.done = true;
            (self.call.observe)(phase, self.status);
        }
    }
}
impl Drop for CallBody {
    fn drop(&mut self) {
        use http_body::Body as _;
        self.finish(if self.inner.is_end_stream() && self.status.is_some() {
            CallPhase::Complete
        } else {
            CallPhase::Interrupted
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dropping_an_unread_model_body_reports_interruption() {
        let phases = Arc::new(Mutex::new(Vec::new()));
        let observed = phases.clone();
        drop(CallBody {
            inner: Body::from("unread"),
            call: Call {
                engine: Arc::new(super::super::tests::ValidationPages),
                observe: Arc::new(move |phase, _| observed.lock().unwrap().push(phase)),
            },
            status: Some(http::StatusCode::OK),
            done: false,
        });
        assert_eq!(*phases.lock().unwrap(), vec![CallPhase::Interrupted]);
    }
}
