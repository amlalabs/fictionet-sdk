//! Shared provider transport lifecycle for host and guest requests.
use super::*;
use http_body::{Body as HttpBody, Frame};

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

/// Removes credentials from decoded provider records before either caller sees them.
pub(super) fn sanitize(
    mut response: Response<Body>,
    secret: Secret,
) -> fictionet::Result<Response<Body>> {
    let streaming = response
        .headers()
        .get("content-type")
        .is_some_and(|value| value.as_bytes().starts_with(b"text/event-stream"));
    response.headers_mut().remove("content-length");
    for value in response.headers_mut().values_mut() {
        if let Ok(text) = value.to_str() {
            *value = secret.redact(text).parse()?;
        }
    }
    Ok(response.map(|body| {
        Body::new(Scrubbed {
            body,
            secret,
            pending: Vec::new(),
            streaming,
            done: false,
        })
    }))
}

fn scrub_json(value: &mut Value, secret: &Secret) {
    match value {
        Value::String(text) => *text = secret.redact(text),
        Value::Array(items) => items.iter_mut().for_each(|value| scrub_json(value, secret)),
        Value::Object(fields) => {
            *fields = std::mem::take(fields)
                .into_iter()
                .map(|(key, mut value)| {
                    scrub_json(&mut value, secret);
                    (secret.redact(&key), value)
                })
                .collect();
        }
        _ => {}
    }
}

struct Scrubbed {
    body: Body,
    secret: Secret,
    pending: Vec<u8>,
    streaming: bool,
    done: bool,
}
impl Scrubbed {
    fn record(&self, bytes: &[u8]) -> Vec<u8> {
        let (prefix, content) = if self.streaming && bytes.starts_with(b"data:") {
            (b"data: ".as_slice(), &bytes[5..])
        } else {
            (b"".as_slice(), bytes)
        };
        if let Ok(mut value) = serde_json::from_slice::<Value>(content) {
            scrub_json(&mut value, &self.secret);
            let mut output = prefix.to_vec();
            output.extend(serde_json::to_vec(&value).expect("provider JSON"));
            if self.streaming && bytes.ends_with(b"\n") {
                output.push(b'\n');
            }
            output
        } else {
            self.secret
                .redact(&String::from_utf8_lossy(bytes))
                .into_bytes()
        }
    }
    fn ready(&mut self, end: bool) -> Vec<u8> {
        let length = if end {
            self.pending.len()
        } else if self.streaming {
            self.pending
                .iter()
                .rposition(|b| *b == b'\n')
                .map_or(0, |i| i + 1)
        } else {
            0
        };
        let bytes: Vec<_> = self.pending.drain(..length).collect();
        if self.streaming {
            bytes
                .split_inclusive(|b| *b == b'\n')
                .flat_map(|line| self.record(line))
                .collect()
        } else {
            self.record(&bytes)
        }
    }
}
impl HttpBody for Scrubbed {
    type Data = Bytes;
    type Error = Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<fictionet::Result<Frame<Bytes>>>> {
        if self.done {
            return Poll::Ready(None);
        }
        loop {
            match Pin::new(&mut self.body).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(bytes) => {
                        self.pending.extend_from_slice(&bytes);
                        let safe = self.ready(false);
                        if !safe.is_empty() {
                            return Poll::Ready(Some(Ok(Frame::data(safe.into()))));
                        }
                    }
                    Err(_) => continue,
                },
                Poll::Ready(Some(Err(error))) => {
                    self.done = true;
                    return Poll::Ready(Some(Err(Error::msg(
                        self.secret.redact(&error.to_string()),
                    ))));
                }
                Poll::Ready(None) => {
                    self.done = true;
                    let tail = self.ready(true);
                    return Poll::Ready((!tail.is_empty()).then(|| Ok(Frame::data(tail.into()))));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Chunks(std::collections::VecDeque<fictionet::Result<Frame<Bytes>>>);
    impl HttpBody for Chunks {
        type Data = Bytes;
        type Error = Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<fictionet::Result<Frame<Bytes>>>> {
            Poll::Ready(self.0.pop_front())
        }
    }

    #[test]
    fn successful_json_and_streams_scrub_decoded_secrets_across_frames() {
        fictionet::block_on(fictionet::lab(fictionet::Seed::from_u64(3), |_| async {
            let secret = Secret::new("provider key", "private-key".into())?;
            for streaming in [false, true] {
                let json = r#"{"text":"private-key and private\u002dkey","private-key":"title"}"#;
                let input = if streaming {
                    format!("event: content_block_delta\ndata: {json}\n\n")
                } else {
                    json.into()
                };
                let frames = input
                    .bytes()
                    .map(|byte| Ok::<_, Error>(Frame::data(Bytes::from(vec![byte]))));
                let response = Response::builder()
                    .header(
                        "content-type",
                        if streaming {
                            "text/event-stream"
                        } else {
                            "application/json"
                        },
                    )
                    .header("x-diagnostic", "private-key")
                    .body(Body::new(Chunks(frames.collect())))?;
                let response = sanitize(response, secret.clone())?;
                assert_eq!(response.headers()["x-diagnostic"], "<provider key>");
                let body = response.into_body().collect().await?.to_bytes();
                let output = String::from_utf8(body.to_vec())?;
                assert!(!output.contains("private"), "{output}");
                assert_eq!(output.matches("<provider key>").count(), 3);
            }
            Ok(())
        }))
        .unwrap();
    }

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
