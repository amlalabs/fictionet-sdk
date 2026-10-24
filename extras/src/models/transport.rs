//! Shared provider transport lifecycle for host and guest requests.
use super::*;
use fictionet::stdlib::{
    codec::{Stream, Wire, try_pump},
    protocols::sse,
};
use http_body::{Body as HttpBody, Frame};

mod text;

pub(super) const RESPONSE_LIMIT: usize = 32 * 1024 * 1024;

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
        let text = String::from_utf8_lossy(value.as_bytes());
        *value = http::HeaderValue::from_bytes(secret.redact(&text).as_bytes())?;
    }
    Ok(response.map(|body| {
        Body::new(Scrubbed {
            body,
            secret,
            pending: Vec::new(),
            streaming,
            records: Vec::new(),
            lines: Stream::new(sse::RawLines::with_limit(RESPONSE_LIMIT)),
            event: Vec::new(),
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
    records: Vec<Record>,
    lines: Stream<sse::RawLines>,
    event: Vec<sse::Line>,
}
enum Record {
    Json(Value, Vec<u8>),
    Raw(Vec<u8>),
}
impl Scrubbed {
    fn feed(&mut self, bytes: &[u8]) -> fictionet::Result<()> {
        let mut decoded = Vec::new();
        try_pump(&mut self.lines, bytes, |line| {
            decoded.push(line);
            Ok::<_, Error>(())
        })
        .map_err(|_| Error::msg("Invalid provider event stream"))?;
        for line in decoded {
            if line != sse::Line::Empty {
                self.event.push(line);
                continue;
            }
            let mut data = Vec::new();
            let mut metadata = Vec::new();
            let mut raw = Vec::new();
            for line in self.event.drain(..) {
                if let sse::Line::Data(text) = &line {
                    data.push(text.as_str().to_owned());
                } else {
                    line.write(&mut metadata)
                        .map_err(|_| Error::msg("Invalid provider event metadata"))?;
                }
                // Payload lines may exceed the ordinary line writer's default bound.
                if let sse::Line::Data(text) = line {
                    raw.extend(format!("data: {text}\n").bytes());
                } else {
                    line.write(&mut raw)
                        .map_err(|_| Error::msg("Invalid provider event metadata"))?;
                }
            }
            raw.push(b'\n');
            let data = data.join("\n");
            let record = match serde_json::from_str(&data) {
                Ok(value) => Record::Json(
                    value,
                    self.secret
                        .redact(&String::from_utf8_lossy(&metadata))
                        .into_bytes(),
                ),
                Err(_) => Record::Raw(
                    self.secret
                        .redact(&String::from_utf8_lossy(&raw))
                        .into_bytes(),
                ),
            };
            self.records.push(record);
        }
        Ok(())
    }

    fn ready(&mut self, end: bool) -> Vec<u8> {
        if !self.streaming {
            if !end {
                return Vec::new();
            }
            return if let Ok(mut value) = serde_json::from_slice::<Value>(&self.pending) {
                text::scrub(std::slice::from_mut(&mut value), &self.secret, true);
                serde_json::to_vec(&value).expect("provider JSON")
            } else {
                self.secret
                    .redact(&String::from_utf8_lossy(&self.pending))
                    .into_bytes()
            };
        }
        let mut values: Vec<_> = self
            .records
            .iter()
            .filter_map(|record| match record {
                Record::Json(value, _) => Some(value.clone()),
                Record::Raw(_) => None,
            })
            .collect();
        let safe = text::scrub(&mut values, &self.secret, end);
        let mut values = values.into_iter().enumerate();
        let mut ready = self.records.len();
        for (index, record) in self.records.iter_mut().enumerate() {
            if let Record::Json(value, _) = record {
                let (item, scrubbed) = values.next().expect("decoded record");
                *value = scrubbed;
                if item >= safe {
                    ready = ready.min(index);
                }
            }
        }
        let mut output = Vec::new();
        for record in self.records.drain(..ready) {
            match record {
                Record::Json(value, metadata) => {
                    output.extend(metadata);
                    output.extend(b"data: ");
                    output.extend(serde_json::to_vec(&value).expect("provider JSON"));
                    output.extend(b"\n\n");
                }
                Record::Raw(bytes) => output.extend(bytes),
            }
        }
        output
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
                        if self.streaming {
                            if let Err(error) = self.feed(&bytes) {
                                self.done = true;
                                return Poll::Ready(Some(Err(error)));
                            }
                        } else {
                            self.pending.extend_from_slice(&bytes);
                        }
                        let held: usize = self
                            .records
                            .iter()
                            .map(|record| match record {
                                Record::Json(value, metadata) => {
                                    value.to_string().len() + metadata.len()
                                }
                                Record::Raw(bytes) => bytes.len(),
                            })
                            .sum();
                        let event_bytes: usize = self.event.len()
                            * std::mem::size_of::<sse::Line>()
                            + self
                                .event
                                .iter()
                                .map(|line| match line {
                                    sse::Line::Data(text)
                                    | sse::Line::Event(text)
                                    | sse::Line::Id(text)
                                    | sse::Line::Comment(text)
                                    | sse::Line::Retry(text) => text.len(),
                                    sse::Line::Ignored { name, value } => name.len() + value.len(),
                                    sse::Line::Empty => 0,
                                })
                                .sum::<usize>();
                        if self.pending.len() + held + event_bytes + self.lines.held()
                            > RESPONSE_LIMIT
                        {
                            self.done = true;
                            return Poll::Ready(Some(Err(Error::msg(
                                "Provider response exceeds sanitization limit",
                            ))));
                        }
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
                    .header(
                        "x-opaque",
                        http::HeaderValue::from_bytes(b"\xff private-key").unwrap(),
                    )
                    .body(Body::new(Chunks(frames.collect())))?;
                let response = sanitize(response, secret.clone())?;
                assert_eq!(response.headers()["x-diagnostic"], "<provider key>");
                assert!(
                    !String::from_utf8_lossy(response.headers()["x-opaque"].as_bytes())
                        .contains("private-key")
                );
                let body = response.into_body().collect().await?.to_bytes();
                let output = String::from_utf8(body.to_vec())?;
                assert!(!output.contains("private"), "{output}");
                assert_eq!(output.matches("<provider key>").count(), 3);
            }
            Ok(())
        }))
        .unwrap();
    }

    #[test]
    fn assembled_blocks_and_stream_deltas_never_release_a_split_credential() {
        fictionet::block_on(fictionet::lab(fictionet::Seed::from_u64(4), |_| async {
            let secret = Secret::new("provider key", "private-key".into())?;
            for split in 1.."private-key".len() {
                let (first, second) = "private-key".split_at(split);
                let value = json!({"content":[{"type":"text","text":format!("Before {first}")},{"type":"text","text":format!("{second} after")} ]});
                let response = sanitize(Response::new(Body::from(value.to_string())), secret.clone())?;
                let value: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
                let assembled = format!("{}{}", value["content"][0]["text"].as_str().unwrap(), value["content"][1]["text"].as_str().unwrap());
                assert_eq!(assembled, "Before <provider key> after");
                for chat in [false, true] {
                    let event = |text: &str| if chat {
                        json!({"choices":[{"index":0,"delta":{"content":text}}]})
                    } else {
                        json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":text}})
                    };
                    let input = format!("data: {}\n\nevent: ping\ndata: {{\"type\":\"ping\"}}\n\ndata: {}\n\ndata: {}\n\n", event(&format!("Before {first}")), event(second), event(" after"));
                    let frames = input.bytes().map(|byte| Ok(Frame::data(Bytes::from(vec![byte])))).collect();
                    let response = sanitize(Response::builder().header("content-type", "text/event-stream").body(Body::new(Chunks(frames)))?, secret.clone())?;
                    let body = response.into_body().collect().await?.to_bytes();
                    let output = std::str::from_utf8(&body)?;
                    let values: Vec<Value> = output.lines().filter_map(|line| line.strip_prefix("data: ")).map(serde_json::from_str).collect::<Result<_, _>>()?;
                    assert_eq!(values.len(), 4);
                    assert_eq!(values[1]["type"], "ping");
                    let path = if chat { "/choices/0/delta/content" } else { "/delta/text" };
                    let assembled: String = values.iter().filter_map(|value| value.pointer(path).and_then(Value::as_str)).collect();
                    assert_eq!(assembled, "Before <provider key> after", "{output}");
                }
            }
            Ok(())
        })).unwrap();
    }

    #[test]
    fn tool_argument_streams_are_scrubbed_after_json_assembly() {
        fictionet::block_on(fictionet::lab(fictionet::Seed::from_u64(9), |_| async {
            let secret = Secret::new("provider key", "private-key".into())?;
            let parts = [r#"{"value":"private\u00"#, r#"2dkey"}"#];
            let input: String = parts.into_iter().map(|partial| format!("data: {}\n\n", json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":partial}}))).collect();
            let response = sanitize(Response::builder().header("content-type", "text/event-stream").body(Body::from(input))?, secret)?;
            let bytes = response.into_body().collect().await?.to_bytes();
            let output = std::str::from_utf8(&bytes)?;
            let arguments: String = output.lines().filter_map(|line| line.strip_prefix("data: ")).map(|line| serde_json::from_str::<Value>(line).unwrap()["delta"]["partial_json"].as_str().unwrap().to_owned()).collect();
            let value: Value = serde_json::from_str(&arguments)?;
            assert_eq!(value["value"], "<provider key>");
            Ok(())
        })).unwrap();
    }

    #[test]
    fn multiline_events_are_decoded_before_text_blocks_are_assembled() {
        fictionet::block_on(fictionet::lab(fictionet::Seed::from_u64(11), |_| async {
            let input = b"id: report\r\nevent: message\r\ndata: {\"content\":[{\"type\":\"text\",\"text\":\"private-\"},\r\ndata: {\"type\":\"text\",\"text\":\"key\"}]}\r\n\r\n";
            let frames = input.iter().map(|byte| Ok(Frame::data(Bytes::from(vec![*byte])))).collect();
            let response = sanitize(Response::builder().header("content-type", "text/event-stream").body(Body::new(Chunks(frames)))?, Secret::new("provider key", "private-key".into())?)?;
            let bytes = response.into_body().collect().await?.to_bytes();
            let event = sse::Event::parse(&bytes)?;
            assert_eq!(event.id, "report");
            assert_eq!(event.event, "message");
            let value: Value = serde_json::from_str(&event.data)?;
            let text: String = value["content"].as_array().unwrap().iter().map(|block| block["text"].as_str().unwrap()).collect();
            assert_eq!(text, "<provider key>");
            Ok(())
        })).unwrap();
    }

    #[test]
    fn response_items_and_chat_content_parts_are_scrubbed_as_assembled_text() {
        fictionet::block_on(fictionet::lab(fictionet::Seed::from_u64(12), |_| async {
            for (body, pointers) in [
                (json!({"output":[{"content":[{"text":"private-"}]},{"content":[{"text":"key"}]}]}), ["/output/0/content/0/text", "/output/1/content/0/text"]),
                (json!({"choices":[{"message":{"content":[{"text":"private-"},{"text":"key"}]}}]}), ["/choices/0/message/content/0/text", "/choices/0/message/content/1/text"]),
            ] {
                let response = sanitize(Response::new(Body::from(body.to_string())), Secret::new("provider key", "private-key".into())?)?;
                let value: Value = serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
                let text: String = pointers.into_iter().map(|path| value.pointer(path).unwrap().as_str().unwrap()).collect();
                assert_eq!(text, "<provider key>");
            }
            Ok(())
        })).unwrap();
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
