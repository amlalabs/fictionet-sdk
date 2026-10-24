//! The Responses API over a WebSocket, which Codex opens before HTTP.
//!
//! The world answers the handshake itself and keeps HTTP streaming to the
//! upstream, so every upstream works the same way. Each `response.create`
//! message becomes one POST through the site's HTTP path: the credential
//! swap, the budget, the `model.call` event and the search splice. Its
//! streamed events go back as text messages, and a refused call as an
//! `error` event carrying its HTTP status, the shapes OpenAI documents for
//! [WebSocket mode](https://developers.openai.com/api/docs/guides/websocket-mode).
//! Each lane keeps its latest response, so a continuation can name it in
//! `previous_response_id` and send only its new input.

use super::*;
use fictionet::stdlib::codec::{AssembleError, Fail, PumpError, Side, Stream, Wire, try_pump};
use fictionet::stdlib::network::{Connection, ConnectionExt};
use fictionet::stdlib::protocols::sse;
use fictionet::stdlib::protocols::websocket::{self as ws, Message, Messages, close_code};
use std::collections::{HashMap, VecDeque};
use std::time::Duration;
use tokio::sync::mpsc;

/// Responses in flight at once on one connection, across its lanes.
const ACTIVE: usize = 16;
/// Responses one connection holds waiting behind running ones.
const QUEUED: usize = 16;
/// Named lanes one connection accepts.
const LANES: usize = 32;
/// How long one connection takes new responses.
const LIFETIME: Duration = Duration::from_secs(60 * 60);
/// The most output items one response may report.
const ITEMS: usize = 4096;

/// Marks a request that came over the socket, for the `model.call` event.
#[derive(Clone, Copy)]
pub(super) struct Upgraded;

/// Whether `request` opens the provider's Responses WebSocket.
pub(super) fn wanted(provider: Provider, request: &Request<Body>) -> bool {
    let path = request.uri().path();
    request.method() == http::Method::GET
        && matches!(provider, Provider::OpenAi | Provider::ChatGpt)
        && provider.allows(path)
        && path.ends_with("/responses")
        && request.headers().get_all("upgrade").iter().any(|v| {
            v.as_bytes()
                .split(|b| *b == b',')
                .any(|t| t.trim_ascii().eq_ignore_ascii_case(b"websocket"))
        })
}

/// Answers the handshake: `101` with the socket served after it, or the
/// refusal a wrong credential or a broken handshake gets.
pub(super) fn accept(model: Model, request: Request<Body>) -> Response<Body> {
    if !model.authorized(request.headers()) {
        return model.unauthorized();
    }
    let fields: Vec<(&str, &str)> = request
        .headers()
        .iter()
        .filter_map(|(name, value)| Some((name.as_str(), value.to_str().ok()?)))
        .collect();
    let headers = match ws::check_request(&fields).and_then(|u| u.response_headers(None)) {
        Ok(headers) => headers,
        Err(error) => {
            let status = error.status_code();
            let mut response =
                model
                    .provider
                    .error(status, "invalid_request_error", &error.to_string());
            if status == 426 {
                response.headers_mut().insert(
                    "sec-websocket-version",
                    http::HeaderValue::from_static(ws::VERSION),
                );
            }
            return response;
        }
    };
    let mut response = Response::new(Body::empty());
    *response.status_mut() = http::StatusCode::SWITCHING_PROTOCOLS;
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::try_from(name),
            http::HeaderValue::try_from(value),
        ) {
            response.headers_mut().append(name, value);
        }
    }
    if let Ok(id) = http::HeaderValue::try_from(format!("req_{}", hex(&model.cx, 16))) {
        response.headers_mut().insert("x-request-id", id);
    }

    let (head, _) = request.into_parts();
    response
        .extensions_mut()
        .insert(httpd::UpgradeHandler::new(move |cx, conn| {
            serve(model, head, cx, conn)
        }));
    response
}

fn hex(cx: &Cx, len: usize) -> String {
    let mut bytes = vec![0; len];
    cx.fill_random(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// An `invalid_request_error` as OpenAI writes it.
fn invalid(code: Option<&str>, message: &str, param: Option<&str>) -> Value {
    json!({"type":"invalid_request_error","code":code,"message":message,"param":param})
}

/// The `error` event for a refused call: the HTTP status, the body's
/// error, and the rate limit headers a client reads its wait from.
fn wrapped(status: u16, headers: &http::HeaderMap, body: &[u8]) -> Value {
    let error = serde_json::from_slice::<Value>(body)
        .ok()
        .map(|body| body["error"].clone())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({"type":"server_error","code":"server_error","message":"The server had an error while processing your request. Sorry about that!","param":null}));
    let mut event = json!({"type":"error","status":status,"error":error});
    let kept: serde_json::Map<String, Value> = headers
        .iter()
        .filter(|(name, _)| {
            let name = name.as_str();
            name == "retry-after"
                || name.starts_with("x-ratelimit-")
                || name.starts_with("x-codex-")
        })
        .filter_map(|(name, value)| Some((name.as_str().to_owned(), json!(value.to_str().ok()?))))
        .collect();
    if !kept.is_empty() {
        event["headers"] = Value::Object(kept);
    }
    event
}

/// One server event, with its text as the upstream wrote it, or the end
/// of a response.
enum Out {
    Event(String, Value),
    Done,
}
/// What a response's task reports, tagged with its lane and start.
struct Note {
    lane: Option<String>,
    serial: u64,
    out: Out,
}
type Task = Pin<Box<dyn Future<Output = ()> + Send>>;

#[derive(Default)]
struct Lane {
    /// The lane's latest finished response: its id, and its input and
    /// output as the client saw them.
    latest: Option<(String, Vec<Value>)>,
    current: Option<Current>,
}
struct Current {
    serial: u64,
    previous: Option<String>,
    input: Vec<Value>,
    /// The response as its latest start event showed it.
    response: Value,
    /// Finished output items by their index.
    items: Vec<Value>,
    sequence: u64,
    terminal: Option<Value>,
    failed: bool,
    /// The relay, until it ends or an interrupt drops it.
    task: Option<Task>,
}

struct Session {
    model: Model,
    cx: Cx,
    head: http::request::Parts,
    opened: fictionet::time::Instant,
    tx: mpsc::UnboundedSender<Note>,
    pending: VecDeque<(Option<String>, serde_json::Map<String, Value>)>,
    lanes: HashMap<Option<String>, Lane>,
    outbox: Vec<Message>,
    serial: u64,
    responses: u64,
}

impl Session {
    /// Queues an event for the client, naming its lane when it has one.
    fn send(&mut self, lane: &Option<String>, mut event: Value) {
        if let Some(lane) = lane {
            event["stream_id"] = json!(lane);
        }
        self.outbox.push(Message::Text(event.to_string()));
    }
    fn error(&mut self, lane: &Option<String>, status: u16, error: Value) {
        self.send(lane, json!({"type":"error","status":status,"error":error}));
    }
    /// Handles one client message, or gives the close that ends the socket.
    fn message(&mut self, message: Message) -> Result<(), Message> {
        match message {
            Message::Text(text) => self.receive(&text),
            Message::Ping(data) => self.outbox.push(Message::Pong(data)),
            Message::Pong(_) => {}
            Message::Binary(_) => {
                return Err(Message::Close(Some(ws::Close::new(
                    close_code::UNSUPPORTED_DATA,
                ))));
            }
            // Answer a close with its own code, as RFC 6455 asks.
            Message::Close(frame) => {
                return Err(Message::Close(frame.map(|f| ws::Close::new(f.code))));
            }
        }
        Ok(())
    }
    fn receive(&mut self, text: &str) {
        let event = match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(event)) => event,
            _ => {
                return self.error(
                    &None,
                    400,
                    invalid(
                        None,
                        "We could not parse the JSON body of your request. (HINT: This likely means you aren't using your HTTP library correctly. The OpenAI API expects a JSON payload, but what was sent was not valid JSON. If you have trouble figuring out how to fix this, please contact us through our help center at help.openai.com.)",
                        None,
                    ),
                );
            }
        };
        match event.get("type").and_then(Value::as_str) {
            Some("response.create") => self.create(event),
            Some("response.interrupt") => self.interrupt(&event),
            kind => {
                let message = format!("Invalid value: '{}'.", kind.unwrap_or(""));
                self.error(
                    &None,
                    400,
                    invalid(Some("invalid_value"), &message, Some("type")),
                );
            }
        }
    }
    fn create(&mut self, mut event: serde_json::Map<String, Value>) {
        let lane = match event.remove("stream_id") {
            None | Some(Value::Null) => None,
            Some(Value::String(id))
                if (1..=256).contains(&id.len())
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)) =>
            {
                Some(id)
            }
            Some(_) => {
                return self.error(
                    &None,
                    400,
                    invalid(
                        Some("invalid_stream_id"),
                        "The 'stream_id' field must be a non-empty string with at most 256 characters and may only contain letters, numbers, underscores, hyphens, and periods.",
                        Some("stream_id"),
                    ),
                );
            }
        };
        if self.cx.now() >= self.opened + LIFETIME {
            return self.error(
                &None,
                400,
                invalid(
                    Some("websocket_connection_limit_reached"),
                    "Responses websocket connection limit reached (60 minutes). Create a new websocket connection to continue.",
                    None,
                ),
            );
        }
        if self.pending.len() >= QUEUED {
            return self.error(
                &lane,
                400,
                invalid(
                    Some("websocket_queue_limit_reached"),
                    "This WebSocket connection has reached its maximum number of queued responses (16). Wait for a response to finish before sending another response.create.",
                    None,
                ),
            );
        }
        if lane.is_some() && !self.lanes.contains_key(&lane) {
            if self.lanes.keys().filter(|k| k.is_some()).count() >= LANES {
                return self.error(
                    &lane,
                    400,
                    invalid(
                        Some("websocket_stream_limit_reached"),
                        "This WebSocket connection has reached its maximum number of distinct stream IDs (32). Reuse an existing stream_id or open a new WebSocket connection.",
                        Some("stream_id"),
                    ),
                );
            }
            self.lanes.insert(lane.clone(), Lane::default());
        }
        self.pending.push_back((lane, event));
        self.pump();
    }
    /// Starts queued requests in order: one at a time on a lane, and at
    /// most [`ACTIVE`] on the connection.
    fn pump(&mut self) {
        let mut waiting: VecDeque<(Option<String>, _)> = VecDeque::new();
        while let Some((lane, event)) = self.pending.pop_front() {
            let busy = self.lanes.get(&lane).is_some_and(|l| l.current.is_some());
            let active = self.lanes.values().filter(|l| l.current.is_some()).count();
            if busy || active >= ACTIVE || waiting.iter().any(|(l, _)| *l == lane) {
                waiting.push_back((lane, event));
            } else {
                self.start(lane, event);
            }
        }
        self.pending = waiting;
    }
    fn start(&mut self, lane: Option<String>, mut event: serde_json::Map<String, Value>) {
        let previous = match event.remove("previous_response_id") {
            Some(Value::String(id)) => Some(id),
            _ => None,
        };
        let mut input = match event.remove("input") {
            Some(Value::Array(items)) => items,
            Some(Value::String(text)) => vec![json!({"role":"user","content":text})],
            _ => Vec::new(),
        };
        if let Some(id) = &previous {
            let found = self.lanes.values().find_map(|l| {
                l.latest
                    .as_ref()
                    .filter(|(latest, _)| latest == id)
                    .map(|(_, items)| items.clone())
            });
            let Some(items) = found else {
                let message = format!("Previous response with id '{id}' not found.");
                return self.error(
                    &lane,
                    400,
                    invalid(
                        Some("previous_response_not_found"),
                        &message,
                        Some("previous_response_id"),
                    ),
                );
            };
            input = items.into_iter().chain(input).collect();
        }
        event.remove("type");
        if event.remove("generate") == Some(Value::Bool(false)) {
            return self.warm(lane, previous, input, event);
        }
        let mut body = Value::Object(event);
        body["input"] = Value::Array(input.clone());
        body["stream"] = json!(true);
        self.serial += 1;
        let task = relay(
            self.model.clone(),
            self.request(&body),
            lane.clone(),
            self.serial,
            self.tx.clone(),
        );
        self.lanes.entry(lane).or_default().current = Some(Current {
            serial: self.serial,
            previous,
            input,
            response: Value::Null,
            items: Vec::new(),
            sequence: 0,
            terminal: None,
            failed: false,
            task: Some(Box::pin(task)),
        });
    }
    /// The POST the site's HTTP path serves for one `response.create`,
    /// with the handshake's headers.
    fn request(&self, body: &Value) -> Request<Body> {
        let mut request = Request::new(Body::from(body.to_string()));
        *request.method_mut() = http::Method::POST;
        *request.uri_mut() = self.head.uri.clone();
        *request.extensions_mut() = self.head.extensions.clone();
        request.extensions_mut().insert(Upgraded);
        let headers = request.headers_mut();
        for (name, value) in &self.head.headers {
            let socket = name.as_str().starts_with("sec-websocket-")
                || matches!(name.as_str(), "upgrade" | "connection" | "content-length")
                || (name == "openai-beta" && value.as_bytes().starts_with(b"responses_websockets"));
            if !socket {
                headers.append(name.clone(), value.clone());
            }
        }
        headers.insert(
            "content-type",
            http::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            "accept",
            http::HeaderValue::from_static("text/event-stream"),
        );
        request
    }
    /// Answers `generate: false`: a response with no output that later
    /// requests can continue from, and no upstream call.
    fn warm(
        &mut self,
        lane: Option<String>,
        previous: Option<String>,
        input: Vec<Value>,
        event: serde_json::Map<String, Value>,
    ) {
        if let Some(stop) = self.model.admit(self.head.uri.path(), false) {
            let (parts, body) = stop.into_parts();
            let bytes = body.bytes().unwrap_or_default();
            let mut event = wrapped(parts.status.as_u16(), &parts.headers, &bytes);
            if let Some(lane) = &lane {
                event["stream_id"] = json!(lane);
            }
            self.outbox.push(Message::Text(event.to_string()));
            return;
        }
        let id = format!("resp_{}", hex(&self.cx, 25));
        let mut response = json!({"id":&id,"object":"response","created_at":time::OffsetDateTime::now_utc().unix_timestamp(),"status":"in_progress","background":false,"error":null,"incomplete_details":null,"output":[],"previous_response_id":previous,"usage":null});
        for (key, value) in event {
            if !matches!(key.as_str(), "stream" | "include" | "client_metadata") {
                response[key] = value;
            }
        }
        self.send(
            &lane,
            json!({"type":"response.created","response":response,"sequence_number":0}),
        );
        response["status"] = json!("completed");
        response["usage"] = json!({"input_tokens":0,"input_tokens_details":{"cached_tokens":0},"output_tokens":0,"output_tokens_details":{"reasoning_tokens":0},"total_tokens":0});
        self.send(
            &lane,
            json!({"type":"response.completed","response":response,"sequence_number":1}),
        );
        self.lanes.entry(lane).or_default().latest = Some((id, input));
        self.responses += 1;
    }
    /// Stops a running response, keeping the items it finished, as
    /// `response.incomplete` with the reason `interrupted`.
    fn interrupt(&mut self, event: &serde_json::Map<String, Value>) {
        let id = event
            .get("response_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let running = self.lanes.iter().find_map(|(lane, l)| {
            l.current
                .as_ref()
                .is_some_and(|c| c.terminal.is_none() && !c.failed && c.response["id"] == id)
                .then(|| lane.clone())
        });
        let Some(lane) = running else {
            // A response that already ended has nothing left to stop.
            let ended = self.lanes.values().any(|l| {
                l.latest.as_ref().is_some_and(|(latest, _)| *latest == id)
                    || l.current.as_ref().is_some_and(|c| c.response["id"] == id)
            });
            let kind = if ended && !id.is_empty() {
                "response.interrupt.accepted"
            } else {
                "response.interrupt.failed"
            };
            return self.send(&None, json!({"type":kind,"response_id":id}));
        };
        let current = self
            .lanes
            .get_mut(&lane)
            .and_then(|l| l.current.as_mut())
            .expect("running lane");
        current.task = None;
        let mut response = current.response.clone();
        response["status"] = json!("incomplete");
        response["incomplete_details"] = json!({"reason":"interrupted"});
        response["output"] = json!(
            current
                .items
                .iter()
                .filter(|i| !i.is_null())
                .cloned()
                .collect::<Vec<_>>()
        );
        let sequence = current.sequence + 1;
        current.terminal = Some(response.clone());
        self.send(
            &lane,
            json!({"type":"response.interrupt.accepted","response_id":id}),
        );
        self.send(
            &lane,
            json!({"type":"response.incomplete","response":response,"sequence_number":sequence}),
        );
        self.finish(&lane);
    }
    fn deliver(&mut self, note: Note) {
        let Some(current) = self
            .lanes
            .get_mut(&note.lane)
            .and_then(|l| l.current.as_mut())
            .filter(|c| c.serial == note.serial)
        else {
            return;
        };
        let (text, event) = match note.out {
            Out::Done => return self.finish(&note.lane),
            Out::Event(text, event) => (text, event),
        };
        if let Some(sequence) = event["sequence_number"].as_u64() {
            current.sequence = sequence;
        }
        match event["type"].as_str().unwrap_or("") {
            "response.created" | "response.in_progress" => {
                current.response = event["response"].clone();
            }
            "response.output_item.done" => {
                let index = event["output_index"].as_u64().unwrap_or(0) as usize;
                if index < ITEMS {
                    if current.items.len() <= index {
                        current.items.resize(index + 1, Value::Null);
                    }
                    current.items[index] = event["item"].clone();
                }
            }
            "response.completed" | "response.incomplete" => {
                current.terminal = Some(event["response"].clone());
            }
            "response.failed" | "error" => current.failed = true,
            _ => {}
        }
        // The event as the upstream wrote it, with its lane first.
        let text = match &note.lane {
            Some(lane) if text.starts_with('{') && text.len() > 2 => {
                format!("{{\"stream_id\":{},{}", json!(lane), &text[1..])
            }
            _ => text,
        };
        self.outbox.push(Message::Text(text));
    }
    /// Ends a lane's response: a finished one becomes the lane's latest,
    /// and a failed continuation drops the response it continued.
    fn finish(&mut self, lane: &Option<String>) {
        let Some(state) = self.lanes.get_mut(lane) else {
            return;
        };
        let Some(current) = state.current.take() else {
            return;
        };
        self.responses += 1;
        match current.terminal {
            Some(response) if !current.failed => {
                let output = response["output"]
                    .as_array()
                    .filter(|output| !output.is_empty())
                    .cloned()
                    .unwrap_or_else(|| {
                        current.items.into_iter().filter(|i| !i.is_null()).collect()
                    });
                if let Some(id) = response["id"].as_str() {
                    state.latest = Some((
                        id.to_owned(),
                        current.input.into_iter().chain(output).collect(),
                    ));
                }
            }
            _ => {
                if current.previous.is_some()
                    && state.latest.as_ref().map(|(id, _)| id) == current.previous.as_ref()
                {
                    state.latest = None;
                }
            }
        }
        self.pump();
    }
    fn poll_tasks(&mut self, context: &mut Context<'_>) {
        for lane in self.lanes.values_mut() {
            if let Some(current) = &mut lane.current
                && let Some(task) = &mut current.task
                && task.as_mut().poll(context).is_ready()
            {
                current.task = None;
            }
        }
    }
    async fn flush(&mut self, cx: &Cx, conn: &mut Box<dyn Connection>) -> Result<(), ()> {
        for message in std::mem::take(&mut self.outbox) {
            let bytes = message
                .to_frame(None)
                .and_then(|frame| Wire::to_bytes(&frame))
                .map_err(|_| ())?;
            conn.write_all(cx, &bytes).await.map_err(|_| ())?;
        }
        Ok(())
    }
}

/// Runs one response through the site's HTTP path and reports its events.
async fn relay(
    model: Model,
    request: Request<Body>,
    lane: Option<String>,
    serial: u64,
    tx: mpsc::UnboundedSender<Note>,
) {
    let note = |out| {
        let _ = tx.send(Note {
            lane: lane.clone(),
            serial,
            out,
        });
    };
    let failed = |_: &Model, _: Error| {
        let event = wrapped(500, &http::HeaderMap::new(), b"");
        Out::Event(event.to_string(), event)
    };
    match model.clone().send_observed(request).await {
        Ok(response) if response.status().is_success() => {
            if let Err(error) = events(response, &note).await {
                note(failed(&model, error));
            }
        }
        Ok(response) => {
            let (parts, body) = response.into_parts();
            let bytes = body
                .collect()
                .await
                .map(|body| body.to_bytes())
                .unwrap_or_default();
            let event = wrapped(parts.status.as_u16(), &parts.headers, &bytes);
            note(Out::Event(event.to_string(), event));
        }
        Err(error) => note(failed(&model, error)),
    }
    note(Out::Done);
}

/// Reports a successful response's events: a stream's events as they
/// come, or the events a stream would have carried for a whole response.
async fn events(response: Response<Body>, note: &impl Fn(Out)) -> fictionet::Result<()> {
    let stream = response
        .headers()
        .get("content-type")
        .is_some_and(|v| v.as_bytes().starts_with(b"text/event-stream"));
    let mut body = response.into_body();
    if !stream {
        let bytes = body.collect().await?.to_bytes();
        let response: Value =
            serde_json::from_slice(&bytes).map_err(|_| Error::msg("Invalid response"))?;
        let output = response["output"].as_array().cloned().unwrap_or_default();
        let mut started = response.clone();
        started["status"] = json!("in_progress");
        started["output"] = json!([]);
        let mut events = vec![json!({"type":"response.created","response":started})];
        for (index, item) in output.into_iter().enumerate() {
            events.push(
                json!({"type":"response.output_item.added","output_index":index,"item":item}),
            );
            events
                .push(json!({"type":"response.output_item.done","output_index":index,"item":item}));
        }
        let end = match response["status"].as_str() {
            Some("incomplete") => "response.incomplete",
            Some("failed") => "response.failed",
            _ => "response.completed",
        };
        events.push(json!({"type":end,"response":response}));
        for (sequence, mut event) in events.into_iter().enumerate() {
            event["sequence_number"] = json!(sequence);
            note(Out::Event(event.to_string(), event));
        }
        return Ok(());
    }
    let mut decoder = Stream::new(sse::Events::new());
    let mut ended = false;
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        let Some(bytes) = frame.data_ref() else {
            continue;
        };
        let mut found = Vec::new();
        try_pump(&mut decoder, bytes, |event| {
            found.push(event.data);
            Ok::<_, sse::Error>(())
        })
        .map_err(|_| Error::msg("Invalid response stream"))?;
        for data in found {
            if data.trim() == "[DONE]" {
                continue;
            }
            let event: Value =
                serde_json::from_str(&data).map_err(|_| Error::msg("Invalid response event"))?;
            ended |= matches!(
                event["type"].as_str(),
                Some("response.completed" | "response.incomplete" | "response.failed" | "error")
            );
            note(Out::Event(data, event));
        }
    }
    if ended {
        Ok(())
    } else {
        Err(Error::msg("Model stream ended before response completion"))
    }
}

/// What woke the socket's loop.
enum Wake {
    Read(Result<usize, fictionet::stdlib::network::ConnError>),
    Note(Note),
}

/// The close code for a client that broke the protocol.
fn broken(fail: &Fail<AssembleError<ws::Error>>) -> u16 {
    match fail {
        Fail::Protocol(AssembleError::Inner(error)) => error.close_code(),
        Fail::Protocol(AssembleError::TooLong { .. }) | Fail::Refused { .. } => {
            close_code::MESSAGE_TOO_BIG
        }
        _ => close_code::PROTOCOL_ERROR,
    }
}

/// Serves one socket until either side closes it or the world stops.
async fn serve(model: Model, head: http::request::Parts, cx: Cx, mut conn: Box<dyn Connection>) {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut session = Session {
        model: model.clone(),
        cx: cx.clone(),
        head,
        opened: cx.now(),
        tx,
        pending: VecDeque::new(),
        lanes: HashMap::new(),
        outbox: Vec::new(),
        serial: 0,
        responses: 0,
    };
    let mut decoder = Stream::new(Messages::for_receiver(Side::Server));
    let mut buf = vec![0; 64 * 1024];
    let close = loop {
        if session.flush(&cx, &mut conn).await.is_err() {
            break None;
        }
        let wake = cx
            .race(
                None,
                std::future::poll_fn(|context| {
                    session.poll_tasks(context);
                    if let Poll::Ready(Some(note)) = rx.poll_recv(context) {
                        return Poll::Ready(Wake::Note(note));
                    }
                    conn.poll_read(&cx, context, &mut buf).map(Wake::Read)
                }),
            )
            .await;
        match wake {
            Ok(Wake::Note(note)) => session.deliver(note),
            // Decodes as it pushes, so a read that completes one message
            // and starts the next fits within the decoder's limit.
            Ok(Wake::Read(Ok(n))) if n > 0 => {
                match try_pump(&mut decoder, &buf[..n], |message| session.message(message)) {
                    Ok(_) => {}
                    Err(PumpError::Handler(close)) => break Some(close),
                    Err(PumpError::Decode(fail)) => {
                        break Some(Message::Close(Some(ws::Close::new(broken(&fail)))));
                    }
                }
            }
            Ok(Wake::Read(_)) | Err(_) => break None,
        }
    };

    if let Some(close) = close {
        session.outbox.push(close);
        if session.flush(&cx, &mut conn).await.is_ok() {
            let _ = conn.shutdown(&cx).await;
        }
    }
}
