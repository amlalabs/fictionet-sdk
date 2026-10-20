use super::*;
use fictionet::stdlib::codec::{Stream, try_pump};
use fictionet::stdlib::protocols::sse;
use http_body::{Body as HttpBody, Frame};

pub(super) struct Call {
    cx: Cx,
    id: u64,
    provider: Provider,
    path: String,
    model: String,
    stream: bool,
    request_bytes: usize,
    response_bytes: usize,
    start: Instant,
    first: Option<u64>,
    pub status: u16,
    pub stop: String,
    input: u64,
    output: u64,
    cache_read: u64,
    cache_write: u64,
    cache_write_1h: u64,
    cost: Option<f64>,
    usage: bool,
    complete: bool,
    free: bool,
    ledger: Arc<Mutex<Ledger>>,
    prices: Option<Prices>,
    secret: Secret,
}
impl Call {
    pub fn new(site: &Model, path: String, body: &Value, request: &[u8], free: bool) -> Self {
        let call = Self {
            cx: site.cx.clone(),
            id: site.cx.random_u64(),
            provider: site.provider,
            path,
            model: site
                .credential
                .real
                .redact(body["model"].as_str().unwrap_or("")),
            stream: body["stream"].as_bool().unwrap_or(false),
            request_bytes: request.len(),
            response_bytes: 0,
            start: Instant::now(),
            first: None,
            status: 0,
            stop: "cancelled".into(),
            input: 0,
            output: 0,
            cache_read: 0,
            cache_write: 0,
            cache_write_1h: 0,
            cost: None,
            usage: false,
            complete: false,
            free,
            ledger: site.ledger.clone(),
            prices: site.prices.as_ref().and_then(|(model, prices)| {
                (body["model"].as_str() == Some(model.as_str())).then_some(*prices)
            }),
            secret: site.credential.real.clone(),
        };
        call.transcript(
            "request",
            site.credential
                .real
                .redact(&String::from_utf8_lossy(request))
                .as_bytes(),
        );
        call
    }
    fn transcript(&self, direction: &str, data: &[u8]) {
        for chunk in data.chunks(64 * 1024) {
            self.cx.emit("model", "body", |e| {
                e.field("call", self.id)
                    .field("direction", direction)
                    .field("encoding", "base64")
                    .field("data", fictionet::stdlib::codec::base64::encode(chunk))
            });
        }
    }
    fn read(&mut self, value: &Value) {
        if matches!(
            value["type"].as_str(),
            Some("message_stop" | "response.completed" | "response.failed" | "response.incomplete")
        ) {
            self.complete = true;
        }
        let value = value
            .get("message")
            .or_else(|| value.get("response"))
            .unwrap_or(value);
        if let Some(usage) = value.get("usage").or_else(|| value.get("usageMetadata")) {
            for (slot, names) in [
                (
                    &mut self.input,
                    &["input_tokens", "prompt_tokens", "promptTokenCount"][..],
                ),
                (
                    &mut self.output,
                    &["output_tokens", "completion_tokens", "candidatesTokenCount"][..],
                ),
                (
                    &mut self.cache_read,
                    &["cache_read_input_tokens", "cachedContentTokenCount"][..],
                ),
                (&mut self.cache_write, &["cache_creation_input_tokens"][..]),
            ] {
                if let Some(n) = names.iter().find_map(|name| usage[*name].as_u64()) {
                    *slot = n;
                    self.usage = true;
                }
            }
            if let Some(n) = usage["cache_creation"]["ephemeral_1h_input_tokens"].as_u64() {
                self.cache_write_1h = n;
            }
            if let Some(n) = usage["input_tokens_details"]["cached_tokens"]
                .as_u64()
                .or_else(|| usage["prompt_tokens_details"]["cached_tokens"].as_u64())
            {
                self.cache_read = n;
            }
            if let Some(thinking) = usage["thoughtsTokenCount"].as_u64() {
                self.output = usage["candidatesTokenCount"]
                    .as_u64()
                    .unwrap_or(0)
                    .saturating_add(thinking);
            }
            if let Some(n) = usage["cost"]
                .as_f64()
                .filter(|n| n.is_finite() && *n >= 0.0)
            {
                self.cost = Some(n);
            }
        }
        if let Some(stop) = value["stop_reason"]
            .as_str()
            .or_else(|| value["delta"]["stop_reason"].as_str())
            .or_else(|| value["choices"][0]["finish_reason"].as_str())
            .or_else(|| value["candidates"][0]["finishReason"].as_str())
            .or_else(|| value["status"].as_str())
        {
            self.stop = self.secret.redact(stop);
            if self.provider == Provider::Gemini {
                self.complete = true;
            }
        }
    }
}
impl Drop for Call {
    fn drop(&mut self) {
        let cost = self
            .cost
            .or_else(|| {
                self.prices.map(|p| {
                    let uncached = if self.path.ends_with("/messages") {
                        self.input
                    } else {
                        self.input.saturating_sub(self.cache_read)
                    };
                    (uncached as f64 * p.input
                        + self.output as f64 * p.output
                        + self.cache_read as f64 * p.cache_read
                        + self.cache_write.saturating_sub(self.cache_write_1h) as f64
                            * p.cache_write
                        + self.cache_write_1h as f64 * p.cache_write_1h)
                        / 1_000_000.0
                })
            })
            .filter(|cost| cost.is_finite() && *cost >= 0.0);
        if !self.free {
            let mut ledger = self.ledger.lock().unwrap();
            ledger.input = ledger.input.saturating_add(self.input);
            ledger.output = ledger.output.saturating_add(self.output);
            ledger.usd += cost.unwrap_or(0.0);
            ledger.unknown |= self.status < 400 && (!self.complete || !self.usage);
            ledger.unknown_cost |= self.status < 400 && cost.is_none();
        }
        self.cx.emit("model", "call", |e| {
            e.field("call", self.id)
                .field("provider", self.provider.host())
                .field("host", self.provider.host())
                .field("path", self.path.as_str())
                .field("model", self.model.as_str())
                .field("stream", self.stream)
                .field("status", self.status as u64)
                .field("input_tokens", self.input)
                .field("output_tokens", self.output)
                .field("cache_read_input_tokens", self.cache_read)
                .field("cache_creation_input_tokens", self.cache_write)
                .field("request_bytes", self.request_bytes as u64)
                .field("response_bytes", self.response_bytes as u64)
                .field("first_byte_ms", self.first.unwrap_or(0))
                .field("total_ms", self.start.elapsed().as_millis() as u64)
                .field("stop_reason", self.stop.as_str())
                .field("credential", "placeholder")
        });
    }
}

pub(super) struct Metered {
    body: Body,
    call: Option<Call>,
    sse: Option<Stream<sse::Events>>,
    json: Vec<u8>,
    secret: Secret,
    pending: Vec<u8>,
    done: bool,
}
impl Metered {
    pub fn new(body: Body, call: Call, sse: bool, secret: Secret) -> Self {
        Self {
            body,
            call: Some(call),
            sse: sse.then(|| Stream::new(sse::Events::new())),
            json: Vec::new(),
            secret,
            pending: Vec::new(),
            done: false,
        }
    }
    fn consume(&mut self, bytes: &[u8]) {
        let call = self.call.as_mut().unwrap();
        call.first
            .get_or_insert_with(|| call.start.elapsed().as_millis() as u64);
        call.response_bytes += bytes.len();
        if let Some(decoder) = &mut self.sse {
            if try_pump(decoder, bytes, |event| {
                if event.data == "[DONE]" {
                    call.complete = true;
                }
                if let Ok(value) = serde_json::from_str::<Value>(&event.data) {
                    call.read(&value);
                }
                Ok::<_, sse::Error>(())
            })
            .is_err()
            {
                call.stop = "invalid_stream".into();
            }
        } else if self.json.len() + bytes.len() <= 1024 * 1024 {
            self.json.extend_from_slice(bytes);
        }
    }
    fn scrub(&mut self, end: bool) -> Vec<u8> {
        let needle = self.secret.value.as_bytes();
        let replacement = self.secret.to_string();
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.pending.len() {
            let rest = &self.pending[i..];
            if rest.starts_with(needle) {
                out.extend_from_slice(replacement.as_bytes());
                i += needle.len();
            } else if !end && needle.starts_with(rest) {
                break;
            } else {
                out.push(rest[0]);
                i += 1;
            }
        }
        self.pending.drain(..i);
        out
    }
    fn finish(&mut self) {
        if let Some(mut call) = self.call.take() {
            if self.sse.is_none()
                && let Ok(value) = serde_json::from_slice::<Value>(&self.json)
            {
                call.read(&value);
                call.complete = true;
            }
            if !call.complete {
                call.stop = "incomplete".into();
            } else if call.stop == "cancelled" {
                call.stop = "complete".into();
            }
        }
    }
}
impl HttpBody for Metered {
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
                        self.consume(&bytes);
                        self.pending.extend_from_slice(&bytes);
                        let safe = self.scrub(false);
                        if !safe.is_empty() {
                            if let Some(call) = &self.call {
                                call.transcript("response", &safe);
                            }
                            return Poll::Ready(Some(Ok(Frame::data(safe.into()))));
                        }
                    }
                    Err(_) => continue,
                },
                Poll::Ready(Some(Err(error))) => {
                    self.done = true;
                    if let Some(call) = self.call.as_mut() {
                        call.stop = "transport_error".into();
                    }
                    self.call.take();
                    return Poll::Ready(Some(Err(Error::msg(
                        self.secret.redact(&error.to_string()),
                    ))));
                }
                Poll::Ready(None) => {
                    self.done = true;
                    let tail = self.scrub(true);
                    if let Some(call) = &self.call {
                        call.transcript("response", &tail);
                    }
                    self.finish();
                    return Poll::Ready((!tail.is_empty()).then(|| Ok(Frame::data(tail.into()))));
                }
            }
        }
    }
}
