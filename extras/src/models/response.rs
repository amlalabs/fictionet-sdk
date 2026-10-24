use super::*;
use fictionet::stdlib::codec::{Stream, try_pump};
use fictionet::stdlib::protocols::sse;
use http_body::{Body as HttpBody, Frame};

pub(super) struct Call {
    provider: Provider,
    path: String,
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
    pub fn new(
        site: &Model,
        path: String,
        model: Option<&str>,
        free: bool,
        secret: &Secret,
    ) -> Self {
        Self {
            provider: site.provider,
            path,
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
            prices: site.prices.as_ref().and_then(|(priced_model, prices)| {
                (model == Some(priced_model.as_str())).then_some(*prices)
            }),
            secret: secret.clone(),
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
            let input = if self.path.ends_with("/messages") {
                self.input
                    .saturating_add(self.cache_read)
                    .saturating_add(self.cache_write)
            } else {
                self.input
            };
            ledger.input = ledger.input.saturating_add(input);
            ledger.output = ledger.output.saturating_add(self.output);
            ledger.usd += cost.unwrap_or(0.0);
            ledger.unknown |= self.status < 400 && (!self.complete || !self.usage);
            ledger.unknown_cost |= self.status < 400 && cost.is_none();
        }
    }
}

pub(super) struct Metered {
    body: Body,
    call: Option<Call>,
    sse: Option<Stream<sse::Events>>,
    json: Vec<u8>,

    done: bool,
}
impl Metered {
    pub fn new(body: Body, call: Call, sse: bool) -> Self {
        Self {
            body,
            call: Some(call),
            sse: sse.then(|| Stream::new(sse::Events::new())),
            json: Vec::new(),

            done: false,
        }
    }
    fn consume(&mut self, bytes: &[u8]) {
        let call = self.call.as_mut().unwrap();
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
                        return Poll::Ready(Some(Ok(Frame::data(bytes))));
                    }
                    Err(_) => continue,
                },
                Poll::Ready(Some(Err(error))) => {
                    self.done = true;
                    if let Some(call) = self.call.as_mut() {
                        call.stop = "transport_error".into();
                    }
                    self.call.take();
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => {
                    self.done = true;
                    self.finish();
                    return Poll::Ready(None);
                }
            }
        }
    }
}
