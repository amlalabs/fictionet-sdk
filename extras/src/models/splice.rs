use super::*;
use fictionet::stdlib::codec::{Stream, try_pump};
use fictionet::stdlib::protocols::sse;
use http_body::{Body as HttpBody, Frame};
use ring::aead;
use tokio::sync::mpsc;

pub(super) struct TokenCipher(aead::LessSafeKey);
impl TokenCipher {
    pub fn new(cx: &Cx) -> Self {
        let mut bytes = [0; 32];
        cx.fill_random(&mut bytes);
        Self(aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &bytes).unwrap(),
        ))
    }
    pub(super) fn encrypt(&self, cx: &Cx, value: &Value) -> String {
        let mut nonce = [0; 12];
        cx.fill_random(&mut nonce);
        let mut bytes = value.to_string().into_bytes();
        self.0
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::empty(),
                &mut bytes,
            )
            .unwrap();
        let bytes = [nonce.as_slice(), bytes.as_slice()].concat();
        fictionet::stdlib::codec::base64::encode(&bytes)
            .trim_end_matches('=')
            .replace('+', "-")
            .replace('/', "_")
    }
    pub(super) fn open(&self, value: &str) -> fictionet::Result<Value> {
        let mut value = value.replace('-', "+").replace('_', "/");
        while !value.len().is_multiple_of(4) {
            value.push('=');
        }
        let mut bytes = fictionet::stdlib::codec::base64::decode(
            value.as_bytes(),
            fictionet::stdlib::codec::base64::Padding::Canonical,
        )
        .ok_or_else(invalid)?;
        if bytes.len() < 28 {
            return Err(invalid());
        }
        let nonce: [u8; 12] = bytes[..12].try_into().unwrap();
        let plain = self
            .0
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::empty(),
                &mut bytes[12..],
            )
            .map_err(|_| invalid())?;
        serde_json::from_slice(plain).map_err(|_| invalid())
    }
}
fn invalid() -> Error {
    Error::msg("Invalid server tool history")
}

pub(super) fn needed(body: &Value) -> bool {
    body["tools"]
        .as_array()
        .is_some_and(|tools| tools.iter().any(|t| kind(t).is_some()))
        || body["messages"].as_array().is_some_and(|ms| {
            ms.iter().any(|m| {
                m["content"]
                    .as_array()
                    .is_some_and(|bs| bs.iter().any(|b| b["type"] == "server_tool_use"))
            })
        })
}
fn kind(tool: &Value) -> Option<&'static str> {
    let kind = tool["type"].as_str()?;
    if kind.starts_with("web_search_") {
        Some("web_search")
    } else if kind.starts_with("web_fetch_") {
        Some("web_fetch")
    } else {
        None
    }
}
fn definition(name: &str, kind: &str) -> Value {
    if kind == "web_search" {
        json!({"name":name,"description":"Search the web.","input_schema":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}})
    } else {
        json!({"name":name,"description":"Fetch a web page.","input_schema":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}})
    }
}
fn original_id(cipher: &TokenCipher, id: &Value) -> fictionet::Result<String> {
    let token = id
        .as_str()
        .and_then(|id| id.strip_prefix("srvtoolu_"))
        .ok_or_else(invalid)?;
    cipher.open(token)?["id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(invalid)
}
fn history(body: &mut Value, cipher: &TokenCipher) -> fictionet::Result<()> {
    let Some(messages) = body["messages"].as_array_mut() else {
        return Err(invalid());
    };
    let mut reshaped: Vec<Value> = Vec::new();
    for message in std::mem::take(messages) {
        let Some(blocks) = message["content"]
            .as_array()
            .filter(|_| message["role"] == "assistant")
        else {
            if message["role"] == "user" && reshaped.last().is_some_and(|m| m["role"] == "user") {
                let previous = reshaped.last_mut().unwrap();
                let extra = message["content"]
                    .as_array()
                    .cloned()
                    .unwrap_or_else(|| vec![json!({"type":"text","text":message["content"]})]);
                previous["content"]
                    .as_array_mut()
                    .ok_or_else(invalid)?
                    .extend(extra);
            } else {
                reshaped.push(message);
            }
            continue;
        };
        let mut assistant = Vec::new();
        let mut results = Vec::new();
        for block in blocks {
            let typ = block["type"].as_str().unwrap_or("");
            if !matches!(typ, "web_search_tool_result" | "web_fetch_tool_result")
                && !results.is_empty()
            {
                reshaped.push(json!({"role":"assistant","content":std::mem::take(&mut assistant)}));
                reshaped.push(json!({"role":"user","content":std::mem::take(&mut results)}));
            }
            match typ {
                "server_tool_use" => {
                    let mut block = block.clone();
                    block["id"] = json!(original_id(cipher, &block["id"])?);
                    block["type"] = json!("tool_use");
                    assistant.push(block);
                }
                "web_search_tool_result" | "web_fetch_tool_result" => {
                    let id = original_id(cipher, &block["tool_use_id"])?;
                    if !assistant
                        .iter()
                        .any(|b| b["type"] == "tool_use" && b["id"] == id)
                    {
                        return Err(invalid());
                    }
                    let content = &block["content"];
                    let text = if let Some(error) = content["error_code"].as_str() {
                        json!({"error":error}).to_string()
                    } else if typ == "web_search_tool_result" {
                        let entries = content.as_array().ok_or_else(invalid)?;
                        if entries.is_empty() {
                            "[]".into()
                        } else {
                            let token = entries[0]["encrypted_content"]
                                .as_str()
                                .ok_or_else(invalid)?;
                            let payload = cipher.open(token)?;
                            if payload["id"] != id {
                                return Err(invalid());
                            }
                            let visible = payload["visible"].as_array().ok_or_else(invalid)?;
                            if visible.len() != entries.len() {
                                return Err(invalid());
                            }
                            for (a, b) in entries.iter().zip(visible) {
                                if a["url"] != b["url"]
                                    || a["title"] != b["title"]
                                    || a["encrypted_content"] != token
                                {
                                    return Err(invalid());
                                }
                            }
                            payload["text"].as_str().ok_or_else(invalid)?.into()
                        }
                    } else {
                        content["content"]["source"]["data"]
                            .as_str()
                            .ok_or_else(invalid)?
                            .into()
                    };
                    results.push(json!({"type":"tool_result","tool_use_id":id,"content":text}));
                }
                _ => assistant.push(block.clone()),
            }
        }
        if !assistant.is_empty() {
            reshaped.push(json!({"role":"assistant","content":assistant}));
        }
        if !results.is_empty() {
            reshaped.push(json!({"role":"user","content":results}));
        }
    }
    *messages = reshaped;
    Ok(())
}

struct Output {
    sender: Option<mpsc::Sender<fictionet::Result<Frame<Bytes>>>>,
    message: Value,
    content: Vec<Value>,
}
impl Output {
    async fn event(&mut self, value: Value) -> fictionet::Result<()> {
        if let Some(sender) = &self.sender {
            let kind = value["type"].as_str().unwrap_or("message");
            let data = format!("event: {kind}\ndata: {value}\n\n");
            sender
                .send(Ok(Frame::data(data.into())))
                .await
                .map_err(|_| Error::msg("Model response reader closed"))?;
        }
        Ok(())
    }
    async fn block(&mut self, block: Value) -> fictionet::Result<()> {
        let index = self.content.len();
        self.event(json!({"type":"content_block_start","index":index,"content_block":block}))
            .await?;
        self.event(json!({"type":"content_block_stop","index":index}))
            .await?;
        self.content.push(block);
        Ok(())
    }
}
pub(super) struct Channel(pub(super) mpsc::Receiver<fictionet::Result<Frame<Bytes>>>);
impl HttpBody for Channel {
    type Data = Bytes;
    type Error = Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<fictionet::Result<Frame<Bytes>>>> {
        self.0.poll_recv(cx)
    }
}

type Tools = std::collections::HashMap<String, (&'static str, Value)>;

/// Replaces the web tools with their function definitions. Returns each
/// tool's kind and settings by name.
fn definitions(body: &mut Value) -> Tools {
    let mut tools = Tools::new();
    if let Some(entries) = body["tools"].as_array_mut() {
        for entry in entries {
            if let Some(kind) = kind(entry) {
                let name = entry["name"].as_str().unwrap_or(kind).to_owned();
                tools.insert(name.clone(), (kind, entry.clone()));
                *entry = definition(&name, kind);
            }
        }
    }
    tools
}

fn invalid_history(model: &Model) -> Response<Body> {
    model
        .provider
        .error(400, "invalid_request_error", "Invalid server tool history")
}

/// Counts the tokens of the request the splice would send: its history and
/// web tools translated. The count comes back as the upstream wrote it.
pub(super) async fn count(
    mut model: Model,
    parts: http::request::Parts,
    mut body: Value,
) -> fictionet::Result<Response<Body>> {
    model.engine = None;
    if history(&mut body, &model.cipher).is_err() {
        return Ok(invalid_history(&model));
    }
    definitions(&mut body);
    upstream(&model, &parts, &body).await
}

pub(super) async fn serve(
    mut model: Model,
    parts: http::request::Parts,
    mut body: Value,
) -> fictionet::Result<Response<Body>> {
    let engine = model.engine.take().expect("engine checked");
    if history(&mut body, &model.cipher).is_err() {
        return Ok(invalid_history(&model));
    }
    let tools = definitions(&mut body);
    let stream = body["stream"] == true;
    let response = upstream(&model, &parts, &body).await?;
    if !response.status().is_success() {
        return Ok(response);
    }
    let mut output = Output {
        sender: None,
        message: Value::Null,
        content: Vec::new(),
    };
    if stream {
        let (tx, rx) = mpsc::channel(8);
        output.sender = Some(tx.clone());
        let cx = model.cx.clone();
        cx.spawn(move |cx| async move {
            let result = match run(model, engine, parts, body, tools, response, &mut output).await {
                Ok(Some(refused)) => failed(refused, &mut output).await,
                Ok(None) => Ok(()),
                Err(error) => Err(error),
            };
            if let Err(error) = result {
                cx.emit("model", "splice_error", |e| {
                    e.field("message", error.to_string())
                });
                let _ = tx.send(Err(error)).await;
            }
            Ok(())
        });
        Ok(Response::builder()
            .header("content-type", "text/event-stream")
            .body(Body::new(Channel(rx)))?)
    } else {
        if let Some(refused) = run(model, engine, parts, body, tools, response, &mut output).await?
        {
            return Ok(refused);
        }
        output.message["content"] = json!(output.content);
        Ok(Response::builder()
            .header("content-type", "application/json")
            .body(Body::from(output.message.to_string()))?)
    }
}
/// Ends a stream whose continuation was refused, such as by a budget stop,
/// with Anthropic's `error` event carrying the refusal's type and message.
async fn failed(refused: Response<Body>, output: &mut Output) -> fictionet::Result<()> {
    let kind = match refused.status().as_u16() {
        400 => "invalid_request_error",
        401 => "authentication_error",
        402 => "billing_error",
        403 => "permission_error",
        404 => "not_found_error",
        413 => "request_too_large",
        429 => "rate_limit_error",
        529 => "overloaded_error",
        _ => "api_error",
    };
    let bytes = http_body_util::Limited::new(refused.into_body(), 64 * 1024)
        .collect()
        .await
        .map(|body| body.to_bytes())
        .unwrap_or_default();
    let body = serde_json::from_slice::<Value>(&bytes).unwrap_or_default();
    let kind = body["error"]["type"].as_str().unwrap_or(kind);
    let message = body["error"]["message"]
        .as_str()
        .or_else(|| body["message"].as_str())
        .unwrap_or("Model continuation was refused");
    output
        .event(json!({"type":"error","error":{"type":kind,"message":message}}))
        .await
}

pub(super) async fn upstream(
    model: &Model,
    parts: &http::request::Parts,
    body: &Value,
) -> fictionet::Result<Response<Body>> {
    let mut request = Request::new(Body::from(body.to_string()));
    *request.method_mut() = parts.method.clone();
    *request.uri_mut() = parts.uri.clone();
    *request.headers_mut() = parts.headers.clone();
    *request.extensions_mut() = parts.extensions.clone();
    *request.version_mut() = parts.version;
    request.headers_mut().remove("content-length");
    model.clone().boxed(request).await
}

struct Turn {
    content: Vec<Value>,
    ids: std::collections::HashMap<String, String>,
    usage: Value,
    stop: Value,
}
async fn read(
    response: Response<Body>,
    model: &Model,
    tools: &Tools,
    output: &mut Output,
) -> fictionet::Result<Turn> {
    let streaming = response
        .headers()
        .get("content-type")
        .is_some_and(|s| s.as_bytes().starts_with(b"text/event-stream"));
    let offset = output.content.len();
    let mut turn = Turn {
        content: Vec::new(),
        ids: Default::default(),
        usage: json!({}),
        stop: Value::Null,
    };
    if !streaming {
        let bytes = response.into_body().collect().await?.to_bytes();
        let message: Value = serde_json::from_slice(&bytes)?;
        if output.message.is_null() {
            output.message = message.clone();
        }
        turn.content = message["content"]
            .as_array()
            .cloned()
            .ok_or_else(|| Error::msg("Invalid model message"))?;
        turn.usage = message["usage"].clone();
        turn.stop = message["stop_reason"].clone();
        for block in &turn.content {
            output
                .block(visible(block.clone(), model, tools, &mut turn.ids))
                .await?;
        }
        return Ok(turn);
    }
    let mut decoder = Stream::new(sse::Events::new());
    let mut body = response.into_body();
    let mut inputs: std::collections::HashMap<usize, String> = Default::default();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        let Some(bytes) = frame.data_ref() else {
            continue;
        };
        let mut events = Vec::new();
        try_pump(&mut decoder, bytes, |e| {
            events.push(e);
            Ok::<_, sse::Error>(())
        })
        .map_err(|_| Error::msg("Invalid model stream"))?;
        for event in events {
            let mut event: Value =
                serde_json::from_str(&event.data).map_err(|_| Error::msg("Invalid model event"))?;
            let index = event["index"].as_u64().unwrap_or(0) as usize;
            match event["type"].as_str().unwrap_or("") {
                "message_start" => {
                    turn.usage = event["message"]["usage"].clone();
                    if output.message.is_null() {
                        output.message = event["message"].clone();
                        output.event(event).await?;
                    }
                    continue;
                }
                "message_delta" => {
                    if let Some(usage) = event["usage"].as_object() {
                        for (key, value) in usage {
                            turn.usage[key] = value.clone();
                        }
                    }
                    turn.stop = event["delta"]["stop_reason"].clone();
                    continue;
                }
                "message_stop" => return Ok(turn),
                "content_block_start" => {
                    if index != turn.content.len() {
                        return Err(Error::msg("Invalid model block index"));
                    }
                    turn.content.push(event["content_block"].clone());
                    event["content_block"] =
                        visible(event["content_block"].clone(), model, tools, &mut turn.ids);
                    output.content.push(event["content_block"].clone());
                    event["index"] = json!(offset + index);
                }
                "content_block_delta" => {
                    let block = turn
                        .content
                        .get_mut(index)
                        .ok_or_else(|| Error::msg("Invalid model block delta"))?;
                    let delta = &event["delta"];
                    match delta["type"].as_str().unwrap_or("") {
                        "input_json_delta" => inputs
                            .entry(index)
                            .or_default()
                            .push_str(delta["partial_json"].as_str().unwrap_or("")),
                        "text_delta" | "thinking_delta" | "signature_delta" => {
                            let field = match delta["type"].as_str().unwrap() {
                                "text_delta" => "text",
                                "thinking_delta" => "thinking",
                                _ => "signature",
                            };
                            let text = format!(
                                "{}{}",
                                block[field].as_str().unwrap_or(""),
                                delta[field].as_str().unwrap_or("")
                            );
                            block[field] = json!(text);
                        }
                        "citations_delta" => {
                            if !block["citations"].is_array() {
                                block["citations"] = json!([]);
                            }
                            block["citations"]
                                .as_array_mut()
                                .unwrap()
                                .push(delta["citation"].clone());
                        }
                        _ => {}
                    }
                    event["index"] = json!(offset + index);
                }
                "content_block_stop" => {
                    let block = turn
                        .content
                        .get_mut(index)
                        .ok_or_else(|| Error::msg("Invalid model block stop"))?;
                    if let Some(input) = inputs.remove(&index) {
                        block["input"] = serde_json::from_str(&input)
                            .map_err(|_| Error::msg("Invalid model tool input"))?;
                    }
                    let mut shown = block.clone();
                    if let Some(id) = block["id"].as_str().and_then(|id| turn.ids.get(id)) {
                        shown["id"] = json!(id);
                        shown["type"] = json!("server_tool_use");
                    }
                    output.content[offset + index] = shown;
                    event["index"] = json!(offset + index);
                }
                "error" => return Err(Error::msg("Model stream reported an error")),
                _ => {}
            }
            output.event(event).await?;
        }
    }
    Err(Error::msg("Model stream ended before message_stop"))
}
fn visible(
    mut block: Value,
    model: &Model,
    tools: &Tools,
    ids: &mut std::collections::HashMap<String, String>,
) -> Value {
    if block["type"] == "tool_use"
        && block["name"]
            .as_str()
            .is_some_and(|name| tools.contains_key(name))
    {
        let original = block["id"].as_str().unwrap_or("").to_owned();
        let id = format!(
            "srvtoolu_{}",
            model.cipher.encrypt(&model.cx, &json!({"id":original}))
        );
        ids.insert(original, id.clone());
        block["type"] = json!("server_tool_use");
        block["id"] = json!(id);
    }
    block
}
async fn run(
    model: Model,
    engine: Arc<dyn Engine>,
    parts: http::request::Parts,
    mut body: Value,
    tools: Tools,
    mut response: Response<Body>,
    output: &mut Output,
) -> fictionet::Result<Option<Response<Body>>> {
    let mut uses: std::collections::HashMap<String, u64> = Default::default();
    let mut output_tokens = 0u64;
    let mut searches = 0u64;
    for _ in 0..16 {
        let turn = read(response, &model, &tools, output).await?;
        output_tokens += turn.usage["output_tokens"].as_u64().unwrap_or(0);
        let mut results = Vec::new();
        for block in &turn.content {
            let Some(id) = block["id"].as_str().and_then(|id| turn.ids.get(id)) else {
                continue;
            };
            let name = block["name"].as_str().unwrap();
            let (kind, settings) = &tools[name];
            let count = uses.entry(name.into()).or_default();
            *count += 1;
            let start = Instant::now();
            let (content, text) =
                answer(&model, engine.clone(), &body, block, kind, settings, *count).await;
            if *kind == "web_search" {
                searches += 1;
            }
            model
                .cx
                .emitter(&model.connection)
                .emit("model", "tool", |e| {
                    e.field("tool", *kind)
                        .field("query", block["input"]["query"].as_str().unwrap_or(""))
                        .field("url", block["input"]["url"].as_str().unwrap_or(""))
                        .field("source", "world")
                        .field("results", content.as_array().map_or(0, Vec::len) as u64)
                        .field("ms", start.elapsed().as_millis() as u64)
                });
            output.block(json!({"type":format!("{kind}_tool_result"),"tool_use_id":id,"content":content})).await?;
            results.push(json!({"type":"tool_result","tool_use_id":block["id"],"content":text}));
        }
        let external = turn.content.iter().any(|b| {
            b["type"] == "tool_use" && !turn.ids.contains_key(b["id"].as_str().unwrap_or(""))
        });
        if results.is_empty() || external {
            let mut usage = turn.usage;
            usage["output_tokens"] = json!(output_tokens);
            usage["server_tool_use"] = json!({"web_search_requests":searches});
            output.message["usage"] = usage.clone();
            output.message["stop_reason"] = turn.stop.clone();
            output.event(json!({"type":"message_delta","delta":{"stop_reason":turn.stop,"stop_sequence":null},"usage":usage})).await?;
            output.event(json!({"type":"message_stop"})).await?;
            return Ok(None);
        }
        let messages = body["messages"].as_array_mut().ok_or_else(invalid)?;
        messages.push(json!({"role":"assistant","content":turn.content}));
        messages.push(json!({"role":"user","content":results}));
        body.as_object_mut().unwrap().remove("tool_choice");
        response = upstream(&model, &parts, &body).await?;
        if !response.status().is_success() {
            return Ok(Some(response));
        }
    }
    Err(Error::msg("Server tool turn limit reached"))
}
async fn answer(
    model: &Model,
    engine: Arc<dyn Engine>,
    body: &Value,
    block: &Value,
    kind: &str,
    settings: &Value,
    used: u64,
) -> (Value, String) {
    let error = |code: &str| {
        (
            json!({"type":format!("{kind}_tool_result_error"),"error_code":code}),
            json!({"error":code}).to_string(),
        )
    };
    if used > settings["max_uses"].as_u64().unwrap_or(8) {
        return error("max_uses_exceeded");
    }
    if kind == "web_search" {
        let Some(query) = block["input"]["query"].as_str() else {
            return error("invalid_input");
        };
        let Ok(results) = engine
            .search(
                model.cx.clone(),
                query.into(),
                "claude_web_search",
                settings.clone(),
            )
            .await
        else {
            return error("unavailable");
        };
        let results: Vec<_> = results
            .into_iter()
            .filter(|r| tools::allowed(settings, &r.url))
            .collect();
        let text = serde_json::to_string(&results).unwrap();
        let mut content: Vec<Value> = results.iter().map(|r| json!({"type":"web_search_result","url":r.url,"title":r.title,"page_age":r.date})).collect();
        let token = model.cipher.encrypt(
            &model.cx,
            &json!({"id":block["id"],"text":text,"visible":content}),
        );
        for entry in &mut content {
            entry["encrypted_content"] = json!(token);
        }
        (json!(content), text)
    } else {
        let Some(url) = block["input"]["url"].as_str() else {
            return error("invalid_input");
        };
        if !body["messages"].to_string().contains(url) {
            return error("url_not_in_prior_context");
        }
        if !tools::allowed(settings, url)
            || !tools::host(url).is_some_and(|host| engine.serves(&host))
        {
            return error("url_not_accessible");
        }
        let Ok(page) = engine.fetch(model.cx.clone(), url.into()).await else {
            return error("url_not_accessible");
        };
        let pdf = page.media_type == "application/pdf";
        let mut text = if pdf {
            fictionet::stdlib::codec::base64::encode(&page.body)
        } else if let Some(text) = tools::text(&page) {
            text
        } else {
            return error("unsupported_content_type");
        };
        if let Some(limit) = settings["max_content_tokens"].as_u64() {
            if pdf && text.len() as u64 > limit.saturating_mul(4) {
                return error("max_content_tokens_exceeded");
            }
            if !pdf {
                text = text
                    .chars()
                    .take(limit.saturating_mul(4) as usize)
                    .collect();
            }
        }
        let content = json!({"type":"web_fetch_result","url":url,"retrieved_at":rfc3339(time::OffsetDateTime::now_utc()),"content":{"type":"document","source":{"type":if pdf {"base64"} else {"text"},"media_type":if pdf {"application/pdf"} else {"text/plain"},"data":text},"title":page.title,"citations":{"enabled":settings["citations"]["enabled"] == true}}});
        (content, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Pages;
    impl Engine for Pages {
        fn search(
            self: Arc<Self>,
            _: Cx,
            _: String,
            _: &'static str,
            _: Value,
        ) -> tools::Answer<Vec<crate::search::Result>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn fetch(self: Arc<Self>, _: Cx, _: String) -> tools::Answer<tools::Page> {
            Box::pin(async {
                Ok(tools::Page {
                    title: "Title".into(),
                    media_type: "text/html".into(),
                    body: b"<p>Visible</p><script>hidden</script>".to_vec(),
                })
            })
        }
        fn serves(&self, host: &str) -> bool {
            host == "example.com"
        }
    }
    #[test]
    fn fetch_uses_prior_context_and_limits_and_round_trips_history() {
        fictionet::block_on(fictionet::run(fictionet::RunOptions::new(fictionet::Seed::from_u64(9)), |cx| async move {
            let credential = Credential::api_key(&cx, Secret::new("key", "private".into())?);
            let model = Model::at(&cx, Provider::Anthropic, credential, "http://127.0.0.1:1".parse()?)?;
            let engine: Arc<dyn Engine> = Arc::new(Pages);
            let block = json!({"type":"tool_use","id":"toolu_fetch","name":"web_fetch","input":{"url":"https://example.com/page"}});
            let body = json!({"messages":[{"role":"user","content":"Read https://example.com/page"}]});
            let settings = json!({"max_uses":1,"max_content_tokens":1});
            let (content, text) = answer(&model, engine.clone(), &body, &block, "web_fetch", &settings, 1).await;
            assert_eq!(text, "Visi");
            assert_eq!(content["content"]["source"]["data"], "Visi");
            let (error, _) = answer(&model, engine.clone(), &json!({"messages":[]}), &block, "web_fetch", &settings, 1).await;
            assert_eq!(error["error_code"], "url_not_in_prior_context");
            let (error, _) = answer(&model, engine.clone(), &body, &block, "web_fetch", &settings, 2).await;
            assert_eq!(error["error_code"], "max_uses_exceeded");
            let (error, _) = answer(&model, engine, &body, &block, "web_fetch", &json!({"blocked_domains":["example.com"]}), 1).await;
            assert_eq!(error["error_code"], "url_not_accessible");
            let shown = visible(block.clone(), &model, &std::collections::HashMap::from([("web_fetch".into(), ("web_fetch", settings))]), &mut Default::default());
            let mut replay = body.clone();
            replay["messages"].as_array_mut().unwrap().push(json!({"role":"assistant","content":[shown.clone(),{"type":"web_fetch_tool_result","tool_use_id":shown["id"],"content":content},{"type":"text","text":"Done"}]}));
            history(&mut replay, &model.cipher)?;
            assert_eq!(replay["messages"][1]["content"][0], block);
            assert_eq!(replay["messages"][2]["content"][0]["content"], text);
            assert_eq!(replay["messages"][3]["content"][0]["text"], "Done");
            Ok(())
        })).unwrap();
    }
}
