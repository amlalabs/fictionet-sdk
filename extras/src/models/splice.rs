use super::*;
use fictionet::stdlib::codec::{Stream, try_pump};
use fictionet::stdlib::protocols::sse;
use http_body::{Body as HttpBody, Frame};
use response::{Block as OutputBlock, Delta, EventKind};
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

use request::{
    Block, Content, Message as InputMessage, Messages, Role, Tool, TypedBlock, WebSettings, WebTool,
};

fn definition(name: &str, kind: WebTool) -> Tool {
    match kind {
        WebTool::Search => Tool::function(
            name,
            "Search the web.",
            json!({"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}),
        ),
        WebTool::Fetch => Tool::function(
            name,
            "Fetch a web page.",
            json!({"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}),
        ),
    }
}
fn original_id(cipher: &TokenCipher, id: &str) -> fictionet::Result<String> {
    let token = id.strip_prefix("srvtoolu_").ok_or_else(invalid)?;
    cipher.open(token)?["id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(invalid)
}
fn history(body: &mut Messages, cipher: &TokenCipher) -> fictionet::Result<()> {
    let messages = body.messages.as_mut().ok_or_else(invalid)?;
    let mut reshaped: Vec<InputMessage> = Vec::new();
    for mut message in std::mem::take(messages) {
        if message.role != Role::Assistant || !matches!(message.content, Some(Content::Blocks(_))) {
            if message.role == Role::User && reshaped.last().is_some_and(|m| m.role == Role::User) {
                let previous = reshaped.last_mut().unwrap();
                let mut blocks = previous
                    .content
                    .take()
                    .unwrap_or(Content::Empty(()))
                    .into_blocks();
                blocks.extend(
                    message
                        .content
                        .take()
                        .unwrap_or(Content::Empty(()))
                        .into_blocks(),
                );
                previous.content = Some(Content::Blocks(blocks));
            } else {
                reshaped.push(message);
            }
            continue;
        }
        let mut assistant = Vec::new();
        let mut results = Vec::new();
        for block in message.content.take().unwrap().into_blocks() {
            let tool_result = matches!(&block, Content::Block(block) if matches!(**block, Block::Typed(TypedBlock::WebSearchToolResult { .. } | TypedBlock::WebFetchToolResult { .. })));
            if !tool_result && !results.is_empty() {
                reshaped.push(InputMessage::new(
                    Role::Assistant,
                    Content::Blocks(std::mem::take(&mut assistant)),
                ));
                reshaped.push(InputMessage::new(
                    Role::User,
                    Content::Blocks(std::mem::take(&mut results)),
                ));
            }
            let Content::Block(block) = block else {
                return Err(invalid());
            };
            match *block {
                Block::Typed(TypedBlock::ServerToolUse { id, name, input }) => {
                    assistant.push(Content::typed(TypedBlock::ToolUse {
                        id: Some(original_id(cipher, &id)?),
                        name,
                        input,
                        caller: None,
                        cache_control: None,
                    }));
                }
                Block::Typed(
                    result @ (TypedBlock::WebSearchToolResult { .. }
                    | TypedBlock::WebFetchToolResult { .. }),
                ) => {
                    let (tool_use_id, content, search) = match result {
                        TypedBlock::WebSearchToolResult {
                            tool_use_id,
                            content,
                        } => (tool_use_id, content, true),
                        TypedBlock::WebFetchToolResult {
                            tool_use_id,
                            content,
                        } => (tool_use_id, content, false),
                        _ => unreachable!(),
                    };
                    let id = original_id(cipher, &tool_use_id)?;
                    if !assistant.iter().any(|block| matches!(block, Content::Block(block) if matches!(&**block, Block::Typed(TypedBlock::ToolUse { id: Some(existing), .. }) if *existing == id))) { return Err(invalid()); }
                    // The encrypted result is an opaque wire token, checked against its
                    // decoded visible fields before it becomes local tool text.
                    let content = serde_json::to_value(content)?;
                    let text = if let Some(error) = content["error_code"].as_str() {
                        json!({"error":error}).to_string()
                    } else if search {
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
                    results.push(Content::typed(TypedBlock::ToolResult {
                        tool_use_id: id,
                        content: Some(Content::Text(text)),
                        is_error: None,
                        cache_control: None,
                    }));
                }
                block => assistant.push(Content::Block(Box::new(block))),
            }
        }
        if !assistant.is_empty() {
            reshaped.push(InputMessage::new(
                Role::Assistant,
                Content::Blocks(assistant),
            ));
        }
        if !results.is_empty() {
            reshaped.push(InputMessage::new(Role::User, Content::Blocks(results)));
        }
    }
    *messages = reshaped;
    Ok(())
}

struct Output {
    sender: Option<mpsc::Sender<fictionet::Result<Frame<Bytes>>>>,
    message: Value,
    content: Vec<OutputBlock>,
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
    async fn block(&mut self, block: OutputBlock) -> fictionet::Result<()> {
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

type Tools = std::collections::HashMap<String, (WebTool, WebSettings)>;

fn definitions(body: &mut Messages) -> Tools {
    let mut tools = Tools::new();
    if let Some(entries) = &mut body.tools {
        for entry in entries {
            if let Some((kind, settings)) = entry.web() {
                let name = settings.name.as_deref().unwrap_or(kind.name()).to_owned();
                tools.insert(name.clone(), (kind, settings.clone()));
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
    mut body: Messages,
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
    mut body: Messages,
) -> fictionet::Result<Response<Body>> {
    let engine = model.engine.take().expect("engine checked");
    if history(&mut body, &model.cipher).is_err() {
        return Ok(invalid_history(&model));
    }
    let tools = definitions(&mut body);
    let stream = body.stream == Some(true);
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
        cx.spawn(move |_| async move {
            let result = match run(model, engine, parts, body, tools, response, &mut output).await {
                Ok(Some(refused)) => failed(refused, &mut output).await,
                Ok(None) => Ok(()),
                Err(error) => Err(error),
            };
            if let Err(error) = result {
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
    body: &impl serde::Serialize,
) -> fictionet::Result<Response<Body>> {
    let mut request = Request::new(Body::from(serde_json::to_vec(body)?));
    *request.method_mut() = parts.method.clone();
    *request.uri_mut() = parts.uri.clone();
    *request.headers_mut() = parts.headers.clone();
    *request.extensions_mut() = parts.extensions.clone();
    *request.version_mut() = parts.version;
    request.headers_mut().remove("content-length");
    model.clone().boxed(request).await
}

struct Turn {
    content: Vec<OutputBlock>,
    /// The id the client sees for each server tool block, by its index in `content`.
    /// Upstream ids may repeat, so a client tool can share one with a server tool.
    ids: std::collections::HashMap<usize, String>,
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
        turn.content = serde_json::from_value(message["content"].clone())
            .map_err(|_| Error::msg("Invalid model message"))?;
        turn.usage = message["usage"].clone();
        turn.stop = message["stop_reason"].clone();
        for (index, block) in turn.content.iter().enumerate() {
            output
                .block(visible(block.clone(), index, model, tools, &mut turn.ids))
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
            match EventKind::read(&event) {
                EventKind::MessageStart => {
                    turn.usage = event["message"]["usage"].clone();
                    if output.message.is_null() {
                        output.message = event["message"].clone();
                        output.event(event).await?;
                    }
                    continue;
                }
                EventKind::MessageDelta => {
                    if let Some(usage) = event["usage"].as_object() {
                        for (key, value) in usage {
                            turn.usage[key] = value.clone();
                        }
                    }
                    turn.stop = event["delta"]["stop_reason"].clone();
                    continue;
                }
                EventKind::MessageStop => return Ok(turn),
                EventKind::BlockStart => {
                    if index != turn.content.len() {
                        return Err(Error::msg("Invalid model block index"));
                    }
                    let block: OutputBlock =
                        serde_json::from_value(event["content_block"].clone())?;
                    turn.content.push(block.clone());
                    let shown = visible(block, index, model, tools, &mut turn.ids);
                    event["content_block"] = serde_json::to_value(&shown)?;
                    output.content.push(shown);
                    event["index"] = json!(offset + index);
                }
                EventKind::BlockDelta => {
                    let block = turn
                        .content
                        .get_mut(index)
                        .ok_or_else(|| Error::msg("Invalid model block delta"))?;
                    let delta: Delta = serde_json::from_value(event["delta"].clone())
                        .map_err(|_| Error::msg("Invalid model delta"))?;
                    match delta {
                        Delta::InputJson { partial_json } => {
                            inputs.entry(index).or_default().push_str(&partial_json)
                        }
                        delta => block.apply(delta)?,
                    }
                    event["index"] = json!(offset + index);
                }
                EventKind::BlockStop => {
                    let block = turn
                        .content
                        .get_mut(index)
                        .ok_or_else(|| Error::msg("Invalid model block stop"))?;
                    if let Some(input) = inputs.remove(&index) {
                        block.set_input(
                            serde_json::from_str(&input)
                                .map_err(|_| Error::msg("Invalid model tool input"))?,
                        )?;
                    }
                    let shown = turn
                        .ids
                        .get(&index)
                        .map(|id| block.show_tool(id.clone()))
                        .unwrap_or_else(|| block.clone());
                    output.content[offset + index] = shown;
                    event["index"] = json!(offset + index);
                }
                EventKind::Error => return Err(Error::msg("Model stream reported an error")),
                _ => {}
            }
            output.event(event).await?;
        }
    }
    Err(Error::msg("Model stream ended before message_stop"))
}
fn visible(
    block: OutputBlock,
    index: usize,
    model: &Model,
    tools: &Tools,
    ids: &mut std::collections::HashMap<usize, String>,
) -> OutputBlock {
    if let Some((original, _, _)) = block
        .tool()
        .filter(|(_, name, _)| tools.contains_key(*name))
    {
        let id = format!(
            "srvtoolu_{}",
            model.cipher.encrypt(&model.cx, &json!({"id":original}))
        );
        ids.insert(index, id.clone());
        return block.show_tool(id);
    }
    block
}
async fn run(
    model: Model,
    engine: Arc<dyn Engine>,
    parts: http::request::Parts,
    mut body: Messages,
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
        for (index, block) in turn.content.iter().enumerate() {
            let (Some((original, name, _)), Some(id)) = (block.tool(), turn.ids.get(&index)) else {
                continue;
            };
            let (kind, settings) = &tools[name];
            let count = uses.entry(name.into()).or_default();
            *count += 1;
            let (content, text) = answer(
                &model,
                engine.clone(),
                &body,
                block,
                *kind,
                settings,
                *count,
            )
            .await;
            if *kind == WebTool::Search {
                searches += 1;
            }

            output.block(serde_json::from_value(json!({"type":format!("{}_tool_result", kind.name()),"tool_use_id":id,"content":content}))?).await?;
            results.push(json!({"type":"tool_result","tool_use_id":original,"content":text}));
        }
        let external = turn
            .content
            .iter()
            .enumerate()
            .any(|(index, block)| block.tool().is_some() && !turn.ids.contains_key(&index));
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
        let messages = body.messages.as_mut().ok_or_else(invalid)?;
        messages.push(InputMessage::new(
            Role::Assistant,
            serde_json::from_value(json!(turn.content))?,
        ));
        messages.push(InputMessage::new(
            Role::User,
            serde_json::from_value(json!(results))?,
        ));
        body.tool_choice = None;
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
    body: &Messages,
    block: &OutputBlock,
    kind: WebTool,
    settings: &WebSettings,
    used: u64,
) -> (Value, String) {
    let error = |code: &str| {
        (
            json!({"type":format!("{}_tool_result_error", kind.name()),"error_code":code}),
            json!({"error":code}).to_string(),
        )
    };
    let Some((id, _, input)) = block.tool() else {
        return error("invalid_input");
    };
    if used > settings.max_uses.unwrap_or(8) {
        return error("max_uses_exceeded");
    }
    let domains = settings.domains();
    if kind == WebTool::Search {
        let Some(query) = input["query"].as_str() else {
            return error("invalid_input");
        };
        let Ok(results) = engine
            .search(model.cx.clone(), query.into(), domains.clone())
            .await
        else {
            return error("unavailable");
        };
        let results: Vec<_> = results
            .into_iter()
            .filter(|r| tools::allowed(&domains, &r.url))
            .collect();
        let text = serde_json::to_string(&results).unwrap();
        let mut content: Vec<Value> = results.iter().map(|r| json!({"type":"web_search_result","url":r.url,"title":r.title,"page_age":r.date})).collect();
        let token = model
            .cipher
            .encrypt(&model.cx, &json!({"id":id,"text":text,"visible":content}));
        for entry in &mut content {
            entry["encrypted_content"] = json!(token);
        }
        (json!(content), text)
    } else {
        let Some(url) = input["url"].as_str() else {
            return error("invalid_input");
        };
        if !serde_json::to_string(&body.messages).unwrap().contains(url) {
            return error("url_not_in_prior_context");
        }
        if !tools::allowed(&domains, url)
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
        if let Some(limit) = settings.max_content_tokens {
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
        let content = json!({"type":"web_fetch_result","url":url,"retrieved_at":rfc3339(time::OffsetDateTime::now_utc()),"content":{"type":"document","source":{"type":if pdf {"base64"} else {"text"},"media_type":if pdf {"application/pdf"} else {"text/plain"},"data":text},"title":page.title,"citations":{"enabled":settings.citations.as_ref().is_some_and(|citations| citations["enabled"] == true)}}});
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
            _: tools::Domains,
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
        fictionet::block_on(fictionet::run(fictionet::Seed::from_u64(9), |cx| async move {
            let credential = Credential::api_key(&cx, Secret::new("key", "private".into())?);
            let model = Model::at(&cx, Provider::Anthropic, credential, "http://127.0.0.1:1".parse()?)?;
            let engine: Arc<dyn Engine> = Arc::new(Pages);
            let block = json!({"type":"tool_use","id":"toolu_fetch","name":"web_fetch","input":{"url":"https://example.com/page"}});
            let native: OutputBlock = serde_json::from_value(block.clone())?;
            let body: Messages = serde_json::from_value(json!({"messages":[{"role":"user","content":"Read https://example.com/page"}]}))?;
            let settings: WebSettings = serde_json::from_value(json!({"max_uses":1,"max_content_tokens":1}))?;
            let (content, text) = answer(&model, engine.clone(), &body, &native, WebTool::Fetch, &settings, 1).await;
            assert_eq!(text, "Visi");
            assert_eq!(content["content"]["source"]["data"], "Visi");
            let (error, _) = answer(&model, engine.clone(), &serde_json::from_value(json!({"messages":[]}))?, &native, WebTool::Fetch, &settings, 1).await;
            assert_eq!(error["error_code"], "url_not_in_prior_context");
            let (error, _) = answer(&model, engine.clone(), &body, &native, WebTool::Fetch, &settings, 2).await;
            assert_eq!(error["error_code"], "max_uses_exceeded");
            let (error, _) = answer(&model, engine, &body, &native, WebTool::Fetch, &serde_json::from_value(json!({"blocked_domains":["example.com"]}))?, 1).await;
            assert_eq!(error["error_code"], "url_not_accessible");
            let shown = visible(native.clone(), 0, &model, &std::collections::HashMap::from([("web_fetch".into(), (WebTool::Fetch, settings))]), &mut Default::default());
            let shown = serde_json::to_value(shown)?;
            let mut replay = body.clone();
            replay.messages.as_mut().unwrap().push(serde_json::from_value(json!({"role":"assistant","content":[shown.clone(),{"type":"web_fetch_tool_result","tool_use_id":shown["id"],"content":content},{"type":"text","text":"Done"}]}))?);
            history(&mut replay, &model.cipher)?;
            let replay = serde_json::to_value(replay)?;
            assert_eq!(replay["messages"][1]["content"][0], block);
            assert_eq!(replay["messages"][2]["content"][0]["content"], text);
            assert_eq!(replay["messages"][3]["content"][0]["text"], "Done");
            Ok(())
        })).unwrap();
    }
}
