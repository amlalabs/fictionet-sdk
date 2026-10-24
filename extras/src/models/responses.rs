//! OpenAI's hosted web search tool, answered by the world.
//!
//! The hosted `web_search` tool becomes three functions upstream, one per
//! action the real tool takes: `search`, `open_page` and `find_in_page`.
//! The model's calls to them are answered from the world's own search and
//! pages, shown to the client as `web_search_call` items, and the model's
//! continuation is relayed as the rest of the same response.

use super::*;
use fictionet::stdlib::codec::{Stream, try_pump};
use fictionet::stdlib::protocols::sse;
use http_body::Frame;
use response::{Block as OutputBlock, EventKind};
use std::collections::HashMap;
use tokio::sync::mpsc;

/// Page text handed to the model is cut at this many characters.
const PAGE_CHARS: usize = 20_000;
/// At most this many matching lines answer one `find_in_page`.
const MATCHES: usize = 20;

use request::{Block, Content, Responses, Tool, TypedBlock};
fn hosted(value: &Value) -> bool {
    serde_json::from_value::<Tool>(value.clone())
        .ok()
        .is_some_and(|tool| tool.web().is_some())
}

/// The functions sent upstream in place of the hosted tool. They never
/// change between turns, so a provider's prompt cache keeps working.
fn functions() -> [Tool; 3] {
    let function = |name: &str, description: &str, properties: Value| {
        let required: Vec<_> = properties.as_object().unwrap().keys().cloned().collect();
        serde_json::from_value(json!({"type":"function","name":name,"description":description,"strict":true,
            "parameters":{"type":"object","properties":properties,"required":required,"additionalProperties":false}})).expect("local function definition")
    };
    [
        function(
            "web_search",
            "Search the web.",
            json!({"query":{"type":"string"}}),
        ),
        function(
            "open_page",
            "Open a web page and read its text.",
            json!({"url":{"type":"string"}}),
        ),
        function(
            "find_in_page",
            "Find the lines of a web page that contain a pattern.",
            json!({"url":{"type":"string"},"pattern":{"type":"string"}}),
        ),
    ]
}
#[derive(Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum WorldFunction {
    WebSearch,
    OpenPage,
    FindInPage,
}
fn world_function(item: &OutputBlock) -> Option<WorldFunction> {
    let (name, _, _) = item.function()?;
    serde_json::from_value(json!(name)).ok()
}
fn is_world(item: &OutputBlock) -> bool {
    world_function(item).is_some()
}
/// Turns the client's `web_search_call` items back into the function call
/// and output the model saw. The world's encrypted token carries both.
fn history(body: &mut Responses, cipher: &splice::TokenCipher) -> fictionet::Result<()> {
    let Some(input) = body.input.take() else {
        return Ok(());
    };
    let mut restored = Vec::new();
    for item in input.into_input() {
        let Content::Block(block) = item else {
            restored.push(item);
            continue;
        };
        match *block {
            Block::Typed(TypedBlock::WebSearchCall {
                id,
                encrypted_content,
                ..
            }) => {
                let value = cipher.open(
                    &encrypted_content.ok_or_else(|| Error::msg("Invalid search history"))?,
                )?;
                if value["id"] != id {
                    return Err(Error::msg("Invalid search history"));
                }
                restored.push(serde_json::from_value(value["call"].clone())?);
                restored.push(serde_json::from_value(value["result"].clone())?);
            }
            block => restored.push(Content::Block(Box::new(block))),
        }
    }
    body.input = Some(Content::Blocks(restored));
    Ok(())
}

struct Output {
    tx: Option<mpsc::Sender<fictionet::Result<Frame<Bytes>>>>,
    sequence: u64,
    response: Value,
    items: Vec<OutputBlock>,
    tools: Value,
    tool_choice: Value,
}
impl Output {
    async fn emit(&mut self, mut event: Value) -> fictionet::Result<()> {
        event["sequence_number"] = json!(self.sequence);
        self.sequence += 1;
        if let Some(tx) = &self.tx {
            let kind = event["type"].as_str().unwrap_or("message");
            tx.send(Ok(Frame::data(Bytes::from(format!(
                "event: {kind}\ndata: {event}\n\n"
            )))))
            .await
            .map_err(|_| Error::msg("Model response reader closed"))?;
        }
        Ok(())
    }
    /// The response as the client sent it: its own tools, not the functions.
    fn shown(&self, mut response: Value) -> Value {
        if response.get("tools").is_some() {
            response["tools"] = self.tools.clone();
        }
        if response.get("tool_choice").is_some() {
            response["tool_choice"] = self.tool_choice.clone();
        }
        response
    }
}
struct Turn {
    response: Value,
    /// World calls by their index in this turn's output, with the visible id.
    calls: HashMap<usize, String>,
}

pub(super) async fn serve(
    mut model: Model,
    parts: http::request::Parts,
    mut body: Responses,
) -> fictionet::Result<Response<Body>> {
    let engine = model.engine.take().expect("engine checked");
    if history(&mut body, &model.cipher).is_err() {
        return Ok(model
            .provider
            .error(400, "invalid_request_error", "Invalid search history"));
    }
    let mut output = Output {
        tx: None,
        sequence: 0,
        response: Value::Null,
        items: Vec::new(),
        tools: serde_json::to_value(&body.tools)?,
        tool_choice: body.tool_choice.clone().unwrap_or(Value::Null),
    };
    let mut settings = request::WebSettings::default();
    if let Some(tools) = &mut body.tools {
        let mut rewritten = Vec::new();
        for tool in std::mem::take(tools) {
            if let Some((_, web)) = tool.web() {
                settings = web.clone();
                rewritten.extend(functions());
            } else {
                rewritten.push(tool);
            }
        }
        *tools = rewritten;
    }
    if body.tool_choice.as_ref().is_some_and(hosted) {
        body.tool_choice = Some(json!({"type":"function","name":"web_search"}));
    }
    let stream = body.stream == Some(true);
    let response = splice::upstream(&model, &parts, &body).await?;
    if !response.status().is_success() {
        return Ok(response);
    }
    if stream {
        let (tx, rx) = mpsc::channel(8);
        output.tx = Some(tx.clone());
        let cx = model.cx.clone();
        cx.spawn(move |_| async move {
            let result = run(model, engine, parts, body, settings, response, &mut output).await;
            let result = match result {
                Ok(None) => Ok(()),
                Ok(Some(refused)) => failed(refused, &mut output).await,
                Err(error) => Err(error),
            };
            if let Err(error) = result {
                let _ = tx.send(Err(error)).await;
            }
            Ok(())
        });
        Ok(Response::builder()
            .header("content-type", "text/event-stream")
            .body(Body::new(splice::Channel(rx)))?)
    } else {
        if let Some(refused) =
            run(model, engine, parts, body, settings, response, &mut output).await?
        {
            return Ok(refused);
        }
        Ok(Response::builder()
            .header("content-type", "application/json")
            .body(Body::from(output.response.to_string()))?)
    }
}

/// Ends a stream whose continuation was refused, such as by a budget stop,
/// with the provider's `response.failed` carrying the refusal's error.
async fn failed(refused: Response<Body>, output: &mut Output) -> fictionet::Result<()> {
    let bytes = http_body_util::Limited::new(refused.into_body(), 64 * 1024)
        .collect()
        .await
        .map(|body| body.to_bytes())
        .unwrap_or_default();
    let error = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .map(|body| body["error"].clone())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({"code":"server_error","message":"The server had an error while processing your request."}));
    let mut response = output.response.clone();
    response["status"] = json!("failed");
    response["error"] = error;
    response["output"] = json!(output.items);
    output
        .emit(json!({"type":"response.failed","response":response}))
        .await
}

fn started(model: &Model) -> Value {
    let mut bytes = [0; 25];
    model.cx.fill_random(&mut bytes);
    let id: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    json!({"type":"web_search_call","id":format!("ws_{id}"),"status":"in_progress"})
}

async fn read(
    response: Response<Body>,
    model: &Model,
    output: &mut Output,
) -> fictionet::Result<Turn> {
    let stream = response
        .headers()
        .get("content-type")
        .is_some_and(|v| v.as_bytes().starts_with(b"text/event-stream"));
    let offset = output.items.len();
    let first = output.response.is_null();
    let mut calls = HashMap::new();
    if !stream {
        let bytes = response.into_body().collect().await?.to_bytes();
        let response: Value = serde_json::from_slice(&bytes)?;
        if first {
            output.response = output.shown(response.clone());
        }
        let items: Vec<OutputBlock> = serde_json::from_value(response["output"].clone())
            .map_err(|_| Error::msg("Invalid response output"))?;
        for (index, item) in items.iter().enumerate() {
            if is_world(item) {
                let visible = started(model);
                calls.insert(index, visible["id"].as_str().unwrap().to_owned());
                output.items.push(serde_json::from_value(visible)?);
            } else {
                output.items.push(item.clone());
            }
        }
        return Ok(Turn { response, calls });
    }
    let mut body = response.into_body();
    let mut decoder = Stream::new(sse::Events::new());
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
        .map_err(|_| Error::msg("Invalid response stream"))?;
        for event in events {
            if event.data.trim() == "[DONE]" {
                continue;
            }
            let mut event: Value = serde_json::from_str(&event.data)
                .map_err(|_| Error::msg("Invalid response event"))?;
            let index = event["output_index"].as_u64().unwrap_or(0) as usize;
            if event.get("output_index").is_some() {
                event["output_index"] = json!(offset + index);
            }
            match EventKind::read(&event) {
                // The client sees one response: the first turn's start events.
                EventKind::ResponseCreated | EventKind::ResponseInProgress => {
                    if !first {
                        continue;
                    }
                    output.response = output.shown(event["response"].clone());
                    event["response"] = output.response.clone();
                }
                EventKind::ResponseCompleted
                | EventKind::ResponseIncomplete
                | EventKind::ResponseFailed => {
                    return Ok(Turn {
                        response: event["response"].clone(),
                        calls,
                    });
                }
                EventKind::ItemAdded => {
                    if offset + index != output.items.len() {
                        return Err(Error::msg("Invalid response item index"));
                    }
                    if is_world(&serde_json::from_value(event["item"].clone())?) {
                        let visible = started(model);
                        let id = visible["id"].as_str().unwrap().to_owned();
                        event["item"] = visible;
                        output
                            .items
                            .push(serde_json::from_value(event["item"].clone())?);
                        output.emit(event).await?;
                        output
                            .emit(json!({"type":"response.web_search_call.in_progress","item_id":id,"output_index":offset+index}))
                            .await?;
                        calls.insert(index, id);
                        continue;
                    }
                    output
                        .items
                        .push(serde_json::from_value(event["item"].clone())?);
                }
                EventKind::ArgumentsDelta | EventKind::ArgumentsDone
                    if calls.contains_key(&index) =>
                {
                    continue;
                }
                EventKind::ItemDone => {
                    if let Some(id) = calls.get(&index) {
                        output
                            .emit(json!({"type":"response.web_search_call.searching","item_id":id,"output_index":offset+index}))
                            .await?;
                        continue;
                    }
                    let item = output
                        .items
                        .get_mut(offset + index)
                        .ok_or_else(|| Error::msg("Invalid response item"))?;
                    *item = serde_json::from_value(event["item"].clone())?;
                }
                EventKind::Error => {
                    output.emit(event).await?;
                    return Err(Error::msg("Model response reported an error"));
                }
                _ => {}
            }
            output.emit(event).await?;
        }
    }
    Err(Error::msg("Model stream ended before response completion"))
}

/// Answers one world function call: the action shown to the client, the
/// output the model reads, and the number of results for the log.
async fn answer(
    model: &Model,
    engine: &Arc<dyn Engine>,
    settings: &request::WebSettings,
    include_sources: bool,
    call: &OutputBlock,
) -> (Value, String, u64) {
    let arguments = call
        .function()
        .map(|(_, arguments, _)| arguments)
        .and_then(|arguments| arguments.as_str())
        .and_then(|arguments| serde_json::from_str::<Value>(arguments).ok())
        .unwrap_or(Value::Null);
    let error = |action: Value, code: &str| (action, json!({"error":code}).to_string(), 0);
    let domains = settings.filters.clone().unwrap_or_default();
    let Some(function) = world_function(call) else {
        return error(json!({}), "invalid_input");
    };
    match function {
        WorldFunction::WebSearch => {
            #[derive(serde::Deserialize)]
            struct Search {
                query: String,
            }
            let Ok(Search { query }) = serde_json::from_value(arguments) else {
                return error(json!({"type":"search"}), "invalid_input");
            };
            let mut action = json!({"type":"search","query":query,"queries":[query]});
            let Ok(found) = engine
                .clone()
                .search(model.cx.clone(), query.clone(), domains.clone())
                .await
            else {
                return error(action, "unavailable");
            };
            let found: Vec<_> = found
                .into_iter()
                .filter(|r| tools::allowed(&domains, &r.url))
                .collect();
            if include_sources {
                action["sources"] = json!(
                    found
                        .iter()
                        .map(|r| json!({"type":"url","url":r.url}))
                        .collect::<Vec<_>>()
                );
            }
            let count = found.len() as u64;
            (action, serde_json::to_string(&found).unwrap(), count)
        }
        WorldFunction::OpenPage | WorldFunction::FindInPage => {
            #[derive(serde::Deserialize)]
            struct Page {
                url: String,
                #[serde(default)]
                pattern: String,
            }
            let Ok(Page { url, pattern }) = serde_json::from_value(arguments) else {
                return error(json!({}), "invalid_input");
            };
            let action = if function == WorldFunction::OpenPage {
                json!({"type":"open_page","url":url})
            } else {
                json!({"type":"find_in_page","url":url,"pattern":pattern})
            };
            if !tools::allowed(&domains, &url)
                || !tools::host(&url).is_some_and(|host| engine.serves(&host))
            {
                return error(action, "url_not_accessible");
            }
            let Ok(page) = engine.clone().fetch(model.cx.clone(), url.clone()).await else {
                return error(action, "url_not_accessible");
            };
            let Some(body) = tools::text(&page) else {
                return error(action, "unsupported_content_type");
            };
            if function == WorldFunction::OpenPage {
                let body: String = body.chars().take(PAGE_CHARS).collect();
                let output = json!({"url":url,"title":page.title,"text":body});
                return (action, output.to_string(), 1);
            }
            let needle = pattern.to_lowercase();
            let matches: Vec<_> = body
                .lines()
                .map(str::trim)
                .filter(|line| !needle.is_empty() && line.to_lowercase().contains(&needle))
                .take(MATCHES)
                .collect();
            let count = matches.len() as u64;
            let output = json!({"url":url,"title":page.title,"pattern":pattern,"matches":matches});
            (action, output.to_string(), count)
        }
    }
}

/// Relays model turns, answering world calls, until a turn needs the client.
/// Returns a refused continuation, such as a budget stop, for the caller to show.
async fn run(
    model: Model,
    engine: Arc<dyn Engine>,
    parts: http::request::Parts,
    mut body: Responses,
    settings: request::WebSettings,
    mut response: Response<Body>,
    output: &mut Output,
) -> fictionet::Result<Option<Response<Body>>> {
    let limit = body.max_tool_calls.unwrap_or(8);
    let include_sources = body
        .include
        .as_ref()
        .is_some_and(|fields| fields.iter().any(|f| f == "web_search_call.action.sources"));
    let mut used = 0;
    let mut tokens = 0;
    for _ in 0..16 {
        let offset = output.items.len();
        let turn = read(response, &model, output).await?;
        tokens += turn.response["usage"]["output_tokens"]
            .as_u64()
            .unwrap_or(0);
        let original: Vec<OutputBlock> = serde_json::from_value(turn.response["output"].clone())
            .map_err(|_| Error::msg("Invalid response output"))?;
        let mut results = Vec::new();
        for (index, call) in original.iter().enumerate() {
            let Some(id) = turn.calls.get(&index) else {
                continue;
            };
            used += 1;
            let (action, text, _count) = if used > limit {
                (
                    json!({"type":"search"}),
                    json!({"error":"max_tool_calls"}).to_string(),
                    0,
                )
            } else {
                answer(&model, &engine, &settings, include_sources, call).await
            };
            let result = json!({"type":"function_call_output","call_id":call.function().and_then(|(_, _, id)| id),"output":text});
            let token = model
                .cipher
                .encrypt(&model.cx, &json!({"id":id,"call":call,"result":result}));
            let item = json!({"type":"web_search_call","id":id,"status":"completed","action":action,"encrypted_content":token});
            output.items[offset + index] = serde_json::from_value(item.clone())?;

            output
                .emit(json!({"type":"response.web_search_call.completed","item_id":id,"output_index":offset+index}))
                .await?;
            output
                .emit(json!({"type":"response.output_item.done","item":item,"output_index":offset+index}))
                .await?;
            results.push(result);
        }
        let external = original
            .iter()
            .any(|item| item.external_function() && !is_world(item));
        if results.is_empty() || external || turn.response["status"] != "completed" {
            let mut usage = turn.response["usage"].clone();
            if !usage.is_object() {
                usage = json!({});
            }
            usage["output_tokens"] = json!(tokens);
            usage["total_tokens"] = json!(tokens + usage["input_tokens"].as_u64().unwrap_or(0));
            for field in ["status", "error", "incomplete_details", "completed_at"] {
                if let Some(value) = turn.response.get(field) {
                    output.response[field] = value.clone();
                }
            }
            output.response["usage"] = usage;
            output.response["output"] = json!(output.items);
            if let (Some(shown), Some(last)) =
                (output.response["id"].as_str(), turn.response["id"].as_str())
                && shown != last
            {
                model
                    .continued
                    .lock()
                    .unwrap()
                    .insert(shown.to_owned(), last.to_owned());
            }
            let kind = match output.response["status"].as_str() {
                Some("incomplete") => "response.incomplete",
                Some("failed") => "response.failed",
                _ => "response.completed",
            };
            let response = output.response.clone();
            output
                .emit(json!({"type":kind,"response":response}))
                .await?;
            return Ok(None);
        }
        let mut input = body.input.take().unwrap_or(Content::Empty(())).into_input();
        for item in original {
            input.push(item.into_content()?);
        }
        for result in results {
            input.push(serde_json::from_value(result)?);
        }
        body.input = Some(Content::Blocks(input));
        body.tool_choice = Some(json!("auto"));
        response = splice::upstream(&model, &parts, &body).await?;
        if !response.status().is_success() {
            return Ok(Some(response));
        }
    }
    Err(Error::msg("Server tool turn limit reached"))
}
