use super::splice_tests::{Pages, receive};
use super::*;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) fn answer(socket: &mut std::net::TcpStream, items: Vec<Value>, stream: bool) {
    echo(socket, items, stream, &json!({}));
}
/// Answers like `answer`, echoing the request's tools as providers do.
pub(super) fn echo(
    socket: &mut std::net::TcpStream,
    items: Vec<Value>,
    stream: bool,
    request: &Value,
) {
    let mut response = json!({"id":"resp_one","object":"response","created_at":1,"model":"small","status":"completed","output":items,"usage":{"input_tokens":7,"output_tokens":2,"total_tokens":9},"error":null,"incomplete_details":null});
    if let Some(tools) = request.get("tools") {
        response["tools"] = tools.clone();
    }
    let (typ, body) = if stream {
        let mut initial = response.clone();
        initial["output"] = json!([]);
        initial["status"] = json!("in_progress");
        let mut events = vec![json!({"type":"response.created","response":initial})];
        for (index, item) in items.iter().enumerate() {
            let mut first = item.clone();
            if item["type"] == "function_call" {
                first["arguments"] = json!("");
            }
            events.push(
                json!({"type":"response.output_item.added","output_index":index,"item":first}),
            );
            if item["type"] == "function_call" {
                events.push(json!({"type":"response.function_call_arguments.delta","output_index":index,"item_id":item["id"],"delta":item["arguments"]}));
                events.push(json!({"type":"response.function_call_arguments.done","output_index":index,"item_id":item["id"],"arguments":item["arguments"]}));
            }
            events
                .push(json!({"type":"response.output_item.done","output_index":index,"item":item}));
        }
        events.push(json!({"type":"response.completed","response":response}));
        (
            "text/event-stream",
            events
                .into_iter()
                .enumerate()
                .map(|(index, mut e)| {
                    e["sequence_number"] = json!(index);
                    format!("event: {}\ndata: {e}\n\n", e["type"].as_str().unwrap())
                })
                .collect::<String>()
                + "data: [DONE]\n\n",
        )
    } else {
        ("application/json", response.to_string())
    };
    write!(
        socket,
        "HTTP/1.1 200 OK\r\nContent-Type: {typ}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    for chunk in body.as_bytes().chunks(11) {
        socket.write_all(chunk).unwrap();
    }
}
async fn collect(response: Response<Body>, stream: bool) -> Value {
    assert_eq!(response.status(), 200);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    if !stream {
        return serde_json::from_slice(&bytes).unwrap();
    }
    let mut decoder =
        fictionet::stdlib::codec::Stream::new(fictionet::stdlib::protocols::sse::Events::new());
    let mut count = 0;
    let mut starts = 0;
    let mut stops = 0;
    let mut completed = Value::Null;
    let mut indexes = Vec::new();
    fictionet::stdlib::codec::try_pump(&mut decoder, &bytes, |event| {
        let event: Value = serde_json::from_str(&event.data).unwrap();
        assert_eq!(event["sequence_number"], count);
        count += 1;
        if event["type"] == "response.created" {
            starts += 1;
        }
        if event["type"] == "response.completed" {
            stops += 1;
            completed = event["response"].clone();
        }
        if event["type"] == "response.output_item.added" {
            indexes.push(event["output_index"].as_u64().unwrap());
        }
        assert_ne!(event["type"], "response.function_call_arguments.delta");
        Ok::<_, fictionet::stdlib::protocols::sse::Error>(())
    })
    .unwrap();
    assert_eq!(starts, 1);
    assert_eq!(stops, 1);
    assert_eq!(indexes, (0..indexes.len() as u64).collect::<Vec<_>>());
    completed
}
#[test]
fn responses_search_preserves_reasoning_and_restores_function_pairs() {
    for stream in [false, true] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let first = receive(&mut socket);
            assert_eq!(first["tools"][0]["type"], "function");
            assert_eq!(
                first["tool_choice"],
                json!({"type":"function","name":"web_search"})
            );
            let reasoning = json!({"type":"reasoning","id":"rs_first","encrypted_content":"preserved","summary":[]});
            let call = json!({"type":"function_call","id":"fc_first","call_id":"call_first","name":"web_search","arguments":"{\"query\":\"page\"}","status":"completed"});
            answer(&mut socket, vec![reasoning.clone(), call.clone()], stream);
            let (mut socket, _) = listener.accept().unwrap();
            let second = receive(&mut socket);
            assert_eq!(second["tools"], first["tools"]);
            assert_eq!(second["input"][1], reasoning);
            assert_eq!(second["input"][2], call);
            assert_eq!(second["input"][3]["type"], "function_call_output");
            assert!(
                second["input"][3]["output"]
                    .as_str()
                    .unwrap()
                    .contains("Page title")
            );
            let text = json!({"type":"message","id":"msg_final","role":"assistant","status":"completed","content":[{"type":"output_text","text":"Page title","annotations":[]}]});
            answer(&mut socket, vec![text.clone()], stream);
            let (mut socket, _) = listener.accept().unwrap();
            let third = receive(&mut socket);
            assert_eq!(
                &third["input"].as_array().unwrap()[..4],
                second["input"].as_array().unwrap()
            );
            assert_eq!(third["input"][4], text);
            answer(&mut socket, vec![text], stream);
        });
        let pages = Arc::new(Pages(AtomicUsize::new(0)));
        let engine = pages.clone();
        fictionet::block_on(fictionet::run(fictionet::RunOptions::new(fictionet::Seed::from_u64(10)), |cx| async move {
            let credential = Credential::api_key(&cx, Secret::new("key", "private".into())?);
            let key = credential.wire(Provider::OpenAi, false);
            let model = Model::at(&cx, Provider::OpenAi, credential, format!("http://{address}").parse()?)?.search(engine);
            let request = |body: &Value| Request::post("/v1/responses").header("authorization", &key).body(Body::from(body.to_string())).unwrap();
            let mut body = json!({"model":"small","stream":stream,"store":false,"input":[{"role":"user","content":"Search"}],"tools":[{"type":"web_search","filters":{"allowed_domains":["example.com"]}}],"tool_choice":{"type":"web_search"},"include":["reasoning.encrypted_content","web_search_call.action.sources"]});
            let response = collect(model.clone().send(request(&body)).await?, stream).await;
            assert_eq!(response["usage"]["output_tokens"], 4);
            assert_eq!(response["output"][0]["encrypted_content"], "preserved");
            assert_eq!(response["output"][1]["type"], "web_search_call");
            assert_eq!(response["output"][1]["action"]["sources"][0]["url"], "https://example.com/page");
            body["input"].as_array_mut().unwrap().extend(response["output"].as_array().unwrap().iter().cloned());
            body["input"].as_array_mut().unwrap().push(json!({"role":"user","content":"Continue"}));
            let mut invalid = body.clone();
            invalid["input"][2]["encrypted_content"] = json!("invalid");
            assert_eq!(model.clone().send(request(&invalid)).await?.status(), 400);
            collect(model.clone().send(request(&body)).await?, stream).await;
            Ok(())
        })).unwrap();
        server.join().unwrap();
        assert_eq!(pages.0.load(Ordering::SeqCst), 1);
    }
}
#[test]
fn zstd_requests_are_decoded_and_metered() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let body = receive(&mut socket);
        assert_eq!(body["input"], "hello");
        answer(&mut socket, vec![], true);
    });
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(11)),
        |cx| async move {
            let credential = Credential::api_key(&cx, Secret::new("key", "private".into())?);
            let key = credential.wire(Provider::OpenAi, false);
            let model = Model::at(
                &cx,
                Provider::OpenAi,
                credential,
                format!("http://{address}").parse()?,
            )?
            .budget(Budget::new().calls(1));
            let bytes = zstd::encode_all(
                br#"{"model":"small","stream":true,"input":"hello"}"#.as_slice(),
                1,
            )?;
            let request = Request::post("/v1/responses")
                .header("authorization", &key)
                .header("content-encoding", "zstd")
                .header("content-length", bytes.len())
                .body(Body::from(bytes))?;
            let response = model.clone().send(request).await?;
            assert_eq!(response.status(), 200);
            response.into_body().collect().await?;
            assert_eq!(model.ledger.lock().unwrap().calls, 1);
            assert_eq!(model.ledger.lock().unwrap().output, 2);
            Ok(())
        },
    ))
    .unwrap();
    server.join().unwrap();
}
/// Every SSE event of a streamed response, in order.
async fn events(response: Response<Body>) -> Vec<Value> {
    assert_eq!(response.status(), 200);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let mut decoder =
        fictionet::stdlib::codec::Stream::new(fictionet::stdlib::protocols::sse::Events::new());
    let mut events = Vec::new();
    fictionet::stdlib::codec::try_pump(&mut decoder, &bytes, |event| {
        events.push(serde_json::from_str(&event.data).unwrap());
        Ok::<_, fictionet::stdlib::protocols::sse::Error>(())
    })
    .unwrap();
    events
}
#[test]
fn page_actions_read_world_pages_and_keep_the_client_tools() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let first = receive(&mut socket);
        let names: Vec<_> = first["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap_or(t["type"].as_str().unwrap()))
            .collect();
        assert_eq!(
            names,
            [
                "exec_command",
                "web_search",
                "open_page",
                "find_in_page",
                "agents"
            ]
        );
        let call = |id: &str, name: &str, arguments: Value| json!({"type":"function_call","id":format!("fc_{id}"),"call_id":format!("call_{id}"),"name":name,"arguments":arguments.to_string(),"status":"completed"});
        echo(
            &mut socket,
            vec![
                call(
                    "open",
                    "open_page",
                    json!({"url":"https://example.com/page"}),
                ),
                call(
                    "find",
                    "find_in_page",
                    json!({"url":"https://example.com/page","pattern":"PAGE TEXT"}),
                ),
                call("away", "open_page", json!({"url":"https://other.org/page"})),
            ],
            true,
            &first,
        );
        let (mut socket, _) = listener.accept().unwrap();
        let second = receive(&mut socket);
        let outputs: Vec<Value> = second["input"].as_array().unwrap()[4..]
            .iter()
            .map(|item| {
                assert_eq!(item["type"], "function_call_output");
                serde_json::from_str(item["output"].as_str().unwrap()).unwrap()
            })
            .collect();
        assert_eq!(
            outputs[0],
            json!({"url":"https://example.com/page","title":"Page title","text":"Page title\nThe page text"})
        );
        assert_eq!(outputs[1]["matches"], json!(["The page text"]));
        assert_eq!(outputs[2], json!({"error":"url_not_accessible"}));
        let text = json!({"type":"message","id":"msg_final","role":"assistant","status":"completed","content":[{"type":"output_text","text":"Read it","annotations":[]}]});
        answer(&mut socket, vec![text], true);
    });
    let memory = Arc::new(fictionet_observe::Memory::default());
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(12))
            .observer(Arc::new(fictionet_observe::Aggregate::new(memory.clone()))),
        |cx| async move {
            let credential = Credential::api_key(&cx, Secret::new("key", "private".into())?);
            let key = credential.wire(Provider::OpenAi, false);
            let model = Model::at(
                &cx,
                Provider::OpenAi,
                credential,
                format!("http://{address}").parse()?,
            )?
            .search(Arc::new(Pages(AtomicUsize::new(0))));
            let namespace = json!({"type":"namespace","name":"agents","tools":[{"type":"function","name":"spawn","parameters":{}}]});
            let tools = json!([{"type":"function","name":"exec_command","parameters":{}},{"type":"web_search","external_web_access":true},namespace]);
            let body = json!({"model":"small","stream":true,"input":[{"role":"user","content":"Read"}],"tools":tools,"tool_choice":"auto"});
            let request = Request::post("/v1/responses")
                .header("authorization", &key)
                .body(Body::from(body.to_string()))?;
            let events = events(model.clone().send(request).await?).await;
            assert_eq!(events[0]["type"], "response.created");
            let completed = events.last().unwrap();
            assert_eq!(completed["type"], "response.completed");
            assert_eq!(completed["response"]["tools"], tools);
            let actions: Vec<_> = completed["response"]["output"].as_array().unwrap()[..3]
                .iter()
                .map(|item| {
                    assert_eq!(item["type"], "web_search_call");
                    item["action"].clone()
                })
                .collect();
            assert_eq!(
                actions,
                [
                    json!({"type":"open_page","url":"https://example.com/page"}),
                    json!({"type":"find_in_page","url":"https://example.com/page","pattern":"PAGE TEXT"}),
                    json!({"type":"open_page","url":"https://other.org/page"}),
                ]
            );
            let kinds: Vec<_> = events
                .iter()
                .filter(|e| e["output_index"] == 0)
                .map(|e| e["type"].as_str().unwrap().to_owned())
                .collect();
            assert_eq!(
                kinds,
                [
                    "response.output_item.added",
                    "response.web_search_call.in_progress",
                    "response.web_search_call.searching",
                    "response.web_search_call.completed",
                    "response.output_item.done",
                ]
            );
            Ok(())
        },
    ))
    .unwrap();
    server.join().unwrap();
    let tools = memory.checked_of("model", "tool").unwrap();
    let logged: Vec<_> = tools
        .iter()
        .map(|e| (e.str("tool").unwrap(), e.u64("results").unwrap()))
        .collect();
    assert_eq!(
        logged,
        [("open_page", 1), ("find_in_page", 1), ("open_page", 0)]
    );
}
#[test]
fn a_budget_stop_during_a_search_fails_the_response_like_openai() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().unwrap();
            let body = receive(&mut socket);
            let stream = body["stream"] == true;
            let call = json!({"type":"function_call","id":"fc_one","call_id":"call_one","name":"web_search","arguments":"{\"query\":\"page\"}","status":"completed"});
            answer(&mut socket, vec![call], stream);
        }
    });
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(13)),
        |cx| async move {
            let credential = Credential::api_key(&cx, Secret::new("key", "private".into())?);
            let key = credential.wire(Provider::OpenAi, false);
            let model = Model::at(
                &cx,
                Provider::OpenAi,
                credential,
                format!("http://{address}").parse()?,
            )?
            .search(Arc::new(Pages(AtomicUsize::new(0))))
            .budget(Budget::new().calls(1));
            let request = |stream: bool| {
                let body = json!({"model":"small","stream":stream,"input":"Search","tools":[{"type":"web_search"}]});
                Request::post("/v1/responses")
                    .header("authorization", &key)
                    .body(Body::from(body.to_string()))
                    .unwrap()
            };
            let events = events(model.clone().send(request(true)).await?).await;
            let last = events.last().unwrap();
            assert_eq!(last["type"], "response.failed");
            assert_eq!(last["response"]["status"], "failed");
            assert_eq!(last["response"]["error"]["code"], "insufficient_quota");
            assert_eq!(last["response"]["output"][0]["type"], "web_search_call");
            assert!(!events.iter().any(|e| e["type"] == "response.completed"));
            model.set_budget(Budget::new().calls(2));
            let response = model.clone().send(request(false)).await?;
            assert_eq!(response.status(), 429);
            let body: Value =
                serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
            assert_eq!(body["error"]["type"], "insufficient_quota");
            assert!(
                body["error"]["message"]
                    .as_str()
                    .unwrap()
                    .starts_with("You exceeded your current quota")
            );
            Ok(())
        },
    ))
    .unwrap();
    server.join().unwrap();
}
