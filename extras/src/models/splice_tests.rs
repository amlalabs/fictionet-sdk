use super::*;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
pub(super) struct Pages(pub(super) AtomicUsize);
impl Engine for Pages {
    fn search(
        self: Arc<Self>,
        _: Cx,
        _: String,
        _: &'static str,
        _: Value,
    ) -> tools::Answer<Vec<crate::search::Result>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Ok(vec![crate::search::Result {
                url: "https://example.com/page".into(),
                title: "Page title".into(),
                snippet: "The page text".into(),
                date: "2026-10-20".into(),
            }])
        })
    }
    fn fetch(self: Arc<Self>, _: Cx, _: String) -> tools::Answer<tools::Page> {
        Box::pin(async {
            Ok(tools::Page {
                title: "Page title".into(),
                media_type: "text/html".into(),
                body: b"<h1>Page title</h1><p>The page text</p><script>hidden()</script>".to_vec(),
            })
        })
    }
    fn serves(&self, host: &str) -> bool {
        host == "example.com"
    }
}
pub(super) fn receive(socket: &mut std::net::TcpStream) -> Value {
    exchange(socket).1
}
/// The request head and JSON body.
pub(super) fn exchange(socket: &mut std::net::TcpStream) -> (String, Value) {
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        headers.push(byte[0]);
    }
    let headers = String::from_utf8(headers).unwrap();
    let size: usize = headers
        .lines()
        .find_map(|l| l.strip_prefix("content-length: "))
        .unwrap()
        .parse()
        .unwrap();
    let mut body = vec![0; size];
    socket.read_exact(&mut body).unwrap();
    (headers, serde_json::from_slice(&body).unwrap())
}
fn response(socket: &mut std::net::TcpStream, content: Vec<Value>, stop: &str, stream: bool) {
    let mut message = json!({"type":"message","id":"msg_abc","role":"assistant","model":"claude","content":[],"usage":{"input_tokens":7,"output_tokens":2},"stop_reason":null,"stop_sequence":null});
    let (typ, body) = if stream {
        let mut events = vec![json!({"type":"message_start","message":message})];
        for (index, mut block) in content.into_iter().enumerate() {
            let input = if block["type"] == "tool_use" {
                let input = block["input"].take().to_string();
                block["input"] = json!({});
                Some(input)
            } else {
                None
            };
            events.push(json!({"type":"content_block_start","index":index,"content_block":block}));
            if let Some(input) = input {
                events.push(json!({"type":"content_block_delta","index":index,"delta":{"type":"input_json_delta","partial_json":input}}));
            }
            events.push(json!({"type":"content_block_stop","index":index}));
        }
        events.push(json!({"type":"message_delta","delta":{"stop_reason":stop},"usage":{"output_tokens":2}}));
        events.push(json!({"type":"message_stop"}));
        (
            "text/event-stream",
            events
                .into_iter()
                .map(|v| format!("event: {}\ndata: {v}\n\n", v["type"].as_str().unwrap()))
                .collect::<String>()
                + "data: [DONE]\n\n",
        )
    } else {
        message["content"] = json!(content);
        message["stop_reason"] = json!(stop);
        ("application/json", message.to_string())
    };
    write!(
        socket,
        "HTTP/1.1 200 OK\r\nContent-Type: {typ}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    for chunk in body.as_bytes().chunks(7) {
        socket.write_all(chunk).unwrap();
    }
}
async fn collected(response: Response<Body>, stream: bool) -> Value {
    assert_eq!(response.status(), 200);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    if !stream {
        return serde_json::from_slice(&bytes).unwrap();
    }
    let mut decoder =
        fictionet::stdlib::codec::Stream::new(fictionet::stdlib::protocols::sse::Events::new());
    let mut message = Value::Null;
    let mut content = Vec::new();
    let mut starts = 0;
    let mut stops = 0;
    fictionet::stdlib::codec::try_pump(&mut decoder, &bytes, |event| {
        let event: Value = serde_json::from_str(&event.data).unwrap();
        match event["type"].as_str().unwrap() {
            "message_start" => {
                starts += 1;
                message = event["message"].clone();
            }
            "content_block_start" => {
                assert_eq!(event["index"], content.len());
                content.push(event["content_block"].clone());
            }
            "content_block_delta" => {
                let index = event["index"].as_u64().unwrap() as usize;
                content[index]["input"] =
                    serde_json::from_str(event["delta"]["partial_json"].as_str().unwrap()).unwrap();
            }
            "message_delta" => {
                message["usage"] = event["usage"].clone();
                message["stop_reason"] = event["delta"]["stop_reason"].clone();
            }
            "message_stop" => stops += 1,
            "content_block_stop" => {}
            _ => panic!("Unexpected event {event}"),
        }
        Ok::<_, fictionet::stdlib::protocols::sse::Error>(())
    })
    .unwrap();
    assert_eq!(starts, 1);
    assert_eq!(stops, 1);
    message["content"] = json!(content);
    message
}
#[test]
fn search_splices_and_replays_exact_history_with_thinking() {
    for guest in [false, true] {
        for stream in [false, true] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let first = vec![
                json!({"type":"thinking","thinking":"Consider the question.","signature":"signed-thinking"}),
                json!({"type":"tool_use","id":"toolu_original","name":"web_search","input":{"query":"page"}}),
            ];
            let second = vec![
                json!({"type":"thinking","thinking":"Read the result.","signature":"next-signature"}),
                json!({"type":"text","text":"The page text."}),
            ];
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                let a = receive(&mut socket);
                assert!(a["tools"][0].get("type").is_none());
                assert_eq!(a["tool_choice"], json!({"type":"tool","name":"web_search"}));
                response(&mut socket, first.clone(), "tool_use", stream);
                let (mut socket, _) = listener.accept().unwrap();
                let b = receive(&mut socket);
                assert_eq!(b["tools"], a["tools"]);
                assert!(b.get("tool_choice").is_none());
                assert_eq!(b["messages"][1]["content"], json!(first));
                assert_eq!(
                    b["messages"][2]["content"][0]["tool_use_id"],
                    "toolu_original"
                );
                response(&mut socket, second.clone(), "end_turn", stream);
                let (mut socket, _) = listener.accept().unwrap();
                let c = receive(&mut socket);
                assert_eq!(c["tools"], b["tools"]);
                assert_eq!(c["messages"][1], b["messages"][1]);
                assert_eq!(c["messages"][2], b["messages"][2]);
                assert_eq!(c["messages"][3]["content"], json!(second));
                assert_eq!(c["messages"][4]["content"], "Continue");
                response(
                    &mut socket,
                    vec![json!({"type":"text","text":"Done."})],
                    "end_turn",
                    stream,
                );
            });
            let pages = Arc::new(Pages(AtomicUsize::new(0)));
            let engine = pages.clone();
            fictionet::block_on(fictionet::run(fictionet::Seed::from_u64(8), |cx| async move {
            let credential = Credential::api_key(&cx, Secret::new("key", "sk-ant-api03-private".into())?);
            let key = credential.placeholder().to_owned();
            let model = if guest { Model::guest_at(&cx, Provider::Anthropic, format!("http://{address}").parse()?)? } else { Model::at(&cx, Provider::Anthropic, credential, format!("http://{address}").parse()?)? }.search(engine);
            let request = |body: &Value| Request::post("/v1/messages").header("x-api-key", &key).body(Body::from(body.to_string())).unwrap();
            let mut body = json!({"model":"claude","stream":stream,"max_tokens":100,"messages":[{"role":"user","content":"Search for page"}],"tools":[{"type":"web_search_20250305","name":"web_search","max_uses":1}],"tool_choice":{"type":"tool","name":"web_search"}});
            let answer = collected(model.clone().send(request(&body)).await?, stream).await;
            assert_eq!(answer["stop_reason"], "end_turn");
            assert_eq!(answer["usage"]["output_tokens"], 4);
            assert_eq!(answer["usage"]["server_tool_use"]["web_search_requests"], 1);
            assert_eq!(answer["content"][1]["type"], "server_tool_use");
            assert_eq!(answer["content"][2]["type"], "web_search_tool_result");
            assert_eq!(answer["content"][2]["content"][0]["title"], "Page title");
            body["messages"].as_array_mut().unwrap().extend([json!({"role":"assistant","content":answer["content"]}), json!({"role":"user","content":"Continue"})]);
            body.as_object_mut().unwrap().remove("tool_choice");
            let mut tampered = body.clone();
            tampered["messages"][1]["content"][2]["content"][0]["encrypted_content"] = json!("invalid");
            assert_eq!(model.clone().send(request(&tampered)).await?.status(), 400);
            let result = collected(model.clone().send(request(&body)).await?, stream).await;
            assert_eq!(result["content"][0]["text"], "Done.");
            Ok(())
        })).unwrap();
            server.join().unwrap();
            assert_eq!(pages.0.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn domain_filters_match_host_boundaries() {
    let tool = json!({"allowed_domains":["example.com"],"blocked_domains":["private.example.com"]});
    assert!(tools::allowed(&tool, "https://example.com/page"));
    assert!(tools::allowed(&tool, "https://www.example.com/page"));
    assert!(!tools::allowed(&tool, "https://notexample.com/page"));
    assert!(!tools::allowed(&tool, "https://example.com.evil.com/page"));
    assert!(!tools::allowed(&tool, "https://private.example.com/page"));
    assert!(!tools::allowed(&tool, "https://user@example.com/page"));
}

#[test]
fn token_counting_with_web_tools_and_history_returns_the_count() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let count = |socket: &mut std::net::TcpStream| {
            let body = r#"{"input_tokens":42}"#;
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        };
        let (mut socket, _) = listener.accept().unwrap();
        let (head, first) = exchange(&mut socket);
        assert!(
            head.starts_with("POST /v1/messages/count_tokens "),
            "{head}"
        );
        assert!(first["tools"][0].get("type").is_none(), "{first}");
        assert_eq!(first["tools"][0]["name"], "web_search");
        count(&mut socket);
        let (mut socket, _) = listener.accept().unwrap();
        receive(&mut socket);
        let call = json!({"type":"tool_use","id":"toolu_original","name":"web_search","input":{"query":"page"}});
        response(&mut socket, vec![call.clone()], "tool_use", false);
        let (mut socket, _) = listener.accept().unwrap();
        receive(&mut socket);
        response(
            &mut socket,
            vec![json!({"type":"text","text":"The page text."})],
            "end_turn",
            false,
        );
        let (mut socket, _) = listener.accept().unwrap();
        let (head, replay) = exchange(&mut socket);
        assert!(
            head.starts_with("POST /v1/messages/count_tokens "),
            "{head}"
        );
        assert!(replay["tools"][0].get("type").is_none(), "{replay}");
        assert_eq!(replay["messages"][1]["content"][0], call);
        assert_eq!(
            replay["messages"][2]["content"][0]["tool_use_id"],
            "toolu_original"
        );
        count(&mut socket);
    });
    let pages = Arc::new(Pages(AtomicUsize::new(0)));
    fictionet::block_on(fictionet::run(fictionet::Seed::from_u64(10), |cx| async move {
        let credential = Credential::api_key(&cx, Secret::new("key", "sk-ant-api03-private".into())?);
        let key = credential.placeholder().to_owned();
        let model = Model::at(&cx, Provider::Anthropic, credential, format!("http://{address}").parse()?)?
            .search(pages)
            .budget(Budget::new().calls(2));
        let request = |path: &str, body: &Value| Request::post(path).header("x-api-key", &key).body(Body::from(body.to_string())).unwrap();
        let tools = json!([{"type":"web_search_20250305","name":"web_search","max_uses":1}]);
        let mut body = json!({"model":"claude","messages":[{"role":"user","content":"Search for page"}],"tools":tools});
        let counted = model.clone().send(request("/v1/messages/count_tokens", &body)).await?;
        assert_eq!(counted.status(), 200);
        assert_eq!(counted.into_body().collect().await?.to_bytes(), r#"{"input_tokens":42}"#);
        body["max_tokens"] = json!(100);
        let answer = collected(model.clone().send(request("/v1/messages", &body)).await?, false).await;
        assert_eq!(answer["content"][0]["type"], "server_tool_use");
        body.as_object_mut().unwrap().remove("max_tokens");
        body["messages"].as_array_mut().unwrap().extend([json!({"role":"assistant","content":answer["content"]}), json!({"role":"user","content":"Continue"})]);
        // Both calls are spent; counting stays free.
        let counted = model.clone().send(request("/v1/messages/count_tokens", &body)).await?;
        assert_eq!(counted.status(), 200);
        assert_eq!(counted.into_body().collect().await?.to_bytes(), r#"{"input_tokens":42}"#);
        assert_eq!(model.ledger.lock().unwrap().calls, 2);
        Ok(())
    })).unwrap();
    server.join().unwrap();
}

#[derive(Clone, Copy)]
enum Refusal {
    Budget,
    OAuth,
    Upstream(u16, bool),
}

fn continuation_refusal(stream: bool, source: Refusal) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let status = match source {
        Refusal::Budget => 400,
        Refusal::OAuth => 429,
        Refusal::Upstream(status, _) => status,
    };
    let kind = match status {
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
    let upstream_body = match source {
        Refusal::Upstream(_, true) => {
            json!({"type":"error","error":{"type":kind,"message":"Try again later"}})
        }
        _ => json!({"error":{"code":status,"message":"Try again later"}}),
    };
    let sent = upstream_body.clone();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        receive(&mut socket);
        response(
            &mut socket,
            vec![
                json!({"type":"tool_use","id":"toolu_search","name":"web_search","input":{"query":"page"}}),
            ],
            "tool_use",
            stream,
        );
        if let Refusal::Upstream(_, _) = source {
            let (mut socket, _) = listener.accept().unwrap();
            let continuation = receive(&mut socket);
            assert_eq!(
                continuation["messages"][2]["content"][0]["type"],
                "tool_result"
            );
            let body = sent.to_string();
            write!(socket, "HTTP/1.1 {status} Refused\r\nContent-Type: application/json\r\nRetry-After: 7\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
        listener.set_nonblocking(true).unwrap();
        listener
    });
    let directory = if matches!(source, Refusal::OAuth) {
        let mut bytes = [0; 8];
        fictionet::random_bytes(&mut bytes).unwrap();
        let directory =
            std::env::temp_dir().join(format!("continuation-{}", u64::from_le_bytes(bytes)));
        std::fs::create_dir(&directory).unwrap();
        Some(directory)
    } else {
        None
    };
    let directory_path = directory.clone();
    fictionet::block_on(fictionet::run(fictionet::Seed::from_u64(13), |cx| async move {
        let mut credential = Credential::api_key(&cx, Secret::new("key", "private-key".into())?);
        let expected = if let Some(directory) = directory_path {
            let store = oauth::Store::open(directory.join("credentials.redb"))?;
            store.put(oauth::Login::Claude, oauth::Tokens::new(
                Secret::new("access", "sk-ant-oat01-host-access".into())?,
                Secret::new("refresh", "host-refresh".into())?,
                u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp())? + 3600,
            ))?;
            let authority = oauth::OAuth::at(&cx, oauth::Login::Claude, store, format!("http://{address}").parse()?)?;
            let expected = authority.stop();
            credential = Credential { real: authority.secret().await?, placeholder: authority.placeholder(), oauth: Some(authority) };
            expected
        } else if matches!(source, Refusal::Budget) {
            Provider::Anthropic.stop()
        } else {
            Response::builder().status(status).header("content-type", "application/json").header("retry-after", "7").body(Body::from(upstream_body.to_string()))?
        };
        let (expected_parts, expected_body) = expected.into_parts();
        let expected_bytes = expected_body.collect().await?.to_bytes();
        let expected_json: Value = serde_json::from_slice(&expected_bytes)?;
        let key = credential.wire(Provider::Anthropic, false);
        let model = Model::at(&cx, Provider::Anthropic, credential, format!("http://{address}").parse()?)?.search(Arc::new(Pages(AtomicUsize::new(0))));
        let model = if matches!(source, Refusal::Upstream(_, _)) { model } else { model.budget(Budget::new().calls(1)) };
        let request = Request::post("/v1/messages").header(if matches!(source, Refusal::OAuth) { "authorization" } else { "x-api-key" }, key)
            .body(Body::from(json!({"model":"claude","stream":stream,"messages":[{"role":"user","content":"Search page"}],"tools":[{"type":"web_search_20250305","name":"web_search"}]}).to_string()))?;
        let answer = model.clone().send(request).await?;
        if stream {
            assert_eq!(answer.status(), 200);
            let bytes = answer.into_body().collect().await?.to_bytes();
            let mut decoder = fictionet::stdlib::codec::Stream::new(fictionet::stdlib::protocols::sse::Events::new());
            let mut events = Vec::new();
            fictionet::stdlib::codec::try_pump(&mut decoder, &bytes, |event| {
                events.push(serde_json::from_str::<Value>(&event.data).unwrap());
                Ok::<_, fictionet::stdlib::protocols::sse::Error>(())
            }).unwrap();
            assert_eq!(events.last().unwrap(), &json!({"type":"error","error":{"type":kind,"message":expected_json["error"]["message"]}}));
            assert_eq!(events.iter().filter(|event| event["type"] == "error").count(), 1);
            assert!(!events.iter().any(|event| event["type"] == "message_stop"));
        } else {
            assert_eq!(answer.status(), status);
            for (name, value) in &expected_parts.headers {
                if name.as_str().ends_with("reset") {
                    assert!(answer.headers()[name].to_str()?.parse::<u64>().is_ok());
                } else {
                    assert_eq!(answer.headers().get(name), Some(value));
                }
            }
            assert_eq!(answer.into_body().collect().await?.to_bytes(), expected_bytes);
        }
        assert_eq!(model.ledger.lock().unwrap().calls, if matches!(source, Refusal::Upstream(_, _)) { 2 } else { 1 });
        cx.cancel();
        Ok(())
    })).unwrap();
    let listener = server.join().unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    if let Some(directory) = directory {
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[test]
fn continuation_budget_response() {
    continuation_refusal(false, Refusal::Budget);
}
#[test]
fn continuation_budget_stream() {
    continuation_refusal(true, Refusal::Budget);
}
#[test]
fn continuation_oauth_response() {
    continuation_refusal(false, Refusal::OAuth);
}
#[test]
fn continuation_oauth_stream() {
    continuation_refusal(true, Refusal::OAuth);
}
#[test]
fn continuation_rate_limit_response() {
    continuation_refusal(false, Refusal::Upstream(429, true));
}
#[test]
fn continuation_rate_limit_stream() {
    continuation_refusal(true, Refusal::Upstream(429, true));
}
#[test]
fn continuation_status_error_types() {
    for status in [400, 401, 402, 403, 404, 413, 429, 529, 500] {
        for stream in [false, true] {
            continuation_refusal(stream, Refusal::Upstream(status, false));
        }
    }
}

#[test]
fn anthropic_openrouter_runs_world_tools_before_continuing() {
    for stream in [false, true] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for content in [
                vec![
                    json!({"type":"tool_use","id":"toolu_search","name":"web_search","input":{"query":"page"}}),
                ],
                vec![
                    json!({"type":"tool_use","id":"toolu_fetch","name":"web_fetch","input":{"url":"https://example.com/page"}}),
                ],
                vec![json!({"type":"text","text":"Done."})],
            ] {
                let (mut socket, _) = listener.accept().unwrap();
                let (headers, body) = exchange(&mut socket);
                assert!(headers.starts_with("POST /api/v1/messages "));
                assert!(headers.contains("authorization: Bearer sk-ant-api03-private"));
                assert!(body["tools"][0].get("type").is_none());
                let stop = if content[0]["type"] == "text" {
                    "end_turn"
                } else {
                    "tool_use"
                };
                response(&mut socket, content, stop, stream);
            }
        });
        let pages = Arc::new(Pages(AtomicUsize::new(0)));
        let engine = pages.clone();
        fictionet::block_on(fictionet::run(fictionet::Seed::from_u64(8), |cx| async move {
            let credential = Credential::api_key(&cx, Secret::new("ANTHROPIC_API_KEY", "sk-ant-api03-private".into())?);
            let key = credential.placeholder().to_owned();
            let model = Model::at(&cx, Provider::Anthropic, credential, format!("http://{address}").parse()?)?.anthropic_openrouter().search(engine);
            let body = json!({"model":"claude","stream":stream,"max_tokens":1000,"messages":[{"role":"user","content":"Search for page and read https://example.com/page"}],"tools":[{"type":"web_search_20250305","name":"web_search","max_uses":8},{"type":"web_fetch_20250910","name":"web_fetch","max_uses":8}]});
            let request = Request::post("/v1/messages").header("x-api-key", key).body(Body::from(body.to_string()))?;
            let answer = collected(model.send(request).await?, stream).await;
            assert_eq!(answer["stop_reason"], "end_turn");
            assert_eq!(answer["content"][1]["type"], "web_search_tool_result");
            assert_eq!(answer["content"][3]["type"], "web_fetch_tool_result");
            assert_eq!(answer["content"][3]["content"]["content"]["source"]["data"], "Page title\nThe page text");
            Ok(())
        })).unwrap();
        server.join().unwrap();
        assert_eq!(pages.0.load(Ordering::SeqCst), 1);
    }
}
