use super::*;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
struct Pages(AtomicUsize);
impl Engine for Pages {
    fn search(self: Arc<Self>, _: Cx, _: String) -> tools::Answer<Vec<crate::search::Result>> {
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
fn receive(socket: &mut std::net::TcpStream) -> Value {
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
    serde_json::from_slice(&body).unwrap()
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
        fictionet::block_on(fictionet::run(fictionet::RunOptions::new(fictionet::Seed::from_u64(8)), |cx| async move {
            let credential = Credential::api_key(&cx, Secret::new("key", "sk-ant-api03-private".into())?);
            let key = credential.placeholder().to_owned();
            let mut model = Model::at(&cx, Provider::Anthropic, credential, format!("http://{address}").parse()?)?.search(engine);
            let request = |body: &Value| Request::post("/v1/messages").header("x-api-key", &key).body(Body::from(body.to_string())).unwrap();
            let mut body = json!({"model":"claude","stream":stream,"max_tokens":100,"messages":[{"role":"user","content":"Search for page"}],"tools":[{"type":"web_search_20250305","name":"web_search","max_uses":1}],"tool_choice":{"type":"tool","name":"web_search"}});
            let answer = collected(model.call(request(&body)).await?, stream).await;
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
            assert_eq!(model.call(request(&tampered)).await?.status(), 400);
            let result = collected(model.call(request(&body)).await?, stream).await;
            assert_eq!(result["content"][0]["text"], "Done.");
            Ok(())
        })).unwrap();
        server.join().unwrap();
        assert_eq!(pages.0.load(Ordering::SeqCst), 1);
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
