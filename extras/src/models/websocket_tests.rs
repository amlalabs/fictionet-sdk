use super::responses_tests::answer;
use super::splice_tests::Pages;
use super::*;
use fictionet::stdlib::codec::{Side, Stream, Wire};
use fictionet::stdlib::network::{ConnectionExt, ip, tcp};
use fictionet::stdlib::protocols::websocket::{Close, Message, Messages};
use fictionet::stdlib::world::net;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// A fake upstream's view of one POST: its head, lowercased, and its body.
fn received(socket: &mut std::net::TcpStream) -> (String, Value) {
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap().to_lowercase();
    let size: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length: "))
        .unwrap()
        .parse()
        .unwrap();
    let mut body = vec![0; size];
    socket.read_exact(&mut body).unwrap();
    (head, serde_json::from_slice(&body).unwrap())
}

/// A WebSocket client inside the world, talking to the model site.
struct Client {
    cx: Cx,
    conn: tcp::TcpConnection,
    stream: Stream<Messages>,
}
impl Client {
    /// Opens a connection to `model` served on port 80 of a world host.
    async fn connect(cx: &Cx, model: Model) -> tcp::TcpConnection {
        let (attacher, attachments) = fictionet::attachments();
        net::Net::new()
            .host("api", |host| {
                host.at(Ipv4Addr::new(198, 18, 0, 1))
                    .dns_name("api.openai.com")
                    .port_server(80, httpd::Server::new(model))
            })
            .start(cx, attachments)
            .unwrap();
        let end = attacher.attach("client").unwrap();
        let (t, _u, _i, _o) = ip::split_protocols(cx, end);
        tcp::endpoint(cx, t, Ipv4Addr::new(10, 0, 0, 2).into())
            .connect(cx, SocketAddr::from(([198, 18, 0, 1], 80)))
            .await
            .unwrap()
    }
    /// Sends Codex's handshake with `authorization` and `version`, and
    /// returns the response head, lowercased, with the connection.
    async fn handshake(
        cx: &Cx,
        mut conn: tcp::TcpConnection,
        authorization: &str,
        version: &str,
    ) -> (String, Client) {
        let request = format!(
            "GET /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nConnection: Upgrade\r\n\
             Upgrade: websocket\r\nSec-WebSocket-Version: {version}\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\
             Authorization: {authorization}\r\nOpenAI-Beta: responses_websockets=2026-02-06\r\n\
             originator: codex_exec\r\n\r\n"
        );
        conn.write_all(cx, request.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            assert_eq!(conn.read(cx, &mut byte).await.unwrap(), 1);
            head.push(byte[0]);
        }
        let client = Client {
            cx: cx.clone(),
            conn,
            stream: Stream::new(Messages::for_receiver(Side::Client)),
        };
        (String::from_utf8(head).unwrap().to_lowercase(), client)
    }
    async fn open(cx: &Cx, model: &Model) -> Client {
        let key = model.credential.wire(model.provider, false);
        let conn = Client::connect(cx, model.clone()).await;
        let (head, client) = Client::handshake(cx, conn, &key, "13").await;
        assert!(head.starts_with("http/1.1 101"), "{head}");
        client
    }
    async fn send_message(&mut self, message: Message) {
        let bytes = message
            .to_frame(Some([7, 1, 9, 4]))
            .unwrap()
            .to_bytes()
            .unwrap();
        self.conn.write_all(&self.cx, &bytes).await.unwrap();
    }
    async fn send(&mut self, event: Value) {
        self.send_message(Message::Text(event.to_string())).await;
    }
    async fn next(&mut self) -> Message {
        let deadline = self.cx.now() + Duration::from_secs(20);
        loop {
            if let Some(message) = self.stream.next() {
                return message.unwrap();
            }
            let mut buf = [0; 16 * 1024];
            let n = self
                .cx
                .race(Some(deadline), self.conn.read(&self.cx, &mut buf))
                .await
                .expect("a message before the deadline")
                .unwrap();
            assert!(n > 0, "the socket closed");
            assert_eq!(self.stream.push(&buf[..n]), n);
        }
    }
    async fn event(&mut self) -> Value {
        match self.next().await {
            Message::Text(text) => serde_json::from_str(&text).unwrap(),
            other => panic!("expected an event, got {other:?}"),
        }
    }
    /// Events up to and including the first of type `last`.
    async fn until(&mut self, last: &str) -> Vec<Value> {
        let mut events = Vec::new();
        loop {
            let event = self.event().await;
            let done = event["type"] == last;
            events.push(event);
            if done {
                return events;
            }
        }
    }
}

fn openai(cx: &Cx, address: SocketAddr) -> fictionet::Result<Model> {
    let credential = Credential::api_key(cx, Secret::new("key", "private".into())?);
    Model::at(
        cx,
        Provider::OpenAi,
        credential,
        format!("http://{address}").parse()?,
    )
}

fn observed() -> (Arc<fictionet_observe::Memory>, fictionet::RunOptions) {
    let memory = Arc::new(fictionet_observe::Memory::default());
    let options = fictionet::RunOptions::new(fictionet::Seed::from_u64(21))
        .observer(Arc::new(fictionet_observe::Aggregate::new(memory.clone())));
    (memory, options)
}

#[test]
fn the_handshake_and_socket_answer_like_openai() {
    let (memory, options) = observed();
    fictionet::block_on(fictionet::run(options, |cx| async move {
        // Nothing listens there: no request may reach an upstream.
        let model = openai(&cx, "127.0.0.1:1".parse()?)?;
        let key = model.credential.wire(model.provider, false);
        let conn = Client::connect(&cx, model.clone()).await;
        let (head, _) = Client::handshake(&cx, conn, "Bearer sk-proj-wrong", "13").await;
        assert!(head.starts_with("http/1.1 401"), "{head}");
        let conn = Client::connect(&cx, model.clone()).await;
        let (head, _) = Client::handshake(&cx, conn, &key, "12").await;
        assert!(head.starts_with("http/1.1 426"), "{head}");
        assert!(head.contains("sec-websocket-version: 13\r\n"), "{head}");

        let conn = Client::connect(&cx, model.clone()).await;
        let (head, mut client) = Client::handshake(&cx, conn, &key, "13").await;
        assert!(head.starts_with("http/1.1 101"), "{head}");
        assert!(head.contains("upgrade: websocket\r\n"), "{head}");
        assert!(head.contains("connection: upgrade\r\n"), "{head}");
        assert!(
            head.contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo=\r\n"),
            "{head}"
        );
        assert!(head.contains("x-request-id: req_"), "{head}");
        // Compression is offered and declined, which RFC 6455 allows.
        assert!(!head.contains("sec-websocket-extensions"), "{head}");

        client.send_message(Message::Ping(b"are you there".to_vec())).await;
        assert_eq!(client.next().await, Message::Pong(b"are you there".to_vec()));

        client.send_message(Message::Text("{not json".into())).await;
        let error = client.event().await;
        assert_eq!(error["type"], "error");
        assert_eq!(error["status"], 400);
        assert_eq!(error["error"]["type"], "invalid_request_error");

        let missing = json!({"type":"response.create","model":"small","previous_response_id":"resp_gone","input":[]});
        client.send(missing).await;
        let error = client.event().await;
        assert_eq!(error["status"], 400);
        assert_eq!(error["error"]["code"], "previous_response_not_found");
        assert_eq!(error["error"]["param"], "previous_response_id");

        // A warmup on a named lane: no output, no upstream call, and an id
        // to continue from. The lane's events carry its name.
        let warm = json!({"type":"response.create","stream_id":"main","model":"small","generate":false,"store":false,"input":[{"role":"user","content":"hi"}],"tools":[]});
        client.send(warm).await;
        let created = client.event().await;
        assert_eq!(created["type"], "response.created");
        assert_eq!(created["stream_id"], "main");
        let completed = client.event().await;
        assert_eq!(completed["type"], "response.completed");
        assert_eq!(completed["stream_id"], "main");
        assert_eq!(completed["response"]["output"], json!([]));
        assert_eq!(completed["response"]["model"], "small");
        let id = completed["response"]["id"].as_str().unwrap().to_owned();
        assert!(id.starts_with("resp_"));
        assert_eq!(created["response"]["id"], id);

        let bad = json!({"type":"response.create","stream_id":"","model":"small","generate":false,"input":[]});
        client.send(bad).await;
        let error = client.event().await;
        assert_eq!(error["error"]["code"], "invalid_stream_id");

        client
            .send(json!({"type":"response.interrupt","response_id":"resp_unknown","mode":"discard_partial_items"}))
            .await;
        assert_eq!(client.event().await["type"], "response.interrupt.failed");

        client.send_message(Message::Binary(vec![1])).await;
        assert_eq!(
            client.next().await,
            Message::Close(Some(Close::new(1003)))
        );
        assert_eq!(model.ledger.lock().unwrap().calls, 0);
        cx.cancel();
        Ok(())
    }))
    .unwrap();
    let opened = memory.checked_of("model", "transport").unwrap();
    assert!(
        opened
            .iter()
            .any(|e| e.u64("status") == Some(101) && e.str("transport") == Some("websocket"))
    );
    assert!(opened.iter().any(|e| e.u64("closed") == Some(1003)));
    assert!(memory.checked_of("model", "call").unwrap().is_empty());
}

#[test]
fn a_codex_turn_runs_over_the_socket_with_a_world_search() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let (head, first) = received(&mut socket);
        // The upstream gets plain HTTP streaming with the real key.
        assert!(head.starts_with("post /v1/responses http/1.1"), "{head}");
        assert!(head.contains("authorization: bearer private\r\n"), "{head}");
        assert!(head.contains("originator: codex_exec\r\n"), "{head}");
        for socket_only in ["upgrade:", "sec-websocket-", "openai-beta:"] {
            assert!(!head.contains(socket_only), "{head}");
        }
        assert_eq!(first["stream"], true);
        for field in ["type", "generate", "previous_response_id"] {
            assert!(first.get(field).is_none(), "{first}");
        }
        assert_eq!(first["instructions"], "Be brief.");
        // The warmup's input, continued with no new items.
        assert_eq!(
            first["input"],
            json!([{"type":"message","role":"user","content":[{"type":"input_text","text":"Search for the page"}]}])
        );
        assert_eq!(first["tools"][0]["name"], "web_search");
        let call = json!({"type":"function_call","id":"fc_first","call_id":"call_first","name":"web_search","arguments":"{\"query\":\"page\"}","status":"completed"});
        answer(&mut socket, vec![call.clone()], true);

        let (mut socket, _) = listener.accept().unwrap();
        let (_, second) = received(&mut socket);
        assert_eq!(second["input"][1], call);
        assert_eq!(second["input"][2]["type"], "function_call_output");
        let text = json!({"type":"message","id":"msg_final","role":"assistant","status":"completed","content":[{"type":"output_text","text":"Page title","annotations":[]}]});
        answer(&mut socket, vec![text.clone()], true);

        // The next turn names the finished response and sends only its
        // new message; the upstream gets the whole history, with the
        // search back in the form the model saw it.
        let (mut socket, _) = listener.accept().unwrap();
        let (_, third) = received(&mut socket);
        let input = third["input"].as_array().unwrap();
        assert_eq!(&input[..3], second["input"].as_array().unwrap());
        assert_eq!(input[3], text);
        assert_eq!(input[4], json!({"role":"user","content":"Thanks"}));
        assert_eq!(input.len(), 5);
        let done = json!({"type":"message","id":"msg_done","role":"assistant","status":"completed","content":[{"type":"output_text","text":"Welcome","annotations":[]}]});
        answer(&mut socket, vec![done], true);
    });
    let pages = Arc::new(Pages(AtomicUsize::new(0)));
    let engine = pages.clone();
    let (memory, options) = observed();
    fictionet::block_on(fictionet::run(options, |cx| async move {
        let model = openai(&cx, address)?.search(engine);
        let mut client = Client::open(&cx, &model).await;
        let request = |input: Value| {
            json!({"type":"response.create","model":"small","instructions":"Be brief.","input":input,
                "tools":[{"type":"web_search","external_web_access":true}],"tool_choice":"auto",
                "parallel_tool_calls":false,"store":false,"stream":true,
                "include":["reasoning.encrypted_content"],"client_metadata":{"session_id":"s1"}})
        };
        let mut warm = request(json!([{"type":"message","role":"user","content":[{"type":"input_text","text":"Search for the page"}]}]));
        warm["generate"] = json!(false);
        client.send(warm).await;
        let warmed = client.until("response.completed").await;
        assert_eq!(warmed.len(), 2);
        let warm_id = warmed[1]["response"]["id"].clone();

        let mut turn = request(json!([]));
        turn["previous_response_id"] = warm_id;
        client.send(turn).await;
        let events = client.until("response.completed").await;
        assert_eq!(events[0]["type"], "response.created");
        let kinds: Vec<_> = events
            .iter()
            .filter(|e| e["output_index"] == 0)
            .map(|e| e["type"].as_str().unwrap())
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
        let completed = &events.last().unwrap()["response"];
        assert_eq!(completed["output"][0]["type"], "web_search_call");
        assert_eq!(completed["output"][0]["action"]["query"], "page");
        assert_eq!(completed["output"][1]["content"][0]["text"], "Page title");
        assert!(events.iter().all(|e| e.get("stream_id").is_none()));

        let mut next = request(json!([{"role":"user","content":"Thanks"}]));
        next["previous_response_id"] = completed["id"].clone();
        client.send(next).await;
        let events = client.until("response.completed").await;
        assert_eq!(
            events.last().unwrap()["response"]["output"][0]["content"][0]["text"],
            "Welcome"
        );
        assert_eq!(model.ledger.lock().unwrap().calls, 3);
        cx.cancel();
        Ok(())
    }))
    .unwrap();
    upstream.join().unwrap();
    assert_eq!(pages.0.load(Ordering::SeqCst), 1);
    let calls = memory.checked_of("model", "call").unwrap();
    assert_eq!(calls.len(), 3);
    for call in &calls {
        assert_eq!(call.str("transport"), Some("websocket"));
        assert_eq!(call.str("path"), Some("/v1/responses"));
        assert_eq!(call.u64("status"), Some(200));
    }
    let tools = memory.checked_of("model", "tool").unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].str("source"), Some("world"));
    assert_eq!(tools[0].u64("results"), Some(1));
}

#[test]
fn a_budget_stop_reaches_the_socket_as_openai_sends_it() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        received(&mut socket);
        let call = json!({"type":"function_call","id":"fc_one","call_id":"call_one","name":"web_search","arguments":"{\"query\":\"page\"}","status":"completed"});
        answer(&mut socket, vec![call], true);
        // No other request may arrive: the budget stops the rest.
        listener.set_nonblocking(true).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert!(listener.accept().is_err());
    });
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(22)),
        |cx| async move {
            let model = openai(&cx, address)?
                .search(Arc::new(Pages(AtomicUsize::new(0))))
                .budget(Budget::new().calls(1));
            let mut client = Client::open(&cx, &model).await;
            let create = json!({"type":"response.create","model":"small","input":"Search","tools":[{"type":"web_search"}],"store":false});
            // The search's continuation is the second call: the response
            // fails with OpenAI's quota error, as a stream would.
            client.send(create.clone()).await;
            let events = client.until("response.failed").await;
            let failed = &events.last().unwrap()["response"];
            assert_eq!(failed["status"], "failed");
            assert_eq!(failed["error"]["code"], "insufficient_quota");
            assert_eq!(failed["output"][0]["type"], "web_search_call");
            assert!(!events.iter().any(|e| e["type"] == "response.completed"));
            // A new request is refused before any upstream call, as an
            // error event carrying the HTTP status.
            client.send(create.clone()).await;
            let error = client.event().await;
            assert_eq!(error["type"], "error");
            assert_eq!(error["status"], 429);
            assert_eq!(error["error"]["type"], "insufficient_quota");
            assert_eq!(error["error"]["code"], "insufficient_quota");
            assert!(
                error["error"]["message"]
                    .as_str()
                    .unwrap()
                    .starts_with("You exceeded your current quota")
            );
            let mut warm = create;
            warm["generate"] = json!(false);
            client.send(warm).await;
            let error = client.event().await;
            assert_eq!(error["status"], 429);
            assert_eq!(error["error"]["code"], "insufficient_quota");
            // The socket stays open for the client's next try.
            client.send_message(Message::Ping(b"still".to_vec())).await;
            assert_eq!(client.next().await, Message::Pong(b"still".to_vec()));
            assert_eq!(model.ledger.lock().unwrap().calls, 1);
            cx.cancel();
            Ok(())
        },
    ))
    .unwrap();
    upstream.join().unwrap();
}

#[test]
fn an_interrupt_ends_a_running_response_with_its_finished_items() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let upstream = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        received(&mut socket);
        let response = json!({"id":"resp_slow","object":"response","created_at":1,"model":"small","status":"in_progress","output":[]});
        let item = json!({"type":"message","id":"msg_one","role":"assistant","status":"completed","content":[{"type":"output_text","text":"One","annotations":[]}]});
        let events = [
            json!({"type":"response.created","sequence_number":0,"response":response}),
            json!({"type":"response.output_item.added","sequence_number":1,"output_index":0,"item":item}),
            json!({"type":"response.output_item.done","sequence_number":2,"output_index":0,"item":item}),
        ];
        let mut body = String::new();
        for event in events {
            body.push_str(&format!(
                "event: {}\ndata: {event}\n\n",
                event["type"].as_str().unwrap()
            ));
        }
        write!(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n",
            body.len()
        )
        .unwrap();
        socket.flush().unwrap();
        // Hold the stream open until the client has interrupted it.
        released.recv().unwrap();
    });
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(23)),
        |cx| async move {
            let model = openai(&cx, address)?;
            let mut client = Client::open(&cx, &model).await;
            client
                .send(json!({"type":"response.create","model":"small","input":"Count","store":false}))
                .await;
            let events = client.until("response.output_item.done").await;
            assert_eq!(events[0]["response"]["id"], "resp_slow");
            client
                .send(json!({"type":"response.interrupt","response_id":"resp_slow","mode":"discard_partial_items"}))
                .await;
            let accepted = client.event().await;
            assert_eq!(accepted["type"], "response.interrupt.accepted");
            assert_eq!(accepted["response_id"], "resp_slow");
            let incomplete = client.event().await;
            assert_eq!(incomplete["type"], "response.incomplete");
            assert_eq!(incomplete["sequence_number"], 3);
            let response = &incomplete["response"];
            assert_eq!(response["id"], "resp_slow");
            assert_eq!(response["status"], "incomplete");
            assert_eq!(response["incomplete_details"]["reason"], "interrupted");
            assert_eq!(response["output"][0]["id"], "msg_one");
            // The interrupted response is still one to continue from.
            client
                .send(json!({"type":"response.create","model":"small","generate":false,"previous_response_id":"resp_slow","input":[]}))
                .await;
            assert_eq!(client.until("response.completed").await.len(), 2);
            release.send(()).unwrap();
            cx.cancel();
            Ok(())
        },
    ))
    .unwrap();
    upstream.join().unwrap();
}
