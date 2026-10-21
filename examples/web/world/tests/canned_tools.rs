use web_world::{
    events::LogObserver,
    pages::{Pages, Seed, store},
    search::Searches,
};
use example_common::log::Log;
use fictionet::stdlib::web::httpd::{Exchange, Handler, Reply};
use fictionet::{events::Fanout, stdlib::web::Body};
use fictionet_extras::models::{Credential, Model, Provider, Secret};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
struct Output(Arc<Mutex<Vec<u8>>>);
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn anthropic_tools_read_the_store_and_log_without_external_searches() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = std::thread::spawn(move || {
        for turn in 0..3 {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.starts_with("POST /v1/messages "));
            let mut length = None;
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(n) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = Some(n.trim().parse::<usize>().unwrap());
                }
            }
            let mut bytes = vec![0; length.unwrap()];
            reader.read_exact(&mut bytes).unwrap();
            let request: Value = serde_json::from_slice(&bytes).unwrap();
            assert!(
                request["tools"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|t| t.get("type").is_none())
            );
            assert_eq!(request["model"], "claude-mythos");
            let content = match turn {
                0 => {
                    json!([{"type":"tool_use","id":"toolu_search","name":"web_search","input":{"query":"httpx vs requests async concurrency"}}])
                }
                1 => {
                    let text = request["messages"].to_string();
                    assert!(text.contains("Async support"));
                    assert!(text.contains("https://www.python-httpx.org/async/"));
                    json!([{"type":"tool_use","id":"toolu_fetch","name":"web_fetch","input":{"url":"https://www.python-httpx.org/async/"}}])
                }
                _ => {
                    assert!(
                        request["messages"]
                            .to_string()
                            .contains("asyncio.Semaphore(8)")
                    );
                    json!([{"type":"text","text":"Use a shared AsyncClient with bounded concurrency."}])
                }
            };
            let reply = json!({"id":"msg_local","type":"message","role":"assistant","model":"claude-mythos","content":content,"stop_reason":if turn<2 {"tool_use"} else {"end_turn"},"stop_sequence":null,"usage":{"input_tokens":30,"output_tokens":20}}).to_string();
            write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",reply.len()).unwrap();
        }
    });
    let pages =
        Arc::new(Pages::canned(Seed::builtin("web").unwrap(), &store::canned_root("web")).unwrap());
    let searches = Arc::new(Searches::of(&pages));
    let output = Output(Arc::default());
    let log = Arc::new(Log::new(Box::new(output.clone()), &[], |s| s));
    let observer = Arc::new(Fanout::new(vec![
        searches.clone(),
        Arc::new(LogObserver { log: log.clone() }),
    ]));
    let run_log = log.clone();
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(17)).observer(observer),
        |cx| async move {
            run_log.attach(&cx);
            let credential =
                Credential::api_key(&cx, Secret::new("local credential", "local-only".into())?);
            let key = credential.placeholder().to_owned();
            let model = Model::at(&cx, Provider::Anthropic, credential, origin)?.search(pages);
            let request = http::Request::post("/v1/messages")
                .header("x-api-key", key)
                .header("anthropic-version", "2023-06-01")
                .header("anthropic-beta", "web-fetch-2025-09-10")
                .body(Body::from(include_str!("anthropic-search.json")))?;
            let response = match model.call(
                request,
                &mut Exchange::new(cx.now(), &cx, &Default::default()),
            ) {
                Reply::Later(work) => work(cx.clone()).await?,
                _ => panic!("model request did not enter the answering side"),
            };
            assert_eq!(response.status(), 200);
            let bytes = response.into_body().collect().await?.to_bytes();
            let reply: Value = serde_json::from_slice(&bytes)?;
            let content = reply["content"].as_array().unwrap();
            let search = content
                .iter()
                .find(|b| b["type"] == "web_search_tool_result")
                .unwrap();
            assert_eq!(search["content"].as_array().unwrap().len(), 6);
            assert_eq!(
                search["content"][0]["url"],
                "https://www.python-httpx.org/async/"
            );
            assert!(search["content"][0]["encrypted_content"].as_str().is_some());
            let fetch = content
                .iter()
                .find(|b| b["type"] == "web_fetch_tool_result")
                .unwrap();
            assert!(
                fetch["content"]["content"]["source"]["data"]
                    .as_str()
                    .unwrap()
                    .contains("asyncio.Semaphore(8)")
            );
            assert_eq!(reply["stop_reason"], "end_turn");
            Ok(())
        },
    ))
    .unwrap();
    server.join().unwrap();
    log.finish().unwrap();
    let snapshot = searches.snapshot();
    assert_eq!(snapshot.queries.len(), 1);
    assert_eq!(
        snapshot.queries[0].via.as_deref(),
        Some("claude_web_search")
    );
    assert_eq!(snapshot.queries[0].results, Some(6));
    let bytes = output.0.lock().unwrap();
    let rows: Vec<Value> = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let entries: Vec<_> = rows.iter().filter(|r| r["type"] == "search").collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["source"], "claude_web_search");
    assert_eq!(entries[0]["query"], "httpx vs requests async concurrency");
    assert_eq!(entries[0]["results"].as_array().unwrap().len(), 6);
    assert!(!rows.iter().any(|r| r["type"] == "dns"));
}
