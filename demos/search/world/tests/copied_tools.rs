use example_common::log::Log;
use fictionet::stdlib::web::httpd::{Exchange, Handler, Reply};
use fictionet::{events::Fanout, stdlib::web::Body};
use fictionet_extras::models::{Model, Provider};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
};
use web_world::{
    events::LogObserver,
    pages::{Pages, Seed},
    search::Searches,
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
fn anthropic_tools_search_the_index_fetch_the_corpus_and_log_once() {
    for bearer in [false, true] {
        intercepted_search(bearer);
    }
}

fn intercepted_search(bearer: bool) {
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
            let mut credentials = Vec::new();
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                let lower = line.to_ascii_lowercase();
                if lower.starts_with("authorization:") || lower.starts_with("x-api-key:") {
                    credentials.push(lower.trim().to_owned());
                }
                if let Some(n) = lower.strip_prefix("content-length:") {
                    length = Some(n.trim().parse::<usize>().unwrap());
                }
            }
            assert_eq!(
                credentials,
                [if bearer {
                    "authorization: bearer local-only"
                } else {
                    "x-api-key: local-only"
                }]
            );
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
                    json!([{"type":"tool_use","id":"toolu_search","name":"web_search","input":{"query":"black hole"}}])
                }
                1 => {
                    let text = request["messages"].to_string();
                    assert!(text.contains("Black holes"));
                    assert!(text.contains("https://sky.org/black-hole"));
                    json!([{"type":"tool_use","id":"toolu_fetch","name":"web_fetch","input":{"url":"https://sky.org/black-hole"}}])
                }
                _ => {
                    assert!(request["messages"].to_string().contains("bends spacetime"));
                    json!([{"type":"text","text":"Black holes bend spacetime."}])
                }
            };
            let reply = json!({"id":"msg_local","type":"message","role":"assistant","model":"claude-mythos","content":content,"stop_reason":if turn<2 {"tool_use"} else {"end_turn"},"stop_sequence":null,"usage":{"input_tokens":30,"output_tokens":20}}).to_string();
            write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",reply.len()).unwrap();
        }
    });
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../extras/tests/fixtures");
    let pages = Arc::new(
        Pages::copied(
            Seed::builtin("web").unwrap(),
            &root,
            &["https://sky.org/".into()],
            None,
        )
        .unwrap(),
    );
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
            let (header, key) = if bearer {
                ("authorization", "Bearer local-only")
            } else {
                ("x-api-key", "local-only")
            };
            let model = Model::guest_at(&cx, Provider::Anthropic, origin)?.search(pages);
            let request = http::Request::post("/v1/messages")
                .header(header, key)
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
            assert_eq!(search["content"].as_array().unwrap().len(), 1);
            assert_eq!(search["content"][0]["url"], "https://sky.org/black-hole");
            assert!(search["content"][0]["encrypted_content"].as_str().is_some());
            let fetch = content
                .iter()
                .find(|b| b["type"] == "web_fetch_tool_result")
                .unwrap();
            assert!(
                fetch["content"]["content"]["source"]["data"]
                    .as_str()
                    .unwrap()
                    .contains("bends spacetime")
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
    assert_eq!(snapshot.queries[0].results, Some(1));
    let bytes = output.0.lock().unwrap();
    let rows: Vec<Value> = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let entries: Vec<_> = rows.iter().filter(|r| r["type"] == "search").collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["source"], "claude_web_search");
    assert_eq!(entries[0]["query"], "black hole");
    assert_eq!(entries[0]["results"].as_array().unwrap().len(), 1);
    assert!(!rows.iter().any(|r| r["type"] == "dns"));
}
