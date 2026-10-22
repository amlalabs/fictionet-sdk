use example_common::events::field;
use fictionet::events::{
    ConnInfo, Event, Interest, Metadata, Observation, Observer, Stamp, Stream, TopologyKind,
};
use fictionet::time::Instant;
use fictionet_extras::search::Engine;
use serde_json::json;
use web_world::pages::model::Provider;
use web_world::pages::{GeneratorKind, Pages, Seed, store::Store};
use web_world::search::*;

fn feed(s: &Searches, seq: u64, event: Event) {
    s.observe(
        Stamp {
            stream: Stream::Events,
            seq,
            at: Instant::from_since_start(std::time::Duration::from_millis(seq * 10)),
        },
        Observation::Event(&event),
    );
}
fn searches() -> Searches {
    Searches::new(SeedCard::default(), Generator::default())
}

fn query(id: u64, engine: &str, key: &str) -> Event {
    Event::new("web", "query")
        .field("query_id", id)
        .field("engine", engine)
        .field("key", key)
        .field("search", key)
        .field("start", 0u64)
}
fn answer(id: u64, complete: bool) -> Event {
    Event::new("http", "request")
        .field("query_id", id)
        .field("query", "q=a")
        .field("kind", "search")
        .field("cache", "generated")
        .field("complete", complete)
        .field("results", 1u64)
        .field("serve_ms", 20u64)
        .field("gen_ms", 15u64)
        .field(
            "listed",
            field(&json!([{"rank":1,"url":"https://a.com/","title":"A"}])),
        )
}
fn page(path: &str, cache: &str, model: &str, reason: serde_json::Value) -> Event {
    Event::new("http", "request")
        .field("kind", "page")
        .field("scheme", "https")
        .field("host", "a.com")
        .field("path", path)
        .field("status", 200u64)
        .field("cache", cache)
        .field("model", model)
        .field("reason", field(&reason))
        .field("serve_ms", 20u64)
        .field("gen_ms", 15u64)
        .field("title", "Title")
}
fn model_world_tools(stream: bool) {
    use fictionet::stdlib::web::{Body, httpd};
    use fictionet_extras::models::{Credential, Model, Provider, Secret};
    use http_body_util::BodyExt;
    use std::io::{Read, Write};
    use std::sync::Arc;
    use web_world::pages::{Pages as WorldPages, Seed as WorldSeed};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let url = "https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html";
    let words = "learn rust ownership";
    let server = std::thread::spawn(move || {
        for content in [
            json!([{"type":"tool_use","id":"toolu_search","name":"web_search","input":{"query":words}}]),
            json!([{"type":"tool_use","id":"toolu_fetch","name":"web_fetch","input":{"url":url}}]),
            json!([{"type":"text","text":"Done."}]),
        ] {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            let head = String::from_utf8(head).unwrap();
            let size: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length: "))
                .unwrap()
                .parse()
                .unwrap();
            let mut body = vec![0; size];
            socket.read_exact(&mut body).unwrap();
            let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(request["tools"][0].get("type").is_none());
            let stop = if content[0]["type"] == "text" {
                "end_turn"
            } else {
                "tool_use"
            };
            let body = json!({"type":"message","id":"msg_page","role":"assistant","model":"claude","content":content,"stop_reason":stop,"usage":{"input_tokens":7,"output_tokens":2}}).to_string();
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
    });
    let state = Arc::new(Searches::from_seed(&WorldSeed::builtin("web").unwrap()));
    let observed = state.clone();
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(8)).observer(state),
        move |cx| async move {
            let mut seed = WorldSeed::builtin("web").unwrap();
            seed.fixed.push(web_world::pages::seed::Fixed {
                url: url.into(), file: "ownership.html".into(),
                host: "doc.rust-lang.org".into(),
                target: "/book/ch04-00-understanding-ownership.html".into(),
                title: "Learn Rust ownership".into(), description: "Learn Rust ownership".into(),
                content_type: "text/html".into(), body: b"<h1>Learn Rust ownership</h1>".to_vec(),
            });
            let pages = Arc::new(WorldPages::new(seed));
            let credential = Credential::api_key(&cx, Secret::new("ANTHROPIC_API_KEY", "sk-ant-api03-private".into())?);
            let key = credential.placeholder().to_owned();
            let model = Model::at(&cx, Provider::Anthropic, credential, format!("http://{address}").parse()?)?.search(pages);
            let body = json!({"model":"claude","stream":stream,"max_tokens":1000,"messages":[{"role":"user","content":format!("Search for {words}, then read {url}")}],"tools":[{"type":"web_search_20250305","name":"web_search","max_uses":8},{"type":"web_fetch_20250910","name":"web_fetch","max_uses":8}]});
            let request = http::Request::post("/v1/messages").header("x-api-key", key).body(Body::from(body.to_string()))?;
            let conn = ConnInfo::default();
            let mut exchange = httpd::Exchange::new(cx.now(), &cx, &conn);
            let httpd::Reply::Later(work) = httpd::Handler::call(&model, request, &mut exchange) else { panic!("expected deferred model reply") };
            let response = work(cx.clone()).await?;
            assert_eq!(response.status(), 200);
            response.into_body().collect().await?;
            let snapshot = observed.snapshot();
            assert_eq!(snapshot.queries.len(), 1, "{snapshot:?}");
            let query = &snapshot.queries[0];
            assert_eq!(serde_json::to_value(query).unwrap()["via"], "claude_web_search");
            assert_eq!(query.search, words);
            assert_eq!(query.engine, Engine::Google);
            assert_eq!(query.outcome, Outcome::Served);
            assert!(query.results.unwrap() > 0);
            assert!(!snapshot.results[0].listed.is_empty());
            assert_eq!(snapshot.results[0].query_id, query.id);
            assert!(snapshot.results[0].listed.iter().any(|result| result.url == url));
            assert_eq!(query.carries, Some(0));
            assert_eq!(snapshot.pages[0].url, url);
            assert!(!snapshot.pages[0].making);
            assert_eq!(snapshot.pages[0].carries, Some(0));
            assert_eq!(serde_json::to_value(&snapshot.pages[0]).unwrap()["via"], "web_fetch");
            Ok(())
        },
    )).unwrap();
    server.join().unwrap();
}

#[path = "search/queries.rs"]
mod queries;

#[path = "search/pages.rs"]
mod pages;

#[path = "search/observations.rs"]
mod observations;
