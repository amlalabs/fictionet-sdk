//! The model client against an HTTP server on 127.0.0.1, through the SDK's
//! own HTTP client.

use fictionet_extras::models::{Https, Key};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use serde_json::{Value, json};
use web_world::pages::model::{Model, Provider};
use web_world::pages::prompts;

const KEY: &str = "sk-or-test-key";

/// What the server got: the request line, the headers (lowercased names)
/// and the JSON body.
type Received = (String, Vec<(String, String)>, Value);

/// Answers one request with `status` and `reply`.
fn serve_once(
    listener: TcpListener,
    status: u16,
    reply: Value,
) -> std::thread::JoinHandle<Received> {
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let mut headers = Vec::new();
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).unwrap();
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            let (name, value) = header.split_once(':').unwrap();
            headers.push((name.to_lowercase(), value.trim().to_owned()));
        }
        let length: usize = headers
            .iter()
            .find(|(name, _)| name == "content-length")
            .unwrap()
            .1
            .parse()
            .unwrap();
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        let reply = reply.to_string();
        let mut stream = stream;
        write!(
            stream,
            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
            Connection: close\r\n\r\n{reply}",
            reply.len()
        )
        .unwrap();
        (
            line.trim_end().to_owned(),
            headers,
            serde_json::from_slice(&body).unwrap(),
        )
    })
}

#[test]
fn a_model_answers_over_http() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin: http::Uri = format!("http://{}", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let reply = json!({
        "model": "answered/model",
        "choices": [{"message": {"content": "RESULT\nURL: https://a.com/x\nTITLE: A\nSNIPPET: a"}}],
        "usage": {"prompt_tokens": 12, "completion_tokens": 3, "cost": 0.0001},
    });
    let server = serve_once(listener, 200, reply);
    let (tx, rx) = std::sync::mpsc::channel();
    fictionet::block_on(fictionet::run(
        fictionet::Seed::from_u64(1),
        move |cx| async move {
            let https = Https::at(&cx, origin, "/api/v1/chat/completions")?;
            let key = Key::new("OPENROUTER_API_KEY", Some(KEY.into())).unwrap();
            let model = Model::new(
                Provider::OpenRouter,
                "some/model",
                "low",
                key,
                Arc::new(https),
            );
            let (answer, ledger) = model
                .ask(&cx, "system", "user", 50, prompts::read_search)
                .await;
            let answer = answer.map_err(|f| fictionet::Error::msg(f.error))?;
            tx.send((answer.fields, ledger.usage())).unwrap();
            Ok(())
        },
    ))
    .unwrap();
    let (search, usage) = rx.recv().unwrap();
    assert_eq!(search.results[0].url, "https://a.com/x");
    assert_eq!(usage.model, "answered/model");
    assert_eq!(
        (usage.input_tokens, usage.output_tokens, usage.cost),
        (Some(12), Some(3), Some(0.0001))
    );
    let (line, headers, body) = server.join().unwrap();
    assert_eq!(line, "POST /api/v1/chat/completions HTTP/1.1");
    let header = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(
        header("authorization"),
        Some(format!("Bearer {KEY}").as_str())
    );
    assert_eq!(header("content-type"), Some("application/json"));
    assert_eq!(body["model"], "some/model");
    assert_eq!(body["max_tokens"], 50);
    assert_eq!(body["reasoning"], json!({"effort": "low"}));
    assert_eq!(
        body["messages"][1],
        json!({"role": "user", "content": "user"})
    );
}

#[test]
fn an_http_failure_is_redacted_and_not_retried_when_permanent() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin: http::Uri = format!("http://{}", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = serve_once(
        listener,
        401,
        json!({"error": format!("Invalid key {KEY}: {KEY}")}),
    );
    let (tx, rx) = std::sync::mpsc::channel();
    fictionet::block_on(fictionet::run(
        fictionet::Seed::from_u64(1),
        move |cx| async move {
            let https = Https::at(&cx, origin, "/v1/messages")?;
            let key = Key::new("ANTHROPIC_API_KEY", Some(KEY.into())).unwrap();
            let model = Model::new(Provider::Anthropic, "", "", key, Arc::new(https));
            let (answer, ledger) = model
                .ask(&cx, "system", "user", 50, prompts::read_search)
                .await;
            tx.send((answer.err().unwrap().error, ledger.attempts))
                .unwrap();
            Ok(())
        },
    ))
    .unwrap();
    let (error, attempts) = rx.recv().unwrap();
    assert!(!error.contains(KEY), "{error}");
    assert!(
        error.contains("HTTP 401") && error.contains("<ANTHROPIC_API_KEY>"),
        "{error}"
    );
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].outcome, "http 401");
    assert!(!attempts[0].error.as_deref().unwrap().contains(KEY));
    let (_, headers, _) = server.join().unwrap();
    assert!(headers.contains(&("x-api-key".into(), KEY.into())));
}
