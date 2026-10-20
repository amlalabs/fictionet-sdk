use super::*;

#[test]
fn paths_are_exact() {
    for (provider, path) in [
        (Provider::Anthropic, "/v1/messages"),
        (Provider::OpenAi, "/v1/responses"),
        (Provider::OpenRouter, "/api/v1/messages"),
        (
            Provider::Gemini,
            "/v1beta/models/gemini-flash:generateContent",
        ),
    ] {
        assert!(provider.allows(path));
        assert!(!provider.allows(&format!("{path}/batches")));
        assert!(!provider.allows("/v1/files"));
        assert!(!provider.allows("/v1beta/models/../files:generateContent"));
    }
}

#[test]
fn credential_formatting_does_not_disclose_value() {
    let secret = Secret::new("ANTHROPIC_API_KEY", "sk-ant-api03-private".into()).unwrap();
    assert_eq!(format!("{secret:?}"), "<ANTHROPIC_API_KEY>");
    assert_eq!(
        secret.redact("failure sk-ant-api03-private"),
        "failure <ANTHROPIC_API_KEY>"
    );
}

#[test]
fn swap_stream_and_budget_against_upstream() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut buf = [0; 4096];
        loop {
            let n = socket.read(&mut buf).unwrap();
            assert_ne!(n, 0);
            request.extend_from_slice(&buf[..n]);
            if let Some(head) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&request[..head]);
                let size: usize = headers
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(str::to_owned)
                    })
                    .unwrap()
                    .parse()
                    .unwrap();
                if request.len() >= head + 4 + size {
                    break;
                }
            }
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.contains("x-api-key: sk-ant-api03-private"));
        assert!(request.contains("anthropic-beta: keep-this"));
        assert!(request.contains("accept-encoding: identity"));
        assert!(!request.contains("guest-cookie"));
        let body = concat!(
            "event: message_start\ndata: {\"message\":{\"usage\":{\"input_tokens\":7}}}\n\n",
            "event: content_block_delta\ndata: {\"delta\":{\"text\":\"sk-ant-api03-private\"}}\n\n",
            "event: message_delta\ndata: {\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":3}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
        );
        write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
        for byte in body.bytes() {
            socket.write_all(&[byte]).unwrap();
        }
    });
    let memory = Arc::new(fictionet_observe::Memory::default());
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(1))
            .observer(Arc::new(fictionet_observe::Aggregate::new(memory.clone()))),
        |cx| async move {
            let credential = Credential::api_key(
                &cx,
                Secret::new("ANTHROPIC_API_KEY", "sk-ant-api03-private".into())?,
            );
            let placeholder = credential.placeholder().to_owned();
            assert_eq!(placeholder.len(), "sk-ant-api03-private".len());
            assert_ne!(placeholder, "sk-ant-api03-private");
            let mut site = Model::at(
                &cx,
                Provider::Anthropic,
                credential,
                format!("http://{address}").parse()?,
            )?
            .budget(Budget::new().calls(1));
            let request = |path: &str, key: &str| {
                Request::post(path)
                    .header("x-api-key", key)
                    .header("anthropic-beta", "keep-this")
                    .header("cookie", "guest-cookie")
                    .body(Body::from(r#"{"model":"claude-haiku","stream":true}"#))
                    .unwrap()
            };
            assert_eq!(
                site.call(request("/v1/messages", "wrong")).await?.status(),
                401
            );
            assert_eq!(
                site.call(request("/v1/messages/batches", &placeholder))
                    .await?
                    .status(),
                404
            );
            let response = site
                .call(request("/v1/messages?beta=true", &placeholder))
                .await?;
            assert_eq!(response.status(), 200);
            let body = response.into_body().collect().await?.to_bytes();
            let text = std::str::from_utf8(&body).unwrap();
            assert!(!text.contains("sk-ant-api03-private"));
            assert!(text.contains("<ANTHROPIC_API_KEY>"));
            let response = site.call(request("/v1/messages", &placeholder)).await?;
            assert_eq!(response.status(), 400);
            assert_eq!(site.ledger.lock().unwrap().input, 7);
            assert_eq!(site.ledger.lock().unwrap().output, 3);
            Ok(())
        },
    ))
    .unwrap();
    upstream.join().unwrap();
    let calls = memory.checked_of("model", "call").unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].u64("input_tokens"), Some(7));
    assert_eq!(calls[0].u64("output_tokens"), Some(3));
    assert_eq!(calls[0].str("credential"), Some("placeholder"));
    let bodies = memory.checked_of("model", "body").unwrap();
    assert!(!bodies.is_empty());
    let mut response = Vec::new();
    for event in bodies
        .iter()
        .filter(|e| e.str("direction") == Some("response"))
    {
        response.extend(
            fictionet::stdlib::codec::base64::decode(
                event.str("data").unwrap().as_bytes(),
                fictionet::stdlib::codec::base64::Padding::Canonical,
            )
            .unwrap(),
        );
    }
    let response = String::from_utf8(response).unwrap();
    assert!(response.contains("<ANTHROPIC_API_KEY>"));
    assert!(!response.contains("sk-ant-api03-private"));
    for event in memory.checked_all().unwrap() {
        assert!(!event.to_line().unwrap().contains("sk-ant-api03-private"));
    }
}

#[test]
fn bearer_and_google_keys_and_usage() {
    use std::io::{Read, Write};
    for (provider, path, header, response) in [
        (
            Provider::OpenAi,
            "/v1/responses",
            "authorization: Bearer private-key",
            r#"{"status":"completed","usage":{"input_tokens":11,"output_tokens":4}}"#,
        ),
        (
            Provider::OpenRouter,
            "/api/v1/chat/completions",
            "authorization: Bearer private-key",
            r#"{"choices":[{"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":4,"cost":0.02}}"#,
        ),
        (
            Provider::Gemini,
            "/v1beta/models/gemini-flash:generateContent",
            "x-goog-api-key: private-key",
            r#"{"usageMetadata":{"promptTokenCount":11,"candidatesTokenCount":4}}"#,
        ),
    ] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            loop {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8(request).unwrap();
            assert!(text.contains(header));
            let size: usize = text
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .unwrap()
                .parse()
                .unwrap();
            socket.read_exact(&mut vec![0; size]).unwrap();
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).unwrap();
        });
        fictionet::block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(2)),
            |cx| async move {
                let credential = Credential::api_key(
                    &cx,
                    Secret::new(provider.key_variable(), "private-key".into())?,
                );
                let key = credential.wire(provider, false);
                let mut site = Model::at(
                    &cx,
                    provider,
                    credential,
                    format!("http://{address}").parse()?,
                )?
                .budget(Budget::new().output_tokens(4));
                let request = || {
                    Request::post(path)
                        .header(provider.header(), &key)
                        .body(Body::from(r#"{"model":"small"}"#))
                        .unwrap()
                };
                let body = site
                    .call(request())
                    .await?
                    .into_body()
                    .collect()
                    .await?
                    .to_bytes();
                assert_eq!(body, response);
                let stopped = site.call(request()).await?;
                assert_eq!(
                    stopped.status().as_u16(),
                    if provider == Provider::OpenRouter {
                        402
                    } else {
                        429
                    }
                );
                assert_eq!(site.ledger.lock().unwrap().input, 11);
                assert_eq!(site.ledger.lock().unwrap().output, 4);
                Ok(())
            },
        ))
        .unwrap();
        thread.join().unwrap();
    }
}
