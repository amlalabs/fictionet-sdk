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
            let site = Model::at(
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
                site.clone()
                    .send(request("/v1/messages", "wrong"))
                    .await?
                    .status(),
                401
            );
            assert_eq!(
                site.clone()
                    .send(request("/v1/messages/batches", &placeholder))
                    .await?
                    .status(),
                404
            );
            let response = site
                .clone()
                .send(request("/v1/messages?beta=true", &placeholder))
                .await?;
            assert_eq!(response.status(), 200);
            let body = response.into_body().collect().await?.to_bytes();
            let text = std::str::from_utf8(&body).unwrap();
            assert!(!text.contains("sk-ant-api03-private"));
            assert!(text.contains("<ANTHROPIC_API_KEY>"));
            let response = site
                .clone()
                .send(request("/v1/messages", &placeholder))
                .await?;
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
                let site = Model::at(
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
                    .clone()
                    .send(request())
                    .await?
                    .into_body()
                    .collect()
                    .await?
                    .to_bytes();
                assert_eq!(body, response);
                let stopped = site.clone().send(request()).await?;
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

#[test]
fn cached_input_counts_once_toward_budget() {
    use std::io::Write;
    for (provider, path, usage, total) in [
        (
            Provider::Anthropic,
            "/v1/messages",
            json!({"input_tokens":1,"cache_read_input_tokens":1000,"cache_creation_input_tokens":1000,"output_tokens":1}),
            2001,
        ),
        (
            Provider::OpenAi,
            "/v1/responses",
            json!({"input_tokens":1000,"input_tokens_details":{"cached_tokens":900},"output_tokens":1}),
            1000,
        ),
    ] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            super::splice_tests::receive(&mut socket);
            let body = json!({"type":"message","content":[],"usage":usage}).to_string();
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            listener.set_nonblocking(true).unwrap();
            listener
        });
        let memory = Arc::new(fictionet_observe::Memory::default());
        fictionet::block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(12))
                .observer(Arc::new(fictionet_observe::Aggregate::new(memory.clone()))),
            |cx| async move {
                let credential =
                    Credential::api_key(&cx, Secret::new("key", "private-key".into())?);
                let key = credential.wire(provider, false);
                let model = Model::at(
                    &cx,
                    provider,
                    credential,
                    format!("http://{address}").parse()?,
                )?
                .budget(Budget::new().input_tokens(100));
                let request = || {
                    Request::post(path)
                        .header(provider.header(), &key)
                        .body(Body::from(r#"{"model":"small"}"#))
                        .unwrap()
                };
                let response = model.clone().send(request()).await?;
                assert_eq!(response.status(), 200);
                response.into_body().collect().await?;
                assert_eq!(model.ledger.lock().unwrap().input, total);
                let refused = model.clone().send(request()).await?;
                assert_eq!(refused.status(), provider.stop().status());
                assert_eq!(
                    refused.into_body().collect().await?.to_bytes(),
                    provider.stop().into_body().collect().await?.to_bytes()
                );
                assert_eq!(model.ledger.lock().unwrap().calls, 1);
                Ok(())
            },
        ))
        .unwrap();
        let listener = server.join().unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let calls = memory.checked_of("model", "call").unwrap();
        assert_eq!(calls.len(), 1);
        if provider == Provider::Anthropic {
            assert_eq!(calls[0].u64("input_tokens"), Some(1));
            assert_eq!(calls[0].u64("cache_read_input_tokens"), Some(1000));
            assert_eq!(calls[0].u64("cache_creation_input_tokens"), Some(1000));
        }
    }
}

async fn catalog_request(cx: &Cx, site: Model, request: Request<Body>) -> Response<Bytes> {
    use fictionet::stdlib::network::{ConnectionExt, ip, tcp};
    use fictionet::stdlib::world::net;
    use std::net::{Ipv4Addr, SocketAddr};
    let (attacher, attachments) = fictionet::attachments();
    net::Net::new()
        .host("catalog", |host| {
            host.at(Ipv4Addr::new(198, 18, 0, 1))
                .dns_name("chatgpt.com")
                .port_server(80, httpd::Server::new(site))
        })
        .start(cx, attachments)
        .unwrap();
    let end = attacher.attach("client").unwrap();
    let (t, _u, _i, _o) = ip::split_protocols(cx, end);
    let mut conn = tcp::endpoint(cx, t, Ipv4Addr::new(10, 0, 0, 2).into())
        .connect(cx, SocketAddr::from(([198, 18, 0, 1], 80)))
        .await
        .unwrap();
    let mut wire = format!(
        "{} {} HTTP/1.1\r\nHost: chatgpt.com\r\nConnection: close\r\n",
        request.method(),
        request.uri()
    );
    for (name, value) in request.headers() {
        wire.push_str(&format!("{name}: {}\r\n", value.to_str().unwrap()));
    }
    wire.push_str("Content-Length: 0\r\n\r\n");
    conn.write_all(cx, wire.as_bytes()).await.unwrap();
    let mut decoder = fictionet::stdlib::protocols::http1::Responses::new();
    decoder.expect_method(request.method().as_str()).unwrap();
    let mut stream = fictionet::stdlib::codec::Stream::new(decoder);
    let decoded = loop {
        if let Some(response) = stream.next() {
            break response.unwrap();
        }
        let mut buf = [0; 4096];
        let n = conn.read(cx, &mut buf).await.unwrap();
        assert_ne!(n, 0, "catalog connection ended before its response");
        assert_eq!(stream.push(&buf[..n]), n);
    };
    let mut response = Response::builder().status(decoded.head.status);
    for header in decoded.head.headers {
        response = response.header(header.name, header.value);
    }
    response.body(Bytes::from(decoded.body)).unwrap()
}

#[test]
fn codex_catalog_openrouter_requires_supplied_catalog() {
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(34)),
        |cx| async move {
            let key = "sk-or-v1-private";
            let mut credential = Credential::api_key(
                &cx,
                Secret::new("OPENAI_API_KEY", format!("sk-proj-{}", "a".repeat(128)))?,
            );
            credential.real = Secret::new("OPENROUTER_API_KEY", key.into())?;
            let mut model = Model::at(
                &cx,
                Provider::OpenAi,
                credential,
                "https://openrouter.ai".parse()?,
            )?;
            model.upstream_provider = Provider::OpenRouter;
            model.path_prefix = "/api";
            let origin = "https://chatgpt.com".parse()?;
            let error = model
                .codex_catalog(origin, None)
                .err()
                .expect("OpenRouter forwarding must be rejected")
                .to_string();
            assert!(error.contains("supplied catalog"), "{error}");
            assert!(!error.contains(key));
            let catalog = Bytes::from_static(br#"{"models":[]}"#);
            let site = model.codex_catalog(
                "https://chatgpt.com".parse()?,
                Some(("https://example.test/models".into(), catalog.clone())),
            )?;
            let response = site
                .send(
                    Request::get("/backend-api/codex/models")
                        .header(
                            "authorization",
                            model.credential.wire(Provider::OpenAi, false),
                        )
                        .body(Body::empty())?,
                )
                .await?;
            assert_eq!(response.status(), 200);
            assert_eq!(response.into_body().collect().await?.to_bytes(), catalog);
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn codex_catalog_forward_origin_without_fields() {
    let origin = "https://chatgpt.com/backend-api/codex/models";
    for existing in [false, true] {
        let mut response = Response::new(Body::empty());
        if existing {
            response.extensions_mut().insert(
                fictionet::events::Fields::new()
                    .with("forwarded", "https://chatgpt.com")
                    .with("other", "preserved"),
            );
        }
        set_catalog_origin(&mut response, origin);
        let fields = response
            .extensions()
            .get::<fictionet::events::Fields>()
            .unwrap();
        assert_eq!(
            fields.get("forwarded").and_then(|v| v.as_str()),
            Some(origin)
        );
        if existing {
            assert_eq!(
                fields.get("other").and_then(|v| v.as_str()),
                Some("preserved")
            );
        }
    }
}

#[test]
fn codex_catalog_answer_checks_credentials_and_passes_a_pause() {
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(31)),
        |cx| async move {
            let model = Model::at(
                &cx,
                Provider::OpenAi,
                Credential::api_key(&cx, Secret::new("OPENAI_API_KEY", "sk-private".into())?),
                "http://127.0.0.1:1".parse()?,
            )?
            .budget(Budget::new().calls(0));
            model.pause(true);
            let catalog = Bytes::from_static(br#"{"models":[]}"#);
            let site = model.codex_catalog(
                "http://127.0.0.1:1".parse()?,
                Some(("https://raw.githubusercontent.com".into(), catalog.clone())),
            )?;
            let request = |method, path, bearer: &str| {
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", bearer)
                    .body(Body::empty())
                    .unwrap()
            };
            let bearer = model.credential.wire(Provider::OpenAi, false);
            let response = catalog_request(
                &cx,
                site.clone(),
                request(
                    "GET",
                    "/backend-api/codex/models?client_version=0.163.0",
                    &bearer,
                ),
            )
            .await;
            assert_eq!(response.status(), 200);
            assert_eq!(response.headers()["content-type"], "application/json");
            assert_eq!(response.into_body(), catalog);
            assert_eq!(
                catalog_request(
                    &cx,
                    site.clone(),
                    request("GET", "/backend-api/codex/models", "Bearer wrong")
                )
                .await
                .status(),
                401
            );
            for (method, path) in [
                ("POST", "/backend-api/codex/responses"),
                ("GET", "/backend-api/wham/usage"),
                ("POST", "/backend-api/codex/models"),
            ] {
                assert_eq!(
                    catalog_request(&cx, site.clone(), request(method, path, &bearer))
                        .await
                        .status(),
                    404
                );
            }
            assert_eq!(model.ledger.lock().unwrap().calls, 0);
            cx.cancel();
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn codex_catalog_forward_swaps_key_and_preserves_response() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = std::thread::spawn(move || {
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
        let head = String::from_utf8(head).unwrap().to_lowercase();
        assert!(
            head.starts_with("get /backend-api/codex/models?client_version=0.163.0 http/1.1\r\n"),
            "{head}"
        );
        assert!(head.contains("authorization: bearer sk-private\r\n"));
        assert!(head.contains("if-none-match: old-catalog\r\n"));
        assert!(!head.contains("guest-cookie"));
        let body = r#"{"models":[],"message":"sk-private"}"#;
        write!(socket, "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nETag: catalog-version\r\nX-Message: sk-private\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    });
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(32)),
        |cx| async move {
            let model = Model::at(
                &cx,
                Provider::OpenAi,
                Credential::api_key(&cx, Secret::new("OPENAI_API_KEY", "sk-private".into())?),
                "http://127.0.0.1:1".parse()?,
            )?
            .budget(Budget::new().calls(0));
            model.pause(true);
            let site = model.codex_catalog(format!("http://{address}").parse()?, None)?;
            let request = |bearer: String| {
                Request::get("/backend-api/codex/models?client_version=0.163.0")
                    .header("authorization", bearer)
                    .header("if-none-match", "old-catalog")
                    .header("cookie", "guest-cookie")
                    .body(Body::empty())
                    .unwrap()
            };
            assert_eq!(
                catalog_request(&cx, site.clone(), request("Bearer wrong".into()))
                    .await
                    .status(),
                401
            );
            let model_call = Request::post("/backend-api/codex/responses")
                .header(
                    "authorization",
                    model.credential.wire(Provider::OpenAi, false),
                )
                .body(Body::empty())?;
            assert_eq!(
                catalog_request(&cx, site.clone(), model_call)
                    .await
                    .status(),
                404
            );
            let response = catalog_request(
                &cx,
                site,
                request(model.credential.wire(Provider::OpenAi, false)),
            )
            .await;
            assert_eq!(response.status(), 202);
            assert_eq!(response.headers()["etag"], "catalog-version");
            assert_eq!(response.headers()["x-message"], "<OPENAI_API_KEY>");
            let body = response.into_body();
            let decoded: Value = serde_json::from_slice(&body)?;
            assert_eq!(decoded["message"], "<OPENAI_API_KEY>");
            assert_eq!(model.ledger.lock().unwrap().calls, 0);
            cx.cancel();
            Ok(())
        },
    ))
    .unwrap();
    upstream.join().unwrap();
}

#[test]
fn codex_catalog_forward_origin_is_separate_from_model_calls() {
    struct Transport;
    impl web::Upstream for Transport {
        fn request(self: Arc<Self>, _: Request<Body>) -> web::UpstreamFuture {
            Box::pin(async { Ok(Response::new(Body::from(r#"{"models":[]}"#))) })
        }
    }
    fictionet::block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(33)),
        |cx| async move {
            let origin: http::Uri = "https://chatgpt.com".parse()?;
            let credential =
                Credential::api_key(&cx, Secret::new("OPENAI_API_KEY", "sk-private".into())?);
            let mut model = Model::with_forward(
                &cx,
                Provider::OpenAi,
                credential,
                web::forward(&cx, origin.clone(), Arc::new(Transport))?,
                "chatgpt.com".into(),
            );
            let mut catalog_site = model.codex_catalog(origin, None)?;
            catalog_site.forward = model.forward.clone();
            model.provider = Provider::ChatGpt;
            let bearer = model.credential.wire(Provider::ChatGpt, false);
            for catalog in [false, true] {
                let site = if catalog { &catalog_site } else { &model };
                let request = if catalog {
                    Request::get("/backend-api/codex/models?client_version=0.163.0")
                        .header("authorization", &bearer)
                        .body(Body::empty())?
                } else {
                    Request::post("/backend-api/codex/responses")
                        .header("authorization", &bearer)
                        .body(Body::from(r#"{"model":"gpt-5","input":"Hello"}"#))?
                };
                let response = site.clone().send(request).await?;
                let fields = response
                    .extensions()
                    .get::<fictionet::events::Fields>()
                    .unwrap();
                assert_eq!(
                    fields.get("forwarded").and_then(|value| value.as_str()),
                    Some(if catalog {
                        "https://chatgpt.com/backend-api/codex/models"
                    } else {
                        "https://chatgpt.com"
                    })
                );
                response.into_body().collect().await?;
            }
            Ok(())
        },
    ))
    .unwrap();
}
