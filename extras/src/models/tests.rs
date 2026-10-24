use super::*;

#[test]
fn claude_code_policy_limits_require_credentials() {
    fictionet::block_on(fictionet::run(
        fictionet::Seed::from_u64(1),
        |cx| async move {
            let credential =
                Credential::api_key(&cx, Secret::new("ANTHROPIC_API_KEY", "private-key".into())?);
            let key = credential.placeholder().to_owned();
            let site = Model::at(
                &cx,
                Provider::Anthropic,
                credential,
                "http://127.0.0.1:1".parse()?,
            )?;
            let path = "/api/claude_code/policy_limits";
            let response = site
                .clone()
                .send(
                    Request::get(path)
                        .header("x-api-key", &key)
                        .body(Body::empty())?,
                )
                .await?;
            assert_eq!(response.status(), 200);
            assert_eq!(response.headers()["content-type"], "application/json");
            let body = response.into_body().collect().await?.to_bytes();
            assert_eq!(body, r#"{"restrictions":{}}"#);
            for credential in [None, Some("wrong")] {
                let mut request = Request::get(path);
                if let Some(credential) = credential {
                    request = request.header("x-api-key", credential);
                }
                let response = site.clone().send(request.body(Body::empty())?).await?;
                assert_eq!(response.status(), 401);
                assert_eq!(response.headers()["content-type"], "application/json");
                let body = response.into_body().collect().await?.to_bytes();
                let body: Value = serde_json::from_slice(&body)?;
                assert_eq!(body["error"]["type"], "authentication_error");
            }
            let response = site
                .clone()
                .send(
                    Request::get("/api/claude_code/settings")
                        .header("x-api-key", &key)
                        .body(Body::empty())?,
                )
                .await?;
            assert_eq!(response.status(), 404);
            assert_eq!(site.ledger.lock().unwrap().calls, 0);
            Ok(())
        },
    ))
    .unwrap();
}

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
        write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: Text/Event-Stream; Charset=UTF-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
        for byte in body.bytes() {
            socket.write_all(&[byte]).unwrap();
        }
    });

    fictionet::block_on(fictionet::run(
        fictionet::Seed::from_u64(1),
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
            fictionet::Seed::from_u64(2),
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

        fictionet::block_on(fictionet::run(
            fictionet::Seed::from_u64(12),
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
    }
}

async fn catalog_request(cx: &Cx, site: Model, request: Request<Body>) -> Response<Bytes> {
    use fictionet::stdlib::network::{ConnectionExt, ip, tcp};
    use fictionet::stdlib::world::net;
    use std::net::{Ipv4Addr, SocketAddr};
    let (attacher, attachments) = fictionet::attachments();
    net::Net::new()
        .host("catalog", |host| {
            host.at(Ipv4Addr::new(104, 18, 0, 1))
                .dns_name("chatgpt.com")
                .port_server(80, httpd::Server::new(site))
        })
        .start(cx, attachments)
        .unwrap();
    let end = attacher.attach("client").unwrap();
    let (t, _u, _i, _o) = ip::split_protocols(cx, end);
    let mut conn = tcp::endpoint(cx, t, Ipv4Addr::new(10, 0, 0, 2).into())
        .connect(cx, SocketAddr::from(([104, 18, 0, 1], 80)))
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
        fictionet::Seed::from_u64(34),
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
                            model
                                .credential
                                .as_ref()
                                .unwrap()
                                .wire(Provider::OpenAi, false),
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
fn codex_catalog_answer_checks_credentials_and_passes_a_pause() {
    fictionet::block_on(fictionet::run(
        fictionet::Seed::from_u64(31),
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
            let bearer = model
                .credential
                .as_ref()
                .unwrap()
                .wire(Provider::OpenAi, false);
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
        fictionet::Seed::from_u64(32),
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
                    model
                        .credential
                        .as_ref()
                        .unwrap()
                        .wire(Provider::OpenAi, false),
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
                request(
                    model
                        .credential
                        .as_ref()
                        .unwrap()
                        .wire(Provider::OpenAi, false),
                ),
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
        fictionet::Seed::from_u64(33),
        |cx| async move {
            let origin: http::Uri = "https://chatgpt.com".parse()?;
            let credential =
                Credential::api_key(&cx, Secret::new("OPENAI_API_KEY", "sk-private".into())?);
            let mut model = Model::with_forward(
                &cx,
                Provider::OpenAi,
                Some(credential),
                web::forward(&cx, origin.clone(), Arc::new(Transport))?,
                "chatgpt.com".into(),
            );
            let mut catalog_site = model.codex_catalog(origin, None)?;
            catalog_site.forward = model.forward.clone();
            model.provider = Provider::ChatGpt;
            let bearer = model
                .credential
                .as_ref()
                .unwrap()
                .wire(Provider::ChatGpt, false);
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
                response.into_body().collect().await?;
            }
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn guest_credentials_follow_each_request_without_replacement() {
    use std::io::Write;
    for provider in [Provider::Anthropic, Provider::OpenAi, Provider::ChatGpt] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for token in ["first-session", "refreshed-session"] {
                let (mut socket, _) = listener.accept().unwrap();
                let (head, body) = super::splice_tests::exchange(&mut socket);
                assert!(head.contains(&format!("authorization: Bearer {token}\r\n")));
                assert!(head.contains("chatgpt-account-id: own-account\r\n"));
                assert!(head.contains("anthropic-beta: oauth-2025-04-20\r\n"));
                assert!(head.contains("cookie: session=own-cookie\r\n"));
                assert_eq!(body["model"], "small");
                let body = r#"{"model":"small","usage":{}}"#;
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        fictionet::block_on(fictionet::run(
            fictionet::Seed::from_u64(1),
            |cx| async move {
                let model = Model::guest_at(&cx, provider, format!("http://{address}").parse()?)?;
                assert!(model.guest_env().is_empty());
                let path = match provider {
                    Provider::Anthropic => "/v1/messages",
                    Provider::ChatGpt => "/backend-api/codex/responses",
                    _ => "/v1/responses",
                };
                assert_eq!(
                    model
                        .clone()
                        .send(Request::post(path).body(Body::from("{}"))?)
                        .await?
                        .status(),
                    401
                );
                for path in [
                    "/api/oauth/../../v1/messages",
                    "/api/oauth/%2e%2e/%2e%2e/v1/messages",
                ] {
                    let response = model
                        .clone()
                        .send(
                            Request::post(path)
                                .header("authorization", "Bearer own-session")
                                .body(Body::from("{}"))?,
                        )
                        .await?;
                    assert_eq!(response.status(), 404);
                }
                for token in ["first-session", "refreshed-session"] {
                    let path = if provider == Provider::Anthropic && token == "refreshed-session" {
                        "/api/oauth/cli/create_api_key"
                    } else {
                        path
                    };
                    let response = model
                        .clone()
                        .send(
                            Request::post(path)
                                .header("authorization", format!("Bearer {token}"))
                                .header("chatgpt-account-id", "own-account")
                                .header("anthropic-beta", "oauth-2025-04-20")
                                .header("cookie", "session=own-cookie")
                                .body(Body::from(r#"{"model":"small"}"#))?,
                        )
                        .await?;
                    assert_eq!(response.status(), 200);
                    response.into_body().collect().await?;
                }
                Ok(())
            },
        ))
        .unwrap();
        server.join().unwrap();
    }
}

#[test]
fn remote_content_and_mixed_server_tools_never_reach_the_transport() {
    struct Transport;
    impl web::Upstream for Transport {
        fn request(self: Arc<Self>, _: Request<Body>) -> web::UpstreamFuture {
            panic!("refused request entered the upstream transport")
        }
    }
    fictionet::block_on(fictionet::run(fictionet::Seed::from_u64(4), |cx| async move {
        for (provider, path) in [
            (Provider::Anthropic, "/v1/messages"),
            (Provider::Anthropic, "/v1/messages/count_tokens"),
            (Provider::OpenAi, "/v1/responses"),
            (Provider::OpenAi, "/v1/chat/completions"),
            (Provider::ChatGpt, "/backend-api/codex/responses"),
            (Provider::OpenRouter, "/api/v1/chat/completions"),
            (Provider::Gemini, "/v1beta/models/gemini-flash:generateContent"),
        ] {
            let model = Model::with_forward(&cx, provider, None,
                web::forward(&cx, format!("https://{}", provider.host()).parse()?, Arc::new(Transport))?,
                provider.host().into()).search(Arc::new(ValidationPages));
            let content = [
                json!({"type":"image","source":{"type":"url","url":"https://example.com/image"}}),
                json!({"type":"document","source":{"type":"url","url":"https://example.com/file"}}),
                json!({"type":"image_url","image_url":{"url":"https://example.com/image"}}),
                json!({"type":"input_image","image_url":"https://example.com/image"}),
                json!({"type":"input_file","file_url":"https://example.com/file"}),
                json!({"type":"input_file","file_id":"external-file"}),
                json!({"type":"file","file":{"file_data":"https://example.com/file"}}),
                json!({"fileData":{"fileUri":"https://example.com/file"}}),
                json!({"file_data":{"file_uri":"https://example.com/file"}}),
            ];
            let mut blocked = Vec::new();
            for block in content {
                blocked.push(json!({"model":"small", "messages":[{"role":"user","content":[block.clone()]}]}));
                blocked.push(json!({"model":"small", "input":[{"role":"user","content":[block.clone()]}]}));
                blocked.push(json!({"contents":[{"role":"user","parts":[block.clone()]}]}));
                blocked.push(json!({"model":"small", "messages":[{"role":"user","content":[{"type":"tool_result", "tool_use_id":"local", "content":[block]}]}]}));
            }
            for tool in [json!({"type":"future_server_tool"}), json!({"type":"web_search_future"}), json!({"googleSearch":{}}), json!({"urlContext":{}}), json!({"type":"mcp", "server_url":"https://example.com"})] {
                blocked.push(json!({"model":"small", "tools":[tool.clone()]}));
                blocked.push(json!({"model":"small", "tools":[{"type":"web_search_20250305", "name":"web_search"},tool.clone()]}));
                blocked.push(json!({"model":"small", "tools":[{"type":"web_search"},tool]}));
            }
            blocked.extend([
                json!({"model":"small", "prompt":{"id":"pmpt_example", "variables":{"photo":{"type":"input_image", "image_url":"https://example.org/pixel.png", "detail":"auto"}}}}),
                json!({"model":"small", "prompt":{"id":"pmpt_example", "variables":{"document":{"type":"input_file", "file_url":"https://example.org/private.pdf"}}}}),
                json!({"model":"small", "prompt":{"id":"pmpt_example"}}),
                json!({"model":"small", "future_inputs":{"image_url":"https://example.org/pixel.png"}}),
                json!({"messages":[{"role":"user", "content":[{"type":"text", "text":"hello", "future_source":{"url":"https://example.org/pixel.png"}}]}]}),
                json!({"model":"small", "plugins":[{"id":"web"}], "tools":[{"type":"web_search_20250305","name":"web_search"}]}),
                json!({"model":"small", "mcp_servers":[{"url":"https://example.com"}], "tools":[{"type":"web_search"}]}),
                json!({"model":"small:online"}),
                json!({"models":["small:online"]}),
                json!({"safeguards":[{"type":"remote_fetch", "url":"https://example.org/file"}]}),
                json!({"safeguards":[{"type":"dangerous_tool_use", "classifier_context":{}, "url":"https://example.org/file"}]}),
                json!({"model":"small:online:free"}),
                json!({"model":"small-search-preview"}),
            ]);
            for body in blocked {
                let request = Request::post(path).header("authorization", "Bearer local-token").header("x-api-key", "local-token").header("x-goog-api-key", "local-token").body(Body::from(body.to_string()))?;
                let response = model.clone().send(request).await?;
                assert_eq!(response.status(), 400, "{provider:?} {body}");
            }
        }
        Ok(())
    })).unwrap();
}

#[test]
fn inline_content_and_client_url_arguments_stay_usable() {
    for (provider, path, body) in [
        (
            Provider::Anthropic,
            "/v1/messages",
            json!({"messages":[{"role":"user","content":"Read https://example.com"}]}),
        ),
        (
            Provider::Anthropic,
            "/v1/messages",
            json!({"messages":[{"role":"user","content":"Research passkeys", "output_config":{"effort":"medium"}}], "output_config":{"effort":"medium"}, "safeguards":[{"type":"dangerous_tool_use","classifier_context":{"permission_mode":"auto","trusted_directories":{"primary":{"path":"/home/analyst"}}}}], "diagnostics":{"previous_message_id":null}}),
        ),
        (
            Provider::Anthropic,
            "/v1/messages",
            json!({"messages":[{"role":"assistant","content":[{"type":"tool_use","name":"WebFetch","input":{"url":"https://example.com"}}]}]}),
        ),
        (
            Provider::Anthropic,
            "/v1/messages",
            json!({"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"YQ=="}}]}]}),
        ),
        (
            Provider::OpenAi,
            "/v1/responses",
            json!({"input":[{"role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,YQ=="},{"type":"input_file","file_data":"data:application/pdf;base64,YQ=="}]}]}),
        ),
        (
            Provider::Gemini,
            "/v1beta/models/flash:generateContent",
            json!({"contents":[{"parts":[{"inlineData":{"mimeType":"image/png","data":"YQ=="}}]}]}),
        ),
    ] {
        assert!(safe_request(provider, path, &body, false), "{body}");
    }
}

#[test]
fn anthropic_client_tools_accept_both_wire_spellings() {
    for provider in [Provider::Anthropic, Provider::OpenRouter] {
        let path = if provider == Provider::Anthropic {
            "/v1/messages"
        } else {
            "/api/v1/messages"
        };
        for typed in [false, true] {
            let mut tool = json!({"name":"WebFetch", "description":"Read a page", "input_schema":{"type":"object", "properties":{"url":{"type":"string"}}}});
            if typed {
                tool["type"] = json!("custom");
            }
            assert!(safe_request(
                provider,
                path,
                &json!({"tools":[tool]}),
                false
            ));
        }
    }
}

#[test]
fn deferred_client_tool_references_preserve_the_provider_boundary() {
    let mut body = json!({
        "tools": [{"name":"WebFetch", "defer_loading":true, "input_schema":{"type":"object", "properties":{"url":{"type":"string"}}}}],
        "messages": [
            {"role":"assistant", "content":[{"type":"tool_use", "id":"discovery", "name":"ToolSearch", "input":{"query":"WebFetch"}, "caller":{"type":"direct"}}]},
            {"role":"user", "content":[{"type":"tool_result", "tool_use_id":"discovery", "content":[{"type":"tool_reference", "tool_name":"WebFetch"}]}]}
        ]
    });
    assert!(safe_request(
        Provider::Anthropic,
        "/v1/messages",
        &body,
        false
    ));
    body["messages"][1]["content"][0]["content"]
        .as_array_mut()
        .unwrap()
        .push(
            json!({"type":"image", "source":{"type":"url", "url":"https://example.com/image.png"}}),
        );
    assert!(!safe_request(
        Provider::Anthropic,
        "/v1/messages",
        &body,
        false
    ));
    body["messages"][1]["content"][0]["content"]
        .as_array_mut()
        .unwrap()
        .pop();
    body["tools"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"web_fetch_20260209", "name":"web_fetch"}));
    assert!(!safe_request(
        Provider::Anthropic,
        "/v1/messages",
        &body,
        false
    ));
}

pub(super) struct ValidationPages;
impl Engine for ValidationPages {
    fn serves(&self, _: &str) -> bool {
        true
    }
    fn search(
        self: Arc<Self>,
        _: Cx,
        _: String,
        _: tools::Domains,
    ) -> tools::Answer<Vec<crate::search::Result>> {
        panic!("refused before search")
    }
    fn fetch(self: Arc<Self>, _: Cx, _: String) -> tools::Answer<tools::Page> {
        panic!("refused before fetch")
    }
}

#[test]
fn the_provider_receives_only_the_validated_json_value() {
    struct Transport;
    impl web::Upstream for Transport {
        fn request(self: Arc<Self>, request: Request<Body>) -> web::UpstreamFuture {
            Box::pin(async move {
                let bytes = request.into_body().collect().await?.to_bytes();
                let wire = std::str::from_utf8(&bytes).unwrap();
                assert!(!wire.contains("web_search_preview"));
                assert!(!wire.contains("https://example.com"));
                let body: Value = serde_json::from_slice(&bytes)?;
                assert_eq!(body["tools"][0]["type"], "function");
                assert_eq!(body["input"], "local text");
                Ok(Response::new(Body::from(r#"{"usage":{}}"#)))
            })
        }
    }
    fictionet::block_on(fictionet::run(fictionet::Seed::from_u64(5), |cx| async move {
        let model = Model::with_forward(&cx, Provider::OpenAi, None,
            web::forward(&cx, "https://api.openai.com".parse()?, Arc::new(Transport))?, "api.openai.com".into());
        let body = r#"{"model":"small","tools":[{"type":"web_search_preview"}],"input":[{"role":"user","content":[{"type":"input_image","image_url":"https://example.com/image"}]}],"tools":[{"type":"function","name":"local","parameters":{}}],"input":"local text"}"#;
        let response = model.send(Request::post("/v1/responses").header("authorization", "Bearer local-token").body(Body::from(body))?).await?;
        assert_eq!(response.status(), 200);
        response.into_body().collect().await?;
        Ok(())
    })).unwrap();
}

#[tokio::test]
async fn long_lived_claude_token_stays_on_the_host() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let router = axum::Router::new().route(
            "/v1/messages",
            axum::routing::post(|headers: http::HeaderMap| async move {
                assert_eq!(headers["authorization"], "Bearer sk-ant-oat01-host-private");
                assert_eq!(headers["anthropic-beta"], "oauth-2025-04-20");
                assert!(!headers.contains_key("x-api-key"));
                assert!(!headers.contains_key("cookie"));
                axum::Json(json!({"content":[{"type":"text","text":"sk-ant-oat01-host-private"}]}))
            }),
        );
        axum::serve(listener, router).await.unwrap();
    });
    fictionet::run(fictionet::Seed::from_u64(91), |cx| async move {
        let credential = Credential::claude_token(&cx, Secret::new("Claude OAuth token", "sk-ant-oat01-host-private".into())?)?;
        assert!(credential.placeholder().starts_with("sk-ant-oat01-"));
        assert_ne!(credential.placeholder(), "sk-ant-oat01-host-private");
        let bearer = format!("Bearer {}", credential.placeholder());
        let site = Model::at(&cx, Provider::Anthropic, credential, format!("http://{address}").parse()?)?;
        assert_eq!(site.guest_env()[0].0, "CLAUDE_CODE_OAUTH_TOKEN");
        for authorization in [None, Some("Bearer wrong")] {
            let mut request = Request::post("/v1/messages");
            if let Some(authorization) = authorization { request = request.header("authorization", authorization); }
            assert_eq!(site.clone().send(request.body(Body::from("{}"))?).await?.status(), 401);
        }
        let response = site.clone().send(Request::get("/api/claude_code/policy_limits").header("authorization", &bearer).body(Body::empty())?).await?;
        assert_eq!(response.status(), 200);
        for path in ["/v1/files", "/api/oauth/cli/create_api_key", "/v1/oauth/token"] {
            assert_eq!(site.clone().send(Request::post(path).header("authorization", &bearer).body(Body::from("{}"))?).await?.status(), 404);
        }
        let response = site.send(Request::post("/v1/messages")
            .header("authorization", bearer).header("anthropic-beta", "oauth-2025-04-20")
            .header("x-api-key", "unused").header("cookie", "unused")
            .body(Body::from(r#"{"model":"claude","max_tokens":10,"messages":[{"role":"user","content":"Hello"}]}"#))?).await?;
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await?.to_bytes();
        let body = String::from_utf8_lossy(&body);
        assert!(!body.contains("sk-ant-oat01-host-private"));
        assert!(body.contains("<Claude OAuth token>"));
        Ok(())
    }).await.unwrap();
    server.abort();
}

#[test]
fn custom_client_tool_formats_remain_local_inputs() {
    let tool = json!({"type":"custom","name":"local_tool","format":{"type":"text"}});
    assert!(safe_request(
        Provider::OpenAi,
        "/v1/responses",
        &json!({"input":"Read https://sky.org", "tools":[tool.clone()]}),
        false
    ));
    let mut remote = tool;
    remote["server_url"] = json!("https://sky.org/mcp");
    assert!(!safe_request(
        Provider::OpenAi,
        "/v1/responses",
        &json!({"input":"Read", "tools":[remote]}),
        false
    ));
}

#[test]
fn protocols_reject_foreign_controls() {
    for (provider, path, valid, foreign) in [
        (
            Provider::Anthropic,
            "/v1/messages",
            json!({"messages":[]}),
            json!({"input":"text","conversation":"old","modalities":["audio"],"audio":{},"generationConfig":{},"provider":{}}),
        ),
        (
            Provider::OpenAi,
            "/v1/responses",
            json!({"input":"text"}),
            json!({"messages":[],"system":"text","thinking":{},"max_tokens":1,"generationConfig":{}}),
        ),
        (
            Provider::OpenAi,
            "/v1/chat/completions",
            json!({"messages":[]}),
            json!({"input":"text","instructions":"text","provider":{},"thinking":{},"max_output_tokens":1}),
        ),
        (
            Provider::Gemini,
            "/v1beta/models/flash:generateContent",
            json!({"contents":[]}),
            json!({"messages":[],"system":"text","input":"text","stream":true,"max_tokens":1}),
        ),
    ] {
        assert!(safe_request(provider, path, &valid, false));
        for (key, value) in foreign.as_object().unwrap() {
            let mut body = valid.clone();
            body[key] = value.clone();
            assert!(
                !safe_request(provider, path, &body, false),
                "{provider:?}: {key}"
            );
        }
    }
}

#[test]
fn account_policy_messages_remain_executable() {
    let body = json!({
        "messages":[
            {"role":"user","content":"Research passkeys"},
            {"role":"system","content":[{"type":"text","text":"Use current account policy","cache_control":{"type":"ephemeral"}}],"output_config":{"effort":"medium"}}
        ],
        "thinking":{"type":"adaptive"},
        "output_config":{"effort":"medium"}
    });
    assert!(safe_request(
        Provider::Anthropic,
        "/v1/messages",
        &body,
        false
    ));
}

#[test]
fn responses_messages_use_their_own_roles() {
    for tagged in [false, true] {
        for role in [
            "system",
            "developer",
            "user",
            "assistant",
            "tool",
            "function",
            "model",
            "unknown",
        ] {
            let mut message = json!({"role":role, "content":"Local text"});
            if tagged {
                message["type"] = json!("message");
            }
            let valid = safe_request(
                Provider::OpenAi,
                "/v1/responses",
                &json!({"input":[message]}),
                false,
            );
            assert_eq!(
                valid,
                matches!(role, "system" | "developer" | "user" | "assistant"),
                "{tagged} {role}"
            );
        }
    }
}
