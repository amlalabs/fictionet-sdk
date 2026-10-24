use super::*;
use fictionet::{
    Cx,
    stdlib::{
        codec::Wire,
        protocols::{
            dns::rr::{RData, RecordType},
            http1,
        },
    },
};
use fictionet_test_support::sandbox::{self, Machine, machine};
use http_body_util::BodyExt;
use serde_json::json;
use tower_service::Service;

fn pages() -> Arc<Pages> {
    Arc::new(
        Pages::copied(
            web_world::pages::Seed::builtin("web").unwrap(),
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../extras/tests/fixtures"),
            &["https://sky.org/".into()],
            None,
        )
        .unwrap(),
    )
}
async fn fetch(cx: &Cx, machine: &Machine, host: &str, path: &str, start: std::time::SystemTime) {
    let dns = machine
        .lookup(cx, "10.0.0.1".parse().unwrap(), host, RecordType::A)
        .await
        .unwrap();
    let address = dns
        .answers
        .iter()
        .find_map(|r| match r.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .unwrap();
    let mut connection = machine
        .tls(cx, (address, 443).into(), host, None, start)
        .await
        .unwrap();
    let request = http1::Request::parse(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Firefox/1\r\n\r\n").as_bytes(),
    )
    .unwrap();
    let response = sandbox::request(cx, &mut connection, &request)
        .await
        .unwrap();
    assert_eq!(response.head.status, 200);
}

#[tokio::test]
async fn real_search_page_and_dns_facts_reach_the_owned_views_without_an_observer() {
    let pages = pages();
    let (_, (mut observations, _)) = Page::new(&pages, false);
    fictionet::lab(fictionet::Seed::from_u64(7),move |cx|async move {
        let seed=pages.seed().clone();
        let start=web_world::world_start(&seed.date)?;
        let world=web_world::World {pages:pages.clone(),..web_world::World::new(&cx,seed,start)?};
        let (attacher,attachments)=fictionet::attachments();
        let log=Arc::new(fictionet_extras::log::Log::new(Box::new(std::io::sink()),&[],|s|s));
        let net=crate::network::build(&world,&cx,log, None)?;
        net.start(&cx,attachments)?;
        let client=machine(&cx,attacher.attach("workstation")?,"10.0.0.2".parse::<std::net::Ipv4Addr>()?);
        fetch(&cx,&client,"www.google.com","/search?q=black+hole",start).await;
        fetch(&cx,&client,"sky.org","/black-hole",start).await;
        client.lookup(&cx,"10.0.0.1".parse()?,"wiki.corp",RecordType::A).await?;
        assert!(client.tcp.connect(&cx,"1.1.1.1:443".parse()?).await.is_err());
        let mut views=Views::default();
        while let Ok(observation)=observations.try_recv() {views.push(observation);}
        let current=views.current();
        let google=current.sites.iter().find(|s|s.host=="www.google.com").unwrap();
        assert!(google.address.is_some());
        assert_eq!(google.searches.len(),1);
        assert_eq!(google.searches[0].query,"black hole");
        assert_eq!(google.searches[0].results.len(),1);
        assert_eq!(google.searches[0].results[0].url,"https://sky.org/black-hole");
        let site=current.sites.iter().find(|s|s.host=="sky.org").unwrap();
        assert_eq!(site.requests.len(),1);
        let request=&site.requests[0];
        assert_eq!(request.path,"/black-hole");
        assert_eq!(request.status,200);
        assert!(request.has_preview);
        assert!(views.preview(&"https://sky.org/black-hole".parse().unwrap(),current.at_ms).unwrap().text().unwrap().contains("bends spacetime"));
        assert!(matches!(request.source,PageSource::Copy { .. }));
        assert_eq!(request.headers,vec![("host".into(),"sky.org".into()),("user-agent".into(),"Firefox/1".into())]);
        assert!(current.activity.iter().any(|row|matches!(&row.fact,SearchObs::Resolved {name,address:None} if name.to_ascii()=="wiki.corp")));
        assert!(current.activity.iter().any(|row|matches!(&row.fact,SearchObs::NoRoute {from,to} if *from == "10.0.0.2".parse::<std::net::IpAddr>().unwrap() && *to == "1.1.1.1".parse::<std::net::IpAddr>().unwrap())));
        cx.cancel();
        Ok(())
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_reader_loads_a_complete_compressed_article_from_the_corpus() {
    use fictionet_demo::kit::{RunDir, shot};
    use fictionet_extras::warc;
    use std::{io::Write, time::Duration};
    let root = RunDir::new(&std::env::temp_dir(), "search-reader").unwrap();
    let document = format!(
        "<html><head><title>Supply chain security</title><style>{}</style></head><body><main><h1>Supply chain security</h1><p>Pin actions to immutable commits.</p><p>Review changes to build credentials.</p></main></body></html>",
        " ".repeat(200_000)
    );
    let mut compressed = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    compressed.write_all(document.as_bytes()).unwrap();
    warc::Archive::default()
        .append(
            &root.path().join("pages.warc.gz"),
            "https://sky.org/article",
            &warc::Response {
                status: http::StatusCode::OK,
                headers: http::HeaderMap::from_iter([
                    (http::header::CONTENT_TYPE, "text/html".parse().unwrap()),
                    (http::header::CONTENT_ENCODING, "gzip".parse().unwrap()),
                ]),
                body: compressed.finish().unwrap().into(),
            },
        )
        .unwrap();
    let pages = Arc::new(
        Pages::copied(
            web_world::pages::Seed::builtin("web").unwrap(),
            root.path(),
            &["https://sky.org/article".into()],
            None,
        )
        .unwrap(),
    );
    let (page, (mut observations, _)) = Page::new(&pages, true);
    fictionet::lab(fictionet::Seed::from_u64(7), move |cx| async move {
        let seed = pages.seed().clone();
        let start = web_world::world_start(&seed.date)?;
        let world = web_world::World {
            pages,
            ..web_world::World::new(&cx, seed, start)?
        };
        let (attacher, attachments) = fictionet::attachments();
        let log = Arc::new(fictionet_extras::log::Log::new(
            Box::new(std::io::sink()),
            &[],
            |s| s,
        ));
        crate::network::build(&world, &cx, log, None)?.start(&cx, attachments)?;
        let client = machine(
            &cx,
            attacher.attach("workstation")?,
            "10.0.0.2".parse::<std::net::Ipv4Addr>()?,
        );
        fetch(&cx, &client, "sky.org", "/article", start).await;
        cx.cancel();
        Ok(())
    })
    .await
    .unwrap();
    while let Ok(observation) = observations.try_recv() {
        page.publish(observation);
    }
    let at_ms = page.views.lock().unwrap().current().at_ms;
    let response = page
        .router()
        .call(
            http::Request::get(format!(
                "/preview?host=sky.org&path=%2Farticle&at_ms={at_ms}"
            ))
            .body(axum::body::Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .as_ref(),
        document.as_bytes()
    );
    assert!(
        !serde_json::to_string(&page.views.lock().unwrap().current())
            .unwrap()
            .contains("Pin actions")
    );
    let server = serve(page.router(), 0).await.unwrap();
    let url = server.url.clone();
    tokio::task::spawn_blocking(move || {
        let temporary = RunDir::new(&std::env::temp_dir(), "reader-screenshots").unwrap();
        let output = std::env::var_os("SEARCH_SCREENSHOTS").map(std::path::PathBuf::from).unwrap_or_else(|| temporary.path().into());
        std::fs::create_dir_all(&output).unwrap();
        for (name, size, scheme) in [
            ("reader-dark", (1440, 900), "dark"),
            ("reader-light", (1440, 900), "light"),
            ("reader-laptop-dark", (1280, 800), "dark"),
            ("reader-laptop-light", (1280, 800), "light"),
        ] {
            let path = output.join(format!("{name}.png"));
            shot::capture_at(&url, &[
                shot::Step { ready: "!!document.querySelector('#map .node[aria-label=\"sky.org\"]')", action: Some(r#"document.querySelector('#map .node[aria-label="Sites ›"]').dispatchEvent(new MouseEvent('click')); [...document.querySelectorAll('#detail-body button')].find(button => button.textContent.includes('sky.org')).click(); [...document.querySelectorAll('#detail-body button')].find(button => button.textContent === 'Page').click();"#), color_scheme: Some(scheme), out: None },
                shot::Step { ready: "document.querySelector('.recorded-page')?.srcdoc.includes('Review changes to build credentials.')", action: Some(r#"(() => { const body = new DOMParser().parseFromString(document.querySelector('.recorded-page').srcdoc, 'text/html').body; if (!body.querySelector('h1') || body.querySelectorAll('p').length !== 2) throw new Error('incomplete article'); })()"#), color_scheme: Some(scheme), out: Some(&path) },
            ], Duration::from_secs(15), size).unwrap();
        }
    }).await.unwrap();
}

#[test]
fn rewind_keeps_the_original_call_and_tool_state_and_never_uses_future_events() {
    let mut views = Views::default();
    let call = |status, streaming, complete| SearchObs::ModelCall {
        call: 3,
        host: "api.anthropic.com".parse().unwrap(),
        path: http::uri::PathAndQuery::from_static("/v1/messages"),
        status,
        method: http::Method::POST,
        phase: if complete {
            CallPhase::Complete
        } else if streaming {
            CallPhase::Streaming
        } else {
            CallPhase::Connecting
        },
    };
    for (at_ms, fact) in [
        (100, call(None, false, false)),
        (200, call(Some(http::StatusCode::OK), true, false)),
        (
            300,
            SearchObs::Tool {
                call: 3,
                tool: Tool::WebSearch,
                target: "black hole".into(),
                results: vec![Hit {
                    url: "https://sky.org/black-hole".into(),
                    title: "Black holes".into(),
                }],
                error: None,
            },
        ),
        (400, call(Some(http::StatusCode::OK), false, true)),
    ] {
        views.push(Observation { at_ms, fact });
    }
    assert!(views.at(99).calls.is_empty());
    let before = views.at(150);
    assert_eq!(before.calls[0].status, None);
    assert!(before.calls[0].tools.is_empty());
    let during = views.at(350);
    assert_eq!(during.calls[0].phase, CallPhase::Streaming);
    assert_eq!(during.calls[0].tools[0].results[0].title, "Black holes");
    let after = views.current();
    assert_eq!(after.calls.len(), 1);
    assert_eq!(after.calls[0].phase, CallPhase::Complete);
    assert!(views.at(200).calls[0].tools.is_empty());
}

#[test]
fn retained_history_has_a_known_start_and_empty_histories_are_valid() {
    let mut views = Views::default();
    assert_eq!(views.current().at_ms, 0);
    for at_ms in 0..HISTORY as u64 + 10 {
        views.push(Observation {
            at_ms,
            fact: SearchObs::NoRoute {
                from: "10.0.0.2".parse().unwrap(),
                to: "1.1.1.1".parse().unwrap(),
            },
        });
    }
    let view = views.current();
    assert_eq!(view.activity.len(), HISTORY);
    assert_eq!(view.oldest_ms, 10);
    assert!(views.at(9).activity.is_empty());
}

#[tokio::test]
async fn world_controls_report_errors_and_restart_the_visible_history() {
    let pages = pages();
    let (page, (_, control)) = Page::new(&pages, false);
    let commands = page.commands.clone();
    let world = page.world.clone();
    let views = page.views.clone();
    let snapshots = page.snapshots.clone();
    fictionet::lab(fictionet::Seed::from_u64(1), move |cx| async move {
        page.run_commands(&cx, pages.clone(), control);
        let (reply, receive) = tokio::sync::oneshot::channel();
        commands
            .send((
                Command::SetSource {
                    source: Source::ModelWritten,
                },
                reply,
            ))
            .unwrap();
        assert_eq!(
            receive.await.unwrap().unwrap_err(),
            "Model-written pages need a host model credential"
        );
        assert_eq!(pages.new_pages(), NewPages::Copied);
        views.lock().unwrap().push(Observation {
            at_ms: 20,
            fact: SearchObs::NoRoute {
                from: "10.0.0.2".parse().unwrap(),
                to: "1.1.1.1".parse()?,
            },
        });
        let (reply, receive) = tokio::sync::oneshot::channel();
        commands.send((Command::Restart, reply)).unwrap();
        receive.await.unwrap().unwrap();
        assert!(views.lock().unwrap().current().activity.is_empty());
        assert!(snapshots.borrow().activity.is_empty());
        assert!(matches!(world.borrow().source, PageSource::Copy { .. }));
        cx.cancel();
        Ok(())
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn page_routes_serve_local_components_and_stream_current_state() {
    let (page, (_, _)) = Page::new(&pages(), true);
    for (path, mime) in [
        ("/", "text/html"),
        ("/search.mjs", "text/javascript"),
        ("/terminal.mjs", "text/javascript"),
        ("/screen.mjs", "text/javascript"),
        ("/style.css", "text/css"),
        (
            "/vendor/ghostty-web/dist/ghostty-vt.wasm",
            "application/wasm",
        ),
        ("/vendor/novnc/core/rfb.js", "text/javascript"),
    ] {
        let mut router = page.router();
        let response = router
            .call(
                http::Request::get(path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{path}");
        assert!(
            response.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with(mime)
        );
        assert!(
            !response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
    }
    page.views.lock().unwrap().push(Observation {
        at_ms: 1,
        fact: SearchObs::Request {
            scheme: http::uri::Scheme::HTTPS,
            host: "sky.org".parse().unwrap(),
            method: http::Method::GET,
            path: http::uri::PathAndQuery::from_static("/article"),
            status: http::StatusCode::OK,
            bytes: 15,
            content_type: "text/html".into(),
            source: PageSource::Copy { captured: None },
            elapsed_ms: 1,
            headers: http::HeaderMap::new(),
            preview: Some(Arc::<str>::from("<p>Document</p>").into()),
        },
    });
    let mut preview = page.router();
    let response = preview
        .call(
            http::Request::get("/preview?host=sky.org&path=%2Farticle&at_ms=1")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-type"],
        "text/plain; charset=utf-8"
    );
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "<p>Document</p>"
    );
    assert!(
        !serde_json::to_string(&page.views.lock().unwrap().current())
            .unwrap()
            .contains("Document")
    );
    let response = preview
        .call(
            http::Request::get("/preview?host=sky.org&path=%2Farticle&at_ms=0")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    let mut router = page.router();
    let response = router
        .call(
            http::Request::get("/state")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let mut body = response.into_body();
    let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert!(String::from_utf8_lossy(&first).contains("\"sites\":[]"));
    page.snapshots.send_replace(View {
        at_ms: 42,
        ..Views::default().current()
    });
    let next = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert!(String::from_utf8_lossy(&next).contains("\"at_ms\":42"));
    assert!(
        serde_json::from_value::<Command>(json!({"command":"plant_fact","text":"hello"})).is_err()
    );
}

#[tokio::test]
async fn authenticated_server_rejects_cross_origin_reads_and_writes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (page, (_, _)) = Page::new(&pages(), true);
    let server = serve(page.router(), 0).await.unwrap();
    let uri: http::Uri = server.url.parse().unwrap();
    let token = uri.query().unwrap().strip_prefix("token=").unwrap();
    async fn request(uri: &http::Uri, text: String) -> String {
        let mut socket = tokio::net::TcpStream::connect(uri.authority().unwrap().as_str())
            .await
            .unwrap();
        socket.write_all(text.as_bytes()).await.unwrap();
        let mut reply = String::new();
        socket.read_to_string(&mut reply).await.unwrap();
        reply
    }
    let host = uri.authority().unwrap();
    let denied = request(
        &uri,
        format!("GET /world HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(denied.starts_with("HTTP/1.1 403"));
    let bootstrap = request(
        &uri,
        format!("GET /?token={token} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(bootstrap.starts_with("HTTP/1.1 200"));
    assert!(bootstrap.contains("HttpOnly; SameSite=Strict"));
    for path in ["/world", "/command", "/screen", "/terminal"] {
        let reply=request(&uri,format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nCookie: search={token}\r\nOrigin: https://elsewhere.example\r\nConnection: close\r\n\r\n")).await;
        assert!(reply.starts_with("HTTP/1.1 403"), "{path}");
    }
    let allowed=request(&uri,format!("GET /world HTTP/1.1\r\nHost: {host}\r\nCookie: search={token}\r\nConnection: close\r\n\r\n")).await;
    assert!(allowed.starts_with("HTTP/1.1 200"));
    assert!(allowed.contains("\"copied\":{\"kind\":\"available\"}"));
    server.shutdown().await;
}

#[test]
fn activity_updates_a_model_call_in_place_and_local_calls_have_no_egress() {
    let mut views = Views::default();
    for (at_ms, phase) in [
        (100, CallPhase::Connecting),
        (200, CallPhase::Receiving),
        (300, CallPhase::Complete),
    ] {
        views.push(Observation {
            at_ms,
            fact: SearchObs::ModelCall {
                call: 1,
                host: "api.anthropic.com".parse().unwrap(),
                method: http::Method::GET,
                path: http::uri::PathAndQuery::from_static("/api/hello"),
                status: Some(http::StatusCode::OK),
                phase,
            },
        });
    }
    let view = views.current();
    assert_eq!(view.activity.len(), 1);
    assert_eq!(view.activity[0].at_ms, 100);
    assert_eq!(view.calls.len(), 1);
    assert!(view.egress.is_empty());
    assert!(matches!(
        view.activity[0].fact,
        SearchObs::ModelCall {
            phase: CallPhase::Complete,
            ..
        }
    ));
    views.push(Observation {
        at_ms: 400,
        fact: SearchObs::Egress {
            attempt: 1,
            host: "www.cisa.gov".parse().unwrap(),
            method: "GET".into(),
            path: "/news-events/cybersecurity-advisories".into(),
            purpose: web_world::observation::EgressPurpose::LiveCapture,
            phase: web_world::observation::EgressPhase::Attempt,
            status: None,
        },
    });
    assert!(views.at(399).egress.is_empty());
    assert_eq!(views.current().egress.len(), 1);
}

#[tokio::test]
async fn each_launch_preserves_its_own_readable_private_record_and_drains_the_queue() {
    use std::os::unix::fs::PermissionsExt;
    let directory =
        fictionet_demo::kit::RunDir::new(&std::env::temp_dir(), "search-record").unwrap();
    for _ in 0..2 {
        let pages = pages();
        let (page, _) = Page::new(&pages, true);
        let (sender, receiver) = mpsc::channel(4);
        for at_ms in [100, 200] {
            sender
                .try_send(Observation {
                    at_ms,
                    fact: SearchObs::NoRoute {
                        from: "10.0.0.2".parse().unwrap(),
                        to: "1.1.1.1".parse().unwrap(),
                    },
                })
                .unwrap();
        }
        drop(sender);
        page.record(receiver, directory.path()).await.unwrap();
        assert_eq!(page.snapshots.borrow().activity.len(), 2);
    }
    let files: Vec<_> = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|file| file.unwrap().path())
        .collect();
    assert_eq!(files.len(), 2);
    for file in files {
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let text = std::fs::read_to_string(file).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0]["timestamp"].as_str().unwrap().ends_with('Z'));
        assert_eq!(lines[1]["at_ms"], 200);
    }
}

#[tokio::test]
async fn observation_failure_is_recorded_and_fails_the_recording_task() {
    let directory =
        fictionet_demo::kit::RunDir::new(&std::env::temp_dir(), "search-record").unwrap();
    let (page, _) = Page::new(&pages(), true);
    let (sender, receiver) = mpsc::channel(2);
    sender
        .try_send(Observation {
            at_ms: 1,
            fact: SearchObs::ObservationFailed {
                reason: "Observation queue exceeded its capacity".into(),
            },
        })
        .unwrap();
    drop(sender);
    assert!(
        page.record(receiver, directory.path())
            .await
            .unwrap_err()
            .to_string()
            .contains("capacity")
    );
    let file = std::fs::read_dir(directory.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(
        std::fs::read_to_string(file)
            .unwrap()
            .contains("observation_failed")
    );
}

#[test]
fn previews_match_the_exact_page_scheme_query_and_observation_time() {
    let mut views = Views::default();
    for (at_ms, scheme, path, text) in [
        (100, http::uri::Scheme::HTTPS, "/black-hole", "Black hole"),
        (
            200,
            http::uri::Scheme::HTTPS,
            "/solar-system",
            "Solar system",
        ),
        (300, http::uri::Scheme::HTTP, "/black-hole", "Plain HTTP"),
        (
            400,
            http::uri::Scheme::HTTPS,
            "/black-hole?edition=2",
            "Second edition",
        ),
    ] {
        views.push(Observation {
            at_ms,
            fact: SearchObs::Request {
                scheme,
                host: "sky.org".parse().unwrap(),
                method: http::Method::GET,
                path: path.parse().unwrap(),
                status: http::StatusCode::OK,
                bytes: text.len(),
                content_type: "text/html".into(),
                source: PageSource::Copy { captured: None },
                elapsed_ms: 0,
                headers: http::HeaderMap::new(),
                preview: Some(Arc::<str>::from(text).into()),
            },
        });
    }
    for (url, expected) in [
        ("https://sky.org/black-hole", "Black hole"),
        ("https://sky.org/solar-system", "Solar system"),
        ("http://sky.org/black-hole", "Plain HTTP"),
        ("https://sky.org/black-hole?edition=2", "Second edition"),
    ] {
        assert_eq!(
            views
                .preview(&url.parse().unwrap(), 400)
                .map(|body| body.text().unwrap())
                .as_deref(),
            Some(expected)
        );
    }
    assert!(
        views
            .preview(&"https://sky.org/solar-system".parse().unwrap(), 100)
            .is_none()
    );
    assert!(
        views
            .preview(&"https://sky.org/unopened".parse().unwrap(), 400)
            .is_none()
    );
}

#[test]
fn request_details_show_retained_headers_and_omit_removed_values() {
    let mut views = Views::default();
    views.push(Observation {
        at_ms: 100,
        fact: SearchObs::Request {
            scheme: http::uri::Scheme::HTTPS,
            host: "sky.org".parse().unwrap(),
            method: http::Method::GET,
            path: "/black-hole".parse().unwrap(),
            status: http::StatusCode::OK,
            bytes: 0,
            content_type: "text/html".into(),
            source: PageSource::Copy { captured: None },
            elapsed_ms: 0,
            headers: http::HeaderMap::from_iter([
                (http::header::HOST, "sky.org".parse().unwrap()),
                (http::header::ACCEPT_ENCODING, "gzip".parse().unwrap()),
                (http::header::CONNECTION, "[redacted]".parse().unwrap()),
                (http::header::AUTHORIZATION, "[redacted]".parse().unwrap()),
            ]),
            preview: None,
        },
    });
    let view = views.current();
    let headers = &view.sites[0].requests[0].headers;
    assert_eq!(headers.len(), 2);
    assert!(headers.contains(&("host".into(), "sky.org".into())));
    assert!(headers.contains(&("accept-encoding".into(), "gzip".into())));
    assert_eq!(view.sites[0].requests[0].url, "https://sky.org/black-hole");
}

#[test]
fn source_choices_include_the_reason_they_are_unavailable() {
    let state = serde_json::to_value(world_state(&pages(), true)).unwrap();
    assert_eq!(state["copied"], json!({"kind": "available"}));
    assert_eq!(
        state["model_written"],
        json!({"kind": "unavailable", "reason": "no_page_writer"})
    );
    assert_eq!(
        serde_json::to_value(Availability::new(false, UnavailableReason::NoCaptures)).unwrap(),
        json!({"kind": "unavailable", "reason": "no_captures"})
    );
    assert_eq!(
        serde_json::to_value(Availability::new(false, UnavailableReason::NoSearchKey)).unwrap(),
        json!({"kind": "unavailable", "reason": "no_search_key"})
    );
}

#[test]
fn live_connections_and_sign_in_policy_remain_visible_after_activity_expires() {
    let mut views = Views::default();
    views.push(Observation {
        at_ms: 100,
        fact: SearchObs::Egress {
            attempt: 1,
            host: "www.cisa.gov".parse().unwrap(),
            method: "GET".into(),
            path: "/news-events/cybersecurity-advisories".into(),
            purpose: web_world::observation::EgressPurpose::LiveCapture,
            phase: web_world::observation::EgressPhase::Attempt,
            status: None,
        },
    });
    views.push(Observation {
        at_ms: 200,
        fact: SearchObs::Signin {
            open: false,
            exceptions: vec![web_world::observation::SigninException::ClaudeAccount],
        },
    });
    for at_ms in 300..HISTORY as u64 + 400 {
        views.push(Observation {
            at_ms,
            fact: SearchObs::NoRoute {
                from: "10.0.0.2".parse().unwrap(),
                to: "1.1.1.1".parse().unwrap(),
            },
        });
    }
    let view = views.current();
    assert!(view.egress.is_empty());
    assert_eq!(view.connections.len(), 1);
    assert_eq!(view.connections[0].host, "www.cisa.gov");
    assert!(matches!(
        view.signin.unwrap().fact,
        SearchObs::Signin { open: false, .. }
    ));
    assert!(views.at(99).connections.is_empty());
    assert!(views.at(199).signin.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_destinations_start_at_the_search_and_sites_services() {
    use fictionet_demo::kit::{RunDir, shot};
    use std::time::Duration;
    use web_world::observation::{EgressPhase, EgressPurpose};
    let (page, _) = Page::new(&pages(), true);
    {
        let mut views = page.views.lock().unwrap();
        for (at_ms, host, purpose) in [
            (100, "api.exa.ai", EgressPurpose::LiveSearch),
            (200, "www.cisa.gov", EgressPurpose::LiveCapture),
        ] {
            views.push(Observation {
                at_ms,
                fact: SearchObs::Egress {
                    attempt: at_ms,
                    host: host.parse().unwrap(),
                    method: "GET".into(),
                    path: "/".into(),
                    purpose,
                    phase: EgressPhase::Response,
                    status: Some(200),
                },
            });
        }
        views.push(Observation {
            at_ms: 210,
            fact: SearchObs::Resolved {
                name: "www.cisa.gov".parse().unwrap(),
                address: Some("104.16.80.12".parse().unwrap()),
            },
        });
        views.push(Observation {
            at_ms: 220,
            fact: SearchObs::Search {
                engine: web_world::observation::Engine::Google,
                query: "supply chain".into(),
                results: vec![web_world::observation::Hit {
                    title: "Supply chain advisory".into(),
                    url: "https://www.cisa.gov/advisory".into(),
                }],
            },
        });
        views.push(Observation {
            at_ms: 230,
            fact: SearchObs::Request {
                scheme: http::uri::Scheme::HTTPS,
                host: "www.cisa.gov".parse().unwrap(),
                method: http::Method::GET,
                path: "/advisory".parse().unwrap(),
                status: http::StatusCode::OK,
                bytes: 60_000,
                content_type: "text/html".into(),
                source: PageSource::Copy { captured: None },
                elapsed_ms: 0,
                headers: http::HeaderMap::new(),
                preview: Some(Arc::<str>::from("<h1>Supply chain advisory</h1>").into()),
            },
        });
        for at_ms in [1000, 12000, 23000, 34000, 45000, 80000] {
            views.push(Observation {
                at_ms,
                fact: SearchObs::NoRoute {
                    from: "10.0.0.2".parse().unwrap(),
                    to: "1.1.1.1".parse().unwrap(),
                },
            });
        }
        page.snapshots.send_replace(views.current());
    }
    let server = serve(page.router(), 0).await.unwrap();
    let url = server.url.clone();
    tokio::task::spawn_blocking(move || {
        let temporary = RunDir::new(&std::env::temp_dir(), "search-page").unwrap();
        let output = std::env::var_os("SEARCH_SCREENSHOTS").map(std::path::PathBuf::from)
            .unwrap_or_else(|| temporary.path().into());
        std::fs::create_dir_all(&output).unwrap();
        let ready = "document.querySelectorAll('#map .wire.observed').length === 2";
        let routes = r#"(() => {
            const map = document.getElementById('map');
            const center = label => {
                const rect = map.querySelector(`.node[aria-label="${label}"] rect`);
                if (!rect) throw new Error(`missing ${label}`);
                return Number(rect.getAttribute('y')) + Number(rect.getAttribute('height')) / 2;
            };
            const starts = [...map.querySelectorAll('.wire.observed')].map(path => Number(path.getAttribute('d').match(/^M[\d.]+ ([\d.]+)/)[1]));
            for (const label of ['Search', 'Sites ›']) {
                if (!starts.includes(center(label))) throw new Error(`no upstream route from ${label}`);
            }
            if (starts.includes(center('model gateway'))) throw new Error('Live traffic crossed the model gateway');
            for (const node of map.querySelectorAll('.node rect')) {
                if (Number(node.getAttribute('height')) <= 0) throw new Error('collapsed map node');
            }
            map.querySelector('.node[aria-label="Sites ›"]').dispatchEvent(new MouseEvent('click'));
            if (!document.getElementById('detail-body').textContent.includes('www.cisa.gov')) throw new Error('captured site disappeared');
            map.querySelector('.node[aria-label="Search"]').dispatchEvent(new MouseEvent('click'));
            if (document.getElementById('detail-title').textContent !== 'Search') throw new Error('search inspector');
            if (!document.getElementById('detail-body').textContent.includes('supply chain')) throw new Error('missing search');
            map.querySelector('.node[aria-label="router"]').dispatchEvent(new MouseEvent('click'));
            if (document.querySelectorAll('#detail-body .detail-row').length !== 2) throw new Error('TCP retries were split or a separate attempt disappeared');
            map.querySelector('.node[aria-label="Sites ›"]').dispatchEvent(new MouseEvent('click'));
            [...document.querySelectorAll('#detail-body button')].find(button => button.textContent.includes('www.cisa.gov')).click();
            const request = document.querySelector('#detail-body details');
            request.open = true;
            if (!request.textContent.includes('60 KB on the wire')) throw new Error('missing transfer size label');
            if (!request.textContent.includes('<1 ms') || request.textContent.includes('0 ms')) throw new Error('misleading elapsed time');
        })()"#;
        for (name, size, scheme) in [
            ("live-map-dark", (1440, 900), "dark"),
            ("live-map-light", (1440, 900), "light"),
            ("live-map-laptop", (1280, 800), "light"),
        ] {
            let path = output.join(format!("{name}.png"));
            shot::capture_at(&url, &[shot::Step {
                ready, action: Some(routes), color_scheme: Some(scheme), out: Some(&path),
            }], Duration::from_secs(15), size).unwrap();
        }
    }).await.unwrap();
    server.shutdown().await;
}
