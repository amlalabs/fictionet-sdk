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
        assert!(views.preview(&"https://sky.org/black-hole".parse().unwrap(),current.at_ms).unwrap().contains("bends spacetime"));
        assert!(matches!(request.source,PageSource::Copy { .. }));
        assert_eq!(request.headers,vec![("host".into(),"sky.org".into()),("user-agent".into(),"Firefox/1".into())]);
        assert!(current.activity.iter().any(|row|matches!(&row.fact,SearchObs::Resolved {name,address:None} if name.to_ascii()=="wiki.corp")));
        assert!(current.activity.iter().any(|row|matches!(&row.fact,SearchObs::NoRoute {from,to} if *from == "10.0.0.2".parse::<std::net::IpAddr>().unwrap() && *to == "1.1.1.1".parse::<std::net::IpAddr>().unwrap())));
        cx.cancel();
        Ok(())
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
            preview: Some(Arc::from("<p>Document</p>")),
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
    assert!(allowed.contains("\"copied\":true"));
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
            host: "archive.ubuntu.com".parse().unwrap(),
            method: "GET".into(),
            path: "/ubuntu/dists/noble/InRelease".into(),
            purpose: web_world::observation::EgressPurpose::Setup,
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
                preview: Some(Arc::from(text)),
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
            views.preview(&url.parse().unwrap(), 400).as_deref(),
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
fn setup_connections_and_sign_in_policy_remain_visible_after_activity_expires() {
    let mut views = Views::default();
    views.push(Observation {
        at_ms: 100,
        fact: SearchObs::Egress {
            attempt: 1,
            host: "archive.ubuntu.com".parse().unwrap(),
            method: "GET".into(),
            path: "/ubuntu/dists/noble/InRelease".into(),
            purpose: web_world::observation::EgressPurpose::Setup,
            phase: web_world::observation::EgressPhase::Attempt,
            status: None,
        },
    });
    views.push(Observation {
        at_ms: 200,
        fact: SearchObs::Signin {
            open: false,
            exceptions: vec![web_world::observation::SigninException::TokenRefresh],
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
    assert_eq!(view.connections[0].host, "archive.ubuntu.com");
    assert!(matches!(
        view.signin.unwrap().fact,
        SearchObs::Signin { open: false, .. }
    ));
    assert!(views.at(99).connections.is_empty());
    assert!(views.at(199).signin.is_none());
}
