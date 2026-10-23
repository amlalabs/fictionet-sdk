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
        let net=crate::network::build(&world,&cx,log,fictionet_demo::kit::mirror::new(&cx)?, None)?;
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
        assert!(views.preview("sky.org","/black-hole",current.at_ms).unwrap().contains("bends spacetime"));
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
            "Model-written pages need OPENROUTER_API_KEY"
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
