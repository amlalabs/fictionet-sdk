//! The whole world, with its offline generator, runs in a lab: no sockets
//! or files.
use fictionet::{
    Cx,
    stdlib::{
        codec::Wire,
        protocols::{
            dns::rr::{RData, RecordType},
            http1,
        },
        web::httpd,
    },
};
use fictionet_test_support::sandbox::{self, Machine, machine};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::SystemTime,
};
use web_world::{World, observation::SearchObs, pages::Seed};

/// The caller's own site: "caller content" on every path.
struct CallerContent;

#[test]
fn copied_world_resolves_captured_and_forwarded_hosts_but_refuses_unknown_hosts() {
    fictionet::block_on(fictionet::lab(
        fictionet::Seed::from_u64(7),
        |cx| async move {
            use fictionet::stdlib::protocols::dns::op::ResponseCode;
            let seed = Seed::builtin("web")?;
            let start = web_world::world_start(&seed.date)?;
            let world = World::new(&cx, seed.clone(), start)?;
            let world = World {
                pages: Arc::new(
                    web_world::pages::Pages::copied(
                        seed,
                        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                            .join("../../../extras/tests/fixtures"),
                        &["https://sky.org/".into()],
                        None,
                    )
                    .map_err(fictionet::Error::msg)?,
                ),
                ..world
            };
            let log = Arc::new(fictionet_extras::log::Log::new(
                Box::new(std::io::sink()),
                &[],
                |s| s,
            ));
            let (attacher, attachments) = fictionet::attachments();
            world
                .net(&cx, log, |name| {
                    (name == "forwarded.com").then(|| {
                        fictionet::stdlib::web::Site::handler(CallerContent).into_host(name)
                    })
                })
                .start(&cx, attachments)?;
            let m = machine(
                &cx,
                attacher.attach("workstation")?,
                Ipv4Addr::new(10, 0, 0, 2),
            );
            for host in ["sky.org", "www.google.com", "www.bing.com", "forwarded.com"] {
                let answer = m
                    .lookup(&cx, web_world::GATEWAY.into(), host, RecordType::A)
                    .await?;
                assert_eq!(
                    answer.metadata.response_code,
                    ResponseCode::NoError,
                    "{host}"
                );
                assert!(!answer.answers.is_empty(), "{host}");
            }
            for host in ["thisdoesnotexist-qx.com", "uncaptured.org", "wiki.corp"] {
                let answer = m
                    .lookup(&cx, web_world::GATEWAY.into(), host, RecordType::A)
                    .await?;
                assert_eq!(
                    answer.metadata.response_code,
                    ResponseCode::NXDomain,
                    "{host}"
                );
                assert!(answer.answers.is_empty(), "{host}");
                assert!(!world.pages.serves_host(host));
            }
            let (status, _) = fetch(&cx, &m, "sky.org", "/black-hole", start, "reader").await;
            assert_eq!(status, 200);
            let (status, _) = fetch(&cx, &m, "sky.org", "/missing", start, "reader").await;
            assert_eq!(status, 404);
            cx.cancel();
            Ok(())
        },
    ))
    .unwrap();
}

impl httpd::Handler for CallerContent {
    fn call(&self, _: http::Request<httpd::Body>, _: &mut httpd::Exchange<'_>) -> httpd::Reply {
        httpd::Reply::Now(httpd::text(http::StatusCode::OK, "caller content"))
    }
}

async fn fetch(
    cx: &Cx,
    m: &Machine,
    host: &str,
    path: &str,
    start: SystemTime,
    user_agent: &str,
) -> (u16, Vec<u8>) {
    let answer = m
        .lookup(cx, "10.0.0.1".parse().unwrap(), host, RecordType::A)
        .await
        .unwrap();
    let addr = answer
        .answers
        .iter()
        .find_map(|r| {
            if let RData::A(a) = &r.data {
                Some(a.0)
            } else {
                None
            }
        })
        .unwrap();
    let mut conn = m
        .tls(cx, SocketAddr::new(addr.into(), 443), host, None, start)
        .await
        .unwrap();
    let request = http1::Request::parse(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\n\r\n")
            .as_bytes(),
    )
    .unwrap();
    let response = sandbox::request(cx, &mut conn, &request).await.unwrap();
    (response.head.status, response.body)
}
#[test]
fn caller_sites_precede_generated_sites_and_reserved_names_are_refused() {
    let (sender, mut observations) =
        tokio::sync::mpsc::channel(web_world::observation::OBSERVATION_CAPACITY);
    fictionet::block_on(fictionet::lab(
        fictionet::Seed::from_u64(7),
        move |cx| async move {
            let seed = Seed::builtin("web")?;
            let start = web_world::world_start(&seed.date)?;
            let world = World::new(&cx, seed, start)?;
            world.pages.observe(sender);
            let tls = world.ca.config(&cx, "forwarded.com")?.0;
            let log = Arc::new(fictionet_extras::log::Log::new(
                Box::new(std::io::sink()),
                &[],
                |s| s,
            ));
            let (attacher, attachments) = fictionet::attachments();
            world
                .net(&cx, log, move |name| {
                    (name == "forwarded.com").then(|| {
                        fictionet::stdlib::web::Site::handler(CallerContent)
                            .tls(tls.clone())
                            .into_host(name)
                    })
                })
                .start(&cx, attachments)?;
            let m = machine(
                &cx,
                attacher.attach("workstation")?,
                Ipv4Addr::new(10, 0, 0, 2),
            );
            let (status, body) = fetch(
                &cx,
                &m,
                "forwarded.com",
                "/",
                start,
                "Mozilla/5.0 Firefox/145.0",
            )
            .await;
            assert_eq!(status, 200);
            assert_eq!(body, b"caller content");
            let answer = m
                .lookup(&cx, "10.0.0.1".parse()?, "forwarded.com", RecordType::A)
                .await?;
            let (assigned, why) = world.addresses.assign("forwarded.com")?.unwrap();
            assert_eq!(why, "pool");
            assert!(matches!(
                assigned.octets(),
                [104, 21, _, _] | [172, 67, _, _]
            ));
            assert_eq!(answer.answers.len(), 1);
            assert!(matches!(&answer.answers[0].data, RData::A(a) if a.0 == assigned));
            assert_eq!(
                fetch(
                    &cx,
                    &m,
                    "freshnews.com",
                    "/news",
                    start,
                    "Mozilla/5.0 Firefox/145.0"
                )
                .await
                .0,
                200
            );
            let refused = m
                .lookup(&cx, "10.0.0.1".parse()?, "wiki.corp", RecordType::A)
                .await?;
            assert!(refused.answers.is_empty());
            cx.cancel();
            Ok(())
        },
    ))
    .unwrap();
    let mut facts = Vec::new();
    while let Ok(observation) = observations.try_recv() {
        facts.push(observation.fact);
    }
    assert_eq!(facts.iter().filter(|fact| matches!(fact, SearchObs::Resolved { name, address: Some(_) } if name.to_ascii() == "forwarded.com")).count(), 1);
    assert!(facts.iter().any(|fact| matches!(fact, SearchObs::Resolved { name, address: Some(_) } if name.to_ascii() == "freshnews.com")));
    assert!(facts.iter().any(|fact| matches!(fact, SearchObs::Resolved { name, address: None } if name.to_ascii() == "wiki.corp")));
}

#[test]
fn guest_fetches_keep_their_typed_request_headers() {
    let seed = Seed::builtin("web").unwrap();
    let (sender, mut observations) =
        tokio::sync::mpsc::channel(web_world::observation::OBSERVATION_CAPACITY);
    fictionet::block_on(fictionet::lab(
        fictionet::Seed::from_u64(7),
        move |cx| async move {
            let start = web_world::world_start(&seed.date)?;
            let world = World::new(&cx, seed, start)?;
            world.pages.observe(sender);
            let log = Arc::new(fictionet_extras::log::Log::new(
                Box::new(std::io::sink()),
                &[],
                |s| s,
            ));
            let (attacher, attachments) = fictionet::attachments();
            world.serve(&cx, log, attachments)?;
            let m = machine(&cx, attacher.attach("agent")?, Ipv4Addr::new(10, 0, 0, 2));
            for user_agent in [
                "Claude-User (claude-code/2.1.292; +https://support.anthropic.com/)",
                "Mozilla/5.0 (X11; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0",
            ] {
                let (status, _) = fetch(
                    &cx,
                    &m,
                    "docs.python.org",
                    "/3/library/itertools.html",
                    start,
                    user_agent,
                )
                .await;
                assert_eq!(status, 200);
            }

            cx.cancel();
            Ok(())
        },
    ))
    .unwrap();
    let mut requests = Vec::new();
    while let Ok(observation) = observations.try_recv() {
        if let SearchObs::Request {
            host,
            method,
            path,
            status,
            headers,
            ..
        } = observation.fact
        {
            assert_eq!(host.to_ascii(), "docs.python.org");
            assert_eq!(method, http::Method::GET);
            assert_eq!(path, "/3/library/itertools.html");
            assert_eq!(status, http::StatusCode::OK);
            requests.push(headers);
        }
    }
    assert_eq!(requests.len(), 2);
    assert!(
        requests[0][http::header::USER_AGENT]
            .to_str()
            .unwrap()
            .starts_with("Claude-User")
    );
    assert!(
        requests[1][http::header::USER_AGENT]
            .to_str()
            .unwrap()
            .contains("Firefox/")
    );
}
