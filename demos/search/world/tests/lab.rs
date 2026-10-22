//! The whole world, with its offline generator, runs in a lab: no sockets
//! or files.
use fictionet::{
    Cx,
    events::Fanout,
    stdlib::{
        codec::Wire,
        protocols::{
            dns::rr::{RData, RecordType},
            http1,
        },
        web::httpd,
        world::sandbox::{self, Machine, machine},
    },
};
use fictionet_observe::Memory;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::SystemTime,
};
use web_world::{World, pages::Seed, search::Searches};

/// The caller's own site: "caller content" on every path.
struct CallerContent;

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
    let events = Arc::new(Memory::default());
    let observed = events.clone();
    fictionet::block_on(fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(7)).observer(events.clone()),
        move |cx| async move {
            let seed = Seed::builtin("web")?;
            let start = web_world::world_start(&seed.date)?;
            let world = World::new(&cx, seed, start)?;
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
            let sites = events.checked_of("web", "site").unwrap();
            let forwarded: Vec<_> = sites
                .iter()
                .filter(|e| e.str("host") == Some("forwarded.com"))
                .collect();
            assert_eq!(forwarded.len(), 1);
            assert_eq!(
                forwarded[0].str("addr"),
                Some(assigned.to_string().as_str())
            );
            assert_eq!(forwarded[0].str("why"), Some("pool"));
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
    let sites = observed.checked_of("web", "site").unwrap();
    assert!(sites.iter().any(|e| e.str("host") == Some("freshnews.com")));
    assert_eq!(
        sites
            .iter()
            .filter(|e| e.str("host") == Some("forwarded.com"))
            .count(),
        1
    );
    assert!(
        !observed
            .checked_of("web", "cert")
            .unwrap()
            .iter()
            .any(|e| e.str("host") == Some("forwarded.com"))
    );
    assert!(
        observed
            .checked_of("web", "refused")
            .unwrap()
            .iter()
            .any(|e| e.str("host") == Some("wiki.corp"))
    );
}

#[test]
fn guest_fetches_attribute_claude_and_keep_browser_requests_unmarked() {
    let events = Arc::new(Memory::default());
    let seed = Seed::builtin("web").unwrap();
    let searches = Arc::new(Searches::from_seed(&seed));
    let observed = events.clone();
    let projection = searches.clone();
    let observer = Arc::new(Fanout::new(vec![events, searches]));
    fictionet::block_on(fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(7)).observer(observer),
        move |cx| async move {
            let start = web_world::world_start(&seed.date)?;
            let world = World::new(&cx, seed, start)?;
            let log = Arc::new(fictionet_extras::log::Log::new(
                Box::new(std::io::sink()),
                &[],
                |s| s,
            ));
            let (attacher, attachments) = fictionet::attachments();
            world.serve(&cx, log, attachments)?;
            let m = machine(&cx, attacher.attach("agent")?, Ipv4Addr::new(10, 0, 0, 2));
            for (user_agent, via) in [
                (
                    "Claude-User (claude-code/2.1.292; +https://support.anthropic.com/)",
                    Some("web_fetch"),
                ),
                (
                    "Mozilla/5.0 (X11; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0",
                    None,
                ),
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
                let requests = observed.checked_of("http", "request").unwrap();
                let request = requests.last().unwrap();
                assert_eq!(request.str("via"), via);
                let snapshot = projection.snapshot();
                assert_eq!(snapshot.pages.len(), 1);
                assert_eq!(snapshot.pages[0].via.as_deref(), via);
                assert_eq!(snapshot.pages[0].status, Some(200));
            }
            assert_eq!(projection.snapshot().pages[0].fetches, 2);
            cx.cancel();
            Ok(())
        },
    ))
    .unwrap();
}
