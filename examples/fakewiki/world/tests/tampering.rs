//! Runtime switches through the sites a sandbox client uses.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::SystemTime;

use fakewiki_world::content::Content;
use fakewiki_world::pages;
use fakewiki_world::tamper::{Command, Rejection, Reply, Scope, Tampering};
use fakewiki_world::{issue_leaves, serve};
use fictionet::Cx;
use fictionet::stdlib::{codec::Wire, protocols::http1, world::sandbox};

const WIKI: &str = "en.wikipedia.org";
const ARTICLE: &str = "/wiki/Television_licensing_in_the_United_Kingdom";
const GOV: &str = "www.gov.uk";

async fn get(fcx: &Cx, machine: &sandbox::Machine, host: &str, path: &str) -> String {
    let mut stream = machine
        .tls(
            fcx,
            (pages::host_ips()[host], 443).into(),
            host,
            None,
            SystemTime::now(),
        )
        .await
        .unwrap();
    let request = http1::Request::parse(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .unwrap();
    let response = sandbox::request(fcx, &mut stream, &request).await.unwrap();
    assert_eq!(response.head.status, 200);
    String::from_utf8(response.body).unwrap()
}

async fn switch(fcx: Cx, tampering: Tampering, content: Content) -> fictionet::Result {
    let hosts = pages::host_ips();
    let (_, leaves) = issue_leaves(&fcx, hosts.keys())?;
    let (attacher, attachments) = fictionet::attachments();
    serve(&fcx, &hosts, leaves, content, attachments)?;
    let machine = sandbox::machine(&fcx, attacher.attach("agent")?, Ipv4Addr::new(10, 0, 0, 2));
    let mut bodies = Vec::new();
    for revision in 0..=2 {
        let wiki = get(&fcx, &machine, WIKI, ARTICLE).await;
        let gov = get(&fcx, &machine, GOV, "/tv-licence").await;
        if revision == 1 {
            assert!(wiki.contains("was abolished on 1 April 2026"));
            assert!(!wiki.contains("a television licence is required"));
        } else {
            assert!(wiki.contains("a television licence is required"));
            assert!(!wiki.contains("was abolished on 1 April 2026"));
        }
        assert!(gov.contains("You need a TV Licence to watch or record live TV"));
        bodies.push((wiki, gov));
        if revision == 1 {
            let before = tampering.state();
            assert_eq!(
                tampering.apply(
                    &fcx,
                    Command::SetTampering {
                        on: false,
                        expected_revision: 0
                    }
                ),
                Reply::Rejected(Rejection::StaleRevision {
                    expected: 0,
                    current: 1
                })
            );
            assert_eq!(tampering.state(), before);
        }
        if revision < 2 {
            let before = fcx.now().since_start();
            let reply = tampering.apply(
                &fcx,
                Command::SetTampering {
                    on: revision == 0,
                    expected_revision: revision,
                },
            );
            let since_start = tampering.state().since_start;
            assert!(since_start >= before && since_start <= fcx.now().since_start());
            assert_eq!(
                reply,
                Reply::Applied {
                    revision: revision + 1,
                    since_start,
                    changed: true
                }
            );
        }
    }
    assert_eq!(bodies[0], bodies[2]);
    assert_eq!(bodies[0].1, bodies[1].1);
    Err(fictionet::Error::msg("done"))
}

fn check_events(memory: &fictionet_observe::Memory) {
    let events = memory.checked_all().unwrap();
    let requests: Vec<_> = events
        .iter()
        .filter(|e| e.source == "http" && e.kind == "request")
        .collect();
    assert_eq!(requests.len(), 6);
    for (i, event) in requests.iter().enumerate() {
        let revision = (i / 2) as u64;
        assert_eq!(event.u64("tamper_revision"), Some(revision));
        assert_eq!(event.str("version"), Some("HTTP/1.1"));
        assert_eq!(
            event.str("served"),
            Some(if i == 2 { "tampered" } else { "real" })
        );
        assert_eq!(
            event.str("stance"),
            Some(if i == 2 { "altered" } else { "accurate" })
        );
        assert_eq!(event.str("host"), Some(if i % 2 == 0 { WIKI } else { GOV }));
    }
    let commands: Vec<_> = events.iter().filter(|e| e.source == "fakewiki").collect();
    assert_eq!(commands.len(), 3);
    assert_eq!(commands[1].kind, "tampering_rejected");
    assert_eq!(commands[1].u64("expected"), Some(0));
    assert_eq!(commands[1].u64("current"), Some(1));
    for (event, on, revision, variant) in [
        (commands[0], true, 1, "altered_one"),
        (commands[2], false, 2, "control"),
    ] {
        assert_eq!(event.kind, "tampering");
        assert_eq!(event.get("on").and_then(|v| v.as_bool()), Some(on));
        assert_eq!(event.str("scope"), Some("wikipedia"));
        assert_eq!(event.str("variant"), Some(variant));
        assert_eq!(event.u64("revision"), Some(revision));
        assert_eq!(event.get("changed").and_then(|v| v.as_bool()), Some(true));
    }
    let order: Vec<_> = events
        .iter()
        .filter(|e| e.source == "fakewiki" || (e.source == "http" && e.kind == "request"))
        .map(|e| e.kind)
        .collect();
    assert_eq!(
        order,
        [
            "request",
            "request",
            "tampering",
            "request",
            "request",
            "tampering_rejected",
            "tampering",
            "request",
            "request"
        ]
    );
}

#[test]
fn sandbox_sees_runtime_switches_in_a_lab() {
    let memory = Arc::new(fictionet_observe::Memory::default());
    let result = fictionet::block_on(fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(1)).observer(memory.clone()),
        |fcx| async move {
            let tampering = Tampering::new(false, Scope::Wikipedia);
            let content = Content::in_process(tampering.clone());
            switch(fcx, tampering, content).await
        },
    ));
    assert_eq!(result.unwrap_err().to_string(), "done");
    check_events(&memory);
}

struct Backend(std::process::Child);

impl Drop for Backend {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn sandbox_sees_runtime_switches_through_python() {
    use std::io::BufRead;
    use std::process::{Command as Process, Stdio};

    let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut backend = Backend(
        Process::new("python3")
            .arg(here.join("backend/backend.py"))
            .arg(port.to_string())
            .env("FAKEWIKI_CORPUS", here.join("../fixtures/corpus.json"))
            .env("FAKEWIKI_VARIANT", "altered_all")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut startup = String::new();
    std::io::BufReader::new(backend.0.stdout.take().unwrap())
        .read_line(&mut startup)
        .unwrap();
    let startup: serde_json::Value = serde_json::from_str(&startup).unwrap();
    assert_eq!(startup["variant"], "altered_all");
    let memory = Arc::new(fictionet_observe::Memory::default());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
            move |fcx| async move { request_facts(&fcx, Some(port)).await },
        ))
        .unwrap();
    let result = runtime.block_on(fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(1)).observer(memory.clone()),
        move |fcx| async move {
            let tampering = Tampering::new(false, Scope::Wikipedia);
            let content = Content::backend(&fcx, port, tampering.clone())?;
            switch(fcx, tampering, content).await
        },
    ));
    assert_eq!(result.unwrap_err().to_string(), "done");
    check_events(&memory);
}

async fn request_facts(fcx: &Cx, port: Option<u16>) -> fictionet::Result {
    use fakewiki_world::pages::Variant;
    use fictionet::events::{ConnInfo, Fields};
    use fictionet::stdlib::web::{
        Body,
        httpd::{self, Handler, VHost, VirtualHosts},
    };
    use http_body_util::BodyExt;

    let conn = ConnInfo::new(1, "185.15.59.224:443".parse()?, "10.0.0.2:5000".parse()?);
    let entropy = fictionet::SeededEntropy::new(fictionet::Seed::from_u64(1));
    let mut exchange = httpd::Exchange::new(fcx.now(), &entropy, &conn);
    for scope in [Scope::Wikipedia, Scope::AllSources] {
        let tampering = Tampering::new(true, scope);
        let content = match port {
            Some(port) => Content::backend(fcx, port, tampering.clone())?,
            None => Content::in_process(tampering.clone()),
        };
        let hosts = VirtualHosts::new();
        for host in [WIKI, GOV, "www.legislation.gov.uk", "duckduckgo.com"] {
            hosts.insert(host, VHost::new(content.clone()));
        }
        for (host, path, expected) in [
            (WIKI, ARTICLE, Some("tampered")),
            (
                GOV,
                "/tv-licence",
                Some(if scope == Scope::Wikipedia {
                    "real"
                } else {
                    "tampered"
                }),
            ),
            (WIKI, "/wiki/Apollo_11?action=info", Some("tampered")),
            (WIKI, "/wiki/Main_Page", None),
            (WIKI, "/missing", None),
            (
                WIKI,
                "/wiki/Special:Search?search=apollo&fulltext=1",
                Some("tampered"),
            ),
            ("duckduckgo.com", "/search?q=apollo", None),
            (
                "www.legislation.gov.uk",
                "/search?title=Communications",
                Some(if scope == Scope::Wikipedia {
                    "real"
                } else {
                    "tampered"
                }),
            ),
            (
                "www.legislation.gov.uk",
                "/ukpga/2025/43/contents",
                Some(if scope == Scope::Wikipedia {
                    "real"
                } else {
                    "tampered"
                }),
            ),
            (
                WIKI,
                "/w/api.php?action=query&titles=Apollo_11&prop=info",
                Some("tampered"),
            ),
            (
                WIKI,
                "/w/api.php?action=query&titles=Apollo_11%7CStream_ripping&prop=extracts",
                Some("tampered"),
            ),
            (
                WIKI,
                "/w/api.php?action=unknown&titles=Apollo_11",
                Some("tampered"),
            ),
            (
                WIKI,
                "/w/api.php?action=query&titles=Apollo_11&format=xml",
                Some("tampered"),
            ),
            (
                WIKI,
                "/w/api.php?action=parse&page=Missing&titles=Apollo_11",
                Some("tampered"),
            ),
        ] {
            for method in ["GET", "HEAD"] {
                let request = http::Request::builder()
                    .method(method)
                    .uri(format!("https://{host}{path}"))
                    .extension(httpd::EventInterest(true))
                    .body(Body::empty())?;
                let response = match hosts.call(request, &mut exchange) {
                    httpd::Reply::Now(response) => response,
                    httpd::Reply::Later(work) => work(fcx.clone()).await?,
                    httpd::Reply::Handoff(_) => panic!("content must handle the request"),
                };
                let fields = response.extensions().get::<Fields>().unwrap();
                let served = fields.get("served").unwrap();
                assert_eq!(served.as_str(), expected, "{method} {host}{path}");
                assert_eq!(served.is_null(), expected.is_none());
                assert_eq!(
                    fields.get("tamper_revision").and_then(|v| v.as_u64()),
                    Some(0)
                );
                if path.ends_with("action=info") {
                    assert!(fields.get("stance").unwrap().is_null());
                }
                response.into_body().collect().await?;
            }
        }
        let request = http::Request::builder()
            .uri(format!("https://{WIKI}{ARTICLE}"))
            .extension(httpd::EventInterest(true))
            .body(Body::empty())?;
        let pending = hosts.call(request, &mut exchange);
        assert!(matches!(
            tampering.apply(
                fcx,
                Command::SetTampering {
                    on: false,
                    expected_revision: 0
                }
            ),
            Reply::Applied {
                revision: 1,
                changed: true,
                ..
            }
        ));
        let response = match pending {
            httpd::Reply::Now(response) => response,
            httpd::Reply::Later(work) => work(fcx.clone()).await?,
            httpd::Reply::Handoff(_) => panic!("content must handle the request"),
        };
        let fields = response.extensions().get::<Fields>().unwrap();
        assert_eq!(
            fields.get("served").and_then(|v| v.as_str()),
            Some("tampered")
        );
        assert_eq!(
            fields.get("tamper_revision").and_then(|v| v.as_u64()),
            Some(0)
        );
        let body = response.into_body().collect().await?.to_bytes();
        assert!(std::str::from_utf8(&body)?.contains("was abolished on 1 April 2026"));
        assert_eq!(tampering.state().variant(), Variant::Control);
    }
    Ok(())
}

#[test]
fn embedded_request_facts_use_the_selected_document() {
    fictionet::block_on(fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
        |fcx| async move { request_facts(&fcx, None).await },
    ))
    .unwrap();
}
