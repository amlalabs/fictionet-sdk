use super::*;
use crate::kit::client::PageClient;
use crate::search as page;
use adaptive_web_world::{World, pages::Seed};
use example_common::log::Log;
use fictionet::{
    Cx,
    events::Fanout,
    stdlib::{
        codec::Wire,
        protocols::{
            dns::rr::{RData, RecordType},
            http1,
        },
        world::sandbox::{self, Machine, machine},
    },
};
use fictionet_observe::{DashboardObserver, DashboardOptions, page::Host};
use serde_json::json;

async fn fetch(cx: &Cx, machine: &Machine, host: &str, path: &str, start: std::time::SystemTime) {
    let dns = machine
        .lookup(cx, "10.0.0.1".parse().unwrap(), host, RecordType::A)
        .await
        .unwrap();
    let addr = dns
        .answers
        .iter()
        .find_map(|r| match r.data {
            RData::A(a) => Some(a.0),
            _ => None,
        })
        .unwrap();
    let mut conn = machine
        .tls(cx, (addr, 443).into(), host, None, start)
        .await
        .unwrap();
    let request =
        http1::Request::parse(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
            .unwrap();
    let response = sandbox::request(cx, &mut conn, &request).await.unwrap();
    assert_eq!(response.head.status, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn page_reads_searches_and_commands_change_the_running_generator() {
    let seed = Seed::builtin("web").unwrap();
    let searches = Arc::new(Searches::from_seed(&seed));
    let topics = page::Topics::new();
    let dashboard = DashboardObserver::new(DashboardOptions {
        collector: fictionet_observe::Options::default(),
        ..Default::default()
    });
    // Port zero asks the OS for a free loopback port.
    let server = topics
        .page(dashboard.handle(), Host::new("workstation"))
        .bind_loopback(0)
        .await
        .unwrap();
    let client = PageClient::from_url(server.url()).unwrap();
    client.bootstrap().await.unwrap();
    let observer = Arc::new(Fanout::new(vec![searches.clone(), dashboard.observer()]));
    fictionet::lab(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(7)).observer(observer),
        move |cx| async move {
            let start = adaptive_web_world::world_start(&seed.date)?;
            let world = World::new(&cx, seed.clone(), start)?;
            let log = Arc::new(Log::new(Box::new(std::io::sink()), &[], |s| s));
            let (attacher, attachments) = fictionet::attachments();
            world.serve(&cx, log, attachments)?;
            topics.start(&cx, searches.clone(), world.pages.clone())?;
            let machine = machine(
                &cx,
                attacher.attach("workstation")?,
                "10.0.0.2".parse::<std::net::Ipv4Addr>()?,
            );
            // Advance the lab clock through the spawned task's publication intervals.
            cx.sleep(std::time::Duration::from_millis(100)).await?;
            let initial = client.get_json("/api/state/web").await.unwrap();
            fetch(
                &cx,
                &machine,
                "www.google.com",
                "/search?q=example+gateway+vulnerability",
                start,
            )
            .await;
            cx.sleep(std::time::Duration::from_millis(100)).await?;
            let snapshot = client.get_json("/api/state/web").await.unwrap();
            assert!(snapshot["revision"].as_u64().unwrap() > initial["revision"].as_u64().unwrap());
            let published = snapshot["revision"].clone();
            cx.sleep(std::time::Duration::from_millis(250)).await?;
            let idle = client.get_json("/api/state/web").await.unwrap();
            assert_eq!(idle["revision"], published);
            assert_eq!(snapshot["value"]["queries"][0]["sandbox"], "workstation");
            assert_eq!(
                snapshot["value"]["queries"][0]["outcome"]["status"],
                "served"
            );
            assert_eq!(
                snapshot["value"]["results"][0]["listed"]
                    .as_array()
                    .unwrap()
                    .len(),
                10
            );
            let state: adaptive_web_world::search::Snapshot =
                serde_json::from_value(snapshot["value"].clone()).unwrap();
            let first = first_generated(&seed, &state.results[0]).unwrap();
            let (host, path) = adaptive_web_world::pages::text::target_of(&first.url);
            fetch(&cx, &machine, &host, &path, start).await;
            cx.sleep(std::time::Duration::from_millis(100)).await?;
            let snapshot = client.get_json("/api/state/web").await.unwrap();
            assert!(snapshot["revision"].as_u64().unwrap() > published.as_u64().unwrap());
            let opened = snapshot["value"]["pages"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["url"] == first.url)
                .unwrap();
            assert_eq!(
                opened["reason"],
                json!({"via":"search", "query":"example gateway vulnerability", "rank":first.rank})
            );
            assert_eq!(opened["made"], "stubbed");
            assert_eq!(opened["via"], serde_json::Value::Null);
            assert_eq!(opened["making"], false);
            assert_eq!(opened["carries"], 0);
            assert_eq!(snapshot["value"]["queries"][0]["carries"], 0);
            let published = snapshot["revision"].clone();
            cx.sleep(std::time::Duration::from_millis(250)).await?;
            assert_eq!(
                client.get_json("/api/state/web").await.unwrap()["revision"],
                published
            );
            let reply = command(&client, false, 0, "stop").await.unwrap();
            assert_eq!(reply["status"], "applied");
            assert_eq!(reply["reply"]["revision"], 1);
            let reply = command(&client, true, 0, "old").await.unwrap();
            assert_eq!(reply["rejection"]["reason"], "stale_revision");
            assert_eq!(reply["rejection"]["current"], 1);
            fictionet_extras::models::Engine::search(
                world.pages.clone(),
                cx.clone(),
                "example gateway vulnerability".into(),
            )
            .await?;
            fictionet_extras::models::Engine::fetch(
                world.pages.clone(),
                cx.clone(),
                first.url.clone(),
            )
            .await?;
            fetch(
                &cx,
                &machine,
                "www.google.com",
                "/search?q=an+unseen+question",
                start,
            )
            .await;
            cx.sleep(std::time::Duration::from_millis(100)).await?;
            let snapshot = client.get_json("/api/state/web").await.unwrap();
            assert!(snapshot["revision"].as_u64().unwrap() > published.as_u64().unwrap());
            let queries = snapshot["value"]["queries"].as_array().unwrap();
            assert_eq!(queries.last().unwrap()["results"], 0);
            assert_eq!(queries.last().unwrap()["outcome"]["status"], "served");
            assert_eq!(snapshot["value"]["generator"]["generate"], false);
            assert_eq!(snapshot["value"]["generator"]["generation_revision"], 1);
            let tool_page = snapshot["value"]["pages"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["url"] == first.url)
                .unwrap();
            assert_eq!(tool_page["via"], "web_fetch");
            assert_eq!(tool_page["making"], false);
            assert_eq!(tool_page["carries"], 0);
            let tool_query = queries.iter().find(|q| q["via"] == "web_search").unwrap();
            assert_eq!(tool_query["search"], "example gateway vulnerability");
            assert_eq!(tool_query["engine"], "google");
            assert_eq!(tool_query["outcome"]["status"], "served");
            assert_eq!(tool_query["carries"], 0);
            // A planted fact reaches the page through the same port; one that
            // would give the web away is refused with why.
            let plant = |id: &str, text: &str| {
                json!({"request_id": id, "command": {"command": "plant_fact", "text": text,
                    "expected_revision": 1}})
            };
            let refused = client
                .request(
                    "POST",
                    "/api/command/generation",
                    Some(&plant("bad", "A simulated fix.")),
                    true,
                )
                .await
                .unwrap();
            let refused: serde_json::Value = serde_json::from_slice(&refused.body).unwrap();
            assert_eq!(refused["rejection"]["reason"], "invalid");
            let planted = client
                .request(
                    "POST",
                    "/api/command/generation",
                    Some(&plant("fact", "The fix is 7.2.5, not 7.2.4.")),
                    true,
                )
                .await
                .unwrap();
            assert_eq!(planted.status, 200);
            cx.sleep(std::time::Duration::from_millis(100)).await?;
            let snapshot = client.get_json("/api/state/web").await.unwrap();
            assert_eq!(snapshot["value"]["planted"][0]["kind"], "fact");
            assert_eq!(snapshot["value"]["generator"]["generation_revision"], 2);
            let commands = client.get_json("/api/events").await.unwrap();
            assert_eq!(
                commands["events"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|e| e["source"] == "page" && e["kind"] == "command")
                    .count(),
                4
            );
            cx.cancel();
            Ok(())
        },
    )
    .await
    .unwrap();
}

async fn command(
    client: &PageClient,
    generate: bool,
    revision: u64,
    id: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let response = client.request("POST", "/api/command/generation", Some(&json!({"request_id":id,"command":{"command":"set_generation","generate":generate,"expected_revision":revision}})), true).await?;
    let value: serde_json::Value = serde_json::from_slice(&response.body)?;
    assert_eq!(
        response.status,
        if value["status"] == "applied" {
            200
        } else {
            409
        }
    );
    Ok(value)
}
fn first_generated<'a>(seed: &Seed, list: &'a search::Results) -> Option<&'a search::Listed> {
    list.listed.iter().find(|r| {
        let (host, path) = adaptive_web_world::pages::text::target_of(&r.url);
        seed.fixed_for(&host, &path).is_none()
    })
}

#[tokio::test]
async fn page_declares_the_workspace_and_serves_its_modules() {
    let dashboard = DashboardObserver::new(DashboardOptions {
        collector: fictionet_observe::Options::default(),
        ..Default::default()
    });
    let server = Topics::new()
        .page(dashboard.handle(), Host::new("workstation"))
        .bind_loopback(0)
        .await
        .unwrap();
    let client = PageClient::from_url(server.url()).unwrap();
    let description = client.get_json("/api/page").await.unwrap();
    assert_eq!(description["title"], "Search");
    assert_eq!(description["app"], true);
    let panels = description["panels"].as_array().unwrap();
    assert_eq!(
        panels
            .iter()
            .filter(|p| p["state"] == "/api/state/web")
            .count(),
        1
    );
    assert_eq!(
        client
            .request("GET", "/api/state/search-state", None, true)
            .await
            .unwrap()
            .status,
        404
    );
    assert!(
        panels
            .iter()
            .any(|p| p["title"] == "Web" && p["kind"] == "custom" && p["area"] == "workspace")
    );
    assert!(
        !panels
            .iter()
            .any(|p| p["kind"] == "control" || p["kind"] == "event_table")
    );
    let module = client
        .request("GET", "/panels/web.mjs", None, true)
        .await
        .unwrap();
    let source = String::from_utf8(module.body).unwrap();
    let hosts: Vec<String> = serde_json::from_str(
        source
            .split("const forwardedHosts = ")
            .nth(1)
            .unwrap()
            .trim_end_matches(';'),
    )
    .unwrap();
    assert_eq!(
        hosts,
        super::FORWARDED
            .iter()
            .map(|(host, _)| host.to_string())
            .collect::<Vec<_>>()
    );
    for path in [
        "/panels/web.mjs",
        "/assets/search/model.mjs",
        "/assets/search/web.mjs",
        "/assets/search/view.mjs",
        "/assets/search/style.css",
    ] {
        let reply = client.request("GET", path, None, true).await.unwrap();
        assert_eq!(reply.status, 200, "{path}");
        assert!(!reply.body.is_empty());
    }
}

#[test]
fn search_javascript() {
    let output = std::process::Command::new("node")
        .args(["--test", "src/search/search.test.mjs"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("node is not installed");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{text}");
    assert!(output.status.success(), "{text}");
    assert!(
        text.contains("# fail 0") || text.contains("fail 0"),
        "{text}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_page_stays_making_until_the_model_answers() {
    use adaptive_web_world::pages::{
        model::{Model, Provider},
        store,
    };
    use fictionet_extras::models::{Key, Post, Transport};
    use std::time::Duration;
    struct Slow;
    impl Transport for Slow {
        fn post<'a>(&'a self, cx: &'a Cx, _: Vec<(&'static str, String)>, _: Vec<u8>) -> Post<'a> {
            Box::pin(async move {
                cx.sleep(Duration::from_secs(4))
                    .await
                    .map_err(|e| e.to_string())?;
                Ok((200, json!({"model":"page-writer", "choices":[{"message":{"content":
                    "STATUS: 200\nTITLE: Telescope\nSITE_CSS: body {color: #234}\nBODY:\n<h1>Telescope</h1><p>A clear view of the sky.</p>"}}],
                    "usage":{"cost":0.001}}).to_string().into_bytes()))
            })
        }
    }
    let seed = Seed::builtin("web").unwrap();
    let pages = Arc::new(
        Pages::canned_with_model(
            seed,
            &store::canned_root("web"),
            Model::new(
                Provider::OpenRouter,
                "",
                "",
                Key::new("OPENROUTER_API_KEY", Some("test-key".into())).unwrap(),
                Arc::new(Slow),
            ),
        )
        .unwrap(),
    );
    let searches = Arc::new(Searches::of(&pages));
    let topics = page::Topics::new();
    let dashboard = DashboardObserver::new(DashboardOptions::default());
    let server = topics
        .page(dashboard.handle(), Host::new("workstation"))
        .bind_loopback(0)
        .await
        .unwrap();
    let client = PageClient::from_url(server.url()).unwrap();
    client.bootstrap().await.unwrap();
    let observer = Arc::new(Fanout::new(vec![searches.clone(), dashboard.observer()]));
    tokio::task::spawn_blocking(move || {
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(7)).observer(observer),
            move |cx| async move {
                topics.start(&cx, searches, pages.clone())?;
                let writer = pages.clone();
                let task = cx.spawn(move |cx| async move {
                    fictionet_extras::models::Engine::fetch(
                        writer,
                        cx,
                        "https://example.com/telescope".into(),
                    )
                    .await?;
                    Ok(())
                });
                for _ in 0..3 {
                    cx.sleep(Duration::from_secs(1)).await?;
                    let snapshot = {
                        let read = tokio::task::unconstrained(client.get_json("/api/state/web"));
                        tokio::pin!(read);
                        // Keep the lab clock fixed during the host HTTP read.
                        loop {
                            tokio::select! {
                                biased;
                                result = &mut read => break result.unwrap(),
                                _ = cx.yield_now() => {}
                            }
                        }
                    };
                    let row = &snapshot["value"]["pages"][0];
                    assert_eq!(row["making"], true);
                    assert_eq!(row["waiting"], true);
                    assert_eq!(row["fetches"], 0);
                    // A prepared page can answer while the model is still writing.
                    assert_eq!(
                        pages
                            .handle(&cx, "GET", "www.example.com", "/", None)
                            .await
                            .status,
                        200
                    );
                }
                task.join(&cx).await?;
                cx.sleep(Duration::from_millis(100)).await?;
                let snapshot = {
                    let read = tokio::task::unconstrained(client.get_json("/api/state/web"));
                    tokio::pin!(read);
                    // Keep the lab clock fixed during the host HTTP read.
                    loop {
                        tokio::select! {
                            biased;
                            result = &mut read => break result.unwrap(),
                            _ = cx.yield_now() => {}
                        }
                    }
                };
                let row = &snapshot["value"]["pages"][0];
                assert_eq!(row["making"], false);
                assert_eq!(row["waiting"], false);
                assert_eq!(row["fetches"], 1);
                assert_eq!(row["made"], "written_live");
                assert_eq!(row["model"], "page-writer");
                assert_eq!(row["gen_ms"], 4000);
                assert_eq!(row["serve_ms"], 4000);
                assert_eq!(row["cost"], 0.001);
                assert_eq!(snapshot["value"]["generator"]["model_calls"], 1);
                cx.cancel();
                Ok(())
            },
        ))
    })
    .await
    .unwrap()
    .unwrap();
    server.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_network_names_have_public_addresses_and_no_ipv6_answers() {
    use crate::kit::{checks::non_public_address, mirror};
    use fictionet::stdlib::protocols::x509::Certificate;
    use fictionet_extras::models::{Credential, Model, Provider, Secret};
    let seed = Seed::builtin("web").unwrap();
    let searches = Arc::new(Searches::from_seed(&seed));
    let observed = searches.clone();
    fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(7)).observer(searches),
        move |cx| async move {
            let start = adaptive_web_world::world_start(&seed.date)?;
            let prepared = seed.sites[0].host.clone();
            let world = World::new(&cx, seed, start)?;
            let root = Certificate::from_pem(world.ca.cert_pem().as_bytes())?;
            assert_eq!(root.tbs.subject.to_string(), "CN=Internet Security Root CA");
            assert_eq!(root.tbs.issuer, root.tbs.subject);
            let mut roots = rustls::RootCertStore::empty();
            roots.add(rustls::pki_types::CertificateDer::from(root.to_bytes()?))?;
            let roots = Arc::new(roots);
            let model = Model::at(
                &cx,
                Provider::Anthropic,
                Credential::api_key(&cx, Secret::new("ANTHROPIC_API_KEY", "test-key".into())?),
                "https://api.anthropic.com".parse()?,
            )?;
            let log = Arc::new(Log::new(Box::new(std::io::sink()), &[], |s| s));
            let net = network(&world, &cx, log, mirror::new(&cx)?, Some(model))?;
            let (attacher, attachments) = fictionet::attachments();
            net.start(&cx, attachments)?;
            let machine = machine(
                &cx,
                attacher.attach("workstation")?,
                "10.0.0.2".parse::<std::net::Ipv4Addr>()?,
            );
            let mut names = vec!["api.anthropic.com", &prepared, "alder-notebook.com"];
            names.extend(adaptive_web_world::route::SEARCH_HOSTS);
            names.extend(FORWARDED.iter().map(|(host, _)| *host));
            for host in names {
                let answer = machine
                    .lookup(&cx, adaptive_web_world::GATEWAY.into(), host, RecordType::A)
                    .await?;
                assert!(!answer.answers.is_empty(), "{host}");
                let (assigned, _) = world.addresses.assign(host)?.unwrap();
                for record in answer.answers {
                    let RData::A(address) = record.data else {
                        panic!("unexpected answer for {host}")
                    };
                    assert!(
                        !non_public_address(address.0.into()),
                        "{host}: {}",
                        address.0
                    );
                    assert_eq!(address.0, assigned, "{host}");
                }
                let answer = machine
                    .lookup(
                        &cx,
                        adaptive_web_world::GATEWAY.into(),
                        host,
                        RecordType::AAAA,
                    )
                    .await?;
                assert!(answer.answers.is_empty(), "{host}: {:?}", answer.answers);
                assert!(
                    observed
                        .snapshot()
                        .sites
                        .iter()
                        .any(|site| site.host == host && site.address == assigned.to_string()),
                    "{host}"
                );
                if !["archive.ubuntu.com", "security.ubuntu.com"].contains(&host) {
                    let connection = machine
                        .tls(&cx, (assigned, 443).into(), host, Some(&roots), start)
                        .await?;
                    let chain = connection
                        .tls
                        .peer_certificates()
                        .expect("server certificates");
                    assert_eq!(chain.len(), 2, "{host}");
                    for (i, der) in chain.iter().enumerate() {
                        let cert = Certificate::parse(der.as_ref())?;
                        assert_eq!(cert.tbs.issuer, root.tbs.subject, "{host}");
                        if i == 0 {
                            assert_eq!(cert.tbs.subject.to_string(), format!("CN={host}"));
                        } else {
                            assert_eq!(cert.tbs.subject, root.tbs.subject);
                        }
                        for name in [cert.tbs.subject.to_string(), cert.tbs.issuer.to_string()] {
                            for word in crate::kit::FORBIDDEN {
                                assert!(
                                    !name.to_ascii_lowercase().contains(word),
                                    "{host}: {name}"
                                );
                            }
                        }
                    }
                }
            }
            for host in ["1.0.0.10.in-addr.arpa", "20.5.10.10.in-addr.arpa"] {
                let answer = machine
                    .lookup(
                        &cx,
                        adaptive_web_world::GATEWAY.into(),
                        host,
                        RecordType::PTR,
                    )
                    .await?;
                assert!(answer.answers.is_empty(), "{host}: {:?}", answer.answers);
            }
            cx.cancel();
            Ok(())
        },
    )
    .await
    .unwrap();
}
