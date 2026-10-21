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
    let seed = Seed::builtin("halvard-cve").unwrap();
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
                "/search?q=halvard+gateway+vulnerability",
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
                json!({"via":"search", "query":"halvard gateway vulnerability", "rank":first.rank})
            );
            assert_eq!(opened["made"], "stubbed");
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
    for path in [
        "/panels/web.mjs",
        "/assets/search/model.mjs",
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
