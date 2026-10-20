use super::*;
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
use fictionet_demo::kit::client::PageClient;
use fictionet_observe::{
    DashboardObserver, DashboardOptions,
    page::{Action, Page},
};
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
    let dashboard = DashboardObserver::new(DashboardOptions::demo());
    // Port zero asks the OS for a free loopback port.
    let server = Page::new("Search test", dashboard.handle())
        .state("search-state", topics.searches.clone())
        .state("policy", topics.policy.clone())
        .control(
            "Generation",
            topics.commands.clone(),
            vec![Action {
                label: "Stop".into(),
                command: json!({"command":"set_generation","generate":false,"expected_revision":0}),
            }],
        )
        .control_state(topics.generation.clone())
        .control_revision("/value/revision")
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
            let ca = Arc::new(Ca::in_memory(&cx, start)?);
            let addresses = Arc::new(Addresses::new(seed.fixed_addresses(), None)?);
            let stub = Arc::new(Stub::new(seed.clone()));
            let log = Arc::new(Log::new(Box::new(std::io::sink()), &[], |s| s));
            let (attacher, attachments) = fictionet::attachments();
            adaptive_web_world::serve(&cx, addresses, ca, stub.clone(), log, start, attachments)?;
            topics.start(&cx, searches.clone(), stub)?;
            let machine = machine(
                &cx,
                attacher.attach("workstation")?,
                "10.0.0.2".parse::<std::net::Ipv4Addr>()?,
            );
            // Advance the lab clock through the spawned task's publication intervals.
            cx.sleep(std::time::Duration::from_millis(100)).await?;
            let initial = gate::get(&client, "/api/state/search-state").await.unwrap();
            fetch(
                &cx,
                &machine,
                "www.google.com",
                "/search?q=halvard+gateway+vulnerability",
                start,
            )
            .await;
            cx.sleep(std::time::Duration::from_millis(100)).await?;
            let snapshot = gate::get(&client, "/api/state/search-state").await.unwrap();
            assert!(snapshot["revision"].as_u64().unwrap() > initial["revision"].as_u64().unwrap());
            let published = snapshot["revision"].clone();
            cx.sleep(std::time::Duration::from_millis(250)).await?;
            let idle = gate::get(&client, "/api/state/search-state").await.unwrap();
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
            let first = gate::first_generated(&seed, &state.results[0]).unwrap();
            let (host, path) = adaptive_web_world::stub::text::target_of(&first.url);
            fetch(&cx, &machine, &host, &path, start).await;
            cx.sleep(std::time::Duration::from_millis(100)).await?;
            let snapshot = gate::get(&client, "/api/state/search-state").await.unwrap();
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
                gate::get(&client, "/api/state/search-state").await.unwrap()["revision"],
                published
            );
            let reply = gate::command(&client, false, 0, "stop").await.unwrap();
            assert_eq!(reply["status"], "applied");
            assert_eq!(reply["reply"]["revision"], 1);
            let reply = gate::command(&client, true, 0, "old").await.unwrap();
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
            let snapshot = gate::get(&client, "/api/state/search-state").await.unwrap();
            assert!(snapshot["revision"].as_u64().unwrap() > published.as_u64().unwrap());
            let queries = snapshot["value"]["queries"].as_array().unwrap();
            assert_eq!(queries.last().unwrap()["results"], 0);
            assert_eq!(queries.last().unwrap()["outcome"]["status"], "served");
            assert_eq!(snapshot["value"]["generator"]["generate"], false);
            assert_eq!(snapshot["value"]["generator"]["generation_revision"], 1);
            let policy = gate::get(&client, "/api/state/policy").await.unwrap();
            assert_eq!(
                policy["value"],
                serde_json::to_value(page::policy()).unwrap()
            );
            assert_eq!(policy["value"]["forwarded"].as_array().unwrap().len(), 3);
            let commands = gate::get(&client, "/api/events").await.unwrap();
            assert_eq!(
                commands["events"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|e| e["source"] == "page" && e["kind"] == "command")
                    .count(),
                2
            );
            let generation = gate::get(&client, "/api/state/generation").await.unwrap();
            assert_eq!(
                generation["value"],
                json!({"generate":false,"revision":1,"generator":"stub generator (no model)"})
            );
            cx.cancel();
            Ok(())
        },
    )
    .await
    .unwrap();
}
