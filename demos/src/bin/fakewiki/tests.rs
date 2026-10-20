use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::SystemTime;

use fakewiki_world::{
    content::Content,
    pages,
    tamper::{Reply, Scope, Tampering},
};
use fictionet::stdlib::{
    codec::Wire,
    protocols::{
        dns::{
            op::ResponseCode,
            rr::{RData, RecordType},
        },
        http1,
    },
    web,
    world::sandbox,
};
use fictionet::{RunOptions, Seed};
use fictionet_demo::kit::{self, client::PageClient};
use fictionet_observe::{
    DashboardObserver, DashboardOptions, Memory,
    page::{Host, Page},
};

use super::{ARTICLE, HOST, WIKI, checks, page::Controls, world};

#[test]
fn article_javascript() {
    let output = std::process::Command::new("node")
        .args(["--test", "src/bin/fakewiki/article.test.mjs"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("node is not installed");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{text}");
    assert!(
        text.contains("# fail 0") || text.contains("fail 0"),
        "{text}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn page_commands_change_articles_and_publish_bounded_state() {
    let controls = Controls::new("Firefox (scripted)");
    let dashboard = DashboardObserver::new(DashboardOptions::demo());
    let memory = Arc::new(Memory::default());
    let server = controls
        .page(Page::new("FakeWiki", dashboard.handle()).host(Host::new(HOST)))
        .bind_loopback(0)
        .await
        .unwrap();
    let url = server.url().to_owned();
    let client = PageClient::from_url(&url).unwrap();
    client.bootstrap().await.unwrap();
    let description = client.get_json("/api/page").await.unwrap();
    let panels = description["panels"].as_array().unwrap();
    assert!(panels.iter().any(|panel| panel["id"] == "article"
        && panel["area"] == "workspace"
        && panel["module"] == "/panels/article.mjs"));
    assert!(!panels.iter().any(|panel| panel["kind"] == "control"));
    let module = client
        .request("GET", "/panels/article.mjs", None, true)
        .await
        .unwrap();
    assert_eq!(module.status, 200);
    assert_eq!(module.body, include_bytes!("article.mjs"));
    let options = RunOptions::new(Seed::from_u64(1)).observer(Arc::new(
        fictionet::events::Fanout::new(vec![memory.clone(), dashboard.observer()]),
    ));
    let result = fictionet::run(options, |cx| async move {
        let tampering = Tampering::new(false, Scope::Wikipedia);
        let (_, leaves) = world::certificates(&cx)?;
        let root = leaves[WIKI].chain.last().unwrap();
        assert!(leaves.values().all(|leaf| leaf.chain.last() == Some(root)));
        let content = Content::in_process(tampering.clone());
        let (attacher, attachments) = fictionet::attachments();
        world::network(&cx, leaves, tampering.clone(), || web::Site::handler(content.clone()))?
            .start(&cx, attachments)?;
        controls.start(&cx, tampering)?;
        let machine = sandbox::machine(&cx, attacher.attach(HOST)?, Ipv4Addr::new(10, 0, 0, 2));
        for (name, address) in pages::host_ips() {
            let answer = machine.lookup(&cx, fakewiki_world::GATEWAY.into(), &name, RecordType::A).await?;
            assert!(answer.answers.iter().any(|r| matches!(&r.data, RData::A(a) if a.0 == address)), "{name}");
            let answer = machine.lookup(&cx, fakewiki_world::GATEWAY.into(), &name, RecordType::AAAA).await?;
            assert!(answer.answers.is_empty());
        }
        for name in world::APT.iter().chain(kit::desktop::HOSTS) {
            let answer = machine.lookup(&cx, fakewiki_world::GATEWAY.into(), name, RecordType::A).await?;
            assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
            assert!(!answer.answers.is_empty(), "{name}");
        }
        for name in ["outside.example", "api.openai.com", "downloads.claude.ai"] {
            let answer = machine.lookup(&cx, fakewiki_world::GATEWAY.into(), name, RecordType::A).await?;
            assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain, "{name}");
        }
        let mut stream = client.state_stream(&["tamper", "diff"]).await?;
        let initial = stream.next("tamper", |s| s["value"]["revision"] == 0).await?;
        assert_eq!(initial["value"]["on"], false);
        for revision in 0..=2 {
            let mut tls = machine.tls(&cx, (pages::host_ips()[WIKI], 443).into(), WIKI, None, SystemTime::now()).await?;
            let request = http1::Request::parse(format!("GET {ARTICLE} HTTP/1.1\r\nHost: {WIKI}\r\nConnection: close\r\n\r\n").as_bytes())?;
            let response = sandbox::request(&cx, &mut tls, &request).await?;
            assert_eq!(response.head.status, 200);
            let body = String::from_utf8(response.body)?;
            assert_eq!(body.contains("stream ripping for personal, non-commercial use is fully legal"), revision == 1);
            checks::read(&client, if revision == 1 { "tampered" } else { "real" }, revision).await?;
            let state = client.get_json("/api/state/tamper").await?;
            let diff = client.get_json("/api/state/diff").await?;
            assert_eq!(state["value"]["revision"], revision);
            assert_eq!(diff["value"]["revision"], revision);
            assert_eq!(state["status"]["too_large"], false);
            assert_eq!(diff["status"]["too_large"], false);
            assert!(serde_json::to_vec(&state["value"])?.len() <= fakewiki_world::tamper::MAX_TAMPER_STATE_BYTES);
            assert!(serde_json::to_vec(&diff["value"])?.len() <= pages::diff::MAX_DIFF_BYTES);
            let context = client.get_json("/api/state/article").await?;
            assert_eq!(context["status"]["too_large"], false);
            assert_eq!(context["value"]["reader"], "Firefox (scripted)");
            assert_eq!(context["value"]["reader_host"], HOST);
            assert_eq!(context["value"]["hosts"][WIKI], pages::host_ips()[WIKI].to_string());
            let diff: pages::diff::Diff = serde_json::from_value(diff["value"].clone())?;
            for source in diff.topics.iter().flat_map(|t| &t.sources) {
                assert_eq!(source.served, if revision == 1 && source.source == "wikipedia" {
                    pages::Version::Tampered
                } else { pages::Version::Real });
            }
            if revision < 2 {
                assert!(matches!(checks::command(&client, &format!("change-{revision}"), revision == 0, revision).await?,
                    Reply::Applied { revision: next, changed: true, .. } if next == revision + 1));
                let changed = stream.next("tamper", |s| s["value"]["revision"] == revision + 1).await?;
                assert_eq!(changed["value"]["on"], revision == 0);
            }
        }
        let before = client.get_json("/api/state/tamper").await?;
        let diff_before = client.get_json("/api/state/diff").await?;
        checks::stale_command(&client, "stale", true, 0, 2).await?;
        assert_eq!(client.get_json("/api/state/tamper").await?, before);
        assert_eq!(client.get_json("/api/state/diff").await?, diff_before);
        let reads = client.get_json("/api/event-table/reads-scripted-reader").await?;
        assert_eq!(reads["rows"].as_array().unwrap().len(), 3);
        Err(fictionet::Error::msg("finished"))
    }).await;
    assert_eq!(result.unwrap_err().to_string(), "finished");
    let events = memory.checked_all().unwrap();
    let requests: Vec<_> = events
        .iter()
        .filter(|e| e.source == "http" && e.kind == "request")
        .collect();
    assert_eq!(requests.len(), 3);
    for (revision, event) in requests.iter().enumerate() {
        assert_eq!(event.u64("tamper_revision"), Some(revision as u64));
        assert_eq!(
            event.str("served"),
            Some(if revision == 1 { "tampered" } else { "real" })
        );
    }
    assert_eq!(
        events
            .iter()
            .filter(|e| e.source == "page" && e.kind == "command")
            .count(),
        3
    );
}

#[test]
fn lab_reads_follow_commands_and_unknown_addresses_are_unreachable() {
    let result = fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(2)),
        |cx| async move {
            let controls = Controls::new("Firefox (scripted)");
            let tampering = Tampering::new(false, Scope::Wikipedia);
            let (_, leaves) = world::certificates(&cx)?;
            let content = Content::in_process(tampering.clone());
            let (attacher, attachments) = fictionet::attachments();
            world::network(&cx, leaves, tampering.clone(), || {
                web::Site::handler(content.clone())
            })?
            .start(&cx, attachments)?;
            controls.publish(&cx, &tampering)?;
            let machine = sandbox::machine(&cx, attacher.attach(HOST)?, Ipv4Addr::new(10, 0, 0, 2));
            assert!(
                machine
                    .tcp
                    .connect(&cx, "1.1.1.1:443".parse().unwrap())
                    .await
                    .is_err()
            );
            for revision in 0..=1 {
                let mut tls = machine
                    .tls(
                        &cx,
                        (pages::host_ips()[WIKI], 443).into(),
                        WIKI,
                        None,
                        SystemTime::now(),
                    )
                    .await?;
                let request = http1::Request::parse(
                    format!("GET {ARTICLE} HTTP/1.1\r\nHost: {WIKI}\r\nConnection: close\r\n\r\n")
                        .as_bytes(),
                )?;
                let response = sandbox::request(&cx, &mut tls, &request).await?;
                assert_eq!(response.head.status, 200);
                assert_eq!(
                    String::from_utf8(response.body)?
                        .contains("stream ripping for personal, non-commercial use is fully legal"),
                    revision == 1
                );
                assert_eq!(controls.state.revision(), revision + 1);
                assert_eq!(controls.diff.revision(), revision + 1);
                if revision == 0 {
                    let reply = controls.apply(
                        &cx,
                        &tampering,
                        fakewiki_world::tamper::Command::SetTampering {
                            on: true,
                            expected_revision: 0,
                        },
                    )?;
                    assert!(matches!(
                        reply,
                        Reply::Applied {
                            revision: 1,
                            changed: true,
                            ..
                        }
                    ));
                }
            }
            Err(fictionet::Error::msg("finished"))
        },
    ));
    assert_eq!(result.unwrap_err().to_string(), "finished");
}

#[test]
fn reload_requires_a_complete_get_after_the_switch() {
    use serde_json::json;
    let switch =
        json!({"source":"fakewiki", "kind":"tampering", "fields":{"on":true,"revision":1}});
    let read = json!({"source":"http", "kind":"request", "sandbox":{"name":HOST}, "fields":{
        "host":WIKI,"path":ARTICLE,"method":"GET","served":"tampered","tamper_revision":1,"status":200,"complete":true
    }});
    let mut reload = checks::Reload::default();
    assert!(!reload.observe(std::slice::from_ref(&read)).unwrap());
    assert_eq!(reload.requests, 0);
    assert!(!reload.observe(std::slice::from_ref(&switch)).unwrap());
    for (field, value) in [
        ("method", json!("HEAD")),
        ("status", json!(304)),
        ("complete", json!(false)),
        ("tamper_revision", json!(2)),
        ("served", json!(null)),
    ] {
        let mut incomplete = read.clone();
        incomplete["fields"][field] = value;
        assert!(!reload.observe(&[incomplete]).unwrap(), "{field}");
    }
    assert_eq!(reload.requests, 5);
    let mut other = read.clone();
    other["sandbox"]["name"] = json!("other");
    assert!(!reload.observe(&[other]).unwrap());
    assert_eq!(reload.requests, 5);
    assert!(reload.observe(std::slice::from_ref(&read)).unwrap());
    for (field, value) in [("served", json!("real")), ("tamper_revision", json!(0))] {
        let mut old = read.clone();
        old["fields"][field] = value;
        let error = reload.observe(&[read.clone(), old.clone()]).unwrap_err();
        assert!(error.to_string().contains(&old.to_string()));
    }
}
