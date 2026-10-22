//! Commands pass through HTTP and execute in the world's task.

use super::*;
use fictionet::stdlib::services::ca::Ca;
use fictionet::{RunOptions, Seed};
use fictionet_demo::kit::client::PageClient;
use fictionet_observe::{DashboardObserver, DashboardOptions};
use serde_json::{Value, json};
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_commands_change_the_route_and_record_inputs() {
    let dashboard = DashboardObserver::new(DashboardOptions {
        collector: fictionet_observe::Options::default(),
        ..Default::default()
    });
    let control = control::Control::new(&control::scenario()).unwrap();
    let server = control
        .page(Page::new("Border", dashboard.handle()))
        .bind_loopback(0)
        .await
        .unwrap();
    let client = PageClient::from_url(server.url()).unwrap();
    client.bootstrap().await.unwrap();
    let initial: Value = client.get_json("/api/state/routing").await.unwrap();
    assert_eq!(initial["value"]["revision"], 0);
    // Receive the external inputs before advancing the closed lab.
    let url = server.url().to_owned();
    let request = tokio::spawn(async move {
        api::set_route(&PageClient::from_url(url).unwrap(), "flip", "hijack", 0)
            .await
            .unwrap()
    });
    let first = control.port.recv().await.unwrap();
    let url = server.url().to_owned();
    let repeat = tokio::spawn(async move {
        api::set_route(&PageClient::from_url(url).unwrap(), "stale", "hijack", 0)
            .await
            .unwrap()
    });
    let second = control.port.recv().await.unwrap();
    let url = server.url().to_owned();
    let unchanged = tokio::spawn(async move {
        api::set_route(
            &PageClient::from_url(url).unwrap(),
            "unchanged",
            "hijack",
            1,
        )
        .await
        .unwrap()
    });
    let third = control.port.recv().await.unwrap();
    let url = server.url().to_owned();
    let off = tokio::spawn(async move {
        api::world(
            &PageClient::from_url(url).unwrap(),
            "off",
            json!({"command": "impostor", "on": false}),
            1,
        )
        .await
        .unwrap()
    });
    let fourth = control.port.recv().await.unwrap();
    let url = server.url().to_owned();
    let restart = tokio::spawn(async move {
        api::world(
            &PageClient::from_url(url).unwrap(),
            "restart",
            json!({"command": "restart"}),
            2,
        )
        .await
        .unwrap()
    });
    let fifth = control.port.recv().await.unwrap();
    let state_slot = Arc::new(std::sync::Mutex::new(None));
    let state_out = state_slot.clone();
    fictionet::lab(
        RunOptions::new(Seed::from_u64(19)).observer(dashboard.observer()),
        move |cx| async move {
            let ca = Ca::new(&cx, "Test Root CA")?;
            let ids = border_world::identities(&cx, &ca)?;
            let (_attacher, attachments) = fictionet::attachments();
            let routing = border_world::start(&cx, control::scenario(), ids, attachments)?;
            kit::answer_command(&cx, first, |route| control.apply(&cx, &routing, route))?;
            let changed = routing.state();
            assert_eq!(changed.revision, 1);
            assert_eq!(changed.mode, border_world::scenario::Variant::Hijack);
            kit::answer_command(&cx, second, |route| control.apply(&cx, &routing, route))?;
            assert_eq!(routing.state(), changed);
            kit::answer_command(&cx, third, |route| control.apply(&cx, &routing, route))?;
            assert_eq!(routing.state(), changed);
            kit::answer_command(&cx, fourth, |command| control.apply(&cx, &routing, command))?;
            let silent = routing.state();
            assert_eq!(
                (silent.revision, silent.mode, silent.impostor),
                (2, changed.mode, false)
            );
            kit::answer_command(&cx, fifth, |command| control.apply(&cx, &routing, command))?;
            let restarted = routing.state();
            assert_eq!(
                (restarted.revision, restarted.mode, restarted.impostor),
                (3, border_world::scenario::Variant::Legitimate, true)
            );
            *state_out.lock().unwrap() = Some((changed, restarted));
            cx.cancel();
            Ok(())
        },
    )
    .await
    .unwrap();
    let (changed, restarted) = state_slot.lock().unwrap().clone().unwrap();
    let applied = request.await.unwrap();
    assert_eq!(
        applied["reply"],
        json!({"revision": 1, "at_ms": changed.since_ms})
    );
    let stale = repeat.await.unwrap();
    assert_eq!(stale["status"], "rejected");
    assert_eq!(stale["rejection"]["reason"], "stale_revision");
    let unchanged = unchanged.await.unwrap();
    assert_eq!(unchanged["status"], "rejected");
    assert_eq!(unchanged["rejection"]["reason"], "invalid");
    assert_eq!(
        unchanged["rejection"]["message"],
        "The route is already hijacked."
    );
    assert_eq!(off.await.unwrap()["reply"]["revision"], 2);
    assert_eq!(restart.await.unwrap()["reply"]["revision"], 3);
    let state: Value = client.get_json("/api/state/routing").await.unwrap();
    assert_eq!(state["value"], serde_json::to_value(&restarted).unwrap());
    let unknown = client.request("POST", "/api/command/world", Some(&json!({"request_id":"unknown", "command":{"command":"route","mode":"legitimate", "expected_revision":3,"surprise":true}})), true).await.unwrap();
    assert_eq!(unknown.status, 400);
    assert!(
        String::from_utf8(unknown.body)
            .unwrap()
            .contains("surprise")
    );
    let state: Value = client.get_json("/api/state/routing").await.unwrap();
    assert_eq!(state["value"], serde_json::to_value(&restarted).unwrap());
    let events = client
        .request("GET", "/api/events", None, true)
        .await
        .unwrap();
    let events = String::from_utf8(events.body).unwrap();
    assert!(events.contains("\"source\":\"page\""), "{events}");
    assert!(events.contains("\"kind\":\"command\""));
    assert!(events.contains("\"request_id\":\"flip\""));
    assert!(events.contains("\"expected_revision\":0"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn world_menu_buttons_use_the_world_revision() {
    let dashboard = DashboardObserver::new(DashboardOptions {
        collector: fictionet_observe::Options::default(),
        ..Default::default()
    });
    let control = control::Control::new(&control::scenario()).unwrap();
    let server = control
        .page(
            Page::new("Border", dashboard.handle())
                .host(fictionet_observe::page::Host::new(guest::HOSTNAME))
                .standard_panels(),
        )
        .bind_loopback(0)
        .await
        .unwrap();
    let (send, received) = tokio::sync::oneshot::channel();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let worker = tokio::spawn(fictionet::run(
        RunOptions::new(Seed::from_u64(20)).observer(dashboard.observer()),
        move |cx| async move {
            let ca = Ca::new(&cx, "Test Root CA")?;
            let (_attacher, attachments) = fictionet::attachments();
            let routing = border_world::start(
                &cx,
                control::scenario(),
                border_world::identities(&cx, &ca)?,
                attachments,
            )?;
            send.send(routing.clone()).ok();
            cx.spawn(move |cx| control.serve(cx, routing));
            cx.race(None, stopped)
                .await
                .map_err(|_| fictionet::Cancelled)?
                .ok();
            cx.cancel();
            Ok(())
        },
    ));
    let routing = received.await.unwrap();
    let dir = std::env::temp_dir().join(format!("border-page-{}", kit::random_uuid()));
    std::fs::create_dir(&dir).unwrap();
    struct RemoveDirectory(PathBuf);
    impl Drop for RemoveDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _directory = RemoveDirectory(dir.clone());
    for (name, action, mode, impostor, revision, theme) in [
        ("normal", "", "normal", "on", 0, "light"),
        ("hijacked", "Hijacked", "hijack", "on", 1, "light"),
        ("silent", "Off", "hijack", "off", 2, "light"),
        ("restarted", "Restart", "normal", "on", 3, "light"),
        ("hijacked-dark", "Hijacked", "hijack", "on", 4, "dark"),
        ("restarted-dark", "Restart", "normal", "on", 5, "dark"),
    ] {
        let condition = format!(
            r#"(() => {{
            const buttons = [...document.querySelectorAll('#world-menu button')];
            const world = document.querySelector('.border-world');
            if (!world || !buttons.length || buttons.some(b => b.disabled)) return false;
            if ({action:?} && !window.sent) {{
                window.sent = true;
                buttons.find(b => b.textContent === {action:?}).click();
                return false;
            }}
            const pressed = buttons.filter(b => b.getAttribute('aria-pressed') === 'true').map(b => b.textContent);
            return world.dataset.mode === {mode:?} && world.dataset.impostor === {impostor:?}
                && pressed.includes({mode:?} === 'hijack' ? 'Hijacked' : 'Normal')
                && pressed.includes({impostor:?} === 'on' ? 'On' : 'Off');
        }})()"#
        );
        let url = server.url().replace("/#", &format!("/?theme={theme}#"));
        let path = dir.join(format!("{name}.png"));
        let captured = tokio::task::spawn_blocking(move || {
            kit::shot::capture(
                &url,
                &[kit::shot::Step {
                    ready: &condition,
                    out: Some(&path),
                    ..Default::default()
                }],
                Duration::from_secs(20),
            )?;
            Ok::<_, std::io::Error>(path.display().to_string())
        })
        .await
        .unwrap()
        .unwrap();
        let state = routing.state();
        assert_eq!(state.revision, revision);
        assert_eq!(state.impostor, impostor == "on");
        assert_eq!(
            json!(state.mode),
            if mode == "hijack" {
                "hijack"
            } else {
                "legitimate"
            }
        );
        println!("Browser World menu capture: {captured}");
    }
    stop.send(()).unwrap();
    worker.await.unwrap().unwrap();
}

pub(super) mod api {
    use super::*;
    use border_world::scenario::{BANK_ADDR, HIJACK_PREFIX, IMPOSTOR_ADDR, Variant};
    use std::io;
    /// Sends a World menu command, as the page does, at `revision`.
    pub async fn world(
        client: &PageClient,
        id: &str,
        mut command: Value,
        revision: u64,
    ) -> io::Result<Value> {
        command["expected_revision"] = revision.into();
        client.command("world", id, command).await
    }

    /// Asks the World menu's Route for `mode` at `revision`.
    pub async fn set_route(
        client: &PageClient,
        id: &str,
        mode: &str,
        revision: u64,
    ) -> io::Result<Value> {
        world(
            client,
            id,
            json!({"command": "route", "mode": mode}),
            revision,
        )
        .await
    }

    pub const HIJACKED_PAGE: &str = r#"(() => {
    const world = document.querySelector('.border-world');
    if (!world || world.dataset.mode !== 'hijack' || world.dataset.impostor !== 'on') return false;
    const row = [...world.querySelectorAll('.border-row.hot')].find(r => r.textContent.includes('POST /login'));
    return !!row && row.textContent.includes('workstation → impostor')
        && !!world.querySelector('.node.impostor.hot')
        && !!world.querySelector('.token.shown')
        && !!world.querySelector('.edge.bad')
        && !world.classList.contains('flash')
        && world.getAnimations({ subtree: true }).every(a => a.playState !== 'running');
})()"#;
    pub async fn observed(client: &PageClient, hijacked: bool) -> io::Result<()> {
        client
            .wait_for(
                "/api/state/border",
                Duration::from_secs(10),
                Duration::from_millis(100),
                "Border observations did not contain the complete traffic story",
                |snapshot| {
                    if exposes_password(snapshot) {
                        return Err(io::Error::other("Border state exposed the password"));
                    }
                    if snapshot["status"]["too_large"] == true {
                        return Err(io::Error::other("Border state exceeded its byte bound"));
                    }
                    Ok(observed_complete(&snapshot["value"], hijacked))
                },
            )
            .await?;
        Ok(())
    }

    fn exposes_password(value: &Value) -> bool {
        value
            .to_string()
            .to_lowercase()
            .contains(&border_world::bank::ACCOUNT.password.to_lowercase())
    }

    fn observed_complete(view: &Value, hijacked: bool) -> bool {
        let rows = |key: &str| {
            view[key]["rows"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default()
        };
        let mut hops: Vec<String> = routed(hijacked)
            .hops(BANK_ADDR)
            .iter()
            .map(ToString::to_string)
            .collect();
        hops.push(BANK_ADDR.to_string());
        let hijack_prefix = format!("{}/{}", HIJACK_PREFIX.addr, HIJACK_PREFIX.len);
        let trace =
            view["links"].as_array().is_some_and(|links| {
                links.iter().any(|t| {
                    t["sandbox"] == crate::guest::HOSTNAME
                        && t["trace"]["complete"] == true
                        && t["trace"]["dropped"] == 0
                        && t["trace"]["hops"].as_array().is_some_and(|actual| {
                            actual.len() == hops.len()
                                && actual.iter().zip(&hops).enumerate().all(|(i, (a, b))| {
                                    a["address"] == b.as_str() && a["ttl"] == i + 1
                                })
                        })
                })
            });
        let bgp = rows("bgp").iter().any(|e| {
            e["sandbox"] == crate::guest::HOSTNAME
                && e["kind"] == "sent"
                && e["message"] == "UPDATE"
                && e[if hijacked { "announced" } else { "withdrawn" }]
                    .as_array()
                    .is_some_and(|routes| routes.iter().any(|p| *p == hijack_prefix))
        });
        let moments: Vec<_> = rows("moments")
            .iter()
            .filter(|m| {
                m["sandbox"] == crate::guest::HOSTNAME
                    && m["password"] == true
                    && m["endpoint"]["machine"] == IMPOSTOR_ADDR.to_string()
                    && m["endpoint"]["reached"] == BANK_ADDR.to_string()
            })
            .collect();
        let tls = moments.iter().any(|m| {
            m["connection"].as_u64().is_some()
                && rows("tls").iter().any(|t| {
                    t["sandbox"] == crate::guest::HOSTNAME
                        && t["identity"] == "impostor"
                        && t["outcome"] == "accepted"
                        && t["connection"] == m["connection"]
                        && t["endpoint"] == m["endpoint"]
                })
        });
        let row = |from: &str, to: Option<&str>, what: &str, tone: &str| {
            rows("rows").iter().any(|r| {
                r["from"] == from
                    && r["to"] == to.map_or(Value::Null, Into::into)
                    && r["what"] == what
                    && r["tone"] == tone
            })
        };
        let pictured = if hijacked {
            row("Transpeak", None, "Route announced", "")
                && row("workstation", Some("impostor"), "POST /login", "hot")
                && row(
                    "workstation",
                    Some("impostor"),
                    "Certificate refused",
                    "warn",
                )
        } else {
            row("Transpeak", None, "Route withdrawn", "")
                && row("workstation", Some("Kestrelmoor"), "GET /balance", "")
        };
        trace
            && bgp
            && tls
            && pictured
            && moments.len() == 1
            && view["lost"] == 0
            && view["truncated"] == 0
    }
    fn routed(hijacked: bool) -> border_world::scenario::Scenario {
        crate::control::scenario().routed(if hijacked {
            Variant::Hijack
        } else {
            Variant::Legitimate
        })
    }
}
