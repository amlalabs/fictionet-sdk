//! Commands pass through HTTP and execute in the world's task.

use super::*;
use fictionet::stdlib::services::ca::Ca;
use fictionet::{RunOptions, Seed};
use fictionet_demo::kit::client::PageClient;
use fictionet_observe::{DashboardObserver, DashboardOptions};
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_commands_change_the_route_and_record_inputs() {
    let dashboard = DashboardObserver::new(DashboardOptions::demo());
    let control = control::Control::new(&control::scenario()).unwrap();
    let server = control
        .page(Page::new("Border", dashboard.handle()))
        .bind_loopback(0)
        .await
        .unwrap();
    let client = PageClient::from_url(server.url()).unwrap();
    client.bootstrap().await.unwrap();
    let initial = client
        .request("GET", "/api/state/routing", None, true)
        .await
        .unwrap();
    let initial: Value = serde_json::from_slice(&initial.body).unwrap();
    assert_eq!(initial["value"]["revision"], 0);
    // Receive the external inputs before advancing the closed lab.
    let url = server.url().to_owned();
    let request = tokio::spawn(async move {
        story::set_route(&PageClient::from_url(url).unwrap(), "flip", "hijack", 0)
            .await
            .unwrap()
    });
    let first = control.port.recv().await.unwrap();
    let url = server.url().to_owned();
    let repeat = tokio::spawn(async move {
        story::set_route(&PageClient::from_url(url).unwrap(), "stale", "hijack", 0)
            .await
            .unwrap()
    });
    let second = control.port.recv().await.unwrap();
    let url = server.url().to_owned();
    let unchanged = tokio::spawn(async move {
        story::set_route(
            &PageClient::from_url(url).unwrap(),
            "unchanged",
            "hijack",
            1,
        )
        .await
        .unwrap()
    });
    let third = control.port.recv().await.unwrap();
    let state_slot = Arc::new(std::sync::Mutex::new(None));
    let state_out = state_slot.clone();
    fictionet::lab(
        RunOptions::new(Seed::from_u64(19)).observer(dashboard.observer()),
        move |cx| async move {
            let ca = Ca::new(&cx, "Test Root CA")?;
            let ids = border_world::identities(&cx, &ca)?;
            let (_attacher, attachments) = fictionet::attachments();
            let routing = border_world::start(&cx, control::scenario(), ids, attachments)?;
            control.apply(&cx, &routing, first)?;
            let changed = routing.state();
            assert_eq!(changed.revision, 1);
            assert_eq!(changed.mode, border_world::scenario::Variant::Hijack);
            control.apply(&cx, &routing, second)?;
            assert_eq!(routing.state(), changed);
            control.apply(&cx, &routing, third)?;
            assert_eq!(routing.state(), changed);
            *state_out.lock().unwrap() = Some(changed);
            cx.cancel();
            Ok(())
        },
    )
    .await
    .unwrap();
    let changed = state_slot.lock().unwrap().clone().unwrap();
    let applied = request.await.unwrap();
    assert_eq!(
        applied["reply"],
        json!({"revision": 1, "at_ms": changed.since_ms})
    );
    let state = client
        .request("GET", "/api/state/routing", None, true)
        .await
        .unwrap();
    let state: Value = serde_json::from_slice(&state.body).unwrap();
    assert_eq!(state["value"], serde_json::to_value(&changed).unwrap());
    let stale = repeat.await.unwrap();
    assert_eq!(stale["status"], "rejected");
    assert_eq!(stale["rejection"]["reason"], "stale_revision");
    let unchanged = unchanged.await.unwrap();
    assert_eq!(unchanged["status"], "rejected");
    assert_eq!(unchanged["rejection"]["reason"], "invalid");
    assert_eq!(
        unchanged["rejection"]["message"],
        "the route is already Hijacked (revision 1)"
    );
    let unknown = client.request("POST", "/api/command/routing", Some(&json!({"request_id":"unknown", "command":{"mode":"legitimate", "expected_revision":1,"surprise":true}})), true).await.unwrap();
    assert_eq!(unknown.status, 400);
    assert!(
        String::from_utf8(unknown.body)
            .unwrap()
            .contains("surprise")
    );
    let state = client
        .request("GET", "/api/state/routing", None, true)
        .await
        .unwrap();
    let state: Value = serde_json::from_slice(&state.body).unwrap();
    assert_eq!(state["value"], serde_json::to_value(&changed).unwrap());
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
async fn browser_buttons_use_the_world_revision() {
    let dashboard = DashboardObserver::new(DashboardOptions::demo());
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
    for (name, action, mode, revision, theme) in [
        ("normal", "", "legitimate", 0, "light"),
        ("hijacked", "Hijacked", "hijack", 1, "light"),
        ("restored", "Normal", "legitimate", 2, "light"),
        ("normal-dark", "", "legitimate", 2, "dark"),
        ("hijacked-dark", "Hijacked", "hijack", 3, "dark"),
        ("restored-dark", "Normal", "legitimate", 4, "dark"),
    ] {
        let condition = format!(
            r#"(() => {{
            const tab = document.querySelector('#tab-routing');
            if (!tab) return false;
            if (tab.getAttribute('aria-selected') !== 'true') {{ tab.click(); return false; }}
            const state = document.querySelector('.control-state');
            const buttons = [...document.querySelectorAll('.control-actions button')];
            if (!state || !buttons.length || buttons.some(b => b.disabled)) return false;
            if ({action:?} && !window.sent) {{
                window.sent = true;
                buttons.find(b => b.textContent === {action:?}).click();
                return false;
            }}
            const rows = [...state.querySelectorAll('dt')];
            return rows.some(row => row.textContent === 'Revision' && row.nextElementSibling.textContent === String({revision}))
                && rows.some(row => row.textContent === 'Mode' && row.nextElementSibling.textContent === {mode:?});
        }})()"#
        );
        let url = server.url().replace("/#", &format!("/?theme={theme}#"));
        let path = dir.join(format!("{name}.png"));
        let captured = tokio::task::spawn_blocking(move || {
            kit::shot::capture(&url, &path, &condition, Duration::from_secs(20))
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(routing.state().revision, revision);
        assert_eq!(routing.state().mode.as_str(), mode);
        println!("Browser routing capture: {captured}");
    }
    stop.send(()).unwrap();
    worker.await.unwrap().unwrap();
}
