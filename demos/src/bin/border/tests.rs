//! Commands pass through HTTP and execute in the world's task.

use super::*;
use fictionet::stdlib::services::ca::Ca;
use fictionet::{RunOptions, Seed};
use fictionet_demo::kit::client::PageClient;
use fictionet_observe::{DashboardObserver, DashboardOptions};
use serde_json::{Value, json};

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
    let url = server.url().to_owned();
    let off = tokio::spawn(async move {
        story::world(
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
        story::world(
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
