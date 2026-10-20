//! The scripted terminal story and the page's own command client.

use super::{checks, guest::HOSTNAME};
use fictionet_demo::kit::{
    self, Run,
    client::{Capability, PageClient},
    ssh::{self, quote},
};
use serde_json::{Value, json};
use std::io;
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

pub async fn command(ssh: &ssh::Session, command: &str) -> io::Result<ssh::Output> {
    let output =
        tokio::time::timeout(Duration::from_secs(100), ssh.run_bounded(command, 1 << 20)).await??;
    if output.code != 0 {
        return Err(io::Error::other(format!(
            "{command}: exit {}\n{}{}",
            output.code, output.stdout, output.stderr
        )));
    }
    Ok(output)
}

async fn begin(ssh: &ssh::Session, step: &str) -> io::Result<()> {
    let line = format!("bank-check {step}");
    command(
        ssh,
        &format!(
            "tmux send-keys -t main -l {} && tmux send-keys -t main Enter",
            quote(&line)
        ),
    )
    .await?;
    Ok(())
}

async fn finish(ssh: &ssh::Session, step: &str, hijacked: bool) -> io::Result<()> {
    command(ssh, "timeout 90 tmux wait-for bank-check").await?;
    let text = command(ssh, "cat ~/.cache/bank-check/output").await?;
    let status = command(ssh, "cat ~/.cache/bank-check/status").await?;
    let output = ssh::Output {
        code: status.stdout.trim().parse().map_err(io::Error::other)?,
        stdout: text.stdout,
        stderr: text.stderr,
    };
    println!(
        "agent$ bank-check {step}\n{}[exit {}]",
        output.stdout, output.code
    );
    if !checks::check(
        step,
        &output,
        hijacked,
        super::control::scenario().gateway(),
    ) {
        return Err(io::Error::other(format!(
            "bank-check {step} did not produce the expected result"
        )));
    }
    Ok(())
}

async fn step(ssh: &ssh::Session, step: &str, hijacked: bool) -> io::Result<()> {
    begin(ssh, step).await?;
    finish(ssh, step, hijacked).await
}

/// Asks the page's Routing control for `mode` at `revision`.
pub async fn set_route(
    client: &PageClient,
    id: &str,
    mode: &str,
    revision: u64,
) -> io::Result<Value> {
    client
        .command(
            "routing",
            id,
            json!({"mode": mode, "expected_revision": revision}),
        )
        .await
}

async fn flip(client: &PageClient, mode: &str, revision: u64) -> io::Result<()> {
    let reply = set_route(client, &kit::random_uuid(), mode, revision).await?;
    if reply["status"] != "applied" || reply["reply"]["revision"] != revision + 1 {
        return Err(io::Error::other(format!("route was not applied: {reply}")));
    }
    println!("Routing: {mode}, applied revision {}", revision + 1);
    Ok(())
}

async fn title(ssh: &ssh::Session) -> io::Result<String> {
    Ok(command(ssh, "env DISPLAY=:1 sh -c 'xdotool search --onlyvisible --class firefox | head -n1 | xargs -r xdotool getwindowname'").await?.stdout.trim().to_owned())
}

async fn border_state(client: &PageClient) -> io::Result<Value> {
    Ok(client.get_json("/api/state/border").await?["value"].take())
}

fn aborted_after(view: &Value, after: u64) -> bool {
    view["tls"]["rows"].as_array().is_some_and(|rows| {
        rows.iter().any(|row| {
            row["event"].as_u64().is_some_and(|seq| seq > after)
                && row["sandbox"] == HOSTNAME
                && row["identity"] == "impostor"
                && row["outcome"] == "alert"
                && row["endpoint"]["machine"] == "45.144.30.10"
                && row["endpoint"]["reached"] == "84.21.44.10"
        })
    })
}

/// Whether the bank served Firefox in the guest its home page: the request
/// event ends once the whole response is written.
fn firefox_home_served(event: &Value) -> bool {
    let firefox = event["fields"]["headers"]
        .as_array()
        .is_some_and(|headers| {
            headers.iter().any(|h| {
                h[0] == "user-agent" && h[1].as_str().is_some_and(|ua| ua.contains("Firefox/"))
            })
        });
    event["source"] == "http"
        && event["kind"] == "request"
        && event["sandbox"]["name"] == HOSTNAME
        && event["fields"]["served_by"] == "bank"
        && event["fields"]["page"] == "home"
        && event["fields"]["method"] == "GET"
        && firefox
}

/// Reloads Firefox in the guest. A hijacked reload ends at the certificate
/// warning, after the world saw the guest abort a new handshake with the
/// impostor. A normal reload ends at the bank's page, after the bank served
/// Firefox's request for it.
async fn reload(run: &Run, hijacked: bool) -> io::Result<()> {
    let ssh = run.guest(HOSTNAME).ssh();
    let client = PageClient::from_url(run.page_url())?;
    let mut titles = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(60), async {
        let before = border_state(&client).await?;
        let after = before["tls"]["rows"].as_array().into_iter().flatten()
            .filter_map(|row| row["event"].as_u64()).max().unwrap_or(0);
        let mut cursor = client.last_event().await?;
        command(ssh, "env DISPLAY=:1 sh -c 'xdotool search --onlyvisible --class firefox | head -n1 | xargs -r -I{} xdotool key --window {} ctrl+r'").await?;
        let mut served = false;
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        loop {
            interval.tick().await;
            let current = title(ssh).await?;
            if !titles.contains(&current) {
                println!("Firefox title: {current:?}");
                titles.push(current.clone());
            }
            if !hijacked && !served && client.find_event(&mut cursor, |e| Ok(password_hidden(e)? && firefox_home_served(e))).await?.is_some() {
                served = true;
                println!("Firefox: the bank served the reloaded page.");
            }
            let bank = current.contains("Kestrelmoor");
            if !current.is_empty() && bank != hijacked
                && (hijacked || served)
                && (!hijacked || aborted_after(&border_state(&client).await?, after)) {
                println!("Firefox final title: {current:?}");
                if hijacked {
                    println!("Browser TLS: the impostor answered and the guest aborted with an alert.");
                }
                return Ok(());
            }
        }
    }).await;
    match result {
        Ok(result) => result,
        Err(_) => Err(io::Error::other(format!(
            "browser reload did not finish; titles seen: {titles:?}"
        ))),
    }
}

async fn terminal(client: &PageClient, ssh: &ssh::Session) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let expected = command(ssh, "tail -1 ~/.cache/bank-check/output").await?.stdout;
        let expected = expected.trim();
        if expected.is_empty() {
            return Err(io::Error::other("the agent's last output line is empty"));
        }
        let ticket = client.ticket(HOSTNAME, Capability::Terminal).await?;
        let mut socket = client.open(HOSTNAME, Capability::Terminal, Some(&ticket.ticket)).await?;
        socket.read_until(expected.as_bytes(), 64 << 10).await?;
        // The tmux client flag proves input is disabled before sending a command.
        let clients = command(ssh, "tmux list-clients -t main -F '#{client_readonly}'").await?;
        if !clients.stdout.lines().any(|line| line == "1") {
            return Err(io::Error::other("page terminal is not a read-only tmux client"));
        }
        let marker = format!("/tmp/terminal-{}", kit::random_uuid());
        socket.write_all(format!("touch {}\r", quote(&marker)).as_bytes()).await?;
        socket.flush().await?;
        // A fresh agent command supplies output after the viewer's input.
        step(ssh, "bgp 2", false).await?;
        command(ssh, &format!("test ! -e {}", quote(&marker))).await?;
        let pane = command(ssh, "tmux capture-pane -p -t main").await?;
        if pane.stdout.contains(&marker) {
            return Err(io::Error::other("viewer input reached the agent's pane"));
        }
        println!("Page terminal: agent output visible; viewer typing did not reach the read-only session.");
        Ok(())
    }).await?
}

/// The Border workspace at the hijack: the route flipped, the guest's
/// four-hop traceroute matching it, and the credential alert, with the
/// panel's animations finished.
pub const HIJACKED_PAGE: &str = r#"(() => {
    const panel = document.querySelector('.border-panel');
    if (!panel || panel.dataset.mode !== 'hijack') return false;
    const alert = panel.querySelector('.border-alert');
    const trace = panel.querySelector('.border-trace')?.textContent || '';
    return !!alert && !alert.hidden
        && alert.querySelector('h2')?.textContent === 'The password reached the impostor'
        && !!panel.querySelector('.border-path li.border-foreign')
        && trace.includes('3 45.144.30.1 → 4 84.21.44.10')
        && trace.includes('The observed path matches the current route.')
        && panel.getAnimations({ subtree: true }).every(a => a.playState !== 'running');
})()"#;

async fn screen(run: &Run, out: &Path, hijacked: bool) -> io::Result<()> {
    reload(run, hijacked).await?;
    let name = if hijacked { "hijacked" } else { "normal" };
    let (_, settled) = run
        .settled_screen(HOSTNAME, &out.join(format!("{name}.png")))
        .await?;
    if settled.is_none() {
        return Err(io::Error::other(format!(
            "the {name} screen was still changing"
        )));
    }
    println!(
        "Captured Firefox title: {:?}",
        title(run.guest(HOSTNAME).ssh()).await?
    );
    Ok(())
}

pub async fn run(run: &Run, out: &Path) -> io::Result<()> {
    let ssh = run.guest(HOSTNAME).ssh();
    run.guest(HOSTNAME)
        .wait_cloud_init(Duration::from_secs(100))
        .await?;
    command(ssh, "tmux has-session -t main").await?;
    println!(
        "Boot to agent-ready: {:.2} s",
        run.boot_started().elapsed().as_secs_f64()
    );
    let client = PageClient::from_url(run.page_url())?;
    client.bootstrap().await?;
    println!("Normal: trusted sign-in, balance, certificate, three hops and two BGP routes.");
    for name in ["signin", "balance", "cert", "route", "bgp 2"] {
        step(ssh, name, false).await?;
    }
    terminal(&client, ssh).await?;
    screen(run, out, false).await?;
    println!("Opening a persistent HTTPS connection before the flip.");
    begin(ssh, "hold").await?;
    command(ssh, "timeout 30 tmux wait-for connected").await?;
    flip(&client, "hijack", 0).await?;
    let stale = set_route(&client, &kit::random_uuid(), "hijack", 0).await?;
    if stale["status"] != "rejected"
        || stale["rejection"]["reason"] != "stale_revision"
        || stale["rejection"]["current"] != 1
    {
        return Err(io::Error::other(format!(
            "expected a stale revision rejection: {stale}"
        )));
    }
    println!("Repeated command: rejected stale_revision; revision remains 1.");
    let state = client.get_json("/api/state/routing").await?;
    if state["value"]["revision"] != 1 || state["value"]["mode"] != "hijack" {
        return Err(io::Error::other(
            "the rejected command changed the route state",
        ));
    }
    command(ssh, "printf x > /tmp/bank-continue").await?;
    finish(ssh, "hold", true).await?;
    println!(
        "Hijacked: the existing session fails, four hops, three BGP routes, and an untrusted certificate."
    );
    for name in ["route", "bgp 3", "balance", "cert -k"] {
        step(ssh, name, true).await?;
    }
    let cursor = client.last_event().await?;
    step(ssh, "signin-insecure", true).await?;
    password_received(&client, cursor).await?;
    println!("Page events: impostor received credentials; the event contains no password.");
    observed(&client, true).await?;
    println!(
        "Border observations: four hops, the more specific announcement, an impostor TLS session, and credentials without the password."
    );
    run.page_shot(
        &out.join("page-hijacked.png"),
        HIJACKED_PAGE,
        Duration::from_secs(60),
    )
    .await?;
    screen(run, out, true).await?;
    flip(&client, "legitimate", 1).await?;
    for name in ["route", "balance", "bgp 2"] {
        step(ssh, name, false).await?;
    }
    reload(run, false).await?;
    observed(&client, false).await?;
    println!(
        "Border observations: the more specific route was withdrawn and the new traceroute has three hops."
    );
    println!(
        "Restored: three hops, a fresh trusted balance request, and Firefox reloaded the bank's page."
    );
    Ok(())
}

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
    let mut hops = vec![
        super::control::scenario().gateway().to_string(),
        "84.21.44.1".into(),
    ];
    if hijacked {
        hops.push("45.144.30.1".into());
    }
    hops.push("84.21.44.10".into());
    let trace = view["links"].as_array().is_some_and(|links| {
        links.iter().any(|t| {
            t["sandbox"] == HOSTNAME
                && t["trace"]["complete"] == true
                && t["trace"]["dropped"] == 0
                && t["trace"]["hops"].as_array().is_some_and(|actual| {
                    actual.len() == hops.len()
                        && actual
                            .iter()
                            .zip(&hops)
                            .enumerate()
                            .all(|(i, (a, b))| a["address"] == b.as_str() && a["ttl"] == i + 1)
                })
        })
    });
    let bgp = rows("bgp").iter().any(|e| {
        e["sandbox"] == HOSTNAME
            && e["kind"] == "sent"
            && e["message"] == "UPDATE"
            && e[if hijacked { "announced" } else { "withdrawn" }]
                .as_array()
                .is_some_and(|routes| routes.iter().any(|p| p == "84.21.44.0/25"))
    });
    let moments: Vec<_> = rows("moments")
        .iter()
        .filter(|m| {
            m["sandbox"] == HOSTNAME
                && m["password"] == true
                && m["endpoint"]["machine"] == "45.144.30.10"
                && m["endpoint"]["reached"] == "84.21.44.10"
        })
        .collect();
    let tls = moments.iter().any(|m| {
        m["connection"].as_u64().is_some()
            && rows("tls").iter().any(|t| {
                t["sandbox"] == HOSTNAME
                    && t["identity"] == "impostor"
                    && t["outcome"] == "accepted"
                    && t["connection"] == m["connection"]
                    && t["endpoint"] == m["endpoint"]
            })
    });
    trace && bgp && tls && moments.len() == 1 && view["lost"] == 0 && view["truncated"] == 0
}

/// Whether a page event leaves the password out. An event that carries it
/// is an error.
fn password_hidden(event: &Value) -> io::Result<bool> {
    if exposes_password(event) {
        return Err(io::Error::other("page events exposed the password"));
    }
    Ok(true)
}

async fn password_received(client: &PageClient, cursor: u64) -> io::Result<()> {
    client
        .wait_for_event(
            cursor,
            Duration::from_secs(10),
            Duration::from_millis(100),
            "page events did not show a password-bearing impostor request",
            |event| Ok(password_hidden(event)? && has_password_event(event)),
        )
        .await?;
    // Every event the page now holds, not only those read up to the match,
    // must still leave the password out.
    client
        .find_event(&mut 0, |event| Ok(!password_hidden(event)?))
        .await?;
    Ok(())
}

fn has_password_event(value: &Value) -> bool {
    match value {
        Value::Object(fields) => {
            (fields.get("source").is_some_and(|s| s == "http")
                && fields.get("kind").is_some_and(|s| s == "request")
                && value["fields"]["served_by"] == "impostor"
                && value["fields"]["carries_password"] == true)
                || fields.values().any(has_password_event)
        }
        Value::Array(values) => values.iter().any(has_password_event),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_alert_requires_a_new_guest_handshake_at_the_impostor() {
        let row = json!({"event": 12, "sandbox": HOSTNAME, "identity": "impostor",
            "outcome": "alert", "endpoint": {"machine": "45.144.30.10", "reached": "84.21.44.10"}});
        let view = |row| json!({"tls": {"rows": [row]}});
        assert!(aborted_after(&view(row.clone()), 11));
        assert!(!aborted_after(&view(row.clone()), 12));
        for (key, value) in [
            ("outcome", "accepted"),
            ("sandbox", "other"),
            ("identity", "bank"),
        ] {
            let mut changed = row.clone();
            changed[key] = value.into();
            assert!(!aborted_after(&view(changed), 11));
        }
        let mut changed = row;
        changed["endpoint"]["machine"] = "84.21.44.10".into();
        assert!(!aborted_after(&view(changed), 11));
    }

    #[test]
    fn a_reload_counts_only_firefox_getting_the_bank_home_page_in_the_guest() {
        let event = json!({"source": "http", "kind": "request", "sandbox": {"name": HOSTNAME},
            "fields": {"served_by": "bank", "page": "home", "method": "GET", "headers": [
                ["host", "kestrelmoor.co.uk"],
                ["user-agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"]]}});
        assert!(firefox_home_served(&event));
        for (pointer, value) in [
            ("/kind", "error"),
            ("/sandbox/name", "other"),
            ("/fields/served_by", "impostor"),
            ("/fields/page", "balance"),
            ("/fields/method", "POST"),
            ("/fields/headers/1/1", "curl/8.5.0"),
            ("/fields/headers/1/0", "x-user-agent"),
        ] {
            let mut changed = event.clone();
            *changed.pointer_mut(pointer).unwrap() = value.into();
            assert!(!firefox_home_served(&changed), "{pointer}");
        }
    }

    #[test]
    fn password_events_require_the_source_and_classification() {
        let event = json!({"source":"http","kind":"request","fields":{"served_by":"impostor","carries_password":true}});
        assert!(has_password_event(
            &json!([{"data":{"events":[event.clone()]}}])
        ));
        for field in ["served_by", "carries_password"] {
            let mut changed = event.clone();
            changed["fields"][field] = Value::Null;
            assert!(!has_password_event(&changed));
        }
    }
}
