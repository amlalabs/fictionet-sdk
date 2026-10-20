//! The scripted terminal story and the page's own command client.

use super::{
    checks,
    guest::{HOSTNAME, USER},
};
use fictionet_demo::kit::{self, Run, client::PageClient, ssh};
use serde_json::{Value, json};
use std::io;
use std::path::Path;
use std::time::Duration;

/// Quotes one literal argument for a POSIX shell, including embedded quotes.
pub fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

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

pub async fn set_route(
    client: &PageClient,
    id: &str,
    mode: &str,
    revision: u64,
) -> io::Result<Value> {
    let response = client
        .request(
            "POST",
            "/api/command/routing",
            Some(&json!({"request_id": id, "command":{"mode":mode,"expected_revision":revision}})),
            true,
        )
        .await?;
    let value: Value = serde_json::from_slice(&response.body)?;
    if response.status != 200 && response.status != 409 {
        return Err(io::Error::other(format!(
            "routing HTTP {}: {value}",
            response.status
        )));
    }
    Ok(value)
}

async fn flip(client: &PageClient, mode: &str, revision: u64) -> io::Result<()> {
    let reply = set_route(client, &kit::random_uuid(), mode, revision).await?;
    if reply["status"] != "applied" || reply["reply"]["revision"] != revision + 1 {
        return Err(io::Error::other(format!("route was not applied: {reply}")));
    }
    println!("Routing: {mode}, applied revision {}", revision + 1);
    Ok(())
}

async fn reload(run: &Run, hijacked: bool) -> io::Result<()> {
    let expected = if hijacked {
        "Warning: Potential Security Risk Ahead"
    } else {
        "Kestrelmoor"
    };
    let browser = format!(
        "export DISPLAY=:1; window=$(xdotool search --sync --onlyvisible --class firefox | head -n1); xdotool key --window \"$window\" ctrl+r; until xdotool getwindowname \"$window\" | grep -F {}; do sleep 0.2; done",
        quote(expected)
    );
    command(
        run.guest(HOSTNAME).ssh(),
        &format!("timeout 60 sudo -u {USER} bash -c {}", quote(&browser)),
    )
    .await?;
    Ok(())
}

async fn screen(run: &Run, out: &Path, hijacked: bool) -> io::Result<()> {
    reload(run, hijacked).await?;
    let file = if hijacked {
        "hijacked.png"
    } else {
        "normal.png"
    };
    let capture = tokio::time::timeout(
        Duration::from_secs(30),
        kit::rfb::capture_page(run.page_url(), HOSTNAME, &run.path().join(file)),
    )
    .await??;
    if capture.colors < 16 {
        return Err(io::Error::other(
            "the captured desktop has fewer than 16 colors",
        ));
    }
    std::fs::copy(&capture.png, out.join(file))?;
    println!("Screen: {}", out.join(file).display());
    Ok(())
}

pub async fn run(run: &Run, out: &Path) -> io::Result<()> {
    let ssh = run.guest(HOSTNAME).ssh();
    command(ssh, "cloud-init status --wait").await?;
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
    let state = client
        .request("GET", "/api/state/routing", None, true)
        .await?;
    let state: Value = serde_json::from_slice(&state.body)?;
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
    let before = events(&client, 0).await?;
    let cursor = before["last"]
        .as_u64()
        .ok_or_else(|| io::Error::other("events reply has no last sequence"))?;
    step(ssh, "signin-insecure", true).await?;
    password_received(&client, cursor).await?;
    println!("Page events: impostor received credentials; the event contains no password.");
    screen(run, out, true).await?;
    flip(&client, "legitimate", 1).await?;
    for name in ["route", "balance"] {
        step(ssh, name, false).await?;
    }
    reload(run, false).await?;
    println!(
        "Restored: three hops, a fresh trusted balance request, and the bank browser title succeeded."
    );
    Ok(())
}

async fn events(client: &PageClient, after: u64) -> io::Result<Value> {
    let response = client
        .request(
            "GET",
            &format!("/api/events?after={after}&max=1000"),
            None,
            true,
        )
        .await?;
    if response.status != 200 {
        return Err(io::Error::other(format!("events HTTP {}", response.status)));
    }
    let text = String::from_utf8(response.body).map_err(io::Error::other)?;
    if text
        .to_lowercase()
        .contains(&border_world::bank::ACCOUNT.password.to_lowercase())
    {
        return Err(io::Error::other("page events exposed the password"));
    }
    serde_json::from_str(&text).map_err(io::Error::other)
}

async fn password_received(client: &PageClient, mut cursor: u64) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let batch = events(client, cursor).await?;
            if has_password_event(&batch) {
                return Ok(());
            }
            let rows = batch["events"]
                .as_array()
                .ok_or_else(|| io::Error::other("events reply has no rows"))?;
            if let Some(last) = rows.last() {
                cursor = last["seq"]
                    .as_u64()
                    .ok_or_else(|| io::Error::other("event has no sequence"))?;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| io::Error::other("page events did not show a password-bearing impostor request"))?
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
    fn shell_arguments_round_trip_without_expansion() {
        for text in ["", "hello world", "a'b", "$(exit 7); `exit 8`\n$HOME"] {
            let output = std::process::Command::new("sh")
                .args(["-c", &format!("printf %s {}", quote(text))])
                .output()
                .unwrap();
            assert!(output.status.success());
            assert_eq!(output.stdout, text.as_bytes());
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
