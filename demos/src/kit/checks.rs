//! The checks every demo runs: required checks, waiting for cloud-init,
//! screenshots, the guest's side of a failure, and keeping the page open.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fictionet_observe::page::{Containment, ProbeOutcome};

use super::client::{Capability, PageClient};
use super::{GuestHandle, Run, containment, rfb, shot};

/// How long the screen capture through the page may take.
const SCREEN_TIMEOUT: Duration = Duration::from_secs(30);
/// How long Chromium may take to load the page and paint the screen.
const PAGE_TIMEOUT: Duration = Duration::from_secs(30);
/// A captured screen with fewer colors than this is blank.
const MIN_COLORS: usize = 16;
/// How often [`Run::settled_screen`] captures, and for how long at most.
const SETTLE_INTERVAL: Duration = Duration::from_millis(500);
const SETTLE_LIMIT: Duration = Duration::from_secs(20);

/// How long a scripted story holds each step before the next one, so a
/// person watching the page and the screen can follow it. No check may
/// depend on it: every check waits for the world's state.
pub const STEP_PAUSE: Duration = Duration::from_millis(1500);

/// Prints a required check as `[pass] name` or `[FAIL] name`. A failed check
/// is an error that names it.
pub fn check(name: &str, ok: bool) -> io::Result<()> {
    println!("[{}] {name}", if ok { "pass" } else { "FAIL" });
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(format!("required check failed: {name}")))
    }
}

/// Checks that the page API refuses a request without the run's bearer and
/// answers one with it, after signing in as a browser tab does.
pub async fn bearer_required(client: &PageClient) -> io::Result<()> {
    let refused = client.request("GET", "/api/page", None, false).await?;
    check(
        "the page API refuses a request without the bearer",
        refused.status == 401,
    )?;
    client.bootstrap().await?;
    let allowed = client.request("GET", "/api/page", None, true).await?;
    check(
        "the page API answers a request with the bearer",
        allowed.status == 200,
    )
}

/// Checks that `host`'s console refuses an upgrade without a ticket, opens
/// with one, and refuses that ticket a second time.
pub async fn single_use_ticket(
    client: &PageClient,
    host: &str,
    capability: Capability,
) -> io::Result<()> {
    let refused = |result: io::Result<super::client::Socket>| {
        result
            .err()
            .is_some_and(|e| e.to_string().starts_with("HTTP/1.1 401 "))
    };
    let name = capability.name();
    check(
        &format!("the {host} {name} refuses an upgrade without a ticket"),
        refused(client.open(host, capability, None).await),
    )?;
    let ticket = client.ticket(host, capability).await?;
    let open = client.open(host, capability, Some(&ticket.ticket)).await?;
    check(
        &format!("the {host} {name} refuses a ticket used once"),
        refused(client.open(host, capability, Some(&ticket.ticket)).await),
    )?;
    drop(open);
    Ok(())
}

/// The line [`terminal_runs_on`] types: it prints `name:<hostname>:end`.
/// The line itself holds no hostname, so its echo cannot match.
pub(crate) const HOSTNAME_LINE: &[u8] = b"printf 'name:%s:end\\n' \"$(hostname)\"\r";

/// Checks that the page's terminal on `host` runs a command there: it types
/// one that prints the guest's own hostname and waits up to 30 s for it.
pub async fn terminal_runs_on(client: &PageClient, host: &str) -> io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let run = async {
        let ticket = client.ticket(host, Capability::Terminal).await?;
        let mut socket = client
            .open(host, Capability::Terminal, Some(&ticket.ticket))
            .await?;
        socket.write_all(HOSTNAME_LINE).await?;
        socket
            .read_until(format!("name:{host}:end").as_bytes(), 64 << 10)
            .await
    };
    let ran = tokio::time::timeout(Duration::from_secs(30), run).await;
    if let Ok(Err(error)) = &ran {
        println!("{host} terminal: {error}");
    }
    check(
        &format!("the page terminal runs a command on {host}"),
        matches!(ran, Ok(Ok(()))),
    )
}

/// Prints that the page stays open, then waits for Ctrl-C.
pub async fn stay_open() -> io::Result<()> {
    println!("The page stays open until Ctrl-C.");
    tokio::signal::ctrl_c().await
}

/// What [`Run::screenshots`] saved.
pub struct Screenshots {
    /// The guest's screen as the page's screen bridge delivers it.
    pub screen: rfb::Capture,
    /// The page as Chromium renders it.
    pub page: PathBuf,
}

impl Run {
    /// Saves `host`'s screen to `out` through the page's screen bridge, as a
    /// signed-in viewer that claims no input. The capture must finish within
    /// 30 s and show at least 16 colors.
    pub async fn screen(&self, host: &str, out: &Path) -> io::Result<rfb::Capture> {
        screen(self.page_url(), host, out).await
    }

    /// Saves `host`'s screen to `out` once two captures in a row match, so
    /// a page the guest is loading has finished. It captures every 500 ms
    /// for at most 20 s, and returns the number of captures it took, or None
    /// when the screen was still changing and the last capture was kept.
    pub async fn settled_screen(
        &self,
        host: &str,
        out: &Path,
    ) -> io::Result<(rfb::Capture, Option<usize>)> {
        let started = tokio::time::Instant::now();
        let mut tick = tokio::time::interval(SETTLE_INTERVAL);
        let (mut previous, mut captures) = (None, 0);
        let (capture, settled) = loop {
            tick.tick().await;
            captures += 1;
            let capture = capture(self.page_url(), host, out).await?;
            let pixels = std::fs::read(&capture.png)?;
            if previous.as_ref() == Some(&pixels) {
                break (capture, Some(captures));
            }
            if started.elapsed() >= SETTLE_LIMIT {
                break (capture, None);
            }
            previous = Some(pixels);
        };
        colorful(host, &capture)?;
        match settled {
            Some(n) => println!(
                "{host} screen through the page: {} (settled after {n} captures)",
                capture.png.display()
            ),
            None => println!(
                "{host} screen through the page: {} (still changing after {SETTLE_LIMIT:?})",
                capture.png.display()
            ),
        }
        Ok((capture, settled))
    }

    /// Waits up to 90 s until the page shows every guest's containment
    /// probes, prints them, and checks that none was forwarded or answered
    /// from outside the world.
    pub async fn containment(&self) -> io::Result<()> {
        let client = PageClient::from_url(self.page_url())?;
        client.bootstrap().await?;
        let guests: Vec<&str> = self
            .guests
            .iter()
            .map(|guest| guest.guest.attachment.as_str())
            .collect();
        let complete = |value: &serde_json::Value| {
            let rows = value["value"]["probes"].as_array();
            guests.iter().all(|guest| {
                rows.into_iter()
                    .flatten()
                    .filter(|r| r["guest"] == *guest)
                    .count()
                    == containment::PROBES.len()
            })
        };
        client
            .wait_for(
                "/api/state/containment",
                Duration::from_secs(90),
                Duration::from_millis(250),
                "the page did not show every guest's containment probes",
                |value| Ok(complete(value)),
            )
            .await?;
        let probes: Containment = client.state("containment").await?;
        for probe in &probes.probes {
            println!(
                "containment: {}: {}: {:?}; world: {}",
                probe.guest, probe.name, probe.outcome, probe.world_answer
            );
        }
        check(
            "no containment probe was forwarded or answered from outside the world",
            !probes.probes.is_empty()
                && probes.probes.iter().all(|probe| {
                    !matches!(
                        probe.outcome,
                        ProbeOutcome::Forwarded | ProbeOutcome::NotContained
                    )
                }),
        )
    }

    /// Saves the page from Chromium to `out` once the JavaScript expression
    /// `ready` is true in it, within `timeout`.
    pub async fn page_shot(
        &self,
        out: &Path,
        ready: &str,
        timeout: Duration,
    ) -> io::Result<PathBuf> {
        let (url, path, ready) = (
            self.page_url().to_string(),
            out.to_path_buf(),
            ready.to_string(),
        );
        let page = tokio::task::spawn_blocking(move || {
            shot::capture(&url, &path, &ready, timeout).map(|_| path)
        })
        .await
        .map_err(io::Error::other)??;
        println!("page in Chromium: {}", page.display());
        Ok(page)
    }

    /// Saves `host`'s screen to `screen` as [`Run::settled_screen`] does,
    /// then the page to `page` from Chromium once the page shows that screen
    /// painted, within 30 s.
    pub async fn screenshots(
        &self,
        host: &str,
        screen: &Path,
        page: &Path,
    ) -> io::Result<Screenshots> {
        let (capture, _) = self.settled_screen(host, screen).await?;
        let page = self
            .page_shot(page, &shot::desktop_painted(host), PAGE_TIMEOUT)
            .await?;
        Ok(Screenshots {
            screen: capture,
            page,
        })
    }
}

/// Saves `host`'s screen to `out` through the page at `url`, within 30 s.
async fn capture(url: &str, host: &str, out: &Path) -> io::Result<rfb::Capture> {
    tokio::time::timeout(SCREEN_TIMEOUT, rfb::capture_page(url, host, out))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{host}: the screen capture took over {SCREEN_TIMEOUT:?}"),
            )
        })?
}

/// Fails unless the capture shows a desktop: at least 16 colors.
fn colorful(host: &str, capture: &rfb::Capture) -> io::Result<()> {
    if capture.colors < MIN_COLORS {
        return Err(io::Error::other(format!(
            "{host}: the captured screen has {} colors; a desktop shows at least {MIN_COLORS}",
            capture.colors
        )));
    }
    Ok(())
}

/// [`Run::screen`] for any signed page URL.
async fn screen(url: &str, host: &str, out: &Path) -> io::Result<rfb::Capture> {
    let capture = capture(url, host, out).await?;
    colorful(host, &capture)?;
    println!(
        "{host} screen through the page: {} ({}x{}, {}{} colors, {})",
        capture.png.display(),
        capture.width,
        capture.height,
        capture.colors,
        if capture.colors == 256 { "+" } else { "" },
        capture.banner
    );
    Ok(capture)
}

/// The commands [`GuestHandle::diagnostics`] runs on every guest.
const DIAGNOSTICS: &[&str] = &[
    "cloud-init status --long",
    "sudo tail -n 30 /var/log/cloud-init-output.log",
];
/// The commands it adds for a guest with a desktop.
const DESKTOP_DIAGNOSTICS: &[&str] = &[
    "systemctl is-active vnc",
    "tail -n 15 /tmp/xvnc.log /tmp/xfce.log",
    "tail -n 40 /tmp/firefox.log",
    super::desktop::FIREFOX_TITLE,
];
/// Each diagnostic command's time and output bounds.
const DIAGNOSTIC_TIMEOUT: Duration = Duration::from_secs(3);
const DIAGNOSTIC_BYTES: usize = 16 << 10;

impl GuestHandle {
    /// Waits up to `timeout` for cloud-init to finish on the guest, and
    /// returns the time from VM startup. Fails with cloud-init's exit code
    /// and its `status --long` report, bounded to 64 KiB, unless cloud-init
    /// finished cleanly.
    pub async fn wait_cloud_init(&self, timeout: Duration) -> io::Result<Duration> {
        let output = tokio::time::timeout(
            timeout,
            self.ssh()
                .run_bounded("sudo cloud-init status --wait --long", 64 << 10),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "{}: cloud-init did not finish within {} s",
                    self.name(),
                    timeout.as_secs()
                ),
            )
        })??;
        if output.code != 0 {
            return Err(io::Error::other(format!(
                "{}: cloud-init exit {}\n{}{}",
                self.name(),
                output.code,
                output.stdout,
                output.stderr
            )));
        }
        Ok(self.boot.elapsed())
    }

    /// The guest's side of a failed run, for a demo to print: cloud-init's
    /// report and log tail, the desktop's state and logs when the guest has
    /// one, and the serial console tail. Each command has 3 s and 16 KiB.
    pub async fn diagnostics(&self) -> String {
        let mut out = format!("--- {} diagnostics ---\n", self.name());
        match &self.ssh {
            None => out.push_str("No SSH session; only the console tail is available.\n"),
            Some(ssh) => {
                let desktop = self.guest.desktop.is_some().then_some(DESKTOP_DIAGNOSTICS);
                for command in DIAGNOSTICS.iter().chain(desktop.into_iter().flatten()) {
                    let result = tokio::time::timeout(
                        DIAGNOSTIC_TIMEOUT,
                        ssh.run_bounded(command, DIAGNOSTIC_BYTES),
                    )
                    .await;
                    out.push_str(&match result {
                        Ok(Ok(output)) => format!(
                            "guest$ {command}\n{}{}[exit {}]\n",
                            output.stdout, output.stderr, output.code
                        ),
                        Ok(Err(error)) => format!("guest$ {command}\nunavailable: {error}\n"),
                        Err(_) => format!("guest$ {command}\ntimed out\n"),
                    });
                }
            }
        }
        if let Some(vm) = &self.vm {
            out.push_str(&format!(
                "--- {} console tail ---\n{}\n",
                self.name(),
                vm.console_tail()
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet_observe::page::{Host, HostState, HostStatus, Page, StateLimits, StateTopic};
    use fictionet_observe::{DashboardObserver, DashboardOptions};

    #[test]
    fn a_failed_check_is_an_error_that_names_it() {
        check("the screen painted", true).unwrap();
        let error = check("the screen painted", false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "required check failed: the screen painted"
        );
    }

    #[tokio::test]
    async fn a_blank_screen_fails_the_capture() {
        let dashboard = DashboardObserver::new(DashboardOptions::demo());
        let status = StateTopic::new(StateLimits::default());
        status
            .publish(
                fictionet::time::Instant::ZERO,
                &HostStatus {
                    state: HostState::DesktopUp,
                    addresses: vec![],
                    screen: true,
                    terminal: false,
                },
            )
            .unwrap();
        let page = Page::new("Preview", dashboard.handle())
            .host(
                Host::new("preview")
                    .status(status)
                    .console(super::super::preview::Console::new()),
            )
            .bind_loopback(0)
            .await
            .unwrap();
        let dir = super::super::util::RunDir::new(&std::env::temp_dir(), "blank").unwrap();
        let out = dir.path().join("screen.png");
        let error = screen(page.url(), "preview", &out).await.err().unwrap();
        assert_eq!(
            error.to_string(),
            "preview: the captured screen has 2 colors; a desktop shows at least 16"
        );
        page.shutdown(Duration::from_secs(1)).await;
    }
}
