//! What every demo gate does: required checks, waiting for cloud-init,
//! screenshots, the guest's side of a failure, and keeping the page open.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{GuestHandle, Run, rfb, shot};

/// How long the screen capture through the page may take.
const SCREEN_TIMEOUT: Duration = Duration::from_secs(30);
/// How long Chromium may take to load the page and paint the screen.
const PAGE_TIMEOUT: Duration = Duration::from_secs(30);
/// A captured screen with fewer colors than this is blank.
const MIN_COLORS: usize = 16;

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

    /// Saves `host`'s screen to `screen` as [`Run::screen`] does, then the
    /// page to `page` from Chromium once the page shows that screen painted,
    /// within 30 s.
    pub async fn screenshots(
        &self,
        host: &str,
        screen: &Path,
        page: &Path,
    ) -> io::Result<Screenshots> {
        let capture = self.screen(host, screen).await?;
        let (url, out, condition) = (
            self.page_url().to_string(),
            page.to_path_buf(),
            shot::desktop_painted(host),
        );
        let page = tokio::task::spawn_blocking(move || {
            shot::capture(&url, &out, &condition, PAGE_TIMEOUT).map(|_| out)
        })
        .await
        .map_err(io::Error::other)??;
        println!("{host} page in Chromium: {}", page.display());
        Ok(Screenshots {
            screen: capture,
            page,
        })
    }
}

/// [`Run::screen`] for any signed page URL.
async fn screen(url: &str, host: &str, out: &Path) -> io::Result<rfb::Capture> {
    let capture = tokio::time::timeout(SCREEN_TIMEOUT, rfb::capture_page(url, host, out))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{host}: the screen capture took over {SCREEN_TIMEOUT:?}"),
            )
        })??;
    if capture.colors < MIN_COLORS {
        return Err(io::Error::other(format!(
            "{host}: the captured screen has {} colors; a desktop shows at least {MIN_COLORS}",
            capture.colors
        )));
    }
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
    "env DISPLAY=:1 sh -c 'xdotool search --onlyvisible --class firefox | head -n1 | xargs -r xdotool getwindowname'",
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

    /// The guest's side of a failed run, for a gate to print: cloud-init's
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
