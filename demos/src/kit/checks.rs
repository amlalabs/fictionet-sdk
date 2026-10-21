//! The checks every demo runs: required checks, waiting for cloud-init,
//! screenshots, the guest's side of a failure, and keeping the page open.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fictionet_observe::page::Containment;

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

/// The setup bounds used by every check run.
const CLOUD_INIT_TIMEOUT: Duration = Duration::from_secs(300);
const DESKTOP_TIMEOUT: Duration = Duration::from_secs(300);

type Error = Box<dyn std::error::Error>;
/// A demo's story borrows the running guests and its output folder.
pub type Story<'a, E = Error> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), E>> + 'a>>;

/// Creates the output folder shared by check runs and their logs.
pub fn output(downloads: &Path, name: &str) -> io::Result<PathBuf> {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let out = downloads.join("runs").join(format!("{name}-{time}"));
    std::fs::create_dir_all(&out)?;
    println!("Output: {}", out.display());
    Ok(out)
}

/// A story and its checks after the guests have stopped.
pub trait Check<E: From<io::Error>> {
    fn play<'a>(&'a mut self, run: &'a Run, out: &'a Path) -> Story<'a, E>;
    fn finish(&mut self) -> Story<'_, E> {
        Box::pin(async { Ok(()) })
    }
}

/// A story closure and optional log checks.
pub struct Closure<F, E> {
    play: Option<F>,
    finish: Option<Box<dyn FnOnce() -> Story<'static, E>>>,
}

pub fn story<E, F>(play: F) -> Closure<F, E>
where
    F: for<'a> FnOnce(&'a Run, &'a Path) -> Story<'a, E>,
{
    Closure {
        play: Some(play),
        finish: None,
    }
}

impl<F, E> Closure<F, E> {
    /// Checks a demo's log after all producers have stopped.
    pub fn finish_with(mut self, finish: impl FnOnce() -> Story<'static, E> + 'static) -> Self {
        self.finish = Some(Box::new(finish));
        self
    }
}

impl<E, F> Check<E> for Closure<F, E>
where
    E: From<io::Error>,
    F: for<'a> FnOnce(&'a Run, &'a Path) -> Story<'a, E>,
{
    fn play<'a>(&'a mut self, run: &'a Run, out: &'a Path) -> Story<'a, E> {
        self.play.take().expect("story runs once")(run, out)
    }
    fn finish(&mut self) -> Story<'_, E> {
        Box::pin(async move {
            match self.finish.take() {
                Some(finish) => finish().await,
                None => Ok(()),
            }
        })
    }
}

/// Boots, checks and shuts down a demo. Only the story is demo owned.
pub async fn run<W, F, E>(
    kit: super::Kit<W>,
    downloads: &Path,
    out: &Path,
    mut story: impl Check<E>,
) -> Result<(), E>
where
    E: From<io::Error> + std::fmt::Display,
    W: FnOnce(fictionet::Cx, super::World) -> F + Send + 'static,
    F: std::future::Future<Output = fictionet::Result> + Send + 'static,
{
    let run = match kit.boot(downloads).await {
        Ok(run) => run,
        Err(error) => {
            let _ = story.finish().await;
            return Err(error.into());
        }
    };
    let result = sequence(&run, out, &mut story).await;
    if let Err(error) = &result {
        eprintln!("checks failed: {error}");
        for guest in run.guests() {
            eprint!("{}", guest.diagnostics().await);
        }
    }
    let shutdown = run.shutdown().await;
    let finished = story.finish().await;
    if let Err(error) = &shutdown {
        eprintln!("shutdown failed: {error}");
    }
    if let Err(error) = &finished {
        eprintln!("final checks failed: {error}");
    }
    result?;
    shutdown?;
    finished?;
    println!("every required check passed");
    Ok(())
}

pub(super) async fn sequence<E: From<io::Error>>(
    run: &Run,
    out: &Path,
    story: &mut impl Check<E>,
) -> Result<(), E> {
    for guest in run.guests() {
        guest.wait_cloud_init(CLOUD_INIT_TIMEOUT).await?;
    }
    for guest in run.guests() {
        if guest.guest.desktop.is_some() {
            guest.wait_desktop(DESKTOP_TIMEOUT).await?;
        }
    }
    let client = PageClient::from_url(run.page_url())?;
    bearer_required(&client).await?;
    let page = client.get_json("/api/page").await?;
    let hosts = page["hosts"]
        .as_array()
        .ok_or_else(|| io::Error::other("page has no hosts"))?;
    for host in hosts {
        let name = host["name"]
            .as_str()
            .ok_or_else(|| io::Error::other("host has no name"))?;
        if host["screen"].is_string() {
            single_use_ticket(&client, name, Capability::Screen).await?;
        }
        if host["terminal"].is_string() {
            single_use_ticket(&client, name, Capability::Terminal).await?;
            let guest = run.guest(name);
            if read_only_terminal(guest.guest.terminal.as_deref()) {
                terminal_rejects_input(&client, guest).await?;
            } else {
                terminal_runs_on(&client, name).await?;
            }
        }
    }
    story.play(run, out).await?;
    run.containment().await?;
    for host in hosts {
        if host["screen"].is_string() {
            let name = host["name"].as_str().unwrap();
            run.screenshots(
                name,
                &out.join(format!("{name}-screen.png")),
                &out.join(format!("{name}-page.png")),
            )
            .await?;
        }
    }
    let screens = hosts
        .iter()
        .filter(|host| host["screen"].is_string())
        .map(|host| host["name"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    run.world_shots(out, page["app"] == true, &screens).await?;
    Ok(())
}

fn word_pattern<'a>(words: impl Iterator<Item = &'a str>) -> serde_json::Value {
    let escaped = words
        .map(|word| {
            let mut escaped = String::new();
            for character in word.chars() {
                if r"\^$.*+?()[]{}|".contains(character) {
                    escaped.push('\\');
                }
                escaped.push(character);
            }
            escaped
        })
        .collect::<Vec<_>>();
    serde_json::json!(if escaped.is_empty() {
        "(?!)".into()
    } else {
        format!("\\b(?:{})\\b", escaped.join("|"))
    })
}

impl Run {
    /// Scans page words and the visible terminal output separately.
    pub fn visible_words(&self) -> String {
        let page_pattern = word_pattern(self.page_words.iter().map(String::as_str));
        let guest_pattern = word_pattern(
            super::FORBIDDEN.iter().copied().chain(
                self.guests
                    .iter()
                    .flat_map(|guest| guest.guest.forbidden.iter().map(String::as_str)),
            ),
        );
        format!(
            r#"(() => {{
            const pagePattern = new RegExp({page_pattern}, 'gi');
            const guestPattern = new RegExp({guest_pattern}, 'gi');
            const inspect = (where, text, pattern = pagePattern) => {{
                const hits = Array.from(text.matchAll(pattern), match => match[0]);
                if (hits.length) throw new Error(`Visible words '${{hits.join("', '")}}' in ${{where}}`);
            }};
            const tab = document.querySelector('.app-world [role="tab"][aria-selected="true"]')?.innerText;
            for (const node of document.querySelectorAll('svg text, svg [aria-label]')) {{
                if (node.getClientRects().length && getComputedStyle(node).visibility !== 'hidden') {{
                    inspect('map', node.textContent);
                    inspect('map label', node.getAttribute('aria-label') || '');
                }}
            }}
            inspect(tab ? tab + ' tab' : 'page', document.body.innerText);
            for (const rows of document.querySelectorAll('.xterm-rows')) {{
                if (rows.getClientRects().length && getComputedStyle(rows).visibility !== 'hidden')
                    inspect('terminal', rows.innerText, guestPattern);
            }}
            const button = document.querySelector('.app-menu-button');
            if (button) {{
                button.click();
                try {{ inspect('open World menu', document.querySelector('#world-menu').innerText); }}
                finally {{ button.click(); }}
            }}
        }})()"#
        )
    }

    async fn world_shots(&self, out: &Path, app: bool, screens: &[String]) -> io::Result<()> {
        let url = self.page_url().to_string();
        let out = out.to_path_buf();
        let words = self.visible_words();
        let screens = screens
            .iter()
            .map(|host| shot::desktop_painted(host))
            .collect::<Vec<_>>();
        tokio::task::spawn_blocking(move || {
            let light = out.join("world-light.png");
            let dark = out.join("world-dark.png");
            let loaded = "document.querySelector('#demo')?.dataset.state === 'ready'";
            let ready = r#"(() => {
                if (document.querySelector('#demo')?.dataset.state !== 'ready') return false;
                const panel = [...document.querySelectorAll('#app-world-panel, #app-packets-panel, #inspector-content')]
                    .find(node => !node.hidden && node.getClientRects().length);
                return panel && panel.childElementCount > 0 && !panel.querySelector('.loading-line')
                    && panel.getAnimations({subtree: true}).every(animation =>
                        animation.playState !== 'running' || animation.effect.getTiming().iterations === Infinity);
            })()"#;
            let ready = std::iter::once(ready.to_string()).chain(screens)
                .map(|condition| format!("({condition})")).collect::<Vec<_>>().join(" && ");
            let select = r#"document.querySelector('#app-world-tab')?.click()"#;
            let mut steps = Vec::new();
            if app {
                steps.push(shot::Step {
                    ready: loaded,
                    action: Some(select),
                    ..Default::default()
                });
                steps.push(shot::Step {
                    ready: &ready,
                    action: Some(&words),
                    color_scheme: Some("light"),
                    out: Some(&light),
                });
            }
            steps.push(shot::Step {
                ready: &ready,
                action: Some(&words),
                color_scheme: Some("dark"),
                out: Some(&dark),
            });
            shot::capture(&url, &steps, PAGE_TIMEOUT)?;
            for step in steps {
                if let Some(path) = step.out {
                    println!("page in Chromium: {}", path.display());
                }
            }
            Ok(())
        })
        .await
        .map_err(io::Error::other)?
    }
}

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

pub use fictionet::stdlib::network::ip::{non_public_address, reserved_address};

/// Whether a link address has an ordinary vendor prefix.
pub fn vendor_mac(mac: [u8; 6]) -> bool {
    mac[0] & 3 == 0 && !mac.windows(2).any(|bytes| bytes == [0x66, 0x6e])
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

fn read_only_terminal(command: Option<&str>) -> bool {
    command.is_some_and(|command| {
        command
            .split_whitespace()
            .collect::<Vec<_>>()
            .windows(3)
            .any(|words| words == ["tmux", "attach", "-r"])
    })
}

/// Checks a read-only tmux view from both the page and admin SSH.
pub async fn terminal_rejects_input(client: &PageClient, guest: &GuestHandle) -> io::Result<()> {
    use tokio::io::AsyncWriteExt;
    tokio::time::timeout(Duration::from_secs(30), async {
        let ticket = client.ticket(guest.name(), Capability::Terminal).await?;
        let mut socket = client
            .open(guest.name(), Capability::Terminal, Some(&ticket.ticket))
            .await?;
        let ssh = guest.ssh();
        // tmux enters the alternate screen after attaching its client.
        socket.read_until(b"\x1b[?1049h", 64 << 10).await?;
        let clients = ssh
            .run("tmux list-clients -F '#{client_readonly} #{session_id}'")
            .await?;
        let sessions = clients
            .stdout
            .lines()
            .map(|line| line.split_once(' '))
            .collect::<Option<Vec<_>>>();
        let sessions = sessions
            .filter(|sessions| {
                clients.code == 0
                    && !sessions.is_empty()
                    && sessions.iter().all(|(mode, _)| *mode == "1")
            })
            .ok_or_else(|| {
                io::Error::other(format!(
                    "the attached terminal clients are not read-only: exit {}; {}{}",
                    clients.code, clients.stdout, clients.stderr
                ))
            })?;
        let target = super::ssh::quote(sessions[0].1);
        let token = super::random_uuid();
        let path = format!("/tmp/{token}");
        let command = format!("printf reached > {path}");
        pane_round_trip(ssh, &mut socket, &target, "ready", &token).await?;
        socket.write_all(format!("{command}\r").as_bytes()).await?;
        pane_round_trip(ssh, &mut socket, &target, "done", &token).await?;
        let absent = ssh.run(&format!("[ ! -e {path} ]")).await?;
        check(
            &format!("the page terminal cannot run a command on {}", guest.name()),
            absent.code == 0,
        )?;
        let control = format!(
            "tmux send-keys -t {target} {} Enter",
            super::ssh::quote(&command)
        );
        check(
            "the same command reaches the pane over admin SSH",
            ssh.run(&control).await?.code == 0,
        )?;
        pane_round_trip(ssh, &mut socket, &target, "finished", &token).await?;
        let output = ssh.run(&format!("cat {path}; rm -f {path}")).await?;
        check(
            "admin SSH confirms the command can run in the guest",
            output.code == 0 && output.stdout == "reached",
        )
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "read-only terminal check timed out",
        )
    })?
}

async fn pane_round_trip(
    ssh: &super::ssh::Session,
    socket: &mut super::client::Socket,
    target: &str,
    phase: &str,
    token: &str,
) -> io::Result<()> {
    // The command echo cannot contain the formatted response.
    let command = super::ssh::quote(&format!("printf '{phase}:%s:end\\n' '{token}'"));
    let output = ssh
        .run(&format!("tmux send-keys -t {target} {command} Enter"))
        .await?;
    check(
        "admin SSH can type into the terminal pane",
        output.code == 0,
    )?;
    socket
        .read_until(format!("{phase}:{token}:end").as_bytes(), 64 << 10)
        .await
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
        client
            .wait_for(
                "/api/state/containment",
                Duration::from_secs(90),
                Duration::from_millis(250),
                "the page did not show every guest's containment probes",
                |value| {
                    let probes: Containment =
                        serde_json::from_value(value["value"].clone()).map_err(io::Error::other)?;
                    Ok(containment::complete(&probes, &guests))
                },
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
            containment::passed(&probes, &guests),
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
            shot::capture(
                &url,
                &[shot::Step {
                    ready: &ready,
                    out: Some(&path),
                    ..Default::default()
                }],
                timeout,
            )
            .map(|()| path)
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
        self.setup.done(self.name());
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

    #[tokio::test]
    async fn visible_words_checks_tabs_and_open_menu_in_chromium() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        let Ok(byte) = stream.read_u8().await else {
                            return;
                        };
                        request.push(byte);
                    }
                    let body = r#"<div class="app-world"><button role="tab" aria-selected="true">Web</button></div>
                        <header>Fictionet</header><p id="tab-text">Prepared pages</p><div class="xterm-rows">Ready</div>
                        <button class="app-menu-button" onclick="document.querySelector('#world-menu').hidden = !document.querySelector('#world-menu').hidden">World</button>
                        <div id="world-menu" hidden>Improvised</div>"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        let action = format!(
            r#"(() => {{
            const scan = () => {scan};
            const tab = document.querySelector('[role="tab"]');
            const text = document.querySelector('#tab-text');
            const menu = document.querySelector('#world-menu');
            const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            const label = document.createElementNS(svg.namespaceURI, 'text');
            label.setAttribute('y', '20');
            svg.append(label);
            document.body.append(svg);
            for (const name of ['Web', 'Packets']) {{
                tab.innerText = name;
                for (const word of ['canned','stub','stubbed','seed','splice','store','stored','generator','generated','cache']) {{
                    for (const where of [name + ' tab', 'open World menu', 'map', 'map label']) {{
                        text.innerText = where.endsWith('tab') ? word.toUpperCase() : 'Prepared pages';
                        menu.innerText = where.endsWith('menu') ? word.toUpperCase() : 'Improvised';
                        label.textContent = where === 'map' ? word.toUpperCase() : 'Map';
                        label.setAttribute('aria-label', where === 'map label' ? word.toUpperCase() : 'Map');
                        let failure;
                        try {{ scan(); }} catch (error) {{ failure = error.message; }}
                        if (!failure?.includes(word.toUpperCase()) || !failure.includes(where))
                            throw new Error(`Missing word or location: ${{word}} ${{where}} ${{failure}}`);
                        if (!menu.hidden) throw new Error('World menu stayed open');
                    }}
                }}
            }}
            label.remove();
            text.innerText = 'bookstore seedling cached generation';
            menu.innerText = 'Prepared';
            scan();
            const rows = document.querySelector('.xterm-rows');
            for (const word of ['fictionet', 'eval', 'sandbox', 'world', 'scripted', 'demo', 'probe', 'privateword', 'private-word', 'two words']) {{
                text.innerText = word;
                menu.innerText = word;
                scan();
                rows.innerText = word.toUpperCase();
                let failure;
                try {{ scan(); }} catch (error) {{ failure = error.message; }}
                if (!failure?.includes(word.toUpperCase()) || !failure.includes('terminal'))
                    throw new Error(`Missing terminal word: ${{word}} ${{failure}}`);
                rows.hidden = true;
                scan();
                rows.hidden = false;
                rows.innerText = 'Ready';
            }}
        }})()"#,
            scan = {
                let mut kit = super::super::Kit::new("words")
                    .page_words(&[
                        "canned",
                        "stub",
                        "stubbed",
                        "seed",
                        "splice",
                        "store",
                        "stored",
                        "generator",
                        "generated",
                        "cache",
                    ])
                    .guest(super::super::Guest::ubuntu("station", "analyst").forbid(&[
                        "privateword",
                        "private-word",
                        "two words",
                    ]));
                let (run, _) = kit.prepare().unwrap();
                run.visible_words()
            }
        );
        let result = tokio::task::spawn_blocking(move || {
            shot::capture(
                &url,
                &[shot::Step {
                    ready: "!!document.querySelector('.app-menu-button')",
                    action: Some(&action),
                    ..Default::default()
                }],
                Duration::from_secs(10),
            )
        })
        .await;
        server.abort();
        result.unwrap().unwrap();
    }

    #[tokio::test]
    async fn page_scan_adds_no_words_when_the_demo_supplies_none() {
        let mut kit = super::super::Kit::new("words")
            .guest(super::super::Guest::ubuntu("station", "analyst"));
        let (run, _) = kit.prepare().unwrap();
        let scan = run.visible_words();
        tokio::task::spawn_blocking(move || {
            shot::capture(
                "data:text/html,<header>Fictionet canned cache</header><button class='app-menu-button' onclick=\"document.getElementById('world-menu').hidden=!document.getElementById('world-menu').hidden\">World</button><div id='world-menu' hidden>generated</div>",
                &[shot::Step {
                    ready: "!!document.querySelector('.app-menu-button')",
                    action: Some(&scan),
                    ..Default::default()
                }],
                Duration::from_secs(10),
            )
        }).await.unwrap().unwrap();
    }

    #[test]
    fn terminal_access_follows_the_declared_console_command() {
        assert!(!read_only_terminal(None));
        assert!(!read_only_terminal(Some(
            "cloud-init status --wait; exec bash -l"
        )));
        assert!(!read_only_terminal(Some("tmux attach -t main")));
        assert!(read_only_terminal(Some(
            "cloud-init status --wait && tmux attach -r -t main; exec bash -l"
        )));
    }

    #[test]
    fn setup_timeouts_are_owned_by_the_kit() {
        assert_eq!(CLOUD_INIT_TIMEOUT, Duration::from_secs(300));
        assert_eq!(DESKTOP_TIMEOUT, Duration::from_secs(300));
        assert_eq!(STEP_PAUSE, Duration::from_millis(1500));
    }

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
        let dashboard = DashboardObserver::new(DashboardOptions {
            collector: fictionet_observe::Options::default(),
            ..Default::default()
        });
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
