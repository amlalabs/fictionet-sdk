//! The desktop gate on the shared microVM kit.
//! Run with `cargo xtask demo desktop`.

mod guest;
mod world;

use fictionet_demo::kit::client::{Capability, PageClient};
use fictionet_demo::kit::gate::check;
use fictionet_demo::kit::{self, Kit, b64_decode, rfb, ssh};
use fictionet_observe::page::{Column, Page, StateLimits, StateTopic};
use serde_json::{Value, json};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;

const HOSTNAME: &str = "workstation";
const USER: &str = "analyst";
/// The world's HTTPS site the guest fetches with the Zscaler chain.
const SITE: &str = "example.test";

type Error = Box<dyn std::error::Error>;

fn boxed<E: std::fmt::Display>(error: E) -> Error {
    error.to_string().into()
}

fn main() -> ExitCode {
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    let [downloads, rest @ ..] = args.as_slice() else {
        eprintln!(
            "usage: desktop <downloads-directory> [observation-socket]\n\
             run it with `cargo xtask demo desktop` first to fetch the pinned files"
        );
        return ExitCode::FAILURE;
    };
    if rest.len() > 1 {
        eprintln!("desktop: too many arguments");
        return ExitCode::FAILURE;
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("desktop: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(gate(downloads, rest.first().cloned())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("desktop: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn gate(downloads: &Path, observation: Option<PathBuf>) -> Result<(), Error> {
    let total = Instant::now();
    let loaded = Arc::new(AtomicBool::new(false));
    let agents = StateTopic::<Vec<Value>>::new(StateLimits::default());
    let table = agents.clone();
    let (world_clock, clock) = tokio::sync::oneshot::channel();
    let kit = Kit::new("desktop")
        .guest(guest::workstation(HOSTNAME, USER, SITE))
        .page(move |dashboard, hosts| {
            Page::new("Desktop", dashboard)
                .host(hosts.take(HOSTNAME))
                .standard_panels()
                .table(
                    "Coding agents",
                    table,
                    vec![
                        Column::new("Agent", "/name"),
                        Column::new("Version", "/version"),
                        Column::new("Status", "/status"),
                    ],
                )
        })
        .observer(Arc::new(world::SiteLoaded {
            host: SITE.into(),
            loaded: loaded.clone(),
        }))
        .world(move |fcx, world| async move {
            let _ = world_clock.send(fcx.clone());
            world::start(fcx, world, SITE.into()).await
        });
    // Screenshots survive the run (the run dir does not).
    let shots = downloads.join("shots");
    std::fs::create_dir_all(&shots)?;

    let run = kit.boot(downloads).await?;
    let cx = clock.await?;
    let _observation = observation
        .as_ref()
        .map(|p| fictionet_observe::serve(run.dashboard(), p))
        .transpose()
        .map_err(boxed)?;
    let workstation = run.guest(HOSTNAME);
    let vm = workstation.vm();

    // Show where Cloud Hypervisor runs from: a memfd when the binary is
    // embedded (nothing on disk), the downloaded path otherwise.
    let ch_pid = vm.pid();
    if let Some(pid) = ch_pid
        && let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe"))
    {
        println!("Cloud Hypervisor (pid {pid}) runs from {}\n", exe.display());
    }

    let ssh_ready_ms = workstation.ssh_ready().as_millis();
    println!(
        "ssh from the jump host ({}) is up after {ssh_ready_ms} ms; waiting for the desktop \
            install\n",
        kit::jump::JUMP_ADDR
    );
    let result = run_checks(&run, &loaded, &shots, &agents, &cx)
        .await
        .map(|checks| (ssh_ready_ms, checks));
    if result.is_err() {
        eprint!("{}", workstation.diagnostics().await);
    }
    let run_dir = run.path().to_path_buf();
    let stop = run.shutdown().await;

    println!("\n=== shutdown ===");
    let mut failures = Vec::new();
    if let Err(error) = &stop {
        println!("shutdown: {error}");
    }
    failures.extend(
        check(
            "the guest powered off over ACPI and Cloud Hypervisor exited",
            stop.is_ok(),
        )
        .err(),
    );
    let ch_gone = ch_pid.is_none_or(|pid| !Path::new(&format!("/proc/{pid}")).exists());
    failures.extend(
        check(
            "nothing is left behind: no Cloud Hypervisor process, no run directory",
            ch_gone && !run_dir.exists(),
        )
        .err(),
    );

    let (ssh_ready_ms, checks) = result?;
    println!("\n=== measurements ===");
    println!("boot to ssh-ready:  {ssh_ready_ms} ms");
    println!("boot to desktop:    {} ms", checks.desktop_ready_ms);
    println!("boot to cloud-init done: {} ms", checks.cloud_init_ready_ms);
    println!("coding agents:      {}", checks.agents_install);
    println!("whole run:          {} ms", total.elapsed().as_millis());
    println!("peak VM memory:     {} MiB", checks.peak_rss_mib);
    for shot in &checks.screenshots {
        println!("screenshot:         {shot}");
    }
    if !failures.is_empty() {
        return Err(format!("the gate's shutdown checks failed: {}", joined(&failures)).into());
    }
    println!("\nevery required check passed");
    Ok(())
}

fn joined(failures: &[std::io::Error]) -> String {
    failures
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

struct Checks {
    desktop_ready_ms: u128,
    cloud_init_ready_ms: u128,
    /// The guest's own measure of the coding agents' install: bytes
    /// downloaded and seconds taken.
    agents_install: String,
    peak_rss_mib: u64,
    screenshots: Vec<String>,
}

async fn run_checks(
    run: &kit::Run,
    loaded: &AtomicBool,
    shots: &Path,
    agents: &StateTopic<Vec<Value>>,
    cx: &fictionet::Cx,
) -> Result<Checks, Error> {
    let workstation = run.guest(HOSTNAME);
    let boot = run.boot_started();
    let page_url = run.page_url();
    let vm = workstation.vm();
    let session = workstation.ssh();
    // Every required check that failed; the gate fails at the end if any did.
    let mut failures = Vec::new();

    // Block until cloud-init finishes, but not forever: a stalled install must
    // fail the gate, not hang it.
    let cloud_init = workstation.wait_cloud_init(Duration::from_secs(300)).await;
    let cloud_init_ready_ms = match &cloud_init {
        Ok(ready) => {
            println!("cloud-init finished after {} ms\n", ready.as_millis());
            ready.as_millis()
        }
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
            return Err(error.to_string().into());
        }
        Err(error) => {
            println!("{error}\n");
            boot.elapsed().as_millis()
        }
    };
    failures.extend(check("cloud-init finished", cloud_init.is_ok()).err());
    let desktop_ready_ms = workstation
        .wait_desktop(Duration::from_secs(300))
        .await?
        .as_millis();

    // What the guest looks like, for the log.
    for command in [
        "cloud-init status --long",
        "cat /proc/cmdline",
        "sudo dmidecode -s system-manufacturer; sudo dmidecode -s system-product-name",
        "pgrep -a Xvnc || echo 'no Xvnc'",
        "pgrep -af firefox | head -1 || echo 'no firefox'",
        "ls /etc/ssl/certs | grep -i zscaler || echo 'no zscaler cert'",
        // How much the guest pulled from the world's mirror at boot.
        "echo \"packages downloaded: $(du -shc /var/cache/apt/archives/*.deb 2>/dev/null | tail \
            -1 | cut -f1) in $(ls /var/cache/apt/archives/*.deb 2>/dev/null | wc -l) files\"",
        // Every socket the guest listens on, and from where.
        "sudo ss -tulnpH",
    ] {
        guest_cmd(session, command).await?;
    }

    // Required: the guest's address is the one the world leased it by DHCP.
    let lease = workstation.addr();
    let addr = guest_cmd(session, "ip -4 -o addr show dev eth0").await?;
    failures.extend(
        check(
            &format!(
                "the guest has its address from the world's DHCP ({})",
                lease.map_or("no lease".to_string(), |a| a.to_string())
            ),
            lease.is_some_and(|a| addr.stdout.contains(&format!("inet {a}/"))),
        )
        .err(),
    );

    // Required: no vsock device for the guest to find.
    let pci = guest_cmd(session, "lspci -nn").await?;
    let vsock = pci.stdout.lines().any(|line| {
        let line = line.to_ascii_lowercase();
        line.contains("socket") || line.contains("[1af4:1053]") || line.contains("[1af4:1012]")
    });
    failures.extend(
        check(
            "lspci shows no Virtio socket device",
            pci.code == 0 && !pci.stdout.is_empty() && !vsock,
        )
        .err(),
    );

    // Required: this session reaches sshd from the jump host's address.
    let ssh_peers = guest_cmd(session, "ss -tnH state established '( sport = :22 )'").await?;
    let peers: Vec<Option<IpAddr>> = ssh_peers
        .stdout
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .map(peer_ip)
        .collect();
    failures.extend(
        check(
            &format!(
                "ss shows the SSH session coming from the jump host ({})",
                kit::jump::JUMP_ADDR
            ),
            !peers.is_empty()
                && peers
                    .iter()
                    .all(|p| *p == Some(kit::jump::JUMP_ADDR.into())),
        )
        .err(),
    );

    // Required: Ubuntu's sshd and the desktop are running, and Xvnc listens
    // on the loopback only, so sshd is the guest's one network service of ours.
    let services = guest_cmd(session, "systemctl is-active ssh.service vnc.service").await?;
    failures.extend(
        check(
            "ssh.service and vnc.service are active",
            services
                .stdout
                .lines()
                .filter(|l| l.trim() == "active")
                .count()
                == 2,
        )
        .err(),
    );
    let vnc = guest_cmd(session, "ss -tlnH '( sport = :5900 or sport = :5901 )'").await?;
    let vnc_listeners: Vec<Option<IpAddr>> = vnc
        .stdout
        .lines()
        .filter_map(|line| line.split_whitespace().nth(3))
        .map(peer_ip)
        .collect();
    failures.extend(
        check(
            "Xvnc listens on the guest's loopback only",
            !vnc_listeners.is_empty()
                && vnc_listeners
                    .iter()
                    .all(|a| a.is_some_and(|a| a.is_loopback())),
        )
        .err(),
    );

    // Required: the trust store, the Zscaler chain, Firefox.
    let login_env = guest_cmd(
        session,
        "bash -lc 'env | grep -iE \"SSL_CERT|REQUESTS_CA|NODE_USE\"' || echo 'no login trust env'",
    )
    .await?;
    failures.extend(
        check(
            "login shells have the trust environment",
            login_env.stdout.contains("SSL_CERT_FILE="),
        )
        .err(),
    );
    let session_env = guest_cmd(
        session,
        "sudo cat /proc/$(pgrep -xo xfce4-session || echo 1)/environ 2>/dev/null | tr '\\0' \
            '\\n' | grep -iE 'SSL_CERT|REQUESTS_CA|NODE_USE' || echo 'no session trust env'",
    )
    .await?;
    failures.extend(
        check(
            "the desktop session has the trust environment",
            session_env.stdout.contains("SSL_CERT_FILE="),
        )
        .err(),
    );
    let verify = guest_cmd(
        session,
        &format!(
            "openssl s_client -connect {SITE}:443 -servername {SITE} \
             </dev/null 2>&1 | grep -E 'Verify return code|issuer='"
        ),
    )
    .await?;
    failures.extend(
        check(
            &format!("openssl verifies the {SITE} chain"),
            verify.stdout.contains("Verify return code: 0"),
        )
        .err(),
    );
    let firefox = guest_cmd(
        session,
        "firefox --version 2>/dev/null; test -x /usr/lib/firefox/firefox && echo 'Mozilla \
            firefox (not snap)'",
    )
    .await?;
    failures.extend(
        check(
            "Mozilla's Firefox is installed, not the snap",
            firefox.stdout.contains("not snap"),
        )
        .err(),
    );

    // Required: Firefox loaded the site, seen as the world's http.request
    // event with Firefox's User-Agent.
    let firefox_deadline = Instant::now() + Duration::from_secs(90);
    while !loaded.load(Ordering::SeqCst) && Instant::now() < firefox_deadline {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    failures.extend(
        check(
            "Firefox loaded the site (the world's http.request event)",
            loaded.load(Ordering::SeqCst),
        )
        .err(),
    );
    // A moment for Firefox to finish painting the page and its padlock. A
    // failed load fails the gate, which then prints the guest's Firefox log.
    if loaded.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_secs(6)).await;
    }

    // Required: the coding agents are on the desktop user's PATH over SSH,
    // each at its pinned release.
    let claude = guest_cmd(session, "claude --version").await?;
    failures.extend(
        check(
            &format!("claude --version is Claude Code {}", guest::CLAUDE_VERSION),
            claude.code == 0
                && claude
                    .stdout
                    .contains(&format!("{} (Claude Code)", guest::CLAUDE_VERSION)),
        )
        .err(),
    );
    let codex = guest_cmd(session, "codex --version").await?;
    failures.extend(
        check(
            &format!("codex --version is codex-cli {}", guest::CODEX_VERSION),
            codex.code == 0 && codex.stdout.trim() == format!("codex-cli {}", guest::CODEX_VERSION),
        )
        .err(),
    );

    let rows: Vec<_> = [("Claude Code", &claude), ("Codex", &codex)]
        .into_iter()
        .filter(|(_, output)| output.code == 0)
        .filter_map(|(name, output)| {
            agent_version(&output.stdout)
                .map(|version| json!({"name":name, "version":version, "status":"installed"}))
        })
        .collect();
    agents.publish(cx.now(), &rows).map_err(boxed)?;

    // A screenshot of the guest's own screen, over ssh, decoded on the host.
    let mut screenshots = Vec::new();
    let shot = session
        .run(
            "sudo -u analyst env DISPLAY=:1 scrot -o /tmp/guest.png 2>/dev/null && base64 -w0 \
            /tmp/guest.png",
        )
        .await?;
    let guest_png = save_png(&shot.stdout, &shots.join("guest-desktop.png"));
    failures.extend(check("the guest's own screen was captured", guest_png.is_some()).err());
    screenshots.extend(guest_png);

    // Required: the desktop as the viewer delivers it, proved without a
    // browser -- connect to the page's own WebSocket and speak RFB through the
    // bridge (page -> WebSocket -> SSH tunnel across the world -> Xvnc) --
    // and then as the host's headless Chromium renders the page.
    let captured = run
        .screenshots(
            HOSTNAME,
            &shots.join("viewer-desktop.png"),
            &shots.join("page-desktop.png"),
        )
        .await;
    match &captured {
        Ok(saved) => screenshots.extend([
            saved.screen.png.display().to_string(),
            saved.page.display().to_string(),
        ]),
        Err(error) => println!("screenshots: {error}"),
    }
    failures.extend(
        check(
            "the viewer shows the desktop through the SSH tunnel",
            captured.is_ok(),
        )
        .err(),
    );

    page_checks(page_url, session, &mut failures).await;

    // Required: each agent's own HTTP client trusts the world's CA through
    // the system store, with no flags. Each asks the site for a path it does
    // not serve; reporting the site's 404 means the client verified the
    // Zscaler chain, where a distrusted chain reports a certificate error.
    let claude_tls = guest_cmd(
        session,
        &format!("timeout 60 claude plugin marketplace add https://{SITE}/marketplace.json 2>&1"),
    )
    .await?;
    failures.extend(
        check(
            &format!("Claude Code's client gets the {SITE} site's answer over the Zscaler chain"),
            claude_tls.stdout.contains("HTTP 404") && !claude_tls.stdout.contains("certificate"),
        )
        .err(),
    );
    // Codex's doctor probes the active model provider's inference URL.
    let codex_tls = guest_cmd(
        session,
        &format!(
            "timeout 60 codex -c model_provider=site \
             -c 'model_providers.site={{name=\"site\",base_url=\"https://{SITE}\
                 \",requires_openai_auth=false}}' \
             doctor --no-color --ascii 2>&1 | grep -iE 'inference URL|TLS|certificate|sandbox'"
        ),
    )
    .await?;
    failures.extend(
        check(
            &format!("Codex's client gets the {SITE} site's answer over the Zscaler chain"),
            codex_tls
                .stdout
                .contains(&format!("https://{SITE}/responses reachable (HTTP 404)")),
        )
        .err(),
    );
    let agents = guest_cmd(
        session,
        "sudo grep -h '^coding agents:' /var/log/cloud-init-output.log || echo 'coding agents: \
            not installed'",
    )
    .await?;
    let agents_install = agents
        .stdout
        .trim()
        .trim_start_matches("coding agents:")
        .trim()
        .to_string();

    let peak_rss_mib = vm.peak_rss_mib().unwrap_or(0);
    if !failures.is_empty() {
        return Err(format!("the gate's required checks failed: {}", joined(&failures)).into());
    }
    Ok(Checks {
        desktop_ready_ms,
        cloud_init_ready_ms,
        agents_install,
        peak_rss_mib,
        screenshots,
    })
}

async fn probe(
    failures: &mut Vec<std::io::Error>,
    name: &str,
    test: impl std::future::Future<Output = std::io::Result<bool>>,
) {
    let result = tokio::time::timeout(Duration::from_secs(45), test).await;
    let ok = match result {
        Ok(Ok(ok)) => ok,
        Ok(Err(error)) => {
            println!("{name}: {error}");
            false
        }
        Err(error) => {
            println!("{name}: {error}");
            false
        }
    };
    failures.extend(check(name, ok).err());
}

async fn page_checks(url: &str, session: &ssh::Session, failures: &mut Vec<std::io::Error>) {
    let page = PageClient::from_url(url).expect("the kit's signed page URL");
    probe(
        failures,
        "the page requires the bearer for API calls",
        async {
            let refused = page.request("GET", "/api/page", None, false).await?;
            page.bootstrap().await?;
            let allowed = page.request("GET", "/api/page", None, true).await?;
            Ok(refused.status == 401 && allowed.status == 200)
        },
    )
    .await;
    probe(
        failures,
        "the page requires a single-use screen ticket",
        async {
            let missing = page.open(HOSTNAME, Capability::Screen, None).await;
            let ticket = page.ticket(HOSTNAME, Capability::Screen).await?;
            let socket = page
                .open(HOSTNAME, Capability::Screen, Some(&ticket.ticket))
                .await?;
            let viewer = rfb::Viewer::handshake(socket).await?;
            drop(viewer);
            let reused = page
                .open(HOSTNAME, Capability::Screen, Some(&ticket.ticket))
                .await;
            let unauthorized = |result: std::io::Result<kit::client::Socket>| {
                result
                    .err()
                    .is_some_and(|error| error.to_string().starts_with("HTTP/1.1 401 "))
            };
            Ok(unauthorized(missing) && unauthorized(reused))
        },
    )
    .await;
    probe(
        failures,
        "the page terminal runs hostname on workstation",
        async {
            let ticket = page.ticket(HOSTNAME, Capability::Terminal).await?;
            let mut socket = page
                .open(HOSTNAME, Capability::Terminal, Some(&ticket.ticket))
                .await?;
            socket.write_all(b"echo \"name:$(hostname):end\"\r").await?;
            socket.read_until(b"name:workstation:end", 64 << 10).await?;
            Ok(true)
        },
    )
    .await;
    probe(
        failures,
        "the screen drops pointer input without a lease and accepts it with a lease",
        pointer_check(&page, session),
    )
    .await;
}

async fn pointer_position(session: &ssh::Session) -> std::io::Result<(u16, u16)> {
    let output = session
        .run("sudo -u analyst env DISPLAY=:1 xdotool getmouselocation --shell")
        .await?;
    if output.code != 0 {
        return Err(std::io::Error::other(format!(
            "pointer query: {}",
            output.stderr
        )));
    }
    let coordinate = |name| {
        output
            .stdout
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| {
                std::io::Error::other(format!("pointer query has no {name}: {}", output.stdout))
            })
    };
    Ok((coordinate("X=")?, coordinate("Y=")?))
}

async fn pointer_check(page: &PageClient, session: &ssh::Session) -> std::io::Result<bool> {
    let before = pointer_position(session).await?;
    let ticket = page.ticket(HOSTNAME, Capability::Screen).await?;
    let socket = page
        .open(HOSTNAME, Capability::Screen, Some(&ticket.ticket))
        .await?;
    let mut viewer = rfb::Viewer::handshake(socket).await?;
    let (width, height) = viewer.size();
    if width < 4 || height < 4 || before.0 >= width || before.1 >= height {
        return Err(std::io::Error::other(
            "pointer or screen dimensions are invalid",
        ));
    }
    let away = |point: (u16, u16)| {
        (
            ((u32::from(point.0) + u32::from(width / 2)) % u32::from(width)) as u16,
            ((u32::from(point.1) + u32::from(height / 2)) % u32::from(height)) as u16,
        )
    };
    let denied = away(before);
    viewer.pointer(denied.0, denied.1, 0).await?;
    viewer.update().await?;
    let unchanged = pointer_position(session).await? == before;
    drop(viewer);

    let ticket = page.ticket(HOSTNAME, Capability::Screen).await?;
    let socket = page
        .open(HOSTNAME, Capability::Screen, Some(&ticket.ticket))
        .await?;
    let mut viewer = rfb::Viewer::handshake(socket).await?;
    // The lease API requires an open screen session.
    let body = json!({"host":HOSTNAME,"session":ticket.session});
    let lease = page
        .request("POST", "/api/lease", Some(&body), true)
        .await?;
    if lease.status != 200 {
        return Err(std::io::Error::other(format!(
            "claim input: {}",
            lease.status_line
        )));
    }
    let target = ((denied.0 + 1) % width, denied.1);
    let moved = tokio::time::timeout(Duration::from_secs(20), async {
        viewer.pointer(target.0, target.1, 0).await?;
        viewer.update().await?;
        Ok::<_, std::io::Error>(pointer_position(session).await? == target)
    })
    .await;
    let released = page
        .request("DELETE", "/api/lease", Some(&body), true)
        .await?;
    drop(viewer);
    Ok(unchanged && moved?? && released.status == 200)
}

/// The address in an `ss` address column (`10.0.0.2:22`,
/// `[::ffff:10.10.5.20]:51234`, `*:22`), with IPv4-mapped IPv6 as IPv4.
fn peer_ip(column: &str) -> Option<IpAddr> {
    let (host, _port) = column.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let host = host.split('%').next()?;
    match host.parse::<IpAddr>().ok()? {
        IpAddr::V6(v6) => Some(v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)),
        v4 => Some(v4),
    }
}

/// Runs a command on the guest, prints it and its output for the log, and
/// returns the result.
async fn guest_cmd(session: &ssh::Session, command: &str) -> Result<ssh::Output, Error> {
    let out = session.run(command).await?;
    println!("guest$ {command}");
    if !out.stdout.is_empty() {
        print!("{}", out.stdout);
    }
    if !out.stderr.is_empty() {
        eprint!("{}", out.stderr);
    }
    println!("[exit {}]\n", out.code);
    Ok(out)
}

/// Decodes a base64 PNG from the guest and writes it; returns the path.
fn save_png(b64: &str, path: &Path) -> Option<String> {
    let bytes = b64_decode(b64.trim())?;
    if bytes.len() < 8 || &bytes[1..4] != b"PNG" {
        return None;
    }
    std::fs::write(path, &bytes).ok()?;
    Some(path.display().to_string())
}

fn agent_version(output: &str) -> Option<&str> {
    let output = output.trim();
    let version = output
        .strip_suffix(" (Claude Code)")
        .or_else(|| output.strip_prefix("codex-cli "))?;
    let parts: Vec<_> = version.split('.').collect();
    (parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())))
    .then_some(version)
}

#[cfg(test)]
mod tests {
    use super::agent_version;

    #[test]
    fn agent_versions_come_from_command_output() {
        for (output, expected) in [
            ("2.1.292 (Claude Code)\n", Some("2.1.292")),
            ("codex-cli 0.163.0\n", Some("0.163.0")),
            ("9.8.7 (Claude Code)", Some("9.8.7")),
            ("codex-cli 8.7.6", Some("8.7.6")),
            ("", None),
            ("command not found", None),
            ("codex-cli 1.2", None),
            ("codex-cli 1..3", None),
            ("codex-cli x.2.3", None),
            ("1.2.3.4 (Claude Code)", None),
            ("error\ncodex-cli 1.2.3", None),
        ] {
            assert_eq!(agent_version(output), expected, "{output:?}");
        }
    }
}
