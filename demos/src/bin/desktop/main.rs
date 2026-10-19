//! The desktop gate on the shared microVM kit.
//! Run with `cargo xtask demo desktop`.

mod guest;
mod page;
mod world;

use fictionet_demo::kit::{self, Kit, b64_decode, rfb, shot, ssh};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

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
    let dashboard =
        fictionet_observe::DashboardObserver::new(fictionet_observe::DashboardOptions::demo());
    let _observation = observation
        .as_ref()
        .map(|p| fictionet_observe::serve(dashboard.handle(), p))
        .transpose()
        .map_err(boxed)?;
    let kit = Kit::new("desktop")
        .guest(guest::workstation(HOSTNAME, USER, SITE))
        .observer(dashboard.observer())
        .observer(Arc::new(world::SiteLoaded {
            host: SITE.into(),
            loaded: loaded.clone(),
        }))
        .world(|fcx, world| world::start(fcx, world, SITE.into()));
    // Screenshots survive the run (the run dir does not).
    let shots = downloads.join("shots");
    std::fs::create_dir_all(&shots)?;

    // The desktop viewer, bound before boot so a port already in use fails
    // here rather than after a minute of install. It serves on 127.0.0.1
    // only and tunnels to the guest's VNC through the admin's SSH session
    // once that is up.
    let page = page::Page::bind(0).await.map_err(boxed)?;
    let page_url = page.url();
    let page_port = page.port();

    let tunnel = page::Tunnel::default();
    let viewer = tokio::spawn(page.serve(tunnel.clone()));
    println!("desktop viewer: {page_url}");
    let run = match kit.boot(downloads).await {
        Ok(run) => run,
        Err(error) => {
            viewer.abort();
            let _ = viewer.await;
            return Err(error.into());
        }
    };
    let boot = run.boot_started();
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
    let _ = tunnel.set(workstation.ssh().clone());
    let result = run_checks(workstation, &loaded, boot, &shots, &page_url, page_port)
        .await
        .map(|checks| (ssh_ready_ms, checks));
    viewer.abort();
    let _ = viewer.await;
    let run_dir = run.path().to_path_buf();
    let stop = run.shutdown().await;

    println!("\n=== shutdown ===");
    let mut failures = Vec::new();
    if let Err(error) = &stop {
        println!("shutdown: {error}");
    }
    check(
        &mut failures,
        "the guest powered off over ACPI and Cloud Hypervisor exited",
        stop.is_ok(),
    );
    let ch_gone = ch_pid.is_none_or(|pid| !Path::new(&format!("/proc/{pid}")).exists());
    check(
        &mut failures,
        "nothing is left behind: no Cloud Hypervisor process, no run directory",
        ch_gone && !run_dir.exists(),
    );

    let (ssh_ready_ms, checks) = result?;
    println!("\n=== measurements ===");
    println!("boot to ssh-ready:  {ssh_ready_ms} ms");
    println!("boot to desktop:    {} ms", checks.desktop_ready_ms);
    println!("coding agents:      {}", checks.agents_install);
    println!("whole run:          {} ms", total.elapsed().as_millis());
    println!("peak VM memory:     {} MiB", checks.peak_rss_mib);
    for shot in &checks.screenshots {
        println!("screenshot:         {shot}");
    }
    if !failures.is_empty() {
        return Err(format!("the gate's shutdown checks failed: {}", failures.join("; ")).into());
    }
    println!("\nevery required check passed");
    Ok(())
}

/// Prints a required check's outcome, and records it when it failed.
fn check(failures: &mut Vec<String>, what: &str, ok: bool) {
    println!("[{}] {what}", if ok { "pass" } else { "FAIL" });
    if !ok {
        failures.push(what.to_string());
    }
}

struct Checks {
    desktop_ready_ms: u128,
    /// The guest's own measure of the coding agents' install: bytes
    /// downloaded and seconds taken.
    agents_install: String,
    peak_rss_mib: u64,
    screenshots: Vec<String>,
}

async fn run_checks(
    workstation: &kit::GuestHandle,
    loaded: &AtomicBool,
    boot: Instant,
    shots: &Path,
    page_url: &str,
    page_port: u16,
) -> Result<Checks, Error> {
    let vm = workstation.vm();
    let session = workstation.ssh();
    // Every required check that failed; the gate fails at the end if any did.
    let mut failures: Vec<String> = Vec::new();

    // Block until cloud-init finishes, but not forever: a stalled install must
    // fail the gate, not hang it.
    let wait = match tokio::time::timeout(
        Duration::from_secs(300),
        session.run("sudo cloud-init status --wait >/dev/null 2>&1; echo $?"),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => return Err("cloud-init did not finish within 300 s".into()),
    };
    let desktop_ready_ms = boot.elapsed().as_millis();
    let cloud_init_rc = wait.stdout.trim().to_string();
    println!("cloud-init finished after {desktop_ready_ms} ms (rc {cloud_init_rc})\n");
    check(&mut failures, "cloud-init finished", cloud_init_rc == "0");

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
    check(
        &mut failures,
        &format!(
            "the guest has its address from the world's DHCP ({})",
            lease.map_or("no lease".to_string(), |a| a.to_string())
        ),
        lease.is_some_and(|a| addr.stdout.contains(&format!("inet {a}/"))),
    );

    // Required: no vsock device for the guest to find.
    let pci = guest_cmd(session, "lspci -nn").await?;
    let vsock = pci.stdout.lines().any(|line| {
        let line = line.to_ascii_lowercase();
        line.contains("socket") || line.contains("[1af4:1053]") || line.contains("[1af4:1012]")
    });
    check(
        &mut failures,
        "lspci shows no Virtio socket device",
        pci.code == 0 && !pci.stdout.is_empty() && !vsock,
    );

    // Required: this session reaches sshd from the jump host's address.
    let ssh_peers = guest_cmd(session, "ss -tnH state established '( sport = :22 )'").await?;
    let peers: Vec<Option<IpAddr>> = ssh_peers
        .stdout
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .map(peer_ip)
        .collect();
    check(
        &mut failures,
        &format!(
            "ss shows the SSH session coming from the jump host ({})",
            kit::jump::JUMP_ADDR
        ),
        !peers.is_empty()
            && peers
                .iter()
                .all(|p| *p == Some(kit::jump::JUMP_ADDR.into())),
    );

    // Required: Ubuntu's sshd and the desktop are running, and Xvnc listens
    // on the loopback only, so sshd is the guest's one network service of ours.
    let services = guest_cmd(session, "systemctl is-active ssh.service vnc.service").await?;
    check(
        &mut failures,
        "ssh.service and vnc.service are active",
        services
            .stdout
            .lines()
            .filter(|l| l.trim() == "active")
            .count()
            == 2,
    );
    let vnc = guest_cmd(session, "ss -tlnH '( sport = :5900 or sport = :5901 )'").await?;
    let vnc_listeners: Vec<Option<IpAddr>> = vnc
        .stdout
        .lines()
        .filter_map(|line| line.split_whitespace().nth(3))
        .map(peer_ip)
        .collect();
    check(
        &mut failures,
        "Xvnc listens on the guest's loopback only",
        !vnc_listeners.is_empty()
            && vnc_listeners
                .iter()
                .all(|a| a.is_some_and(|a| a.is_loopback())),
    );

    // Required: the trust store, the Zscaler chain, Firefox.
    let login_env = guest_cmd(
        session,
        "bash -lc 'env | grep -iE \"SSL_CERT|REQUESTS_CA|NODE_USE\"' || echo 'no login trust env'",
    )
    .await?;
    check(
        &mut failures,
        "login shells have the trust environment",
        login_env.stdout.contains("SSL_CERT_FILE="),
    );
    let session_env = guest_cmd(
        session,
        "sudo cat /proc/$(pgrep -xo xfce4-session || echo 1)/environ 2>/dev/null | tr '\\0' \
            '\\n' | grep -iE 'SSL_CERT|REQUESTS_CA|NODE_USE' || echo 'no session trust env'",
    )
    .await?;
    check(
        &mut failures,
        "the desktop session has the trust environment",
        session_env.stdout.contains("SSL_CERT_FILE="),
    );
    let verify = guest_cmd(
        session,
        &format!(
            "openssl s_client -connect {SITE}:443 -servername {SITE} \
             </dev/null 2>&1 | grep -E 'Verify return code|issuer='"
        ),
    )
    .await?;
    check(
        &mut failures,
        &format!("openssl verifies the {SITE} chain"),
        verify.stdout.contains("Verify return code: 0"),
    );
    let firefox = guest_cmd(
        session,
        "firefox --version 2>/dev/null; test -x /usr/lib/firefox/firefox && echo 'Mozilla \
            firefox (not snap)'",
    )
    .await?;
    check(
        &mut failures,
        "Mozilla's Firefox is installed, not the snap",
        firefox.stdout.contains("not snap"),
    );

    // Required: Firefox loaded the site, seen as the world's http.request
    // event with Firefox's User-Agent.
    let firefox_deadline = Instant::now() + Duration::from_secs(90);
    while !loaded.load(Ordering::SeqCst) && Instant::now() < firefox_deadline {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    check(
        &mut failures,
        "Firefox loaded the site (the world's http.request event)",
        loaded.load(Ordering::SeqCst),
    );
    if loaded.load(Ordering::SeqCst) {
        // A moment for Firefox to finish painting the page and its padlock.
        tokio::time::sleep(Duration::from_secs(6)).await;
    } else {
        // Pull the launch logs so a failed run still shows why.
        for command in [
            "pgrep -af firefox || echo 'no firefox process'",
            "echo '--- /tmp/firefox.log ---'; tail -40 /tmp/firefox.log 2>&1",
            "echo '--- /tmp/xfce.log ---'; tail -20 /tmp/xfce.log 2>&1",
            "echo '--- .mozilla ---'; ls -laR /home/analyst/.mozilla 2>&1 | head -30",
        ] {
            guest_cmd(session, command).await?;
        }
    }

    // A screenshot of the guest's own screen, over ssh, decoded on the host.
    let mut screenshots = Vec::new();
    let shot = session
        .run(
            "sudo -u analyst env DISPLAY=:1 scrot -o /tmp/guest.png 2>/dev/null && base64 -w0 \
            /tmp/guest.png",
        )
        .await?;
    let guest_png = save_png(&shot.stdout, &shots.join("guest-desktop.png"));
    check(
        &mut failures,
        "the guest's own screen was captured",
        guest_png.is_some(),
    );
    screenshots.extend(guest_png);

    // Required: the desktop as the viewer delivers it, proved without a
    // browser -- connect to the page's own WebSocket and speak RFB through the
    // bridge (page -> WebSocket -> SSH tunnel across the world -> Xvnc),
    // saving the guest's screen.
    let viewer_png = shots.join("viewer-desktop.png");
    let capture = tokio::time::timeout(
        Duration::from_secs(30),
        rfb::capture_page(page_port, &viewer_png),
    )
    .await
    .unwrap_or_else(|_| Err(std::io::Error::other("timed out")));
    match &capture {
        Ok(cap) => {
            println!(
                "the guest's VNC server answered through the page's WebSocket bridge with \
                 \"{}\"; its {}x{} screen, {}{} colors, saved to {}",
                cap.banner,
                cap.width,
                cap.height,
                cap.colors,
                if cap.colors == 256 { "+" } else { "" },
                cap.png.display()
            );
            screenshots.push(cap.png.display().to_string());
        }
        Err(error) => println!("viewer capture: not completed ({error})"),
    }
    check(
        &mut failures,
        "the viewer shows the desktop through the SSH tunnel",
        capture.is_ok_and(|cap| cap.colors >= 16),
    );

    // The same desktop as a real browser renders it: the host's headless
    // Chromium loads the embedded noVNC page over the same bridge. Best
    // effort -- it needs a Chromium whose network works in this sandbox.
    let out = shots.join("novnc.png");
    let url = page_url.to_string();
    let captured = tokio::task::spawn_blocking(move || shot::capture(&url, &out)).await?;
    match captured {
        Some(path) => {
            println!("noVNC viewer screenshot saved: {path}");
            screenshots.push(path);
        }
        None => println!("noVNC viewer screenshot: not captured"),
    }

    // Required: the coding agents are on the desktop user's PATH over SSH,
    // each at its pinned release.
    let claude = guest_cmd(session, "claude --version").await?;
    check(
        &mut failures,
        &format!("claude --version is Claude Code {}", guest::CLAUDE_VERSION),
        claude.code == 0
            && claude
                .stdout
                .contains(&format!("{} (Claude Code)", guest::CLAUDE_VERSION)),
    );
    let codex = guest_cmd(session, "codex --version").await?;
    check(
        &mut failures,
        &format!("codex --version is codex-cli {}", guest::CODEX_VERSION),
        codex.code == 0 && codex.stdout.trim() == format!("codex-cli {}", guest::CODEX_VERSION),
    );

    // Required: each agent's own HTTP client trusts the world's CA through
    // the system store, with no flags. Each asks the site for a path it does
    // not serve; reporting the site's 404 means the client verified the
    // Zscaler chain, where a distrusted chain reports a certificate error.
    let claude_tls = guest_cmd(
        session,
        &format!("timeout 60 claude plugin marketplace add https://{SITE}/marketplace.json 2>&1"),
    )
    .await?;
    check(
        &mut failures,
        &format!("Claude Code's client gets the {SITE} site's answer over the Zscaler chain"),
        claude_tls.stdout.contains("HTTP 404") && !claude_tls.stdout.contains("certificate"),
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
    check(
        &mut failures,
        &format!("Codex's client gets the {SITE} site's answer over the Zscaler chain"),
        codex_tls
            .stdout
            .contains(&format!("https://{SITE}/responses reachable (HTTP 404)")),
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
        return Err(format!("the gate's required checks failed: {}", failures.join("; ")).into());
    }
    Ok(Checks {
        desktop_ready_ms,
        agents_install,
        peak_rss_mib,
        screenshots,
    })
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
