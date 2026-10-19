//! Boots Ubuntu 24.04's official cloud image unmodified in Cloud
//! Hypervisor, provisions it through cloud-init from a Fictionet world, and
//! reaches it the way an admin would, with no guest agent: SSH from a jump
//! host across the world's network, and VNC tunneled through that session.
//!
//! `cargo xtask cloudimage` downloads the pinned image, kernel, initrd and
//! Cloud Hypervisor binary and runs this with their paths. The per-run
//! overlay ([`disk`]) and cloud-init seed ([`seed`]) are written in Rust;
//! the world ([`world`]) joins the guest to the network through the
//! vhost-user backend ([`net`]), and its jump host carries the SSH session
//! ([`ssh`]) that the desktop viewer ([`page`]) tunnels VNC through.

mod ch;
mod disk;
mod mirror;
mod net;
mod page;
mod seed;
mod shot;
mod ssh;
mod viewer;
mod world;

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The overlay's virtual size: well above the image, so growpart has room.
const DISK_SIZE: u64 = 10 << 30;
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
    let [ch_bin, image, vmlinuz, initrd] = args.as_slice() else {
        eprintln!(
            "usage: cloudimage <cloud-hypervisor> <image.img> <vmlinuz> <initrd>\n\
             run it with `cargo xtask cloudimage` first to fetch the pinned files"
        );
        return ExitCode::FAILURE;
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("cloudimage: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(gate(ch_bin, image, vmlinuz, initrd)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cloudimage: {error}");
            ExitCode::FAILURE
        }
    }
}

/// A private run directory, removed when dropped.
struct RunDir(PathBuf);

impl RunDir {
    fn new() -> std::io::Result<RunDir> {
        use std::os::unix::fs::DirBuilderExt;
        let mut bytes = [0u8; 8];
        getrandom(&mut bytes);
        let path = std::env::temp_dir().join(format!("cloudimage-{}", u64::from_ne_bytes(bytes)));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(RunDir(path))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn getrandom(dest: &mut [u8]) {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(dest))
        .expect("read /dev/urandom");
}

async fn gate(ch_bin: &Path, image: &Path, vmlinuz: &Path, initrd: &Path) -> Result<(), Error> {
    let total = Instant::now();
    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let dir = RunDir::new()?;

    // This run's ssh identity.
    let identity = ssh::Identity::generate()?;

    // Start the world: it mints the Zscaler chain, hands out DHCP, serves
    // the HTTPS site, and gives us the CA root for the seed. The guest's
    // frames reach it through the vhost-user backend on this socket.
    let net_socket = dir.path().join("net.sock");
    let world = world::start(world::Config {
        now_unix,
        site: SITE.to_string(),
        net_socket: net_socket.clone(),
    })
    .await
    .map_err(boxed)?;

    // The cloud-init seed, carrying the world's CA.
    let seed_bytes = seed::build(&seed::Provision {
        hostname: HOSTNAME,
        user: USER,
        authorized_key: &identity.authorized_key,
        ca_pem: &world.ca_pem,
        site: SITE,
    })?;
    let seed_path = dir.path().join("seed.img");
    std::fs::write(&seed_path, &seed_bytes)?;

    // The per-run overlay over the untouched download.
    let overlay = dir.path().join("overlay.qcow2");
    disk::write_overlay(&overlay, &std::fs::canonicalize(image)?, DISK_SIZE)?;

    // Screenshots survive the run (the run dir does not).
    let shots = image
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("shots");
    std::fs::create_dir_all(&shots)?;

    // The desktop viewer, bound before boot so a port already in use fails
    // here rather than after a minute of install. It serves on 127.0.0.1
    // only and tunnels to the guest's VNC through the admin's SSH session
    // once that is up.
    let page = page::Page::bind(0).await.map_err(boxed)?;
    let page_url = page.url();
    let page_port = page.port();

    // Boot.
    let boot = Instant::now();
    let vm = ch::Vm::start(
        &ch::Config {
            cloud_hypervisor: ch_bin,
            vmlinuz,
            initrd,
            cmdline: "root=LABEL=cloudimg-rootfs ro console=ttyS0,115200n8 net.ifnames=0",
            overlay: &overlay,
            seed: &seed_path,
            vcpus: 4,
            memory_mib: 4096,
            manufacturer: "LENOVO",
            product: "20UES000-WS",
            uuid: &random_uuid(),
            net_socket: &net_socket,
            mac: world::GUEST_MAC,
        },
        dir.path(),
    )?;

    // Serve the viewer for the rest of the run; dropped when the gate returns.
    let tunnel = page::Tunnel::default();
    let viewer = tokio::spawn(page.serve(tunnel.clone()));
    println!("desktop viewer: {page_url}");

    // Show where Cloud Hypervisor runs from: a memfd when the binary is
    // embedded (nothing on disk), the downloaded path otherwise.
    let ch_pid = vm.pid();
    if let Some(pid) = ch_pid
        && let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe"))
    {
        println!("Cloud Hypervisor (pid {pid}) runs from {}\n", exe.display());
    }

    // The admin's SSH session, from the jump host to the guest's sshd. The
    // viewer tunnels through it once it is up.
    let result = match admin_session(&vm, &world, &identity).await {
        Ok(session) => {
            let ssh_ready_ms = boot.elapsed().as_millis();
            println!(
                "ssh from the jump host ({}) is up after {ssh_ready_ms} ms; waiting for the desktop install\n",
                world::JUMP_ADDR
            );
            let session = Arc::new(session);
            let _ = tunnel.set(session.clone());
            run_checks(&vm, &session, &world, boot, &shots, &page_url, page_port)
                .await
                .map(|checks| (ssh_ready_ms, checks))
        }
        Err(error) => Err(error),
    };
    viewer.abort();

    // ACPI poweroff over the session, then a bounded kill as backup. The
    // guest may go before it answers, so the command is not waited on long.
    if let Some(session) = tunnel.get() {
        let _ = tokio::time::timeout(
            Duration::from_secs(10),
            session.run("sudo systemctl poweroff"),
        )
        .await;
    }
    let stop = vm.stop(Duration::from_secs(60)).await;
    world.shutdown();
    let run_dir = dir.path().to_path_buf();
    drop(dir);

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

/// Connects the admin's SSH session: from the jump host, through the world,
/// to the guest's sshd on the address it leased.
async fn admin_session(
    vm: &ch::Vm,
    world: &world::World,
    identity: &ssh::Identity,
) -> Result<ssh::Session, Error> {
    let dial = || world.connect_guest(22, Duration::from_secs(10));
    match ssh::Session::connect(dial, identity, USER, Duration::from_secs(300)).await {
        Ok(session) => Ok(session),
        Err(error) => Err(format!(
            "{error}\n--- cloud-hypervisor stderr ---\n{}\n--- guest console tail ---\n{}",
            vm.ch_stderr_tail(),
            vm.console_tail()
        )
        .into()),
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
    vm: &ch::Vm,
    session: &ssh::Session,
    world: &world::World,
    boot: Instant,
    shots: &Path,
    page_url: &str,
    page_port: u16,
) -> Result<Checks, Error> {
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
        "echo \"packages downloaded: $(du -shc /var/cache/apt/archives/*.deb 2>/dev/null | tail -1 | cut -f1) in $(ls /var/cache/apt/archives/*.deb 2>/dev/null | wc -l) files\"",
        // Every socket the guest listens on, and from where.
        "sudo ss -tulnpH",
    ] {
        guest_cmd(session, command).await?;
    }

    // Required: the guest's address is the one the world leased it by DHCP.
    let lease = world.guest_addr();
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
            world::JUMP_ADDR
        ),
        !peers.is_empty() && peers.iter().all(|p| *p == Some(world::JUMP_ADDR.into())),
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
        "sudo cat /proc/$(pgrep -xo xfce4-session || echo 1)/environ 2>/dev/null | tr '\\0' '\\n' | grep -iE 'SSL_CERT|REQUESTS_CA|NODE_USE' || echo 'no session trust env'",
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
        "firefox --version 2>/dev/null; test -x /usr/lib/firefox/firefox && echo 'Mozilla firefox (not snap)'",
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
    while !world.firefox_loaded() && Instant::now() < firefox_deadline {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    check(
        &mut failures,
        "Firefox loaded the site (the world's http.request event)",
        world.firefox_loaded(),
    );
    if world.firefox_loaded() {
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
        .run("sudo -u analyst env DISPLAY=:1 scrot -o /tmp/guest.png 2>/dev/null && base64 -w0 /tmp/guest.png")
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
        viewer::capture(page_port, &viewer_png),
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
        &format!("claude --version is Claude Code {}", seed::CLAUDE_VERSION),
        claude.code == 0
            && claude
                .stdout
                .contains(&format!("{} (Claude Code)", seed::CLAUDE_VERSION)),
    );
    let codex = guest_cmd(session, "codex --version").await?;
    check(
        &mut failures,
        &format!("codex --version is codex-cli {}", seed::CODEX_VERSION),
        codex.code == 0 && codex.stdout.trim() == format!("codex-cli {}", seed::CODEX_VERSION),
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
             -c 'model_providers.site={{name=\"site\",base_url=\"https://{SITE}\",requires_openai_auth=false}}' \
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
        "sudo grep -h '^coding agents:' /var/log/cloud-init-output.log || echo 'coding agents: not installed'",
    )
    .await?;
    let agents_install = agents
        .stdout
        .trim()
        .trim_start_matches("coding agents:")
        .trim()
        .to_string();

    let peak_rss_mib = vm_peak_rss_mib(vm).unwrap_or(0);
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

/// Decodes standard base64 (ignoring whitespace).
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for &c in s.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = val(c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// The VM child's peak resident memory, in MiB.
fn vm_peak_rss_mib(vm: &ch::Vm) -> Option<u64> {
    let pid = vm.pid()?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.trim().trim_end_matches(" kB").parse::<u64>().ok())
        .map(|kb| kb >> 10)
}

fn random_uuid() -> String {
    let mut b = [0u8; 16];
    getrandom(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}
