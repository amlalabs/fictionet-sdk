//! Boots Ubuntu 24.04's official cloud image unmodified in Cloud
//! Hypervisor, provisions it through cloud-init from a Fictionet world, and
//! reaches it over ssh on vsock with no guest agent.
//!
//! `cargo xtask cloudimage` downloads the pinned image, kernel, initrd and
//! Cloud Hypervisor binary and runs this with their paths. The per-run
//! overlay ([`disk`]) and cloud-init seed ([`seed`]) are written in Rust;
//! the world ([`world`]) joins the guest to the network through the
//! vhost-user backend ([`net`]) and reaches it over vsock ([`ssh`]).

mod ch;
mod disk;
mod net;
mod page;
mod seed;
mod shot;
mod ssh;
mod viewer;
mod world;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
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
    // only and bridges to the guest's VNC over vsock once the guest is up.
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
    let viewer = tokio::spawn(page.serve(vm.vsock_socket().to_path_buf()));
    println!("desktop viewer: {page_url}");

    let result = run_checks(&vm, &identity, boot, &shots, &world, &page_url, page_port).await;
    viewer.abort();

    // ACPI poweroff over ssh, then a bounded kill as backup.
    if let Ok(session) =
        ssh::Session::connect(vm.vsock_socket(), &identity, USER, Duration::from_secs(5)).await
    {
        let _ = session.run("sudo systemctl poweroff").await;
    }
    let stop = vm.stop(Duration::from_secs(60)).await;
    world.shutdown();

    let checks = result?;
    println!("\n=== measurements ===");
    println!("boot to ssh-ready:  {} ms", checks.ssh_ready_ms);
    println!("boot to desktop:    {} ms", checks.desktop_ready_ms);
    println!("whole run:          {} ms", total.elapsed().as_millis());
    println!("peak VM memory:     {} MiB", checks.peak_rss_mib);
    for shot in &checks.screenshots {
        println!("screenshot:         {shot}");
    }
    match &stop {
        Ok(()) => println!("the guest powered off; Cloud Hypervisor exited"),
        Err(e) => println!("shutdown: {e}"),
    }
    println!("the run directory is removed; nothing is left behind");
    stop?;
    Ok(())
}

struct Checks {
    ssh_ready_ms: u128,
    desktop_ready_ms: u128,
    peak_rss_mib: u64,
    screenshots: Vec<String>,
}

async fn run_checks(
    vm: &ch::Vm,
    identity: &ssh::Identity,
    boot: Instant,
    shots: &Path,
    world: &world::World,
    page_url: &str,
    page_port: u16,
) -> Result<Checks, Error> {
    let session =
        match ssh::Session::connect(vm.vsock_socket(), identity, USER, Duration::from_secs(300))
            .await
        {
            Ok(session) => session,
            Err(error) => {
                return Err(format!(
                    "{error}\n--- cloud-hypervisor stderr ---\n{}\n--- guest console tail ---\n{}",
                    vm.ch_stderr_tail(),
                    vm.console_tail()
                )
                .into());
            }
        };
    let ssh_ready_ms = boot.elapsed().as_millis();
    println!("ssh over vsock is up after {ssh_ready_ms} ms; waiting for the desktop install\n");

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
    if cloud_init_rc != "0" {
        failures.push(format!("cloud-init exited {cloud_init_rc}"));
    }

    // What the guest looks like, for the log.
    for command in [
        "cloud-init status --long",
        "cat /proc/cmdline",
        "sudo dmidecode -s system-manufacturer; sudo dmidecode -s system-product-name",
        "pgrep -a Xvnc || echo 'no Xvnc'",
        "pgrep -af firefox | head -1 || echo 'no firefox'",
        "ls /etc/ssl/certs | grep -i zscaler || echo 'no zscaler cert'",
    ] {
        guest_cmd(&session, command).await?;
    }

    // Required: the services, the trust store, the Zscaler chain, Firefox.
    let services = guest_cmd(&session, "systemctl is-active vnc.service vnc-vsock.socket sshd-vsock.socket").await?;
    if services.stdout.lines().filter(|l| l.trim() == "active").count() != 3 {
        failures.push("a required service is not active".into());
    }
    let login_env = guest_cmd(
        &session,
        "bash -lc 'env | grep -iE \"SSL_CERT|REQUESTS_CA|NODE_USE\"' || echo 'no login trust env'",
    )
    .await?;
    if !login_env.stdout.contains("SSL_CERT_FILE=") {
        failures.push("the trust store is missing from login shells".into());
    }
    let session_env = guest_cmd(
        &session,
        "sudo cat /proc/$(pgrep -xo xfce4-session || echo 1)/environ 2>/dev/null | tr '\\0' '\\n' | grep -iE 'SSL_CERT|REQUESTS_CA|NODE_USE' || echo 'no session trust env'",
    )
    .await?;
    if !session_env.stdout.contains("SSL_CERT_FILE=") {
        failures.push("the trust store is missing from the desktop session".into());
    }
    let verify = guest_cmd(
        &session,
        &format!(
            "openssl s_client -connect {SITE}:443 -servername {SITE} \
             </dev/null 2>&1 | grep -E 'Verify return code|issuer='"
        ),
    )
    .await?;
    if !verify.stdout.contains("Verify return code: 0") {
        failures.push(format!("the guest did not trust the {SITE} chain"));
    }
    let firefox = guest_cmd(
        &session,
        "firefox --version 2>/dev/null; test -x /usr/lib/firefox/firefox && echo 'Mozilla firefox (not snap)'",
    )
    .await?;
    if !firefox.stdout.contains("not snap") {
        failures.push("Mozilla's Firefox is not installed".into());
    }

    // Required: Firefox loaded the site, seen as the world's http.request
    // event (nothing else fetches it over HTTP).
    let firefox_deadline = Instant::now() + Duration::from_secs(90);
    while !world.firefox_loaded() && Instant::now() < firefox_deadline {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    if world.firefox_loaded() {
        println!("Firefox loaded the site (seen as the world's http.request event)\n");
        // A moment for Firefox to finish painting the page and its padlock.
        tokio::time::sleep(Duration::from_secs(6)).await;
    } else {
        failures.push("Firefox did not load the site".into());
        println!("Firefox did not load the site within the deadline\n");
        // Pull the launch logs so a failed run still shows why.
        for command in [
            "pgrep -af firefox || echo 'no firefox process'",
            "echo '--- /tmp/firefox.log ---'; tail -40 /tmp/firefox.log 2>&1",
            "echo '--- /tmp/xfce.log ---'; tail -20 /tmp/xfce.log 2>&1",
            "echo '--- .mozilla ---'; ls -laR /home/analyst/.mozilla 2>&1 | head -30",
        ] {
            guest_cmd(&session, command).await?;
        }
    }

    // A screenshot of the guest's own screen, over ssh, decoded on the host.
    let mut screenshots = Vec::new();
    let shot = session
        .run("sudo -u analyst env DISPLAY=:1 scrot -o /tmp/guest.png 2>/dev/null && base64 -w0 /tmp/guest.png")
        .await?;
    if let Some(path) = save_png(&shot.stdout, &shots.join("guest-desktop.png")) {
        println!("guest screenshot saved: {path}");
        screenshots.push(path);
    } else {
        failures.push("the guest's screen could not be captured".into());
        println!("guest screenshot: not captured");
    }

    // Required: the desktop as the viewer delivers it, proved without a
    // browser -- connect to the page's own WebSocket and speak RFB through the
    // bridge (page -> WebSocket -> vsock -> Xvnc), saving the guest's screen.
    let viewer_png = shots.join("viewer-desktop.png");
    match tokio::time::timeout(
        Duration::from_secs(30),
        viewer::capture(page_port, &viewer_png),
    )
    .await
    {
        Ok(Ok(cap)) => {
            println!(
                "viewer path verified: the guest's VNC server answered through the page's \
                 WebSocket bridge with \"{}\"; its {}x{} screen saved to {}\n",
                cap.banner,
                cap.width,
                cap.height,
                cap.png.display()
            );
            screenshots.push(cap.png.display().to_string());
        }
        Ok(Err(error)) => {
            failures.push(format!("the viewer path did not work ({error})"));
            println!("viewer capture: not completed ({error})\n");
        }
        Err(_) => {
            failures.push("the viewer path did not work (timed out)".into());
            println!("viewer capture: not completed (timed out)\n");
        }
    }

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

    let peak_rss_mib = vm_peak_rss_mib(vm).unwrap_or(0);
    if !failures.is_empty() {
        return Err(format!("the gate's required checks failed: {}", failures.join("; ")).into());
    }
    Ok(Checks {
        ssh_ready_ms,
        desktop_ready_ms,
        peak_rss_mib,
        screenshots,
    })
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
