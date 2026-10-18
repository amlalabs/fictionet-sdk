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
mod seed;
mod ssh;
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
        wait_online: true,
    })?;
    let seed_path = dir.path().join("seed.img");
    std::fs::write(&seed_path, &seed_bytes)?;

    // The per-run overlay over the untouched download.
    let overlay = dir.path().join("overlay.qcow2");
    disk::write_overlay(&overlay, &std::fs::canonicalize(image)?, DISK_SIZE)?;

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
            vcpus: 2,
            memory_mib: 2048,
            manufacturer: "LENOVO",
            product: "20UES000-WS",
            uuid: &random_uuid(),
            net_socket: &net_socket,
            mac: world::GUEST_MAC,
        },
        dir.path(),
    )?;

    let result = run_checks(&vm, &identity, boot).await;

    // ACPI poweroff over ssh, then a bounded kill as backup.
    if let Ok(session) =
        ssh::Session::connect(vm.vsock_socket(), &identity, USER, Duration::from_secs(5)).await
    {
        let _ = session.run("sudo systemctl poweroff").await;
    }
    let stop = vm.stop(Duration::from_secs(30)).await;
    world.shutdown();

    let checks = result?;
    println!("\n=== measurements ===");
    println!("boot to ssh-ready: {} ms", checks.ssh_ready_ms);
    println!("whole run:         {} ms", total.elapsed().as_millis());
    println!("peak VM memory:    {} MiB", checks.peak_rss_mib);
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
    peak_rss_mib: u64,
}

async fn run_checks(vm: &ch::Vm, identity: &ssh::Identity, boot: Instant) -> Result<Checks, Error> {
    let session =
        match ssh::Session::connect(vm.vsock_socket(), identity, USER, Duration::from_secs(240))
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
    println!("ssh over vsock is up after {ssh_ready_ms} ms\n");

    for command in [
        "cloud-init status --long",
        "uname -a",
        "systemctl is-system-running",
        "cat /proc/cmdline",
        "sudo dmidecode -t system",
        "lspci 2>/dev/null || echo 'lspci not installed'",
        "ip -br link",
        "ip -4 addr show dev eth0 | grep inet || echo 'no DHCP lease'",
        "ip route | grep default || true",
        "ls /etc/ssl/certs | grep -i zscaler || echo 'no zscaler cert'",
        &format!(
            "openssl s_client -connect {SITE}:443 -servername {SITE} \
             </dev/null 2>&1 | grep -E 'Verify return code|subject=|issuer='"
        ),
        "env | grep -iE 'SSL_CERT|REQUESTS_CA|NODE_USE' || echo 'no trust env (milestone 2)'",
    ] {
        let out = session.run(command).await?;
        println!("guest$ {command}");
        if !out.stdout.is_empty() {
            print!("{}", out.stdout);
        }
        if !out.stderr.is_empty() {
            eprint!("{}", out.stderr);
        }
        println!("[exit {}]\n", out.code);
    }

    let peak_rss_mib = vm_peak_rss_mib(vm).unwrap_or(0);
    Ok(Checks {
        ssh_ready_ms,
        peak_rss_mib,
    })
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
