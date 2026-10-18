//! Prepares the per-run inputs to boot Ubuntu 24.04's official cloud image
//! unmodified under a hypervisor, provisioned by a Fictionet world through
//! cloud-init, with no guest agent.
//!
//! These parts are the same whatever hypervisor boots the image:
//!
//! - a per-run qcow2 overlay over the read-only download ([`disk`]);
//! - a cloud-init NoCloud `cidata` seed written in Rust ([`seed`]), carrying
//!   a neutral hostname, a user with this run's SSH key, the world's CA as
//!   `zscaler.crt`, and an sshd-over-vsock socket unit;
//! - an embedded SSH client that reaches the guest over the hypervisor's
//!   vsock ([`ssh`]).
//!
//! `cargo xtask cloudimage` downloads the pinned image, kernel, initrd and a
//! hypervisor; this tool turns a download into a bootable overlay and seed.
//! Joining the guest to a world (DHCP, the HTTPS site) is the hypervisor's
//! network backend, which depends on the VMM and is not built here.

mod disk;
mod seed;
mod ssh;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use example_common::zscaler::{DEFAULT_CLOUD, zscaler};

/// The overlay's virtual size: well above the image, so cloud-init's
/// growpart has room to expand the root.
const DISK_SIZE: u64 = 10 << 30;
const HOSTNAME: &str = "workstation";
const USER: &str = "analyst";

type Error = Box<dyn std::error::Error>;

fn main() -> ExitCode {
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    let [image, out_dir] = args.as_slice() else {
        eprintln!(
            "usage: cloudimage <image.img> <out-dir>\n\
             writes <out-dir>/overlay.qcow2 and <out-dir>/seed.img, the per-run\n\
             inputs a hypervisor boots. Run `cargo xtask cloudimage` first to fetch\n\
             the pinned image."
        );
        return ExitCode::FAILURE;
    };
    match prepare(image, out_dir) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cloudimage: {error}");
            ExitCode::FAILURE
        }
    }
}

fn prepare(image: &Path, out_dir: &Path) -> Result<(), Error> {
    std::fs::create_dir_all(out_dir)?;

    // This run's SSH identity. The private key stays here; the public key
    // goes into the seed.
    let identity = ssh::Identity::generate()?;

    // The world's CA root, minted the same way the running world will.
    let ca_pem = zscaler_root_pem()?;

    // The cloud-init seed.
    let seed_bytes = seed::build(&seed::Provision {
        hostname: HOSTNAME,
        user: USER,
        authorized_key: &identity.authorized_key,
        ca_pem: &ca_pem,
        wait_online: true,
    })?;
    let seed_path = out_dir.join("seed.img");
    std::fs::write(&seed_path, &seed_bytes)?;

    // The per-run overlay over the untouched download.
    let overlay = out_dir.join("overlay.qcow2");
    disk::write_overlay(&overlay, &std::fs::canonicalize(image)?, DISK_SIZE)?;

    println!("prepared the per-run boot inputs:");
    println!(
        "  overlay: {}  (qcow2 over {})",
        overlay.display(),
        image.display()
    );
    println!("  seed:    {}  (cloud-init cidata)", seed_path.display());
    println!("  ssh key: {}", identity.authorized_key.trim_end());
    println!(
        "\nboot with any hypervisor: the image's own kernel and initrd, the overlay as\n\
         the root disk, the seed as a second disk, cmdline\n\
         `root=LABEL=cloudimg-rootfs ro console=ttyS0,115200n8`, and the guest reached\n\
         over vsock port 22. The network backend that joins the guest to the world is\n\
         the hypervisor's; see demos/README.md."
    );
    Ok(())
}

/// Mints the look-alike Zscaler CA and returns its root in PEM, exactly as
/// the running world will, so the seed installs the same trust anchor.
fn zscaler_root_pem() -> Result<String, Error> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let out = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let sink = out.clone();
    fictionet::block_on(fictionet::lab(
        fictionet::Seed::random(),
        move |fcx| async move {
            let z = zscaler(&fcx, DEFAULT_CLOUD, now)?;
            *sink.lock().unwrap() = z.root_pem().to_string();
            Ok(())
        },
    ))
    .map_err(|e| e.to_string())?;
    Ok(std::mem::take(&mut *out.lock().unwrap()))
}
