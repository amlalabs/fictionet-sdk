//! `cargo xtask cloudimage`: downloads the pinned files for booting Ubuntu
//! 24.04's official cloud image unmodified.
//!
//! Everything downloads into `demos/downloads/cloudimage` (git ignores it),
//! each file pinned by the sha256 Canonical signs in its `SHA256SUMS`: the
//! image, its matching kernel and initrd. The image is never modified; the
//! kernel and initrd boot it directly, so nothing is extracted or rebuilt.
//! A Cloud Hypervisor static binary is also pinned; it booted the image
//! unmodified in a probe, and the pin is kept for whichever hypervisor the
//! single-process demo settles on.
//!
//! Turning a download into a per-run overlay and cloud-init seed is the
//! `cloudimage` demo binary; booting it is the hypervisor's job.

use std::path::Path;

use crate::process::{Result, capture, cmd, run as execute};
use crate::vm::{download, private_dir};

/// A Cloud Hypervisor static x86-64 release binary (used in the boot probe;
/// kept pinned pending the single-process hypervisor choice).
const CH_URL: &str = "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v54.0/cloud-hypervisor-static";
const CH_SHA256: &str = "4f4f98a3d661a40f3e5272627cc895a1b2e525f2f6bedf5f895f9cd21ba5c65b";

/// The cloud image release serial every Ubuntu file is taken from.
const BASE: &str = "https://cloud-images.ubuntu.com/releases/noble/release-20261017";
const IMAGE: &str = "ubuntu-24.04-server-cloudimg-amd64.img";
const IMAGE_SHA256: &str = "04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94";
const VMLINUZ: &str = "ubuntu-24.04-server-cloudimg-amd64-vmlinuz-generic";
const VMLINUZ_SHA256: &str = "41ba36d860aa0b0cd995f4ca8856d80249b244577e704929b55be13fbd1ebd2f";
const INITRD: &str = "ubuntu-24.04-server-cloudimg-amd64-initrd-generic";
const INITRD_SHA256: &str = "bf276ffc12872256080890698b42db0dc9c5a469c896d8b59af6bc4e723cd186";

pub fn run(args: &[String]) -> Result {
    match args {
        [] => {
            assets()?;
            build()?;
            demo()
        }
        [step] if step == "assets" => assets(),
        _ => Err("usage: cargo xtask cloudimage [assets]".into()),
    }
}

/// The downloaded files the demo boots from.
/// Downloads every pinned file into the gitignored downloads folder,
/// verified by sha256.
fn assets() -> Result {
    let dir = crate::root().join("demos/downloads/cloudimage");
    private_dir(&dir)?;
    let cloud_hypervisor = dir.join("cloud-hypervisor");
    download(CH_URL, &cloud_hypervisor, "sha256sum", CH_SHA256)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&cloud_hypervisor)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&cloud_hypervisor, perms)?;
    }
    download(
        &format!("{BASE}/{IMAGE}"),
        &dir.join(IMAGE),
        "sha256sum",
        IMAGE_SHA256,
    )?;
    download(
        &format!("{BASE}/unpacked/{VMLINUZ}"),
        &dir.join(VMLINUZ),
        "sha256sum",
        VMLINUZ_SHA256,
    )?;
    download(
        &format!("{BASE}/unpacked/{INITRD}"),
        &dir.join(INITRD),
        "sha256sum",
        INITRD_SHA256,
    )?;
    println!("downloaded into {}", dir.display());
    Ok(())
}

fn build() -> Result {
    execute(&mut cmd(
        "cargo",
        &[
            "build",
            "--locked",
            "--release",
            "-p",
            "fictionet-demo",
            "--bin",
            "cloudimage",
        ],
    ))
}

/// Runs the demo with the downloaded paths, inheriting its output.
fn demo() -> Result {
    let dir = crate::root().join("demos/downloads/cloudimage");
    let metadata: serde_json::Value = serde_json::from_str(&capture(&mut cmd(
        "cargo",
        &["metadata", "--locked", "--no-deps", "--format-version", "1"],
    ))?)?;
    let target = metadata["target_directory"]
        .as_str()
        .ok_or("cargo metadata gave no target directory")?;
    let binary = Path::new(target).join("release/cloudimage");
    execute(
        std::process::Command::new(&binary)
            .arg(dir.join("cloud-hypervisor"))
            .arg(dir.join(IMAGE))
            .arg(dir.join(VMLINUZ))
            .arg(dir.join(INITRD)),
    )
}
