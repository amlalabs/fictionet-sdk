//! Downloads, builds, and launches the in-process demos.

use std::path::Path;

use crate::process::{Result, capture, cmd, run as execute};
use crate::vm::{download, private_dir};

/// Cloud Hypervisor's static x86-64 release binary, which the demo embeds.
const CH_URL: &str = "https://github.com/cloud-hypervisor/cloud-hypervisor/\
    releases/download/v54.0/cloud-hypervisor-static";
const CH_SHA256: &str = "4f4f98a3d661a40f3e5272627cc895a1b2e525f2f6bedf5f895f9cd21ba5c65b";

/// The cloud image release serial every Ubuntu file is taken from.
const BASE: &str = "https://cloud-images.ubuntu.com/releases/noble/release-20261017";
const IMAGE: &str = "ubuntu-24.04-server-cloudimg-amd64.img";
const IMAGE_SHA256: &str = "04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94";
const VMLINUZ: &str = "ubuntu-24.04-server-cloudimg-amd64-vmlinuz-generic";
const VMLINUZ_SHA256: &str = "41ba36d860aa0b0cd995f4ca8856d80249b244577e704929b55be13fbd1ebd2f";
const INITRD: &str = "ubuntu-24.04-server-cloudimg-amd64-initrd-generic";
const INITRD_SHA256: &str = "bf276ffc12872256080890698b42db0dc9c5a469c896d8b59af6bc4e723cd186";

/// The downloaded files the demo boots from.
/// Downloads every pinned file into the gitignored downloads folder,
/// verified by sha256.
pub fn assets() -> Result {
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
    super::libraries::assets()?;
    println!("downloaded into {}", dir.display());
    Ok(())
}

pub fn build(name: &str) -> Result {
    execute(&mut cmd(
        "cargo",
        &[
            "build",
            "--locked",
            "--release",
            "-p",
            "fictionet-demo",
            "--bin",
            name,
        ],
    ))
}

/// Runs the demo, inheriting its output. With `downloads`, the downloads
/// folder comes before `args`.
pub fn launch(name: &str, downloads: bool, args: &[String]) -> Result {
    let dir = crate::root().join("demos/downloads/cloudimage");
    let metadata: serde_json::Value = serde_json::from_str(&capture(&mut cmd(
        "cargo",
        &["metadata", "--locked", "--no-deps", "--format-version", "1"],
    ))?)?;
    let target = metadata["target_directory"]
        .as_str()
        .ok_or("cargo metadata gave no target directory")?;
    let binary = Path::new(target).join("release").join(name);
    let mut command = std::process::Command::new(&binary);
    if downloads {
        command.arg(dir);
    }
    execute(command.args(args))
}
