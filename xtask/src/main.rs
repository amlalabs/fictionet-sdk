//! Host tooling for reproducible demo images.

use fictionet_demo::kit::{RunDir, image};
use std::{
    io,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt, process::Command};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() -> Result {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("search-image") {
        return Err("usage: cargo xtask search-image <downloads>".into());
    }
    let downloads = PathBuf::from(args.next().ok_or("missing downloads directory")?);
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    build(&downloads).await
}

async fn checked(command: &mut Command) -> Result {
    let status = command.status().await?;
    if !status.success() {
        return Err(format!("command failed: {status}").into());
    }
    Ok(())
}

async fn download(root: &Path, name: &str, url: &str) -> Result {
    if root.join(name).is_file() {
        return Ok(());
    }
    let part = root.join(format!("{name}.part"));
    checked(
        Command::new("curl")
            .args(["--fail", "--location", "--retry", "3", "--output"])
            .arg(&part)
            .arg(url),
    )
    .await?;
    std::fs::rename(part, root.join(name))?;
    Ok(())
}

async fn verify(path: &Path, checksum: &str) -> Result {
    let output = Command::new("sha256sum").arg(path).output().await?;
    if !output.status.success()
        || String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .next()
            != Some(checksum)
    {
        return Err(format!("checksum mismatch: {}", path.display()).into());
    }
    Ok(())
}

async fn build(downloads: &Path) -> Result {
    let start = Instant::now();
    std::fs::create_dir_all(downloads)?;
    let root = std::fs::canonicalize(downloads)?;
    let ubuntu = "ubuntu-24.04-server-cloudimg-amd64";
    for (suffix, checksum) in [
        (
            ".img",
            "04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94",
        ),
        (
            "-vmlinuz-generic",
            "41ba36d860aa0b0cd995f4ca8856d80249b244577e704929b55be13fbd1ebd2f",
        ),
        (
            "-initrd-generic",
            "bf276ffc12872256080890698b42db0dc9c5a469c896d8b59af6bc4e723cd186",
        ),
    ] {
        let name = format!("{ubuntu}{suffix}");
        let source = format!("noble-server-cloudimg-amd64{suffix}");
        let remote = if suffix == ".img" {
            source
        } else {
            format!("unpacked/{source}")
        };
        download(
            &root,
            &name,
            &format!("https://cloud-images.ubuntu.com/noble/20261017/{remote}"),
        )
        .await?;
        verify(&root.join(name), checksum).await?;
    }
    download(&root, "cloud-hypervisor", "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v54.0/cloud-hypervisor-static").await?;
    verify(
        &root.join("cloud-hypervisor"),
        "4f4f98a3d661a40f3e5272627cc895a1b2e525f2f6bedf5f895f9cd21ba5c65b",
    )
    .await?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        root.join("cloud-hypervisor"),
        std::fs::Permissions::from_mode(0o755),
    )?;
    let dir = RunDir::new(&root, "image-build")?;
    let disk = dir.path().join("workstation.qcow2");
    checked(
        Command::new("qemu-img")
            .args(["convert", "-O", "qcow2"])
            .arg(root.join(format!("{ubuntu}.img")))
            .arg(&disk),
    )
    .await?;
    checked(Command::new("qemu-img").arg("resize").arg(&disk).arg("10G")).await?;
    let mut script = image::installation()?;
    script.push_str("systemctl disable image-build.service\nrm -f /root/build.sh /etc/systemd/system/image-build.service\necho IMAGE_READY >/dev/ttyS0\nsystemctl poweroff\n");
    let seed = dir.path().join("build.img");
    std::fs::write(&seed, image::disk("build", "build.sh", &script)?)?;
    let log_path = root.join("search-image-build.log");
    let log = std::fs::File::create(&log_path)?;
    let mut child = Command::new("qemu-system-x86_64")
        .args([
            "-enable-kvm",
            "-cpu",
            "host",
            "-smp",
            "4",
            "-m",
            "4096",
            "-display",
            "none",
            "-no-reboot",
            "-monitor",
            "none",
            "-serial",
            "stdio",
        ])
        .arg("-kernel")
        .arg(root.join(format!("{ubuntu}-vmlinuz-generic")))
        .arg("-initrd")
        .arg(root.join(format!("{ubuntu}-initrd-generic")))
        .args([
            "-append",
            "root=LABEL=cloudimg-rootfs rw console=ttyS0 net.ifnames=0 init=/bin/bash",
        ])
        .arg("-drive")
        .arg(format!("file={},if=virtio,format=qcow2", disk.display()))
        .arg("-drive")
        .arg(format!(
            "file={},if=virtio,format=raw,readonly=on",
            seed.display()
        ))
        .args([
            "-netdev",
            "user,id=net",
            "-device",
            "virtio-net-pci,netdev=net",
        ])
        .stdin(Stdio::piped())
        .stdout(log.try_clone()?)
        .stderr(log)
        .kill_on_drop(true)
        .spawn()?;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if std::fs::read_to_string(&log_path)?.contains("root@(none):/#") {
                break Ok::<(), io::Error>(());
            }
            if child.try_wait()?.is_some() {
                return Err(io::Error::other("image VM exited before its setup shell"));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    let bootstrap = "mount -t proc proc /proc; mount -t sysfs sysfs /sys; mkdir -p /mnt/build; mount /dev/vdb /mnt/build; touch /etc/cloud/cloud-init.disabled; mkdir -p /etc/systemd/network; printf '[Match]\\nName=eth0\\n[Network]\\nDHCP=ipv4\\n' > /etc/systemd/network/05-eth0.network; cp /mnt/build/build.sh /root/build.sh; umount /mnt/build; printf '[Unit]\\nAfter=network-online.target\\nWants=network-online.target\\n[Service]\\nType=oneshot\\nStandardOutput=journal+console\\nStandardError=journal+console\\nExecStart=/bin/bash -c \"/bin/bash /root/build.sh || { echo IMAGE_FAILED >/dev/ttyS0; systemctl poweroff; }\"\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/image-build.service; mkdir -p /etc/systemd/system/multi-user.target.wants; ln -s /etc/systemd/system/image-build.service /etc/systemd/system/multi-user.target.wants/image-build.service; exec /sbin/init\n";
    child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("missing VM input"))?
        .write_all(bootstrap.as_bytes())
        .await?;
    println!("Building workstation; progress: {}", log_path.display());
    let waited = tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(1800), child.wait()) => result.map_err(io::Error::other),
        result = tokio::signal::ctrl_c() => {
            result?;
            Err(io::Error::new(io::ErrorKind::Interrupted, "image construction interrupted"))
        }
    };
    let status = match waited {
        Ok(status) => status?,
        Err(error) => {
            child.kill().await?;
            child.wait().await?;
            return Err(error.into());
        }
    };
    let log = std::fs::read_to_string(&log_path)?;
    if !status.success() || !log.lines().any(|line| line.trim() == "IMAGE_READY") {
        return Err(format!("image construction failed; see {}", log_path.display()).into());
    }
    let output = root.join(image::WORKSTATION);
    let compact = dir.path().join("compact.qcow2");
    checked(
        Command::new("qemu-img")
            .args(["convert", "-O", "qcow2"])
            .arg(&disk)
            .arg(&compact),
    )
    .await?;
    std::fs::rename(compact, &output)?;
    println!(
        "Image: {} ({} seconds)",
        output.display(),
        start.elapsed().as_secs()
    );
    Ok(())
}
