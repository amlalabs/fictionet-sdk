//! Construct and boot-check an image before publishing it.
use crate::{Result, workstation};
use fictionet_demo::kit::{RunDir, image, ssh, vm};
use fictionet_extras::zscaler::Roots;
use std::{
    io::{self, Read},
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncWriteExt,
    process::{Child, Command},
};

#[derive(Debug, PartialEq, Eq)]
enum Completion {
    Installed,
    Verified { packages: String },
}

async fn checked(command: &mut Command) -> Result {
    let status = command.status().await?;
    if !status.success() {
        return Err(format!("command failed: {status}").into());
    }
    Ok(())
}

async fn download(root: &Path, staging: &Path, name: &str, url: &str, checksum: &str) -> Result {
    if root.join(name).is_file() {
        return verify(&root.join(name), checksum).await;
    }
    let part = staging.join(name);
    checked(
        Command::new("curl")
            .args([
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--retry",
                "3",
                "--output",
            ])
            .arg(&part)
            .arg(url),
    )
    .await?;
    verify(&part, checksum).await?;
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

pub async fn build(downloads: &Path) -> Result {
    let start = Instant::now();
    std::fs::create_dir_all(downloads)?;
    let root = std::fs::canonicalize(downloads)?;
    let dir = RunDir::new(&root, "image-build")?;
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
            dir.path(),
            &name,
            &format!("https://cloud-images.ubuntu.com/noble/20261017/{remote}"),
            checksum,
        )
        .await?;
    }
    download(&root, dir.path(), "cloud-hypervisor", "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v54.0/cloud-hypervisor-static",
        "4f4f98a3d661a40f3e5272627cc895a1b2e525f2f6bedf5f895f9cd21ba5c65b").await?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        root.join("cloud-hypervisor"),
        std::fs::Permissions::from_mode(0o755),
    )?;
    let disk = dir.path().join("workstation.qcow2");
    checked(
        Command::new("qemu-img")
            .args(["convert", "-O", "qcow2"])
            .arg(root.join(format!("{ubuntu}.img")))
            .arg(&disk),
    )
    .await?;
    checked(Command::new("qemu-img").arg("resize").arg(&disk).arg("10G")).await?;
    // The keys, the trust root and the credential placeholder are made once
    // here, baked into the image, and kept beside it for the host.
    let admin = ssh::Identity::generate()?;
    let placeholder = fictionet_extras::models::Credential::claude_token_placeholder()?;
    let (send, receive) = tokio::sync::oneshot::channel();
    fictionet::run(fictionet::Seed::random(), |cx| async move {
        let _ = send.send(Roots::generate(
            &cx,
            fictionet_extras::zscaler::DEFAULT_CLOUD,
        )?);
        Ok(())
    })
    .await?;
    let roots = receive.await?;
    let mut script = image::installation(&workstation::recipe(
        &admin,
        roots.root_pem(),
        &placeholder,
    )?);
    script.push_str("systemctl disable image-build.service\nrm -f /root/build.sh /etc/systemd/system/image-build.service\nmkdir -p /mnt/build\nmount /dev/vdb /mnt/build\nprintf installed > /mnt/build/result\nsync\numount /mnt/build\nsystemctl poweroff\n");
    let seed = dir.path().join("build.img");
    std::fs::write(&seed, image::disk("build", "build.sh", &script)?)?;
    let log_path = dir.path().join("build.log");
    let mut child = launch(
        &root,
        &disk,
        &seed,
        &log_path,
        "root=LABEL=cloudimg-rootfs rw console=ttyS0 net.ifnames=0 init=/bin/bash",
        "user,id=net",
    )?;
    let bootstrap = "mount -t proc proc /proc; mount -t sysfs sysfs /sys; mkdir -p /mnt/build; mount /dev/vdb /mnt/build; touch /etc/cloud/cloud-init.disabled; mkdir -p /etc/systemd/network; printf '[Match]\\nName=eth0\\n[Network]\\nDHCP=ipv4\\n' > /etc/systemd/network/05-eth0.network; cp /mnt/build/build.sh /root/build.sh; umount /mnt/build; printf '[Unit]\\nAfter=network-online.target\\nWants=network-online.target\\n[Service]\\nType=oneshot\\nStandardOutput=journal+console\\nStandardError=journal+console\\nExecStart=/bin/bash -c \"/bin/bash /root/build.sh || { echo installation failed >/dev/ttyS0; systemctl poweroff; }\"\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/image-build.service; mkdir -p /etc/systemd/system/multi-user.target.wants; ln -s /etc/systemd/system/image-build.service /etc/systemd/system/multi-user.target.wants/image-build.service; exec /sbin/init\n";
    bootstrap_shell(&mut child, &log_path, bootstrap).await?;
    println!("Building workstation; progress: {}", log_path.display());
    let built = finish(&mut child, Duration::from_secs(1800), &seed).await;
    publish_log(&log_path, &root, dir.path(), "search-image-build.log")?;
    let installed = built.map_err(|error| {
        format!(
            "{error}; see {}",
            root.join("search-image-build.log").display()
        )
    })?;
    if installed != Completion::Installed {
        return Err("image installation did not complete".into());
    }
    let check = dir.path().join("check.img");
    std::fs::write(&check, image::disk("check", "check.sh", &verification())?)?;
    let verification_disk = dir.path().join("verify.qcow2");
    checked(
        Command::new("qemu-img")
            .args(["create", "-f", "qcow2", "-F", "qcow2", "-b"])
            .arg(&disk)
            .arg(&verification_disk),
    )
    .await?;
    let check_log = dir.path().join("verify.log");
    let mut child = launch(
        &root,
        &verification_disk,
        &check,
        &check_log,
        "root=LABEL=cloudimg-rootfs rw console=ttyS0 net.ifnames=0 init=/bin/bash",
        "user,id=net,restrict=on",
    )?;
    // The check runs once the desktop is allowed to start. Its network has
    // no time server, so the desktop does not wait for network time.
    let bootstrap = "mount -t proc proc /proc; mount -t sysfs sysfs /sys; mkdir -p /mnt/check; mount /dev/vdb /mnt/check; cp /mnt/check/check.sh /root/image-check.sh; umount /mnt/check; printf '[Unit]\\nAfter=vnc.service\\n[Service]\\nType=oneshot\\nStandardOutput=journal+console\\nStandardError=journal+console\\nExecStart=/bin/bash /root/image-check.sh\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/systemd/system/image-check.service; mkdir -p /etc/systemd/system/multi-user.target.wants; ln -s /etc/systemd/system/image-check.service /etc/systemd/system/multi-user.target.wants/image-check.service; ln -sf /dev/null /etc/systemd/system/systemd-time-wait-sync.service; exec /sbin/init\n";
    bootstrap_shell(&mut child, &check_log, bootstrap).await?;
    println!("Checking desktop; progress: {}", check_log.display());
    let verified = finish(&mut child, Duration::from_secs(180), &check).await;
    publish_log(&check_log, &root, dir.path(), "search-image-verify.log")?;
    let verified = verified.map_err(|error| {
        format!(
            "{error}; see {}",
            root.join("search-image-verify.log").display()
        )
    })?;
    let Completion::Verified { packages } = verified else {
        return Err("desktop verification did not complete".into());
    };
    println!("Installed package set: {packages}");
    let baked = image::Baked::new(&root, workstation::IMAGE);
    let output = baked.image().to_owned();
    let compact = dir.path().join("compact.qcow2");
    checked(
        Command::new("qemu-img")
            .args(["convert", "-O", "qcow2"])
            .arg(&disk)
            .arg(&compact),
    )
    .await?;
    checked(Command::new("qemu-img").arg("check").arg(&compact)).await?;
    admin.write(&baked.admin_key())?;
    image::write_private(&baked.trust_root(), &roots.to_pem())?;
    image::write_private(&baked.placeholder(), &placeholder)?;
    std::fs::rename(compact, &output)?;
    println!(
        "Image: {} ({} seconds)",
        output.display(),
        start.elapsed().as_secs()
    );
    Ok(())
}

fn launch(
    root: &Path,
    disk: &Path,
    seed: &Path,
    log_path: &Path,
    append: &str,
    network: &str,
) -> Result<Child> {
    let ubuntu = "ubuntu-24.04-server-cloudimg-amd64";
    let log = std::fs::File::create(log_path)?;
    let mut command = Command::new("qemu-system-x86_64");
    vm::own_child(&mut command);
    let child = command
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
        .args(["-append", append])
        .arg("-drive")
        .arg(format!("file={},if=virtio,format=qcow2", disk.display()))
        .arg("-drive")
        .arg(format!("file={},if=virtio,format=raw", seed.display()))
        .args(["-netdev", network, "-device", "virtio-net-pci,netdev=net"])
        .stdin(Stdio::piped())
        .stdout(log.try_clone()?)
        .stderr(log)
        .kill_on_drop(true)
        .spawn()?;
    Ok(child)
}

/// Waits for the shell that `init=/bin/bash` opens on the serial console,
/// then types `bootstrap` into it.
async fn bootstrap_shell(child: &mut Child, log_path: &Path, bootstrap: &str) -> Result {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if std::fs::read_to_string(log_path)?.contains("root@(none):/#") {
                break Ok::<(), io::Error>(());
            }
            if child.try_wait()?.is_some() {
                return Err(io::Error::other("image VM exited before its setup shell"));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("missing VM input"))?
        .write_all(bootstrap.as_bytes())
        .await?;
    Ok(())
}

fn publish_log(source: &Path, root: &Path, staging: &Path, name: &str) -> io::Result<()> {
    let temporary = staging.join(name);
    std::fs::copy(source, &temporary)?;
    std::fs::rename(temporary, root.join(name))
}

fn result(seed: &Path) -> Result<Completion> {
    let disk = std::fs::File::open(seed)?;
    let fs = fatfs::FileSystem::new(disk, fatfs::FsOptions::new())?;
    let mut result = String::new();
    fs.root_dir()
        .open_file("result")?
        .read_to_string(&mut result)?;
    match result.lines().collect::<Vec<_>>().as_slice() {
        ["installed"] => Ok(Completion::Installed),
        ["verified", packages]
            if packages.len() == 64 && packages.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            Ok(Completion::Verified {
                packages: (*packages).into(),
            })
        }
        _ => Err("image VM did not complete its task".into()),
    }
}

async fn finish(child: &mut Child, timeout: Duration, seed: &Path) -> Result<Completion> {
    let waited = tokio::select! {
        result = tokio::time::timeout(timeout, child.wait()) => result.map_err(io::Error::other),
        signal = tokio::signal::ctrl_c() => {
            signal?;
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
    if !status.success() {
        return Err(format!("image VM failed: {status}").into());
    }
    result(seed)
}

/// The desktop, the user's terminal session, the admin account and the
/// trust root are in place, and the tools run.
fn verification() -> String {
    let ready = fictionet_demo::kit::desktop::BROWSER_READY;
    format!(
        r#"set -euo pipefail
trap 'systemctl poweroff' EXIT
timeout 90 bash -c 'until runuser -u analyst -- sh -c "{ready}"; do sleep 0.2; done'
runuser -u analyst -- tmux has-session -t main
[ "$(runuser -u analyst -- tmux show-options -gv status)" = off ]
[ "$(runuser -u analyst -- tmux show-options -gv mouse)" = on ]
[ "$(runuser -u analyst -- tmux show-environment -g DISPLAY)" = DISPLAY=:1 ]
[ -f /home/analyst/.hushlogin ]
[ -s /home/ops/.ssh/authorized_keys ]
[ -f /etc/ssl/certs/office.pem ]
[ "$(cat /etc/hostname)" = workstation ]
python3 -m venv /var/tmp/check-venv
/var/tmp/check-venv/bin/python -c 'import ssl; import pip'
rm -rf /var/tmp/check-venv
claude --version
firefox --version
python3 --version
packages=$(dpkg-query -W -f='${{binary:Package}} ${{Version}}\n' | LC_ALL=C sort | sha256sum | cut -d ' ' -f1)
mkdir -p /mnt/check
mount /dev/vdb /mnt/check
printf 'verified\n%s\n' "$packages" > /mnt/check/result
sync
umount /mnt/check
"#
    )
}
