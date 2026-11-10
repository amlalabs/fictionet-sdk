//! A Nitro Sandbox: stock Firecracker v1.18 under its jailer, as an
//! unprivileged user in a network namespace of its own, in direct mode. The
//! guest's one card is a TAP device in that namespace. The kit owns a second
//! TAP there, and the kernel redirects every frame between the two, so the
//! guest's frames reach only the world and never the parent's IP stack.
//!
//! The host needs, as root: `/dev/nitro_enclaves` with a reserved memory
//! pool, `ip` and `tc`, `qemu-img`, the user [`USER`], and the Firecracker
//! and jailer release binaries in the downloads folder.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::process::Command;

use super::{Ownership, Vm, own_child};

/// The Firecracker release binary, in the downloads folder.
pub const FIRECRACKER: &str = "firecracker-v1.18.0-x86_64";
/// Its jailer, in the downloads folder.
pub const JAILER: &str = "jailer-v1.18.0-x86_64";
/// The unprivileged user Firecracker runs as.
pub const USER: &str = "fictionet-vm";
const JAIL_BASE: &str = "/srv/jailer";
/// The guest's TAP device, which Firecracker opens.
const VM_TAP: &str = "tap0";
/// The kit's TAP device.
const OWN_TAP: &str = "tap0-fn";

/// How to boot one sandbox.
pub struct Config<'a> {
    pub downloads: &'a Path,
    /// The unmodified Ubuntu kernel; Firecracker builds the enclave image
    /// from it, the initrd and the command line.
    pub vmlinuz: &'a Path,
    pub initrd: &'a Path,
    pub cmdline: &'a str,
    /// The prepared qcow2 image. Its raw copy beside it is made once, and
    /// each run boots a copy of that.
    pub image: &'a Path,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub mac: &'a str,
}

/// The sandbox's namespace and jail, removed when dropped.
pub struct Sandbox {
    netns: String,
    jail: PathBuf,
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::process::Command::new("ip")
            .args(["netns", "del", &self.netns])
            .stderr(Stdio::null())
            .status();
        let _ = std::fs::remove_dir_all(&self.jail);
    }
}

/// Makes the namespace `fictionet-<id>` with the guest's TAP device, owned
/// by [`USER`], and the kit's own, with every frame redirected between
/// them. Returns the sandbox and the kit's device, which the kit reads and
/// writes frames on.
pub fn network(id: &str, mtu: u16) -> io::Result<(Sandbox, OwnedFd)> {
    let (uid, gid) = user()?;
    let netns = format!("fictionet-{id}");
    let sandbox = Sandbox {
        jail: Path::new(JAIL_BASE).join(FIRECRACKER).join(id),
        netns: netns.clone(),
    };
    // A namespace or jail left by an earlier run that did not stop goes first.
    let _ = std::process::Command::new("ip")
        .args(["netns", "del", &netns])
        .stderr(Stdio::null())
        .status();
    let _ = std::fs::remove_dir_all(&sandbox.jail);
    ip(&["netns", "add", &netns])?;
    ip(&[
        "-n",
        &netns,
        "tuntap",
        "add",
        "dev",
        VM_TAP,
        "mode",
        "tap",
        "user",
        &uid.to_string(),
        "group",
        &gid.to_string(),
    ])?;
    // The guest's device stays down until both redirects are in place, so
    // the kernel refuses whatever Firecracker writes before then.
    ip(&["-n", &netns, "link", "set", VM_TAP, "down"])?;
    let own = open_tap_in(&netns)?;
    let mtu = mtu.to_string();
    ip(&["-n", &netns, "link", "set", OWN_TAP, "mtu", &mtu, "up"])?;
    for (from, to) in [(VM_TAP, OWN_TAP), (OWN_TAP, VM_TAP)] {
        tc(&["-n", &netns, "qdisc", "add", "dev", from, "ingress"])?;
        // A basic filter with no match takes every frame; Amazon Linux's
        // kernel has no matchall.
        tc(&[
            "-n", &netns, "filter", "add", "dev", from, "parent", "ffff:", "protocol", "all",
            "basic", "action", "mirred", "egress", "redirect", "dev", to,
        ])?;
    }
    ip(&["-n", &netns, "link", "set", VM_TAP, "mtu", &mtu, "up"])?;
    Ok((sandbox, own))
}

/// Boots the sandbox in `sandbox`'s jail. The guest's console goes to
/// `dir/console.log`.
pub fn start(
    config: &Config,
    sandbox: Sandbox,
    dir: &Path,
    ownership: &Ownership,
) -> io::Result<Vm> {
    let (uid, gid) = user()?;
    let root = sandbox.jail.join("root");
    std::fs::create_dir_all(&root)?;
    std::fs::copy(config.vmlinuz, root.join("vmlinuz"))?;
    std::fs::copy(config.initrd, root.join("initrd"))?;
    copy(&raw_image(config.image)?, &root.join("disk.raw"))?;
    std::fs::write(root.join("firecracker.log"), "")?;
    let sandbox_config = serde_json::json!({
        "boot-source": {
            "kernel_image_path": "/vmlinuz",
            "initrd_path": "/initrd",
            "boot_args": config.cmdline,
        },
        // Not the root device: Firecracker would add root=/dev/vda, and
        // the command line names the root by its label.
        "drives": [{"drive_id": "disk", "path_on_host": "/disk.raw",
            "is_root_device": false, "is_read_only": false}],
        "network-interfaces": [{"iface_id": "eth0", "host_dev_name": VM_TAP,
            "guest_mac": config.mac}],
        "machine-config": {"vcpu_count": config.vcpus, "mem_size_mib": config.memory_mib},
        // Direct mode boots the stock kernel's virtio drivers; the parent
        // runs both sides. The guest's vCPUs share the parent's cores, so a
        // guest larger than the Nitro CPU pool fits. Debug mode gives the
        // console on Firecracker's output.
        "enclave": {"direct_mode": true, "debug_mode": true, "cpu_overcommit": true},
    });
    std::fs::write(root.join("sandbox.json"), sandbox_config.to_string())?;
    for file in [
        "",
        "vmlinuz",
        "initrd",
        "disk.raw",
        "firecracker.log",
        "sandbox.json",
    ] {
        std::os::unix::fs::chown(root.join(file), Some(uid), Some(gid))?;
    }
    let console_log = dir.join("console.log");
    let stderr_log = dir.join("jailer.stderr.log");
    let id = sandbox
        .jail
        .file_name()
        .and_then(|id| id.to_str())
        .expect("the jail is named by its id")
        .to_owned();
    let mut command = Command::new(config.downloads.join(JAILER));
    command
        .arg("--id")
        .arg(&id)
        .arg("--exec-file")
        .arg(config.downloads.join(FIRECRACKER))
        .args(["--uid", &uid.to_string(), "--gid", &gid.to_string()])
        .args(["--chroot-base-dir", JAIL_BASE])
        .arg("--netns")
        .arg(format!("/var/run/netns/{}", sandbox.netns))
        .args(["--cgroup-version", "2", "--"])
        .args([
            "--no-api",
            "--config-file",
            "/sandbox.json",
            "--log-path",
            "/firecracker.log",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(std::fs::File::create(&console_log)?))
        .stderr(Stdio::from(std::fs::File::create(&stderr_log)?))
        .kill_on_drop(true);
    own_child(&mut command);
    ownership.inherit(&mut command);
    let child = command.spawn()?;
    Ok(Vm {
        child,
        _socket_dir: std::fs::File::open(dir)?,
        console_log,
        stderr_log,
        _ch_memfd: None,
        sandbox: Some(sandbox),
    })
}

/// The uid and gid of [`USER`].
fn user() -> io::Result<(u32, u32)> {
    let name = std::ffi::CString::new(USER).expect("no NUL");
    // SAFETY: getpwnam reads a valid C string; its result is read at once,
    // before any other call could reuse the static buffer.
    let entry = unsafe { libc::getpwnam(name.as_ptr()) };
    if entry.is_null() {
        return Err(io::Error::other(format!(
            "no user {USER}; make it with useradd -r -M -s /sbin/nologin {USER}"
        )));
    }
    // SAFETY: checked non-null above.
    let entry = unsafe { &*entry };
    Ok((entry.pw_uid, entry.pw_gid))
}

/// The raw copy beside the qcow2 `image`, made when missing or older than it.
fn raw_image(image: &Path) -> io::Result<PathBuf> {
    let raw = image.with_extension("raw");
    let current = match (raw.metadata(), image.metadata()) {
        (Ok(raw), Ok(image)) => raw.modified()? >= image.modified()?,
        _ => false,
    };
    if !current {
        let partial = image.with_extension("raw.partial");
        run(std::process::Command::new("qemu-img")
            .args(["convert", "-f", "qcow2", "-O", "raw"])
            .arg(image)
            .arg(&partial))?;
        std::fs::rename(&partial, &raw)?;
    }
    Ok(raw)
}

/// Copies a disk, sharing its blocks where the filesystem can.
fn copy(from: &Path, to: &Path) -> io::Result<()> {
    run(std::process::Command::new("cp")
        .args(["--reflink=auto", "--sparse=always"])
        .arg(from)
        .arg(to))
}

fn ip(args: &[&str]) -> io::Result<()> {
    run(std::process::Command::new("ip").args(args))
}

fn tc(args: &[&str]) -> io::Result<()> {
    run(std::process::Command::new("tc").args(args))
}

fn run(command: &mut std::process::Command) -> io::Result<()> {
    let output = command.stdin(Stdio::null()).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{command:?} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// Makes the kit's TAP device inside `netns`, with no offloads, so the
/// kernel finishes checksums and splits large frames before the kit reads
/// them. Closing the fd removes the device.
fn open_tap_in(netns: &str) -> io::Result<OwnedFd> {
    let path = format!("/var/run/netns/{netns}");
    // A thread of its own enters the namespace, so no other thread moves.
    std::thread::spawn(move || {
        let ns = std::fs::File::open(&path)?;
        // SAFETY: setns on an open namespace file affects only this thread.
        if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh open of a constant path.
        let raw = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: open succeeded; the descriptor is owned from here.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut ifr = [0u8; 40];
        ifr[..OWN_TAP.len()].copy_from_slice(OWN_TAP.as_bytes());
        let flags: libc::c_short = 0x0002 /* IFF_TAP */ | 0x1000 /* IFF_NO_PI */;
        ifr[16..18].copy_from_slice(&flags.to_ne_bytes());
        // SAFETY: TUNSETIFF reads and writes the 40-byte ifreq above.
        if unsafe { libc::ioctl(fd.as_raw_fd(), 0x400454ca, ifr.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // The namespace's own stack sends nothing on either device.
        for device in [VM_TAP, OWN_TAP] {
            std::fs::write(
                format!("/proc/sys/net/ipv6/conf/{device}/disable_ipv6"),
                "1",
            )?;
        }
        Ok(fd)
    })
    .join()
    .map_err(|_| io::Error::other("the namespace thread panicked"))?
}
