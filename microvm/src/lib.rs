//! A microVM run by a re-executed child of this program.
//!
//! `msb_krun` boots the guest, and its `Vm::enter` never returns: when the
//! guest stops, the VMM exits the whole process. So the program runs each
//! VM in a child: it starts itself again with [`run_if_child`]'s argument,
//! hands the child only the descriptors it needs, and keeps the world, the
//! network and the guest control in the parent.
//!
//! ```text
//! parent                                   child (same executable)
//!   Vm::start ── socketpair: Ethernet ──── virtio-net, unixstream backend
//!             ── socketpair: console ───── virtio-console port "agent"
//!             ── pipe: liveness ─────────── exits when the parent is gone
//!   Agent ─────── agentd's protocol over the console
//! ```
//!
//! The guest is three assets, each zstd-compressed: the kernel, which the
//! child decompresses into memory of its own, microsandbox's
//! `agentd`, which starts as the guest's first process, and an ext4 root
//! filesystem, which the parent copies into private storage for each VM.
//! `agentd` mounts it as the root, pivots into it, and then runs commands
//! for the parent.
//!
//! Nothing else of the host reaches the guest: TSI is off, and the two
//! virtio-fs shares are private directories this crate makes, one holding
//! only `agentd` and the other only the files the guest is given. The guest
//! can still write to both, with no limit on how much.

mod child;
mod guest;
mod image;

pub use child::run_if_child;
pub use guest::{Agent, Output};

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

/// The guest, as `cargo xtask microvm` writes it: each asset
/// zstd-compressed.
#[derive(Clone, Copy)]
pub struct Assets {
    /// The kernel: its guest load address and entry point, each a
    /// little-endian u64, then the flat image.
    pub kernel: &'static [u8],
    /// microsandbox's guest agent, a static Linux executable.
    pub agent: &'static [u8],
    /// The root filesystem, an ext4 image.
    pub rootfs: &'static [u8],
}

/// How to run one VM.
pub struct Config {
    /// Virtual CPUs.
    pub vcpus: u8,
    /// Guest memory, in MiB.
    pub memory_mib: u32,
    /// A CA certificate, in PEM, that the agent adds to the guest's trust
    /// store before anything runs.
    pub ca_pem: Option<String>,
}

/// A running VM: its child process, its private storage, and the parent's
/// ends of its links.
pub struct Vm {
    child: tokio::process::Child,
    dir: PrivateDir,
    net: Option<OwnedFd>,
    console: Option<OwnedFd>,
    /// The write end of the pipe the child watches. Dropping it stops the
    /// child.
    alive: Option<OwnedFd>,
}

/// The descriptors the child finds its links at.
const CHILD_NET: RawFd = 3;
const CHILD_CONSOLE: RawFd = 4;
const CHILD_ALIVE: RawFd = 5;

impl Vm {
    /// Prepares the VM's storage and starts its child. The guest boots in
    /// the background; [`agent`](Vm::agent) waits for it.
    pub fn start(assets: &Assets, config: &Config) -> io::Result<Vm> {
        // The child would fail on the same open, with less to say.
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .map_err(|e| io::Error::new(e.kind(), format!("this needs KVM: /dev/kvm: {e}")))?;
        let dir = PrivateDir::new()?;
        let boot = dir.path().join("boot");
        // The mount points agentd expects in the root it starts from.
        for sub in ["dev", "proc", "sys", "newroot", ".msb"] {
            std::fs::create_dir_all(boot.join(sub))?;
        }
        image::extract(assets.agent, &boot.join("agentd"), 0o755)?;
        image::extract(assets.rootfs, &dir.path().join("rootfs.ext4"), 0o600)?;
        let runtime = dir.path().join("runtime");
        std::fs::create_dir(&runtime)?;
        if let Some(pem) = &config.ca_pem {
            std::fs::create_dir(runtime.join("tls"))?;
            std::fs::write(runtime.join("tls/ca.pem"), pem)?;
        }

        let (net, net_child) = socketpair()?;
        let (console, console_child) = socketpair()?;
        let (alive_child, alive) = pipe()?;
        // The parent writes the bootstrap before the guest boots; the socket
        // holds it until agentd reads it.
        guest::send_bootstrap(&console)?;

        // Above every descriptor the child is given, so the moves into place
        // below cannot overwrite one another.
        let moved = [
            (dup_above(&net_child)?, CHILD_NET),
            (dup_above(&console_child)?, CHILD_CONSOLE),
            (dup_above(&alive_child)?, CHILD_ALIVE),
        ];
        let mut command = tokio::process::Command::new("/proc/self/exe");
        command
            .arg(child::ARG)
            .arg(dir.path())
            .arg(config.vcpus.to_string())
            .arg(config.memory_mib.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .kill_on_drop(true);
        let fds: Vec<(RawFd, RawFd)> = moved.iter().map(|(f, to)| (f.as_raw_fd(), *to)).collect();
        // SAFETY: the closure only calls dup2, which is async-signal-safe,
        // on descriptors that stay open until spawn returns.
        unsafe {
            command.pre_exec(move || {
                for &(from, to) in &fds {
                    if libc::dup2(from, to) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let child = command.spawn()?;
        Ok(Vm {
            child,
            dir,
            net: Some(net),
            console: Some(console),
            alive: Some(alive),
        })
    }

    /// The child's process ID.
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// The VM's private storage: its copy of the root filesystem, the
    /// directory agentd starts from, the files given to the guest, and the
    /// guest console's log.
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// The parent's end of the guest's network card: a Unix stream socket
    /// that carries Ethernet frames, each after a 32-bit big-endian length.
    pub fn take_net(&mut self) -> Option<OwnedFd> {
        self.net.take()
    }

    /// Waits for the guest agent to come up, and connects to it.
    pub async fn agent(&mut self, timeout: Duration) -> io::Result<Agent> {
        let console = self
            .console
            .take()
            .ok_or_else(|| io::Error::other("the agent is already connected"))?;
        enum Ended {
            Agent(io::Result<Agent>),
            TimedOut,
            Child(io::Result<ExitStatus>),
        }
        let ended = tokio::select! {
            agent = tokio::time::timeout(timeout, guest::connect(console)) => match agent {
                Ok(agent) => Ended::Agent(agent),
                Err(_) => Ended::TimedOut,
            },
            status = self.child.wait() => Ended::Child(status),
        };
        match ended {
            Ended::Agent(agent) => agent,
            Ended::TimedOut => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "the guest agent was not ready in {timeout:?}{}",
                    self.console_tail()
                ),
            )),
            Ended::Child(status) => Err(io::Error::other(format!(
                "the VM child exited ({}) before the guest agent was ready{}",
                status?,
                self.console_tail()
            ))),
        }
    }

    /// The last lines the guest kernel wrote to its console, for an error.
    pub fn console_tail(&self) -> String {
        let log = std::fs::read_to_string(self.dir.path().join("console.log")).unwrap_or_default();
        let lines: Vec<&str> = log.lines().collect();
        let tail = lines[lines.len().saturating_sub(20)..].join("\n");
        if tail.is_empty() {
            tail
        } else {
            format!("; the guest console ended with:\n{tail}")
        }
    }

    /// Asks the guest to power off, then waits up to `timeout` for the
    /// child to exit. A child still running then is killed. The VM's
    /// storage goes either way.
    pub async fn stop(mut self, agent: Agent, timeout: Duration) -> io::Result<ExitStatus> {
        agent.shutdown().await;
        let status = match tokio::time::timeout(timeout, self.child.wait()).await {
            Ok(status) => status?,
            Err(_) => {
                self.child.kill().await?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("the guest did not power off in {timeout:?}; its child was killed"),
                ));
            }
        };
        drop(self.alive.take());
        Ok(status)
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        // Closing the pipe stops a child that is still running, even if the
        // kill below fails; the private directory goes with `dir`.
        drop(self.alive.take());
        if let Ok(None) = self.child.try_wait()
            && let Err(error) = self.child.start_kill()
        {
            eprintln!("stopping the VM child: {error}");
        }
    }
}

/// A directory only this user can enter, removed when dropped.
struct PrivateDir(PathBuf);

impl PrivateDir {
    fn new() -> io::Result<PrivateDir> {
        use std::os::unix::fs::DirBuilderExt;
        let base = std::env::temp_dir();
        for _ in 0..16 {
            let mut name = OsString::from("fictionet-vm-");
            name.push(format!("{:016x}", random_u64()?));
            let path = base.join(name);
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(PrivateDir(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other("no free name for the VM's directory"))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            eprintln!("removing {}: {error}", self.0.display());
        }
    }
}

fn random_u64() -> io::Result<u64> {
    let mut bytes = [0u8; 8];
    // SAFETY: `bytes` is valid for writes of its length.
    let n = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    if n != bytes.len() as isize {
        return Err(io::Error::last_os_error());
    }
    Ok(u64::from_ne_bytes(bytes))
}

/// A connected pair of Unix stream sockets, both close-on-exec.
fn socketpair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: `fds` is valid for two descriptors, which are owned from here.
    let r = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair returned two new descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// A pipe, both ends close-on-exec: (read end, write end).
fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: `fds` is valid for two descriptors, which are owned from here.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 returned two new descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// A close-on-exec copy of `fd` numbered above the child's descriptors.
fn dup_above(fd: &OwnedFd) -> io::Result<OwnedFd> {
    // SAFETY: plain syscall; the new descriptor is owned from here.
    let new = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, CHILD_ALIVE + 1) };
    if new < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl returned a new descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(new) })
}
