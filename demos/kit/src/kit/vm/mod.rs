//! Cloud Hypervisor as a child process: it boots the unmodified image's
//! kernel and initrd directly, attaches the per-run overlay and the
//! cloud-init seed, and takes the guest's one network card from our
//! vhost-user backend. The guest has no vsock or other side channel: the
//! host reaches it over that card, through the world.

pub mod disk;

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::{Child, Command};

// `pub static CH_BIN: Option<&[u8]>`: Cloud Hypervisor's static binary when
// it is in demos/downloads/cloudimage (see build.rs), else `None`.
include!(concat!(env!("OUT_DIR"), "/ch_bin.rs"));

/// How to boot one VM.
pub struct Config<'a> {
    /// The downloaded executable used when no embedded binary is available.
    pub cloud_hypervisor: &'a Path,
    /// The unmodified Ubuntu kernel.
    pub vmlinuz: &'a Path,
    /// The unmodified Ubuntu initial ramdisk.
    pub initrd: &'a Path,
    /// The guest kernel command line.
    pub cmdline: &'a str,
    /// The writable disk backed by the unmodified cloud image.
    pub overlay: &'a Path,
    /// The read-only NoCloud seed image.
    pub seed: &'a Path,
    /// The number of virtual CPUs.
    pub vcpus: u8,
    /// The memory size in MiB.
    pub memory_mib: u32,
    /// Neutral DMI strings, so `dmidecode` does not read "Cloud Hypervisor".
    pub manufacturer: &'a str,
    /// The guest-visible DMI product name.
    pub product: &'a str,
    /// The guest-visible DMI UUID.
    pub uuid: &'a str,
    /// The vhost-user-net backend socket.
    pub net_socket: &'a Path,
    /// The guest's MAC.
    pub mac: &'a str,
}

/// A running VM child.
pub struct Vm {
    child: Child,
    _socket_dir: std::fs::File,
    console_log: PathBuf,
    stderr_log: PathBuf,
    /// The write-protected memfd the embedded binary runs from, held open for the
    /// child's life so its `/proc/self/fd` entry stays valid.
    _ch_memfd: Option<OwnedFd>,
}

impl Vm {
    /// Starts Cloud Hypervisor in its own process group. `dir` holds the
    /// run's API socket and logs.
    pub fn start(config: &Config, dir: &Path, ownership: &Ownership) -> io::Result<Vm> {
        let console_log = dir.join("console.log");
        let stderr_log = dir.join("ch.stderr.log");
        let socket_dir = std::fs::File::open(dir)?;
        let api_socket = super::util::socket_path(&socket_dir, "api.sock");

        // Prefer the embedded binary, run from a write-protected in-memory file with
        // nothing written to disk; fall back to the downloaded path.
        let (program, ch_memfd) = match CH_BIN {
            Some(bytes) => {
                let memfd = memfd_exe(bytes)?;
                let path = PathBuf::from(format!("/proc/self/fd/{}", memfd.as_raw_fd()));
                (path, Some(memfd))
            }
            None => (config.cloud_hypervisor.to_path_buf(), None),
        };

        let mut command = Command::new(&program);
        command
            .arg("--kernel")
            .arg(config.vmlinuz)
            .arg("--initramfs")
            .arg(config.initrd)
            .arg("--cmdline")
            .arg(config.cmdline)
            .arg("--disk")
            .arg(format!(
                "path={},image_type=qcow2,backing_files=on",
                config.overlay.display()
            ))
            .arg(format!(
                "path={},readonly=on,image_type=raw",
                config.seed.display()
            ))
            .arg("--net")
            .arg(format!(
                "vhost_user=true,socket={},mac={}",
                config.net_socket.display(),
                config.mac
            ))
            .arg("--cpus")
            .arg(format!("boot={}", config.vcpus))
            .arg("--memory")
            .arg(format!("size={}M,shared=on", config.memory_mib))
            .arg("--serial")
            .arg(format!("file={}", console_log.display()))
            .arg("--console")
            .arg("off")
            .arg("--platform")
            .arg(format!(
                "system_manufacturer={},system_product_name={},system_uuid={}",
                config.manufacturer, config.product, config.uuid
            ))
            .arg("--api-socket")
            .arg(&api_socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&stderr_log)?))
            .kill_on_drop(true);
        own_child(&mut command);
        ownership.inherit(&mut command);
        let child = command.spawn()?;
        Ok(Vm {
            child,
            _socket_dir: socket_dir,
            console_log,
            stderr_log,
            _ch_memfd: ch_memfd,
        })
    }

    /// The VM child's peak resident memory, in MiB.
    pub fn peak_rss_mib(&self) -> Option<u64> {
        let pid = self.pid()?;
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        status
            .lines()
            .find_map(|l| l.strip_prefix("VmHWM:"))
            .and_then(|v| v.trim().trim_end_matches(" kB").parse::<u64>().ok())
            .map(|kb| kb >> 10)
    }

    /// The last lines Cloud Hypervisor wrote to its stderr, for an error.
    pub fn ch_stderr_tail(&self) -> String {
        let log = std::fs::read_to_string(&self.stderr_log).unwrap_or_default();
        let lines: Vec<&str> = log.lines().collect();
        lines[lines.len().saturating_sub(30)..].join("\n")
    }

    /// Cloud Hypervisor's process ID, while it runs.
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Reports an early process exit while the guest is starting.
    pub fn exited(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }

    /// Waits up to `timeout` for Cloud Hypervisor to exit (as it does when
    /// the guest powers off over ACPI), then kills it as a backup.
    pub async fn stop(mut self, timeout: Duration) -> io::Result<()> {
        match tokio::time::timeout(timeout, self.child.wait()).await {
            Ok(status) => {
                let status = status?;
                if status.success() {
                    Ok(())
                } else {
                    Err(io::Error::other(format!(
                        "Cloud Hypervisor exited with {status}: {}",
                        self.ch_stderr_tail()
                    )))
                }
            }
            Err(_) => {
                self.child.kill().await?;
                self.child.wait().await?;
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("the guest did not power off in {timeout:?}; it was killed"),
                ))
            }
        }
    }

    /// The last lines of the guest console, for an error.
    pub fn console_tail(&self) -> String {
        let log = std::fs::read_to_string(&self.console_log).unwrap_or_default();
        let clean = strip_ansi(&log);
        let lines: Vec<&str> = clean.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    }
}

/// The kernel kills the VM even when its owner cannot run destructors.
pub fn own_child(command: &mut Command) {
    let parent = std::process::id() as libc::pid_t;
    // SAFETY: these operations are async-signal-safe and allocate nothing in the child.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 || libc::setpgid(0, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                libc::_exit(1);
            }
            Ok(())
        });
    }
}

/// Exclusive ownership of a demo, retained by its owner and VM children.
pub struct Ownership(std::fs::File);

impl Ownership {
    pub(super) fn acquire(name: &str) -> io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        if name.is_empty()
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
        {
            return Err(io::Error::other("invalid demo name"));
        }
        // The file stays in place so contenders always lock the same inode.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(
                std::env::temp_dir().join(format!("{name}-{}.lock", unsafe { libc::geteuid() })),
            )?;
        file.try_lock().map_err(|error| {
            io::Error::other(format!(
                "{name} is already owned or cannot be locked: {error}"
            ))
        })?;
        Ok(Self(file))
    }

    fn inherit(&self, command: &mut Command) {
        let fd = self.0.as_raw_fd();
        // SAFETY: fcntl changes only the child's descriptor flags before exec.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
}

/// Writes `bytes` to a write-protected, in-memory file and returns it, ready to exec
/// through `/proc/self/fd/<n>`. The bytes never touch disk, and the seals stop
/// their contents changing before or after exec.
fn memfd_exe(bytes: &[u8]) -> io::Result<OwnedFd> {
    let name = c"cloud-hypervisor";
    // SAFETY: a valid C-string name and known flags.
    let raw =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: memfd_create returned a fresh, owned fd.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut written = 0;
    while written < bytes.len() {
        // SAFETY: writing `len` bytes from a valid slice to the owned fd.
        let n = unsafe {
            libc::write(
                fd.as_raw_fd(),
                bytes[written..].as_ptr() as *const libc::c_void,
                bytes.len() - written,
            )
        };
        if n <= 0 {
            return Err(io::Error::last_os_error());
        }
        written += n as usize;
    }
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: the owned fd and the write-protection flags.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Removes ANSI escape sequences from console text.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for e in chars.by_ref() {
                if e.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod process_tests {
    use super::*;

    #[tokio::test]
    async fn demo_ownership_is_exclusive_until_owner_and_children_exit() {
        if std::env::var_os("DEMO_OWNERSHIP_TEST").is_none() {
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "kit::vm::process_tests::demo_ownership_is_exclusive_until_owner_and_children_exit"])
                .env("DEMO_OWNERSHIP_TEST", "1").kill_on_drop(true).status().await.unwrap();
            assert!(status.success());
            return;
        }
        let name = format!("owned-demo-{}", std::process::id());
        let ownership = Ownership::acquire(&name).unwrap();
        assert!(Ownership::acquire(&name).is_err());
        let mut command = Command::new("sh");
        command
            .args(["-c", "read value"])
            .stdin(Stdio::piped())
            .kill_on_drop(true);
        ownership.inherit(&mut command);
        let mut child = command.spawn().unwrap();
        drop(ownership);
        assert!(Ownership::acquire(&name).is_err());
        child.kill().await.unwrap();
        Ownership::acquire(&name).unwrap();
    }

    #[tokio::test]
    async fn child_dies_when_its_owner_is_killed() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
        if std::env::var_os("VM_OWNER_TEST").is_some() {
            let mut command = Command::new("sleep");
            command.arg("60");
            own_child(&mut command);
            let _child = command.spawn().unwrap();
            println!("child ready");
            std::future::pending::<()>().await;
            return;
        }
        let mut owner = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "kit::vm::process_tests::child_dies_when_its_owner_is_killed",
                "--nocapture",
            ])
            .env("VM_OWNER_TEST", "1")
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut output = BufReader::new(owner.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(output.read_line(&mut line).await.unwrap(), 0);
            if line.contains("child ready") {
                break;
            }
        }
        owner.kill().await.unwrap();
        let mut tail = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), output.read_to_end(&mut tail))
            .await
            .expect("VM retained its owner's output pipe after parent death")
            .unwrap();
    }

    #[tokio::test]
    async fn shutdown_rejects_unsuccessful_process_status() {
        for code in [0, 7] {
            let dir = crate::kit::util::RunDir::new(&std::env::temp_dir(), "process").unwrap();
            let child = Command::new("sh")
                .args(["-c", &format!("exit {code}")])
                .spawn()
                .unwrap();
            let vm = Vm {
                child,
                console_log: dir.path().join("console"),
                stderr_log: dir.path().join("stderr"),
                _socket_dir: std::fs::File::open(dir.path()).unwrap(),
                _ch_memfd: None,
            };
            assert_eq!(vm.stop(Duration::from_secs(5)).await.is_ok(), code == 0);
        }
    }
}
