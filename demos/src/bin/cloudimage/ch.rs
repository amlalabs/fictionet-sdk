//! Cloud Hypervisor as a child process: it boots the unmodified image's
//! kernel and initrd directly, attaches the per-run overlay and the
//! cloud-init seed, exposes the guest over vsock, and takes its network card
//! from our vhost-user backend.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::{Child, Command};

// `pub static CH_BIN: Option<&[u8]>`: Cloud Hypervisor's static binary when
// `cargo xtask cloudimage` has downloaded it (see build.rs), else `None`.
include!(concat!(env!("OUT_DIR"), "/ch_bin.rs"));

/// How to boot one VM.
pub struct Config<'a> {
    pub cloud_hypervisor: &'a Path,
    pub vmlinuz: &'a Path,
    pub initrd: &'a Path,
    pub cmdline: &'a str,
    pub overlay: &'a Path,
    pub seed: &'a Path,
    pub vcpus: u8,
    pub memory_mib: u32,
    /// Neutral DMI strings, so `dmidecode` does not read "Cloud Hypervisor".
    pub manufacturer: &'a str,
    pub product: &'a str,
    pub uuid: &'a str,
    /// The vhost-user-net backend socket.
    pub net_socket: &'a Path,
    /// The guest's MAC.
    pub mac: &'a str,
}

/// A running VM child, with the sockets the host talks to it on.
pub struct Vm {
    child: Child,
    vsock_socket: PathBuf,
    console_log: PathBuf,
    stderr_log: PathBuf,
    /// The sealed memfd the embedded binary runs from, held open for the
    /// child's life so its `/proc/self/fd` entry stays valid.
    _ch_memfd: Option<OwnedFd>,
}

impl Vm {
    /// Starts Cloud Hypervisor in its own process group. `dir` holds the
    /// run's sockets and console log.
    pub fn start(config: &Config, dir: &Path) -> io::Result<Vm> {
        let vsock_socket = dir.join("vsock.sock");
        let console_log = dir.join("console.log");
        let stderr_log = dir.join("ch.stderr.log");
        let api_socket = dir.join("api.sock");

        // Prefer the embedded binary, run from a sealed in-memory file with
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
            .arg("--vsock")
            .arg(format!("cid=3,socket={}", vsock_socket.display()))
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
        // Its own process group, so a Ctrl-C to the terminal does not reach
        // the VM.
        // SAFETY: setpgid in the child before exec is async-signal-safe.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn()?;
        Ok(Vm {
            child,
            vsock_socket,
            console_log,
            stderr_log,
            _ch_memfd: ch_memfd,
        })
    }

    /// The last lines Cloud Hypervisor wrote to its stderr, for an error.
    pub fn ch_stderr_tail(&self) -> String {
        let log = std::fs::read_to_string(&self.stderr_log).unwrap_or_default();
        let lines: Vec<&str> = log.lines().collect();
        lines[lines.len().saturating_sub(30)..].join("\n")
    }

    /// The host Unix socket for the guest's vsock (CH's hybrid protocol).
    pub fn vsock_socket(&self) -> &Path {
        &self.vsock_socket
    }

    /// Cloud Hypervisor's process ID, while it runs.
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Waits up to `timeout` for Cloud Hypervisor to exit (as it does when
    /// the guest powers off over ACPI), then kills it as a backup.
    pub async fn stop(mut self, timeout: Duration) -> io::Result<()> {
        match tokio::time::timeout(timeout, self.child.wait()).await {
            Ok(status) => {
                status?;
                Ok(())
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

/// Writes `bytes` to a sealed, in-memory file and returns it, ready to exec
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
    // SAFETY: the owned fd and the seal flags.
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
