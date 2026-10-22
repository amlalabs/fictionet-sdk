//! What attach owns while it runs, and how it lets go: the signal handler
//! and what it removes or undoes, the ready file, and the files attach
//! opens as its own.

use std::fs;
use std::io;
use std::path::Path;

use crate::netlink::Request;
use crate::world::{Failure, err};

static READY_FILE: std::sync::OnceLock<std::ffi::CString> = std::sync::OnceLock::new();

/// A socket file to remove on a signal: `attach tap`'s, while it listens.
static SOCKET_FILE: std::sync::OnceLock<std::ffi::CString> = std::sync::OnceLock::new();
static SOCKET_FILE_LIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The device and inode of [`SOCKET_FILE`], so the handler removes only
/// the file attach made.
static SOCKET_FILE_ID: std::sync::OnceLock<(u64, u64)> = std::sync::OnceLock::new();

/// Has the signal handler remove `path`, until [`keep_on_signal`], if it
/// is still the file with device and inode `id`. Only one path is ever
/// set.
pub(crate) fn remove_on_signal(path: &std::path::Path, id: (u64, u64)) {
    use std::os::unix::ffi::OsStrExt;
    if let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "set once per process, by Unlink::new in run_qemu, the only caller"
        )]
        let _ = SOCKET_FILE.set(c);
        #[expect(
            clippy::let_underscore_must_use,
            reason = "set once per process, by Unlink::new in run_qemu, the only caller"
        )]
        let _ = SOCKET_FILE_ID.set(id);
        SOCKET_FILE_LIVE.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Has the signal handler remove the ready file at `path`. `attach tap`
/// calls it once it owns its VM link, so that a second attach, refused,
/// leaves the first one's ready file alone. Only one path is ever set.
pub(crate) fn remove_ready_on_signal(path: &std::path::Path) {
    use std::os::unix::ffi::OsStrExt;
    if let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "set once per process: main passes the path for tun and proxy, and None for tap, whose take_ready_file runs once"
        )]
        let _ = READY_FILE.set(c);
    }
}

/// Ordered netlink requests, serialized before setup changes any device.
/// Normal cleanup sends each request and waits for its ack. Signal cleanup
/// sends the same bytes in one datagram, without waiting for replies.
pub(crate) struct NetlinkCleanup {
    message: Vec<u8>,
    requests: Vec<std::ops::Range<usize>>,
}

impl NetlinkCleanup {
    pub(crate) fn new(requests: impl IntoIterator<Item = Request>) -> Self {
        let mut message = Vec::new();
        let mut ranges = Vec::new();
        for request in requests {
            let start = message.len();
            message.extend_from_slice(&request.finish());
            ranges.push(start..message.len());
        }
        Self {
            message,
            requests: ranges,
        }
    }

    pub(crate) fn requests(&self) -> impl Iterator<Item = &[u8]> {
        self.requests.iter().map(|r| &self.message[r.clone()])
    }
}

/// The cleanup the signal handler sends before exiting: `attach tap
/// --vm tap:<name>` sets the VM's device down and removes its redirect.
static NETLINK_ON_SIGNAL: std::sync::OnceLock<NetlinkCleanup> = std::sync::OnceLock::new();

/// Registers the cleanup once, before setup, and returns the same plan
/// for normal teardown. The caller keeps its device lock until process
/// exit, so a later signal cannot undo another attach's setup.
pub(crate) fn netlink_on_signal(cleanup: NetlinkCleanup) -> &'static NetlinkCleanup {
    NETLINK_ON_SIGNAL.get_or_init(|| cleanup)
}

#[cfg(test)]
pub(crate) fn registered_netlink_cleanup() -> Option<&'static NetlinkCleanup> {
    NETLINK_ON_SIGNAL.get()
}

/// Stops the signal handler removing the path given to
/// [`remove_on_signal`].
pub(crate) fn keep_on_signal() {
    SOCKET_FILE_LIVE.store(false, std::sync::atomic::Ordering::SeqCst);
}

/// Ends the process on SIGTERM, SIGINT and SIGHUP. The kernel then closes
/// the tun fd, which removes the device, or the proxy's listening socket,
/// and the world socket, which the world reads as a detach. A handler is needed because attach is often
/// process 1 in a container, and process 1 ignores signals it has no
/// handler for.
/// The ready file is removed too, so a healthcheck stops passing.
pub(crate) fn exit_on_signals(ready_file: Option<&std::path::Path>) {
    if let Some(path) = ready_file {
        remove_ready_on_signal(path);
    }
    extern "C" fn on_signal(sig: libc::c_int) {
        if let Some(path) = READY_FILE.get() {
            // SAFETY: unlink is async-signal-safe. A OnceLock read returns
            // the path only once it is fully set, which may be after the
            // handler was installed.
            unsafe { libc::unlink(path.as_ptr()) };
        }
        if SOCKET_FILE_LIVE.load(std::sync::atomic::Ordering::SeqCst)
            && let (Some(path), Some(&(dev, ino))) = (SOCKET_FILE.get(), SOCKET_FILE_ID.get())
        {
            // SAFETY: as above; an atomic load and OnceLock reads that
            // completed before the flag was set are signal-safe, and so is
            // lstat.
            unsafe {
                let mut st: libc::stat = std::mem::zeroed();
                if libc::lstat(path.as_ptr(), &mut st) == 0 && st.st_dev == dev && st.st_ino == ino
                {
                    libc::unlink(path.as_ptr());
                }
            }
        }
        if let Some(cleanup) = NETLINK_ON_SIGNAL.get() {
            let msg = &cleanup.message;
            // SAFETY: socket, sendto and close are async-signal-safe; the
            // message was built before it was set. The kernel handles a
            // route netlink request inside sendto, so no answer is awaited.
            unsafe {
                let fd = libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    libc::NETLINK_ROUTE,
                );
                if fd >= 0 {
                    let mut kernel: libc::sockaddr_nl = std::mem::zeroed();
                    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
                    libc::sendto(
                        fd,
                        msg.as_ptr().cast(),
                        msg.len(),
                        0,
                        (&raw const kernel).cast(),
                        std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                    );
                    libc::close(fd);
                }
            }
        }
        // SAFETY: _exit is async-signal-safe.
        unsafe { libc::_exit(128 + sig) };
    }
    for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        // SAFETY: installs a handler that only calls _exit.
        unsafe { libc::signal(sig, on_signal as *const () as libc::sighandler_t) };
    }
}

/// Removes a ready file left over from an earlier run, so it cannot report
/// this one as ready.
pub(crate) fn clear_ready_file(path: Option<&Path>) {
    if let Some(path) = path {
        let _ = fs::remove_file(path);
    }
}

/// Writes the ready file: the sandbox's name and a newline. Attach often
/// runs as root, so the file is made new, never written through what is
/// at the path: whatever is there (such as a symlink to another file) is
/// removed first, and a file that appears in between is an error. If
/// writing fails, tries to remove the created file, leaving replacements
/// alone.
pub(crate) fn write_ready_file(path: Option<&Path>, name: &str) -> Result<(), Failure> {
    write_ready_file_with(path, name, io::Write::write_all)
}

fn write_ready_file_with(
    path: Option<&Path>,
    name: &str,
    write: impl FnOnce(&mut fs::File, &[u8]) -> io::Result<()>,
) -> Result<(), Failure> {
    if let Some(path) = path {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "open_own_file below uses O_EXCL, so a file that was not removed fails it"
        )]
        let _ = fs::remove_file(path);
        let mut f = open_own_file(path, true).map_err(err("writing the ready file"))?;
        if let Err(e) = write(&mut f, format!("{name}\n").as_bytes()) {
            use std::os::unix::fs::MetadataExt;
            // Keep f open so its inode cannot be reused for a replacement.
            if let (Ok(owned), Ok(current)) = (f.metadata(), fs::symlink_metadata(path))
                && (owned.dev(), owned.ino()) == (current.dev(), current.ino())
            {
                let _ = fs::remove_file(path);
            }
            return Err(err("writing the ready file")(e));
        }
    }
    Ok(())
}

/// Opens `path` for writing as a plain file of its own: never through a
/// symlink (`O_NOFOLLOW`), and only if it is a regular file with one link,
/// so neither a symlink nor a hard link can send the write to another
/// file. With `new`, the file must not exist yet (`O_EXCL`); otherwise it
/// is made if missing and left as it is (the caller truncates it).
pub(crate) fn open_own_file(path: &Path, new: bool) -> io::Result<fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut options = fs::OpenOptions::new();
    options
        .write(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    if new {
        options.create_new(true);
    } else {
        options.create(true);
    }
    let f = options.open(path).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) {
            io::Error::other(format!(
                "{} is a symlink, which attach does not write through",
                path.display()
            ))
        } else {
            e
        }
    })?;
    let meta = f.metadata()?;
    if !meta.file_type().is_file() {
        return Err(io::Error::other(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if meta.nlink() > 1 {
        return Err(io::Error::other(format!(
            "{} has other hard links, which attach does not write through",
            path.display()
        )));
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_and_signal_cleanup_use_the_same_requests_in_order() {
        use crate::netlink;

        let cleanup = NetlinkCleanup::new([
            netlink::link_down(7),
            netlink::del_ingress(7),
            netlink::link_down(8),
        ]);
        let requests: Vec<_> = cleanup.requests().collect();
        assert_eq!(
            requests,
            [
                netlink::link_down(7).finish(),
                netlink::del_ingress(7).finish(),
                netlink::link_down(8).finish(),
            ]
        );
        // Decode the datagram's boundaries as the kernel does. Each
        // acknowledged request must also be a complete signal request.
        let mut signal = cleanup.message.as_slice();
        for request in requests {
            let len = u32::from_ne_bytes(signal[..4].try_into().unwrap()) as usize;
            assert_eq!(&signal[..len], request);
            signal = &signal[(len + 3) & !3..];
        }
        assert!(signal.is_empty());
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("fn-world-{name}-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A symlink at the ready file's path is replaced, not written through.
    #[test]
    fn the_ready_file_is_never_written_through_a_symlink() {
        let dir = temp_dir("ready");
        let target = dir.join("target");
        fs::write(&target, "keep\n").unwrap();
        let ready = dir.join("attach.ready");
        std::os::unix::fs::symlink(&target, &ready).unwrap();
        write_ready_file(Some(&ready), "agent")
            .map_err(|_| "write failed")
            .unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep\n");
        assert!(fs::symlink_metadata(&ready).unwrap().file_type().is_file());
        assert_eq!(fs::read_to_string(&ready).unwrap(), "agent\n");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failed_ready_file_write_removes_empty_and_partial_files() {
        let dir = temp_dir("ready-failed");
        let ready = dir.join("attach.ready");
        for written in [0, 3] {
            let result = write_ready_file_with(Some(&ready), "agent", |f, bytes| {
                io::Write::write_all(f, &bytes[..written])?;
                assert_eq!(fs::read(&ready).unwrap(), &bytes[..written]);
                Err(io::Error::from_raw_os_error(libc::ENOSPC))
            });
            let Err(Failure::Error(message)) = result else {
                panic!("expected a ready-file write error");
            };
            assert_eq!(
                message,
                format!(
                    "writing the ready file: {}",
                    io::Error::from_raw_os_error(libc::ENOSPC)
                )
            );
            assert_eq!(
                fs::symlink_metadata(&ready).unwrap_err().kind(),
                io::ErrorKind::NotFound
            );
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failed_ready_file_write_leaves_replacements_alone() {
        let dir = temp_dir("ready-replaced");
        let ready = dir.join("attach.ready");
        let original = dir.join("original");
        for symlink in [false, true] {
            let result = write_ready_file_with(Some(&ready), "agent", |f, bytes| {
                io::Write::write_all(f, &bytes[..3])?;
                fs::rename(&ready, &original)?;
                if symlink {
                    std::os::unix::fs::symlink(&original, &ready)?;
                } else {
                    fs::write(&ready, "replacement\n")?;
                }
                Err(io::Error::from_raw_os_error(libc::ENOSPC))
            });
            assert!(matches!(result, Err(Failure::Error(_))));
            if symlink {
                assert_eq!(fs::read_link(&ready).unwrap(), original);
            } else {
                assert_eq!(fs::read_to_string(&ready).unwrap(), "replacement\n");
            }
            assert_eq!(fs::read_to_string(&original).unwrap(), "age");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn own_files_refuse_symlinks_and_hard_links() {
        let dir = temp_dir("own");
        let target = dir.join("target");
        fs::write(&target, "keep\n").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_own_file(&link, false).is_err());
        let hard = dir.join("hard");
        fs::hard_link(&target, &hard).unwrap();
        assert!(open_own_file(&hard, false).is_err());
        assert!(open_own_file(&dir.join("fresh"), true).is_ok());
        assert!(
            open_own_file(&dir.join("fresh"), true).is_err(),
            "new means new"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep\n");
        fs::remove_dir_all(&dir).unwrap();
    }
}
