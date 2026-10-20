//! The `--vm qemu:<path>` transport: the socket path's lock, the listening
//! socket and its file's lifetime, and the one accepted connection.
//! This module also holds writes to QEMU's socket.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use fictionet::relay::{self, unix};
use fictionet::stdlib::network::ethernet::stream::{Decoder, Outbox};

use crate::config::TapArgs;
use crate::lifecycle;
use crate::world::{self, Failure, err};

use super::{End, OUTBOX, Port, greeting, relay_and_report, take_ready_file};

/// `--vm qemu:<path>`: takes the socket path's lock, listens, connects to
/// the world, then serves QEMU's one connection.
pub(super) fn run_qemu(
    args: &TapArgs,
    path: &Path,
    lock: &mut Option<OwnedFd>,
) -> Result<End, Failure> {
    take_ready_file(args, lock, lock_path(path)?);
    let listener = listen(path)
        .map_err(|e| Failure::Error(format!("listening at {}: {e}", path.display())))?;
    // Until QEMU connects, the socket file goes with this process.
    let mut unlink = Some(Unlink::new(path).map_err(err("checking the socket file"))?);
    let sock = world::handshake(&greeting(args))?;
    eprintln!(
        "fictionet attach: {} attached; waiting for QEMU at {}",
        args.name,
        path.display()
    );
    lifecycle::write_ready_file(args.ready_file.as_deref(), &args.name)?;
    let Some(vm) = accept(&listener, sock.as_raw_fd())? else {
        return Ok(End::World);
    };
    // One connection only: the socket file goes now, so a second QEMU
    // cannot connect, and a restarted attach can make a new one at the
    // same path.
    drop(listener);
    drop(unlink.take());
    eprintln!("fictionet attach: QEMU connected");
    let mut port = Port::Stream {
        fd: vm,
        decoder: Decoder::new(),
        outbox: Outbox::new(OUTBOX),
    };
    relay_and_report(args, &mut port, sock.as_raw_fd())
}

/// Takes the lock for a QEMU socket path: an exclusive `flock` on
/// `<path>.lock`, made with mode 0600 if it is missing, and held until
/// attach exits. One attach at a time owns a socket path, so a second one
/// stops here, before it touches the socket or the ready file. The lock
/// is on the file, not its name, so another spelling of the same path
/// finds it too. The file stays after attach exits; the kernel releases
/// the lock however attach ends.
fn lock_path(path: &Path) -> Result<OwnedFd, Failure> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut lock = path.as_os_str().to_owned();
    lock.push(".lock");
    let lock = Path::new(&lock);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(lock)
        .map_err(|e| Failure::Error(format!("opening the lock file {}: {e}", lock.display())))?;
    let fd = OwnedFd::from(file);
    // SAFETY: plain syscall on an fd we own.
    if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::WouldBlock {
            return Err(Failure::Error(format!(
                "another attach is using {} (it holds {})",
                path.display(),
                lock.display()
            )));
        }
        return Err(Failure::Error(format!("locking {}: {e}", lock.display())));
    }
    Ok(fd)
}

/// Removes the socket file when dropped, and tells the signal handler to
/// remove it too while it lives. Either removes it only while it is still
/// the file attach made, so a newer attach's socket at the same path stays.
struct Unlink<'a> {
    path: &'a Path,
    id: (u64, u64),
}

impl<'a> Unlink<'a> {
    fn new(path: &'a Path) -> io::Result<Unlink<'a>> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(path)?;
        let id = (meta.dev(), meta.ino());
        lifecycle::remove_on_signal(path, id);
        Ok(Unlink { path, id })
    }
}

impl Drop for Unlink<'_> {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        lifecycle::keep_on_signal();
        if std::fs::symlink_metadata(self.path).is_ok_and(|m| (m.dev(), m.ino()) == self.id) {
            #[expect(
                clippy::let_underscore_must_use,
                reason = "removes attach's own socket file in Drop, when attach is done with it"
            )]
            let _ = std::fs::remove_file(self.path);
        }
    }
}

/// Listens on a Unix stream socket at `path`, mode 0600, so only attach's
/// user can connect. The caller holds the path's lock ([`lock_path`]), so
/// no other attach is listening there. A socket file left by an attach
/// that has exited is replaced. One that a live socket of another program
/// is bound to, as `/proc/net/unix` lists them, or any other file, is an
/// error.
fn listen(path: &Path) -> io::Result<OwnedFd> {
    // SAFETY: plain syscall; the fd is owned from here.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let (addr, len) = unix::address(path).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the socket path must be 1 to 107 bytes",
        )
    })?;
    let bind = || {
        // The file is made with mode 0600. umask is per process, and attach
        // has one thread here.
        // SAFETY: plain syscalls; `addr` is a valid sockaddr_un.
        let old = unsafe { libc::umask(0o177) };
        let r = unsafe { libc::bind(fd.as_raw_fd(), (&raw const addr).cast(), len) };
        let e = io::Error::last_os_error();
        unsafe { libc::umask(old) };
        if r < 0 { Err(e) } else { Ok(()) }
    };
    match bind() {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EADDRINUSE) => {
            use std::os::unix::fs::FileTypeExt;
            let meta = std::fs::symlink_metadata(path)?;
            if !meta.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "the path exists and is not a socket",
                ));
            }
            if socket_bound_at(path)? {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "a live socket is bound there, by a program other than attach",
                ));
            }
            std::fs::remove_file(path)?;
            bind()?;
        }
        Err(e) => return Err(e),
    }
    // SAFETY: plain syscall.
    if unsafe { libc::listen(fd.as_raw_fd(), 1) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Whether a socket in this network namespace is bound to `path`, as
/// `/proc/net/unix` lists them, by the path given or its absolute form.
fn socket_bound_at(path: &Path) -> io::Result<bool> {
    let list = std::fs::read("/proc/net/unix")?;
    let absolute = std::path::absolute(path)?;
    let want = [path.as_os_str().as_bytes(), absolute.as_os_str().as_bytes()];
    Ok(list
        .split(|&b| b == b'\n')
        .skip(1)
        .filter_map(bound_path)
        .any(|p| want.contains(&p)))
}

/// The path in one line of `/proc/net/unix`: everything after its seven
/// fixed fields, spaces included. `None` for an unnamed socket.
fn bound_path(line: &[u8]) -> Option<&[u8]> {
    let mut rest = line;
    for _ in 0..7 {
        let start = rest.iter().position(|&b| b != b' ')?;
        rest = &rest[start..];
        let end = rest.iter().position(|&b| b == b' ')?;
        rest = &rest[end..];
    }
    let start = rest.iter().position(|&b| b != b' ')?;
    Some(&rest[start..])
}

/// Waits for QEMU to connect. `None` if the world closed its connection
/// first. Packets the world sends meanwhile are dropped, since there is no
/// VM to take them yet. Any other message ends attach with an error, as it
/// does once QEMU is connected.
fn accept(listener: &OwnedFd, world: RawFd) -> Result<Option<OwnedFd>, Failure> {
    let mut buf = vec![0u8; relay::MAX_MESSAGE + 1];
    loop {
        let mut fds = [
            libc::pollfd {
                fd: listener.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: world,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: `fds` is valid for the call.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Failure::Error(format!("poll: {e}")));
        }
        if fds[1].revents != 0 && !world::read_packets(world, &mut buf, None, |_| Ok(()))? {
            return Ok(None);
        }
        if fds[0].revents != 0 {
            // SAFETY: plain syscall; the fd is owned from here.
            let fd = unsafe {
                libc::accept4(
                    listener.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                )
            };
            if fd < 0 {
                let e = io::Error::last_os_error();
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionAborted
                ) {
                    continue;
                }
                return Err(Failure::Error(format!("accepting QEMU's connection: {e}")));
            }
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            unix::raise_buffers(fd.as_raw_fd());
            return Ok(Some(fd));
        }
    }
}

/// Writes what the outbox holds, as far as QEMU's socket takes it.
/// `false` if QEMU closed the connection.
pub(super) fn flush(vm: RawFd, outbox: &mut Outbox) -> Result<bool, Failure> {
    while !outbox.is_empty() {
        let p = outbox.pending();
        // SAFETY: `p` is valid for reads of its length. MSG_NOSIGNAL: a
        // closed socket is an error here, not a SIGPIPE.
        let n = unsafe {
            libc::send(
                vm,
                p.as_ptr().cast(),
                p.len(),
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::WouldBlock => return Ok(true),
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => return Ok(false),
                _ => return Err(err("writing to QEMU's socket")(e)),
            }
        }
        outbox.written(n as usize);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_net_unix_paths_keep_their_spaces() {
        let line = b"0000000000000000: 00000002 00000000 00010000 0001 01 4242 /tmp/vm one.sock";
        assert_eq!(bound_path(line), Some(&b"/tmp/vm one.sock"[..]));
        let unnamed = b"0000000000000000: 00000003 00000000 00000000 0001 03 4243";
        assert_eq!(bound_path(unnamed), None);
    }
}
