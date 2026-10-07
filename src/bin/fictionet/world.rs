//! What every attach type shares: connecting to the world's socket, the
//! `hello` handshake, the ready file, and how attach ends.

use std::fs;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::time::Duration;

use fictionet::relay::{self, Hello, Message, unix};

/// How attach ended, and the exit status that goes with it.
pub(crate) enum Failure {
    /// The world refused the `hello`. Exit status 3.
    Refused(String),
    /// Anything else. Exit status 1.
    Error(String),
}

impl Failure {
    pub(crate) fn status(&self) -> i32 {
        match self {
            Failure::Refused(_) => 3,
            Failure::Error(_) => 1,
        }
    }
}

pub(crate) fn err(context: &str) -> impl FnOnce(io::Error) -> Failure + '_ {
    move |e| Failure::Error(format!("{context}: {e}"))
}

/// What the `hello` says.
pub(crate) struct Greeting<'a> {
    /// The world socket's path.
    pub(crate) world: &'a str,
    /// How long to keep trying while the socket is missing.
    pub(crate) world_wait: Duration,
    /// The attach type, such as `tun` or `https_proxy`.
    pub(crate) kind: &'a str,
    pub(crate) name: &'a str,
    pub(crate) mtu: u16,
}

/// Connects, sends `hello`, and waits for `accept`. Returns the socket,
/// nonblocking.
pub(crate) fn handshake(g: &Greeting<'_>) -> Result<OwnedFd, Failure> {
    let sock = connect(g.world, g.world_wait).map_err(|e| {
        let hint = if e.kind() == io::ErrorKind::PermissionDenied {
            ". The socket belongs to the world's user, and attach may not write to it: run both as \
             the same user, or give attach CAP_DAC_OVERRIDE"
        } else {
            ""
        };
        Failure::Error(format!("connecting to the world at {}: {e}{hint}", g.world))
    })?;
    let fd = sock.as_raw_fd();
    unix::raise_buffers(fd);
    set_recv_timeout(fd, Some(relay::HANDSHAKE_TIMEOUT + Duration::from_secs(1)))
        .map_err(err("setting the handshake timeout"))?;
    let hello = Hello { version: relay::VERSION, mtu: g.mtu, kind: g.kind.into(), name: g.name.into() };
    unix::send(fd, &Message::Hello(hello).encode(), false).map_err(err("sending hello"))?;
    let mut buf = vec![0u8; relay::MAX_MESSAGE + 1];
    let n = match unix::recv(fd, &mut buf, false) {
        Ok(n) => n,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            return Err(Failure::Error("the world did not answer hello in time".into()));
        }
        Err(e) => return Err(Failure::Error(format!("waiting for the world's answer: {e}"))),
    };
    if n == 0 {
        return Err(Failure::Error("the world closed the connection without answering hello".into()));
    }
    if n > relay::MAX_MESSAGE {
        return Err(Failure::Error("the world answered hello with a message longer than 65,536 bytes".into()));
    }
    match relay::decode(&buf[..n]) {
        Ok(Message::Accept) => {}
        Ok(Message::Refuse(reason)) => return Err(Failure::Refused(reason)),
        Ok(other) => return Err(Failure::Error(format!("the world answered hello with {other:?}"))),
        Err(e) => return Err(Failure::Error(format!("the world's answer to hello: {e}"))),
    }
    set_recv_timeout(fd, None).map_err(err("clearing the handshake timeout"))?;
    unix::set_nonblocking(fd, true).map_err(err("making the socket nonblocking"))?;
    Ok(sock)
}

/// Connects to the world's socket. With a wait, a socket that does not
/// exist yet, or that no one is listening on yet, is tried again every
/// 100 ms until the wait is over.
fn connect(path: &str, wait: Duration) -> io::Result<OwnedFd> {
    let deadline = std::time::Instant::now() + wait;
    let mut said = false;
    loop {
        match unix::connect(path) {
            Ok(sock) => return Ok(sock),
            Err(e)
                if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused)
                    && std::time::Instant::now() < deadline =>
            {
                if !said {
                    eprintln!("fictionet attach: waiting up to {} s for the world at {path}", wait.as_secs());
                    said = true;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) if said => {
                return Err(io::Error::new(e.kind(), format!("{e}, after waiting {} s", wait.as_secs())));
            }
            Err(e) => return Err(e),
        }
    }
}

fn set_recv_timeout(fd: RawFd, timeout: Option<Duration>) -> io::Result<()> {
    let tv = match timeout {
        Some(d) => libc::timeval { tv_sec: d.as_secs() as _, tv_usec: d.subsec_micros() as _ },
        None => libc::timeval { tv_sec: 0, tv_usec: 0 },
    };
    // SAFETY: setsockopt with a timeval value.
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
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
/// removed first, and a file that appears in between is an error.
pub(crate) fn write_ready_file(path: Option<&Path>, name: &str) -> Result<(), Failure> {
    if let Some(path) = path {
        let _ = fs::remove_file(path);
        let mut f = open_own_file(path, true).map_err(err("writing the ready file"))?;
        io::Write::write_all(&mut f, format!("{name}\n").as_bytes()).map_err(err("writing the ready file"))?;
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
    options.write(true).mode(0o644).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    if new {
        options.create_new(true);
    } else {
        options.create(true);
    }
    let f = options.open(path).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) {
            io::Error::other(format!("{} is a symlink, which attach does not write through", path.display()))
        } else {
            e
        }
    })?;
    let meta = f.metadata()?;
    if !meta.file_type().is_file() {
        return Err(io::Error::other(format!("{} is not a regular file", path.display())));
    }
    if meta.nlink() > 1 {
        return Err(io::Error::other(format!("{} has other hard links, which attach does not write through", path.display())));
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
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
        write_ready_file(Some(&ready), "agent").map_err(|_| "write failed").unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep\n");
        assert!(fs::symlink_metadata(&ready).unwrap().file_type().is_file());
        assert_eq!(fs::read_to_string(&ready).unwrap(), "agent\n");
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
        assert!(open_own_file(&dir.join("fresh"), true).is_err(), "new means new");
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep\n");
        fs::remove_dir_all(&dir).unwrap();
    }
}
