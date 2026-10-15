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
    /// The attach type, such as `tun` or `http_proxy`.
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
    unix::set_timeout(
        fd,
        libc::SO_RCVTIMEO,
        Some(relay::HANDSHAKE_TIMEOUT + Duration::from_secs(1)),
    )
    .map_err(err("setting the handshake timeout"))?;
    let hello = Hello {
        version: relay::VERSION,
        mtu: g.mtu,
        kind: g.kind.into(),
        name: g.name.into(),
    };
    unix::send(fd, &Message::Hello(hello).encode(), false).map_err(err("sending hello"))?;
    let mut buf = vec![0u8; relay::MAX_MESSAGE + 1];
    let n = match unix::recv(fd, &mut buf, false) {
        Ok(n) => n,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            return Err(Failure::Error(
                "the world did not answer hello in time".into(),
            ));
        }
        Err(e) => {
            return Err(Failure::Error(format!(
                "waiting for the world's answer: {e}"
            )));
        }
    };
    if n == 0 {
        return Err(Failure::Error(
            "the world closed the connection without answering hello".into(),
        ));
    }
    if n > relay::MAX_MESSAGE {
        return Err(Failure::Error(
            "the world answered hello with a message longer than 65,536 bytes".into(),
        ));
    }
    match relay::decode(&buf[..n]) {
        Ok(Message::Accept) => {}
        Ok(Message::Refuse(reason)) => return Err(Failure::Refused(reason)),
        Ok(other) => {
            return Err(Failure::Error(format!(
                "the world answered hello with {other:?}"
            )));
        }
        Err(e) => return Err(Failure::Error(format!("the world's answer to hello: {e}"))),
    }
    unix::set_timeout(fd, libc::SO_RCVTIMEO, None)
        .map_err(err("clearing the handshake timeout"))?;
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
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) && std::time::Instant::now() < deadline =>
            {
                if !said {
                    eprintln!(
                        "fictionet attach: waiting up to {} s for the world at {path}",
                        wait.as_secs()
                    );
                    said = true;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) if said => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("{e}, after waiting {} s", wait.as_secs()),
                ));
            }
            Err(e) => return Err(e),
        }
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

pub(crate) fn context(e: io::Error, what: &str) -> io::Error {
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

/// Reads until blocked, with an optional message limit. `false` means the world closed.
pub(crate) fn read_packets(
    fd: RawFd,
    buf: &mut [u8],
    mut limit: Option<usize>,
    mut packet: impl FnMut(&[u8]) -> Result<(), Failure>,
) -> Result<bool, Failure> {
    while limit != Some(0) {
        if let Some(left) = &mut limit {
            *left -= 1;
        }
        let n = match unix::recv(fd, buf, true) {
            Ok(0) => return Ok(false),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => return Ok(false),
            Err(e) => return Err(Failure::Error(format!("reading from the world: {e}"))),
        };
        packet(world_packet(&buf[..n]).map_err(Failure::Error)?)?;
    }
    Ok(true)
}

/// Reads one message from the world. After `accept`, the relay protocol
/// allows only `packet`: anything else, a message the protocol cannot
/// decode, or one longer than its limit ends attach with an error.
pub(crate) fn world_packet(msg: &[u8]) -> Result<&[u8], String> {
    if msg.len() > relay::MAX_MESSAGE {
        return Err("the world sent a message longer than 65,536 bytes".into());
    }
    match relay::decode(msg) {
        Ok(Message::Packet(p)) => Ok(p),
        Ok(other) => Err(format!("the world sent {other:?} after accept; closing")),
        Err(e) => Err(format!("the world sent a bad message: {e}; closing")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
