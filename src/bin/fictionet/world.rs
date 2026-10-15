//! What every attach type shares: connecting to the world's socket, the
//! `hello` handshake, and how attach ends.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
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
