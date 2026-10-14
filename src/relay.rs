//! The [relay protocol](crate::proto): its messages, and the
//! local transport, a Unix `SOCK_SEQPACKET` socket with one message per
//! datagram.
//!
//! Shared by [`listen`](crate::listen) and the `fictionet attach` binary.
//! Not part of the public API: it is public only so that the binary can use
//! it, and may change at any time.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

/// The protocol version that `hello` carries.
pub const VERSION: u16 = 1;

/// Message kinds: the first byte of each message.
pub const AUTH: u8 = 0;
pub const HELLO: u8 = 1;
pub const ACCEPT: u8 = 2;
pub const REFUSE: u8 = 3;
pub const PACKET: u8 = 4;
pub const REQUEST: u8 = 5;
pub const REPLY: u8 = 6;

/// The `hello` type of an observer session, which is not a sandbox.
pub const OBSERVE: &str = "observe";
/// The version of the observe API that a world speaks, as its `world`
/// request reports.
pub const OBSERVE_VERSION: u32 = 1;

/// `reply` flags. `MORE`: the value goes on in the next reply with the
/// same id. `END`: no more replies come for this id. `BINARY`: the value
/// is raw bytes, not JSON.
pub const MORE: u8 = 1;
pub const END: u8 = 2;
pub const BINARY: u8 = 4;

/// The most payload one `reply` carries: the message limit, less the kind
/// byte, the id and the flags.
pub const MAX_REPLY_CHUNK: usize = MAX_MESSAGE - 6;

/// Steps 1 and 2 of a connection must finish within this.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The longest message a stream transport may carry. A seqpacket transport
/// needs no lengths, but no message is longer than this either: one byte
/// for the message kind, and an IP packet of at most 65,535 bytes.
pub const MAX_MESSAGE: usize = 65_536;

/// The body of a `hello`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub version: u16,
    pub mtu: u16,
    /// The attach type, such as `tun`. ASCII.
    pub kind: String,
    /// The sandbox's name. UTF-8; 1 to 255 bytes to be accepted.
    pub name: String,
}

/// Why a message could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The message is empty.
    Empty,
    /// The first byte is not a known kind.
    UnknownKind(u8),
    /// The body is too short, too long, or not valid text.
    BadBody,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Empty => f.write_str("empty message"),
            DecodeError::UnknownKind(k) => write!(f, "unknown message kind {k}"),
            DecodeError::BadBody => f.write_str("malformed message body"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// One message of the protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message<'a> {
    Auth(&'a [u8]),
    Hello(Hello),
    Accept,
    Refuse(String),
    Packet(&'a [u8]),
    /// An observer's request: its id, and a JSON object with an `op`.
    Request {
        id: u32,
        body: &'a [u8],
    },
    /// The world's reply to request `id`: flags, then a piece of a value.
    Reply {
        id: u32,
        flags: u8,
        body: &'a [u8],
    },
}

impl Message<'_> {
    /// The message as bytes: its kind, then its body.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Message::Auth(token) => [&[AUTH][..], token].concat(),
            Message::Hello(hello) => {
                let mut out = Vec::with_capacity(7 + hello.kind.len() + hello.name.len());
                out.push(HELLO);
                out.extend_from_slice(&hello.version.to_be_bytes());
                out.extend_from_slice(&hello.mtu.to_be_bytes());
                // Longer strings are cut to 255 bytes here; the world then
                // sees a different name, so callers check lengths first.
                let kind = &hello.kind.as_bytes()[..hello.kind.len().min(255)];
                out.push(kind.len() as u8);
                out.extend_from_slice(kind);
                let name = &hello.name.as_bytes()[..hello.name.len().min(255)];
                out.push(name.len() as u8);
                out.extend_from_slice(name);
                out
            }
            Message::Accept => vec![ACCEPT],
            Message::Refuse(reason) => [&[REFUSE][..], reason.as_bytes()].concat(),
            Message::Packet(packet) => [&[PACKET][..], packet].concat(),
            Message::Request { id, body } => [&[REQUEST][..], &id.to_be_bytes(), body].concat(),
            Message::Reply { id, flags, body } => {
                [&[REPLY][..], &id.to_be_bytes(), &[*flags], body].concat()
            }
        }
    }
}

/// Reads one message. Messages longer than [`MAX_MESSAGE`] are malformed.
pub fn decode(message: &[u8]) -> Result<Message<'_>, DecodeError> {
    if message.len() > MAX_MESSAGE {
        return Err(DecodeError::BadBody);
    }
    let (&kind, body) = message.split_first().ok_or(DecodeError::Empty)?;
    match kind {
        AUTH => Ok(Message::Auth(body)),
        HELLO => decode_hello(body).map(Message::Hello),
        ACCEPT if body.is_empty() => Ok(Message::Accept),
        ACCEPT => Err(DecodeError::BadBody),
        REFUSE => String::from_utf8(body.to_vec())
            .map(Message::Refuse)
            .map_err(|_| DecodeError::BadBody),
        PACKET => Ok(Message::Packet(body)),
        REQUEST if body.len() >= 4 => Ok(Message::Request {
            id: u32::from_be_bytes(body[..4].try_into().unwrap()),
            body: &body[4..],
        }),
        REPLY if body.len() >= 5 => Ok(Message::Reply {
            id: u32::from_be_bytes(body[..4].try_into().unwrap()),
            flags: body[4],
            body: &body[5..],
        }),
        REQUEST | REPLY => Err(DecodeError::BadBody),
        other => Err(DecodeError::UnknownKind(other)),
    }
}

fn decode_hello(body: &[u8]) -> Result<Hello, DecodeError> {
    let mut rest = body;
    let mut take = |n: usize| -> Result<&[u8], DecodeError> {
        if rest.len() < n {
            return Err(DecodeError::BadBody);
        }
        let (head, tail) = rest.split_at(n);
        rest = tail;
        Ok(head)
    };
    let version = u16::from_be_bytes(take(2)?.try_into().unwrap());
    let mtu = u16::from_be_bytes(take(2)?.try_into().unwrap());
    let kind_len = take(1)?[0] as usize;
    let kind = take(kind_len)?;
    if !kind.is_ascii() {
        return Err(DecodeError::BadBody);
    }
    let kind = String::from_utf8(kind.to_vec()).unwrap();
    let name_len = take(1)?[0] as usize;
    let name = std::str::from_utf8(take(name_len)?)
        .map_err(|_| DecodeError::BadBody)?
        .to_owned();
    if !rest.is_empty() {
        return Err(DecodeError::BadBody);
    }
    Ok(Hello {
        version,
        mtu,
        kind,
        name,
    })
}

pub mod proxy;

/// Unix `SOCK_SEQPACKET` sockets: the local transport.
pub mod unix {
    use super::*;

    pub(crate) fn cvt(n: libc::c_int) -> io::Result<libc::c_int> {
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n)
        }
    }

    /// Sets a socket's receive or send timeout. `None` waits forever.
    pub fn set_timeout(
        fd: RawFd,
        option: libc::c_int,
        timeout: Option<Duration>,
    ) -> io::Result<()> {
        let tv = match timeout {
            Some(t) => libc::timeval {
                tv_sec: t.as_secs() as _,
                tv_usec: t.subsec_micros() as _,
            },
            None => libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
        };
        // SAFETY: setsockopt with a timeval.
        cvt(unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&raw const tv).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        })?;
        Ok(())
    }

    /// A `sockaddr_un` for `path`.
    pub fn address(path: &std::path::Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
        use std::os::unix::ffi::OsStrExt;
        // SAFETY: an all-zero sockaddr_un is valid.
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() || bytes.len() >= addr.sun_path.len() || bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bad Unix socket path",
            ));
        }
        for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
            *dst = *src as libc::c_char;
        }
        let len = std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1;
        Ok((addr, len as libc::socklen_t))
    }

    /// Raises a socket's send and receive buffers to 4 MiB, past the
    /// system limit if the process has CAP_NET_ADMIN, else as far as the
    /// limit allows. A seqpacket socket's default send buffer holds only
    /// about a hundred full-size packets, fewer than one TCP window, so a
    /// burst would lose packets. Failure is fine: the defaults still work.
    pub fn raise_buffers(fd: std::os::fd::RawFd) {
        let size: libc::c_int = 4 << 20;
        for (force, plain) in [
            (libc::SO_SNDBUFFORCE, libc::SO_SNDBUF),
            (libc::SO_RCVBUFFORCE, libc::SO_RCVBUF),
        ] {
            for opt in [force, plain] {
                // SAFETY: setsockopt with an int value.
                let r = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        opt,
                        (&raw const size).cast(),
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if r == 0 {
                    break;
                }
            }
        }
    }

    /// A new `SOCK_SEQPACKET` socket.
    pub(crate) fn socket(nonblocking: bool) -> io::Result<OwnedFd> {
        let mut ty = libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC;
        if nonblocking {
            ty |= libc::SOCK_NONBLOCK;
        }
        // SAFETY: plain syscall; the fd is owned from here.
        let fd = cvt(unsafe { libc::socket(libc::AF_UNIX, ty, 0) })?;
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// Connects to the world socket at `path`. The socket blocks.
    pub fn connect(path: impl AsRef<std::path::Path>) -> io::Result<OwnedFd> {
        let fd = socket(false)?;
        let (addr, len) = address(path.as_ref())?;
        loop {
            // SAFETY: `addr` is a valid sockaddr_un of length `len`.
            let r = unsafe { libc::connect(fd.as_raw_fd(), (&raw const addr).cast(), len) };
            if r == 0 {
                return Ok(fd);
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }

    /// Sets or clears `O_NONBLOCK`.
    pub fn set_nonblocking(fd: RawFd, nonblocking: bool) -> io::Result<()> {
        // SAFETY: fcntl on an fd the caller owns.
        let flags = cvt(unsafe { libc::fcntl(fd, libc::F_GETFL) })?;
        let flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        cvt(unsafe { libc::fcntl(fd, libc::F_SETFL, flags) })?;
        Ok(())
    }

    /// Sends one message as one datagram. With `nonblocking`, a full buffer
    /// is `WouldBlock` instead of a wait.
    pub fn send(fd: RawFd, message: &[u8], nonblocking: bool) -> io::Result<()> {
        send_parts(fd, &[message], nonblocking)
    }

    /// Sends the concatenation of `parts` as one datagram.
    pub fn send_parts(fd: RawFd, parts: &[&[u8]], nonblocking: bool) -> io::Result<()> {
        let iovec = |p: &&[u8]| libc::iovec {
            iov_base: p.as_ptr() as *mut libc::c_void,
            iov_len: p.len(),
        };
        // Every caller passes one or two parts (a kind byte or header, then
        // a payload), so those need no allocation.
        let mut stack = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }; 2];
        let mut heap: Vec<libc::iovec>;
        let iov: &mut [libc::iovec] = if parts.len() <= stack.len() {
            for (v, p) in stack.iter_mut().zip(parts) {
                *v = iovec(p);
            }
            &mut stack[..parts.len()]
        } else {
            heap = parts.iter().map(iovec).collect();
            &mut heap
        };
        // SAFETY: an all-zero msghdr is valid; the iovecs point into `parts`.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = iov.as_mut_ptr();
        msg.msg_iovlen = iov.len() as _;
        let mut flags = libc::MSG_NOSIGNAL;
        if nonblocking {
            flags |= libc::MSG_DONTWAIT;
        }
        loop {
            // SAFETY: `msg` is valid for the call.
            let n = unsafe { libc::sendmsg(fd, &msg, flags) };
            if n >= 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }

    /// Receives one datagram into `buf`. `Ok(0)` means the other side
    /// closed. A datagram longer than `buf` is cut to `buf.len()` bytes,
    /// so callers pass [`MAX_MESSAGE`] + 1 bytes. A length above
    /// [`MAX_MESSAGE`] marks an oversized or truncated message, which
    /// [`decode`] rejects.
    pub fn recv(fd: RawFd, buf: &mut [u8], nonblocking: bool) -> io::Result<usize> {
        let flags = if nonblocking { libc::MSG_DONTWAIT } else { 0 };
        loop {
            // SAFETY: `buf` is valid for writes of its length.
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), flags) };
            if n >= 0 {
                return Ok(n as usize);
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }

    /// Shuts the connection down both ways, so the other side reads its end.
    pub fn shutdown(fd: RawFd) {
        // SAFETY: plain syscall on an fd the caller owns.
        unsafe { libc::shutdown(fd, libc::SHUT_RDWR) };
    }
}

/// A blocking observer: connects to a world socket with an `observe`
/// hello, sends requests, and reads replies. Used by `fictionet observe`,
/// `fictionet dashboard`, and tests.
pub mod observer {
    use super::*;
    use crate::observe::json::Parser;

    /// One observer session.
    pub struct Client {
        fd: OwnedFd,
        next_id: u32,
        buf: Vec<u8>,
        partial: Option<Value>,
    }

    /// One whole value of a reply: its chunks joined.
    #[derive(Debug)]
    pub struct Value {
        /// The request this value answers.
        pub id: u32,
        /// The original bytes, without normalization or interpretation.
        pub bytes: Vec<u8>,
        /// The value is binary rather than JSON.
        pub binary: bool,
        /// No more replies come for this id.
        pub end: bool,
    }

    /// An observer event or error, inspected without changing the raw value.
    #[derive(Debug, PartialEq, Eq)]
    pub enum Envelope<'a> {
        /// A stream event with a string name and any JSON data.
        Event {
            /// The decoded event name.
            name: String,
            /// The exact JSON text of the data value, borrowed from the reply.
            data: &'a str,
        },
        /// The world's decoded error message.
        Error(String),
    }

    impl Value {
        /// Inspects a JSON event (`event` and `data`) or error (`error`).
        /// Field order, whitespace and string escapes do not affect inspection.
        /// Unknown fields are ignored. Names and errors must be strings; event
        /// data may be any JSON value. Duplicate envelope fields and objects
        /// mixing an error with event fields are not recognized.
        ///
        /// Recognition does not depend on size, element count or nesting depth.
        /// Data and unknown fields are validated without building a JSON tree.
        /// Returns `None` for binary values, other replies, invalid envelopes,
        /// invalid JSON or invalid UTF-8. The original bytes and flags are
        /// unchanged, including when inspection fails.
        pub fn envelope(&self) -> Option<Envelope<'_>> {
            if self.binary {
                return None;
            }
            let text = std::str::from_utf8(&self.bytes).ok()?;
            let mut p = Parser {
                b: text.as_bytes(),
                i: 0,
            };
            p.ws();
            p.eat(b'{')?;
            let (mut event, mut data, mut error) = (None, None, None);
            loop {
                p.ws();
                let key = p.string(true)?;
                p.ws();
                p.eat(b':')?;
                p.ws();
                match key.as_str() {
                    "event" | "error" => {
                        let slot = if key == "event" {
                            &mut event
                        } else {
                            &mut error
                        };
                        if slot.replace(p.string(true)?).is_some() {
                            return None;
                        }
                    }
                    "data" => {
                        let start = p.i;
                        p.skip_value()?;
                        if data.replace(&text[start..p.i]).is_some() {
                            return None;
                        }
                    }
                    _ => p.skip_value()?,
                }
                p.ws();
                if p.eat(b'}').is_some() {
                    break;
                }
                p.eat(b',')?;
            }
            p.ws();
            if p.i != text.len() {
                return None;
            }
            match (event, data, error) {
                (Some(name), Some(data), None) => Some(Envelope::Event { name, data }),
                (None, None, Some(error)) => Some(Envelope::Error(error)),
                _ => None,
            }
        }
    }

    impl Client {
        /// Connects to the world socket at `path` as an observer called
        /// `name`. Fails with the world's reason if it refuses.
        /// Sending hello and waiting for its answer each time out after
        /// 11 seconds. After acceptance, replies wait forever unless
        /// [`Self::set_timeout`] sets a limit.
        pub fn connect(path: &str, name: &str) -> Result<Client, String> {
            let fd = unix::connect(path)
                .map_err(|e| format!("connecting to the world at {path}: {e}"))?;
            Self::hello(fd, name, HANDSHAKE_TIMEOUT + Duration::from_secs(1))
        }

        fn hello(fd: OwnedFd, name: &str, timeout: Duration) -> Result<Client, String> {
            for option in [libc::SO_SNDTIMEO, libc::SO_RCVTIMEO] {
                unix::set_timeout(fd.as_raw_fd(), option, Some(timeout))
                    .map_err(|e| format!("setting the handshake timeout: {e}"))?;
            }
            let handshake_error = |e: io::Error| match e.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                    "the observer hello handshake timed out".to_owned()
                }
                _ => e.to_string(),
            };
            let hello = Hello {
                version: VERSION,
                mtu: 0,
                kind: OBSERVE.into(),
                name: name.into(),
            };
            unix::send(fd.as_raw_fd(), &Message::Hello(hello).encode(), false)
                .map_err(handshake_error)?;
            let mut client = Client {
                fd,
                next_id: 1,
                buf: vec![0; MAX_MESSAGE + 1],
                partial: None,
            };
            let n = unix::recv(client.fd.as_raw_fd(), &mut client.buf, false)
                .map_err(handshake_error)?;
            if n > MAX_MESSAGE {
                return Err("the world sent a message longer than 65,536 bytes".into());
            }
            match decode(&client.buf[..n]) {
                Ok(Message::Accept) => {
                    for option in [libc::SO_SNDTIMEO, libc::SO_RCVTIMEO] {
                        unix::set_timeout(client.fd.as_raw_fd(), option, None)
                            .map_err(|e| format!("clearing the handshake timeout: {e}"))?;
                    }
                    Ok(client)
                }
                Ok(Message::Refuse(reason)) => Err(format!("the world refused: {reason}")),
                _ if n == 0 => Err("the world closed the connection".into()),
                _ => Err("the world sent something other than accept".into()),
            }
        }

        /// Sends a request, a JSON object such as `{"op":"graph"}`, and
        /// returns its id.
        pub fn request(&mut self, json: &str) -> io::Result<u32> {
            let id = self.next_id;
            self.next_id += 1;
            unix::send(
                self.fd.as_raw_fd(),
                &Message::Request {
                    id,
                    body: json.as_bytes(),
                }
                .encode(),
                false,
            )?;
            Ok(id)
        }

        /// Waits for the next whole value, of any request. `None` once the
        /// world has closed the session between values. `WouldBlock` and
        /// `TimedOut` preserve partial values for the next call. EOF during a
        /// value returns `UnexpectedEof`. A malformed or oversized reply,
        /// invalid flags, or a continuation with a different id or binary flag
        /// shuts down the session and returns `InvalidData`.
        pub fn next_value(&mut self) -> io::Result<Option<Value>> {
            loop {
                let n = match unix::recv(self.fd.as_raw_fd(), &mut self.buf, false) {
                    Ok(n) => n,
                    Err(error) => {
                        if !matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) {
                            self.partial = None;
                        }
                        return Err(error);
                    }
                };
                if n > MAX_MESSAGE {
                    self.partial = None;
                    unix::shutdown(self.fd.as_raw_fd());
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the world sent a message longer than 65,536 bytes",
                    ));
                }
                if n == 0 {
                    if self.partial.take().is_some() {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "the world closed during a reply value",
                        ));
                    }
                    return Ok(None);
                }
                let Ok(Message::Reply { id, flags, body }) = decode(&self.buf[..n]) else {
                    self.partial = None;
                    unix::shutdown(self.fd.as_raw_fd());
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "not a reply"));
                };
                let binary = flags & BINARY != 0;
                if flags & !(MORE | END | BINARY) != 0
                    || flags & (MORE | END) == MORE | END
                    || self
                        .partial
                        .as_ref()
                        .is_some_and(|v| v.id != id || v.binary != binary)
                {
                    self.partial = None;
                    unix::shutdown(self.fd.as_raw_fd());
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid reply flags or continuation",
                    ));
                }
                let v = self.partial.get_or_insert_with(|| Value {
                    id,
                    bytes: Vec::new(),
                    binary,
                    end: false,
                });
                v.bytes.extend_from_slice(body);
                v.end = flags & END != 0;
                if flags & MORE == 0 {
                    return Ok(self.partial.take());
                }
            }
        }

        /// Sends a request and returns its first value.
        pub fn call(&mut self, json: &str) -> io::Result<Value> {
            self.request(json)?;
            self.next_value()?
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "the world closed"))
        }

        /// Gives up waiting for replies after `timeout`, or never.
        pub fn set_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            unix::set_timeout(self.fd.as_raw_fd(), libc::SO_RCVTIMEO, timeout)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn value(bytes: &[u8]) -> Value {
            Value {
                id: 7,
                bytes: bytes.to_vec(),
                binary: false,
                end: true,
            }
        }

        #[test]
        fn envelopes_ignore_json_formatting_and_keep_raw_values() {
            for (bytes, data) in [
                (
                    br#"{"event":"ended","data":{"n":1}}"#.as_slice(),
                    r#"{"n":1}"#,
                ),
                (
                    b" \n{ \"data\": { \"n\": 1 }, \"extra\": true, \"event\": \"ended\" }\t",
                    r#"{ "n": 1 }"#,
                ),
                (
                    br#"{"d\u0061ta":{"n":1},"ev\u0065nt":"end\u0065d"}"#,
                    r#"{"n":1}"#,
                ),
            ] {
                let value = value(bytes);
                assert_eq!(
                    value.envelope(),
                    Some(Envelope::Event {
                        name: "ended".into(),
                        data,
                    })
                );
                assert_eq!(value.bytes, bytes);
                assert_eq!(value.id, 7);
                assert!(!value.binary);
                assert!(value.end);
            }
            for bytes in [
                br#"{"error":"not found"}"#.as_slice(),
                b" \n{ \"extra\": 1, \"err\\u006fr\": \"not found\" }\n",
            ] {
                assert_eq!(
                    value(bytes).envelope(),
                    Some(Envelope::Error("not found".into()))
                );
            }
            assert!(matches!(
                value(br#"{"event":"custom","data":null}"#).envelope(),
                Some(Envelope::Event { data: "null", .. })
            ));
        }

        #[test]
        fn envelopes_validate_data_and_unknown_fields() {
            for data in [
                "null",
                "true",
                "false",
                "0",
                "-0",
                "1.25e+1234567890",
                r#""\"\\\/\b\f\n\r\t\u0000\uD83D\uDE00é""#,
                r#"[0, {"x": [true, false, null, [], {}]}, "text"]"#,
                r#"{ "x": 1, "x": 2 }"#,
            ] {
                let bytes = format!(r#"{{"extra":{data},"event":"custom","data": {data} }}"#);
                assert_eq!(
                    value(bytes.as_bytes()).envelope(),
                    Some(Envelope::Event {
                        name: "custom".into(),
                        data,
                    })
                );
            }
            assert_eq!(
                value(br#"{"err\u006fr":"\uD83D\uDE00\n"}"#).envelope(),
                Some(Envelope::Error("😀\n".into())),
            );
            for data in [
                "01",
                "-01",
                "+1",
                ".1",
                "1.",
                "1e",
                "1e+",
                "--1",
                "NaN",
                "True",
                "nul",
                "[1,]",
                "[,1]",
                "[1 2]",
                "[}",
                "{]",
                r#"{"x" 1}"#,
                r#"{"x":1,}"#,
                r#"{1:2}"#,
                r#"{"x":}"#,
                r#""\x00""#,
                r#""\u+123""#,
                r#""\uD83D""#,
                r#""\uDE00""#,
                r#""\uD83D\u0041""#,
                "\"raw\nline\"",
            ] {
                for bytes in [
                    format!(r#"{{"event":"custom","data":{data}}}"#),
                    format!(r#"{{"error":"x","extra":{data}}}"#),
                ] {
                    assert_eq!(value(bytes.as_bytes()).envelope(), None, "{bytes}");
                }
            }
        }

        #[test]
        fn envelopes_recognize_large_data_without_copying_it() {
            let data = format!("[{}0]", "0,      ".repeat(150_000));
            assert!(data.len() > 1024 * 1024);
            let bytes = format!(r#"{{"event":"snapshot","data":{data}}}"#);
            let value = value(bytes.as_bytes());
            let Some(Envelope::Event { name, data: raw }) = value.envelope() else {
                panic!("large snapshot was not recognized");
            };
            assert_eq!(name, "snapshot");
            assert_eq!(raw, data);
            assert!(value.bytes.as_ptr_range().contains(&raw.as_ptr()));
        }

        #[test]
        fn envelopes_handle_deep_data_without_recursion() {
            let data = format!("{}0{}", "[".repeat(200_000), "]".repeat(200_000));
            let bytes = format!(r#"{{"data":{data},"event":"snapshot"}}"#);
            assert_eq!(
                value(bytes.as_bytes()).envelope(),
                Some(Envelope::Event {
                    name: "snapshot".into(),
                    data: &data,
                })
            );
            let bytes = format!(r#"{{"data":{data},"extra":[{data},],"event":"snapshot"}}"#);
            assert_eq!(value(bytes.as_bytes()).envelope(), None);
        }

        #[test]
        fn invalid_envelopes_and_binary_values_are_not_inspected() {
            for bytes in [
                br#"{"event":"ended","data":}"#.as_slice(),
                br#"{"error":"truncated""#,
                br#"{"event":"ended","data":{}} false"#,
                br#"{"event":"ended"}"#,
                br#"{"event":false,"data":{}}"#,
                br#"{"error":null}"#,
                br#"{"event":"ended","data":{},"error":"x"}"#,
                br#"{"event":"ended","event":"node","data":{}}"#,
                br#"{"event":"ended","data":{},"d\u0061ta":null}"#,
                br#"{"error":"x","error":"y"}"#,
                br#"{"error":"x","data":null}"#,
                br#"{"event":"ended","data":{},}"#,
                br#"{"event":"\uD800","data":{}}"#,
                br#"{"error":"\uDC00"}"#,
                br#"{"error":"x","\uD800":0}"#,
                br#"{"nested":{"event":"ended","data":{}}}"#,
                br#"[{"error":"x"}]"#,
                b"{\"error\":\"\xff\"}",
                b"{\"error\":\"x\",\"extra\":\"\xff\"}",
            ] {
                assert_eq!(value(bytes).envelope(), None, "{bytes:?}");
            }
            let mut binary = value(br#"{"error":"x"}"#);
            binary.binary = true;
            assert_eq!(binary.envelope(), None);
            assert_eq!(binary.bytes, br#"{"error":"x"}"#);
        }

        fn pair() -> (OwnedFd, OwnedFd) {
            let mut fds = [-1; 2];
            // SAFETY: fds has space for both descriptors, owned from here.
            unsafe {
                assert_eq!(
                    libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()),
                    0
                );
                (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))
            }
        }

        #[test]
        fn hello_times_out_on_a_silent_peer() {
            let (fd, peer) = pair();
            let (tx, rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                tx.send(Client::hello(fd, "test", Duration::from_millis(20)).err())
                    .unwrap();
            });
            let result = rx.recv_timeout(Duration::from_secs(5));
            drop(peer);
            thread.join().unwrap();
            assert_eq!(
                result.unwrap().as_deref(),
                Some("the observer hello handshake timed out")
            );
        }

        #[test]
        fn accept_clears_both_hello_timeouts() {
            let (fd, peer) = pair();
            unix::send(peer.as_raw_fd(), &Message::Accept.encode(), false).unwrap();
            let mut client = Client::hello(fd, "test", Duration::from_millis(20)).unwrap();
            for option in [libc::SO_SNDTIMEO, libc::SO_RCVTIMEO] {
                let mut tv = libc::timeval {
                    tv_sec: -1,
                    tv_usec: -1,
                };
                let mut len = std::mem::size_of_val(&tv) as libc::socklen_t;
                // SAFETY: getsockopt writes a timeval into tv and its size into len.
                assert_eq!(
                    unsafe {
                        libc::getsockopt(
                            client.fd.as_raw_fd(),
                            libc::SOL_SOCKET,
                            option,
                            (&raw mut tv).cast(),
                            &mut len,
                        )
                    },
                    0
                );
                assert_eq!((tv.tv_sec, tv.tv_usec), (0, 0));
            }
            client.set_timeout(Some(Duration::from_millis(20))).unwrap();
            assert_eq!(
                client.next_value().unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_enforces_the_message_limit() {
        for kind in [AUTH, REFUSE, PACKET, REQUEST, REPLY] {
            let mut frame = vec![b'x'; MAX_MESSAGE];
            frame[0] = kind;
            assert!(decode(&frame).is_ok());
            frame.push(b'x');
            assert_eq!(decode(&frame), Err(DecodeError::BadBody));
        }
    }

    #[test]
    fn observer_messages_round_trip() {
        let req = Message::Request {
            id: 7,
            body: br#"{"op":"graph"}"#,
        };
        let bytes = req.encode();
        assert_eq!(&bytes[..5], &[5, 0, 0, 0, 7]);
        assert_eq!(decode(&bytes), Ok(req));
        let reply = Message::Reply {
            id: 7,
            flags: MORE | BINARY,
            body: &[1, 2],
        };
        let bytes = reply.encode();
        assert_eq!(bytes, [6, 0, 0, 0, 7, 5, 1, 2]);
        assert_eq!(decode(&bytes), Ok(reply));
        assert_eq!(decode(&[5, 0, 0]), Err(DecodeError::BadBody));
        assert_eq!(decode(&[6, 0, 0, 0, 1]), Err(DecodeError::BadBody));
    }

    #[test]
    fn hello_round_trip() {
        let hello = Hello {
            version: 1,
            mtu: 1500,
            kind: "tun".into(),
            name: "abc".into(),
        };
        let bytes = Message::Hello(hello.clone()).encode();
        assert_eq!(
            bytes,
            [1, 0, 1, 5, 220, 3, b't', b'u', b'n', 3, b'a', b'b', b'c']
        );
        assert_eq!(decode(&bytes), Ok(Message::Hello(hello)));
    }

    #[test]
    fn other_messages() {
        assert_eq!(decode(&Message::Accept.encode()), Ok(Message::Accept));
        assert_eq!(
            decode(&Message::Refuse("no".into()).encode()),
            Ok(Message::Refuse("no".into()))
        );
        assert_eq!(
            decode(&Message::Packet(&[1, 2, 3]).encode()),
            Ok(Message::Packet(&[1, 2, 3]))
        );
        assert_eq!(decode(&[9]), Err(DecodeError::UnknownKind(9)));
        assert_eq!(decode(&[7]), Err(DecodeError::UnknownKind(7)));
        assert_eq!(decode(&[]), Err(DecodeError::Empty));
        assert_eq!(decode(&[1, 0, 1]), Err(DecodeError::BadBody));
        // Trailing bytes after the name.
        assert_eq!(
            decode(&[1, 0, 1, 5, 220, 0, 1, b'a', 0]),
            Err(DecodeError::BadBody)
        );
    }
}
