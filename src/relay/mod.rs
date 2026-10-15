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

mod wire;
pub use wire::*;

pub mod proxy;

/// Unix `SOCK_SEQPACKET` sockets: the local transport.
pub mod unix;

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
