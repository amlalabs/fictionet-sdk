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
