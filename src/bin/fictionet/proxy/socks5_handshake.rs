//! The SOCKS5 door, `--type socks5` (RFC 1928, with RFC 1929's
//! username/password method).
//!
//! Only `CONNECT` is served. A target given as a name (`socks5h://` in
//! curl, `ATYP` 3) is looked up in the world. `BIND` and `UDP ASSOCIATE`
//! get reply 7, "command not supported", and IPv6 targets reply 8,
//! "address type not supported". The client must offer the
//! username/password method and give the sandbox's token as the password.
//!
//! The handshake is read with [`socks::ClientMessages`].

use std::net::SocketAddrV4;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use fictionet::stdlib::codec::{Fail, Stream, Wire};
use fictionet::stdlib::socks::{
    self, Address, AuthReply, ClientMessage, ClientMessages, Command, FrameError, Method, Reply,
    ReplyCode, Selection,
};

use fictionet::relay::proxy::Host;
use fictionet::relay::proxy::auth::Token;

/// How the handshake ended without a target.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Not SOCKS5, or cut short: closed with no answer.
    Malformed(&'static str),
    /// The client did not offer username/password: answered `0xff`.
    NoMethod,
    /// The wrong token, or none: answered with status 1.
    BadToken,
    /// Answered with this reply code.
    Reply(ReplyCode, &'static str),
}

/// A `CONNECT` the handshake accepted, before any reply to it.
#[derive(Debug, PartialEq, Eq)]
pub struct Connect {
    pub host: Host,
    pub port: u16,
    /// Bytes the client sent after its request, without waiting for the
    /// reply. They belong to the tunnel.
    pub early: Vec<u8>,
}

const SHORT: Refusal = Refusal::Malformed("the client closed the connection during the handshake");

/// Runs the handshake up to the request: greeting, login, request.
/// Returns the target, or why there is none, after answering the client.
pub async fn handshake<S>(s: &mut S, token: &Token) -> Result<Connect, Refusal>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = Stream::new(ClientMessages::new());
    loop {
        let phase = stream.decoder().phase();
        let message = match stream.next() {
            Some(Ok(Ok(message))) => message,
            Some(Ok(Err(e))) => {
                let why = match e {
                    socks::Error::Command(_) => "only CONNECT is supported",
                    socks::Error::AddressType(_) => "unknown address type",
                    _ => "the request is malformed",
                };
                return Err(refuse(s, e.reply_code(), why).await);
            }
            Some(Err(Fail::Protocol(FrameError::AddressType(_)))) => {
                return Err(refuse(
                    s,
                    ReplyCode::AddressTypeNotSupported,
                    "unknown address type",
                )
                .await);
            }
            Some(Err(Fail::Protocol(FrameError::Version(_)))) => {
                return Err(Refusal::Malformed(if phase == socks::ServerPhase::Auth {
                    "not version 1 of the username/password method"
                } else {
                    "not SOCKS version 5"
                }));
            }
            Some(Err(_)) => return Err(SHORT),
            None if stream.is_done() => return Err(SHORT),
            None => {
                let spare = stream.spare();
                if spare.is_empty() {
                    return Err(SHORT);
                }
                match s.read(spare).await {
                    Ok(0) | Err(_) => stream.end(),
                    Ok(n) => stream.commit(n),
                }
                continue;
            }
        };
        match message {
            ClientMessage::Greeting(g) => {
                if !g.methods.contains(&Method::UsernamePassword) {
                    let _ = s
                        .write_all(&write(&Selection {
                            method: Method::NoAcceptable,
                        }))
                        .await;
                    return Err(Refusal::NoMethod);
                }
                s.write_all(&write(&Selection {
                    method: Method::UsernamePassword,
                }))
                .await
                .map_err(|_| SHORT)?;
                stream.decoder().select(Method::UsernamePassword);
            }
            ClientMessage::Auth(login) => {
                // The token may be the password, or the username with no
                // password. Both are checked, so the time taken does not
                // say which one matched.
                let ok = token.matches(&login.password)
                    | (login.password.is_empty() & token.matches(&login.username));
                stream.decoder().verified(ok);
                if !ok {
                    let _ = s.write_all(&write(&AuthReply { status: 1 })).await;
                    return Err(Refusal::BadToken);
                }
                s.write_all(&write(&AuthReply {
                    status: socks::AUTH_SUCCESS,
                }))
                .await
                .map_err(|_| SHORT)?;
            }
            ClientMessage::Request(req) => {
                if req.command != Command::Connect {
                    return Err(refuse(
                        s,
                        ReplyCode::CommandNotSupported,
                        "only CONNECT is supported",
                    )
                    .await);
                }
                let host = match &req.address {
                    Address::Ipv4(a) => Host::V4(*a),
                    Address::Ipv6(_) => {
                        return Err(refuse(
                            s,
                            ReplyCode::AddressTypeNotSupported,
                            "IPv6 is not supported",
                        )
                        .await);
                    }
                    Address::Domain(name) => {
                        match std::str::from_utf8(name).ok().and_then(Host::parse) {
                            Some(Host::V6(_)) => {
                                return Err(refuse(
                                    s,
                                    ReplyCode::AddressTypeNotSupported,
                                    "IPv6 is not supported",
                                )
                                .await);
                            }
                            Some(host) => host,
                            None => {
                                return Err(refuse(
                                    s,
                                    ReplyCode::HostUnreachable,
                                    "the name is not a valid host name",
                                )
                                .await);
                            }
                        }
                    }
                };
                return Ok(Connect {
                    host,
                    port: req.port,
                    early: stream.unread().to_vec(),
                });
            }
            ClientMessage::Socks4(_) => return Err(Refusal::Malformed("not SOCKS version 5")),
        }
    }
}

fn write<W: Wire>(value: &W) -> Vec<u8>
where
    W::WriteError: std::fmt::Debug,
{
    value
        .to_bytes()
        .expect("the door writes only values it can")
}

async fn refuse<W: AsyncWrite + Unpin>(w: &mut W, code: ReplyCode, why: &'static str) -> Refusal {
    let _ = w.write_all(&reply(code, None)).await;
    Refusal::Reply(code, why)
}

/// The reply: VER, REP, RSV, ATYP 1, BND.ADDR, BND.PORT.
pub fn reply(code: ReplyCode, bound: Option<SocketAddrV4>) -> Vec<u8> {
    let bound = bound.unwrap_or(SocketAddrV4::new([0, 0, 0, 0].into(), 0));
    write(&Reply {
        code,
        address: Address::Ipv4(*bound.ip()),
        port: bound.port(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::duplex;

    fn token() -> Token {
        Token::new(b"tok").unwrap()
    }

    fn login(user: &[u8], password: &[u8]) -> Vec<u8> {
        let mut v = vec![1, user.len() as u8];
        v.extend_from_slice(user);
        v.push(password.len() as u8);
        v.extend_from_slice(password);
        v
    }

    /// Feeds `input` to the handshake and returns its result and every
    /// byte it wrote back.
    pub(crate) fn run(input: Vec<u8>) -> (Result<Connect, Refusal>, Vec<u8>) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let (mut client, mut server) = duplex(4096);
            client.write_all(&input).await.unwrap();
            client.shutdown().await.unwrap();
            let r = handshake(&mut server, &token()).await;
            drop(server);
            let mut out = Vec::new();
            client.read_to_end(&mut out).await.unwrap();
            (r, out)
        })
    }

    fn connect_by_name(name: &str, port: u16) -> Vec<u8> {
        let mut v = vec![5, 1, 0, 3, name.len() as u8];
        v.extend_from_slice(name.as_bytes());
        v.extend_from_slice(&port.to_be_bytes());
        v
    }

    fn full(request: &[u8]) -> Vec<u8> {
        [&[5, 2, 0, 2][..], &login(b"relay", b"tok"), request].concat()
    }

    fn target(r: Result<Connect, Refusal>) -> Result<(Host, u16), Refusal> {
        r.map(|c| (c.host, c.port))
    }

    #[test]
    fn connect_by_name_and_by_address() {
        let (r, out) = run(full(&connect_by_name("Example.Test", 443)));
        assert_eq!(target(r), Ok((Host::Name("example.test".into()), 443)));
        assert_eq!(out, [5, 2, 1, 0]);
        let (r, _) = run(full(&[5, 1, 0, 1, 203, 0, 113, 10, 0, 80]));
        assert_eq!(
            target(r),
            Ok((Host::V4(Ipv4Addr::new(203, 0, 113, 10)), 80))
        );
        // The token as the username, with no password.
        let (r, _) = run([
            &[5, 1, 2][..],
            &login(b"tok", b""),
            &connect_by_name("a.test", 1),
        ]
        .concat());
        assert_eq!(target(r), Ok((Host::Name("a.test".into()), 1)));
    }

    #[test]
    fn bytes_sent_ahead_of_the_reply_go_to_the_tunnel() {
        // The whole handshake and the start of a TLS ClientHello in one
        // write: the door reads past the request, and hands that on.
        let (r, out) = run([full(&connect_by_name("a.test", 443)), vec![0x16, 3, 1]].concat());
        assert_eq!(r.unwrap().early, [0x16, 3, 1]);
        assert_eq!(out, [5, 2, 1, 0]);
    }

    #[test]
    fn a_bad_or_missing_token_is_refused() {
        let (r, out) = run([&[5, 1, 2][..], &login(b"relay", b"nope")].concat());
        assert_eq!(r, Err(Refusal::BadToken));
        assert_eq!(out, [5, 2, 1, 1]);
        // Only "no authentication" offered.
        let (r, out) = run(vec![5, 1, 0]);
        assert_eq!(r, Err(Refusal::NoMethod));
        assert_eq!(out, [5, 0xff]);
        let (r, _) = run([&[5, 1, 2][..], &login(b"", b"")].concat());
        assert_eq!(r, Err(Refusal::BadToken));
    }

    #[test]
    fn other_commands_and_address_types() {
        // BIND and UDP ASSOCIATE.
        for cmd in [2, 3] {
            let (r, out) = run(full(&[5, cmd, 0, 1, 10, 0, 0, 1, 0, 53]));
            assert_eq!(
                r,
                Err(Refusal::Reply(
                    ReplyCode::CommandNotSupported,
                    "only CONNECT is supported"
                ))
            );
            assert_eq!(&out[4..], [5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
        // A command SOCKS5 does not have.
        let (r, out) = run(full(&[5, 9, 0, 1, 10, 0, 0, 1, 0, 53]));
        assert_eq!(
            r,
            Err(Refusal::Reply(
                ReplyCode::CommandNotSupported,
                "only CONNECT is supported"
            ))
        );
        assert_eq!(out[5], 7);
        // IPv6, as an address and as a name.
        let mut v6 = vec![5, 1, 0, 4];
        v6.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        v6.extend_from_slice(&[1, 187]);
        let (r, out) = run(full(&v6));
        assert_eq!(
            r,
            Err(Refusal::Reply(
                ReplyCode::AddressTypeNotSupported,
                "IPv6 is not supported"
            ))
        );
        assert_eq!(out[5], 8);
        let (r, _) = run(full(&connect_by_name("[fd00::1]", 443)));
        assert_eq!(
            r,
            Err(Refusal::Reply(
                ReplyCode::AddressTypeNotSupported,
                "IPv6 is not supported"
            ))
        );
        // An unknown address type.
        let (r, out) = run(full(&[5, 1, 0, 9]));
        assert_eq!(
            r,
            Err(Refusal::Reply(
                ReplyCode::AddressTypeNotSupported,
                "unknown address type"
            ))
        );
        assert_eq!(out[5], 8);
        // A name that is not a host name.
        let (r, out) = run(full(&connect_by_name("a b", 80)));
        assert_eq!(
            r,
            Err(Refusal::Reply(
                ReplyCode::HostUnreachable,
                "the name is not a valid host name"
            ))
        );
        assert_eq!(out[5], 4);
    }

    #[test]
    fn malformed_and_short_input_closes() {
        assert_eq!(run(vec![4, 1, 0, 80]).0, Err(SHORT));
        assert_eq!(
            run(b"GET / HTTP/1.1\r\n\r\n".to_vec()).0,
            Err(Refusal::Malformed("not SOCKS version 5"))
        );
        let whole = full(&connect_by_name("example.test", 443));
        for n in 0..whole.len() {
            let (r, _) = run(whole[..n].to_vec());
            assert!(matches!(r, Err(Refusal::Malformed(_))), "cut at {n}: {r:?}");
        }
        // Login with version 2, and a request with version 4.
        assert_eq!(
            run([&[5, 1, 2, 2][..], &[0, 0]].concat()).0,
            Err(Refusal::Malformed(
                "not version 1 of the username/password method"
            ))
        );
        assert_eq!(
            run(full(&[4, 1, 0, 1, 10, 0, 0, 1, 0, 53])).0,
            Err(Refusal::Malformed("not SOCKS version 5"))
        );
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..2000 {
            let mut v = Vec::new();
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let len = (seed % 64) as usize;
            // Start like a real client half the time, so the later steps
            // see random bytes too.
            if seed & 1 == 0 {
                v.extend_from_slice(&[5, 1, 2, 1, 0, 3, b't', b'o', b'k']);
            }
            for _ in 0..len {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                v.push(seed as u8);
            }
            let _ = run(v);
        }
    }

    #[test]
    fn replies() {
        assert_eq!(
            reply(
                ReplyCode::Succeeded,
                Some("10.0.0.2:50000".parse().unwrap())
            ),
            [5, 0, 0, 1, 10, 0, 0, 2, 0xc3, 0x50]
        );
        assert_eq!(
            reply(ReplyCode::ConnectionRefused, None),
            [5, 5, 0, 1, 0, 0, 0, 0, 0, 0]
        );
    }
}
