//! The SOCKS5 door, `--type socks5` (RFC 1928, with RFC 1929's
//! username/password method).
//!
//! Only `CONNECT` is served. A target given as a name (`socks5h://` in
//! curl, `ATYP` 3) is looked up in the world. `BIND` and `UDP ASSOCIATE`
//! get reply 7, "command not supported", and IPv6 targets reply 8,
//! "address type not supported". The client must offer the
//! username/password method and give the sandbox's token as the password.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::auth::Token;
use fictionet::tokio::ConnectionTokioExt;

use super::log;
use super::pump;
use super::stack::{Fail, Host, Stack};

/// The greeting, the login and the request must all arrive within this.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const VERSION: u8 = 5;
const USER_PASSWORD: u8 = 2;
const NO_METHOD: u8 = 0xff;

/// Reply codes (RFC 1928, section 6).
pub(crate) mod reply {
    pub(crate) const SUCCEEDED: u8 = 0;
    pub(crate) const GENERAL_FAILURE: u8 = 1;
    pub(crate) const NETWORK_UNREACHABLE: u8 = 3;
    pub(crate) const HOST_UNREACHABLE: u8 = 4;
    pub(crate) const REFUSED: u8 = 5;
    pub(crate) const TTL_EXPIRED: u8 = 6;
    pub(crate) const COMMAND_NOT_SUPPORTED: u8 = 7;
    pub(crate) const ADDRESS_NOT_SUPPORTED: u8 = 8;
}

/// The reply code a failed connection gets.
pub(crate) fn reply_for(fail: &Fail) -> u8 {
    match fail {
        Fail::NoSuchName | Fail::Dns(_) => reply::HOST_UNREACHABLE,
        Fail::Refused | Fail::Unreachable(3) => reply::REFUSED,
        Fail::Unreachable(0) => reply::NETWORK_UNREACHABLE,
        Fail::Unreachable(_) => reply::HOST_UNREACHABLE,
        Fail::TimedOut => reply::TTL_EXPIRED,
        Fail::WorldGone => reply::GENERAL_FAILURE,
        Fail::BadAddress(_) => reply::ADDRESS_NOT_SUPPORTED,
    }
}

/// How the handshake ended without a target.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Not SOCKS5, or cut short: closed with no answer.
    Malformed(&'static str),
    /// The client did not offer username/password: answered `0xff`.
    NoMethod,
    /// The wrong token, or none: answered with status 1.
    BadToken,
    /// Answered with this reply code.
    Reply(u8, &'static str),
}

/// Runs the handshake up to the request: greeting, login, request.
/// Returns the target, or why there is none, after answering the client.
pub(crate) async fn handshake<S>(s: &mut S, token: &Token) -> Result<(Host, u16), Refusal>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let short = |_| Refusal::Malformed("the client closed the connection during the handshake");
    // Greeting: VER, NMETHODS, METHODS.
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await.map_err(short)?;
    if head[0] != VERSION {
        return Err(Refusal::Malformed("not SOCKS version 5"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    s.read_exact(&mut methods).await.map_err(short)?;
    if !methods.contains(&USER_PASSWORD) {
        let _ = s.write_all(&[VERSION, NO_METHOD]).await;
        return Err(Refusal::NoMethod);
    }
    s.write_all(&[VERSION, USER_PASSWORD]).await.map_err(short)?;

    // Login (RFC 1929): VER 1, ULEN, UNAME, PLEN, PASSWD.
    let mut ver = [0u8; 2];
    s.read_exact(&mut ver).await.map_err(short)?;
    if ver[0] != 1 {
        return Err(Refusal::Malformed("not version 1 of the username/password method"));
    }
    let mut user = vec![0u8; ver[1] as usize];
    s.read_exact(&mut user).await.map_err(short)?;
    let mut plen = [0u8; 1];
    s.read_exact(&mut plen).await.map_err(short)?;
    let mut password = vec![0u8; plen[0] as usize];
    s.read_exact(&mut password).await.map_err(short)?;
    // The token may be the password, or the username with no password.
    let ok = token.matches(&password) | (password.is_empty() & token.matches(&user));
    if !ok {
        let _ = s.write_all(&[1, 1]).await;
        return Err(Refusal::BadToken);
    }
    s.write_all(&[1, 0]).await.map_err(short)?;

    // Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT.
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await.map_err(short)?;
    if req[0] != VERSION {
        return Err(Refusal::Malformed("not SOCKS version 5"));
    }
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).await.map_err(short)?;
            Some(Host::V4(Ipv4Addr::from(a)))
        }
        3 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await.map_err(short)?;
            let mut name = vec![0u8; len[0] as usize];
            s.read_exact(&mut name).await.map_err(short)?;
            std::str::from_utf8(&name).ok().and_then(Host::parse)
        }
        4 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a).await.map_err(short)?;
            Some(Host::V6(a.into()))
        }
        _ => {
            send_reply(s, reply::ADDRESS_NOT_SUPPORTED, None).await;
            return Err(Refusal::Reply(reply::ADDRESS_NOT_SUPPORTED, "unknown address type"));
        }
    };
    let mut port = [0u8; 2];
    s.read_exact(&mut port).await.map_err(short)?;
    let port = u16::from_be_bytes(port);
    if req[1] != 1 {
        send_reply(s, reply::COMMAND_NOT_SUPPORTED, None).await;
        return Err(Refusal::Reply(reply::COMMAND_NOT_SUPPORTED, "only CONNECT is supported"));
    }
    let Some(host) = host else {
        send_reply(s, reply::HOST_UNREACHABLE, None).await;
        return Err(Refusal::Reply(reply::HOST_UNREACHABLE, "the name is not a valid host name"));
    };
    if matches!(host, Host::V6(_)) {
        send_reply(s, reply::ADDRESS_NOT_SUPPORTED, None).await;
        return Err(Refusal::Reply(reply::ADDRESS_NOT_SUPPORTED, "IPv6 is not supported"));
    }
    Ok((host, port))
}

/// The reply: VER, REP, RSV, ATYP 1, BND.ADDR, BND.PORT.
pub(crate) fn reply_bytes(code: u8, bound: Option<SocketAddr>) -> [u8; 10] {
    let (ip, port) = match bound {
        Some(SocketAddr::V4(a)) => (a.ip().octets(), a.port()),
        _ => ([0; 4], 0),
    };
    let p = port.to_be_bytes();
    [VERSION, code, 0, 1, ip[0], ip[1], ip[2], ip[3], p[0], p[1]]
}

async fn send_reply<W: AsyncWrite + Unpin>(w: &mut W, code: u8, bound: Option<SocketAddr>) {
    let _ = w.write_all(&reply_bytes(code, bound)).await;
}

/// Serves one client connection.
pub(crate) async fn serve(mut client: TcpStream, stack: Stack, token: Token) {
    let (host, port) = match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&mut client, &token)).await {
        Err(_) => return log("socks5: no whole handshake within 10 s"),
        Ok(Ok(target)) => target,
        Ok(Err(Refusal::Malformed(why))) => return log(&format!("socks5: {why}")),
        Ok(Err(Refusal::NoMethod)) => return log("socks5: the client did not offer username/password"),
        Ok(Err(Refusal::BadToken)) => return log("socks5: wrong token"),
        Ok(Err(Refusal::Reply(code, why))) => return log(&format!("socks5: reply {code}, {why}")),
    };
    let what = format!("socks5 CONNECT {host}:{port}");
    let started = Instant::now();
    let (conn, addr) = match stack.connect(&host, port).await {
        Ok(c) => c,
        Err(fail) => {
            let code = reply_for(&fail);
            log(&format!("{what} reply {code}, {fail}"));
            send_reply(&mut client, code, None).await;
            return;
        }
    };
    let bound = conn.local_addr();
    let mut world = conn.into_tokio(stack.cx());
    if client.write_all(&reply_bytes(reply::SUCCEEDED, Some(bound))).await.is_err() {
        return log(&format!("{what} ({}) reply 0, but the client closed the connection first", IpAddr::V4(addr)));
    }
    let (moved, error) = pump::tunnel(&mut client, &mut world).await;
    let end = error.map(|e| format!(", ended early by {e}")).unwrap_or_default();
    log(&format!(
        "{what} ({}) reply 0, {} bytes up, {} down, {:.3} s{end}",
        IpAddr::V4(addr),
        moved.up,
        moved.down,
        started.elapsed().as_secs_f64()
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn run(input: Vec<u8>) -> (Result<(Host, u16), Refusal>, Vec<u8>) {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
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
        [&[5, 2, 0, 2][..], &login(b"fictionet", b"tok"), request].concat()
    }

    #[test]
    fn connect_by_name_and_by_address() {
        let (r, out) = run(full(&connect_by_name("Example.Test", 443)));
        assert_eq!(r, Ok((Host::Name("example.test".into()), 443)));
        assert_eq!(out, [5, 2, 1, 0]);
        let (r, _) = run(full(&[5, 1, 0, 1, 203, 0, 113, 10, 0, 80]));
        assert_eq!(r, Ok((Host::V4(Ipv4Addr::new(203, 0, 113, 10)), 80)));
        // The token as the username, with no password.
        let (r, _) = run([&[5, 1, 2][..], &login(b"tok", b""), &connect_by_name("a.test", 1)].concat());
        assert_eq!(r, Ok((Host::Name("a.test".into()), 1)));
    }

    #[test]
    fn a_bad_or_missing_token_is_refused() {
        let (r, out) = run([&[5, 1, 2][..], &login(b"fictionet", b"nope")].concat());
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
            assert_eq!(r, Err(Refusal::Reply(7, "only CONNECT is supported")));
            assert_eq!(&out[4..], [5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
        // IPv6.
        let mut v6 = vec![5, 1, 0, 4];
        v6.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        v6.extend_from_slice(&[1, 187]);
        let (r, out) = run(full(&v6));
        assert_eq!(r, Err(Refusal::Reply(8, "IPv6 is not supported")));
        assert_eq!(out[5], 8);
        // An unknown address type.
        let (r, out) = run(full(&[5, 1, 0, 9]));
        assert_eq!(r, Err(Refusal::Reply(8, "unknown address type")));
        assert_eq!(out[5], 8);
        // A name that is not a host name.
        let (r, out) = run(full(&connect_by_name("a b", 80)));
        assert_eq!(r, Err(Refusal::Reply(4, "the name is not a valid host name")));
        assert_eq!(out[5], 4);
    }

    #[test]
    fn malformed_and_short_input_closes() {
        assert!(matches!(run(vec![4, 1, 0, 80]).0, Err(Refusal::Malformed(_))));
        assert!(matches!(run(b"GET / HTTP/1.1\r\n\r\n".to_vec()).0, Err(Refusal::Malformed(_))));
        let whole = full(&connect_by_name("example.test", 443));
        for n in 0..whole.len() {
            let (r, _) = run(whole[..n].to_vec());
            assert!(matches!(r, Err(Refusal::Malformed(_))), "cut at {n}: {r:?}");
        }
        // Login with version 2.
        assert!(matches!(run([&[5, 1, 2, 2][..], &[0, 0]].concat()).0, Err(Refusal::Malformed(_))));
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
        assert_eq!(reply_bytes(0, Some("10.0.0.2:50000".parse().unwrap())), [5, 0, 0, 1, 10, 0, 0, 2, 0xc3, 0x50]);
        assert_eq!(reply_bytes(5, None), [5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(reply_for(&Fail::NoSuchName), reply::HOST_UNREACHABLE);
        assert_eq!(reply_for(&Fail::Refused), reply::REFUSED);
        assert_eq!(reply_for(&Fail::Unreachable(1)), reply::HOST_UNREACHABLE);
        assert_eq!(reply_for(&Fail::Unreachable(0)), reply::NETWORK_UNREACHABLE);
        assert_eq!(reply_for(&Fail::TimedOut), reply::TTL_EXPIRED);
        assert_eq!(reply_for(&Fail::WorldGone), reply::GENERAL_FAILURE);
    }
}
