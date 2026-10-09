//! The SOCKS5 door, `--type socks5`, served over a client's TCP
//! connection. The handshake is [`super::socks5_handshake`].

use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::socks5_handshake::{Connect, Refusal, handshake, reply};
use fictionet::relay::proxy::auth::Token;
use fictionet::stdlib::socks::ReplyCode;
use fictionet::tokio::ConnectionTokioExt;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::log;
use super::pump;
use super::stack::{Fail, Stack};

/// The greeting, the login and the request must all arrive within this.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The reply code a failed connection gets.
pub(crate) fn reply_for(fail: &Fail) -> ReplyCode {
    match fail {
        Fail::NoSuchName | Fail::Dns(_) => ReplyCode::HostUnreachable,
        Fail::Refused | Fail::Unreachable(3) => ReplyCode::ConnectionRefused,
        Fail::Unreachable(0) => ReplyCode::NetworkUnreachable,
        Fail::Unreachable(_) => ReplyCode::HostUnreachable,
        Fail::TimedOut => ReplyCode::TtlExpired,
        Fail::WorldGone => ReplyCode::GeneralFailure,
        Fail::BadAddress(_) => ReplyCode::AddressTypeNotSupported,
    }
}

async fn send_reply<W: AsyncWrite + Unpin>(w: &mut W, code: ReplyCode) {
    let _ = w.write_all(&reply(code, None)).await;
}

/// Serves one client connection.
pub(crate) async fn serve(mut client: TcpStream, stack: Stack, token: Token) {
    let Connect { host, port, early } =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake(&mut client, &token)).await {
            Err(_) => return log("socks5: no whole handshake within 10 s"),
            Ok(Ok(connect)) => connect,
            Ok(Err(Refusal::Malformed(why))) => return log(&format!("socks5: {why}")),
            Ok(Err(Refusal::NoMethod)) => {
                return log("socks5: the client did not offer username/password");
            }
            Ok(Err(Refusal::BadToken)) => return log("socks5: wrong token"),
            Ok(Err(Refusal::Reply(code, why))) => {
                return log(&format!("socks5: reply {}, {why}", code.code()));
            }
        };
    let what = format!("socks5 CONNECT {host}:{port}");
    let started = Instant::now();
    let (conn, addr) = match stack.connect(&host, port).await {
        Ok(c) => c,
        Err(fail) => {
            let code = reply_for(&fail);
            log(&format!("{what} reply {}, {fail}", code.code()));
            send_reply(&mut client, code).await;
            return;
        }
    };
    let bound = match conn.local_addr() {
        std::net::SocketAddr::V4(a) => Some(a),
        std::net::SocketAddr::V6(_) => None,
    };
    let mut world = conn.into_tokio(stack.fcx());
    if client
        .write_all(&reply(ReplyCode::Succeeded, bound))
        .await
        .is_err()
    {
        return log(&format!(
            "{what} ({}) reply 0, but the client closed the connection first",
            IpAddr::V4(addr)
        ));
    }
    if !early.is_empty() && world.write_all(&early).await.is_err() {
        return log(&format!(
            "{what} ({}) reply 0, but the site closed the connection first",
            IpAddr::V4(addr)
        ));
    }
    let (moved, error) = pump::tunnel(&mut client, &mut world).await;
    let end = error
        .map(|e| format!(", ended early by {e}"))
        .unwrap_or_default();
    log(&format!(
        "{what} ({}) reply 0, {} bytes up, {} down, {:.3} s{end}",
        IpAddr::V4(addr),
        moved.up + early.len() as u64,
        moved.down,
        started.elapsed().as_secs_f64()
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_map_to_reply_codes() {
        assert_eq!(reply_for(&Fail::NoSuchName), ReplyCode::HostUnreachable);
        assert_eq!(reply_for(&Fail::Refused), ReplyCode::ConnectionRefused);
        assert_eq!(reply_for(&Fail::Unreachable(1)), ReplyCode::HostUnreachable);
        assert_eq!(
            reply_for(&Fail::Unreachable(0)),
            ReplyCode::NetworkUnreachable
        );
        assert_eq!(reply_for(&Fail::TimedOut), ReplyCode::TtlExpired);
        assert_eq!(reply_for(&Fail::WorldGone), ReplyCode::GeneralFailure);
    }
}
