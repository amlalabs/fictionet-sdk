// A route that changes mid-run: after a delay, the bank's address leads
// to an impostor machine instead of the bank. This is the core of a BGP
// hijack, which examples/border plays out in full.
//
//     cargo run --example route_change -- /run/fictionet/world.sock 20

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fictionet::prelude::*;
use fictionet::stdlib::{ip, route, tcp};
use fictionet::time::Duration;
use fictionet::{Cx, Interface, pair};

/// The agent decides how many connections it opens and how slowly it
/// sends, so each machine serves at most this many at once ...
const MAX_CONNECTIONS: usize = 64;
/// ... and gives each one this long to send its request and read the
/// answer. Every connection ends with a reset, which removes its socket
/// without waiting for the client, so the client cannot keep sockets
/// open past the count.
const TIME_LIMIT: Duration = Duration::from_secs(10);

/// Starts a machine at `addr` on `side` that answers every HTTP request
/// on port 80 with `body`.
fn web_machine(fcx: &Cx, side: impl Interface, addr: IpAddr, body: &'static str) -> fictionet::Result {
    let (tcp, _udp, _icmp, _other) = ip::split_protocols(fcx, side);
    let mut listener = tcp::endpoint(fcx, tcp, addr).listen(80)?;
    let open = Arc::new(AtomicUsize::new(0));
    fcx.spawn(move |fcx| async move {
        while let Ok(mut conn) = listener.accept(&fcx).await {
            if open.fetch_add(1, Ordering::Relaxed) >= MAX_CONNECTIONS {
                // Too many.
                open.fetch_sub(1, Ordering::Relaxed);
                conn.reset();
                continue;
            }
            let open = open.clone();
            // One task per connection. It returns `Ok` whatever happens,
            // so a client that misbehaves cannot fail the world.
            fcx.spawn(move |fcx| async move {
                tokio::select! {
                    _ = answer(&fcx, &mut conn, body) => {}
                    _ = fcx.sleep(TIME_LIMIT) => {}
                }
                conn.reset();
                open.fetch_sub(1, Ordering::Relaxed);
                Ok(())
            });
        }
        Ok(())
    });
    Ok(())
}

/// Reads one request, answers it with `body`, and waits for the client to
/// close its side: by then it has read the answer.
async fn answer(fcx: &Cx, conn: &mut tcp::TcpConnection, body: &str) {
    // Read until the blank line that ends the headers, up to 8 KiB.
    let mut request = [0u8; 8192];
    let mut len = 0;
    while !request[..len].windows(4).any(|w| w == b"\r\n\r\n") {
        match conn.read(fcx, &mut request[len..]).await {
            Ok(0) | Err(_) => return,
            Ok(n) => len += n,
        }
    }
    // The answer to HEAD has the headers of the answer to GET, and no body.
    let content = if request.starts_with(b"HEAD ") { "" } else { body };
    let response =
        format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{content}", body.len());
    if conn.write_all(fcx, response.as_bytes()).await.is_err() || conn.shutdown(fcx).await.is_err() {
        return;
    }
    while let Ok(1..) = conn.read(fcx, &mut request).await {}
}

fn main() -> fictionet::Result {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| "/run/fictionet/world.sock".into());
    let after: u64 = args.next().map(|s| s.parse()).transpose()?.unwrap_or(20);
    let (attacher, mut attachments) = fictionet::attachments();
    let _listening = fictionet::listen(fictionet::WorldSocket::UnixSocket(path.clone().into()), attacher)?;
    println!("listening on {path}");

    fictionet::block_on(fictionet::run(move |fcx| async move {
        let agent = attachments.get(&fcx, "agent").await?;
        let (to_bank, bank_side) = pair();
        web_machine(&fcx, bank_side, "203.0.113.10".parse()?, "the real bank\n")?;

        // The sandbox's subnet leads to the sandbox, and the bank's
        // network to the bank.
        let router = route::router(
            &fcx,
            vec![
                ("10.0.0.0/24".parse()?, Box::new(agent) as Box<dyn Interface>),
                ("203.0.113.0/24".parse()?, Box::new(to_bank)),
            ],
        );
        println!("agent attached: 203.0.113.0/24 leads to the bank");

        fcx.sleep(Duration::from_secs(after)).await?;

        // A more specific route wins, as in a real hijack: the bank's
        // address now leads to the impostor. The rest of 203.0.113.0/24
        // still leads to the bank.
        let (to_impostor, impostor_side) = pair();
        web_machine(&fcx, impostor_side, "203.0.113.10".parse()?, "an impostor\n")?;
        router.add("203.0.113.10/32".parse()?, Box::new(to_impostor));
        println!("{after} s later: 203.0.113.10/32 leads to the impostor");
        Ok(())
    }))
}
