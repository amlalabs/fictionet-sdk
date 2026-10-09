// A route that changes mid-run: after a delay, the bank's address leads
// to an impostor machine instead of the bank. This is the core of a BGP
// hijack, which examples/border plays out in full.
//
//     cargo run --example route_change -- /run/fictionet/world.sock 20

use std::net::IpAddr;
use std::sync::Arc;

use fictionet::stdlib::{httpd, ip, route, serve, tcp};
use fictionet::time::Duration;
use fictionet::{Cx, Interface, pair};

/// Each machine serves at most this many connections at once.
/// Connections past the cap are reset at once.
const MAX_CONNECTIONS: usize = 64;
/// A connection closes after this long without input while serve waits.
const TIME_LIMIT: Duration = Duration::from_secs(10);

/// Starts a machine at `addr` on `side` that answers every HTTP request
/// on port 80 with `body`.
fn web_machine(
    fcx: &Cx,
    side: impl Interface,
    addr: IpAddr,
    body: &'static str,
) -> fictionet::Result {
    let (tcp, _udp, _icmp, _other) = ip::split_protocols(fcx, side);
    let listener = tcp::endpoint(fcx, tcp, addr).listen(80)?;
    let site =
        httpd::Router::new().fallback(move |_, _| http::Response::new(bytes::Bytes::from(body)));
    let opts = serve::ServeOptions::default()
        .max_conns(MAX_CONNECTIONS)
        .idle(Some(TIME_LIMIT));
    serve::listen(
        fcx,
        listener,
        Arc::new(()),
        move || httpd::Http1::new(site.clone()),
        opts,
    );
    Ok(())
}

fn main() -> fictionet::Result {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .unwrap_or_else(|| "/run/fictionet/world.sock".into());
    let after: u64 = args.next().map(|s| s.parse()).transpose()?.unwrap_or(20);
    let (_listening, mut attachments) =
        fictionet::Listening::bind(fictionet::WorldSocket::UnixSocket(path.clone().into()))?;
    println!("listening on {path}");

    fictionet::block_on(fictionet::run(
        fictionet::Seed::random(),
        move |fcx| async move {
            let agent = attachments.get(&fcx, "agent").await?;
            let (to_bank, bank_side) = pair();
            web_machine(&fcx, bank_side, "203.0.113.10".parse()?, "the real bank\n")?;

            // The sandbox's subnet leads to the sandbox, and the bank's
            // network to the bank.
            let router = route::router(
                &fcx,
                vec![
                    (
                        "10.0.0.0/24".parse()?,
                        Box::new(agent) as Box<dyn Interface>,
                    ),
                    ("203.0.113.0/24".parse()?, Box::new(to_bank)),
                ],
            );
            println!("agent attached: 203.0.113.0/24 leads to the bank");

            fcx.sleep(Duration::from_secs(after)).await?;

            // A more specific route wins, as in a real hijack: the bank's
            // address now leads to the impostor. The rest of 203.0.113.0/24
            // still leads to the bank.
            let (to_impostor, impostor_side) = pair();
            web_machine(
                &fcx,
                impostor_side,
                "203.0.113.10".parse()?,
                "an impostor\n",
            )?;
            router.add("203.0.113.10/32".parse()?, Box::new(to_impostor));
            println!("{after} s later: 203.0.113.10/32 leads to the impostor");
            Ok(())
        },
    ))
}
