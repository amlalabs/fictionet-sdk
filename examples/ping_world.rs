//! A tiny world: it answers every ICMP echo request (ping) from every
//! sandbox, at any address, and drops every other packet.
//!
//! ```text
//! cargo run --example ping_world -- /run/fictionet/world.sock
//! ```
//!
//! Each sandbox's cable is split by protocol with
//! [`ip::split_protocols`](fictionet::stdlib::ip::split_protocols), which
//! also puts fragmented pings back together. The ICMP end gets a loop that
//! answers with [`icmp::echo_reply`](fictionet::stdlib::icmp::echo_reply).
//! The TCP, UDP and other ends are dropped, so those packets go nowhere.
//!
//! It prints `attached <name>` and `detached <name>` lines, which the
//! Docker test in `tests/docker/ping` reads.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use fictionet::prelude::*;
use fictionet::stdlib::{icmp, ip};
use fictionet::{Attachment, Cx, Interface, Packet, RecvError, Result};

fn main() -> Result {
    let path = std::env::args().nth(1).unwrap_or_else(|| "/run/fictionet/world.sock".into());
    let (attacher, mut attachments) = fictionet::attachments();
    let _listening = fictionet::listen(fictionet::WorldSocket::UnixSocket(path.clone().into()), attacher)?;
    println!("listening on {path}");
    fictionet::block_on(fictionet::run(move |cx| async move {
        // `next` returns `Cancelled` when the world stops, and `?` ends
        // the loop with it.
        loop {
            let sandbox = attachments.next(&cx).await?;
            cx.spawn(move |cx| serve(cx, sandbox));
        }
    }))
}

async fn serve(cx: Cx, sandbox: Attachment) -> Result {
    let name = sandbox.name().to_owned();
    println!("attached {name} mtu {}", sandbox.mtu());
    let (_tcp, _udp, mut pings, _other) = ip::split_protocols(&cx, sandbox);
    let mut answered = 0u64;
    loop {
        match pings.recv(&cx).await {
            Ok(packet) => {
                // Answer at whatever address the sandbox pinged.
                let Some(addr) = destination(&packet) else { continue };
                if let Some(reply) = icmp::echo_reply(&packet, addr) {
                    pings.send(reply);
                    answered += 1;
                }
            }
            // The split closes this end when the sandbox detaches.
            Err(RecvError::Closed) => break,
            Err(RecvError::Cancelled) => return Ok(()),
        }
    }
    println!("detached {name} after {answered} echo replies");
    Ok(())
}

/// The destination address of an IPv4 or IPv6 packet.
fn destination(Packet(p): &Packet) -> Option<IpAddr> {
    match p.first()? >> 4 {
        4 => Some(Ipv4Addr::from(<[u8; 4]>::try_from(p.get(16..20)?).ok()?).into()),
        6 => Some(Ipv6Addr::from(<[u8; 16]>::try_from(p.get(24..40)?).ok()?).into()),
        _ => None,
    }
}
