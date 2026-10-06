//! A private IP LAN for real GOAD or GOAD-like virtual machines.
//!
//! This world does not simulate Active Directory services. Every member is a
//! real VM (or container) attached to the world, and the world carries its IP
//! packets unchanged. The default addresses are the upstream GOAD topology.
//!
//! ```text
//! cargo run --example goad -- /run/fictionet/goad.sock 192.168.56
//! ```
//!
//! Attach members by these names: `provisioner`, `attacker`, `dc01`, `dc02`,
//! `dc03`, `srv02`, `srv03` and `ws01`. GOAD-Light uses the attacker and the
//! `dc01`, `dc02` and `srv02` members. See `examples/goad/README.md`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use fictionet::stdlib::route::{self, Prefix};
use fictionet::{Interface, Result};

const MEMBERS: &[(&str, u8)] = &[
    ("provisioner", 3),
    ("dc01", 10),
    ("dc02", 11),
    ("dc03", 12),
    ("srv02", 22),
    ("srv03", 23),
    ("ws01", 31),
    ("attacker", 100),
];

const USAGE: &str = "\
usage: goad [WORLD_SOCKET] [A.B.C]

  WORLD_SOCKET  the Unix socket the world listens on (default /run/fictionet/goad.sock)
  A.B.C         the first three octets of the lab's /24 (default 192.168.56)
";

fn main() -> Result {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return Ok(());
    }
    if let Some(flag) = args.iter().find(|a| a.starts_with('-')) {
        return Err(format!("unknown option {flag:?}\n{USAGE}").into());
    }
    if args.len() > 2 {
        return Err(format!("unexpected argument {:?}\n{USAGE}", args[2]).into());
    }
    let socket = args.first().cloned().unwrap_or_else(|| "/run/fictionet/goad.sock".into());
    let prefix = parse_prefix(args.get(1).map_or("192.168.56", String::as_str))?;

    let subnet: Prefix = format!("{}.{}.{}.0/24", prefix[0], prefix[1], prefix[2]).parse()?;
    let members: HashMap<&str, IpAddr> = MEMBERS
        .iter()
        .map(|&(name, host)| {
            (
                name,
                Ipv4Addr::new(prefix[0], prefix[1], prefix[2], host).into(),
            )
        })
        .collect();

    let (attacher, mut attachments) = fictionet::attachments();
    let _listening = fictionet::listen(
        fictionet::WorldSocket::UnixSocket(socket.clone().into()),
        attacher,
    )?;
    println!("GOAD LAN {}/24 listening on {socket}", subnet.addr);
    for &(name, _) in MEMBERS {
        let addr = members[name];
        println!("  {name:<11} {addr}");
    }

    fictionet::block_on(fictionet::run(move |cx| async move {
        let lan = route::lan(&cx, subnet);
        while let Some(sandbox) = attachments.next(&cx).await {
            let name = sandbox.name().to_owned();
            let Some(&addr) = members.get(name.as_str()) else {
                println!("turned away {name}: no address is assigned to that member");
                continue;
            };
            println!("attached {name} at {addr}");
            cx.event("goad_member_attached")
                .str("name", &name)
                .str("address", &addr.to_string())
                .emit();
            lan.add(addr, Box::new(sandbox) as Box<dyn Interface>)?;
        }
        Ok(())
    }))
}

fn parse_prefix(text: &str) -> Result<[u8; 3]> {
    let parts = text
        .split('.')
        .map(str::parse)
        .collect::<std::result::Result<Vec<u8>, _>>();
    let parts =
        parts.map_err(|_| format!("{text:?} is not the first three octets of an IPv4 network"))?;
    <[u8; 3]>::try_from(parts)
        .map_err(|_| format!("{text:?} is not the first three octets of an IPv4 network").into())
}
