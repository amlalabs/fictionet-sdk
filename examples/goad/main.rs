//! A private IP LAN for real GOAD or GOAD-like virtual machines.
//!
//! This world does not simulate Active Directory services. Every member is a
//! real VM (or container) attached to the world, and the world carries its IP
//! packets unchanged. The default addresses are the upstream GOAD topology.
//!
//! ```text
//! cargo run --example goad -- /run/fictionet/goad.sock 192.168.56 [observation.sock]
//! ```
//!
//! Attach members by these names: `provisioner`, `attacker`, `dc01`, `dc02`,
//! `dc03`, `srv02`, `srv03` and `ws01`. GOAD-Light uses the attacker and the
//! `dc01`, `dc02` and `srv02` members. See `examples/goad/README.md`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use fictionet::stdlib::network::route::{self, Prefix};
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
usage: goad [WORLD_SOCKET] [A.B.C] [OBSERVATION_SOCKET]

  WORLD_SOCKET        the Unix socket the world listens on (default /run/fictionet/goad.sock)
  A.B.C               the first three octets of the lab's /24 (default 192.168.56)
  OBSERVATION_SOCKET  an optional Unix observation socket
";

fn main() -> Result {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return Ok(());
    }
    if let Some(flag) = args.iter().find(|a| a.starts_with('-')) {
        return Err(fictionet::Error::msg(format!(
            "unknown option {flag:?}\n{USAGE}"
        )));
    }
    if args.len() > 3 {
        return Err(fictionet::Error::msg(format!(
            "unexpected argument {:?}\n{USAGE}",
            args[3]
        )));
    }
    let socket = args
        .first()
        .cloned()
        .unwrap_or_else(|| "/run/fictionet/goad.sock".into());
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

    let mut options = fictionet::RunOptions::new(fictionet::Seed::random());
    let _observation = if let Some(path) = args.get(2) {
        let dashboard = fictionet_observe::DashboardObserver::new(Default::default());
        options = options.observer(std::sync::Arc::new(fictionet::events::Aggregate::new(
            dashboard.observer(),
        )));
        Some(fictionet_observe::serve(dashboard.handle(), path)?)
    } else {
        None
    };
    let (_listening, mut attachments) =
        fictionet::Listening::bind(fictionet::WorldSocket::UnixSocket(socket.clone().into()))?;
    println!("GOAD LAN {}/24 listening on {socket}", subnet.addr);
    for &(name, _) in MEMBERS {
        let addr = members[name];
        println!("  {name:<11} {addr}");
    }

    fictionet::block_on(fictionet::run(options, move |fcx| async move {
        let lan = route::lan(&fcx, subnet, |event| event);
        loop {
            let sandbox = attachments.next(&fcx).await?;
            let name = sandbox.name().to_owned();
            let Some(&addr) = members.get(name.as_str()) else {
                println!("turned away {name}: no address is assigned to that member");
                continue;
            };
            println!("attached {name} at {addr}");
            fcx.emit("goad", "member_attached", |event| {
                event
                    .summary(format_args!("{name} attached at {addr}"))
                    .field("name", name.as_str())
                    .field("address", addr.to_string())
            });
            lan.add(addr, Box::new(sandbox) as Box<dyn Interface>, None)?;
        }
    }))
}

fn parse_prefix(text: &str) -> Result<[u8; 3]> {
    let parts = text
        .split('.')
        .map(str::parse)
        .collect::<std::result::Result<Vec<u8>, _>>();
    let not_octets = || {
        fictionet::Error::msg(format!(
            "{text:?} is not the first three octets of an IPv4 network"
        ))
    };
    let parts = parts.map_err(|_| not_octets())?;
    <[u8; 3]>::try_from(parts).map_err(|_| not_octets())
}
