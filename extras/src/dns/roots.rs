//! The root letters and the `gtld-servers.net` servers as a world plays
//! them: the `gtld-servers.net` servers' names and addresses, what each
//! server's software does wherever it answers (the payload size it
//! advertises and its answer to QTYPE ANY) as fronts for a world's
//! servers at their addresses.

use std::net::{Ipv4Addr, Ipv6Addr};

use fictionet::stdlib::protocols::dns::rr::RecordType;
use fictionet::stdlib::services::dns::authority::{Identity, ServerConfig};
use fictionet::stdlib::services::dns::resolver::{NameServer, ROOT_SERVERS};
use fictionet::stdlib::services::dns::zone::AnyResponse;
use fictionet::stdlib::world::net::Host;
use fictionet::stdlib::world::net::dns::internet::server_host;

/// One of the thirteen root server letters, with what its operator's
/// software does wherever it answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Letter {
    /// `<letter>.root-servers.net.` and its addresses.
    pub server: NameServer,
    /// The EDNS payload size its replies advertise (RFC 6891 §6.2.5).
    pub payload: u16,
    /// What it sends for QTYPE ANY at the root (RFC 8482 §4).
    pub any: AnyResponse,
}

impl Letter {
    /// The front of a server playing this letter, with `identity`.
    pub fn front(&self, identity: Identity) -> ServerConfig {
        ServerConfig {
            identity,
            payload: self.payload,
            any: self.any,
            ..ServerConfig::generic()
        }
    }
}

/// The root letter `index` of [`ROOT_SERVERS`], with what its operator's
/// software does.
const fn letter(index: usize, payload: u16, any: AnyResponse) -> Letter {
    Letter {
        server: ROOT_SERVERS[index],
        payload,
        any,
    }
}

/// The root letters, in letter order, at the addresses of
/// [`ROOT_SERVERS`]. The payload sizes and ANY answers were seen at each
/// letter on 2026-11-01: b, j, and k answer `. ANY` with the NS RRset
/// alone, h and l with the SOA alone, and the others with every RRset.
pub const ROOT_LETTERS: [Letter; 13] = [
    letter(0, 4096, AnyResponse::All),
    letter(1, 1232, AnyResponse::OneRrset(RecordType::NS)),
    letter(2, 1232, AnyResponse::All),
    letter(3, 1450, AnyResponse::All),
    letter(4, 1472, AnyResponse::All),
    letter(5, 1472, AnyResponse::All),
    letter(6, 1232, AnyResponse::All),
    letter(7, 1232, AnyResponse::OneRrset(RecordType::SOA)),
    letter(8, 1232, AnyResponse::All),
    letter(9, 1472, AnyResponse::OneRrset(RecordType::NS)),
    letter(10, 1232, AnyResponse::OneRrset(RecordType::NS)),
    letter(11, 4096, AnyResponse::OneRrset(RecordType::SOA)),
    letter(12, 1232, AnyResponse::All),
];

/// The letter whose IPv4 address is `v4`, if one is.
pub fn letter_at(v4: Ipv4Addr) -> Option<&'static Letter> {
    ROOT_LETTERS.iter().find(|letter| letter.server.v4 == v4)
}

/// The front of a server playing a `gtld-servers.net` server, with
/// `identity`: a 4096-octet payload and every RRset of the name for ANY.
/// Verisign runs these servers and a.root, so they take a.root's values;
/// they were not measured at the `gtld-servers.net` servers themselves.
pub fn gtld_front(identity: Identity) -> ServerConfig {
    ROOT_LETTERS[0].front(identity)
}

const fn server(host: &'static str, v4: Ipv4Addr, v6: Ipv6Addr) -> NameServer {
    NameServer { host, v4, v6 }
}

/// The servers of `com` and `net`, which serve both zones, as the root
/// zone's glue gave them on 2026-11-01.
pub const GTLD_SERVERS: [NameServer; 13] = [
    server(
        "a.gtld-servers.net.",
        Ipv4Addr::new(192, 5, 6, 30),
        Ipv6Addr::new(0x2001, 0x503, 0xa83e, 0, 0, 0, 0x2, 0x30),
    ),
    server(
        "b.gtld-servers.net.",
        Ipv4Addr::new(192, 33, 14, 30),
        Ipv6Addr::new(0x2001, 0x503, 0x231d, 0, 0, 0, 0x2, 0x30),
    ),
    server(
        "c.gtld-servers.net.",
        Ipv4Addr::new(192, 26, 92, 30),
        Ipv6Addr::new(0x2001, 0x503, 0x83eb, 0, 0, 0, 0, 0x30),
    ),
    server(
        "d.gtld-servers.net.",
        Ipv4Addr::new(192, 31, 80, 30),
        Ipv6Addr::new(0x2001, 0x500, 0x856e, 0, 0, 0, 0, 0x30),
    ),
    server(
        "e.gtld-servers.net.",
        Ipv4Addr::new(192, 12, 94, 30),
        Ipv6Addr::new(0x2001, 0x502, 0x1ca1, 0, 0, 0, 0, 0x30),
    ),
    server(
        "f.gtld-servers.net.",
        Ipv4Addr::new(192, 35, 51, 30),
        Ipv6Addr::new(0x2001, 0x503, 0xd414, 0, 0, 0, 0, 0x30),
    ),
    server(
        "g.gtld-servers.net.",
        Ipv4Addr::new(192, 42, 93, 30),
        Ipv6Addr::new(0x2001, 0x503, 0xeea3, 0, 0, 0, 0, 0x30),
    ),
    server(
        "h.gtld-servers.net.",
        Ipv4Addr::new(192, 54, 112, 30),
        Ipv6Addr::new(0x2001, 0x502, 0x8cc, 0, 0, 0, 0, 0x30),
    ),
    server(
        "i.gtld-servers.net.",
        Ipv4Addr::new(192, 43, 172, 30),
        Ipv6Addr::new(0x2001, 0x503, 0x39c1, 0, 0, 0, 0, 0x30),
    ),
    server(
        "j.gtld-servers.net.",
        Ipv4Addr::new(192, 48, 79, 30),
        Ipv6Addr::new(0x2001, 0x502, 0x7094, 0, 0, 0, 0, 0x30),
    ),
    server(
        "k.gtld-servers.net.",
        Ipv4Addr::new(192, 52, 178, 30),
        Ipv6Addr::new(0x2001, 0x503, 0xd2d, 0, 0, 0, 0, 0x30),
    ),
    server(
        "l.gtld-servers.net.",
        Ipv4Addr::new(192, 41, 162, 30),
        Ipv6Addr::new(0x2001, 0x500, 0xd937, 0, 0, 0, 0, 0x30),
    ),
    server(
        "m.gtld-servers.net.",
        Ipv4Addr::new(192, 55, 83, 30),
        Ipv6Addr::new(0x2001, 0x501, 0xb1f9, 0, 0, 0, 0, 0x30),
    ),
];

/// One host per `gtld-servers.net` server, at both of its addresses,
/// finished by `build` as
/// [`root_servers`](fictionet::stdlib::world::net::dns::internet::root_servers)
/// finishes a root letter's.
pub fn gtld_servers(build: impl Fn(&NameServer, Host) -> Host) -> Vec<Host> {
    GTLD_SERVERS
        .iter()
        .map(|server| build(server, server_host(server)))
        .collect()
}
