//! What the root letters' and `gtld-servers.net` servers' software does
//! wherever they answer: the payload size each advertises and its answer
//! to QTYPE ANY, as fronts for a world's servers at their addresses.

use std::net::Ipv4Addr;

use fictionet::stdlib::protocols::dns::rr::RecordType;
use fictionet::stdlib::services::dns::authority::{Identity, ServerConfig};
use fictionet::stdlib::services::dns::resolver::{NameServer, ROOT_SERVERS};
use fictionet::stdlib::services::dns::zone::AnyResponse;

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
