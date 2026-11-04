//! What servers answer to CHAOS-class questions about themselves: the
//! names they answer (RFC 4892 §2), and the two looks most of them have,
//! built from [`Identity`] and [`ChaosZone`]. BIND's look, a zone of its
//! own at each name, is [`bind::chaos_zone`](super::bind::chaos_zone).

use fictionet::stdlib::protocols::dns::op::ResponseCode;
use fictionet::stdlib::protocols::dns::rr::rdata::TXT;
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData};
use fictionet::stdlib::services::dns::authority::{ChaosZone, Identity};

fn name(text: &str) -> LowerName {
    LowerName::new(&Name::from_ascii(text).expect("a valid name"))
}

/// `id.server.`: which server instance answered (RFC 4892 §2).
pub fn id_server() -> LowerName {
    name("id.server.")
}

/// `version.server.`: the server's software version, as some operators
/// publish it.
pub fn version_server() -> LowerName {
    name("version.server.")
}

/// `hostname.bind.`: BIND's name for the instance (RFC 4892 §2).
pub fn hostname_bind() -> LowerName {
    name("hostname.bind.")
}

/// `version.bind.`: BIND's name for the software version.
pub fn version_bind() -> LowerName {
    name("version.bind.")
}

/// `authors.bind.`: BIND's list of its authors.
pub fn authors_bind() -> LowerName {
    name("authors.bind.")
}

/// The plain look, as NSD, Knot, Unbound, and the public resolvers answer
/// a name: `text` as one TXT record with `ttl` at `name`, in a zone of its
/// own with no SOA. Other types there are NODATA, and names below it
/// NXDOMAIN.
pub fn txt(name: &LowerName, ttl: u32, text: &str) -> ChaosZone {
    let txt = RData::TXT(TXT::new(vec![text.to_string()]));
    ChaosZone::new(Name::from(name)).record(ttl, txt)
}

/// The refusing look: every CHAOS-class question gets `rcode` and no
/// records, as Google Public DNS answers with SERVFAIL and OpenDNS with
/// REFUSED.
pub fn refusing(rcode: ResponseCode) -> Identity {
    Identity {
        unlisted: rcode,
        ..Identity::none()
    }
}
