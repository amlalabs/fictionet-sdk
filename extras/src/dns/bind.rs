//! BIND as a world plays it: the CHAOS-class zone it serves at each name
//! it answers about itself.

use fictionet::stdlib::protocols::dns::rr::rdata::SOA;
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name};
use fictionet::stdlib::services::dns::authority::{ChaosAnswer, ChaosZone};

/// The zone BIND serves at the CHAOS name `name`, with TXT `txt` at its
/// apex if any, as c, g, i, and m at the root and a local BIND 9.20
/// answered on 2026-11-02: SOA
/// `<name> hostmaster.<name> 0 28800 7200 604800 86400` with TTL 86400,
/// and NS `<name>` with TTL 0.
pub fn chaos_zone(name: &LowerName, txt: Option<String>) -> ChaosAnswer {
    let name = Name::from(name);
    let hostmaster = Name::from_ascii("hostmaster")
        .and_then(|label| label.append_name(&name))
        .unwrap_or_else(|_| name.clone());
    ChaosAnswer::Zone(Box::new(ChaosZone {
        soa: SOA::new(name.clone(), hostmaster, 0, 28800, 7200, 604800, 86400),
        soa_ttl: 86400,
        ns: name,
        ns_ttl: 0,
        txt,
    }))
}
