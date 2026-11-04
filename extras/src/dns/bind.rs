//! BIND as a world plays it: the CHAOS-class zone it serves at each name
//! it answers about itself.

use fictionet::stdlib::protocols::dns::rr::rdata::{NS, SOA};
use fictionet::stdlib::protocols::dns::rr::{Name, RData};
use fictionet::stdlib::services::dns::authority::ChaosZone;

/// `zone` as BIND serves a CHAOS name: its records, then an SOA and an NS
/// record at its apex, as c, g, i, and m at the root and a local BIND
/// 9.20 answered on 2026-11-02: SOA
/// `<apex> hostmaster.<apex> 0 28800 7200 604800 86400` with TTL 86400,
/// and NS `<apex>` with TTL 0. A name BIND answers with text is
/// [`chaos::txt`](super::chaos::txt) through this, and one without, such
/// as `authors.bind`, an empty zone through this.
pub fn chaos_zone(zone: ChaosZone) -> ChaosZone {
    let apex = zone.apex().clone();
    let hostmaster = Name::from_ascii("hostmaster")
        .and_then(|label| label.append_name(&apex))
        .unwrap_or_else(|_| apex.clone());
    let soa = SOA::new(apex.clone(), hostmaster, 0, 28800, 7200, 604800, 86400);
    zone.record(86400, RData::SOA(soa))
        .record(0, RData::NS(NS(apex)))
}
