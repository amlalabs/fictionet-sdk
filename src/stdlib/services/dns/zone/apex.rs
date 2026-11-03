//! The apex records of a zone that holds no data of its own.

use fictionet::stdlib::protocols::dns::rr::rdata::{NS, SOA};
use fictionet::stdlib::protocols::dns::rr::{Name, RData, Record, RecordSet};

use super::zone::{Zone, ZoneBuilder};

/// The SOA and NS records of an empty zone, such as one a resolver serves
/// itself (RFC 6303 §3).
///
/// The SOA has serial 1, the refresh 3600, retry 1200, and expire 604800
/// of RFC 6303 §3, and [`ttl`](EmptyApex::ttl) as its minimum.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EmptyApex {
    /// The NS target, which is also the SOA's MNAME. `None` names the
    /// zone itself, as RFC 6303 §3 recommends.
    pub ns: Option<Name>,
    /// The SOA's RNAME.
    pub rname: Name,
    /// The TTL of both RRsets, and the SOA's minimum.
    pub ttl: u32,
}

impl EmptyApex {
    /// The apex RFC 6303 §3 recommends: the zone's own name as NS target
    /// and MNAME, `nobody.invalid.` as RNAME, and TTL 10800.
    pub fn rfc6303() -> EmptyApex {
        EmptyApex {
            ns: None,
            rname: Name::from_ascii("nobody.invalid.").expect("a valid name"),
            ttl: 10800,
        }
    }

    /// The SOA of the zone at `apex`.
    pub fn soa(&self, apex: &Name) -> SOA {
        SOA::new(
            self.target(apex),
            self.rname.clone(),
            1,
            3600,
            1200,
            604800,
            self.ttl,
        )
    }

    /// The SOA and NS RRsets of the zone at `apex`.
    pub fn records(&self, apex: &Name) -> (RecordSet, RecordSet) {
        (
            self.rrset(apex, RData::SOA(self.soa(apex))),
            self.rrset(apex, RData::NS(NS(self.target(apex)))),
        )
    }

    /// A zone at `apex` that holds these records, for the records added
    /// after them.
    pub fn zone(&self, apex: &Name) -> ZoneBuilder {
        let (_, ns) = self.records(apex);
        Zone::builder(apex.clone(), self.soa(apex), self.ttl).rrset(ns)
    }

    fn target(&self, apex: &Name) -> Name {
        self.ns.clone().unwrap_or_else(|| apex.clone())
    }

    fn rrset(&self, owner: &Name, rdata: RData) -> RecordSet {
        let mut set = RecordSet::with_ttl(owner.clone(), rdata.record_type(), self.ttl);
        set.set_records(vec![Record::from_rdata(owner.clone(), self.ttl, rdata)]);
        set
    }
}
