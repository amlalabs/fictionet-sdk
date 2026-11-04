//! Zones a resolver serves itself instead of asking the internet: the
//! special-use names of RFC 6761, RFC 6762, and RFC 7686, the reverse
//! zones of private and special addresses (RFC 6303), `home.arpa` (RFC 8375),
//! `resolver.arpa` (RFC 9462), and `service.arpa` (RFC 9665). The SVCB
//! parameters of a resolver's encrypted endpoints in `resolver.arpa` are
//! here too: [`alpn`], [`port`], [`ipv4_hint`], [`ipv6_hint`], and
//! [`dohpath`].
//!
//! Each zone takes the [`EmptyApex`] it gives its SOA and NS records.
//! [`EmptyApex::rfc6303`] is the form RFC 6303 §3 recommends; RFC 6303
//! also lets operators choose other values, so a world that plays some
//! resolver software passes that software's. [`defaults`] gives every
//! zone here, and a resolver's configuration holds the ones it serves.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use fictionet::stdlib::protocols::dns::op::Query;
use fictionet::stdlib::protocols::dns::rr::rdata::svcb::{
    Alpn, IpHint, SvcParamKey, SvcParamValue, Unknown,
};
use fictionet::stdlib::protocols::dns::rr::rdata::{A, AAAA, SVCB};
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData, Record, RecordSet};

use super::apex::EmptyApex;
use super::data::{Denied, Fact, Revision, View, ZoneData};
use super::zone::{Node, Zone, ZoneBuilder};

/// Every zone here, each with `apex`: `localhost`, the zones of
/// [`rfc6303`], `home.arpa`, an empty `resolver.arpa`, `service.arpa`,
/// `onion`, `test`, `invalid`, and `local`.
pub fn defaults(apex: &EmptyApex) -> Vec<Arc<dyn ZoneData>> {
    let mut zones: Vec<Arc<dyn ZoneData>> = vec![Arc::new(localhost(apex))];
    for zone in rfc6303(apex) {
        zones.push(Arc::new(zone));
    }
    zones.push(Arc::new(home_arpa(apex)));
    zones.push(Arc::new(resolver_arpa(apex, Vec::new(), apex.ttl)));
    zones.push(Arc::new(service_arpa(apex)));
    zones.push(Arc::new(onion(apex)));
    zones.push(Arc::new(test(apex)));
    zones.push(Arc::new(invalid(apex)));
    zones.push(Arc::new(local(apex)));
    zones
}

/// `localhost`, whose names are all the loopback host (RFC 6761 §6.3):
/// the apex and every name below it answer A with 127.0.0.1 and AAAA
/// with ::1, and every other type, SOA and NS among them, with NODATA,
/// the immediate negative answer RFC 6761 §6.3 asks of resolvers.
pub fn localhost(apex: &EmptyApex) -> SpecialUse {
    let name = name("localhost.");
    let sets = [
        RData::A(A(Ipv4Addr::LOCALHOST)),
        RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
    ]
    .map(|rdata| {
        let set = rrset(&name, rdata, apex.ttl);
        (set.record_type(), set)
    });
    SpecialUse::new(&name, apex, Some(Node::Data(BTreeMap::from(sets))))
}

/// The empty zones of RFC 6303 §4, for the reverse names of private and
/// special-use addresses, so their questions never leave the resolver,
/// with the reverse zones of the Shared Address Space, 100.64.0.0/10,
/// that RFC 6598 §7 added to the same registry.
pub fn rfc6303(apex: &EmptyApex) -> Vec<Zone> {
    let mut apexes: Vec<String> = vec!["10.in-addr.arpa.".to_string()];
    apexes.extend((16..=31).map(|octet| format!("{octet}.172.in-addr.arpa.")));
    apexes.extend((64..=127).map(|octet| format!("{octet}.100.in-addr.arpa.")));
    apexes.extend(
        [
            "168.192.in-addr.arpa.",
            "0.in-addr.arpa.",
            "127.in-addr.arpa.",
            "254.169.in-addr.arpa.",
            "2.0.192.in-addr.arpa.",
            "100.51.198.in-addr.arpa.",
            "113.0.203.in-addr.arpa.",
            "255.255.255.255.in-addr.arpa.",
            UNSPECIFIED_V6,
            LOOPBACK_V6,
            "d.f.ip6.arpa.",
            "8.e.f.ip6.arpa.",
            "9.e.f.ip6.arpa.",
            "a.e.f.ip6.arpa.",
            "b.e.f.ip6.arpa.",
            "8.b.d.0.1.0.0.2.ip6.arpa.",
        ]
        .map(str::to_string),
    );
    apexes
        .iter()
        .map(|text| built(apex.zone(&name(text))))
        .collect()
}

/// The reverse zone of `::` (RFC 6303 §4.3).
const UNSPECIFIED_V6: &str =
    "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.";
/// The reverse zone of `::1` (RFC 6303 §4.3).
const LOOPBACK_V6: &str =
    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.";

/// `home.arpa`, for names inside a home network, which a resolver answers
/// locally (RFC 8375 §7).
pub fn home_arpa(apex: &EmptyApex) -> Zone {
    built(apex.zone(&name("home.arpa.")))
}

/// `resolver.arpa`, holding the resolver's own encrypted endpoints as
/// SVCB records at `_dns.resolver.arpa` with `ttl`, for clients that
/// discover them (RFC 9462 §4). With no endpoints it is an empty zone
/// (RFC 9462 §6.4).
pub fn resolver_arpa(apex: &EmptyApex, endpoints: Vec<SVCB>, ttl: u32) -> Zone {
    let owner = name("_dns.resolver.arpa.");
    let records = endpoints
        .into_iter()
        .map(|svcb| Record::from_rdata(owner.clone(), ttl, RData::SVCB(svcb)))
        .collect::<Vec<_>>();
    let mut zone = apex.zone(&name("resolver.arpa."));
    if !records.is_empty() {
        let mut set = RecordSet::with_ttl(owner, records[0].record_type(), ttl);
        set.set_records(records);
        zone = zone.rrset(set);
    }
    built(zone)
}

/// The `alpn` parameter of an SVCB record, the ALPN IDs of `protocols`
/// (RFC 9460 §7.1), such as `dot` for DNS over TLS or `h2` for DNS over
/// HTTPS on HTTP/2 (RFC 9461 §4).
pub fn alpn(protocols: &[&str]) -> (SvcParamKey, SvcParamValue) {
    let protocols = protocols.iter().map(|p| p.to_string()).collect();
    (SvcParamKey::Alpn, SvcParamValue::Alpn(Alpn(protocols)))
}

/// The `port` parameter of an SVCB record (RFC 9460 §7.2).
pub fn port(port: u16) -> (SvcParamKey, SvcParamValue) {
    (SvcParamKey::Port, SvcParamValue::Port(port))
}

/// The `ipv4hint` parameter of an SVCB record, holding `addresses`
/// (RFC 9460 §7.3).
pub fn ipv4_hint(addresses: &[Ipv4Addr]) -> (SvcParamKey, SvcParamValue) {
    let hints = addresses.iter().map(|a| A(*a)).collect();
    (
        SvcParamKey::Ipv4Hint,
        SvcParamValue::Ipv4Hint(IpHint(hints)),
    )
}

/// The `ipv6hint` parameter of an SVCB record, holding `addresses`
/// (RFC 9460 §7.3).
pub fn ipv6_hint(addresses: &[Ipv6Addr]) -> (SvcParamKey, SvcParamValue) {
    let hints = addresses.iter().map(|a| AAAA(*a)).collect();
    (
        SvcParamKey::Ipv6Hint,
        SvcParamValue::Ipv6Hint(IpHint(hints)),
    )
}

/// The `dohpath` parameter of an SVCB record (RFC 9461 §5), SvcParamKey
/// 7, which hickory carries as an unknown key: the URI template
/// `/dns-query{?dns}`, the path the world's DNS over HTTPS fronts serve.
pub fn dohpath() -> (SvcParamKey, SvcParamValue) {
    (
        SvcParamKey::Unknown(7),
        SvcParamValue::Unknown(Unknown(b"/dns-query{?dns}".to_vec())),
    )
}

/// `onion`, whose names are reached through Tor and never through DNS:
/// the apex and every name below it are NXDOMAIN, as a caching server
/// must answer every `.onion` query (RFC 7686 §2).
pub fn onion(apex: &EmptyApex) -> SpecialUse {
    SpecialUse::new(&name("onion."), apex, None)
}

/// `test`, kept for testing: the apex and every name below it get the
/// immediate negative answer, NXDOMAIN, a caching server gives every
/// query for `test.` and the names within it (RFC 6761 §6.2).
pub fn test(apex: &EmptyApex) -> SpecialUse {
    SpecialUse::new(&name("test."), apex, None)
}

/// `invalid`, which never exists: the apex and every name below it are
/// NXDOMAIN (RFC 6761 §6.4).
pub fn invalid(apex: &EmptyApex) -> SpecialUse {
    SpecialUse::new(&name("invalid."), apex, None)
}

/// `local`, whose names Multicast DNS resolves on the local link: the
/// apex and every name below it get the immediate NXDOMAIN a caching
/// server gives every query for them, never asking the internet
/// (RFC 6762 §22.1).
pub fn local(apex: &EmptyApex) -> SpecialUse {
    SpecialUse::new(&name("local."), apex, None)
}

/// A special-use zone a resolver answers by itself, every name in it
/// alike (RFC 6761 §6.3 and §6.4): every name at or below the apex is one
/// node, or none, when every name is NXDOMAIN. The SOA RRset its
/// [`EmptyApex`] gives is no node's data. It goes only in the authority
/// section of negative answers (RFC 2308 §3), so a question for the SOA
/// or NS RRset of such a name gets a negative answer too.
pub struct SpecialUse(Arc<Alike>);

impl SpecialUse {
    fn new(apex: &Name, empty: &EmptyApex, node: Option<Node>) -> SpecialUse {
        let (soa, _) = empty.records(apex);
        SpecialUse(Arc::new(Alike {
            apex: LowerName::new(apex),
            soa,
            node,
        }))
    }
}

impl ZoneData for SpecialUse {
    fn apex(&self) -> &LowerName {
        &self.0.apex
    }

    fn view(&self, _question: &Query) -> Arc<dyn View + Send + Sync> {
        self.0.clone()
    }
}

/// The data of a [`SpecialUse`] zone, which never changes.
struct Alike {
    apex: LowerName,
    soa: RecordSet,
    node: Option<Node>,
}

impl View for Alike {
    fn apex(&self) -> &LowerName {
        &self.apex
    }

    fn revision(&self) -> Revision {
        Revision(0)
    }

    fn soa(&self) -> &RecordSet {
        &self.soa
    }

    fn node(&self, name: &LowerName) -> Fact<&Node> {
        match &self.node {
            Some(node) if self.apex.zone_of(name) => Fact::Present(node),
            _ => Fact::Absent,
        }
    }

    /// The zone is unsigned.
    fn denial(&self, _name: &LowerName, _kind: Denied) -> Fact<Vec<RecordSet>> {
        Fact::Present(Vec::new())
    }
}

/// `service.arpa`, for names of services inside a home network, as an
/// empty zone (RFC 9665).
pub fn service_arpa(apex: &EmptyApex) -> Zone {
    built(apex.zone(&name("service.arpa.")))
}

fn rrset(owner: &Name, rdata: RData, ttl: u32) -> RecordSet {
    let mut set = RecordSet::with_ttl(owner.clone(), rdata.record_type(), ttl);
    set.set_records(vec![Record::from_rdata(owner.clone(), ttl, rdata)]);
    set
}

fn built(builder: ZoneBuilder) -> Zone {
    builder
        .build()
        .expect("a locally served zone is well formed")
}

fn name(text: &str) -> Name {
    Name::from_ascii(text).expect("a locally served zone's name is valid")
}
