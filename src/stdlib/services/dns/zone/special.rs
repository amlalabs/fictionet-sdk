//! Zones a resolver serves itself instead of asking the internet: the
//! special-use names of RFC 6761 and RFC 7686, the reverse zones of
//! private and special addresses (RFC 6303), `home.arpa` (RFC 8375),
//! `resolver.arpa` (RFC 9462), and `service.arpa` (RFC 9665).
//!
//! Each zone has the apex records Unbound gives all of these zones in
//! `add_empty_default` (`services/localzone.c`): `localhost.` as the NS
//! target and as the SOA's MNAME, `nobody.invalid.` as RNAME, serial 1,
//! and the refresh 3600, retry 1200, expire 604800, and minimum 10800 of
//! RFC 6303 §3, with TTL 10800. A resolver's configuration holds the ones
//! it serves. Unbound serves them; Google's and Cloudflare's public
//! resolvers do not.

use std::net::{Ipv4Addr, Ipv6Addr};

use fictionet::stdlib::protocols::dns::rr::rdata::{A, AAAA, NS, PTR, SOA, SVCB};
use fictionet::stdlib::protocols::dns::rr::{Name, RData, Record, RecordSet};

use super::zone::{Zone, ZoneBuilder};

/// The TTL of the records of the zones a resolver serves itself, and the
/// minimum of their SOA (RFC 6303 §3).
pub const LOCAL_TTL: u32 = 10800;

/// `localhost`, whose names all point at the loopback addresses
/// (RFC 6761 §6.3): A 127.0.0.1 and AAAA ::1 at the apex and, through a
/// wildcard, at every name below it.
pub fn localhost() -> Zone {
    let apex = name("localhost.");
    let wildcard = name("*.localhost.");
    let mut zone = builder(&apex);
    for owner in [&apex, &wildcard] {
        zone = zone
            .rrset(rrset(owner, RData::A(A(Ipv4Addr::LOCALHOST))))
            .rrset(rrset(owner, RData::AAAA(AAAA(Ipv6Addr::LOCALHOST))));
    }
    built(zone)
}

/// The empty zones of RFC 6303 §4, for the reverse names of private and
/// special-use addresses, so their questions never leave the resolver,
/// with the reverse zones of the Shared Address Space, 100.64.0.0/10,
/// that RFC 6598 §7 added to the same registry and Unbound serves too.
/// `1.0.0.127.in-addr.arpa` and the reverse name of `::1` point back at
/// `localhost.`, as in Unbound.
pub fn rfc6303() -> Vec<Zone> {
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
        .map(|text| {
            let apex = name(text);
            let loopback = match text.as_str() {
                "127.in-addr.arpa." => Some(name("1.0.0.127.in-addr.arpa.")),
                LOOPBACK_V6 => Some(apex.clone()),
                _ => None,
            };
            let mut zone = builder(&apex);
            if let Some(owner) = loopback {
                zone = zone.rrset(rrset(&owner, RData::PTR(PTR(name("localhost.")))));
            }
            built(zone)
        })
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
pub fn home_arpa() -> Zone {
    built(builder(&name("home.arpa.")))
}

/// `resolver.arpa`, holding the resolver's own encrypted endpoints as
/// SVCB records at `_dns.resolver.arpa` with `ttl`, for clients that
/// discover them (RFC 9462 §4).
pub fn resolver_arpa(endpoints: Vec<SVCB>, ttl: u32) -> Zone {
    let owner = name("_dns.resolver.arpa.");
    let records = endpoints
        .into_iter()
        .map(|svcb| Record::from_rdata(owner.clone(), ttl, RData::SVCB(svcb)))
        .collect::<Vec<_>>();
    let mut zone = builder(&name("resolver.arpa."));
    if !records.is_empty() {
        let mut set = RecordSet::with_ttl(owner, records[0].record_type(), ttl);
        set.set_records(records);
        zone = zone.rrset(set);
    }
    built(zone)
}

/// `onion`, whose names are reached through Tor and never through DNS:
/// every name below the apex is NXDOMAIN (RFC 7686 §2).
pub fn onion() -> Zone {
    built(builder(&name("onion.")))
}

/// `test`, kept for testing: every name below the apex is NXDOMAIN
/// (RFC 6761 §6.2).
pub fn test() -> Zone {
    built(builder(&name("test.")))
}

/// `invalid`, which never exists: every name below the apex is NXDOMAIN
/// (RFC 6761 §6.4).
pub fn invalid() -> Zone {
    built(builder(&name("invalid.")))
}

/// `service.arpa`, for names of services inside a home network, which
/// Unbound serves as an empty zone (RFC 9665).
pub fn service_arpa() -> Zone {
    built(builder(&name("service.arpa.")))
}

/// The SOA Unbound gives a zone it serves itself: `localhost.` as MNAME,
/// `nobody.invalid.` as RNAME, serial 1, the refresh, retry, and expire
/// of RFC 6303 §3, and `minimum`.
pub fn local_soa(minimum: u32) -> SOA {
    SOA::new(
        name("localhost."),
        name("nobody.invalid."),
        1,
        3600,
        1200,
        604800,
        minimum,
    )
}

/// The SOA and NS RRsets Unbound gives a zone it serves itself at
/// `apex`, with `ttl` as their TTL and as the SOA's minimum: the SOA of
/// [`local_soa`] and `NS localhost.`.
pub fn local_apex(apex: &Name, ttl: u32) -> (RecordSet, RecordSet) {
    (
        rrset_with(apex, RData::SOA(local_soa(ttl)), ttl),
        rrset_with(apex, RData::NS(NS(name("localhost."))), ttl),
    )
}

/// A zone at `apex` that holds the RRsets of [`local_apex`], for the
/// records added after them.
pub fn local_zone(apex: &Name, ttl: u32) -> ZoneBuilder {
    let (_, ns) = local_apex(apex, ttl);
    Zone::builder(apex.clone(), local_soa(ttl), ttl).rrset(ns)
}

/// A zone at `apex` with the apex records of every zone here.
fn builder(apex: &Name) -> ZoneBuilder {
    local_zone(apex, LOCAL_TTL)
}

fn rrset(owner: &Name, rdata: RData) -> RecordSet {
    rrset_with(owner, rdata, LOCAL_TTL)
}

fn rrset_with(owner: &Name, rdata: RData, ttl: u32) -> RecordSet {
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
