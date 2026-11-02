//! Zones a resolver serves itself instead of asking the internet: the
//! special-use names of RFC 6761 and RFC 7686, the reverse zones of
//! private and special addresses (RFC 6303), `home.arpa` (RFC 8375), and
//! `resolver.arpa` (RFC 9462).
//!
//! Each zone uses its apex as its NS target, as Unbound's `localhost.`
//! zone does (`localhost. NS localhost.`), and the SOA of RFC 6303 §3:
//! the apex as MNAME, `nobody.invalid.` as RNAME, serial 1, refresh 3600,
//! retry 1200, expire 604800, and minimum 10800, with TTL 10800. A
//! resolver's configuration holds the ones it serves. Unbound serves them;
//! Google's and Cloudflare's public resolvers do not.

use std::net::{Ipv4Addr, Ipv6Addr};

use fictionet::stdlib::protocols::dns::rr::rdata::{A, AAAA, NS, PTR, SOA, SVCB};
use fictionet::stdlib::protocols::dns::rr::{Name, RData, Record, RecordSet};

use super::zone::{Zone, ZoneBuilder};

/// The TTL of every record here (RFC 6303 §3).
const TTL: u32 = 10800;

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

/// A zone at `apex` with the SOA and NS RRsets of RFC 6303 §3.
fn builder(apex: &Name) -> ZoneBuilder {
    let soa = SOA::new(
        apex.clone(),
        name("nobody.invalid."),
        1,
        3600,
        1200,
        604800,
        10800,
    );
    Zone::builder(apex.clone(), soa, TTL).rrset(rrset(apex, RData::NS(NS(apex.clone()))))
}

fn rrset(owner: &Name, rdata: RData) -> RecordSet {
    let mut set = RecordSet::with_ttl(owner.clone(), rdata.record_type(), TTL);
    set.set_records(vec![Record::from_rdata(owner.clone(), TTL, rdata)]);
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
