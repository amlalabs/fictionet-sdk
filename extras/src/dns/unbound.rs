//! Unbound 1.26 as a world plays it: the resolver configuration its
//! documented defaults give, and the apex records it gives the zones it
//! serves itself.

use std::sync::Arc;
use std::time::Duration;

use fictionet::stdlib::protocols::dns::dnssec::AlgorithmPolicy;
use fictionet::stdlib::protocols::dns::rr::rdata::PTR;
use fictionet::stdlib::protocols::dns::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::services::dns::authority::Identity;
use fictionet::stdlib::services::dns::resolver::{Config, LocalZone, Work};
use fictionet::stdlib::services::dns::zone::{EmptyApex, Zone, ZoneData, special};

use super::chaos;

/// The version Unbound gives `version.server` and `version.bind`: the
/// release of 2026-10-21.
pub const VERSION: &str = "unbound 1.26.2";

/// The apex records Unbound gives every zone it serves itself, in
/// `add_empty_default` (`services/localzone.c`): `localhost.` as the NS
/// target and as the SOA's MNAME, `nobody.invalid.` as RNAME, and TTL
/// 10800, with the SOA timers of RFC 6303 §3.
pub fn apex() -> EmptyApex {
    EmptyApex {
        ns: Some(name("localhost.")),
        ..EmptyApex::rfc6303()
    }
}

/// Unbound's default local zones, each with [`apex`]: `localhost`, the
/// reverse zones of RFC 6303 and RFC 6598 (its default AS112, RFC 1918,
/// and Shared Address Space zones), `home.arpa`, `resolver.arpa`,
/// `service.arpa`, `onion`, `test`, and `invalid`. With no DDR
/// endpoints, `resolver.arpa` is an empty zone (RFC 9462 §6.4).
/// `1.0.0.127.in-addr.arpa` and the reverse name of `::1` point back at
/// `localhost.`. Answers from all of them carry AA, as `local_encode` in
/// Unbound's `services/localzone.c` sets it.
pub fn local_zones() -> Vec<LocalZone> {
    let apex = apex();
    let localhost = name("localhost.");
    let loopbacks = [
        (name("127.in-addr.arpa."), name("1.0.0.127.in-addr.arpa.")),
        (name(LOOPBACK_V6), name(LOOPBACK_V6)),
    ];
    let mut zones: Vec<Arc<dyn ZoneData>> = vec![Arc::new(special::localhost(&apex))];
    for zone in special::rfc6303(&apex) {
        let loopback = loopbacks
            .iter()
            .find(|(zone_apex, _)| *zone.apex() == LowerName::new(zone_apex));
        let zone = match loopback {
            Some((zone_apex, owner)) => {
                let mut ptr = RecordSet::with_ttl(owner.clone(), RecordType::PTR, apex.ttl);
                ptr.set_records(vec![Record::from_rdata(
                    owner.clone(),
                    apex.ttl,
                    RData::PTR(PTR(localhost.clone())),
                )]);
                built(apex.zone(zone_apex).rrset(ptr).build())
            }
            None => zone,
        };
        zones.push(Arc::new(zone));
    }
    zones.push(Arc::new(special::home_arpa(&apex)));
    zones.push(Arc::new(special::resolver_arpa(&apex, Vec::new(), 3600)));
    zones.push(Arc::new(special::service_arpa(&apex)));
    zones.push(Arc::new(special::onion(&apex)));
    zones.push(Arc::new(special::test(&apex)));
    zones.push(Arc::new(special::invalid(&apex)));
    zones.into_iter().map(LocalZone::new).collect()
}

/// Unbound 1.26 with its documented defaults, read from the
/// `unbound.conf` manual on 2026-11-01, over [`Config::new`]:
///
/// - The IANA root hints, which Unbound has built in, and its default
///   local zones ([`local_zones`]).
/// - `edns-buffer-size: 1232`, `qname-minimisation: yes` with
///   `qname-minimisation-strict: no`, `use-caps-for-id: no`,
///   `aggressive-nsec: yes`, `serve-expired: no`, `ede: no`,
///   `deny-any: no`.
/// - `cache-max-ttl: 86400` and `cache-max-negative-ttl: 3600`.
/// - `val-nsec3-keysize-iterations: "1024 150 2048 150 4096 150"`:
///   NSEC3 records with more than 150 iterations make an answer
///   Insecure, whatever the key size.
/// - `max-global-quota: 200` queries for one client question, and
///   `max-query-restarts: 11` aliases.
/// - `unknown-server-time-limit: 376` milliseconds for a server it has no
///   round-trip time for, and `infra-host-ttl: 900` seconds.
/// - `infra-cache-min-rtt: 50` and `infra-cache-max-rtt: 120000`
///   milliseconds, the shortest and longest wait for a server, and the
///   400-millisecond band of servers it chooses among, `RTT_BAND` in its
///   `util/rtt.h`.
/// - `hide-identity: no` and `hide-version: no`: `id.server` and
///   `hostname.bind` give the host name, which this leaves as
///   `localhost` for a world to set; `version.server` and `version.bind`
///   give [`VERSION`]. Other CHAOS names get REFUSED.
/// - The `allow` access control: a query with RD clear is answered only
///   from local zones and is otherwise REFUSED.
/// - Validation with the IANA root anchors.
///
/// A failure is cached for 5 seconds, inside the bounds of RFC 9520 §3.2.
pub fn config() -> Config {
    let identity = Identity::none()
        .zone(chaos::txt(&chaos::id_server(), 0, "localhost"))
        .zone(chaos::txt(&chaos::hostname_bind(), 0, "localhost"))
        .zone(chaos::txt(&chaos::version_server(), 0, VERSION))
        .zone(chaos::txt(&chaos::version_bind(), 0, VERSION));
    Config {
        local: local_zones(),
        payload: 1232,
        policy: AlgorithmPolicy {
            max_nsec3_iterations: 150,
            ..AlgorithmPolicy::iana()
        },
        work: Work {
            queries: 200,
            depth: 11,
        },
        failure_ttl: Duration::from_secs(5),
        max_ttl: Duration::from_secs(86400),
        max_negative_ttl: Duration::from_secs(3600),
        rd0_from_cache: false,
        ede: false,
        aggressive_nsec: true,
        identity,
        retransmit: Duration::from_millis(376),
        server_ttl: Duration::from_secs(900),
        min_timeout: Duration::from_millis(50),
        max_timeout: Duration::from_secs(120),
        band: Duration::from_millis(400),
        ..Config::new()
    }
}

/// The reverse zone of `::1` (RFC 6303 §4.3).
const LOOPBACK_V6: &str =
    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.";

fn built(zone: Result<Zone, fictionet::stdlib::services::dns::zone::ZoneError>) -> Zone {
    zone.expect("a locally served zone is well formed")
}

fn name(text: &str) -> Name {
    Name::from_ascii(text).expect("a valid name")
}

#[cfg(test)]
mod tests {
    use fictionet::stdlib::protocols::dns::op::Query;

    use fictionet::stdlib::protocols::dns::rr::rdata::NS;
    use fictionet::stdlib::services::dns::zone::{Fact, Node};

    use super::*;

    /// The records `data` holds at `owner` of type `rtype`.
    fn records(data: &dyn ZoneData, owner: &str, rtype: RecordType) -> Vec<RData> {
        let question = Query::query(name(owner), rtype);
        let view = data.view(&question);
        match view.node(&LowerName::new(&name(owner))) {
            Fact::Present(Node::Data(sets)) => sets
                .values()
                .filter(|set| set.record_type() == rtype)
                .flat_map(|set| set.records_without_rrsigs().map(|r| r.data.clone()))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Every zone Unbound serves by default names `localhost.` as its
    /// SOA's MNAME, and as its name server where its apex has one:
    /// the special-use zones answer NS with a negative: `localhost` with
    /// NODATA, and `invalid`, `test`, and `onion` with NXDOMAIN at the
    /// apex (RFC 6761 §6.2, §6.3, §6.4, RFC 7686 §2). The loopback
    /// addresses' reverse names point at `localhost.`.
    #[test]
    fn unbound_zones_name_localhost() {
        let zones = local_zones();
        assert_eq!(zones.len(), 1 + 97 + 6);
        for zone in &zones {
            assert!(zone.keep_aa);
            let apex = zone.data.apex().to_string();
            let ns = match apex.as_str() {
                "localhost." | "invalid." | "test." | "onion." => vec![],
                _ => vec![RData::NS(NS(name("localhost.")))],
            };
            assert_eq!(records(&*zone.data, &apex, RecordType::NS), ns, "{apex}");
            let question = Query::query(name(&apex), RecordType::SOA);
            let view = zone.data.view(&question);
            let soa: Vec<&RData> = view
                .soa()
                .records_without_rrsigs()
                .map(|record| &record.data)
                .collect();
            let [RData::SOA(soa)] = soa.as_slice() else {
                panic!("{apex}: one SOA");
            };
            assert_eq!(soa.mname, name("localhost."), "{apex}");
            assert_eq!(soa.rname, name("nobody.invalid."), "{apex}");
        }
        let ptr = RData::PTR(PTR(name("localhost.")));
        let find = |apex: &str| {
            zones
                .iter()
                .find(|zone| *zone.data.apex() == LowerName::new(&name(apex)))
                .expect("a default zone")
        };
        assert_eq!(
            records(
                &*find("127.in-addr.arpa.").data,
                "1.0.0.127.in-addr.arpa.",
                RecordType::PTR
            ),
            vec![ptr.clone()]
        );
        assert_eq!(
            records(&*find(LOOPBACK_V6).data, LOOPBACK_V6, RecordType::PTR),
            vec![ptr]
        );
    }

    #[test]
    fn unbound_answers_its_version() {
        let identity = config().identity;
        for name in [chaos::version_bind(), chaos::version_server()] {
            let zone = chaos::txt(&name, 0, VERSION);
            assert!(identity.zones.contains(&zone), "{name}");
        }
    }
}
