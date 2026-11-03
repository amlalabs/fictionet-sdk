//! The resolver's cache on its own: what newer data displaces, and how
//! long a validated RRset lives.

use std::time::Duration;

use fictionet::stdlib::protocols::dns::dnssec::{
    Algorithm, KeyFlags, Validation, Window, ZoneKey, sign,
};
use fictionet::stdlib::protocols::dns::rr::rdata::{NS, SOA};
use fictionet::stdlib::protocols::dns::rr::{DNSClass, LowerName, RData, RecordSet, RecordType};
use fictionet::stdlib::services::dns::resolver::{
    Cache, Checked, Entry, FailureKind, Key, Limits, Negative, Offer, Rank,
};
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};

use super::resolver::{a, at, date, name, rrset};

fn cache() -> Cache {
    Cache::new(Limits {
        max_ttl: Duration::from_secs(86400),
        max_negative_ttl: Duration::from_secs(3600),
        failure_ttl: Duration::from_secs(5),
        stale: Duration::ZERO,
    })
}

fn key(owner: &str, rtype: RecordType) -> Key {
    Key::new(LowerName::new(&name(owner)), rtype, DNSClass::IN)
}

fn soa() -> RecordSet {
    rrset(
        "example.",
        300,
        vec![RData::SOA(SOA::new(
            name("ns.example."),
            name("hostmaster.example."),
            1,
            7200,
            3600,
            1209600,
            300,
        ))],
    )
}

fn nxdomain(owner: &str) -> Offer {
    Offer::Negative {
        key: key(owner, RecordType::A),
        kind: Negative::NxDomain,
        soa: Some(soa()),
        denial: Vec::new(),
        validation: Validation::NotPerformed,
        truncated: false,
    }
}

fn positive(set: RecordSet) -> Offer {
    Offer::Positive {
        set,
        rank: Rank::AuthAnswer,
        validation: Validation::NotPerformed,
        proof: Vec::new(),
        truncated: false,
    }
}

#[test]
fn newer_data_at_a_name_ends_its_nxdomain() {
    let mut cache = cache();
    cache.insert(at(100), nxdomain("nope.example."));
    cache.insert(
        at(201),
        positive(rrset("nope.example.", 300, vec![a("192.0.2.14")])),
    );
    let now = at(201);
    assert!(
        cache
            .nxdomain_above(&LowerName::new(&name("nope.example.")), DNSClass::IN, now)
            .is_none()
    );
    assert!(matches!(
        cache.get(&key("nope.example.", RecordType::A), now),
        Some(Entry::Positive { .. })
    ));
}

#[test]
fn newer_nodata_at_a_name_ends_its_nxdomain() {
    let mut cache = cache();
    cache.insert(at(100), nxdomain("www.example."));
    cache.insert(
        at(110),
        Offer::Negative {
            key: key("www.example.", RecordType::A),
            kind: Negative::NoData,
            soa: Some(soa()),
            denial: Vec::new(),
            validation: Validation::NotPerformed,
            truncated: false,
        },
    );
    let now = at(111);
    assert!(
        cache
            .nxdomain_above(&LowerName::new(&name("www.example.")), DNSClass::IN, now)
            .is_none()
    );
}

/// Data at a name ends its NXDOMAIN under every type, not only under ANY:
/// the copy under the type the NXDOMAIN answered goes too.
#[test]
fn data_below_a_name_ends_its_nxdomain_under_the_type_it_answered() {
    let mut cache = cache();
    cache.insert(at(100), nxdomain("foo.example."));
    cache.insert(
        at(101),
        positive(rrset("bar.foo.example.", 300, vec![a("192.0.2.14")])),
    );
    let now = at(102);
    assert!(
        cache
            .get(&key("foo.example.", RecordType::ANY), now)
            .is_none()
    );
    assert!(
        cache
            .get(&key("foo.example.", RecordType::A), now)
            .is_none()
    );
}

/// A failure is cached over a referral's NS RRset, which answers no
/// client, and keeps it beneath for finding the zone's servers
/// (RFC 9520 §3.2). Data that answers clients keeps a failure out.
#[test]
fn a_failure_is_laid_over_data_that_answers_no_client() {
    let mut cache = cache();
    let ns_key = key("example.", RecordType::NS);
    let ns = rrset("example.", 3600, vec![RData::NS(NS(name("ns.example.")))]);
    cache.insert(
        at(100),
        Offer::Positive {
            set: ns.clone(),
            rank: Rank::NonAuthAuthority,
            validation: Validation::NotPerformed,
            proof: Vec::new(),
            truncated: false,
        },
    );
    let failure = |key: &Key| Offer::Failure {
        key: key.clone(),
        why: FailureKind::NoReachableAuthority,
    };
    cache.insert(at(100), failure(&ns_key));
    assert!(matches!(
        cache.get(&ns_key, at(101)),
        Some(Entry::Failure { .. })
    ));
    assert!(matches!(
        cache.data(&ns_key, at(101)),
        Some(Entry::Positive {
            rank: Rank::NonAuthAuthority,
            ..
        })
    ));
    // Once the failure expires, the NS RRset still finds the servers for
    // the rest of its TTL.
    assert!(matches!(
        cache.data(&ns_key, at(200)),
        Some(Entry::Positive { .. })
    ));

    let www = key("www.example.", RecordType::A);
    cache.insert(
        at(100),
        positive(rrset("www.example.", 300, vec![a("192.0.2.1")])),
    );
    cache.insert(at(100), failure(&www));
    assert!(matches!(
        cache.get(&www, at(101)),
        Some(Entry::Positive { .. })
    ));
}

#[test]
fn glue_does_not_end_an_nxdomain() {
    let mut cache = cache();
    cache.insert(at(100), nxdomain("nope.example."));
    cache.insert(
        at(101),
        Offer::Positive {
            set: rrset("nope.example.", 300, vec![a("192.0.2.14")]),
            rank: Rank::Glue,
            validation: Validation::NotPerformed,
            proof: Vec::new(),
            truncated: false,
        },
    );
    let now = at(102);
    assert!(
        cache
            .nxdomain_above(&LowerName::new(&name("nope.example.")), DNSClass::IN, now)
            .is_some()
    );
}

/// `set` with an RRSIG whose own TTL is `ttl` and whose Original TTL is
/// `original`.
fn signed(mut set: RecordSet, ttl: u32, original: u32) -> RecordSet {
    let entropy = SeededEntropy::new(Seed::from_u64(1));
    let key = ZoneKey::generate(&entropy, Algorithm::Ed25519, KeyFlags::ZSK);
    let mut as_signed = set.clone();
    as_signed.set_ttl(original);
    let window = Window {
        inception: date(1_700_000_000),
        expiration: date(1_800_000_000),
    };
    let mut rrsig = sign(&key, &as_signed, &name("example."), window).unwrap();
    rrsig.ttl = ttl;
    set.insert_rrsig(rrsig);
    set
}

fn expires(cache: &Cache, key: &Key, now: Instant) -> Instant {
    match cache.get(key, now) {
        Some(entry @ Entry::Positive { .. }) => entry.expires(),
        other => panic!("expected an RRset, got {other:?}"),
    }
}

#[test]
fn a_secure_rrset_lives_no_longer_than_its_rrsigs_original_ttl() {
    let mut cache = cache();
    let www = key("www.example.", RecordType::A);
    let set = signed(
        rrset("www.example.", 86400, vec![a("192.0.2.1")]),
        86400,
        300,
    );
    cache.insert(at(0), positive(set.clone()));
    cache.validated(
        &www,
        &Checked::Rrset(set),
        Validation::Secure,
        Some(at(2_000_000)),
        Some(300),
        at(1),
    );
    assert_eq!(expires(&cache, &www, at(1)), at(300));
}

/// A validation's result lands only on the data it checked: an RRset
/// stored at the key while the validation waited keeps what it had.
#[test]
fn a_result_applies_only_to_the_data_it_checked() {
    let mut cache = cache();
    let www = key("www.example.", RecordType::A);
    let signed = signed(rrset("www.example.", 600, vec![a("192.0.2.80")]), 600, 600);
    let replaced = rrset("www.example.", 600, vec![a("203.0.113.66")]);
    cache.insert(at(0), positive(replaced.clone()));
    cache.validated(
        &www,
        &Checked::Rrset(signed),
        Validation::Secure,
        None,
        None,
        at(1),
    );
    let validation = |cache: &Cache| match cache.get(&www, at(1)) {
        Some(Entry::Positive { validation, .. }) => *validation,
        other => panic!("expected an RRset, got {other:?}"),
    };
    assert_eq!(validation(&cache), Validation::NotPerformed);
    // The same records, with other TTLs and owner case, are the data.
    let mut same = rrset("WWW.Example.", 60, vec![a("203.0.113.66")]);
    same.set_ttl(60);
    cache.validated(
        &www,
        &Checked::Rrset(same),
        Validation::Insecure(fictionet::stdlib::protocols::dns::dnssec::Insecure::NoAnchor),
        None,
        None,
        at(1),
    );
    assert!(matches!(validation(&cache), Validation::Insecure(_)));
}

#[test]
fn an_rrsets_ttl_is_no_longer_than_its_rrsigs_ttl() {
    let mut cache = cache();
    let www = key("www.example.", RecordType::A);
    let set = signed(
        rrset("www.example.", 86400, vec![a("192.0.2.1")]),
        600,
        86400,
    );
    cache.insert(at(0), positive(set));
    assert_eq!(expires(&cache, &www, at(0)), at(600));
}
