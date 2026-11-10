//! The resolver's cache on its own: what newer data displaces, and how
//! long a validated RRset lives.

use std::time::Duration;

use fictionet::stdlib::layer::Budget;
use fictionet::stdlib::protocols::dns::dnssec::{
    Algorithm, KeyFlags, Validation, Window, ZoneKey, sign,
};
use fictionet::stdlib::protocols::dns::rr::rdata::{NS, SOA, TXT};
use fictionet::stdlib::protocols::dns::rr::{DNSClass, LowerName, RData, RecordSet, RecordType};
use fictionet::stdlib::services::dns::resolver::{
    Cache, Checked, Entry, FailureKind, Key, Limits, Negative, Offer, Rank,
};
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};

use super::resolver::{a, at, date, name, rrset};

fn limits(max_entries: usize) -> Limits {
    Limits {
        max_ttl: Duration::from_secs(86400),
        max_negative_ttl: Duration::from_secs(3600),
        failure_ttl: Duration::from_secs(5),
        stale: Duration::ZERO,
        max_entries,
    }
}

/// A cache of at most `max_entries` things, on a budget that never
/// refuses.
fn counted(max_entries: usize) -> Cache {
    Cache::new(limits(max_entries), &Budget::unlimited()).unwrap()
}

/// A cache that holds far more than any test here stores.
fn cache() -> Cache {
    counted(4096)
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
        rank: Rank::AuthAnswer,
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

/// An NXDOMAIN is kept under ANY and under the type it answered. A later
/// NXDOMAIN of another type with a shorter TTL replaces the entry under
/// ANY, so the first copy outlives it. Data at the name then ends that
/// copy too: the name exists, and no type at it is NXDOMAIN.
#[test]
fn newer_data_ends_an_nxdomain_copy_that_outlived_its_entry() {
    let short_soa = rrset(
        "example.",
        60,
        vec![RData::SOA(SOA::new(
            name("ns.example."),
            name("hostmaster.example."),
            1,
            7200,
            3600,
            1209600,
            60,
        ))],
    );
    let mut cache = cache();
    // NXDOMAIN for A, 300 s: under ANY and under A until 400.
    cache.insert(at(100), nxdomain("nope.example."));
    // NXDOMAIN for TXT, 60 s: under ANY until 260, and under TXT.
    cache.insert(
        at(200),
        Offer::Negative {
            key: key("nope.example.", RecordType::TXT),
            kind: Negative::NxDomain,
            soa: Some(short_soa),
            rank: Rank::AuthAnswer,
            denial: Vec::new(),
            validation: Validation::NotPerformed,
            truncated: false,
        },
    );
    // The entry under ANY has expired; the copy under A has not.
    cache.insert(
        at(300),
        positive(rrset(
            "nope.example.",
            300,
            vec![RData::TXT(TXT::new(vec!["exists".to_string()]))],
        )),
    );
    let now = at(301);
    assert!(matches!(
        cache.get(&key("nope.example.", RecordType::TXT), now),
        Some(Entry::Positive { .. })
    ));
    assert!(
        cache
            .get(&key("nope.example.", RecordType::A), now)
            .is_none(),
        "the name has data, so no type at it is NXDOMAIN: {:?}",
        cache.get(&key("nope.example.", RecordType::A), now)
    );
}

/// A negative answer ranks as the answer it came in (RFC 2181 §5.4.1): a
/// forwarder's NODATA gives way to the forwarder's data for the key, and
/// an authoritative NODATA does not.
#[test]
fn a_negative_ranks_as_the_answer_it_came_in() {
    let nodata = |rank| Offer::Negative {
        key: key("x.example.", RecordType::A),
        kind: Negative::NoData,
        soa: Some(soa()),
        rank,
        denial: Vec::new(),
        validation: Validation::NotPerformed,
        truncated: false,
    };
    let forwarded = Offer::Positive {
        set: rrset("x.example.", 300, vec![a("192.0.2.88")]),
        rank: Rank::NonAuthAnswer,
        validation: Validation::NotPerformed,
        proof: Vec::new(),
        truncated: false,
    };
    for (rank, replaced) in [(Rank::NonAuthAnswer, true), (Rank::AuthAnswer, false)] {
        let mut cache = cache();
        cache.insert(at(100), nodata(rank));
        cache.insert(at(110), forwarded.clone());
        let entry = cache.get(&key("x.example.", RecordType::A), at(111));
        assert_eq!(
            matches!(entry, Some(Entry::Positive { .. })),
            replaced,
            "{rank:?}: {entry:?}"
        );
    }
}

/// An NXDOMAIN of lower rank than live data of the type it answered
/// neither replaces that data nor hides the name behind it (RFC 2181
/// §5.4.1): the data shows the name exists.
#[test]
fn a_lower_ranked_nxdomain_leaves_data_of_its_type() {
    let mut cache = cache();
    cache.insert(
        at(100),
        Offer::Positive {
            set: rrset("x.example.", 3600, vec![a("192.0.2.88")]),
            rank: Rank::AuthAuthority,
            validation: Validation::NotPerformed,
            proof: Vec::new(),
            truncated: false,
        },
    );
    cache.insert(
        at(110),
        Offer::Negative {
            key: key("x.example.", RecordType::A),
            kind: Negative::NxDomain,
            soa: Some(soa()),
            rank: Rank::NonAuthAnswer,
            denial: Vec::new(),
            validation: Validation::NotPerformed,
            truncated: false,
        },
    );
    let now = at(1000);
    assert!(matches!(
        cache.get(&key("x.example.", RecordType::A), now),
        Some(Entry::Positive { .. })
    ));
    assert!(
        cache
            .nxdomain_above(&LowerName::new(&name("x.example.")), DNSClass::IN, at(111))
            .is_none()
    );
}

/// Live data of any type at a name, or at a name below it, shows that the
/// name exists: an NXDOMAIN of lower rank for another type is not kept,
/// and hides none of it (RFC 2181 §5.4.1, RFC 8020 §2).
#[test]
fn a_lower_ranked_nxdomain_leaves_data_of_any_type_at_or_below_its_name() {
    for owner in ["x.example.", "y.x.example."] {
        let mut cache = cache();
        cache.insert(
            at(100),
            Offer::Positive {
                set: rrset(owner, 3600, vec![a("192.0.2.88")]),
                rank: Rank::AuthAuthority,
                validation: Validation::NotPerformed,
                proof: Vec::new(),
                truncated: false,
            },
        );
        cache.insert(
            at(110),
            Offer::Negative {
                key: key("x.example.", RecordType::MX),
                kind: Negative::NxDomain,
                soa: Some(soa()),
                rank: Rank::NonAuthAnswer,
                denial: Vec::new(),
                validation: Validation::NotPerformed,
                truncated: false,
            },
        );
        let now = at(111);
        assert!(
            cache
                .nxdomain_above(&LowerName::new(&name("x.example.")), DNSClass::IN, now)
                .is_none(),
            "{owner}"
        );
        assert!(
            cache.get(&key("x.example.", RecordType::MX), now).is_none(),
            "{owner}"
        );
        assert!(matches!(
            cache.get(&key(owner, RecordType::A), now),
            Some(Entry::Positive { .. })
        ));
    }
}

#[test]
fn nxdomain_rank_protection_is_independent_of_the_question_type() {
    for owner in ["x.example.", "y.x.example."] {
        for rtype in [RecordType::A, RecordType::MX, RecordType::ANY] {
            for nodata in [false, true] {
                for rank in [Rank::NonAuthAnswer, Rank::AuthAnswer] {
                    let mut cache = cache();
                    let evidence = if nodata {
                        Offer::Negative {
                            key: key(owner, RecordType::A),
                            kind: Negative::NoData,
                            soa: Some(soa()),
                            rank,
                            denial: Vec::new(),
                            validation: Validation::NotPerformed,
                            truncated: false,
                        }
                    } else {
                        Offer::Positive {
                            set: rrset(owner, 300, vec![a("192.0.2.88")]),
                            rank,
                            validation: Validation::NotPerformed,
                            proof: Vec::new(),
                            truncated: false,
                        }
                    };
                    cache.insert(at(100), evidence);
                    cache.insert(
                        at(110),
                        Offer::Negative {
                            key: key("x.example.", rtype),
                            kind: Negative::NxDomain,
                            soa: Some(soa()),
                            rank: Rank::NonAuthAnswer,
                            denial: Vec::new(),
                            validation: Validation::NotPerformed,
                            truncated: false,
                        },
                    );
                    let denied = cache
                        .nxdomain_above(&LowerName::new(&name("x.example.")), DNSClass::IN, at(111))
                        .is_some();
                    assert_eq!(
                        denied,
                        rank <= Rank::NonAuthAnswer,
                        "owner {owner}, question {rtype:?}, nodata {nodata}, rank {rank:?}"
                    );
                }
            }
        }
    }
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
            rank: Rank::AuthAnswer,
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
        cd: false,
        follows: None,
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
        at(1),
    );
    assert!(matches!(validation(&cache), Validation::Insecure(_)));
}

/// The RRSIGs are an RRset of their own: their TTL does not shorten data
/// that has not validated, and a Secure RRset lives no longer than the
/// RRSIGs that verified it keep it Secure (RFC 4035 §5.3.3), as the
/// resolver works that out.
#[test]
fn a_secure_rrset_lives_no_longer_than_its_result() {
    let mut cache = cache();
    let www = key("www.example.", RecordType::A);
    let set = signed(
        rrset("www.example.", 86400, vec![a("192.0.2.1")]),
        600,
        86400,
    );
    cache.insert(at(0), positive(set.clone()));
    assert_eq!(expires(&cache, &www, at(0)), at(86400));
    cache.validated(
        &www,
        &Checked::Rrset(set),
        Validation::Secure,
        Some(at(600)),
        at(1),
    );
    assert_eq!(expires(&cache, &www, at(1)), at(600));
}

/// A failure that persists is cached twice as long each time, up to 5
/// minutes, and one that comes long after the last starts again at the
/// failure TTL (RFC 9520 §3.2).
#[test]
fn a_persistent_failure_is_cached_longer_each_time() {
    let mut cache = cache();
    let www = key("www.example.", RecordType::A);
    let fail = |cache: &mut Cache, now: u64| {
        let follows = cache.persisting(&www, at(now));
        cache.insert(
            at(now),
            Offer::Failure {
                key: www.clone(),
                why: FailureKind::NoReachableAuthority,
                cd: false,
                follows,
            },
        );
        cache.get(&www, at(now)).map(Entry::expires)
    };
    let mut now = 0;
    let mut lasted = Vec::new();
    for _ in 0..7 {
        let until = fail(&mut cache, now)
            .expect("cached")
            .since_start()
            .as_secs();
        lasted.push(until - now);
        // Asked again a second after it ends.
        now = until + 1;
    }
    assert_eq!(lasted, [5, 10, 20, 40, 80, 160, 300]);
    assert_eq!(fail(&mut cache, now), Some(at(now + 300)));
    // Long after the last one ended, a failure is new again.
    let later = now + 300 + 300 + 1;
    assert_eq!(fail(&mut cache, later), Some(at(later + 5)));
}

/// Whether a failure persists is read when the resolution that fails
/// again begins, so one that begins while the last failure persists and
/// ends long after is still cached twice as long (RFC 9520 §3.2).
#[test]
fn a_failure_persists_from_when_its_resolution_began() {
    let mut cache = cache();
    let www = key("www.example.", RecordType::A);
    let offer = |follows| Offer::Failure {
        key: www.clone(),
        why: FailureKind::NoReachableAuthority,
        cd: false,
        follows,
    };
    cache.insert(at(0), offer(None));
    assert_eq!(cache.persisting(&www, at(9)), Some(Duration::from_secs(5)));
    assert_eq!(cache.persisting(&www, at(10)), None);
    // Began at 6, while the first failure persisted, and failed at 60.
    let follows = cache.persisting(&www, at(6));
    cache.insert(at(60), offer(follows));
    assert_eq!(cache.get(&www, at(60)).map(Entry::expires), Some(at(70)));
}

/// A cache on a budget with room for its index and `room` bytes more.
fn limited(room: usize) -> Cache {
    let budget = Budget::new(Cache::storage(64).unwrap() + room);
    Cache::new(limits(64), &budget).unwrap()
}

/// What a cache charges its budget for storing `offer`.
fn charge(offer: Offer) -> usize {
    let mut cache = cache();
    let empty = cache.budget().used();
    cache.insert(at(0), offer);
    cache.budget().used() - empty
}

/// A TXT RRset at `owner` whose one string is 200 octets.
fn text(owner: &str, ttl: u32) -> RecordSet {
    rrset(
        owner,
        ttl,
        vec![RData::TXT(TXT::new(vec!["x".repeat(200)]))],
    )
}

/// Past its entry limit the cache keeps the entries that live longest.
#[test]
fn the_cache_holds_no_more_entries_than_its_limit() {
    let mut cache = counted(3);
    for ttl in [40, 10, 50, 20, 30] {
        let owner = format!("ttl{ttl}.example.");
        cache.insert(at(0), positive(rrset(&owner, ttl, vec![a("192.0.2.1")])));
    }
    let kept: Vec<String> = cache
        .entries(at(0))
        .map(|(key, _)| key.name.to_string())
        .collect();
    assert_eq!(kept.len(), 3);
    for ttl in [30, 40, 50] {
        assert!(kept.contains(&format!("ttl{ttl}.example.")), "{kept:?}");
    }
}

/// Past its budget the cache keeps what lives longest and fits.
#[test]
fn the_cache_holds_no_more_memory_than_its_budget() {
    // Every owner has as many octets, so each entry is charged the same:
    // two fit and three do not.
    let one = charge(positive(text("ttl40.example.", 40)));
    let mut cache = limited(2 * one + one / 2);
    for ttl in [40, 10, 50, 20] {
        cache.insert(at(0), positive(text(&format!("ttl{ttl}.example."), ttl)));
        assert!(cache.budget().used() <= cache.budget().limit());
    }
    let kept: Vec<String> = cache
        .entries(at(0))
        .map(|(key, _)| key.name.to_string())
        .collect();
    assert_eq!(kept.len(), 2, "{kept:?}");
    for ttl in [40, 50] {
        assert!(kept.contains(&format!("ttl{ttl}.example.")), "{kept:?}");
    }
}

/// The records that support an entry are charged with it, as the entry's
/// own are.
#[test]
fn an_entry_whose_proof_is_past_the_budget_is_not_kept() {
    let small = rrset("www.example.", 60, vec![a("192.0.2.80")]);
    let proved = || Offer::Positive {
        set: small.clone(),
        rank: Rank::AuthAnswer,
        validation: Validation::NotPerformed,
        proof: (0..3)
            .map(|index| text(&format!("p{index}.example."), 60))
            .collect(),
        truncated: false,
    };
    let alone = charge(positive(small.clone()));
    assert!(charge(proved()) > alone);
    let mut cache = limited(alone);
    cache.insert(at(0), proved());
    assert!(
        cache
            .get(&key("www.example.", RecordType::A), at(0))
            .is_none()
    );
    // Without the proof it fits.
    cache.insert(at(0), positive(small));
    assert!(
        cache
            .get(&key("www.example.", RecordType::A), at(0))
            .is_some()
    );
}
