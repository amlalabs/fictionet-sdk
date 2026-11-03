//! Signed zones as validators see them: negative answers at a DNAME
//! owner, the HINFO answer to ANY, and what `check_chain` reports for a
//! zone changed after signing.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
use fictionet::stdlib::protocols::dns::dnssec::{
    Algorithm, AlgorithmPolicy, Anchors, Chain, DigestType, Fetched, KeyFlags, KeySet, Link, Ring,
    Sign, TBS, Validation, Verify, Window, ZoneKey, ds, validate_denial, validate_rrset,
};
use fictionet::stdlib::protocols::dns::op::{Edns, Message, MessageType, OpCode, Query};
use fictionet::stdlib::protocols::dns::rr::rdata::{A, NS, NULL, SOA};
use fictionet::stdlib::protocols::dns::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::protocols::dns::{Parsed, Request};
use fictionet::stdlib::services::dns::zone::{
    Answered, AnyResponse, ChainProblem, Denial, Signed, Zone, ZoneData, answer, check_chain, dname,
};
use fictionet::stdlib::services::serve::Transport;
use fictionet::{Seed, SeededEntropy};

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

fn rrset(owner: &str, data: Vec<RData>) -> RecordSet {
    let owner = name(owner);
    let mut set = RecordSet::with_ttl(owner.clone(), data[0].record_type(), 3600);
    set.set_records(
        data.into_iter()
            .map(|data| Record::from_rdata(owner.clone(), 3600, data))
            .collect(),
    );
    set
}

fn time(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

/// A time inside [`window`].
fn now() -> SystemTime {
    time(1_750_000_000)
}

fn window() -> Window {
    Window {
        inception: time(1_700_000_000),
        expiration: time(1_800_000_000),
    }
}

fn keys() -> KeySet {
    let key = |seed: u64, algorithm, flags| -> Arc<dyn Sign> {
        Arc::new(ZoneKey::generate(
            &SeededEntropy::new(Seed::from_u64(seed)),
            algorithm,
            flags,
        ))
    };
    KeySet {
        keys: vec![
            key(1, Algorithm::Ed25519, KeyFlags::KSK),
            key(2, Algorithm::EcdsaP256Sha256, KeyFlags::ZSK),
        ],
    }
}

/// `example.` with its name server and a DNAME at `d.example.`.
fn zone() -> Zone {
    let soa = SOA::new(
        name("ns1.example."),
        name("hostmaster.example."),
        1,
        7200,
        3600,
        1209600,
        300,
    );
    Zone::builder(name("example."), soa, 3600)
        .rrset(rrset("example.", vec![RData::NS(NS(name("ns1.example.")))]))
        .rrset(rrset("ns1.example.", vec![RData::A(A::new(192, 0, 2, 1))]))
        .rrset(rrset("d.example.", vec![dname(&name("target.test."))]))
        .build()
        .unwrap()
}

fn denials() -> [Denial; 2] {
    [
        Denial::Nsec,
        Denial::Nsec3 {
            opt_out: false,
            salt: Vec::new(),
        },
    ]
}

/// `data`'s answer to `qname` `qtype`, asked with DO.
fn ask(data: &dyn ZoneData, qname: &str, qtype: RecordType, any: AnyResponse) -> Message {
    let mut message = Message::new(7, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(name(qname), qtype));
    let mut edns = Edns::new();
    edns.set_max_payload(1232).set_dnssec_ok(true);
    message.set_edns(edns);
    let Parsed::Request(request) = Request::parse(&message.to_vec().unwrap(), Transport::Udp)
    else {
        panic!("a query parses");
    };
    match answer(&*data.view(&request.question), &request, any) {
        Answered::Response(response) => response.message,
        Answered::Unknown { name } => panic!("{name} is unknown"),
    }
}

/// `records` gathered into RRsets, each RRSIG with the RRset it covers.
fn sets(records: &[Record]) -> Vec<RecordSet> {
    let mut out: Vec<RecordSet> = Vec::new();
    for record in records
        .iter()
        .filter(|r| r.record_type() != RecordType::RRSIG)
    {
        let at = out.iter().position(|set| {
            *set.name() == record.name && set.record_type() == record.record_type()
        });
        let at = at.unwrap_or_else(|| {
            out.push(RecordSet::with_ttl(
                record.name.clone(),
                record.record_type(),
                record.ttl,
            ));
            out.len() - 1
        });
        out[at].insert(record.clone(), 0);
    }
    for record in records {
        if let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &record.data {
            let covered = rrsig.input().type_covered;
            if let Some(set) = out
                .iter_mut()
                .find(|set| *set.name() == record.name && set.record_type() == covered)
            {
                set.insert_rrsig(record.clone());
            }
        }
    }
    out
}

/// The chain of `data`, anchored at its own apex.
fn chain(data: &dyn ZoneData) -> (Chain, Anchors) {
    let dnskey =
        sets(&ask(data, "example.", RecordType::DNSKEY, AnyResponse::All).answers).remove(0);
    let chain = Chain {
        links: vec![Link {
            zone: name("example."),
            ds: Fetched::Failed,
            dnskey: Fetched::Answer(dnskey),
        }],
    };
    (chain, Anchors::of(vec![keys().anchor(&name("example."))]))
}

fn validate(data: &dyn ZoneData, set: &RecordSet) -> Validation {
    let (chain, anchors) = chain(data);
    validate_rrset(
        set,
        &[],
        &chain,
        &anchors,
        &AlgorithmPolicy::iana(),
        now(),
        &Ring,
    )
}

#[test]
fn nodata_at_a_dname_owner_validates() {
    // A DNAME bit stops an NSEC or NSEC3 from proving names below its
    // owner, not types at it (RFC 6840 §4.1).
    for denial in denials() {
        let offline = zone().signed(&keys(), window(), denial.clone()).unwrap();
        let online = Signed::new(zone(), keys(), window(), denial.clone());
        for (how, data) in [
            ("signed once", &offline as &dyn ZoneData),
            ("signed as asked", &online),
        ] {
            let reply = ask(data, "d.example.", RecordType::TXT, AnyResponse::All);
            assert!(reply.answers.is_empty(), "{denial:?} {how}");
            let (chain, anchors) = chain(data);
            let validation = validate_denial(
                &Query::query(name("d.example."), RecordType::TXT),
                reply.metadata.response_code,
                &sets(&reply.authorities),
                &chain,
                &anchors,
                &AlgorithmPolicy::iana(),
                now(),
                &Ring,
            )
            .validation;
            assert_eq!(validation, Validation::Secure, "{denial:?} {how}");
        }
    }
}

#[test]
fn the_hinfo_answer_to_any_is_signed_where_the_zone_can_sign() {
    // RFC 8482 §4.2: a synthesized HINFO in a signed zone must be signed.
    let online = Signed::new(zone(), keys(), window(), Denial::Nsec);
    let reply = ask(&online, "ns1.example.", RecordType::ANY, AnyResponse::Hinfo);
    let answer = sets(&reply.answers);
    assert_eq!(answer.len(), 1);
    assert_eq!(answer[0].record_type(), RecordType::HINFO);
    assert_eq!(validate(&online, &answer[0]), Validation::Secure);

    // A zone signed once holds no keys to sign it with, so it answers
    // with one RRset of the name and its RRSIGs (RFC 8482 §4.1).
    let offline = zone().signed(&keys(), window(), Denial::Nsec).unwrap();
    let reply = ask(
        &offline,
        "ns1.example.",
        RecordType::ANY,
        AnyResponse::Hinfo,
    );
    let answer = sets(&reply.answers);
    assert_eq!(answer.len(), 1);
    assert_eq!(answer[0].record_type(), RecordType::A);
    assert_eq!(validate(&offline, &answer[0]), Validation::Secure);
}

#[test]
fn check_chain_reports_an_rrset_changed_after_signing() {
    let signed = zone().signed(&keys(), window(), Denial::Nsec).unwrap();
    assert_eq!(check_chain(&[&signed], &AlgorithmPolicy::iana(), now()), []);

    // A record added to a signed RRset leaves its RRSIG behind.
    let grown = signed
        .with(rrset("ns1.example.", vec![RData::A(A::new(192, 0, 2, 99))]))
        .unwrap();
    let served = sets(&ask(&grown, "ns1.example.", RecordType::A, AnyResponse::All).answers);
    assert!(matches!(validate(&grown, &served[0]), Validation::Bogus(_)));
    assert_eq!(
        check_chain(&[&grown], &AlgorithmPolicy::iana(), now()),
        [ChainProblem::SignatureInvalid {
            apex: LowerName::new(&name("example.")),
            owner: LowerName::new(&name("ns1.example.")),
            rtype: RecordType::A,
        }]
    );

    // A new RRset has no RRSIG at all.
    let added = signed
        .with(rrset("new.example.", vec![RData::A(A::new(192, 0, 2, 7))]))
        .unwrap();
    assert_eq!(
        check_chain(&[&added], &AlgorithmPolicy::iana(), now()),
        [ChainProblem::SignatureInvalid {
            apex: LowerName::new(&name("example.")),
            owner: LowerName::new(&name("new.example.")),
            rtype: RecordType::A,
        }]
    );
}

/// The algorithms of the RRSIGs among `records`.
fn rrsig_algorithms(records: &[Record]) -> Vec<u8> {
    let mut algorithms: Vec<u8> = records
        .iter()
        .filter_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => Some(u8::from(rrsig.input().algorithm)),
            _ => None,
        })
        .collect();
    algorithms.sort();
    algorithms.dedup();
    algorithms
}

#[test]
fn a_ksk_and_zsk_of_two_algorithms_sign_every_rrset_with_both() {
    // Ed25519 (15) and ECDSA P-256 (13): RFC 4035 §2.2 wants an RRSIG of
    // each algorithm in the DNSKEY RRset on every RRset.
    let signed = zone().signed(&keys(), window(), Denial::Nsec).unwrap();
    for (qname, qtype) in [
        ("ns1.example.", RecordType::A),
        ("example.", RecordType::DNSKEY),
        ("example.", RecordType::SOA),
    ] {
        let reply = ask(&signed, qname, qtype, AnyResponse::All);
        assert_eq!(
            rrsig_algorithms(&reply.answers),
            [13, 15],
            "{qname} {qtype}"
        );
    }
}

#[test]
fn check_chain_reports_a_wrong_sha256_ds_beside_a_right_sha1_one() {
    // A validator ignores SHA-1 DS records next to a stronger digest
    // (RFC 4509 §3), so the right SHA-1 record cannot save the child.
    let child_keys = keys();
    let soa = SOA::new(
        name("ns1.child.example."),
        name("hostmaster.child.example."),
        1,
        7200,
        3600,
        1209600,
        300,
    );
    let child = Zone::builder(name("child.example."), soa, 3600)
        .rrset(rrset(
            "child.example.",
            vec![RData::NS(NS(name("ns1.child.example.")))],
        ))
        .rrset(rrset(
            "ns1.child.example.",
            vec![RData::A(A::new(192, 0, 2, 2))],
        ))
        .build()
        .unwrap()
        .signed(&child_keys, window(), Denial::Nsec)
        .unwrap();
    let ksk = child_keys.keys[0].dnskey();
    let other = ZoneKey::generate(
        &SeededEntropy::new(Seed::from_u64(9)),
        Algorithm::Ed25519,
        KeyFlags::KSK,
    )
    .dnskey();
    let owner = name("child.example.");
    let ds_records = [
        ds(&owner, &ksk, DigestType::Sha1),
        ds(&owner, &other, DigestType::Sha256),
    ]
    .map(|record| Record::from_rdata(owner.clone(), 3600, RData::DNSSEC(DNSSECRData::DS(record))));
    let mut ds_set = RecordSet::with_ttl(owner.clone(), RecordType::DS, 3600);
    ds_set.set_records(ds_records.to_vec());
    let parent_keys = KeySet {
        keys: vec![Arc::new(ZoneKey::generate(
            &SeededEntropy::new(Seed::from_u64(10)),
            Algorithm::Ed25519,
            KeyFlags::KSK,
        ))],
    };
    let parent = Zone::builder(
        name("example."),
        SOA::new(
            name("ns1.example."),
            name("hostmaster.example."),
            1,
            7200,
            3600,
            1209600,
            300,
        ),
        3600,
    )
    .rrset(rrset("example.", vec![RData::NS(NS(name("ns1.example.")))]))
    .rrset(rrset("ns1.example.", vec![RData::A(A::new(192, 0, 2, 1))]))
    .delegate(
        owner.clone(),
        rrset(
            "child.example.",
            vec![RData::NS(NS(name("ns1.child.example.")))],
        ),
        vec![rrset(
            "ns1.child.example.",
            vec![RData::A(A::new(192, 0, 2, 2))],
        )],
        Some(ds_set),
    )
    .build()
    .unwrap()
    .signed(&parent_keys, window(), Denial::Nsec)
    .unwrap();
    assert_eq!(
        check_chain(&[&parent, &child], &AlgorithmPolicy::iana(), now()),
        [ChainProblem::DsMismatch {
            parent: LowerName::new(&name("example.")),
            child: LowerName::new(&owner),
        }]
    );
}

/// One algorithm the policy validates is enough for a path (RFC 6840
/// §5.11): a zone with a KSK and a ZSK of Ed25519 and of ECDSA P-256 is
/// Secure, and has no problem, under a policy that drops either one.
#[test]
fn check_chain_finds_a_zone_of_two_algorithms_whole_with_either() {
    let key = |seed: u64, algorithm, flags| -> Arc<dyn Sign> {
        Arc::new(ZoneKey::generate(
            &SeededEntropy::new(Seed::from_u64(seed)),
            algorithm,
            flags,
        ))
    };
    let both = KeySet {
        keys: vec![
            key(1, Algorithm::Ed25519, KeyFlags::KSK),
            key(2, Algorithm::Ed25519, KeyFlags::ZSK),
            key(3, Algorithm::EcdsaP256Sha256, KeyFlags::KSK),
            key(4, Algorithm::EcdsaP256Sha256, KeyFlags::ZSK),
        ],
    };
    let signed = zone().signed(&both, window(), Denial::Nsec).unwrap();
    let served = sets(&ask(&signed, "ns1.example.", RecordType::A, AnyResponse::All).answers);
    let dnskey =
        sets(&ask(&signed, "example.", RecordType::DNSKEY, AnyResponse::All).answers).remove(0);
    let chain = Chain {
        links: vec![Link {
            zone: name("example."),
            ds: Fetched::Failed,
            dnskey: Fetched::Answer(dnskey),
        }],
    };
    let anchors = Anchors::of(vec![both.anchor(&name("example."))]);
    for dropped in [13, 15] {
        let mut policy = AlgorithmPolicy::iana();
        policy.validate.remove(&dropped);
        assert_eq!(
            check_chain(&[&signed], &policy, now()),
            [],
            "without {dropped}"
        );
        let validation = validate_rrset(&served[0], &[], &chain, &anchors, &policy, now(), &Ring);
        assert_eq!(validation, Validation::Secure, "without {dropped}");
    }
    // Without both, validators find the zone Insecure.
    let mut policy = AlgorithmPolicy::iana();
    policy.validate.remove(&13);
    policy.validate.remove(&15);
    let apex = LowerName::new(&name("example."));
    assert_eq!(
        check_chain(&[&signed], &policy, now()),
        [
            ChainProblem::UnsupportedAlgorithm {
                apex: apex.clone(),
                algorithm: 15,
            },
            ChainProblem::UnsupportedAlgorithm {
                apex,
                algorithm: 13,
            },
        ]
    );
}

/// `text` as an uncompressed name on the wire.
fn wire(text: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for label in name(text).iter() {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label);
    }
    bytes.push(0);
    bytes
}

/// RDATA of type `code`, which hickory carries as unknown, from `parts`.
fn unknown(code: u16, parts: &[&[u8]]) -> RData {
    RData::Unknown {
        code: RecordType::from(code),
        rdata: NULL::with(parts.concat()),
    }
}

/// The names in the RDATA of the types RFC 4034 §6.2 item 3 lists, as
/// RFC 6840 §5.1 amends it, that hickory carries as unknown RDATA are
/// signed in canonical, lowercase form, as other validators check them,
/// whatever their case in the zone, and validate as served. The other
/// fields keep their octets, letters among them.
#[test]
fn names_in_unknown_rdata_are_signed_in_lowercase() {
    // A 16-bit field and an A6 address suffix whose octets are ASCII
    // capitals.
    let field: &[u8] = b"AB";
    let suffix: &[u8] = b"CDEFGHIJ";
    // (owner, as served, as another validator signs it)
    let cases = [
        (
            "d.example.",
            dname(&name("Target.TEST.")),
            dname(&name("target.test.")),
        ),
        (
            "rp.example.",
            unknown(17, &[&wire("Admin.Example."), &wire("Txt.Example.")]),
            unknown(17, &[&wire("admin.example."), &wire("txt.example.")]),
        ),
        (
            "afsdb.example.",
            unknown(18, &[field, &wire("AFS.Example.")]),
            unknown(18, &[field, &wire("afs.example.")]),
        ),
        (
            "px.example.",
            unknown(26, &[field, &wire("Map.Example."), &wire("X400.Example.")]),
            unknown(26, &[field, &wire("map.example."), &wire("x400.example.")]),
        ),
        (
            "a6.example.",
            unknown(38, &[&[64], suffix, &wire("Prefix.Example.")]),
            unknown(38, &[&[64], suffix, &wire("prefix.example.")]),
        ),
        (
            "mb.example.",
            unknown(7, &[&wire("Host.Example.")]),
            unknown(7, &[&wire("host.example.")]),
        ),
    ];
    let soa = SOA::new(
        name("ns1.example."),
        name("hostmaster.example."),
        1,
        7200,
        3600,
        1209600,
        300,
    );
    let mut zone = Zone::builder(name("example."), soa, 3600)
        .rrset(rrset("example.", vec![RData::NS(NS(name("ns1.example.")))]))
        .rrset(rrset("ns1.example.", vec![RData::A(A::new(192, 0, 2, 1))]));
    for (owner, served, _) in &cases {
        zone = zone.rrset(rrset(owner, vec![served.clone()]));
    }
    let signed = zone
        .build()
        .unwrap()
        .signed(&keys(), window(), Denial::Nsec)
        .unwrap();
    let keys: Vec<_> = keys().keys.iter().map(|key| key.dnskey()).collect();
    for (owner, data, canonical) in cases {
        let rtype = data.record_type();
        let served = sets(&ask(&signed, owner, rtype, AnyResponse::All).answers);
        assert_eq!(validate(&signed, &served[0]), Validation::Secure, "{owner}");
        // The bytes another validator checks: the names in lowercase.
        let canonical = rrset(owner, vec![canonical]);
        assert_eq!(served[0].rrsigs().len(), 2);
        for record in served[0].rrsigs() {
            let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &record.data else {
                panic!("an RRSIG");
            };
            let tbs = TBS::from_input(
                canonical.name(),
                canonical.dns_class(),
                rrsig.input(),
                canonical.records_without_rrsigs(),
            )
            .unwrap();
            let verified = keys
                .iter()
                .any(|key| Ring.verify(key, tbs.as_ref(), rrsig.sig()));
            assert!(verified, "{owner}: the {:?} RRSIG", rrsig.input().algorithm);
        }
    }
}
