//! Signed zones as validators see them: negative answers at a DNAME
//! owner, the HINFO answer to ANY, and what `check_chain` reports for a
//! zone changed after signing.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fictionet::stdlib::protocols::dns::EdeCode;
use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
use fictionet::stdlib::protocols::dns::dnssec::{
    Algorithm, AlgorithmPolicy, Anchors, Chain, DigestType, Fetched, KeyFlags, KeySet, Link, Ring,
    Sign, TBS, Validation, Verify, Window, ZoneKey, ds, validate_denial, validate_rrset,
};
use fictionet::stdlib::protocols::dns::op::{
    Edns, Message, MessageType, OpCode, Query, ResponseCode,
};
use fictionet::stdlib::protocols::dns::rr::rdata::{A, CNAME, MX, NS, NULL, SOA};
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
    ask_with(data, qname, qtype, any, true)
}

/// `data`'s answer to `qname` `qtype`, asked with DO as `dnssec_ok` says.
fn ask_with(
    data: &dyn ZoneData,
    qname: &str,
    qtype: RecordType,
    any: AnyResponse,
    dnssec_ok: bool,
) -> Message {
    let mut message = Message::new(7, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(name(qname), qtype));
    let mut edns = Edns::new();
    edns.set_max_payload(1232).set_dnssec_ok(dnssec_ok);
    message.set_edns(edns);
    let Parsed::Request(request) = Request::parse(&message.to_vec().unwrap(), Transport::Udp)
    else {
        panic!("a query parses");
    };
    match answer(&*data.view(&request.question), &request, any) {
        Answered::Response(response) => response.message,
        Answered::Unknown { name, .. } => panic!("{name} is unknown"),
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
    .validation
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

/// NODATA for a wildcard's own name is a NODATA for a name that exists:
/// it carries the one record that matches the name (RFC 4035 §3.1.3.1,
/// RFC 5155 §7.2.3), and no more. NODATA for a name the wildcard answers
/// for carries the records that deny the name and the one that matches
/// the wildcard, and with NSEC3 the one that matches the closest
/// encloser too (RFC 4035 §3.1.3.4, RFC 5155 §7.2.5). Every one
/// validates.
#[test]
fn wildcard_nodata_carries_the_proof_for_the_name_asked() {
    for denial in denials() {
        let base = || {
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
                .rrset(rrset(
                    "*.wild.example.",
                    vec![RData::A(A::new(192, 0, 2, 9))],
                ))
                .build()
                .unwrap()
        };
        let offline = base().signed(&keys(), window(), denial.clone()).unwrap();
        let online = Signed::new(base(), keys(), window(), denial.clone());
        let denials = match denial {
            Denial::Nsec => RecordType::NSEC,
            Denial::Nsec3 { .. } => RecordType::NSEC3,
        };
        for (how, data) in [
            ("signed once", &offline as &dyn ZoneData),
            ("signed as asked", &online),
        ] {
            for qname in ["*.wild.example.", "x.wild.example."] {
                let reply = ask(data, qname, RecordType::TXT, AnyResponse::All);
                let case = format!("{denial:?} {how} {qname}");
                assert_eq!(
                    reply.metadata.response_code,
                    ResponseCode::NoError,
                    "{case}"
                );
                assert!(reply.answers.is_empty(), "{case}");
                let proof: Vec<RecordSet> = sets(&reply.authorities)
                    .into_iter()
                    .filter(|set| set.record_type() == denials)
                    .collect();
                if qname.starts_with('*') {
                    assert_eq!(proof.len(), 1, "{case}: {proof:?}");
                }
                let (chain, anchors) = chain(data);
                let validation = validate_denial(
                    &Query::query(name(qname), RecordType::TXT),
                    reply.metadata.response_code,
                    &sets(&reply.authorities),
                    &chain,
                    &anchors,
                    &AlgorithmPolicy::iana(),
                    now(),
                    &Ring,
                )
                .validation;
                assert_eq!(validation, Validation::Secure, "{case}");
            }
        }
    }
}

/// A wildcard that is only an empty non-terminal, with data below it,
/// still matches a name that does not exist, and the answer is NODATA
/// (RFC 4592 §2.2.1). It has no NSEC (RFC 4035 §2.3), so the NSEC that
/// covers it, whose next name is below it, proves it holds no records,
/// beside the NSEC that covers the name. Every way of signing gives a
/// proof that validates, and the proof never stands for an NXDOMAIN.
#[test]
fn nodata_at_an_empty_non_terminal_wildcard_validates() {
    for denial in denials() {
        let base = || {
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
                .rrset(rrset("a.*.example.", vec![RData::A(A::new(192, 0, 2, 9))]))
                .rrset(rrset("www.example.", vec![RData::A(A::new(192, 0, 2, 10))]))
                .build()
                .unwrap()
        };
        let offline = base().signed(&keys(), window(), denial.clone()).unwrap();
        let online = Signed::new(base(), keys(), window(), denial.clone());
        for (how, data) in [
            ("signed once", &offline as &dyn ZoneData),
            ("signed as asked", &online),
        ] {
            let case = format!("{denial:?} {how}");
            let reply = ask(data, "x.example.", RecordType::A, AnyResponse::All);
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::NoError,
                "{case}"
            );
            assert!(reply.answers.is_empty(), "{case}");
            let (chain, anchors) = chain(data);
            let validate = |rcode| {
                validate_denial(
                    &Query::query(name("x.example."), RecordType::A),
                    rcode,
                    &sets(&reply.authorities),
                    &chain,
                    &anchors,
                    &AlgorithmPolicy::iana(),
                    now(),
                    &Ring,
                )
                .validation
            };
            assert_eq!(
                validate(ResponseCode::NoError),
                Validation::Secure,
                "{case}"
            );
            assert_ne!(
                validate(ResponseCode::NXDomain),
                Validation::Secure,
                "{case}: the wildcard exists"
            );
        }
    }
}

/// The signed NSEC at a wildcard owner, copied to another owner, still
/// verifies, since its RRSIG's labels field rebuilds the wildcard. It
/// proves nothing there (RFC 4035 §5.4): alone it leaves an NXDOMAIN
/// unproven, and beside a real proof it is a record the resolver may not
/// use to deny other names.
#[test]
fn an_nsec_moved_off_its_wildcard_owner_proves_nothing() {
    let wild = Zone::builder(
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
    .rrset(rrset("www.example.", vec![RData::A(A::new(192, 0, 2, 2))]))
    .rrset(rrset("*.example.", vec![RData::A(A::new(192, 0, 2, 3))]))
    .build()
    .unwrap()
    .signed(&keys(), window(), Denial::Nsec)
    .unwrap();
    let nsec =
        sets(&ask(&wild, "*.example.", RecordType::NSEC, AnyResponse::All).answers).remove(0);
    let renamed = {
        let owner = name("v.example.");
        let mut set = RecordSet::with_ttl(owner.clone(), RecordType::NSEC, nsec.ttl());
        for record in nsec.records_without_rrsigs() {
            set.insert(
                Record::from_rdata(owner.clone(), record.ttl, record.data.clone()),
                0,
            );
        }
        for rrsig in nsec.rrsigs() {
            set.insert_rrsig(Record::from_rdata(
                owner.clone(),
                rrsig.ttl,
                rrsig.data.clone(),
            ));
        }
        set
    };
    let (chain, anchors) = chain(&wild);
    let deny = |qname: &str, authority: &[RecordSet]| {
        validate_denial(
            &Query::query(name(qname), RecordType::A),
            ResponseCode::NXDomain,
            authority,
            &chain,
            &anchors,
            &AlgorithmPolicy::iana(),
            now(),
            &Ring,
        )
    };
    // The real NXDOMAIN of a name the wildcard does not cover.
    let reply = ask(&wild, "a.b.ns1.example.", RecordType::A, AnyResponse::All);
    let proof = sets(&reply.authorities);
    let soa: Vec<RecordSet> = proof
        .iter()
        .filter(|set| set.record_type() == RecordType::SOA)
        .cloned()
        .collect();
    assert_eq!(soa.len(), 1);
    assert_eq!(
        deny("a.b.ns1.example.", &proof).validation,
        Validation::Secure
    );

    // The moved record spans v.example. to ns1.example., past the end of
    // the zone, so it would cover www.example. and the wildcard.
    let forged = deny("www.example.", &[renamed.clone(), soa[0].clone()]);
    assert_eq!(forged.validation, Validation::Bogus(EdeCode::NSEC_MISSING));

    let beside = deny(
        "a.b.ns1.example.",
        &proof.iter().cloned().chain([renamed]).collect::<Vec<_>>(),
    );
    assert_eq!(beside.unverified, Some(EdeCode::NSEC_MISSING));
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
        assert_eq!(
            validation.validation,
            Validation::Secure,
            "without {dropped}"
        );
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

/// A 768-bit RSA key, below the 1024 bits ring verifies.
const RSA_768: &str = "\
-----BEGIN PRIVATE KEY-----
MIIB5gIBADANBgkqhkiG9w0BAQEFAASCAdAwggHMAgEAAmEAv/j377CXA6WwFmuu
6z3A/fHdVuv4PvK2W84mGtO5aBJ+g24/wWbLvxz0dMNb+nIkZHItdMB3qioDE4p9
wFCTqaAw6Ad6fBASe/iAe5C0js/hs5T84EUBzwVJtc6Nu8uVAgMBAAECYFa++9o1
Y6fkQNOAyUPHXePiXPAgJMbdCgYl+xX4QjmC0eQ1910/RCYRwWzZskBTPtI5j15m
TeeZa7osw6yGz3EzGo8zDHLtVmdbAM4D8DCmfQYG7s6yUWR0ftqC8DYUwQIxAOIV
uQ8SY5ixEs1e33GwRwrSdtZ1jyeBAjQTxjF7XU0ukDuV2CWwALGFOHeo7TQ43QIx
ANlfvj1HNJtyB1vLeZLp/F04pRO3nNIUZy/vlXjYEQFuBjRp8s0SWYZtzHmobihW
GQIxAIRCVv9lL5SMykYQYUD98aF4HAM7xKJEi0hx5PjfhWZ4ffINp+PsQYuYNr9x
uEpblQIxAM0ub57d6I1V/BYsoWwIi1rfDgrnhRJTifcYegmgQaUM2rR80V+7E2At
ohWv45MVeQIxALIFJ1ICBy/LeiFLIT7pL09Op6t633mfL1jXD5J9lwuMeC9acSLw
Xo2a4bUygBz7Cg==
-----END PRIVATE KEY-----
";

/// RFC 5702 §2 allows RSA/SHA-256 moduli from 512 bits, and a zone signed
/// with such a key validates Secure: the signer and the verifier agree
/// (RFC 4035 §5.3). A signature over other data still fails.
#[test]
fn a_zone_signed_with_a_768_bit_rsa_key_validates() {
    use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
    let der = rsa::RsaPrivateKey::from_pkcs8_pem(RSA_768)
        .unwrap()
        .to_pkcs8_der()
        .unwrap();
    let rsa = ZoneKey::from_pkcs8(der.as_bytes(), Algorithm::RsaSha256, KeyFlags::KSK).unwrap();
    let keys = KeySet {
        keys: vec![Arc::new(rsa)],
    };
    let signed = zone().signed(&keys, window(), Denial::Nsec).unwrap();
    assert_eq!(check_chain(&[&signed], &AlgorithmPolicy::iana(), now()), []);
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
    let anchors = Anchors::of(vec![keys.anchor(&name("example."))]);
    let policy = AlgorithmPolicy::iana();
    let validation = validate_rrset(&served[0], &[], &chain, &anchors, &policy, now(), &Ring);
    assert_eq!(validation.validation, Validation::Secure);

    let dnskey = keys.keys[0].dnskey();
    let tbs = b"to be signed";
    let signature = keys.keys[0].sign(tbs);
    assert!(Ring.verify(&dnskey, tbs, &signature));
    assert!(!Ring.verify(&dnskey, b"something else", &signature));
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

/// The records of an RRset are signed in canonical order, by their RDATA
/// with its names in lowercase (RFC 4034 §6.3), however the names are
/// written: `Bob.example.` comes after `ann.example.`, though `B` comes
/// before `a`. Both what this signer makes and what another signer made
/// in that order validate.
#[test]
fn records_are_signed_in_canonical_order_whatever_the_case_of_their_names() {
    let mx = |exchange: &str| RData::MX(MX::new(10, name(exchange)));
    let written = rrset("mx.example.", vec![mx("Bob.example."), mx("ann.example.")]);
    let canonical = rrset("mx.example.", vec![mx("ann.example."), mx("bob.example.")]);
    let signed = Zone::builder(
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
    .rrset(written.clone())
    .build()
    .unwrap()
    .signed(&keys(), window(), Denial::Nsec)
    .unwrap();
    let served = sets(&ask(&signed, "mx.example.", RecordType::MX, AnyResponse::All).answers);
    assert_eq!(validate(&signed, &served[0]), Validation::Secure);
    // The bytes another validator checks: the records in canonical order.
    let dnskeys: Vec<_> = keys().keys.iter().map(|key| key.dnskey()).collect();
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
        let verified = dnskeys
            .iter()
            .any(|key| Ring.verify(key, tbs.as_ref(), rrsig.sig()));
        assert!(verified, "the {:?} RRSIG", rrsig.input().algorithm);
    }

    // The RRSIGs another signer made over the canonical records validate
    // the records as written.
    let mut theirs = written;
    for rrsig in sets(
        &ask(
            &zone()
                .with(canonical.clone())
                .unwrap()
                .signed(&keys(), window(), Denial::Nsec)
                .unwrap(),
            "mx.example.",
            RecordType::MX,
            AnyResponse::All,
        )
        .answers,
    )[0]
    .rrsigs()
    {
        theirs.insert_rrsig(rrsig.clone());
    }
    assert_eq!(validate(&signed, &theirs), Validation::Secure);
}

/// `example.` with a CNAME, an empty non-terminal at `b.example.`, and an
/// unsigned delegation of `sub.example.` with glue.
fn branching() -> Zone {
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
        .rrset(rrset(
            "alias.example.",
            vec![RData::CNAME(CNAME(name("ns1.example.")))],
        ))
        .rrset(rrset("a.b.example.", vec![RData::A(A::new(192, 0, 2, 2))]))
        .delegate(
            name("sub.example."),
            rrset("sub.example.", vec![RData::NS(NS(name("ns.sub.example.")))]),
            vec![rrset(
                "ns.sub.example.",
                vec![RData::A(A::new(192, 0, 2, 53))],
            )],
            None,
        )
        .build()
        .unwrap()
}

fn rtypes(records: &[Record]) -> Vec<(String, RecordType)> {
    records
        .iter()
        .map(|record| (record.name.to_string(), record.record_type()))
        .collect()
}

/// QTYPE NSEC at a zone cut of data signed as it is asked gets the NSEC
/// the parent's side holds there when it denies with NSEC, and a referral
/// when it denies with NSEC3, which holds none (RFC 4035 §2.6, §3.1.4).
#[test]
fn nsec_at_a_cut_of_data_signed_as_asked_is_the_parents_or_a_referral() {
    for dnssec_ok in [false, true] {
        let online = Signed::new(branching(), keys(), window(), Denial::Nsec);
        let reply = ask_with(
            &online,
            "sub.example.",
            RecordType::NSEC,
            AnyResponse::All,
            dnssec_ok,
        );
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.metadata.authoritative, "{dnssec_ok}");
        let nsec = sets(&reply.answers);
        assert_eq!(nsec.len(), 1);
        assert_eq!(nsec[0].record_type(), RecordType::NSEC);
        assert_eq!(*nsec[0].name(), name("sub.example."));
        if dnssec_ok {
            assert_eq!(validate(&online, &nsec[0]), Validation::Secure);
        }

        let denial = Denial::Nsec3 {
            opt_out: false,
            salt: Vec::new(),
        };
        let online = Signed::new(branching(), keys(), window(), denial);
        let reply = ask_with(
            &online,
            "sub.example.",
            RecordType::NSEC,
            AnyResponse::All,
            dnssec_ok,
        );
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(!reply.metadata.authoritative);
        assert!(reply.answers.is_empty());
        assert!(rtypes(&reply.authorities).contains(&("sub.example.".to_string(), RecordType::NS)));
        assert_eq!(
            rtypes(&reply.additionals),
            vec![("ns.sub.example.".to_string(), RecordType::A)]
        );
    }
}

/// QTYPE NSEC at a name that exists, empty non-terminals included, gets
/// the NSEC the online signer makes for it when it denies with NSEC, so no
/// NODATA proof lists the type it denies. With NSEC3 the zone holds no
/// NSEC, and the NODATA validates.
#[test]
fn nsec_at_an_existing_name_of_data_signed_as_asked_validates() {
    let online = Signed::new(branching(), keys(), window(), Denial::Nsec);
    for qname in ["ns1.example.", "b.example.", "alias.example."] {
        let reply = ask(&online, qname, RecordType::NSEC, AnyResponse::All);
        let answer = sets(&reply.answers);
        assert_eq!(answer.len(), 1, "{qname}");
        assert_eq!(answer[0].record_type(), RecordType::NSEC, "{qname}");
        assert_eq!(*answer[0].name(), name(qname));
        assert_eq!(validate(&online, &answer[0]), Validation::Secure, "{qname}");
    }

    let denial = Denial::Nsec3 {
        opt_out: false,
        salt: Vec::new(),
    };
    let online = Signed::new(branching(), keys(), window(), denial);
    for qname in ["ns1.example.", "b.example."] {
        let reply = ask(&online, qname, RecordType::NSEC, AnyResponse::All);
        assert!(reply.answers.is_empty(), "{qname}");
        let (chain, anchors) = chain(&online);
        let validation = validate_denial(
            &Query::query(name(qname), RecordType::NSEC),
            reply.metadata.response_code,
            &sets(&reply.authorities),
            &chain,
            &anchors,
            &AlgorithmPolicy::iana(),
            now(),
            &Ring,
        );
        assert_eq!(validation.validation, Validation::Secure, "{qname}");
    }
}

/// ANY at a CNAME of a zone that answers with a made-up HINFO gets the
/// signed CNAME, never a HINFO beside it (RFC 8482 §4.2).
#[test]
fn any_at_a_signed_cname_gets_the_cname() {
    let online = Signed::new(branching(), keys(), window(), Denial::Nsec);
    let reply = ask(
        &online,
        "alias.example.",
        RecordType::ANY,
        AnyResponse::Hinfo,
    );
    let answer = sets(&reply.answers);
    assert_eq!(answer.len(), 1);
    assert_eq!(answer[0].record_type(), RecordType::CNAME);
    assert_eq!(validate(&online, &answer[0]), Validation::Secure);
}
