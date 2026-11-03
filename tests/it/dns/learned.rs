//! Zones learned from their real servers: what a learned zone answers
//! from the responses filed into it, that an unknown fact never becomes a
//! negative, which zones copies find each address serves, and, on a
//! simulated network with a fake upstream, that a lookup the world's
//! policy refuses leaves the server silent and that a namespace advance
//! drops what was learned.

use std::future::{Future, ready};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fictionet::stdlib::protocols::dns::dnssec::proof::nodata;
use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
use fictionet::stdlib::protocols::dns::dnssec::{
    Algorithm, KeyFlags, KeySet, Proof, Sign, ZoneKey,
};
use fictionet::stdlib::protocols::dns::op::{Edns, Message, MessageType, OpCode, Query};
use fictionet::stdlib::protocols::dns::rr::rdata::A;
use fictionet::stdlib::protocols::dns::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::protocols::dns::{Parsed, Request};
use fictionet::stdlib::services::dns::authority::{
    Authority, AuthorityEngine, Copies, ServerConfig, Step, Zones,
};
use fictionet::stdlib::services::dns::zone::{
    Answered, AnyResponse, Denial, Filing, Learned, Section, Zone, ZoneData, answer,
};
use fictionet::stdlib::services::dns::{
    Action, Client, ClientQuery, Engine, Generation, Input, Looked, Lookup, WallClock,
};
use fictionet::stdlib::services::serve::Transport;
use fictionet::stdlib::world::net::Net;
use fictionet::stdlib::world::net::dns::{Authoritative, Namespace, Only, Upstream};
use fictionet::time::Instant;
use fictionet::{Cx, Seed, SeededEntropy};
use fictionet_test_support::dns::TestInternet;
use fictionet_test_support::sandbox::{Machine, machine};
use fictionet_test_support::timeout;

use crate::common::world::world;

const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

/// The real zone the learned zone copies: data, an alias, a wildcard, an
/// empty non-terminal, and an unsigned delegation with glue.
const EXAMPLE: &str = "\
example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 3600 1209600 300
example. 3600 IN NS ns.example.
ns.example. 3600 IN A 192.0.2.53
www.example. 300 IN A 192.0.2.80
www.example. 300 IN AAAA 2001:db8::80
alias.example. 300 IN CNAME www.example.
*.wild.example. 300 IN A 192.0.2.99
host.ent.example. 300 IN A 192.0.2.7
child.example. 3600 IN NS ns.child.example.
ns.child.example. 3600 IN A 192.0.2.54
";

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

fn lower(text: &str) -> LowerName {
    LowerName::new(&name(text))
}

/// The request for `qname` and `qtype`, with an OPT record and DO as
/// given.
fn request(qname: &str, qtype: RecordType, dnssec_ok: bool) -> Request {
    let mut message = Message::new(7, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(name(qname), qtype));
    let mut edns = Edns::new();
    edns.set_max_payload(1232).set_dnssec_ok(dnssec_ok);
    message.set_edns(edns);
    let Parsed::Request(request) = Request::parse(&message.to_vec().unwrap(), Transport::Udp)
    else {
        panic!("{qname} {qtype} parses");
    };
    request
}

/// What `zone` answers `request`, as its real server does.
fn real(zone: &Zone, request: &Request) -> Message {
    match answer(zone, request, AnyResponse::All) {
        Answered::Response(response) => response.message,
        Answered::Unknown { name, .. } => panic!("a complete zone knows {name}"),
    }
}

/// What `learned` answers `request`, or `None` when a fact it rests on is
/// unknown.
fn copied(learned: &Learned, request: &Request) -> Option<Message> {
    match answer(&*learned.view(&request.question), request, AnyResponse::All) {
        Answered::Response(response) => Some(response.message),
        Answered::Unknown { .. } => None,
    }
}

/// A message's RCODE, AA bit, and records, each record as text, sorted
/// by section.
fn shape(message: &Message) -> (String, bool, [Vec<String>; 3]) {
    let texts = |records: &[Record]| {
        let mut texts: Vec<String> = records
            .iter()
            .map(|record| {
                format!(
                    "{} {} {} {}",
                    record.name,
                    record.ttl,
                    record.record_type(),
                    record.data
                )
            })
            .collect();
        texts.sort();
        texts
    };
    (
        message.metadata.response_code.to_string(),
        message.metadata.authoritative,
        [
            texts(&message.answers),
            texts(&message.authorities),
            texts(&message.additionals),
        ],
    )
}

/// `EXAMPLE` signed with `denial` by a fresh key.
fn signed(denial: Denial) -> Zone {
    signed_master(EXAMPLE, denial)
}

/// The zone of the master file `text` signed with `denial` by a fresh
/// key.
fn signed_master(text: &str, denial: Denial) -> Zone {
    let entropy = SeededEntropy::new(Seed::from_u64(5));
    let key = ZoneKey::generate(&entropy, Algorithm::Ed25519, KeyFlags::KSK);
    let keys = KeySet {
        keys: vec![Arc::new(key) as Arc<dyn Sign>],
    };
    Zone::from_master(text, None)
        .unwrap()
        .signed(&keys, TestInternet::window(), denial)
        .unwrap()
}

/// The zone of `text` unsigned, signed with NSEC, and signed with NSEC3,
/// each with its name.
fn three_ways(text: &str) -> [(&'static str, Zone); 3] {
    [
        ("unsigned", Zone::from_master(text, None).unwrap()),
        ("NSEC", signed_master(text, Denial::Nsec)),
        (
            "NSEC3",
            signed_master(
                text,
                Denial::Nsec3 {
                    opt_out: false,
                    salt: Vec::new(),
                },
            ),
        ),
    ]
}

/// A zone whose answers run through DNAMEs and a wildcard CNAME: `d`
/// maps names onto `deep`, which holds nothing, `long` onto a target so
/// long that a name below it cannot be rewritten, and every name under
/// `wild` is an alias of the name server.
fn chains() -> String {
    let long = vec!["x".repeat(61); 4].join(".");
    format!(
        "\
example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 3600 1209600 300
example. 3600 IN NS ns.example.
ns.example. 3600 IN A 192.0.2.53
*.wild.example. 300 IN CNAME ns.example.
d.example. 300 IN DNAME deep.example.
long.example. 300 IN DNAME {long}.
"
    )
}

/// A copy follows a DNAME as the answer does, whatever the type asked
/// (RFC 6672 §3.2): a CNAME or ANY question below `d` is answered with
/// the DNAME, the CNAME made from it, and the NXDOMAIN of the new name,
/// once the response to it is filed. A name below `long`, which no
/// rewritten name could hold, gets YXDOMAIN with the DNAME, which the
/// copy keeps from the real server's YXDOMAIN (RFC 6672 §2.2).
#[test]
fn a_copy_follows_dnames_as_the_zone_does() {
    for (how, zone) in three_ways(&chains()) {
        for (qname, qtype) in [
            ("h.d.example.", RecordType::CNAME),
            ("h.d.example.", RecordType::ANY),
            ("h.d.example.", RecordType::A),
            ("a-label-long-enough.long.example.", RecordType::A),
            ("a-label-long-enough.long.example.", RecordType::ANY),
        ] {
            let learned = Learned::new(&name("example."));
            let asked = request(qname, qtype, true);
            learned.file(Generation(0), &asked.question, &real(&zone, &asked));
            for dnssec_ok in [true, false] {
                let request = request(qname, qtype, dnssec_ok);
                let got = copied(&learned, &request)
                    .unwrap_or_else(|| panic!("{how} {qname} {qtype} DO {dnssec_ok}: unknown"));
                assert_eq!(
                    shape(&got),
                    shape(&real(&zone, &request)),
                    "{how} {qname} {qtype} DO {dnssec_ok}"
                );
            }
        }
    }
}

/// One response can prove two negatives: `a.wild.example. MX` is answered
/// by the wildcard's CNAME, whose proof shows no closer name exists, and
/// ends in the NODATA of `ns.example. MX`. The copy keeps each proof
/// apart, so a later reply for either one alone carries its own records,
/// as the real zone's reply does (RFC 4035 §3.1.3, RFC 5155 §7.2).
#[test]
fn each_negative_keeps_only_its_own_proof() {
    for (how, zone) in three_ways(&chains()) {
        let learned = Learned::new(&name("example."));
        let asked = request("a.wild.example.", RecordType::MX, true);
        learned.file(Generation(0), &asked.question, &real(&zone, &asked));
        for (qname, qtype) in [
            ("a.wild.example.", RecordType::MX),
            ("a.wild.example.", RecordType::CNAME),
            ("ns.example.", RecordType::MX),
        ] {
            let request = request(qname, qtype, true);
            let got = copied(&learned, &request)
                .unwrap_or_else(|| panic!("{how} {qname} {qtype}: unknown"));
            assert_eq!(
                shape(&got),
                shape(&real(&zone, &request)),
                "{how} {qname} {qtype}"
            );
        }
    }
}

/// The questions the copy is asked: positive answers, NODATA, NXDOMAIN,
/// an alias, a wildcard's answer and NODATA, an empty non-terminal, a
/// referral, and DS at the cut.
const QUESTIONS: [(&str, RecordType); 13] = [
    ("www.example.", RecordType::A),
    ("www.example.", RecordType::AAAA),
    ("www.example.", RecordType::TXT),
    ("nx.example.", RecordType::A),
    ("deep.nx.example.", RecordType::A),
    ("alias.example.", RecordType::A),
    ("a.wild.example.", RecordType::A),
    ("b.wild.example.", RecordType::TXT),
    ("ent.example.", RecordType::A),
    ("www.child.example.", RecordType::A),
    ("child.example.", RecordType::DS),
    ("example.", RecordType::NS),
    ("ns.example.", RecordType::A),
];

/// For an unsigned zone, one signed with NSEC, and one signed with NSEC3,
/// a learned copy answers each question, once the response to it is
/// filed, exactly as the real zone does, with and without DO: the same
/// RCODE, AA bit, and records, RRSIGs and denial records included, TTLs
/// as sent. After every response is filed, each question is answered as
/// the real zone answers it, or not at all.
#[test]
fn a_copy_answers_as_the_zone_it_copied() {
    let zones = [
        ("unsigned", Zone::from_master(EXAMPLE, None).unwrap()),
        ("NSEC", signed(Denial::Nsec)),
        (
            "NSEC3",
            signed(Denial::Nsec3 {
                opt_out: false,
                salt: Vec::new(),
            }),
        ),
    ];
    for (how, zone) in zones {
        let learned = Learned::new(&name("example."));
        for (qname, qtype) in QUESTIONS {
            let asked = request(qname, qtype, true);
            // A lookup asks with DO.
            learned.file(Generation(0), &asked.question, &real(&zone, &asked));
            for dnssec_ok in [true, false] {
                let request = request(qname, qtype, dnssec_ok);
                let got = copied(&learned, &request)
                    .unwrap_or_else(|| panic!("{how} {qname} {qtype} DO {dnssec_ok}: unknown"));
                assert_eq!(
                    shape(&got),
                    shape(&real(&zone, &request)),
                    "{how} {qname} {qtype} DO {dnssec_ok}"
                );
            }
        }
        for (qname, qtype) in QUESTIONS {
            for dnssec_ok in [true, false] {
                let request = request(qname, qtype, dnssec_ok);
                if let Some(got) = copied(&learned, &request) {
                    assert_eq!(
                        shape(&got),
                        shape(&real(&zone, &request)),
                        "{how} {qname} {qtype} DO {dnssec_ok}, after every filing"
                    );
                }
            }
        }
    }
}

/// What a learned zone has not been told stays unknown: never NXDOMAIN,
/// never NODATA, with or without DO.
#[test]
fn an_unknown_never_becomes_nxdomain_or_nodata() {
    let zone = signed(Denial::Nsec);
    let learned = Learned::new(&name("example."));
    for (qname, qtype) in QUESTIONS {
        for dnssec_ok in [true, false] {
            assert!(
                copied(&learned, &request(qname, qtype, dnssec_ok)).is_none(),
                "{qname} {qtype} before anything is filed"
            );
        }
    }

    // What one positive answer, one NODATA, one referral, and one wildcard
    // answer leave unknown.
    for (qname, qtype) in [
        ("www.example.", RecordType::A),
        ("www.example.", RecordType::TXT),
        ("www.child.example.", RecordType::A),
        ("a.wild.example.", RecordType::A),
    ] {
        let asked = request(qname, qtype, true);
        learned.file(Generation(0), &asked.question, &real(&zone, &asked));
    }
    for (qname, qtype) in [
        // Another type at a name with data.
        ("www.example.", RecordType::AAAA),
        ("www.example.", RecordType::MX),
        // Every type at a name never asked.
        ("nx.example.", RecordType::A),
        ("mail.example.", RecordType::A),
        // ANY, which only its own response answers.
        ("www.example.", RecordType::ANY),
        // Another name under the wildcard, which needs its own proof.
        ("b.wild.example.", RecordType::A),
        // The wildcard's parent, which no response showed with data.
        ("wild.example.", RecordType::A),
        // DS at the cut, which only a NODATA for it answers: the referral
        // carries no SOA, and may come from a child zone the server also
        // serves.
        ("child.example.", RecordType::DS),
    ] {
        for dnssec_ok in [true, false] {
            let got = copied(&learned, &request(qname, qtype, dnssec_ok));
            assert!(
                got.is_none(),
                "{qname} {qtype} DO {dnssec_ok} is unknown, got {got:?}"
            );
        }
    }

    // A server of the learned zone with no upstream looks the question up
    // and, when nothing comes, sends nothing: no negative answer.
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let zones = Zones::new(vec![Arc::new(learned) as Arc<dyn ZoneData>]);
    let mut engine = AuthorityEngine::new(zones, ServerConfig::generic(), local);
    let entropy = SeededEntropy::new(Seed::from_u64(1));
    let mut message = Message::new(9, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(name("nx.example."), RecordType::A));
    let client = Client {
        peer: "198.51.100.7:5353".parse().unwrap(),
        local,
        transport: Transport::Udp,
        connection: None,
        sandbox: None,
    };
    let query = ClientQuery {
        client,
        bytes: message.to_vec().unwrap(),
    };
    engine.handle(Input::Query(query), Instant::ZERO, &entropy);
    let mut actions: Vec<Action> = std::iter::from_fn(|| engine.poll()).collect();
    let deadline = engine.next_deadline().expect("a lookup to wait on");
    engine.handle(Input::Tick, deadline, &entropy);
    actions.extend(std::iter::from_fn(|| engine.poll()));
    assert!(
        actions
            .iter()
            .any(|action| matches!(action, Action::Lookup { .. }))
    );
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, Action::Answer(_))),
        "no answer in {actions:?}"
    );
}

/// The records of `message`'s additional section, as `shape` shows them.
fn additionals(message: &Message) -> Vec<String> {
    let [_, _, additional] = shape(message).2;
    additional
}

/// Additional data never answers a question (RFC 2181 §5.4.1). The glue
/// an MX answer carries for a target below a cut the copy has not seen
/// stays unknown until the real referral is filed, and an address that
/// came only as additional data, possibly without its RRSIGs, is looked
/// up before it is served as an answer.
#[test]
fn additional_data_never_answers() {
    let text = format!("{EXAMPLE}mx.example. 300 IN MX 10 ns.child.example.\n");
    let unsigned = Zone::from_master(&text, None).unwrap();
    let entropy = SeededEntropy::new(Seed::from_u64(5));
    let key = ZoneKey::generate(&entropy, Algorithm::Ed25519, KeyFlags::KSK);
    let keys = KeySet {
        keys: vec![Arc::new(key) as Arc<dyn Sign>],
    };
    let nsec = Zone::from_master(&text, None)
        .unwrap()
        .signed(&keys, TestInternet::window(), Denial::Nsec)
        .unwrap();
    for (how, zone) in [("unsigned", unsigned), ("NSEC", nsec)] {
        let learned = Learned::new(&name("example."));
        for (qname, qtype) in [
            ("mx.example.", RecordType::MX),
            ("example.", RecordType::NS),
        ] {
            let asked = request(qname, qtype, true);
            let response = real(&zone, &asked);
            assert!(
                !additionals(&response).is_empty(),
                "{how}: the real {qname} {qtype} carries additional data"
            );
            learned.file(Generation(0), &asked.question, &response);
        }
        for qname in ["ns.child.example.", "ns.example."] {
            for dnssec_ok in [true, false] {
                let got = copied(&learned, &request(qname, RecordType::A, dnssec_ok));
                assert!(
                    got.is_none(),
                    "{how} {qname} A DO {dnssec_ok} is unknown, got {:?}",
                    got.as_ref().map(shape)
                );
            }
        }
        // What the MX answer carries is still served as its additional
        // data.
        let mx = request("mx.example.", RecordType::MX, false);
        let got = copied(&learned, &mx).expect("the MX answer was filed");
        assert_eq!(shape(&got), shape(&real(&zone, &mx)), "{how} MX");
        for qname in ["ns.child.example.", "ns.example."] {
            let asked = request(qname, RecordType::A, true);
            learned.file(Generation(0), &asked.question, &real(&zone, &asked));
            for dnssec_ok in [true, false] {
                let request = request(qname, RecordType::A, dnssec_ok);
                let got = copied(&learned, &request).expect("filed");
                assert_eq!(
                    shape(&got),
                    shape(&real(&zone, &request)),
                    "{how} {qname} A DO {dnssec_ok}"
                );
            }
        }
    }
}

/// An address a wildcard made, sent as additional data beside an MX
/// answer as some servers send it, is kept at its own name: the MX
/// answer's authority section is not the proof for the expansion, so the
/// name stays unknown, with and without DO, until its own answer is filed,
/// even once the wildcard's address is known from another name.
#[test]
fn additional_data_from_a_wildcard_brings_no_proof() {
    let text = format!("{EXAMPLE}mx.example. 300 IN MX 10 mail.wild.example.\n");
    let entropy = SeededEntropy::new(Seed::from_u64(5));
    let key = ZoneKey::generate(&entropy, Algorithm::Ed25519, KeyFlags::KSK);
    let keys = KeySet {
        keys: vec![Arc::new(key) as Arc<dyn Sign>],
    };
    let zone = Zone::from_master(&text, None)
        .unwrap()
        .signed(&keys, TestInternet::window(), Denial::Nsec)
        .unwrap();
    let learned = Learned::new(&name("example."));
    let mx = request("mx.example.", RecordType::MX, true);
    let mut response = real(&zone, &mx);
    let mail = request("mail.wild.example.", RecordType::A, true);
    let expanded = real(&zone, &mail);
    response
        .additionals
        .extend(expanded.answers.iter().cloned());
    learned.file(Generation(0), &mx.question, &response);
    let other = request("a.wild.example.", RecordType::A, true);
    learned.file(Generation(0), &other.question, &real(&zone, &other));
    for dnssec_ok in [true, false] {
        let got = copied(
            &learned,
            &request("mail.wild.example.", RecordType::A, dnssec_ok),
        );
        assert!(
            got.is_none(),
            "mail.wild.example A DO {dnssec_ok} is unknown, got {:?}",
            got.as_ref().map(shape)
        );
    }
    learned.file(Generation(0), &mail.question, &expanded);
    for dnssec_ok in [true, false] {
        let request = request("mail.wild.example.", RecordType::A, dnssec_ok);
        let got = copied(&learned, &request).expect("filed");
        assert_eq!(shape(&got), shape(&real(&zone, &request)), "DO {dnssec_ok}");
    }
}

/// The section, owner, and type of each RRset `filing` kept, in order.
fn kept(filing: &Filing) -> Vec<(Section, String, RecordType)> {
    filing
        .sets
        .iter()
        .map(|(section, set)| (*section, set.name().to_ascii(), set.record_type()))
        .collect()
}

/// A filing says what the zone kept, each RRset as the real server sent
/// it with the section it came from: a referral's NS RRset from its
/// authority section and in-domain glue from additional data, an
/// answer's RRset from the answer section at the name the response gave
/// it even when a wildcard made it, a name server's address from
/// additional data, and nothing for a response the zone does not keep,
/// such as one for another zone.
#[test]
fn a_filing_shows_the_rrsets_the_zone_kept() {
    let zone = signed(Denial::Nsec);
    let learned = Learned::new(&name("example."));
    let file = |qname: &str, qtype: RecordType| {
        let asked = request(qname, qtype, true);
        let response = real(&zone, &asked);
        (
            learned.file(Generation(0), &asked.question, &response),
            response,
        )
    };

    let (referral, _) = file("www.child.example.", RecordType::A);
    assert_eq!(referral.zone, lower("example."));
    assert_eq!(
        kept(&referral),
        vec![
            (
                Section::Authority,
                "child.example.".to_string(),
                RecordType::NS
            ),
            (
                Section::Additional,
                "ns.child.example.".to_string(),
                RecordType::A
            ),
        ]
    );

    let (answer, response) = file("www.example.", RecordType::A);
    assert_eq!(
        kept(&answer),
        vec![(Section::Answer, "www.example.".to_string(), RecordType::A)]
    );
    let sent = response
        .answers
        .iter()
        .filter(|record| record.record_type() == RecordType::A)
        .cloned()
        .collect::<Vec<_>>();
    let (_, filed) = answer
        .sets
        .iter()
        .find(|(_, set)| set.record_type() == RecordType::A && set.name() == &name("www.example."))
        .expect("the A RRset");
    assert_eq!(
        filed.records_without_rrsigs().cloned().collect::<Vec<_>>(),
        sent,
        "as sent"
    );
    assert!(!filed.rrsigs().is_empty(), "with its RRSIGs");

    let (apex, _) = file("example.", RecordType::NS);
    assert_eq!(
        kept(&apex),
        vec![
            (Section::Answer, "example.".to_string(), RecordType::NS),
            (
                Section::Additional,
                "ns.example.".to_string(),
                RecordType::A
            ),
        ],
        "the name server's address is additional data"
    );

    let (expanded, _) = file("a.wild.example.", RecordType::A);
    assert_eq!(
        kept(&expanded)
            .into_iter()
            .filter(|(section, _, _)| *section == Section::Answer)
            .collect::<Vec<_>>(),
        vec![(
            Section::Answer,
            "a.wild.example.".to_string(),
            RecordType::A
        )],
        "at the name the response gave"
    );

    // The same records, as the response to a question about another zone.
    let other = request("www.other.", RecordType::A, true);
    let mut foreign = real(&zone, &request("www.example.", RecordType::AAAA, true));
    foreign.queries = vec![other.question.clone()];
    assert!(
        learned
            .file(Generation(0), &other.question, &foreign)
            .sets
            .is_empty(),
        "a question outside the zone"
    );
}

/// A truncated response may lack records its full form has (RFC 2181
/// §9): it files nothing, so what it would have answered stays unknown.
#[test]
fn a_truncated_response_files_nothing() {
    let zone = Zone::from_master(EXAMPLE, None).unwrap();
    let learned = Learned::new(&name("example."));
    let asked = request("www.example.", RecordType::A, true);
    let mut response = real(&zone, &asked);
    response.metadata.truncation = true;
    let filing = learned.file(Generation(0), &asked.question, &response);
    assert!(filing.sets.is_empty(), "kept {:?}", kept(&filing));
    for dnssec_ok in [true, false] {
        let got = copied(&learned, &request("www.example.", RecordType::A, dnssec_ok));
        assert!(
            got.is_none(),
            "DO {dnssec_ok}: got {:?}",
            got.as_ref().map(shape)
        );
    }
}

/// A referral shows that a cut has no DS, but carries no SOA, which the
/// NODATA answer to DS at the cut needs (RFC 2308 §3). Until the NODATA
/// for DS at the cut is filed, DS there stays unknown.
#[test]
fn ds_at_a_cut_waits_for_the_soa_a_referral_lacks() {
    let zones = [
        ("unsigned", Zone::from_master(EXAMPLE, None).unwrap()),
        ("NSEC", signed(Denial::Nsec)),
        (
            "NSEC3",
            signed(Denial::Nsec3 {
                opt_out: false,
                salt: Vec::new(),
            }),
        ),
    ];
    for (how, zone) in zones {
        let learned = Learned::new(&name("example."));
        let referral = request("www.child.example.", RecordType::A, true);
        learned.file(Generation(0), &referral.question, &real(&zone, &referral));
        for dnssec_ok in [true, false] {
            let got = copied(
                &learned,
                &request("child.example.", RecordType::DS, dnssec_ok),
            );
            assert!(
                got.is_none(),
                "{how} DO {dnssec_ok}: DS at the cut is unknown, got {:?}",
                got.as_ref().map(shape)
            );
        }
        let asked = request("child.example.", RecordType::DS, true);
        learned.file(Generation(0), &asked.question, &real(&zone, &asked));
        for dnssec_ok in [true, false] {
            let ds = request("child.example.", RecordType::DS, dnssec_ok);
            let got = copied(&learned, &ds).expect("the NODATA was filed");
            assert_eq!(
                shape(&got),
                shape(&real(&zone, &ds)),
                "{how} DO {dnssec_ok}"
            );
        }
    }
}

/// An answer to ANY or RRSIG that a wildcard made keeps the proof that
/// no closer name exists (RFC 4035 §3.1.3.3, RFC 5155 §7.2.6). Another
/// name under the wildcard, which no response showed absent, stays
/// unknown.
#[test]
fn any_and_rrsig_at_a_wildcard_keep_its_proof() {
    let zones = [
        ("NSEC", signed(Denial::Nsec)),
        (
            "NSEC3",
            signed(Denial::Nsec3 {
                opt_out: false,
                salt: Vec::new(),
            }),
        ),
    ];
    for (how, zone) in zones {
        for qtype in [RecordType::ANY, RecordType::RRSIG] {
            let learned = Learned::new(&name("example."));
            let asked = request("a.wild.example.", qtype, true);
            learned.file(Generation(0), &asked.question, &real(&zone, &asked));
            for dnssec_ok in [true, false] {
                let request = request("a.wild.example.", qtype, dnssec_ok);
                let got = copied(&learned, &request).expect("filed");
                assert_eq!(
                    shape(&got),
                    shape(&real(&zone, &request)),
                    "{how} {qtype} DO {dnssec_ok}"
                );
            }
            for dnssec_ok in [true, false] {
                let other = copied(&learned, &request("b.wild.example.", qtype, dnssec_ok));
                assert!(
                    other.is_none(),
                    "{how} {qtype} DO {dnssec_ok}: b.wild.example may exist"
                );
            }
        }
    }
}

/// `child.example`, which the parent's server serves too.
const CHILD: &str = "\
child.example. 3600 IN SOA ns.child.example. hostmaster.example. 1 7200 3600 1209600 300
child.example. 3600 IN NS ns.child.example.
ns.child.example. 3600 IN A 192.0.2.54
www.child.example. 300 IN A 192.0.2.81
";

/// A real server that serves `example` and its child `child.example`
/// answers for the child's names from the child's data, never with a
/// referral. Copies of the server noted only as serving `example` learn
/// the child from the responses, file them into the child's copy, and
/// answer every question as the real server does: none stays silent.
#[test]
fn copies_learn_a_child_zone_its_server_also_serves() {
    let real = Zones::new(vec![
        Arc::new(Zone::from_master(EXAMPLE, None).unwrap()) as Arc<dyn ZoneData>,
        Arc::new(Zone::from_master(CHILD, None).unwrap()) as Arc<dyn ZoneData>,
    ]);
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let server = ServerConfig::generic();
    let client = Client {
        peer: "198.51.100.7:5353".parse().unwrap(),
        local,
        transport: Transport::Udp,
        connection: None,
        sandbox: None,
    };
    let reply = |authority: &dyn Authority, request: &Request| match authority
        .respond(request, local, &server, &client)
    {
        Step::Reply(response) => Some(response.message),
        Step::Need(lookup) => panic!("the real server needs {lookup:?}"),
        Step::Silent => None,
    };
    let copies = Copies::new();
    copies.serves(local.ip(), &lower("example."));
    for (qname, qtype) in [
        ("nx.child.example.", RecordType::A),
        ("www.child.example.", RecordType::A),
        ("www.child.example.", RecordType::TXT),
        ("child.example.", RecordType::SOA),
        ("child.example.", RecordType::DS),
        ("www.example.", RecordType::A),
        ("nx.example.", RecordType::A),
    ] {
        for dnssec_ok in [false, true] {
            let request = request(qname, qtype, dnssec_ok);
            let mut looked = Vec::new();
            let got = loop {
                match copies.respond(&request, local, &server, &client) {
                    Step::Reply(response) => break response.message,
                    Step::Need(lookup) => {
                        assert!(
                            !looked.contains(&lookup),
                            "{qname} {qtype} DO {dnssec_ok}: {lookup:?} again, so silent"
                        );
                        let asked = self::request(
                            &lookup.question.name().to_ascii(),
                            lookup.question.query_type(),
                            true,
                        );
                        let response = reply(&real, &asked).expect("the real server answers");
                        copies.file(&lookup, &Looked::Response(response), Generation(0));
                        looked.push(lookup);
                    }
                    Step::Silent => panic!("{qname} {qtype} DO {dnssec_ok}: silent"),
                }
            };
            let want = reply(&real, &request).expect("the real server answers");
            assert_eq!(shape(&got), shape(&want), "{qname} {qtype} DO {dnssec_ok}");
        }
    }
}

/// An upstream that answers every lookup with one A record whose address
/// ends in how many lookups it has answered, and keeps each lookup.
#[derive(Clone, Default)]
struct Counting {
    asked: Arc<Mutex<Vec<Lookup>>>,
}

impl Upstream for Counting {
    fn lookup<'a>(
        &'a self,
        _fcx: &'a Cx,
        lookup: Lookup,
    ) -> Pin<Box<dyn Future<Output = Looked> + Send + 'a>> {
        let mut asked = self.asked.lock().unwrap();
        asked.push(lookup.clone());
        let mut response = Message::response(1, OpCode::Query);
        response.metadata.authoritative = true;
        response.add_query(lookup.question.clone());
        let last = u8::try_from(asked.len()).unwrap();
        response.add_answer(Record::from_rdata(
            lookup.question.name().clone(),
            300,
            RData::A(A::new(203, 0, 113, last)),
        ));
        Box::pin(ready(Looked::Response(response)))
    }
}

/// What `server` answers a query for `qname` A over UDP, if it answers
/// within two seconds.
async fn ask(fcx: &Cx, m: &Machine, server: SocketAddr, id: u16, qname: &str) -> Option<Message> {
    let mut query = Message::new(id, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(name(qname), RecordType::A));
    let mut socket = m.udp.bind(0).ok()?;
    socket.send_to(&query.to_vec().ok()?, server);
    let (bytes, _) = timeout(fcx, Duration::from_secs(2), socket.recv(fcx))
        .await?
        .ok()?;
    Message::from_vec(&bytes).ok()
}

fn addresses(reply: &Message) -> Vec<IpAddr> {
    reply
        .answers
        .iter()
        .filter_map(|record| record.data.ip_addr())
        .collect()
}

/// A lookup the world's policy refuses never reaches the upstream, and
/// the server that needed it stays silent, now and when asked again:
/// it never answers NXDOMAIN for what it could not learn.
#[test]
fn a_policy_refused_lookup_leaves_the_server_silent() {
    world(Duration::from_secs(60), |fcx| async move {
        let address = Ipv4Addr::new(203, 0, 113, 53);
        let upstream = Counting::default();
        let allowed = lower("allowed.example.");
        let policy =
            move |lookup: &Lookup| allowed.zone_of(&LowerName::new(lookup.question.name()));
        let learned = Learned::new(&name("example."));
        let zones = Zones::new(vec![Arc::new(learned) as Arc<dyn ZoneData>]);
        let program = Authoritative::new(zones, ServerConfig::generic())
            .upstream(Only::new(policy, upstream.clone()));
        let (attacher, attachments) = fictionet::attachments();
        Net::new()
            .ipv4_only()
            .host("copy", |h| h.at(address).program(program))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let server = SocketAddr::new(address.into(), 53);

        let reply = ask(&fcx, &m, server, 1, "www.allowed.example.")
            .await
            .expect("an answer");
        assert_eq!(
            addresses(&reply),
            [IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))]
        );
        for id in [2, 3] {
            let reply = ask(&fcx, &m, server, id, "www.refused.example.").await;
            assert!(reply.is_none(), "the server answered {reply:?}");
        }
        let asked: Vec<LowerName> = upstream
            .asked
            .lock()
            .unwrap()
            .iter()
            .map(|lookup| LowerName::new(lookup.question.name()))
            .collect();
        assert_eq!(asked, [lower("www.allowed.example.")]);
        Ok(())
    });
}

/// What a learned zone copied belongs to its session: once the namespace
/// advances, the server looks the name up again and answers from the new
/// session's copy.
#[test]
fn a_namespace_advance_clears_learned_data() {
    world(Duration::from_secs(60), |fcx| async move {
        let address = Ipv4Addr::new(203, 0, 113, 53);
        let clock = WallClock {
            start: SystemTime::UNIX_EPOCH,
        };
        let namespace = Namespace::new(clock);
        let upstream = Counting::default();
        let learned = Learned::new(&name("example."));
        let zones = Zones::new(vec![Arc::new(learned) as Arc<dyn ZoneData>]);
        let program = Authoritative::new(zones, ServerConfig::generic())
            .upstream(upstream.clone())
            .namespace(&namespace);
        let (attacher, attachments) = fictionet::attachments();
        Net::new()
            .ipv4_only()
            .host("copy", |h| h.at(address).program(program))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let server = SocketAddr::new(address.into(), 53);
        let first = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let second = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));

        for id in [1, 2] {
            let reply = ask(&fcx, &m, server, id, "www.example.")
                .await
                .expect("an answer");
            assert_eq!(addresses(&reply), [first]);
        }
        assert_eq!(upstream.asked.lock().unwrap().len(), 1, "one copy");

        namespace.advance(clock);
        let reply = ask(&fcx, &m, server, 3, "www.example.")
            .await
            .expect("an answer");
        assert_eq!(addresses(&reply), [second], "the new session's copy");
        assert_eq!(upstream.asked.lock().unwrap().len(), 2);
        Ok(())
    });
}

/// `EXAMPLE` with an alias to a name outside the zone, and a wildcard
/// alias.
fn edges() -> String {
    format!(
        "{EXAMPLE}\
out.example. 300 IN CNAME www.other.
*.cw.example. 300 IN CNAME www.example.
"
    )
}

/// The NSEC RRset may sit beside a CNAME, and the one at a cut is the
/// parent's data (RFC 4035 §2.5, §2.6), so a copy answers an NSEC
/// question there only from what the response to that question showed:
/// the NSEC RRset, or the CNAME or referral the real server gave for it.
/// What other questions filed never answers it, and every answer the copy
/// gives is the real zone's.
#[test]
fn an_nsec_question_is_answered_from_its_own_response() {
    let cases: [(&[(&str, RecordType)], &str); 4] = [
        (&[("out.example.", RecordType::A)], "out.example."),
        (
            &[
                ("alias.example.", RecordType::A),
                ("www.example.", RecordType::NSEC),
            ],
            "alias.example.",
        ),
        (&[("www.child.example.", RecordType::A)], "child.example."),
        (&[("a.cw.example.", RecordType::A)], "a.cw.example."),
    ];
    for (how, zone) in three_ways(&edges()) {
        for (filed, qname) in cases {
            let learned = Learned::new(&name("example."));
            for (filed_name, filed_type) in filed {
                let asked = request(filed_name, *filed_type, true);
                learned.file(Generation(0), &asked.question, &real(&zone, &asked));
            }
            for dnssec_ok in [true, false] {
                let request = request(qname, RecordType::NSEC, dnssec_ok);
                let got = copied(&learned, &request);
                assert!(
                    got.is_none(),
                    "{how} {qname} DO {dnssec_ok}: answered before its own response, {:?}",
                    got.as_ref().map(shape)
                );
            }
            let asked = request(qname, RecordType::NSEC, true);
            learned.file(Generation(0), &asked.question, &real(&zone, &asked));
            for dnssec_ok in [true, false] {
                let request = request(qname, RecordType::NSEC, dnssec_ok);
                let got = copied(&learned, &request)
                    .unwrap_or_else(|| panic!("{how} {qname} DO {dnssec_ok}: unknown"));
                assert_eq!(
                    shape(&got),
                    shape(&real(&zone, &request)),
                    "{how} {qname} DO {dnssec_ok}"
                );
            }
        }
    }
}

/// `EXAMPLE` with an alias and a DNAME whose chains end below the cut at
/// `child`.
fn into_the_cut() -> String {
    format!(
        "{EXAMPLE}\
c10.example. 300 IN CNAME host.child.example.
dn.example. 300 IN DNAME child.example.
"
    )
}

/// A chain that ends below a cut ends in a referral: AA, the alias in the
/// answer section, the cut's NS RRset in the authority section, and no
/// SOA (RFC 1034 §4.3.2 step 3b, RFC 6672 §3.2). A copy files the cut
/// from it and answers the question as the real zone does.
#[test]
fn a_chain_into_a_cut_is_answered_with_its_referral() {
    for (how, zone) in three_ways(&into_the_cut()) {
        for qname in ["c10.example.", "www.dn.example."] {
            let learned = Learned::new(&name("example."));
            let asked = request(qname, RecordType::A, true);
            learned.file(Generation(0), &asked.question, &real(&zone, &asked));
            for dnssec_ok in [true, false] {
                let request = request(qname, RecordType::A, dnssec_ok);
                let got = copied(&learned, &request)
                    .unwrap_or_else(|| panic!("{how} {qname} DO {dnssec_ok}: unknown"));
                assert_eq!(
                    shape(&got),
                    shape(&real(&zone, &request)),
                    "{how} {qname} DO {dnssec_ok}"
                );
            }
        }
    }
}

/// A referral shows only that its server holds no zone at the name it
/// referred, nor between it and the cut (RFC 1034 §4.3.2): the copy
/// refers that name and the names above it, and looks up any other name
/// below the cut, which the server may answer from a zone of its own.
#[test]
fn a_referral_refers_only_the_name_it_was_for() {
    let zone = Zone::from_master(EXAMPLE, None).unwrap();
    let learned = Learned::new(&name("example."));
    let asked = request("www.child.example.", RecordType::A, true);
    learned.file(Generation(0), &asked.question, &real(&zone, &asked));
    for qname in ["www.child.example.", "child.example."] {
        let request = request(qname, RecordType::A, false);
        let got = copied(&learned, &request).unwrap_or_else(|| panic!("{qname}: unknown"));
        assert_eq!(shape(&got), shape(&real(&zone, &request)), "{qname}");
    }
    for qname in ["other.child.example.", "a.www.child.example."] {
        let got = copied(&learned, &request(qname, RecordType::A, false));
        assert!(got.is_none(), "{qname}: got {:?}", got.as_ref().map(shape));
    }
}

/// A Wildcard No Data response needs the NSEC3 records matching the
/// closest encloser and the wildcard and the one covering the next closer
/// name (RFC 5155 §7.2.5). The proof filed for a wildcard expanded to
/// another type and the one filed for the wildcard's own name hold only
/// some of them, so the copy looks the question up, and answers with the
/// real server's whole proof once that is filed.
#[test]
fn a_wildcard_nodata_rests_on_its_own_proof() {
    for opt_out in [false, true] {
        let zone = signed(Denial::Nsec3 {
            opt_out,
            salt: Vec::new(),
        });
        let learned = Learned::new(&name("example."));
        for (qname, qtype) in [
            ("a.wild.example.", RecordType::A),
            ("*.wild.example.", RecordType::MX),
        ] {
            let asked = request(qname, qtype, true);
            learned.file(Generation(0), &asked.question, &real(&zone, &asked));
        }
        let asked = request("a.wild.example.", RecordType::MX, true);
        let got = copied(&learned, &asked);
        assert!(
            got.is_none(),
            "opt-out {opt_out}: answered from two partial proofs, {:?}",
            got.as_ref().map(shape)
        );
        learned.file(Generation(0), &asked.question, &real(&zone, &asked));
        let got = copied(&learned, &asked).expect("the NODATA was filed");
        assert_eq!(
            shape(&got),
            shape(&real(&zone, &asked)),
            "opt-out {opt_out}"
        );
        let authority = rrsets_of(&got.authorities);
        let proof = nodata(
            &name("a.wild.example."),
            RecordType::MX,
            &name("example."),
            &authority,
            150,
        );
        assert_ne!(proof, Proof::Unproven, "opt-out {opt_out}");
    }
}

/// The records of a section as RRsets, each with its RRSIGs.
fn rrsets_of(records: &[Record]) -> Vec<RecordSet> {
    let mut sets: Vec<RecordSet> = Vec::new();
    for record in records {
        let covered = match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => rrsig.input().type_covered,
            data => data.record_type(),
        };
        let index = sets
            .iter()
            .position(|set| set.name() == &record.name && set.record_type() == covered)
            .unwrap_or_else(|| {
                sets.push(RecordSet::with_ttl(
                    record.name.clone(),
                    covered,
                    record.ttl,
                ));
                sets.len() - 1
            });
        if record.record_type() == RecordType::RRSIG {
            sets[index].insert_rrsig(record.clone());
        } else {
            sets[index].insert(record.clone(), 0);
        }
    }
    sets
}

/// What `real` gives each lookup of a copy at `local`.
type Real<'a> = &'a dyn Fn(&Lookup) -> Message;

/// What `authority` at `local` replies to `request`, with each lookup it
/// needs answered by `real` and filed, and the lookups it made. It must
/// never need a lookup it already made, which would leave it silent.
fn through(
    authority: &dyn Authority,
    real: Real<'_>,
    local: SocketAddr,
    request: &Request,
) -> (Message, Vec<Lookup>) {
    let server = ServerConfig::generic();
    let client = Client {
        peer: "198.51.100.7:5353".parse().unwrap(),
        local,
        transport: Transport::Udp,
        connection: None,
        sandbox: None,
    };
    let mut looked = Vec::new();
    loop {
        match authority.respond(request, local, &server, &client) {
            Step::Reply(response) => return (response.message, looked),
            Step::Need(lookup) => {
                assert!(
                    !looked.contains(&lookup),
                    "{request:?}: {lookup:?} again, so silent"
                );
                authority.file(&lookup, &Looked::Response(real(&lookup)), Generation(0));
                looked.push(lookup);
            }
            Step::Silent => panic!("{request:?}: silent"),
        }
    }
}

/// What `zones` at a real server reply to `lookup`'s question, asked with
/// DO.
fn reply_of(zones: &Zones, lookup: &Lookup) -> Message {
    let asked = request(
        &lookup.question.name().to_ascii(),
        lookup.question.query_type(),
        true,
    );
    let local: SocketAddr = SocketAddr::new(lookup.server.ip(), 53);
    let client = Client {
        peer: "198.51.100.7:5353".parse().unwrap(),
        local,
        transport: Transport::Udp,
        connection: None,
        sandbox: None,
    };
    match zones.respond(&asked, local, &ServerConfig::generic(), &client) {
        Step::Reply(response) => response.message,
        step => panic!("the real server gave {step:?}"),
    }
}

/// `srv.child.example`, a zone below the cut at `child.example` that the
/// parent's servers also serve, as the root servers serve
/// `root-servers.net` below `net`.
const SRV: &str = "\
srv.child.example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 3600 1209600 300
srv.child.example. 3600 IN NS ns.example.
www.srv.child.example. 300 IN A 192.0.2.82
";

/// A copy that holds a cut still finds a zone below it that its real
/// servers serve: the cut refers only names a referral was filed for, so
/// any other name is looked up at the server asked. An authoritative
/// answer from the zone below, which need not show the zone's apex, has
/// the server asked for the SOA RRset at the name, whose response does
/// (RFC 2308 §3), and the zone is noted at that address. Each address
/// finds it for itself.
#[test]
fn copies_find_a_zone_below_a_cut_they_hold() {
    let real = Zones::new(vec![
        Arc::new(Zone::from_master(EXAMPLE, None).unwrap()) as Arc<dyn ZoneData>,
        Arc::new(Zone::from_master(SRV, None).unwrap()) as Arc<dyn ZoneData>,
    ]);
    let answer = |lookup: &Lookup| reply_of(&real, lookup);
    let first: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let second: SocketAddr = "192.0.2.153:53".parse().unwrap();
    let copies = Copies::new();
    for local in [first, second] {
        copies.serves(local.ip(), &lower("example."));
    }
    let referral = request("x.child.example.", RecordType::A, false);
    let (got, _) = through(&copies, &answer, first, &referral);
    assert_eq!(shape(&got), shape(&reply_of(&real, &own(first, &referral))));
    let below = request("www.srv.child.example.", RecordType::A, false);
    for local in [first, second] {
        let (got, looked) = through(&copies, &answer, local, &below);
        assert_eq!(
            shape(&got),
            shape(&reply_of(&real, &own(local, &below))),
            "at {local}"
        );
        assert!(got.metadata.authoritative, "at {local}");
        // The question, the SOA RRset at its name, which shows the zone
        // the answer came from, and the question in that zone, whose copy
        // the second address shares.
        let asked: Vec<(LowerName, RecordType)> = looked
            .iter()
            .map(|lookup| (lookup.zone.clone(), lookup.question.query_type()))
            .collect();
        let mut want = vec![
            (lower("example."), RecordType::A),
            (lower("example."), RecordType::SOA),
        ];
        if local == first {
            want.push((lower("srv.child.example."), RecordType::A));
        }
        assert_eq!(asked, want, "at {local}");
    }
}

/// The lookup of `request`'s question at `local`, in `example`.
fn own(local: SocketAddr, request: &Request) -> Lookup {
    Lookup::new(local, lower("example."), &request.question)
}

/// An address noted for a zone its real server does not serve, as a
/// lame delegation names, answers as that server does once a lookup
/// shows it: from the zones it does serve, with the referral the real
/// server gives, or REFUSED when none holds the name (RFC 1034 §4.3.1,
/// RFC 8906 §3.1.1). It never stays silent.
#[test]
fn copies_drop_a_zone_their_real_server_does_not_serve() {
    // `lame` is delegated to the parent's own server, which does not
    // serve it.
    let text = format!(
        "{EXAMPLE}\
lame.example. 3600 IN NS ns.lame.example.
ns.lame.example. 3600 IN A 192.0.2.53
"
    );
    let real = Zones::new(vec![
        Arc::new(Zone::from_master(&text, None).unwrap()) as Arc<dyn ZoneData>
    ]);
    let answer = |lookup: &Lookup| reply_of(&real, lookup);
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let copies = Copies::new();
    for zone in ["example.", "lame.example.", "elsewhere.test."] {
        copies.serves(local.ip(), &lower(zone));
    }
    for qname in ["www.lame.example.", "www.elsewhere.test."] {
        for round in 0..2 {
            let request = request(qname, RecordType::A, false);
            let (got, _) = through(&copies, &answer, local, &request);
            let want = reply_of(&real, &own(local, &request));
            assert_eq!(shape(&got), shape(&want), "{qname} round {round}");
        }
    }
}

/// A real server that stops a chain early, as BIND does at the CNAME a
/// DNAME makes for a CNAME question, and as it answers NODATA for NSEC at
/// a CNAME in an NSEC3 zone: the copy goes on where the chain leads, as
/// RFC 1034 §4.3.2 and RFC 6672 §3.2 say, and looks up the name the chain
/// reached, so it answers as the RFCs do and never stays silent.
#[test]
fn a_copy_looks_up_where_a_stopped_chain_leads() {
    let text = format!(
        "{EXAMPLE}\
dn.example. 300 IN DNAME target.example.
a.target.example. 300 IN A 192.0.2.41
"
    );
    let zone = signed_master(
        &text,
        Denial::Nsec3 {
            opt_out: false,
            salt: Vec::new(),
        },
    );
    let zones = Zones::new(vec![Arc::new(zone.clone()) as Arc<dyn ZoneData>]);
    let soa: Vec<Record> = real(&zone, &request("example.", RecordType::SOA, true)).answers;
    let stopping = |lookup: &Lookup| {
        let mut message = reply_of(&zones, lookup);
        let qtype = lookup.question.query_type();
        let dname = message
            .answers
            .iter()
            .any(|record| record.record_type() == RecordType::DNAME);
        let cname = message
            .answers
            .first()
            .is_some_and(|record| record.record_type() == RecordType::CNAME);
        if qtype == RecordType::CNAME && dname {
            // The DNAME and the CNAME made from it, with their RRSIGs,
            // and no more.
            message.answers.retain(|record| {
                record.name == name("dn.example.") || record.name == *lookup.question.name()
            });
            message.authorities.clear();
        } else if qtype == RecordType::NSEC && cname {
            message.answers.clear();
            message.authorities = soa.clone();
        }
        message
    };
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let copies = Copies::new();
    copies.serves(local.ip(), &lower("example."));
    let cname = request("a.dn.example.", RecordType::CNAME, true);
    let (got, looked) = through(&copies, &stopping, local, &cname);
    assert_eq!(shape(&got), shape(&real(&zone, &cname)));
    let reached: Vec<String> = looked
        .iter()
        .map(|lookup| lookup.question.name().to_ascii())
        .collect();
    assert_eq!(reached, ["a.dn.example.", "a.target.example."]);

    let alias = request("alias.example.", RecordType::A, true);
    through(&copies, &stopping, local, &alias);
    let nsec = request("alias.example.", RecordType::NSEC, true);
    let (got, _) = through(&copies, &stopping, local, &nsec);
    assert_eq!(shape(&got), shape(&real(&zone, &nsec)));
}
