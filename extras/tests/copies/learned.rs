//! Zones learned from their real servers: what a learned zone answers
//! from the responses filed into it, that an unknown fact never becomes a
//! negative, and which zones copies find each address serves.

use std::net::SocketAddr;
use std::sync::Arc;

use fictionet::stdlib::protocols::dns::dnssec::proof::nodata;
use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
use fictionet::stdlib::protocols::dns::dnssec::{
    Algorithm, KeyFlags, KeySet, Proof, Sign, ZoneKey,
};
use fictionet::stdlib::protocols::dns::op::{
    Edns, Message, MessageType, OpCode, Query, ResponseCode,
};
use fictionet::stdlib::protocols::dns::rr::{
    DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::protocols::dns::{Parsed, Request};
use fictionet::stdlib::services::dns::authority::{
    Authority, AuthorityEngine, ServerConfig, Step, Zones,
};
use fictionet::stdlib::services::dns::zone::{
    Answered, AnyResponse, Denial, Denied, Fact, Zone, ZoneData, answer,
};
use fictionet::stdlib::services::dns::{
    Action, Client, ClientQuery, Engine, Generation, Input, Looked, Lookup,
};
use fictionet::stdlib::services::serve::Transport;
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};
use fictionet_extras::dns::copies::Copies;
use fictionet_extras::dns::learned::{Filing, Learned, Section};
use fictionet_test_support::dns::TestInternet;

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
    let filed = [
        ("www.example.", RecordType::A),
        ("www.example.", RecordType::TXT),
        ("www.child.example.", RecordType::A),
        ("a.wild.example.", RecordType::A),
    ];
    for (qname, qtype) in filed {
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

    // A server of a copy holding the same responses, with no upstream,
    // looks the question up and, when nothing comes, sends nothing: no
    // negative answer.
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let copies = Copies::new();
    copies.serves(local.ip(), &lower("example."));
    for (qname, qtype) in filed {
        let asked = request(qname, qtype, true);
        let lookup = Lookup::new(local, lower("example."), &asked.question);
        let looked = Looked::Response(real(&zone, &asked));
        copies.keep(&lookup, &looked, Generation(0));
    }
    let mut engine = AuthorityEngine::new(copies, ServerConfig::generic(), local);
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
    through_as(authority, &ServerConfig::generic(), real, local, request)
}

/// [`through`], with `server` as the front of `authority`.
fn through_as(
    authority: &dyn Authority,
    server: &ServerConfig,
    real: Real<'_>,
    local: SocketAddr,
    request: &Request,
) -> (Message, Vec<Lookup>) {
    let client = Client {
        peer: "198.51.100.7:5353".parse().unwrap(),
        local,
        transport: Transport::Udp,
        connection: None,
        sandbox: None,
    };
    let mut looked = Vec::new();
    loop {
        match authority.respond(request, local, server, &client) {
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
/// server serves: the cut refers only names a referral was filed for, so
/// any other name is looked up at the address. The authoritative answer
/// from the zone below, here a minimal one that shows no apex, is filed
/// at that address, which answers the question from it from then on.
/// Each address looks the question up itself, once, and at its own real
/// server, whatever another address learned.
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
        // The question alone, at the address itself.
        assert_eq!(looked, vec![own(local, &below)], "at {local}");
        let (again, looked) = through(&copies, &answer, local, &below);
        assert_eq!(shape(&again), shape(&got), "at {local}, again");
        assert!(looked.is_empty(), "at {local}, again: {looked:?}");
    }
}

/// A copy of a signed zone that is asked ANY with DO before it holds the
/// zone's SOA still knows the zone is signed: the name's own RRsets carry
/// RRSIGs (RFC 4035 §2.2). It never sends an unsigned HINFO, which a
/// validator rejects, and answers as the real server does, with one
/// RRset and its RRSIGs (RFC 8482 §4.1).
#[test]
fn a_fresh_copy_of_a_signed_zone_answers_any_as_the_zone_does() {
    for denial in [
        Denial::Nsec,
        Denial::Nsec3 {
            opt_out: false,
            salt: Vec::new(),
        },
    ] {
        for qname in ["example.", "www.example."] {
            let real = Zones::new(vec![Arc::new(signed(denial.clone())) as Arc<dyn ZoneData>]);
            let answer = |lookup: &Lookup| reply_of(&real, lookup);
            let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
            let copies = Copies::new();
            copies.serves(local.ip(), &lower("example."));
            let any = request(qname, RecordType::ANY, true);
            let (got, _) = through(&copies, &answer, local, &any);
            assert_eq!(
                shape(&got),
                shape(&reply_of(&real, &own(local, &any))),
                "{qname} {denial:?}"
            );
            assert!(
                got.answers
                    .iter()
                    .any(|record| record.record_type() == RecordType::RRSIG),
                "{qname} {denial:?}: signed"
            );
        }
    }
}

/// A copy answers a NODATA question for a wildcard's own name, and for a
/// name the wildcard answers for, as the zone it copied does, with the
/// same denial records (RFC 5155 §7.2.3, §7.2.5).
#[test]
fn a_copy_denies_at_a_wildcard_as_the_zone_does() {
    for (how, zone) in three_ways(EXAMPLE) {
        for qname in ["*.wild.example.", "x.wild.example."] {
            let learned = Learned::new(&name("example."));
            let asked = request(qname, RecordType::TXT, true);
            learned.file(Generation(0), &asked.question, &real(&zone, &asked));
            let copy = copied(&learned, &asked).expect("the copy knows the NODATA");
            assert_eq!(shape(&copy), shape(&real(&zone, &asked)), "{how} {qname}");
        }
    }
}

/// Two real servers of `example`: the first also serves
/// `srv.child.example`, below the cut at `child.example`, and the second
/// does not, so it refers names there to the cut.
fn two_servers() -> [(SocketAddr, Zones); 2] {
    let zone = |text: &str| Arc::new(Zone::from_master(text, None).unwrap()) as Arc<dyn ZoneData>;
    [
        (
            "192.0.2.53:53".parse().unwrap(),
            Zones::new(vec![zone(EXAMPLE), zone(SRV)]),
        ),
        (
            "192.0.2.153:53".parse().unwrap(),
            Zones::new(vec![zone(EXAMPLE)]),
        ),
    ]
}

/// Each address answers as its own real server does, whichever address
/// asked first: each keeps its own copy of `example`, so the minimal
/// answer of the server that also serves a zone below an unknown cut, and
/// the referral of the one that does not (RFC 1034 §4.2.1, §4.3.2), stay
/// with the address that got them. Each address looks the question up at
/// its own real server, even after the other filed its answer.
#[test]
fn each_address_answers_as_its_own_server_whichever_asked_first() {
    let servers = two_servers();
    let real = |lookup: &Lookup| {
        let (_, zones) = servers
            .iter()
            .find(|(addr, _)| addr.ip() == lookup.server.ip())
            .expect("a real server at the address");
        reply_of(zones, lookup)
    };
    for qtype in [RecordType::A, RecordType::NS] {
        let qname = match qtype {
            RecordType::NS => "srv.child.example.",
            _ => "www.srv.child.example.",
        };
        let question = request(qname, qtype, false);
        for order in [[0, 1], [1, 0]] {
            let copies = Copies::new();
            for (addr, _) in &servers {
                copies.serves(addr.ip(), &lower("example."));
            }
            for at in order {
                let local = servers[at].0;
                let (got, looked) = through(&copies, &real, local, &question);
                let want = reply_of(&servers[at].1, &own(local, &question));
                assert_eq!(
                    shape(&got),
                    shape(&want),
                    "{qname} {qtype} at {local}, asked in order {order:?}"
                );
                assert_eq!(
                    looked,
                    vec![own(local, &question)],
                    "{qname} {qtype} at {local}, asked in order {order:?}"
                );
            }
        }
    }
}

/// A zone whose name servers lie below one of its own cuts, as the root
/// servers lie below `net`: their addresses are glue under the cut.
const SERVERS_BELOW: &str = "\
top. 3600 IN SOA a.servers.net.top. hostmaster.top. 1 7200 3600 1209600 300
top. 3600 IN NS a.servers.net.top.
top. 3600 IN NS b.servers.net.top.
a.servers.net.top. 3600 IN A 192.0.2.1
b.servers.net.top. 3600 IN A 192.0.2.2
net.top. 3600 IN NS x.gtld.net.top.
x.gtld.net.top. 3600 IN A 192.0.2.10
";

/// The addresses of an apex's name servers that lie below a cut go out
/// with its NS RRset as the real server sends them, whether the copy
/// learned the cut before or after the apex's NS RRset.
#[test]
fn an_apex_ns_answer_keeps_its_addresses_below_a_cut() {
    for (signing, zone) in three_ways(SERVERS_BELOW) {
        let real = Zones::new(vec![Arc::new(zone) as Arc<dyn ZoneData>]);
        let answer = |lookup: &Lookup| reply_of(&real, lookup);
        let local: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let ns = request("top.", RecordType::NS, false);
        let client = Client {
            peer: "198.51.100.7:5353".parse().unwrap(),
            local,
            transport: Transport::Udp,
            connection: None,
            sandbox: None,
        };
        let Step::Reply(want) = real.respond(&ns, local, &ServerConfig::generic(), &client) else {
            panic!("the real server answers");
        };
        let want = want.message;
        assert_eq!(additionals(&want).len(), 2, "{:?}", want.additionals);
        for order in [
            ["www.net.top.", "top.", "top."],
            ["top.", "www.net.top.", "top."],
        ] {
            let copies = Copies::new();
            copies.serves(local.ip(), &lower("top."));
            let mut got = None;
            for qname in order {
                let qtype = match qname {
                    "top." => RecordType::NS,
                    _ => RecordType::A,
                };
                let question = request(qname, qtype, false);
                got = Some(through(&copies, &answer, local, &question).0);
            }
            let got = got.expect("an answer");
            assert_eq!(shape(&got), shape(&want), "{signing}, {order:?}");
        }
    }
}

/// A copy answers an NS question at the apex from the response to that
/// question, not from the NS RRset another response carried in its
/// authority section. A server leaves out additional data to fit each
/// response (RFC 2181 §9), so only the NS question's own response carries
/// the addresses the server sends with that answer.
#[test]
fn an_apex_ns_question_is_answered_from_its_own_response() {
    for (signing, zone) in three_ways(EXAMPLE) {
        let real = Zones::new(vec![Arc::new(zone) as Arc<dyn ZoneData>]);
        // The server sends the apex NS RRset in the SOA answer's authority
        // section, as BIND does, and leaves the addresses out, as a
        // server short of room does.
        let answer = |lookup: &Lookup| {
            let mut reply = reply_of(&real, lookup);
            if lookup.question.query_type() == RecordType::SOA {
                let apex = Query::query(name("example."), RecordType::NS);
                let ns = reply_of(
                    &real,
                    &Lookup::new(lookup.server, lookup.zone.clone(), &apex),
                );
                reply.authorities.extend(ns.answers);
                reply.additionals.clear();
            }
            reply
        };
        let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
        let copies = Copies::new();
        copies.serves(local.ip(), &lower("example."));
        let soa = request("example.", RecordType::SOA, true);
        through(&copies, &answer, local, &soa);
        let ns = request("example.", RecordType::NS, true);
        let want = reply_of(&real, &own(local, &ns));
        assert!(!additionals(&want).is_empty(), "{signing}");
        let (got, looked) = through(&copies, &answer, local, &ns);
        assert_eq!(shape(&got), shape(&want), "{signing}");
        assert_eq!(looked, vec![own(local, &ns)], "{signing}");
    }
}

/// What each address filed belongs to its session. When the session
/// advances, every address looks its questions up again, a response to a
/// lookup of the session before files nothing when it comes late, and
/// the new session's response answers as the real server does.
#[test]
fn a_session_advance_clears_every_address_and_drops_late_responses() {
    let servers = two_servers();
    let real = |lookup: &Lookup| {
        let (_, zones) = servers
            .iter()
            .find(|(addr, _)| addr.ip() == lookup.server.ip())
            .expect("a real server at the address");
        reply_of(zones, lookup)
    };
    let copies = Copies::new();
    for (addr, _) in &servers {
        copies.serves(addr.ip(), &lower("example."));
    }
    let question = request("www.example.", RecordType::A, false);
    let server = ServerConfig::generic();
    let step = |local: SocketAddr| {
        let client = Client {
            peer: "198.51.100.7:5353".parse().unwrap(),
            local,
            transport: Transport::Udp,
            connection: None,
            sandbox: None,
        };
        copies.respond(&question, local, &server, &client)
    };
    for (local, zones) in &servers {
        let (got, looked) = through(&copies, &real, *local, &question);
        assert_eq!(looked, [own(*local, &question)], "{local}");
        assert_eq!(
            shape(&got),
            shape(&reply_of(zones, &own(*local, &question)))
        );
        assert!(matches!(step(*local), Step::Reply(_)), "{local}: filed");
    }

    copies.advance(Generation(1));
    for (local, zones) in &servers {
        let lookup = own(*local, &question);
        let Step::Need(needed) = step(*local) else {
            panic!("{local}: the new session looks the question up again");
        };
        assert_eq!(needed, lookup, "{local}");
        copies.file(&lookup, &Looked::Response(real(&lookup)), Generation(0));
        assert!(
            matches!(step(*local), Step::Need(_)),
            "{local}: the session before filed into this one"
        );
        copies.file(&lookup, &Looked::Response(real(&lookup)), Generation(1));
        let Step::Reply(got) = step(*local) else {
            panic!("{local}: the new session's response answers");
        };
        assert_eq!(shape(&got.message), shape(&reply_of(zones, &lookup)));
    }
}

/// An address noted for `example` whose real server serves only
/// `srv.child.example` below it answers DS at that zone's apex from the
/// child, NODATA, as that server does: a server of a zone above would
/// answer from the zone above (RFC 4035 §3.1.4.1), so the address serves
/// no zone above, and the copy never stays silent.
#[test]
fn an_address_that_serves_only_the_child_answers_ds_at_its_apex() {
    let real = Zones::new(vec![
        Arc::new(Zone::from_master(SRV, None).unwrap()) as Arc<dyn ZoneData>
    ]);
    let answer = |lookup: &Lookup| reply_of(&real, lookup);
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let copies = Copies::new();
    copies.serves(local.ip(), &lower("example."));
    let ds = request("srv.child.example.", RecordType::DS, false);
    let (got, _) = through(&copies, &answer, local, &ds);
    let want = reply_of(&real, &own(local, &ds));
    assert_eq!(shape(&got), shape(&want));
    assert_eq!(got.metadata.response_code, ResponseCode::NoError);
    assert!(got.metadata.authoritative);
}

/// The lookup of `request`'s question at `local`, in `example`.
fn own(local: SocketAddr, request: &Request) -> Lookup {
    Lookup::new(local, lower("example."), &request.question)
}

/// A transfer is refused before anything else, with no lookup, even of a
/// name below a cut whose zone the address knows only from a minimal
/// answer and still looks other questions up for: a transfer lists a
/// zone, and a copy lists none (RFC 5936 §2.2).
#[test]
fn copies_refuse_a_transfer_below_a_cut() {
    let real = Zones::new(vec![
        Arc::new(Zone::from_master(EXAMPLE, None).unwrap()) as Arc<dyn ZoneData>,
        Arc::new(Zone::from_master(SRV, None).unwrap()) as Arc<dyn ZoneData>,
    ]);
    let answer = |lookup: &Lookup| reply_of(&real, lookup);
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let copies = Copies::new();
    copies.serves(local.ip(), &lower("example."));
    let server = ServerConfig::generic();
    let client = Client {
        peer: "198.51.100.7:5353".parse().unwrap(),
        local,
        transport: Transport::Tcp,
        connection: None,
        sandbox: None,
    };
    // A referral files the cut, and a minimal authoritative answer from
    // the zone below it, which shows no apex, the name's A RRset.
    through(
        &copies,
        &answer,
        local,
        &request("x.child.example.", RecordType::A, false),
    );
    let below = request("www.srv.child.example.", RecordType::A, false);
    let Step::Need(lookup) = copies.respond(&below, local, &server, &client) else {
        panic!("the copy looks the question up");
    };
    copies.file(&lookup, &Looked::Response(answer(&lookup)), Generation(0));
    // Any other question there is still looked up at the address.
    let other = request("www.srv.child.example.", RecordType::TXT, false);
    match copies.respond(&other, local, &server, &client) {
        Step::Need(lookup) => {
            assert_eq!(lookup.server, local);
            assert_eq!(lookup.question, other.question);
        }
        step => panic!("the copy looks TXT up: {step:?}"),
    }
    for qtype in [RecordType::AXFR, RecordType::IXFR] {
        let mut message = Message::new(7, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(name("www.srv.child.example."), qtype));
        let Parsed::Request(transfer) = Request::parse(&message.to_vec().unwrap(), Transport::Tcp)
        else {
            panic!("{qtype} over TCP parses");
        };
        match copies.respond(&transfer, local, &server, &client) {
            Step::Reply(response) => assert_eq!(
                response.message.metadata.response_code,
                ResponseCode::Refused,
                "{qtype}"
            ),
            step => panic!("{qtype}: {step:?}"),
        }
    }
}

/// An address noted for a zone its real server does not serve, as a
/// lame delegation names, answers each question as that server did: from
/// the zones it does serve, with the referral the real server gives, or
/// REFUSED when none holds the name (RFC 1034 §4.3.1, RFC 8906 §3.1.1).
/// It never stays silent.
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

/// An address noted for the root, whose real server serves only the
/// signed `example` below it, answers each question as that server does
/// in every order: a refusal in the root does not hide the child zone
/// the server serves (RFC 1034 §4.3.2 step 2, RFC 8906 §3.1.1).
#[test]
fn a_lame_address_finds_the_child_its_server_serves_in_any_order() {
    let real = Zones::new(vec![
        Arc::new(signed_master(EXAMPLE, Denial::Nsec)) as Arc<dyn ZoneData>
    ]);
    let answer = |lookup: &Lookup| reply_of(&real, lookup);
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let client = Client {
        peer: "198.51.100.7:5353".parse().unwrap(),
        local,
        transport: Transport::Udp,
        connection: None,
        sandbox: None,
    };
    let want =
        |request: &Request| match real.respond(request, local, &ServerConfig::generic(), &client) {
            Step::Reply(response) => response.message,
            step => panic!("the real server gave {step:?}"),
        };
    let questions = [
        request("foo.", RecordType::A, false),
        request("www.example.", RecordType::A, false),
        request("www.example.", RecordType::A, true),
        request("nx.example.", RecordType::A, true),
    ];
    for order in [[0, 1, 2, 3], [1, 0, 3, 2], [3, 2, 1, 0]] {
        let copies = Copies::new();
        copies.serves(local.ip(), &lower("."));
        for round in 0..2 {
            for at in order {
                let asked = &questions[at];
                let (got, _) = through(&copies, &answer, local, asked);
                assert_eq!(
                    shape(&got),
                    shape(&want(asked)),
                    "{:?}, order {order:?}, round {round}",
                    asked.question
                );
            }
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

/// A CNAME loop is an error (RFC 1034 §3.6.2): the real server answers
/// SERVFAIL with the chain, and its copy answers every question at the
/// loop with the same RCODE and records, in any order of questions.
#[test]
fn a_copy_answers_a_cname_loop_as_its_server_does() {
    let text = format!(
        "{EXAMPLE}\
self.example. 300 IN CNAME self.example.
loop1.example. 300 IN CNAME loop2.example.
loop2.example. 300 IN CNAME loop1.example.
"
    );
    let real = Zones::new(vec![
        Arc::new(Zone::from_master(&text, None).unwrap()) as Arc<dyn ZoneData>
    ]);
    let answer = |lookup: &Lookup| reply_of(&real, lookup);
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let questions = [
        request("self.example.", RecordType::A, true),
        request("self.example.", RecordType::CNAME, true),
        request("loop1.example.", RecordType::A, true),
        request("loop2.example.", RecordType::TXT, true),
        request("loop2.example.", RecordType::CNAME, true),
    ];
    for order in [[0, 1, 2, 3, 4], [1, 0, 4, 3, 2], [4, 2, 3, 1, 0]] {
        let copies = Copies::new();
        copies.serves(local.ip(), &lower("example."));
        for round in 0..2 {
            for at in order {
                let asked = &questions[at];
                let (got, _) = through(&copies, &answer, local, asked);
                let want = answer(&own(local, asked));
                assert_eq!(
                    shape(&got),
                    shape(&want),
                    "{:?}, order {order:?}, round {round}",
                    asked.question
                );
            }
        }
    }
    let want = answer(&own(local, &questions[0]));
    assert_eq!(want.metadata.response_code, ResponseCode::ServFail);
}

/// A real server that answers NSEC at a CNAME, or at a name a wildcard
/// CNAME answers for, with NODATA, as BIND does in an NSEC3 zone, though
/// its denial records show the CNAME there. Without an NSEC RRset beside
/// it the CNAME is followed (RFC 1034 §4.3.2 step 3a, RFC 4035 §2.5), so
/// the copy asks for the CNAME and answers every question as the RFCs do,
/// in any order of questions.
#[test]
fn a_copy_follows_an_alias_its_server_stopped_at_for_nsec() {
    let text = format!(
        "{EXAMPLE}*.wc.example. 300 IN CNAME www.example.
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
    // The NSEC3 records of every proof such a NODATA may need, which
    // show the CNAME at the name or at the wildcard in their type bitmaps.
    let view = zone.view(&Query::query(name("example."), RecordType::NSEC));
    let wc = lower("wc.example.");
    let mut nsec3: Vec<Record> = Vec::new();
    for (owner, kind) in [
        ("y.wc.example.", Denied::Name),
        (
            "y.wc.example.",
            Denied::Wildcard {
                closest_encloser: wc,
            },
        ),
        ("*.wc.example.", Denied::Type(RecordType::NSEC)),
        ("alias.example.", Denied::Type(RecordType::NSEC)),
    ] {
        let Fact::Present(sets) = view.denial(&lower(owner), kind) else {
            panic!("{owner}: the zone proves it");
        };
        for record in sets.iter().flat_map(|set| set.records(true)) {
            if !nsec3.contains(record) {
                nsec3.push(record.clone());
            }
        }
    }
    let stopping = |lookup: &Lookup| {
        let mut message = reply_of(&zones, lookup);
        let cname = message
            .answers
            .first()
            .is_some_and(|record| record.record_type() == RecordType::CNAME);
        if lookup.question.query_type() == RecordType::NSEC && cname {
            message.answers.clear();
            message.authorities = soa.iter().chain(&nsec3).cloned().collect();
        }
        message
    };
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let questions = [
        request("y.wc.example.", RecordType::NSEC, true),
        request("y.wc.example.", RecordType::CNAME, true),
        request("*.wc.example.", RecordType::NSEC, true),
        request("alias.example.", RecordType::NSEC, true),
        request("alias.example.", RecordType::A, true),
        request("y.wc.example.", RecordType::NSEC, false),
    ];
    for order in [[0, 1, 2, 3, 4, 5], [4, 2, 1, 0, 5, 3], [5, 3, 4, 2, 0, 1]] {
        let copies = Copies::new();
        copies.serves(local.ip(), &lower("example."));
        for round in 0..2 {
            for at in order {
                let asked = &questions[at];
                let (got, _) = through(&copies, &stopping, local, asked);
                assert_eq!(
                    shape(&got),
                    shape(&real(&zone, asked)),
                    "{:?}, order {order:?}, round {round}",
                    asked.question
                );
            }
        }
    }
}

/// `child.example` as its own zone, with a cut of its own at
/// `sub.child.example`.
const CHILD_WITH_CUT: &str = "\
child.example. 3600 IN SOA ns.child.example. hostmaster.example. 1 7200 3600 1209600 300
child.example. 3600 IN NS ns.child.example.
ns.child.example. 3600 IN A 192.0.2.54
sub.child.example. 3600 IN NS ns.sub.child.example.
ns.sub.child.example. 3600 IN A 192.0.2.60
";

/// Two real servers of `example`: the first also serves `child.example`,
/// so it refers names below `sub.child.example` there, and the second
/// refers them to `child.example`. Each address answers as its own
/// server, in every order the two are asked, and never stays silent: each
/// files its own referrals, and a referral to one cut says nothing of
/// another (RFC 1034 §4.2.1, §4.3.2 step 3b).
#[test]
fn each_address_refers_to_its_own_servers_deepest_cut() {
    let zone = |text: &str| Arc::new(Zone::from_master(text, None).unwrap()) as Arc<dyn ZoneData>;
    let servers: [(SocketAddr, Zones); 2] = [
        (
            "192.0.2.53:53".parse().unwrap(),
            Zones::new(vec![zone(EXAMPLE), zone(CHILD_WITH_CUT)]),
        ),
        (
            "192.0.2.153:53".parse().unwrap(),
            Zones::new(vec![zone(EXAMPLE)]),
        ),
    ];
    let real = |lookup: &Lookup| {
        let (_, zones) = servers
            .iter()
            .find(|(addr, _)| addr.ip() == lookup.server.ip())
            .expect("a real server at the address");
        reply_of(zones, lookup)
    };
    let questions = [
        request("www.sub.child.example.", RecordType::A, false),
        request("nope.child.example.", RecordType::TXT, false),
        request("sub.child.example.", RecordType::MX, false),
    ];
    for order in [[0, 1, 0], [1, 0, 1]] {
        for first in &questions {
            for second in &questions {
                let copies = Copies::new();
                for (addr, _) in &servers {
                    copies.serves(addr.ip(), &lower("example."));
                }
                for (step, at) in order.into_iter().enumerate() {
                    let question = if step == 1 { second } else { first };
                    let local = servers[at].0;
                    let (got, _) = through(&copies, &real, local, question);
                    let want = reply_of(&servers[at].1, &own(local, question));
                    assert_eq!(
                        shape(&got),
                        shape(&want),
                        "{:?} at {local}, order {order:?}, step {step}",
                        question.question
                    );
                }
            }
        }
    }
}

/// A real server may answer a question with an error RCODE that gives no
/// records, such as FORMERR to a type it will not serve or SERVFAIL to a
/// CNAME loop. The copy answers that question with the same RCODE, never
/// with silence (RFC 8906 §3.1).
#[test]
fn a_copy_answers_with_the_error_its_real_server_gave() {
    let real = Zones::new(vec![
        Arc::new(Zone::from_master(EXAMPLE, None).unwrap()) as Arc<dyn ZoneData>
    ]);
    let erring = |lookup: &Lookup| {
        let mut message = reply_of(&real, lookup);
        let rcode = match lookup.question.query_type() {
            RecordType::NULL => ResponseCode::FormErr,
            RecordType::TXT => ResponseCode::ServFail,
            RecordType::MX => ResponseCode::NotImp,
            _ => return message,
        };
        message.metadata.response_code = rcode;
        message.answers.clear();
        message.authorities.clear();
        message.additionals.clear();
        message
    };
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let copies = Copies::new();
    copies.serves(local.ip(), &lower("example."));
    for (qtype, rcode) in [
        (RecordType::NULL, ResponseCode::FormErr),
        (RecordType::TXT, ResponseCode::ServFail),
        (RecordType::MX, ResponseCode::NotImp),
    ] {
        for round in 0..2 {
            let asked = request("www.example.", qtype, false);
            let (got, _) = through(&copies, &erring, local, &asked);
            assert_eq!(got.metadata.response_code, rcode, "{qtype} round {round}");
            assert!(got.answers.is_empty(), "{qtype} round {round}");
        }
    }
    // A name whose own records the copy still learns from its server.
    let asked = request("www.example.", RecordType::A, false);
    let (got, _) = through(&copies, &erring, local, &asked);
    assert_eq!(shape(&got), shape(&reply_of(&real, &own(local, &asked))));
}

/// The real servers of `example` and of `srv.child.example` below its cut
/// at `child.example`, with an alias in the child that leads out of both,
/// answering with minimal responses: no authority or additional section
/// beside an answer.
fn minimal_servers() -> impl Fn(&Lookup) -> Message {
    let text = format!("{SRV}alias.srv.child.example. 300 IN CNAME www.elsewhere.test.\n");
    let real = Zones::new(vec![
        Arc::new(Zone::from_master(EXAMPLE, None).unwrap()) as Arc<dyn ZoneData>,
        Arc::new(Zone::from_master(&text, None).unwrap()) as Arc<dyn ZoneData>,
    ]);
    move |lookup: &Lookup| {
        let mut message = reply_of(&real, lookup);
        if !message.answers.is_empty() {
            message.authorities.clear();
            message.additionals.clear();
        }
        message
    }
}

/// An alias in a zone below a cut answers at its name with the CNAME
/// alone (RFC 1034 §3.6.2), which shows no apex when the server sends no
/// authority section. The copy files it at the address in a zone below
/// the cut, and answers as the real server does, never with silence,
/// while a name the server refers is still referred.
#[test]
fn copies_place_an_alias_below_a_cut() {
    let real = minimal_servers();
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    for qtype in [RecordType::A, RecordType::SOA] {
        let copies = Copies::new();
        copies.serves(local.ip(), &lower("example."));
        // A referral files the cut at `child.example`.
        let referral = request("x.child.example.", RecordType::A, false);
        through(&copies, &real, local, &referral);
        let asked = request("alias.srv.child.example.", qtype, false);
        for round in 0..2 {
            let (got, _) = through(&copies, &real, local, &asked);
            let want = real(&own(local, &asked));
            assert_eq!(shape(&got), shape(&want), "{qtype} round {round}");
            assert_eq!(got.answers.len(), 1, "{qtype} round {round}");
        }
        for qname in ["x.child.example.", "y.child.example."] {
            let referred = request(qname, RecordType::A, false);
            let (got, _) = through(&copies, &real, local, &referred);
            let want = real(&own(local, &referred));
            assert!(!want.metadata.authoritative, "{qtype}: {qname} is referred");
            assert_eq!(shape(&got), shape(&want), "{qtype}: {qname}");
        }
    }
}

/// An address whose real server refuses some questions below a cut and
/// answers others answers each as its server did: REFUSED where the
/// server refused (RFC 8906 §3.1.1), the server's answer elsewhere, and
/// never silence.
#[test]
fn an_address_answers_refused_where_its_server_refused() {
    let minimal = minimal_servers();
    let refusing = |lookup: &Lookup| {
        let mut message = minimal(lookup);
        if lookup.question.query_type() == RecordType::SOA {
            message.metadata.response_code = ResponseCode::Refused;
            message.metadata.authoritative = false;
            message.answers.clear();
            message.authorities.clear();
            message.additionals.clear();
        }
        message
    };
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let copies = Copies::new();
    copies.serves(local.ip(), &lower("example."));
    through(
        &copies,
        &refusing,
        local,
        &request("x.child.example.", RecordType::A, false),
    );
    for round in 0..2 {
        for qtype in [RecordType::SOA, RecordType::A] {
            let asked = request("www.srv.child.example.", qtype, false);
            let (got, _) = through(&copies, &refusing, local, &asked);
            let want = refusing(&own(local, &asked));
            assert_eq!(shape(&got), shape(&want), "{qtype} round {round}");
            let rcode = match qtype {
                RecordType::SOA => ResponseCode::Refused,
                _ => ResponseCode::NoError,
            };
            assert_eq!(got.metadata.response_code, rcode, "{qtype} round {round}");
        }
    }
}

/// A real server may answer ANY with DO at an NSEC-signed name with the
/// name's NSEC RRset alone (RFC 8482 §4.1). The copy that filed that
/// answer still knows the name has data, so it answers ANY without DO as
/// the real server does, never with NODATA.
#[test]
fn an_any_answer_of_only_nsec_never_makes_a_nodata() {
    let text = format!("{EXAMPLE}svc.example. 300 IN HTTPS 1 . alpn=h2\n");
    let real = Zones::new(vec![
        Arc::new(signed_master(&text, Denial::Nsec)) as Arc<dyn ZoneData>
    ]);
    let answer = |lookup: &Lookup| reply_of(&real, lookup);
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let copies = Copies::new();
    copies.serves(local.ip(), &lower("example."));
    let with_do = request("svc.example.", RecordType::ANY, true);
    let (got, _) = through(&copies, &answer, local, &with_do);
    assert_eq!(shape(&got), shape(&reply_of(&real, &own(local, &with_do))));
    assert!(
        got.answers
            .iter()
            .all(|record| matches!(record.record_type(), RecordType::NSEC | RecordType::RRSIG)),
        "the real server answers with the NSEC RRset: {got:?}"
    );
    let without_do = request("svc.example.", RecordType::ANY, false);
    let (got, _) = through(&copies, &answer, local, &without_do);
    let want = match real.respond(
        &without_do,
        local,
        &ServerConfig::generic(),
        &Client {
            peer: "198.51.100.7:5353".parse().unwrap(),
            local,
            transport: Transport::Udp,
            connection: None,
            sandbox: None,
        },
    ) {
        Step::Reply(response) => response.message,
        step => panic!("the real server gave {step:?}"),
    };
    assert_eq!(shape(&got), shape(&want));
    assert!(!got.answers.is_empty(), "no NODATA: {got:?}");
}

/// QCLASS * gets FORMERR at a name below a cut that a minimal answer
/// gave, as at every other name (RFC 1034 §3.7.1), with no lookup.
#[test]
fn qclass_any_gets_formerr_below_a_cut() {
    let real = Zones::new(vec![
        Arc::new(Zone::from_master(EXAMPLE, None).unwrap()) as Arc<dyn ZoneData>,
        Arc::new(Zone::from_master(SRV, None).unwrap()) as Arc<dyn ZoneData>,
    ]);
    let answer = |lookup: &Lookup| reply_of(&real, lookup);
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let copies = Copies::new();
    copies.serves(local.ip(), &lower("example."));
    let server = ServerConfig::generic();
    let client = Client {
        peer: "198.51.100.7:5353".parse().unwrap(),
        local,
        transport: Transport::Udp,
        connection: None,
        sandbox: None,
    };
    through(
        &copies,
        &answer,
        local,
        &request("x.child.example.", RecordType::A, false),
    );
    let below = request("www.srv.child.example.", RecordType::A, false);
    let Step::Need(lookup) = copies.respond(&below, local, &server, &client) else {
        panic!("the copy looks the question up");
    };
    copies.file(&lookup, &Looked::Response(answer(&lookup)), Generation(0));
    let mut message = Message::new(7, MessageType::Query, OpCode::Query);
    let mut query = Query::query(name("www.srv.child.example."), RecordType::A);
    query.set_query_class(DNSClass::ANY);
    message.add_query(query);
    let Parsed::Request(any_class) = Request::parse(&message.to_vec().unwrap(), Transport::Udp)
    else {
        panic!("QCLASS * parses");
    };
    for (authority, what) in [(&copies as &dyn Authority, "copy"), (&real, "real")] {
        match authority.respond(&any_class, local, &server, &client) {
            Step::Reply(response) => assert_eq!(
                response.message.metadata.response_code,
                ResponseCode::FormErr,
                "{what}"
            ),
            step => panic!("{what}: {step:?}"),
        }
    }
}

/// A root zone whose `com` and `net` servers sit below the `net` cut,
/// as `gtld-servers.net` does.
const SIBLINGS: &str = "\
. 86400 IN SOA a.root-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 86400
. 518400 IN NS a.root-servers.net.
com. 172800 IN NS a.gtld-servers.net.
com. 172800 IN NS b.gtld-servers.net.
net. 172800 IN NS a.gtld-servers.net.
net. 172800 IN NS b.gtld-servers.net.
a.gtld-servers.net. 172800 IN A 192.5.6.30
a.gtld-servers.net. 172800 IN AAAA 2001:503:a83e::2:30
b.gtld-servers.net. 172800 IN A 192.33.14.30
a.root-servers.net. 518400 IN A 198.41.0.4
";

/// A copy answers its first referral with the sibling glue the real
/// server sent with it, the addresses of name servers below another cut
/// the copy has not learned yet (RFC 9471 §3.2), as the real server does.
#[test]
fn a_copys_first_referral_carries_the_sibling_glue() {
    let real = Zones::new(vec![
        Arc::new(Zone::from_master(SIBLINGS, None).unwrap()) as Arc<dyn ZoneData>
    ]);
    let answer = |lookup: &Lookup| reply_of(&real, lookup);
    let local: SocketAddr = "198.41.0.4:53".parse().unwrap();
    let copies = Copies::new();
    copies.serves(local.ip(), &lower("."));
    for dnssec_ok in [false, true] {
        let asked = request("com.", RecordType::A, dnssec_ok);
        let (got, _) = through(&copies, &answer, local, &asked);
        let want = reply_of(&real, &Lookup::new(local, lower("."), &asked.question));
        assert_eq!(shape(&got), shape(&want), "DO {dnssec_ok}");
        assert!(!got.additionals.is_empty(), "DO {dnssec_ok}: glue");
    }
}

/// A parent zone for questions asked in any order: data, aliases into
/// itself, out of it, into a child, and in a loop; wildcards, one with an
/// alias into the child; DNAMEs into itself and onto the child; and cuts
/// at `child.example` and at `sec.example`, a lame delegation to the
/// parent's own server.
const MIXED_PARENT: &str = "\
example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 3600 1209600 300
example. 3600 IN NS ns.example.
example. 300 IN MX 10 mail.example.
ns.example. 3600 IN A 192.0.2.53
mail.example. 300 IN A 192.0.2.25
www.example. 300 IN A 192.0.2.80
www.example. 300 IN AAAA 2001:db8::80
www.example. 300 IN TXT \"hi\"
alias.example. 300 IN CNAME www.example.
alias2.example. 300 IN CNAME alias.example.
out.example. 300 IN CNAME www.other.test.
intochild.example. 300 IN CNAME www.child.example.
intosrv.example. 300 IN CNAME www.srv.child.example.
*.wild.example. 300 IN A 192.0.2.99
*.wild.example. 300 IN TXT \"wild\"
sub.wild.example. 300 IN A 192.0.2.98
*.wc.example. 300 IN CNAME www.example.
host.ent.example. 300 IN A 192.0.2.7
d.example. 300 IN DNAME deep.example.
x.deep.example. 300 IN A 192.0.2.8
l1.example. 300 IN CNAME l2.example.
l2.example. 300 IN CNAME l1.example.
child.example. 3600 IN NS ns.child.example.
ns.child.example. 3600 IN A 192.0.2.54
sec.example. 3600 IN NS ns.example.
d2.example. 300 IN DNAME child.example.
*.wc2.example. 300 IN CNAME www.child.example.
";

/// The child of [`MIXED_PARENT`]: data, a wildcard, and an alias back
/// into the parent.
const MIXED_CHILD: &str = "\
child.example. 3600 IN SOA ns.child.example. h.child.example. 1 7200 3600 1209600 600
child.example. 3600 IN NS ns.child.example.
ns.child.example. 3600 IN A 192.0.2.54
www.child.example. 300 IN A 192.0.2.55
*.child.example. 300 IN TXT \"cw\"
back.child.example. 300 IN CNAME www.example.
";

/// The names asked in any order.
const MIXED_NAMES: &[&str] = &[
    "example.",
    "www.example.",
    "alias.example.",
    "alias2.example.",
    "out.example.",
    "intochild.example.",
    "intosrv.example.",
    "a.wild.example.",
    "b.wild.example.",
    "sub.wild.example.",
    "x.sub.wild.example.",
    "wild.example.",
    "a.wc.example.",
    "wc.example.",
    "ent.example.",
    "host.ent.example.",
    "d.example.",
    "a.d.example.",
    "x.d.example.",
    "deep.example.",
    "x.deep.example.",
    "l1.example.",
    "nx.example.",
    "deep.nx.example.",
    "child.example.",
    "www.child.example.",
    "ns.child.example.",
    "a.child.example.",
    "back.child.example.",
    "srv.child.example.",
    "www.srv.child.example.",
    "sec.example.",
    "a.sec.example.",
    "mail.example.",
    "ns.example.",
    "*.wild.example.",
    "y.a.wild.example.",
    "a.d2.example.",
    "www.d2.example.",
    "x.wc2.example.",
    "d2.example.",
    "q.back.child.example.",
];

/// The types asked in any order.
const MIXED_TYPES: &[RecordType] = &[
    RecordType::A,
    RecordType::AAAA,
    RecordType::TXT,
    RecordType::MX,
    RecordType::NS,
    RecordType::SOA,
    RecordType::DS,
    RecordType::NSEC,
    RecordType::CNAME,
    RecordType::DNAME,
    RecordType::ANY,
    RecordType::RRSIG,
    RecordType::HINFO,
];

/// `text` as a zone: unsigned, signed with NSEC, or signed with NSEC3,
/// as `signing` says (0, 1, or 2).
fn mixed_zone(text: &str, signing: usize) -> Arc<dyn ZoneData> {
    let zone = match signing {
        0 => Zone::from_master(text, None).unwrap(),
        1 => signed_master(text, Denial::Nsec),
        _ => signed_master(
            text,
            Denial::Nsec3 {
                opt_out: false,
                salt: Vec::new(),
            },
        ),
    };
    Arc::new(zone)
}

/// The real servers of [`MIXED_PARENT`], each noted for it: one that also
/// serves [`SRV`] below the child's cut, one that also serves the child,
/// one that serves the parent alone, and one that serves only the child,
/// so its delegation from the parent is lame.
fn mixed_servers(signing: usize) -> Vec<(SocketAddr, Zones)> {
    let parent = || mixed_zone(MIXED_PARENT, signing);
    let child = || mixed_zone(MIXED_CHILD, signing);
    vec![
        (
            "192.0.2.53:53".parse().unwrap(),
            Zones::new(vec![parent(), mixed_zone(SRV, signing)]),
        ),
        (
            "192.0.2.153:53".parse().unwrap(),
            Zones::new(vec![parent(), child()]),
        ),
        (
            "192.0.2.253:53".parse().unwrap(),
            Zones::new(vec![parent()]),
        ),
        ("192.0.2.99:53".parse().unwrap(), Zones::new(vec![child()])),
    ]
}

/// What `zones`, a real server at `local`, reply to `request`.
fn real_at(zones: &Zones, local: SocketAddr, request: &Request) -> Message {
    real_as(zones, &ServerConfig::generic(), local, request)
}

/// [`real_at`], with `server` as the real server's front.
fn real_as(zones: &Zones, server: &ServerConfig, local: SocketAddr, request: &Request) -> Message {
    let client = Client {
        peer: "198.51.100.7:5353".parse().unwrap(),
        local,
        transport: Transport::Udp,
        connection: None,
        sandbox: None,
    };
    match zones.respond(request, local, server, &client) {
        Step::Reply(response) => response.message,
        step => panic!("the real server gave {step:?}"),
    }
}

/// What `authority` at `local` replies to `request`, with each lookup put
/// to `real` and filed, or what kept it from replying.
fn answer_through(
    authority: &dyn Authority,
    real: Real<'_>,
    local: SocketAddr,
    request: &Request,
) -> Result<Message, String> {
    let client = Client {
        peer: "198.51.100.7:5353".parse().unwrap(),
        local,
        transport: Transport::Udp,
        connection: None,
        sandbox: None,
    };
    let mut looked: Vec<Lookup> = Vec::new();
    loop {
        match authority.respond(request, local, &ServerConfig::generic(), &client) {
            Step::Reply(response) => return Ok(response.message),
            Step::Need(lookup) if looked.contains(&lookup) => {
                return Err(format!("silent: {lookup:?} again"));
            }
            Step::Need(lookup) => {
                authority.file(&lookup, &Looked::Response(real(&lookup)), Generation(0));
                looked.push(lookup);
            }
            Step::Silent => return Err("silent".to_string()),
        }
    }
}

/// A question asked of a real server and of its copy: the server's
/// address, the name, the type, and whether DO is set.
type Asked<'a> = (SocketAddr, &'a str, RecordType, bool);

/// Asks `asked` in turn of copies of
/// `servers`' zones noted at every one of their addresses for `example`,
/// and of the real servers. The first question whose replies differ, with
/// both replies.
fn first_difference(servers: &[(SocketAddr, Zones)], asked: &[Asked<'_>]) -> Option<String> {
    let real = |lookup: &Lookup| {
        let (_, zones) = servers
            .iter()
            .find(|(addr, _)| addr.ip() == lookup.server.ip())
            .expect("a real server at the address");
        reply_of(zones, lookup)
    };
    let copies = Copies::new();
    for (addr, _) in servers {
        copies.serves(addr.ip(), &lower("example."));
    }
    for (step, (local, qname, qtype, dnssec_ok)) in asked.iter().enumerate() {
        let req = request(qname, *qtype, *dnssec_ok);
        let (_, zones) = servers
            .iter()
            .find(|(addr, _)| addr == local)
            .expect("a real server at the address");
        let want = shape(&real_at(zones, *local, &req));
        match answer_through(&copies, &real, *local, &req) {
            Ok(got) if shape(&got) == want => {}
            got => {
                return Some(format!(
                    "step {step}, {local} {qname} {qtype} DO={dnssec_ok}:\n  got  {:?}\n  want {want:?}",
                    got.map(|got| shape(&got))
                ));
            }
        }
    }
    None
}

/// Each address answers as its own real server does, whatever was asked
/// before at it or at the others: lame addresses, chains into a child
/// some addresses serve, signed and unsigned, and names a child holds
/// below a cut.
#[test]
fn each_address_answers_as_its_own_server_after_any_questions() {
    let (both, alone, lame, srv): (SocketAddr, SocketAddr, SocketAddr, SocketAddr) = (
        "192.0.2.153:53".parse().unwrap(),
        "192.0.2.253:53".parse().unwrap(),
        "192.0.2.99:53".parse().unwrap(),
        "192.0.2.53:53".parse().unwrap(),
    );
    let cases: Vec<(usize, Vec<Asked>)> = vec![
        // The child's signature shows its data is the child's, so the
        // address that serves the parent alone refers the alias's target.
        (
            1,
            vec![
                (both, "intochild.example.", RecordType::A, true),
                (alone, "intochild.example.", RecordType::A, false),
            ],
        ),
        (
            1,
            vec![
                (both, "www.d2.example.", RecordType::A, true),
                (alone, "www.d2.example.", RecordType::A, true),
            ],
        ),
        (
            2,
            vec![
                (both, "www.d2.example.", RecordType::RRSIG, false),
                (alone, "www.d2.example.", RecordType::RRSIG, true),
            ],
        ),
        // A lame address refuses, whatever another address answered.
        (
            1,
            vec![
                (srv, "y.a.wild.example.", RecordType::TXT, true),
                (lame, "y.a.wild.example.", RecordType::TXT, false),
            ],
        ),
        (
            0,
            vec![
                (srv, "alias2.example.", RecordType::A, false),
                (lame, "alias2.example.", RecordType::A, false),
            ],
        ),
        // A lame address answers for the child it serves.
        (
            0,
            vec![
                (lame, "alias.example.", RecordType::SOA, false),
                (lame, "www.child.example.", RecordType::A, true),
            ],
        ),
        (
            0,
            vec![
                (lame, "wc.example.", RecordType::DS, false),
                (lame, "ns.child.example.", RecordType::ANY, false),
            ],
        ),
        (
            0,
            vec![(lame, "back.child.example.", RecordType::NSEC, true)],
        ),
        // Another address's answer to ANY leaves this one's additional
        // data in place.
        (
            0,
            vec![
                (alone, "mail.example.", RecordType::ANY, true),
                (both, "example.", RecordType::MX, false),
            ],
        ),
        // Chains into the child below a cut learned at another address.
        (
            0,
            vec![
                (alone, "www.child.example.", RecordType::A, false),
                (both, "x.wc2.example.", RecordType::A, false),
                (both, "a.d2.example.", RecordType::A, false),
            ],
        ),
        (
            0,
            vec![
                (alone, "www.child.example.", RecordType::A, false),
                (srv, "intosrv.example.", RecordType::A, false),
            ],
        ),
        (
            0,
            vec![
                (alone, "www.d2.example.", RecordType::DS, false),
                (both, "back.child.example.", RecordType::DNAME, true),
            ],
        ),
        (
            0,
            vec![
                (both, "back.child.example.", RecordType::DS, false),
                (srv, "back.child.example.", RecordType::CNAME, false),
            ],
        ),
    ];
    for (signing, asked) in cases {
        let servers = mixed_servers(signing);
        if let Some(difference) = first_difference(&servers, &asked) {
            panic!("signing {signing}, {asked:?}: {difference}");
        }
    }
}

/// Copies answer as their real servers do over many questions in a
/// pseudo-random order, the same each run, unsigned and signed with NSEC
/// and NSEC3.
#[test]
fn copies_answer_as_their_servers_in_any_order() {
    for signing in 0..3 {
        let servers = mixed_servers(signing);
        // A linear congruential generator (Knuth's MMIX constants).
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15 ^ signing as u64;
        let mut next = |n: usize| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as usize % n
        };
        for trial in 0..300 {
            let asked: Vec<Asked> = (0..100)
                .map(|_| {
                    let (local, _) = &servers[next(servers.len())];
                    let qname = MIXED_NAMES[next(MIXED_NAMES.len())];
                    let qtype = MIXED_TYPES[next(MIXED_TYPES.len())];
                    (*local, qname, qtype, next(2) == 0)
                })
                .collect();
            if let Some(difference) = first_difference(&servers, &asked) {
                panic!("signing {signing}, trial {trial}, after {asked:?}: {difference}");
            }
        }
    }
}

/// The root zone, with cuts at `net` and `com`.
const ROOT_WITH_CUTS: &str = "\
. 86400 IN SOA a.root-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 86400
. 518400 IN NS a.root-servers.net.
net. 172800 IN NS a.gtld-servers.net.
com. 172800 IN NS a.gtld-servers.net.
a.gtld-servers.net. 172800 IN A 192.5.6.30
";

/// `root-servers.net`, below the cut at `net`, which the root servers
/// also serve.
const ROOT_SERVERS_NET: &str = "\
root-servers.net. 3600000 IN SOA a.root-servers.net. nstld.verisign-grs.com. 1 14400 7200 1209600 3600000
root-servers.net. 3600000 IN NS a.root-servers.net.
a.root-servers.net. 3600000 IN A 198.41.0.4
";

/// The root zone with its servers' glue below the cut at `net`, and
/// `arpa` delegated to a root server.
const ROOT_WITH_GLUE: &str = "\
. 86400 IN SOA a.root-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 86400
. 518400 IN NS a.root-servers.net.
a.root-servers.net. 518400 IN A 198.41.0.4
net. 172800 IN NS a.gtld-servers.net.
a.gtld-servers.net. 172800 IN A 192.5.6.30
arpa. 172800 IN NS a.root-servers.net.
";

/// A root letter whose server answers `a.root-servers.net A` minimally,
/// from `root-servers.net`, with nothing that shows that zone, still
/// sends the root zone's glue for that name as additional data, as its
/// server does: with the root's NS RRset and in a referral, whichever
/// question came first.
#[test]
fn a_minimal_answer_from_a_child_keeps_the_parents_additional_data() {
    for signing in 0..3 {
        let real = Zones::new(vec![
            mixed_zone(ROOT_WITH_GLUE, signing),
            mixed_zone(ROOT_SERVERS_NET, 0),
        ]);
        let answer = |lookup: &Lookup| reply_of(&real, lookup);
        let local: SocketAddr = "170.247.170.2:53".parse().unwrap();
        let copies = Copies::new();
        copies.serves(local.ip(), &LowerName::new(&Name::root()));
        for (qname, qtype) in [
            (".", RecordType::NS),
            ("a.root-servers.net.", RecordType::A),
            (".", RecordType::NS),
            ("arpa.", RecordType::NS),
            ("a.root-servers.net.", RecordType::A),
        ] {
            for dnssec_ok in [false, true] {
                let req = request(qname, qtype, dnssec_ok);
                let got = answer_through(&copies, &answer, local, &req).unwrap();
                assert_eq!(
                    shape(&got),
                    shape(&real_at(&real, local, &req)),
                    "signing {signing}: {qname} {qtype} DO {dnssec_ok}"
                );
            }
        }
    }
}

/// A root letter answers DS at `root-servers.net`'s apex from that zone,
/// since the zone that holds the cut there is `net`'s, which it does not
/// serve (RFC 4035 §3.1.4.1). It still serves the root.
#[test]
fn a_root_letter_answers_ds_below_another_cut_and_still_serves_the_root() {
    let zone = |text: &str| Arc::new(Zone::from_master(text, None).unwrap()) as Arc<dyn ZoneData>;
    let real = Zones::new(vec![zone(ROOT_WITH_CUTS), zone(ROOT_SERVERS_NET)]);
    let answer = |lookup: &Lookup| reply_of(&real, lookup);
    let local: SocketAddr = "198.41.0.4:53".parse().unwrap();
    let copies = Copies::new();
    copies.serves(local.ip(), &LowerName::new(&Name::root()));
    for (qname, qtype) in [
        ("root-servers.net.", RecordType::DS),
        ("com.", RecordType::NS),
        ("root-servers.net.", RecordType::DS),
        (".", RecordType::SOA),
    ] {
        let req = request(qname, qtype, false);
        let got = answer_through(&copies, &answer, local, &req).unwrap();
        assert_eq!(
            shape(&got),
            shape(&real_at(&real, local, &req)),
            "{qname} {qtype}"
        );
    }
}

/// An alias into a child the address also serves, below a cut another
/// address learned, is followed into the child, as the real
/// server does (RFC 1034 §4.3.2 step 3a).
#[test]
fn a_chain_into_a_hosted_child_below_a_learned_cut_is_followed() {
    let zone = |text: &str| Arc::new(Zone::from_master(text, None).unwrap()) as Arc<dyn ZoneData>;
    let alone: SocketAddr = "192.0.2.253:53".parse().unwrap();
    let both: SocketAddr = "192.0.2.153:53".parse().unwrap();
    let servers = [
        (alone, Zones::new(vec![zone(MIXED_PARENT)])),
        (
            both,
            Zones::new(vec![zone(MIXED_PARENT), zone(MIXED_CHILD)]),
        ),
    ];
    let asked = [
        (alone, "www.child.example.", RecordType::A, false),
        (both, "intochild.example.", RecordType::A, false),
    ];
    assert_eq!(first_difference(&servers, &asked), None);
}

/// A copy of a signed zone holds the one RRset its server sends for ANY
/// with DO, and answers ANY without DO with the HINFO its server sends,
/// whose TTL is the operator's (RFC 8482 §4.2).
#[test]
fn any_without_do_at_a_signed_copy_gets_its_servers_hinfo() {
    for signing in [1, 2] {
        let servers = [(
            "192.0.2.53:53".parse().unwrap(),
            Zones::new(vec![mixed_zone(MIXED_PARENT, signing)]),
        )];
        let local = servers[0].0;
        let asked = [
            (local, "example.", RecordType::ANY, false),
            (local, "www.example.", RecordType::ANY, true),
            (local, "www.example.", RecordType::ANY, false),
        ];
        assert_eq!(
            first_difference(&servers, &asked),
            None,
            "signing {signing}"
        );
    }
}

/// What `zones`, a real server with `server` as its front, reply to
/// `lookup`'s question, asked with DO.
fn real_lookup(zones: &Zones, server: &ServerConfig, lookup: &Lookup) -> Message {
    let asked = request(
        &lookup.question.name().to_ascii(),
        lookup.question.query_type(),
        true,
    );
    real_as(
        zones,
        server,
        SocketAddr::new(lookup.server.ip(), 53),
        &asked,
    )
}

/// A placed server sends every RRset its copies hold for ANY, with the
/// DNSSEC records only as DO asks ([`AnyResponse::AllFollowingDo`]), and
/// the copies hold the real server's answer to ANY with DO. A client
/// without DO gets that answer without its RRSIGs, as from a real server
/// that answers ANY with one RRset and sends no DNSSEC records without DO
/// (RFC 3225 §3, RFC 8482 §4.1).
#[test]
fn any_without_do_at_a_placed_copy_gets_no_rrsigs() {
    let one = ServerConfig {
        any: AnyResponse::OneRrset(RecordType::SOA),
        ..ServerConfig::generic()
    };
    let placed = ServerConfig {
        any: AnyResponse::AllFollowingDo,
        ede: false,
        ..ServerConfig::generic()
    };
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    for signing in [1, 2] {
        let real = Zones::new(vec![mixed_zone(EXAMPLE, signing)]);
        let answer = |lookup: &Lookup| real_lookup(&real, &one, lookup);
        let copies = Copies::new();
        copies.serves(local.ip(), &lower("example."));
        for dnssec_ok in [true, false, true] {
            let asked = request("example.", RecordType::ANY, dnssec_ok);
            let (got, _) = through_as(&copies, &placed, &answer, local, &asked);
            let want = real_as(&real, &one, local, &asked);
            assert_eq!(
                shape(&got),
                shape(&want),
                "signing {signing}, DO {dnssec_ok}"
            );
            let signed = got
                .answers
                .iter()
                .any(|record| record.record_type() == RecordType::RRSIG);
            assert_eq!(signed, dnssec_ok, "signing {signing}");
        }
    }
}

/// A front's answer to ANY means the same over copies as over the real
/// zones: a copy whose front is [`AnyResponse::All`], as at most root
/// letters, sends the NSEC RRset and the RRSIGs without DO too, as its
/// real server does.
#[test]
fn any_at_a_copy_follows_its_front_as_the_real_server_does() {
    let all = ServerConfig {
        any: AnyResponse::All,
        ..ServerConfig::generic()
    };
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    for signing in [1, 2] {
        let real = Zones::new(vec![mixed_zone(EXAMPLE, signing)]);
        let answer = |lookup: &Lookup| real_lookup(&real, &all, lookup);
        let copies = Copies::new();
        copies.serves(local.ip(), &lower("example."));
        for dnssec_ok in [true, false, true] {
            let asked = request("example.", RecordType::ANY, dnssec_ok);
            let (got, _) = through_as(&copies, &all, &answer, local, &asked);
            let want = real_as(&real, &all, local, &asked);
            assert_eq!(
                shape(&got),
                shape(&want),
                "signing {signing}, DO {dnssec_ok}"
            );
            let signed = got
                .answers
                .iter()
                .any(|record| record.record_type() == RecordType::RRSIG);
            assert!(signed, "signing {signing}, DO {dnssec_ok}");
        }
    }
}

/// A zone the real server at `example`'s address also serves, which no
/// referral names for that address.
const OTHER: &str = "\
other. 3600 IN SOA ns.example. hostmaster.example. 1 7200 3600 1209600 300
other. 3600 IN NS ns.example.
www.other. 300 IN A 192.0.2.81
";

/// A real server serves zones that no referral named it for, such as
/// a sibling of the zone a world noted it serves. Its copy answers for
/// them as it does, from the lookups it makes there: a name in none of
/// the zones the address knows is looked up, and a CNAME into such a
/// zone goes on there, as its real server's answer does (RFC 1034
/// §4.3.2 step 3a). A name its real server does not serve is refused,
/// as the real server refuses it.
#[test]
fn an_address_answers_for_a_zone_no_referral_named() {
    let example = format!("{EXAMPLE}cross.example. 300 IN CNAME www.other.\n");
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    for signing in 0..3 {
        let servers = [(
            local,
            Zones::new(vec![
                mixed_zone(&example, signing),
                mixed_zone(OTHER, signing),
            ]),
        )];
        let asked = [
            (local, "www.other.", RecordType::A, true),
            (local, "www.other.", RecordType::A, false),
            (local, "nx.other.", RecordType::A, true),
            (local, "www.elsewhere.test.", RecordType::A, false),
        ];
        assert_eq!(
            first_difference(&servers, &asked),
            None,
            "signing {signing}"
        );
        for dnssec_ok in [true, false] {
            let asked = [(local, "cross.example.", RecordType::A, dnssec_ok)];
            assert_eq!(
                first_difference(&servers, &asked),
                None,
                "signing {signing}, DO {dnssec_ok}"
            );
        }
        let copies = Copies::new();
        copies.serves(local.ip(), &lower("example."));
        let answer = |lookup: &Lookup| reply_of(&servers[0].1, lookup);
        let (got, _) = through(
            &copies,
            &answer,
            local,
            &request("cross.example.", RecordType::A, false),
        );
        let answers: Vec<(String, RecordType)> = got
            .answers
            .iter()
            .map(|record| (record.name.to_string(), record.record_type()))
            .collect();
        assert_eq!(
            answers,
            [
                ("cross.example.".to_string(), RecordType::CNAME),
                ("www.other.".to_string(), RecordType::A),
            ],
            "signing {signing}"
        );
        let (got, _) = through(
            &copies,
            &answer,
            local,
            &request("www.elsewhere.test.", RecordType::A, false),
        );
        assert_eq!(got.metadata.response_code, ResponseCode::Refused);
    }
}

/// A CNAME chain into a zone no referral named that ends in NXDOMAIN or
/// NODATA there shows that zone only by the SOA and denial records of its
/// authority section. The copy goes on in that zone as the real server
/// does, with its RCODE, its SOA, and its proofs (RFC 1034 §4.3.2 step
/// 3a, RFC 2308 §2.1 and §2.2), asked first or again.
#[test]
fn a_chain_into_another_zone_ends_in_that_zones_negative() {
    let example = format!(
        "{EXAMPLE}crossnx.example. 300 IN CNAME nx.other.\ncross.example. 300 IN CNAME www.other.\n"
    );
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    for signing in 0..3 {
        let servers = [(
            local,
            Zones::new(vec![
                mixed_zone(&example, signing),
                mixed_zone(OTHER, signing),
            ]),
        )];
        for dnssec_ok in [true, false] {
            for (qname, qtype) in [
                ("crossnx.example.", RecordType::A),
                ("cross.example.", RecordType::TXT),
            ] {
                let asked = [
                    (local, qname, qtype, dnssec_ok),
                    (local, qname, qtype, dnssec_ok),
                ];
                assert_eq!(
                    first_difference(&servers, &asked),
                    None,
                    "signing {signing}, DO {dnssec_ok}"
                );
            }
        }
    }
}

/// BIND sends the SOA of a negative to QTYPE SOA with TTL 0, and with
/// min(SOA TTL, MINIMUM) for every other type (RFC 2308 §3). The copy
/// answers each negative it holds with the SOA its server sent for that
/// type, so one SOA question leaves the negative TTL of the others as
/// they were.
#[test]
fn each_question_type_keeps_the_negative_soa_its_server_sent() {
    let zones = Zones::new(vec![
        Arc::new(Zone::from_master(EXAMPLE, None).unwrap()) as Arc<dyn ZoneData>
    ]);
    let answer = |lookup: &Lookup| {
        let mut reply = reply_of(&zones, lookup);
        if lookup.question.query_type() == RecordType::SOA {
            for record in &mut reply.authorities {
                record.ttl = 0;
            }
        }
        reply
    };
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let copies = Copies::new();
    copies.serves(local.ip(), &lower("example."));
    for (qname, qtype, ttl, filed) in [
        ("nothere.example.", RecordType::A, 300, false),
        ("zzz.example.", RecordType::SOA, 0, false),
        ("nothere.example.", RecordType::A, 300, true),
        ("x.nothere.example.", RecordType::MX, 300, true),
        ("zzz.example.", RecordType::SOA, 0, true),
    ] {
        let (got, looked) = through(&copies, &answer, local, &request(qname, qtype, false));
        assert_eq!(
            got.metadata.response_code,
            ResponseCode::NXDomain,
            "{qname} {qtype}"
        );
        let soa: Vec<u32> = got
            .authorities
            .iter()
            .filter(|record| record.record_type() == RecordType::SOA)
            .map(|record| record.ttl)
            .collect();
        assert_eq!(soa, [ttl], "{qname} {qtype}");
        if filed {
            assert!(looked.is_empty(), "{qname} {qtype}: {looked:?}");
        }
    }
}

/// Some servers set AA on a referral. The copy files it as the referral
/// it is, and refers the question as the real server did, never silent.
#[test]
fn a_referral_with_aa_set_is_answered_as_a_referral() {
    let real = Zones::new(vec![
        Arc::new(Zone::from_master(EXAMPLE, None).unwrap()) as Arc<dyn ZoneData>
    ]);
    let answer = |lookup: &Lookup| {
        let mut message = reply_of(&real, lookup);
        let referral = message.metadata.response_code == ResponseCode::NoError
            && message.answers.is_empty()
            && message
                .authorities
                .iter()
                .all(|record| record.record_type() == RecordType::NS);
        if referral {
            message.metadata.authoritative = true;
        }
        message
    };
    let local: SocketAddr = "192.0.2.53:53".parse().unwrap();
    let copies = Copies::new();
    copies.serves(local.ip(), &lower("example."));
    for round in 0..2 {
        let asked = request("www.child.example.", RecordType::A, false);
        let got = answer_through(&copies, &answer, local, &asked).unwrap();
        let want = reply_of(&real, &own(local, &asked));
        assert_eq!(shape(&got), shape(&want), "round {round}");
        assert!(!got.metadata.authoritative);
        assert_eq!(
            shape(&got).2[1],
            ["child.example. 3600 NS ns.child.example."],
            "round {round}"
        );
        assert_eq!(
            shape(&got).2[2],
            ["ns.child.example. 3600 A 192.0.2.54"],
            "round {round}"
        );
    }
}

#[test]
fn an_apex_alias_does_not_replace_the_servers_other_answers() {
    use fictionet::stdlib::protocols::dns::rr::rdata::CNAME;

    let zone = signed(Denial::Nsec);
    for alias_first in [true, false] {
        let learned = Learned::new(&name("example."));
        let alias_question = request("example.", RecordType::A, true);
        let mut alias = real(&zone, &alias_question);
        alias.answers = vec![Record::from_rdata(
            name("example."),
            300,
            RData::CNAME(CNAME(name("outside.test."))),
        )];
        alias.authorities.clear();
        if alias_first {
            learned.file(Generation(0), &alias_question.question, &alias);
            for rtype in [
                RecordType::DNSKEY,
                RecordType::SOA,
                RecordType::NS,
                RecordType::DS,
            ] {
                assert!(copied(&learned, &request("example.", rtype, true)).is_none());
            }
        }
        for rtype in [
            RecordType::DNSKEY,
            RecordType::SOA,
            RecordType::NS,
            RecordType::DS,
        ] {
            let asked = request("example.", rtype, true);
            let response = real(&zone, &asked);
            learned.file(Generation(0), &asked.question, &response);
        }
        if !alias_first {
            learned.file(Generation(0), &alias_question.question, &alias);
        }
        for rtype in [
            RecordType::DNSKEY,
            RecordType::SOA,
            RecordType::NS,
            RecordType::DS,
        ] {
            let asked = request("example.", rtype, true);
            let got = copied(&learned, &asked).expect("the type was copied");
            assert_eq!(shape(&got), shape(&real(&zone, &asked)), "{rtype}");
        }
        assert_eq!(
            shape(&copied(&learned, &alias_question).unwrap()),
            shape(&alias)
        );
    }
}
