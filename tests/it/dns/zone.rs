//! Zones, views, and the authoritative answer: the rules a zone is built
//! under, every branch of `answer`, unknown facts never becoming
//! negatives, zones that grow, the locally served zones, and the real
//! root zone's master file format.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fictionet::stdlib::network::Transport;
use fictionet::stdlib::protocols::dns::dnssec::Nsec3HashAlgorithm;
use fictionet::stdlib::protocols::dns::dnssec::rdata::{DNSSECRData, NSEC, NSEC3};
use fictionet::stdlib::protocols::dns::op::{
    Edns, Message, MessageType, OpCode, Query, ResponseCode,
};
use fictionet::stdlib::protocols::dns::rr::rdata::svcb::{Alpn, SvcParamKey, SvcParamValue};
use fictionet::stdlib::protocols::dns::rr::rdata::{A, CNAME, HTTPS, MX, NS, PTR, SOA, SVCB, TXT};
use fictionet::stdlib::protocols::dns::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::protocols::dns::serialize::binary::BinEncodable;
use fictionet::stdlib::protocols::dns::{Parsed, Request, Response};
use fictionet::stdlib::services::dns::WallClock;
use fictionet::stdlib::services::dns::zone::{
    Answered, AnyResponse, Denied, EmptyApex, Fact, Lazy, MasterError, Node, Revision, Shown,
    Transparent, View, Zone, ZoneBuilder, ZoneData, ZoneError, answer, dname, dname_target,
    special,
};
use fictionet::time::Instant;

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

fn lower(text: &str) -> LowerName {
    LowerName::new(&name(text))
}

fn rrset(owner: &str, ttl: u32, data: Vec<RData>) -> RecordSet {
    let owner = name(owner);
    let mut set = RecordSet::with_ttl(owner.clone(), data[0].record_type(), ttl);
    set.set_records(
        data.into_iter()
            .map(|data| Record::from_rdata(owner.clone(), ttl, data))
            .collect(),
    );
    set
}

fn a(text: &str) -> RData {
    RData::A(A(text.parse().unwrap()))
}

fn ns(text: &str) -> RData {
    RData::NS(NS(name(text)))
}

fn cname(text: &str) -> RData {
    RData::CNAME(CNAME(name(text)))
}

fn txt(text: &str) -> RData {
    RData::TXT(TXT::new(vec![text.to_string()]))
}

fn soa(apex: &str, minimum: u32) -> SOA {
    SOA::new(
        name(&format!("ns1.{apex}")),
        name(&format!("hostmaster.{apex}")),
        1,
        7200,
        3600,
        1209600,
        minimum,
    )
}

/// A builder for `apex` with its NS RRset and the glue-free address of
/// its name server.
fn builder(apex: &str) -> ZoneBuilder {
    let server = format!("ns1.{apex}");
    Zone::builder(name(apex), soa(apex, 300), 3600)
        .rrset(rrset(apex, 3600, vec![ns(&server)]))
        .rrset(rrset(&server, 3600, vec![a("192.0.2.1")]))
}

fn request(qname: &str, qtype: RecordType, dnssec_ok: bool) -> Request {
    let mut message = Message::new(7, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(name(qname), qtype));
    if dnssec_ok {
        let mut edns = Edns::new();
        edns.set_max_payload(1232).set_dnssec_ok(true);
        message.set_edns(edns);
    }
    match Request::parse(&message.to_vec().unwrap(), Transport::Udp) {
        Parsed::Request(request) => request,
        other => panic!("not a request: {other:?}"),
    }
}

fn response(view: &dyn View, qname: &str, qtype: RecordType, dnssec_ok: bool) -> Response {
    match answer(view, &request(qname, qtype, dnssec_ok), AnyResponse::All) {
        Answered::Response(response) => response,
        Answered::Unknown { name, .. } => panic!("{qname} {qtype}: unknown at {name}"),
    }
}

fn ask(view: &dyn View, qname: &str, qtype: RecordType) -> Message {
    response(view, qname, qtype, false).message
}

fn ask_do(view: &dyn View, qname: &str, qtype: RecordType) -> Message {
    response(view, qname, qtype, true).message
}

/// Each record's owner and type, in order.
fn rows(records: &[Record]) -> Vec<(String, RecordType)> {
    records
        .iter()
        .map(|record| (record.name.to_string(), record.record_type()))
        .collect()
}

fn row(owner: &str, rtype: RecordType) -> (String, RecordType) {
    (owner.to_string(), rtype)
}

fn addresses(records: &[Record]) -> Vec<String> {
    records
        .iter()
        .filter_map(|record| record.data.ip_addr().map(|ip| ip.to_string()))
        .collect()
}

fn view_of(data: &dyn ZoneData, qname: &str, qtype: RecordType) -> Arc<dyn View + Send + Sync> {
    data.view(&Query::query(name(qname), qtype))
}

/// A label of 63 octets.
fn long_label(c: char) -> String {
    std::iter::repeat_n(c, 63).collect()
}

/// A zone with something at every branch of the answer.
fn example_text() -> String {
    let long_target = format!("{0}.{0}.{0}.test.", long_label('x'));
    format!(
        "$ORIGIN example.
$TTL 3600
@        IN SOA ns1 hostmaster (
                2026110101 ; serial
                7200 3600 1209600
                300 )      ; minimum
@        NS    ns1
ns1      A     192.0.2.1
ns1      AAAA  2001:db8::1
www      A     192.0.2.10
         A     192.0.2.10 ; the same record again, kept once
         TXT   \"hello world\"
mail     MX    10 www
alias    CNAME www
chain    CNAME alias
loop1    CNAME loop2
loop2    CNAME loop1
dangling CNAME gone
away     CNAME www.elsewhere.test.
a.b.c    A     192.0.2.20
*.w      300 TXT \"wild\"
*.w      300 A 192.0.2.30
deep.e.w A     192.0.2.31
*.cw     CNAME www
x.*.m    A     192.0.2.40
d        DNAME target
x.target A     192.0.2.50
long     DNAME {long_target}
sub      NS    ns.sub
sub      NS    ns.zone
sub      NS    ns.elsewhere.test.
sub      DS    12345 13 2 8ACBB0CD28F41250A80A491389424D341522D946B0DA0C0291F2D3D771D7805A
ns.sub   A     192.0.2.53
zone     NS    ns.zone
ns.zone  A     192.0.2.54
"
    )
}

fn example() -> Zone {
    Zone::from_master(&example_text(), None).unwrap()
}

// The zone and its builder.

#[test]
fn a_master_file_reads_into_nodes() {
    let zone = example();
    assert_eq!(*zone.apex(), lower("example."));
    assert_eq!(zone.revision(), Revision(0));
    assert_eq!(View::revision(&zone), Revision(0));

    let Some(Node::Data(www)) = zone.node(&lower("www.example.")) else {
        panic!("www is data");
    };
    // The duplicate A record collapsed (RFC 2181 §5).
    assert_eq!(www[&RecordType::A].records_count(), 1);
    assert!(www.contains_key(&RecordType::TXT));

    // Names between the apex and a node are empty non-terminals.
    assert_eq!(zone.node(&lower("b.c.example.")), Some(&Node::Empty));
    assert_eq!(zone.node(&lower("c.example.")), Some(&Node::Empty));
    assert_eq!(zone.node(&lower("*.m.example.")), Some(&Node::Empty));
    assert_eq!(zone.node(&lower("nope.example.")), None);

    let Some(Node::Cut { ns, ds, glue }) = zone.node(&lower("sub.example.")) else {
        panic!("sub is a cut");
    };
    assert_eq!(ns.records_count(), 3);
    assert!(ds.is_some());
    assert_eq!(
        rows(
            &glue[0]
                .records_without_rrsigs()
                .cloned()
                .collect::<Vec<_>>()
        ),
        vec![row("ns.sub.example.", RecordType::A)]
    );
    // Glue is held in the cut, not as nodes below it.
    assert_eq!(zone.node(&lower("ns.sub.example.")), None);

    let Some(Node::Dname(dname_set, _)) = zone.node(&lower("d.example.")) else {
        panic!("d is a DNAME");
    };
    let target = dname_target(&dname_set.records_without_rrsigs().next().unwrap().data);
    assert_eq!(target, Some(name("target.example.")));

    // Nodes come in canonical order (RFC 4034 §6.1).
    let names: Vec<&LowerName> = zone.nodes().map(|(name, _)| name).collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
    assert_eq!(names[0], &lower("example."));
}

#[test]
fn dname_rdata_round_trips() {
    let rdata = dname(&name("Target.Example."));
    assert_eq!(rdata.record_type(), RecordType::DNAME);
    assert_eq!(dname_target(&rdata), Some(name("Target.Example.")));
    assert_eq!(dname_target(&a("192.0.2.1")), None);
}

#[test]
fn every_zone_rule_is_checked() {
    let fail = |builder: ZoneBuilder| builder.build().unwrap_err();

    assert_eq!(
        fail(builder("example.").rrset(rrset("www.other.", 60, vec![a("192.0.2.1")]))),
        ZoneError::OutOfZone {
            owner: lower("www.other.")
        }
    );
    let apex_ns = rrset("example.", 60, vec![ns("ns1.example.")]);
    assert_eq!(
        fail(builder("example.").delegate(name("example."), apex_ns, vec![], None)),
        ZoneError::OutOfZone {
            owner: lower("example.")
        }
    );
    assert_eq!(
        fail(builder("example.").rrset(rrset("example.", 60, vec![cname("www.example.")]))),
        ZoneError::CnameAtApex
    );
    assert_eq!(
        fail(
            builder("example.")
                .rrset(rrset("alias.example.", 60, vec![cname("www.example.")]))
                .rrset(rrset("alias.example.", 60, vec![a("192.0.2.1")]))
        ),
        ZoneError::CnameWithOtherData {
            owner: lower("alias.example.")
        }
    );
    assert_eq!(
        fail(builder("example.").rrset(rrset(
            "alias.example.",
            60,
            vec![cname("www.example."), cname("mail.example.")]
        ))),
        ZoneError::CnameWithOtherData {
            owner: lower("alias.example.")
        }
    );
    assert_eq!(
        fail(
            builder("example.")
                .rrset(rrset(
                    "d.example.",
                    60,
                    vec![dname(&name("target.example."))]
                ))
                .rrset(rrset("x.d.example.", 60, vec![a("192.0.2.1")]))
        ),
        ZoneError::DataBelowDname {
            owner: lower("x.d.example.")
        }
    );
    assert_eq!(
        fail(builder("example.").rrset(rrset(
            "d.example.",
            60,
            vec![dname(&name("one.test.")), dname(&name("two.test."))]
        ))),
        ZoneError::TwoDnames {
            owner: lower("d.example.")
        }
    );
    assert_eq!(
        fail(
            builder("example.")
                .rrset(rrset("sub.example.", 60, vec![ns("ns.elsewhere.test.")]))
                .rrset(rrset("x.sub.example.", 60, vec![txt("hidden")]))
        ),
        ZoneError::DataBelowCut {
            owner: lower("x.sub.example."),
            cut: lower("sub.example.")
        }
    );
    assert_eq!(
        fail(
            builder("example.")
                .rrset(rrset("sub.example.", 60, vec![ns("ns.elsewhere.test.")]))
                .rrset(rrset(
                    "deeper.sub.example.",
                    60,
                    vec![ns("ns.elsewhere.test.")]
                ))
        ),
        ZoneError::DataBelowCut {
            owner: lower("deeper.sub.example."),
            cut: lower("sub.example.")
        }
    );
    assert_eq!(
        fail(builder("example.").rrset(rrset("sub.example.", 60, vec![ns("ns.sub.example.")]))),
        ZoneError::MissingInDomainGlue {
            child: lower("sub.example."),
            ns: lower("ns.sub.example.")
        }
    );
    let mx = RData::MX(MX::new(10, name("alias.example.")));
    assert_eq!(
        fail(
            builder("example.")
                .rrset(rrset("mail.example.", 60, vec![mx]))
                .rrset(rrset("alias.example.", 60, vec![cname("ns1.example.")]))
        ),
        ZoneError::TargetIsAlias {
            owner: lower("mail.example."),
            target: lower("alias.example.")
        }
    );
    assert_eq!(
        fail(
            builder("example.")
                .delegate(
                    name("sub.example."),
                    rrset("sub.example.", 60, vec![ns("alias.example.")]),
                    vec![],
                    None
                )
                .rrset(rrset("alias.example.", 60, vec![cname("ns1.example.")]))
        ),
        ZoneError::TargetIsAlias {
            owner: lower("sub.example."),
            target: lower("alias.example.")
        }
    );

    let mut mixed = rrset("www.example.", 60, vec![a("192.0.2.1"), a("192.0.2.2")]);
    let mut records: Vec<Record> = mixed.records_without_rrsigs().cloned().collect();
    records[1].ttl = 120;
    mixed.set_records(records);
    assert_eq!(
        fail(builder("example.").rrset(mixed)),
        ZoneError::RrsetTtlsDiffer {
            owner: lower("www.example."),
            rtype: RecordType::A
        }
    );
    assert_eq!(
        fail(builder("example.").rrset(rrset("www.example.", 1 << 31, vec![a("192.0.2.1")]))),
        ZoneError::TtlTooLarge {
            owner: lower("www.example."),
            ttl: 1 << 31
        }
    );
    assert_eq!(
        fail(Zone::builder(name("example."), soa("example.", 300), 3600)),
        ZoneError::MissingApexNs
    );
}

#[test]
fn rules_are_checked_in_order() {
    // A zone that breaks the TTL rule and the apex NS rule reports the TTL
    // first, since the rules are checked in the order ZoneError lists
    // them.
    let error = Zone::builder(name("example."), soa("example.", 300), 3600)
        .rrset(rrset("www.example.", 1 << 31, vec![a("192.0.2.1")]))
        .build()
        .unwrap_err();
    assert_eq!(
        error,
        ZoneError::TtlTooLarge {
            owner: lower("www.example."),
            ttl: 1 << 31
        }
    );
    // A CNAME at the apex beside the NS RRset is a CNAME at the apex.
    let error = builder("example.")
        .rrset(rrset("example.", 60, vec![cname("www.example.")]))
        .build()
        .unwrap_err();
    assert_eq!(error, ZoneError::CnameAtApex);
}

#[test]
fn master_file_faults_name_their_line() {
    let fault = |text: &str| match Zone::from_master(text, None) {
        Err(ZoneError::Master { line, error }) => (line, error),
        other => panic!("expected a master file fault, got {other:?}"),
    };
    let head =
        "$ORIGIN example.\n$TTL 60\n@ SOA ns1 hostmaster 1 2 3 4 5\n@ NS ns1\nns1 A 192.0.2.1\n";
    let with = |line: &str| format!("{head}{line}\n");

    assert_eq!(
        fault(&with("www TXT \"open")),
        (6, MasterError::UnclosedQuote)
    );
    // A line break inside a quoted string must be escaped, as BIND reads
    // it, and never reaches hickory's parser, where a `$INCLUDE` after it
    // would read a file.
    assert_eq!(
        fault(&with("www TXT \"a\n$INCLUDE /etc/hostname\"")),
        (
            6,
            MasterError::Rdata {
                rtype: RecordType::TXT
            }
        )
    );
    assert_eq!(
        fault(&with("www A ( 192.0.2.1")),
        (7, MasterError::UnbalancedParentheses)
    );
    assert_eq!(
        fault(&with("www A 192.0.2.1 )")),
        (6, MasterError::UnbalancedParentheses)
    );
    assert_eq!(
        fault(&with("$INCLUDE other.zone")),
        (6, MasterError::Include)
    );
    assert_eq!(
        fault(&with("$GENERATE 1-2 x A 192.0.2.1")),
        (6, MasterError::UnknownDirective)
    );
    assert_eq!(
        fault(&with("bad..name A 192.0.2.1")),
        (6, MasterError::BadName)
    );
    assert_eq!(fault(&with("www 1x A 192.0.2.1")), (6, MasterError::BadTtl));
    assert_eq!(fault(&with("www 60 IN")), (6, MasterError::NoType));
    assert_eq!(fault(&with("www BOGUS 1")), (6, MasterError::UnknownType));
    assert_eq!(fault(&with("www CH TXT \"x\"")), (6, MasterError::Class));
    assert_eq!(
        fault(&with("www A 192.0.2")),
        (
            6,
            MasterError::Rdata {
                rtype: RecordType::A
            }
        )
    );
    assert_eq!(
        fault(&with("www TYPE65400 abc")),
        (
            6,
            MasterError::Rdata {
                rtype: RecordType::from(65400)
            }
        )
    );
    assert_eq!(
        fault(&with("www TYPE65400 \\# 3 abcd")),
        (
            6,
            MasterError::Rdata {
                rtype: RecordType::from(65400)
            }
        )
    );
    assert_eq!(
        fault(&with("@ SOA ns1 hostmaster 2 2 3 4 5")),
        (6, MasterError::SecondSoa)
    );
    assert_eq!(
        fault(&with(
            "www RRSIG A 8 2 60 20261114230000 20261101220000 1 example. AAAA"
        )),
        (
            6,
            MasterError::SignatureWithoutRrset {
                covered: RecordType::A
            }
        )
    );
    assert_eq!(fault(" A 192.0.2.1\n"), (1, MasterError::NoOwner));
    assert_eq!(fault("www.example. A 192.0.2.1\n"), (1, MasterError::NoTtl));
    assert_eq!(fault("www A 192.0.2.1\n"), (1, MasterError::BadName));
    // A relative name in the RDATA needs an origin as much as an owner does.
    let soa = "example. 60 SOA ns1.example. hostmaster.example. 1 2 3 4 5\n\
               example. 60 NS ns1.example.\n";
    for line in [
        "example. 60 SOA ns h 1 2 3 4 5",
        "example. 60 NS ns1",
        "www.example. 60 CNAME target",
        "www.example. 60 MX 10 mail",
    ] {
        let text = if line.contains("SOA") {
            format!("{line}\n")
        } else {
            format!("{soa}{line}\n")
        };
        let at = text.lines().count();
        assert_eq!(fault(&text), (at, MasterError::BadName), "{line}");
    }
    let absolute = format!("{soa}www.example. 60 CNAME target.example.\n");
    assert_eq!(Zone::from_master(&absolute, None).map(|_| ()), Ok(()));
    assert_eq!(
        fault("www.example. 60 A 192.0.2.1\n\n"),
        (2, MasterError::NoSoa)
    );
}

#[test]
fn master_files_take_origins_ttls_and_generic_rdata() {
    let text = "; a comment on its own line
$TTL 1h
example. SOA ns1.example. hostmaster.example. 1 2 3 4 5
example. NS ns1.example.
$ORIGIN example.
ns1 A 192.0.2.1
odd 120 IN TYPE65400 \\# 3 abcdef
    TXT \"two words\" \"and \\\"quoted\\\"\" ; the owner carries over
$ORIGIN sub.example.
deep A 192.0.2.2
";
    let zone = Zone::from_master(text, None).unwrap();
    let Some(Node::Data(odd)) = zone.node(&lower("odd.example.")) else {
        panic!("odd is data");
    };
    let unknown = &odd[&RecordType::from(65400)];
    assert_eq!(unknown.ttl(), 120);
    let record = unknown.records_without_rrsigs().next().unwrap();
    let RData::Unknown { rdata, .. } = &record.data else {
        panic!("generic RDATA stays unknown");
    };
    assert_eq!(rdata.anything, vec![0xab, 0xcd, 0xef]);
    // The TXT record has no TTL of its own, so it takes $TTL, not the 120
    // written before it (RFC 2308 §4).
    let txt = &odd[&RecordType::TXT];
    assert_eq!(txt.ttl(), 3600);
    let RData::TXT(strings) = &txt.records_without_rrsigs().next().unwrap().data else {
        panic!("TXT");
    };
    assert_eq!(strings.txt_data.len(), 2);
    assert_eq!(&*strings.txt_data[1], b"and \"quoted\"");
    // A relative name after a second $ORIGIN.
    assert!(zone.node(&lower("deep.sub.example.")).is_some());
    // $TTL 1h is 3600 seconds.
    let Some(Node::Data(ns1)) = zone.node(&lower("ns1.example.")) else {
        panic!("ns1 is data");
    };
    assert_eq!(ns1[&RecordType::A].ttl(), 3600);

    // An origin given to the reader works like $ORIGIN.
    let text = "@ 60 SOA ns1 hostmaster 1 2 3 4 5\n@ 60 NS ns1\nns1 60 A 192.0.2.1\n";
    let zone = Zone::from_master(text, Some(name("given."))).unwrap();
    assert_eq!(*zone.apex(), lower("given."));
}

/// Names are read as BIND reads them: `@` anywhere a name goes, any
/// octets in a label, and `\DDD` and `\X` escapes (RFC 1035 §5.1,
/// RFC 2181 §11). A UTF-8 label keeps its octets.
#[test]
fn master_file_names_take_at_signs_escapes_and_any_octets() {
    let head = "$TTL 300\n@ IN SOA @ h 1 2 3 4 5\n@ IN NS ns\nns IN A 192.0.2.1\n";
    let read = |line: &str| {
        Zone::from_master(&format!("{head}{line}\n"), Some(name("t.")))
            .unwrap_or_else(|e| panic!("{line}: {e}"))
    };
    let data = |zone: &Zone, owner: &[u8], rtype: RecordType| -> RData {
        let owner = LowerName::new(&Name::from_labels(owner.split(|b| *b == b'.')).unwrap());
        let Some(Node::Data(sets)) = zone.node(&owner) else {
            panic!("no data at {owner}");
        };
        sets[&rtype]
            .records_without_rrsigs()
            .next()
            .unwrap()
            .data
            .clone()
    };
    let t = name("t.");
    let www = read("www IN CNAME @");
    assert_eq!(
        data(&www, b"www.t", RecordType::CNAME),
        RData::CNAME(CNAME(t.clone()))
    );
    let x = read("x IN MX 10 @");
    assert_eq!(
        data(&x, b"x.t", RecordType::MX),
        RData::MX(MX::new(10, t.clone()))
    );
    let x = read("x IN PTR @");
    assert_eq!(
        data(&x, b"x.t", RecordType::PTR),
        RData::PTR(PTR(t.clone()))
    );
    for line in ["x IN NS @", "x IN SRV 0 0 80 @"] {
        read(line);
    }
    // The SOA's own names may be the origin too.
    let Some(Node::Data(apex)) = www.node(&lower("t.")) else {
        panic!("apex");
    };
    let RData::SOA(soa) = &apex[&RecordType::SOA]
        .records_without_rrsigs()
        .next()
        .unwrap()
        .data
    else {
        panic!("SOA");
    };
    assert_eq!(&soa.mname, &t);

    // Labels BIND loads, with check-names warnings at most.
    let underscores = read("xa_b.t. 300 IN A 192.0.2.41");
    assert!(underscores.node(&lower("xa_b.t.")).is_some());
    for (line, owner) in [
        ("a_.t. 300 IN A 192.0.2.1", &b"a_.t"[..]),
        ("\\200.t. 300 IN A 192.0.2.1", b"\xc8.t"),
        ("\\001.t. 300 IN A 192.0.2.1", b"\x01.t"),
        ("a\\032b.t. 300 IN A 192.0.2.1", b"a b.t"),
        ("a\\ b.t. 300 IN A 192.0.2.1", b"a b.t"),
        ("a*b.t. 300 IN A 192.0.2.1", b"a*b.t"),
        ("a@b.t. 300 IN A 192.0.2.1", b"a@b.t"),
        ("a\\.b.t. 300 IN A 192.0.2.1", b"a.b.t"),
    ] {
        let zone = read(line);
        let label = &owner[..owner.len() - 2];
        let wanted = LowerName::new(&Name::from_labels([label, &b"t"[..]]).unwrap());
        assert!(zone.node(&wanted).is_some(), "{line}");
    }
    let x = read("x.t. 300 IN CNAME a_b.t.");
    assert_eq!(
        data(&x, b"x.t", RecordType::CNAME),
        RData::CNAME(CNAME(Name::from_labels([&b"a_b"[..], b"t"]).unwrap()))
    );
    read("n.t. 300 IN NS ns_1.example.");
    let x = read("x.t. 300 IN MX 1 \\200.t.");
    assert_eq!(
        data(&x, b"x.t", RecordType::MX),
        RData::MX(MX::new(1, Name::from_labels([&b"\xc8"[..], b"t"]).unwrap()))
    );
    let svcb = read("_dns.t. 300 IN SVCB 1 dns_1.t. alpn=dot");
    let RData::SVCB(record) = data(&svcb, b"_dns.t", RecordType::SVCB) else {
        panic!("SVCB");
    };
    assert_eq!(
        record.target_name,
        Name::from_labels([&b"dns_1"[..], b"t"]).unwrap()
    );

    // A UTF-8 label is its octets, never punycode.
    let utf8 = read("é.t. 300 IN A 1.2.3.4");
    let octets = Name::from_labels(["é".as_bytes(), b"t"]).unwrap();
    assert!(utf8.node(&LowerName::new(&octets)).is_some());
    assert!(utf8.node(&lower("xn--9ca.t.")).is_none());
}

/// Character-strings, SvcParams, and DNSSEC algorithm fields read as BIND
/// reads them: `\DDD` is one octet of that decimal value (RFC 1035 §5.1),
/// SvcParams in any order go out in increasing order of key and a key
/// written twice is refused (RFC 9460 §2.1, §2.2), and an algorithm may
/// be its mnemonic (RFC 4034 §2.2, §3.2, §5.3).
#[test]
fn master_file_strings_parameters_and_algorithms_read_as_bind_reads_them() {
    let head = "$TTL 300\n@ IN SOA @ h 1 2 3 4 5\n@ IN NS ns\nns IN A 192.0.2.1\n";
    let read = |line: &str| {
        Zone::from_master(&format!("{head}{line}\n"), Some(name("t."))).map_err(Box::new)
    };
    let data = |line: &str, owner: &str, rtype: RecordType| -> RData {
        let zone = read(line).unwrap_or_else(|e| panic!("{line}: {e}"));
        let Some(Node::Data(sets)) = zone.node(&lower(owner)) else {
            panic!("no data at {owner}");
        };
        let data = sets[&rtype]
            .records_without_rrsigs()
            .next()
            .unwrap()
            .data
            .clone();
        assert!(data.to_bytes().is_ok(), "{line} encodes");
        data
    };

    let RData::TXT(txt) = data(
        "x TXT \"\\065\\066C\" \"tab\\009x\" \\200 \"q\\\"\"",
        "x.t.",
        RecordType::TXT,
    ) else {
        panic!("TXT");
    };
    let strings: Vec<&[u8]> = txt.txt_data.iter().map(|s| &s[..]).collect();
    assert_eq!(strings, [&b"ABC"[..], b"tab\tx", b"\xc8", b"q\""]);
    let RData::HINFO(hinfo) = data("x HINFO \"\\065\" os", "x.t.", RecordType::HINFO) else {
        panic!("HINFO");
    };
    assert_eq!((&hinfo.cpu[..], &hinfo.os[..]), (&b"A"[..], &b"os"[..]));
    let RData::CAA(caa) = data("x CAA 0 issue \"ca\\046example\"", "x.t.", RecordType::CAA) else {
        panic!("CAA");
    };
    assert_eq!(caa.value, b"ca.example".to_vec());
    let RData::NAPTR(naptr) = data(
        "x NAPTR 10 20 \"\\083\" \"SIP\\043D2U\" \"\" @",
        "x.t.",
        RecordType::NAPTR,
    ) else {
        panic!("NAPTR");
    };
    assert_eq!(&naptr.flags[..], b"S");
    assert_eq!(&naptr.services[..], b"SIP+D2U");
    assert_eq!(naptr.replacement, name("t."));
    // A string past 255 octets is no character-string.
    let long = format!("x TXT {}", "a".repeat(256));
    assert!(read(&long).is_err());

    let keys = |data: RData| -> Vec<SvcParamKey> {
        let svcb = match data {
            RData::SVCB(svcb) | RData::HTTPS(HTTPS(svcb)) => svcb,
            other => panic!("{other:?}"),
        };
        svcb.svc_params.iter().map(|(key, _)| *key).collect()
    };
    assert_eq!(
        keys(data(
            "svc SVCB 1 . alpn=\"h2,h3\" ipv6hint=2001:db8::1 mandatory=alpn",
            "svc.t.",
            RecordType::SVCB,
        )),
        [
            SvcParamKey::Mandatory,
            SvcParamKey::Alpn,
            SvcParamKey::Ipv6Hint
        ]
    );
    assert_eq!(
        keys(data(
            "h HTTPS 1 . ech=AEX+ alpn=h2",
            "h.t.",
            RecordType::HTTPS
        )),
        [SvcParamKey::Alpn, SvcParamKey::EchConfigList]
    );
    // A comma or a backslash inside one ALPN ID is escaped (RFC 9460
    // Appendix A.1).
    let RData::SVCB(svcb) = data(
        "a SVCB 1 . alpn=\"f\\\\\\\\oo\\\\,bar,h2\"",
        "a.t.",
        RecordType::SVCB,
    ) else {
        panic!("SVCB");
    };
    assert_eq!(
        svcb.svc_params,
        [(
            SvcParamKey::Alpn,
            SvcParamValue::Alpn(Alpn(vec!["f\\oo,bar".to_owned(), "h2".to_owned()]))
        )]
    );
    for line in [
        "d SVCB 1 . alpn=h2 alpn=h3",
        "d SVCB 1 . mandatory=alpn,alpn alpn=h2",
        "d SVCB 1 . key65535=x",
    ] {
        assert_eq!(
            read(line).err(),
            Some(Box::new(ZoneError::Master {
                line: 5,
                error: MasterError::Rdata {
                    rtype: RecordType::SVCB
                }
            })),
            "{line}"
        );
    }

    let key = "7uMa/2wdqJXCNCJt0hp/MA==";
    let digest = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    for (mnemonic, number) in [
        (
            format!("t. DNSKEY 257 3 ECDSAP256SHA256 {key}"),
            format!("t. DNSKEY 257 3 13 {key}"),
        ),
        (
            format!("c.t. DS 12345 ecdsap256sha256 2 {digest}"),
            format!("c.t. DS 12345 13 2 {digest}"),
        ),
    ] {
        let rtype = if mnemonic.contains("DS ") {
            RecordType::DS
        } else {
            RecordType::DNSKEY
        };
        let owner = mnemonic.split(' ').next().unwrap();
        let with = |line: &str| {
            let zone = Zone::from_master(&format!("{head}c.t. NS ns\n{line}\n"), Some(name("t.")))
                .unwrap_or_else(|e| panic!("{line}: {e}"));
            match zone.node(&lower(owner)) {
                Some(Node::Data(sets)) => sets[&rtype].clone(),
                Some(Node::Cut { ds: Some(ds), .. }) => ds.clone(),
                other => panic!("{line}: {other:?}"),
            }
        };
        assert_eq!(with(&mnemonic), with(&number), "{mnemonic}");
    }
    let rrsig = |algorithm: &str| {
        format!("t. RRSIG SOA {algorithm} 1 300 20261121000000 20261031000000 12345 t. AAAA")
    };
    let signatures = |algorithm: &str| {
        let zone = read(&rrsig(algorithm)).unwrap_or_else(|e| panic!("{algorithm}: {e}"));
        let Some(Node::Data(apex)) = zone.node(&lower("t.")) else {
            panic!("apex");
        };
        apex[&RecordType::SOA].rrsigs().to_vec()
    };
    assert_eq!(signatures("ECDSAP256SHA256"), signatures("13"));
    assert!(read(&rrsig("NOSUCHALGORITHM")).is_err());
}

/// The standard types hickory has no mnemonic for read by name, and their
/// RDATA is the wire form BIND 9.20 writes for the same line (from
/// `dig +unknownformat` of the zone loaded in `named`). Lines BIND refuses
/// are refused.
#[test]
fn master_file_reads_every_standard_type_bind_reads() {
    let head = "$TTL 300\n@ IN SOA @ h 1 2 3 4 5\n@ IN NS ns\nns IN A 192.0.2.1\n";
    let read = |line: &str| {
        Zone::from_master(&format!("{head}x {line}\n"), Some(name("t."))).map_err(Box::new)
    };
    let wire = |line: &str| -> String {
        let zone = read(line).unwrap_or_else(|e| panic!("{line}: {e}"));
        let Some(Node::Data(sets)) = zone.node(&lower("x.t.")) else {
            panic!("{line}: no data");
        };
        let data = &sets
            .values()
            .next()
            .unwrap()
            .records_without_rrsigs()
            .next()
            .unwrap()
            .data;
        data.to_bytes()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect()
    };
    for (line, bind) in [
        ("SPF \"v=spf1 -all\"", "0B763D73706631202D616C6C"),
        (
            "RP mbox.example.com. txt.example.com.",
            "046D626F78076578616D706C6503636F6D0003747874076578616D706C6503636F6D00",
        ),
        (
            "AFSDB 1 AfsDb.Example.Com.",
            "0001054166734462074578616D706C6503436F6D00",
        ),
        ("KX 10 Kx.Example.", "000A024B78074578616D706C6500"),
        (
            "MINFO Rm.Example. Em.Example.",
            "02526D074578616D706C650002456D074578616D706C6500",
        ),
        (
            "LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m",
            "000016138B3CF018810CBCE0009895B8",
        ),
        (
            "LOC 42 21 54 N 71 06 18 W -24m 30m",
            "0033161389172DD070BE15F000988D20",
        ),
        (
            "LOC 60 S 120 W 15.5 1500m 7 0.25",
            "0015722173201A006640340000989C8E",
        ),
        (
            "LOC 90 0 0.000 S 180 W 42849672.95m 90000000m 9.99m 0.01",
            "009992106CB0270059604E00FFFFFFFF",
        ),
        (
            "URI 10 1 \"https://example.com/\"",
            "000A000168747470733A2F2F6578616D706C652E636F6D2F",
        ),
        (
            "APL 1:192.168.32.0/21 !1:192.168.38.0/28 2:2001:db8::/32 1:0.0.0.0/0",
            "00011503C0A82000011C83C0A8260002200420010DB800010000",
        ),
        ("APL", ""),
        (
            "DHCID AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=",
            "000201636FC0B8271C82825BB1AC5C41CF5351AA69B4FEBD94E8F17CDB95000DA48C40",
        ),
        ("EUI48 00-00-5e-00-53-2a", "00005E00532A"),
        ("EUI64 00-00-5E-EF-10-00-00-2a", "00005EEF1000002A"),
        ("NID 10 0014:4fff:ff20:ee64", "000A00144FFFFF20EE64"),
        ("NID 20 1:2:3:a", "0014000100020003000A"),
        ("L32 10 10.1.2.0", "000A0A010200"),
        ("L64 10 2001:0DB8:1140:1000", "000A20010DB811401000"),
        (
            "LP 10 l64-subnet1.example.com.",
            "000A0B6C36342D7375626E657431076578616D706C6503636F6D00",
        ),
        (
            "HTTPS 1 . alpn=h2 dohpath=/dns-query{?dns}",
            "00010000010003026832000700102F646E732D71756572797B3F646E737D",
        ),
        (
            "SVCB 1 . mandatory=dohpath dohpath=/q{?dns}",
            "000100000000020007000700082F717B3F646E737D",
        ),
    ] {
        assert_eq!(wire(line), bind, "{line}");
    }
    for line in [
        "LOC 90 0 0.001 S 180 W 0",
        "LOC 52 22 23.0005 N 4 E 0",
        "LOC 52 60 N 4 E 0",
        "LOC 52 22 23 n 4 e 0",
        "LOC 52 22 23 N 4 E 0 90000001m",
        "EUI48 0-00-5e-00-53-2a",
        "URI 10 1 abc",
    ] {
        assert!(read(line).is_err(), "{line}");
    }
}

/// A DS RRset belongs at a zone cut, where the parent holds it, and BIND
/// refuses a zone with one anywhere else (RFC 4035 §2.4).
#[test]
fn a_ds_rrset_away_from_a_cut_is_refused() {
    let ds = "1 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    let head = "t. 300 IN SOA ns.t. h.t. 1 2 3 4 5\nt. 300 IN NS ns.t.\nns.t. 300 IN A 192.0.2.1\n";
    for owner in ["n.t.", "t."] {
        let text = format!("{head}{owner} 300 IN DS {ds}\n");
        assert_eq!(
            Zone::from_master(&text, None).err(),
            Some(ZoneError::DsNotAtCut {
                owner: lower(owner)
            }),
            "{owner}"
        );
    }
    // At a cut it is the cut's.
    let text = format!("{head}n.t. 300 IN NS ns.elsewhere.\nn.t. 300 IN DS {ds}\n");
    let zone = Zone::from_master(&text, None).unwrap();
    assert!(matches!(
        zone.node(&lower("n.t.")),
        Some(Node::Cut { ds: Some(_), .. })
    ));
}

#[test]
fn with_and_with_delegation_make_new_revisions() {
    let zone = example();
    let added = zone
        .with(rrset("new.example.", 60, vec![a("192.0.2.99")]))
        .unwrap();
    assert_eq!(added.revision(), Revision(1));
    assert!(added.node(&lower("new.example.")).is_some());
    // The zone it came from is unchanged.
    assert_eq!(zone.node(&lower("new.example.")), None);
    assert_eq!(zone.revision(), Revision(0));

    // A record already held is kept once.
    let again = added
        .with(rrset(
            "new.example.",
            60,
            vec![a("192.0.2.99"), a("192.0.2.98")],
        ))
        .unwrap();
    let Some(Node::Data(sets)) = again.node(&lower("new.example.")) else {
        panic!("data");
    };
    assert_eq!(sets[&RecordType::A].records_count(), 2);
    assert_eq!(again.revision(), Revision(2));

    // `with` checks the same rules as the builder.
    assert_eq!(
        added
            .with(rrset("new.example.", 120, vec![a("192.0.2.97")]))
            .unwrap_err(),
        ZoneError::RrsetTtlsDiffer {
            owner: lower("new.example."),
            rtype: RecordType::A
        }
    );
    assert_eq!(
        zone.with(rrset("x.sub.example.", 60, vec![txt("no")]))
            .unwrap_err(),
        ZoneError::DataBelowCut {
            owner: lower("x.sub.example."),
            cut: lower("sub.example.")
        }
    );

    let delegated = zone
        .with_delegation(
            name("kid.example."),
            rrset("kid.example.", 60, vec![ns("ns.kid.example.")]),
            vec![rrset("ns.kid.example.", 60, vec![a("192.0.2.77")])],
            None,
        )
        .unwrap();
    assert_eq!(delegated.revision(), Revision(1));
    let reply = response(&delegated, "www.kid.example.", RecordType::A, false);
    assert!(!reply.message.metadata.authoritative);
    assert_eq!(addresses(&reply.message.additionals), vec!["192.0.2.77"]);
    assert_eq!(reply.required_additional, 1);
    // The rest of the zone came along.
    assert_eq!(
        addresses(&ask(&delegated, "www.example.", RecordType::A).answers),
        vec!["192.0.2.10"]
    );
}

// The answer, branch by branch.

#[test]
fn a_name_with_the_type_answers_authoritatively() {
    let zone = example();
    let reply = ask(&zone, "WWW.Example.", RecordType::A);
    assert!(reply.metadata.authoritative);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(reply.metadata.id, 7);
    // Owners are QNAME in lowercase; the server front restores the case.
    assert_eq!(
        rows(&reply.answers),
        vec![row("www.example.", RecordType::A)]
    );
    assert_eq!(reply.answers[0].ttl, 3600);
    assert!(reply.authorities.is_empty());

    // NS, MX, and SRV targets in the zone bring their addresses.
    let reply = ask(&zone, "mail.example.", RecordType::MX);
    assert_eq!(addresses(&reply.additionals), vec!["192.0.2.10"]);
    let reply = ask(&zone, "example.", RecordType::NS);
    assert_eq!(
        addresses(&reply.additionals),
        vec!["192.0.2.1", "2001:db8::1"]
    );
}

#[test]
fn a_name_outside_the_zone_is_refused() {
    let reply = ask(&example(), "www.other.", RecordType::A);
    assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
    assert!(!reply.metadata.authoritative);
    assert!(reply.answers.is_empty());
}

#[test]
fn a_cut_gives_a_referral_with_required_then_sibling_glue() {
    let zone = example();
    let reply = response(&zone, "www.sub.example.", RecordType::A, false);
    let message = &reply.message;
    assert!(!message.metadata.authoritative);
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert!(message.answers.is_empty());
    assert_eq!(
        rows(&message.authorities),
        vec![row("sub.example.", RecordType::NS); 3]
    );
    // In-domain glue first and required (RFC 9471 §3.1), then the address
    // this zone holds under its other cut (RFC 9471 §3.2).
    assert_eq!(
        addresses(&message.additionals),
        vec!["192.0.2.53", "192.0.2.54"]
    );
    assert_eq!(reply.required_additional, 1);

    // The cut itself, asked for NS, is a referral too.
    let reply = ask(&zone, "sub.example.", RecordType::NS);
    assert!(!reply.metadata.authoritative);
    assert!(reply.answers.is_empty());

    // With DO the DS RRset rides along (RFC 4035 §3.1.4).
    let reply = ask_do(&zone, "www.sub.example.", RecordType::A);
    assert!(rows(&reply.authorities).contains(&row("sub.example.", RecordType::DS)));
    // Without DO it does not.
    let reply = ask(&zone, "www.sub.example.", RecordType::A);
    assert!(!rows(&reply.authorities).contains(&row("sub.example.", RecordType::DS)));
}

#[test]
fn ds_at_a_cut_is_answered_from_the_parent() {
    let zone = example();
    let reply = ask(&zone, "sub.example.", RecordType::DS);
    assert!(reply.metadata.authoritative);
    assert_eq!(
        rows(&reply.answers),
        vec![row("sub.example.", RecordType::DS)]
    );

    // An unsigned child: NODATA with the SOA, from the parent.
    let reply = ask(&zone, "zone.example.", RecordType::DS);
    assert!(reply.metadata.authoritative);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.answers.is_empty());
    assert_eq!(
        rows(&reply.authorities),
        vec![row("example.", RecordType::SOA)]
    );
}

#[test]
fn cnames_restart_inside_the_zone() {
    let zone = example();
    let reply = ask(&zone, "chain.example.", RecordType::A);
    assert!(reply.metadata.authoritative);
    assert_eq!(
        rows(&reply.answers),
        vec![
            row("chain.example.", RecordType::CNAME),
            row("alias.example.", RecordType::CNAME),
            row("www.example.", RecordType::A),
        ]
    );

    // A loop is an error (RFC 1034 §3.6.2): SERVFAIL with AA, and the
    // chain up to the first name seen again.
    let reply = ask(&zone, "loop1.example.", RecordType::A);
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert!(reply.metadata.authoritative);
    assert_eq!(
        rows(&reply.answers),
        vec![
            row("loop1.example.", RecordType::CNAME),
            row("loop2.example.", RecordType::CNAME)
        ]
    );

    // A target outside the zone ends the chain.
    let reply = ask(&zone, "away.example.", RecordType::A);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.metadata.authoritative);
    assert_eq!(
        rows(&reply.answers),
        vec![row("away.example.", RecordType::CNAME)]
    );
    assert!(reply.authorities.is_empty());

    // QTYPE CNAME is answered with the CNAME itself.
    let reply = ask(&zone, "alias.example.", RecordType::CNAME);
    assert_eq!(
        rows(&reply.answers),
        vec![row("alias.example.", RecordType::CNAME)]
    );
}

#[test]
fn after_a_chain_the_rcode_is_the_last_names() {
    // RFC 6604 §2: the CNAME stays in the answer, and the RCODE and the
    // SOA are those of the name it points at.
    let reply = ask(&example(), "dangling.example.", RecordType::A);
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert!(reply.metadata.authoritative);
    assert_eq!(
        rows(&reply.answers),
        vec![row("dangling.example.", RecordType::CNAME)]
    );
    assert_eq!(
        rows(&reply.authorities),
        vec![row("example.", RecordType::SOA)]
    );
}

#[test]
fn a_dname_substitutes_and_overflow_is_yxdomain() {
    let zone = example();
    let reply = ask(&zone, "x.d.example.", RecordType::A);
    assert_eq!(
        rows(&reply.answers),
        vec![
            row("d.example.", RecordType::DNAME),
            row("x.d.example.", RecordType::CNAME),
            row("x.target.example.", RecordType::A),
        ]
    );
    // The synthesized CNAME has the DNAME's TTL (RFC 6672 §3.1).
    assert_eq!(reply.answers[1].ttl, reply.answers[0].ttl);
    assert_eq!(reply.answers[1].data, cname("x.target.example."));

    // A new name of 256 octets or more is YXDOMAIN (RFC 6672 §2.2).
    let long = format!("{}.long.example.", &long_label('y')[..60]);
    let reply = ask(&zone, &long, RecordType::A);
    assert_eq!(reply.metadata.response_code, ResponseCode::YXDomain);
    assert_eq!(
        rows(&reply.answers),
        vec![row("long.example.", RecordType::DNAME)]
    );

    // A short one leaves the zone, which ends the chain.
    let reply = ask(&zone, "short.long.example.", RecordType::A);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(reply.answers.len(), 2);

    // At its own owner, a DNAME is ordinary data.
    let reply = ask(&zone, "d.example.", RecordType::DNAME);
    assert_eq!(
        rows(&reply.answers),
        vec![row("d.example.", RecordType::DNAME)]
    );
    let reply = ask(&zone, "d.example.", RecordType::A);
    assert!(reply.answers.is_empty());
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
}

/// A chain that passes one DNAME twice sends it once, as BIND does: two
/// records with the same owner, class, type, and data are one
/// (RFC 2181 §5).
#[test]
fn a_dname_a_chain_passes_twice_goes_out_once() {
    let zone = builder("example.")
        .rrset(rrset("d.example.", 300, vec![dname(&name("t.example."))]))
        .rrset(rrset("x.t.example.", 300, vec![cname("y.d.example.")]))
        .rrset(rrset("y.t.example.", 300, vec![a("192.0.2.9")]))
        .rrset(rrset(
            "loopd.example.",
            300,
            vec![dname(&name("e.loopd.example."))],
        ))
        .build()
        .unwrap();
    let reply = ask(&zone, "x.d.example.", RecordType::A);
    assert_eq!(
        rows(&reply.answers),
        vec![
            row("d.example.", RecordType::DNAME),
            row("x.d.example.", RecordType::CNAME),
            row("x.t.example.", RecordType::CNAME),
            row("y.d.example.", RecordType::CNAME),
            row("y.t.example.", RecordType::A),
        ]
    );

    // A DNAME whose target is below its owner repeats until the name
    // passes 255 octets, and still goes out once.
    let reply = ask(&zone, "a.loopd.example.", RecordType::A);
    assert_eq!(reply.metadata.response_code, ResponseCode::YXDomain);
    let dnames = reply
        .answers
        .iter()
        .filter(|record| record.record_type() == RecordType::DNAME)
        .count();
    assert_eq!(dnames, 1);
}

#[test]
fn empty_non_terminals_and_missing_types_are_nodata() {
    let zone = example();
    for (qname, qtype) in [
        ("b.c.example.", RecordType::A),
        ("c.example.", RecordType::TXT),
        ("www.example.", RecordType::AAAA),
    ] {
        let reply = ask(&zone, qname, qtype);
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NoError,
            "{qname}"
        );
        assert!(reply.metadata.authoritative);
        assert!(reply.answers.is_empty());
        assert_eq!(
            rows(&reply.authorities),
            vec![row("example.", RecordType::SOA)]
        );
    }
}

#[test]
fn negative_answers_carry_the_soa_with_the_lower_ttl() {
    let zone = example();
    let reply = ask(&zone, "nope.example.", RecordType::A);
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert!(reply.metadata.authoritative);
    // min(SOA TTL 3600, MINIMUM 300) (RFC 2308 §3).
    assert_eq!(reply.authorities[0].ttl, 300);

    // The other way round: an SOA TTL below MINIMUM.
    let zone = Zone::builder(name("low."), soa("low.", 900), 60)
        .rrset(rrset("low.", 60, vec![ns("ns1.low.")]))
        .rrset(rrset("ns1.low.", 60, vec![a("192.0.2.1")]))
        .build()
        .unwrap();
    let reply = ask(&zone, "nope.low.", RecordType::A);
    assert_eq!(reply.authorities[0].ttl, 60);
    let reply = ask(&zone, "ns1.low.", RecordType::TXT);
    assert_eq!(reply.authorities[0].ttl, 60);
}

#[test]
fn wildcards_answer_for_absent_names() {
    let zone = example();
    // The owner is QNAME and the TTL the wildcard's (RFC 4592 §3.3).
    let reply = ask(&zone, "anything.w.example.", RecordType::TXT);
    assert!(reply.metadata.authoritative);
    assert_eq!(
        rows(&reply.answers),
        vec![row("anything.w.example.", RecordType::TXT)]
    );
    assert_eq!(reply.answers[0].ttl, 300);
    // Two labels below the closest encloser match too.
    let reply = ask(&zone, "two.labels.w.example.", RecordType::A);
    assert_eq!(addresses(&reply.answers), vec!["192.0.2.30"]);

    // No RRset of the type at the wildcard: NODATA (RFC 4592 §4.3).
    let reply = ask(&zone, "anything.w.example.", RecordType::AAAA);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.answers.is_empty());
    assert_eq!(
        rows(&reply.authorities),
        vec![row("example.", RecordType::SOA)]
    );

    // A wildcard CNAME is followed.
    let reply = ask(&zone, "foo.cw.example.", RecordType::A);
    assert_eq!(
        rows(&reply.answers),
        vec![
            row("foo.cw.example.", RecordType::CNAME),
            row("www.example.", RecordType::A)
        ]
    );

    // The wildcard's own name is an ordinary name.
    let reply = ask(&zone, "*.w.example.", RecordType::TXT);
    assert_eq!(
        rows(&reply.answers),
        vec![row("*.w.example.", RecordType::TXT)]
    );
}

#[test]
fn a_closer_name_stops_a_wildcard() {
    let zone = example();
    // e.w exists (an empty non-terminal above deep.e.w), so it is the
    // closest encloser of x.e.w, and *.w does not apply (RFC 4592 §2.2.2).
    let reply = ask(&zone, "x.e.w.example.", RecordType::A);
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert!(reply.answers.is_empty());
    // deep.e.w answers for itself.
    let reply = ask(&zone, "deep.e.w.example.", RecordType::A);
    assert_eq!(addresses(&reply.answers), vec!["192.0.2.31"]);
}

#[test]
fn a_star_after_the_first_label_is_ordinary() {
    let zone = example();
    let reply = ask(&zone, "x.*.m.example.", RecordType::A);
    assert_eq!(addresses(&reply.answers), vec!["192.0.2.40"]);
    // It does not match other labels (RFC 4592 §2.1.3). *.m.example
    // exists only as an empty non-terminal, so it matches with nothing.
    let reply = ask(&zone, "x.y.m.example.", RecordType::A);
    assert!(reply.answers.is_empty());
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
}

#[test]
fn any_follows_rfc_8482() {
    let zone = example();
    let any = |mode| match answer(
        &zone,
        &request("www.example.", RecordType::ANY, false),
        mode,
    ) {
        Answered::Response(response) => response.message,
        Answered::Unknown { name, .. } => panic!("unknown at {name}"),
    };
    let all = any(AnyResponse::All);
    assert_eq!(
        rows(&all.answers),
        vec![
            row("www.example.", RecordType::A),
            row("www.example.", RecordType::TXT)
        ]
    );
    let one = any(AnyResponse::OneRrset(RecordType::TXT));
    assert_eq!(
        rows(&one.answers),
        vec![row("www.example.", RecordType::TXT)]
    );
    // Without an RRset of the type it prefers, the first in type order.
    let one = any(AnyResponse::OneRrset(RecordType::MX));
    assert_eq!(rows(&one.answers), vec![row("www.example.", RecordType::A)]);
    // Its TTL is the operator's, not the name's data's (RFC 8482 §4.2).
    let hinfo = any(AnyResponse::Hinfo { ttl: 3789 });
    assert_eq!(
        rows(&hinfo.answers),
        vec![row("www.example.", RecordType::HINFO)]
    );
    assert_eq!(hinfo.answers[0].ttl, 3789);
    let RData::HINFO(synthesized) = &hinfo.answers[0].data else {
        panic!("HINFO");
    };
    assert_eq!(&*synthesized.cpu, b"RFC8482");
    assert!(synthesized.os.is_empty());
    assert!(hinfo.metadata.authoritative);

    // ANY at an empty non-terminal is NODATA.
    let reply = ask(&zone, "c.example.", RecordType::ANY);
    assert!(reply.answers.is_empty());
    assert_eq!(
        rows(&reply.authorities),
        vec![row("example.", RecordType::SOA)]
    );
}

/// No HINFO is made up for ANY at a CNAME (RFC 8482 §4.2): the CNAME
/// answers, its own or a wildcard's.
#[test]
fn any_at_a_cname_gets_the_cname_rather_than_a_hinfo() {
    let zone = example();
    for (qname, owner) in [
        ("alias.example.", "alias.example."),
        ("x.cw.example.", "x.cw.example."),
    ] {
        let reply = match answer(
            &zone,
            &request(qname, RecordType::ANY, false),
            AnyResponse::Hinfo { ttl: 3600 },
        ) {
            Answered::Response(response) => response.message,
            Answered::Unknown { name, .. } => panic!("unknown at {name}"),
        };
        assert_eq!(rows(&reply.answers), vec![row(owner, RecordType::CNAME)]);
        assert!(reply.metadata.authoritative);
    }
}

// DNSSEC records in answers.

/// A zone with RRSIGs and an NSEC chain. The signatures are not real;
/// the answer only carries them.
fn signed_text() -> String {
    let sig = |covered: &str, labels: u8| {
        format!("RRSIG {covered} 13 {labels} 300 20261201000000 20261101000000 4242 signed. AAAA")
    };
    format!(
        "$ORIGIN signed.
$TTL 300
@        SOA   ns hostmaster 1 7200 3600 1209600 60
@        {soa}
@        NS    ns
@        {ns_sig}
@        NSEC  child NS SOA RRSIG NSEC
@        {apex_nsec}
child    NS    ns.child
child    NSEC  ns NS RRSIG NSEC
child    {child_nsec}
ns.child A     192.0.2.9
ns       A     192.0.2.1
ns       {ns_a}
ns       NSEC  www A RRSIG NSEC
ns       {ns_nsec}
www      A     192.0.2.2
www      {www_a}
www      NSEC  signed. A RRSIG NSEC
www      {www_nsec}
",
        soa = sig("SOA", 1),
        ns_sig = sig("NS", 1),
        apex_nsec = sig("NSEC", 1),
        child_nsec = sig("NSEC", 2),
        ns_a = sig("A", 2),
        ns_nsec = sig("NSEC", 2),
        www_a = sig("A", 2),
        www_nsec = sig("NSEC", 2),
    )
}

fn signed() -> Zone {
    Zone::from_master(&signed_text(), None).unwrap()
}

#[test]
fn rrsigs_travel_only_with_do() {
    let zone = signed();
    let plain = ask(&zone, "www.signed.", RecordType::A);
    assert_eq!(
        rows(&plain.answers),
        vec![row("www.signed.", RecordType::A)]
    );
    let with_do = ask_do(&zone, "www.signed.", RecordType::A);
    assert_eq!(
        rows(&with_do.answers),
        vec![
            row("www.signed.", RecordType::A),
            row("www.signed.", RecordType::RRSIG)
        ]
    );

    // A server that answers ANY with every RRset sends NSEC and RRSIG
    // without DO, as the root servers do: it counts ANY as asking for
    // them (RFC 4035 §3.2.1).
    let any = ask(&zone, "www.signed.", RecordType::ANY);
    assert_eq!(
        rows(&any.answers),
        vec![
            row("www.signed.", RecordType::A),
            row("www.signed.", RecordType::NSEC),
            row("www.signed.", RecordType::RRSIG),
            row("www.signed.", RecordType::RRSIG)
        ]
    );
    // One that sends every RRset only as DO asks leaves them out without
    // DO (RFC 3225 §3), and sends them with it.
    let following = |dnssec_ok| match answer(
        &zone,
        &request("www.signed.", RecordType::ANY, dnssec_ok),
        AnyResponse::AllFollowingDo,
    ) {
        Answered::Response(response) => response.message,
        Answered::Unknown { name, .. } => panic!("unknown at {name}"),
    };
    assert_eq!(
        rows(&following(false).answers),
        vec![row("www.signed.", RecordType::A)]
    );
    let types: BTreeSet<RecordType> = following(true)
        .answers
        .iter()
        .map(|r| r.record_type())
        .collect();
    assert_eq!(
        types,
        BTreeSet::from([RecordType::A, RecordType::NSEC, RecordType::RRSIG])
    );
    // One that sends one RRset leaves them out.
    let one = |qname: &str, rtype| match answer(
        &zone,
        &request(qname, RecordType::ANY, false),
        AnyResponse::OneRrset(rtype),
    ) {
        Answered::Response(response) => rows(&response.message.answers),
        Answered::Unknown { name, .. } => panic!("unknown at {name}"),
    };
    assert_eq!(
        one("www.signed.", RecordType::NSEC),
        vec![row("www.signed.", RecordType::A)]
    );
    // It sends the RRset of the type it prefers: the SOA at the apex,
    // though NS comes first in type order.
    assert_eq!(
        one("signed.", RecordType::SOA),
        vec![row("signed.", RecordType::SOA)]
    );
    let any = ask_do(&zone, "www.signed.", RecordType::ANY);
    let types: BTreeSet<RecordType> = any.answers.iter().map(|r| r.record_type()).collect();
    assert_eq!(
        types,
        BTreeSet::from([RecordType::A, RecordType::NSEC, RecordType::RRSIG])
    );

    // Asked for by type, they come without DO.
    let nsec = ask(&zone, "www.signed.", RecordType::NSEC);
    assert_eq!(
        rows(&nsec.answers),
        vec![row("www.signed.", RecordType::NSEC)]
    );
    let rrsig = ask(&zone, "www.signed.", RecordType::RRSIG);
    assert_eq!(
        rows(&rrsig.answers),
        vec![row("www.signed.", RecordType::RRSIG); 2]
    );
}

#[test]
fn negatives_bring_their_nsec_proofs_with_do() {
    let zone = signed();
    // nope.signed. sorts between child.signed. and ns.signed., so the NSEC
    // at child proves the name absent; the wildcard *.signed. sorts first
    // after the apex, so the apex NSEC proves it absent (RFC 4035
    // §3.1.3.2).
    let reply = ask_do(&zone, "nope.signed.", RecordType::A);
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(
        rows(&reply.authorities),
        vec![
            row("signed.", RecordType::SOA),
            row("signed.", RecordType::RRSIG),
            row("child.signed.", RecordType::NSEC),
            row("child.signed.", RecordType::RRSIG),
            row("signed.", RecordType::NSEC),
            row("signed.", RecordType::RRSIG),
        ]
    );
    // A name the apex NSEC covers needs it only once.
    let reply = ask_do(&zone, "aaa.signed.", RecordType::A);
    assert_eq!(
        rows(&reply.authorities),
        vec![
            row("signed.", RecordType::SOA),
            row("signed.", RecordType::RRSIG),
            row("signed.", RecordType::NSEC),
            row("signed.", RecordType::RRSIG),
        ]
    );
    // The SOA's RRSIG takes the negative TTL too.
    assert_eq!(reply.authorities[0].ttl, 60);
    assert_eq!(reply.authorities[1].ttl, 60);
    // Without DO: the SOA alone.
    let reply = ask(&zone, "nope.signed.", RecordType::A);
    assert_eq!(
        rows(&reply.authorities),
        vec![row("signed.", RecordType::SOA)]
    );

    // NODATA brings the NSEC at the name.
    let reply = ask_do(&zone, "www.signed.", RecordType::TXT);
    assert!(rows(&reply.authorities).contains(&row("www.signed.", RecordType::NSEC)));

    // A referral to an unsigned child brings the NSEC at the cut, which
    // proves it has no DS.
    let reply = ask_do(&zone, "host.child.signed.", RecordType::A);
    assert!(!reply.metadata.authoritative);
    assert_eq!(
        rows(&reply.authorities),
        vec![
            row("child.signed.", RecordType::NS),
            row("child.signed.", RecordType::NSEC),
            row("child.signed.", RecordType::RRSIG),
        ]
    );
    let reply = ask(&zone, "host.child.signed.", RecordType::A);
    assert_eq!(
        rows(&reply.authorities),
        vec![row("child.signed.", RecordType::NS)]
    );
}

/// The NSEC at a cut is the parent's data, so the parent answers it with
/// AA set, as it answers DS, rather than referring (RFC 4035 §2.6, §4.2).
/// A zone with no NSEC at the cut refers.
#[test]
fn the_nsec_at_a_cut_is_answered_by_the_parent() {
    let zone = signed();
    for reply in [
        ask_do(&zone, "child.signed.", RecordType::NSEC),
        ask(&zone, "child.signed.", RecordType::NSEC),
    ] {
        assert!(reply.metadata.authoritative);
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert_eq!(
            rows(&reply.answers)[0],
            row("child.signed.", RecordType::NSEC)
        );
        assert!(
            rows(&reply.authorities)
                .iter()
                .all(|(_, rtype)| *rtype != RecordType::NS)
        );
    }
    assert_eq!(
        rows(&ask_do(&zone, "child.signed.", RecordType::NSEC).answers),
        vec![
            row("child.signed.", RecordType::NSEC),
            row("child.signed.", RecordType::RRSIG),
        ]
    );

    let unsigned = example();
    let reply = ask(&unsigned, "sub.example.", RecordType::NSEC);
    assert!(!reply.metadata.authoritative);
    assert!(reply.answers.is_empty());
}

#[test]
fn nsec3_zones_prove_with_hashed_owners() {
    // The owner label of an NSEC3 record is the base32hex hash of the name
    // it covers (RFC 5155 §3.3); hickory writes that label for the next
    // hashed owner, so it is borrowed from there.
    let hash = |text: &str| {
        Nsec3HashAlgorithm::SHA1
            .hash(&[], &name(text), 0)
            .unwrap()
            .as_ref()
            .to_vec()
    };
    let label = |hash: &[u8]| {
        let nsec3 = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            vec![],
            hash.to_vec(),
            [],
        );
        nsec3.next_hashed_owner_name_base32().unwrap().to_string()
    };
    let mut hashes = [
        (hash("n3."), vec![RecordType::NS, RecordType::SOA]),
        (hash("www.n3."), vec![RecordType::A]),
    ];
    hashes.sort();
    let mut zone = builder("n3.").rrset(rrset("www.n3.", 60, vec![a("192.0.2.2")]));
    let mut owners = Vec::new();
    for (index, (hash, types)) in hashes.iter().enumerate() {
        let next = hashes[(index + 1) % hashes.len()].0.clone();
        let owner = format!("{}.n3.", label(hash));
        let rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            0,
            vec![],
            next,
            types.clone(),
        );
        zone = zone.rrset(rrset(
            &owner,
            60,
            vec![RData::DNSSEC(DNSSECRData::NSEC3(rdata))],
        ));
        owners.push(owner);
    }
    // ns1.n3. from the builder needs no NSEC3 of its own for these
    // questions.
    let zone = zone.build().unwrap();
    // Hashed owners are not names of the zone.
    assert_eq!(zone.node(&lower(&owners[0])), None);

    let apex_owner = format!("{}.n3.", label(&hash("n3.")));
    let reply = ask_do(&zone, "nope.n3.", RecordType::A);
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    let proof: BTreeSet<String> = reply
        .authorities
        .iter()
        .filter(|r| r.record_type() == RecordType::NSEC3)
        .map(|r| r.name.to_string())
        .collect();
    // The closest encloser, n3., is matched (RFC 5155 §7.2.2), and every
    // record is one of the zone's.
    assert!(proof.contains(&apex_owner));
    assert!(proof.iter().all(|owner| owners.contains(owner)));

    let www_owner = format!("{}.n3.", label(&hash("www.n3.")));
    let reply = ask_do(&zone, "www.n3.", RecordType::TXT);
    let proof: Vec<String> = reply
        .authorities
        .iter()
        .filter(|r| r.record_type() == RecordType::NSEC3)
        .map(|r| r.name.to_string())
        .collect();
    assert_eq!(proof, vec![www_owner]);
}

#[test]
fn an_unsigned_zone_denies_with_nothing() {
    let zone = example();
    assert_eq!(
        View::denial(&zone, &lower("nope.example."), Denied::Name),
        Fact::Present(vec![])
    );
    let reply = ask_do(&zone, "nope.example.", RecordType::A);
    assert_eq!(
        rows(&reply.authorities),
        vec![row("example.", RecordType::SOA)]
    );
}

// Unknown facts.

/// A complete zone with one fact made unknown: the node at `unknown`, or
/// with `denial`, the denial records at it.
struct Partial<'z> {
    zone: &'z Zone,
    unknown: LowerName,
    denial: bool,
}

impl View for Partial<'_> {
    fn apex(&self) -> &LowerName {
        View::apex(self.zone)
    }

    fn revision(&self) -> Revision {
        View::revision(self.zone)
    }

    fn soa(&self) -> &RecordSet {
        View::soa(self.zone)
    }

    fn node(&self, name: &LowerName) -> Fact<&Node> {
        if !self.denial && *name == self.unknown {
            return Fact::Unknown;
        }
        View::node(self.zone, name)
    }

    fn denial(&self, name: &LowerName, kind: Denied) -> Fact<Vec<RecordSet>> {
        if self.denial && *name == self.unknown {
            return Fact::Unknown;
        }
        View::denial(self.zone, name, kind)
    }
}

fn wildcard(name: &LowerName) -> LowerName {
    LowerName::new(&Name::from(name).prepend_label("*").unwrap())
}

/// Every name an answer in `zone` to `qname` could read: the zone's
/// nodes, the names from the apex to `qname`, and the wildcards below all
/// of them.
fn candidates(zone: &Zone, qname: &str) -> BTreeSet<LowerName> {
    let mut names: BTreeSet<LowerName> = zone.nodes().map(|(name, _)| name.clone()).collect();
    let mut name = lower(qname);
    while zone.apex().zone_of(&name) {
        names.insert(name.clone());
        if name == *zone.apex() {
            break;
        }
        name = name.base_name();
    }
    let wildcards: Vec<LowerName> = names.iter().map(wildcard).collect();
    names.extend(wildcards);
    names
}

#[test]
fn an_unknown_fact_never_becomes_a_negative() {
    let questions = [
        ("www.example.", RecordType::A),
        ("mail.example.", RecordType::MX),
        ("example.", RecordType::NS),
        ("www.sub.example.", RecordType::A),
        ("sub.example.", RecordType::DS),
        ("zone.example.", RecordType::DS),
        ("chain.example.", RecordType::A),
        ("loop1.example.", RecordType::A),
        ("dangling.example.", RecordType::A),
        ("x.d.example.", RecordType::A),
        ("b.c.example.", RecordType::A),
        ("www.example.", RecordType::AAAA),
        ("nope.example.", RecordType::A),
        ("anything.w.example.", RecordType::TXT),
        ("anything.w.example.", RecordType::AAAA),
        ("foo.cw.example.", RecordType::A),
        ("x.e.w.example.", RecordType::A),
        ("www.example.", RecordType::ANY),
    ];
    let zone = example();
    for (qname, qtype) in questions {
        for dnssec_ok in [false, true] {
            let req = request(qname, qtype, dnssec_ok);
            let complete = answer(&zone, &req, AnyResponse::All);
            assert!(
                matches!(complete, Answered::Response(_)),
                "a complete zone knows everything"
            );
            let mut read = 0;
            for unknown in candidates(&zone, qname) {
                let partial = Partial {
                    zone: &zone,
                    unknown: unknown.clone(),
                    denial: false,
                };
                let partly = answer(&partial, &req, AnyResponse::All);
                // Either the answer did not need the fact and is the
                // complete zone's, or it ends at the unknown name. It is
                // never any other reply, so never a negative the complete
                // zone would not give. An unknown NS, MX, or SRV target
                // only leaves its addresses out of the optional
                // additional data.
                if matches!(&partly, Answered::Unknown { name, .. } if *name == unknown) {
                    read += 1;
                } else if partly != complete {
                    let (Answered::Response(partly), Answered::Response(complete)) =
                        (&partly, &complete)
                    else {
                        panic!("{qname} {qtype} with {unknown} unknown: {partly:?}");
                    };
                    // The optional records at or below the unknown name
                    // are left out; the required glue comes first.
                    let mut without = complete.clone();
                    let required = without.required_additional;
                    let mut index = 0;
                    without.message.additionals.retain(|record| {
                        index += 1;
                        index <= required || !unknown.zone_of(&LowerName::new(&record.name))
                    });
                    assert_eq!(*partly, without, "{qname} {qtype} with {unknown} unknown");
                    read += 1;
                }
            }
            assert!(read > 0, "{qname} {qtype} read no fact");
        }
    }
}

#[test]
fn negatives_rest_on_facts_that_must_be_known() {
    let zone = example();
    // (question, a fact the negative rests on, the name the answer had
    // reached)
    let cases = [
        // NXDOMAIN needs the name absent and the wildcard absent.
        (
            "nope.example.",
            RecordType::A,
            "nope.example.",
            "nope.example.",
        ),
        (
            "nope.example.",
            RecordType::A,
            "*.example.",
            "nope.example.",
        ),
        // A closer name stops a wildcard only if it is known to exist.
        (
            "x.e.w.example.",
            RecordType::A,
            "e.w.example.",
            "x.e.w.example.",
        ),
        (
            "x.e.w.example.",
            RecordType::A,
            "*.e.w.example.",
            "x.e.w.example.",
        ),
        // NODATA needs the node known.
        (
            "b.c.example.",
            RecordType::A,
            "b.c.example.",
            "b.c.example.",
        ),
        (
            "www.example.",
            RecordType::AAAA,
            "www.example.",
            "www.example.",
        ),
        // Every name on the way down.
        ("b.c.example.", RecordType::A, "c.example.", "b.c.example."),
        ("nope.example.", RecordType::A, "example.", "nope.example."),
        // A wildcard NODATA needs the wildcard known.
        (
            "anything.w.example.",
            RecordType::AAAA,
            "*.w.example.",
            "anything.w.example.",
        ),
        // After a chain, the RCODE rests on the target, which the answer
        // has reached.
        (
            "dangling.example.",
            RecordType::A,
            "gone.example.",
            "gone.example.",
        ),
        // DS NODATA at a cut needs the cut known.
        (
            "zone.example.",
            RecordType::DS,
            "zone.example.",
            "zone.example.",
        ),
    ];
    for (qname, qtype, unknown, reached) in cases {
        let partial = Partial {
            zone: &zone,
            unknown: lower(unknown),
            denial: false,
        };
        assert_eq!(
            answer(&partial, &request(qname, qtype, false), AnyResponse::All),
            Answered::Unknown {
                name: lower(unknown),
                reached: lower(reached),
            },
            "{qname} {qtype} with {unknown} unknown"
        );
    }

    // With DO, the denial records are facts too.
    let zone = signed();
    let cases = [
        ("nope.signed.", RecordType::A, "nope.signed."),
        ("www.signed.", RecordType::TXT, "www.signed."),
        ("host.child.signed.", RecordType::A, "child.signed."),
    ];
    for (qname, qtype, unknown) in cases {
        let partial = Partial {
            zone: &zone,
            unknown: lower(unknown),
            denial: true,
        };
        assert_eq!(
            answer(&partial, &request(qname, qtype, true), AnyResponse::All),
            Answered::Unknown {
                name: lower(unknown),
                reached: lower(qname),
            },
            "{qname} {qtype} with the denial at {unknown} unknown"
        );
        // Without DO the denial records are not read.
        let reply = answer(&partial, &request(qname, qtype, false), AnyResponse::All);
        assert!(matches!(reply, Answered::Response(_)));
    }
}

#[test]
fn transparent_turns_absence_into_unknown() {
    let transparent = Transparent(example());
    assert_eq!(*transparent.apex(), lower("example."));
    let view = view_of(&transparent, "www.example.", RecordType::A);
    assert_eq!(
        addresses(&ask(&*view, "www.example.", RecordType::A).answers),
        vec!["192.0.2.10"]
    );
    // A name it holds without the type is still NODATA.
    let reply = ask(&*view, "www.example.", RecordType::AAAA);
    assert!(reply.answers.is_empty());
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    // An absent name is unknown, so a resolver goes on to iterate. Each
    // question gets its own view: a transparent view holds the facts of
    // its question.
    assert_eq!(
        answer(
            &*view_of(&transparent, "nope.example.", RecordType::A),
            &request("nope.example.", RecordType::A, false),
            AnyResponse::All
        ),
        Answered::Unknown {
            name: lower("nope.example."),
            reached: lower("nope.example."),
        }
    );
    // So is a name that only an absent wildcard would deny.
    assert_eq!(
        answer(
            &*view_of(&transparent, "x.e.w.example.", RecordType::A),
            &request("x.e.w.example.", RecordType::A, false),
            AnyResponse::All
        ),
        Answered::Unknown {
            name: lower("x.e.w.example."),
            reached: lower("x.e.w.example."),
        }
    );
}

/// A transparent zone walks past an empty non-terminal on the way to a
/// CNAME's target, and an answer that ends at one stays unknown, whether
/// asked for or reached through a CNAME.
#[test]
fn transparent_walks_past_empty_non_terminals_to_a_cname_target() {
    let zone = Zone::builder(name("example."), soa("example.", 300), 3600)
        .rrset(rrset("example.", 3600, vec![ns("ns.example.")]))
        .rrset(rrset("ns.example.", 3600, vec![a("192.0.2.1")]))
        .rrset(rrset("www.example.", 3600, vec![cname("a.b.example.")]))
        .rrset(rrset("a.b.example.", 3600, vec![a("192.0.2.3")]))
        .rrset(rrset("ent.example.", 3600, vec![cname("b.example.")]))
        .build()
        .unwrap();
    let transparent = Transparent(zone);
    let reply = ask(
        &*view_of(&transparent, "www.example.", RecordType::A),
        "www.example.",
        RecordType::A,
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(reply.answers[0].record_type(), RecordType::CNAME);
    assert_eq!(addresses(&reply.answers), vec!["192.0.2.3"]);
    for qname in ["b.example.", "ent.example."] {
        assert_eq!(
            answer(
                &*view_of(&transparent, qname, RecordType::A),
                &request(qname, RecordType::A, false),
                AnyResponse::All
            ),
            Answered::Unknown {
                name: lower("b.example."),
                reached: lower("b.example."),
            },
            "{qname}"
        );
    }
}

/// Shown data answers only the types it holds at its one name: an A RRset
/// says nothing about AAAA, SOA, or NS there, nor about any name below,
/// so those stay unknown and never become NODATA or a made-up apex.
#[test]
fn shown_data_knows_only_its_own_rrsets() {
    let shown = Shown::new(
        &name("www.example."),
        [rrset("www.example.", 300, vec![a("192.0.2.80")])],
    )
    .unwrap();
    assert_eq!(*shown.apex(), lower("www.example."));
    let reply = ask(
        &*view_of(&shown, "www.example.", RecordType::A),
        "www.example.",
        RecordType::A,
    );
    assert_eq!(addresses(&reply.answers), vec!["192.0.2.80"]);
    assert!(reply.authorities.is_empty());
    for (qname, qtype) in [
        ("www.example.", RecordType::AAAA),
        ("www.example.", RecordType::SOA),
        ("www.example.", RecordType::NS),
        ("www.example.", RecordType::HTTPS),
        ("www.example.", RecordType::ANY),
        ("x.www.example.", RecordType::A),
    ] {
        let answered = answer(
            &*view_of(&shown, qname, qtype),
            &request(qname, qtype, false),
            AnyResponse::All,
        );
        assert!(
            matches!(answered, Answered::Unknown { .. }),
            "{qname} {qtype}: {answered:?}"
        );
    }

    // A CNAME answers every type at its name but NSEC, whose RRset may
    // sit beside it (RFC 4035 §2.5): whether the name has one is unknown.
    let alias = Shown::new(
        &name("www.example."),
        [rrset("www.example.", 300, vec![cname("edge.cdn.test.")])],
    )
    .unwrap();
    let reply = ask(
        &*view_of(&alias, "www.example.", RecordType::AAAA),
        "www.example.",
        RecordType::AAAA,
    );
    assert_eq!(
        rows(&reply.answers),
        vec![row("www.example.", RecordType::CNAME)]
    );
    let answered = answer(
        &*view_of(&alias, "www.example.", RecordType::NSEC),
        &request("www.example.", RecordType::NSEC, false),
        AnyResponse::All,
    );
    assert!(
        matches!(answered, Answered::Unknown { .. }),
        "NSEC at the alias: {answered:?}"
    );
    let reply = ask(
        &*view_of(&alias, "www.example.", RecordType::ANY),
        "www.example.",
        RecordType::ANY,
    );
    assert_eq!(
        rows(&reply.answers),
        vec![row("www.example.", RecordType::CNAME)]
    );
    // It carries no RRSIGs, so which RRSIGs the name has is unknown, never
    // NODATA under a made-up SOA.
    assert_eq!(
        answer(
            &*view_of(&alias, "www.example.", RecordType::RRSIG),
            &request("www.example.", RecordType::RRSIG, false),
            AnyResponse::All
        ),
        Answered::Unknown {
            name: lower("www.example."),
            reached: lower("www.example."),
        }
    );

    // Shown data holds one name's RRsets.
    assert_eq!(
        Shown::new(
            &name("www.example."),
            [rrset("mail.example.", 300, vec![a("192.0.2.25")])]
        )
        .err(),
        Some(ZoneError::OutOfZone {
            owner: lower("mail.example.")
        })
    );
    assert_eq!(
        Shown::new(
            &name("www.example."),
            [
                rrset("www.example.", 300, vec![cname("edge.cdn.test.")]),
                rrset("www.example.", 300, vec![a("192.0.2.80")]),
            ]
        )
        .err(),
        Some(ZoneError::CnameWithOtherData {
            owner: lower("www.example.")
        })
    );

    // A signed alias holds its NSEC RRset beside the CNAME (RFC 4035
    // §2.5), as a capture with DO shows it: the NSEC answers an NSEC
    // question, and the CNAME every other type.
    let nsec = RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
        name("x.example."),
        [RecordType::CNAME, RecordType::RRSIG, RecordType::NSEC],
    )));
    let signed_alias = Shown::new(
        &name("www.example."),
        [
            rrset("www.example.", 300, vec![cname("edge.cdn.test.")]),
            rrset("www.example.", 300, vec![nsec]),
        ],
    )
    .unwrap();
    let reply = ask(
        &*view_of(&signed_alias, "www.example.", RecordType::NSEC),
        "www.example.",
        RecordType::NSEC,
    );
    assert_eq!(
        rows(&reply.answers),
        vec![row("www.example.", RecordType::NSEC)]
    );
    let reply = ask(
        &*view_of(&signed_alias, "www.example.", RecordType::A),
        "www.example.",
        RecordType::A,
    );
    assert_eq!(
        rows(&reply.answers),
        vec![row("www.example.", RecordType::CNAME)]
    );
}

// Zones that grow.

type Book = Arc<Mutex<BTreeMap<LowerName, Fact<Vec<RecordSet>>>>>;
type Asked = Arc<Mutex<Vec<LowerName>>>;

/// A lazy zone `lazy.` whose provider reads `book` (absent when a name is
/// not in it) and logs each name it is asked about.
fn lazy(book: &Book, asked: &Asked) -> Lazy<impl fictionet::stdlib::services::dns::zone::Provider> {
    let (book, asked) = (book.clone(), asked.clone());
    Lazy::new(
        name("lazy."),
        soa("lazy.", 60),
        rrset("lazy.", 3600, vec![ns("lazy.")]),
        3600,
        move |name: &LowerName| {
            asked.lock().unwrap().push(name.clone());
            book.lock()
                .unwrap()
                .get(name)
                .cloned()
                .unwrap_or(Fact::Absent)
        },
    )
}

fn put(book: &Book, owner: &str, fact: Fact<Vec<RecordSet>>) {
    book.lock().unwrap().insert(lower(owner), fact);
}

fn times_asked(asked: &Asked, owner: &str) -> usize {
    asked
        .lock()
        .unwrap()
        .iter()
        .filter(|name| **name == lower(owner))
        .count()
}

fn lazy_ask(zone: &dyn ZoneData, qname: &str, qtype: RecordType) -> Answered {
    let view = view_of(zone, qname, qtype);
    answer(&*view, &request(qname, qtype, false), AnyResponse::All)
}

fn lazy_reply(zone: &dyn ZoneData, qname: &str, qtype: RecordType) -> Message {
    match lazy_ask(zone, qname, qtype) {
        Answered::Response(response) => response.message,
        Answered::Unknown { name, .. } => panic!("unknown at {name}"),
    }
}

#[test]
fn a_lazy_zone_keeps_what_is_present_and_asks_again_about_the_rest() {
    let (book, asked) = (Book::default(), Asked::default());
    let zone = lazy(&book, &asked);
    assert_eq!(*ZoneData::apex(&zone), lower("lazy."));

    let reply = lazy_reply(&zone, "www.lazy.", RecordType::A);
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(
        rows(&reply.authorities),
        vec![row("lazy.", RecordType::SOA)]
    );

    // Absent was not kept, so the name that now exists is found.
    put(
        &book,
        "www.lazy.",
        Fact::Present(vec![rrset("www.lazy.", 60, vec![a("10.0.0.1")])]),
    );
    let reply = lazy_reply(&zone, "www.lazy.", RecordType::A);
    assert_eq!(addresses(&reply.answers), vec!["10.0.0.1"]);
    assert_eq!(times_asked(&asked, "www.lazy."), 2);

    // Present was kept: the provider changing its mind changes nothing,
    // and it is not asked again.
    put(
        &book,
        "www.lazy.",
        Fact::Present(vec![rrset("www.lazy.", 60, vec![a("10.0.0.2")])]),
    );
    let reply = lazy_reply(&zone, "www.lazy.", RecordType::A);
    assert_eq!(addresses(&reply.answers), vec!["10.0.0.1"]);
    assert_eq!(times_asked(&asked, "www.lazy."), 2);
    // A name it holds without the type is NODATA.
    let reply = lazy_reply(&zone, "www.lazy.", RecordType::TXT);
    assert!(reply.answers.is_empty());
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
}

#[test]
fn a_lazy_view_is_one_revision_however_the_zone_grows() {
    let (book, asked) = (Book::default(), Asked::default());
    let zone = lazy(&book, &asked);
    let before = view_of(&zone, "x.lazy.", RecordType::A);
    let nxdomain = answer(
        &*before,
        &request("x.lazy.", RecordType::A, false),
        AnyResponse::All,
    );
    let Answered::Response(nxdomain) = nxdomain else {
        panic!("answered");
    };
    assert_eq!(
        nxdomain.message.metadata.response_code,
        ResponseCode::NXDomain
    );

    put(
        &book,
        "x.lazy.",
        Fact::Present(vec![rrset("x.lazy.", 60, vec![a("10.0.0.7")])]),
    );
    put(
        &book,
        "y.lazy.",
        Fact::Present(vec![rrset("y.lazy.", 60, vec![a("10.0.0.8")])]),
    );
    let after = view_of(&zone, "x.lazy.", RecordType::A);
    assert_eq!(
        addresses(&ask(&*after, "x.lazy.", RecordType::A).answers),
        vec!["10.0.0.7"]
    );
    lazy_reply(&zone, "y.lazy.", RecordType::A);

    // The earlier view still answers from its own revision.
    assert!(before.revision() < after.revision());
    assert_eq!(
        answer(
            &*before,
            &request("x.lazy.", RecordType::A, false),
            AnyResponse::All
        ),
        Answered::Response(nxdomain)
    );
}

#[test]
fn a_provider_that_changes_while_asked_gives_one_coherent_answer() {
    // Every call gives a new address, so two reads of one name would
    // disagree.
    let calls = Arc::new(Mutex::new(0u8));
    let counter = calls.clone();
    let zone = Lazy::new(
        name("lazy."),
        soa("lazy.", 60),
        rrset("lazy.", 3600, vec![ns("lazy.")]),
        3600,
        move |asked: &LowerName| {
            let mut calls = counter.lock().unwrap();
            *calls += 1;
            let address = a(&format!("10.0.0.{}", *calls));
            let owner = asked.to_string();
            match owner.as_str() {
                "www.lazy." => Fact::Present(vec![
                    rrset(&owner, 60, vec![RData::MX(MX::new(10, name("mail.lazy.")))]),
                    rrset(&owner, 60, vec![address]),
                ]),
                "mail.lazy." => Fact::Present(vec![rrset(&owner, 60, vec![address])]),
                _ => Fact::Absent,
            }
        },
    );
    let view = view_of(&zone, "www.lazy.", RecordType::MX);
    let reply = ask(&*view, "www.lazy.", RecordType::MX);
    // The MX target was asked while the view was made, and its address
    // is the one the zone kept.
    let target = addresses(&reply.additionals);
    assert_eq!(target.len(), 1);
    let kept = lazy_reply(&zone, "mail.lazy.", RecordType::A);
    assert_eq!(addresses(&kept.answers), target);
    assert_eq!(view.revision(), Revision(2));
    // Asking again reads the same view of the same facts.
    assert_eq!(ask(&*view, "www.lazy.", RecordType::MX), reply);
}

#[test]
fn an_unknown_provider_answer_is_unknown_and_not_kept() {
    let (book, asked) = (Book::default(), Asked::default());
    let zone = lazy(&book, &asked);
    put(&book, "dark.lazy.", Fact::Unknown);
    assert_eq!(
        lazy_ask(&zone, "dark.lazy.", RecordType::A),
        Answered::Unknown {
            name: lower("dark.lazy."),
            reached: lower("dark.lazy."),
        }
    );
    assert_eq!(
        lazy_ask(&zone, "below.dark.lazy.", RecordType::A),
        Answered::Unknown {
            name: lower("dark.lazy."),
            reached: lower("below.dark.lazy."),
        }
    );
    put(
        &book,
        "dark.lazy.",
        Fact::Present(vec![rrset("dark.lazy.", 60, vec![a("10.0.0.3")])]),
    );
    assert_eq!(
        addresses(&lazy_reply(&zone, "dark.lazy.", RecordType::A).answers),
        vec!["10.0.0.3"]
    );
}

#[test]
fn a_lazy_name_makes_its_ancestors_empty_non_terminals() {
    let (book, asked) = (Book::default(), Asked::default());
    let zone = lazy(&book, &asked);
    // The provider says nothing of b.lazy. but gives a.b.lazy.
    put(
        &book,
        "a.b.lazy.",
        Fact::Present(vec![rrset("a.b.lazy.", 60, vec![a("10.0.0.4")])]),
    );
    let reply = lazy_reply(&zone, "a.b.lazy.", RecordType::A);
    assert_eq!(addresses(&reply.answers), vec!["10.0.0.4"]);
    // So a question for the parent is NODATA, not NXDOMAIN.
    let reply = lazy_reply(&zone, "b.lazy.", RecordType::A);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.answers.is_empty());
}

#[test]
fn a_lazy_ns_rrset_is_a_cut_with_glue() {
    let (book, asked) = (Book::default(), Asked::default());
    let zone = lazy(&book, &asked);
    put(
        &book,
        "sub.lazy.",
        Fact::Present(vec![rrset("sub.lazy.", 60, vec![ns("ns.sub.lazy.")])]),
    );
    put(
        &book,
        "ns.sub.lazy.",
        Fact::Present(vec![rrset("ns.sub.lazy.", 60, vec![a("10.0.0.5")])]),
    );
    let view = view_of(&zone, "www.sub.lazy.", RecordType::A);
    let reply = response(&*view, "www.sub.lazy.", RecordType::A, false);
    assert!(!reply.message.metadata.authoritative);
    assert_eq!(
        rows(&reply.message.authorities),
        vec![row("sub.lazy.", RecordType::NS)]
    );
    assert_eq!(addresses(&reply.message.additionals), vec!["10.0.0.5"]);
    assert_eq!(reply.required_additional, 1);
}

#[test]
fn transparent_over_lazy_lets_absent_names_through() {
    let (book, asked) = (Book::default(), Asked::default());
    let zone = Transparent(lazy(&book, &asked));
    put(
        &book,
        "www.lazy.",
        Fact::Present(vec![rrset("www.lazy.", 60, vec![a("10.0.0.6")])]),
    );
    assert_eq!(
        addresses(&lazy_reply(&zone, "www.lazy.", RecordType::A).answers),
        vec!["10.0.0.6"]
    );
    assert_eq!(
        lazy_ask(&zone, "other.lazy.", RecordType::A),
        Answered::Unknown {
            name: lower("other.lazy."),
            reached: lower("other.lazy."),
        }
    );
}

/// A transparent zone answers only where it has RRsets, as Unbound's
/// does: a name with nothing of its own but a name below it is unknown,
/// while the names above a name with RRsets still lead down to it.
#[test]
fn transparent_leaves_empty_non_terminals_unknown() {
    let (book, asked) = (Book::default(), Asked::default());
    let zone = Transparent(lazy(&book, &asked));
    put(
        &book,
        "a.b.lazy.",
        Fact::Present(vec![rrset("a.b.lazy.", 60, vec![a("10.0.0.9")])]),
    );
    assert_eq!(
        addresses(&lazy_reply(&zone, "a.b.lazy.", RecordType::A).answers),
        vec!["10.0.0.9"]
    );
    assert_eq!(
        lazy_ask(&zone, "b.lazy.", RecordType::A),
        Answered::Unknown {
            name: lower("b.lazy."),
            reached: lower("b.lazy."),
        }
    );
    // A name with RRsets, without the asked type, is NODATA.
    let reply = lazy_reply(&zone, "a.b.lazy.", RecordType::TXT);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.answers.is_empty());
}

/// A name the provider does not know stays unknown, whatever was asked
/// below it before: it is never an empty non-terminal, so never NODATA.
#[test]
fn a_lazy_name_the_provider_does_not_know_stays_unknown_after_a_name_below_it() {
    let (book, asked) = (Book::default(), Asked::default());
    let zone = lazy(&book, &asked);
    put(&book, "a.lazy.", Fact::Unknown);
    put(
        &book,
        "www.a.lazy.",
        Fact::Present(vec![rrset("www.a.lazy.", 60, vec![a("10.0.0.1")])]),
    );
    let unknown = |reached: &str| Answered::Unknown {
        name: lower("a.lazy."),
        reached: lower(reached),
    };
    assert_eq!(
        lazy_ask(&zone, "a.lazy.", RecordType::A),
        unknown("a.lazy.")
    );
    // The walk down to the name below passes the unknown one.
    assert_eq!(
        lazy_ask(&zone, "www.a.lazy.", RecordType::A),
        unknown("www.a.lazy.")
    );
    assert_eq!(
        lazy_ask(&zone, "a.lazy.", RecordType::A),
        unknown("a.lazy.")
    );
    // Once the provider calls it absent, it is an empty non-terminal.
    put(&book, "a.lazy.", Fact::Absent);
    let reply = lazy_reply(&zone, "a.lazy.", RecordType::A);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.answers.is_empty());
    assert_eq!(
        addresses(&lazy_reply(&zone, "www.a.lazy.", RecordType::A).answers),
        vec!["10.0.0.1"]
    );
}

/// A cut whose in-domain glue the provider does not know yet is unknown,
/// and gets its glue once the provider knows it (RFC 9471 §3.1).
#[test]
fn a_lazy_cut_waits_for_its_in_domain_glue() {
    let (book, asked) = (Book::default(), Asked::default());
    let zone = lazy(&book, &asked);
    put(
        &book,
        "sub.lazy.",
        Fact::Present(vec![rrset("sub.lazy.", 60, vec![ns("ns.sub.lazy.")])]),
    );
    put(&book, "ns.sub.lazy.", Fact::Unknown);
    assert_eq!(
        lazy_ask(&zone, "www.sub.lazy.", RecordType::A),
        Answered::Unknown {
            name: lower("sub.lazy."),
            reached: lower("www.sub.lazy."),
        }
    );
    put(
        &book,
        "ns.sub.lazy.",
        Fact::Present(vec![rrset("ns.sub.lazy.", 60, vec![a("10.0.0.53")])]),
    );
    let view = view_of(&zone, "www.sub.lazy.", RecordType::A);
    let reply = response(&*view, "www.sub.lazy.", RecordType::A, false);
    assert!(!reply.message.metadata.authoritative);
    assert_eq!(
        rows(&reply.message.authorities),
        vec![row("sub.lazy.", RecordType::NS)]
    );
    assert_eq!(addresses(&reply.message.additionals), vec!["10.0.0.53"]);
    assert_eq!(reply.required_additional, 1);
}

/// The addresses of NS, MX, and SRV targets are optional additional data
/// (RFC 2181 §5.4.1, RFC 9471 §3.2). A view that does not know a target
/// still answers, without the target's addresses.
#[test]
fn an_unknown_target_leaves_out_only_its_addresses() {
    let mx = |target: &str| RData::MX(MX::new(10, name(target)));

    let shown = Shown::new(
        &name("example."),
        [rrset("example.", 300, vec![mx("mail.example.")])],
    )
    .unwrap();
    let reply = ask(
        &*view_of(&shown, "example.", RecordType::MX),
        "example.",
        RecordType::MX,
    );
    assert_eq!(rows(&reply.answers), vec![row("example.", RecordType::MX)]);
    assert!(reply.additionals.is_empty());

    let corp = Zone::builder(name("corp."), soa("corp.", 300), 3600)
        .rrset(rrset("corp.", 3600, vec![ns("ns.corp.")]))
        .rrset(rrset("ns.corp.", 3600, vec![a("192.0.2.1")]))
        .rrset(rrset("www.corp.", 3600, vec![mx("mail.corp.")]))
        .build()
        .unwrap();
    let transparent = Transparent(corp);
    let reply = ask(
        &*view_of(&transparent, "www.corp.", RecordType::MX),
        "www.corp.",
        RecordType::MX,
    );
    assert_eq!(rows(&reply.answers), vec![row("www.corp.", RecordType::MX)]);
    assert!(reply.additionals.is_empty());

    let (book, asked) = (Book::default(), Asked::default());
    let zone = lazy(&book, &asked);
    put(
        &book,
        "www.lazy.",
        Fact::Present(vec![rrset("www.lazy.", 60, vec![mx("mail.lazy.")])]),
    );
    put(&book, "mail.lazy.", Fact::Unknown);
    let reply = lazy_reply(&zone, "www.lazy.", RecordType::MX);
    assert_eq!(rows(&reply.answers), vec![row("www.lazy.", RecordType::MX)]);
    assert!(reply.additionals.is_empty());
    // The provider was still asked about the target.
    assert_eq!(times_asked(&asked, "mail.lazy."), 1);
    // Once it knows the target, the answer carries its address.
    put(
        &book,
        "mail.lazy.",
        Fact::Present(vec![rrset("mail.lazy.", 60, vec![a("10.0.0.25")])]),
    );
    let reply = lazy_reply(&zone, "www.lazy.", RecordType::MX);
    assert_eq!(addresses(&reply.additionals), vec!["10.0.0.25"]);

    // A referral whose NS target outside the cut is unknown still refers.
    put(
        &book,
        "sub.lazy.",
        Fact::Present(vec![rrset("sub.lazy.", 60, vec![ns("ns.other.lazy.")])]),
    );
    put(&book, "other.lazy.", Fact::Unknown);
    let view = view_of(&zone, "www.sub.lazy.", RecordType::A);
    let reply = response(&*view, "www.sub.lazy.", RecordType::A, false);
    assert!(!reply.message.metadata.authoritative);
    assert_eq!(
        rows(&reply.message.authorities),
        vec![row("sub.lazy.", RecordType::NS)]
    );
    assert!(reply.message.additionals.is_empty());
}

// Locally served zones.

/// Every name at or below `localhost` is the loopback host: A and AAAA
/// questions get the loopback addresses, owned by the name asked, and
/// every other type, SOA and NS included, gets NODATA, the immediate
/// negative answer RFC 6761 §6.3 asks for.
#[test]
fn localhost_points_every_name_at_loopback() {
    let zone = special::localhost(&EmptyApex::rfc6303());
    let ask = |qname: &str, qtype| ask(&*view_of(&zone, qname, qtype), qname, qtype);
    for qname in ["localhost.", "anything.below.localhost."] {
        let reply = ask(qname, RecordType::A);
        assert_eq!(addresses(&reply.answers), vec!["127.0.0.1"], "{qname}");
        assert_eq!(rows(&reply.answers), vec![row(qname, RecordType::A)]);
        let reply = ask(qname, RecordType::AAAA);
        assert_eq!(addresses(&reply.answers), vec!["::1"], "{qname}");
        for qtype in [RecordType::NS, RecordType::SOA, RecordType::MX] {
            let reply = ask(qname, qtype);
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::NoError,
                "{qname} {qtype}"
            );
            assert!(reply.metadata.authoritative, "{qname} {qtype}");
            assert!(reply.answers.is_empty(), "{qname} {qtype}");
            assert_eq!(
                rows(&reply.authorities),
                vec![row("localhost.", RecordType::SOA)],
                "{qname} {qtype}"
            );
        }
    }
}

/// `invalid` never exists, and neither does any name below it (RFC 6761
/// §6.4); a caching server answers every query for `test` and the names
/// within it negatively (RFC 6761 §6.2), and every `.onion` query with
/// NXDOMAIN (RFC 7686 §2), as it does every query for `local` and the
/// names within it (RFC 6762 §22.1). Each question gets NXDOMAIN, at the
/// apex too.
#[test]
fn invalid_onion_test_and_local_are_nxdomain_at_their_apex_too() {
    let apex = EmptyApex::rfc6303();
    for zone in [
        special::invalid(&apex),
        special::onion(&apex),
        special::test(&apex),
        special::local(&apex),
    ] {
        let apex = zone.apex().to_string();
        for qname in [apex.clone(), format!("x.{apex}")] {
            for qtype in [RecordType::A, RecordType::SOA, RecordType::NS] {
                let reply = ask(&*view_of(&zone, &qname, qtype), &qname, qtype);
                assert_eq!(
                    reply.metadata.response_code,
                    ResponseCode::NXDomain,
                    "{qname} {qtype}"
                );
                assert!(reply.answers.is_empty(), "{qname} {qtype}");
                assert_eq!(
                    rows(&reply.authorities),
                    vec![row(&apex, RecordType::SOA)],
                    "{qname} {qtype}"
                );
            }
        }
    }
}

#[test]
fn special_use_zones_are_empty_with_the_apex_they_are_given() {
    let zones = special::rfc6303(&EmptyApex::rfc6303());
    // 33 zones of RFC 6303 and the 64 of the Shared Address Space
    // (RFC 6598 §7).
    assert_eq!(zones.len(), 97);
    let find = |apex: &str| {
        zones
            .iter()
            .find(|zone| *zone.apex() == lower(apex))
            .unwrap()
    };
    for apex in [
        "10.in-addr.arpa.",
        "31.172.in-addr.arpa.",
        "168.192.in-addr.arpa.",
        "8.b.d.0.1.0.0.2.ip6.arpa.",
        "64.100.in-addr.arpa.",
        "127.100.in-addr.arpa.",
    ] {
        let zone = find(apex);
        let reply = ask(zone, &format!("5.{apex}"), RecordType::PTR);
        assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
        let RData::SOA(soa) = &reply.authorities[0].data else {
            panic!("SOA");
        };
        // The zone names itself (RFC 6303 §3).
        assert_eq!(soa.mname, name(apex));
        assert_eq!(soa.rname, name("nobody.invalid."));
        assert_eq!(
            (soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum),
            (1, 3600, 1200, 604800, 10800)
        );
        assert_eq!(reply.authorities[0].ttl, 10800);
    }
    // The reverse zone of 127.0.0.0/8 is as empty as the others.
    let reply = ask(
        find("127.in-addr.arpa."),
        "1.0.0.127.in-addr.arpa.",
        RecordType::PTR,
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);

    // Each zone takes the name server and MNAME it is given, here
    // `localhost.`, and its TTL.
    let apex = EmptyApex {
        ns: Some(name("localhost.")),
        ttl: 300,
        ..EmptyApex::rfc6303()
    };
    let zones = special::rfc6303(&apex);
    for zone in [
        special::home_arpa(&apex),
        special::service_arpa(&apex),
        special::resolver_arpa(&apex, vec![], 3600),
        zones[0].clone(),
    ] {
        let apex = zone.apex().to_string();
        let reply = ask(&zone, &format!("anything.{apex}"), RecordType::A);
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NXDomain,
            "{apex}"
        );
        let RData::SOA(soa) = &reply.authorities[0].data else {
            panic!("SOA");
        };
        assert_eq!(soa.mname, name("localhost."), "{apex}");
        assert_eq!(soa.minimum, 300, "{apex}");
        assert_eq!(reply.authorities[0].ttl, 300, "{apex}");
        let reply = ask(&zone, &apex, RecordType::NS);
        assert_eq!(reply.answers[0].data, ns("localhost."), "{apex}");
    }
}

#[test]
fn resolver_arpa_holds_the_resolvers_endpoints() {
    let endpoint = SVCB::new(1, name("dns.example."), vec![]);
    let zone = special::resolver_arpa(&EmptyApex::rfc6303(), vec![endpoint.clone()], 300);
    let reply = ask(&zone, "_dns.resolver.arpa.", RecordType::SVCB);
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(reply.answers[0].data, RData::SVCB(endpoint));
    assert_eq!(reply.answers[0].ttl, 300);
    let empty = special::resolver_arpa(&EmptyApex::rfc6303(), vec![], 300);
    let reply = ask(&empty, "_dns.resolver.arpa.", RecordType::SVCB);
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
}

#[test]
fn the_wall_clock_adds_run_time_to_its_start() {
    let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_793_570_400);
    let clock = WallClock { start };
    assert_eq!(clock.at(Instant::ZERO), start);
    let later = Instant::from_since_start(Duration::from_secs(90));
    assert_eq!(clock.at(later), start + Duration::from_secs(90));
}

// The real root zone.

#[test]
fn the_root_zone_format_reads() {
    let root = Zone::from_master(ROOT_ZONE_EXCERPT, None).unwrap();
    assert_eq!(*root.apex(), lower("."));

    // `. NS` with every root server's addresses, which the root holds as
    // glue under `net`.
    let reply = ask(&root, ".", RecordType::NS);
    assert!(reply.metadata.authoritative);
    assert_eq!(reply.answers.len(), 13);
    assert_eq!(reply.additionals.len(), 26);
    assert!(addresses(&reply.additionals).contains(&"198.41.0.4".to_string()));

    // A referral to `com`: the gTLD servers' addresses come from under
    // `net`, so they are optional sibling glue (RFC 9471 §3.2).
    let reply = response(&root, "example.com.", RecordType::A, true);
    let message = &reply.message;
    assert!(!message.metadata.authoritative);
    assert_eq!(
        message
            .authorities
            .iter()
            .filter(|r| r.record_type() == RecordType::NS)
            .count(),
        13
    );
    assert!(rows(&message.authorities).contains(&row("com.", RecordType::DS)));
    assert_eq!(message.additionals.len(), 26);
    assert_eq!(reply.required_additional, 0);
    // A referral to `net`: the same addresses, now in-domain and required.
    let reply = response(&root, "example.net.", RecordType::A, false);
    assert_eq!(reply.required_additional, 26);

    // DS at a TLD, with its RRSIG.
    let reply = ask_do(&root, "com.", RecordType::DS);
    assert_eq!(
        rows(&reply.answers),
        vec![row("com.", RecordType::DS), row("com.", RecordType::RRSIG)]
    );

    // An absent TLD: NXDOMAIN, the SOA at min(86400, 86400), and the apex
    // NSEC, which covers both `aa.` and the wildcard `*.`.
    let reply = ask_do(&root, "aa.", RecordType::A);
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(reply.authorities[0].ttl, 86400);
    assert!(rows(&reply.authorities).contains(&row(".", RecordType::NSEC)));

    // The apex holds the DNSKEY and ZONEMD RRsets with their RRSIGs.
    let Some(Node::Data(apex)) = root.node(&lower(".")) else {
        panic!("the apex is data");
    };
    assert_eq!(apex[&RecordType::DNSKEY].records_count(), 3);
    assert_eq!(apex[&RecordType::DNSKEY].rrsigs().len(), 1);
    let zonemd = &apex[&RecordType::from(63)];
    let RData::Unknown { rdata, .. } = &zonemd.records_without_rrsigs().next().unwrap().data else {
        panic!("ZONEMD is unknown to hickory");
    };
    // Serial, scheme, hash algorithm, and a SHA-384 digest (RFC 8976 §2.2).
    assert_eq!(rdata.anything.len(), 4 + 1 + 1 + 48);
    assert_eq!(&rdata.anything[..4], &2026110102u32.to_be_bytes());

    // The SOA's RRSIG reads with its dates (RFC 4034 §3.2).
    let soa = View::soa(&root);
    let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &soa.rrsigs()[0].data else {
        panic!("RRSIG");
    };
    let input = rrsig.input();
    assert_eq!(input.type_covered, RecordType::SOA);
    assert_eq!(input.key_tag, 8763);
    assert_eq!(input.sig_expiration.get(), 1_794_697_200); // 2026-11-14 23:00:00 UTC
    assert_eq!(input.sig_inception.get(), 1_793_570_400); // 2026-11-01 22:00:00 UTC
    assert_eq!(input.signer_name, Name::root());

    // A world edits it like any zone.
    let edited = root
        .with_delegation(
            name("fict."),
            rrset("fict.", 172800, vec![ns("ns.fict.")]),
            vec![rrset("ns.fict.", 172800, vec![a("192.0.2.80")])],
            None,
        )
        .unwrap();
    let reply = response(&edited, "www.fict.", RecordType::A, false);
    assert_eq!(addresses(&reply.message.additionals), vec!["192.0.2.80"]);
}

/// Lines of the root zone published at
/// https://www.internic.net/domain/root.zone (serial 2026110102, fetched
/// 2026-11-01), unchanged: the apex, `com` and `net`, the gTLD servers'
/// glue, and the root servers' glue.
const ROOT_ZONE_EXCERPT: &str = r"
.			86400	IN	SOA	a.root-servers.net. nstld.verisign-grs.com. 2026110102 1800 900 604800 86400
.			86400	IN	RRSIG	SOA 8 0 86400 20261114230000 20261101220000 8763 . sI2hYFABc0e2mCsTs0ILkeQU2UwSVxw17yVxRmHsQBePIGvu/zTgODu0t8fPugnrND0L6ajUSF5SC3gyHVjYiGw8QUwdEmovQKJkgU+TvpTq8G+OCg85so86LuHZsKWUdJ7A+oL3o2ktNwL9dFFYYDfu/DKgHo2GpVsGEKQdjHTdL3ZJ7lF+WIdnMAmS25nk/rKYuDycF0n0azre4QyIsA8AhKFW8Wrl6s599wCUXa8w2ypQ1whGIanhsgRYA/RbLOgpmuQ09LT2YucimPlwTVaBHOZehtA3YVYxECTuIfj+J6pqTQp6JPYdYphtTPxHPvMjPkAr7TszRX1uh3dY9Q==
.			518400	IN	NS	a.root-servers.net.
.			518400	IN	NS	b.root-servers.net.
.			518400	IN	NS	c.root-servers.net.
.			518400	IN	NS	d.root-servers.net.
.			518400	IN	NS	e.root-servers.net.
.			518400	IN	NS	f.root-servers.net.
.			518400	IN	NS	g.root-servers.net.
.			518400	IN	NS	h.root-servers.net.
.			518400	IN	NS	i.root-servers.net.
.			518400	IN	NS	j.root-servers.net.
.			518400	IN	NS	k.root-servers.net.
.			518400	IN	NS	l.root-servers.net.
.			518400	IN	NS	m.root-servers.net.
.			518400	IN	RRSIG	NS 8 0 518400 20261114230000 20261101220000 8763 . jUL4OCt6vAe1eDa5FjQrvCvUy1D0UK7zdbXvowV23i0UPTFftqgjKIqHg1Hb9ugHvx58P96knfllWk9iu1jPJ298AbJvPbcQyJkFinJytHpPOopMQWXuhAhIamGhlR6P8sYYW5IXZMBVzywGqQoqvSoPkdkCda/Ic7exusSUb80vZbGCz33swjiQmgD1hZtQvd6rQkEnMOy3I6vthIqpKuHC35T2NvISF6mWWAWTjhMSvtglk4DY66zrzJci4so++1NFdC1dQpPFi5zWeznU3JgyfVrZ+WWvagC39ComeApr1k1rfVe5VC9uAHAoFtZxrmpAuB9tKgMF47POvS8QEw==
.			86400	IN	NSEC	aaa. NS SOA RRSIG NSEC DNSKEY ZONEMD
.			86400	IN	RRSIG	NSEC 8 0 86400 20261114230000 20261101220000 8763 . naNFUcriMKgID+OLg7bqenQ2i76S9sAkwECEvhqluMwwqMQQm+WV0FWrb/wEPybarAMZa5irKfmbFKXv+z6q8h8YV2LZRCT6THs25eXeGFJpkFTuzeBPFY4OJdmylMbwlKMhY/5QGSG+NaenmB3BSQUse4tSyDLfK+WzonCt+W2Mhed/kqhWPYHGGihcmYJ8p2xw47quMDm5LCOJBFBtvNH4kL/+YUetO+XQUDuPTTuqbyNeSbQ9aNsYy8bphtMSpeJxwYL2c+sTr7miaq7AsXgxhU6ZbjbvVZHwNGoNZ5jV/mCk55Z0JaPKXrFU8dL6Er5Dw8fCFWLoydEDw/qbVQ==
.			172800	IN	DNSKEY	256 3 8 AwEAAcorNxNc9t0ue1ZenPjVMRujlQ2YLBJ0pR/4XMjHby9vr03cRxFSKnWpxeg5PL384D9VeqdS1bjrGyTsHtoagzI3NiXFd8sjHMOnZxu5pp/+UBIg7tasYgVMMdUiM1Yu/c+t30d1Qw/v6NYLNnOnywTu6HuUh7Y1sZRq/GZcrxLENXHQoyKpOrOr8R3+qd6wK69IKB80ZBZtkX9rdEqKJk+yYXjEZzZ0zkAFthmNgCreAoU9PVlU66dyOsaLjf3wKUlUm9SNOKs+tK6LuSmRbK6+1T/tPaRaMBSEuv2G6vXfnJ1uyMbGvtpRn/YDcvTjrp6DzE6XyF44QdwJ3oKx4ek=
.			172800	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
.			172800	IN	DNSKEY	257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=
.			172800	IN	RRSIG	DNSKEY 8 0 172800 20261121000000 20261031000000 38696 . UFkJYhexq5ZgfvP+oIz2WUJQgF8bhW8st3LnXtIBP0eRcSQXrYg7+luxwQYg+3iiZV2+BJPcNmf/pDu+uNPaplkHPJLXh9WS0oEVZKUNk/0wk3A0XL5UOSTdPWn/IoTWWxyGxun+udV7eRQqVpRvSdlBFaqPWSDIDkX0QQIfye72TB4tsPBnA2iWDye6U157EcPBdNeKv4cfh1cAOlePIaxLs1NoNHIu/ZrqEY5zM+GNJ4Z72Tba09jYjz3ayBSPVinI64OYOORqZsYtuLXUrBdD6UWfV8Ljf3b0MGfBs7BoZYAJxVyNr5CQF13CLw+4xrbMsmQWdTBqzp5iEtB9VA==
.			86400	IN	ZONEMD	2026110102 1 1 3BD07D0C5820F3E93F32D9F8A07AB603C62197601A086B1F230CD927FA7DAD4586952E752493C6CA619E81D2E0C7FD4B
.			86400	IN	RRSIG	ZONEMD 8 0 86400 20261114230000 20261101220000 8763 . kBw9sYP8jcH5Qh/QNkxuUyeSxp4lrZWSUyQJ3yblNcskQwit0F/AwxbInXfgqJztkzYzL7TP+Ez9fl/TFh0fI2jGKC57i/eD8Zh861jN8VFZPVFtsiOoEZzYm1J+wbIkuvjKdoKjxy9F67pWmy/eHB4Lb8Sr/yQ1R+8c1R/k2nwVHD1GeDQoBQcWnyfuyy4/kiSNcdvtbsecPGAfhiGtXkcvfgzCyc+7D6hyXdrNylKRRhi0H25riWWLIEf5w3TTw/utT5wxdww4NJC2v8ng+pPx4rOSRJ0R3hDUoaNND7IJgoROp9+rgy90Td1zQomYe4TjJpBEKVNkNxoqYbhhZg==
com.			172800	IN	NS	a.gtld-servers.net.
com.			172800	IN	NS	b.gtld-servers.net.
com.			172800	IN	NS	c.gtld-servers.net.
com.			172800	IN	NS	d.gtld-servers.net.
com.			172800	IN	NS	e.gtld-servers.net.
com.			172800	IN	NS	f.gtld-servers.net.
com.			172800	IN	NS	g.gtld-servers.net.
com.			172800	IN	NS	h.gtld-servers.net.
com.			172800	IN	NS	i.gtld-servers.net.
com.			172800	IN	NS	j.gtld-servers.net.
com.			172800	IN	NS	k.gtld-servers.net.
com.			172800	IN	NS	l.gtld-servers.net.
com.			172800	IN	NS	m.gtld-servers.net.
com.			86400	IN	DS	19718 13 2 8ACBB0CD28F41250A80A491389424D341522D946B0DA0C0291F2D3D771D7805A
com.			86400	IN	RRSIG	DS 8 1 86400 20261114230000 20261101220000 8763 . jekZymhuhymID4v2y+prq+rXq5R7AD0Y2oVDDuIY41FwCgdNDbBg2vgkGBVDsuntKTEbK7W2XVGCMsZT7IBfplrSK/3tpeG3TOc6fh8T8jf2gUqgmFzBolTrxStlff3YZmRvE4ee1OTn6MD06q38T3LmyUqZGoIw5RjWzAlLznYl8YB6Os5YVikINXxZfZKCxaJK1OVUAJVnxkJF7Y2LKG8P+Ee1SUOeY7Rv32Kkz5w5A4UD/Jxox0L3y+Edfy/AdOLLYZIYGdMdO1U7TPfVh4dWPZIGJPkfHd/3mrx1uh73PW+QW1+FdpeBk2OP7xsXNDjtgIp3ZC2GMO/1g0ELxg==
com.			86400	IN	NSEC	commbank. NS DS RRSIG NSEC
com.			86400	IN	RRSIG	NSEC 8 1 86400 20261114230000 20261101220000 8763 . CBd1CNWjtDAyT3wON+HNeecJPNYI3t97yLglgwT9eRosdzIEIv4auOqw2615vhDQB2PjFGs9VYeO+L7f3O7JdEXIDJlusdOGmQ7VMUw2z2/qtD4Qd18ZIbRLav73NCQyyBgSoGOW81N88y+1hFKnDLGdu0JdNS206uK4+Gj6706y3BQmyoEtts9H2SxVRnnaCwf9lTVMlJM/Hui2UUIpUL3NOYSUtIsPuBOjFb2pd4HixhqiiSdzM0TVG/A11EbjRLcPEgdM5QaD8FbaBl5GSXXwRxoGUR4Pqk6A4hFE0A2Ugv+VrElMqGFIiHDnj7VUVCn8gMVOrTIksGRd5H857Q==
net.			172800	IN	NS	a.gtld-servers.net.
net.			172800	IN	NS	b.gtld-servers.net.
net.			172800	IN	NS	c.gtld-servers.net.
net.			172800	IN	NS	d.gtld-servers.net.
net.			172800	IN	NS	e.gtld-servers.net.
net.			172800	IN	NS	f.gtld-servers.net.
net.			172800	IN	NS	g.gtld-servers.net.
net.			172800	IN	NS	h.gtld-servers.net.
net.			172800	IN	NS	i.gtld-servers.net.
net.			172800	IN	NS	j.gtld-servers.net.
net.			172800	IN	NS	k.gtld-servers.net.
net.			172800	IN	NS	l.gtld-servers.net.
net.			172800	IN	NS	m.gtld-servers.net.
net.			86400	IN	DS	37331 13 2 2F0BEC2D6F79DFBD1D08FD21A3AF92D0E39A4B9EF1E3F4111FFF282490DA453B
net.			86400	IN	RRSIG	DS 8 1 86400 20261114230000 20261101220000 8763 . UAUZeQqmNGDsghSbdiShLgKbKt2u6hVBbMv9IHZGcNv1BcSuEoPNPUjIWB4vdDE/zBNFKzy0ATzCb5IUHC8kCzRXqxCyKQq/qdVGAhSp/PZ454uXNenO59BV4HchYSaVI5Fb1QSsijowORpTCFTZMTTQb7IcgLZQlBVZcttQVNp12UnMGyHpUxmgiEPEDLydniMkEbfMQDfPOyzMKNreFaBpHsed/6fpjgsR3Z0OmgHSiUDEFHogJW98C3ExxG8n6+Eh6SigehzOvfvwOXLcaz9wSpB9WGaOf7GziMTT26Ez8rNrmtJyA8NeV6kvDIX4TELFYX+5kef6+yw+uzRTvA==
net.			86400	IN	NSEC	netbank. NS DS RRSIG NSEC
net.			86400	IN	RRSIG	NSEC 8 1 86400 20261114230000 20261101220000 8763 . Y+Ec/xJD5Yun0Ulq3gDwlrCj9z3f1ryrjM2VtgtPrSbLUctHQBc4QPaKDMnQYosHtJJh3ZM6vEnimbPsULO2uKYk2yGSxmPYDVPAALCP19gHJ28r160WgBhQJvKGfii45DhOF7XwmucO1gb1ZFVDXVXz5s4URTzs6ZcNiz0mX5mVGIJskxEg/OXx7QwWYYPnhV6uob6w0Gt1lkuNIITlqN/r2pUkcuMKzuw0dPIJzT5uAPW7sNdl6JY4exqUbHTSExCOgield1vkFt4Uyu1aAaZYSx16gJHWJVEvPkb7gkVfdZvt0/wlsfNSbFxFp7cVlvQz5mCrcSIHUjuVa2Wx2A==
a.gtld-servers.net.	172800	IN	A	192.5.6.30
a.gtld-servers.net.	172800	IN	AAAA	2001:503:a83e:0:0:0:2:30
b.gtld-servers.net.	172800	IN	A	192.33.14.30
b.gtld-servers.net.	172800	IN	AAAA	2001:503:231d:0:0:0:2:30
c.gtld-servers.net.	172800	IN	A	192.26.92.30
c.gtld-servers.net.	172800	IN	AAAA	2001:503:83eb:0:0:0:0:30
d.gtld-servers.net.	172800	IN	A	192.31.80.30
d.gtld-servers.net.	172800	IN	AAAA	2001:500:856e:0:0:0:0:30
e.gtld-servers.net.	172800	IN	A	192.12.94.30
e.gtld-servers.net.	172800	IN	AAAA	2001:502:1ca1:0:0:0:0:30
f.gtld-servers.net.	172800	IN	A	192.35.51.30
f.gtld-servers.net.	172800	IN	AAAA	2001:503:d414:0:0:0:0:30
g.gtld-servers.net.	172800	IN	A	192.42.93.30
g.gtld-servers.net.	172800	IN	AAAA	2001:503:eea3:0:0:0:0:30
h.gtld-servers.net.	172800	IN	A	192.54.112.30
h.gtld-servers.net.	172800	IN	AAAA	2001:502:8cc:0:0:0:0:30
i.gtld-servers.net.	172800	IN	A	192.43.172.30
i.gtld-servers.net.	172800	IN	AAAA	2001:503:39c1:0:0:0:0:30
j.gtld-servers.net.	172800	IN	A	192.48.79.30
j.gtld-servers.net.	172800	IN	AAAA	2001:502:7094:0:0:0:0:30
k.gtld-servers.net.	172800	IN	A	192.52.178.30
k.gtld-servers.net.	172800	IN	AAAA	2001:503:d2d:0:0:0:0:30
l.gtld-servers.net.	172800	IN	A	192.41.162.30
l.gtld-servers.net.	172800	IN	AAAA	2001:500:d937:0:0:0:0:30
m.gtld-servers.net.	172800	IN	A	192.55.83.30
m.gtld-servers.net.	172800	IN	AAAA	2001:501:b1f9:0:0:0:0:30
a.root-servers.net.	518400	IN	A	198.41.0.4
a.root-servers.net.	518400	IN	AAAA	2001:503:ba3e:0:0:0:2:30
b.root-servers.net.	518400	IN	A	170.247.170.2
b.root-servers.net.	518400	IN	AAAA	2801:1b8:10:0:0:0:0:b
c.root-servers.net.	518400	IN	A	192.33.4.12
c.root-servers.net.	518400	IN	AAAA	2001:500:2:0:0:0:0:c
d.root-servers.net.	518400	IN	A	199.7.91.13
d.root-servers.net.	518400	IN	AAAA	2001:500:2d:0:0:0:0:d
e.root-servers.net.	518400	IN	A	192.203.230.10
e.root-servers.net.	518400	IN	AAAA	2001:500:a8:0:0:0:0:e
f.root-servers.net.	518400	IN	A	192.5.5.241
f.root-servers.net.	518400	IN	AAAA	2001:500:2f:0:0:0:0:f
g.root-servers.net.	518400	IN	A	192.112.36.4
g.root-servers.net.	518400	IN	AAAA	2001:500:12:0:0:0:0:d0d
h.root-servers.net.	518400	IN	A	198.97.190.53
h.root-servers.net.	518400	IN	AAAA	2001:500:1:0:0:0:0:53
i.root-servers.net.	518400	IN	A	192.36.148.17
i.root-servers.net.	518400	IN	AAAA	2001:7fe:0:0:0:0:0:53
j.root-servers.net.	518400	IN	A	192.58.128.30
j.root-servers.net.	518400	IN	AAAA	2001:503:c27:0:0:0:2:30
k.root-servers.net.	518400	IN	A	193.0.14.129
k.root-servers.net.	518400	IN	AAAA	2001:7fd:0:0:0:0:0:1
l.root-servers.net.	518400	IN	A	199.7.83.42
l.root-servers.net.	518400	IN	AAAA	2001:500:9f:0:0:0:0:42
m.root-servers.net.	518400	IN	A	202.12.27.33
m.root-servers.net.	518400	IN	AAAA	2001:dc3:0:0:0:0:0:35
";
