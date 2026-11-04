//! The authoritative engine driven directly with inputs: the server
//! front's header and EDNS rules, CHAOS answers, refusals, lookups of what
//! an authority lacks, completions that must change nothing, sessions,
//! overlays, unknown facts, and the order of events and actions.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fictionet::stdlib::protocols::dns::dnssec::rdata::{DNSSECRData, NSEC3};
use fictionet::stdlib::protocols::dns::dnssec::{
    Algorithm, DigestType, KeyFlags, Nsec3HashAlgorithm, Sign, Validation, Window, ZoneKey, ds,
    sign,
};
use fictionet::stdlib::protocols::dns::op::{
    Edns, Message, MessageType, OpCode, Query, ResponseCode,
};
use fictionet::stdlib::protocols::dns::rr::rdata::opt::EdnsOption;
use fictionet::stdlib::protocols::dns::rr::rdata::{A, CNAME, NS, SOA, TXT};
use fictionet::stdlib::protocols::dns::rr::{
    DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::protocols::dns::{Ede, EdeCode, Nsid, Request, Response};
use fictionet::stdlib::services::dns::authority::{
    Authority, AuthorityEngine, ChaosZone, Identity, Observe, Overlay, ServerConfig, Step, Zones,
    bare_reply,
};
use fictionet::stdlib::services::dns::zone::{Fact, Lazy, Transparent, Zone, ZoneData};
use fictionet::stdlib::services::dns::{
    Action, Client, ClientQuery, Engine, Event, ExchangeFailure, Generation, Input, Looked, Lookup,
    Session, Token, Unmatched, WallClock,
};
use fictionet::stdlib::services::serve::Transport;
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};
use fictionet_extras::dns::place::Place;
use fictionet_extras::dns::public::PUBLIC_RESOLVERS;
use fictionet_extras::dns::roots::gtld_front;
use fictionet_extras::dns::unbound;
use fictionet_extras::dns::{bind, chaos};
use fictionet_test_support::lookup_authority::LookupAuthority;

/// The server the engines under test run at.
const LOCAL: &str = "192.0.2.53:53";

fn local() -> SocketAddr {
    LOCAL.parse().unwrap()
}

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
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

fn soa(apex: &str) -> SOA {
    SOA::new(
        name(&format!("ns1.{apex}")),
        name(&format!("hostmaster.{apex}")),
        1,
        7200,
        3600,
        1209600,
        300,
    )
}

/// `example.test.` with `www` and its name server `ns1` at 192.0.2.1.
fn example() -> Zone {
    Zone::builder(name("example.test."), soa("example.test."), 3600)
        .rrset(rrset("example.test.", 3600, vec![ns("ns1.example.test.")]))
        .rrset(rrset("ns1.example.test.", 3600, vec![a("192.0.2.1")]))
        .rrset(rrset("www.example.test.", 300, vec![a("192.0.2.10")]))
        .build()
        .unwrap()
}

fn zones(zones: Vec<Zone>) -> Zones {
    Zones::new(
        zones
            .into_iter()
            .map(|zone| Arc::new(zone) as Arc<dyn ZoneData>)
            .collect(),
    )
}

fn client(transport: Transport) -> Client {
    Client {
        peer: "198.51.100.7:40000".parse().unwrap(),
        local: local(),
        transport,
        connection: None,
        sandbox: None,
    }
}

/// A query for `qname` `qtype` with ID 0x1234, changed by `change`.
fn query(qname: &str, qtype: RecordType, change: impl FnOnce(&mut Message)) -> Message {
    let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(name(qname), qtype));
    change(&mut message);
    message
}

fn edns(payload: u16, dnssec_ok: bool) -> Edns {
    let mut edns = Edns::new();
    edns.set_max_payload(payload).set_dnssec_ok(dnssec_ok);
    edns
}

fn entropy() -> SeededEntropy {
    SeededEntropy::new(Seed::from_u64(1))
}

/// Hands `input` to `engine` at `now` and drains what it queued.
fn run(engine: &mut impl Engine, input: Input, now: Instant) -> Vec<Action> {
    engine.handle(input, now, &entropy());
    std::iter::from_fn(|| engine.poll()).collect()
}

fn ask_with(engine: &mut impl Engine, message: &Message, transport: Transport) -> Vec<Action> {
    let input = Input::Query(ClientQuery {
        client: client(transport),
        bytes: message.to_vec().unwrap(),
    });
    run(engine, input, Instant::ZERO)
}

/// The answers among `actions`, decoded.
fn answers(actions: &[Action]) -> Vec<Message> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Answer(answer) => Some(Message::from_vec(&answer.bytes).unwrap()),
            _ => None,
        })
        .collect()
}

/// The one answer among `actions`.
fn the_answer(actions: &[Action]) -> Message {
    let mut all = answers(actions);
    assert_eq!(all.len(), 1, "one answer in {actions:?}");
    all.remove(0)
}

fn answer_bytes(actions: &[Action]) -> Vec<u8> {
    let bytes: Vec<&Vec<u8>> = actions
        .iter()
        .filter_map(|action| match action {
            Action::Answer(answer) => Some(&answer.bytes),
            _ => None,
        })
        .collect();
    assert_eq!(bytes.len(), 1, "one answer in {actions:?}");
    bytes[0].clone()
}

/// The lookups among `actions`, with their tokens.
fn lookups(actions: &[Action]) -> Vec<(Token, Lookup)> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Lookup { token, lookup } => Some((*token, lookup.clone())),
            _ => None,
        })
        .collect()
}

fn abandoned(actions: &[Action]) -> Vec<Token> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Abandon(token) => Some(*token),
            _ => None,
        })
        .collect()
}

fn ignored(actions: &[Action]) -> Vec<Unmatched> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Event(Event::Ignored { why, .. }) => Some(*why),
            _ => None,
        })
        .collect()
}

/// A short name for each action, in order.
fn kinds(actions: &[Action]) -> Vec<&'static str> {
    actions
        .iter()
        .map(|action| match action {
            Action::Send(_) => "send",
            Action::Lookup { .. } => "lookup",
            Action::Answer(_) => "answer",
            Action::Abandon(_) => "abandon",
            Action::Event(Event::Query { .. }) => "query",
            Action::Event(Event::Reply { .. }) => "reply",
            Action::Event(Event::Looked { .. }) => "looked",
            Action::Event(Event::Ignored { .. }) => "ignored",
            Action::Event(Event::Upstream { .. }) => "upstream",
        })
        .collect()
}

fn edes(message: &Message) -> Vec<EdeCode> {
    message
        .edns
        .iter()
        .flat_map(|edns| edns.options().as_ref())
        .filter_map(|(_, option)| Ede::from_option(option))
        .map(|ede| ede.code)
        .collect()
}

fn nsid(message: &Message) -> Option<Nsid> {
    message
        .edns
        .iter()
        .flat_map(|edns| edns.options().as_ref())
        .find_map(|(_, option)| Nsid::from_option(option))
}

/// The octets of the question in a message: after the 12-octet header, up
/// to and including QTYPE and QCLASS.
fn question_octets(bytes: &[u8]) -> &[u8] {
    let mut end = 12;
    while bytes[end] != 0 {
        end += usize::from(bytes[end]) + 1;
    }
    &bytes[12..end + 5]
}

/// What a lookup gave, as the engine's input.
fn looked(token: Token, looked: Looked) -> Input {
    Input::Looked { token, looked }
}

/// What a real server of the zone answers to `lookup`: its question, AA
/// set, an OPT record with DO, and the records `build` adds.
fn real_response(lookup: &Lookup, build: impl FnOnce(&mut Message)) -> Looked {
    let mut message = Message::response(0x4242, OpCode::Query);
    message.metadata.authoritative = true;
    message.add_query(lookup.question.clone());
    message.set_edns(edns(1232, true));
    build(&mut message);
    Looked::Response(message)
}

/// An authority that counts its calls and answers SERVFAIL.
struct Counting(Arc<AtomicUsize>);

impl Authority for Counting {
    fn respond(
        &self,
        req: &Request,
        _local: SocketAddr,
        _server: &ServerConfig,
        _client: &Client,
    ) -> Step {
        self.0.fetch_add(1, Ordering::SeqCst);
        Step::Reply(bare_reply(req, ResponseCode::ServFail, None))
    }
}

/// A server of `example.test.` that knows only what its lookups of the
/// real server at its own address gave it.
fn lookup_engine() -> AuthorityEngine<LookupAuthority> {
    AuthorityEngine::new(
        LookupAuthority::new("example.test."),
        ServerConfig::generic(),
        local(),
    )
}

/// The lookup a server at [`LOCAL`] makes of `qname` and `qtype`
/// for the zone at `zone`.
fn lookup_of(zone: &str, qname: &str, qtype: RecordType) -> Lookup {
    Lookup::new(
        local(),
        LowerName::new(&name(zone)),
        &Query::query(name(qname), qtype),
    )
}

fn session(generation: u64) -> Session {
    Session {
        generation: Generation(generation),
        clock: WallClock {
            start: SystemTime::UNIX_EPOCH,
        },
    }
}

// The server front.

#[test]
fn the_front_sets_the_header_and_echoes_the_question_case() {
    let mut engine = AuthorityEngine::new(zones(vec![example()]), ServerConfig::generic(), local());
    let message = query("WwW.ExAmPlE.TeSt.", RecordType::A, |m| {
        m.metadata.recursion_desired = true;
        m.metadata.checking_disabled = true;
        m.metadata.authentic_data = true;
    });
    let sent = message.to_vec().unwrap();
    let bytes = answer_bytes(&ask_with(&mut engine, &message, Transport::Udp));
    let reply = Message::from_vec(&bytes).unwrap();

    assert_eq!(reply.metadata.id, 0x1234);
    assert_eq!(reply.metadata.message_type, MessageType::Response);
    assert_eq!(reply.metadata.op_code, OpCode::Query);
    assert!(reply.metadata.authoritative);
    assert!(reply.metadata.recursion_desired);
    assert!(reply.metadata.checking_disabled);
    assert!(!reply.metadata.recursion_available);
    assert!(!reply.metadata.authentic_data);
    assert!(!reply.metadata.truncation);
    // Z, the bit between RA and AD, is clear.
    assert_eq!(bytes[3] & 0x40, 0);
    assert_eq!(question_octets(&bytes), question_octets(&sent));
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(reply.answers[0].name.to_string(), "WwW.ExAmPlE.TeSt.");
    // No OPT record, since the query had none (RFC 6891 §7).
    assert!(reply.edns.is_none());
}

#[test]
fn the_front_zeroes_unknown_edns_flags_and_copies_do() {
    let mut server = ServerConfig::generic();
    server.identity = Identity {
        nsid: Some(b"sjc05".to_vec()),
        ..Identity::none()
    };
    let mut engine = AuthorityEngine::new(zones(vec![example()]), server, local());
    for dnssec_ok in [false, true] {
        let message = query("www.example.test.", RecordType::A, |m| {
            let mut edns = edns(4096, dnssec_ok);
            // Unknown flag bits, the ednscomp `ednsflags` test.
            edns.flags_mut().z = 0x4000;
            // An unknown option and a client cookie, neither echoed.
            edns.options_mut()
                .insert(EdnsOption::Unknown(65001, vec![1, 2, 3]));
            edns.options_mut()
                .insert(EdnsOption::Unknown(10, vec![9; 8]));
            m.set_edns(edns);
        });
        let reply = the_answer(&ask_with(&mut engine, &message, Transport::Udp));
        let opt = reply.edns.expect("an OPT record, since the query had one");
        assert_eq!(opt.version(), 0);
        assert_eq!(opt.max_payload(), 1232);
        assert_eq!(opt.flags().dnssec_ok, dnssec_ok);
        assert_eq!(opt.flags().z, 0);
        assert!(opt.options().as_ref().is_empty(), "{:?}", opt.options());
    }
}

#[test]
fn nsid_goes_out_only_when_asked() {
    let mut server = ServerConfig::generic();
    server.identity = Identity {
        nsid: Some(b"sjc05".to_vec()),
        ..Identity::none()
    };
    let mut engine = AuthorityEngine::new(zones(vec![example()]), server, local());

    let plain = query("www.example.test.", RecordType::A, |m| {
        m.set_edns(edns(1232, false));
    });
    assert_eq!(
        nsid(&the_answer(&ask_with(&mut engine, &plain, Transport::Udp))),
        None
    );

    let asking = query("www.example.test.", RecordType::A, |m| {
        let mut edns = edns(1232, false);
        edns.options_mut().insert(Nsid(Vec::new()).to_option());
        m.set_edns(edns);
    });
    assert_eq!(
        nsid(&the_answer(&ask_with(&mut engine, &asking, Transport::Udp))),
        Some(Nsid(b"sjc05".to_vec()))
    );

    // Without an OPT record in the query there is no OPT to carry it.
    let bare = query("www.example.test.", RecordType::A, |_| {});
    assert!(
        the_answer(&ask_with(&mut engine, &bare, Transport::Udp))
            .edns
            .is_none()
    );
}

#[test]
fn a_query_without_opt_gets_no_opt_even_with_an_error() {
    let mut engine = AuthorityEngine::new(zones(vec![example()]), ServerConfig::generic(), local());
    let outside = query("www.other.test.", RecordType::A, |_| {});
    let reply = the_answer(&ask_with(&mut engine, &outside, Transport::Udp));
    assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
    assert!(reply.edns.is_none());
}

#[test]
fn outside_every_zone_is_refused_with_ede_20() {
    let outside = query("www.other.test.", RecordType::A, |m| {
        m.set_edns(edns(1232, false));
    });
    let mut engine = AuthorityEngine::new(zones(vec![example()]), ServerConfig::generic(), local());
    let reply = the_answer(&ask_with(&mut engine, &outside, Transport::Udp));
    assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
    assert!(!reply.metadata.authoritative);
    assert_eq!(edes(&reply), vec![EdeCode::NOT_AUTHORITATIVE]);

    let mut quiet = ServerConfig::generic();
    quiet.ede = false;
    let mut engine = AuthorityEngine::new(zones(vec![example()]), quiet, local());
    let reply = the_answer(&ask_with(&mut engine, &outside, Transport::Udp));
    assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
    assert!(edes(&reply).is_empty());
    assert!(reply.edns.is_some());
}

/// An answer to QCLASS * can never be authoritative (RFC 1034 §3.7.1):
/// zones answer it FORMERR without AA, as BIND 9.20 does, for a name
/// that exists and one that does not.
#[test]
fn qclass_any_gets_formerr_without_aa() {
    let mut engine = AuthorityEngine::new(zones(vec![example()]), ServerConfig::generic(), local());
    for qname in ["www.example.test.", "nx.example.test."] {
        let any = query(qname, RecordType::A, |m| {
            m.queries[0].set_query_class(DNSClass::ANY);
        });
        let reply = the_answer(&ask_with(&mut engine, &any, Transport::Udp));
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::FormErr,
            "{qname}"
        );
        assert!(!reply.metadata.authoritative, "{qname}");
        assert!(reply.answers.is_empty(), "{qname}");
        assert!(reply.authorities.is_empty(), "{qname}");
    }
}

/// TSIG and TKEY are meta-types, records of the one message they travel
/// in and never data to ask for (RFC 6895 §3.1): a question for either
/// gets FORMERR, as one for OPT does and as BIND 9.20 answers, never a
/// NODATA a resolver could cache.
#[test]
fn meta_qtypes_get_formerr() {
    let mut engine = AuthorityEngine::new(zones(vec![example()]), ServerConfig::generic(), local());
    for qtype in [RecordType::TSIG, RecordType::from(249), RecordType::OPT] {
        let meta = query("example.test.", qtype, |m| {
            m.set_edns(edns(1232, true));
        });
        let reply = the_answer(&ask_with(&mut engine, &meta, Transport::Udp));
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::FormErr,
            "{qtype}"
        );
        assert!(!reply.metadata.authoritative, "{qtype}");
        assert!(reply.authorities.is_empty(), "{qtype}");
    }
}

#[test]
fn ds_at_a_hosted_child_is_answered_from_the_parent() {
    let key = ZoneKey::generate(&entropy(), Algorithm::Ed25519, KeyFlags::KSK);
    let ds = RData::DNSSEC(DNSSECRData::DS(ds(
        &name("example.test."),
        &key.dnskey(),
        DigestType::Sha256,
    )));
    let parent = Zone::builder(name("test."), soa("test."), 3600)
        .rrset(rrset("test.", 3600, vec![ns("ns1.test.")]))
        .rrset(rrset("ns1.test.", 3600, vec![a("192.0.2.2")]))
        .delegate(
            name("example.test."),
            rrset("example.test.", 3600, vec![ns("ns1.example.test.")]),
            vec![rrset("ns1.example.test.", 3600, vec![a("192.0.2.1")])],
            Some(rrset("example.test.", 3600, vec![ds])),
        )
        .build()
        .unwrap();
    let mut engine = AuthorityEngine::new(
        zones(vec![parent, example()]),
        ServerConfig::generic(),
        local(),
    );
    let reply = the_answer(&ask_with(
        &mut engine,
        &query("example.test.", RecordType::DS, |_| {}),
        Transport::Udp,
    ));
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(reply.answers[0].record_type(), RecordType::DS);

    // Every other type at the child's apex is the child's.
    let reply = the_answer(&ask_with(
        &mut engine,
        &query("example.test.", RecordType::NS, |_| {}),
        Transport::Udp,
    ));
    assert!(reply.metadata.authoritative);
    assert_eq!(reply.answers[0].record_type(), RecordType::NS);
}

/// A server for a zone and its grandparent, but not its parent, answers
/// DS at the zone's apex with NODATA from the zone itself (RFC 4035
/// §3.1.4.1), not with the grandparent's referral to the parent.
#[test]
fn ds_at_a_hosted_zone_whose_parent_is_not_hosted_is_nodata_from_the_zone() {
    let grandparent = Zone::builder(name("test."), soa("test."), 3600)
        .rrset(rrset("test.", 3600, vec![ns("ns1.test.")]))
        .rrset(rrset("ns1.test.", 3600, vec![a("192.0.2.2")]))
        .delegate(
            name("sub.test."),
            rrset("sub.test.", 3600, vec![ns("ns1.sub.test.")]),
            vec![rrset("ns1.sub.test.", 3600, vec![a("192.0.2.3")])],
            None,
        )
        .build()
        .unwrap();
    let child = Zone::builder(name("example.sub.test."), soa("example.sub.test."), 3600)
        .rrset(rrset(
            "example.sub.test.",
            3600,
            vec![ns("ns1.example.sub.test.")],
        ))
        .rrset(rrset("ns1.example.sub.test.", 3600, vec![a("192.0.2.1")]))
        .build()
        .unwrap();
    let mut engine = AuthorityEngine::new(
        zones(vec![grandparent, child]),
        ServerConfig::generic(),
        local(),
    );
    let reply = the_answer(&ask_with(
        &mut engine,
        &query("example.sub.test.", RecordType::DS, |_| {}),
        Transport::Udp,
    ));
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.metadata.authoritative);
    assert!(reply.answers.is_empty());
    assert_eq!(reply.authorities.len(), 1);
    assert_eq!(reply.authorities[0].record_type(), RecordType::SOA);
    assert_eq!(reply.authorities[0].name, name("example.sub.test."));
}

#[test]
fn a_referral_carries_the_address_its_zone_holds_for_a_name_server() {
    // RFC 1034 §4.3.2 step 3b: the addresses available go in the
    // additional section, the zone's own data as well as glue.
    let zone = Zone::builder(name("example."), soa("example."), 3600)
        .rrset(rrset("example.", 3600, vec![ns("ns.example.")]))
        .rrset(rrset("ns.example.", 3600, vec![a("192.0.2.1")]))
        .delegate(
            name("child.example."),
            rrset("child.example.", 3600, vec![ns("ns.example.")]),
            vec![],
            None,
        )
        .build()
        .unwrap();
    let mut engine = AuthorityEngine::new(zones(vec![zone]), ServerConfig::generic(), local());
    let reply = the_answer(&ask_with(
        &mut engine,
        &query("www.child.example.", RecordType::A, |_| {}),
        Transport::Udp,
    ));
    assert!(!reply.metadata.authoritative);
    assert_eq!(reply.authorities[0].record_type(), RecordType::NS);
    assert_eq!(reply.additionals.len(), 1, "{reply}");
    assert_eq!(reply.additionals[0].name, name("ns.example."));
    assert_eq!(reply.additionals[0].data, a("192.0.2.1"));
}

#[test]
fn an_unknown_fact_gives_servfail_never_a_negative() {
    let unknown = Lazy::new(
        name("lazy.test."),
        soa("lazy.test."),
        rrset("lazy.test.", 3600, vec![ns("lazy.test.")]),
        3600,
        |_: &LowerName| Fact::Unknown,
    );
    let mut engine = AuthorityEngine::new(
        Zones::new(vec![Arc::new(unknown)]),
        ServerConfig::generic(),
        local(),
    );
    let reply = the_answer(&ask_with(
        &mut engine,
        &query("www.lazy.test.", RecordType::A, |_| {}),
        Transport::Udp,
    ));
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert!(reply.answers.is_empty());
    assert!(reply.authorities.is_empty());
}

// CHAOS.

#[test]
fn chaos_questions_are_answered_from_the_identitys_data() {
    let calls = Arc::new(AtomicUsize::new(0));
    let identity = Identity {
        unlisted: ResponseCode::ServFail,
        ..Identity::none()
    }
    .zone(chaos::txt(&chaos::id_server(), 60, "sjc07"))
    .rcode(chaos::version_bind(), ResponseCode::Refused);
    let server = ServerConfig {
        identity,
        ..ServerConfig::generic()
    };
    let mut engine = AuthorityEngine::new(Counting(calls.clone()), server, local());
    let mut ask = |qname: &str, qtype: RecordType| {
        let message = query(qname, qtype, |m| {
            m.queries[0].set_query_class(DNSClass::CH);
            m.set_edns(Edns::new());
        });
        the_answer(&ask_with(&mut engine, &message, Transport::Udp))
    };

    // The text, with AA set, in the question's case.
    let reply = ask("ID.Server.", RecordType::TXT);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.metadata.authoritative);
    assert_eq!(reply.answers.len(), 1);
    let record = &reply.answers[0];
    assert_eq!(record.name.to_string(), "ID.Server.");
    assert_eq!(record.dns_class, DNSClass::CH);
    assert_eq!(record.ttl, 60);
    assert_eq!(record.data, RData::TXT(TXT::new(vec!["sjc07".to_string()])));
    // Every reply to a query with an OPT record has one, with the
    // server's payload (RFC 6891 §7).
    assert_eq!(reply.edns.map(|edns| edns.max_payload()), Some(1232));

    // Another type at the name is NODATA, and a name below it NXDOMAIN,
    // both without an SOA, since the zone has none.
    for (qname, qtype, rcode) in [
        ("id.server.", RecordType::A, ResponseCode::NoError),
        ("id.server.", RecordType::SOA, ResponseCode::NoError),
        ("foo.id.server.", RecordType::TXT, ResponseCode::NXDomain),
    ] {
        let reply = ask(qname, qtype);
        assert_eq!(reply.metadata.response_code, rcode, "{qname} {qtype}");
        assert!(reply.metadata.authoritative, "{qname} {qtype}");
        assert!(reply.answers.is_empty(), "{qname} {qtype}");
        assert!(reply.authorities.is_empty(), "{qname} {qtype}");
    }

    // A name with an RCODE of its own gets it for every type, and an
    // unlisted name gets the identity's, all without AA.
    for (qname, qtype, rcode) in [
        ("version.bind.", RecordType::TXT, ResponseCode::Refused),
        ("version.bind.", RecordType::A, ResponseCode::Refused),
        ("hostname.bind.", RecordType::TXT, ResponseCode::ServFail),
        ("hostname.bind.", RecordType::A, ResponseCode::ServFail),
    ] {
        let reply = ask(qname, qtype);
        assert_eq!(reply.metadata.response_code, rcode, "{qname} {qtype}");
        assert!(!reply.metadata.authoritative, "{qname} {qtype}");
        assert!(reply.answers.is_empty(), "{qname} {qtype}");
        assert!(reply.edns.is_some(), "{qname} {qtype}");
    }

    // The IN lookup never sees a CHAOS question.
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// An RCODE for a name is for that name alone, and a name below a zone is
/// answered from the deepest zone above it.
#[test]
fn chaos_zones_nest_and_rcodes_name_one_name() {
    let identity = Identity::none()
        .zone(chaos::txt(&LowerName::new(&name("server.")), 0, "outer"))
        .zone(chaos::txt(&chaos::id_server(), 0, "inner"))
        .rcode(chaos::version_server(), ResponseCode::NotImp);
    let server = ServerConfig {
        identity,
        ..ServerConfig::generic()
    };
    let mut engine = AuthorityEngine::new(zones(vec![example()]), server, local());
    let mut ask = |qname: &str| {
        let message = query(qname, RecordType::TXT, |m| {
            m.queries[0].set_query_class(DNSClass::CH);
        });
        the_answer(&ask_with(&mut engine, &message, Transport::Udp))
    };
    let texts = |reply: &Message| -> Vec<String> {
        reply
            .answers
            .iter()
            .map(|record| record.data.to_string())
            .collect()
    };
    let reply = ask("server.");
    assert_eq!(texts(&reply), ["outer"]);
    let reply = ask("id.server.");
    assert_eq!(texts(&reply), ["inner"]);
    let reply = ask("a.id.server.");
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    let reply = ask("version.server.");
    assert_eq!(reply.metadata.response_code, ResponseCode::NotImp);
    // Below the name with an RCODE is the outer zone's, where it is not.
    let reply = ask("a.version.server.");
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert!(reply.metadata.authoritative);
}

#[test]
#[should_panic(expected = "a CHAOS zone holds no aliases")]
fn a_chaos_zone_holds_no_alias() {
    let _ = ChaosZone::new(name("id.server.")).record(0, RData::CNAME(CNAME(name("a."))));
}

/// A CHAOS name with a zone of its own answers from the zone's records,
/// as each CHAOS name of a BIND server does ([`bind::chaos_zone`]).
#[test]
fn a_chaos_zone_answers_from_its_records() {
    let hostname = chaos::hostname_bind();
    let authors = chaos::authors_bind();
    let identity = Identity::none()
        .zone(bind::chaos_zone(chaos::txt(&hostname, 0, "lax1a")))
        .zone(bind::chaos_zone(ChaosZone::new(Name::from(&authors))))
        .rcode(chaos::version_server(), ResponseCode::Refused);
    let server = ServerConfig {
        identity,
        ..ServerConfig::generic()
    };
    let mut engine = AuthorityEngine::new(zones(vec![example()]), server, local());
    let mut ask = |qname: &str, qtype: RecordType, rd: bool| {
        let message = query(qname, qtype, |m| {
            m.queries[0].set_query_class(DNSClass::CH);
            m.metadata.recursion_desired = rd;
        });
        the_answer(&ask_with(&mut engine, &message, Transport::Udp))
    };
    let section = |records: &[Record]| -> Vec<(String, RecordType, u32)> {
        records
            .iter()
            .map(|record| (record.name.to_string(), record.record_type(), record.ttl))
            .collect()
    };
    let host = |kind: RecordType, ttl: u32| ("hostname.bind.".to_string(), kind, ttl);
    use RecordType::{A, ANY, NS as Ns, SOA as Soa, TXT as Txt};

    // (question, RD, RCODE, answer section, authority section)
    let cases = [
        // The text, whatever RD says, with nothing in the authority
        // section, where it is optional.
        (
            ("hostname.bind.", Txt),
            false,
            ResponseCode::NoError,
            vec![host(Txt, 0)],
            vec![],
        ),
        (
            ("hostname.bind.", Txt),
            true,
            ResponseCode::NoError,
            vec![host(Txt, 0)],
            vec![],
        ),
        // The zone's own SOA and NS are answers.
        (
            ("hostname.bind.", Soa),
            false,
            ResponseCode::NoError,
            vec![host(Soa, 86400)],
            vec![],
        ),
        (
            ("hostname.bind.", Ns),
            false,
            ResponseCode::NoError,
            vec![host(Ns, 0)],
            vec![],
        ),
        (
            ("hostname.bind.", ANY),
            false,
            ResponseCode::NoError,
            vec![host(Txt, 0), host(Soa, 86400), host(Ns, 0)],
            vec![],
        ),
        // Another type is NODATA with the SOA.
        (
            ("hostname.bind.", A),
            false,
            ResponseCode::NoError,
            vec![],
            vec![host(Soa, 86400)],
        ),
        // Below the zone is NXDOMAIN with the SOA, whose TTL is the
        // smaller of its own and its MINIMUM for any question
        // (RFC 2308 §3).
        (
            ("foo.hostname.bind.", Txt),
            false,
            ResponseCode::NXDomain,
            vec![],
            vec![host(Soa, 86400)],
        ),
        (
            ("foo.hostname.bind.", Soa),
            false,
            ResponseCode::NXDomain,
            vec![],
            vec![host(Soa, 86400)],
        ),
        // A zone with no text.
        (
            ("authors.bind.", Txt),
            false,
            ResponseCode::NoError,
            vec![],
            vec![("authors.bind.".to_string(), Soa, 86400)],
        ),
        // A name that is not a zone, and what is below it.
        (
            ("version.server.", Txt),
            false,
            ResponseCode::Refused,
            vec![],
            vec![],
        ),
        (
            ("foo.version.server.", Txt),
            false,
            ResponseCode::Refused,
            vec![],
            vec![],
        ),
    ];
    for ((qname, qtype), rd, rcode, answers, authorities) in cases {
        let reply = ask(qname, qtype, rd);
        let case = format!("{qname} {qtype} rd={rd}: {reply}");
        assert_eq!(reply.metadata.response_code, rcode, "{case}");
        assert_eq!(
            reply.metadata.authoritative,
            rcode != ResponseCode::Refused,
            "{case}"
        );
        assert_eq!(section(&reply.answers), answers, "{case}");
        assert_eq!(section(&reply.authorities), authorities, "{case}");
        assert!(
            reply
                .answers
                .iter()
                .chain(&reply.authorities)
                .all(|r| r.dns_class == DNSClass::CH),
            "{case}"
        );
    }
    let reply = ask("hostname.bind.", Soa, false);
    let RData::SOA(soa) = &reply.answers[0].data else {
        panic!("an SOA");
    };
    assert_eq!(soa.mname.to_string(), "hostname.bind.");
    assert_eq!(soa.rname.to_string(), "hostmaster.hostname.bind.");
    assert_eq!(
        (soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum),
        (0, 28800, 7200, 604800, 86400)
    );
}

/// A CNAME chain whose target lies in another zone the server hosts, out
/// of the zone or below one of its cuts, goes on in that zone: the reply
/// carries the chain and the target's data with AA, and no referral back
/// to the server itself, as step 1 searches every zone the server has
/// (RFC 1034 §4.3.2 step 3a). A chain that comes back to a name it passed
/// is a loop, answered SERVFAIL with the chain (RFC 1034 §3.6.2), within
/// one zone or across two, and one whose target no hosted zone holds ends
/// with its CNAME.
#[test]
fn a_chain_goes_on_in_the_other_zones_the_server_hosts() {
    let master = |text: &str| Zone::from_master(text, None).unwrap();
    let example = master(
        "\
example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 3600 1209600 300
example. 3600 IN NS ns.example.
ns.example. 3600 IN A 192.0.2.53
alias.example. 300 IN CNAME www.other.
inchild.example. 300 IN CNAME www.child.example.
back.example. 300 IN CNAME loop.other.
away.example. 300 IN CNAME www.elsewhere.
self.example. 300 IN CNAME self.example.
child.example. 3600 IN NS ns.example.
",
    );
    let other = master(
        "\
other. 3600 IN SOA ns.example. hostmaster.example. 1 7200 3600 1209600 300
other. 3600 IN NS ns.example.
www.other. 300 IN A 192.0.2.90
loop.other. 300 IN CNAME back.example.
",
    );
    let child = master(
        "\
child.example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 3600 1209600 300
child.example. 3600 IN NS ns.example.
www.child.example. 300 IN A 192.0.2.91
",
    );
    let texts = |records: &[Record]| -> Vec<String> {
        records
            .iter()
            .map(|record| format!("{} {} {}", record.name, record.record_type(), record.data))
            .collect()
    };
    use ResponseCode::{NoError, ServFail};
    let cases: [(&str, ResponseCode, &[&str]); 5] = [
        (
            "inchild.example.",
            NoError,
            &[
                "inchild.example. CNAME www.child.example.",
                "www.child.example. A 192.0.2.91",
            ],
        ),
        (
            "alias.example.",
            NoError,
            &["alias.example. CNAME www.other.", "www.other. A 192.0.2.90"],
        ),
        (
            "back.example.",
            ServFail,
            &[
                "back.example. CNAME loop.other.",
                "loop.other. CNAME back.example.",
            ],
        ),
        (
            "away.example.",
            NoError,
            &["away.example. CNAME www.elsewhere."],
        ),
        (
            "self.example.",
            ServFail,
            &["self.example. CNAME self.example."],
        ),
    ];
    for (qname, rcode, want) in cases {
        let mut engine = AuthorityEngine::new(
            zones(vec![example.clone(), other.clone(), child.clone()]),
            ServerConfig::generic(),
            local(),
        );
        let reply = the_answer(&ask_with(
            &mut engine,
            &query(qname, RecordType::A, |_| {}),
            Transport::Udp,
        ));
        assert_eq!(reply.metadata.response_code, rcode, "{qname}");
        assert!(reply.metadata.authoritative, "{qname}");
        assert_eq!(texts(&reply.answers), want, "{qname}");
        assert!(
            reply
                .authorities
                .iter()
                .all(|record| record.record_type() != RecordType::NS),
            "{qname}: no referral"
        );
    }
}

#[test]
fn zone_transfers_are_the_authoritys_to_decide() {
    let calls = Arc::new(AtomicUsize::new(0));
    let axfr = query("example.test.", RecordType::AXFR, |_| {});

    // Over UDP a transfer is malformed (RFC 5936 §4.2), and never reaches
    // the authority.
    let mut engine =
        AuthorityEngine::new(Counting(calls.clone()), ServerConfig::generic(), local());
    let reply = the_answer(&ask_with(&mut engine, &axfr, Transport::Udp));
    assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // Over TCP the authority decides it, as any question.
    ask_with(&mut engine, &axfr, Transport::Tcp);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // IXFR is defined over UDP too (RFC 1995 §2), so the authority
    // decides it there as well, and zones refuse it on both transports.
    let ixfr = query("example.test.", RecordType::IXFR, |_| {});
    ask_with(&mut engine, &ixfr, Transport::Udp);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    for transport in [Transport::Udp, Transport::Tcp] {
        let mut engine =
            AuthorityEngine::new(zones(vec![example()]), ServerConfig::generic(), local());
        let reply = the_answer(&ask_with(&mut engine, &ixfr, transport));
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::Refused,
            "{transport:?}"
        );
    }

    // Zone data answers questions; it cannot list a zone, so zones refuse,
    // and so do an authority that looks up what it lacks and an overlay
    // on it.
    let mut engine = AuthorityEngine::new(zones(vec![example()]), ServerConfig::generic(), local());
    let reply = the_answer(&ask_with(&mut engine, &axfr, Transport::Tcp));
    assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
    let mut engine = lookup_engine();
    let actions = ask_with(&mut engine, &axfr, Transport::Tcp);
    assert!(lookups(&actions).is_empty());
    assert_eq!(
        the_answer(&actions).metadata.response_code,
        ResponseCode::Refused
    );
    for qname in ["fict.com.", "www.fict.com.", "com."] {
        let axfr = query(qname, RecordType::AXFR, |_| {});
        let mut engine = AuthorityEngine::new(overlay(), ServerConfig::generic(), local());
        let actions = ask_with(&mut engine, &axfr, Transport::Tcp);
        assert!(lookups(&actions).is_empty(), "{qname}");
        let reply = the_answer(&actions);
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::Refused,
            "{qname}"
        );
        assert!(reply.authorities.is_empty(), "{qname}: no referral");
    }
}

/// A transfer of a CHAOS zone is refused (RFC 5936 §2.2), as BIND
/// refuses it, rather than answered as a question.
#[test]
fn a_chaos_zone_transfer_is_refused() {
    let version = chaos::version_bind();
    let identity = Identity::none().zone(bind::chaos_zone(ChaosZone::new(Name::from(&version))));
    let server = ServerConfig {
        identity,
        ..ServerConfig::generic()
    };
    let mut engine = AuthorityEngine::new(zones(vec![example()]), server, local());
    for qtype in [RecordType::AXFR, RecordType::IXFR] {
        let message = query("version.bind.", qtype, |m| {
            m.queries[0].set_query_class(DNSClass::CH);
        });
        let reply = the_answer(&ask_with(&mut engine, &message, Transport::Tcp));
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::Refused,
            "{qtype}"
        );
        assert!(reply.answers.is_empty() && reply.authorities.is_empty());
    }
}

/// Every root letter, `gtld-servers.net` server, and public resolver of
/// [`Place::san_francisco_bay_area`], and the Unbound look, answer each
/// CHAOS TXT name a guest asks as they were measured to: the RCODE, and
/// the text and TTL of each TXT record.
#[test]
fn the_measured_servers_answer_chaos_txt_as_measured() {
    use ResponseCode::{NoError, NotImp, Refused, ServFail};
    let place = Place::san_francisco_bay_area();
    let egress = std::net::Ipv4Addr::new(45, 70, 0, 9);
    let mut servers: Vec<(String, Identity)> = place
        .servers
        .iter()
        .map(|(addr, site)| (addr.to_string(), site.identity.clone()))
        .collect();
    for resolver in &PUBLIC_RESOLVERS {
        let site = place.resolver(resolver.addresses[0].v4);
        let config = resolver.whoami(resolver.config(site.identity.clone()), &site, egress);
        servers.push((resolver.addresses[0].v4.to_string(), config.identity));
    }
    servers.push(("unbound".to_string(), unbound::config().identity));
    let names = [
        "id.server.",
        "hostname.bind.",
        "version.bind.",
        "version.server.",
        "authors.bind.",
        "whoami.cloudflare.",
    ];
    let mut seen = Vec::new();
    for (server, identity) in servers {
        let front = ServerConfig {
            identity,
            ..ServerConfig::generic()
        };
        let mut engine = AuthorityEngine::new(zones(vec![example()]), front, local());
        for qname in names {
            let message = query(qname, RecordType::TXT, |m| {
                m.queries[0].set_query_class(DNSClass::CH);
            });
            let reply = the_answer(&ask_with(&mut engine, &message, Transport::Udp));
            let texts: Vec<(String, u32)> = reply
                .answers
                .iter()
                .filter_map(|record| match &record.data {
                    RData::TXT(txt) => Some((txt.to_string(), record.ttl)),
                    _ => None,
                })
                .collect();
            seen.push((server.clone(), qname, reply.metadata.response_code, texts));
        }
    }
    type Row = (
        &'static str,
        &'static str,
        ResponseCode,
        &'static [(&'static str, u32)],
    );
    let measured: &[Row] = &[
        ("170.247.170.2", "id.server.", NoError, &[("b1-iad", 0)]),
        ("170.247.170.2", "hostname.bind.", NoError, &[("b1-iad", 0)]),
        (
            "170.247.170.2",
            "version.bind.",
            NoError,
            &[("knot 3.x", 0)],
        ),
        (
            "170.247.170.2",
            "version.server.",
            NoError,
            &[("knot 3.x", 0)],
        ),
        ("170.247.170.2", "authors.bind.", Refused, &[]),
        ("170.247.170.2", "whoami.cloudflare.", Refused, &[]),
        (
            "192.5.5.241",
            "id.server.",
            NoError,
            &[("SJC.cf.f.root-servers.org", 60)],
        ),
        (
            "192.5.5.241",
            "hostname.bind.",
            NoError,
            &[("SJC.cf.f.root-servers.org", 60)],
        ),
        (
            "192.5.5.241",
            "version.bind.",
            NoError,
            &[("2026.10.4", 60)],
        ),
        ("192.5.5.241", "version.server.", NotImp, &[]),
        ("192.5.5.241", "authors.bind.", NotImp, &[]),
        ("192.5.5.241", "whoami.cloudflare.", NotImp, &[]),
        ("192.5.6.30", "id.server.", NoError, &[("nnn1-ussjc-3", 0)]),
        (
            "192.5.6.30",
            "hostname.bind.",
            NoError,
            &[("nnn1-ussjc-3", 0)],
        ),
        ("192.5.6.30", "version.bind.", NoError, &[("ATLAS", 0)]),
        ("192.5.6.30", "version.server.", NoError, &[("ATLAS", 0)]),
        ("192.5.6.30", "authors.bind.", Refused, &[]),
        ("192.5.6.30", "whoami.cloudflare.", Refused, &[]),
        (
            "192.12.94.30",
            "id.server.",
            NoError,
            &[("nnn1-ussjc-3", 0)],
        ),
        (
            "192.12.94.30",
            "hostname.bind.",
            NoError,
            &[("nnn1-ussjc-3", 0)],
        ),
        ("192.12.94.30", "version.bind.", NoError, &[("ATLAS", 0)]),
        ("192.12.94.30", "version.server.", NoError, &[("ATLAS", 0)]),
        ("192.12.94.30", "authors.bind.", Refused, &[]),
        ("192.12.94.30", "whoami.cloudflare.", Refused, &[]),
        (
            "192.26.92.30",
            "id.server.",
            NoError,
            &[("nnn1-ussjc-3", 0)],
        ),
        (
            "192.26.92.30",
            "hostname.bind.",
            NoError,
            &[("nnn1-ussjc-3", 0)],
        ),
        ("192.26.92.30", "version.bind.", NoError, &[("ATLAS", 0)]),
        ("192.26.92.30", "version.server.", NoError, &[("ATLAS", 0)]),
        ("192.26.92.30", "authors.bind.", Refused, &[]),
        ("192.26.92.30", "whoami.cloudflare.", Refused, &[]),
        (
            "192.31.80.30",
            "id.server.",
            NoError,
            &[("nnn1-ussjc-3", 0)],
        ),
        (
            "192.31.80.30",
            "hostname.bind.",
            NoError,
            &[("nnn1-ussjc-3", 0)],
        ),
        ("192.31.80.30", "version.bind.", NoError, &[("ATLAS", 0)]),
        ("192.31.80.30", "version.server.", NoError, &[("ATLAS", 0)]),
        ("192.31.80.30", "authors.bind.", Refused, &[]),
        ("192.31.80.30", "whoami.cloudflare.", Refused, &[]),
        (
            "192.33.4.12",
            "id.server.",
            NoError,
            &[("lax1b.c.root-servers.org", 0)],
        ),
        (
            "192.33.4.12",
            "hostname.bind.",
            NoError,
            &[("lax1a.c.root-servers.org", 0)],
        ),
        ("192.33.4.12", "version.bind.", NoError, &[("c-root", 0)]),
        ("192.33.4.12", "version.server.", Refused, &[]),
        ("192.33.4.12", "authors.bind.", NoError, &[]),
        ("192.33.4.12", "whoami.cloudflare.", Refused, &[]),
        ("192.33.14.30", "id.server.", NoError, &[("nnn1-ein4", 0)]),
        (
            "192.33.14.30",
            "hostname.bind.",
            NoError,
            &[("nnn1-ein1", 0)],
        ),
        ("192.33.14.30", "version.bind.", NoError, &[("ATLAS", 0)]),
        ("192.33.14.30", "version.server.", NoError, &[("ATLAS", 0)]),
        ("192.33.14.30", "authors.bind.", Refused, &[]),
        ("192.33.14.30", "whoami.cloudflare.", Refused, &[]),
        (
            "192.35.51.30",
            "id.server.",
            NoError,
            &[("nnn1-uschi-2c", 0)],
        ),
        (
            "192.35.51.30",
            "hostname.bind.",
            NoError,
            &[("nnn1-uschi-2a", 0)],
        ),
        ("192.35.51.30", "version.bind.", NoError, &[("ATLAS", 0)]),
        ("192.35.51.30", "version.server.", NoError, &[("ATLAS", 0)]),
        ("192.35.51.30", "authors.bind.", Refused, &[]),
        ("192.35.51.30", "whoami.cloudflare.", Refused, &[]),
        ("192.36.148.17", "id.server.", NoError, &[("s1.pix", 0)]),
        ("192.36.148.17", "hostname.bind.", NoError, &[("s1.pix", 0)]),
        (
            "192.36.148.17",
            "version.bind.",
            NoError,
            &[("contact info@netnod.se", 0)],
        ),
        ("192.36.148.17", "version.server.", Refused, &[]),
        ("192.36.148.17", "authors.bind.", NoError, &[]),
        ("192.36.148.17", "whoami.cloudflare.", Refused, &[]),
        (
            "192.41.162.30",
            "id.server.",
            NoError,
            &[("nnn1-usdal-3c", 0)],
        ),
        (
            "192.41.162.30",
            "hostname.bind.",
            NoError,
            &[("nnn1-usdal-3a", 0)],
        ),
        ("192.41.162.30", "version.bind.", NoError, &[("ATLAS", 0)]),
        ("192.41.162.30", "version.server.", NoError, &[("ATLAS", 0)]),
        ("192.41.162.30", "authors.bind.", Refused, &[]),
        ("192.41.162.30", "whoami.cloudflare.", Refused, &[]),
        (
            "192.42.93.30",
            "id.server.",
            NoError,
            &[("nnn1-uschi-2c", 0)],
        ),
        (
            "192.42.93.30",
            "hostname.bind.",
            NoError,
            &[("nnn1-uschi-2b", 0)],
        ),
        ("192.42.93.30", "version.bind.", NoError, &[("ATLAS", 0)]),
        ("192.42.93.30", "version.server.", NoError, &[("ATLAS", 0)]),
        ("192.42.93.30", "authors.bind.", Refused, &[]),
        ("192.42.93.30", "whoami.cloudflare.", Refused, &[]),
        (
            "192.43.172.30",
            "id.server.",
            NoError,
            &[("nnn1-uschi-2b", 0)],
        ),
        (
            "192.43.172.30",
            "hostname.bind.",
            NoError,
            &[("nnn1-uschi-2b", 0)],
        ),
        ("192.43.172.30", "version.bind.", NoError, &[("ATLAS", 0)]),
        ("192.43.172.30", "version.server.", NoError, &[("ATLAS", 0)]),
        ("192.43.172.30", "authors.bind.", Refused, &[]),
        ("192.43.172.30", "whoami.cloudflare.", Refused, &[]),
        (
            "192.48.79.30",
            "id.server.",
            NoError,
            &[("nnn1-usdal-3b", 0)],
        ),
        (
            "192.48.79.30",
            "hostname.bind.",
            NoError,
            &[("nnn1-usdal-3b", 0)],
        ),
        ("192.48.79.30", "version.bind.", NoError, &[("ATLAS", 0)]),
        ("192.48.79.30", "version.server.", NoError, &[("ATLAS", 0)]),
        ("192.48.79.30", "authors.bind.", Refused, &[]),
        ("192.48.79.30", "whoami.cloudflare.", Refused, &[]),
        (
            "192.52.178.30",
            "id.server.",
            NoError,
            &[("nnn1-usdal-3a", 0)],
        ),
        (
            "192.52.178.30",
            "hostname.bind.",
            NoError,
            &[("nnn1-usdal-3a", 0)],
        ),
        ("192.52.178.30", "version.bind.", NoError, &[("ATLAS", 0)]),
        ("192.52.178.30", "version.server.", NoError, &[("ATLAS", 0)]),
        ("192.52.178.30", "authors.bind.", Refused, &[]),
        ("192.52.178.30", "whoami.cloudflare.", Refused, &[]),
        (
            "192.54.112.30",
            "id.server.",
            NoError,
            &[("nnn1-uschi-2a", 0)],
        ),
        (
            "192.54.112.30",
            "hostname.bind.",
            NoError,
            &[("nnn1-uschi-2b", 0)],
        ),
        ("192.54.112.30", "version.bind.", NoError, &[("ATLAS", 0)]),
        ("192.54.112.30", "version.server.", NoError, &[("ATLAS", 0)]),
        ("192.54.112.30", "authors.bind.", Refused, &[]),
        ("192.54.112.30", "whoami.cloudflare.", Refused, &[]),
        (
            "192.55.83.30",
            "id.server.",
            NoError,
            &[("nnn1-usdal-3c", 0)],
        ),
        (
            "192.55.83.30",
            "hostname.bind.",
            NoError,
            &[("nnn1-usdal-3c", 0)],
        ),
        ("192.55.83.30", "version.bind.", NoError, &[("ATLAS", 0)]),
        ("192.55.83.30", "version.server.", NoError, &[("ATLAS", 0)]),
        ("192.55.83.30", "authors.bind.", Refused, &[]),
        ("192.55.83.30", "whoami.cloudflare.", Refused, &[]),
        (
            "192.58.128.30",
            "id.server.",
            NoError,
            &[("rootns-ussjc-3", 0)],
        ),
        (
            "192.58.128.30",
            "hostname.bind.",
            NoError,
            &[("rootns-ussjc-3", 0)],
        ),
        ("192.58.128.30", "version.bind.", NoError, &[("KnotDNS", 0)]),
        (
            "192.58.128.30",
            "version.server.",
            NoError,
            &[("KnotDNS", 0)],
        ),
        ("192.58.128.30", "authors.bind.", Refused, &[]),
        ("192.58.128.30", "whoami.cloudflare.", Refused, &[]),
        ("192.112.36.4", "id.server.", Refused, &[]),
        (
            "192.112.36.4",
            "hostname.bind.",
            NoError,
            &[("groot-con2-2", 0)],
        ),
        ("192.112.36.4", "version.bind.", Refused, &[]),
        ("192.112.36.4", "version.server.", Refused, &[]),
        ("192.112.36.4", "authors.bind.", Refused, &[]),
        ("192.112.36.4", "whoami.cloudflare.", Refused, &[]),
        (
            "192.203.230.10",
            "id.server.",
            NoError,
            &[("c01.SEA.eroot", 60)],
        ),
        (
            "192.203.230.10",
            "hostname.bind.",
            NoError,
            &[("c01.SEA.eroot", 60)],
        ),
        (
            "192.203.230.10",
            "version.bind.",
            NoError,
            &[("2026.10.4", 60)],
        ),
        ("192.203.230.10", "version.server.", NotImp, &[]),
        ("192.203.230.10", "authors.bind.", NotImp, &[]),
        ("192.203.230.10", "whoami.cloudflare.", NotImp, &[]),
        (
            "193.0.14.129",
            "id.server.",
            NoError,
            &[("ns3.gb-lon.k.ripe.net", 0)],
        ),
        (
            "193.0.14.129",
            "hostname.bind.",
            NoError,
            &[("ns2.gb-lon.k.ripe.net", 0)],
        ),
        ("193.0.14.129", "version.bind.", NoError, &[("BIND", 0)]),
        ("193.0.14.129", "version.server.", Refused, &[]),
        ("193.0.14.129", "authors.bind.", Refused, &[]),
        ("193.0.14.129", "whoami.cloudflare.", Refused, &[]),
        ("198.41.0.4", "id.server.", NoError, &[("nnn1-ussea-4c", 0)]),
        (
            "198.41.0.4",
            "hostname.bind.",
            NoError,
            &[("nnn1-ussea-4c", 0)],
        ),
        ("198.41.0.4", "version.bind.", NoError, &[("ATLAS", 0)]),
        ("198.41.0.4", "version.server.", NoError, &[("ATLAS", 0)]),
        ("198.41.0.4", "authors.bind.", NoError, &[]),
        ("198.41.0.4", "whoami.cloudflare.", NoError, &[]),
        (
            "198.97.190.53",
            "id.server.",
            NoError,
            &[("001.nzy.h.root-servers.org", 0)],
        ),
        (
            "198.97.190.53",
            "hostname.bind.",
            NoError,
            &[("001.nzy.h.root-servers.org", 0)],
        ),
        ("198.97.190.53", "version.bind.", NoError, &[("NSD 4.x", 0)]),
        (
            "198.97.190.53",
            "version.server.",
            NoError,
            &[("NSD 4.x", 0)],
        ),
        ("198.97.190.53", "authors.bind.", Refused, &[]),
        ("198.97.190.53", "whoami.cloudflare.", Refused, &[]),
        ("199.7.83.42", "id.server.", NoError, &[("us-lax-aa", 0)]),
        (
            "199.7.83.42",
            "hostname.bind.",
            NoError,
            &[("us-lax-aa", 0)],
        ),
        ("199.7.83.42", "version.bind.", NoError, &[("NSD 4", 0)]),
        ("199.7.83.42", "version.server.", NoError, &[("NSD 4", 0)]),
        ("199.7.83.42", "authors.bind.", Refused, &[]),
        ("199.7.83.42", "whoami.cloudflare.", Refused, &[]),
        (
            "199.7.91.13",
            "id.server.",
            NoError,
            &[("paca7.droot.maxgigapop.net", 0)],
        ),
        (
            "199.7.91.13",
            "hostname.bind.",
            NoError,
            &[("paca8.droot.maxgigapop.net", 0)],
        ),
        ("199.7.91.13", "version.bind.", NoError, &[("NSD 4", 0)]),
        ("199.7.91.13", "version.server.", NoError, &[("NSD 4", 0)]),
        ("199.7.91.13", "authors.bind.", Refused, &[]),
        ("199.7.91.13", "whoami.cloudflare.", Refused, &[]),
        ("202.12.27.33", "id.server.", NoError, &[("M-SJC-4", 0)]),
        ("202.12.27.33", "hostname.bind.", NoError, &[("M-SJC-4", 0)]),
        ("202.12.27.33", "version.bind.", NoError, &[("9.16", 0)]),
        ("202.12.27.33", "version.server.", Refused, &[]),
        ("202.12.27.33", "authors.bind.", NoError, &[]),
        ("202.12.27.33", "whoami.cloudflare.", Refused, &[]),
        ("8.8.8.8", "id.server.", ServFail, &[]),
        ("8.8.8.8", "hostname.bind.", ServFail, &[]),
        ("8.8.8.8", "version.bind.", ServFail, &[]),
        ("8.8.8.8", "version.server.", ServFail, &[]),
        ("8.8.8.8", "authors.bind.", ServFail, &[]),
        ("8.8.8.8", "whoami.cloudflare.", ServFail, &[]),
        ("1.1.1.1", "id.server.", NoError, &[("sjc10", 0)]),
        ("1.1.1.1", "hostname.bind.", Refused, &[]),
        ("1.1.1.1", "version.bind.", Refused, &[]),
        ("1.1.1.1", "version.server.", NoError, &[("2026.10.11", 0)]),
        ("1.1.1.1", "authors.bind.", Refused, &[]),
        (
            "1.1.1.1",
            "whoami.cloudflare.",
            NoError,
            &[("45.70.0.9", 0)],
        ),
        ("9.9.9.9", "id.server.", NoError, &[("res711.pao", 0)]),
        ("9.9.9.9", "hostname.bind.", ServFail, &[]),
        (
            "9.9.9.9",
            "version.bind.",
            NoError,
            &[("Q9-P-2026080500", 0)],
        ),
        ("9.9.9.9", "version.server.", ServFail, &[]),
        ("9.9.9.9", "authors.bind.", ServFail, &[]),
        ("9.9.9.9", "whoami.cloudflare.", Refused, &[]),
        ("208.67.222.222", "id.server.", Refused, &[]),
        ("208.67.222.222", "hostname.bind.", Refused, &[]),
        ("208.67.222.222", "version.bind.", Refused, &[]),
        ("208.67.222.222", "version.server.", Refused, &[]),
        ("208.67.222.222", "authors.bind.", Refused, &[]),
        ("208.67.222.222", "whoami.cloudflare.", Refused, &[]),
        ("unbound", "id.server.", NoError, &[("localhost", 0)]),
        ("unbound", "hostname.bind.", NoError, &[("localhost", 0)]),
        (
            "unbound",
            "version.bind.",
            NoError,
            &[("unbound 1.26.2", 0)],
        ),
        (
            "unbound",
            "version.server.",
            NoError,
            &[("unbound 1.26.2", 0)],
        ),
        ("unbound", "authors.bind.", Refused, &[]),
        ("unbound", "whoami.cloudflare.", Refused, &[]),
    ];
    assert_eq!(seen.len(), measured.len());
    for ((server, qname, rcode, texts), row) in seen.iter().zip(measured) {
        let texts: Vec<(&str, u32)> = texts.iter().map(|(text, ttl)| (&text[..], *ttl)).collect();
        assert_eq!((&server[..], *qname, *rcode, &texts[..]), *row);
    }
}

#[test]
fn malformed_queries_get_the_parse_outcome() {
    let mut engine = AuthorityEngine::new(zones(vec![example()]), ServerConfig::generic(), local());
    let short = Input::Query(ClientQuery {
        client: client(Transport::Udp),
        bytes: vec![0; 5],
    });
    assert!(run(&mut engine, short, Instant::ZERO).is_empty());

    let versioned = query("www.example.test.", RecordType::A, |m| {
        let mut edns = edns(1232, true);
        edns.set_version(1);
        m.set_edns(edns);
    });
    let actions = ask_with(&mut engine, &versioned, Transport::Udp);
    assert_eq!(kinds(&actions), ["reply", "answer"]);
    let reply = the_answer(&actions);
    // BADVERS shares 16 with BADSIG (RFC 6891 §9), which hickory reads.
    assert_eq!(
        u16::from(reply.metadata.response_code),
        u16::from(ResponseCode::BADVERS)
    );
    let opt = reply.edns.unwrap();
    assert_eq!(opt.version(), 0);
    assert_eq!(opt.max_payload(), 1232);
}

#[test]
fn a_reply_larger_than_the_client_takes_is_truncated() {
    let mut engine = lookup_engine();
    let message = query("big.example.test.", RecordType::A, |_| {});
    let actions = ask_with(&mut engine, &message, Transport::Udp);
    let (token, lookup) = lookups(&actions)[0].clone();
    // A response the upstream fetched over TCP, far past 512 octets.
    let real = real_response(&lookup, |m| {
        for host in 1..=60 {
            m.add_answer(Record::from_rdata(
                name("big.example.test."),
                60,
                a(&format!("192.0.2.{host}")),
            ));
        }
    });
    let bytes = answer_bytes(&run(&mut engine, looked(token, real), Instant::ZERO));
    assert!(bytes.len() <= 512);
    let reply = Message::from_vec(&bytes).unwrap();
    assert!(reply.metadata.truncation);
    assert_eq!(reply.metadata.id, 0x1234);
}

// Completions that change nothing.

#[test]
fn completions_for_the_wrong_question_or_of_another_kind_are_ignored() {
    let mut engine = lookup_engine();
    let actions = ask_with(
        &mut engine,
        &query("www.example.test.", RecordType::A, |_| {}),
        Transport::Udp,
    );
    let (token, lookup) = lookups(&actions)[0].clone();
    let deadline = engine.next_deadline();
    let good = real_response(&lookup, |m| {
        m.add_answer(Record::from_rdata(
            name("www.example.test."),
            60,
            a("192.0.2.10"),
        ));
    });

    let other_question = real_response(&lookup, |m| {
        m.queries[0].set_query_type(RecordType::AAAA);
    });
    let not_a_response = real_response(&lookup, |m| {
        m.metadata.message_type = MessageType::Query;
    });
    let bytes = Input::Reply {
        token,
        from: local(),
        transport: Transport::Udp,
        bytes: vec![0; 12],
    };
    let failed = Input::Failed {
        token,
        failure: ExchangeFailure::Unreachable,
    };
    let cases = [
        (looked(token, other_question), Unmatched::WrongQuestion),
        (looked(token, not_a_response), Unmatched::WrongQuestion),
        // The engine carries no bytes of its own.
        (bytes, Unmatched::NotOutstanding),
        (failed, Unmatched::NotOutstanding),
    ];
    for (input, why) in cases {
        let actions = run(&mut engine, input, Instant::ZERO);
        assert_eq!(ignored(&actions), [why]);
        assert_eq!(kinds(&actions), ["ignored"]);
        // The lookup is still pending, with the same deadline.
        assert_eq!(engine.next_deadline(), deadline);
    }

    let actions = run(&mut engine, looked(token, good.clone()), Instant::ZERO);
    assert_eq!(answers(&actions).len(), 1);

    // The same response again is stale.
    let actions = run(&mut engine, looked(token, good), Instant::ZERO);
    assert_eq!(ignored(&actions), [Unmatched::NotOutstanding]);
    assert!(matches!(
        actions[0],
        Action::Event(Event::Ignored { from: None, .. })
    ));
}

#[test]
fn advance_abandons_every_lookup_drops_what_was_learned_and_restarts_the_requests() {
    let mut engine = lookup_engine();
    let first = ask_with(
        &mut engine,
        &query("one.example.test.", RecordType::A, |_| {}),
        Transport::Udp,
    );
    let second = ask_with(
        &mut engine,
        &query("two.example.test.", RecordType::A, |_| {}),
        Transport::Udp,
    );
    let old: Vec<(Token, Lookup)> = lookups(&first)
        .into_iter()
        .chain(lookups(&second))
        .collect();
    assert_eq!(old.len(), 2);
    assert_eq!(engine.generation(), Generation(0));

    // `one` is answered and filed in session 0.
    let one = real_response(&old[0].1, |m| {
        m.add_answer(Record::from_rdata(
            name("one.example.test."),
            60,
            a("192.0.2.1"),
        ));
    });
    let actions = run(&mut engine, looked(old[0].0, one), Instant::ZERO);
    assert_eq!(the_answer(&actions).answers[0].data, a("192.0.2.1"));

    engine.advance(session(1));
    let actions: Vec<Action> = std::iter::from_fn(|| engine.poll()).collect();
    assert_eq!(engine.generation(), Generation(1));
    assert_eq!(kinds(&actions), ["abandon", "lookup"]);
    assert_eq!(abandoned(&actions), [old[1].0]);
    let new = lookups(&actions);
    assert_eq!(new[0].0.generation(), Generation(1));
    assert_eq!(new[0].1, old[1].1);

    // A completion of the old session changes nothing.
    let stale = real_response(&old[1].1, |_| {});
    let actions = run(&mut engine, looked(old[1].0, stale), Instant::ZERO);
    assert_eq!(ignored(&actions), [Unmatched::OldGeneration]);

    // What session 0 learned is gone: `one` is looked up again.
    let actions = ask_with(
        &mut engine,
        &query("one.example.test.", RecordType::A, |_| {}),
        Transport::Udp,
    );
    assert_eq!(kinds(&actions), ["query", "lookup"]);

    // The restarted request is answered from the new session.
    let fresh = real_response(&new[0].1, |m| {
        m.add_answer(Record::from_rdata(
            name("two.example.test."),
            60,
            a("192.0.2.12"),
        ));
    });
    let actions = run(&mut engine, looked(new[0].0, fresh), Instant::ZERO);
    assert_eq!(the_answer(&actions).answers[0].data, a("192.0.2.12"));

    // A session that is not newer changes nothing.
    engine.advance(session(1));
    engine.advance(session(0));
    assert!(engine.poll().is_none());
    assert_eq!(engine.generation(), Generation(1));
}

#[test]
fn requests_needing_the_same_fact_share_one_lookup() {
    let mut engine = lookup_engine();
    let message = query("www.example.test.", RecordType::A, |_| {});
    let mut other = client(Transport::Udp);
    other.peer = "198.51.100.8:40000".parse().unwrap();
    let first = ask_with(&mut engine, &message, Transport::Udp);
    let second = run(
        &mut engine,
        Input::Query(ClientQuery {
            client: other.clone(),
            bytes: message.to_vec().unwrap(),
        }),
        Instant::ZERO,
    );
    assert_eq!(lookups(&first).len(), 1);
    assert!(lookups(&second).is_empty());
    let (token, lookup) = lookups(&first)[0].clone();

    let real = real_response(&lookup, |m| {
        m.add_answer(Record::from_rdata(
            name("www.example.test."),
            60,
            a("192.0.2.10"),
        ));
    });
    let actions = run(&mut engine, looked(token, real), Instant::ZERO);
    let clients: Vec<&Client> = actions
        .iter()
        .filter_map(|action| match action {
            Action::Answer(answer) => Some(&answer.client),
            _ => None,
        })
        .collect();
    assert_eq!(clients, [&client(Transport::Udp), &other]);
}

#[test]
fn gone_drops_only_that_clients_waits() {
    let mut engine = lookup_engine();
    let message = query("www.example.test.", RecordType::A, |_| {});
    let mut other = client(Transport::Tcp);
    other.connection = Some(9);
    let first = ask_with(&mut engine, &message, Transport::Tcp);
    run(
        &mut engine,
        Input::Query(ClientQuery {
            client: other.clone(),
            bytes: message.to_vec().unwrap(),
        }),
        Instant::ZERO,
    );
    let (token, _) = lookups(&first)[0].clone();

    // One of two waiters leaves: the lookup goes on for the other.
    let actions = run(&mut engine, Input::Gone(other), Instant::ZERO);
    assert!(actions.is_empty());
    assert!(engine.next_deadline().is_some());

    // The last waiter leaves: the lookup is abandoned.
    let actions = run(
        &mut engine,
        Input::Gone(client(Transport::Tcp)),
        Instant::ZERO,
    );
    assert_eq!(abandoned(&actions), [token]);
    assert_eq!(engine.next_deadline(), None);
}

// Overlays.

/// The invented zone `fict.com.`, with its name server at 192.0.2.80.
fn fict() -> Zone {
    Zone::builder(name("fict.com."), soa("fict.com."), 3600)
        .rrset(rrset("fict.com.", 3600, vec![ns("ns1.fict.com.")]))
        .rrset(rrset("ns1.fict.com.", 3600, vec![a("192.0.2.80")]))
        .rrset(rrset("www.fict.com.", 300, vec![a("192.0.2.81")]))
        .build()
        .unwrap()
}

/// `fict.com.` invented below a server of `com.` that looks up the real
/// one at its address.
fn overlay() -> Overlay<LookupAuthority> {
    Overlay::new(LookupAuthority::new("com."), name("com."))
        .below(name("fict.com."), zones(vec![fict()]))
}

/// The names between `com` and a deeper invented apex are the base's, so
/// `com` could deny `nonexistent.com` and refer names under it.
#[test]
#[should_panic(expected = "not a child of com.")]
fn an_invented_zone_must_be_a_child_of_the_overlays_zone() {
    let _ = Overlay::new(LookupAuthority::new("com."), name("com."))
        .below(name("shop.nonexistent.com."), zones(vec![fict()]));
}

/// `com`'s SOA record.
fn com_soa() -> Record {
    let soa = SOA::new(
        name("a.gtld-servers.net."),
        name("nstld.verisign-grs.com."),
        1,
        1800,
        900,
        604800,
        900,
    );
    Record::from_rdata(name("com."), 900, RData::SOA(soa))
}

/// The NSEC3 record and its RRSIG that `com` sends to deny `fict.com DS`
/// with an opt-out span.
fn com_denial() -> Vec<Record> {
    let next = Nsec3HashAlgorithm::SHA1
        .hash(&[], &name("zzz.com."), 0)
        .unwrap()
        .as_ref()
        .to_vec();
    let nsec3 = NSEC3::new(
        Nsec3HashAlgorithm::SHA1,
        true,
        0,
        vec![],
        next,
        [RecordType::NS, RecordType::DS, RecordType::RRSIG],
    );
    let owner = "ck0pojmg874ljref7efn8430qvit8bsm.com.";
    let set = rrset(owner, 86400, vec![RData::DNSSEC(DNSSECRData::NSEC3(nsec3))]);
    let key = ZoneKey::generate(&entropy(), Algorithm::Ed25519, KeyFlags::ZSK);
    let window = Window {
        inception: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        expiration: SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000),
    };
    let rrsig = sign(&key, &set, &name("com."), window).unwrap();
    let mut records: Vec<Record> = set.records_without_rrsigs().cloned().collect();
    records.push(rrsig);
    records
}

#[test]
fn an_overlay_refers_with_the_denial_records_its_base_copied() {
    let mut engine = AuthorityEngine::new(overlay(), gtld_front(Identity::none()), local());
    let message = query("www.fict.com.", RecordType::A, |m| {
        m.set_edns(edns(1232, true));
    });
    let actions = ask_with(&mut engine, &message, Transport::Udp);
    assert_eq!(kinds(&actions), ["query", "lookup"]);
    let (token, lookup) = lookups(&actions)[0].clone();
    assert_eq!(lookup, lookup_of("com.", "fict.com.", RecordType::DS));

    // `com` denies the name with its SOA and the opt-out NSEC3 record.
    let denial = com_denial();
    let real = real_response(&lookup, |m| {
        m.metadata.response_code = ResponseCode::NXDomain;
        m.add_authority(com_soa());
        for record in &denial {
            m.add_authority(record.clone());
        }
    });
    let actions = run(&mut engine, looked(token, real), Instant::ZERO);
    let reply = the_answer(&actions);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(!reply.metadata.authoritative);
    assert!(reply.answers.is_empty());
    let ns: Vec<&Record> = reply
        .authorities
        .iter()
        .filter(|record| record.record_type() == RecordType::NS)
        .collect();
    assert_eq!(ns.len(), 1);
    assert_eq!(ns[0].name, name("fict.com."));
    let carried: Vec<Record> = reply
        .authorities
        .iter()
        .filter(|record| record.record_type() != RecordType::NS)
        .cloned()
        .collect();
    assert_eq!(carried, denial);
    assert_eq!(reply.additionals.len(), 1);
    assert_eq!(reply.additionals[0].name, name("ns1.fict.com."));
}

/// `bytes` in base32hex without padding (RFC 4648 §7), as NSEC3 owners
/// write a hash.
fn base32hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(DIGITS[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(DIGITS[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// `hash` moved one up (`up`) or down as a big-endian number, wrapping.
fn step(hash: &[u8], up: bool) -> Vec<u8> {
    let mut out = hash.to_vec();
    for byte in out.iter_mut().rev() {
        let (moved, carried) = if up {
            byte.overflowing_add(1)
        } else {
            byte.overflowing_sub(1)
        };
        *byte = moved;
        if !carried {
            break;
        }
    }
    out
}

/// What `com` sends to deny `fict.com DS` when the name does not exist:
/// its SOA, the NSEC3 matching `com`, the opt-out NSEC3 covering
/// `fict.com`, and the NSEC3 covering `*.com`, each signed. The second
/// value names the records of the wildcard's cover.
fn com_nxdomain() -> (Vec<Record>, Name) {
    let hash = |text: &str| {
        Nsec3HashAlgorithm::SHA1
            .hash(&[], &name(text), 0)
            .unwrap()
            .as_ref()
            .to_vec()
    };
    let key = ZoneKey::generate(&entropy(), Algorithm::Ed25519, KeyFlags::ZSK);
    let window = Window {
        inception: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        expiration: SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000),
    };
    let mut records = vec![com_soa()];
    let mut nsec3 = |owner: Vec<u8>, next: Vec<u8>, opt_out: bool, types: &[RecordType]| {
        let rdata = NSEC3::new(
            Nsec3HashAlgorithm::SHA1,
            opt_out,
            0,
            vec![],
            next,
            types.iter().copied(),
        );
        let owner = format!("{}.com.", base32hex(&owner));
        let set = rrset(
            &owner,
            86400,
            vec![RData::DNSSEC(DNSSECRData::NSEC3(rdata))],
        );
        records.extend(set.records_without_rrsigs().cloned());
        records.push(sign(&key, &set, &name("com."), window).unwrap());
        name(&owner)
    };
    let apex = hash("com.");
    nsec3(
        apex.clone(),
        step(&apex, true),
        false,
        &[RecordType::SOA, RecordType::NS, RecordType::DNSKEY],
    );
    let fict = hash("fict.com.");
    nsec3(
        step(&fict, false),
        step(&fict, true),
        true,
        &[RecordType::NS],
    );
    let wildcard = hash("*.com.");
    let cover = nsec3(
        step(&wildcard, false),
        step(&wildcard, true),
        false,
        &[RecordType::NS],
    );
    (records, cover)
}

/// For an invented name under an opt-out NSEC3 parent, the overlay sends
/// what real `com` sends for an unsigned delegation: the closest
/// encloser's NSEC3 and the opt-out span over the name, without the
/// NXDOMAIN's proof that no wildcard matched, in a referral and in the
/// NODATA for its DS.
#[test]
fn an_overlay_sends_the_unsigned_delegation_proof_without_the_wildcard_cover() {
    let (nxdomain, wildcard_cover) = com_nxdomain();
    let kept: Vec<Record> = nxdomain
        .iter()
        .filter(|record| record.record_type() != RecordType::SOA)
        .filter(|record| record.name != wildcard_cover)
        .cloned()
        .collect();
    assert_eq!(kept.len(), 4, "two NSEC3 records and their RRSIGs");
    for (qname, qtype) in [
        ("www.fict.com.", RecordType::A),
        ("fict.com.", RecordType::DS),
    ] {
        let mut engine = AuthorityEngine::new(overlay(), gtld_front(Identity::none()), local());
        let message = query(qname, qtype, |m| {
            m.set_edns(edns(1232, true));
        });
        let actions = ask_with(&mut engine, &message, Transport::Udp);
        let (token, lookup) = lookups(&actions)[0].clone();
        let real = real_response(&lookup, |m| {
            m.metadata.response_code = ResponseCode::NXDomain;
            for record in &nxdomain {
                m.add_authority(record.clone());
            }
        });
        let actions = run(&mut engine, looked(token, real), Instant::ZERO);
        let reply = the_answer(&actions);
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NoError,
            "{qtype}"
        );
        let denial: Vec<Record> = reply
            .authorities
            .iter()
            .filter(|record| !matches!(record.record_type(), RecordType::NS | RecordType::SOA))
            .cloned()
            .collect();
        assert_eq!(denial, kept, "{qtype}");
        let soa = reply
            .authorities
            .iter()
            .any(|record| record.record_type() == RecordType::SOA);
        assert_eq!(
            soa,
            qtype == RecordType::DS,
            "{qtype}: the SOA only in NODATA"
        );
    }
}

/// Without DO the referral carries only the NS RRset, once the base's
/// authoritative answer for `<apex> DS` shows it serves the parent.
#[test]
fn an_overlay_refers_without_do_once_the_base_answers_for_the_parent() {
    let mut engine = AuthorityEngine::new(overlay(), ServerConfig::generic(), local());
    let actions = ask_with(
        &mut engine,
        &query("www.fict.com.", RecordType::A, |_| {}),
        Transport::Udp,
    );
    let (token, lookup) = lookups(&actions)[0].clone();
    assert_eq!(lookup, lookup_of("com.", "fict.com.", RecordType::DS));
    let (nxdomain, _) = com_nxdomain();
    let real = real_response(&lookup, |m| {
        m.metadata.response_code = ResponseCode::NXDomain;
        for record in &nxdomain {
            m.add_authority(record.clone());
        }
    });
    let actions = run(&mut engine, looked(token, real), Instant::ZERO);
    let reply = the_answer(&actions);
    assert!(!reply.metadata.authoritative);
    assert_eq!(reply.authorities.len(), 1);
    assert_eq!(reply.authorities[0].record_type(), RecordType::NS);
}

/// An overlay on a server that does not serve the parent, such as a root
/// server, answers as its base: the root refers to `com`, never straight
/// to a zone invented below it (RFC 1034 §4.2.1).
#[test]
fn an_overlay_on_a_server_of_another_zone_answers_as_its_base() {
    let root_soa = SOA::new(
        name("a.root-servers.net."),
        name("nstld.verisign-grs.com."),
        1,
        1800,
        900,
        604800,
        86400,
    );
    let root = Zone::builder(name("."), root_soa, 86400)
        .rrset(rrset(".", 3600, vec![ns("a.root-servers.net.")]))
        .rrset(rrset("a.root-servers.net.", 3600, vec![a("198.41.0.4")]))
        .delegate(
            name("com."),
            rrset("com.", 172800, vec![ns("a.gtld-servers.net.")]),
            Vec::new(),
            None,
        )
        .build()
        .unwrap();
    let overlay =
        Overlay::new(zones(vec![root]), name("com.")).below(name("fict.com."), zones(vec![fict()]));
    let at = "198.41.0.4:53".parse().unwrap();
    let mut engine = AuthorityEngine::new(overlay, ServerConfig::generic(), at);
    for dnssec_ok in [false, true] {
        let message = query("www.fict.com.", RecordType::A, |m| {
            m.set_edns(edns(1232, dnssec_ok));
        });
        let reply = the_answer(&ask_with(&mut engine, &message, Transport::Udp));
        assert!(!reply.metadata.authoritative);
        let ns: Vec<&Record> = reply
            .authorities
            .iter()
            .filter(|record| record.record_type() == RecordType::NS)
            .collect();
        assert_eq!(ns.len(), 1, "DO {dnssec_ok}");
        assert_eq!(ns[0].name, name("com."), "DO {dnssec_ok}");
        assert!(
            reply
                .additionals
                .iter()
                .all(|record| record.name != name("ns1.fict.com.")),
            "DO {dnssec_ok}"
        );
    }
}

/// A referral needs the glue for a name server at or below the invented
/// apex (RFC 9471 §3.1). When the invented zone does not know the server's
/// address, a server of the parent answers SERVFAIL in its place.
#[test]
fn an_overlay_without_the_glue_it_needs_answers_servfail() {
    let com = Zone::builder(name("com."), soa("com."), 86400)
        .rrset(rrset("com.", 172800, vec![ns("a.gtld-servers.net.")]))
        .build()
        .unwrap();
    let without = Zone::builder(name("fict.com."), soa("fict.com."), 3600)
        .rrset(rrset("fict.com.", 3600, vec![ns("ns1.fict.com.")]))
        .rrset(rrset("www.fict.com.", 300, vec![a("192.0.2.81")]))
        .build()
        .unwrap();
    let inner = Zones::new(vec![Arc::new(Transparent(without)) as Arc<dyn ZoneData>]);
    let overlay = Overlay::new(zones(vec![com]), name("com.")).below(name("fict.com."), inner);
    let mut engine = AuthorityEngine::new(overlay, ServerConfig::generic(), local());
    let actions = ask_with(
        &mut engine,
        &query("www.fict.com.", RecordType::A, |_| {}),
        Transport::Udp,
    );
    assert!(lookups(&actions).is_empty());
    let reply = the_answer(&actions);
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
}

/// Where the parent holds a DS RRset at the invented apex, as for a real
/// signed domain the invented zone stands in for, a referral with DO
/// carries that DS RRset (RFC 4035 §3.1.4): the same one the overlay
/// answers `<apex> DS` with.
#[test]
fn an_overlay_refers_with_the_ds_its_base_holds() {
    let base = Zone::from_master(
        "\
example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 3600 1209600 300
example. 3600 IN NS ns.example.
ns.example. 3600 IN A 192.0.2.53
inv.example. 3600 IN NS ns.elsewhere.test.
inv.example. 3600 IN DS 12345 8 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
",
        None,
    )
    .unwrap();
    let invented = Zone::builder(name("inv.example."), soa("inv.example."), 3600)
        .rrset(rrset("inv.example.", 3600, vec![ns("ns1.inv.example.")]))
        .rrset(rrset("ns1.inv.example.", 3600, vec![a("192.0.2.99")]))
        .build()
        .unwrap();
    let overlay = Overlay::new(zones(vec![base]), name("example."))
        .below(name("inv.example."), zones(vec![invented]));
    let mut engine = AuthorityEngine::new(overlay, ServerConfig::generic(), local());
    let mut ask = |qname: &str, qtype: RecordType| {
        let message = query(qname, qtype, |m| {
            m.set_edns(edns(1232, true));
        });
        the_answer(&ask_with(&mut engine, &message, Transport::Udp))
    };
    let ds = |records: &[Record]| -> Vec<RData> {
        records
            .iter()
            .filter(|record| record.record_type() == RecordType::DS)
            .map(|record| record.data.clone())
            .collect()
    };
    let answer = ask("inv.example.", RecordType::DS);
    assert!(answer.metadata.authoritative);
    assert_eq!(ds(&answer.answers).len(), 1);
    let referral = ask("www.inv.example.", RecordType::A);
    assert!(!referral.metadata.authoritative);
    assert_eq!(ds(&referral.authorities), ds(&answer.answers));
}

/// An answer to QCLASS * can never be authoritative (RFC 1034 §3.7.1), so
/// a server of the parent answers it with FORMERR for an invented name as
/// for any other: one address answers as one server.
#[test]
fn an_overlay_answers_qclass_any_as_its_base_does() {
    let base = Zone::from_master(
        "\
example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 3600 1209600 300
example. 3600 IN NS ns.example.
ns.example. 3600 IN A 192.0.2.53
www.example. 300 IN A 192.0.2.80
",
        None,
    )
    .unwrap();
    let invented = Zone::builder(name("inv.example."), soa("inv.example."), 3600)
        .rrset(rrset("inv.example.", 3600, vec![ns("ns1.inv.example.")]))
        .rrset(rrset("ns1.inv.example.", 3600, vec![a("192.0.2.99")]))
        .build()
        .unwrap();
    let overlay = Overlay::new(zones(vec![base]), name("example."))
        .below(name("inv.example."), zones(vec![invented]));
    let mut engine = AuthorityEngine::new(overlay, ServerConfig::generic(), local());
    for qname in ["www.example.", "www.inv.example.", "inv.example."] {
        let message = query(qname, RecordType::A, |m| {
            m.queries[0].set_query_class(DNSClass::ANY);
        });
        let reply = the_answer(&ask_with(&mut engine, &message, Transport::Udp));
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::FormErr,
            "{qname}"
        );
        assert!(reply.authorities.is_empty(), "{qname}");
    }
}

#[test]
fn an_overlay_is_silent_when_the_ds_lookup_gets_no_reply() {
    let mut engine = AuthorityEngine::new(overlay(), ServerConfig::generic(), local());
    let message = query("www.fict.com.", RecordType::A, |m| {
        m.set_edns(edns(1232, true));
    });
    ask_with(&mut engine, &message, Transport::Udp);
    let deadline = engine.next_deadline().unwrap();
    let actions = run(&mut engine, Input::Tick, deadline);
    assert_eq!(kinds(&actions), ["abandon", "looked"]);
}

#[test]
fn an_overlay_leaves_other_names_and_apex_ds_to_the_base() {
    let mut engine = AuthorityEngine::new(overlay(), ServerConfig::generic(), local());
    for (qname, qtype) in [
        ("www.real.com.", RecordType::A),
        ("fict.com.", RecordType::DS),
    ] {
        let message = query(qname, qtype, |_| {});
        let actions = ask_with(&mut engine, &message, Transport::Udp);
        let (_, lookup) = &lookups(&actions)[0];
        assert_eq!(*lookup, lookup_of("com.", qname, qtype));
    }
}

#[test]
fn at_the_invented_zones_own_server_the_zone_answers() {
    let at = "192.0.2.80:53".parse().unwrap();
    let mut engine = AuthorityEngine::new(overlay(), ServerConfig::generic(), at);
    let actions = ask_with(
        &mut engine,
        &query("www.fict.com.", RecordType::A, |_| {}),
        Transport::Udp,
    );
    let reply = the_answer(&actions);
    assert!(reply.metadata.authoritative);
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(reply.answers[0].data, a("192.0.2.81"));
}

// Order and observation.

#[test]
fn events_come_before_the_actions_they_explain() {
    let seen: Arc<Mutex<Vec<(String, ResponseCode)>>> = Arc::default();
    let log = seen.clone();
    let observed = Observe::new(
        LookupAuthority::new("example.test."),
        move |req: &Request, _client: &Client, response: &Response| {
            log.lock().unwrap().push((
                req.question.name().to_string(),
                response.message.metadata.response_code,
            ));
        },
    );
    let mut engine = AuthorityEngine::new(observed, ServerConfig::generic(), local());
    let actions = ask_with(
        &mut engine,
        &query("www.example.test.", RecordType::A, |_| {}),
        Transport::Udp,
    );
    assert_eq!(kinds(&actions), ["query", "lookup"]);
    assert!(matches!(
        &actions[0],
        Action::Event(Event::Query { server, question, .. })
            if *server == local() && question.name() == &name("www.example.test.")
    ));
    assert!(seen.lock().unwrap().is_empty());

    let (token, lookup) = lookups(&actions)[0].clone();
    let real = real_response(&lookup, |m| {
        m.add_answer(Record::from_rdata(
            name("www.example.test."),
            60,
            a("192.0.2.10"),
        ));
    });
    engine.handle(looked(token, real), Instant::ZERO, &entropy());
    // The callback ran while the engine handled the lookup's end, before
    // the answer could leave.
    assert_eq!(
        *seen.lock().unwrap(),
        [("www.example.test.".to_string(), ResponseCode::NoError)]
    );
    let actions: Vec<Action> = std::iter::from_fn(|| engine.poll()).collect();
    assert_eq!(kinds(&actions), ["looked", "reply", "answer"]);
    match &actions[1] {
        Action::Event(Event::Reply {
            server,
            rcode,
            flags,
            validation,
            cached,
            size,
            ..
        }) => {
            assert_eq!(*server, local());
            assert_eq!(*rcode, ResponseCode::NoError);
            assert!(flags.aa);
            assert_eq!(*validation, Validation::NotPerformed);
            assert!(!cached);
            assert_eq!(usize::from(*size), answer_bytes(&actions).len());
        }
        other => panic!("not a reply event: {other:?}"),
    }
}

#[test]
fn an_authority_that_needs_a_lookup_it_made_stays_silent() {
    /// Needs the same lookup whatever its zones hold.
    struct Forgetful;
    impl Authority for Forgetful {
        fn respond(
            &self,
            _req: &Request,
            _local: SocketAddr,
            _server: &ServerConfig,
            _client: &Client,
        ) -> Step {
            Step::Need(lookup_of(
                "example.test.",
                "www.example.test.",
                RecordType::A,
            ))
        }
    }
    for ends in ["deadline", "response"] {
        let mut engine = AuthorityEngine::new(Forgetful, ServerConfig::generic(), local());
        let actions = ask_with(
            &mut engine,
            &query("www.example.test.", RecordType::A, |_| {}),
            Transport::Udp,
        );
        let (token, lookup) = lookups(&actions)[0].clone();
        let actions = match ends {
            "deadline" => {
                let deadline = engine.next_deadline().unwrap();
                run(&mut engine, Input::Tick, deadline)
            }
            _ => run(
                &mut engine,
                looked(token, real_response(&lookup, |_| {})),
                Instant::ZERO,
            ),
        };
        assert!(answers(&actions).is_empty(), "{ends}");
        assert!(lookups(&actions).is_empty(), "{ends}");
        assert_eq!(engine.next_deadline(), None, "{ends}");
    }
}
