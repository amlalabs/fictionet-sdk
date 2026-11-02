//! The authoritative engine driven directly with inputs: the server
//! front's header and EDNS rules, CHAOS answers, refusals, relays,
//! completions that must change nothing, sessions, overlays, unknown
//! facts, and the order of events and actions.

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
use fictionet::stdlib::protocols::dns::rr::rdata::{A, NS, SOA, TXT};
use fictionet::stdlib::protocols::dns::rr::{
    DNSClass, LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::protocols::dns::{Ede, EdeCode, Nsid, Request, Response};
use fictionet::stdlib::services::dns::authority::{
    Ask, Authority, AuthorityEngine, ChaosAnswer, ChaosReply, Identity, Known, Observe, Overlay,
    Relay, ServerConfig, Step, Zones, bare_reply, chaos,
};
use fictionet::stdlib::services::dns::zone::{Fact, Lazy, Zone, ZoneData};
use fictionet::stdlib::services::dns::{
    Action, Client, ClientQuery, Engine, Event, ExchangeFailure, Generation, Input, ObservedKind,
    Session, Token, Transmit, Unmatched, WallClock,
};
use fictionet::stdlib::services::serve::Transport;
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};

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

fn sends(actions: &[Action]) -> Vec<Transmit> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Send(transmit) => Some(transmit.clone()),
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
            Action::Answer(_) => "answer",
            Action::Abandon(_) => "abandon",
            Action::Event(Event::Query { .. }) => "query",
            Action::Event(Event::Reply { .. }) => "reply",
            Action::Event(Event::Asked { .. }) => "asked",
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

fn reply_to(transmit: &Transmit, bytes: Vec<u8>) -> Input {
    Input::Reply {
        token: transmit.token,
        from: transmit.to,
        transport: transmit.transport,
        bytes,
    }
}

/// What a real server answers to the query in `transmit`: its ID and
/// question in lowercase, AA set, and the records `build` adds.
fn real_reply(transmit: &Transmit, build: impl FnOnce(&mut Message)) -> Vec<u8> {
    let query = Message::from_vec(&transmit.bytes).unwrap();
    let asked = &query.queries[0];
    let mut message = Message::response(query.metadata.id, OpCode::Query);
    message.metadata.authoritative = true;
    let mut lowered = asked.clone();
    lowered.set_name(Name::from(LowerName::new(asked.name())));
    message.add_query(lowered);
    message.edns = query.edns.clone();
    build(&mut message);
    message.to_vec().unwrap()
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
        _known: &dyn Known,
    ) -> Step {
        self.0.fetch_add(1, Ordering::SeqCst);
        Step::Reply(bare_reply(req, ResponseCode::ServFail, None))
    }
}

fn relay_engine() -> AuthorityEngine<Relay> {
    AuthorityEngine::new(Relay::new(), ServerConfig::generic(), local())
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
    server.identity = Some(Identity {
        nsid: Some(b"sjc05".to_vec()),
        ..Identity::none()
    });
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
    server.identity = Some(Identity {
        nsid: Some(b"sjc05".to_vec()),
        ..Identity::none()
    });
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
fn chaos_questions_are_answered_by_name_from_the_identity() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut server = ServerConfig::generic();
    let identity = Identity {
        unlisted: ChaosReply::rcode(ResponseCode::ServFail),
        aa: true,
        ..Identity::none()
    }
    .answer(chaos::id_server(), ChaosAnswer::Txt("sjc07".to_string()))
    .answer(
        chaos::version_bind(),
        ChaosAnswer::Reply(ChaosReply::rcode(ResponseCode::Refused)),
    )
    .ttl(60);
    server.identity = Some(identity.clone());
    let mut engine = AuthorityEngine::new(Counting(calls.clone()), server, local());
    let chaos_query = |qname: &str, qtype: RecordType| {
        query(qname, qtype, |m| {
            m.queries[0].set_query_class(DNSClass::CH);
        })
    };

    let reply = the_answer(&ask_with(
        &mut engine,
        &chaos_query("ID.Server.", RecordType::TXT),
        Transport::Udp,
    ));
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.metadata.authoritative);
    assert_eq!(reply.answers.len(), 1);
    let record = &reply.answers[0];
    assert_eq!(record.name.to_string(), "ID.Server.");
    assert_eq!(record.dns_class, DNSClass::CH);
    assert_eq!(record.ttl, 60);
    assert_eq!(record.data, RData::TXT(TXT::new(vec!["sjc07".to_string()])));

    let reply = the_answer(&ask_with(
        &mut engine,
        &chaos_query("version.bind.", RecordType::TXT),
        Transport::Udp,
    ));
    assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
    assert!(reply.answers.is_empty());

    let reply = the_answer(&ask_with(
        &mut engine,
        &chaos_query("hostname.bind.", RecordType::TXT),
        Transport::Udp,
    ));
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);

    // The IN lookup never sees a CHAOS question.
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // NSD leaves AA clear and refuses other types; Verisign answers them
    // with NOTIMP and no OPT record; e.root and f.root with NOTIMP and EDE
    // 21, advertising 512 octets.
    let not_supported = Ede {
        code: EdeCode::NOT_SUPPORTED,
        text: Some("Unsupported DNS Type for Class CHAOS".to_string()),
    };
    let fronts = [
        (
            Identity {
                aa: false,
                other_types: ChaosReply::rcode(ResponseCode::Refused),
                ..identity.clone()
            },
            false,
            ResponseCode::Refused,
            Some(1232),
            None,
        ),
        (
            Identity {
                other_types: ChaosReply {
                    edns: false,
                    ..ChaosReply::rcode(ResponseCode::NotImp)
                },
                ..identity.clone()
            },
            true,
            ResponseCode::NotImp,
            None,
            None,
        ),
        (
            Identity {
                other_types: ChaosReply {
                    ede: Some(not_supported.clone()),
                    ..ChaosReply::rcode(ResponseCode::NotImp)
                },
                payload: Some(512),
                ..identity
            },
            true,
            ResponseCode::NotImp,
            Some(512),
            Some(not_supported),
        ),
    ];
    for (identity, aa, rcode, payload, ede) in fronts {
        let server = ServerConfig {
            identity: Some(identity),
            ..ServerConfig::generic()
        };
        let mut engine = AuthorityEngine::new(Counting(calls.clone()), server, local());
        let mut txt = chaos_query("id.server.", RecordType::TXT);
        txt.set_edns(Edns::new());
        let reply = the_answer(&ask_with(&mut engine, &txt, Transport::Udp));
        assert_eq!(reply.metadata.authoritative, aa);
        assert_eq!(reply.answers.len(), 1);
        let mut a = chaos_query("id.server.", RecordType::A);
        a.set_edns(Edns::new());
        let reply = the_answer(&ask_with(&mut engine, &a, Transport::Udp));
        assert_eq!(reply.metadata.response_code, rcode);
        assert!(!reply.metadata.authoritative);
        assert!(reply.authorities.is_empty());
        assert_eq!(reply.edns.as_ref().map(|edns| edns.max_payload()), payload);
        let sent = reply
            .edns
            .iter()
            .flat_map(|edns| edns.options().as_ref().iter());
        assert_eq!(
            sent.filter_map(|(_, option)| Ede::from_option(option))
                .next(),
            ede
        );
    }
}

/// Each CHAOS name of a BIND server is a zone of its own, as c.root,
/// g.root, and a local BIND 9.20 answered on 2026-11-02.
#[test]
fn bind_serves_each_chaos_name_as_a_zone() {
    let identity = Identity::none()
        .answer(
            chaos::hostname_bind(),
            ChaosAnswer::Zone(Some("lax1a".to_string())),
        )
        .answer(chaos::authors_bind(), ChaosAnswer::Zone(None))
        .answer(
            chaos::version_server(),
            ChaosAnswer::Reply(ChaosReply::rcode(ResponseCode::Refused)),
        );
    let server = ServerConfig {
        identity: Some(identity),
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
        // The text, with the zone's NS when RD is clear.
        (
            ("hostname.bind.", Txt),
            false,
            ResponseCode::NoError,
            vec![host(Txt, 0)],
            vec![host(Ns, 0)],
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
            vec![host(Ns, 0)],
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
        // Below the zone is NXDOMAIN with the SOA, TTL 0 for an SOA question.
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
            vec![host(Soa, 0)],
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

#[test]
fn zone_transfers_reach_the_authority_only_when_offered() {
    let calls = Arc::new(AtomicUsize::new(0));
    let axfr = query("example.test.", RecordType::AXFR, |_| {});

    let mut engine =
        AuthorityEngine::new(Counting(calls.clone()), ServerConfig::generic(), local());
    let reply = the_answer(&ask_with(&mut engine, &axfr, Transport::Tcp));
    assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    // Over UDP a transfer is malformed (RFC 5936 §4.2).
    let reply = the_answer(&ask_with(&mut engine, &axfr, Transport::Udp));
    assert_eq!(reply.metadata.response_code, ResponseCode::FormErr);

    let mut offering = ServerConfig::generic();
    offering.transfer = true;
    let mut engine = AuthorityEngine::new(Counting(calls.clone()), offering.clone(), local());
    ask_with(&mut engine, &axfr, Transport::Tcp);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Zone data answers questions; it cannot list a zone, so zones refuse.
    let mut engine = AuthorityEngine::new(zones(vec![example()]), offering, local());
    let reply = the_answer(&ask_with(&mut engine, &axfr, Transport::Tcp));
    assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
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

// Relays.

#[test]
fn a_relay_answers_with_the_real_reply_restored() {
    let mut engine = relay_engine();
    let message = query("WwW.ExAmPlE.TeSt.", RecordType::A, |m| {
        m.metadata.recursion_desired = true;
        m.set_edns(edns(1232, true));
    });
    let sent = message.to_vec().unwrap();
    let actions = ask_with(&mut engine, &message, Transport::Udp);
    assert_eq!(kinds(&actions), ["query", "send"]);
    let transmit = &sends(&actions)[0];
    assert_eq!(transmit.to, local());
    assert_eq!(transmit.transport, Transport::Udp);
    assert_eq!(Message::from_vec(&transmit.bytes).unwrap(), message);
    assert_eq!(
        engine.next_deadline(),
        Some(Instant::ZERO + Duration::from_secs(5))
    );

    // The real server answers in lowercase, with a record of a type
    // hickory does not know, which must pass as it is (RFC 3597).
    let real = real_reply(transmit, |m| {
        m.add_answer(Record::from_rdata(
            name("www.example.test."),
            60,
            a("192.0.2.10"),
        ));
        m.add_answer(Record::from_rdata(
            name("www.example.test."),
            60,
            RData::Unknown {
                code: RecordType::Unknown(65400),
                rdata: fictionet::stdlib::protocols::dns::rr::rdata::NULL::with(vec![1, 2, 3, 4]),
            },
        ));
    });
    let actions = run(&mut engine, reply_to(transmit, real.clone()), Instant::ZERO);
    assert_eq!(kinds(&actions), ["asked", "reply", "answer"]);
    let bytes = answer_bytes(&actions);
    assert_eq!(bytes.len(), real.len());
    assert_eq!(question_octets(&bytes), question_octets(&sent));
    let at = 12 + question_octets(&sent).len();
    assert_eq!(&bytes[..2], &sent[..2]);
    assert_eq!(&bytes[2..12], &real[2..12]);
    assert_eq!(&bytes[at..], &real[at..]);
    assert_eq!(engine.next_deadline(), None);
}

#[test]
fn a_relay_is_silent_when_the_real_server_times_out() {
    let mut engine = relay_engine();
    let actions = ask_with(
        &mut engine,
        &query("www.example.test.", RecordType::A, |_| {}),
        Transport::Udp,
    );
    let transmit = sends(&actions)[0].clone();
    let deadline = engine.next_deadline().unwrap();

    // A tick before the deadline changes nothing.
    let early = run(
        &mut engine,
        Input::Tick,
        Instant::ZERO + Duration::from_secs(1),
    );
    assert!(early.is_empty());

    let actions = run(&mut engine, Input::Tick, deadline);
    assert_eq!(kinds(&actions), ["abandon", "asked"]);
    assert_eq!(abandoned(&actions), [transmit.token]);
    assert!(matches!(
        actions[1],
        Action::Event(Event::Asked {
            observed: ObservedKind::Timeout,
            ..
        })
    ));
    assert_eq!(engine.next_deadline(), None);
}

#[test]
fn a_relay_is_silent_when_the_real_server_is_unreachable() {
    for failure in [
        ExchangeFailure::Unreachable,
        ExchangeFailure::Refused,
        ExchangeFailure::Closed,
    ] {
        let mut engine = relay_engine();
        let actions = ask_with(
            &mut engine,
            &query("www.example.test.", RecordType::A, |_| {}),
            Transport::Tcp,
        );
        let transmit = sends(&actions)[0].clone();
        assert_eq!(transmit.transport, Transport::Tcp);
        let failed = Input::Failed {
            token: transmit.token,
            failure,
        };
        let actions = run(&mut engine, failed, Instant::ZERO);
        assert_eq!(kinds(&actions), ["asked"]);
        assert!(matches!(
            actions[0],
            Action::Event(Event::Asked {
                observed: ObservedKind::Unreachable,
                ..
            })
        ));
        assert_eq!(engine.next_deadline(), None);
    }
}

#[test]
fn a_relayed_reply_larger_than_the_client_takes_is_truncated() {
    let mut engine = relay_engine();
    let message = query("big.example.test.", RecordType::A, |_| {});
    let actions = ask_with(&mut engine, &message, Transport::Udp);
    let transmit = sends(&actions)[0].clone();
    // A reply a source fetched over TCP, far past 512 octets.
    let real = real_reply(&transmit, |m| {
        for host in 1..=60 {
            m.add_answer(Record::from_rdata(
                name("big.example.test."),
                60,
                a(&format!("192.0.2.{host}")),
            ));
        }
    });
    assert!(real.len() > 512);
    let bytes = answer_bytes(&run(&mut engine, reply_to(&transmit, real), Instant::ZERO));
    assert!(bytes.len() <= 512);
    let reply = Message::from_vec(&bytes).unwrap();
    assert!(reply.metadata.truncation);
    assert_eq!(reply.metadata.id, 0x1234);
}

// Completions that change nothing.

#[test]
fn completions_from_the_wrong_place_or_for_the_wrong_question_are_ignored() {
    let mut engine = relay_engine();
    let actions = ask_with(
        &mut engine,
        &query("www.example.test.", RecordType::A, |_| {}),
        Transport::Udp,
    );
    let transmit = sends(&actions)[0].clone();
    let deadline = engine.next_deadline();
    let good = real_reply(&transmit, |m| {
        m.add_answer(Record::from_rdata(
            name("www.example.test."),
            60,
            a("192.0.2.10"),
        ));
    });

    let elsewhere = Input::Reply {
        token: transmit.token,
        from: "192.0.2.99:53".parse().unwrap(),
        transport: Transport::Udp,
        bytes: good.clone(),
    };
    let over_tcp = Input::Reply {
        token: transmit.token,
        from: transmit.to,
        transport: Transport::Tcp,
        bytes: good.clone(),
    };
    let mut wrong_id = good.clone();
    wrong_id[0] ^= 0xff;
    let other_question = real_reply(&transmit, |m| {
        m.queries[0].set_query_type(RecordType::AAAA);
    });
    let not_a_response = transmit.bytes.clone();
    let cases = [
        (elsewhere, Unmatched::WrongPeer),
        (over_tcp, Unmatched::WrongPeer),
        (reply_to(&transmit, wrong_id), Unmatched::WrongId),
        (
            reply_to(&transmit, other_question),
            Unmatched::WrongQuestion,
        ),
        (reply_to(&transmit, not_a_response), Unmatched::Malformed),
        (reply_to(&transmit, vec![0; 7]), Unmatched::Malformed),
    ];
    for (input, why) in cases {
        let actions = run(&mut engine, input, Instant::ZERO);
        assert_eq!(ignored(&actions), [why]);
        assert_eq!(kinds(&actions), ["ignored"]);
        // The exchange is still outstanding, with the same deadline.
        assert_eq!(engine.next_deadline(), deadline);
    }

    let actions = run(
        &mut engine,
        reply_to(&transmit, good.clone()),
        Instant::ZERO,
    );
    assert_eq!(answers(&actions).len(), 1);

    // The same reply again, and a failure after it, are stale.
    let actions = run(&mut engine, reply_to(&transmit, good), Instant::ZERO);
    assert_eq!(ignored(&actions), [Unmatched::NotOutstanding]);
    let late = Input::Failed {
        token: transmit.token,
        failure: ExchangeFailure::Unreachable,
    };
    let actions = run(&mut engine, late, Instant::ZERO);
    assert_eq!(ignored(&actions), [Unmatched::NotOutstanding]);
    assert!(matches!(
        actions[0],
        Action::Event(Event::Ignored { from: None, .. })
    ));
}

#[test]
fn advance_abandons_every_exchange_and_restarts_the_requests() {
    let mut engine = relay_engine();
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
    let old: Vec<Transmit> = sends(&first).into_iter().chain(sends(&second)).collect();
    assert_eq!(old.len(), 2);
    assert_eq!(engine.generation(), Generation(0));

    engine.advance(session(1));
    let actions: Vec<Action> = std::iter::from_fn(|| engine.poll()).collect();
    assert_eq!(engine.generation(), Generation(1));
    assert_eq!(kinds(&actions), ["abandon", "abandon", "send", "send"]);
    let mut gone = abandoned(&actions);
    gone.sort();
    let mut tokens: Vec<Token> = old.iter().map(|transmit| transmit.token).collect();
    tokens.sort();
    assert_eq!(gone, tokens);
    let new = sends(&actions);
    for (old, new) in old.iter().zip(&new) {
        assert_eq!(new.token.generation(), Generation(1));
        assert!(!tokens.contains(&new.token));
        assert_eq!(new.bytes, old.bytes);
    }

    // A completion of the old session changes nothing.
    let stale = real_reply(&old[0], |_| {});
    let actions = run(&mut engine, reply_to(&old[0], stale), Instant::ZERO);
    assert_eq!(ignored(&actions), [Unmatched::OldGeneration]);

    // The restarted request is answered from the new session.
    let fresh = real_reply(&new[0], |m| {
        m.add_answer(Record::from_rdata(
            name("one.example.test."),
            60,
            a("192.0.2.11"),
        ));
    });
    let actions = run(&mut engine, reply_to(&new[0], fresh), Instant::ZERO);
    assert_eq!(the_answer(&actions).answers.len(), 1);

    // A session that is not newer changes nothing.
    engine.advance(session(1));
    engine.advance(session(0));
    assert!(engine.poll().is_none());
    assert_eq!(engine.generation(), Generation(1));
}

#[test]
fn requests_asking_the_same_question_share_one_exchange() {
    let mut engine = relay_engine();
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
    assert_eq!(sends(&first).len(), 1);
    assert!(sends(&second).is_empty());
    let transmit = sends(&first)[0].clone();

    let actions = run(
        &mut engine,
        reply_to(&transmit, real_reply(&transmit, |_| {})),
        Instant::ZERO,
    );
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
    let mut engine = relay_engine();
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
    let transmit = sends(&first)[0].clone();

    // One of two waiters leaves: the exchange goes on for the other.
    let actions = run(&mut engine, Input::Gone(other), Instant::ZERO);
    assert!(actions.is_empty());
    assert!(engine.next_deadline().is_some());

    // The last waiter leaves: the exchange is abandoned.
    let actions = run(
        &mut engine,
        Input::Gone(client(Transport::Tcp)),
        Instant::ZERO,
    );
    assert_eq!(abandoned(&actions), [transmit.token]);
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

fn overlay() -> Overlay<Relay> {
    Overlay::new(Relay::new(), name("com.")).below(name("fict.com."), zones(vec![fict()]))
}

/// The names between `com` and a deeper invented apex are the base's, so
/// `com` could deny `nonexistent.com` and refer names under it.
#[test]
#[should_panic(expected = "not a child of com.")]
fn an_invented_zone_must_be_a_child_of_the_overlays_zone() {
    let _ = Overlay::new(Relay::new(), name("com."))
        .below(name("shop.nonexistent.com."), zones(vec![fict()]));
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
fn an_overlay_refers_with_the_bases_denial_records_decoded() {
    let mut engine = AuthorityEngine::new(overlay(), ServerConfig::gtld(Identity::none()), local());
    let message = query("www.fict.com.", RecordType::A, |m| {
        m.set_edns(edns(1232, true));
    });
    let actions = ask_with(&mut engine, &message, Transport::Udp);
    assert_eq!(kinds(&actions), ["query", "send"]);
    let transmit = sends(&actions)[0].clone();
    let asked = Message::from_vec(&transmit.bytes).unwrap();
    assert_eq!(asked.queries[0].name(), &name("fict.com."));
    assert_eq!(asked.queries[0].query_type(), RecordType::DS);
    assert!(asked.edns.as_ref().unwrap().flags().dnssec_ok);

    // `com` denies the DS RRset with an SOA and the opt-out NSEC3 record.
    let denial = com_denial();
    let real = real_reply(&transmit, |m| {
        m.metadata.response_code = ResponseCode::NXDomain;
        let com_soa = SOA::new(
            name("a.gtld-servers.net."),
            name("nstld.verisign-grs.com."),
            1,
            1800,
            900,
            604800,
            900,
        );
        m.add_authority(Record::from_rdata(name("com."), 900, RData::SOA(com_soa)));
        for record in &denial {
            m.add_authority(record.clone());
        }
    });
    let actions = run(&mut engine, reply_to(&transmit, real), Instant::ZERO);
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
    let soa = SOA::new(
        name("a.gtld-servers.net."),
        name("nstld.verisign-grs.com."),
        1,
        1800,
        900,
        604800,
        900,
    );
    let mut records = vec![Record::from_rdata(name("com."), 900, RData::SOA(soa))];
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
        let mut engine =
            AuthorityEngine::new(overlay(), ServerConfig::gtld(Identity::none()), local());
        let message = query(qname, qtype, |m| {
            m.set_edns(edns(1232, true));
        });
        let actions = ask_with(&mut engine, &message, Transport::Udp);
        let transmit = sends(&actions)[0].clone();
        let real = real_reply(&transmit, |m| {
            m.metadata.response_code = ResponseCode::NXDomain;
            m.metadata.authoritative = true;
            for record in &nxdomain {
                m.add_authority(record.clone());
            }
        });
        let actions = run(&mut engine, reply_to(&transmit, real), Instant::ZERO);
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
    let transmit = sends(&actions)[0].clone();
    let asked = Message::from_vec(&transmit.bytes).unwrap();
    assert_eq!(asked.queries[0].name(), &name("fict.com."));
    assert_eq!(asked.queries[0].query_type(), RecordType::DS);
    let (nxdomain, _) = com_nxdomain();
    let real = real_reply(&transmit, |m| {
        m.metadata.response_code = ResponseCode::NXDomain;
        for record in &nxdomain {
            m.add_authority(record.clone());
        }
    });
    let actions = run(&mut engine, reply_to(&transmit, real), Instant::ZERO);
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

#[test]
fn an_overlay_is_silent_when_the_ds_question_times_out() {
    let mut engine = AuthorityEngine::new(overlay(), ServerConfig::generic(), local());
    let message = query("www.fict.com.", RecordType::A, |m| {
        m.set_edns(edns(1232, true));
    });
    ask_with(&mut engine, &message, Transport::Udp);
    let deadline = engine.next_deadline().unwrap();
    let actions = run(&mut engine, Input::Tick, deadline);
    assert_eq!(kinds(&actions), ["abandon", "asked"]);
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
        let transmit = &sends(&actions)[0];
        assert_eq!(Message::from_vec(&transmit.bytes).unwrap(), message);
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
        Relay::new(),
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
    assert_eq!(kinds(&actions), ["query", "send"]);
    assert!(matches!(
        &actions[0],
        Action::Event(Event::Query { server, question, .. })
            if *server == local() && question.name() == &name("www.example.test.")
    ));
    assert!(seen.lock().unwrap().is_empty());

    let transmit = sends(&actions)[0].clone();
    engine.handle(
        reply_to(&transmit, real_reply(&transmit, |_| {})),
        Instant::ZERO,
        &entropy(),
    );
    // The callback ran while the engine handled the reply, before the
    // answer could leave.
    assert_eq!(
        *seen.lock().unwrap(),
        [("www.example.test.".to_string(), ResponseCode::NoError)]
    );
    let actions: Vec<Action> = std::iter::from_fn(|| engine.poll()).collect();
    assert_eq!(kinds(&actions), ["asked", "reply", "answer"]);
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
fn an_authority_that_asks_again_what_it_knows_fails() {
    /// Asks the same question whatever it already knows.
    struct Forgetful;
    impl Authority for Forgetful {
        fn respond(
            &self,
            _req: &Request,
            local: SocketAddr,
            _server: &ServerConfig,
            _client: &Client,
            _known: &dyn Known,
        ) -> Step {
            Step::Need(Ask {
                server: local,
                transport: Transport::Udp,
                query: query("www.example.test.", RecordType::A, |_| {})
                    .to_vec()
                    .unwrap(),
            })
        }
    }
    let mut engine = AuthorityEngine::new(Forgetful, ServerConfig::generic(), local());
    let actions = ask_with(
        &mut engine,
        &query("www.example.test.", RecordType::A, |_| {}),
        Transport::Udp,
    );
    let transmit = sends(&actions)[0].clone();
    let deadline = engine.next_deadline().unwrap();
    let actions = run(&mut engine, Input::Tick, deadline);
    let reply = the_answer(&actions);
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(abandoned(&actions), [transmit.token]);
}
