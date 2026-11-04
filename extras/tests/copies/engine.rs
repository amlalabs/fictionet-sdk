//! The authoritative engine running copies, driven directly with inputs:
//! a copy looks up what it lacks and answers from what it filed, follows
//! an alias into a child its server serves, and stays silent when the
//! real server gives nothing.

use std::net::SocketAddr;
use std::time::Duration;

use fictionet::stdlib::protocols::dns::op::{
    Edns, Message, MessageType, OpCode, Query, ResponseCode,
};
use fictionet::stdlib::protocols::dns::rr::rdata::{A, CNAME, NS};
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData, Record, RecordType};
use fictionet::stdlib::services::dns::authority::{AuthorityEngine, ServerConfig};
use fictionet::stdlib::services::dns::{
    Action, Client, ClientQuery, Engine, Event, Input, Looked, Lookup, LookupOutcome, Token,
};
use fictionet::stdlib::services::serve::Transport;
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};
use fictionet_extras::dns::copies::Copies;

/// The server the engines under test run at.
const LOCAL: &str = "192.0.2.53:53";

fn local() -> SocketAddr {
    LOCAL.parse().unwrap()
}

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

fn a(text: &str) -> RData {
    RData::A(A(text.parse().unwrap()))
}

fn ns(text: &str) -> RData {
    RData::NS(NS(name(text)))
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

/// A server of `example.test.` whose zone is learned from the real
/// server at its own address.
fn learned_engine() -> AuthorityEngine<Copies> {
    AuthorityEngine::new(
        learned(&["example.test."]),
        ServerConfig::generic(),
        local(),
    )
}

/// Copies of the zones at `apexes`, served at [`LOCAL`] and learned from
/// the real server there.
fn learned(apexes: &[&str]) -> Copies {
    let copies = Copies::new();
    for apex in apexes {
        copies.serves(local().ip(), &LowerName::new(&name(apex)));
    }
    copies
}

/// The lookup a learned server at [`LOCAL`] makes of `qname` and `qtype`
/// for the zone at `zone`.
fn lookup_of(zone: &str, qname: &str, qtype: RecordType) -> Lookup {
    Lookup::new(
        local(),
        LowerName::new(&name(zone)),
        &Query::query(name(qname), qtype),
    )
}

#[test]
fn a_learned_server_looks_up_what_it_lacks_and_answers_from_what_it_filed() {
    let mut engine = learned_engine();
    let message = query("WwW.ExAmPlE.TeSt.", RecordType::A, |m| {
        m.metadata.recursion_desired = true;
        m.set_edns(edns(1232, true));
    });
    let sent = message.to_vec().unwrap();
    let actions = ask_with(&mut engine, &message, Transport::Udp);
    assert_eq!(kinds(&actions), ["query", "lookup"]);
    let (token, lookup) = lookups(&actions)[0].clone();
    assert_eq!(
        lookup,
        lookup_of("example.test.", "www.example.test.", RecordType::A)
    );
    assert_eq!(
        engine.next_deadline(),
        Some(Instant::ZERO + Duration::from_secs(5))
    );

    // The real server answers with the A RRset and a record of a type
    // hickory does not know (RFC 3597), filed as an RRset of its own.
    let real = real_response(&lookup, |m| {
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
    let actions = run(&mut engine, looked(token, real), Instant::ZERO);
    assert_eq!(kinds(&actions), ["looked", "reply", "answer"]);
    assert!(matches!(
        actions[0],
        Action::Event(Event::Looked {
            outcome: LookupOutcome::Response {
                rcode: ResponseCode::NoError
            },
            ..
        })
    ));
    let bytes = answer_bytes(&actions);
    // The world's own reply: the client's ID and question case, AA from
    // the zone, and only the RRset asked for.
    assert_eq!(&bytes[..2], &sent[..2]);
    assert_eq!(question_octets(&bytes), question_octets(&sent));
    let reply = Message::from_vec(&bytes).unwrap();
    assert!(reply.metadata.authoritative);
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(reply.answers[0].data, a("192.0.2.10"));
    assert_eq!(reply.answers[0].name.to_string(), "WwW.ExAmPlE.TeSt.");
    assert_eq!(engine.next_deadline(), None);

    // The fact is held now: the same question needs no lookup.
    let actions = ask_with(&mut engine, &message, Transport::Udp);
    assert_eq!(kinds(&actions), ["query", "reply", "answer"]);
    // Another type at the name is not known, so it is looked up, never
    // answered NODATA.
    let other = query("www.example.test.", RecordType::AAAA, |_| {});
    let actions = ask_with(&mut engine, &other, Transport::Udp);
    assert_eq!(kinds(&actions), ["query", "lookup"]);
}

/// A real server that serves `example.test` and its child
/// `sub.example.test` follows an alias into the child from the child's
/// data, as step 1 searches every zone it holds (RFC 1034 §4.3.2 step
/// 3a). A copy of it answers the alias with the chain, whether or not it
/// was noted for the child: it never stays silent.
#[test]
fn a_learned_alias_into_a_child_its_server_serves_is_answered() {
    let alias = || {
        Record::from_rdata(
            name("alias3.example.test."),
            300,
            RData::CNAME(CNAME(name("www.sub.example.test."))),
        )
    };
    let target = || Record::from_rdata(name("www.sub.example.test."), 300, a("192.0.2.20"));
    let child_ns =
        || Record::from_rdata(name("sub.example.test."), 3600, ns("ns1.sub.example.test."));
    for noted in [
        &["example.test."][..],
        &["example.test.", "sub.example.test."],
    ] {
        let mut engine = AuthorityEngine::new(learned(noted), ServerConfig::generic(), local());
        let message = query("alias3.example.test.", RecordType::A, |_| {});
        let mut actions = ask_with(&mut engine, &message, Transport::Udp);
        let mut asked = Vec::new();
        while let [(token, lookup)] = lookups(&actions).as_slice() {
            let (token, lookup) = (*token, lookup.clone());
            assert!(!asked.contains(&lookup), "{noted:?}: {lookup:?} again");
            let real = real_response(&lookup, |m| {
                if lookup.question.name().to_ascii() == "alias3.example.test." {
                    m.add_answer(alias());
                } else {
                    // The child's data, with the child's NS RRset in the
                    // authority section, as BIND sends it.
                    m.add_answer(target());
                    m.add_authority(child_ns());
                }
            });
            asked.push(lookup);
            actions = run(&mut engine, looked(token, real), Instant::ZERO);
        }
        let reply = the_answer(&actions);
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.metadata.authoritative);
        assert_eq!(
            reply
                .answers
                .iter()
                .map(|r| r.data.clone())
                .collect::<Vec<_>>(),
            [alias().data, target().data],
            "{noted:?}"
        );
        let zones: Vec<String> = asked.iter().map(|lookup| lookup.zone.to_string()).collect();
        assert_eq!(
            zones.last().map(String::as_str),
            Some(if noted.len() == 2 {
                "sub.example.test."
            } else {
                "example.test."
            }),
            "{noted:?}: the target is asked in {zones:?}"
        );
    }
}

#[test]
fn a_learned_server_is_silent_when_the_lookup_gets_no_reply() {
    let mut engine = learned_engine();
    let actions = ask_with(
        &mut engine,
        &query("www.example.test.", RecordType::A, |_| {}),
        Transport::Udp,
    );
    let (token, _) = lookups(&actions)[0].clone();
    let deadline = engine.next_deadline().unwrap();

    // A tick before the deadline changes nothing.
    let early = run(
        &mut engine,
        Input::Tick,
        Instant::ZERO + Duration::from_secs(1),
    );
    assert!(early.is_empty());

    let actions = run(&mut engine, Input::Tick, deadline);
    assert_eq!(kinds(&actions), ["abandon", "looked"]);
    assert_eq!(abandoned(&actions), [token]);
    assert!(matches!(
        actions[1],
        Action::Event(Event::Looked {
            outcome: LookupOutcome::NoReply,
            ..
        })
    ));
    assert_eq!(engine.next_deadline(), None);
}

/// A copy's server sends nothing when the real server could not be
/// reached or sent nothing. When the real server refused the question, or
/// answered it without authority, it does not serve the zone (RFC 8906
/// §3.1.1), and the copy's server refuses it too ([`Copies`]). It never
/// makes up an answer.
#[test]
fn a_learned_server_is_silent_when_the_real_server_is_unreachable_or_says_nothing() {
    let refused = |lookup: &Lookup| {
        real_response(lookup, |m| {
            m.metadata.authoritative = false;
            m.metadata.response_code = ResponseCode::Refused;
        })
    };
    let lame = |lookup: &Lookup| {
        // An answer without AA is no authoritative data (RFC 2181 §5.4.1).
        real_response(lookup, |m| {
            m.metadata.authoritative = false;
            m.add_answer(Record::from_rdata(
                name("www.example.test."),
                60,
                a("192.0.2.10"),
            ));
        })
    };
    // What the upstream gives the lookup, in each case.
    type Gives = fn(&Lookup) -> Looked;
    let outcomes: [(&str, Gives, &[&str]); 4] = [
        ("unreachable", |_| Looked::Unreachable, &["looked"]),
        ("no reply", |_| Looked::NoReply, &["looked"]),
        ("refused", refused, &["looked", "reply", "answer"]),
        ("lame", lame, &["looked", "reply", "answer"]),
    ];
    for (what, outcome, expected) in outcomes {
        let mut engine = learned_engine();
        let actions = ask_with(
            &mut engine,
            &query("www.example.test.", RecordType::A, |_| {}),
            Transport::Tcp,
        );
        let (token, lookup) = lookups(&actions)[0].clone();
        let actions = run(&mut engine, looked(token, outcome(&lookup)), Instant::ZERO);
        assert_eq!(kinds(&actions), expected, "{what}");
        if expected.contains(&"answer") {
            let reply = the_answer(&actions);
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::Refused,
                "{what}"
            );
            assert!(reply.answers.is_empty(), "{what}");
        }
        assert_eq!(engine.next_deadline(), None, "{what}");
    }
}
