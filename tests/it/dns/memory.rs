//! The drivers with no runtime: servers in memory, recordings of what
//! they answered, and playing those recordings back to a resolver.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use fictionet::stdlib::network::Transport;
use fictionet::stdlib::protocols::dns::op::{Message, MessageType, OpCode, Query, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::rdata::SOA;
use fictionet::stdlib::protocols::dns::rr::{LowerName, RecordType};
use fictionet::stdlib::protocols::dns::{Parsed, Request};
use fictionet::stdlib::services::dns::authority::{AuthorityEngine, ServerConfig};
use fictionet::stdlib::services::dns::memory::{Exchanges, MemoryNet, Outcome, drive};
use fictionet::stdlib::services::dns::zone::{Answered, AnyResponse, Zone, answer};
use fictionet::stdlib::services::dns::{
    ExchangeFailure, Input, Looked, Lookup, Token, Tokens, Transmit,
};
use fictionet_test_support::lookup_authority::LookupAuthority;

use super::resolver::{
    COM, EXAMPLE, ROOT, a, addresses, at, client, config, dnssec_ok, entropy, internet, ip, name,
    ns, query, resolver, rrset,
};

/// The questions every replay test asks, signed and unsigned, positive
/// and negative, with aliases and name servers without glue.
fn questions() -> Vec<fictionet::stdlib::services::dns::ClientQuery> {
    vec![
        query(client(1), "www.example.com.", RecordType::A, dnssec_ok),
        query(client(2), "alias.example.com.", RecordType::A, dnssec_ok),
        query(client(3), "away.example.com.", RecordType::A, dnssec_ok),
        query(client(4), "nx.example.com.", RecordType::AAAA, dnssec_ok),
        query(client(5), "www.glueless.com.", RecordType::A, |_| {}),
        query(client(6), "www.bad.com.", RecordType::A, dnssec_ok),
        query(client(7), "www.example.org.", RecordType::A, dnssec_ok),
    ]
}

/// A transmit of `qname` `qtype` with `id` to `server`, under a fresh
/// token.
fn transmit(server: &str, qname: &str, qtype: RecordType, id: u16) -> (Transmit, Token) {
    let token = Tokens::new().issue();
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(name(qname), qtype));
    let transmit = Transmit {
        token,
        to: SocketAddr::new(ip(server), 53),
        transport: Transport::Udp,
        bytes: message.to_vec().unwrap(),
    };
    (transmit, token)
}

/// What a fresh resolver gives [`questions`] through `net`, as the
/// answers' octets in the order the questions were asked.
fn answers(net: &mut impl Exchanges, signed_anchor: bool) -> Vec<Vec<u8>> {
    let (_, anchors) = internet(true);
    let anchors = if signed_anchor { anchors } else { None };
    let mut resolver = resolver(config(anchors));
    let mut answers = drive(&mut resolver, net, questions(), at(0), &entropy());
    answers.sort_by_key(|answer| answer.client.peer.port());
    answers.into_iter().map(|answer| answer.bytes).collect()
}

#[test]
fn a_recording_played_back_gives_the_same_answers() {
    let (mut net, _) = internet(true);
    let live = answers(&mut net, true);
    assert_eq!(live.len(), questions().len());
    let replies: Vec<Message> = live.iter().map(|b| Message::from_vec(b).unwrap()).collect();
    assert_eq!(addresses(&replies[0]), ["192.0.2.80"]);
    assert!(replies[0].metadata.authentic_data);
    assert_eq!(replies[3].metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(replies[5].metadata.response_code, ResponseCode::ServFail);

    let mut recording = net.recording();
    let replayed = answers(&mut recording, true);
    assert_eq!(replayed, live);
}

#[test]
fn a_recording_restores_the_id_and_case_and_is_silent_on_what_it_lacks() {
    let (mut net, _) = internet(false);
    // One live exchange to record.
    let (asked, token) = transmit(ROOT, "com.", RecordType::NS, 1);
    let live = net.exchange(&asked, at(0), &entropy());
    assert!(matches!(live.as_slice(), [Input::Reply { .. }]));
    let mut recording = net.recording();

    let (again, _) = transmit(ROOT, "CoM.", RecordType::NS, 0xbeef);
    let inputs = recording.exchange(&again, at(1), &entropy());
    let [
        Input::Reply {
            token: got,
            from,
            bytes,
            ..
        },
    ] = inputs.as_slice()
    else {
        panic!("a recorded reply, got {inputs:?}");
    };
    assert_eq!(*got, token);
    assert_eq!(*from, SocketAddr::new(ip(ROOT), 53));
    let reply = Message::from_vec(bytes).unwrap();
    assert_eq!(reply.metadata.id, 0xbeef);
    assert_eq!(reply.queries[0].name().to_string(), "CoM.");

    // Another question, or the same one to another server, gets nothing.
    let (other, _) = transmit(ROOT, "org.", RecordType::NS, 2);
    assert!(recording.exchange(&other, at(1), &entropy()).is_empty());
    let (elsewhere, _) = transmit(COM, "com.", RecordType::NS, 3);
    assert!(recording.exchange(&elsewhere, at(1), &entropy()).is_empty());
}

#[test]
fn an_address_without_a_server_is_unreachable_and_a_lost_transmit_gets_nothing() {
    let (mut net, _) = internet(false);
    let (nowhere, token) = transmit("203.0.113.1", "com.", RecordType::NS, 1);
    let inputs = net.exchange(&nowhere, at(0), &entropy());
    assert_eq!(
        inputs,
        [Input::Failed {
            token,
            failure: ExchangeFailure::Unreachable
        }]
    );
    net.lose(|transmit| transmit.to.ip() == ip(EXAMPLE));
    let (lost, _) = transmit(EXAMPLE, "www.example.com.", RecordType::A, 2);
    assert!(net.exchange(&lost, at(0), &entropy()).is_empty());
    let recording = net.recording();
    let outcomes: Vec<&Outcome> = recording
        .exchanges()
        .iter()
        .map(|exchange| &exchange.outcome)
        .collect();
    assert_eq!(outcomes, [&Outcome::Unreachable, &Outcome::Timeout]);
}

/// A server whose authority looks up what it lacks gets its lookups
/// answered by the network's upstream, files what came back, and answers
/// from it; a question the upstream gives nothing for gets no reply.
#[test]
fn a_server_in_memory_files_what_its_upstream_gives_and_is_silent_without_it() {
    let soa = SOA::new(
        name("ns1.example.com."),
        name("hostmaster.example.com."),
        1,
        7200,
        3600,
        1209600,
        300,
    );
    let zone = Zone::builder(name("example.com."), soa, 3600)
        .rrset(rrset("example.com.", 3600, vec![ns("ns1.example.com.")]))
        .rrset(rrset("ns1.example.com.", 3600, vec![a(EXAMPLE)]))
        .rrset(rrset("www.example.com.", 300, vec![a("192.0.2.80")]))
        .build()
        .unwrap();
    let local = SocketAddr::new(ip(EXAMPLE), 53);
    let mut net = MemoryNet::new();
    net.serve(
        ip(EXAMPLE),
        AuthorityEngine::new(
            LookupAuthority::new("example.com."),
            ServerConfig::generic(),
            local,
        ),
    );
    // The real server answers `www` from its zone, and nothing else.
    let looked_up: Arc<Mutex<Vec<Lookup>>> = Arc::default();
    let seen = looked_up.clone();
    net.upstream(move |lookup: &Lookup| {
        seen.lock().unwrap().push(lookup.clone());
        if lookup.question.name() != &name("www.example.com.") {
            return Looked::NoReply;
        }
        let mut message = Message::new(1, MessageType::Query, OpCode::Query);
        message.add_query(lookup.question.clone());
        let Parsed::Request(req) = Request::parse(&message.to_vec().unwrap(), Transport::Udp)
        else {
            panic!("a lookup's question parses");
        };
        match answer(&zone, &req, AnyResponse::All) {
            Answered::Response(response) => Looked::Response(response.message),
            Answered::Unknown { name, .. } => panic!("a complete zone knows {name}"),
        }
    });
    for id in [10, 11] {
        let (asked, _) = transmit(EXAMPLE, "www.example.com.", RecordType::A, id);
        let inputs = net.exchange(&asked, at(0), &entropy());
        let [Input::Reply { bytes, .. }] = inputs.as_slice() else {
            panic!("the server answers, got {inputs:?}");
        };
        let reply = Message::from_vec(bytes).unwrap();
        assert_eq!(reply.metadata.id, id);
        assert!(reply.metadata.authoritative);
        assert_eq!(addresses(&reply), ["192.0.2.80"]);
    }
    // The second question was answered from what the first filed.
    assert_eq!(
        *looked_up.lock().unwrap(),
        [Lookup::new(
            local,
            LowerName::new(&name("example.com.")),
            &Query::query(name("www.example.com."), RecordType::A),
        )]
    );

    // A question the upstream gives nothing for: the server stays silent.
    let (unknown, _) = transmit(EXAMPLE, "mail.example.com.", RecordType::A, 12);
    assert!(net.exchange(&unknown, at(0), &entropy()).is_empty());
    assert_eq!(looked_up.lock().unwrap().len(), 2);
    let outcomes: Vec<Outcome> = net
        .recording()
        .exchanges()
        .iter()
        .map(|exchange| exchange.outcome.clone())
        .collect();
    assert!(matches!(outcomes[2], Outcome::Timeout));
}
