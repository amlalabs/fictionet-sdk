//! The drivers with no runtime: servers in memory, recordings of what
//! they answered, and playing those recordings back to a resolver.

use std::net::SocketAddr;

use fictionet::stdlib::protocols::dns::op::{Message, MessageType, OpCode, Query, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::RecordType;
use fictionet::stdlib::services::dns::memory::{Exchanges, Outcome, drive};
use fictionet::stdlib::services::dns::{ExchangeFailure, Input, Token, Tokens, Transmit};
use fictionet::stdlib::services::serve::Transport;

use super::resolver::{
    COM, EXAMPLE, ROOT, addresses, at, client, config, dnssec_ok, entropy, internet, ip, name,
    query, resolver,
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
