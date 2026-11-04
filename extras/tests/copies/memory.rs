//! A copy run in memory, with no runtime: the server files what its
//! upstream gives and stays silent without it.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use fictionet::stdlib::protocols::dns::op::{Message, MessageType, OpCode, Query};
use fictionet::stdlib::protocols::dns::rr::rdata::{A, NS, SOA};
use fictionet::stdlib::protocols::dns::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::protocols::dns::{Parsed, Request};
use fictionet::stdlib::services::dns::authority::{AuthorityEngine, ServerConfig};
use fictionet::stdlib::services::dns::memory::{Exchanges, MemoryNet, Outcome};
use fictionet::stdlib::services::dns::zone::{Answered, AnyResponse, Zone, answer};
use fictionet::stdlib::services::dns::{Input, Looked, Lookup, Token, Tokens, Transmit};
use fictionet::stdlib::services::serve::Transport;
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};
use fictionet_extras::dns::copies::Copies;

/// The address of `example.com`'s real server.
const EXAMPLE: &str = "192.0.2.20";

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
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

fn entropy() -> SeededEntropy {
    SeededEntropy::new(Seed::from_u64(7))
}

fn at(seconds: u64) -> Instant {
    Instant::from_since_start(std::time::Duration::from_secs(seconds))
}

/// The addresses of the A records in `message`'s answer section.
fn addresses(message: &Message) -> Vec<String> {
    message
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(a) => Some(a.0.to_string()),
            _ => None,
        })
        .collect()
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

#[test]
fn a_learned_server_in_memory_files_what_its_upstream_gives_and_is_silent_without_it() {
    let zone = Zone::builder(name("example.com."), soa(), 3600)
        .rrset(rrset("example.com.", 3600, vec![ns("ns1.example.com.")]))
        .rrset(rrset("ns1.example.com.", 3600, vec![a(EXAMPLE)]))
        .rrset(rrset("www.example.com.", 300, vec![a("192.0.2.80")]))
        .build()
        .unwrap();
    let local = SocketAddr::new(ip(EXAMPLE), 53);
    let copies = Copies::new();
    copies.serves(ip(EXAMPLE), &LowerName::new(&name("example.com.")));
    let mut net = MemoryNet::new();
    net.serve(
        ip(EXAMPLE),
        AuthorityEngine::new(copies, ServerConfig::generic(), local),
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
        assert_eq!(addresses(&reply), ["192.0.2.80"]);
    }
    // The second question was answered from what the first filed.
    assert_eq!(looked_up.lock().unwrap().len(), 1);

    // A question the upstream gives nothing for: the server stays silent.
    let (unknown, _) = transmit(EXAMPLE, "mail.example.com.", RecordType::A, 12);
    assert!(net.exchange(&unknown, at(0), &entropy()).is_empty());
    let outcomes: Vec<Outcome> = net
        .recording()
        .exchanges()
        .iter()
        .map(|exchange| exchange.outcome.clone())
        .collect();
    assert!(matches!(outcomes[2], Outcome::Timeout));
}

fn soa() -> SOA {
    SOA::new(
        name("ns1.example.com."),
        name("hostmaster.example.com."),
        1,
        7200,
        3600,
        1209600,
        300,
    )
}
