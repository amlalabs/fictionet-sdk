//! Copies of the test internet, resolved in memory: a copy of a signed
//! zone gives a resolver what the zone gives it, and a world that copies
//! the signed hierarchy validates what it copied as the real hierarchy
//! validates.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use fictionet::stdlib::protocols::dns::dnssec::{Insecure, Ring, Validation};
use fictionet::stdlib::protocols::dns::op::{
    Edns, Message, MessageType, OpCode, Query, ResponseCode,
};
use fictionet::stdlib::protocols::dns::rr::rdata::SOA;
use fictionet::stdlib::protocols::dns::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::protocols::dns::{Ede, EdeCode};
use fictionet::stdlib::services::dns::authority::{AuthorityEngine, ServerConfig, Zones};
use fictionet::stdlib::services::dns::memory::{Exchanges, MemoryNet, drive};
use fictionet::stdlib::services::dns::resolver::{Config, Resolver};
use fictionet::stdlib::services::dns::zone::{
    AnyResponse, Denial, Node, Zone, ZoneBuilder, ZoneData,
};
use fictionet::stdlib::services::dns::{
    Action, Client, ClientQuery, Engine, Event, Generation, Input, Looked, Lookup, Session, Tokens,
    Transmit,
};
use fictionet::stdlib::services::serve::Transport;
use fictionet::stdlib::world::net::dns::internet::ROOT_SERVERS;
use fictionet::time::Instant;
use fictionet::{Entropy, Seed, SeededEntropy};
use fictionet_extras::dns::copies::Copies;
use fictionet_extras::dns::roots::{self, GTLD_SERVERS};
use fictionet_test_support::dns::{DNSSEC_FAILED, EXAMPLE_COM, TestInternet, v6};

/// The sandbox's address.
const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// Where the resolver under test answers.
const RESOLVER: Ipv4Addr = Ipv4Addr::new(45, 33, 53, 53);
/// The seed of the entropy the runs draw from.
const SEED: u64 = 11;

/// One question, as a stub resolver asks it.
#[derive(Clone, Copy, Debug)]
struct Question {
    name: &'static str,
    rtype: RecordType,
    /// DO: the client wants DNSSEC records.
    dnssec_ok: bool,
    /// CD: the client checks signatures itself.
    cd: bool,
    transport: Transport,
}

impl Question {
    fn new(name: &'static str, rtype: RecordType) -> Question {
        Question {
            name,
            rtype,
            dnssec_ok: true,
            cd: false,
            transport: Transport::Udp,
        }
    }

    fn cd(self) -> Question {
        Question { cd: true, ..self }
    }

    fn tcp(self) -> Question {
        Question {
            transport: Transport::Tcp,
            ..self
        }
    }

    /// The query `dig` sends: RD and AD set, and an OPT record offering
    /// 1232 octets, with DO and CD as asked.
    fn bytes(&self, id: u16) -> Vec<u8> {
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.metadata.authentic_data = true;
        message.metadata.checking_disabled = self.cd;
        message.add_query(Query::query(name(self.name), self.rtype));
        let mut edns = Edns::new();
        edns.set_max_payload(1232).set_dnssec_ok(self.dnssec_ok);
        message.set_edns(edns);
        message.to_vec().expect("a query writes")
    }
}

/// The questions every path is asked: positive, negative, and alias
/// answers under a signed zone; a reply too large for UDP; delegations
/// proven unsigned by NSEC and by opt-out NSEC3; a zone invented under an
/// opt-out parent; a broken chain with and without CD; and a reverse name.
fn questions() -> Vec<Question> {
    vec![
        Question::new("www.example.com.", RecordType::A),
        Question::new("example.com.", RecordType::MX),
        Question::new("alias.example.com.", RecordType::A),
        Question::new("nx.example.com.", RecordType::A),
        Question::new("www.example.com.", RecordType::TXT),
        Question::new("big.example.com.", RecordType::TXT).tcp(),
        Question::new("nonexistent-xyz.com.", RecordType::A),
        Question::new("www.example.net.", RecordType::A),
        Question::new("www.example.org.", RecordType::A),
        Question::new("www.fict.com.", RecordType::A),
        Question::new("www.dnssec-failed.com.", RecordType::A),
        Question::new("www.dnssec-failed.com.", RecordType::A).cd(),
        Question::new("8.8.8.8.in-addr.arpa.", RecordType::PTR),
    ]
}

/// What a client saw for one question, and what the resolver established
/// about it. Records are compared without their TTLs, which count down
/// with each path's own clock, and in sorted order, since a section is a
/// set of RRsets.
#[derive(Clone, Debug, PartialEq)]
struct Outcome {
    rcode: ResponseCode,
    aa: bool,
    tc: bool,
    ra: bool,
    ad: bool,
    answers: Vec<String>,
    authorities: Vec<String>,
    edes: Vec<EdeCode>,
    validation: Validation,
    /// The Extended DNS Error the resolver reported with its reply.
    reported: Option<EdeCode>,
}

impl Outcome {
    fn of(reply: &[u8], validation: Validation, reported: Option<EdeCode>) -> Outcome {
        let reply = Message::from_vec(reply).expect("a reply parses");
        let metadata = &reply.metadata;
        Outcome {
            rcode: metadata.response_code,
            aa: metadata.authoritative,
            tc: metadata.truncation,
            ra: metadata.recursion_available,
            ad: metadata.authentic_data,
            answers: records(&reply.answers),
            authorities: records(&reply.authorities),
            edes: edes(&reply),
            validation,
            reported,
        }
    }
}

/// Each record as `owner type data`, sorted.
fn records(records: &[Record]) -> Vec<String> {
    let mut texts: Vec<String> = records
        .iter()
        .map(|record| format!("{} {} {}", record.name, record.record_type(), record.data))
        .collect();
    texts.sort();
    texts
}

fn edes(message: &Message) -> Vec<EdeCode> {
    message
        .edns
        .iter()
        .flat_map(|edns| edns.options().as_ref().iter())
        .filter_map(|(_, option)| Ede::from_option(option))
        .map(|ede| ede.code)
        .collect()
}

/// Every address of `example.com`'s servers.
fn example_com() -> Vec<IpAddr> {
    EXAMPLE_COM
        .iter()
        .flat_map(|a| [IpAddr::V4(*a), IpAddr::V6(v6(*a))])
        .collect()
}

fn name(text: &str) -> Name {
    Name::from_ascii(text).expect("a test name")
}

// ---------------------------------------------------------------------------
// The in-memory path

/// A resolver whose replies' validations are kept as the resolver reports
/// them. The resolver is driven exactly as it would be bare.
struct Watched {
    resolver: Resolver,
    /// Each reply's validation and Extended DNS Error, in order.
    replies: Vec<(Validation, Option<EdeCode>)>,
    now: Instant,
}

impl Engine for Watched {
    fn handle(&mut self, input: Input, now: Instant, entropy: &dyn Entropy) {
        self.now = self.now.max(now);
        self.resolver.handle(input, now, entropy);
    }

    fn poll(&mut self) -> Option<Action> {
        let action = self.resolver.poll();
        if let Some(Action::Event(Event::Reply {
            validation, ede, ..
        })) = &action
        {
            self.replies.push((*validation, *ede));
        }
        action
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.resolver.next_deadline()
    }

    fn advance(&mut self, session: Session) {
        self.resolver.advance(session);
    }

    fn generation(&self) -> Generation {
        self.resolver.generation()
    }
}

fn client(port: u16, transport: Transport) -> Client {
    Client {
        peer: SocketAddr::new(IpAddr::V4(ME), port),
        local: SocketAddr::new(IpAddr::V4(RESOLVER), 53),
        transport,
        connection: (transport == Transport::Tcp).then_some(u64::from(port)),
        sandbox: None,
    }
}

/// What a fresh resolver with `config` gives `questions` through `net`,
/// asked one after another: each reply's octets, and its outcome.
fn in_memory(
    net: &mut impl Exchanges,
    config: &Config,
    questions: &[Question],
) -> Vec<(Vec<u8>, Outcome)> {
    let entropy = SeededEntropy::new(Seed::from_u64(SEED));
    let mut engine = Watched {
        resolver: Resolver::new(config.clone(), Ring, TestInternet::clock()),
        replies: Vec::new(),
        now: Instant::ZERO,
    };
    questions
        .iter()
        .enumerate()
        .map(|(n, question)| {
            let port = 40_000 + n as u16;
            let query = ClientQuery {
                client: client(port, question.transport),
                bytes: question.bytes(port),
            };
            let start = engine.now;
            let answers = drive(&mut engine, net, vec![query], start, &entropy);
            let [answer] = answers.as_slice() else {
                panic!("one answer to {question:?}, got {}", answers.len());
            };
            assert_eq!(engine.replies.len(), n + 1, "one reply event per answer");
            let (validation, ede) = engine.replies[n];
            let outcome = Outcome::of(&answer.bytes, validation, ede);
            (answer.bytes.clone(), outcome)
        })
        .collect()
}

/// `example.com` with only the names below its apex besides its SOA and
/// NS RRsets: a `Lazy` zone holds its apex from the start and never asks
/// its provider about it, so apex data beyond those two RRsets can only
/// come from a complete zone.
fn below_apex(zone: &Zone) -> Zone {
    let (soa, ttl, ns) = apex_of(zone);
    let mut builder = Zone::builder(Name::from(zone.apex()), soa, ttl).rrset(ns);
    for (owner, node) in zone.nodes() {
        if let (false, Node::Data(sets)) = (owner == zone.apex(), node) {
            builder = sets.values().cloned().fold(builder, ZoneBuilder::rrset);
        }
    }
    builder
        .build()
        .expect("the names below the apex make a zone")
}

/// The SOA record data, its TTL, and the NS RRset at `zone`'s apex.
fn apex_of(zone: &Zone) -> (SOA, u32, RecordSet) {
    let Some(Node::Data(sets)) = zone.node(zone.apex()) else {
        panic!("the apex holds data");
    };
    let soa = &sets[&RecordType::SOA];
    let Some(RData::SOA(data)) = soa.records_without_rrsigs().next().map(|r| r.data.clone()) else {
        panic!("an SOA record");
    };
    (data, soa.ttl(), sets[&RecordType::NS].clone())
}

/// The questions the provider and signer test asks of `example.com`.
fn example_questions() -> Vec<Question> {
    vec![
        Question::new("www.example.com.", RecordType::A),
        Question::new("www.example.com.", RecordType::AAAA),
        Question::new("alias.example.com.", RecordType::A),
        Question::new("_dmarc.example.com.", RecordType::TXT),
        Question::new("_xmpp-server._tcp.example.com.", RecordType::SRV),
        Question::new("_tcp.example.com.", RecordType::SRV),
        Question::new("nx.example.com.", RecordType::A),
        Question::new("www.example.com.", RecordType::TXT),
        Question::new("example.com.", RecordType::DNSKEY),
        Question::new("big.example.com.", RecordType::TXT).tcp(),
    ]
}

/// The records of `example.com`, signed once and served from a complete
/// zone, and from a copy learned from what the complete zone's servers
/// answer, get the same validations, Extended DNS Errors, RCODEs, and
/// answers from one resolver configuration.
#[test]
fn a_copy_of_a_signed_zone_validates_as_the_zone_does() {
    let zone = below_apex(&TestInternet::example_com());
    let apex = Name::from(zone.apex());
    let complete = zone
        .signed(
            &TestInternet::example_com_keys(),
            TestInternet::window(),
            Denial::Nsec,
        )
        .expect("the zone signs");
    let complete = Arc::new(complete) as Arc<dyn ZoneData>;
    let questions = example_questions();
    let internet = TestInternet::new();
    let config = internet.config();
    let mut served = internet
        .clone()
        .serving("example.com.", Zones::new(vec![complete.clone()]))
        .memory();
    let want = in_memory(&mut served, &config, &questions);

    // The servers at example.com's addresses answer from a copy of what
    // the complete zone's servers answer them; every other server answers
    // from its zones as before.
    let copies = Copies::new();
    for address in example_com() {
        copies.serves(address, &LowerName::new(&apex));
    }
    let mut served: MemoryNet = internet.clone().serving("example.com.", copies).memory();
    let mut real = internet
        .clone()
        .serving("example.com.", Zones::new(vec![complete]))
        .memory();
    served.upstream(move |lookup| looked_up(&mut real, lookup));
    let got = in_memory(&mut served, &config, &questions);
    for (n, question) in questions.iter().enumerate() {
        let (got, want) = (&got[n].1, &want[n].1);
        assert_eq!(
            (got.validation, got.reported, &got.edes, got.rcode, got.ad),
            (
                want.validation,
                want.reported,
                &want.edes,
                want.rcode,
                want.ad
            ),
            "{question:?} from a copy and from the complete zone"
        );
        assert_eq!(
            got.answers, want.answers,
            "{question:?} from a copy and from the complete zone"
        );
    }
}

// ---------------------------------------------------------------------------
// A world that copies the hierarchy

/// What the servers of `real` give `lookup`, as an upstream on the
/// internet gives it: the query asked over UDP without recursion and
/// with DO, and again over TCP when the response comes back truncated.
fn looked_up(real: &mut MemoryNet, lookup: &Lookup) -> Looked {
    let entropy = SeededEntropy::new(Seed::from_u64(SEED));
    let mut message = Message::new(1, MessageType::Query, OpCode::Query);
    message.add_query(lookup.question.clone());
    let mut edns = Edns::new();
    edns.set_max_payload(1232).set_dnssec_ok(true);
    message.set_edns(edns);
    let bytes = message.to_vec().expect("a lookup's query writes");
    let mut response = None;
    for transport in [Transport::Udp, Transport::Tcp] {
        let transmit = Transmit {
            token: Tokens::new().issue(),
            to: lookup.server,
            transport,
            bytes: bytes.clone(),
        };
        match real.exchange(&transmit, Instant::ZERO, &entropy).as_slice() {
            [Input::Reply { bytes, .. }] => {
                let reply = Message::from_vec(bytes).expect("a real server's reply parses");
                let truncated = reply.metadata.truncation;
                response = Some(reply);
                if !truncated {
                    break;
                }
            }
            [Input::Failed { .. }] => return Looked::Unreachable,
            _ => break,
        }
    }
    response.map_or(Looked::NoReply, Looked::Response)
}

/// `world` with the root letters, the `gtld-servers.net` servers, and the
/// servers of `example.com` and `dnssec-failed.com` answering from
/// copies learned from `real`, behind the fronts `real` gives them. The
/// addresses serve the zones a `Mirror` starts them with, the root at the
/// root letters and `com` and `net` at `gtld-servers.net`, and the zones
/// a `Mirror` would note from the referrals to them. `arpa`, which the
/// real root letters serve too, is learned from their responses.
fn copying(real: &TestInternet, world: TestInternet) -> MemoryNet {
    let mut net = world.memory();
    let copies = Arc::new(Copies::new());
    let mut serve = |addresses: Vec<IpAddr>, front: ServerConfig, apexes: &[&str]| {
        for address in addresses {
            for apex in apexes {
                copies.serves(address, &LowerName::new(&name(apex)));
            }
            let local = SocketAddr::new(address, 53);
            net.serve(
                address,
                AuthorityEngine::new(copies.clone(), front.clone(), local),
            );
        }
    };
    for letter in &ROOT_SERVERS {
        let front = real.letter_front(letter.v4);
        serve(letter.addresses().to_vec(), front, &["."]);
    }
    for server in &GTLD_SERVERS {
        let identity = real.place().site(IpAddr::V4(server.v4)).identity;
        serve(
            server.addresses().to_vec(),
            roots::gtld_front(identity),
            &["com.", "net."],
        );
    }
    let cloudflare = ServerConfig {
        any: AnyResponse::Hinfo { ttl: 3600 },
        ..ServerConfig::generic()
    };
    serve(example_com(), cloudflare, &["example.com."]);
    let failed = [IpAddr::V4(DNSSEC_FAILED), IpAddr::V6(v6(DNSSEC_FAILED))];
    serve(
        failed.to_vec(),
        ServerConfig::generic(),
        &["dnssec-failed.com."],
    );
    let mut upstream = real.memory();
    net.upstream(move |lookup| looked_up(&mut upstream, lookup));
    net
}

/// A world that copies the root, `com`, `net`, `example.com`, and
/// `dnssec-failed.com` from their real servers, here with `example.com`
/// signed with NSEC3, gives the resolver what the real hierarchy gives
/// it: the same validations, Extended DNS Errors, RCODEs, and records.
/// The copied RRSIGs verify, the copied NSEC3 records prove the
/// NXDOMAIN and NODATA answers of `example.com`, the opt-out spans of
/// `com` and `net` prove `fict.com` and `example.net` unsigned and a name
/// under `com` insecurely denied, and the bogus DS of
/// `dnssec-failed.com` stays bogus.
#[test]
fn a_world_that_copies_the_signed_hierarchy_validates_as_the_real_one() {
    let nsec3 = TestInternet::example_com()
        .signed(
            &TestInternet::example_com_keys(),
            TestInternet::window(),
            Denial::Nsec3 {
                opt_out: false,
                salt: Vec::new(),
            },
        )
        .expect("example.com signs with NSEC3");
    let real = TestInternet::new().serving(
        "example.com.",
        Zones::new(vec![Arc::new(nsec3) as Arc<dyn ZoneData>]),
    );
    let config = real.config();
    let questions = questions();

    let mut direct = real.memory();
    let want = in_memory(&mut direct, &config, &questions);
    let mut copied = copying(&real, real.clone());
    let got = in_memory(&mut copied, &config, &questions);
    for (n, question) in questions.iter().enumerate() {
        assert_eq!(got[n].1, want[n].1, "{question:?}");
    }
    let validation = |name: &str, rtype: RecordType| {
        let n = questions
            .iter()
            .position(|question| question.name == name && question.rtype == rtype)
            .expect("a question asked");
        (got[n].1.rcode, got[n].1.validation)
    };
    for (name, rtype, rcode) in [
        ("www.example.com.", RecordType::A, ResponseCode::NoError),
        ("nx.example.com.", RecordType::A, ResponseCode::NXDomain),
        ("www.example.com.", RecordType::TXT, ResponseCode::NoError),
    ] {
        assert_eq!(
            validation(name, rtype),
            (rcode, Validation::Secure),
            "{name} {rtype}"
        );
    }
    // The copied opt-out span over the name proves it insecure, as the
    // real one does (RFC 5155 §9.2).
    assert_eq!(
        validation("nonexistent-xyz.com.", RecordType::A),
        (
            ResponseCode::NXDomain,
            Validation::Insecure(Insecure::OptOutCovered)
        )
    );
    assert!(matches!(
        validation("www.example.net.", RecordType::A).1,
        Validation::Insecure(_)
    ));
    assert_eq!(
        validation("www.dnssec-failed.com.", RecordType::A).0,
        ResponseCode::ServFail
    );
}
