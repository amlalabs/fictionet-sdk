//! The acceptance test of the DNS design: one resolver, unchanged, gives
//! the same answers however its questions travel, and what it accepts
//! depends only on the records it is shown.
//!
//! The same resolver type with the same configuration resolves one list
//! of questions through the test internet three ways: through engines in
//! memory, through hosts on a simulated network, and through the exchanges
//! the first way recorded, played back. Then the same records reach it
//! from a complete zone and from zone data signed as it grows, signed by
//! two implementations of `Sign`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fictionet::stdlib::network::ConnectionExt;
use fictionet::stdlib::network::Transport;
use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSKEY;
use fictionet::stdlib::protocols::dns::dnssec::{
    Insecure, KeyFlags, KeySet, PublicKeyBuf, Ring, Sign, Validation,
};
use fictionet::stdlib::protocols::dns::op::{
    Edns, Message, MessageType, OpCode, Query, ResponseCode,
};
use fictionet::stdlib::protocols::dns::rr::rdata::SOA;
use fictionet::stdlib::protocols::dns::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::protocols::dns::{Ede, EdeCode};
use fictionet::stdlib::services::dns::authority::Zones;
use fictionet::stdlib::services::dns::memory::{Exchanges, Recording, drive};
use fictionet::stdlib::services::dns::resolver::{Config, Resolver};
use fictionet::stdlib::services::dns::zone::{
    Denial, Fact, Lazy, Node, Provider, Signed, Zone, ZoneBuilder, ZoneData,
};
use fictionet::stdlib::services::dns::{
    Action, Client, ClientQuery, Engine, Event, Generation, Input, Session,
};
use fictionet::stdlib::world::net::dns::Recursive;
use fictionet::stdlib::world::net::{Host, Net};
use fictionet::time::Instant;
use fictionet::{Cx, Entropy, Seed, SeededEntropy};
use fictionet_test_support::dns::{EXAMPLE_COM, TestInternet, v6};
use fictionet_test_support::sandbox::{Machine, machine};
use fictionet_test_support::timeout;

use fictionet_test_support::world::world;

/// The sandbox's address on the simulated network.
pub(super) const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// Where the resolver under test answers, on the simulated network and in
/// memory.
const RESOLVER: Ipv4Addr = Ipv4Addr::new(45, 33, 53, 53);
/// The seed of the entropy the in-memory and recorded runs draw from. The
/// recorded run must draw what the first drew, or it would ask servers
/// the recording never heard from.
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

pub(super) fn edes(message: &Message) -> Vec<EdeCode> {
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
// The in-memory and recorded paths

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

// ---------------------------------------------------------------------------
// The packet path

/// What `server` answers `query` over UDP.
pub(super) async fn udp(fcx: &Cx, m: &Machine, server: SocketAddr, query: &[u8]) -> Vec<u8> {
    let mut socket = m.udp.bind(0).expect("a UDP socket");
    socket.send_to(query, server);
    loop {
        let (bytes, from) = timeout(fcx, Duration::from_secs(10), socket.recv(fcx))
            .await
            .unwrap_or_else(|| panic!("{server} answers within ten seconds"))
            .expect("a datagram");
        if from == server {
            return bytes;
        }
    }
}

/// What `server` answers `queries`, sent together on one TCP connection
/// and answered on it in the order the replies come (RFC 7766 §6.2.1.1).
pub(super) async fn tcp(
    fcx: &Cx,
    m: &Machine,
    server: SocketAddr,
    queries: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    let mut conn = m.tcp.connect(fcx, server).await.expect("a TCP connection");
    let mut framed = Vec::new();
    for query in queries {
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(query);
    }
    conn.write_all(fcx, &framed)
        .await
        .expect("the queries are sent");
    let mut replies = Vec::new();
    for _ in queries {
        let mut len = [0u8; 2];
        read_exact(fcx, &mut conn, &mut len).await;
        let mut reply = vec![0u8; usize::from(u16::from_be_bytes(len))];
        read_exact(fcx, &mut conn, &mut reply).await;
        replies.push(reply);
    }
    replies
}

async fn read_exact(fcx: &Cx, conn: &mut impl ConnectionExt, mut buf: &mut [u8]) {
    while !buf.is_empty() {
        let read = timeout(fcx, Duration::from_secs(10), conn.read(fcx, buf))
            .await
            .expect("a reply within ten seconds")
            .expect("the connection stays open");
        assert!(read > 0, "the server closed the connection");
        buf = &mut buf[read..];
    }
}

/// What `question` gets from `server`, over the question's transport.
async fn ask(fcx: &Cx, m: &Machine, server: SocketAddr, question: &Question, id: u16) -> Vec<u8> {
    let query = question.bytes(id);
    match question.transport {
        Transport::Udp => udp(fcx, m, server, &query).await,
        Transport::Tcp => tcp(fcx, m, server, &[query]).await.remove(0),
    }
}

/// What a resolver with `config` on a host of the simulated network gives
/// `questions`, asked one after another from a sandbox, with each reply's
/// validation as the resolver reported it.
fn on_packets(internet: &TestInternet, config: &Config, questions: &[Question]) -> Vec<Outcome> {
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let (hosts, config, questions) = (internet.hosts(), config.clone(), questions.to_vec());
    let kept = outcomes.clone();
    world(Duration::from_secs(300), move |fcx| async move {
        let reported = Arc::new(Mutex::new(Vec::new()));
        let report = reported.clone();
        let resolver = Recursive::new(config, TestInternet::clock()).on_event(move |event| {
            if let Event::Reply {
                validation, ede, ..
            } = event
            {
                report.lock().unwrap().push((*validation, *ede));
            }
        });
        let (attacher, attachments) = fictionet::attachments();
        Net::new(fictionet_extras::network::cdn_pools())
            .hosts(hosts)
            .hosts([Host::new("resolver").at(RESOLVER).program(resolver)])
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let server = SocketAddr::new(IpAddr::V4(RESOLVER), 53);
        for (n, question) in questions.iter().enumerate() {
            let reply = ask(&fcx, &m, server, question, 40_000 + n as u16).await;
            let reported = reported.lock().unwrap().clone();
            assert_eq!(reported.len(), n + 1, "one reply event per answer");
            let (validation, ede) = reported[n];
            kept.lock()
                .unwrap()
                .push(Outcome::of(&reply, validation, ede));
        }
        Ok(())
    });
    Arc::try_unwrap(outcomes).unwrap().into_inner().unwrap()
}

// ---------------------------------------------------------------------------
// Three paths

/// The same `Resolver` with the same `Config` gives the same answers,
/// validations, and Extended DNS Errors through engines in memory, through
/// hosts on a simulated network, and through the recording of the first
/// run played back with the same entropy, and each answer is the one the
/// hierarchy implies.
#[test]
fn one_resolver_answers_alike_in_memory_on_packets_and_from_a_recording() {
    let internet = TestInternet::new();
    let config = internet.config();
    let questions = questions();

    let mut net = internet.memory();
    let memory = in_memory(&mut net, &config, &questions);
    let mut recording: Recording = net.recording();
    // The large TXT RRset came back truncated over UDP, and the resolver
    // asked again over TCP (RFC 7766), which the recording keeps too.
    assert!(recording.exchanges().iter().any(|exchange| {
        exchange.transport == Transport::Tcp && example_com().contains(&exchange.server.ip())
    }));
    let recorded = in_memory(&mut recording, &config, &questions);
    let packets = on_packets(&internet, &config, &questions);
    assert_eq!(packets.len(), questions.len());

    let outcomes: Vec<Outcome> = memory.iter().map(|(_, outcome)| outcome.clone()).collect();
    for (n, question) in questions.iter().enumerate() {
        assert_eq!(
            recorded[n].0, memory[n].0,
            "the recording replays {question:?} octet for octet"
        );
        assert_eq!(
            packets[n], outcomes[n],
            "{question:?} on packets and in memory"
        );
    }

    let of = |name: &str, rtype: RecordType, cd: bool| -> &Outcome {
        let n = questions
            .iter()
            .position(|q| q.name == name && q.rtype == rtype && q.cd == cd)
            .expect("an asked question");
        &outcomes[n]
    };
    let secure = |name: &str, rtype: RecordType| {
        let outcome = of(name, rtype, false);
        assert_eq!(outcome.validation, Validation::Secure, "{name} {rtype}");
        assert!(outcome.ad, "{name} {rtype} has AD");
        assert!(
            !outcome.aa && outcome.ra,
            "{name} {rtype} comes from a resolver"
        );
        outcome
    };
    let www = secure("www.example.com.", RecordType::A);
    assert_eq!(www.rcode, ResponseCode::NoError);
    assert!(
        www.answers
            .contains(&"www.example.com. A 45.33.20.80".to_string()),
        "{www:?}"
    );
    assert!(
        www.answers
            .iter()
            .any(|record| record.starts_with("www.example.com. RRSIG A "))
    );
    let mx = secure("example.com.", RecordType::MX);
    assert!(
        mx.answers
            .contains(&"example.com. MX 10 mail.example.com.".to_string()),
        "{mx:?}"
    );
    let alias = secure("alias.example.com.", RecordType::A);
    assert!(
        alias
            .answers
            .contains(&"alias.example.com. CNAME www.example.com.".to_string())
    );
    assert!(
        alias
            .answers
            .contains(&"www.example.com. A 45.33.20.80".to_string())
    );
    let nx = secure("nx.example.com.", RecordType::A);
    assert_eq!(nx.rcode, ResponseCode::NXDomain);
    assert!(
        nx.authorities
            .iter()
            .any(|record| record.contains(" NSEC ")),
        "{nx:?}"
    );
    let nodata = secure("www.example.com.", RecordType::TXT);
    assert_eq!(nodata.rcode, ResponseCode::NoError);
    assert!(nodata.answers.is_empty());
    assert!(
        nodata
            .authorities
            .iter()
            .any(|record| record.starts_with("example.com. SOA "))
    );
    // An opt-out NSEC3 covering the next closer name leaves room for an
    // unsigned delegation there, so the denial cannot be Secure
    // (RFC 5155 §9.2), as resolvers answer for names under the real com.
    let nx_com = of("nonexistent-xyz.com.", RecordType::A, false);
    assert_eq!(
        nx_com.validation,
        Validation::Insecure(Insecure::OptOutCovered)
    );
    assert_eq!(nx_com.rcode, ResponseCode::NXDomain);
    assert!(!nx_com.ad);
    assert!(
        nx_com
            .authorities
            .iter()
            .any(|record| record.contains(" NSEC3 ")),
        "{nx_com:?}"
    );
    let big = secure("big.example.com.", RecordType::TXT);
    assert!(!big.tc, "over TCP the whole RRset arrives");
    let text = big
        .answers
        .iter()
        .find(|record| record.starts_with("big.example.com. TXT "))
        .expect("the TXT record");
    assert!(text.len() > 1232, "{} octets of text", text.len());

    for (name, rtype, why) in [
        ("www.example.net.", RecordType::A, Insecure::OptOutCovered),
        ("www.example.org.", RecordType::A, Insecure::ProvenNoDs),
        ("www.fict.com.", RecordType::A, Insecure::OptOutCovered),
        (
            "8.8.8.8.in-addr.arpa.",
            RecordType::PTR,
            Insecure::ProvenNoDs,
        ),
    ] {
        let outcome = of(name, rtype, false);
        assert_eq!(outcome.validation, Validation::Insecure(why), "{name}");
        assert_eq!(outcome.rcode, ResponseCode::NoError, "{name}");
        assert!(!outcome.ad, "{name} has no AD");
        assert_eq!(outcome.answers.len(), 1, "{name}: {outcome:?}");
    }
    assert_eq!(
        of("8.8.8.8.in-addr.arpa.", RecordType::PTR, false).answers,
        ["8.8.8.8.in-addr.arpa. PTR dns.google."]
    );

    let failed = of("www.dnssec-failed.com.", RecordType::A, false);
    assert_eq!(
        failed.validation,
        Validation::Bogus(EdeCode::DNSKEY_MISSING)
    );
    assert_eq!(failed.rcode, ResponseCode::ServFail);
    assert_eq!(failed.edes, [EdeCode::DNSKEY_MISSING]);
    assert!(failed.answers.is_empty());
    let unchecked = of("www.dnssec-failed.com.", RecordType::A, true);
    assert_eq!(unchecked.rcode, ResponseCode::NoError);
    assert!(!unchecked.ad);
    assert!(
        unchecked
            .answers
            .contains(&"www.dnssec-failed.com. A 45.33.26.80".to_string())
    );
}

// ---------------------------------------------------------------------------
// Providers and signers

/// `example.com`'s key as ring signs with it: the same RSA key as the
/// zone's `ZoneKey`, read from its PKCS#8 form, publishing a DNSKEY built
/// here from ring's public modulus and exponent and signing with ring's
/// RSASSA-PKCS1-v1_5. Another library, the same records: PKCS#1 v1.5
/// signatures are deterministic (RFC 5702 §3).
struct RingRsa {
    pair: ring::signature::RsaKeyPair,
    dnskey: DNSKEY,
}

impl RingRsa {
    fn new(pkcs8: &[u8]) -> RingRsa {
        let pair = ring::signature::RsaKeyPair::from_pkcs8(pkcs8).expect("an RSA PKCS#8 key");
        let components: ring::rsa::PublicKeyComponents<Vec<u8>> = pair.public().into();
        // RFC 3110 §2: the exponent's length, the exponent, the modulus.
        let exponent_len = u8::try_from(components.e.len()).expect("a short exponent");
        let mut public = vec![exponent_len];
        public.extend_from_slice(&components.e);
        public.extend_from_slice(&components.n);
        let key = PublicKeyBuf::new(public, hickory_proto::dnssec::Algorithm::RSASHA256);
        RingRsa {
            pair,
            dnskey: DNSKEY::with_flags(KeyFlags::KSK.0, key),
        }
    }
}

impl Sign for RingRsa {
    fn dnskey(&self) -> DNSKEY {
        self.dnskey.clone()
    }

    fn sign(&self, tbs: &[u8]) -> Vec<u8> {
        let mut signature = vec![0; self.pair.public().modulus_len()];
        // PKCS#1 v1.5 draws nothing from the generator; ring asks for one
        // for the padding schemes that do.
        let rng = ring::rand::SystemRandom::new();
        self.pair
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &rng,
                tbs,
                &mut signature,
            )
            .expect("ring signs");
        signature
    }
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

/// A provider that knows exactly what `zone` holds: its RRsets at each
/// name, nothing at a name it has no node for, and no RRsets at an empty
/// non-terminal.
fn provider(zone: Zone) -> impl Provider {
    move |name: &LowerName| match zone.node(name) {
        Some(Node::Data(sets)) => Fact::Present(sets.values().cloned().collect()),
        Some(Node::Empty) => Fact::Present(Vec::new()),
        Some(node) => panic!("example.com holds no cuts or DNAMEs, got {node:?} at {name}"),
        None => Fact::Absent,
    }
}

/// `zone` as a `Lazy` zone over [`provider`], signed as it is asked.
fn signed_lazy(zone: &Zone, keys: KeySet) -> Signed<Lazy<impl Provider>> {
    let (soa, ttl, ns) = apex_of(zone);
    let lazy = Lazy::new(
        Name::from(zone.apex()),
        soa,
        ns,
        ttl,
        provider(zone.clone()),
    );
    Signed::new(lazy, keys, TestInternet::window(), Denial::Nsec)
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

/// The same records of `example.com`, signed by `ZoneKey` and by ring and
/// served from a complete zone signed once and from a `Lazy` zone signed
/// as it is asked, get the same validations, Extended DNS Errors, RCODEs,
/// and answers from one resolver configuration in all four ways. The
/// validator sees records only.
#[test]
fn the_validator_sees_the_same_records_however_they_are_served_or_signed() {
    let zone = below_apex(&TestInternet::example_com());
    let zone_key = TestInternet::example_com_keys();
    let ring = KeySet {
        keys: vec![Arc::new(RingRsa::new(&TestInternet::example_com_pkcs8())) as Arc<dyn Sign>],
    };
    let apex = Name::from(zone.apex());
    assert_eq!(
        zone_key.dnskey_rrset(&apex, 3600),
        ring.dnskey_rrset(&apex, 3600),
        "both signers publish the same key"
    );

    let questions = example_questions();
    let internet = TestInternet::new();
    let config = internet.config();
    let mut runs: Vec<(String, Vec<Outcome>)> = Vec::new();
    for (signer, keys) in [("ZoneKey", zone_key), ("ring", ring)] {
        let complete = zone
            .signed(&keys, TestInternet::window(), Denial::Nsec)
            .expect("the zone signs");
        let complete = Arc::new(complete) as Arc<dyn ZoneData>;
        let mut served = internet
            .clone()
            .serving("example.com.", Zones::new(vec![complete.clone()]))
            .memory();
        let outcomes = in_memory(&mut served, &config, &questions);
        runs.push((
            format!("a complete zone signed by {signer}"),
            outcomes.into_iter().map(|(_, o)| o).collect(),
        ));

        let lazy = Arc::new(signed_lazy(&zone, keys)) as Arc<dyn ZoneData>;
        let mut served = internet
            .clone()
            .serving("example.com.", Zones::new(vec![lazy]))
            .memory();
        let outcomes = in_memory(&mut served, &config, &questions);
        runs.push((
            format!("a lazy zone signed by {signer}"),
            outcomes.into_iter().map(|(_, o)| o).collect(),
        ));
    }

    let (first, expected) = &runs[0];
    for (n, question) in questions.iter().enumerate() {
        let outcome = &expected[n];
        let rcode = match (question.name, question.rtype) {
            ("nx.example.com.", _) => ResponseCode::NXDomain,
            _ => ResponseCode::NoError,
        };
        let empty = matches!(
            (question.name, question.rtype),
            ("nx.example.com." | "_tcp.example.com.", _) | ("www.example.com.", RecordType::TXT)
        );
        assert_eq!(outcome.rcode, rcode, "{question:?}");
        assert_eq!(
            outcome.answers.is_empty(),
            empty,
            "{question:?}: {outcome:?}"
        );
        assert_eq!(
            outcome.validation,
            Validation::Secure,
            "{question:?} from {first}"
        );
    }
    for (how, outcomes) in &runs[1..] {
        for (n, question) in questions.iter().enumerate() {
            let (got, want) = (&outcomes[n], &expected[n]);
            assert_eq!(
                (got.validation, got.reported, &got.edes, got.rcode, got.ad),
                (
                    want.validation,
                    want.reported,
                    &want.edes,
                    want.rcode,
                    want.ad
                ),
                "{question:?} from {how} and from {first}"
            );
            assert_eq!(
                got.answers, want.answers,
                "{question:?} from {how} and from {first}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// One resolver through the test internet, question after question

/// An RRset of one record at `owner`, with TTL 300.
fn one(owner: &str, data: RData) -> RecordSet {
    let owner = name(owner);
    let mut set = RecordSet::with_ttl(owner.clone(), data.record_type(), 300);
    set.insert(Record::from_rdata(owner, 300, data), 0);
    set
}

/// The internet with `example.com` signed with NSEC after `change`.
fn with_example_com(change: impl FnOnce(Zone) -> Zone) -> TestInternet {
    let zone = change(TestInternet::example_com());
    let signed = zone
        .signed(
            &TestInternet::example_com_keys(),
            TestInternet::window(),
            Denial::Nsec,
        )
        .expect("example.com signs");
    TestInternet::new().serving(
        "example.com.",
        Zones::new(vec![Arc::new(signed) as Arc<dyn ZoneData>]),
    )
}

#[test]
fn a_zone_invented_under_com_stays_after_its_ds_is_asked() {
    // The parent of an unsigned delegation says NODATA for its DS, never
    // NXDOMAIN, so a validator's DS lookup does not deny the zone.
    let internet = TestInternet::new();
    let questions = [
        Question::new("www.fict.com.", RecordType::A),
        Question::new("fict.com.", RecordType::DS),
        Question::new("www.fict.com.", RecordType::A),
        Question::new("ns1.fict.com.", RecordType::A),
        Question::new("www.fict.com.", RecordType::TXT),
    ];
    let out = in_memory(&mut internet.memory(), &internet.config(), &questions);
    let insecure = Validation::Insecure(Insecure::OptOutCovered);
    assert_eq!(out[0].1.answers, ["www.fict.com. A 45.33.25.80"]);
    assert_eq!(
        (out[1].1.rcode, out[1].1.validation),
        (ResponseCode::NoError, insecure),
        "{:?}",
        out[1].1
    );
    assert!(out[1].1.answers.is_empty());
    assert_eq!(out[2].1.answers, ["www.fict.com. A 45.33.25.80"]);
    assert_eq!(out[3].1.rcode, ResponseCode::NoError, "{:?}", out[3].1);
    assert_eq!(out[3].1.answers.len(), 1, "{:?}", out[3].1);
    assert_eq!(out[4].1.rcode, ResponseCode::NoError, "{:?}", out[4].1);
}

#[test]
fn a_wildcard_answer_carries_the_proof_that_no_closer_name_matched() {
    // RFC 4035 §3.1.3.3: with DO, a validator downstream needs the NSEC
    // that covers the name, fresh and from the cache alike.
    let internet = with_example_com(|zone| {
        zone.with(one(
            "*.wild.example.com.",
            RData::A("45.33.20.99".parse().unwrap()),
        ))
        .unwrap()
    });
    let questions = [
        Question::new("host.wild.example.com.", RecordType::A),
        Question::new("host.wild.example.com.", RecordType::A),
    ];
    let out = in_memory(&mut internet.memory(), &internet.config(), &questions);
    for (_, outcome) in &out {
        assert_eq!(outcome.validation, Validation::Secure);
        assert!(outcome.ad);
        assert!(
            outcome
                .authorities
                .iter()
                .any(|record| record.contains(" NSEC ")),
            "{outcome:?}"
        );
    }
}

#[test]
fn a_cname_synthesized_from_a_signed_dname_validates() {
    // The synthesized CNAME has no RRSIG of its own; the DNAME above it
    // vouches for it (RFC 6672 §3.4).
    let internet = with_example_com(|zone| {
        zone.with(one(
            "d.example.com.",
            fictionet::stdlib::services::dns::zone::dname(&name("example.com.")),
        ))
        .unwrap()
    });
    let questions = [Question::new("www.d.example.com.", RecordType::A)];
    let out = in_memory(&mut internet.memory(), &internet.config(), &questions);
    let outcome = &out[0].1;
    assert_eq!(outcome.rcode, ResponseCode::NoError, "{outcome:?}");
    assert_eq!(outcome.validation, Validation::Secure, "{outcome:?}");
    assert!(
        outcome
            .answers
            .iter()
            .any(|record| record.contains(" DNAME "))
    );
}

#[test]
fn an_unsigned_child_hosted_with_its_signed_parent_is_insecure() {
    let ns = |owner: &str| {
        one(
            owner,
            RData::NS(fictionet::stdlib::protocols::dns::rr::rdata::NS(name(
                "ns1.example.com.",
            ))),
        )
    };
    let parent = TestInternet::example_com()
        .with_delegation(
            name("plain.example.com."),
            ns("plain.example.com."),
            vec![],
            None,
        )
        .unwrap()
        .signed(
            &TestInternet::example_com_keys(),
            TestInternet::window(),
            Denial::Nsec,
        )
        .unwrap();
    let child = Zone::from_master(
        "plain.example.com. 3600 IN SOA ns1.example.com. dns.example.com. 1 7200 3600 1209600 300\n\
         plain.example.com. 3600 IN NS ns1.example.com.\n\
         www.plain.example.com. 300 IN A 45.33.20.77\n",
        None,
    )
    .unwrap();
    let internet = TestInternet::new().serving(
        "example.com.",
        Zones::new(vec![
            Arc::new(parent) as Arc<dyn ZoneData>,
            Arc::new(child) as Arc<dyn ZoneData>,
        ]),
    );
    let questions = [
        Question::new("www.plain.example.com.", RecordType::A),
        Question::new("nope.plain.example.com.", RecordType::A),
    ];
    let out = in_memory(&mut internet.memory(), &internet.config(), &questions);
    let insecure = Validation::Insecure(Insecure::ProvenNoDs);
    assert_eq!(out[0].1.validation, insecure, "{:?}", out[0].1);
    assert_eq!(out[0].1.answers, ["www.plain.example.com. A 45.33.20.77"]);
    assert_eq!(out[1].1.validation, insecure, "{:?}", out[1].1);
    assert_eq!(out[1].1.rcode, ResponseCode::NXDomain);
}

/// An authority that stays silent for DNSKEY questions while `down` is
/// set.
struct NoKeys {
    inner: Zones,
    down: Arc<std::sync::atomic::AtomicBool>,
}

impl fictionet::stdlib::services::dns::authority::Authority for NoKeys {
    fn respond(
        &self,
        req: &fictionet::stdlib::protocols::dns::Request,
        local: SocketAddr,
        server: &fictionet::stdlib::services::dns::authority::ServerConfig,
        client: &Client,
    ) -> fictionet::stdlib::services::dns::authority::Step {
        let down = self.down.load(std::sync::atomic::Ordering::SeqCst);
        if down && req.question.query_type() == RecordType::DNSKEY {
            return fictionet::stdlib::services::dns::authority::Step::Silent;
        }
        self.inner.respond(req, local, server, client)
    }
}

#[test]
fn a_validation_that_failed_is_tried_again_after_the_failure_ttl() {
    // RFC 9520 §3.2: a failure, Indeterminate included, lasts failure_ttl,
    // not the TTL of the RRset it was about.
    let signed = TestInternet::example_com()
        .signed(
            &TestInternet::example_com_keys(),
            TestInternet::window(),
            Denial::Nsec,
        )
        .unwrap();
    let down = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let internet = TestInternet::new().serving(
        "example.com.",
        NoKeys {
            inner: Zones::new(vec![Arc::new(signed) as Arc<dyn ZoneData>]),
            down: down.clone(),
        },
    );
    let config = internet.config();
    let mut net = internet.memory();
    let entropy = SeededEntropy::new(Seed::from_u64(SEED));
    let mut engine = Watched {
        resolver: Resolver::new(config.clone(), Ring, TestInternet::clock()),
        replies: Vec::new(),
        now: Instant::ZERO,
    };
    let question = Question::new("ns1.example.com.", RecordType::A);
    let mut ask = |engine: &mut Watched, port: u16, start: Instant| {
        let query = ClientQuery {
            client: client(port, Transport::Udp),
            bytes: question.bytes(port),
        };
        let answers = drive(engine, &mut net, vec![query], start, &entropy);
        let reply = Message::from_vec(&answers[0].bytes).unwrap();
        (
            reply.metadata.response_code,
            engine.replies.last().unwrap().0,
        )
    };
    let start = engine.now;
    let first = ask(&mut engine, 40_001, start);
    assert_eq!(
        first,
        (ResponseCode::ServFail, Validation::Indeterminate),
        "the keys could not be had"
    );
    down.store(false, std::sync::atomic::Ordering::SeqCst);
    let later = engine.now + config.failure_ttl + Duration::from_secs(1);
    let second = ask(&mut engine, 40_002, later);
    assert_eq!(second, (ResponseCode::NoError, Validation::Secure));
}

#[test]
fn any_at_a_signed_zone_behind_an_hinfo_front_validates() {
    // example.com's servers answer ANY as Cloudflare's do. A zone signed
    // once cannot sign a made-up HINFO, so they send one RRset of the name
    // with its RRSIGs instead (RFC 8482 §4.1), which validates.
    let internet = TestInternet::new();
    let questions = [
        Question::new("www.example.com.", RecordType::A),
        Question::new("www.example.com.", RecordType::ANY),
    ];
    let out = in_memory(&mut internet.memory(), &internet.config(), &questions);
    assert_eq!(out[1].1.rcode, ResponseCode::NoError, "{:?}", out[1].1);
    assert_eq!(out[1].1.validation, Validation::Secure, "{:?}", out[1].1);
}
