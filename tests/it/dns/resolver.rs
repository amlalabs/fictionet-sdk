//! The recursive resolver driven with no runtime, through a hierarchy of
//! authoritative engines in a `MemoryNet`: iteration, priming, QNAME
//! minimisation, TCP after truncation, broken and missing servers, the
//! work bound, the cache's rules, validation, local zones, departed
//! clients, and sessions.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use fictionet::stdlib::protocols::dns::dnssec::rdata::{DNSSECRData, NSEC};
use fictionet::stdlib::protocols::dns::dnssec::{
    Algorithm, AlgorithmPolicy, Anchors, DigestType, KeyFlags, KeySet, Ring, Sign, Validation,
    Window, ZoneKey, sign,
};
use fictionet::stdlib::protocols::dns::op::{
    Edns, Message, MessageType, OpCode, Query, ResponseCode,
};
use fictionet::stdlib::protocols::dns::rr::rdata::{A, CNAME, NS, SOA, TXT};
use fictionet::stdlib::protocols::dns::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::protocols::dns::{Ede, EdeCode, Request, Response, read_message};
use fictionet::stdlib::services::dns::authority::{
    Authority, AuthorityEngine, Identity, ServerConfig, Step, Zones,
};
use fictionet::stdlib::services::dns::memory::{Exchanges, MemoryNet, drive};
use fictionet::stdlib::services::dns::resolver::{Config, Entry, FailureKind, Key, Resolver, Work};
use fictionet::stdlib::services::dns::zone::{
    Denial, Fact, Lazy, Transparent, Zone, ZoneBuilder, ZoneData, dname,
};
use fictionet::stdlib::services::dns::{
    Action, Answer, Client, ClientQuery, Engine, Event, Generation, Input, Session, Unmatched,
    WallClock,
};
use fictionet::stdlib::services::serve::Transport;
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};
use fictionet_extras::dns::public;

pub(super) const ROOT: &str = "198.41.0.4";
pub(super) const COM: &str = "192.0.2.10";
pub(super) const ORG: &str = "192.0.2.12";
pub(super) const EXAMPLE: &str = "192.0.2.20";
pub(super) const EXAMPLE_TOO: &str = "192.0.2.21";
pub(super) const EXAMPLE_ORG: &str = "192.0.2.30";
pub(super) const PROVIDER: &str = "192.0.2.40";
pub(super) const GLUELESS: &str = "192.0.2.41";
pub(super) const BAD: &str = "192.0.2.50";
pub(super) const ODD: &str = "192.0.2.60";
/// Where the resolver under test answers.
pub(super) const RESOLVER: &str = "192.0.2.53:53";

/// A date inside every signature window here.
pub(super) const NOW: u64 = 1_750_000_000;

pub(super) fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

pub(super) fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

pub(super) fn rrset(owner: &str, ttl: u32, data: Vec<RData>) -> RecordSet {
    let owner = name(owner);
    let mut set = RecordSet::with_ttl(owner.clone(), data[0].record_type(), ttl);
    set.set_records(
        data.into_iter()
            .map(|data| Record::from_rdata(owner.clone(), ttl, data))
            .collect(),
    );
    set
}

pub(super) fn a(text: &str) -> RData {
    RData::A(A(text.parse().unwrap()))
}

pub(super) fn ns(text: &str) -> RData {
    RData::NS(NS(name(text)))
}

fn soa(apex: &str) -> SOA {
    let mname = if apex == "." {
        "a.root-servers.net.".to_string()
    } else {
        format!("ns.{apex}")
    };
    let rname = format!("hostmaster.{}", apex.trim_start_matches('.'));
    SOA::new(name(&mname), name(&rname), 1, 7200, 3600, 1209600, 900)
}

fn builder(apex: &str, server: &str) -> fictionet::stdlib::services::dns::zone::ZoneBuilder {
    Zone::builder(name(apex), soa(apex), 3600).rrset(rrset(apex, 3600, vec![ns(server)]))
}

fn delegation(
    zone: fictionet::stdlib::services::dns::zone::ZoneBuilder,
    child: &str,
    server: &str,
    glue: Option<&str>,
    ds: Option<RecordSet>,
) -> fictionet::stdlib::services::dns::zone::ZoneBuilder {
    let glue = glue
        .map(|address| vec![rrset(server, 3600, vec![a(address)])])
        .unwrap_or_default();
    zone.delegate(name(child), rrset(child, 3600, vec![ns(server)]), glue, ds)
}

fn window() -> Window {
    Window {
        inception: date(1_700_000_000),
        expiration: date(1_800_000_000),
    }
}

pub(super) fn date(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

fn keys(seed: u64) -> KeySet {
    let key = |seed: u64, algorithm, flags| -> Arc<dyn Sign> {
        let entropy = SeededEntropy::new(Seed::from_u64(seed));
        Arc::new(ZoneKey::generate(&entropy, algorithm, flags))
    };
    KeySet {
        keys: vec![
            key(seed, Algorithm::Ed25519, KeyFlags::KSK),
            key(seed + 1, Algorithm::EcdsaP256Sha256, KeyFlags::ZSK),
        ],
    }
}

fn ds(keys: &KeySet, apex: &str) -> RecordSet {
    keys.ds(
        &name(apex),
        3600,
        DigestType::Sha256,
        &AlgorithmPolicy::iana(),
    )
    .unwrap()
}

/// The hierarchy every test resolves through:
///
/// - `.` at 198.41.0.4, `a.root-servers.net`, delegating `com` and `org`.
/// - `com` at 192.0.2.10, delegating `example.com` (glue 192.0.2.20),
///   `glueless.com` (served by `ns.provider.org`, no glue), `bad.com`
///   (signed, with a DS for other keys, and `alias.bad.com` a CNAME to
///   `www.example.com`), `odd.com` (a broken server), and
///   `a.com` and `b.com`, each served from a name in the other.
/// - `example.com` at 192.0.2.20 and 192.0.2.21.
/// - `org` at 192.0.2.12, delegating `example.org` (unsigned) and
///   `provider.org`.
///
/// When `signed`, the root, `com`, `org`, `example.com`, and `bad.com` are
/// signed, and the second value holds the root's anchor.
pub(super) fn internet(signed: bool) -> (MemoryNet, Option<Anchors>) {
    internet_appending(signed, None)
}

/// [`internet`], with `appended` added to the authority section of every
/// NXDOMAIN reply from `example.com`'s servers.
fn internet_appending(signed: bool, appended: Option<Record>) -> (MemoryNet, Option<Anchors>) {
    let root_keys = keys(10);
    let com_keys = keys(20);
    let org_keys = keys(30);
    let example_keys = keys(40);
    let bad_keys = keys(50);
    let sign = |zone: Zone, keys: &KeySet| -> Zone {
        if signed {
            zone.signed(keys, window(), Denial::Nsec).unwrap()
        } else {
            zone
        }
    };
    let ds_for = |keys: &KeySet, apex: &str| signed.then(|| ds(keys, apex));

    let mut root = builder(".", "a.root-servers.net.").rrset(rrset(
        "a.root-servers.net.",
        3600,
        vec![a(ROOT)],
    ));
    root = delegation(
        root,
        "com.",
        "ns.nic.com.",
        Some(COM),
        ds_for(&com_keys, "com."),
    );
    root = delegation(
        root,
        "org.",
        "ns.nic.org.",
        Some(ORG),
        ds_for(&org_keys, "org."),
    );
    let root = sign(root.build().unwrap(), &root_keys);

    let mut com = builder("com.", "ns.nic.com.").rrset(rrset("ns.nic.com.", 3600, vec![a(COM)]));
    com = delegation(
        com,
        "example.com.",
        "ns1.example.com.",
        Some(EXAMPLE),
        ds_for(&example_keys, "example.com."),
    );
    com = delegation(com, "glueless.com.", "ns.provider.org.", None, None);
    // The DS is for keys `bad.com` is not signed with.
    com = delegation(
        com,
        "bad.com.",
        "ns.bad.com.",
        Some(BAD),
        ds_for(&keys(70), "bad.com."),
    );
    com = delegation(com, "odd.com.", "ns.odd.com.", Some(ODD), None);
    com = delegation(com, "a.com.", "ns.b.com.", None, None);
    com = delegation(com, "b.com.", "ns.a.com.", None, None);
    let com = sign(com.build().unwrap(), &com_keys);

    let long = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.example.com.";
    let big: Vec<RData> = (0..8)
        .map(|n| RData::TXT(TXT::new(vec![format!("{n}{}", "x".repeat(200))])))
        .collect();
    let example = builder("example.com.", "ns1.example.com.")
        .rrset(rrset(
            "ns1.example.com.",
            3600,
            vec![a(EXAMPLE), a(EXAMPLE_TOO)],
        ))
        .rrset(rrset("www.example.com.", 300, vec![a("192.0.2.80")]))
        .rrset(rrset(
            "alias.example.com.",
            600,
            vec![RData::CNAME(CNAME(name("www.example.com.")))],
        ))
        .rrset(rrset(
            "away.example.com.",
            600,
            vec![RData::CNAME(CNAME(name("www.example.org.")))],
        ))
        .rrset(rrset("x.y.example.com.", 300, vec![a("192.0.2.81")]))
        .rrset(rrset(long, 300, vec![a("192.0.2.82")]))
        .rrset(rrset("big.example.com.", 300, big))
        .build()
        .unwrap();
    let example = sign(example, &example_keys);

    let mut org = builder("org.", "ns.nic.org.").rrset(rrset("ns.nic.org.", 3600, vec![a(ORG)]));
    org = delegation(
        org,
        "example.org.",
        "ns1.example.org.",
        Some(EXAMPLE_ORG),
        None,
    );
    org = delegation(
        org,
        "provider.org.",
        "ns1.provider.org.",
        Some(PROVIDER),
        None,
    );
    let org = sign(org.build().unwrap(), &org_keys);

    let example_org = builder("example.org.", "ns1.example.org.")
        .rrset(rrset("ns1.example.org.", 3600, vec![a(EXAMPLE_ORG)]))
        .rrset(rrset("www.example.org.", 300, vec![a("192.0.2.90")]))
        .build()
        .unwrap();
    let provider = builder("provider.org.", "ns1.provider.org.")
        .rrset(rrset("ns1.provider.org.", 3600, vec![a(PROVIDER)]))
        .rrset(rrset("ns.provider.org.", 3600, vec![a(GLUELESS)]))
        .build()
        .unwrap();
    let glueless = builder("glueless.com.", "ns.provider.org.")
        .rrset(rrset("www.glueless.com.", 300, vec![a("192.0.2.99")]))
        .build()
        .unwrap();
    let bad = builder("bad.com.", "ns.bad.com.")
        .rrset(rrset("ns.bad.com.", 3600, vec![a(BAD)]))
        .rrset(rrset("www.bad.com.", 300, vec![a("192.0.2.98")]))
        .rrset(rrset(
            "alias.bad.com.",
            300,
            vec![RData::CNAME(CNAME(name("www.example.com.")))],
        ))
        .build()
        .unwrap();
    let bad = sign(bad, &bad_keys);

    let mut net = MemoryNet::new();
    let mut serve = |address: &str, zone: Zone| {
        let local = SocketAddr::new(ip(address), 53);
        let zones = Zones::new(vec![Arc::new(zone) as Arc<dyn ZoneData>]);
        match &appended {
            Some(record) if address == EXAMPLE || address == EXAMPLE_TOO => net.serve(
                ip(address),
                AuthorityEngine::new(
                    Appending(zones, record.clone()),
                    ServerConfig::generic(),
                    local,
                ),
            ),
            _ => net.serve(
                ip(address),
                AuthorityEngine::new(zones, ServerConfig::generic(), local),
            ),
        }
    };
    serve(ROOT, root);
    serve(COM, com);
    serve(EXAMPLE, example.clone());
    serve(EXAMPLE_TOO, example);
    serve(ORG, org);
    serve(EXAMPLE_ORG, example_org);
    serve(PROVIDER, provider);
    serve(GLUELESS, glueless);
    serve(BAD, bad);
    let local = SocketAddr::new(ip(ODD), 53);
    net.serve(
        ip(ODD),
        AuthorityEngine::new(Bizarre, ServerConfig::generic(), local),
    );
    let anchors = signed.then(|| Anchors::of(vec![root_keys.anchor(&Name::root())]));
    (net, anchors)
}

/// The zones' server, which adds a record to the authority section of
/// every NXDOMAIN reply.
struct Appending(Zones, Record);

impl Authority for Appending {
    fn respond(
        &self,
        req: &Request,
        local: SocketAddr,
        server: &ServerConfig,
        client: &Client,
    ) -> Step {
        match self.0.respond(req, local, server, client) {
            Step::Reply(mut response)
                if response.message.metadata.response_code == ResponseCode::NXDomain =>
            {
                response.message.add_authority(self.1.clone());
                Step::Reply(response)
            }
            step => step,
        }
    }
}

/// A broken server: it answers every question with a referral to `org`,
/// which is not below the zone it was asked about, with glue for a name
/// server that does not exist.
struct Bizarre;

impl Authority for Bizarre {
    fn respond(
        &self,
        req: &Request,
        _local: SocketAddr,
        _server: &ServerConfig,
        _client: &Client,
    ) -> Step {
        let query = &req.message.metadata;
        let mut message = Message::response(query.id, query.op_code);
        message.add_query(req.question.clone());
        message.add_authority(Record::from_rdata(name("org."), 3600, ns("ns.evil.org.")));
        message.add_additional(Record::from_rdata(
            name("ns.evil.org."),
            3600,
            a("203.0.113.66"),
        ));
        Step::Reply(Response {
            message,
            required_additional: 0,
        })
    }
}

/// The resolver configuration every test starts from: Unbound's preset
/// with the test root as its only hint, no local zones, Extended DNS
/// Errors on, and `anchors`.
pub(super) fn config(anchors: Option<Anchors>) -> Config {
    Config {
        hints: vec![(name("a.root-servers.net."), ip(ROOT))],
        local: Vec::new(),
        anchors,
        ede: true,
        ..Config::unbound()
    }
}

pub(super) fn clock() -> WallClock {
    WallClock { start: date(NOW) }
}

pub(super) fn resolver(config: Config) -> Resolver {
    Resolver::new(config, Ring, clock())
}

pub(super) fn client(port: u16) -> Client {
    Client {
        peer: SocketAddr::new(ip("198.51.100.7"), port),
        local: RESOLVER.parse().unwrap(),
        transport: Transport::Udp,
        connection: None,
        sandbox: None,
    }
}

/// A query for `qname` `qtype` from `client`, with RD and an OPT record
/// offering 1232 octets, changed by `change`.
pub(super) fn query(
    client: Client,
    qname: &str,
    qtype: RecordType,
    change: impl FnOnce(&mut Message),
) -> ClientQuery {
    let mut message = Message::new(0x4242, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name(qname), qtype));
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    message.set_edns(edns);
    change(&mut message);
    ClientQuery {
        client,
        bytes: message.to_vec().unwrap(),
    }
}

pub(super) fn dnssec_ok(message: &mut Message) {
    message.edns.as_mut().unwrap().set_dnssec_ok(true);
}

pub(super) fn entropy() -> SeededEntropy {
    SeededEntropy::new(Seed::from_u64(7))
}

pub(super) fn at(seconds: u64) -> Instant {
    Instant::from_since_start(Duration::from_secs(seconds))
}

/// Resolves one question at `seconds` and returns the reply.
pub(super) fn ask(
    resolver: &mut Resolver,
    net: &mut impl Exchanges,
    seconds: u64,
    query: ClientQuery,
) -> Message {
    let answers = drive(resolver, net, vec![query], at(seconds), &entropy());
    assert_eq!(answers.len(), 1, "one query, one answer");
    Message::from_vec(&answers[0].bytes).unwrap()
}

pub(super) fn addresses(message: &Message) -> Vec<String> {
    message
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(a) => Some(a.0.to_string()),
            _ => None,
        })
        .collect()
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

/// The questions `net` carried, as (server, name, type, transport).
fn asked(net: &MemoryNet) -> Vec<(IpAddr, String, RecordType, Transport)> {
    net.recording()
        .exchanges()
        .iter()
        .map(|ask| {
            let query = Message::from_vec(&ask.query).unwrap();
            let question = &query.queries[0];
            (
                ask.server.ip(),
                question.name().to_lowercase().to_string(),
                question.query_type(),
                ask.transport,
            )
        })
        .collect()
}

/// An engine with the events it emitted kept.
struct Watched<E> {
    engine: E,
    events: Vec<Event>,
}

impl<E: Engine> Engine for Watched<E> {
    fn handle(&mut self, input: Input, now: Instant, entropy: &dyn fictionet::Entropy) {
        self.engine.handle(input, now, entropy);
    }

    fn poll(&mut self) -> Option<Action> {
        let action = self.engine.poll();
        if let Some(Action::Event(event)) = &action {
            self.events.push(event.clone());
        }
        action
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.engine.next_deadline()
    }

    fn advance(&mut self, session: Session) {
        self.engine.advance(session);
    }

    fn generation(&self) -> Generation {
        self.engine.generation()
    }
}

#[test]
fn iteration_goes_from_the_root_through_the_tld_to_the_zone() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(config(None));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "WWW.Example.COM.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(addresses(&reply), ["192.0.2.80"]);
    assert!(reply.metadata.recursion_available);
    assert!(reply.metadata.recursion_desired);
    assert!(!reply.metadata.authoritative);
    assert!(!reply.metadata.authentic_data);
    assert_eq!(reply.metadata.id, 0x4242);
    // The question and the answer owner keep the client's case.
    assert_eq!(reply.queries[0].name().to_string(), "WWW.Example.COM.");
    assert_eq!(reply.answers[0].name.to_string(), "WWW.Example.COM.");
    assert_eq!(reply.answers[0].ttl, 300);

    let servers: Vec<IpAddr> = asked(&net).iter().map(|(server, ..)| *server).collect();
    assert_eq!(servers.first(), Some(&ip(ROOT)));
    assert!(servers.contains(&ip(COM)));
    assert!(
        servers
            .iter()
            .any(|s| *s == ip(EXAMPLE) || *s == ip(EXAMPLE_TOO))
    );
    assert!(!servers.contains(&ip(ORG)));
}

#[test]
fn the_first_question_primes_the_root_from_a_hint() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(config(None));
    ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    let recording = net.recording();
    let first = &recording.exchanges()[0];
    assert_eq!(first.server, SocketAddr::new(ip(ROOT), 53));
    let message = Message::from_vec(&first.query).unwrap();
    assert_eq!(message.queries[0].name(), &Name::root());
    assert_eq!(message.queries[0].query_type(), RecordType::NS);
    assert!(!message.metadata.recursion_desired);
    let edns = message.edns.unwrap();
    assert_eq!(edns.max_payload(), 1232);
    // The root's NS RRset and its server's address are cached from the
    // priming answer, so the next question asks the root nothing new.
    let ns = Key::new(
        LowerName::from(Name::root()),
        RecordType::NS,
        fictionet::stdlib::protocols::dns::rr::DNSClass::IN,
    );
    assert!(matches!(
        resolver.cache().get(&ns, at(1)),
        Some(Entry::Positive { .. })
    ));
}

#[test]
fn qname_minimisation_stays_within_the_rfc_9156_counts() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(config(None));
    let long = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.example.com.";
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), long, RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&reply), ["192.0.2.82"]);
    let questions = asked(&net);
    // The root and the TLD see only one label more than they serve.
    assert!(
        questions
            .iter()
            .any(|(s, n, t, _)| *s == ip(ROOT) && n == "com." && *t == RecordType::A)
    );
    assert!(
        questions
            .iter()
            .any(|(s, n, t, _)| *s == ip(COM) && n == "example.com." && *t == RecordType::A)
    );
    assert!(
        !questions
            .iter()
            .any(|(s, n, _, _)| *s == ip(ROOT) && n == long)
    );
    // At most 10 minimised queries, the first 4 adding one label each,
    // and then the whole name.
    let minimised: Vec<usize> = questions
        .iter()
        .filter(|(_, n, t, _)| *t == RecordType::A && n != long)
        .map(|(_, n, _, _)| name(n).num_labels() as usize)
        .collect();
    assert!(minimised.len() <= 10, "{minimised:?}");
    assert_eq!(&minimised[..4], &[1, 2, 3, 4]);
    assert!(
        minimised.windows(2).all(|pair| pair[0] < pair[1]),
        "{minimised:?}"
    );
    let whole = questions.iter().filter(|(_, n, _, _)| n == long).count();
    assert_eq!(whole, 1);
}

/// The questions `net` carried to the servers of `example.com`.
fn asked_of_example(net: &MemoryNet) -> Vec<String> {
    asked(net)
        .into_iter()
        .filter(|(server, _, _, _)| *server == ip(EXAMPLE) || *server == ip(EXAMPLE_TOO))
        .map(|(_, qname, _, _)| qname)
        .collect()
}

#[test]
fn a_minimised_question_asked_again_after_a_timeout_is_the_same_step() {
    let (mut net, _) = internet(false);
    // The first two queries for `n.example.com` are lost.
    let mut lost = 0;
    net.lose(move |transmit| {
        let query = Message::from_vec(&transmit.bytes).unwrap();
        let lose = query.queries[0].name().to_lowercase() == name("n.example.com.") && lost < 2;
        lost += usize::from(lose);
        lose
    });
    let mut resolver = resolver(config(None));
    let long = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.example.com.";
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), long, RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&reply), ["192.0.2.82"]);
    assert_eq!(
        asked_of_example(&net)[..4],
        [
            "n.example.com.",
            "n.example.com.",
            "n.example.com.",
            "m.n.example.com.",
        ]
    );
}

#[test]
fn qname_minimisation_counts_a_leading_star_as_a_label() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(config(None));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "*.y.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(
        asked_of_example(&net),
        ["y.example.com.", "*.y.example.com."]
    );
}

#[test]
fn a_truncated_reply_is_asked_again_over_tcp_of_the_same_server() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(config(None));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "big.example.com.", RecordType::TXT, |_| {}),
    );
    let questions = asked(&net);
    let tries: Vec<&(IpAddr, String, RecordType, Transport)> = questions
        .iter()
        .filter(|(_, n, t, _)| n == "big.example.com." && *t == RecordType::TXT)
        .collect();
    assert_eq!(tries.len(), 2, "{tries:?}");
    assert_eq!(tries[0].3, Transport::Udp);
    assert_eq!(tries[1].3, Transport::Tcp);
    assert_eq!(tries[0].0, tries[1].0);
    // The client asked over UDP for 1232 octets, so it gets TC, with no
    // partial RRset (RFC 2181 §9).
    assert!(reply.metadata.truncation);
    assert!(reply.answers.is_empty());
    // A client over TCP gets the whole RRset, from the cache.
    let mut tcp = client(2);
    tcp.transport = Transport::Tcp;
    let before = net.recording().exchanges().len();
    let reply = ask(
        &mut resolver,
        &mut net,
        1,
        query(tcp, "big.example.com.", RecordType::TXT, |_| {}),
    );
    assert_eq!(reply.answers.len(), 8);
    assert!(!reply.metadata.truncation);
    assert_eq!(net.recording().exchanges().len(), before);
}

#[test]
fn a_bizarre_referral_is_never_followed_or_cached() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(config(None));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.odd.com.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert!(!asked(&net).iter().any(|(s, ..)| *s == ip("203.0.113.66")));
    for (key, _) in resolver.cache().entries(at(1)) {
        assert_ne!(key.name, LowerName::new(&name("ns.evil.org.")));
        if key.rtype == RecordType::NS {
            assert_ne!(
                key.name,
                LowerName::new(&name("org.")),
                "the referral's NS was cached"
            );
        }
    }
    // The server replied, so the failure is not "no reachable authority"
    // in the cache's terms but a reply that did not fit.
    let failure = Key::new(
        LowerName::new(&name("www.odd.com.")),
        RecordType::A,
        fictionet::stdlib::protocols::dns::rr::DNSClass::IN,
    );
    assert!(matches!(
        resolver.cache().get(&failure, at(1)),
        Some(Entry::Failure {
            why: FailureKind::Unknown,
            ..
        })
    ));
}

#[test]
fn glue_never_answers_a_client() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(config(None));
    ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    // The referral from `com` gave one address for ns1.example.com as glue;
    // the zone itself holds two.
    let before = net.recording().exchanges().len();
    let reply = ask(
        &mut resolver,
        &mut net,
        1,
        query(client(1), "ns1.example.com.", RecordType::A, |_| {}),
    );
    let mut got = addresses(&reply);
    got.sort();
    assert_eq!(got, [EXAMPLE, EXAMPLE_TOO]);
    let after = asked(&net);
    assert!(
        after[before..]
            .iter()
            .any(|(_, n, t, _)| n == "ns1.example.com." && *t == RecordType::A)
    );
}

#[test]
fn a_name_server_found_without_glue_is_looked_up_first() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(config(None));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.glueless.com.", RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&reply), ["192.0.2.99"]);
    let questions = asked(&net);
    assert!(
        questions
            .iter()
            .any(|(s, n, ..)| *s == ip(PROVIDER) && n == "ns.provider.org.")
    );
    assert!(questions.iter().any(|(s, ..)| *s == ip(GLUELESS)));
}

#[test]
fn a_cycle_of_glueless_name_servers_fails_instead_of_waiting_forever() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(config(None));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.a.com.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(edes(&reply), [EdeCode::NO_REACHABLE_AUTHORITY]);
    assert!(resolver.next_deadline().is_none());
}

/// A referral to a zone whose only name server lies inside it, with no
/// glue, cannot be followed. Going back to the cut above gets the same
/// referral again, so the question fails at once, and the failure is
/// cached.
#[test]
fn a_referral_to_in_zone_servers_without_glue_fails_once_and_is_cached() {
    let root = delegation(
        builder(".", "a.root-servers.net.").rrset(rrset(
            "a.root-servers.net.",
            3600,
            vec![a(ROOT)],
        )),
        "com.",
        "ns.nic.com.",
        Some(COM),
        None,
    )
    .build()
    .unwrap();
    // A lazy zone refers with the glue it holds: none, since the provider
    // says nothing is at the name server's name.
    let provider = |name: &LowerName| match name.to_string().as_str() {
        "ns.nic.com." => Fact::Present(vec![rrset("ns.nic.com.", 3600, vec![a(COM)])]),
        "inb.com." => Fact::Present(vec![rrset("inb.com.", 3600, vec![ns("ns.inb.com.")])]),
        _ => Fact::Absent,
    };
    let com = Lazy::new(
        name("com."),
        soa("com."),
        rrset("com.", 3600, vec![ns("ns.nic.com.")]),
        3600,
        provider,
    );
    let mut net = MemoryNet::new();
    let zones: [(&str, Arc<dyn ZoneData>); 2] = [(ROOT, Arc::new(root)), (COM, Arc::new(com))];
    for (address, zone) in zones {
        let local = SocketAddr::new(ip(address), 53);
        net.serve(
            ip(address),
            AuthorityEngine::new(Zones::new(vec![zone]), ServerConfig::generic(), local),
        );
    }
    let mut resolver = resolver(config(None));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.inb.com.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(edes(&reply), [EdeCode::NO_REACHABLE_AUTHORITY]);
    // Priming, the root's referral to `com`, then `com` asked once for the
    // question and once on the way to each of the name server's address
    // types, which end on the cycle.
    let first = net.recording().exchanges().len();
    assert_eq!(first, 5, "{:?}", asked(&net));

    let reply = ask(
        &mut resolver,
        &mut net,
        1,
        query(client(2), "www.inb.com.", RecordType::A, |_| {}),
    );
    assert_eq!(
        edes(&reply),
        [EdeCode::NO_REACHABLE_AUTHORITY, EdeCode::CACHED_ERROR]
    );
    assert_eq!(net.recording().exchanges().len(), first);
}

#[test]
fn the_work_bound_ends_a_question_that_costs_too_much() {
    let (mut net, _) = internet(false);
    let mut config = config(None);
    config.work = Work {
        queries: 3,
        depth: 11,
    };
    let mut resolver = resolver(config);
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    // Servers replied, so the error is EDE 0, not 22 (RFC 8914).
    assert_eq!(edes(&reply), [EdeCode::OTHER]);
    assert_eq!(net.recording().exchanges().len(), 3);
}

#[test]
fn a_failure_is_cached_and_answered_with_ede_13_never_as_a_negative() {
    // The zone's own NS question fails too, although the referral to the
    // zone left its NS RRset in the cache.
    for (qname, qtype) in [
        ("www.example.com.", RecordType::A),
        ("example.com.", RecordType::NS),
    ] {
        let (mut net, _) = internet(false);
        // No server answers at the addresses of `example.com`.
        net.lose(|transmit| {
            let to = transmit.to.ip();
            to == ip(EXAMPLE) || to == ip(EXAMPLE_TOO)
        });
        let mut resolver = resolver(config(None));
        let reply = ask(
            &mut resolver,
            &mut net,
            0,
            query(client(1), qname, qtype, |_| {}),
        );
        assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(edes(&reply), [EdeCode::NO_REACHABLE_AUTHORITY]);
        assert!(reply.authorities.is_empty());

        let before = net.recording().exchanges().len();
        let reply = ask(
            &mut resolver,
            &mut net,
            2,
            query(client(2), qname, qtype, |_| {}),
        );
        assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(
            edes(&reply),
            [EdeCode::NO_REACHABLE_AUTHORITY, EdeCode::CACHED_ERROR],
            "{qname} {qtype}"
        );
        assert!(reply.authorities.is_empty());
        assert_eq!(
            net.recording().exchanges().len(),
            before,
            "{qname} {qtype} is answered from the cache"
        );

        // The failure lasts `failure_ttl`, 5 seconds, and is then asked
        // again.
        ask(
            &mut resolver,
            &mut net,
            30,
            query(client(3), qname, qtype, |_| {}),
        );
        assert!(net.recording().exchanges().len() > before);
    }
}

#[test]
fn nothing_exists_below_a_cached_secure_nxdomain() {
    let (mut net, anchors) = internet(true);
    let mut resolver = resolver(config(anchors));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "nx.example.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert!(reply.metadata.authentic_data);
    assert_eq!(reply.authorities[0].record_type(), RecordType::SOA);
    let before = net.recording().exchanges().len();
    let reply = ask(
        &mut resolver,
        &mut net,
        1,
        query(
            client(1),
            "deeper.nx.example.com.",
            RecordType::MX,
            dnssec_ok,
        ),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(reply.authorities[0].record_type(), RecordType::SOA);
    assert_eq!(
        net.recording().exchanges().len(),
        before,
        "RFC 8020: no new question"
    );
}

#[test]
fn an_nxdomain_that_did_not_validate_denies_only_its_own_name() {
    // Unbound uses only Secure NXDOMAINs for the names below them, since
    // a server may deny an empty non-terminal or a name it does not know
    // is delegated.
    let (mut net, _) = internet(false);
    let mut resolver = resolver(config(None));
    let reply = ask(
        &mut resolver,
        &mut net,
        1,
        query(client(1), "nx.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    let before = net.recording().exchanges().len();
    let reply = ask(
        &mut resolver,
        &mut net,
        2,
        query(client(1), "nx.example.com.", RecordType::MX, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(net.recording().exchanges().len(), before, "its own name");
    let reply = ask(
        &mut resolver,
        &mut net,
        3,
        query(client(1), "deeper.nx.example.com.", RecordType::MX, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert!(
        net.recording().exchanges().len() > before,
        "a name below an unvalidated NXDOMAIN is asked again"
    );
}

#[test]
fn ttls_count_down_in_the_cache_for_answers_and_negatives() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(config(None));
    let reply = ask(
        &mut resolver,
        &mut net,
        10,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.answers[0].ttl, 300);
    let reply = ask(
        &mut resolver,
        &mut net,
        110,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.answers[0].ttl, 200);

    let reply = ask(
        &mut resolver,
        &mut net,
        110,
        query(client(1), "www.example.com.", RecordType::MX, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.answers.is_empty());
    // min(SOA TTL 3600, MINIMUM 900) (RFC 2308 §3).
    assert_eq!(reply.authorities[0].ttl, 900);
    let reply = ask(
        &mut resolver,
        &mut net,
        410,
        query(client(1), "www.example.com.", RecordType::MX, |_| {}),
    );
    assert_eq!(reply.authorities[0].ttl, 600);
}

#[test]
fn ttls_are_capped_at_max_ttl_fresh_and_cached() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(Config {
        max_ttl: Duration::from_secs(100),
        ..config(None)
    });
    let query = || query(client(1), "www.example.com.", RecordType::A, |_| {});
    let reply = ask(&mut resolver, &mut net, 0, query());
    assert_eq!(reply.answers[0].ttl, 100);
    let reply = ask(&mut resolver, &mut net, 40, query());
    assert_eq!(reply.answers[0].ttl, 60);
    let before = net.recording().exchanges().len();
    ask(&mut resolver, &mut net, 101, query());
    assert!(
        net.recording().exchanges().len() > before,
        "expired at the cap"
    );
}

#[test]
fn ttls_count_down_on_a_clock_of_whole_seconds() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(config(None));
    let mut ask_at = |millis: u64| {
        let query = query(client(1), "www.example.com.", RecordType::A, |_| {});
        let now = Instant::from_since_start(Duration::from_millis(millis));
        let answers = drive(&mut resolver, &mut net, vec![query], now, &entropy());
        Message::from_vec(&answers[0].bytes).unwrap().answers[0].ttl
    };
    // Fetched 0.6 seconds into second 0, then asked 5.2 seconds later, in
    // second 5: five seconds have passed on the clock, as Unbound counts.
    assert_eq!(ask_at(600), 300);
    assert_eq!(ask_at(5_800), 295);
    assert_eq!(ask_at(5_999), 295);
    assert_eq!(ask_at(6_000), 294);
}

#[test]
fn an_alias_is_followed_inside_the_zone_and_across_zones() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(config(None));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "alias.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.answers[0].record_type(), RecordType::CNAME);
    assert_eq!(addresses(&reply), ["192.0.2.80"]);
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "away.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.answers[0].record_type(), RecordType::CNAME);
    assert_eq!(addresses(&reply), ["192.0.2.90"]);
}

#[test]
fn ad_is_set_only_for_secure_answers_to_clients_that_ask() {
    let (mut net, anchors) = internet(true);
    let mut resolver = resolver(config(anchors));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(addresses(&reply), ["192.0.2.80"]);
    assert!(reply.metadata.authentic_data);
    assert!(
        reply
            .answers
            .iter()
            .any(|record| record.record_type() == RecordType::RRSIG)
    );

    // Neither DO nor AD: AD stays clear, and no RRSIGs.
    let reply = ask(
        &mut resolver,
        &mut net,
        1,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    assert!(!reply.metadata.authentic_data);
    assert!(
        reply
            .answers
            .iter()
            .all(|record| record.record_type() == RecordType::A)
    );
    // AD in the query asks for it (RFC 6840 §5.7).
    let reply = ask(
        &mut resolver,
        &mut net,
        1,
        query(client(1), "www.example.com.", RecordType::A, |m| {
            m.metadata.authentic_data = true;
        }),
    );
    assert!(reply.metadata.authentic_data);

    // An unsigned zone below a proven insecure delegation is Insecure.
    let reply = ask(
        &mut resolver,
        &mut net,
        2,
        query(client(1), "www.example.org.", RecordType::A, dnssec_ok),
    );
    assert_eq!(addresses(&reply), ["192.0.2.90"]);
    assert!(!reply.metadata.authentic_data);

    // A secure negative answer is Secure too.
    let reply = ask(
        &mut resolver,
        &mut net,
        3,
        query(client(1), "nx.example.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert!(reply.metadata.authentic_data);
    assert!(
        reply
            .authorities
            .iter()
            .any(|record| record.record_type() == RecordType::NSEC)
    );
}

#[test]
fn without_anchors_validation_is_not_performed_and_ad_never_set() {
    let (net, _) = internet(true);
    let mut net = net;
    let mut watched = Watched {
        engine: resolver(config(None)),
        events: Vec::new(),
    };
    let answers = drive(
        &mut watched,
        &mut net,
        vec![query(
            client(1),
            "www.example.com.",
            RecordType::A,
            dnssec_ok,
        )],
        at(0),
        &entropy(),
    );
    let reply = Message::from_vec(&answers[0].bytes).unwrap();
    assert!(!reply.metadata.authentic_data);
    let validation = watched.events.iter().find_map(|event| match event {
        Event::Reply { validation, .. } => Some(*validation),
        _ => None,
    });
    assert_eq!(validation, Some(Validation::NotPerformed));
    // No DS or DNSKEY was fetched.
    assert!(
        !asked(&net)
            .iter()
            .any(|(_, _, t, _)| matches!(t, RecordType::DS | RecordType::DNSKEY))
    );
}

#[test]
fn bogus_answers_servfail_without_cd_and_come_back_with_cd() {
    let (mut net, anchors) = internet(true);
    let mut resolver = resolver(config(anchors));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.bad.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert!(reply.answers.is_empty());
    assert_eq!(edes(&reply), [EdeCode::DNSKEY_MISSING]);

    let reply = ask(
        &mut resolver,
        &mut net,
        1,
        query(client(1), "www.bad.com.", RecordType::A, |m| {
            dnssec_ok(m);
            m.metadata.checking_disabled = true;
        }),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(addresses(&reply), ["192.0.2.98"]);
    assert!(!reply.metadata.authentic_data);
    assert!(reply.metadata.checking_disabled);
}

/// Carries `engine`'s transmits through `net` until it has none, and
/// returns the answers.
fn pump(
    engine: &mut impl Engine,
    net: &mut MemoryNet,
    now: Instant,
    held: Vec<Action>,
) -> Vec<Answer> {
    let entropy = entropy();
    let mut answers = Vec::new();
    let mut actions: Vec<Action> = held;
    loop {
        while let Some(action) = engine.poll() {
            actions.push(action);
        }
        if actions.is_empty() {
            return answers;
        }
        for action in std::mem::take(&mut actions) {
            match action {
                Action::Send(transmit) => {
                    for input in net.exchange(&transmit, now, &entropy) {
                        engine.handle(input, now, &entropy);
                    }
                }
                Action::Answer(answer) => answers.push(answer),
                Action::Lookup { .. } | Action::Abandon(_) | Action::Event(_) => {}
            }
        }
    }
}

#[test]
fn a_departed_client_leaves_the_others_waiting_on_shared_work() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(config(None));
    let entropy = entropy();
    let first = client(1);
    let second = client(2);
    resolver.handle(
        Input::Query(query(
            first.clone(),
            "www.example.com.",
            RecordType::A,
            |_| {},
        )),
        at(0),
        &entropy,
    );
    resolver.handle(
        Input::Query(query(
            second.clone(),
            "www.example.com.",
            RecordType::A,
            |_| {},
        )),
        at(0),
        &entropy,
    );
    let mut held = Vec::new();
    while let Some(action) = resolver.poll() {
        held.push(action);
    }
    // Both wait on one priming exchange.
    let sends = held.iter().filter(|a| matches!(a, Action::Send(_))).count();
    assert_eq!(sends, 1);
    resolver.handle(Input::Gone(first.clone()), at(0), &entropy);
    let answers = pump(&mut resolver, &mut net, at(0), held);
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].client, second);
    let reply = Message::from_vec(&answers[0].bytes).unwrap();
    assert_eq!(addresses(&reply), ["192.0.2.80"]);

    // When the only client goes, its exchange is abandoned.
    resolver.handle(
        Input::Query(query(
            first.clone(),
            "www.example.org.",
            RecordType::A,
            |_| {},
        )),
        at(1),
        &entropy,
    );
    let token = loop {
        match resolver.poll() {
            Some(Action::Send(transmit)) => break transmit.token,
            Some(_) => {}
            None => panic!("the query sends"),
        }
    };
    resolver.handle(Input::Gone(first), at(1), &entropy);
    let mut abandoned = false;
    while let Some(action) = resolver.poll() {
        abandoned |= action == Action::Abandon(token);
    }
    assert!(abandoned);
    assert!(resolver.next_deadline().is_none());
}

#[test]
fn a_new_session_keeps_old_completions_out_and_checks_signatures_against_its_clock() {
    let (mut net, anchors) = internet(true);
    // The run starts long after every signature expired.
    let resolver = Resolver::new(
        config(anchors),
        Ring,
        WallClock {
            start: date(1_900_000_000),
        },
    );
    let mut watched = Watched {
        engine: resolver,
        events: Vec::new(),
    };
    let entropy = entropy();
    watched.handle(
        Input::Query(query(
            client(1),
            "www.example.com.",
            RecordType::A,
            dnssec_ok,
        )),
        at(0),
        &entropy,
    );
    let transmit = loop {
        match watched.poll() {
            Some(Action::Send(transmit)) => break transmit,
            Some(_) => {}
            None => panic!("the query sends"),
        }
    };
    // The session changes before the reply comes, to a date inside the
    // signatures' window.
    watched.advance(Session {
        generation: Generation(1),
        clock: WallClock { start: date(NOW) },
    });
    assert_eq!(watched.generation(), Generation(1));
    let mut abandoned = false;
    while let Some(action) = watched.poll() {
        abandoned |= action == Action::Abandon(transmit.token);
    }
    assert!(abandoned);
    // The old exchange's reply changes nothing.
    let old = net.exchange(&transmit, at(0), &entropy);
    assert_eq!(old.len(), 1);
    assert!(watched.next_deadline().is_some(), "the restart is pending");
    for input in old {
        watched.handle(input, at(0), &entropy);
    }
    let answers = pump(&mut watched, &mut net, at(0), Vec::new());
    assert!(watched.events.iter().any(|event| matches!(
        event,
        Event::Ignored { token, why: Unmatched::OldGeneration, .. } if *token == transmit.token
    )));
    assert_eq!(answers.len(), 1);
    let reply = Message::from_vec(&answers[0].bytes).unwrap();
    assert_eq!(addresses(&reply), ["192.0.2.80"]);
    assert!(
        reply.metadata.authentic_data,
        "validated against the new session's date"
    );
    // Every cache entry is of the new generation.
    assert_eq!(watched.engine.cache().generation(), Generation(1));
}

#[test]
fn the_old_clock_finds_expired_signatures() {
    let (mut net, anchors) = internet(true);
    let mut resolver = Resolver::new(
        config(anchors),
        Ring,
        WallClock {
            start: date(1_900_000_000),
        },
    );
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(edes(&reply), [EdeCode::SIGNATURE_EXPIRED]);
}

/// A zone at `apex` holding `owner` A `address`, served from `local`.
fn small(apex: &str, owner: &str, address: &str) -> Zone {
    Zone::builder(name(apex), soa(apex), 3600)
        .rrset(rrset(apex, 3600, vec![ns(apex)]))
        .rrset(rrset(owner, 60, vec![a(address)]))
        .build()
        .unwrap()
}

#[test]
fn local_zones_answer_deepest_first_and_the_last_added_first_at_equal_depth() {
    let (mut net, _) = internet(false);
    let unknown = |_: &LowerName| Fact::Unknown;
    let sub = Lazy::new(
        name("sub.test."),
        soa("sub.test."),
        rrset("sub.test.", 3600, vec![ns("sub.test.")]),
        3600,
        unknown,
    );
    let config = config(None)
        .local(Arc::new(small("test.", "a.test.", "192.0.2.1")))
        .local(Arc::new(Transparent(small(
            "test.",
            "b.test.",
            "192.0.2.2",
        ))))
        .local(Arc::new(sub))
        .local(Arc::new(Transparent(small("com.", "x.com.", "192.0.2.3"))));
    let mut resolver = resolver(config);
    // The zone added last answers what it holds.
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "b.test.", RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&reply), ["192.0.2.2"]);
    // What it does not hold passes to the zone added before it.
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "a.test.", RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&reply), ["192.0.2.1"]);
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "c.test.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    // The deeper zone knows nothing, so the shallower ones answer.
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "a.sub.test.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert!(net.recording().exchanges().is_empty());
    // A transparent zone's absent name goes on to iteration.
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "x.com.", RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&reply), ["192.0.2.3"]);
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&reply), ["192.0.2.80"]);
    assert!(!net.recording().exchanges().is_empty());
}

#[test]
fn a_resolver_with_no_hints_answers_servfail_with_ede_22() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(Config::gateway());
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(edes(&reply), [EdeCode::NO_REACHABLE_AUTHORITY]);
    // Its local zones still answer: localhost and the RFC 6303 zones.
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "localhost.", RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&reply), ["127.0.0.1"]);
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "1.0.0.10.in-addr.arpa.", RecordType::PTR, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert!(!reply.metadata.authoritative);
    assert!(net.recording().exchanges().is_empty());
}

#[test]
fn rd_clear_is_refused_or_answered_from_the_cache_alone() {
    let (mut net, _) = internet(false);
    let norec = |m: &mut Message| m.metadata.recursion_desired = false;
    let mut unbound = resolver(config(None));
    let reply = ask(
        &mut unbound,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, norec),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::Refused);

    let mut google = resolver(Config {
        rd0_from_cache: true,
        ..config(None)
    });
    let reply = ask(
        &mut google,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, norec),
    );
    // A cold cache has no delegation to refer to.
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert!(net.recording().exchanges().is_empty());
    ask(
        &mut google,
        &mut net,
        1,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    let before = net.recording().exchanges().len();
    let reply = ask(
        &mut google,
        &mut net,
        2,
        query(client(1), "www.example.com.", RecordType::A, norec),
    );
    assert_eq!(addresses(&reply), ["192.0.2.80"]);
    assert!(!reply.metadata.recursion_desired);
    // Not in the cache: the closest delegation it holds.
    let reply = ask(
        &mut google,
        &mut net,
        2,
        query(client(1), "mail.example.com.", RecordType::A, norec),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.answers.is_empty());
    assert_eq!(reply.authorities[0].record_type(), RecordType::NS);
    assert_eq!(net.recording().exchanges().len(), before);
}

/// With RD clear, an alias the cache holds goes in the answer, and the
/// referral is for its target, which the cache does not hold, as a server
/// answering from its cache does (RFC 1034 §4.3.2 steps 3a and 4).
#[test]
fn rd_clear_follows_a_cached_alias_and_refers_for_its_target() {
    let (mut net, _) = internet(false);
    let norec = |m: &mut Message| m.metadata.recursion_desired = false;
    let mut google = resolver(Config {
        rd0_from_cache: true,
        ..config(None)
    });
    // The cache holds the alias, not its target in `example.org`.
    ask(
        &mut google,
        &mut net,
        0,
        query(client(1), "away.example.com.", RecordType::CNAME, |_| {}),
    );
    let before = net.recording().exchanges().len();
    let reply = ask(
        &mut google,
        &mut net,
        1,
        query(client(1), "away.example.com.", RecordType::A, norec),
    );
    assert_eq!(net.recording().exchanges().len(), before);
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    let cnames: Vec<(String, u32)> = reply
        .answers
        .iter()
        .filter(|record| record.record_type() == RecordType::CNAME)
        .map(|record| (record.name.to_string(), record.ttl))
        .collect();
    assert_eq!(cnames, [("away.example.com.".to_string(), 599)]);
    // The closest delegation for `www.example.org.` the cache holds is
    // the root's, not `example.com`'s.
    let ns: Vec<String> = reply
        .authorities
        .iter()
        .filter(|record| record.record_type() == RecordType::NS)
        .map(|record| record.name.to_string())
        .collect();
    assert!(!ns.is_empty());
    assert!(ns.iter().all(|owner| owner == "."), "{ns:?}");
}

#[test]
fn chaos_questions_are_answered_from_the_identity() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(config(None));
    let ch = |m: &mut Message| {
        m.queries[0].set_query_class(fictionet::stdlib::protocols::dns::rr::DNSClass::CH);
    };
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "version.bind.", RecordType::TXT, ch),
    );
    let RData::TXT(txt) = &reply.answers[0].data else {
        panic!("a TXT answer");
    };
    assert_eq!(txt.to_string(), "unbound 1.26.2");
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "authors.bind.", RecordType::TXT, ch),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
    assert!(net.recording().exchanges().is_empty());
}

#[test]
fn validated_nsec_records_deny_other_names_they_cover_without_asking() {
    let (mut net, anchors) = internet(true);
    let mut resolver = resolver(config(anchors));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "nx.example.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    let before = net.recording().exchanges().len();
    // `nz` sorts between `ns1` and `www`, so the same NSEC covers it.
    let reply = ask(
        &mut resolver,
        &mut net,
        1,
        query(client(1), "nz.example.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert!(reply.metadata.authentic_data);
    assert!(
        reply
            .authorities
            .iter()
            .any(|record| record.record_type() == RecordType::SOA)
    );
    assert_eq!(
        net.recording().exchanges().len(),
        before,
        "RFC 8198: no new question"
    );
    // A name the NSEC records do not cover is asked.
    ask(
        &mut resolver,
        &mut net,
        1,
        query(client(1), "zzz.example.com.", RecordType::A, dnssec_ok),
    );
    assert!(net.recording().exchanges().len() > before);
}

/// Below a negative trust anchor nothing is validated (RFC 7646): data
/// whose signatures fail answers without AD, while names outside the
/// anchor validate as before, and the anchor's own DS is the parent's.
#[test]
fn a_negative_trust_anchor_stops_validation_below_it() {
    let (mut net, anchors) = internet(true);
    let bad = LowerName::new(&name("bad.com."));
    let mut resolver = resolver(Config {
        negative_anchors: Some(Arc::new(move |name: &LowerName| *name == bad)),
        ..config(anchors)
    });
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.bad.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(addresses(&reply), ["192.0.2.98"]);
    assert!(!reply.metadata.authentic_data);
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, dnssec_ok),
    );
    assert!(reply.metadata.authentic_data);
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "bad.com.", RecordType::DS, dnssec_ok),
    );
    assert!(reply.metadata.authentic_data, "com validates its DS RRset");
}

/// A trust anchor below a negative trust anchor starts validation again
/// (RFC 7646 §1.1), as Unbound's trust anchors override its
/// `domain-insecure`.
#[test]
fn a_trust_anchor_below_a_negative_one_validates_again() {
    let (mut net, anchors) = internet(true);
    let mut anchors: Vec<_> = anchors.unwrap().iter().cloned().collect();
    anchors.push(keys(40).anchor(&name("example.com.")));
    let com = LowerName::new(&name("com."));
    let mut resolver = resolver(Config {
        negative_anchors: Some(Arc::new(move |name: &LowerName| *name == com)),
        ..config(Some(Anchors::of(anchors)))
    });
    for (qname, secure) in [("www.example.com.", true), ("www.bad.com.", false)] {
        let reply = ask(
            &mut resolver,
            &mut net,
            0,
            query(client(1), qname, RecordType::A, dnssec_ok),
        );
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert_eq!(reply.metadata.authentic_data, secure, "{qname}");
    }
}

/// Validated NSEC records deny nothing below a negative trust anchor
/// (RFC 7646 §2, RFC 8198 §5): a name there is asked, and its answer has
/// no AD, as on a cold cache.
#[test]
fn validated_nsec_records_deny_nothing_below_a_negative_trust_anchor() {
    let (mut net, anchors) = internet(true);
    let anchor = LowerName::new(&name("nz.example.com."));
    let mut resolver = resolver(Config {
        negative_anchors: Some(Arc::new(move |name: &LowerName| *name == anchor)),
        ..config(anchors)
    });
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "nx.example.com.", RecordType::A, dnssec_ok),
    );
    assert!(reply.metadata.authentic_data);
    let before = net.recording().exchanges().len();
    // The NSEC that denied `nx` covers `nz` too.
    let reply = ask(
        &mut resolver,
        &mut net,
        1,
        query(client(1), "nz.example.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert!(!reply.metadata.authentic_data);
    assert!(
        net.recording().exchanges().len() > before,
        "the name is asked"
    );
}

/// A denial made from validated NSEC records carries the records that
/// prove it, however many others the cache holds for the zone (RFC 8198
/// §5.1): the one covering the name and the one covering the wildcard.
#[test]
fn a_denial_from_validated_nsec_records_carries_only_its_proof() {
    let (mut net, anchors) = internet(true);
    let mut resolver = resolver(config(anchors));
    for (n, label) in ["aaa", "ba", "bz", "nx", "wz", "zz", "xa"]
        .iter()
        .enumerate()
    {
        ask(
            &mut resolver,
            &mut net,
            n as u64,
            query(
                client(1),
                &format!("{label}.example.com."),
                RecordType::A,
                dnssec_ok,
            ),
        );
    }
    let before = net.recording().exchanges().len();
    let reply = ask(
        &mut resolver,
        &mut net,
        20,
        query(client(1), "nz.example.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(net.recording().exchanges().len(), before, "from the cache");
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert!(reply.metadata.authentic_data);
    assert!(!reply.metadata.truncation);
    let mut owners: Vec<String> = reply
        .authorities
        .iter()
        .filter(|record| record.record_type() == RecordType::NSEC)
        .map(|record| record.name.to_string())
        .collect();
    owners.sort();
    // `ns1` covers `nz`; the apex covers `*.example.com`.
    assert_eq!(owners, ["example.com.", "ns1.example.com."]);
}

/// An NSEC record that does not verify never makes a denial Secure and
/// is never kept to deny other names: here every NXDOMAIN of
/// `example.com` carries an unsigned NSEC that would cover `www`, which
/// exists.
#[test]
fn an_nsec_record_that_does_not_verify_denies_nothing() {
    use fictionet::stdlib::protocols::dns::dnssec::rdata::{DNSSECRData, NSEC};
    let forged = Record::from_rdata(
        name("nz.example.com."),
        300,
        RData::DNSSEC(DNSSECRData::NSEC(NSEC::new_cover_self(
            name("zzzz.example.com."),
            [RecordType::A],
        ))),
    );
    let (mut net, anchors) = internet_appending(true, Some(forged));
    let mut resolver = resolver(config(anchors));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "nx.example.com.", RecordType::A, dnssec_ok),
    );
    // Unbound fails a reply with any authority RRset that does not verify.
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert!(!reply.metadata.authentic_data);
    let before = net.recording().exchanges().len();
    let reply = ask(
        &mut resolver,
        &mut net,
        1,
        query(client(1), "www.example.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(addresses(&reply), ["192.0.2.80"]);
    assert!(reply.metadata.authentic_data);
    assert!(
        net.recording().exchanges().len() > before,
        "asked, not denied"
    );
}

#[test]
fn a_forwarder_sends_the_whole_question_with_rd_and_takes_the_answer() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(Config {
        ede: true,
        ..Config::dnsmasq(vec![SocketAddr::new(ip(EXAMPLE), 53)])
    });
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "x.y.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&reply), ["192.0.2.81"]);
    let recording = net.recording();
    let [asked] = recording.exchanges() else {
        panic!("one question to the forwarder");
    };
    assert_eq!(asked.server, SocketAddr::new(ip(EXAMPLE), 53));
    let message = Message::from_vec(&asked.query).unwrap();
    assert!(message.metadata.recursion_desired);
    assert_eq!(message.queries[0].name(), &name("x.y.example.com."));
    // dnsmasq does not validate: CD is clear upstream.
    assert!(!message.metadata.checking_disabled);
}

/// An upstream that validates, playing a zone whose signatures fail: it
/// answers SERVFAIL to a question without CD, and the data to one with
/// CD (RFC 4035 §3.2.2).
struct Validating;

impl Authority for Validating {
    fn respond(
        &self,
        req: &Request,
        _local: SocketAddr,
        _server: &ServerConfig,
        _client: &Client,
    ) -> Step {
        let query = &req.message.metadata;
        let mut message = Message::response(query.id, query.op_code);
        message.metadata.recursion_desired = req.rd;
        message.metadata.checking_disabled = req.cd;
        message.metadata.recursion_available = true;
        message.add_query(req.question.clone());
        if req.cd {
            message.add_answer(Record::from_rdata(
                req.question.name().clone(),
                300,
                a("192.0.2.98"),
            ));
        } else {
            message.metadata.response_code = ResponseCode::ServFail;
        }
        Step::Reply(Response {
            message,
            required_additional: 0,
        })
    }
}

/// dnsmasq without DNSSEC passes a client's CD bit on, so a client that
/// sets CD gets the data a validating upstream fails, even just after a
/// client without CD got the upstream's SERVFAIL.
#[test]
fn a_forwarder_that_does_not_validate_passes_cd_on() {
    let upstream = SocketAddr::new(ip(EXAMPLE), 53);
    let mut net = MemoryNet::new();
    net.serve(
        ip(EXAMPLE),
        AuthorityEngine::new(Validating, ServerConfig::generic(), upstream),
    );
    let mut dnsmasq = resolver(Config::dnsmasq(vec![upstream]));
    let reply = ask(
        &mut dnsmasq,
        &mut net,
        0,
        query(client(1), "www.bad.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    let checking_disabled = |message: &mut Message| {
        message.metadata.checking_disabled = true;
        dnssec_ok(message);
    };
    let reply = ask(
        &mut dnsmasq,
        &mut net,
        1,
        query(client(2), "www.bad.com.", RecordType::A, checking_disabled),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(addresses(&reply), ["192.0.2.98"]);
    assert!(!reply.metadata.authentic_data);
    let cd: Vec<bool> = net
        .recording()
        .exchanges()
        .iter()
        .map(|ask| {
            Message::from_vec(&ask.query)
                .unwrap()
                .metadata
                .checking_disabled
        })
        .collect();
    assert_eq!(cd, [false, true]);
}

/// What a client with CD set gets through dnsmasq without DNSSEC never
/// answers a later client without CD: that question goes upstream without
/// CD, and gets the validating upstream's SERVFAIL.
#[test]
fn a_forwarder_never_answers_a_client_without_cd_from_a_cd_answer() {
    let upstream = SocketAddr::new(ip(EXAMPLE), 53);
    let mut net = MemoryNet::new();
    net.serve(
        ip(EXAMPLE),
        AuthorityEngine::new(Validating, ServerConfig::generic(), upstream),
    );
    let mut dnsmasq = resolver(Config::dnsmasq(vec![upstream]));
    let checking_disabled = |message: &mut Message| {
        message.metadata.checking_disabled = true;
        dnssec_ok(message);
    };
    let reply = ask(
        &mut dnsmasq,
        &mut net,
        0,
        query(client(1), "www.bad.com.", RecordType::A, checking_disabled),
    );
    assert_eq!(addresses(&reply), ["192.0.2.98"]);
    let reply = ask(
        &mut dnsmasq,
        &mut net,
        1,
        query(client(2), "www.bad.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert!(addresses(&reply).is_empty());
    let cd: Vec<bool> = net
        .recording()
        .exchanges()
        .iter()
        .map(|ask| {
            Message::from_vec(&ask.query)
                .unwrap()
                .metadata
                .checking_disabled
        })
        .collect();
    assert_eq!(cd, [true, false]);
}

/// A forwarder that answers with a referral does not recurse, so the
/// referral is no step closer: the question fails after one query, never
/// asking the same forwarder again until the work bound runs out.
#[test]
fn a_referral_from_a_forwarder_fails_the_question() {
    let (mut net, _) = internet(false);
    let mut dnsmasq = resolver(Config::dnsmasq(vec![SocketAddr::new(ip(ROOT), 53)]));
    let reply = ask(
        &mut dnsmasq,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(net.recording().exchanges().len(), 1);
}

#[test]
fn google_answers_resolver_arpa_from_its_ddr_records_with_aa() {
    let (mut net, _) = internet(false);
    let identity = fictionet::stdlib::services::dns::authority::Identity::none();
    let mut resolver = resolver(Config {
        hints: vec![(name("a.root-servers.net."), ip(ROOT))],
        ..public::google(identity)
    });
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "_dns.resolver.arpa.", RecordType::SVCB, |_| {}),
    );
    assert!(reply.metadata.authoritative);
    assert_eq!(reply.answers.len(), 2);
    assert!(reply.answers.iter().all(|record| record.ttl == 86400));
    assert_eq!(reply.edns.unwrap().max_payload(), 512);
    assert!(net.recording().exchanges().is_empty());
}

/// [`config`] serving stale data: up to a day past the TTL, with TTL 30,
/// to a client that waited 1.8 seconds, and a server wait of `retransmit`.
fn stale_config(retransmit: Duration) -> Config {
    Config {
        serve_stale: Some(fictionet::stdlib::services::dns::resolver::Stale {
            max_stale: Duration::from_secs(86400),
            reply_ttl: Duration::from_secs(30),
            client_timeout: Duration::from_millis(1800),
        }),
        retransmit,
        ..config(None)
    }
}

fn lose_example(net: &mut MemoryNet) {
    net.lose(|transmit| {
        let to = transmit.to.ip();
        to == ip(EXAMPLE) || to == ip(EXAMPLE_TOO)
    });
}

#[test]
fn expired_data_answers_when_resolution_fails() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(stale_config(Duration::from_millis(376)));
    ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    lose_example(&mut net);
    let reply = ask(
        &mut resolver,
        &mut net,
        400,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(addresses(&reply), ["192.0.2.80"]);
    assert_eq!(reply.answers[0].ttl, 30);
    assert_eq!(edes(&reply), [EdeCode::STALE_ANSWER]);
}

#[test]
fn expired_data_answers_a_client_kept_waiting_while_the_resolution_goes_on() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(stale_config(Duration::from_secs(1)));
    ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    // Both addresses of the zone's server are cached, so the resolution
    // waits a second for each.
    ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "ns1.example.com.", RecordType::A, |_| {}),
    );
    lose_example(&mut net);
    let entropy = entropy();
    resolver.handle(
        Input::Query(query(client(2), "www.example.com.", RecordType::A, |_| {})),
        at(400),
        &entropy,
    );
    let mut answers = pump(&mut resolver, &mut net, at(400), Vec::new());
    assert!(answers.is_empty(), "both servers are being waited for");
    // The first server times out after a second; the client timeout comes
    // before the second server's.
    let mut now = at(400);
    while answers.is_empty() {
        now = resolver.next_deadline().expect("the resolution goes on");
        resolver.handle(Input::Tick, now, &entropy);
        answers = pump(&mut resolver, &mut net, now, Vec::new());
    }
    assert_eq!(now, at(400) + Duration::from_millis(1800));
    let reply = Message::from_vec(&answers[0].bytes).unwrap();
    assert_eq!(addresses(&reply), ["192.0.2.80"]);
    assert_eq!(edes(&reply), [EdeCode::STALE_ANSWER]);
    // The resolution still runs, and caches its failure when it ends.
    assert!(resolver.next_deadline().is_some());
    while let Some(deadline) = resolver.next_deadline() {
        resolver.handle(Input::Tick, deadline, &entropy);
        assert!(pump(&mut resolver, &mut net, deadline, Vec::new()).is_empty());
    }
    let key = Key::new(
        LowerName::new(&name("www.example.com.")),
        RecordType::A,
        fictionet::stdlib::protocols::dns::rr::DNSClass::IN,
    );
    assert!(matches!(
        resolver.cache().get(&key, at(403)),
        Some(Entry::Failure {
            why: FailureKind::NoReachableAuthority,
            ..
        })
    ));
}

/// Stale data is served only as fresh data would be: data a client with
/// CD set fetched, which no check validated, never reaches a client that
/// asked for validation once it expires, on failure or on the client
/// timeout.
#[test]
fn stale_data_no_check_validated_never_reaches_a_validating_client() {
    // The client timeout comes before the resolution fails, then after.
    for client_timeout in [Duration::from_millis(1800), Duration::from_secs(60)] {
        let (mut net, anchors) = internet(true);
        let mut resolver = resolver(Config {
            anchors,
            serve_stale: Some(fictionet::stdlib::services::dns::resolver::Stale {
                max_stale: Duration::from_secs(86400),
                reply_ttl: Duration::from_secs(30),
                client_timeout,
            }),
            ..config(None)
        });
        let checking_disabled = |message: &mut Message| {
            message.metadata.checking_disabled = true;
            dnssec_ok(message);
        };
        let reply = ask(
            &mut resolver,
            &mut net,
            0,
            query(client(1), "www.bad.com.", RecordType::A, checking_disabled),
        );
        assert_eq!(addresses(&reply), ["192.0.2.98"]);
        let reply = ask(
            &mut resolver,
            &mut net,
            1,
            query(client(1), "www.bad.com.", RecordType::A, dnssec_ok),
        );
        assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
        // After the Bogus result's failure TTL, a client with CD set
        // fetches the data again, unchecked.
        ask(
            &mut resolver,
            &mut net,
            6,
            query(client(1), "www.bad.com.", RecordType::A, checking_disabled),
        );
        net.lose(|transmit| transmit.to.ip() == ip(BAD));
        let entropy = entropy();
        resolver.handle(
            Input::Query(query(client(2), "www.bad.com.", RecordType::A, dnssec_ok)),
            at(400),
            &entropy,
        );
        let mut answers = pump(&mut resolver, &mut net, at(400), Vec::new());
        while answers.is_empty() {
            let now = resolver.next_deadline().expect("the resolution goes on");
            resolver.handle(Input::Tick, now, &entropy);
            answers = pump(&mut resolver, &mut net, now, Vec::new());
        }
        let reply = Message::from_vec(&answers[0].bytes).unwrap();
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::ServFail,
            "{client_timeout:?}: {reply:?}"
        );
        assert!(addresses(&reply).is_empty());
    }
}

/// On the client timeout, the aliases a validating client's question
/// followed to stale data are validated before the answer goes out: a
/// Bogus CNAME to a name whose servers stopped answering fails, as it
/// does when they answer.
#[test]
fn stale_data_on_the_client_timeout_never_brings_an_unchecked_alias() {
    for lose in [true, false] {
        let (mut net, anchors) = internet(true);
        let mut resolver = resolver(Config {
            anchors,
            ede: true,
            ..stale_config(Duration::from_secs(1))
        });
        let reply = ask(
            &mut resolver,
            &mut net,
            0,
            query(client(1), "www.example.com.", RecordType::A, dnssec_ok),
        );
        assert!(reply.metadata.authentic_data);
        // Both addresses of the zone's server are cached, so a lost
        // resolution waits a second for each, past the client timeout.
        ask(
            &mut resolver,
            &mut net,
            0,
            query(client(1), "ns1.example.com.", RecordType::A, |_| {}),
        );
        if lose {
            lose_example(&mut net);
        }
        let entropy = entropy();
        resolver.handle(
            Input::Query(query(client(2), "alias.bad.com.", RecordType::A, dnssec_ok)),
            at(400),
            &entropy,
        );
        let mut answers = pump(&mut resolver, &mut net, at(400), Vec::new());
        while answers.is_empty() {
            let now = resolver.next_deadline().expect("the resolution goes on");
            resolver.handle(Input::Tick, now, &entropy);
            answers = pump(&mut resolver, &mut net, now, Vec::new());
        }
        let reply = Message::from_vec(&answers[0].bytes).unwrap();
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::ServFail,
            "servers lost: {lose}: {reply:?}"
        );
        assert!(reply.answers.is_empty(), "servers lost: {lose}: {reply:?}");
        // No DNSKEY in `bad.com` matches the DS.
        assert_eq!(
            edes(&reply),
            [EdeCode::DNSKEY_MISSING],
            "servers lost: {lose}"
        );
    }
}

/// Serves `zones` at `address` in `net`.
fn serve_at(net: &mut MemoryNet, address: &str, zones: Vec<Zone>) {
    let local = SocketAddr::new(ip(address), 53);
    let zones = zones
        .into_iter()
        .map(|zone| Arc::new(zone) as Arc<dyn ZoneData>)
        .collect();
    net.serve(
        ip(address),
        AuthorityEngine::new(Zones::new(zones), ServerConfig::generic(), local),
    );
}

/// The root, `com`, and `example.com`, unsigned, with `example.com`
/// changed by `example` and delegated from `com` with its NS RRset at
/// `ns_ttl` and its glue at `glue_ttl`.
fn delegated(
    example: impl FnOnce(ZoneBuilder) -> ZoneBuilder,
    ns_ttl: u32,
    glue_ttl: u32,
) -> MemoryNet {
    let root = delegation(
        builder(".", "a.root-servers.net.").rrset(rrset(
            "a.root-servers.net.",
            3600,
            vec![a(ROOT)],
        )),
        "com.",
        "ns.nic.com.",
        Some(COM),
        None,
    )
    .build()
    .unwrap();
    let com = builder("com.", "ns.nic.com.")
        .rrset(rrset("ns.nic.com.", 3600, vec![a(COM)]))
        .delegate(
            name("example.com."),
            rrset("example.com.", ns_ttl, vec![ns("ns1.example.com.")]),
            vec![rrset("ns1.example.com.", glue_ttl, vec![a(EXAMPLE)])],
            None,
        )
        .build()
        .unwrap();
    let example = example(
        builder("example.com.", "ns1.example.com.")
            .rrset(rrset("ns1.example.com.", 3600, vec![a(EXAMPLE)]))
            .rrset(rrset("www.example.com.", 300, vec![a("192.0.2.80")])),
    )
    .build()
    .unwrap();
    let mut net = MemoryNet::new();
    serve_at(&mut net, ROOT, vec![root]);
    serve_at(&mut net, COM, vec![com]);
    serve_at(&mut net, EXAMPLE, vec![example]);
    net
}

#[test]
fn a_yxdomain_from_a_dname_is_passed_on_with_the_dname() {
    // The DNAME's substitution passes 255 octets, so the authority answers
    // YXDOMAIN (RFC 6672 §2.2), and that is the answer.
    let target = format!(
        "{}.{}.{}.example.org.",
        "t".repeat(60),
        "u".repeat(60),
        "v".repeat(60)
    );
    let mut net = delegated(
        |zone| zone.rrset(rrset("long.example.com.", 300, vec![dname(&name(&target))])),
        3600,
        3600,
    );
    let mut resolver = resolver(config(None));
    let qname = format!("{}.long.example.com.", "y".repeat(60));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), &qname, RecordType::A, |_| {}),
    );
    assert_eq!(
        reply.metadata.response_code,
        ResponseCode::YXDomain,
        "{:?}",
        edes(&reply)
    );
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(reply.answers[0].name, name("long.example.com."));
    assert_eq!(reply.answers[0].record_type(), RecordType::DNAME);
}

#[test]
fn glue_with_ttl_0_serves_the_resolution_it_came_in() {
    // RFC 1035 §7.4: data with TTL 0 is not cached, but is used for the
    // transaction in progress.
    let mut net = delegated(|zone| zone, 3600, 0);
    let mut resolver = resolver(config(None));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&reply), ["192.0.2.80"]);
}

#[test]
fn a_referral_with_ttl_0_moves_the_resolution_down() {
    let mut net = delegated(|zone| zone, 0, 3600);
    let mut resolver = resolver(config(None));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&reply), ["192.0.2.80"]);
    assert!(net.recording().exchanges().len() < 10);
}

#[test]
fn a_failure_the_work_bound_caused_is_not_cached_for_other_clients() {
    // The bound is one question's. A lookup it cut short says nothing
    // about the servers, so another client's question that fits the bound
    // resolves.
    for queries in 1..14u16 {
        let (mut net, _) = internet(false);
        let mut resolver = resolver(Config {
            work: Work { queries, depth: 11 },
            ..config(None)
        });
        ask(
            &mut resolver,
            &mut net,
            0,
            query(client(1), "away.example.com.", RecordType::A, |_| {}),
        );
        let failures: Vec<String> = resolver
            .cache()
            .entries(at(0))
            .filter(|(_, entry)| {
                matches!(
                    entry,
                    Entry::Failure {
                        why: FailureKind::WorkExceeded,
                        ..
                    }
                )
            })
            .map(|(key, _)| key.name.to_string())
            .collect();
        assert_eq!(failures, Vec::<String>::new(), "{queries} queries");
    }
    let (mut net, _) = internet(false);
    let mut resolver = resolver(Config {
        work: Work {
            queries: 6,
            depth: 11,
        },
        ..config(None)
    });
    let first = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "away.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(first.metadata.response_code, ResponseCode::ServFail);
    let second = ask(
        &mut resolver,
        &mut net,
        1,
        query(client(2), "www.example.org.", RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&second), ["192.0.2.90"]);
}

#[test]
fn a_failed_lookup_keeps_the_glue_it_lays_over() {
    // A failure is no data (RFC 9520 §3): the glue that says where the
    // servers of `example.com` are outlives a failed lookup of their
    // names, so the zone resolves again once they are back.
    let (mut net, _) = internet(false);
    let mut resolver = resolver(config(None));
    let first = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&first), ["192.0.2.80"]);
    net.lose(|transmit| {
        let to = transmit.to.ip();
        to == ip(EXAMPLE) || to == ip(EXAMPLE_TOO)
    });
    let lost = ask(
        &mut resolver,
        &mut net,
        10,
        query(client(2), "ns1.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(lost.metadata.response_code, ResponseCode::ServFail);
    net.lose(|_| false);
    let after = ask(
        &mut resolver,
        &mut net,
        60,
        query(client(3), "x.y.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&after), ["192.0.2.81"]);
}

#[test]
fn an_unsigned_child_its_signed_parents_server_also_serves_is_insecure() {
    // The server answers for the child itself, so no referral shows the
    // cut. The parent's proof that the child has no DS makes the unsigned
    // answer Insecure (RFC 4035 §5.2).
    let root_keys = keys(10);
    let com_keys = keys(20);
    let example_keys = keys(40);
    let root = delegation(
        builder(".", "a.root-servers.net.").rrset(rrset(
            "a.root-servers.net.",
            3600,
            vec![a(ROOT)],
        )),
        "com.",
        "ns.nic.com.",
        Some(COM),
        Some(ds(&com_keys, "com.")),
    )
    .build()
    .unwrap()
    .signed(&root_keys, window(), Denial::Nsec)
    .unwrap();
    let com = delegation(
        builder("com.", "ns.nic.com.").rrset(rrset("ns.nic.com.", 3600, vec![a(COM)])),
        "example.com.",
        "ns1.example.com.",
        Some(EXAMPLE),
        Some(ds(&example_keys, "example.com.")),
    )
    .build()
    .unwrap()
    .signed(&com_keys, window(), Denial::Nsec)
    .unwrap();
    let example = delegation(
        builder("example.com.", "ns1.example.com.").rrset(rrset(
            "ns1.example.com.",
            3600,
            vec![a(EXAMPLE)],
        )),
        "sub.example.com.",
        "ns1.example.com.",
        None,
        None,
    )
    .build()
    .unwrap()
    .signed(&example_keys, window(), Denial::Nsec)
    .unwrap();
    let sub = builder("sub.example.com.", "ns1.example.com.")
        .rrset(rrset("www.sub.example.com.", 300, vec![a("192.0.2.77")]))
        .build()
        .unwrap();
    let mut net = MemoryNet::new();
    serve_at(&mut net, ROOT, vec![root]);
    serve_at(&mut net, COM, vec![com]);
    serve_at(&mut net, EXAMPLE, vec![example, sub]);
    let anchors = Anchors::of(vec![root_keys.anchor(&Name::root())]);
    let mut resolver = resolver(config(Some(anchors)));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.sub.example.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(addresses(&reply), ["192.0.2.77"]);
    assert!(!reply.metadata.authentic_data);
    let key = Key::new(
        LowerName::new(&name("www.sub.example.com.")),
        RecordType::A,
        fictionet::stdlib::protocols::dns::rr::DNSClass::IN,
    );
    assert!(matches!(
        resolver.cache().get(&key, at(0)),
        Some(Entry::Positive {
            validation: Validation::Insecure(_),
            ..
        })
    ));
}

#[test]
fn a_cached_cname_that_runs_out_while_its_target_is_chased_is_fetched_again() {
    // A record the cache gave the answer never goes out past its TTL: the
    // chain is followed again from the question.
    let root = Zone::from_master(
        ". 86400 IN SOA a.root. h.root. 1 7200 3600 1209600 300\n\
         . 518400 IN NS a.root.\n\
         a.root. 518400 IN A 198.41.0.4\n\
         alpha. 172800 IN NS ns1.alpha.\n\
         ns1.alpha. 172800 IN A 192.0.2.1\n\
         beta. 172800 IN NS ns1.beta.\n\
         beta. 172800 IN NS ns2.beta.\n\
         beta. 172800 IN NS ns3.beta.\n\
         beta. 172800 IN NS ns4.beta.\n\
         ns1.beta. 172800 IN A 192.0.2.11\n\
         ns2.beta. 172800 IN A 192.0.2.12\n\
         ns3.beta. 172800 IN A 192.0.2.13\n\
         ns4.beta. 172800 IN A 192.0.2.14\n",
        None,
    )
    .unwrap();
    let alpha = Zone::from_master(
        "alpha. 3600 IN SOA ns1.alpha. h.alpha. 1 7200 3600 1209600 300\n\
         alpha. 3600 IN NS ns1.alpha.\n\
         ns1.alpha. 3600 IN A 192.0.2.1\n\
         alias.alpha. 1 IN CNAME www.beta.\n",
        None,
    )
    .unwrap();
    let beta = Zone::from_master(
        "beta. 3600 IN SOA ns1.beta. h.beta. 1 7200 3600 1209600 300\n\
         beta. 3600 IN NS ns1.beta.\n\
         beta. 3600 IN NS ns2.beta.\n\
         beta. 3600 IN NS ns3.beta.\n\
         beta. 3600 IN NS ns4.beta.\n\
         ns1.beta. 3600 IN A 192.0.2.11\n\
         ns2.beta. 3600 IN A 192.0.2.12\n\
         ns3.beta. 3600 IN A 192.0.2.13\n\
         ns4.beta. 3600 IN A 192.0.2.14\n\
         www.beta. 300 IN A 192.0.2.80\n",
        None,
    )
    .unwrap();
    let mut net = MemoryNet::new();
    serve_at(&mut net, "198.41.0.4", vec![root]);
    serve_at(&mut net, "192.0.2.1", vec![alpha]);
    for address in ["192.0.2.11", "192.0.2.12", "192.0.2.13", "192.0.2.14"] {
        serve_at(&mut net, address, vec![beta.clone()]);
    }
    // The first three queries to the beta servers are lost, so the target
    // takes longer than the CNAME's one second.
    let mut lost = 0;
    net.lose(move |transmit| {
        let beta = ["192.0.2.11", "192.0.2.12", "192.0.2.13", "192.0.2.14"]
            .iter()
            .any(|address| transmit.to.ip() == ip(address));
        let lose = beta && lost < 3;
        lost += usize::from(lose);
        lose
    });
    let mut resolver = resolver(Config {
        hints: vec![(name("a.root."), ip("198.41.0.4"))],
        minimise: None,
        ..config(None)
    });
    // The CNAME question puts the CNAME in the cache, and the A question
    // takes it from there.
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "alias.alpha.", RecordType::CNAME, |_| {}),
    );
    assert_eq!(reply.answers.len(), 1);
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(2), "alias.alpha.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(addresses(&reply), ["192.0.2.80"]);
    for record in &reply.answers {
        assert!(record.ttl > 0, "{record} is past its TTL");
    }
    let cnames = asked(&net)
        .iter()
        .filter(|(server, qname, _, _)| *server == ip("192.0.2.1") && qname == "alias.alpha.")
        .count();
    assert_eq!(cnames, 2, "the CNAME is fetched again after it ran out");
}

#[test]
fn data_that_runs_out_while_it_is_fetched_serves_the_answer_it_came_for() {
    // Each round trip takes longer than the CNAME's and the target's TTL.
    // Data that arrived for the question serves its answer with the TTL it
    // has left (RFC 1035 §7.4), so the question is answered once.
    let (mut net, _) = internet(false);
    let example = builder("example.com.", "ns1.example.com.")
        .rrset(rrset(
            "ns1.example.com.",
            3600,
            vec![a(EXAMPLE), a(EXAMPLE_TOO)],
        ))
        .rrset(rrset(
            "c.example.com.",
            1,
            vec![RData::CNAME(CNAME(name("t.example.org.")))],
        ))
        .build()
        .unwrap();
    serve_at(&mut net, EXAMPLE, vec![example.clone()]);
    serve_at(&mut net, EXAMPLE_TOO, vec![example]);
    let example_org = builder("example.org.", "ns1.example.org.")
        .rrset(rrset("ns1.example.org.", 3600, vec![a(EXAMPLE_ORG)]))
        .rrset(rrset("t.example.org.", 1, vec![a("192.0.2.91")]))
        .build()
        .unwrap();
    serve_at(&mut net, EXAMPLE_ORG, vec![example_org]);
    // The resolver waits longer than a round trip, so no query times out.
    let mut resolver = resolver(Config {
        retransmit: Duration::from_secs(3),
        ..config(None)
    });
    let reply = ask_slowly(
        &mut resolver,
        &mut net,
        query(client(1), "c.example.com.", RecordType::A, |_| {}),
        Duration::from_millis(1100),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(addresses(&reply), ["192.0.2.91"]);
    assert_eq!(reply.answers[0].ttl, 0, "the CNAME has run out");
    let cnames = asked(&net)
        .iter()
        .filter(|(_, qname, rtype, _)| qname == "c.example.com." && *rtype == RecordType::A)
        .count();
    assert_eq!(cnames, 1, "the CNAME is fetched once");
}

#[test]
fn the_root_answers_its_own_ds_question() {
    // The root has no parent, so `. DS` goes to the root's servers, which
    // answer NODATA.
    for signed in [false, true] {
        let (mut net, anchors) = internet(signed);
        let mut resolver = resolver(config(anchors));
        let reply = ask(
            &mut resolver,
            &mut net,
            0,
            query(client(1), ".", RecordType::DS, dnssec_ok),
        );
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.answers.is_empty());
        assert_eq!(reply.metadata.authentic_data, signed);
    }
}

#[test]
fn a_cached_cname_answers_a_question_for_cname_itself() {
    let mut net = delegated(
        |zone| {
            zone.rrset(rrset(
                "dangle.example.com.",
                600,
                vec![RData::CNAME(CNAME(name("nope.example.com.")))],
            ))
        },
        3600,
        3600,
    );
    let mut resolver = resolver(config(None));
    let first = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "dangle.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(first.metadata.response_code, ResponseCode::NXDomain);
    for seconds in [2, 3] {
        let reply = ask(
            &mut resolver,
            &mut net,
            seconds,
            query(client(1), "dangle.example.com.", RecordType::CNAME, |_| {}),
        );
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(reply.answers[0].record_type(), RecordType::CNAME);
        assert!(reply.authorities.is_empty());
    }
    let chased = asked(&net)
        .iter()
        .any(|(_, qname, qtype, _)| qname == "nope.example.com." && *qtype == RecordType::CNAME);
    assert!(!chased, "the target is never asked for a CNAME");
}

#[test]
fn a_question_for_rrsig_gets_the_signatures() {
    let (mut net, anchors) = internet(true);
    let mut resolver = resolver(config(anchors));
    for seconds in [0, 1] {
        let reply = ask(
            &mut resolver,
            &mut net,
            seconds,
            query(client(1), "www.example.com.", RecordType::RRSIG, dnssec_ok),
        );
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(!reply.answers.is_empty());
        assert!(
            reply
                .answers
                .iter()
                .all(|record| record.record_type() == RecordType::RRSIG)
        );
    }
}

#[test]
fn a_silent_root_is_asked_at_most_three_times_per_hint_and_the_failure_is_cached() {
    let (mut net, _) = internet(false);
    net.lose(|_| true);
    let mut resolver = resolver(config(None));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(edes(&reply), [EdeCode::NO_REACHABLE_AUTHORITY]);
    let sent = net.recording().exchanges().len();
    assert_eq!(sent, 3, "the one hint, three times (RFC 9520 §3.1)");
    let again = ask(
        &mut resolver,
        &mut net,
        1,
        query(client(2), "www.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(again.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(net.recording().exchanges().len(), sent, "from the cache");
}

/// Resolves `query` at time zero through `net`, with every reply arriving
/// `delay` after its query was sent.
fn ask_slowly(
    resolver: &mut Resolver,
    net: &mut MemoryNet,
    query: ClientQuery,
    delay: Duration,
) -> Message {
    let entropy = entropy();
    let mut now = Instant::ZERO;
    let mut due: Vec<(Instant, Input)> = Vec::new();
    resolver.handle(Input::Query(query), now, &entropy);
    loop {
        while let Some(action) = resolver.poll() {
            match action {
                Action::Send(transmit) => {
                    for input in net.exchange(&transmit, now, &entropy) {
                        due.push((now + delay, input));
                    }
                }
                Action::Answer(answer) => return Message::from_vec(&answer.bytes).unwrap(),
                Action::Lookup { .. } | Action::Abandon(_) | Action::Event(_) => {}
            }
        }
        let next_reply = due.iter().map(|(when, _)| *when).min();
        let deadline = resolver.next_deadline();
        match next_reply {
            Some(reply) if deadline.is_none_or(|deadline| reply < deadline) => {
                now = reply;
                let index = due.iter().position(|(when, _)| *when == reply).unwrap();
                let (_, input) = due.remove(index);
                resolver.handle(input, now, &entropy);
            }
            _ => {
                now = deadline.expect("the resolver stopped without an answer");
                resolver.handle(Input::Tick, now, &entropy);
            }
        }
    }
}

#[test]
fn servers_slower_than_the_first_wait_are_asked_again_and_answer() {
    // Every server takes 450 ms, past the 376 ms the resolver first waits
    // for a server it does not know. It asks again, waiting longer, and
    // learns how long each server takes.
    let (mut net, _) = internet(false);
    let mut resolver = resolver(config(None));
    let reply = ask_slowly(
        &mut resolver,
        &mut net,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
        Duration::from_millis(450),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(addresses(&reply), ["192.0.2.80"]);
    // A second question for a server it now knows costs no timeout.
    let before = net.recording().exchanges().len();
    let reply = ask_slowly(
        &mut resolver,
        &mut net,
        query(client(1), "x.y.example.com.", RecordType::A, |_| {}),
        Duration::from_millis(450),
    );
    assert_eq!(addresses(&reply), ["192.0.2.81"]);
    let questions = asked(&net)[before..].to_vec();
    let names: Vec<&str> = questions.iter().map(|(_, n, _, _)| n.as_str()).collect();
    let mut unique = names.clone();
    unique.dedup();
    assert_eq!(names, unique, "no question is sent twice: {questions:?}");
}

#[test]
fn truncated_answers_from_a_slow_server_are_fetched_over_tcp() {
    // Each exchange takes 450 ms, over TCP too, past the 376 ms the
    // resolver first waits for a server it does not know.
    let (mut net, _) = internet(false);
    let mut resolver = resolver(config(None));
    let mut tcp = client(1);
    tcp.transport = Transport::Tcp;
    let reply = ask_slowly(
        &mut resolver,
        &mut net,
        query(tcp, "big.example.com.", RecordType::TXT, |_| {}),
        Duration::from_millis(450),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(reply.answers.len(), 8);
}

#[test]
fn a_record_with_empty_rdata_resolves() {
    const TEST: &str = "192.0.2.77";
    let root = delegation(
        builder(".", "a.root-servers.net.").rrset(rrset(
            "a.root-servers.net.",
            3600,
            vec![a(ROOT)],
        )),
        "test.",
        "ns.test.",
        Some(TEST),
        None,
    )
    .build()
    .unwrap();
    // RFC 3597 §5: a record of an unknown type with no RDATA.
    let test = Zone::from_master(
        &format!(
            "$ORIGIN test.
$TTL 3600
@   SOA ns hostmaster 1 7200 3600 1209600 900
@   NS  ns
ns  A   {TEST}
e   TYPE65281 \\# 0
e   A   192.0.2.5
"
        ),
        None,
    )
    .unwrap();
    let mut net = MemoryNet::new();
    serve_at(&mut net, ROOT, vec![root]);
    serve_at(&mut net, TEST, vec![test]);
    let mut resolver = resolver(config(None));
    let empty = RecordType::Unknown(65281);
    let answers = drive(
        &mut resolver,
        &mut net,
        vec![query(client(1), "e.test.", empty, |_| {})],
        at(0),
        &entropy(),
    );
    let reply = read_message(&answers[0].bytes).unwrap();
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(rows(&reply.answers), [("e.test.".to_string(), empty)]);
    let RData::Update0(rtype) = reply.answers[0].data else {
        panic!("empty RDATA: {:?}", reply.answers[0].data);
    };
    assert_eq!(rtype, empty);
}

/// The owner and type of each record.
fn rows(records: &[Record]) -> Vec<(String, RecordType)> {
    records
        .iter()
        .map(|record| (record.name.to_string(), record.record_type()))
        .collect()
}

#[test]
fn a_cname_asked_for_below_a_dname_is_vouched_for_by_the_dname() {
    let root_keys = keys(10);
    let example_keys = keys(40);
    let root = delegation(
        builder(".", "a.root-servers.net.").rrset(rrset(
            "a.root-servers.net.",
            3600,
            vec![a(ROOT)],
        )),
        "example.",
        "ns1.example.",
        Some(EXAMPLE),
        Some(ds(&example_keys, "example.")),
    )
    .build()
    .unwrap()
    .signed(&root_keys, window(), Denial::Nsec)
    .unwrap();
    let example = builder("example.", "ns1.example.")
        .rrset(rrset("ns1.example.", 3600, vec![a(EXAMPLE)]))
        .rrset(rrset("d.example.", 300, vec![dname(&name("t.example."))]))
        .rrset(rrset("x.t.example.", 300, vec![a("192.0.2.77")]))
        .build()
        .unwrap()
        .signed(&example_keys, window(), Denial::Nsec)
        .unwrap();
    let mut net = MemoryNet::new();
    serve_at(&mut net, ROOT, vec![root]);
    serve_at(&mut net, EXAMPLE, vec![example]);
    let anchors = Anchors::of(vec![root_keys.anchor(&Name::root())]);
    for (qtype, last) in [
        (RecordType::A, RecordType::A),
        (RecordType::CNAME, RecordType::CNAME),
    ] {
        let mut resolver = resolver(config(Some(anchors.clone())));
        let reply = ask(
            &mut resolver,
            &mut net,
            0,
            query(client(1), "x.d.example.", qtype, dnssec_ok),
        );
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NoError,
            "{qtype}"
        );
        assert!(reply.metadata.authentic_data, "{qtype}");
        let types: Vec<RecordType> = reply
            .answers
            .iter()
            .map(Record::record_type)
            .filter(|rtype| *rtype != RecordType::RRSIG)
            .collect();
        assert_eq!(
            types[..2],
            [RecordType::DNAME, RecordType::CNAME],
            "{qtype}"
        );
        assert_eq!(types.last(), Some(&last), "{qtype}");
    }
}

#[test]
fn a_bogus_nxdomain_is_fetched_again_after_the_failure_ttl() {
    let (mut net, anchors) = internet(true);
    let mut resolver = resolver(config(anchors));
    let nx = || query(client(1), "nx.bad.com.", RecordType::A, dnssec_ok);
    let reply = ask(&mut resolver, &mut net, 0, nx());
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    // Past the 5 seconds a Bogus result lives, the server is asked again.
    let before = asked(&net).len();
    let reply = ask(&mut resolver, &mut net, 10, nx());
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    let again: Vec<String> = asked(&net)[before..]
        .iter()
        .map(|(_, name, _, _)| name.clone())
        .collect();
    assert!(again.contains(&"nx.bad.com.".to_string()), "{again:?}");
}

#[test]
fn a_fresh_secure_answer_lives_no_longer_than_its_signatures() {
    let (mut net, anchors) = internet(true);
    // The signatures expire 60 seconds after the run starts.
    let mut resolver = Resolver::new(
        config(anchors),
        Ring,
        WallClock {
            start: date(1_800_000_000 - 60),
        },
    );
    for (seconds, port) in [(0, 1), (1, 2)] {
        let reply = ask(
            &mut resolver,
            &mut net,
            seconds,
            query(client(port), "www.example.com.", RecordType::A, dnssec_ok),
        );
        assert!(reply.metadata.authentic_data);
        let limit = 61 - seconds as u32;
        for record in &reply.answers {
            assert!(record.ttl <= limit, "{seconds}: {record}");
        }
    }
}

#[test]
fn root_ns_with_ttl_0_serve_the_question_they_were_primed_for() {
    let root = Zone::builder(name("."), soa("."), 3600)
        .rrset(rrset(".", 0, vec![ns("a.root-servers.net.")]))
        .rrset(rrset("a.root-servers.net.", 3600, vec![a(ROOT)]));
    let root = delegation(root, "com.", "ns.nic.com.", Some(COM), None)
        .build()
        .unwrap();
    let com = delegation(
        builder("com.", "ns.nic.com.").rrset(rrset("ns.nic.com.", 3600, vec![a(COM)])),
        "example.com.",
        "ns1.example.com.",
        Some(EXAMPLE),
        None,
    )
    .build()
    .unwrap();
    let example = builder("example.com.", "ns1.example.com.")
        .rrset(rrset("ns1.example.com.", 3600, vec![a(EXAMPLE)]))
        .rrset(rrset("www.example.com.", 300, vec![a("192.0.2.80")]))
        .build()
        .unwrap();
    let mut net = MemoryNet::new();
    serve_at(&mut net, ROOT, vec![root]);
    serve_at(&mut net, COM, vec![com]);
    serve_at(&mut net, EXAMPLE, vec![example]);
    let mut resolver = resolver(config(None));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&reply), ["192.0.2.80"]);
    let priming = asked(&net)
        .into_iter()
        .filter(|(_, name, rtype, _)| name == "." && *rtype == RecordType::NS)
        .count();
    assert_eq!(priming, 1);
}

#[test]
fn the_work_bound_says_no_reachable_authority_only_when_no_server_replied() {
    // Every server in this hierarchy replies, wherever the bound cuts the
    // question off.
    for queries in 1..14u16 {
        let (mut net, _) = internet(false);
        let mut resolver = resolver(Config {
            work: Work { queries, depth: 11 },
            ..config(None)
        });
        let reply = ask(
            &mut resolver,
            &mut net,
            0,
            query(client(1), "away.example.com.", RecordType::A, |_| {}),
        );
        if reply.metadata.response_code == ResponseCode::ServFail {
            assert_eq!(edes(&reply), [EdeCode::OTHER], "{queries} queries");
        }
    }
}

#[test]
fn priming_offers_room_for_the_roots_ns_rrset_and_glue() {
    // Google's resolver advertises 512 octets to its clients.
    let mut google = Resolver::new(
        Config {
            hints: vec![(name("a.root-servers.net."), ip(ROOT))],
            ..public::google(Identity::none())
        },
        Ring,
        clock(),
    );
    let www = query(client(1), "www.example.com.", RecordType::A, |_| {});
    google.handle(Input::Query(www), at(0), &entropy());
    let sent = std::iter::from_fn(|| google.poll())
        .find_map(|action| match action {
            Action::Send(transmit) => Some(transmit),
            _ => None,
        })
        .expect("a query to the root");
    let priming = Message::from_vec(&sent.bytes).unwrap();
    assert_eq!(priming.queries[0].name(), &Name::root());
    assert_eq!(priming.queries[0].query_type(), RecordType::NS);
    assert_eq!(priming.edns.unwrap().max_payload(), 1232);
}

/// Answers as the authority it wraps does, but never answers a DS
/// question.
struct NoDs<A>(A);

impl<A: Authority> Authority for NoDs<A> {
    fn respond(
        &self,
        req: &Request,
        local: SocketAddr,
        server: &ServerConfig,
        client: &Client,
    ) -> Step {
        if req.question.query_type() == RecordType::DS {
            return Step::Silent;
        }
        self.0.respond(req, local, server, client)
    }
}

#[test]
fn an_insecure_delegation_above_a_server_silent_for_ds_makes_the_answer_insecure() {
    const SUB: &str = "192.0.2.31";
    let root_keys = keys(10);
    let org_keys = keys(30);
    let root = delegation(
        builder(".", "a.root-servers.net.").rrset(rrset(
            "a.root-servers.net.",
            3600,
            vec![a(ROOT)],
        )),
        "org.",
        "ns.nic.org.",
        Some(ORG),
        Some(ds(&org_keys, "org.")),
    )
    .build()
    .unwrap()
    .signed(&root_keys, window(), Denial::Nsec)
    .unwrap();
    // `example.org` is delegated without DS, as org's NSEC proves.
    let org = delegation(
        builder("org.", "ns.nic.org.").rrset(rrset("ns.nic.org.", 3600, vec![a(ORG)])),
        "example.org.",
        "ns1.example.org.",
        Some(EXAMPLE_ORG),
        None,
    )
    .build()
    .unwrap()
    .signed(&org_keys, window(), Denial::Nsec)
    .unwrap();
    let example = delegation(
        builder("example.org.", "ns1.example.org.").rrset(rrset(
            "ns1.example.org.",
            3600,
            vec![a(EXAMPLE_ORG)],
        )),
        "sub.example.org.",
        "ns.sub.example.org.",
        Some(SUB),
        None,
    )
    .build()
    .unwrap();
    let sub = builder("sub.example.org.", "ns.sub.example.org.")
        .rrset(rrset("ns.sub.example.org.", 3600, vec![a(SUB)]))
        .rrset(rrset("www.sub.example.org.", 300, vec![a("192.0.2.77")]))
        .build()
        .unwrap();
    let mut net = MemoryNet::new();
    serve_at(&mut net, ROOT, vec![root]);
    serve_at(&mut net, ORG, vec![org]);
    serve_at(&mut net, SUB, vec![sub]);
    // The server of `example.org` never answers the DS question for
    // `sub.example.org`, which the validation does not need.
    let zones = Zones::new(vec![Arc::new(example) as Arc<dyn ZoneData>]);
    let local = SocketAddr::new(ip(EXAMPLE_ORG), 53);
    net.serve(
        ip(EXAMPLE_ORG),
        AuthorityEngine::new(NoDs(zones), ServerConfig::generic(), local),
    );
    let anchors = Anchors::of(vec![root_keys.anchor(&Name::root())]);
    let mut resolver = resolver(config(Some(anchors)));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.sub.example.org.", RecordType::A, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(addresses(&reply), ["192.0.2.77"]);
    assert!(!reply.metadata.authentic_data);
}

#[test]
fn a_query_with_rd_clear_never_gets_data_no_check_validated() {
    let (mut net, anchors) = internet(true);
    let mut google = resolver(Config {
        rd0_from_cache: true,
        ..config(anchors)
    });
    // Validating `www.bad.com` fetches and caches `bad.com`'s DNSKEY set,
    // which no check validates.
    let reply = ask(
        &mut google,
        &mut net,
        0,
        query(client(1), "www.bad.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    let norec = |message: &mut Message| {
        message.metadata.recursion_desired = false;
        dnssec_ok(message);
    };
    let reply = ask(
        &mut google,
        &mut net,
        1,
        query(client(1), "bad.com.", RecordType::DNSKEY, norec),
    );
    assert!(reply.answers.is_empty(), "{:?}", reply.answers);
    // It gets the referral a server answering from its cache gives.
    assert!(
        reply
            .authorities
            .iter()
            .any(|record| record.record_type() == RecordType::NS)
    );
}

/// A check's result goes to the RRset it checked. Here the signed RRset
/// expires while its check waits for a DS reply, and other, unsigned data
/// is stored at the key by a client with CD set. The Secure result for
/// the old data must not mark the new data Secure: under a signed
/// delegation, unsigned data is Bogus.
#[test]
fn a_check_result_lands_only_on_the_rrset_it_checked() {
    let (mut net, anchors) = internet(true);
    let mut resolver = resolver(Config {
        max_ttl: Duration::from_secs(1),
        retransmit: Duration::from_secs(5),
        server_ttl: Duration::from_nanos(1),
        ..config(anchors)
    });
    let entropy = entropy();
    let ms = |millis: u64| at(0) + Duration::from_millis(millis);
    let checking_disabled = |message: &mut Message| {
        message.metadata.checking_disabled = true;
        dnssec_ok(message);
    };
    // Carries transmits through `net`, holding back the DS question to
    // com when `hold`, and gathers the answers by client port.
    let pump = |resolver: &mut Resolver,
                net: &mut MemoryNet,
                now: Instant,
                hold: bool,
                held: &mut Vec<fictionet::stdlib::services::dns::Transmit>,
                answers: &mut Vec<(u16, Message)>| {
        loop {
            let mut acted = false;
            while let Some(action) = resolver.poll() {
                match action {
                    Action::Send(transmit) => {
                        acted = true;
                        let sent = Message::from_vec(&transmit.bytes).unwrap();
                        let ds = sent.queries[0].query_type() == RecordType::DS;
                        if hold && transmit.to.ip() == ip(COM) && ds {
                            held.push(transmit);
                            continue;
                        }
                        for input in net.exchange(&transmit, now, &entropy) {
                            resolver.handle(input, now, &entropy);
                        }
                    }
                    Action::Answer(answer) => {
                        acted = true;
                        let message = Message::from_vec(&answer.bytes).unwrap();
                        answers.push((answer.client.peer.port(), message));
                    }
                    Action::Lookup { .. } | Action::Abandon(_) | Action::Event(_) => {}
                }
            }
            if !acted {
                return;
            }
        }
    };
    let (mut held, mut answers) = (Vec::new(), Vec::new());
    resolver.handle(
        Input::Query(query(
            client(1),
            "www.example.com.",
            RecordType::A,
            dnssec_ok,
        )),
        ms(0),
        &entropy,
    );
    pump(
        &mut resolver,
        &mut net,
        ms(0),
        true,
        &mut held,
        &mut answers,
    );
    assert!(answers.is_empty(), "the answer waits on the DS");
    assert_eq!(held.len(), 1);

    // The zone changes: `www` now has other data, unsigned.
    let changed = builder("example.com.", "ns1.example.com.")
        .rrset(rrset(
            "ns1.example.com.",
            3600,
            vec![a(EXAMPLE), a(EXAMPLE_TOO)],
        ))
        .rrset(rrset("www.example.com.", 300, vec![a("203.0.113.66")]))
        .build()
        .unwrap();
    serve_at(&mut net, EXAMPLE, vec![changed.clone()]);
    serve_at(&mut net, EXAMPLE_TOO, vec![changed]);
    resolver.handle(
        Input::Query(query(
            client(2),
            "www.example.com.",
            RecordType::A,
            checking_disabled,
        )),
        ms(1500),
        &entropy,
    );
    pump(
        &mut resolver,
        &mut net,
        ms(1500),
        false,
        &mut held,
        &mut answers,
    );

    // The held DS reply arrives inside its wait, and the check of the
    // old data concludes.
    let transmit = held.remove(0);
    for input in net.exchange(&transmit, ms(2000), &entropy) {
        resolver.handle(input, ms(2000), &entropy);
    }
    pump(
        &mut resolver,
        &mut net,
        ms(2000),
        false,
        &mut held,
        &mut answers,
    );
    resolver.handle(
        Input::Query(query(
            client(3),
            "www.example.com.",
            RecordType::A,
            dnssec_ok,
        )),
        ms(2100),
        &entropy,
    );
    pump(
        &mut resolver,
        &mut net,
        ms(2100),
        false,
        &mut held,
        &mut answers,
    );

    let answer = |port: u16| {
        answers
            .iter()
            .find(|(from, _)| *from == port)
            .map(|(_, message)| message)
            .unwrap_or_else(|| panic!("client {port} was answered"))
    };
    assert_eq!(addresses(answer(2)), ["203.0.113.66"]);
    for port in [1, 3] {
        let reply = answer(port);
        assert!(
            !(reply.metadata.authentic_data && addresses(reply) == ["203.0.113.66"]),
            "client {port}: unsigned data marked Secure: {reply:?}"
        );
    }
    let reply = answer(3);
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
}

/// A negative answer for a name server's own name is no data about how
/// its parent reaches it: the glue the parent gave keeps finding the
/// zone's servers (RFC 2181 §5.4.1), as in Unbound.
#[test]
fn a_negative_for_a_name_servers_name_keeps_its_glue() {
    let root = delegation(
        builder(".", "a.root-servers.net.").rrset(rrset(
            "a.root-servers.net.",
            3600,
            vec![a(ROOT)],
        )),
        "com.",
        "ns.nic.com.",
        Some(COM),
        None,
    )
    .build()
    .unwrap();
    let com = delegation(
        builder("com.", "ns.nic.com.").rrset(rrset("ns.nic.com.", 3600, vec![a(COM)])),
        "example.com.",
        "ns1.example.com.",
        Some(EXAMPLE),
        None,
    )
    .build()
    .unwrap();
    // The child holds no address for its own name server, so only the
    // parent's glue gives one: the name is absent (NXDOMAIN), or holds
    // only a TXT record (NODATA for A).
    for (rcode, own) in [
        (ResponseCode::NXDomain, None),
        (
            ResponseCode::NoError,
            Some(rrset(
                "ns1.example.com.",
                300,
                vec![RData::TXT(TXT::new(vec!["x".to_string()]))],
            )),
        ),
    ] {
        let mut example = builder("example.com.", "ns1.example.com.")
            .rrset(rrset("www.example.com.", 300, vec![a("192.0.2.80")]))
            .rrset(rrset("mail.example.com.", 300, vec![a("192.0.2.81")]));
        if let Some(own) = own {
            example = example.rrset(own);
        }
        let mut net = MemoryNet::new();
        serve_at(&mut net, ROOT, vec![root.clone()]);
        serve_at(&mut net, COM, vec![com.clone()]);
        serve_at(&mut net, EXAMPLE, vec![example.build().unwrap()]);
        let mut resolver = resolver(config(None));
        let reply = ask(
            &mut resolver,
            &mut net,
            0,
            query(client(1), "www.example.com.", RecordType::A, |_| {}),
        );
        assert_eq!(addresses(&reply), ["192.0.2.80"]);
        let reply = ask(
            &mut resolver,
            &mut net,
            1,
            query(client(1), "ns1.example.com.", RecordType::A, |_| {}),
        );
        assert_eq!(reply.metadata.response_code, rcode);
        assert!(reply.answers.is_empty(), "{rcode}");
        let reply = ask(
            &mut resolver,
            &mut net,
            2,
            query(client(2), "mail.example.com.", RecordType::A, |_| {}),
        );
        assert_eq!(
            addresses(&reply),
            ["192.0.2.81"],
            "{rcode}: {:?}",
            edes(&reply)
        );
    }
}

/// A validation the work bound cut short says how far one question's
/// budget went, so its result is not cached for other clients
/// (RFC 9520 §3.2): another client with the same budget and a warm cache
/// gets the Secure answer at once.
#[test]
fn a_validation_the_work_bound_cut_short_is_not_cached_for_other_clients() {
    let (mut net, anchors) = internet(true);
    let mut resolver = resolver(Config {
        work: Work {
            queries: 6,
            depth: 11,
        },
        ..config(anchors)
    });
    let first = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(first.metadata.response_code, ResponseCode::ServFail);
    let second = ask(
        &mut resolver,
        &mut net,
        1,
        query(client(2), "www.example.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(addresses(&second), ["192.0.2.80"], "{:?}", edes(&second));
    assert!(second.metadata.authentic_data);
}

/// Stale data answers for an alias too: once the CNAME at the name has
/// expired and its servers stop answering, the expired CNAME and its
/// target are served (RFC 8767 §4).
#[test]
fn an_expired_alias_and_its_target_answer_when_resolution_fails() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(stale_config(Duration::from_millis(376)));
    let fresh = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "alias.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&fresh), ["192.0.2.80"]);
    lose_example(&mut net);
    let reply = ask(
        &mut resolver,
        &mut net,
        700,
        query(client(1), "alias.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        rows(&reply.answers),
        [
            ("alias.example.com.".to_string(), RecordType::CNAME),
            ("www.example.com.".to_string(), RecordType::A),
        ]
    );
    assert!(reply.answers.iter().all(|record| record.ttl == 30));
    assert_eq!(edes(&reply), [EdeCode::STALE_ANSWER]);
}

/// The aliases an answer follows and the lookups for a name server's
/// address nest apart, as Unbound counts CNAME restarts apart from target
/// fetches: after the 11 aliases the preset allows, a zone whose server
/// came without glue still resolves.
#[test]
fn aliases_and_glueless_lookups_count_against_the_depth_apart() {
    const ALPHA: &str = "192.0.2.101";
    const BETA: &str = "192.0.2.102";
    const GAMMA: &str = "192.0.2.103";
    const DELTA: &str = "192.0.2.104";
    let mut root = builder(".", "a.root-servers.net.").rrset(rrset(
        "a.root-servers.net.",
        3600,
        vec![a(ROOT)],
    ));
    root = delegation(root, "alpha.", "ns.alpha.", Some(ALPHA), None);
    root = delegation(root, "beta.", "host.ns.gamma.", None, None);
    root = delegation(root, "gamma.", "ns.gamma.", Some(GAMMA), None);
    root = delegation(root, "delta.", "ns.delta.", Some(DELTA), None);
    let mut alpha = builder("alpha.", "ns.alpha.").rrset(rrset("ns.alpha.", 3600, vec![a(ALPHA)]));
    for (prefix, end) in [("c", "www.beta."), ("d", "www.delta.")] {
        for n in 0..11 {
            let target = if n == 10 {
                end.to_string()
            } else {
                format!("{prefix}{}.alpha.", n + 1)
            };
            alpha = alpha.rrset(rrset(
                &format!("{prefix}{n}.alpha."),
                300,
                vec![RData::CNAME(CNAME(name(&target)))],
            ));
        }
    }
    let beta = builder("beta.", "host.ns.gamma.")
        .rrset(rrset("www.beta.", 300, vec![a("192.0.2.200")]))
        .build()
        .unwrap();
    let gamma = builder("gamma.", "ns.gamma.")
        .rrset(rrset("ns.gamma.", 3600, vec![a(GAMMA)]))
        .rrset(rrset("host.ns.gamma.", 3600, vec![a(BETA)]))
        .build()
        .unwrap();
    let delta = builder("delta.", "ns.delta.")
        .rrset(rrset("ns.delta.", 3600, vec![a(DELTA)]))
        .rrset(rrset("www.delta.", 300, vec![a("192.0.2.201")]))
        .build()
        .unwrap();
    let mut net = MemoryNet::new();
    serve_at(&mut net, ROOT, vec![root.build().unwrap()]);
    serve_at(&mut net, ALPHA, vec![alpha.build().unwrap()]);
    serve_at(&mut net, BETA, vec![beta]);
    serve_at(&mut net, GAMMA, vec![gamma]);
    serve_at(&mut net, DELTA, vec![delta]);
    for (qname, address) in [("d0.alpha.", "192.0.2.201"), ("c0.alpha.", "192.0.2.200")] {
        let mut resolver = resolver(config(None));
        let reply = ask(
            &mut resolver,
            &mut net,
            0,
            query(client(1), qname, RecordType::A, |_| {}),
        );
        assert_eq!(addresses(&reply), [address], "{qname}: {:?}", edes(&reply));
    }
}

/// A Secure negative answer lasts no longer than the RRSIGs of its SOA
/// and NSEC records, cached and as the source of synthesized answers
/// (RFC 4035 §5.3.3, RFC 8198 §5.4): past them it is fetched and
/// validated again, as a positive answer is.
#[test]
fn a_secure_negative_lives_no_longer_than_its_signatures() {
    let (mut net, anchors) = internet(true);
    // The signatures expire 60 seconds after the run starts.
    let mut resolver = Resolver::new(
        config(anchors),
        Ring,
        WallClock {
            start: date(1_800_000_000 - 60),
        },
    );
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "nx.example.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert!(reply.metadata.authentic_data);
    for (seconds, qname) in [(120, "nx.example.com."), (121, "nz.example.com.")] {
        let before = asked(&net).len();
        let reply = ask(
            &mut resolver,
            &mut net,
            seconds,
            query(client(1), qname, RecordType::A, dnssec_ok),
        );
        assert!(asked(&net).len() > before, "{qname}: asked again");
        assert!(!reply.metadata.authentic_data, "{qname}: {reply:?}");
        assert_eq!(edes(&reply), [EdeCode::SIGNATURE_EXPIRED], "{qname}");
    }
}

/// A signed root and `com`, `com` holding `*.wild.com` and
/// `host.wild.com`, so `wild.com` is an empty non-terminal, and
/// `d.com DNAME secure.com.`, where `secure.com` is a signed child.
fn wild_tree(denial: Denial) -> (MemoryNet, Anchors) {
    const SECURE: &str = "192.0.2.70";
    let root_keys = keys(10);
    let com_keys = keys(20);
    let secure_keys = keys(40);
    let root = delegation(
        builder(".", "a.root-servers.net.").rrset(rrset(
            "a.root-servers.net.",
            3600,
            vec![a(ROOT)],
        )),
        "com.",
        "ns.nic.com.",
        Some(COM),
        Some(ds(&com_keys, "com.")),
    )
    .build()
    .unwrap()
    .signed(&root_keys, window(), Denial::Nsec)
    .unwrap();
    let com = delegation(
        builder("com.", "ns.nic.com.")
            .rrset(rrset("ns.nic.com.", 3600, vec![a(COM)]))
            .rrset(rrset("*.wild.com.", 300, vec![a("192.0.2.7")]))
            .rrset(rrset("host.wild.com.", 300, vec![a("192.0.2.8")]))
            .rrset(rrset("d.com.", 300, vec![dname(&name("secure.com."))])),
        "secure.com.",
        "ns.secure.com.",
        Some(SECURE),
        Some(ds(&secure_keys, "secure.com.")),
    )
    .build()
    .unwrap()
    .signed(&com_keys, window(), denial)
    .unwrap();
    let secure = builder("secure.com.", "ns.secure.com.")
        .rrset(rrset("ns.secure.com.", 3600, vec![a(SECURE)]))
        .rrset(rrset("www.secure.com.", 300, vec![a("192.0.2.71")]))
        .build()
        .unwrap()
        .signed(&secure_keys, window(), Denial::Nsec)
        .unwrap();
    let mut net = MemoryNet::new();
    serve_at(&mut net, ROOT, vec![root]);
    serve_at(&mut net, COM, vec![com]);
    serve_at(&mut net, SECURE, vec![secure]);
    (net, Anchors::of(vec![root_keys.anchor(&Name::root())]))
}

fn denials() -> [Denial; 2] {
    [
        Denial::Nsec,
        Denial::Nsec3 {
            opt_out: false,
            salt: Vec::new(),
        },
    ]
}

/// NODATA at an empty non-terminal is proven by the NSEC whose next name
/// lies below it, a wildcard child among them (RFC 4035 §5.4,
/// RFC 4592 §2.2.2).
#[test]
fn nodata_at_an_empty_non_terminal_above_a_wildcard_validates() {
    for denial in denials() {
        let (mut net, anchors) = wild_tree(denial.clone());
        let mut resolver = resolver(config(Some(anchors)));
        let reply = ask(
            &mut resolver,
            &mut net,
            0,
            query(client(1), "wild.com.", RecordType::A, dnssec_ok),
        );
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NoError,
            "{denial:?}: {:?}",
            edes(&reply)
        );
        assert!(reply.answers.is_empty(), "{denial:?}");
        assert!(reply.metadata.authentic_data, "{denial:?}");
    }
}

/// The DNAME's signature vouches for the CNAME synthesized from it,
/// for a name below it that starts with a literal `*` label too
/// (RFC 6672 §5.3.3).
#[test]
fn a_dname_vouches_for_a_name_that_starts_with_a_star() {
    for (qname, rcode) in [
        ("www.d.com.", ResponseCode::NoError),
        ("*.d.com.", ResponseCode::NXDomain),
        ("*.a.d.com.", ResponseCode::NXDomain),
    ] {
        let (mut net, anchors) = wild_tree(Denial::Nsec);
        let mut resolver = resolver(config(Some(anchors)));
        let reply = ask(
            &mut resolver,
            &mut net,
            0,
            query(client(1), qname, RecordType::A, dnssec_ok),
        );
        assert_eq!(
            reply.metadata.response_code,
            rcode,
            "{qname}: {:?}",
            edes(&reply)
        );
        assert!(reply.metadata.authentic_data, "{qname}");
    }
}

/// The root, `com` with `example.com`'s glue at `glue_ttl`, and
/// `example.com`, whose own address record for its name server has
/// `child_ttl`. The NS RRsets live an hour.
fn short_address_tree(glue_ttl: u32, child_ttl: u32) -> MemoryNet {
    let zone = |text: &str| Zone::from_master(text, None).unwrap();
    let root = zone(
        ". 86400 IN SOA a.root-servers.net. h.root. 1 7200 3600 1209600 300\n\
         . 518400 IN NS a.root-servers.net.\n\
         a.root-servers.net. 518400 IN A 198.41.0.4\n\
         com. 172800 IN NS ns.nic.com.\n\
         ns.nic.com. 172800 IN A 192.0.2.10\n",
    );
    let com = zone(&format!(
        "com. 3600 IN SOA ns.nic.com. h.com. 1 7200 3600 1209600 300\n\
         com. 3600 IN NS ns.nic.com.\n\
         ns.nic.com. 3600 IN A 192.0.2.10\n\
         example.com. 3600 IN NS ns1.example.com.\n\
         ns1.example.com. {glue_ttl} IN A 192.0.2.20\n"
    ));
    let example = zone(&format!(
        "example.com. 3600 IN SOA ns1.example.com. h.example.com. 1 7200 3600 1209600 300\n\
         example.com. 3600 IN NS ns1.example.com.\n\
         ns1.example.com. {child_ttl} IN A 192.0.2.20\n\
         www.example.com. 300 IN A 192.0.2.80\n\
         other.example.com. 300 IN A 192.0.2.81\n"
    ));
    let mut net = MemoryNet::new();
    serve_at(&mut net, ROOT, vec![root]);
    serve_at(&mut net, COM, vec![com]);
    serve_at(&mut net, EXAMPLE, vec![example]);
    net
}

/// A zone cut whose NS RRset is live but whose name servers, all inside
/// it, have no address left is of no use: the resolver asks the parent
/// again for a referral with glue rather than failing on the cycle of
/// looking up a name server's address through itself (RFC 1034 §5.3.3).
/// The glue can run out first, or the child's own shorter address record
/// can replace the glue and run out.
#[test]
fn a_cut_whose_name_server_addresses_ran_out_is_asked_of_the_parent() {
    let mut net = short_address_tree(60, 3600);
    let mut r = resolver(config(None));
    let reply = ask(
        &mut r,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&reply), ["192.0.2.80"]);
    let reply = ask(
        &mut r,
        &mut net,
        100,
        query(client(2), "other.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&reply), ["192.0.2.81"], "{:?}", edes(&reply));

    let mut net = short_address_tree(3600, 60);
    let mut r = resolver(config(None));
    let reply = ask(
        &mut r,
        &mut net,
        0,
        query(client(1), "ns1.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&reply), ["192.0.2.20"]);
    let reply = ask(
        &mut r,
        &mut net,
        100,
        query(client(2), "www.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&reply), ["192.0.2.80"], "{:?}", edes(&reply));
    // The second answer came by way of `com`.
    assert!(
        asked(&net)
            .iter()
            .filter(|(server, ..)| *server == ip(COM))
            .count()
            >= 2
    );
}

/// `example.com` as it first is, without `x`, and as it is after `flip`,
/// with `x` at `x_ttl` and `alias` pointing to it.
struct Flipping {
    before: Zones,
    after: Zones,
    flipped: Arc<std::sync::atomic::AtomicBool>,
}

impl Flipping {
    fn new(x_ttl: u32) -> Flipping {
        let zone = |text: &str| {
            let zone = Zone::from_master(text, None).unwrap();
            Zones::new(vec![Arc::new(zone) as Arc<dyn ZoneData>])
        };
        let head = "example.com. 3600 IN NS ns1.example.com.\n\
                    ns1.example.com. 3600 IN A 192.0.2.20\n";
        Flipping {
            before: zone(&format!(
                "example.com. 3600 IN SOA ns1.example.com. h.example.com. 1 7200 3600 1209600 300\n\
                 {head}"
            )),
            after: zone(&format!(
                "example.com. 3600 IN SOA ns1.example.com. h.example.com. 2 7200 3600 1209600 300\n\
                 {head}\
                 x.example.com. {x_ttl} IN A 192.0.2.88\n\
                 alias.example.com. 300 IN CNAME x.example.com.\n"
            )),
            flipped: Arc::default(),
        }
    }
}

impl Authority for Flipping {
    fn respond(
        &self,
        req: &Request,
        local: SocketAddr,
        server: &ServerConfig,
        client: &Client,
    ) -> Step {
        if self.flipped.load(std::sync::atomic::Ordering::SeqCst) {
            self.after.respond(req, local, server, client)
        } else {
            self.before.respond(req, local, server, client)
        }
    }
}

/// `x.example.com` does not exist, then does, with `alias` pointing to
/// it. The reply that answers `alias` carries x's address, and that is
/// the answer, though the NXDOMAIN for x is still cached: the data a
/// reply carries serves the question it came for (RFC 1035 §7.4), even
/// when the cache does not keep it (TTL 0, here from the authority), and
/// a forwarder's later data takes the place of the forwarder's earlier
/// negative, which ranks no higher (RFC 2181 §5.4.1).
#[test]
fn a_chain_answers_with_the_data_its_reply_carried_over_a_cached_negative() {
    let forwarder = Config::dnsmasq(vec![SocketAddr::new(ip(EXAMPLE), 53)]);
    for (config, x_ttl) in [(config(None), 0), (forwarder, 300)] {
        let example = Flipping::new(x_ttl);
        let flipped = example.flipped.clone();
        let mut net = short_address_tree(3600, 3600);
        net.serve(
            ip(EXAMPLE),
            AuthorityEngine::new(
                example,
                ServerConfig::generic(),
                SocketAddr::new(ip(EXAMPLE), 53),
            ),
        );
        let mut r = resolver(config);
        let reply = ask(
            &mut r,
            &mut net,
            0,
            query(client(1), "x.example.com.", RecordType::A, |_| {}),
        );
        assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
        flipped.store(true, std::sync::atomic::Ordering::SeqCst);
        let reply = ask(
            &mut r,
            &mut net,
            10,
            query(client(2), "alias.example.com.", RecordType::A, |_| {}),
        );
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NoError,
            "{x_ttl}"
        );
        assert_eq!(addresses(&reply), ["192.0.2.88"], "{x_ttl}");
    }
}

/// Zones whose server lets `change` touch every reply.
struct Changing<F>(Zones, F);

impl<F: Fn(&Request, &mut Message) + Send + Sync + 'static> Authority for Changing<F> {
    fn respond(
        &self,
        req: &Request,
        local: SocketAddr,
        server: &ServerConfig,
        client: &Client,
    ) -> Step {
        match self.0.respond(req, local, server, client) {
            Step::Reply(mut response) => {
                (self.1)(req, &mut response.message);
                Step::Reply(response)
            }
            step => step,
        }
    }
}

/// [`internet`] signed, with `example.com` holding `www` and a wildcard
/// at `*.wild`, signed with the keys its DS names, and served by servers
/// that let `change` touch every reply.
fn changed_example(
    change: impl Fn(&Request, &mut Message) + Send + Sync + Clone + 'static,
) -> (MemoryNet, Option<Anchors>) {
    let (mut net, anchors) = internet(true);
    let zone = builder("example.com.", "ns1.example.com.")
        .rrset(rrset(
            "ns1.example.com.",
            3600,
            vec![a(EXAMPLE), a(EXAMPLE_TOO)],
        ))
        .rrset(rrset("www.example.com.", 300, vec![a("192.0.2.80")]))
        .rrset(rrset("*.wild.example.com.", 300, vec![a("192.0.2.77")]))
        .build()
        .unwrap()
        .signed(&keys(40), window(), Denial::Nsec)
        .unwrap();
    for address in [EXAMPLE, EXAMPLE_TOO] {
        let zones = Zones::new(vec![Arc::new(zone.clone()) as Arc<dyn ZoneData>]);
        let local = SocketAddr::new(ip(address), 53);
        net.serve(
            ip(address),
            AuthorityEngine::new(
                Changing(zones, change.clone()),
                ServerConfig::generic(),
                local,
            ),
        );
    }
    (net, anchors)
}

/// A Secure RRset lasts as long as the RRSIG that proved it allows
/// (RFC 4035 §5.3.3). An expired RRSIG beside it, as a re-signing can
/// leave behind, proved nothing and bounds nothing.
#[test]
fn an_expired_rrsig_beside_a_valid_one_leaves_a_secure_answers_ttl_alone() {
    let www = rrset("www.example.com.", 300, vec![a("192.0.2.80")]);
    let zsk = keys(40).keys[1].clone();
    let old = Window {
        inception: date(1_600_000_000),
        expiration: date(1_700_000_000),
    };
    let stale = sign(zsk.as_ref(), &www, &name("example.com."), old).unwrap();
    let (mut net, anchors) = changed_example(move |req, message| {
        if req.question.name() == &name("www.example.com.")
            && req.question.query_type() == RecordType::A
            && !message.answers.is_empty()
        {
            message.add_answer(stale.clone());
        }
    });
    let mut resolver = resolver(config(anchors));
    for (seconds, ttl) in [(0, 300), (100, 200)] {
        let reply = ask(
            &mut resolver,
            &mut net,
            seconds,
            query(client(1), "www.example.com.", RecordType::A, dnssec_ok),
        );
        assert!(reply.metadata.authentic_data);
        let a = reply
            .answers
            .iter()
            .find(|record| record.record_type() == RecordType::A)
            .unwrap();
        assert_eq!(a.ttl, ttl, "at {seconds} s");
    }
}

/// An RRSIG inside its validity window whose signature does not verify
/// proved nothing either: neither its small Original TTL nor its small
/// own TTL shortens the Secure RRset beside it, fresh or from the cache
/// (RFC 4035 §5.3.3), whether it comes before the RRset or after it.
#[test]
fn a_current_rrsig_that_does_not_verify_leaves_a_secure_answers_ttl_alone() {
    // Made by the zone's own key over other records, so it names that key
    // and its window is current, but it does not verify over www's A
    // RRset. Its Original TTL and its own TTL are both 60.
    let other = rrset("www.example.com.", 60, vec![a("192.0.2.81")]);
    let zsk = keys(40).keys[1].clone();
    let mut bad = sign(zsk.as_ref(), &other, &name("example.com."), window()).unwrap();
    bad.ttl = 60;
    for first in [false, true] {
        let bad = bad.clone();
        let (mut net, anchors) = changed_example(move |req, message| {
            if req.question.name() == &name("www.example.com.")
                && req.question.query_type() == RecordType::A
                && !message.answers.is_empty()
            {
                if first {
                    message.answers.insert(0, bad.clone());
                } else {
                    message.add_answer(bad.clone());
                }
            }
        });
        let mut resolver = resolver(config(anchors));
        for (seconds, ttl) in [(0, 300), (100, 200)] {
            let reply = ask(
                &mut resolver,
                &mut net,
                seconds,
                query(client(1), "www.example.com.", RecordType::A, dnssec_ok),
            );
            assert!(reply.metadata.authentic_data, "first: {first}");
            let a = reply
                .answers
                .iter()
                .find(|record| record.record_type() == RecordType::A)
                .unwrap();
            assert_eq!(a.ttl, ttl, "first: {first}, at {seconds} s");
        }
    }
}

/// The RRSIG that proved a Secure RRset bounds it by its own TTL too: a
/// server that sends it with a TTL below the RRset's has the RRset go out
/// with the RRSIG's, fresh and from the cache (RFC 4035 §5.3.3).
#[test]
fn the_verifying_rrsigs_own_ttl_bounds_a_secure_answer() {
    let (mut net, anchors) = changed_example(|req, message| {
        if req.question.name() != &name("www.example.com.")
            || req.question.query_type() != RecordType::A
        {
            return;
        }
        for record in &mut message.answers {
            if record.record_type() == RecordType::RRSIG {
                record.ttl = 60;
            }
        }
    });
    let mut resolver = resolver(config(anchors));
    for (seconds, ttl) in [(0, 60), (30, 30)] {
        let reply = ask(
            &mut resolver,
            &mut net,
            seconds,
            query(client(1), "www.example.com.", RecordType::A, dnssec_ok),
        );
        assert!(reply.metadata.authentic_data);
        let a = reply
            .answers
            .iter()
            .find(|record| record.record_type() == RecordType::A)
            .unwrap();
        assert_eq!(a.ttl, ttl, "at {seconds} s");
    }
}

/// A wildcard answer carries the NSEC records that prove no closer name
/// matched (RFC 4035 §3.1.3.3), and only those: an NSEC RRset beside them
/// that proves nothing for it, here one that does not verify, never
/// reaches the client, so AD stands only on authentic data
/// (RFC 4035 §3.2.3).
#[test]
fn a_wildcard_answer_carries_only_its_own_proof() {
    let (mut net, anchors) = changed_example(|req, message| {
        if req.question.name() != &name("x.wild.example.com.") {
            return;
        }
        // A made-up NSEC, carrying the RRSIG of the genuine one.
        let Some(mut rrsig) = message
            .authorities
            .iter()
            .find(|record| record.record_type() == RecordType::RRSIG)
            .cloned()
        else {
            return;
        };
        let owner = name("forged.example.com.");
        let nsec = NSEC::new_cover_self(name("zzz.example.com."), [RecordType::A]);
        message.add_authority(Record::from_rdata(
            owner.clone(),
            900,
            RData::DNSSEC(DNSSECRData::NSEC(nsec)),
        ));
        rrsig.name = owner;
        message.add_authority(rrsig);
    });
    let mut resolver = resolver(config(anchors));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "x.wild.example.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.metadata.authentic_data);
    assert_eq!(addresses(&reply), vec!["192.0.2.77"]);
    let nsec: Vec<String> = reply
        .authorities
        .iter()
        .filter(|record| record.record_type() == RecordType::NSEC)
        .map(|record| record.name.to_string())
        .collect();
    assert_eq!(nsec, ["*.wild.example.com."]);
}

/// A wildcard answer whose proof does not verify is Bogus: the proof goes
/// out with it, and AD may stand only when every RRset there is
/// authentic (RFC 4035 §3.2.3).
#[test]
fn a_wildcard_answer_whose_proof_does_not_verify_is_bogus() {
    let (mut net, anchors) = changed_example(|req, message| {
        if req.question.name() != &name("x.wild.example.com.") {
            return;
        }
        // The covering NSEC lists one type more than its RRSIG signed.
        for record in &mut message.authorities {
            if let RData::DNSSEC(DNSSECRData::NSEC(nsec)) = &record.data {
                let changed = NSEC::new(
                    nsec.next_domain_name().clone(),
                    [
                        RecordType::A,
                        RecordType::TXT,
                        RecordType::RRSIG,
                        RecordType::NSEC,
                    ],
                );
                record.data = RData::DNSSEC(DNSSECRData::NSEC(changed));
            }
        }
    });
    let mut resolver = resolver(config(anchors));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "x.wild.example.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(edes(&reply), [EdeCode::DNSSEC_BOGUS]);
}

/// Whether a record of `records` comes twice.
fn repeats(records: &[Record]) -> bool {
    records
        .iter()
        .enumerate()
        .any(|(index, record)| records[..index].contains(record))
}

/// [`internet`] signed, with `example.com` built by `zone` from its apex
/// NS RRset and name server address, signed with NSEC by the keys its DS
/// names, at both of its servers.
fn signed_example(zone: impl FnOnce(ZoneBuilder) -> ZoneBuilder) -> (MemoryNet, Option<Anchors>) {
    let (mut net, anchors) = internet(true);
    let zone = zone(builder("example.com.", "ns1.example.com.").rrset(rrset(
        "ns1.example.com.",
        3600,
        vec![a(EXAMPLE), a(EXAMPLE_TOO)],
    )))
    .build()
    .unwrap()
    .signed(&keys(40), window(), Denial::Nsec)
    .unwrap();
    serve_at(&mut net, EXAMPLE, vec![zone.clone()]);
    serve_at(&mut net, EXAMPLE_TOO, vec![zone]);
    (net, anchors)
}

/// A CNAME that is no wildcard's answer brings no NSEC records of its
/// own: those of the reply are the proof of the negative its chain ends
/// in, which goes out once (RFC 4035 §3.1.3, RFC 2181 §5). So the reply
/// keeps the size the server's had, with its SOA, and the CNAME answers
/// a later question from the cache without them.
#[test]
fn a_chain_into_a_negative_carries_its_proof_once() {
    let (mut net, anchors) = internet(true);
    let mut r = resolver(config(anchors));
    let reply = ask(
        &mut r,
        &mut net,
        0,
        query(client(1), "alias.example.com.", RecordType::AAAA, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.metadata.authentic_data);
    assert!(!repeats(&reply.authorities), "{:?}", reply.authorities);
    let authority = rows(&reply.authorities);
    assert!(authority.contains(&("www.example.com.".to_string(), RecordType::NSEC)));
    assert!(authority.contains(&("example.com.".to_string(), RecordType::SOA)));

    let (mut net, anchors) = signed_example(|zone| {
        zone.rrset(rrset(
            "gone.example.com.",
            300,
            vec![RData::CNAME(CNAME(name("nothere.example.com.")))],
        ))
    });
    let mut r = resolver(config(anchors));
    let reply = ask(
        &mut r,
        &mut net,
        0,
        query(client(1), "gone.example.com.", RecordType::A, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert!(!reply.metadata.truncation);
    assert!(!repeats(&reply.authorities), "{:?}", reply.authorities);
    let authority = rows(&reply.authorities);
    assert!(authority.contains(&("example.com.".to_string(), RecordType::SOA)));

    let reply = ask(
        &mut r,
        &mut net,
        1,
        query(client(1), "gone.example.com.", RecordType::CNAME, dnssec_ok),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(rows(&reply.answers)[0].1, RecordType::CNAME);
    assert!(
        !reply
            .authorities
            .iter()
            .any(|record| record.record_type() == RecordType::NSEC),
        "{:?}",
        reply.authorities
    );
}

/// A chain that passes one DNAME twice sends that DNAME once
/// (RFC 2181 §5), as the authority's reply did.
#[test]
fn a_dname_the_chain_passes_twice_goes_out_once() {
    let mut net = delegated(
        |zone| {
            zone.rrset(rrset(
                "p.example.com.",
                300,
                vec![dname(&name("q.example.com."))],
            ))
            .rrset(rrset(
                "x.q.example.com.",
                300,
                vec![RData::CNAME(CNAME(name("y.p.example.com.")))],
            ))
            .rrset(rrset("y.q.example.com.", 300, vec![a("192.0.2.77")]))
        },
        3600,
        3600,
    );
    let mut r = resolver(config(None));
    let reply = ask(
        &mut r,
        &mut net,
        0,
        query(client(1), "x.p.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(addresses(&reply), vec!["192.0.2.77"]);
    let dnames = reply
        .answers
        .iter()
        .filter(|record| record.record_type() == RecordType::DNAME)
        .count();
    assert_eq!(dnames, 1, "{:?}", reply.answers);
}

/// Data cached before it validated, here for a client that set CD, lives
/// as long as its TTL once it validates Secure: the RRSIG's TTL counts
/// from when the RRset arrived, not from when the cache gave it out with
/// its TTL counted down (RFC 4035 §5.3.3, RFC 1035 §7.4).
#[test]
fn data_validated_from_the_cache_lives_out_its_ttl() {
    let (mut net, anchors) = internet(true);
    let mut r = resolver(config(anchors));
    let of_example = |net: &MemoryNet| {
        asked(net)
            .into_iter()
            .filter(|(server, qname, qtype, _)| {
                (*server == ip(EXAMPLE) || *server == ip(EXAMPLE_TOO))
                    && qname == "www.example.com."
                    && *qtype == RecordType::A
            })
            .count()
    };
    ask(
        &mut r,
        &mut net,
        0,
        query(client(1), "www.example.com.", RecordType::A, |m| {
            dnssec_ok(m);
            m.metadata.checking_disabled = true;
        }),
    );
    assert_eq!(of_example(&net), 1);
    let a_ttl = |reply: &Message| {
        reply
            .answers
            .iter()
            .find(|record| record.record_type() == RecordType::A)
            .map(|record| record.ttl)
    };
    let reply = ask(
        &mut r,
        &mut net,
        200,
        query(client(1), "www.example.com.", RecordType::A, dnssec_ok),
    );
    assert!(reply.metadata.authentic_data);
    assert_eq!(a_ttl(&reply), Some(100));
    let key = Key::new(
        LowerName::new(&name("www.example.com.")),
        RecordType::A,
        fictionet::stdlib::protocols::dns::rr::DNSClass::IN,
    );
    assert!(r.cache().get(&key, at(200)).is_some());
    let reply = ask(
        &mut r,
        &mut net,
        201,
        query(client(1), "www.example.com.", RecordType::A, dnssec_ok),
    );
    assert!(reply.metadata.authentic_data);
    assert_eq!(a_ttl(&reply), Some(99));
    assert_eq!(of_example(&net), 1, "no new query upstream");
}

/// A plain answer is Secure without the NSEC records beside it, so those
/// never go out with it: here an unsigned one, which would otherwise
/// reach the client under AD (RFC 4035 §3.2.3).
#[test]
fn an_nsec_beside_a_plain_answer_never_reaches_the_client() {
    let (mut net, anchors) = changed_example(|req, message| {
        if req.question.name() != &name("www.example.com.")
            || req.question.query_type() != RecordType::A
        {
            return;
        }
        let nsec = NSEC::new(
            name("zzz.example.com."),
            [RecordType::A, RecordType::RRSIG, RecordType::NSEC],
        );
        message.add_authority(Record::from_rdata(
            name("www.example.com."),
            300,
            RData::DNSSEC(DNSSECRData::NSEC(nsec)),
        ));
    });
    let mut r = resolver(config(anchors));
    for seconds in [0, 1] {
        let reply = ask(
            &mut r,
            &mut net,
            seconds,
            query(client(1), "www.example.com.", RecordType::A, dnssec_ok),
        );
        assert!(reply.metadata.authentic_data, "at {seconds} s");
        assert_eq!(addresses(&reply), vec!["192.0.2.80"]);
        assert!(
            !reply
                .authorities
                .iter()
                .any(|record| record.record_type() == RecordType::NSEC),
            "at {seconds} s: {:?}",
            reply.authorities
        );
    }
}
