//! The recursive resolver driven with no runtime, through a hierarchy of
//! authoritative engines in a `MemoryNet`: iteration, priming, QNAME
//! minimisation, TCP after truncation, broken and missing servers, the
//! work bound, the cache's rules, validation, local zones, departed
//! clients, and sessions.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use fictionet::stdlib::protocols::dns::dnssec::{
    Algorithm, AlgorithmPolicy, Anchors, DigestType, KeyFlags, KeySet, Ring, Sign, Validation,
    Window, ZoneKey,
};
use fictionet::stdlib::protocols::dns::op::{
    Edns, Message, MessageType, OpCode, Query, ResponseCode,
};
use fictionet::stdlib::protocols::dns::rr::rdata::{A, CNAME, NS, SOA, TXT};
use fictionet::stdlib::protocols::dns::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType,
};
use fictionet::stdlib::protocols::dns::{Ede, EdeCode, Request, Response};
use fictionet::stdlib::services::dns::authority::{
    Authority, AuthorityEngine, Known, ServerConfig, Step, Zones,
};
use fictionet::stdlib::services::dns::memory::{Exchanges, MemoryNet, drive};
use fictionet::stdlib::services::dns::resolver::{Config, Entry, FailureKind, Key, Resolver, Work};
use fictionet::stdlib::services::dns::zone::{Denial, Fact, Lazy, Transparent, Zone, ZoneData};
use fictionet::stdlib::services::dns::{
    Action, Answer, Client, ClientQuery, Engine, Event, Generation, Input, Session, Unmatched,
    WallClock,
};
use fictionet::stdlib::services::serve::Transport;
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};

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
///   (signed, with a DS for other keys), `odd.com` (a broken server), and
///   `a.com` and `b.com`, each served from a name in the other.
/// - `example.com` at 192.0.2.20 and 192.0.2.21.
/// - `org` at 192.0.2.12, delegating `example.org` (unsigned) and
///   `provider.org`.
///
/// When `signed`, the root, `com`, `org`, `example.com`, and `bad.com` are
/// signed, and the second value holds the root's anchor.
pub(super) fn internet(signed: bool) -> (MemoryNet, Option<Anchors>) {
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
        .build()
        .unwrap();
    let bad = sign(bad, &bad_keys);

    let mut net = MemoryNet::new();
    let mut serve = |address: &str, zone: Zone| {
        let local = SocketAddr::new(ip(address), 53);
        let zones = Zones::new(vec![Arc::new(zone) as Arc<dyn ZoneData>]);
        net.serve(
            ip(address),
            AuthorityEngine::new(zones, ServerConfig::generic(), local),
        );
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
        _known: &dyn Known,
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
        .map(|(ask, _)| {
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
    let (first, _) = &recording.exchanges()[0];
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
        query(client(1), "www.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(edes(&reply), [EdeCode::NO_REACHABLE_AUTHORITY]);
    assert!(reply.authorities.is_empty());

    let before = net.recording().exchanges().len();
    let reply = ask(
        &mut resolver,
        &mut net,
        2,
        query(client(2), "www.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(
        edes(&reply),
        [EdeCode::NO_REACHABLE_AUTHORITY, EdeCode::CACHED_ERROR]
    );
    assert!(reply.authorities.is_empty());
    assert_eq!(
        net.recording().exchanges().len(),
        before,
        "answered from the cache"
    );

    // The failure lasts `failure_ttl`, 5 seconds, and is then asked again.
    ask(
        &mut resolver,
        &mut net,
        30,
        query(client(3), "www.example.com.", RecordType::A, |_| {}),
    );
    assert!(net.recording().exchanges().len() > before);
}

#[test]
fn nothing_exists_below_a_cached_nxdomain() {
    let (mut net, _) = internet(false);
    let mut resolver = resolver(config(None));
    let reply = ask(
        &mut resolver,
        &mut net,
        0,
        query(client(1), "nx.example.com.", RecordType::A, |_| {}),
    );
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(reply.authorities[0].record_type(), RecordType::SOA);
    let before = net.recording().exchanges().len();
    let reply = ask(
        &mut resolver,
        &mut net,
        1,
        query(client(1), "deeper.nx.example.com.", RecordType::MX, |_| {}),
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
                Action::Abandon(_) | Action::Event(_) => {}
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
    let config = Config {
        ede: true,
        ..Config::gateway()
    };
    let mut resolver = resolver(config);
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
    let [(asked, _)] = recording.exchanges() else {
        panic!("one question to the forwarder");
    };
    assert_eq!(asked.server, SocketAddr::new(ip(EXAMPLE), 53));
    let message = Message::from_vec(&asked.query).unwrap();
    assert!(message.metadata.recursion_desired);
    assert_eq!(message.queries[0].name(), &name("x.y.example.com."));
    // dnsmasq does not validate: CD is clear upstream.
    assert!(!message.metadata.checking_disabled);
}

#[test]
fn google_answers_resolver_arpa_from_its_ddr_records_with_aa() {
    let (mut net, _) = internet(false);
    let identity = fictionet::stdlib::services::dns::authority::Identity::none();
    let mut resolver = resolver(Config {
        hints: vec![(name("a.root-servers.net."), ip(ROOT))],
        ..Config::google(identity)
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
