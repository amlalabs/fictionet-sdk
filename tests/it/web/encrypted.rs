//! DNS over TLS and DNS over HTTPS in front of a resolver program: each
//! front answers the question UDP asked, from the same cache, with the
//! TTL counted down by the time between them and the same validation.
//! The resolver iterates through a signed root and `example.` served by
//! authoritative programs on the network.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use fictionet::Cx;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::codec::base64;
use fictionet::stdlib::network::{ConnectionExt, tcp};
use fictionet::stdlib::protocols::dns::dnssec::{
    Algorithm, AlgorithmPolicy, Anchors, DigestType, KeyFlags, KeySet, Sign, Validation, Window,
    ZoneKey,
};
use fictionet::stdlib::protocols::dns::op::{Edns, Message, Query, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::rdata::{A, NS, SOA};
use fictionet::stdlib::protocols::dns::rr::{Name, RData, Record, RecordSet, RecordType};
use fictionet::stdlib::protocols::json::Value;
use fictionet::stdlib::protocols::x509::{Time, Validity};
use fictionet::stdlib::services::ca::Ca;
use fictionet::stdlib::services::dns::authority::{ServerConfig, Zones};
use fictionet::stdlib::services::dns::resolver::Config;
use fictionet::stdlib::services::dns::zone::{Denial, Node, Zone, ZoneData};
use fictionet::stdlib::services::dns::{Event, WallClock};
use fictionet::stdlib::services::serve::Transport;
use fictionet::stdlib::web::httpd::{self, Body, Exchange, Handler, Reply};
use fictionet::stdlib::world::net::dns::encrypted::Fronts;
use fictionet::stdlib::world::net::dns::{Authoritative, Recursive};
use fictionet::stdlib::world::net::{Host, Net};
use fictionet::{Seed, SeededEntropy};
use fictionet_extras::dns::doh;
use fictionet_extras::dns::public::PUBLIC_RESOLVERS;
use fictionet_extras::hyper_io::{Exec, Io};
use fictionet_test_support::certs;
use fictionet_test_support::sandbox::{Machine, TlsClient, client_config, machine};
use fictionet_test_support::timeout;
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use rustls::RootCertStore;

use fictionet_test_support::world::world;

const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const ROOT: Ipv4Addr = Ipv4Addr::new(198, 41, 0, 4);
const EXAMPLE: Ipv4Addr = Ipv4Addr::new(45, 33, 4, 53);
const WWW: Ipv4Addr = Ipv4Addr::new(45, 33, 4, 80);
const RESOLVER: Ipv4Addr = Ipv4Addr::new(45, 33, 9, 9);
/// The resolver's DNS over HTTPS name.
const DOH_NAME: &str = "dns.example";
/// The TTL of `www.example.`'s address.
const TTL: u32 = 300;
/// A date inside the signatures' window, the world's start.
const NOW: u64 = 1_750_000_000;

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

fn date(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

fn rrset(owner: &str, ttl: u32, data: RData) -> RecordSet {
    let owner = name(owner);
    let mut set = RecordSet::with_ttl(owner.clone(), data.record_type(), ttl);
    set.set_records(vec![Record::from_rdata(owner, ttl, data)]);
    set
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

fn window() -> Window {
    Window {
        inception: date(1_700_000_000),
        expiration: date(1_800_000_000),
    }
}

fn soa(mname: &str) -> SOA {
    SOA::new(
        name(mname),
        name("hostmaster.example."),
        1,
        7200,
        3600,
        1209600,
        900,
    )
}

/// Records at `kinds.example.` whose presentation hickory's own text gets
/// wrong, each as its type number and its RDATA in presentation format,
/// which is what the JSON API must give back. Names stay in ASCII, an
/// A-label as it is, with decimal escapes (RFC 1035 §5.1).
const KINDS: [(u16, &str); 9] = [
    (65, "1 . alpn=h2,h3 ipv4hint=45.33.4.80,45.33.4.53"),
    (64, "1 . mandatory=key9999 key9999=/q"),
    (13, "\"Intel Xeon\" \"\""),
    (257, "0 issue \"a\\\"b; c\""),
    (35, "1 1 \"s\" \"x\\\"y\" \"\" ."),
    (65280, "\\# 2 ABCD"),
    (15, "10 xn--bcher-kva.example."),
    (33, "0 0 80 sp\\032ace.example."),
    (12, "a\\.b.example."),
];

/// The RRset of type `number` at `kinds.example.` that a master file line
/// with RDATA `data` holds.
fn kind(number: u16, data: &str) -> RecordSet {
    let rtype = RecordType::from(number);
    let text = format!(
        "kinds.example. 300 IN SOA ns.kinds.example. h.kinds.example. 1 2 3 4 5\n\
         kinds.example. 300 IN NS ns.kinds.example.\n\
         kinds.example. 300 IN TYPE{number} {data}\n"
    );
    let zone = Zone::from_master(&text, None).unwrap_or_else(|e| panic!("{data}: {e}"));
    let Some(Node::Data(sets)) = zone.node(zone.apex()) else {
        panic!("the apex holds data");
    };
    sets[&rtype].clone()
}

/// The signed root, delegating a signed `example.` to `ns.example.`, and
/// the root's trust anchor.
fn hierarchy() -> (Zone, Zone, Anchors) {
    let root_keys = keys(10);
    let example_keys = keys(20);
    let ds = example_keys
        .ds(
            &name("example."),
            3600,
            DigestType::Sha256,
            &AlgorithmPolicy::iana(),
        )
        .unwrap();
    let root = Zone::builder(Name::root(), soa("a.root-servers.net."), 3600)
        .rrset(rrset(".", 3600, RData::NS(NS(name("a.root-servers.net.")))))
        .rrset(rrset("a.root-servers.net.", 3600, RData::A(A(ROOT))))
        .delegate(
            name("example."),
            rrset("example.", 3600, RData::NS(NS(name("ns.example.")))),
            vec![rrset("ns.example.", 3600, RData::A(A(EXAMPLE)))],
            Some(ds),
        )
        .build()
        .unwrap()
        .signed(&root_keys, window(), Denial::Nsec)
        .unwrap();
    let example = KINDS
        .iter()
        .fold(
            Zone::builder(name("example."), soa("ns.example."), 3600)
                .rrset(rrset("example.", 3600, RData::NS(NS(name("ns.example.")))))
                .rrset(rrset("ns.example.", 3600, RData::A(A(EXAMPLE))))
                .rrset(rrset("www.example.", TTL, RData::A(A(WWW)))),
            |zone, (number, data)| zone.rrset(kind(*number, data)),
        )
        .build()
        .unwrap()
        .signed(&example_keys, window(), Denial::Nsec)
        .unwrap();
    let anchors = Anchors::of(vec![root_keys.anchor(&Name::root())]);
    (root, example, anchors)
}

/// One reply the resolver sent, as its event reports it.
#[derive(Clone, Debug, PartialEq)]
struct Sent {
    transport: Transport,
    sandbox: Option<u64>,
    cached: bool,
    validation: Validation,
}

/// What the tests need of the world.
struct Env {
    roots: Arc<RootCertStore>,
    sent: Arc<Mutex<Vec<Sent>>>,
}

/// The hierarchy's authoritative servers, and its trust anchor.
fn authorities() -> (Vec<Host>, Anchors) {
    let (root, example, anchors) = hierarchy();
    let serve = |label: &str, at: Ipv4Addr, zone: Zone| {
        let zones = Zones::new(vec![Arc::new(zone) as Arc<dyn ZoneData>]);
        Host::new(label)
            .at(at)
            .program(Authoritative::new(zones, ServerConfig::generic()))
    };
    let hosts = vec![
        serve("a.root-servers.net", ROOT, root),
        serve("ns.example", EXAMPLE, example),
    ];
    (hosts, anchors)
}

/// A resolver validating from `anchors`, with one cache per sandbox,
/// whose replies are kept in `sent`.
fn recursive(anchors: Anchors, sent: &Arc<Mutex<Vec<Sent>>>) -> Recursive {
    let seen = sent.clone();
    let config = Config {
        anchors: Some(anchors),
        ..Config::new()
    }
    .hints(&[(name("a.root-servers.net."), IpAddr::V4(ROOT))]);
    Recursive::new(config, WallClock { start: date(NOW) })
        .per_sandbox()
        .on_event(move |event| {
            if let Event::Reply {
                client,
                cached,
                validation,
                ..
            } = event
            {
                seen.lock().unwrap().push(Sent {
                    transport: client.transport,
                    sandbox: client.sandbox.as_ref().map(|sandbox| sandbox.id),
                    cached: *cached,
                    validation: *validation,
                });
            }
        })
}

/// A fallback serving both JSON APIs, so each form of question answers
/// from the one cache.
struct BothJson(Fronts);

impl Handler for BothJson {
    fn call(&self, request: Request<Body>, ex: &mut Exchange<'_>) -> Reply {
        match request.uri().path() {
            "/resolve" => doh::resolve(&self.0, &request, ex),
            "/dns-query" if doh::asks_dns_json(&request) => doh::dns_json(&self.0, &request, ex),
            "/dns-query" => Reply::Now(httpd::text(StatusCode::BAD_REQUEST, "No query.\n")),
            _ => Reply::Now(httpd::text(StatusCode::NOT_FOUND, "Not found.\n")),
        }
    }
}

/// The world: the hierarchy's servers, and at `RESOLVER` a validating
/// resolver with one cache per sandbox and both encrypted fronts, whose
/// certificate the world's CA issued for `dns.example` and the address.
fn start(fcx: &Cx, attachments: fictionet::Attachments) -> fictionet::Result<Env> {
    let (hosts, anchors) = authorities();
    let (ca, leaf) = certs::issue(fcx, "World CA", &[DOH_NAME, &RESOLVER.to_string()])?;
    let tls = leaf.server_config(fcx, date(NOW))?;
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert_der())?;
    let sent: Arc<Mutex<Vec<Sent>>> = Arc::default();
    let resolver = recursive(anchors, &sent);
    let fronts = Fronts::new(resolver.handle(), move |_| tls.clone())
        .names([name("dns.example.")])
        .date(date(NOW));
    let fronts = fronts.clone().fallback(Arc::new(BothJson(fronts)));
    Net::new(fictionet_extras::network::cdn_pools())
        .ipv4_only()
        .hosts(hosts)
        .hosts([fronts.doh(fronts.dot(Host::new("resolver").at(RESOLVER).program(resolver)))])
        .start(fcx, attachments)?;
    Ok(Env {
        roots: Arc::new(roots),
        sent,
    })
}

/// A query for `name_text` of type `kind` with RD and AD set and an OPT
/// record, as a validating stub sends it.
fn query(id: u16, name_text: &str, kind: RecordType) -> Message {
    let mut query = Message::query();
    query.metadata.id = id;
    query.metadata.recursion_desired = true;
    query.metadata.authentic_data = true;
    query.add_query(Query::query(name(name_text), kind));
    query.set_edns(Edns::new());
    query
}

/// The addresses and TTLs of a reply's A answers.
fn answers(reply: &Message) -> Vec<(Ipv4Addr, u32)> {
    reply
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(a) => Some((a.0, record.ttl)),
            _ => None,
        })
        .collect()
}

fn at(addr: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::new(addr.into(), port)
}

/// What the resolver at `server` answers `query` over UDP.
async fn udp(fcx: &Cx, m: &Machine, server: Ipv4Addr, query: &Message) -> Message {
    let mut socket = m.udp.bind(0).unwrap();
    socket.send_to(&query.to_vec().unwrap(), at(server, 53));
    let (bytes, _) = timeout(fcx, Duration::from_secs(5), socket.recv(fcx))
        .await
        .expect("an answer over UDP")
        .unwrap();
    Message::from_vec(&bytes).unwrap()
}

/// A TLS connection to `to`, checked against `roots` for `server`, a name
/// or an address.
async fn tls(
    fcx: &Cx,
    m: &Machine,
    roots: &Arc<RootCertStore>,
    to: SocketAddr,
    server: &str,
    alpn: &[&[u8]],
) -> TlsClient<tcp::TcpConnection> {
    let config = client_config(fcx, date(NOW), Some(roots), alpn).unwrap();
    m.tls_with_config(fcx, to, server, config)
        .await
        .expect("a TLS connection")
}

/// Writes `message` after its two-octet length.
async fn send_framed(fcx: &Cx, conn: &mut TlsClient<tcp::TcpConnection>, message: &Message) {
    let bytes = message.to_vec().unwrap();
    let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&bytes);
    conn.write_all(fcx, &framed).await.unwrap();
}

/// Reads one message after its two-octet length.
async fn read_framed(fcx: &Cx, conn: &mut TlsClient<tcp::TcpConnection>) -> Message {
    let mut read = Vec::new();
    let mut buf = [0; 4096];
    loop {
        if read.len() >= 2 {
            let len = 2 + usize::from(u16::from_be_bytes([read[0], read[1]]));
            if read.len() >= len {
                return Message::from_vec(&read[2..len]).unwrap();
            }
        }
        let n = timeout(fcx, Duration::from_secs(5), conn.read(fcx, &mut buf))
            .await
            .expect("an answer over TLS")
            .unwrap();
        assert!(n > 0, "the connection closed before the answer");
        read.extend_from_slice(&buf[..n]);
    }
}

/// An HTTP response, read whole.
struct Got {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Got {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

/// Sends `request` over `conn` with HTTP/2 when `h2`, else HTTP/1.1.
async fn http(
    fcx: &Cx,
    conn: TlsClient<tcp::TcpConnection>,
    h2: bool,
    request: Request<Full<Bytes>>,
) -> Got {
    let io = Io {
        fcx: fcx.clone(),
        conn,
    };
    let response = if h2 {
        let (mut send, conn) = hyper::client::conn::http2::handshake(Exec(fcx.clone()), io)
            .await
            .unwrap();
        fcx.spawn(move |_| async move {
            let _ = conn.await;
            Ok(())
        });
        send.send_request(request).await.unwrap()
    } else {
        let (mut send, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        fcx.spawn(move |_| async move {
            let _ = conn.await;
            Ok(())
        });
        send.send_request(request).await.unwrap()
    };
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    Got {
        status,
        headers,
        body,
    }
}

/// A GET of `path` at `host`, with `headers`.
fn get(h2: bool, host: &str, path: &str, headers: &[(&str, &str)]) -> Request<Full<Bytes>> {
    let builder = if h2 {
        Request::get(format!("https://{host}{path}"))
    } else {
        Request::get(path).header("host", host)
    };
    headers
        .iter()
        .fold(builder, |builder, (name, value)| {
            builder.header(*name, *value)
        })
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// A request of `method` for `path` at `host` with `body` as `media`.
fn with_body(
    method: Method,
    h2: bool,
    host: &str,
    path: &str,
    media: &str,
    body: Vec<u8>,
) -> Request<Full<Bytes>> {
    let builder = if h2 {
        Request::builder().uri(format!("https://{host}{path}"))
    } else {
        Request::builder().uri(path).header("host", host)
    };
    builder
        .method(method)
        .header("content-type", media)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// `bytes` in base64url without padding (RFC 4648 §5), as a DoH GET
/// carries a query.
fn base64url(bytes: &[u8]) -> String {
    base64::encode(bytes)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

/// The JSON API's answer: its status, AD bit, and A data and TTLs.
fn json_answers(body: &[u8]) -> (u64, bool, Vec<(String, u64)>) {
    let value = Value::parse(body).unwrap();
    let status = value
        .get("Status")
        .and_then(Value::as_number)
        .unwrap()
        .as_f64() as u64;
    let ad = matches!(value.get("AD"), Some(Value::Bool(true)));
    let answers = match value.get("Answer") {
        Some(Value::Array(records)) => records
            .iter()
            .map(|record| {
                let data = record.get("data").and_then(Value::as_str).unwrap();
                let ttl = record
                    .get("TTL")
                    .and_then(Value::as_number)
                    .unwrap()
                    .as_f64() as u64;
                (data.to_owned(), ttl)
            })
            .collect(),
        _ => Vec::new(),
    };
    (status, ad, answers)
}

/// UDP fills the cache; DNS over TLS, DNS over HTTPS by POST over HTTP/2
/// to the name, by GET over HTTP/1.1 to the address with no name, and
/// both JSON forms then answer from it. Each answer is validated, carries
/// AD, and has the TTL counted down by the time since UDP asked.
#[test]
fn each_front_answers_from_the_cache_udp_filled() {
    world(Duration::from_secs(60), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let env = start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("agent")?, ME);
        let www = query(1, "www.example.", RecordType::A);

        let reply = udp(&fcx, &m, RESOLVER, &www).await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.metadata.authentic_data);
        assert_eq!(answers(&reply), vec![(WWW, TTL)]);

        fcx.sleep(Duration::from_secs(7)).await?;
        let mut conn = tls(&fcx, &m, &env.roots, at(RESOLVER, 853), DOH_NAME, &[b"dot"]).await;
        send_framed(&fcx, &mut conn, &query(2, "www.example.", RecordType::A)).await;
        let reply = read_framed(&fcx, &mut conn).await;
        assert_eq!(reply.metadata.id, 2);
        assert!(reply.metadata.authentic_data);
        assert_eq!(answers(&reply), vec![(WWW, TTL - 7)]);

        fcx.sleep(Duration::from_secs(5)).await?;
        let conn = tls(&fcx, &m, &env.roots, at(RESOLVER, 443), DOH_NAME, &[b"h2"]).await;
        // RFC 8484 §4.1 asks DoH clients for ID 0.
        let posted = query(0, "www.example.", RecordType::A);
        let got = http(
            &fcx,
            conn,
            true,
            with_body(
                Method::POST,
                true,
                DOH_NAME,
                "/dns-query",
                "application/dns-message",
                posted.to_vec().unwrap(),
            ),
        )
        .await;
        assert_eq!(got.status, StatusCode::OK);
        assert_eq!(got.header("content-type"), Some("application/dns-message"));
        let ttl = TTL - 12;
        assert_eq!(
            got.header("cache-control"),
            Some(format!("max-age={ttl}").as_str())
        );
        assert!(got.header("date").is_some());
        let reply = Message::from_vec(&got.body).unwrap();
        assert_eq!(reply.metadata.id, 0);
        assert!(reply.metadata.authentic_data);
        assert_eq!(answers(&reply), vec![(WWW, ttl)]);

        fcx.sleep(Duration::from_secs(3)).await?;
        let address = RESOLVER.to_string();
        let conn = tls(
            &fcx,
            &m,
            &env.roots,
            at(RESOLVER, 443),
            &address,
            &[b"http/1.1"],
        )
        .await;
        assert_eq!(conn.tls.alpn_protocol(), Some(&b"http/1.1"[..]));
        let wire = base64url(&query(3, "www.example.", RecordType::A).to_vec().unwrap());
        let path = format!("/dns-query?dns={wire}");
        let got = http(&fcx, conn, false, get(false, &address, &path, &[])).await;
        assert_eq!(got.status, StatusCode::OK);
        let reply = Message::from_vec(&got.body).unwrap();
        assert_eq!(reply.metadata.id, 3);
        assert!(reply.metadata.authentic_data);
        assert_eq!(answers(&reply), vec![(WWW, TTL - 15)]);

        fcx.sleep(Duration::from_secs(1)).await?;
        let conn = tls(&fcx, &m, &env.roots, at(RESOLVER, 443), DOH_NAME, &[b"h2"]).await;
        let got = http(
            &fcx,
            conn,
            true,
            get(true, DOH_NAME, "/resolve?name=www.example&type=a", &[]),
        )
        .await;
        assert_eq!(got.status, StatusCode::OK);
        assert_eq!(
            got.header("content-type"),
            Some("application/json; charset=UTF-8")
        );
        let ttl = u64::from(TTL - 16);
        assert_eq!(
            json_answers(&got.body),
            (0, true, vec![(WWW.to_string(), ttl)])
        );
        let value = Value::parse(&got.body).unwrap();
        let Some(Value::Array(question)) = value.get("Question") else {
            panic!("no question in {value:?}");
        };
        assert_eq!(
            question[0].get("name").and_then(Value::as_str),
            Some("www.example.")
        );

        let conn = tls(
            &fcx,
            &m,
            &env.roots,
            at(RESOLVER, 443),
            DOH_NAME,
            &[b"http/1.1"],
        )
        .await;
        let got = http(
            &fcx,
            conn,
            false,
            get(
                false,
                DOH_NAME,
                "/dns-query?name=www.example.&type=1",
                &[("accept", "application/dns-json")],
            ),
        )
        .await;
        assert_eq!(got.status, StatusCode::OK);
        assert_eq!(got.header("content-type"), Some("application/dns-json"));
        assert_eq!(
            json_answers(&got.body),
            (0, true, vec![(WWW.to_string(), ttl)])
        );

        let sent = env.sent.lock().unwrap().clone();
        let transports: Vec<Transport> = sent.iter().map(|sent| sent.transport).collect();
        assert_eq!(
            transports,
            [Transport::Udp]
                .into_iter()
                .chain([Transport::Tcp; 5])
                .collect::<Vec<_>>()
        );
        let cached: Vec<bool> = sent.iter().map(|sent| sent.cached).collect();
        assert_eq!(cached, vec![false, true, true, true, true, true]);
        assert!(
            sent.iter()
                .all(|sent| sent.validation == Validation::Secure)
        );
        assert!(
            sent.iter().all(|each| each.sandbox == sent[0].sandbox) && sent[0].sandbox.is_some(),
            "{sent:?}"
        );
        Ok(())
    });
}

/// A name the resolver knows does not exist answers NXDOMAIN through the
/// JSON API with the zone's SOA, a validated denial, and a freshness no
/// longer than the SOA's MINIMUM; DNS over TLS answers pipelined queries
/// on one connection, each with its own ID.
#[test]
fn denials_and_pipelined_queries_answer_as_over_udp() {
    world(Duration::from_secs(60), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let env = start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("agent")?, ME);

        let reply = udp(
            &fcx,
            &m,
            RESOLVER,
            &query(1, "nope.example.", RecordType::A),
        )
        .await;
        assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
        assert!(reply.metadata.authentic_data);

        let conn = tls(&fcx, &m, &env.roots, at(RESOLVER, 443), DOH_NAME, &[b"h2"]).await;
        let got = http(
            &fcx,
            conn,
            true,
            get(true, DOH_NAME, "/resolve?name=nope.example&cd=false", &[]),
        )
        .await;
        assert_eq!(got.status, StatusCode::OK);
        assert_eq!(got.header("cache-control"), Some("max-age=900"));
        let value = Value::parse(&got.body).unwrap();
        assert_eq!(json_answers(&got.body), (3, true, Vec::new()));
        let Some(Value::Array(authority)) = value.get("Authority") else {
            panic!("no authority section in {value:?}");
        };
        assert!(
            authority.iter().any(|record| record
                .get("type")
                .and_then(Value::as_number)
                .map(|n| n.as_f64())
                == Some(6.0)),
            "no SOA in {value:?}"
        );

        let mut conn = tls(
            &fcx,
            &m,
            &env.roots,
            at(RESOLVER, 853),
            &RESOLVER.to_string(),
            &[],
        )
        .await;
        send_framed(&fcx, &mut conn, &query(10, "www.example.", RecordType::A)).await;
        send_framed(&fcx, &mut conn, &query(11, "nope.example.", RecordType::A)).await;
        let mut ids = Vec::new();
        for _ in 0..2 {
            let reply = read_framed(&fcx, &mut conn).await;
            let code = reply.metadata.response_code;
            match reply.metadata.id {
                10 => assert_eq!(answers(&reply), vec![(WWW, TTL)]),
                11 => assert_eq!(code, ResponseCode::NXDomain),
                id => panic!("an answer with ID {id}"),
            }
            ids.push(reply.metadata.id);
        }
        ids.sort();
        assert_eq!(ids, vec![10, 11]);
        let sent = env.sent.lock().unwrap().clone();
        assert!(
            sent.iter()
                .all(|sent| sent.validation == Validation::Secure)
        );
        Ok(())
    });
}

/// DNS over HTTPS answers only its own names and its own address: another
/// name by SNI or by host, or another address, is misdirected. Other
/// paths, methods, and media types are refused as RFC 8484 says, and a
/// bad JSON parameter is refused in JSON.
#[test]
fn dns_over_https_refuses_what_it_does_not_serve() {
    world(Duration::from_secs(60), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let env = start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("agent")?, ME);
        let wire = base64url(&query(1, "www.example.", RecordType::A).to_vec().unwrap());
        let path = format!("/dns-query?dns={wire}");

        // The handshake for another name succeeds, with a certificate that
        // does not cover it, which this client does not check.
        let config = client_config(&fcx, date(NOW), None, &[b"http/1.1"]).unwrap();
        let to = at(RESOLVER, 443);
        for (sni, host) in [
            ("other.example", "other.example"),
            ("other.example", DOH_NAME),
        ] {
            let conn = m.tls_with_config(&fcx, to, sni, config.clone()).await?;
            let got = http(&fcx, conn, false, get(false, host, &path, &[])).await;
            assert_eq!(got.status, StatusCode::MISDIRECTED_REQUEST, "{sni} {host}");
        }
        let conn = tls(
            &fcx,
            &m,
            &env.roots,
            at(RESOLVER, 443),
            DOH_NAME,
            &[b"http/1.1"],
        )
        .await;
        let got = http(&fcx, conn, false, get(false, "45.33.9.10", &path, &[])).await;
        assert_eq!(got.status, StatusCode::MISDIRECTED_REQUEST);

        let cases: Vec<(Request<Full<Bytes>>, StatusCode)> = vec![
            (get(false, DOH_NAME, "/", &[]), StatusCode::NOT_FOUND),
            (
                get(false, DOH_NAME, "/dns-query", &[]),
                StatusCode::BAD_REQUEST,
            ),
            (
                get(false, DOH_NAME, "/dns-query?dns=%%%", &[]),
                StatusCode::BAD_REQUEST,
            ),
            (
                with_body(
                    Method::POST,
                    false,
                    DOH_NAME,
                    "/dns-query",
                    "text/plain",
                    b"hello".to_vec(),
                ),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                with_body(
                    Method::POST,
                    false,
                    DOH_NAME,
                    "/dns-query",
                    "application/dns-message",
                    vec![0; 70000],
                ),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                with_body(
                    Method::PUT,
                    false,
                    DOH_NAME,
                    "/dns-query",
                    "application/dns-message",
                    Vec::new(),
                ),
                StatusCode::METHOD_NOT_ALLOWED,
            ),
        ];
        for (request, status) in cases {
            let what = format!("{} {}", request.method(), request.uri());
            let conn = tls(
                &fcx,
                &m,
                &env.roots,
                at(RESOLVER, 443),
                DOH_NAME,
                &[b"http/1.1"],
            )
            .await;
            let got = http(&fcx, conn, false, request).await;
            assert_eq!(got.status, status, "{what}");
            if status == StatusCode::METHOD_NOT_ALLOWED {
                assert_eq!(got.header("allow"), Some("GET, POST"));
            }
        }

        let conn = tls(
            &fcx,
            &m,
            &env.roots,
            at(RESOLVER, 443),
            DOH_NAME,
            &[b"http/1.1"],
        )
        .await;
        let got = http(
            &fcx,
            conn,
            false,
            get(false, DOH_NAME, "/resolve?name=www.example&cd=2", &[]),
        )
        .await;
        assert_eq!(got.status, StatusCode::BAD_REQUEST);
        let value = Value::parse(&got.body).unwrap();
        assert_eq!(
            value.get("error").and_then(Value::as_str),
            Some(
                "Invalid CD flag `2`. Expected to be empty or one of `0`, `false`, `1`, or `true`."
            )
        );
        assert!(
            env.sent.lock().unwrap().is_empty(),
            "a refused request reached the resolver"
        );
        Ok(())
    });
}

/// A public resolver's certificate carries its addresses, so DNS over TLS
/// to 1.1.1.1 is checked against the address. DNS over HTTPS on another
/// host, at the address `cloudflare-dns.com` has, answers from the cache
/// of the resolver at 1.1.1.1.
#[test]
fn a_front_on_another_host_answers_from_the_resolvers_cache() {
    world(Duration::from_secs(60), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let (hosts, anchors) = authorities();
        let cloudflare = &PUBLIC_RESOLVERS[1];
        let one = cloudflare.addresses[0].v4;
        let elsewhere = Ipv4Addr::new(45, 33, 6, 6);
        let ca = Ca::new(&fcx, "World CA")?;
        let validity = Validity {
            not_before: Time::from_unix(946_684_800)?,
            not_after: Time::from_unix(4_102_444_800)?,
        };
        let sans = cloudflare.sans();
        let sans: Vec<&str> = sans.iter().map(String::as_str).collect();
        let config = ca
            .issue(&fcx, &sans, validity)?
            .server_config(&fcx, date(NOW))?;
        let mut roots = RootCertStore::empty();
        roots.add(ca.cert_der())?;
        let roots = Arc::new(roots);
        let sent: Arc<Mutex<Vec<Sent>>> = Arc::default();
        let resolver = recursive(anchors, &sent);
        let fronts =
            Fronts::new(resolver.handle(), move |_| config.clone()).names(cloudflare.doh());
        let away = fronts.clone().resolver_at(IpAddr::V4(one));
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .hosts(hosts)
            .hosts([
                fronts.dot(Host::new("one.one.one.one").at(one).program(resolver)),
                away.doh(Host::new("cloudflare-dns.com").at(elsewhere)),
            ])
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("agent")?, ME);

        let reply = udp(&fcx, &m, one, &query(1, "www.example.", RecordType::A)).await;
        assert_eq!(answers(&reply), vec![(WWW, TTL)]);

        fcx.sleep(Duration::from_secs(2)).await?;
        let mut conn = tls(&fcx, &m, &roots, at(one, 853), &one.to_string(), &[b"dot"]).await;
        assert_eq!(conn.tls.alpn_protocol(), Some(&b"dot"[..]));
        send_framed(&fcx, &mut conn, &query(2, "www.example.", RecordType::A)).await;
        let reply = read_framed(&fcx, &mut conn).await;
        assert!(reply.metadata.authentic_data);
        assert_eq!(answers(&reply), vec![(WWW, TTL - 2)]);

        fcx.sleep(Duration::from_secs(2)).await?;
        let doh = "cloudflare-dns.com";
        let conn = tls(&fcx, &m, &roots, at(elsewhere, 443), doh, &[b"h2"]).await;
        let wire = base64url(&query(0, "www.example.", RecordType::A).to_vec().unwrap());
        let path = format!("/dns-query?dns={wire}");
        let got = http(&fcx, conn, true, get(true, doh, &path, &[])).await;
        assert_eq!(got.status, StatusCode::OK);
        let reply = Message::from_vec(&got.body).unwrap();
        assert!(reply.metadata.authentic_data);
        assert_eq!(answers(&reply), vec![(WWW, TTL - 4)]);

        let sent = sent.lock().unwrap().clone();
        let cached: Vec<bool> = sent.iter().map(|sent| sent.cached).collect();
        assert_eq!(cached, vec![false, true, true]);
        assert!(
            sent.iter()
                .all(|sent| sent.validation == Validation::Secure)
        );
        Ok(())
    });
}

/// Cloudflare's certificate covers `1dot1dot1dot1.cloudflare-dns.com`,
/// the name it gives for DNS over TLS, so a client that checks that name
/// talks DNS over TLS to 1.1.1.1 as it would to the real one.
#[test]
fn dns_over_tls_to_cloudflare_checks_its_documented_name() {
    world(Duration::from_secs(60), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let (hosts, anchors) = authorities();
        let cloudflare = &PUBLIC_RESOLVERS[1];
        let one = cloudflare.addresses[0].v4;
        let ca = Ca::new(&fcx, "World CA")?;
        let validity = Validity {
            not_before: Time::from_unix(946_684_800)?,
            not_after: Time::from_unix(4_102_444_800)?,
        };
        let sans = cloudflare.sans();
        let sans: Vec<&str> = sans.iter().map(String::as_str).collect();
        let config = ca
            .issue(&fcx, &sans, validity)?
            .server_config(&fcx, date(NOW))?;
        let mut roots = RootCertStore::empty();
        roots.add(ca.cert_der())?;
        let roots = Arc::new(roots);
        let sent: Arc<Mutex<Vec<Sent>>> = Arc::default();
        let resolver = recursive(anchors, &sent);
        let fronts =
            Fronts::new(resolver.handle(), move |_| config.clone()).names(cloudflare.doh());
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .hosts(hosts)
            .hosts([fronts.dot(Host::new("one.one.one.one").at(one).program(resolver))])
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("agent")?, ME);
        let documented = "1dot1dot1dot1.cloudflare-dns.com";
        let mut conn = tls(&fcx, &m, &roots, at(one, 853), documented, &[b"dot"]).await;
        send_framed(&fcx, &mut conn, &query(1, "www.example.", RecordType::A)).await;
        let reply = read_framed(&fcx, &mut conn).await;
        assert_eq!(answers(&reply), vec![(WWW, TTL)]);
        Ok(())
    });
}

/// The names a DNS over HTTPS front answers for are its own at its
/// address: a site for one of them cannot be placed there, and requests
/// for the name still reach the resolver.
#[test]
fn a_site_cannot_take_a_fronts_name_at_its_address() {
    world(Duration::from_secs(60), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let (hosts, anchors) = authorities();
        let cloudflare = &PUBLIC_RESOLVERS[1];
        let one = cloudflare.addresses[0].v4;
        let elsewhere = Ipv4Addr::new(45, 33, 6, 6);
        let ca = Ca::new(&fcx, "World CA")?;
        let validity = Validity {
            not_before: Time::from_unix(946_684_800)?,
            not_after: Time::from_unix(4_102_444_800)?,
        };
        let sans = cloudflare.sans();
        let sans: Vec<&str> = sans.iter().map(String::as_str).collect();
        let config = ca
            .issue(&fcx, &sans, validity)?
            .server_config(&fcx, date(NOW))?;
        let site_config = config.clone();
        let mut roots = RootCertStore::empty();
        roots.add(ca.cert_der())?;
        let roots = Arc::new(roots);
        let sent: Arc<Mutex<Vec<Sent>>> = Arc::default();
        let resolver = recursive(anchors, &sent);
        let fronts =
            Fronts::new(resolver.handle(), move |_| config.clone()).names(cloudflare.doh());
        let away = fronts.clone().resolver_at(IpAddr::V4(one));
        let net = Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .hosts(hosts)
            .hosts([
                fronts.dot(Host::new("one.one.one.one").at(one).program(resolver)),
                away.doh(Host::new("cloudflare-dns.com").at(elsewhere)),
            ]);
        let handle = net.handle();
        net.start(&fcx, attachments)?;
        let doh = "cloudflare-dns.com";
        let site = fictionet::stdlib::web::Site::new(super::Plain("site"))
            .tls(site_config)
            .into_host(doh)
            .at(elsewhere);
        assert!(handle.add_host(site).is_err());

        let m = machine(&fcx, attacher.attach("agent")?, ME);
        let conn = tls(&fcx, &m, &roots, at(elsewhere, 443), doh, &[b"h2"]).await;
        let wire = base64url(&query(0, "www.example.", RecordType::A).to_vec().unwrap());
        let path = format!("/dns-query?dns={wire}");
        let got = http(&fcx, conn, true, get(true, doh, &path, &[])).await;
        assert_eq!(got.status, StatusCode::OK);
        assert_eq!(got.header("content-type"), Some("application/dns-message"));
        assert_eq!(
            answers(&Message::from_vec(&got.body).unwrap()),
            vec![(WWW, TTL)]
        );
        Ok(())
    });
}

/// Each public resolver's DNS over HTTPS answers as its operator's does,
/// as seen on 2026-11-02: Google's JSON API at `/resolve` only at
/// `dns.google`, Cloudflare's JSON at `/dns-query` only at
/// `cloudflare-dns.com`, and each operator's own errors elsewhere.
#[test]
fn each_public_resolver_answers_dns_over_https_as_its_operator() {
    world(Duration::from_secs(60), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let (hosts, anchors) = authorities();
        let names: Vec<String> = PUBLIC_RESOLVERS
            .iter()
            .map(|resolver| {
                resolver.doh()[0]
                    .to_ascii()
                    .trim_end_matches('.')
                    .to_owned()
            })
            .collect();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let (ca, leaf) = certs::issue(&fcx, "World CA", &names)?;
        let config = leaf.server_config(&fcx, date(NOW))?;
        let mut roots = RootCertStore::empty();
        roots.add(ca.cert_der())?;
        let roots = Arc::new(roots);
        let sent: Arc<Mutex<Vec<Sent>>> = Arc::default();
        let resolver = recursive(anchors, &sent);
        let address = |n: usize| Ipv4Addr::new(45, 33, 10, 1 + n as u8);
        let fronts: Vec<Host> = PUBLIC_RESOLVERS
            .iter()
            .enumerate()
            .map(|(n, public)| {
                let config = config.clone();
                let fronts = Fronts::new(resolver.handle(), move |_| config.clone())
                    .names(public.doh())
                    .resolver_at(IpAddr::V4(RESOLVER));
                public
                    .doh_fronts(fronts)
                    .doh(Host::new(names[n]).at(address(n)))
            })
            .collect();
        Net::new(fictionet_extras::network::cdn_pools())
            .ipv4_only()
            .hosts(hosts)
            .hosts([Host::new("resolver").at(RESOLVER).program(resolver)])
            .hosts(fronts)
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("agent")?, ME);

        type Headers = &'static [(&'static str, &'static str)];
        // The status and media type at Google, Cloudflare, Quad9, and
        // OpenDNS.
        type PerOperator = [(u16, &'static str); 4];
        let dns_json: Headers = &[("accept", "application/dns-json")];
        let html = "text/html";
        let google_html = "text/html; charset=UTF-8";
        let text = "text/plain; charset=utf-8";
        let cases: [(&str, Headers, PerOperator); 3] = [
            (
                "/resolve?name=www.example",
                &[],
                [
                    (200, "application/json; charset=UTF-8"),
                    (301, google_html),
                    (404, text),
                    (404, html),
                ],
            ),
            (
                "/dns-query?name=www.example",
                dns_json,
                [
                    (400, google_html),
                    (200, "application/dns-json"),
                    (400, text),
                    (400, html),
                ],
            ),
            (
                "/nope",
                &[],
                [
                    (404, google_html),
                    (301, google_html),
                    (404, text),
                    (404, html),
                ],
            ),
        ];
        for (path, headers, expected) in cases {
            for (n, (status, media)) in expected.into_iter().enumerate() {
                let to = at(address(n), 443);
                let conn = tls(&fcx, &m, &roots, to, names[n], &[b"http/1.1"]).await;
                let got = http(&fcx, conn, false, get(false, names[n], path, headers)).await;
                let what = format!("{} {path}", names[n]);
                assert_eq!(got.status.as_u16(), status, "{what}");
                assert_eq!(got.header("content-type"), Some(media), "{what}");
                if status == 301 {
                    assert_eq!(
                        got.header("location"),
                        Some(format!("https://one.one.one.one{path}").as_str()),
                        "{what}"
                    );
                }
            }
        }
        // Google's page names the path it did not find.
        let to = at(address(0), 443);
        let conn = tls(&fcx, &m, &roots, to, names[0], &[b"http/1.1"]).await;
        let got = http(&fcx, conn, false, get(false, names[0], "/nope", &[])).await;
        let body = String::from_utf8_lossy(&got.body);
        assert!(
            body.contains("The requested URL <code>/nope</code> was not found"),
            "{body}"
        );
        // Only the two JSON answers reached the resolver.
        assert_eq!(sent.lock().unwrap().len(), 2);
        Ok(())
    });
}

/// The JSON API gives each record's data in presentation format, which
/// reads back as the same RDATA: SVCB parameters as RFC 9460 writes them,
/// quoted and escaped strings, and the generic form for a type it does
/// not know (RFC 1035 §5.1, RFC 3597 §5).
#[test]
fn json_data_is_in_presentation_format() {
    world(Duration::from_secs(60), |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let env = start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("agent")?, ME);
        for (number, data) in KINDS {
            let conn = tls(&fcx, &m, &env.roots, at(RESOLVER, 443), DOH_NAME, &[b"h2"]).await;
            let path = format!("/resolve?name=kinds.example&type={number}");
            let got = http(&fcx, conn, true, get(true, DOH_NAME, &path, &[])).await;
            assert_eq!(got.status, StatusCode::OK, "{number}");
            let value = Value::parse(&got.body).unwrap();
            let Some(Value::Array(answers)) = value.get("Answer") else {
                panic!("{number}: no answer in {value:?}");
            };
            let given: Vec<&str> = answers
                .iter()
                .filter(|record| {
                    record
                        .get("type")
                        .and_then(Value::as_number)
                        .map(|n| n.as_f64())
                        == Some(f64::from(number))
                })
                .filter_map(|record| record.get("data").and_then(Value::as_str))
                .collect();
            assert_eq!(given, [data], "{number}");
            // Read back, the data is the record the zone holds.
            let held = kind(number, data);
            let back = kind(number, given[0]);
            assert_eq!(
                back.records_without_rrsigs().next().map(|r| &r.data),
                held.records_without_rrsigs().next().map(|r| &r.data),
                "{number}"
            );
        }
        Ok(())
    });
}
