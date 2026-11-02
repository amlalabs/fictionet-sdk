//! The internet presets on a simulated network: a root letter relaying a
//! hierarchy, the mirror placing relays where replies name servers, and
//! the public resolvers' whoami names and per-sandbox caches. The real
//! hierarchy is played by a source that answers from fixed zones.

use std::future::{Future, ready};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fictionet::Cx;
use fictionet::stdlib::network::route::Prefix;
use fictionet::stdlib::protocols::dns::op::{Edns, Message, OpCode, Query, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::rdata::TXT;
use fictionet::stdlib::protocols::dns::rr::{DNSClass, LowerName, Name, RData, Record, RecordType};
use fictionet::stdlib::protocols::dns::{Nsid, Parsed, Request, Response};
use fictionet::stdlib::services::dns::authority::{Ask, Identity, Observed, ServerConfig};
use fictionet::stdlib::services::dns::resolver::Config;
use fictionet::stdlib::services::dns::zone::{Answered, AnyResponse, Zone, ZoneData, answer};
use fictionet::stdlib::services::dns::{Event, Generation, WallClock};
use fictionet::stdlib::services::serve::Transport;
use fictionet::stdlib::world::net::dns::internet::{
    self, Egress, GTLD_SERVERS, Location, Mirror, PUBLIC_RESOLVERS, ROOT_LETTERS,
};
use fictionet::stdlib::world::net::dns::{self, Cached, Recursive, Source};
use fictionet::stdlib::world::net::{Host, Net};
use fictionet_test_support::sandbox::{Machine, machine};
use fictionet_test_support::timeout;

use crate::common::world::world;

const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const EGRESS: Ipv4Addr = Ipv4Addr::new(45, 70, 0, 9);

/// The root zone the source answers for at every root letter: the root
/// servers, `example.` delegated without glue to a server under `org.`,
/// `org.` and `direct.` with glue, `lan.` and `private.` with glue no
/// internet host can be at, `home.` with the egress as its glue, and two
/// names with addresses.
const ROOT: &str = "\
. 86400 IN SOA a.root-servers.net. nstld.verisign-grs.com. 2026110101 1800 900 604800 86400
. 518400 IN NS a.root-servers.net.
. 518400 IN NS b.root-servers.net.
. 518400 IN NS c.root-servers.net.
. 518400 IN NS d.root-servers.net.
. 518400 IN NS e.root-servers.net.
. 518400 IN NS f.root-servers.net.
. 518400 IN NS g.root-servers.net.
. 518400 IN NS h.root-servers.net.
. 518400 IN NS i.root-servers.net.
. 518400 IN NS j.root-servers.net.
. 518400 IN NS k.root-servers.net.
. 518400 IN NS l.root-servers.net.
. 518400 IN NS m.root-servers.net.
a.root-servers.net. 518400 IN A 198.41.0.4
b.root-servers.net. 518400 IN A 170.247.170.2
c.root-servers.net. 518400 IN A 192.33.4.12
d.root-servers.net. 518400 IN A 199.7.91.13
e.root-servers.net. 518400 IN A 192.203.230.10
f.root-servers.net. 518400 IN A 192.5.5.241
g.root-servers.net. 518400 IN A 192.112.36.4
h.root-servers.net. 518400 IN A 198.97.190.53
i.root-servers.net. 518400 IN A 192.36.148.17
j.root-servers.net. 518400 IN A 192.58.128.30
k.root-servers.net. 518400 IN A 193.0.14.129
l.root-servers.net. 518400 IN A 199.7.83.42
m.root-servers.net. 518400 IN A 202.12.27.33
example. 172800 IN NS ns.provider.org.
org. 172800 IN NS ns.org.
ns.org. 172800 IN A 45.33.1.53
direct. 172800 IN NS ns.direct.
ns.direct. 172800 IN A 45.33.5.53
lan. 172800 IN NS ns.lan.
ns.lan. 172800 IN A 45.60.0.77
private. 172800 IN NS ns.private.
ns.private. 172800 IN A 192.168.1.53
home. 172800 IN NS ns.home.
ns.home. 172800 IN A 45.70.0.9
cloudflare-dns.com. 300 IN A 45.33.6.6
plain. 300 IN A 45.33.7.7
";

const ORG: &str = "\
org. 900 IN SOA ns.org. hostmaster.org. 1 1800 900 604800 900
org. 3600 IN NS ns.org.
ns.org. 3600 IN A 45.33.1.53
provider.org. 3600 IN NS ns1.provider.org.
ns1.provider.org. 3600 IN A 45.33.2.53
";

const PROVIDER: &str = "\
provider.org. 900 IN SOA ns1.provider.org. hostmaster.provider.org. 1 1800 900 604800 900
provider.org. 3600 IN NS ns1.provider.org.
ns1.provider.org. 3600 IN A 45.33.2.53
ns.provider.org. 3600 IN A 45.33.3.53
";

const EXAMPLE: &str = "\
example. 900 IN SOA ns.provider.org. hostmaster.example. 1 1800 900 604800 900
example. 3600 IN NS ns.provider.org.
www.example. 300 IN A 45.33.4.80
";

const DIRECT: &str = "\
direct. 900 IN SOA ns.direct. hostmaster.direct. 1 1800 900 604800 900
direct. 3600 IN NS ns.direct.
ns.direct. 3600 IN A 45.33.5.53
www.direct. 300 IN A 45.33.5.80
whoami.direct. 300 IN A 45.70.0.9
whoami.direct. 300 IN TXT \"45.70.0.9\"
";

/// What the real hierarchy answers, played from fixed zones: each server
/// address answers from its zone as an authoritative server does, and
/// every question asked is kept.
#[derive(Clone)]
struct Hierarchy {
    servers: Arc<Vec<(Vec<IpAddr>, Arc<Zone>)>>,
    asked: Arc<Mutex<Vec<(IpAddr, LowerName, RecordType)>>>,
}

impl Hierarchy {
    fn new() -> Hierarchy {
        let zone = |text: &str| Arc::new(Zone::from_master(text, None).expect("a test zone"));
        let root = Arc::new(internet::root_zone(ROOT).expect("the test root zone"));
        let at = |a: [u8; 4]| vec![IpAddr::V4(Ipv4Addr::from(a))];
        let letters = ROOT_LETTERS
            .iter()
            .map(|letter| IpAddr::V4(letter.server.v4))
            .collect();
        Hierarchy {
            servers: Arc::new(vec![
                (letters, root),
                (at([45, 33, 1, 53]), zone(ORG)),
                (at([45, 33, 2, 53]), zone(PROVIDER)),
                (at([45, 33, 3, 53]), zone(EXAMPLE)),
                (at([45, 33, 5, 53]), zone(DIRECT)),
            ]),
            asked: Arc::default(),
        }
    }

    /// The servers asked so far for `name` of type `kind`, in order.
    fn asked_for(&self, name: &str, kind: RecordType) -> Vec<IpAddr> {
        let name = lower(name);
        self.asked
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, asked, asked_kind)| *asked == name && *asked_kind == kind)
            .map(|(server, _, _)| *server)
            .collect()
    }
}

impl Source for Hierarchy {
    fn ask<'a>(
        &'a self,
        _fcx: &'a Cx,
        ask: Ask,
    ) -> Pin<Box<dyn Future<Output = Observed> + Send + 'a>> {
        let Parsed::Request(req) = Request::parse(&ask.query, ask.transport) else {
            panic!("a relay asked something that is not a query");
        };
        let server = ask.server.ip();
        self.asked.lock().unwrap().push((
            server,
            LowerName::new(req.question.name()),
            req.question.query_type(),
        ));
        let zone = self
            .servers
            .iter()
            .find(|(addresses, _)| addresses.contains(&server));
        let Some((_, zone)) = zone else {
            return Box::pin(ready(Observed::Unreachable));
        };
        // Every real server here is the instance `REAL`, by CHAOS name and
        // by NSID.
        let front = ServerConfig {
            identity: Some(Identity {
                nsid: Some(REAL.as_bytes().to_vec()),
                ..Identity::none()
            }),
            ..ServerConfig::generic()
        };
        let response = if req.question.query_class() == DNSClass::CH {
            let mut message = Message::response(req.message.metadata.id, OpCode::Query);
            message.add_query(req.question.clone());
            let mut record = Record::from_rdata(
                req.question.name().clone(),
                0,
                RData::TXT(TXT::new(vec![REAL.to_string()])),
            );
            record.dns_class = DNSClass::CH;
            message.add_answer(record);
            Response {
                message,
                required_additional: 0,
            }
        } else {
            let Answered::Response(response) =
                answer(&*zone.view(&req.question), &req, AnyResponse::All)
            else {
                panic!("a complete zone knows every fact");
            };
            response
        };
        let reply = front.front(&req, response);
        Box::pin(ready(Observed::Reply(
            reply.message.to_vec().expect("a reply"),
        )))
    }
}

/// The instance every real server of [`Hierarchy`] is.
const REAL: &str = "real-uklon";

fn lower(name: &str) -> LowerName {
    LowerName::new(&Name::from_ascii(name).unwrap())
}

fn location() -> Location {
    Location::san_francisco_bay_area(Some(Egress(EGRESS)))
}

/// A query for `name` of type `kind`, with RD as given and an OPT record.
fn query(id: u16, name: &str, kind: RecordType, rd: bool) -> Message {
    let mut query = Message::query();
    query.metadata.id = id;
    query.metadata.recursion_desired = rd;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    query.set_edns(Edns::new());
    query
}

/// A CHAOS-class TXT query for `name`.
fn chaos(id: u16, name: &str) -> Message {
    let mut query = Message::query();
    query.metadata.id = id;
    let mut question = Query::query(Name::from_ascii(name).unwrap(), RecordType::TXT);
    question.set_query_class(DNSClass::CH);
    query.add_query(question);
    query
}

/// What `server` answers `query` over UDP, if it answers within two
/// seconds.
async fn ask(fcx: &Cx, m: &Machine, server: impl Into<IpAddr>, query: &Message) -> Option<Message> {
    let mut socket = m.udp.bind(0).ok()?;
    socket.send_to(&query.to_vec().ok()?, SocketAddr::new(server.into(), 53));
    let (bytes, _) = timeout(fcx, Duration::from_secs(2), socket.recv(fcx))
        .await?
        .ok()?;
    Message::from_vec(&bytes).ok()
}

/// The texts of a reply's TXT answers.
fn texts(reply: &Message) -> Vec<String> {
    reply
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::TXT(txt) => Some(
                txt.txt_data
                    .iter()
                    .map(|part| String::from_utf8_lossy(part).into_owned())
                    .collect(),
            ),
            _ => None,
        })
        .collect()
}

fn addresses(reply: &Message) -> Vec<IpAddr> {
    reply
        .answers
        .iter()
        .chain(&reply.additionals)
        .filter_map(|record| match &record.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            _ => None,
        })
        .collect()
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// One rule says which addresses a public internet host can have, the
/// IANA special-purpose registries' (RFC 6890), for the network and the
/// mirror alike: multicast and `0.0.0.0/8` are no host's, as private
/// space is not.
#[test]
fn no_public_host_has_a_special_purpose_address() {
    use fictionet::stdlib::network::ip::non_public_address;
    for address in [
        "224.0.0.1",
        "0.0.0.1",
        "10.0.0.1",
        "192.0.2.1",
        "ff02::1",
        "fec0::1",
    ] {
        assert!(non_public_address(address.parse().unwrap()), "{address}");
    }
    for address in ["45.33.4.80", "192.0.0.9", "2606:4700:4700::1111"] {
        assert!(!non_public_address(address.parse().unwrap()), "{address}");
    }
}

/// The resolver hints and the root letter presets name the same servers
/// at the same addresses.
#[test]
fn the_root_hints_are_the_root_letters() {
    let letters: Vec<(Name, IpAddr)> = ROOT_LETTERS
        .iter()
        .flat_map(|letter| {
            let name = letter.server.name();
            letter.server.addresses().map(|addr| (name.clone(), addr))
        })
        .collect();
    assert_eq!(internet::root_hints(), letters);
    assert_eq!(Config::unbound().hints, letters);
}

/// `dig @198.41.0.4 . NS` at a root letter relaying the hierarchy: the
/// real server's answer, every root server with its address, after the
/// round trip the location gives a.root, and `id.server` answered from
/// the site that answers there without asking the source.
#[test]
fn a_root_letter_answers_the_root_ns_as_dig_sees_it() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = location();
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let mirror = Mirror::new(hierarchy.clone(), net.handle(), &at);
        net.hosts(internet::root_servers(|s| mirror.relay(s), &at))
            .hosts(internet::gtld_servers(|s| mirror.relay(s), &at))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let a_root = ROOT_LETTERS[0].server.v4;

        let sent = fcx.now().since_start();
        let reply = ask(&fcx, &m, a_root, &query(7, ".", RecordType::NS, false))
            .await
            .expect("an answer");
        let took = fcx.now().since_start() - sent;
        assert_eq!(reply.metadata.id, 7);
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.metadata.authoritative);
        assert!(!reply.metadata.recursion_available);
        assert!(!reply.metadata.truncation);
        let servers: Vec<String> = reply
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::NS(ns) => Some(ns.0.to_string()),
                _ => None,
            })
            .collect();
        let expected: Vec<String> = ROOT_LETTERS
            .iter()
            .map(|letter| letter.server.host.to_string())
            .collect();
        let mut sorted = servers.clone();
        sorted.sort();
        assert_eq!(sorted, expected);
        let mut glue = addresses(&reply);
        glue.sort();
        let mut letters: Vec<IpAddr> = ROOT_LETTERS
            .iter()
            .map(|letter| IpAddr::V4(letter.server.v4))
            .collect();
        letters.sort();
        assert_eq!(glue, letters);
        let rtt = at.site(IpAddr::V4(a_root)).rtt;
        assert!(took >= rtt, "{took:?} is less than a.root's {rtt:?}");
        assert_eq!(hierarchy.asked_for(".", RecordType::NS).len(), 1);

        let reply = ask(&fcx, &m, a_root, &chaos(8, "id.server."))
            .await
            .expect("an answer");
        assert_eq!(texts(&reply), vec!["nnn1-ussea-4c".to_string()]);
        let reply = ask(&fcx, &m, GTLD_SERVERS[0].v4, &chaos(9, "version.bind."))
            .await
            .expect("an answer");
        assert_eq!(texts(&reply), vec!["ATLAS".to_string()]);
        assert_eq!(
            hierarchy.asked.lock().unwrap().len(),
            1,
            "CHAOS is never relayed"
        );
        Ok(())
    });
}

/// The NSID and the CHAOS names of one address name one instance: a root
/// letter's preset site for both, never the real instance's NSID next to
/// the preset's CHAOS names, and a relay the mirror placed the real
/// instance for both.
#[test]
fn a_relayed_server_names_one_instance_by_chaos_and_by_nsid() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = location();
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let mirror = Mirror::new(hierarchy.clone(), net.handle(), &at);
        net.hosts(internet::root_servers(|s| mirror.relay(s), &at))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let a_root = ROOT_LETTERS[0].server.v4;
        let site = at.site(IpAddr::V4(a_root)).identity;
        assert!(site.nsid.is_some());

        let mut soa = query(1, ".", RecordType::SOA, false);
        soa.edns
            .as_mut()
            .unwrap()
            .options_mut()
            .insert(Nsid(Vec::new()).to_option());
        let reply = ask(&fcx, &m, a_root, &soa).await.expect("an answer");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert_eq!(nsid(&reply), site.nsid, "the preset site's NSID");
        let reply = ask(&fcx, &m, a_root, &chaos(2, "hostname.bind."))
            .await
            .expect("an answer");
        assert_ne!(texts(&reply), vec![REAL.to_string()]);

        // The referral to `direct.` places a relay at its glue, which
        // passes the real instance's own answers on.
        let ns = v4(45, 33, 5, 53);
        ask(
            &fcx,
            &m,
            a_root,
            &query(3, "www.direct.", RecordType::A, false),
        )
        .await
        .expect("a referral");
        let reply = ask(&fcx, &m, ns, &chaos(4, "hostname.bind."))
            .await
            .expect("an answer from the real instance");
        assert_eq!(texts(&reply), vec![REAL.to_string()]);
        let mut www = query(5, "www.direct.", RecordType::A, false);
        www.edns
            .as_mut()
            .unwrap()
            .options_mut()
            .insert(Nsid(Vec::new()).to_option());
        let reply = ask(&fcx, &m, ns, &www).await.expect("an answer");
        assert_eq!(nsid(&reply), Some(REAL.as_bytes().to_vec()));
        Ok(())
    });
}

/// A host `placing` places for a name makes every name above it exist,
/// whatever the callback said about those names: they answer NODATA, and
/// names with nothing at or below them stay NXDOMAIN.
#[test]
fn a_placed_host_makes_the_names_above_it_exist() {
    world(Duration::from_secs(60), |fcx| async move {
        let (_attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let handle = net.handle();
        net.start(&fcx, attachments)?;
        let zone = dns::placing(handle, |name| {
            (name == "www.example.com").then(|| Host::new("www").at(Ipv4Addr::new(45, 33, 20, 80)))
        });
        let ask = |qname: &str| {
            let message = query(1, qname, RecordType::A, false);
            let Parsed::Request(request) =
                Request::parse(&message.to_vec().unwrap(), Transport::Udp)
            else {
                panic!("a query parses");
            };
            match answer(&*zone.view(&request.question), &request, AnyResponse::All) {
                Answered::Response(response) => response.message,
                Answered::Unknown { name } => panic!("{name} is unknown"),
            }
        };
        let www = ask("www.example.com.");
        assert_eq!(addresses(&www), vec![v4(45, 33, 20, 80)]);
        for above in ["example.com.", "com."] {
            let reply = ask(above);
            assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
            assert!(reply.answers.is_empty(), "{above} is an empty non-terminal");
        }
        let elsewhere = ask("www.example.org.");
        assert_eq!(elsewhere.metadata.response_code, ResponseCode::NXDomain);
        Ok(())
    });
}

/// The root zone of `placing` answers its own NS RRset, `localhost.`, as
/// an Unbound static local zone at the root does: the view knows that no
/// host has the name of the NS target, so nothing goes in the additional
/// section.
#[test]
fn the_placing_root_answers_its_ns_set() {
    world(Duration::from_secs(60), |fcx| async move {
        let (_attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let handle = net.handle();
        net.start(&fcx, attachments)?;
        let zone = dns::placing(handle, |_| None);
        let message = query(1, ".", RecordType::NS, false);
        let Parsed::Request(request) = Request::parse(&message.to_vec().unwrap(), Transport::Udp)
        else {
            panic!("a query parses");
        };
        let Answered::Response(response) =
            answer(&*zone.view(&request.question), &request, AnyResponse::All)
        else {
            panic!("the root's NS set is known");
        };
        let reply = response.message;
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        let ns: Vec<String> = reply
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::NS(ns) => Some(ns.0.to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(ns, vec!["localhost.".to_string()]);
        assert!(reply.additionals.is_empty());
        Ok(())
    });
}

/// `Cached` answers an ask from a kept reply only when the reply fits it:
/// the same question with the same EDNS, so a query without an OPT record
/// never gets a reply with one (RFC 6891 §7).
#[test]
fn a_cached_reply_answers_only_the_same_question_with_the_same_edns() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let cached = Cached::new(hierarchy.clone());
        let a_root = SocketAddr::new(IpAddr::V4(ROOT_LETTERS[0].server.v4), 53);
        let ask = |message: Message| Ask {
            server: a_root,
            transport: Transport::Udp,
            query: message.to_vec().unwrap(),
        };
        let reply = |observed: Observed| match observed {
            Observed::Reply(bytes) => Message::from_vec(&bytes).unwrap(),
            other => panic!("expected a reply, got {other:?}"),
        };
        let with_opt = query(1, ".", RecordType::NS, false);
        let mut without_opt = with_opt.clone();
        without_opt.metadata.id = 2;
        without_opt.edns = None;

        let first = reply(cached.ask(&fcx, ask(with_opt.clone())).await);
        assert!(first.edns.is_some());
        let again = reply(cached.ask(&fcx, ask(with_opt)).await);
        assert_eq!(again.answers, first.answers);
        assert_eq!(hierarchy.asked_for(".", RecordType::NS).len(), 1, "kept");

        let plain = reply(cached.ask(&fcx, ask(without_opt)).await);
        assert_eq!(plain.metadata.id, 2);
        assert!(
            plain.edns.is_none(),
            "no OPT record for a query without one"
        );
        assert_eq!(hierarchy.asked_for(".", RecordType::NS).len(), 2);
        Ok(())
    });
}

/// `Cached` keeps its replies for one session of its namespace: a new
/// session asks the source again.
#[test]
fn a_cached_reply_stays_in_its_session() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let namespace = dns::Namespace::new(WallClock {
            start: SystemTime::UNIX_EPOCH,
        });
        let cached = Cached::new(hierarchy.clone()).namespace(&namespace);
        let a_root = SocketAddr::new(IpAddr::V4(ROOT_LETTERS[0].server.v4), 53);
        let ask = || Ask {
            server: a_root,
            transport: Transport::Udp,
            query: query(1, ".", RecordType::NS, false).to_vec().unwrap(),
        };
        cached.ask(&fcx, ask()).await;
        cached.ask(&fcx, ask()).await;
        assert_eq!(hierarchy.asked_for(".", RecordType::NS).len(), 1, "kept");
        namespace.advance(WallClock {
            start: SystemTime::UNIX_EPOCH,
        });
        cached.ask(&fcx, ask()).await;
        assert_eq!(
            hierarchy.asked_for(".", RecordType::NS).len(),
            2,
            "asked again in the new session"
        );
        Ok(())
    });
}

/// Per-session state moves only forward: a call still working for an
/// ended session sees fresh state of its own and leaves the current
/// session's state as it was.
#[test]
fn per_session_state_ignores_an_earlier_session() {
    let state: dns::PerSession<Vec<u8>> = dns::PerSession::new();
    state.with(Generation(2), |kept| kept.push(1));
    let seen = state.with(Generation(1), |kept| {
        kept.push(9);
        kept.clone()
    });
    assert_eq!(seen, vec![9]);
    assert_eq!(state.with(Generation(2), |kept| kept.clone()), vec![1]);
    assert!(state.with(Generation(3), |kept| kept.is_empty()));
}

/// The NSID in `reply`, if it has one.
fn nsid(reply: &Message) -> Option<Vec<u8>> {
    reply
        .edns
        .iter()
        .flat_map(|edns| edns.options().as_ref().iter())
        .find_map(|(_, option)| Nsid::from_option(option))
        .map(|nsid| nsid.0)
}

/// A referral with glue places a relay at the glue address before the
/// referral reaches the client, so the client's next question to that
/// address is answered. An answer for a name no relayed NS RRset named
/// places nothing.
#[test]
fn the_mirror_places_a_relay_at_referral_glue_before_the_reply_leaves() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = location();
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let handle = net.handle();
        let mirror = Mirror::new(hierarchy.clone(), handle.clone(), &at);
        net.hosts(internet::root_servers(|s| mirror.relay(s), &at))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let a_root = ROOT_LETTERS[0].server.v4;
        let ns = v4(45, 33, 5, 53);

        assert!(!handle.has_machine(ns));
        let reply = ask(
            &fcx,
            &m,
            a_root,
            &query(1, "www.direct.", RecordType::A, false),
        )
        .await
        .expect("a referral");
        assert!(reply.answers.is_empty());
        assert_eq!(addresses(&reply), vec![ns]);
        assert!(
            handle.has_machine(ns),
            "the relay is placed with the referral"
        );

        let reply = ask(&fcx, &m, ns, &query(2, "www.direct.", RecordType::A, false))
            .await
            .expect("an answer from the placed relay");
        assert!(reply.metadata.authoritative);
        assert_eq!(addresses(&reply), vec![v4(45, 33, 5, 80)]);
        assert_eq!(
            hierarchy.asked_for("www.direct.", RecordType::A),
            vec![IpAddr::V4(a_root), ns]
        );

        let reply = ask(&fcx, &m, a_root, &query(3, "plain.", RecordType::A, false))
            .await
            .expect("an answer");
        assert_eq!(addresses(&reply), vec![v4(45, 33, 7, 7)]);
        assert!(!handle.has_machine(v4(45, 33, 7, 7)));
        Ok(())
    });
}

/// A referral whose glue is the location's own egress places no relay
/// there, so no question is ever sent from the host to its own public
/// address.
#[test]
fn the_mirror_places_no_relay_at_the_egress() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = location();
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let handle = net.handle();
        let mirror = Mirror::new(hierarchy.clone(), handle.clone(), &at);
        net.hosts(internet::root_servers(|s| mirror.relay(s), &at))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let a_root = ROOT_LETTERS[0].server.v4;
        let egress = IpAddr::V4(EGRESS);

        let reply = ask(&fcx, &m, a_root, &query(1, "x.home.", RecordType::A, false))
            .await
            .expect("a referral");
        assert_eq!(
            addresses(&reply),
            vec![egress],
            "the glue is relayed as it was"
        );
        assert!(!handle.has_machine(egress));
        assert!(
            ask(
                &fcx,
                &m,
                egress,
                &query(2, "printer.lan.", RecordType::A, false)
            )
            .await
            .is_none()
        );
        assert!(
            hierarchy
                .asked_for("printer.lan.", RecordType::A)
                .is_empty()
        );
        Ok(())
    });
}

/// A resolver follows a delegation whose name server has no glue: the
/// mirror places relays at the glue of the referrals that lead to the
/// name server's address, then at the address answered for it.
#[test]
fn a_glueless_delegation_resolves_through_the_answer_for_its_name_server() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = location();
        let clock = WallClock {
            start: SystemTime::UNIX_EPOCH,
        };
        // The test hierarchy is unsigned.
        let config = Config {
            anchors: None,
            ..Config::unbound()
        }
        .hints(&internet::root_hints());
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let handle = net.handle();
        let mirror = Mirror::new(hierarchy.clone(), handle.clone(), &at);
        net.hosts(internet::root_servers(|s| mirror.relay(s), &at))
            .gateway(move |h, _| h.program(Recursive::new(config.clone(), clock)))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);

        let reply = ask(
            &fcx,
            &m,
            GATEWAY,
            &query(1, "www.example.", RecordType::A, true),
        )
        .await
        .expect("an answer");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.metadata.recursion_available);
        assert_eq!(addresses(&reply), vec![v4(45, 33, 4, 80)]);
        for relay in [v4(45, 33, 1, 53), v4(45, 33, 2, 53), v4(45, 33, 3, 53)] {
            assert!(handle.has_machine(relay), "no relay at {relay}");
        }
        assert_eq!(
            hierarchy.asked_for("ns.provider.org.", RecordType::A),
            vec![v4(45, 33, 2, 53)]
        );
        assert_eq!(
            hierarchy.asked_for("www.example.", RecordType::A),
            vec![v4(45, 33, 3, 53)]
        );
        Ok(())
    });
}

/// A name server whose address a resolver learned before any NS RRset
/// named it still gets its relay once one does: the resolver has the
/// address cached and asks it, without asking for the address again.
#[test]
fn a_glueless_name_server_known_before_its_delegation_gets_a_relay() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = location();
        let clock = WallClock {
            start: SystemTime::UNIX_EPOCH,
        };
        let config = Config {
            anchors: None,
            ..Config::unbound()
        }
        .hints(&internet::root_hints());
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let handle = net.handle();
        let mirror = Mirror::new(hierarchy.clone(), handle.clone(), &at);
        net.hosts(internet::root_servers(|s| mirror.relay(s), &at))
            .gateway(move |h, _| h.program(Recursive::new(config.clone(), clock)))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let server = v4(45, 33, 3, 53);

        let reply = ask(
            &fcx,
            &m,
            GATEWAY,
            &query(1, "ns.provider.org.", RecordType::A, true),
        )
        .await
        .expect("an answer");
        assert_eq!(addresses(&reply), vec![server]);
        assert!(!handle.has_machine(server), "no NS RRset named it yet");

        let reply = ask(
            &fcx,
            &m,
            GATEWAY,
            &query(2, "www.example.", RecordType::A, true),
        )
        .await
        .expect("an answer");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert_eq!(addresses(&reply), vec![v4(45, 33, 4, 80)]);
        assert!(handle.has_machine(server));
        Ok(())
    });
}

/// Glue on the sandboxes' subnet, or at an address no internet host can
/// have, reaches the client as the real server sent it, and no relay is
/// placed there.
#[test]
fn addresses_on_the_sandbox_subnet_or_off_the_internet_are_never_placed() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = location();
        let me = Ipv4Addr::new(45, 60, 0, 2);
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new()
            .ipv4_only()
            .subnet("45.60.0.0/24".parse::<Prefix>()?);
        let handle = net.handle();
        let mirror = Mirror::new(hierarchy.clone(), handle.clone(), &at);
        net.hosts(internet::root_servers(|s| mirror.relay(s), &at))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, me);
        let a_root = ROOT_LETTERS[0].server.v4;

        for (id, name, glue) in [
            (1, "x.lan.", v4(45, 60, 0, 77)),
            (2, "x.private.", v4(192, 168, 1, 53)),
        ] {
            let reply = ask(&fcx, &m, a_root, &query(id, name, RecordType::A, false))
                .await
                .expect("a referral");
            assert_eq!(
                addresses(&reply),
                vec![glue],
                "the glue is relayed as it was"
            );
            assert!(!handle.has_machine(glue), "a relay at {glue}");
            let reply = ask(&fcx, &m, glue, &query(id + 10, name, RecordType::A, false)).await;
            assert!(reply.is_none(), "{glue} answered");
        }
        Ok(())
    });
}

/// The addresses a relayed reply gives for a name with a front get that
/// front, and no relay.
#[test]
fn a_front_goes_at_the_addresses_answered_for_its_name() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = location();
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let handle = net.handle();
        let fronted: Arc<Mutex<Vec<String>>> = Arc::default();
        let seen = fronted.clone();
        let mirror = Mirror::new(hierarchy.clone(), handle.clone(), &at).front(
            Name::from_ascii("cloudflare-dns.com.")?,
            move |host| {
                seen.lock().unwrap().push("cloudflare-dns.com".to_string());
                host
            },
        );
        net.hosts(internet::root_servers(|s| mirror.relay(s), &at))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let a_root = ROOT_LETTERS[0].server.v4;
        let front = v4(45, 33, 6, 6);

        for id in [1, 2] {
            let reply = ask(
                &fcx,
                &m,
                a_root,
                &query(id, "cloudflare-dns.com.", RecordType::A, false),
            )
            .await
            .expect("an answer");
            assert_eq!(addresses(&reply), vec![front]);
        }
        assert!(handle.has_machine(front));
        assert_eq!(fronted.lock().unwrap().len(), 1, "one front per address");
        let reply = ask(
            &fcx,
            &m,
            front,
            &query(3, "cloudflare-dns.com.", RecordType::A, false),
        )
        .await;
        assert!(reply.is_none(), "a relay answered at the front's address");
        Ok(())
    });
}

/// The whoami names of the public resolvers answer from the world's egress
/// and the resolver's own, before any question leaves the resolver.
#[test]
fn whoami_names_are_answered_from_the_egress_and_never_relayed() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = location();
        let clock = WallClock {
            start: SystemTime::UNIX_EPOCH,
        };
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let mirror = Mirror::new(hierarchy.clone(), net.handle(), &at);
        net.hosts(internet::root_servers(|s| mirror.relay(s), &at))
            .hosts(internet::public_resolvers(
                |r, h| h.program(r.recursive(r.config(&at), clock)),
                &at,
            ))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);

        let cloudflare = PUBLIC_RESOLVERS[1].addresses[0].v4;
        let reply = ask(&fcx, &m, cloudflare, &chaos(1, "whoami.cloudflare."))
            .await
            .expect("an answer");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert_eq!(texts(&reply), vec![EGRESS.to_string()]);

        let google = PUBLIC_RESOLVERS[0].addresses[0].v4;
        let reply = ask(
            &fcx,
            &m,
            google,
            &query(2, "o-o.myaddr.l.google.com.", RecordType::TXT, true),
        )
        .await
        .expect("an answer");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        let mut got = texts(&reply);
        got.sort();
        assert_eq!(
            got,
            vec![
                "172.253.1.21".to_string(),
                "edns0-client-subnet 45.70.0.0/24".to_string()
            ]
        );
        assert_eq!(reply.answers[0].ttl, 60);
        assert!(
            !reply.metadata.authoritative,
            "the real resolver's TXT answer has no AA"
        );
        let reply = ask(
            &fcx,
            &m,
            google,
            &query(3, "_dns.resolver.arpa.", RecordType::SVCB, true),
        )
        .await
        .expect("an answer");
        assert!(
            reply.metadata.authoritative,
            "Google sets AA on its DDR answer"
        );

        let asked = hierarchy.asked.lock().unwrap().clone();
        assert!(asked.is_empty(), "the resolvers asked {asked:?}");

        // The preset knows only the TXT RRset there. Other types are asked
        // of the hierarchy, and no SOA or NS RRset is made up for the name.
        for (id, kind) in [
            (4, RecordType::A),
            (5, RecordType::SOA),
            (6, RecordType::NS),
        ] {
            let reply = ask(
                &fcx,
                &m,
                google,
                &query(id, "o-o.myaddr.l.google.com.", kind, true),
            )
            .await
            .expect("an answer");
            let made_up = reply
                .answers
                .iter()
                .chain(&reply.authorities)
                .any(|record| {
                    LowerName::new(&record.name) == lower("o-o.myaddr.l.google.com.")
                        && matches!(record.data, RData::SOA(_) | RData::NS(_))
                });
            assert!(!made_up, "{kind} got {reply:?}");
        }
        assert!(!hierarchy.asked.lock().unwrap().is_empty());
        Ok(())
    });
}

/// A measured location holds what each server that answered says about
/// itself, and leaves out the ones that did not.
#[test]
fn a_measured_location_holds_what_the_servers_say_about_themselves() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = Location::measured(
            &fcx,
            &hierarchy,
            Some(Egress(EGRESS)),
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(at.egress, Some(Egress(EGRESS)));
        // Only the root letters answer in the test hierarchy.
        assert_eq!(at.servers.len(), ROOT_LETTERS.len());
        assert!(at.resolvers.is_empty());
        let a_root = at.site(IpAddr::V4(ROOT_LETTERS[0].server.v4));
        assert_eq!(a_root.identity.nsid, Some(REAL.as_bytes().to_vec()));
        assert_eq!(
            a_root.identity.chaos.get(&lower("id.server.")),
            Some(&fictionet::stdlib::services::dns::authority::ChaosAnswer::Txt(REAL.to_string()))
        );
        let unknown = at.site(IpAddr::V4(GTLD_SERVERS[0].v4));
        assert_eq!(unknown.identity, Identity::none());
        Ok(())
    });
}

/// Real servers that answer CHAOS questions as the San Francisco preset
/// says each root letter does, and nothing else.
struct Letters(Location);

impl Source for Letters {
    fn ask<'a>(
        &'a self,
        _fcx: &'a Cx,
        ask: Ask,
    ) -> Pin<Box<dyn Future<Output = Observed> + Send + 'a>> {
        let Parsed::Request(req) = Request::parse(&ask.query, ask.transport) else {
            panic!("the probe asked something that is not a query");
        };
        let server = ask.server.ip();
        let letter = ROOT_LETTERS
            .iter()
            .any(|l| IpAddr::V4(l.server.v4) == server);
        if !letter || req.question.query_class() != DNSClass::CH {
            return Box::pin(ready(Observed::Unreachable));
        }
        let identity = self.0.site(server).identity;
        let (response, edns) = identity.reply(&req);
        let mut reply = ServerConfig::root(identity).front(&req, response);
        if !edns {
            reply.message.edns = None;
        }
        Box::pin(ready(Observed::Reply(
            reply.message.to_vec().expect("a reply"),
        )))
    }
}

/// A server measured in Live answers each CHAOS question as the real one
/// does, here as the preset plays it: a BIND server serves the names it
/// answers as zones, whatever it says to `id.server`.
#[test]
fn a_measured_bind_server_serves_its_chaos_names_as_zones() {
    world(Duration::from_secs(60), |fcx| async move {
        let real = location();
        let at =
            Location::measured(&fcx, &Letters(real.clone()), None, Duration::from_secs(2)).await;
        // c.root answers id.server; g.root refuses it.
        for server in [v4(192, 33, 4, 12), v4(192, 112, 36, 4)] {
            let (real, measured) = (real.site(server).identity, at.site(server).identity);
            for qname in [
                "id.server.",
                "hostname.bind.",
                "version.bind.",
                "version.server.",
                "authors.bind.",
                "foo.hostname.bind.",
                "invalid.",
            ] {
                for qtype in [
                    RecordType::TXT,
                    RecordType::A,
                    RecordType::SOA,
                    RecordType::NS,
                    RecordType::ANY,
                ] {
                    let mut message = Message::query();
                    let mut question = Query::query(Name::from_ascii(qname).unwrap(), qtype);
                    question.set_query_class(DNSClass::CH);
                    message.add_query(question);
                    let Parsed::Request(req) =
                        Request::parse(&message.to_vec().unwrap(), Transport::Udp)
                    else {
                        panic!("a query");
                    };
                    let (want, _) = real.reply(&req);
                    let (got, _) = measured.reply(&req);
                    let case = format!("{server} {qname} {qtype}: {got:?}");
                    assert_eq!(
                        got.message.metadata.response_code, want.message.metadata.response_code,
                        "{case}"
                    );
                    assert_eq!(
                        got.message.metadata.authoritative, want.message.metadata.authoritative,
                        "{case}"
                    );
                    assert_eq!(got.message.answers, want.message.answers, "{case}");
                    assert_eq!(got.message.authorities, want.message.authorities, "{case}");
                }
            }
        }
        Ok(())
    });
}

/// A real server that echoes the address a question came from would see
/// a public resolver's own egress, not the world's: `whoami.direct` plays
/// such a server, answering with the address the source asks from.
#[test]
fn an_echoed_address_is_the_public_resolvers_egress() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = location();
        let clock = WallClock {
            start: SystemTime::UNIX_EPOCH,
        };
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let mirror = Mirror::new(hierarchy.clone(), net.handle(), &at);
        // The test root is unsigned, so the resolvers do not validate.
        net.hosts(internet::root_servers(|s| mirror.relay(s), &at))
            .hosts(internet::public_resolvers(
                |r, h| {
                    let config = Config {
                        anchors: None,
                        ..r.config(&at)
                    };
                    h.program(Recursive::new(config, clock))
                },
                &at,
            ))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let cloudflare = PUBLIC_RESOLVERS[1].addresses[0].v4;
        let seen = v4(172, 69, 133, 100);

        let reply = ask(
            &fcx,
            &m,
            cloudflare,
            &query(1, "whoami.direct.", RecordType::A, true),
        )
        .await
        .expect("an answer");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert_eq!(addresses(&reply), vec![seen]);
        let reply = ask(
            &fcx,
            &m,
            cloudflare,
            &query(2, "whoami.direct.", RecordType::TXT, true),
        )
        .await
        .expect("an answer");
        assert_eq!(texts(&reply), vec![seen.to_string()]);
        Ok(())
    });
}

/// Two sandboxes asking a public resolver the same name each fill their
/// own cache: one sandbox's second question is answered from its cache,
/// and the other sandbox's first is resolved again. The test root is
/// unsigned and the preset validates from the IANA root anchor, so every
/// answer is SERVFAIL, a failure the cache keeps as it keeps answers
/// (RFC 9520).
#[test]
fn public_resolvers_keep_one_cache_per_sandbox() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = location();
        let clock = WallClock {
            start: SystemTime::UNIX_EPOCH,
        };
        let replies: Arc<Mutex<Vec<(u64, bool)>>> = Arc::default();
        let kept = replies.clone();
        let record = Arc::new(move |event: &Event| {
            if let Event::Reply { client, cached, .. } = event {
                let sandbox = client.sandbox.as_ref().map_or(0, |sandbox| sandbox.id);
                kept.lock().unwrap().push((sandbox, *cached));
            }
        });
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let mirror = Mirror::new(hierarchy.clone(), net.handle(), &at);
        net.hosts(internet::root_servers(|s| mirror.relay(s), &at))
            .hosts(internet::public_resolvers(
                |r, h| {
                    let record = record.clone();
                    h.program(
                        r.recursive(r.config(&at), clock)
                            .on_event(move |event| record(event)),
                    )
                },
                &at,
            ))
            .start(&fcx, attachments)?;
        let a = machine(&fcx, attacher.attach("a")?, ME);
        let b = machine(&fcx, attacher.attach("b")?, Ipv4Addr::new(10, 0, 0, 3));
        let google = PUBLIC_RESOLVERS[0].addresses[0].v4;

        for (id, m) in [(1, &a), (2, &a), (3, &b)] {
            let reply = ask(
                &fcx,
                m,
                google,
                &query(id, "www.direct.", RecordType::A, true),
            )
            .await
            .expect("an answer");
            assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
        }
        let replies = replies.lock().unwrap().clone();
        let cached: Vec<bool> = replies.iter().map(|(_, cached)| *cached).collect();
        assert_eq!(cached, vec![false, true, false], "{replies:?}");
        assert_eq!(replies[0].0, replies[1].0);
        assert_ne!(replies[0].0, replies[2].0, "two sandboxes");
        let www = v4(45, 33, 5, 53);
        let asked = hierarchy.asked_for("www.direct.", RecordType::A);
        assert_eq!(asked, vec![www, www], "once per sandbox");
        Ok(())
    });
}
