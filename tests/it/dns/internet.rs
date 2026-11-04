//! The internet presets on a simulated network: a root letter copying a
//! hierarchy, the mirror placing servers where replies name them, and the
//! public resolvers' whoami names and per-sandbox caches. The real
//! hierarchy is played by an upstream that answers from fixed zones.

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
use fictionet::stdlib::services::dns::authority::{Identity, Observe, ServerConfig};
use fictionet::stdlib::services::dns::resolver::Config;
use fictionet::stdlib::services::dns::zone::{
    Answered, AnyResponse, Filing, Section, Zone, ZoneData, answer,
};
use fictionet::stdlib::services::dns::{Client, Event, Generation, Looked, Lookup, WallClock};
use fictionet::stdlib::services::serve::Transport;
use fictionet::stdlib::world::net::dns::internet::{self, Mirror, NameServer, ROOT_SERVERS};
use fictionet::stdlib::world::net::dns::{self, Recursive, Upstream};
use fictionet::stdlib::world::net::{Host, Net, NetHandle};
use fictionet_extras::dns::place::{Place, ResolverSite};
use fictionet_extras::dns::public::{PUBLIC_RESOLVERS, PublicResolver};
use fictionet_extras::dns::roots::{self, GTLD_SERVERS};
use fictionet_extras::dns::unbound;
use fictionet_test_support::sandbox::{Machine, machine};
use fictionet_test_support::timeout;

use crate::common::world::world;

const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const EGRESS: Ipv4Addr = Ipv4Addr::new(45, 70, 0, 9);

/// The root zone the upstream answers for at every root letter: the root
/// servers, `example.` delegated without glue to a server under `org.`,
/// `org.` and `direct.` with glue, `lan.` and `private.` with glue no
/// internet host can be at, `home.` with the egress as its glue, and names
/// with addresses, `web.` at the address of `org.`'s name server.
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
alias-dns.com. 300 IN CNAME cloudflare-dns.com.
renamed. 300 IN DNAME com.
doh.com. 300 IN A 45.33.6.7
plain. 300 IN A 45.33.7.7
web. 300 IN A 45.33.1.53
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
home.direct. 300 IN A 45.70.0.9
whoami.v4.direct. 300 IN TXT \"45.70.0.9\"
bin.direct. 300 IN TXT \"45.70.0.9\" \"\\255\\254\"
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
        let letters = ROOT_SERVERS
            .iter()
            .map(|letter| IpAddr::V4(letter.v4))
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

impl Upstream for Hierarchy {
    fn lookup<'a>(
        &'a self,
        _fcx: &'a Cx,
        lookup: Lookup,
    ) -> Pin<Box<dyn Future<Output = Looked> + Send + 'a>> {
        let req = request(&lookup);
        let server = lookup.server.ip();
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
            return Box::pin(ready(Looked::Unreachable));
        };
        // Every real server here is the instance `REAL`, by CHAOS name and
        // by NSID.
        let front = ServerConfig {
            identity: Identity {
                nsid: Some(REAL.as_bytes().to_vec()),
                ..Identity::none()
            },
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
        Box::pin(ready(Looked::Response(reply.message)))
    }
}

/// The query an upstream sends for `lookup`: its question without
/// recursion, and an OPT record with DO.
fn request(lookup: &Lookup) -> Request {
    let mut message = Message::query();
    message.metadata.id = 1;
    message.add_query(lookup.question.clone());
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true);
    message.set_edns(edns);
    let Parsed::Request(req) = Request::parse(&message.to_vec().unwrap(), Transport::Udp) else {
        panic!("a lookup's query parses");
    };
    req
}

/// The instance every real server of [`Hierarchy`] is.
const REAL: &str = "real-uklon";

fn lower(name: &str) -> LowerName {
    LowerName::new(&Name::from_ascii(name).unwrap())
}

/// Where the tests' network is: the San Francisco Bay Area.
fn place() -> Place {
    Place::san_francisco_bay_area()
}

/// The configuration `resolver` runs with at `site`, its whoami names
/// answered for a network behind [`EGRESS`].
fn resolver_config(resolver: &PublicResolver, site: &ResolverSite) -> Config {
    resolver.whoami(resolver.config(site.identity.clone()), site, EGRESS)
}

/// A mirror of `upstream` placing servers with `handle`, as a world that
/// shows the real internet from [`place`] through [`EGRESS`] makes it:
/// the root at every root letter, `com` and `net` at every
/// `gtld-servers.net` server, each placed server behind half the round
/// trip to an authority, no server at the egress, and each public
/// resolver shown its own egress where a real server echoes the asker,
/// as `whoami.direct` does.
fn mirror(upstream: impl Upstream, handle: NetHandle) -> Mirror {
    let at = place();
    let echo = at
        .echo(EGRESS)
        .name(&Name::from_ascii("whoami.direct.").unwrap());
    roots::seed(
        Mirror::new(upstream, handle)
            .delay(at.authority_rtt / 2)
            .egress(IpAddr::V4(EGRESS))
            .wrap(move |authority| echo.over(authority)),
    )
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
/// space is not. The NAT64 Well-Known Prefix holds only global IPv4
/// addresses (RFC 6052 §3.1), so a non-global one there is no host's
/// either.
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
        "64:ff9b::7f00:1",
        "64:ff9b::a00:1",
        "64:ff9b::c0a8:101",
        "64:ff9b::a9fe:a9fe",
    ] {
        assert!(non_public_address(address.parse().unwrap()), "{address}");
    }
    for address in [
        "45.33.4.80",
        "192.0.0.9",
        "2606:4700:4700::1111",
        "64:ff9b::2d21:450",
    ] {
        assert!(!non_public_address(address.parse().unwrap()), "{address}");
    }
}

/// The resolver hints, the hints a configuration starts from, and the
/// root letters the extras give fronts to name the same servers at the
/// same addresses.
#[test]
fn the_root_hints_are_the_root_letters() {
    let letters: Vec<(Name, IpAddr)> = ROOT_SERVERS
        .iter()
        .flat_map(|letter| {
            let name = letter.name();
            letter.addresses().map(|addr| (name.clone(), addr))
        })
        .collect();
    assert_eq!(internet::root_hints(), letters);
    assert_eq!(Config::new().hints, letters);
    assert_eq!(unbound::config().hints, letters);
    let fronted: Vec<NameServer> = roots::ROOT_LETTERS
        .iter()
        .map(|letter| letter.server)
        .collect();
    assert_eq!(fronted, ROOT_SERVERS);
}

/// `dig @198.41.0.4 . NS` at a root letter copying the hierarchy: the
/// real server's answer, every root server with its address, after the
/// round trip the location gives a.root, and `id.server` answered from
/// the site that answers there without asking the upstream.
#[test]
fn a_root_letter_answers_the_root_ns_as_dig_sees_it() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = place();
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let mirror = mirror(hierarchy.clone(), net.handle());
        net.hosts(at.root_servers(|s| mirror.server(s)))
            .hosts(at.gtld_servers(|s| mirror.server(s)))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let a_root = ROOT_SERVERS[0].v4;

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
        let expected: Vec<String> = ROOT_SERVERS
            .iter()
            .map(|letter| letter.host.to_string())
            .collect();
        let mut sorted = servers.clone();
        sorted.sort();
        assert_eq!(sorted, expected);
        let mut glue = addresses(&reply);
        glue.sort();
        let mut letters: Vec<IpAddr> = ROOT_SERVERS
            .iter()
            .map(|letter| IpAddr::V4(letter.v4))
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
            "CHAOS is never looked up"
        );
        Ok(())
    });
}

/// The NSID and the CHAOS names of one address name one instance: a root
/// letter's preset site for both, never the real instance's NSID next to
/// the preset's CHAOS names. A server the mirror placed answers from
/// copied records, so it speaks for no real instance: CHAOS questions get
/// REFUSED from its front, a reply carries no NSID, and no CHAOS question
/// is ever looked up.
#[test]
fn a_mirrored_server_names_one_instance_by_chaos_and_by_nsid() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = place();
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let mirror = mirror(hierarchy.clone(), net.handle());
        net.hosts(at.root_servers(|s| mirror.server(s)))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let a_root = ROOT_SERVERS[0].v4;
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

        // The referral to `direct.` places a server at its glue, which
        // answers from what it copied and never as the real instance.
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
            .expect("an answer from the placed server");
        assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
        assert!(texts(&reply).is_empty());
        let mut www = query(5, "www.direct.", RecordType::A, false);
        www.edns
            .as_mut()
            .unwrap()
            .options_mut()
            .insert(Nsid(Vec::new()).to_option());
        let reply = ask(&fcx, &m, ns, &www).await.expect("an answer");
        assert_eq!(addresses(&reply), vec![v4(45, 33, 5, 80)]);
        assert_eq!(nsid(&reply), None);
        let chaos_looked_up = hierarchy
            .asked
            .lock()
            .unwrap()
            .iter()
            .any(|(_, name, _)| *name == lower("hostname.bind."));
        assert!(!chaos_looked_up);
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
                Answered::Unknown { name, .. } => panic!("{name} is unknown"),
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

/// The root zone of `placing` answers its own NS RRset, which names the
/// root itself (RFC 6303 §3): the view knows that no host has the name
/// of the NS target, so nothing goes in the additional section.
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
        assert_eq!(ns, vec![".".to_string()]);
        assert!(reply.additionals.is_empty());
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

/// A referral with glue, once filed, places a server at the glue address
/// before the referral reaches the client, so the client's next question
/// to that address is answered. An answer for a name no NS RRset named
/// places nothing.
#[test]
fn the_mirror_places_a_server_at_referral_glue_before_the_reply_leaves() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = place();
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let handle = net.handle();
        let mirror = mirror(hierarchy.clone(), handle.clone());
        net.hosts(at.root_servers(|s| mirror.server(s)))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let a_root = ROOT_SERVERS[0].v4;
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
            "the server is placed with the referral"
        );

        let reply = ask(&fcx, &m, ns, &query(2, "www.direct.", RecordType::A, false))
            .await
            .expect("an answer from the placed server");
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

/// The mirror knows the names of its name servers, the targets of the NS
/// RRsets it filed, before an observer sees the filing that named them.
/// A web name at a name server's address is none of them.
#[test]
fn the_mirror_knows_its_server_names_before_observers_run() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = place();
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let handle = net.handle();
        let ns = v4(45, 33, 5, 53);
        let ns_name = LowerName::new(&Name::from_ascii("ns.direct.").unwrap());
        let www = LowerName::new(&Name::from_ascii("www.direct.").unwrap());
        let mirror = mirror(hierarchy.clone(), handle.clone());
        let servers = mirror.servers();
        let seen: Arc<Mutex<Vec<bool>>> = Arc::default();
        let mirror = {
            let (servers, seen, ns_name) = (servers.clone(), seen.clone(), ns_name.clone());
            mirror.observe(move |_| {
                seen.lock()
                    .unwrap()
                    .push(servers.named(Generation(0), &ns_name))
            })
        };
        net.hosts(at.root_servers(|s| mirror.server(s)))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let a_root = ROOT_SERVERS[0].v4;
        assert!(!servers.named(Generation(0), &ns_name));

        ask(
            &fcx,
            &m,
            a_root,
            &query(1, "www.direct.", RecordType::A, false),
        )
        .await
        .expect("a referral");
        let seen = seen.lock().unwrap().clone();
        assert!(
            !seen.is_empty() && seen.iter().all(|&known| known),
            "{seen:?}"
        );

        let reply = ask(&fcx, &m, ns, &query(2, "www.direct.", RecordType::A, false))
            .await
            .expect("an answer");
        assert_eq!(addresses(&reply), vec![v4(45, 33, 5, 80)]);
        assert!(servers.named(Generation(0), &ns_name));
        assert!(!servers.named(Generation(0), &www));
        Ok(())
    });
}

/// A zone transfer asked of a mirrored name server is refused: zone data
/// makes answers to questions, never a listing of a whole zone, and no
/// transfer is ever looked up at the real server.
#[test]
fn a_mirrored_name_server_refuses_zone_transfers() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = place();
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let mirror = mirror(hierarchy.clone(), net.handle());
        net.hosts(at.root_servers(|s| mirror.server(s)))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let a_root = ROOT_SERVERS[0].v4;
        let ns = v4(45, 33, 5, 53);
        ask(
            &fcx,
            &m,
            a_root,
            &query(1, "www.direct.", RecordType::A, false),
        )
        .await
        .expect("a referral that places the server");

        let mut transfer = Message::query();
        transfer.metadata.id = 2;
        transfer.add_query(Query::query(
            Name::from_ascii("direct.").unwrap(),
            RecordType::AXFR,
        ));
        let replies = super::slices::tcp(
            &fcx,
            &m,
            SocketAddr::new(ns, 53),
            &[transfer.to_vec().unwrap()],
        )
        .await;
        let reply = Message::from_vec(&replies[0]).unwrap();
        assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
        assert!(hierarchy.asked_for("direct.", RecordType::AXFR).is_empty());
        Ok(())
    });
}

/// A referral whose glue is the location's own egress places no server
/// there, so no question is ever sent from the host to its own public
/// address.
#[test]
fn the_mirror_places_no_server_at_the_egress() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = place();
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let handle = net.handle();
        let mirror = mirror(hierarchy.clone(), handle.clone());
        net.hosts(at.root_servers(|s| mirror.server(s)))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let a_root = ROOT_SERVERS[0].v4;
        let egress = IpAddr::V4(EGRESS);

        let reply = ask(&fcx, &m, a_root, &query(1, "x.home.", RecordType::A, false))
            .await
            .expect("a referral");
        assert_eq!(
            addresses(&reply),
            vec![egress],
            "the glue goes out as it was"
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
/// mirror places servers at the glue of the referrals that lead to the
/// name server's address, then at the address answered for it.
#[test]
fn a_glueless_delegation_resolves_through_the_answer_for_its_name_server() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = place();
        let clock = WallClock {
            start: SystemTime::UNIX_EPOCH,
        };
        // The test hierarchy is unsigned.
        let config = Config {
            anchors: None,
            ..unbound::config()
        };
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let handle = net.handle();
        let mirror = mirror(hierarchy.clone(), handle.clone());
        net.hosts(at.root_servers(|s| mirror.server(s)))
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
        for server in [v4(45, 33, 1, 53), v4(45, 33, 2, 53), v4(45, 33, 3, 53)] {
            assert!(handle.has_machine(server), "no server at {server}");
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
/// named it still gets its server once one does: the resolver has the
/// address cached and asks it, without asking for the address again.
#[test]
fn a_glueless_name_server_known_before_its_delegation_gets_a_server() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = place();
        let clock = WallClock {
            start: SystemTime::UNIX_EPOCH,
        };
        let config = Config {
            anchors: None,
            ..unbound::config()
        };
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let handle = net.handle();
        let mirror = mirror(hierarchy.clone(), handle.clone());
        net.hosts(at.root_servers(|s| mirror.server(s)))
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

/// A machine a world placed at a name's address before any referral named
/// that address a name server's, as a world places web sites, still gets
/// the name server once a referral does: the server joins the machine,
/// and the delegation resolves.
#[test]
fn a_name_server_joins_a_site_placed_at_its_address_first() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = place();
        let clock = WallClock {
            start: SystemTime::UNIX_EPOCH,
        };
        let config = Config {
            anchors: None,
            ..unbound::config()
        };
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let handle = net.handle();
        let sites = handle.clone();
        // A site at each address an answer gives, as a world that serves
        // web pages places them.
        let mirror = mirror(hierarchy.clone(), handle.clone()).observe(move |filing| {
            for (section, set) in &filing.sets {
                for record in set.records_without_rrsigs() {
                    if let (Section::Answer, RData::A(a)) = (section, &record.data) {
                        let _ = sites.add_host(Host::new("site").at(a.0).ipv4_only());
                    }
                }
            }
        });
        net.hosts(at.root_servers(|s| mirror.server(s)))
            .gateway(move |h, _| h.program(Recursive::new(config.clone(), clock)))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let org = v4(45, 33, 1, 53);

        let reply = ask(&fcx, &m, GATEWAY, &query(1, "web.", RecordType::A, true))
            .await
            .expect("an answer");
        assert_eq!(addresses(&reply), vec![org]);
        assert!(handle.has_machine(org), "the site is placed");

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
        assert!(
            !hierarchy
                .asked_for("ns.provider.org.", RecordType::A)
                .is_empty()
        );
        Ok(())
    });
}

/// Glue on the sandboxes' subnet, or at an address no internet host can
/// have, reaches the client as the real server sent it, and no server is
/// placed there.
#[test]
fn addresses_on_the_sandbox_subnet_or_off_the_internet_are_never_placed() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = place();
        let me = Ipv4Addr::new(45, 60, 0, 2);
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new()
            .ipv4_only()
            .subnet("45.60.0.0/24".parse::<Prefix>()?);
        let handle = net.handle();
        let mirror = mirror(hierarchy.clone(), handle.clone());
        net.hosts(at.root_servers(|s| mirror.server(s)))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, me);
        let a_root = ROOT_SERVERS[0].v4;

        for (id, name, glue) in [
            (1, "x.lan.", v4(45, 60, 0, 77)),
            (2, "x.private.", v4(192, 168, 1, 53)),
        ] {
            let reply = ask(&fcx, &m, a_root, &query(id, name, RecordType::A, false))
                .await
                .expect("a referral");
            assert_eq!(addresses(&reply), vec![glue], "the glue goes out as it was");
            assert!(!handle.has_machine(glue), "a server at {glue}");
            let reply = ask(&fcx, &m, glue, &query(id + 10, name, RecordType::A, false)).await;
            assert!(reply.is_none(), "{glue} answered");
        }
        Ok(())
    });
}

/// The addresses filed for a name with a front get that front, and no
/// server.
#[test]
fn a_front_goes_at_the_addresses_answered_for_its_name() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = place();
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let handle = net.handle();
        let fronted: Arc<Mutex<Vec<String>>> = Arc::default();
        let seen = fronted.clone();
        let mirror = mirror(hierarchy.clone(), handle.clone()).front(
            Name::from_ascii("cloudflare-dns.com.")?,
            move |host| {
                seen.lock().unwrap().push("cloudflare-dns.com".to_string());
                host
            },
        );
        net.hosts(at.root_servers(|s| mirror.server(s)))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let a_root = ROOT_SERVERS[0].v4;
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
        assert!(reply.is_none(), "a server answered at the front's address");
        Ok(())
    });
}

/// A front's name that is an alias gets its front at the addresses filed
/// for the name its CNAME chain ends at.
#[test]
fn a_front_for_an_alias_goes_at_its_targets_addresses() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = place();
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let handle = net.handle();
        let mirror = mirror(hierarchy.clone(), handle.clone())
            .front(Name::from_ascii("alias-dns.com.")?, |host| host);
        net.hosts(at.root_servers(|s| mirror.server(s)))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let a_root = ROOT_SERVERS[0].v4;
        let front = v4(45, 33, 6, 6);

        assert!(!handle.has_machine(front));
        let reply = ask(
            &fcx,
            &m,
            a_root,
            &query(1, "alias-dns.com.", RecordType::A, false),
        )
        .await
        .expect("an answer");
        assert_eq!(addresses(&reply), vec![front]);
        assert!(handle.has_machine(front), "the front is placed");
        Ok(())
    });
}

/// A front's name below a DNAME gets its front at the addresses filed
/// for the name the DNAME substitutes for it (RFC 6672 §2.2), although
/// the copy keeps the DNAME and not the CNAME synthesized from it.
#[test]
fn a_front_below_a_dname_goes_at_its_substitutes_addresses() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = place();
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let handle = net.handle();
        let mirror = mirror(hierarchy.clone(), handle.clone())
            .front(Name::from_ascii("doh.renamed.")?, |host| host);
        net.hosts(at.root_servers(|s| mirror.server(s)))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let a_root = ROOT_SERVERS[0].v4;
        let front = v4(45, 33, 6, 7);

        assert!(!handle.has_machine(front));
        let reply = ask(
            &fcx,
            &m,
            a_root,
            &query(1, "doh.renamed.", RecordType::A, false),
        )
        .await
        .expect("an answer");
        assert_eq!(addresses(&reply), vec![front]);
        assert!(handle.has_machine(front), "the front is placed");
        Ok(())
    });
}

/// A filing as a test compares it: its zone, and the section, owner, and
/// type of each RRset it kept.
type Kept = (String, Vec<(Section, String, RecordType)>);

/// The mirror's observers see what each response gave a mirrored zone,
/// as the zone keeps it, before the reply that needed it leaves: the
/// root's referral to `direct.` with its glue, then the answer of the
/// server placed at that glue. A lookup that the world's policy keeps
/// from leaving files nothing, and the observers see nothing.
#[test]
fn observers_see_each_filing_before_the_reply_leaves() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = place();
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let handle = net.handle();
        let filings: Arc<Mutex<Vec<Kept>>> = Arc::default();
        let seen = filings.clone();
        let refused = lower("plain.");
        let upstream = dns::Only::new(
            move |lookup: &Lookup| LowerName::new(lookup.question.name()) != refused,
            hierarchy.clone(),
        );
        let mirror = mirror(upstream, handle.clone()).observe(move |filing: &Filing| {
            let sets = filing
                .sets
                .iter()
                .map(|(section, set)| (*section, set.name().to_ascii(), set.record_type()))
                .collect();
            seen.lock().unwrap().push((filing.zone.to_ascii(), sets));
        });
        net.hosts(at.root_servers(|s| mirror.server(s)))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let a_root = ROOT_SERVERS[0].v4;
        let ns = v4(45, 33, 5, 53);

        ask(
            &fcx,
            &m,
            a_root,
            &query(1, "www.direct.", RecordType::A, false),
        )
        .await
        .expect("a referral");
        assert_eq!(
            filings.lock().unwrap().clone(),
            vec![(
                ".".to_string(),
                vec![
                    (Section::Authority, "direct.".to_string(), RecordType::NS),
                    (Section::Additional, "ns.direct.".to_string(), RecordType::A),
                ]
            )]
        );
        ask(&fcx, &m, ns, &query(2, "www.direct.", RecordType::A, false))
            .await
            .expect("an answer");
        let last = filings.lock().unwrap().last().cloned().expect("a filing");
        assert_eq!(last.0, "direct.");
        assert!(
            last.1
                .contains(&(Section::Answer, "www.direct.".to_string(), RecordType::A)),
            "{last:?}"
        );

        let count = filings.lock().unwrap().len();
        let reply = ask(&fcx, &m, a_root, &query(3, "plain.", RecordType::A, false)).await;
        assert!(reply.is_none(), "a refused lookup leaves the server silent");
        assert_eq!(filings.lock().unwrap().len(), count, "nothing filed");
        assert!(hierarchy.asked_for("plain.", RecordType::A).is_empty());
        Ok(())
    });
}

/// The whoami names of the public resolvers answer from the world's egress
/// and the resolver's own, before any question leaves the resolver.
#[test]
fn whoami_names_are_answered_from_the_egress_and_never_looked_up() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = place();
        let clock = WallClock {
            start: SystemTime::UNIX_EPOCH,
        };
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let mirror = mirror(hierarchy.clone(), net.handle());
        net.hosts(at.root_servers(|s| mirror.server(s)))
            .hosts(at.public_resolvers(|r, site, h| {
                h.program(Recursive::new(resolver_config(r, site), clock).per_sandbox())
            }))
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

/// A real server that echoes the address a question came from would see
/// a public resolver's own egress, not the world's: `whoami.direct` plays
/// such a server, answering with the address the upstream asks from.
/// Every public resolver shows its own IPv4 egress, and none shows the
/// world's, also in the TXT string of `whoami.v4.direct`, a name the echo
/// was not given, as `whoami.v4.powerdns.org` gives it. `home.direct` is
/// an A record of real data that holds the upstream's address, and every
/// resolver answers it as the real server does. The other strings of an
/// echoed TXT record keep their octets, UTF-8 or not.
#[test]
fn an_echoed_address_is_the_public_resolvers_egress() {
    world(Duration::from_secs(60), |fcx| async move {
        let hierarchy = Hierarchy::new();
        let at = place();
        let clock = WallClock {
            start: SystemTime::UNIX_EPOCH,
        };
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let mirror = mirror(hierarchy.clone(), net.handle());
        // The test root is unsigned, so the resolvers do not validate.
        net.hosts(at.root_servers(|s| mirror.server(s)))
            .hosts(at.public_resolvers(|r, site, h| {
                let config = Config {
                    anchors: None,
                    ..resolver_config(r, site)
                };
                h.program(Recursive::new(config, clock))
            }))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        assert_eq!(
            at.resolver(PUBLIC_RESOLVERS[1].addresses[0].v4).egress,
            Ipv4Addr::new(172, 69, 133, 100)
        );
        for (index, resolver) in PUBLIC_RESOLVERS.iter().enumerate() {
            let address = resolver.addresses[0].v4;
            let seen = at.resolver(address).egress;
            assert_ne!(seen, EGRESS, "{address}");
            let id = 2 * u16::try_from(index).unwrap();
            let reply = ask(
                &fcx,
                &m,
                address,
                &query(id, "whoami.direct.", RecordType::A, true),
            )
            .await
            .expect("an answer");
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::NoError,
                "{address}"
            );
            assert_eq!(addresses(&reply), vec![IpAddr::V4(seen)], "{address}");
            let reply = ask(
                &fcx,
                &m,
                address,
                &query(id + 1, "whoami.direct.", RecordType::TXT, true),
            )
            .await
            .expect("an answer");
            assert_eq!(texts(&reply), vec![seen.to_string()], "{address}");
            let reply = ask(
                &fcx,
                &m,
                address,
                &query(id + 200, "whoami.v4.direct.", RecordType::TXT, true),
            )
            .await
            .expect("an answer");
            assert_eq!(texts(&reply), vec![seen.to_string()], "{address}");
            let reply = ask(
                &fcx,
                &m,
                address,
                &query(id + 300, "bin.direct.", RecordType::TXT, true),
            )
            .await
            .expect("an answer");
            let strings: Vec<Vec<u8>> = reply
                .answers
                .iter()
                .filter_map(|record| match &record.data {
                    RData::TXT(txt) => Some(txt.txt_data.iter().map(|s| s.to_vec())),
                    _ => None,
                })
                .flatten()
                .collect();
            assert_eq!(
                strings,
                vec![seen.to_string().into_bytes(), vec![255, 254]],
                "{address}"
            );
            let reply = ask(
                &fcx,
                &m,
                address,
                &query(id + 100, "home.direct.", RecordType::A, true),
            )
            .await
            .expect("an answer");
            assert_eq!(addresses(&reply), vec![IpAddr::V4(EGRESS)], "{address}");
        }
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
        let at = place();
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
        // The mirrored servers' replies to `www.direct. A`, by the server
        // that gave each.
        let served_www: Arc<Mutex<Vec<IpAddr>>> = Arc::default();
        let served = served_www.clone();
        let (attacher, attachments) = fictionet::attachments();
        let net = Net::new().ipv4_only();
        let mirror = mirror(hierarchy.clone(), net.handle()).wrap(move |authority| {
            let served = served.clone();
            Arc::new(Observe::new(
                authority,
                move |req: &Request, client: &Client, reply: &Response| {
                    let www = Name::from_ascii("www.direct.").unwrap();
                    let asked =
                        req.question.name() == &www && req.question.query_type() == RecordType::A;
                    if asked && reply.message.metadata.authoritative {
                        served.lock().unwrap().push(client.local.ip());
                    }
                },
            ))
        });
        net.hosts(at.root_servers(|s| mirror.server(s)))
            .hosts(at.public_resolvers(|r, site, h| {
                let record = record.clone();
                h.program(
                    Recursive::new(resolver_config(r, site), clock)
                        .per_sandbox()
                        .on_event(move |event| record(event)),
                )
            }))
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
        let served = served_www.lock().unwrap().clone();
        assert_eq!(served, vec![www, www], "resolved once per sandbox");
        // Both resolutions read the one copy of `direct.`: the real server
        // was asked once.
        let asked = hierarchy.asked_for("www.direct.", RecordType::A);
        assert_eq!(asked, vec![www]);
        Ok(())
    });
}
