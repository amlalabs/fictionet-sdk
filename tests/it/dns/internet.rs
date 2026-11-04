//! The internet presets on a simulated network: the root hints, which
//! addresses a public host can have, the placing root, and per-session
//! state. The mirror of the real hierarchy is tested in
//! `fictionet-extras`.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use fictionet::stdlib::protocols::dns::op::{Edns, Message, Query, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::{Name, RData, RecordType};
use fictionet::stdlib::protocols::dns::{Parsed, Request};
use fictionet::stdlib::services::dns::Generation;
use fictionet::stdlib::services::dns::resolver::Config;
use fictionet::stdlib::services::dns::zone::{Answered, AnyResponse, ZoneData, answer};
use fictionet::stdlib::services::serve::Transport;
use fictionet::stdlib::world::net::dns;
use fictionet::stdlib::world::net::dns::internet::{self, NameServer, ROOT_SERVERS};
use fictionet::stdlib::world::net::{Host, Net};
use fictionet_extras::dns::roots;
use fictionet_extras::dns::unbound;
use fictionet_test_support::world::world;

/// A query for `name` of type `kind`, with RD as given and an OPT record.
fn query(id: u16, name: &str, kind: RecordType, rd: bool) -> Message {
    let mut query = Message::query();
    query.metadata.id = id;
    query.metadata.recursion_desired = rd;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    query.set_edns(Edns::new());
    query
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
