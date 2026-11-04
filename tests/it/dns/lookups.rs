//! An authority's lookups on a simulated network with a fake upstream:
//! a lookup the world's policy refuses leaves the server silent, and a
//! namespace advance drops what the lookups filed.

use std::future::{Future, ready};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fictionet::Cx;
use fictionet::stdlib::protocols::dns::op::{Message, MessageType, OpCode, Query};
use fictionet::stdlib::protocols::dns::rr::rdata::A;
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData, Record, RecordType};
use fictionet::stdlib::services::dns::authority::ServerConfig;
use fictionet::stdlib::services::dns::{Looked, Lookup, WallClock};
use fictionet::stdlib::world::net::Net;
use fictionet::stdlib::world::net::dns::{Authoritative, Namespace, Only, Upstream};
use fictionet_test_support::lookup_authority::LookupAuthority;
use fictionet_test_support::sandbox::{Machine, machine};
use fictionet_test_support::timeout;
use fictionet_test_support::world::world;

const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

fn lower(text: &str) -> LowerName {
    LowerName::new(&name(text))
}

/// An upstream that answers every lookup with one A record whose address
/// ends in how many lookups it has answered, and keeps each lookup.
#[derive(Clone, Default)]
struct Counting {
    asked: Arc<Mutex<Vec<Lookup>>>,
}

impl Upstream for Counting {
    fn lookup<'a>(
        &'a self,
        _fcx: &'a Cx,
        lookup: Lookup,
    ) -> Pin<Box<dyn Future<Output = Looked> + Send + 'a>> {
        let mut asked = self.asked.lock().unwrap();
        asked.push(lookup.clone());
        let mut response = Message::response(1, OpCode::Query);
        response.metadata.authoritative = true;
        response.add_query(lookup.question.clone());
        let last = u8::try_from(asked.len()).unwrap();
        response.add_answer(Record::from_rdata(
            lookup.question.name().clone(),
            300,
            RData::A(A::new(203, 0, 113, last)),
        ));
        Box::pin(ready(Looked::Response(response)))
    }
}

/// What `server` answers a query for `qname` A over UDP, if it answers
/// within two seconds.
async fn ask(fcx: &Cx, m: &Machine, server: SocketAddr, id: u16, qname: &str) -> Option<Message> {
    let mut query = Message::new(id, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(name(qname), RecordType::A));
    let mut socket = m.udp.bind(0).ok()?;
    socket.send_to(&query.to_vec().ok()?, server);
    let (bytes, _) = timeout(fcx, Duration::from_secs(2), socket.recv(fcx))
        .await?
        .ok()?;
    Message::from_vec(&bytes).ok()
}

fn addresses(reply: &Message) -> Vec<IpAddr> {
    reply
        .answers
        .iter()
        .filter_map(|record| record.data.ip_addr())
        .collect()
}

/// A lookup the world's policy refuses never reaches the upstream, and
/// the server that needed it stays silent, now and when asked again:
/// it never answers NXDOMAIN for what it could not learn.
#[test]
fn a_policy_refused_lookup_leaves_the_server_silent() {
    world(Duration::from_secs(60), |fcx| async move {
        let address = Ipv4Addr::new(203, 0, 113, 53);
        let upstream = Counting::default();
        let allowed = lower("allowed.example.");
        let policy =
            move |lookup: &Lookup| allowed.zone_of(&LowerName::new(lookup.question.name()));
        let zones = LookupAuthority::new("example.");
        let program = Authoritative::new(zones, ServerConfig::generic())
            .upstream(Only::new(policy, upstream.clone()));
        let (attacher, attachments) = fictionet::attachments();
        Net::new()
            .ipv4_only()
            .host("copy", |h| h.at(address).program(program))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let server = SocketAddr::new(address.into(), 53);

        let reply = ask(&fcx, &m, server, 1, "www.allowed.example.")
            .await
            .expect("an answer");
        assert_eq!(
            addresses(&reply),
            [IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))]
        );
        for id in [2, 3] {
            let reply = ask(&fcx, &m, server, id, "www.refused.example.").await;
            assert!(reply.is_none(), "the server answered {reply:?}");
        }
        let asked: Vec<LowerName> = upstream
            .asked
            .lock()
            .unwrap()
            .iter()
            .map(|lookup| LowerName::new(lookup.question.name()))
            .collect();
        assert_eq!(asked, [lower("www.allowed.example.")]);
        Ok(())
    });
}

/// What an authority filed belongs to its session: once the namespace
/// advances, the server looks the name up again and answers from what the
/// new session filed.
#[test]
fn a_namespace_advance_clears_what_lookups_filed() {
    world(Duration::from_secs(60), |fcx| async move {
        let address = Ipv4Addr::new(203, 0, 113, 53);
        let clock = WallClock {
            start: SystemTime::UNIX_EPOCH,
        };
        let namespace = Namespace::new(clock);
        let upstream = Counting::default();
        let zones = LookupAuthority::new("example.");
        let program = Authoritative::new(zones, ServerConfig::generic())
            .upstream(upstream.clone())
            .namespace(&namespace);
        let (attacher, attachments) = fictionet::attachments();
        Net::new()
            .ipv4_only()
            .host("copy", |h| h.at(address).program(program))
            .start(&fcx, attachments)?;
        let m = machine(&fcx, attacher.attach("client")?, ME);
        let server = SocketAddr::new(address.into(), 53);
        let first = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let second = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));

        for id in [1, 2] {
            let reply = ask(&fcx, &m, server, id, "www.example.")
                .await
                .expect("an answer");
            assert_eq!(addresses(&reply), [first]);
        }
        assert_eq!(upstream.asked.lock().unwrap().len(), 1, "one copy");

        namespace.advance(clock);
        let reply = ask(&fcx, &m, server, 3, "www.example.")
            .await
            .expect("an answer");
        assert_eq!(addresses(&reply), [second], "the new session's copy");
        assert_eq!(upstream.asked.lock().unwrap().len(), 2);
        Ok(())
    });
}
