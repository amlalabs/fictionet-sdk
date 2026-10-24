//! The built-in authoritative DNS service. Name resolution and TCP admission
//! are supplied by Net; query handling only sees lookup and idle-time policy.

use super::hosts::{Admission, Lookup, pings};
use super::normalize;
use fictionet::stdlib::codec::{Collect, CollectError, Decode, Step};
use fictionet::stdlib::network::{ConnError, ip, tcp, udp};
use fictionet::stdlib::protocols::dns::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::{
    DNSClass, RData, Record, RecordType, rdata::A, rdata::AAAA,
};
use fictionet::stdlib::services::serve::ConnInfo;
use fictionet::stdlib::services::serve::{self, ServeOptions, Service};
use fictionet::{Cx, End, Error};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

pub(super) type LookupName = dyn Fn(&str) -> Lookup + Send + Sync;

#[derive(Clone)]
pub(super) struct State {
    pub(super) lookup: Arc<LookupName>,
    pub(super) tcp_idle: Duration,
}

#[derive(Clone)]
pub(super) struct Context {
    pub(super) state: State,
    pub(super) admission: Admission,
}

/// How long resolvers may keep an answer, in seconds.
const TTL: u32 = 60;

/// DNS over UDP and TCP on port 53, and ping replies, at `addr` on `side`.
pub(super) fn start_dns(
    context: Context,
    fcx: &Cx,
    side: End,
    addr: IpAddr,
) -> Result<tcp::Endpoint, Error> {
    let (tcp, udp, icmp, _other) = ip::split_protocols(fcx, side);
    let tcp = tcp::endpoint(fcx, tcp, addr);
    let udp = udp::endpoint(fcx, udp, addr);
    let socket = udp.bind(53)?;
    let listener = tcp.listen(53)?;
    let datagrams = context.clone();
    fcx.spawn(move |fcx| dns_udp(fcx, socket, datagrams));
    fcx.spawn(move |fcx| dns_tcp(fcx, listener, context));
    fcx.spawn(move |fcx| pings(fcx, icmp, addr));
    Ok(tcp)
}

// ---------------------------------------------------------------------------
// DNS at the gateway

/// The answer to one DNS message.
fn answer(lookup: &LookupName, bytes: &[u8]) -> Option<Vec<u8>> {
    let query = match Message::from_vec(bytes) {
        Ok(query) => query,
        Err(_) => {
            if bytes.len() < 12 || bytes[2] & 0x80 != 0 {
                return None;
            }
            return Message::error_msg(
                u16::from_be_bytes([bytes[0], bytes[1]]),
                OpCode::Query,
                ResponseCode::FormErr,
            )
            .to_vec()
            .ok();
        }
    };
    if query.metadata.message_type != MessageType::Query {
        return None;
    }
    let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
    reply.metadata.authoritative = true;
    reply.metadata.recursion_desired = query.metadata.recursion_desired;
    reply.metadata.recursion_available = true;
    reply.queries = query.queries.clone();
    if query.edns.is_some() {
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        reply.edns = Some(edns);
    }
    if query.metadata.op_code != OpCode::Query {
        reply.metadata.response_code = ResponseCode::NotImp;
    } else if query.queries.len() != 1 {
        reply.metadata.response_code = ResponseCode::FormErr;
    } else {
        let q = &query.queries[0];
        let name = normalize(&q.name().to_ascii());
        let found = if name.is_empty() {
            Lookup::NoHost
        } else {
            lookup(&name)
        };
        match found {
            Lookup::NoHost => reply.metadata.response_code = ResponseCode::NXDomain,
            Lookup::Full => reply.metadata.response_code = ResponseCode::ServFail,
            Lookup::Host(placed) => {
                let class_ok = matches!(q.query_class(), DNSClass::IN | DNSClass::ANY);
                let rdata = match (class_ok, q.query_type()) {
                    (true, RecordType::A) => placed.v4.map(|a| RData::A(A(a))),
                    (true, RecordType::AAAA) => placed.v6.map(|a| RData::AAAA(AAAA(a))),
                    _ => None,
                };
                if let Some(rdata) = rdata {
                    reply
                        .answers
                        .push(Record::from_rdata(q.name().clone(), TTL, rdata));
                }
            }
        }
    }
    reply.to_vec().ok()
}

/// Framing for a DNS query over UDP or TCP.
struct DnsQueries {
    tcp: bool,
    datagram: Collect<Vec<u8>, true>,
}

impl Decode for DnsQueries {
    type Item = Vec<u8>;
    type Error = CollectError<core::convert::Infallible>;
    const NAME: &'static str = "DNS query";

    fn capacity(&self) -> usize {
        65537
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Vec<u8>>, Self::Error> {
        if !self.tcp {
            return self.datagram.decode(input, eof);
        }
        let Some(prefix) = input.get(..2) else {
            return Ok(Step::Need);
        };
        let end = 2 + usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
        Ok(match input.get(2..end) {
            Some(query) => Step::Item(query.to_vec(), end),
            None => Step::Need,
        })
    }
}

struct Dns {
    tcp: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QueryTimer {
    Idle,
}

impl Service for Dns {
    type Timer = QueryTimer;
    type Decoder = DnsQueries;
    type State = State;
    type Error = core::convert::Infallible;

    fn decoder(&self) -> DnsQueries {
        DnsQueries {
            tcp: self.tcp,
            datagram: Collect::bytes(65535),
        }
    }

    fn on_open(
        &mut self,
        state: &State,
        driver: &mut serve::Driver<'_, DnsQueries, QueryTimer>,
    ) -> Result<serve::Flow, Self::Error> {
        if self.tcp {
            driver.set_timer(QueryTimer::Idle, state.tcp_idle);
        }
        Ok(serve::Flow::Continue)
    }

    fn on_item(
        &mut self,
        query: Vec<u8>,
        state: &State,
        driver: &mut serve::Driver<'_, DnsQueries, QueryTimer>,
    ) -> Result<serve::Flow, Self::Error> {
        if let Some(reply) = answer(&*state.lookup, &query) {
            if self.tcp {
                if let Ok(n) = u16::try_from(reply.len()) {
                    driver.reply().extend_from_slice(&n.to_be_bytes());
                    driver.reply().extend_from_slice(&reply);
                }
            } else {
                driver.reply().extend_from_slice(&reply);
            }
        }
        self.on_open(state, driver)
    }

    fn on_timer(
        &mut self,
        _: QueryTimer,
        _: &State,
        _: &mut serve::Driver<'_, DnsQueries, QueryTimer>,
    ) -> Result<serve::Flow, Self::Error> {
        Ok(serve::Flow::Close)
    }
}

/// DNS over UDP on the gateway's port 53.
async fn dns_udp(fcx: Cx, socket: udp::Socket, context: Context) -> fictionet::Result {
    let local = socket.local_addr();
    let opts = ServeOptions {
        sandbox: Some(context.admission.sandbox()),
        ..ServeOptions::default()
    };
    let _ = serve::datagram(
        &fcx,
        socket,
        local,
        &mut Dns { tcp: false },
        &context.state,
        &opts,
    )
    .await;
    Ok(())
}

/// DNS over TCP on the gateway's port 53.
async fn dns_tcp(fcx: Cx, mut listener: tcp::Listener, context: Context) -> fictionet::Result {
    loop {
        match listener.accept(&fcx).await {
            Ok(conn) => {
                let Some(conn) = context.admission.admit(&fcx, conn) else {
                    continue;
                };
                let context = context.clone();
                fcx.spawn(move |fcx| async move {
                    let _ = dns_conn(&fcx, conn, &context).await;
                    Ok(())
                });
            }
            Err(ConnError::Cancelled | ConnError::Closed) => return Ok(()),
            Err(_) => {}
        }
    }
}

async fn dns_conn(fcx: &Cx, conn: tcp::TcpConnection, context: &Context) -> Result<(), ConnError> {
    let info = ConnInfo {
        sandbox: Some(context.admission.hooks.sandbox_at(conn.peer_addr().ip())),
        peer: Some(conn.peer_addr()),
        local: Some(conn.local_addr()),
        ..ConnInfo::default()
    };
    let opts = ServeOptions {
        idle: None,
        budget: info
            .sandbox
            .as_ref()
            .and_then(|sandbox| context.admission.hooks.budget(sandbox.id)),
        ..ServeOptions::default()
    };
    let _ = serve::connection(
        fcx,
        conn,
        info,
        &mut Dns { tcp: true },
        &context.state,
        &opts,
    )
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::addresses::Placed;
    use super::super::hosts::{Known, Peers, World};
    use super::super::{Hooks, Limits, MAX_HOSTS, Shared, Subnet, route};
    use super::*;
    use fictionet::stdlib::network::DatagramSocket;
    use fictionet::stdlib::protocols::dns::{op::Query, rr::Name};
    use fictionet::sync::Mutex;
    use std::collections::{BTreeMap, VecDeque};
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicU64;

    /// A UDP socket that hands out `queued` and keeps what is sent.
    struct Datagrams {
        queued: VecDeque<(Vec<u8>, SocketAddr)>,
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl DatagramSocket for Datagrams {
        fn recv(
            &mut self,
            _: &Cx,
        ) -> impl Future<Output = Result<(Vec<u8>, SocketAddr), fictionet::RecvError>> + Send
        {
            let next = self.queued.pop_front();
            async move { next.ok_or(fictionet::RecvError::Closed) }
        }

        fn send_to(&mut self, data: &[u8], _: SocketAddr) {
            self.sent.lock().push(data.to_vec());
        }
    }

    /// Replies the UDP service sends for `queries`.
    fn udp_replies(lookup: Arc<LookupName>, queries: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let socket = Datagrams {
            queued: queries
                .into_iter()
                .map(|q| (q, "10.0.0.2:5353".parse().unwrap()))
                .collect(),
            sent: sent.clone(),
        };
        let state = State {
            lookup,
            tcp_idle: Duration::from_secs(10),
        };
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |fcx| async move {
                let _ = serve::datagram(
                    &fcx,
                    socket,
                    "10.0.0.1:53".parse().unwrap(),
                    &mut Dns { tcp: false },
                    &state,
                    &ServeOptions::default(),
                )
                .await;
                Ok(())
            },
        ))
        .unwrap();
        let sent = sent.lock().clone();
        sent
    }

    /// A query whose questions after the second all point at the second
    /// name. The first name has more labels than hickory keeps compression
    /// candidates for, so a reply that echoes the questions spells every
    /// copy of the second name out in full.
    fn echo_query(pointers: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00];
        q.extend_from_slice(&(2 + pointers).to_be_bytes());
        q.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        for _ in 0..100 {
            q.extend_from_slice(&[1, b'a']);
        }
        q.push(0);
        q.extend_from_slice(&[0, 1, 0, 1]);
        let second = u16::try_from(q.len()).unwrap();
        for len in [63, 63, 63, 61] {
            q.push(len);
            q.extend(std::iter::repeat_n(b'b', usize::from(len)));
        }
        q.push(0);
        q.extend_from_slice(&[0, 1, 0, 1]);
        for _ in 0..pointers {
            q.extend_from_slice(&(0xC000 | second).to_be_bytes());
            q.extend_from_slice(&[0, 1, 0, 1]);
        }
        q
    }

    fn a_query(id: u16, name: &str) -> Message {
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query
            .queries
            .push(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        query
    }

    #[test]
    fn unknown_names_answer_nxdomain() {
        let mut query = Message::new(7, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_ascii("missing.test.").unwrap(),
            RecordType::A,
        ));
        let reply = answer(&|_| Lookup::NoHost, &query.to_vec().unwrap()).unwrap();
        let parsed = Message::from_vec(&reply).unwrap();
        assert_eq!(parsed.metadata.id, 7);
        assert_eq!(parsed.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(parsed.queries, query.queries);
    }

    #[test]
    fn udp_replies_fit_in_512_bytes_without_edns() {
        let query = echo_query(150);
        assert!(query.len() < 1400, "the query fits one Ethernet frame");
        let replies = udp_replies(Arc::new(|_| Lookup::NoHost), vec![query]);
        assert_eq!(replies.len(), 1);
        let reply = Message::from_vec(&replies[0]).unwrap();
        assert_eq!(reply.metadata.id, 0x1234);
        assert!(
            replies[0].len() <= 512,
            "a {}-byte UDP reply to a query without EDNS (TC={})",
            replies[0].len(),
            reply.metadata.truncation
        );
    }

    #[test]
    fn queries_whose_echo_is_too_long_still_get_a_reply() {
        let query = echo_query(260);
        assert!(query.len() < 4096);
        let reply = answer(&|_| Lookup::NoHost, &query).expect("every query gets a reply");
        let parsed = Message::from_vec(&reply).unwrap();
        assert_eq!(parsed.metadata.id, 0x1234);
        assert_eq!(parsed.metadata.response_code, ResponseCode::FormErr);
    }

    #[test]
    fn malformed_queries_keep_their_opcode() {
        // NOTIFY with one question announced and none present.
        let bytes = [0x00, 0x42, 0x20, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        let reply = answer(&|_| Lookup::NoHost, &bytes).unwrap();
        let parsed = Message::from_vec(&reply).unwrap();
        assert_eq!(parsed.metadata.id, 0x42);
        assert_eq!(parsed.metadata.response_code, ResponseCode::FormErr);
        assert_eq!(parsed.metadata.op_code, OpCode::Notify);
    }

    #[test]
    fn unknown_edns_versions_get_badvers() {
        let mut query = a_query(9, "api.stripe.com.");
        let mut edns = Edns::new();
        edns.set_version(1);
        query.edns = Some(edns);
        let host = Lookup::Host(Placed {
            v4: Some("104.18.0.1".parse().unwrap()),
            v6: None,
        });
        let reply = answer(&move |_| host, &query.to_vec().unwrap()).unwrap();
        let parsed = Message::from_vec(&reply).unwrap();
        assert!(parsed.edns.is_some());
        assert_eq!(
            u16::from(parsed.metadata.response_code),
            u16::from(ResponseCode::BADVERS)
        );
        assert!(parsed.answers.is_empty());
    }

    #[test]
    fn parents_of_declared_hosts_are_not_nxdomain() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |fcx| async move {
                let shared = Arc::new(Shared {
                    fcx: fcx.clone(),
                    resolver: None,
                    subnet: Subnet::new("10.0.0.0/24".parse().unwrap()).unwrap(),
                    subnet6: None,
                    router: route::router(&fcx, Vec::new()),
                    world: Arc::new(Mutex::new(World::new(MAX_HOSTS))),
                    leases: Arc::default(),
                    gateway_tcp: Arc::default(),
                    hooks: Arc::new(Hooks {
                        by_addr: Mutex::default(),
                        conns: AtomicU64::new(0),
                        attached: Mutex::default(),
                    }),
                    fixed: Vec::new(),
                    peers: Peers::new(Limits::default().connections_per_peer),
                    limits: Limits::default(),
                    lans: BTreeMap::new(),
                });
                let placed = Placed {
                    v4: Some("104.18.0.1".parse().unwrap()),
                    v6: None,
                };
                // What Net::start does for a host declared with the name.
                shared
                    .world
                    .lock()
                    .names
                    .insert("api.stripe.com".into(), Known::Host(placed));
                let lookup = shared.dns().state.lookup;
                let child =
                    answer(&*lookup, &a_query(1, "api.stripe.com.").to_vec().unwrap()).unwrap();
                let child = Message::from_vec(&child).unwrap();
                assert_eq!(child.metadata.response_code, ResponseCode::NoError);
                assert_eq!(child.answers.len(), 1);
                // NXDOMAIN would say no name exists at or below stripe.com
                // (RFC 8020), which api.stripe.com contradicts.
                let parent =
                    answer(&*lookup, &a_query(2, "stripe.com.").to_vec().unwrap()).unwrap();
                let parent = Message::from_vec(&parent).unwrap();
                assert_eq!(parent.metadata.response_code, ResponseCode::NoError);
                assert!(parent.answers.is_empty());
                fcx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }
}
