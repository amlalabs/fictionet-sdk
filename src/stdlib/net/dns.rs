use super::hosts::{Lookup, pings, too_many};
use super::{Shared, normalize};
use fictionet::events::{ConnInfo, Event, opt as jopt};
use fictionet::stdlib::codec::{Collect, CollectError, Decode, Step};
use fictionet::stdlib::dns::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use fictionet::stdlib::dns::rr::{DNSClass, RData, Record, RecordType, rdata::A, rdata::AAAA};
use fictionet::stdlib::serve::{self, ServeOptions, Service};
use fictionet::stdlib::{ConnError, ip, tcp, udp};
use fictionet::{Cx, End, Error};
use std::net::IpAddr;
use std::sync::Arc;

/// How long resolvers may keep an answer, in seconds.
const TTL: u32 = 60;

/// DNS over UDP and TCP on port 53, and ping replies, at `addr` on `side`.
pub(super) fn start_dns(
    shared: &Arc<Shared>,
    fcx: &Cx,
    side: End,
    addr: IpAddr,
) -> Result<(), Error> {
    let (tcp, udp, icmp, _other) = ip::split_protocols(fcx, side);
    let tcp = tcp::endpoint(fcx, tcp, addr);
    let udp = udp::endpoint(fcx, udp, addr);
    let socket = udp.bind(53)?;
    let listener = tcp.listen(53)?;
    shared.gateway_tcp.lock().push(tcp);
    let s = shared.clone();
    fcx.spawn(move |fcx| dns_udp(fcx, socket, s));
    let s = shared.clone();
    fcx.spawn(move |fcx| dns_tcp(fcx, listener, s));
    fcx.spawn(move |fcx| pings(fcx, icmp, addr));
    Ok(())
}

// ---------------------------------------------------------------------------
// DNS at the gateway

/// What the DNS server answered, for the event.
#[derive(Clone, Debug, PartialEq, Eq)]
enum DnsAnswer {
    Addr(IpAddr),
    NoData,
    NxDomain,
    Error(u16),
    None,
}

/// The answer to one DNS message, and what it was.
struct Answered {
    reply: Option<Vec<u8>>,
    name: Option<String>,
    qtype: Option<u16>,
    answer: DnsAnswer,
}

impl Answered {
    fn none() -> Answered {
        Answered {
            reply: None,
            name: None,
            qtype: None,
            answer: DnsAnswer::None,
        }
    }

    fn event(&self, tcp: bool) -> Event {
        let answer = if self.reply.is_some() {
            self.answer.clone()
        } else {
            DnsAnswer::None
        };
        let (kind, addr, rcode) = match &answer {
            DnsAnswer::Addr(a) => ("addr", Some(a.to_string()), None),
            DnsAnswer::NoData => ("nodata", None, None),
            DnsAnswer::NxDomain => ("nxdomain", None, None),
            DnsAnswer::Error(code) => ("error", None, Some(u32::from(*code))),
            DnsAnswer::None => ("none", None, None),
        };
        Event::new("dns", "query")
            .summary(format!(
                "{} {}: {}",
                self.name.as_deref().unwrap_or("-"),
                self.qtype.unwrap_or(0),
                addr.as_deref().unwrap_or(kind)
            ))
            .field("tcp", tcp)
            .field("name", jopt(self.name.clone()))
            .field("qtype", jopt(self.qtype.map(u32::from)))
            .field("answer", kind)
            .field("addr", jopt(addr))
            .field("rcode", jopt(rcode))
    }
}

/// The answer to one DNS message.
fn answer(shared: &Arc<Shared>, bytes: &[u8]) -> Answered {
    let query = match Message::from_vec(bytes) {
        Ok(q) => q,
        Err(_) => {
            if bytes.len() < 12 || bytes[2] & 0x80 != 0 {
                return Answered::none();
            }
            let id = u16::from_be_bytes([bytes[0], bytes[1]]);
            let reply = Message::error_msg(id, OpCode::Query, ResponseCode::FormErr)
                .to_vec()
                .ok();
            return Answered {
                reply,
                name: None,
                qtype: None,
                answer: DnsAnswer::Error(1),
            };
        }
    };
    if query.metadata.message_type != MessageType::Query {
        return Answered::none();
    }
    let first = query.queries.first().filter(|_| query.queries.len() == 1);
    let mut name = first.map(|q| normalize(&q.name().to_ascii()));
    let qtype = first.map(|q| u16::from(q.query_type()));
    let event_answer;
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
        event_answer = DnsAnswer::Error(4);
    } else if query.queries.len() != 1 {
        reply.metadata.response_code = ResponseCode::FormErr;
        event_answer = DnsAnswer::Error(1);
        name = None;
    } else {
        let q = &query.queries[0];
        let name = name.as_deref().unwrap_or_default();
        let found = if name.is_empty() {
            Lookup::NoHost
        } else {
            shared.lookup(name)
        };
        match found {
            Lookup::NoHost => {
                reply.metadata.response_code = ResponseCode::NXDomain;
                event_answer = DnsAnswer::NxDomain;
            }
            Lookup::Full => {
                reply.metadata.response_code = ResponseCode::ServFail;
                event_answer = DnsAnswer::Error(2);
            }
            Lookup::Host(placed) => {
                let class_ok = matches!(q.query_class(), DNSClass::IN | DNSClass::ANY);
                let rdata = match (class_ok, q.query_type()) {
                    (true, RecordType::A) => placed.v4.map(|a| RData::A(A(a))),
                    (true, RecordType::AAAA) => placed.v6.map(|a| RData::AAAA(AAAA(a))),
                    _ => None,
                };
                match rdata {
                    Some(rdata) => {
                        event_answer = DnsAnswer::Addr(match &rdata {
                            RData::A(a) => a.0.into(),
                            RData::AAAA(a) => a.0.into(),
                            _ => unreachable!("only A and AAAA are made"),
                        });
                        reply
                            .answers
                            .push(Record::from_rdata(q.name().clone(), TTL, rdata));
                    }
                    None => event_answer = DnsAnswer::NoData,
                }
            }
        }
    }
    let qtype = if name.is_some() { qtype } else { None };
    Answered {
        reply: reply.to_vec().ok(),
        name,
        qtype,
        answer: event_answer,
    }
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

impl Service for Dns {
    type Decoder = DnsQueries;
    type State = Arc<Shared>;
    type Error = core::convert::Infallible;

    fn decoder(&self) -> DnsQueries {
        DnsQueries {
            tcp: self.tcp,
            datagram: Collect::bytes(65535),
        }
    }

    fn on_open(
        &mut self,
        shared: &Arc<Shared>,
        driver: &mut serve::Driver<'_, DnsQueries>,
    ) -> Result<serve::Flow, Self::Error> {
        if self.tcp {
            driver.set_timer("query", shared.limits.dns_tcp_idle);
        }
        Ok(serve::Flow::Continue)
    }

    fn on_item(
        &mut self,
        query: Vec<u8>,
        shared: &Arc<Shared>,
        driver: &mut serve::Driver<'_, DnsQueries>,
    ) -> Result<serve::Flow, Self::Error> {
        let answered = answer(shared, &query);
        driver.record(answered.event(self.tcp));
        if let Some(reply) = answered.reply {
            if self.tcp {
                if let Ok(n) = u16::try_from(reply.len()) {
                    driver.reply().extend_from_slice(&n.to_be_bytes());
                    driver.reply().extend_from_slice(&reply);
                }
            } else {
                driver.reply().extend_from_slice(&reply);
            }
        }
        self.on_open(shared, driver)
    }

    fn on_timer(
        &mut self,
        _: serve::Timer,
        _: &Arc<Shared>,
        _: &mut serve::Driver<'_, DnsQueries>,
    ) -> Result<serve::Flow, Self::Error> {
        Ok(serve::Flow::Close)
    }
}

/// DNS over UDP on the gateway's port 53.
async fn dns_udp(fcx: Cx, socket: udp::Socket, shared: Arc<Shared>) -> fictionet::Result {
    let local = socket.local_addr();
    let hooks = shared.hooks.clone();
    let opts = ServeOptions {
        sandbox: Some(Arc::new(move |addr| Some(hooks.sandbox_at(addr)))),
        ..ServeOptions::default()
    };
    let _ = serve::datagram(&fcx, socket, local, &mut Dns { tcp: false }, &shared, &opts).await;
    Ok(())
}

/// DNS over TCP on the gateway's port 53.
async fn dns_tcp(fcx: Cx, mut listener: tcp::Listener, shared: Arc<Shared>) -> fictionet::Result {
    let peers = shared.peers.clone();
    loop {
        match listener.accept(&fcx).await {
            Ok(conn) => {
                let Some(guard) = peers.enter(conn.peer_addr().ip()) else {
                    too_many(&fcx, &shared.hooks, &conn);
                    conn.reset();
                    continue;
                };
                conn.hold_until_gone(Box::new(guard));
                let shared = shared.clone();
                fcx.spawn(move |fcx| async move {
                    let _ = dns_conn(&fcx, conn, &shared).await;
                    Ok(())
                });
            }
            Err(ConnError::Cancelled | ConnError::Closed) => return Ok(()),
            Err(_) => {}
        }
    }
}

async fn dns_conn(
    fcx: &Cx,
    conn: tcp::TcpConnection,
    shared: &Arc<Shared>,
) -> Result<(), ConnError> {
    let info = ConnInfo {
        sandbox: Some(shared.hooks.sandbox_at(conn.peer_addr().ip())),
        peer: Some(conn.peer_addr()),
        local: Some(conn.local_addr()),
        ..ConnInfo::default()
    };
    let opts = ServeOptions {
        idle: None,
        connection_events: false,
        budget: info
            .sandbox
            .as_ref()
            .and_then(|sandbox| shared.hooks.budget(sandbox.id)),
        ..ServeOptions::default()
    };
    let _ = serve::connection(fcx, conn, info, &mut Dns { tcp: true }, shared, &opts).await;
    Ok(())
}
