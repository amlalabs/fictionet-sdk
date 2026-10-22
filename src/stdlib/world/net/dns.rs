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
    use super::*;
    use fictionet::stdlib::protocols::dns::{op::Query, rr::Name};

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
}
