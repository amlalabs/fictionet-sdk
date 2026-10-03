//! The DNS server at the gateway, over UDP and TCP.

use std::sync::Arc;

use super::http_serve::time_limit;
use super::net::{Hooks, Lookup, Peers, Shared};
use super::{Blocked, BlockedWhy, Dns, DnsAnswer, Event, Sandbox};
use crate::stdlib::dns::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use crate::stdlib::dns::rr::{DNSClass, RData, Record, RecordType, rdata::A, rdata::AAAA};
use crate::stdlib::{ConnError, Connection, ConnectionExt, tcp, udp};
use crate::Cx;

/// How long a DNS-over-TCP connection may sit idle between queries, as RFC
/// 7766 suggests (section 6.2.3).
const TCP_IDLE: std::time::Duration = std::time::Duration::from_secs(10);

/// How long resolvers may keep an answer, in seconds. Names never change
/// address within a run, so this only limits how long a stale answer from
/// an earlier run could live in a sandbox's cache.
const TTL: u32 = 60;

/// A name as the callback sees it: lowercase, without the trailing dot.
pub(super) fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// The answer to one DNS message, and what it was, for the event.
pub(super) struct Answered {
    /// The reply to send, or `None` if the message gets no answer at all
    /// (it is not a query, or too short to have an ID).
    pub(super) reply: Option<Vec<u8>>,
    name: Option<String>,
    qtype: Option<u16>,
    answer: DnsAnswer,
}

impl Answered {
    fn none() -> Answered {
        Answered { reply: None, name: None, qtype: None, answer: DnsAnswer::None }
    }

    /// The event for this query, from `sandbox`. Takes all but the reply.
    pub(super) fn event(&mut self, sandbox: Sandbox, tcp: bool) -> Event {
        let answer = if self.reply.is_some() { self.answer.clone() } else { DnsAnswer::None };
        Event::Dns(Dns { sandbox, tcp, name: self.name.take(), qtype: self.qtype, answer })
    }
}

/// The answer to one DNS message.
pub(super) fn answer(shared: &Arc<Shared>, bytes: &[u8]) -> Answered {
    let query = match Message::from_vec(bytes) {
        Ok(q) => q,
        Err(_) => {
            // FORMERR, if there is at least a header to answer.
            if bytes.len() < 12 || bytes[2] & 0x80 != 0 {
                return Answered::none();
            }
            let id = u16::from_be_bytes([bytes[0], bytes[1]]);
            let reply = Message::error_msg(id, OpCode::Query, ResponseCode::FormErr).to_vec().ok();
            return Answered { reply, name: None, qtype: None, answer: DnsAnswer::Error(1) };
        }
    };
    if query.metadata.message_type != MessageType::Query {
        return Answered::none();
    }
    // A name only when there is exactly one question.
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
        let found = if name.is_empty() { Lookup::NoSite } else { shared.lookup(name) };
        match found {
            Lookup::NoSite => {
                reply.metadata.response_code = ResponseCode::NXDomain;
                event_answer = DnsAnswer::NxDomain;
            }
            Lookup::Full => {
                reply.metadata.response_code = ResponseCode::ServFail;
                event_answer = DnsAnswer::Error(2);
            }
            Lookup::Site(placed) => {
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
                        reply.answers.push(Record::from_rdata(q.name().clone(), TTL, rdata));
                    }
                    // Any other type, or a family the site does not have:
                    // NODATA, an empty answer.
                    None => event_answer = DnsAnswer::NoData,
                }
            }
        }
    }
    let qtype = if name.is_some() { qtype } else { None };
    Answered { reply: reply.to_vec().ok(), name, qtype, answer: event_answer }
}

/// DNS over UDP on the gateway's port 53.
pub(super) async fn serve_udp(cx: Cx, mut socket: udp::Socket, shared: Arc<Shared>) -> crate::Result {
    let mut run = 0;
    let hooks = shared.hooks.clone();
    while let Ok((query, from)) = socket.recv(&cx).await {
        let mut answered = answer(&shared, &query);
        if hooks.on() {
            hooks.emit(&cx, answered.event(hooks.sandbox_at(from.ip()), false));
        }
        if let Some(reply) = answered.reply {
            socket.send_to(&reply, from);
        }
        // Counts to 64 and starts again: a count that only grew would
        // overflow, and panic with overflow checks, after 2^31 packets.
        run = (run + 1) % 64;
        if run == 0 && cx.yield_now().await.is_err() {
            break;
        }
    }
    Ok(())
}

/// DNS over TCP on the gateway's port 53. Each connection may carry many
/// queries, each with a two-byte length in front.
pub(super) async fn serve_tcp(cx: Cx, mut listener: tcp::Listener, shared: Arc<Shared>) -> crate::Result {
    let peers = Arc::new(Peers::default());
    loop {
        match listener.accept(&cx).await {
            Ok(conn) => {
                let Some(guard) = peers.enter(conn.peer_addr().ip()) else {
                    too_many(&cx, &shared.hooks, &conn);
                    conn.reset();
                    continue;
                };
                // The count lasts until the socket is gone, closing included.
                conn.hold_until_gone(Box::new(guard));
                let shared = shared.clone();
                cx.spawn(move |cx| async move {
                    let _ = serve_conn(&cx, conn, &shared).await;
                    Ok(())
                });
            }
            Err(ConnError::Cancelled | ConnError::Closed) => return Ok(()),
            Err(_) => {}
        }
    }
}

/// Tells the world that `conn` was reset for being past its sandbox's
/// limit.
pub(super) fn too_many(cx: &Cx, hooks: &Hooks, conn: &tcp::TcpConnection) {
    if hooks.on() {
        let (peer, local) = (conn.peer_addr(), conn.local_addr());
        hooks.emit(
            cx,
            Event::Blocked(Blocked {
                sandbox: hooks.sandbox_at(peer.ip()),
                why: BlockedWhy::TooManyConnections,
                protocol: Some(6),
                src: Some(peer.ip()),
                dst: Some(local.ip()),
                dst_port: Some(local.port()),
            }),
        );
    }
}

async fn serve_conn(cx: &Cx, mut conn: tcp::TcpConnection, shared: &Arc<Shared>) -> Result<(), ConnError> {
    let hooks = shared.hooks.clone();
    // The sandbox, as it was when the connection arrived.
    let sandbox = hooks.on().then(|| hooks.sandbox_at(conn.peer_addr().ip()));
    loop {
        // A connection idle too long, or a query that takes too long to
        // arrive, is closed.
        let read = async {
            let mut len = [0u8; 2];
            if !read_exact(cx, &mut conn, &mut len).await? {
                return Ok::<_, ConnError>(None);
            }
            let mut query = vec![0u8; u16::from_be_bytes(len) as usize];
            if !read_exact(cx, &mut conn, &mut query).await? {
                return Ok(None);
            }
            Ok(Some(query))
        };
        let Some(query) = time_limit(cx, TCP_IDLE, read).await.transpose()?.flatten() else { return Ok(()) };
        let mut answered = answer(shared, &query);
        if let Some(sandbox) = &sandbox {
            hooks.emit(cx, answered.event(sandbox.clone(), true));
        }
        let Some(reply) = answered.reply else { continue };
        let Ok(n) = u16::try_from(reply.len()) else { continue };
        let mut framed = n.to_be_bytes().to_vec();
        framed.extend_from_slice(&reply);
        conn.write_all(cx, &framed).await?;
    }
}

/// Fills `buf`. `Ok(false)` if the stream ended first.
async fn read_exact<C: Connection>(cx: &Cx, conn: &mut C, buf: &mut [u8]) -> Result<bool, ConnError> {
    let mut at = 0;
    while at < buf.len() {
        let n = conn.read(cx, &mut buf[at..]).await?;
        if n == 0 {
            return Ok(false);
        }
        at += n;
    }
    Ok(true)
}
