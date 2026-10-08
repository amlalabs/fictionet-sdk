//! BGP-4: the speaker that plays Harbourline's border router.
//!
//! The speaker sends its OPEN, finishes the OPEN and KEEPALIVE exchange,
//! and once established announces every route of the variant, one UPDATE
//! each. Then it holds the session as a router does: a KEEPALIVE every
//! third of the hold time, and a NOTIFICATION if the peer is silent for the
//! whole hold time. Routes the peer announces are logged and ignored.
//! Every message sent or received is a `bgp` line in the log.

use std::net::SocketAddr;
use std::sync::Arc;

use fictionet::{Cx, RaceError};
use fictionet::prelude::*;
use fictionet::stdlib::bgp::{self, Attribute, Context, Error, Frame, Message, Notification, Open, Origin, Segment, SegmentKind, Update, kind};
use fictionet::stdlib::codec::{Fail, Stream, Wire};
use fictionet::stdlib::tcp::{Listener, TcpConnection};
use fictionet::time::{Duration, Instant};
use serde_json::{Value, json};

use crate::log::Log;
use crate::scenario::{Announcement, HOME, Scenario};

/// The hold time the speaker offers. The session uses the smaller of this
/// and the peer's.
pub const OUR_HOLD: u16 = 90;
/// How long the speaker waits for the peer's OPEN (RFC 4271's large hold
/// time).
const OPEN_WAIT: Duration = Duration::from_secs(240);
/// How long to wait for a message when the peer asked for a hold time of
/// zero (no keepalives).
const IDLE_HOLD_ZERO: Duration = Duration::from_secs(3600);
/// How long a write may wait for the peer to make room.
const WRITE_WAIT: Duration = Duration::from_secs(10);

fn name(kind: u8) -> &'static str {
    match kind {
        kind::OPEN => "OPEN",
        kind::UPDATE => "UPDATE",
        kind::NOTIFICATION => "NOTIFICATION",
        kind::KEEPALIVE => "KEEPALIVE",
        _ => unreachable!("a checked message type"),
    }
}

fn bytes(message: Message) -> Vec<u8> {
    message.to_frame(&Context::default()).and_then(|frame| frame.to_bytes()).expect("a valid message")
}

fn announcement(route: &Announcement) -> Message {
    Message::Update(Update {
        withdrawn: vec![],
        attributes: vec![
            Attribute::Origin(Origin::Igp),
            Attribute::AsPath(vec![Segment { kind: SegmentKind::Sequence, asns: route.as_path.iter().map(|&a| a.into()).collect() }]),
            Attribute::NextHop(HOME.router),
        ],
        nlri: vec![bgp::Prefix::new(route.prefix.addr, route.prefix.len).expect("an IPv4 prefix")],
    })
}

// ---------------------------------------------------------------------------
// The speaker

/// Accepts BGP sessions on `listener` until it closes, one task each.
pub async fn serve(fcx: Cx, mut listener: Listener, scenario: Arc<Scenario>, log: Log, sandbox: Arc<str>) -> fictionet::Result {
    while let Ok(conn) = listener.accept(&fcx).await {
        let (scenario, log, sandbox) = (scenario.clone(), log.clone(), sandbox.clone());
        fcx.spawn(move |fcx| async move {
            let peer = conn.peer_addr();
            let mut session = Session::new(fcx, conn, scenario, log, sandbox, peer, OUR_HOLD);
            session.run().await;
            Ok(())
        });
    }
    Ok(())
}

/// Why a session ended. Already logged.
struct Ended;

/// One BGP session.
pub struct Session {
    fcx: Cx,
    conn: TcpConnection,
    scenario: Arc<Scenario>,
    log: Log,
    sandbox: Arc<str>,
    peer: SocketAddr,
    our_hold: u16,
    /// Frames read from the peer.
    stream: Stream<bgp::Frames>,
    context: Context,
    /// When the hold timer expires.
    hold_deadline: Instant,
    /// The negotiated hold time, once known.
    hold: Duration,
    /// When the next KEEPALIVE is due, once established.
    keepalive_at: Option<Instant>,
}

impl Session {
    /// A session on `conn` that offers `our_hold` seconds as its hold time.
    pub fn new(fcx: Cx, conn: TcpConnection, scenario: Arc<Scenario>, log: Log, sandbox: Arc<str>, peer: SocketAddr, our_hold: u16) -> Session {
        let hold_deadline = fcx.now() + OPEN_WAIT;
        Session {
            fcx,
            conn,
            scenario,
            log,
            sandbox,
            peer,
            our_hold,
            stream: Stream::new(bgp::Frames),
            context: Context::default(),
            hold_deadline,
            hold: OPEN_WAIT,
            keepalive_at: None,
        }
    }

    fn observe(&self, fields: Value) {
        let mut line = serde_json::Map::new();
        line.insert("type".into(), json!("bgp"));
        line.insert("sandbox".into(), json!(&*self.sandbox));
        line.insert("peer".into(), json!(self.peer.to_string()));
        if let Value::Object(fields) = fields {
            line.extend(fields);
        }
        self.log.line(Value::Object(line));
    }

    async fn send(&mut self, message: &[u8], observed: Value) -> Result<(), Ended> {
        let fcx = self.fcx.clone();
        match fcx.race(Some(fcx.now() + WRITE_WAIT), self.conn.write_all(&fcx, message)).await {
            Ok(Ok(())) => {}
            Err(RaceError::Cancelled) => return Err(Ended),
            _ => {
                self.observe(json!({"event": "peer_closed"}));
                return Err(Ended);
            }
        }
        self.observe(observed);
        Ok(())
    }

    async fn fail(&mut self, e: Notification, reason: &str) -> Ended {
        let _ = self
            .send(
                &bytes(Message::Notification(e.clone())),
                json!({"event": "sent", "message": "NOTIFICATION", "code": e.code, "subcode": e.subcode, "reason": reason}),
            )
            .await;
        Ended
    }

    /// The next whole message. Sends KEEPALIVEs while it waits, and ends
    /// the session when the hold timer expires or the peer leaves.
    async fn next(&mut self) -> Result<Frame, Ended> {
        loop {
            if let Some(frame) = self.stream.next() {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(Fail::Protocol(e)) => return Err(self.fail(e.notification().expect("a wire error"), "bad message header").await),
                    Err(_) => return Err(Ended),
                };
                let decoded = if frame.kind == kind::ROUTE_REFRESH {
                    Err(Error::BadMessageType(frame.kind))
                } else {
                    Message::decode(&frame, &self.context)
                };
                if let Err(e @ (Error::BadMessageLength(_) | Error::BadMessageType(_))) = decoded {
                    return Err(self.fail(e.notification().expect("a header error"), "bad message header").await);
                }
                // Any message restarts the hold timer.
                self.hold_deadline = self.fcx.now() + self.hold;
                return Ok(frame);
            }
            let due = match self.keepalive_at {
                Some(k) if k < self.hold_deadline => k,
                _ => self.hold_deadline,
            };
            let fcx = self.fcx.clone();
            let read = fcx.race(Some(due), self.conn.read(&fcx, self.stream.spare())).await;
            match read {
                Ok(Ok(n)) if n > 0 => self.stream.commit(n),
                Ok(_) => {
                    self.observe(json!({"event": "peer_closed"}));
                    return Err(Ended);
                }
                Err(RaceError::Cancelled) => return Err(Ended),
                Err(RaceError::Deadline) => {
                    let now = fcx.now();
                    if now >= self.hold_deadline {
                        return Err(self.fail(Notification { code: bgp::code::HOLD_TIMER_EXPIRED, subcode: 0, data: vec![] }, "hold timer expired").await);
                    }
                    if self.keepalive_at.is_some_and(|k| now >= k) {
                        self.send(&bytes(Message::Keepalive), json!({"event": "sent", "message": "KEEPALIVE"})).await?;
                        self.keepalive_at = Some(now + self.hold / 3);
                    }
                }
            }
        }
    }

    async fn received_notification(&mut self, frame: &Frame) -> Ended {
        let Ok(Message::Notification(n)) = Message::decode(frame, &self.context) else { unreachable!("a checked NOTIFICATION") };
        self.observe(json!({
            "event": "received",
            "message": "NOTIFICATION",
            "code": n.code,
            "subcode": n.subcode,
        }));
        Ended
    }

    fn route(&self, a: &Announcement) -> Value {
        json!({
            "prefix": format!("{}/{}", a.prefix.addr, a.prefix.len),
            "as_path": a.as_path,
            "origin_as": a.origin_as(),
            "hijack": self.scenario.conflicts_with_home(a),
        })
    }

    /// Runs the session until the peer leaves, errs or falls silent.
    pub async fn run(&mut self) {
        let _ = self.drive().await;
    }

    async fn drive(&mut self) -> Result<(), Ended> {
        let mut ours = Open::new(HOME.asn.into(), self.our_hold, HOME.router, vec![]);
        // Open::new adds a capability; Border offers none.
        ours.parameters.clear();
        self.send(&bytes(Message::Open(ours.clone())), json!({"event": "sent", "message": "OPEN"})).await?;

        // OpenSent: the peer's OPEN.
        let frame = self.next().await?;
        let kind = frame.kind;
        match kind {
            kind::NOTIFICATION => return Err(self.received_notification(&frame).await),
            kind::OPEN => {}
            other => return Err(self.fail(Notification { code: bgp::code::FSM, subcode: 0, data: vec![] }, &format!("expected OPEN, got {}", name(other))).await),
        }
        let body = &frame.body;
        let peer = match Message::decode(&frame, &self.context) {
            Ok(Message::Open(peer)) => peer,
            Err(e) => {
                // These fields are readable even when the timer or version is refused.
                if matches!(e, Error::UnsupportedVersion(_) | Error::UnacceptableHoldTime) && body.len() == 10 + usize::from(body[9]) {
                    let peer_as = u16::from_be_bytes([body[1], body[2]]);
                    let peer_hold = u16::from_be_bytes([body[3], body[4]]);
                    self.observe(json!({"event": "received", "message": "OPEN", "peer_as": peer_as, "peer_hold": peer_hold}));
                }
                let reason = match e {
                    Error::UnsupportedVersion(_) => "unsupported version",
                    Error::UnacceptableHoldTime => "unacceptable hold time",
                    _ => "bad OPEN",
                };
                return Err(self.fail(e.notification().expect("an OPEN error"), reason).await);
            }
            _ => unreachable!("an OPEN frame"),
        };
        self.observe(json!({"event": "received", "message": "OPEN", "peer_as": peer.my_as, "peer_hold": peer.hold_time}));
        self.context = Context::negotiated(&ours, &peer);
        let negotiated = self.our_hold.min(peer.hold_time);
        self.hold = if negotiated == 0 { IDLE_HOLD_ZERO } else { Duration::from_secs(u64::from(negotiated)) };
        self.hold_deadline = self.fcx.now() + self.hold;
        self.send(&bytes(Message::Keepalive), json!({"event": "sent", "message": "KEEPALIVE", "hold": negotiated})).await?;

        // OpenConfirm: the peer's KEEPALIVE.
        let frame = self.next().await?;
        let kind = frame.kind;
        match kind {
            kind::NOTIFICATION => return Err(self.received_notification(&frame).await),
            kind::KEEPALIVE => {}
            other => return Err(self.fail(Notification { code: bgp::code::FSM, subcode: 0, data: vec![] }, &format!("expected KEEPALIVE, got {}", name(other))).await),
        }
        self.observe(json!({"event": "received", "message": "KEEPALIVE"}));
        self.observe(json!({"event": "established", "hold": negotiated}));
        if negotiated != 0 {
            self.keepalive_at = Some(self.fcx.now() + self.hold / 3);
        }

        // Established: announce, then hold the session.
        for route in self.scenario.announcements() {
            let message = bytes(announcement(&route));
            let observed = json!({"event": "sent", "message": "UPDATE", "route": self.route(&route)});
            self.send(&message, observed).await?;
        }
        loop {
            let frame = self.next().await?;
            let kind = frame.kind;
            match kind {
                kind::KEEPALIVE => self.observe(json!({"event": "received", "message": "KEEPALIVE"})),
                kind::UPDATE => match Message::decode(&frame, &self.context) {
                    Ok(Message::Update(u)) => self.observe(json!({
                        "event": "received",
                        "message": "UPDATE",
                        "announced": u.nlri.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
                        "withdrawn": u.withdrawn.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
                    })),
                    Err(e) => return Err(self.fail(e.notification().expect("an UPDATE error"), "bad UPDATE").await),
                    _ => unreachable!("an UPDATE frame"),
                },
                kind::NOTIFICATION => return Err(self.received_notification(&frame).await),
                kind::OPEN => return Err(self.fail(Notification { code: bgp::code::FSM, subcode: 0, data: vec![] }, "unexpected OPEN").await),
                _ => unreachable!("a checked message type"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announcement_bytes_are_unchanged() {
        let route = Announcement { prefix: crate::scenario::HIJACK_PREFIX, as_path: vec![65001, 65002] };
        assert_eq!(bytes(announcement(&route)), [
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            0, 48, 2, 0, 0, 0, 20, 64, 1, 1, 0, 64, 2, 6, 2, 2, 253, 233, 253, 234,
            64, 3, 4, 84, 21, 44, 1, 25, 84, 21, 44, 0,
        ]);
    }
}
