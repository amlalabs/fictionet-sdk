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

use fictionet::Cx;
use fictionet::events::ConnInfo;
use fictionet::stdlib::bgp::{
    self, Attribute, Context, Error, Frame, Message, Notification, Open, Origin, Segment,
    SegmentKind, Update, kind,
};
use fictionet::stdlib::codec::{Fail, Frames, Wire};
use fictionet::stdlib::serve::{self, Driver, Flow, ServeOptions, Service, Timer};
use fictionet::stdlib::tcp::Listener;
use fictionet::time::Duration;
use serde_json::{Value, json};
use std::convert::Infallible;

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
    message
        .to_frame(&Context::default())
        .and_then(|frame| frame.to_bytes())
        .expect("a valid message")
}

fn announcement(route: &Announcement) -> Message {
    Message::Update(Update {
        withdrawn: vec![],
        attributes: vec![
            Attribute::Origin(Origin::Igp),
            Attribute::AsPath(vec![Segment {
                kind: SegmentKind::Sequence,
                asns: route.as_path.iter().map(|&a| a.into()).collect(),
            }]),
            Attribute::NextHop(HOME.router),
        ],
        nlri: vec![bgp::Prefix::new(route.prefix.addr, route.prefix.len).expect("an IPv4 prefix")],
    })
}

// ---------------------------------------------------------------------------
// The speaker

/// Accepts BGP sessions on `listener` until it closes, one task each.
pub async fn serve(
    fcx: Cx,
    mut listener: Listener,
    scenario: Arc<Scenario>,
    log: Log,
    sandbox: Arc<str>,
) -> fictionet::Result {
    while let Ok(conn) = listener.accept(&fcx).await {
        let (scenario, log, sandbox) = (scenario.clone(), log.clone(), sandbox.clone());
        fcx.spawn(move |fcx| async move {
            let peer = conn.peer_addr();
            let info = ConnInfo {
                peer: Some(peer),
                local: Some(conn.local_addr()),
                ..ConnInfo::default()
            };
            let mut session = Session::new(scenario, log, sandbox, peer, OUR_HOLD);
            let opts = ServeOptions::default()
                .idle(None)
                .write_timeout(Some(WRITE_WAIT))
                .connection_events(false);
            let _ = serve::connection(&fcx, conn, info, &mut session, &(), &opts).await;
            Ok(())
        });
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Phase {
    OpenSent,
    OpenConfirm,
    Established,
}

/// One BGP session.
pub struct Session {
    scenario: Arc<Scenario>,
    log: Log,
    sandbox: Arc<str>,
    peer: SocketAddr,
    our_hold: u16,
    context: Context,
    hold: Duration,
    negotiated: u16,
    phase: Phase,
}

impl Session {
    /// A session that offers `our_hold` seconds as its hold time.
    pub fn new(
        scenario: Arc<Scenario>,
        log: Log,
        sandbox: Arc<str>,
        peer: SocketAddr,
        our_hold: u16,
    ) -> Session {
        Session {
            scenario,
            log,
            sandbox,
            peer,
            our_hold,
            context: Context::default(),
            hold: OPEN_WAIT,
            negotiated: 0,
            phase: Phase::OpenSent,
        }
    }

    fn open(&self) -> Open {
        let mut ours = Open::new(HOME.asn.into(), self.our_hold, HOME.router, vec![]);
        ours.parameters.clear();
        ours
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

    fn send(&self, driver: &mut Driver<'_, Frames<Frame>>, message: &[u8], observed: Value) {
        driver.reply().extend_from_slice(message);
        self.observe(observed);
    }

    fn fail(&self, driver: &mut Driver<'_, Frames<Frame>>, e: Notification, reason: &str) -> Flow {
        self.send(driver, &bytes(Message::Notification(e.clone())),
            json!({"event": "sent", "message": "NOTIFICATION", "code": e.code, "subcode": e.subcode, "reason": reason}));
        Flow::Close
    }

    fn route(&self, a: &Announcement) -> Value {
        json!({
            "prefix": format!("{}/{}", a.prefix.addr, a.prefix.len),
            "as_path": a.as_path,
            "origin_as": a.origin_as(),
            "hijack": self.scenario.conflicts_with_home(a),
        })
    }
}

impl Service for Session {
    type Decoder = Frames<Frame>;
    type State = ();
    type Error = Infallible;

    fn decoder(&self) -> Self::Decoder {
        Frames::new()
    }

    fn on_open(
        &mut self,
        _: &(),
        driver: &mut Driver<'_, Self::Decoder>,
    ) -> Result<Flow, Infallible> {
        self.send(
            driver,
            &bytes(Message::Open(self.open())),
            json!({"event": "sent", "message": "OPEN"}),
        );
        driver.set_timer("hold", OPEN_WAIT);
        Ok(Flow::Continue)
    }

    fn on_item(
        &mut self,
        frame: Frame,
        _: &(),
        driver: &mut Driver<'_, Self::Decoder>,
    ) -> Result<Flow, Infallible> {
        let decoded = if frame.kind == kind::ROUTE_REFRESH {
            Err(Error::BadMessageType(frame.kind))
        } else {
            Message::decode(&frame, &self.context)
        };
        if let Err(e @ (Error::BadMessageLength(_) | Error::BadMessageType(_))) = decoded {
            return Ok(self.fail(
                driver,
                e.notification().expect("a header error"),
                "bad message header",
            ));
        }
        driver.set_timer("hold", self.hold);
        if let Ok(Message::Notification(n)) = &decoded {
            self.observe(json!({"event": "received", "message": "NOTIFICATION", "code": n.code, "subcode": n.subcode}));
            return Ok(Flow::Close);
        }
        let expected = match self.phase {
            Phase::OpenSent => Some(kind::OPEN),
            Phase::OpenConfirm => Some(kind::KEEPALIVE),
            Phase::Established => None,
        };
        if let Some(expected) = expected.filter(|&k| k != frame.kind) {
            return Ok(self.fail(
                driver,
                Notification {
                    code: bgp::code::FSM,
                    subcode: 0,
                    data: vec![],
                },
                &format!("expected {}, got {}", name(expected), name(frame.kind)),
            ));
        }
        match self.phase {
            Phase::OpenSent => {
                let body = &frame.body;
                let peer = match Message::decode(&frame, &self.context) {
                    Ok(Message::Open(peer)) => peer,
                    Err(e) => {
                        // These fields are readable even when the timer or version is refused.
                        if matches!(
                            e,
                            Error::UnsupportedVersion(_) | Error::UnacceptableHoldTime
                        ) && body.len() == 10 + usize::from(body[9])
                        {
                            let peer_as = u16::from_be_bytes([body[1], body[2]]);
                            let peer_hold = u16::from_be_bytes([body[3], body[4]]);
                            self.observe(json!({"event": "received", "message": "OPEN", "peer_as": peer_as, "peer_hold": peer_hold}));
                        }
                        let reason = match e {
                            Error::UnsupportedVersion(_) => "unsupported version",
                            Error::UnacceptableHoldTime => "unacceptable hold time",
                            _ => "bad OPEN",
                        };
                        return Ok(self.fail(
                            driver,
                            e.notification().expect("an OPEN error"),
                            reason,
                        ));
                    }
                    _ => unreachable!("an OPEN frame"),
                };
                self.observe(json!({"event": "received", "message": "OPEN", "peer_as": peer.my_as, "peer_hold": peer.hold_time}));
                self.context = Context::negotiated(&self.open(), &peer);
                let negotiated = self.our_hold.min(peer.hold_time);
                self.hold = if negotiated == 0 {
                    IDLE_HOLD_ZERO
                } else {
                    Duration::from_secs(u64::from(negotiated))
                };
                self.negotiated = negotiated;
                driver.set_timer("hold", self.hold);
                self.send(
                    driver,
                    &bytes(Message::Keepalive),
                    json!({"event": "sent", "message": "KEEPALIVE", "hold": negotiated}),
                );

                self.phase = Phase::OpenConfirm;
            }
            Phase::OpenConfirm => {
                self.observe(json!({"event": "received", "message": "KEEPALIVE"}));
                self.observe(json!({"event": "established", "hold": self.negotiated}));
                if self.negotiated != 0 {
                    driver.set_timer("keepalive", self.hold / 3);
                }
                for route in self.scenario.announcements() {
                    self.send(
                        driver,
                        &bytes(announcement(&route)),
                        json!({"event": "sent", "message": "UPDATE", "route": self.route(&route)}),
                    );
                }
                self.phase = Phase::Established;
            }
            Phase::Established => match decoded {
                Ok(Message::Keepalive) => {
                    self.observe(json!({"event": "received", "message": "KEEPALIVE"}))
                }
                Ok(Message::Update(u)) => self.observe(json!({
                    "event": "received", "message": "UPDATE",
                    "announced": u.nlri.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
                    "withdrawn": u.withdrawn.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
                })),
                Err(e) if frame.kind == kind::UPDATE => {
                    return Ok(self.fail(
                        driver,
                        e.notification().expect("an UPDATE error"),
                        "bad UPDATE",
                    ));
                }
                _ => {
                    return Ok(self.fail(
                        driver,
                        Notification {
                            code: bgp::code::FSM,
                            subcode: 0,
                            data: vec![],
                        },
                        "unexpected OPEN",
                    ));
                }
            },
        }
        Ok(Flow::Continue)
    }

    fn on_timer(
        &mut self,
        timer: Timer,
        _: &(),
        driver: &mut Driver<'_, Self::Decoder>,
    ) -> Result<Flow, Infallible> {
        if timer == "hold" || driver.timer("hold").is_some_and(|at| at <= driver.now()) {
            return Ok(self.fail(
                driver,
                Notification {
                    code: bgp::code::HOLD_TIMER_EXPIRED,
                    subcode: 0,
                    data: vec![],
                },
                "hold timer expired",
            ));
        }
        self.send(
            driver,
            &bytes(Message::Keepalive),
            json!({"event": "sent", "message": "KEEPALIVE"}),
        );
        driver.set_timer("keepalive", self.hold / 3);
        Ok(Flow::Continue)
    }

    fn on_fail(
        &mut self,
        error: &Fail<Error>,
        _: &(),
        driver: &mut Driver<'_, Self::Decoder>,
    ) -> Result<(), Infallible> {
        if let Fail::Protocol(e) = error {
            self.fail(
                driver,
                e.notification().expect("a wire error"),
                "bad message header",
            );
        }
        Ok(())
    }

    fn on_end(
        &mut self,
        end: serve::Ended,
        _: &(),
        _: &mut Driver<'_, Self::Decoder>,
    ) -> Result<(), Infallible> {
        if matches!(end, serve::Ended::Eof | serve::Ended::Conn(_)) {
            self.observe(json!({"event": "peer_closed"}));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announcement_bytes_are_unchanged() {
        let route = Announcement {
            prefix: crate::scenario::HIJACK_PREFIX,
            as_path: vec![65001, 65002],
        };
        assert_eq!(
            bytes(announcement(&route)),
            [
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0,
                48, 2, 0, 0, 0, 20, 64, 1, 1, 0, 64, 2, 6, 2, 2, 253, 233, 253, 234, 64, 3, 4, 84,
                21, 44, 1, 25, 84, 21, 44, 0,
            ]
        );
    }
}
