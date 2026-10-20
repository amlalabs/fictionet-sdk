//! BGP-4: the speaker that plays Harbourline's border router.
//!
//! The speaker sends its OPEN and finishes the OPEN and KEEPALIVE exchange.
//! Once established, it announces each current route in a separate UPDATE.
//! It sends a KEEPALIVE every third of the hold time and a NOTIFICATION if
//! the peer is silent for the whole hold time. Peer routes are logged and ignored.
//! Route changes wake established sessions. Each session reconciles what it
//! announced with the current table, including withdrawals after restoration.
//! Every message sent or received is an observer fact projected to a `bgp` line.

use std::net::SocketAddr;
use std::sync::Arc;

use fictionet::Cx;
use fictionet::events::{ConnInfo, Event};
use fictionet::stdlib::codec::{Fail, Frames, Wire};
use fictionet::stdlib::network::tcp::Listener;
use fictionet::stdlib::protocols::bgp::{
    self, Attribute, Context, Error, Frame, Message, Notification, Open, Origin, Segment,
    SegmentKind, Update, kind,
};
use fictionet::stdlib::protocols::json::Value;
use fictionet::stdlib::services::serve::{self, Driver, Flow, ServeOptions, Service, Timer};
use fictionet::time::Duration;
use std::convert::Infallible;

use crate::routing::{Route, Routing};
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
    routing: Routing,
    sandbox: Arc<str>,
) -> fictionet::Result {
    while let Ok(conn) = listener.accept(&fcx).await {
        let (scenario, routing, sandbox) = (scenario.clone(), routing.clone(), sandbox.clone());
        fcx.spawn(move |fcx| async move {
            let peer = conn.peer_addr();
            let info = ConnInfo {
                peer: Some(peer),
                local: Some(conn.local_addr()),
                ..ConnInfo::default()
            };
            let mut session = Session::new(scenario, routing, sandbox, peer, OUR_HOLD);
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
    routing: Routing,
    sandbox: Arc<str>,
    peer: SocketAddr,
    our_hold: u16,
    context: Context,
    hold: Duration,
    negotiated: u16,
    phase: Phase,
    announced: Vec<Announcement>,
}

impl Session {
    /// A session that offers `our_hold` seconds as its hold time.
    pub fn new(
        scenario: Arc<Scenario>,
        routing: Routing,
        sandbox: Arc<str>,
        peer: SocketAddr,
        our_hold: u16,
    ) -> Session {
        Session {
            scenario,
            routing,
            sandbox,
            peer,
            our_hold,
            context: Context::default(),
            hold: OPEN_WAIT,
            negotiated: 0,
            phase: Phase::OpenSent,
            announced: Vec::new(),
        }
    }

    fn open(&self) -> Open {
        let mut ours = Open::new(HOME.asn.into(), self.our_hold, HOME.router, vec![]);
        ours.parameters.clear();
        ours
    }

    fn observe(
        &self,
        driver: &Driver<'_, Frames<Frame>>,
        kind: &'static str,
        build: impl FnOnce(Event) -> Event,
    ) {
        driver.emit("bgp", kind, |e| {
            build(
                e.field("sandbox", &*self.sandbox)
                    .display("peer", self.peer),
            )
        });
    }

    fn send(
        &self,
        driver: &mut Driver<'_, Frames<Frame>>,
        message: &[u8],
        build: impl FnOnce(Event) -> Event,
    ) {
        driver.reply().extend_from_slice(message);
        self.observe(driver, "sent", build);
    }

    fn fail(
        &self,
        driver: &mut Driver<'_, Frames<Frame>>,
        e: Notification,
        reason: impl std::fmt::Display,
    ) -> Flow {
        let (code, subcode) = (e.code, e.subcode);
        self.send(driver, &bytes(Message::Notification(e)), |event| {
            event
                .field("message", "NOTIFICATION")
                .field("code", u64::from(code))
                .field("subcode", u64::from(subcode))
                .display("reason", reason)
        });
        Flow::Close
    }

    fn route(&self, a: &Announcement) -> Value {
        Route::new(&self.scenario, a).fact()
    }

    fn update_routes(&mut self, driver: &mut Driver<'_, Frames<Frame>>) {
        let current = self.scenario.routed(self.routing.mode()).announcements();
        for route in &self.announced {
            if !current.iter().any(|r| r.prefix == route.prefix) {
                let prefix =
                    bgp::Prefix::new(route.prefix.addr, route.prefix.len).expect("an IPv4 prefix");
                self.send(
                    driver,
                    &bytes(Message::Update(Update {
                        withdrawn: vec![prefix],
                        attributes: vec![],
                        nlri: vec![],
                    })),
                    |e| {
                        e.field("message", "UPDATE")
                            .field("withdrawn", Value::Array(vec![prefix.to_string().into()]))
                    },
                );
            }
        }
        for route in &current {
            if !self.announced.contains(route) {
                self.send(driver, &bytes(announcement(route)), |e| {
                    e.field("message", "UPDATE")
                        .field("route", self.route(route))
                });
            }
        }
        self.announced = current;
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
        self.send(driver, &bytes(Message::Open(self.open())), |e| {
            e.field("message", "OPEN")
        });
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
            self.observe(driver, "received", |e| {
                e.field("message", "NOTIFICATION")
                    .field("code", u64::from(n.code))
                    .field("subcode", u64::from(n.subcode))
            });
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
                format_args!("expected {}, got {}", name(expected), name(frame.kind)),
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
                            self.observe(driver, "received", |e| {
                                e.field("message", "OPEN")
                                    .field("peer_as", u64::from(peer_as))
                                    .field("peer_hold", u64::from(peer_hold))
                            });
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
                self.observe(driver, "received", |e| {
                    e.field("message", "OPEN")
                        .field("peer_as", u64::from(peer.my_as))
                        .field("peer_hold", u64::from(peer.hold_time))
                });
                self.context = Context::negotiated(&self.open(), &peer);
                let negotiated = self.our_hold.min(peer.hold_time);
                self.hold = if negotiated == 0 {
                    IDLE_HOLD_ZERO
                } else {
                    Duration::from_secs(u64::from(negotiated))
                };
                self.negotiated = negotiated;
                driver.set_timer("hold", self.hold);
                self.send(driver, &bytes(Message::Keepalive), |e| {
                    e.field("message", "KEEPALIVE")
                        .field("hold", u64::from(negotiated))
                });

                self.phase = Phase::OpenConfirm;
            }
            Phase::OpenConfirm => {
                self.observe(driver, "received", |e| e.field("message", "KEEPALIVE"));
                self.observe(driver, "established", |e| {
                    e.field("hold", u64::from(self.negotiated))
                });
                if self.negotiated != 0 {
                    driver.set_timer("keepalive", self.hold / 3);
                }
                self.routing.register(driver.wake_handle());
                self.update_routes(driver);
                self.phase = Phase::Established;
            }
            Phase::Established => match decoded {
                Ok(Message::Keepalive) => {
                    self.observe(driver, "received", |e| e.field("message", "KEEPALIVE"))
                }
                Ok(Message::Update(u)) => self.observe(driver, "received", |e| {
                    e.field("message", "UPDATE")
                        .field(
                            "announced",
                            Value::Array(
                                u.nlri
                                    .iter()
                                    .map(|p| Value::from(p.to_string()))
                                    .collect::<Vec<_>>(),
                            ),
                        )
                        .field(
                            "withdrawn",
                            Value::Array(
                                u.withdrawn
                                    .iter()
                                    .map(|p| Value::from(p.to_string()))
                                    .collect::<Vec<_>>(),
                            ),
                        )
                }),
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

    fn on_wake(
        &mut self,
        _: &(),
        driver: &mut Driver<'_, Self::Decoder>,
    ) -> Result<Flow, Infallible> {
        if matches!(self.phase, Phase::Established) {
            self.update_routes(driver);
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
        self.send(driver, &bytes(Message::Keepalive), |e| {
            e.field("message", "KEEPALIVE")
        });
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
        driver: &mut Driver<'_, Self::Decoder>,
    ) -> Result<(), Infallible> {
        if matches!(end, serve::Ended::Eof | serve::Ended::Conn(_)) {
            self.observe(driver, "peer_closed", |e| e);
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
