//! BGP-4: a small wire codec, and the speaker that plays Harbourline's
//! border router.
//!
//! The codec covers the part of RFC 4271 the speaker needs: the 19-byte
//! header, and OPEN, UPDATE, NOTIFICATION and KEEPALIVE with two-byte AS
//! numbers. No capabilities, no four-byte AS numbers, no multiprotocol
//! routes. A real BGP daemon such as BIRD peers with it, as it did with the
//! Python world's speaker.
//!
//! The speaker sends its OPEN, finishes the OPEN and KEEPALIVE exchange,
//! and once established announces every route of the variant, one UPDATE
//! each. Then it holds the session as a router does: a KEEPALIVE every
//! third of the hold time, and a NOTIFICATION if the peer is silent for the
//! whole hold time. Routes the peer announces are logged and ignored.
//! Every message sent or received is a `bgp` line in the log.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;

use fictionet::Cx;
use fictionet::prelude::*;
use fictionet::stdlib::tcp::{Listener, TcpConnection};
use fictionet::time::{Duration, Instant};
use serde_json::{Value, json};

use crate::log::Log;
use crate::scenario::{Announcement, HOME, Prefix, Scenario};

pub const HEADER: usize = 19;
pub const MAX_MESSAGE: usize = 4096;
pub const VERSION: u8 = 4;
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

const ORIGIN: u8 = 1;
const AS_PATH: u8 = 2;
const NEXT_HOP: u8 = 3;
const TRANSITIVE: u8 = 0x40;
const ORIGIN_IGP: u8 = 0;
const AS_SEQUENCE: u8 = 2;

/// The four message types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Open => "OPEN",
            Kind::Update => "UPDATE",
            Kind::Notification => "NOTIFICATION",
            Kind::Keepalive => "KEEPALIVE",
        }
    }
}

/// A NOTIFICATION's error code and subcode (RFC 4271, section 4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub code: u8,
    pub subcode: u8,
}

pub const HEADER_NOT_SYNCHRONIZED: Error = Error { code: 1, subcode: 1 };
pub const HEADER_BAD_LENGTH: Error = Error { code: 1, subcode: 2 };
pub const HEADER_BAD_TYPE: Error = Error { code: 1, subcode: 3 };
pub const OPEN_ERROR: Error = Error { code: 2, subcode: 0 };
pub const OPEN_BAD_VERSION: Error = Error { code: 2, subcode: 1 };
pub const OPEN_BAD_HOLD: Error = Error { code: 2, subcode: 6 };
pub const UPDATE_ERROR: Error = Error { code: 3, subcode: 0 };
pub const HOLD_EXPIRED: Error = Error { code: 4, subcode: 0 };
pub const FSM_ERROR: Error = Error { code: 5, subcode: 0 };

/// A decoded OPEN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Open {
    pub version: u8,
    pub asn: u16,
    pub hold: u16,
    pub id: Ipv4Addr,
}

/// A decoded UPDATE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub withdrawn: Vec<Prefix>,
    pub as_path: Vec<u16>,
    pub next_hop: Option<Ipv4Addr>,
    pub announced: Vec<Prefix>,
}

fn frame(kind: Kind, body: &[u8]) -> Vec<u8> {
    let len = HEADER + body.len();
    assert!(len <= MAX_MESSAGE, "a BGP message of {len} bytes");
    let mut m = vec![0xff; 16];
    m.extend_from_slice(&(len as u16).to_be_bytes());
    m.push(kind as u8);
    m.extend_from_slice(body);
    m
}

/// An OPEN with no optional parameters.
pub fn open(asn: u16, hold: u16, id: Ipv4Addr) -> Vec<u8> {
    let mut body = vec![VERSION];
    body.extend_from_slice(&asn.to_be_bytes());
    body.extend_from_slice(&hold.to_be_bytes());
    body.extend_from_slice(&id.octets());
    body.push(0);
    frame(Kind::Open, &body)
}

pub fn keepalive() -> Vec<u8> {
    frame(Kind::Keepalive, &[])
}

pub fn notification(e: Error) -> Vec<u8> {
    frame(Kind::Notification, &[e.code, e.subcode])
}

fn encode_prefix(p: &Prefix, out: &mut Vec<u8>) {
    out.push(p.len);
    let octets = (usize::from(p.len)).div_ceil(8);
    out.extend_from_slice(&p.addr.octets()[..octets]);
}

/// An UPDATE that announces `announced` with ORIGIN IGP, `as_path` as one
/// AS_SEQUENCE and `next_hop`, and withdraws `withdrawn`.
pub fn update(announced: &[Prefix], as_path: &[u16], next_hop: Ipv4Addr, withdrawn: &[Prefix]) -> Vec<u8> {
    let mut gone = Vec::new();
    for p in withdrawn {
        encode_prefix(p, &mut gone);
    }
    let mut attrs = Vec::new();
    if !announced.is_empty() {
        attrs.extend_from_slice(&[TRANSITIVE, ORIGIN, 1, ORIGIN_IGP]);
        let mut path = vec![AS_SEQUENCE, as_path.len() as u8];
        for asn in as_path {
            path.extend_from_slice(&asn.to_be_bytes());
        }
        attrs.extend_from_slice(&[TRANSITIVE, AS_PATH, path.len() as u8]);
        attrs.extend_from_slice(&path);
        attrs.extend_from_slice(&[TRANSITIVE, NEXT_HOP, 4]);
        attrs.extend_from_slice(&next_hop.octets());
    }
    let mut body = Vec::new();
    body.extend_from_slice(&(gone.len() as u16).to_be_bytes());
    body.extend_from_slice(&gone);
    body.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    body.extend_from_slice(&attrs);
    for p in announced {
        encode_prefix(p, &mut body);
    }
    frame(Kind::Update, &body)
}

/// Reads a header: the message's kind and the length of its body. The
/// error is the NOTIFICATION to send.
pub fn parse_header(h: &[u8]) -> Result<(Kind, usize), Error> {
    if h.len() < HEADER || h[..16].iter().any(|&b| b != 0xff) {
        return Err(HEADER_NOT_SYNCHRONIZED);
    }
    let len = usize::from(u16::from_be_bytes([h[16], h[17]]));
    if !(HEADER..=MAX_MESSAGE).contains(&len) {
        return Err(HEADER_BAD_LENGTH);
    }
    let kind = match h[18] {
        1 => Kind::Open,
        2 => Kind::Update,
        3 => Kind::Notification,
        4 => Kind::Keepalive,
        _ => return Err(HEADER_BAD_TYPE),
    };
    let body = len - HEADER;
    let ok = match kind {
        Kind::Open => body >= 10,
        Kind::Update => body >= 4,
        Kind::Notification => body >= 2,
        Kind::Keepalive => body == 0,
    };
    if !ok {
        return Err(HEADER_BAD_LENGTH);
    }
    Ok((kind, body))
}

pub fn parse_open(b: &[u8]) -> Result<Open, Error> {
    if b.len() < 10 || b.len() != 10 + usize::from(b[9]) {
        return Err(OPEN_ERROR);
    }
    Ok(Open {
        version: b[0],
        asn: u16::from_be_bytes([b[1], b[2]]),
        hold: u16::from_be_bytes([b[3], b[4]]),
        id: Ipv4Addr::new(b[5], b[6], b[7], b[8]),
    })
}

fn decode_prefixes(mut d: &[u8]) -> Result<Vec<Prefix>, Error> {
    let mut out = Vec::new();
    while let Some((&len, rest)) = d.split_first() {
        if len > 32 {
            return Err(UPDATE_ERROR);
        }
        let octets = usize::from(len).div_ceil(8);
        if rest.len() < octets {
            return Err(UPDATE_ERROR);
        }
        let mut a = [0u8; 4];
        a[..octets].copy_from_slice(&rest[..octets]);
        out.push(Prefix::new(Ipv4Addr::from(a), len));
        d = &rest[octets..];
    }
    Ok(out)
}

pub fn parse_update(b: &[u8]) -> Result<Update, Error> {
    let take = |b: &[u8], at: usize| -> Result<usize, Error> {
        b.get(at..at + 2).map(|s| usize::from(u16::from_be_bytes([s[0], s[1]]))).ok_or(UPDATE_ERROR)
    };
    let wlen = take(b, 0)?;
    let withdrawn = decode_prefixes(b.get(2..2 + wlen).ok_or(UPDATE_ERROR)?)?;
    let alen = take(b, 2 + wlen)?;
    let at = 4 + wlen;
    let mut attrs = b.get(at..at + alen).ok_or(UPDATE_ERROR)?;
    let announced = decode_prefixes(&b[at + alen..])?;
    let mut as_path = Vec::new();
    let mut next_hop = None;
    while !attrs.is_empty() {
        if attrs.len() < 3 {
            return Err(UPDATE_ERROR);
        }
        let (flags, code) = (attrs[0], attrs[1]);
        let (len, head) = if flags & 0x10 != 0 {
            let s = attrs.get(2..4).ok_or(UPDATE_ERROR)?;
            (usize::from(u16::from_be_bytes([s[0], s[1]])), 4)
        } else {
            (usize::from(attrs[2]), 3)
        };
        let value = attrs.get(head..head + len).ok_or(UPDATE_ERROR)?;
        if code == AS_PATH {
            let mut v = value;
            while v.len() >= 2 {
                let count = usize::from(v[1]);
                let asns = v.get(2..2 + 2 * count).ok_or(UPDATE_ERROR)?;
                as_path.extend(asns.chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])));
                v = &v[2 + 2 * count..];
            }
        } else if code == NEXT_HOP && len == 4 {
            next_hop = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
        }
        attrs = &attrs[head + len..];
    }
    Ok(Update { withdrawn, as_path, next_hop, announced })
}

// ---------------------------------------------------------------------------
// The speaker

/// Accepts BGP sessions on `listener` until it closes, one task each.
pub async fn serve(cx: Cx, mut listener: Listener, scenario: Arc<Scenario>, log: Log, sandbox: Arc<str>) -> fictionet::Result {
    while let Ok(conn) = listener.accept(&cx).await {
        let (scenario, log, sandbox) = (scenario.clone(), log.clone(), sandbox.clone());
        cx.spawn(move |cx| async move {
            let peer = conn.peer_addr();
            let mut session = Session::new(cx, conn, scenario, log, sandbox, peer, OUR_HOLD);
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
    cx: Cx,
    conn: TcpConnection,
    scenario: Arc<Scenario>,
    log: Log,
    sandbox: Arc<str>,
    peer: SocketAddr,
    our_hold: u16,
    /// Bytes read and not yet parsed.
    buf: Vec<u8>,
    /// When the hold timer expires.
    hold_deadline: Instant,
    /// The negotiated hold time, once known.
    hold: Duration,
    /// When the next KEEPALIVE is due, once established.
    keepalive_at: Option<Instant>,
}

/// What waiting for a message gave.
enum Next {
    Message(Kind, Vec<u8>),
}

impl Session {
    /// A session on `conn` that offers `our_hold` seconds as its hold time.
    pub fn new(cx: Cx, conn: TcpConnection, scenario: Arc<Scenario>, log: Log, sandbox: Arc<str>, peer: SocketAddr, our_hold: u16) -> Session {
        let hold_deadline = cx.now() + OPEN_WAIT;
        Session {
            cx,
            conn,
            scenario,
            log,
            sandbox,
            peer,
            our_hold,
            buf: Vec::new(),
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
        let cx = self.cx.clone();
        let done = {
            let mut write = pin!(self.conn.write_all(&cx, message));
            let mut wait = pin!(cx.sleep(WRITE_WAIT));
            std::future::poll_fn(|task| {
                if let Poll::Ready(r) = write.as_mut().poll(task) {
                    return Poll::Ready(r.is_ok());
                }
                if wait.as_mut().poll(task).is_ready() {
                    return Poll::Ready(false);
                }
                Poll::Pending
            })
            .await
        };
        if !done {
            self.observe(json!({"event": "peer_closed"}));
            return Err(Ended);
        }
        self.observe(observed);
        Ok(())
    }

    async fn fail(&mut self, e: Error, reason: &str) -> Ended {
        let _ = self
            .send(
                &notification(e),
                json!({"event": "sent", "message": "NOTIFICATION", "code": e.code, "subcode": e.subcode, "reason": reason}),
            )
            .await;
        Ended
    }

    /// The next whole message. Sends KEEPALIVEs while it waits, and ends
    /// the session when the hold timer expires or the peer leaves.
    async fn next(&mut self) -> Result<Next, Ended> {
        loop {
            if self.buf.len() >= HEADER {
                let (kind, body) = match parse_header(&self.buf) {
                    Ok(h) => h,
                    Err(e) => return Err(self.fail(e, "bad message header").await),
                };
                if self.buf.len() >= HEADER + body {
                    let message: Vec<u8> = self.buf.drain(..HEADER + body).skip(HEADER).collect();
                    // Any message restarts the hold timer.
                    self.hold_deadline = self.cx.now() + self.hold;
                    return Ok(Next::Message(kind, message));
                }
            }
            let due = match self.keepalive_at {
                Some(k) if k < self.hold_deadline => k,
                _ => self.hold_deadline,
            };
            let cx = self.cx.clone();
            let mut chunk = [0u8; 4096];
            let read = {
                let mut read = pin!(self.conn.read(&cx, &mut chunk));
                let mut wait = pin!(cx.sleep_until(due));
                std::future::poll_fn(|task| {
                    if let Poll::Ready(r) = read.as_mut().poll(task) {
                        return Poll::Ready(Some(r));
                    }
                    if wait.as_mut().poll(task).is_ready() {
                        return Poll::Ready(None);
                    }
                    Poll::Pending
                })
                .await
            };
            match read {
                Some(Ok(n)) if n > 0 => self.buf.extend_from_slice(&chunk[..n]),
                Some(_) => {
                    self.observe(json!({"event": "peer_closed"}));
                    return Err(Ended);
                }
                None if cx.is_cancelled() => return Err(Ended),
                None => {
                    let now = cx.now();
                    if now >= self.hold_deadline {
                        return Err(self.fail(HOLD_EXPIRED, "hold timer expired").await);
                    }
                    if self.keepalive_at.is_some_and(|k| now >= k) {
                        self.send(&keepalive(), json!({"event": "sent", "message": "KEEPALIVE"})).await?;
                        self.keepalive_at = Some(now + self.hold / 3);
                    }
                }
            }
        }
    }

    async fn received_notification(&mut self, body: &[u8]) -> Ended {
        self.observe(json!({
            "event": "received",
            "message": "NOTIFICATION",
            "code": body.first(),
            "subcode": body.get(1),
        }));
        Ended
    }

    fn route(&self, a: &Announcement) -> Value {
        json!({
            "prefix": a.prefix.to_string(),
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
        self.send(&open(HOME.asn, self.our_hold, HOME.router), json!({"event": "sent", "message": "OPEN"})).await?;

        // OpenSent: the peer's OPEN.
        let Next::Message(kind, body) = self.next().await?;
        match kind {
            Kind::Notification => return Err(self.received_notification(&body).await),
            Kind::Open => {}
            other => return Err(self.fail(FSM_ERROR, &format!("expected OPEN, got {}", other.name())).await),
        }
        let peer = match parse_open(&body) {
            Ok(p) => p,
            Err(e) => return Err(self.fail(e, "bad OPEN").await),
        };
        self.observe(json!({"event": "received", "message": "OPEN", "peer_as": peer.asn, "peer_hold": peer.hold}));
        if peer.version != VERSION {
            return Err(self.fail(OPEN_BAD_VERSION, "unsupported version").await);
        }
        if (1..3).contains(&peer.hold) {
            return Err(self.fail(OPEN_BAD_HOLD, "unacceptable hold time").await);
        }
        let negotiated = self.our_hold.min(peer.hold);
        self.hold = if negotiated == 0 { IDLE_HOLD_ZERO } else { Duration::from_secs(u64::from(negotiated)) };
        self.hold_deadline = self.cx.now() + self.hold;
        self.send(&keepalive(), json!({"event": "sent", "message": "KEEPALIVE", "hold": negotiated})).await?;

        // OpenConfirm: the peer's KEEPALIVE.
        let Next::Message(kind, body) = self.next().await?;
        match kind {
            Kind::Notification => return Err(self.received_notification(&body).await),
            Kind::Keepalive => {}
            other => return Err(self.fail(FSM_ERROR, &format!("expected KEEPALIVE, got {}", other.name())).await),
        }
        self.observe(json!({"event": "received", "message": "KEEPALIVE"}));
        self.observe(json!({"event": "established", "hold": negotiated}));
        if negotiated != 0 {
            self.keepalive_at = Some(self.cx.now() + self.hold / 3);
        }

        // Established: announce, then hold the session.
        for route in self.scenario.announcements() {
            let message = update(&[route.prefix], &route.as_path, HOME.router, &[]);
            let observed = json!({"event": "sent", "message": "UPDATE", "route": self.route(&route)});
            self.send(&message, observed).await?;
        }
        loop {
            let Next::Message(kind, body) = self.next().await?;
            match kind {
                Kind::Keepalive => self.observe(json!({"event": "received", "message": "KEEPALIVE"})),
                Kind::Update => match parse_update(&body) {
                    Ok(u) => self.observe(json!({
                        "event": "received",
                        "message": "UPDATE",
                        "announced": u.announced.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
                        "withdrawn": u.withdrawn.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
                    })),
                    Err(e) => return Err(self.fail(e, "bad UPDATE").await),
                },
                Kind::Notification => return Err(self.received_notification(&body).await),
                Kind::Open => return Err(self.fail(FSM_ERROR, "unexpected OPEN").await),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(text: &str) -> Prefix {
        Prefix::parse(text).unwrap()
    }

    #[test]
    fn open_round_trips() {
        let m = open(65001, 90, Ipv4Addr::new(84, 21, 44, 1));
        assert_eq!(parse_header(&m), Ok((Kind::Open, 10)));
        assert_eq!(parse_open(&m[HEADER..]), Ok(Open { version: 4, asn: 65001, hold: 90, id: Ipv4Addr::new(84, 21, 44, 1) }));
    }

    #[test]
    fn keepalive_is_a_header_and_notification_carries_its_codes() {
        assert_eq!(keepalive(), [&[0xffu8; 16][..], &[0, 19, 4]].concat());
        let n = notification(HOLD_EXPIRED);
        assert_eq!(parse_header(&n), Ok((Kind::Notification, 2)));
        assert_eq!(&n[HEADER..], &[4, 0]);
    }

    #[test]
    fn an_announcement_carries_origin_path_and_next_hop() {
        let m = update(&[p("84.21.44.0/25")], &[65001, 65002], Ipv4Addr::new(84, 21, 44, 1), &[]);
        let (kind, len) = parse_header(&m).unwrap();
        assert_eq!(kind, Kind::Update);
        let u = parse_update(&m[HEADER..HEADER + len]).unwrap();
        assert_eq!(u.announced, vec![p("84.21.44.0/25")]);
        assert_eq!(u.as_path, vec![65001, 65002]);
        assert_eq!(u.next_hop, Some(Ipv4Addr::new(84, 21, 44, 1)));
        assert!(u.withdrawn.is_empty());
        // ORIGIN IGP comes first.
        assert_eq!(&m[HEADER + 4..HEADER + 8], &[0x40, 1, 1, 0]);
    }

    #[test]
    fn a_withdrawal_round_trips() {
        let m = update(&[], &[], Ipv4Addr::UNSPECIFIED, &[p("45.144.30.0/24"), p("0.0.0.0/0")]);
        let u = parse_update(&m[HEADER..]).unwrap();
        assert_eq!(u.withdrawn, vec![p("45.144.30.0/24"), p("0.0.0.0/0")]);
        assert!(u.announced.is_empty() && u.as_path.is_empty() && u.next_hop.is_none());
    }

    #[test]
    fn bad_headers_and_bodies_are_errors() {
        let mut m = keepalive();
        m[0] = 0;
        assert_eq!(parse_header(&m), Err(HEADER_NOT_SYNCHRONIZED));
        let mut m = keepalive();
        m[17] = 18;
        assert_eq!(parse_header(&m), Err(HEADER_BAD_LENGTH));
        let mut m = keepalive();
        m[18] = 9;
        assert_eq!(parse_header(&m), Err(HEADER_BAD_TYPE));
        // A KEEPALIVE with a body, an OPEN too short.
        let mut m = keepalive();
        m[17] = 20;
        assert_eq!(parse_header(&m), Err(HEADER_BAD_LENGTH));
        assert_eq!(parse_open(&[4, 0, 1]), Err(OPEN_ERROR));
        // NLRI with a length past 32, or cut short.
        assert_eq!(parse_update(&[0, 0, 0, 0, 33, 1, 2, 3, 4, 5]), Err(UPDATE_ERROR));
        assert_eq!(parse_update(&[0, 0, 0, 0, 24, 84, 21]), Err(UPDATE_ERROR));
        assert_eq!(parse_update(&[0, 9]), Err(UPDATE_ERROR));
    }
}
