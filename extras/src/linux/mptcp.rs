//! The server's MPTCP listener: how it answers MP_CAPABLE and MP_JOIN, the
//! data level of its MPTCP connections, and the keys of the open ones.
//!
//! The listener reads MPTCP options as Linux does (mptcp_parse_option): an
//! option Linux ignores counts for nothing, and when several count, the
//! last one wins.
//!
//! - On a SYN, MP_CAPABLE counts when it has Length 4, version 1 or
//!   higher, flag B clear, and HMAC-SHA256 as its only algorithm (flags D
//!   to H). MP_JOIN counts when it has Length 12.
//! - On the ACK that completes a handshake, MP_CAPABLE counts when it has
//!   version 1, the same flags, and the Length the segment calls for: 20
//!   on a pure ACK, 22 or 24 when it carries data. MP_JOIN counts when it
//!   has Length 24.
//!
//! A SYN with MP_CAPABLE gets a SYN-ACK with MP_CAPABLE version 1 and a
//! fresh random key (RFC 8684 section 3.1), and asks for checksums when
//! the SYN did, as Linux does with checksums off by default. A SYN with
//! both MP_CAPABLE and MP_JOIN, or neither, gets plain TCP.
//!
//! The connection uses MPTCP once its third ACK echoes the keys, and its
//! token then names it. When that ACK carries no MP_CAPABLE that counts,
//! the connection falls back to plain TCP and has no token, as on Linux.
//! From then on each segment the server sends carries DSS (section 3.3):
//! a mapping of its data and a Data ACK of the client's, as
//! [`DataLevel`] has them. When the client sends data no mapping covers,
//! the connection falls back and the server sends no more DSS (section
//! 3.7).
//!
//! A handshake answered with a SYN cookie keeps nothing, so the server
//! takes its own key from the third ACK's echo, as Linux does. As Linux
//! does, it drops that ACK, with no answer, when the ACK carries both
//! MP_CAPABLE and MP_JOIN, when the client's key is 0, or when the echoed
//! key's token already names an open connection
//! (mptcp_subflow_init_cookie_req).
//!
//! MP_JOIN is answered as a Linux listener with its default limits
//! answers it (section 3.2). A SYN whose token names none of the server's
//! open connections gets a RST with MP_TCPRST "MPTCP-specific error"
//! (section 3.6). One that names a connection on another port gets
//! "administratively prohibited", since the server announces no other
//! port. Otherwise the SYN-ACK carries MP_JOIN, the server's truncated
//! HMAC and a random number. The third ACK must carry the client's HMAC:
//! one with no MP_JOIN is refused with MP_TCPRST "MPTCP-specific error",
//! as Linux refuses a join it would have to fall back. When the HMAC is
//! right and the connection has fewer than [`MAX_SUBFLOWS`] joined
//! subflows, the subflow is taken. Otherwise it is refused with
//! "administratively prohibited", and so is one whose connection has gone.
//! A joined subflow carries nothing from the server: whatever the client
//! sends on it is read, and logged by the observer, and the subflow closes
//! when its connection is gone.
//!
//! A join SYN that gets a SYN cookie is refused with "administratively
//! prohibited" when its connection is full. Otherwise what it carried is
//! kept as Linux keeps it (subflow_init_req_cookie_join_save): in one of
//! [`JOIN_COOKIE_SLOTS`] slots, picked by a keyed hash of its sequence
//! number and ports, which a later join SYN may take. The ACK that returns
//! the cookie with MP_JOIN takes it back, and is checked as any other.
//! When the slot is empty or another join took it, or the connection has
//! gone, that ACK is dropped with no answer (mptcp_subflow_init_cookie_req).
//!
//! [`Tokens`] holds the token, keys and port of each open connection that
//! negotiated MPTCP, from when it is accepted until it is gone, with its
//! joined subflows. It never lets a second connection take a token that is
//! open.

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::SocketAddr;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};

use fictionet::Cx;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::tcp::{
    AckAnswer, Answer, GoneWatch, Handshake, Kept, Received, SegmentVerdict, Segments, Sent, Syn,
    SynAnswer, TcpOption,
};
use fictionet::stdlib::network::{Connection, ConnectionExt};
use fictionet::stdlib::protocols::mptcp::{
    self, Capable, DataLevel, Join, Keys, MptcpOption, algorithm, join_hmac, reason, token,
};
use fictionet::stdlib::world::net::{Arrival, PortServer};
use fictionet::sync::Mutex;

/// How many subflows a connection takes by MP_JOIN beside its first, as
/// Linux's in-kernel path manager takes by default (subflows_max).
pub const MAX_SUBFLOWS: usize = 2;

/// The keys of one connection that uses MPTCP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyPair {
    /// The server's key, whose token names the connection.
    pub local: u64,
    /// The client's key.
    pub remote: u64,
}

/// One open connection in [`Tokens`].
struct Entry {
    keys: KeyPair,
    /// The port it was accepted on.
    port: u16,
    /// Its joined subflows, each with the waker of the task that holds
    /// it, woken when the connection is gone.
    joined: Vec<(u64, Option<Waker>)>,
    primary: Option<Waker>,
    reset: Arc<AtomicBool>,
}

#[derive(Default)]
struct Open {
    entries: HashMap<u32, Entry>,
    /// The number the next joined subflow is known by.
    next: u64,
}

/// The tokens of the server's open MPTCP connections, each with its keys,
/// its port and its joined subflows.
#[derive(Default)]
pub struct Tokens(Mutex<Open>);

impl Tokens {
    /// The keys of the open connection with `token`.
    pub fn keys(&self, token: u32) -> Option<KeyPair> {
        self.0.lock().entries.get(&token).map(|e| e.keys)
    }

    /// Whether an open connection has `token`.
    pub fn knows(&self, token: u32) -> bool {
        self.0.lock().entries.contains_key(&token)
    }

    /// The port of the open connection with `token`.
    pub fn port(&self, token: u32) -> Option<u16> {
        self.0.lock().entries.get(&token).map(|e| e.port)
    }

    /// How many subflows have joined the open connection with `token`.
    pub fn joined(&self, token: u32) -> usize {
        self.0
            .lock()
            .entries
            .get(&token)
            .map_or(0, |e| e.joined.len())
    }

    /// How many open connections use MPTCP.
    pub fn len(&self) -> usize {
        self.0.lock().entries.len()
    }

    /// Whether none does.
    pub fn is_empty(&self) -> bool {
        self.0.lock().entries.is_empty()
    }

    /// Removes a connection immediately and wakes every joined subflow.
    fn close(&self, token: u32, reset: bool) {
        let entry = self.0.lock().entries.remove(&token);
        if let Some(entry) = entry {
            entry.reset.store(reset, Ordering::Relaxed);
            if let Some(waker) = entry.primary {
                waker.wake();
            }
            for (_, waker) in entry.joined {
                if let Some(waker) = waker {
                    waker.wake();
                }
            }
        }
    }

    /// Notes the connection with `keys`, accepted on `port`, until the
    /// guard drops. `None` when its token already names an open
    /// connection: that one keeps it.
    fn open(self: &Arc<Self>, keys: KeyPair, port: u16) -> Option<Opened> {
        let mut open = self.0.lock();
        let token = token(keys.local);
        if open.entries.contains_key(&token) {
            return None;
        }
        open.entries.insert(
            token,
            Entry {
                keys,
                port,
                joined: Vec::new(),
                primary: None,
                reset: Arc::default(),
            },
        );
        Some(Opened {
            tokens: self.clone(),
            token,
        })
    }

    /// Notes a subflow joined to the open connection with `token`, until
    /// the guard drops. `None` when there is no such connection, or it has
    /// [`MAX_SUBFLOWS`] already.
    fn join(self: &Arc<Self>, token: u32) -> Option<Joined> {
        let mut open = self.0.lock();
        let open = &mut *open;
        let entry = open.entries.get_mut(&token)?;
        if entry.joined.len() >= MAX_SUBFLOWS {
            return None;
        }
        let id = open.next;
        open.next += 1;
        entry.joined.push((id, None));
        Some(Joined {
            tokens: self.clone(),
            token,
            id,
            reset: entry.reset.clone(),
        })
    }
}

/// One open connection's entry in [`Tokens`], removed when it drops. Its
/// joined subflows are woken then, and close.
struct Opened {
    tokens: Arc<Tokens>,
    token: u32,
}

impl Drop for Opened {
    fn drop(&mut self) {
        self.tokens.close(self.token, false);
    }
}

/// One joined subflow's place in its connection's entry, removed when it
/// drops.
struct Joined {
    tokens: Arc<Tokens>,
    token: u32,
    id: u64,
    reset: Arc<AtomicBool>,
}

impl Joined {
    /// Ready once the connection the subflow joined is gone.
    fn poll_gone(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut open = self.tokens.0.lock();
        let slot = open
            .entries
            .get_mut(&self.token)
            .and_then(|e| e.joined.iter_mut().find(|(id, _)| *id == self.id));
        match slot {
            Some((_, waker)) => {
                match waker {
                    Some(w) if w.will_wake(cx.waker()) => {}
                    _ => *waker = Some(cx.waker().clone()),
                }
                Poll::Pending
            }
            None => Poll::Ready(()),
        }
    }
}

impl Drop for Joined {
    fn drop(&mut self) {
        if let Some(entry) = self.tokens.0.lock().entries.get_mut(&self.token) {
            entry.joined.retain(|(id, _)| *id != self.id);
        }
    }
}

/// How many joins answered with a SYN cookie Linux keeps at once
/// (COOKIE_JOIN_SLOTS).
pub const JOIN_COOKIE_SLOTS: usize = 1024;

/// What a join SYN that got a SYN cookie carried, and the token it named.
struct JoinCookie {
    token: u32,
    kept: Kept,
}

/// The joins answered with SYN cookies, as Linux keeps them: see the
/// [module docs](self).
struct JoinCookies {
    /// The key of the hash that picks a slot.
    secret: u64,
    slots: Vec<Option<JoinCookie>>,
}

impl JoinCookies {
    fn new(secret: u64) -> JoinCookies {
        JoinCookies {
            secret,
            slots: (0..JOIN_COOKIE_SLOTS).map(|_| None).collect(),
        }
    }

    /// The slot of the SYN with sequence number `seq` from port `from` to
    /// port `to`.
    fn slot(&self, seq: u32, from: u16, to: u16) -> usize {
        let mut hasher = DefaultHasher::new();
        (self.secret, seq, from, to).hash(&mut hasher);
        (hasher.finish() % JOIN_COOKIE_SLOTS as u64) as usize
    }

    /// Keeps `cookie` for the SYN with sequence number `seq` from port
    /// `from` to port `to`, in place of whatever its slot held.
    fn save(&mut self, seq: u32, from: u16, to: u16, cookie: JoinCookie) {
        let slot = self.slot(seq, from, to);
        self.slots[slot] = Some(cookie);
    }

    /// Takes back what the slot of the SYN with sequence number `seq` from
    /// port `from` to port `to` holds, and empties it.
    fn take(&mut self, seq: u32, from: u16, to: u16) -> Option<JoinCookie> {
        let slot = self.slot(seq, from, to);
        self.slots[slot].take()
    }
}

/// The MPTCP options in a list of TCP options, read with the stdlib
/// codec. Options it cannot read are left out, as a host ignores them.
pub fn mptcp_options(options: &[TcpOption]) -> impl Iterator<Item = MptcpOption> + '_ {
    options.iter().filter_map(|o| match o {
        TcpOption::Unknown { kind, data } if *kind == mptcp::KIND => MptcpOption::parse(data).ok(),
        _ => None,
    })
}

/// Whether Linux takes MP_CAPABLE with these flags: B clear, and
/// HMAC-SHA256 as its only algorithm (mptcp_cap_flag_sha256).
fn takes_flags(capable: &Capable) -> bool {
    !capable.extensibility && capable.algorithms == algorithm::HMAC_SHA256
}

/// What a SYN's MPTCP options ask for, as Linux reads them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SynOffer {
    /// MP_CAPABLE counted. The value says whether one that counted asked
    /// for checksums.
    capable: Option<bool>,
    /// The last MP_JOIN that counted: its token and random number.
    join: Option<(u32, u32)>,
}

impl SynOffer {
    fn read(options: &[TcpOption]) -> SynOffer {
        let mut offer = SynOffer::default();
        for option in mptcp_options(options) {
            match option {
                MptcpOption::Capable(c)
                    if c.keys == Keys::Absent && c.version >= mptcp::VERSION && takes_flags(&c) =>
                {
                    let checksums = offer.capable.unwrap_or(false);
                    offer.capable = Some(checksums || c.checksum_required);
                }
                MptcpOption::Join(Join::Syn { token, random, .. }) => {
                    offer.join = Some((token, random));
                }
                _ => {}
            }
        }
        offer
    }
}

/// The MP_CAPABLE of an ACK that completes a handshake, as Linux reads it
/// on a segment that is not a SYN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AckCapable {
    /// The client's key.
    sender: u64,
    /// The key it echoes, the server's.
    receiver: u64,
    /// The Data-Level Length of the data it maps, when the ACK carries
    /// data.
    first: Option<u16>,
    /// Whether one that counted asked for checksums.
    checksums: bool,
}

/// What the ACK that completes a handshake carries, as Linux reads it:
/// the last MP_CAPABLE that counts, with whether any asked for checksums,
/// and the HMAC of the last MP_JOIN that counts. `payload` is how many
/// bytes of data the ACK carries.
fn read_ack(options: &[TcpOption], payload: usize) -> (Option<AckCapable>, Option<[u8; 20]>) {
    let mut capable: Option<AckCapable> = None;
    let mut hmac = None;
    for option in mptcp_options(options) {
        match option {
            MptcpOption::Capable(c) if c.version == mptcp::VERSION && takes_flags(&c) => {
                let (sender, receiver, first) = match (c.keys, payload) {
                    (Keys::Both { sender, receiver }, 0) => (sender, receiver, None),
                    (
                        Keys::Data {
                            sender,
                            receiver,
                            data_level_length,
                            ..
                        },
                        1..,
                    ) => (sender, receiver, Some(data_level_length)),
                    _ => continue,
                };
                let checksums = capable.is_some_and(|c| c.checksums) || c.checksum_required;
                capable = Some(AckCapable {
                    sender,
                    receiver,
                    first,
                    checksums,
                });
            }
            MptcpOption::Join(Join::Ack { hmac: h }) => hmac = Some(h),
            _ => {}
        }
    }
    (capable, hmac)
}

/// How a listener answers `syn` on `port`. `random` gives the key of a new
/// MPTCP connection and the random number of a join's SYN-ACK.
pub fn answer_syn(
    syn: &Syn<'_>,
    port: u16,
    tokens: &Tokens,
    mut random: impl FnMut() -> u64,
) -> SynAnswer {
    let offer = SynOffer::read(syn.options);
    match (offer.capable, offer.join) {
        (Some(checksums), None) => {
            // Linux draws again for a key of 0 or one whose token is open.
            let key = loop {
                let key = random();
                if key != 0 && !tokens.knows(token(key)) {
                    break key;
                }
            };
            SynAnswer::Accept(vec![option(MptcpOption::Capable(Capable {
                version: mptcp::VERSION,
                checksum_required: checksums,
                extensibility: false,
                no_new_subflows: false,
                algorithms: algorithm::HMAC_SHA256,
                keys: Keys::Sender(key),
            }))])
        }
        (None, Some((token, their_random))) => match tokens.keys(token) {
            None => SynAnswer::Refuse(vec![tcprst(reason::MPTCP_SPECIFIC)]),
            Some(_) if tokens.port(token) != Some(port) => {
                SynAnswer::Refuse(vec![tcprst(reason::ADMINISTRATIVELY_PROHIBITED)])
            }
            // A SYN cookie's join is checked for room now, as nothing but
            // what the cookie table keeps is left at its ACK.
            Some(_) if syn.cookie && tokens.joined(token) >= MAX_SUBFLOWS => {
                SynAnswer::Refuse(vec![tcprst(reason::ADMINISTRATIVELY_PROHIBITED)])
            }
            Some(keys) => {
                let our_random = random() as u32;
                let hmac = join_hmac(keys.local, keys.remote, our_random, their_random);
                let mut truncated = [0; 8];
                truncated.copy_from_slice(&hmac[..8]);
                // The initial subflow's address, with no backup flag, as
                // a Linux listener with no endpoints configured answers.
                SynAnswer::Accept(vec![option(MptcpOption::Join(Join::SynAck {
                    backup: false,
                    address_id: 0,
                    hmac: truncated,
                    random: our_random,
                }))])
            }
        },
        _ => SynAnswer::Accept(Vec::new()),
    }
}

/// An MPTCP connection, as its handshake set it up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Negotiated {
    /// Its keys.
    pub keys: KeyPair,
    /// Whether it uses DSS checksums.
    pub checksums: bool,
    /// The Data-Level Length of the client's data the third ACK mapped,
    /// when it carried data.
    pub first: Option<u16>,
    /// Whether its SYN was answered with a SYN cookie.
    pub cookie: bool,
}

/// A join, as its handshake left it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JoinAck {
    /// The token of the connection it joins.
    pub token: u32,
    /// The client's random number, from its SYN.
    pub their_random: u32,
    /// The server's, from its SYN-ACK.
    pub our_random: u32,
    /// The client's HMAC, from its third ACK, if that carried one.
    pub hmac: Option<[u8; 20]>,
}

/// What a completed handshake set up, before the listener's checks
/// against its open connections: see the [module docs](self).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    /// Plain TCP.
    Plain,
    /// An MPTCP connection.
    Mptcp(Negotiated),
    /// A subflow joining a connection. `None` when its SYN was answered
    /// with a SYN cookie and the listener had nothing of it left to check
    /// the join by: Linux drops its ACK.
    Join(Option<JoinAck>),
    /// An ACK Linux drops.
    Drop,
}

/// What `handshake` set up. The server's key is the one its SYN-ACK sent
/// or, after a SYN cookie, the one the third ACK echoes. A join's SYN and
/// SYN-ACK after a SYN cookie are what the listener kept of them, if
/// anything.
pub fn complete(handshake: &Handshake) -> Completion {
    let (capable, hmac) = read_ack(&handshake.ack, handshake.ack_payload);
    let Some(syn_ack) = &handshake.syn_ack else {
        // A SYN cookie with nothing kept: the ACK says it all.
        return match (capable, hmac) {
            (Some(_), Some(_)) => Completion::Drop,
            (Some(c), None) if c.sender == 0 => Completion::Drop,
            (Some(c), None) => Completion::Mptcp(Negotiated {
                keys: KeyPair {
                    local: c.receiver,
                    remote: c.sender,
                },
                checksums: c.checksums,
                first: c.first,
                cookie: true,
            }),
            (None, Some(_)) => Completion::Join(None),
            (None, None) => Completion::Plain,
        };
    };
    for answered in mptcp_options(syn_ack) {
        match answered {
            MptcpOption::Capable(Capable {
                keys: Keys::Sender(local),
                checksum_required,
                ..
            }) => {
                return match capable {
                    Some(c) => Completion::Mptcp(Negotiated {
                        keys: KeyPair {
                            local,
                            remote: c.sender,
                        },
                        checksums: checksum_required || c.checksums,
                        first: c.first,
                        cookie: false,
                    }),
                    None => Completion::Plain,
                };
            }
            MptcpOption::Join(Join::SynAck {
                random: our_random, ..
            }) => {
                let syn = handshake.syn.as_deref().unwrap_or_default();
                let Some((token, their_random)) = SynOffer::read(syn).join else {
                    return Completion::Join(None);
                };
                return Completion::Join(Some(JoinAck {
                    token,
                    their_random,
                    our_random,
                    hmac,
                }));
            }
            _ => {}
        }
    }
    Completion::Plain
}

/// How the listener answers the ACK that completes a handshake: see the
/// [module docs](self).
pub fn answer_ack(handshake: &Handshake, tokens: &Tokens) -> AckAnswer {
    let prohibited = || AckAnswer::Refuse(vec![tcprst(reason::ADMINISTRATIVELY_PROHIBITED)]);
    match complete(handshake) {
        Completion::Plain => AckAnswer::Accept,
        Completion::Mptcp(n) if n.cookie && tokens.knows(token(n.keys.local)) => AckAnswer::Drop,
        Completion::Mptcp(_) => AckAnswer::Accept,
        Completion::Drop | Completion::Join(None) => AckAnswer::Drop,
        Completion::Join(Some(join)) => {
            // A join cannot fall back to TCP, so Linux refuses one whose
            // ACK has no MP_JOIN it takes before it looks for the
            // connection (subflow_syn_recv_sock).
            let Some(hmac) = join.hmac else {
                return AckAnswer::Refuse(vec![tcprst(reason::MPTCP_SPECIFIC)]);
            };
            let Some(keys) = tokens.keys(join.token) else {
                return prohibited();
            };
            let expected = join_hmac(keys.remote, keys.local, join.their_random, join.our_random);
            if hmac[..] == expected[..20] && tokens.joined(join.token) < MAX_SUBFLOWS {
                AckAnswer::Accept
            } else {
                prohibited()
            }
        }
    }
}

/// An MPTCP option as a TCP option.
fn option(option: MptcpOption) -> TcpOption {
    TcpOption::Unknown {
        kind: mptcp::KIND,
        data: option
            .to_bytes()
            .expect("the listener writes only options the codec reads"),
    }
}

/// MP_TCPRST, not transient, with `reason`.
fn tcprst(reason: u8) -> TcpOption {
    option(MptcpOption::TcpRst {
        transient: false,
        reason,
    })
}

/// MPTCP control and data options on an established subflow.
struct Dss {
    level: Option<DataLevel>,
    key: u64,
    tokens: Arc<Tokens>,
}

impl Dss {
    fn verdict(&self, acknowledge: bool) -> SegmentVerdict {
        if self
            .level
            .as_ref()
            .is_some_and(|level| level.error().is_some())
        {
            SegmentVerdict::Reset(vec![tcprst(reason::MPTCP_SPECIFIC)])
        } else if acknowledge {
            SegmentVerdict::Acknowledge
        } else {
            SegmentVerdict::Take
        }
    }
}

impl Segments for Dss {
    fn room(&self) -> usize {
        DataLevel::ROOM
    }

    fn sent(&mut self, segment: &Sent<'_>) -> Vec<TcpOption> {
        self.level
            .as_mut()
            .and_then(|level| {
                level.sent(
                    segment.seq,
                    segment.payload,
                    segment.fin,
                    segment.ack.is_some(),
                )
            })
            .map(|dss| vec![option(MptcpOption::Dss(dss))])
            .unwrap_or_default()
    }

    fn received(&mut self, segment: &Received<'_>) -> SegmentVerdict {
        let options: Vec<_> = mptcp_options(segment.options).collect();
        if options.iter().any(|option| matches!(option, MptcpOption::FastClose { receiver_key } if *receiver_key == self.key)) {
            self.tokens.close(token(self.key), true);
            return SegmentVerdict::Reset(self.reset());
        }
        let acknowledge = if let Some(level) = &mut self.level {
            level.received(segment.seq, segment.payload.len(), options)
        } else {
            options
                .iter()
                .any(|option| matches!(option, MptcpOption::Join(Join::Ack { .. })))
        };
        self.verdict(acknowledge)
    }

    fn arrived(&mut self, seq: u32, data: &[u8], out: &mut Vec<u8>) -> SegmentVerdict {
        if let Some(level) = &mut self.level {
            level.arrived(seq, data, out);
        }
        self.verdict(false)
    }

    /// Linux puts MP_TCPRST on every RST of a subflow that has not fallen
    /// back, with "unspecified error" unless it had a reason
    /// (mptcp_established_options_rst).
    fn reset(&mut self) -> Vec<TcpOption> {
        if self.level.as_ref().is_some_and(DataLevel::fallen_back) {
            Vec::new()
        } else {
            vec![tcprst(reason::UNSPECIFIED)]
        }
    }
}

/// A port server with an MPTCP listener in front: it answers handshakes as
/// the [module docs](self) say, notes each MPTCP connection's token while
/// the connection is open, holds joined subflows, and hands every other
/// connection to `inner`.
pub struct Listener<S> {
    inner: S,
    tokens: Arc<Tokens>,
    port: u16,
    joins: Arc<Mutex<JoinCookies>>,
    fcx: Cx,
    timestamp: Arc<dyn Fn() -> u32 + Send + Sync>,
}

impl<S> Listener<S> {
    /// `inner` on `port` behind an MPTCP listener whose keys come from
    /// `fcx`. `timestamp` supplies IPv4 option timestamps in milliseconds
    /// since midnight UTC.
    pub fn new(
        fcx: &Cx,
        timestamp: impl Fn() -> u32 + Send + Sync + 'static,
        tokens: Arc<Tokens>,
        port: u16,
        inner: S,
    ) -> Listener<S> {
        Listener {
            inner,
            tokens,
            port,
            joins: Arc::new(Mutex::new(JoinCookies::new(fcx.random_u64()))),
            fcx: fcx.clone(),
            timestamp: Arc::new(timestamp),
        }
    }
}

/// The listener's answers, as the endpoint asks for them.
struct Answers {
    tokens: Arc<Tokens>,
    port: u16,
    joins: Arc<Mutex<JoinCookies>>,
    fcx: Cx,
    timestamp: Arc<dyn Fn() -> u32 + Send + Sync>,
}

impl Answer for Answers {
    fn syn(&self, syn: &Syn<'_>) -> SynAnswer {
        let answer = answer_syn(syn, self.port, &self.tokens, || self.fcx.random_u64());
        let offer = SynOffer::read(syn.options);
        if let (true, None, Some((token, _)), SynAnswer::Accept(added)) =
            (syn.cookie, offer.capable, offer.join, &answer)
            && let Some(ipv4) = self.ipv4_options(syn)
        {
            let kept = Kept {
                syn: syn.options.into(),
                syn_ack: added.as_slice().into(),
                syn_ipv4: syn.to.is_ipv4().then(|| syn.ipv4_options.into()),
                syn_ack_ipv4: syn.to.is_ipv4().then(|| ipv4.options.into()),
            };
            let cookie = JoinCookie { token, kept };
            self.joins
                .lock()
                .save(syn.seq, syn.from.port(), self.port, cookie);
        }
        answer
    }

    fn ipv4_options(&self, syn: &Syn<'_>) -> Option<fictionet::stdlib::network::ip::Ipv4Reply> {
        super::syn_ipv4_options(syn, (self.timestamp)())
    }

    fn retransmit_ipv4_options(
        &self,
        handshake: &Handshake,
    ) -> Option<Vec<fictionet::stdlib::network::ip::Ipv4Option>> {
        super::handshake_ipv4_options(handshake, (self.timestamp)())
    }

    fn cookie(&self, from: SocketAddr, handshake: &Handshake) -> Option<Kept> {
        // Only an ACK with MP_JOIN alone looks for what a join kept.
        let (None, Some(_)) = read_ack(&handshake.ack, handshake.ack_payload) else {
            return None;
        };
        let cookie = self
            .joins
            .lock()
            .take(handshake.irs, from.port(), self.port)?;
        self.tokens.knows(cookie.token).then_some(cookie.kept)
    }

    fn ack(&self, handshake: &Handshake) -> AckAnswer {
        answer_ack(handshake, &self.tokens)
    }

    fn segments(&self, handshake: &Handshake) -> Option<Box<dyn Segments>> {
        let (key, level) = match complete(handshake) {
            Completion::Mptcp(n) => (
                n.keys.local,
                Some(
                    DataLevel::new(
                        n.keys.local,
                        n.keys.remote,
                        handshake.iss,
                        handshake.irs,
                        n.checksums,
                        n.first,
                    )
                    .ack_width(super::mptcp_ack_width()),
                ),
            ),
            Completion::Join(Some(join)) => (self.tokens.keys(join.token)?.local, None),
            _ => return None,
        };
        Some(Box::new(Dss {
            level,
            key,
            tokens: self.tokens.clone(),
        }))
    }
}

/// Reads a joined subflow until the client closes it or the connection it
/// joined is gone.
async fn hold(fcx: Cx, mut conn: Box<dyn Connection>, socket: GoneWatch, joined: Joined) {
    let mut buf = [0; 4096];
    loop {
        let mut read = pin!(conn.read(&fcx, &mut buf));
        let step = poll_fn(|cx| {
            if joined.poll_gone(cx).is_ready() {
                return Poll::Ready(None);
            }
            read.as_mut().poll(cx).map(Some)
        })
        .await;
        if step.is_none() && joined.reset.load(Ordering::Relaxed) {
            socket.reset();
        }
        if !matches!(step, Some(Ok(1..))) {
            return;
        }
    }
}

impl<S: PortServer> PortServer for Listener<S> {
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        match complete(
            arrival
                .info
                .handshake
                .as_ref()
                .expect("accepted TCP handshake"),
        ) {
            Completion::Mptcp(n) => {
                if let Some(opened) = self.tokens.open(n.keys, self.port) {
                    arrival.socket.hold_until_gone(Box::new(opened));
                }
                let socket = arrival.socket.clone();
                let tokens = self.tokens.clone();
                let token = token(n.keys.local);
                let mut service = self.inner.serve(fcx, arrival);
                Box::pin(async move {
                    poll_fn(|cx| {
                        let mut open = tokens.0.lock();
                        let Some(entry) = open.entries.get_mut(&token) else {
                            drop(open);
                            socket.reset();
                            return Poll::Ready(());
                        };
                        entry.primary = Some(cx.waker().clone());
                        drop(open);
                        service.as_mut().poll(cx)
                    })
                    .await;
                })
            }
            Completion::Join(Some(join)) => match self.tokens.join(join.token) {
                Some(joined) => {
                    // Linux's first keepalive on a subflow comes no sooner
                    // than its connection's, which ends long before.
                    arrival.socket.set_keep_alive(None);
                    Box::pin(hold(fcx, arrival.conn, arrival.socket, joined))
                }
                None => {
                    arrival.socket.reset();
                    Box::pin(async {})
                }
            },
            Completion::Plain | Completion::Join(None) | Completion::Drop => {
                self.inner.serve(fcx, arrival)
            }
        }
    }

    fn alpn(&self) -> Vec<Vec<u8>> {
        self.inner.alpn()
    }

    fn backlog(&self) -> Option<usize> {
        self.inner.backlog()
    }

    fn answer(&self) -> Option<Box<dyn Answer>> {
        Some(Box::new(Answers {
            tokens: self.tokens.clone(),
            port: self.port,
            joins: self.joins.clone(),
            fcx: self.fcx.clone(),
            timestamp: self.timestamp.clone(),
        }))
    }
}
