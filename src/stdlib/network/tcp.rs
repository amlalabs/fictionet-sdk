//! TCP: listeners and connections for a machine on the simulated network.
//!
//! Use this module to give a machine TCP, so that a sandbox can connect to
//! it, or so that it can connect out. [`endpoint`] takes an [`Interface`]
//! that carries the machine's TCP packets, and the machine's address. It
//! returns an [`Endpoint`], one machine's TCP. From it you
//! [`listen`](Endpoint::listen) on a port and [`accept`](Listener::accept)
//! connections, or [`connect`](Endpoint::connect) to another machine. Each
//! connection is a [`TcpConnection`], which implements [`Connection`].
//!
//! [`endpoint_with`] takes custom [`Options`]. [`prepare_endpoint`] builds
//! the same endpoint without starting a task, so listeners can be opened
//! before [`Prepared::start`]. Drop the driver and its handles to discard
//! the preparation.
//!
//! Inside, an endpoint is one background task that runs the smoltcp TCP
//! stack. The interface it takes comes from
//! [`ip::split_protocols`](fictionet::stdlib::network::ip::split_protocols), which
//! splits a machine's packets so that only TCP, and ICMP errors about it,
//! reach this layer.
//!
//! smoltcp handles TCP receive windows, acknowledgments, and retransmission.
//! Empty buffer pages are released only when the socket also holds no
//! out-of-order data.
//!
//! This builds a machine at `104.18.32.7` and accepts connections on its
//! port 443. The other end of the [`pair`](fictionet::pair) goes to a router,
//! as the [`route`](fictionet::stdlib::network::route) page shows:
//!
//! ```
//! # use fictionet::{Cx, Result, pair};
//! # use fictionet::stdlib::network::{ip, tcp};
//! # async fn stripe(fcx: Cx) -> Result {
//! // A link between the router and Stripe's machine.
//! let (router_side, stripe_side) = pair();
//! // ...give router_side to the router for 104.18.32.7/32...
//!
//! let (tcp, _udp, _icmp, _other) = ip::split_protocols(&fcx, stripe_side);
//! let stripe = tcp::endpoint(&fcx, tcp, "104.18.32.7".parse()?);
//! let mut listener = stripe.listen(443)?;
//! while let Ok(conn) = listener.accept(&fcx).await {
//!     // TLS, then HTTP
//! #   drop(conn);
//! }
//! # drop(router_side);
//! # Ok(())
//! # }
//! ```

use fictionet::stdlib::codec::Side;
use fictionet::sync::Mutex;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::future::{Future, poll_fn};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use smoltcp::iface::{Config, Interface as Iface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, RxToken, TxToken};
use smoltcp::socket::tcp::{self as stcp, State as TcpState};
use smoltcp::wire::{Ipv4Packet, TcpOption as WireOption, TcpPacket, TcpRepr};

use fictionet::CancelWait;
use fictionet::stdlib::network::ip::{
    Header, checksum,
    protocol::{ICMP, TCP},
    strip_extension_headers, transport_checksum,
};
use fictionet::stdlib::network::{ConnError, Connection};
use fictionet::time::{Duration, Instant};
use fictionet::{Cx, Error, Interface, Packet};

/// The MTU the endpoint assumes. Segments it sends are at most the smaller
/// of this and what the peer's MSS option allows.
const MTU: usize = 1500;
/// Packets emitted before downstream tasks get a turn. Splits handle
/// 64 packets per turn across both directions, including returning ACKs.
const EGRESS_PACKETS: usize = 32;
/// Receive and send buffer per connection, unless [`Options::buffer`] says
/// otherwise. The receive buffer is the window.
const BUFFER: usize = 256 * 1024;
/// The smallest and largest buffers [`Options::buffer`] allows.
const MIN_BUFFER: usize = 4 * 1024;
const MAX_BUFFER: usize = 64 * 1024 * 1024;
/// How often buffers of connections that went quiet are given back to the
/// system.
const RELEASE_EVERY: Duration = Duration::from_secs(1);
/// A connection whose peer sends nothing for this long while it waits for
/// an answer (a SYN, unacknowledged data, a keepalive) is given up.
const TIMEOUT: Duration = Duration::from_secs(120);
/// A handshake whose last ACK has not come this long after its SYN is
/// dropped without a RST, as Linux drops it: by default Linux resends the
/// SYN-ACK five times (tcp_synack_retries), 1, 3, 7, 15 and 31 seconds
/// after the first, and waits 32 seconds after the last.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(63);
/// A connection whose handle was dropped is given up when the peer sends
/// nothing for this long, and forgotten this long after it enters
/// FIN-WAIT-2, as when the peer never closes its side.
const ORPHAN_TIMEOUT: Duration = Duration::from_secs(60);
/// Idle connections send a keepalive this often, so a peer that is gone is
/// noticed within `TIMEOUT`.
const KEEPALIVE: Duration = Duration::from_secs(45);
/// Connections per port that have arrived but not been accepted yet,
/// unless [`Options::backlog`] says otherwise. More connection attempts get
/// SYN cookies.
const BACKLOG: usize = 4096;
/// The largest backlog [`Options::backlog`] allows.
const MAX_BACKLOG: usize = 65_536;
/// Of those, at most this many from one peer address. More attempts from
/// that address get SYN cookies, so spoofed attempts cannot prevent a
/// real peer from completing its handshake. A peer whose address cannot be
/// spoofed has them dropped instead.
const BACKLOG_PER_PEER: usize = 256;
/// The first local port for outgoing connections.
const EPHEMERAL: u16 = 49152;
/// Dropped TIME-WAIT sockets per endpoint. Past this limit, those first
/// seen in TIME-WAIT by housekeeping are forgotten first.
const MAX_TIME_WAIT: usize = 1024;

/// The option bytes a listener's [`Answer`] can add to a SYN-ACK or a RST:
/// what the 40 bytes of option space leave beside the endpoint's own
/// options.
pub const SYN_OPTIONS_ROOM: usize = stcp::SYN_OPTIONS_ROOM;

/// One option of a TCP header (RFC 9293 section 3.1): one a peer's SYN or
/// ACK carried ([`Handshake`]), or one a listener adds to its SYN-ACK
/// ([`Answer`]). End of Option List is not one: the list just ends there.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TcpOption {
    /// No-Operation (kind 1), which pads the next option to a word.
    NoOperation,
    /// Maximum Segment Size (kind 2).
    MaxSegmentSize(u16),
    /// Window Scale (kind 3, RFC 7323): the shift as sent, even over 14.
    WindowScale(u8),
    /// SACK-Permitted (kind 4, RFC 2018).
    SackPermitted,
    /// SACK (kind 5, RFC 2018): one to four blocks, each a left and a
    /// right edge.
    Sack(Vec<(u32, u32)>),
    /// Timestamps (kind 8, RFC 7323).
    Timestamps {
        /// TSval, the sender's clock.
        tsval: u32,
        /// TSecr, the TSval it echoes.
        tsecr: u32,
    },
    /// Any other kind, such as MPTCP's 30 (RFC 8684), or a known kind with
    /// a Length its RFC does not define, which Linux ignores: the bytes
    /// after Kind and Length.
    Unknown {
        /// The option's kind.
        kind: u8,
        /// The bytes after Kind and Length.
        data: Vec<u8>,
    },
}

impl TcpOption {
    /// The option smoltcp read, or `None` for End of Option List.
    fn from_wire(option: WireOption) -> Option<TcpOption> {
        Some(match option {
            WireOption::EndOfList => return None,
            WireOption::NoOperation => TcpOption::NoOperation,
            WireOption::MaxSegmentSize(mss) => TcpOption::MaxSegmentSize(mss),
            WireOption::WindowScale(shift) => TcpOption::WindowScale(shift),
            WireOption::SackPermitted => TcpOption::SackPermitted,
            WireOption::SackRange(blocks) => {
                TcpOption::Sack(blocks.into_iter().flatten().collect())
            }
            WireOption::TimeStamp { tsval, tsecr } => TcpOption::Timestamps { tsval, tsecr },
            WireOption::Unknown { kind, data } => TcpOption::Unknown {
                kind,
                data: data.to_vec(),
            },
        })
    }

    /// The option for smoltcp to write, or `None` for SACK without one to
    /// four blocks.
    fn to_wire(&self) -> Option<WireOption<'_>> {
        Some(match self {
            TcpOption::NoOperation => WireOption::NoOperation,
            TcpOption::MaxSegmentSize(mss) => WireOption::MaxSegmentSize(*mss),
            TcpOption::WindowScale(shift) => WireOption::WindowScale(*shift),
            TcpOption::SackPermitted => WireOption::SackPermitted,
            TcpOption::Sack(blocks) => {
                if blocks.is_empty() || blocks.len() > 4 {
                    return None;
                }
                let mut wire = [None; 4];
                for (slot, block) in wire.iter_mut().zip(blocks) {
                    *slot = Some(*block);
                }
                WireOption::SackRange(wire)
            }
            TcpOption::Timestamps { tsval, tsecr } => WireOption::TimeStamp {
                tsval: *tsval,
                tsecr: *tsecr,
            },
            TcpOption::Unknown { kind, data } => WireOption::Unknown { kind: *kind, data },
        })
    }
}

/// Why [`options`] could not read all of a segment's options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OptionsError {
    /// The segment is shorter than 20 bytes or than its header length
    /// says, or its header length is under 20 bytes.
    Header,
    /// An option's Length is under 2 or runs past the header. Holds the
    /// options before it, which read correctly.
    Malformed(Vec<TcpOption>),
}

impl std::fmt::Display for OptionsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OptionsError::Header => f.write_str("TCP header length does not fit the segment"),
            OptionsError::Malformed(read) => {
                write!(f, "TCP option malformed after {} good ones", read.len())
            }
        }
    }
}

impl std::error::Error for OptionsError {}

/// The options in the header of `segment`, a TCP segment from its first
/// header byte, in the order they were sent. Reading stops at End of
/// Option List. The checks are those the world's TCP makes, so any bytes
/// may be passed, such as a packet straight off an attachment.
pub fn options(segment: &[u8]) -> Result<Vec<TcpOption>, OptionsError> {
    let iter = TcpPacket::new_unchecked(segment)
        .options_iter()
        .map_err(|_| OptionsError::Header)?;
    let mut read = Vec::new();
    for option in iter {
        match option {
            Ok(option) => read.extend(TcpOption::from_wire(option)),
            Err(_) => return Err(OptionsError::Malformed(read)),
        }
    }
    Ok(read)
}

/// The options of `segment`, a TCP segment that smoltcp parsed, up to the
/// first malformed one.
fn segment_options(segment: &[u8]) -> Arc<[TcpOption]> {
    match options(segment) {
        Ok(read) | Err(OptionsError::Malformed(read)) => read.into(),
        Err(OptionsError::Header) => Arc::default(),
    }
}

/// Whether `addr` can be one host's address, as smoltcp asks of a source:
/// not unspecified, multicast, or the IPv4 limited broadcast.
fn unicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => !(a.is_unspecified() || a.is_multicast() || a.is_broadcast()),
        IpAddr::V6(a) => !(a.is_unspecified() || a.is_multicast()),
    }
}

/// The options as they go on the wire, or `None` if they cannot be sent:
/// more than [`SYN_OPTIONS_ROOM`] bytes, or one that would not read back
/// as written.
fn encode(options: &[TcpOption]) -> Option<Vec<u8>> {
    let wire: Option<Vec<_>> = options.iter().map(TcpOption::to_wire).collect();
    stcp::encode_options(&wire?).ok()
}

/// How a listener retained a connection's handshake.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum HandshakeOrigin {
    /// The endpoint kept the SYN while waiting for the final ACK.
    #[default]
    Syn,
    /// The peer returned a SYN cookie; the listener may have retained options.
    Cookie,
}

/// What a handshake carried, for a connection a listener accepted: what
/// a listener's [`Answer::ack`] sees, and what the connection keeps
/// ([`TcpConnection::handshake`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Handshake {
    /// Whether the endpoint kept the SYN or used a SYN cookie.
    pub origin: HandshakeOrigin,
    /// The options of the peer's SYN, in the order it sent them, up to the
    /// first malformed one. `None` when the endpoint kept nothing of the
    /// SYN, because its SYN-ACK was a SYN cookie (see [`Options::backlog`]),
    /// unless the listener kept them itself ([`Answer::cookie`]).
    pub syn: Option<Arc<[TcpOption]>>,
    /// The options the listener's [`Answer::syn`] added to its SYN-ACK, in
    /// order. `None` as for `syn`.
    pub syn_ack: Option<Arc<[TcpOption]>>,
    /// The options of the ACK that completed the handshake, as `syn` reads
    /// them.
    pub ack: Arc<[TcpOption]>,
    /// How many bytes of data that ACK carried.
    pub ack_payload: usize,
    /// The peer's initial sequence number, its SYN's.
    pub irs: u32,
    /// This side's initial sequence number, its SYN-ACK's.
    pub iss: u32,
}

/// A SYN for a listening port, as [`Answer::syn`] sees it.
#[derive(Clone, Copy, Debug)]
pub struct Syn<'a> {
    /// Its options, in the order sent, up to the first malformed one.
    pub options: &'a [TcpOption],
    /// Its source address and port.
    pub from: SocketAddr,
    /// Its sequence number.
    pub seq: u32,
    /// Whether it gets a SYN cookie, as the backlog is full: the endpoint
    /// keeps nothing of the attempt (see [`Options::backlog`]).
    pub cookie: bool,
}

/// What a handshake answered with a SYN cookie carried at its SYN and
/// SYN-ACK, as the listener kept it: what [`Answer::cookie`] returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kept {
    /// The SYN's options: the handshake's [`syn`](Handshake::syn).
    pub syn: Arc<[TcpOption]>,
    /// The options the SYN-ACK added: its [`syn_ack`](Handshake::syn_ack).
    pub syn_ack: Arc<[TcpOption]>,
}

/// How a listener answers one connection attempt's SYN: what
/// [`Answer::syn`] returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SynAnswer {
    /// Answer with a SYN-ACK that carries these options after the
    /// endpoint's own. An empty list is the SYN-ACK the endpoint sends
    /// with no answer set.
    Accept(Vec<TcpOption>),
    /// Refuse with a RST that carries these options, as an MPTCP host
    /// refuses a subflow for a connection it does not know with MP_TCPRST
    /// (RFC 8684 section 3.6). The attempt never reaches `accept`.
    Refuse(Vec<TcpOption>),
}

/// How a listener answers the ACK that completes a handshake: what
/// [`Answer::ack`] returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AckAnswer {
    /// Take the connection: it goes to `accept`.
    Accept,
    /// Refuse it with a RST that carries these options, as an MPTCP host
    /// refuses a subflow at its third ACK with MP_TCPRST (RFC 8684 sections
    /// 3.2 and 3.6). The connection never reaches `accept`.
    Refuse(Vec<TcpOption>),
    /// Drop the ACK and forget the connection without sending anything,
    /// as Linux drops an ACK that returns a SYN cookie when it cannot set
    /// up what the ACK asks for. The connection never reaches `accept`.
    Drop,
}

/// A listener's say in its handshakes, set with [`Listener::answer`]: the
/// options its SYN-ACKs carry, which connections it refuses, and the
/// options the connections it takes carry from then on. A server for
/// MPTCP (RFC 8684) answers MP_CAPABLE and MP_JOIN here.
///
/// Each runs inside the endpoint with its lock held, so none may use the
/// endpoint or its connections. Any function from a [`Syn`] to a
/// [`SynAnswer`] is an `Answer` that takes every connection at its ACK.
pub trait Answer: Send {
    /// How to answer `syn`. A socket keeps the attempt while the backlog
    /// has room, and a copy of the SYN does not ask again. Past the
    /// backlog the SYN gets a SYN cookie and nothing is kept (see
    /// [`Options::backlog`]), so each copy of the SYN asks again, and an
    /// answer that draws something new, such as a key, gives each copy a
    /// different one.
    fn syn(&self, syn: &Syn<'_>) -> SynAnswer;

    /// What the SYN and SYN-ACK of `handshake`, answered with a SYN cookie,
    /// carried, if this listener kept that itself when it answered the SYN,
    /// as Linux keeps an MP_JOIN's (RFC 8684 section 3.2). Asked once, when
    /// the ACK that returns the cookie arrives from `from`, before
    /// [`ack`](Answer::ack). What it returns becomes the handshake's `syn`
    /// and `syn_ack`. The default keeps nothing.
    fn cookie(&self, from: SocketAddr, handshake: &Handshake) -> Option<Kept> {
        let _ = (from, handshake);
        None
    }

    /// Whether to take the connection whose handshake this is, when the
    /// ACK that completes it arrives. The default takes every one.
    fn ack(&self, handshake: &Handshake) -> AckAnswer {
        let _ = handshake;
        AckAnswer::Accept
    }

    /// What adds options to the segments of a connection this took, from
    /// the ACK that completed its handshake on, such as an MPTCP host's
    /// DSS (RFC 8684 section 3.3). The default adds none.
    fn segments(&self, handshake: &Handshake) -> Option<Box<dyn Segments>> {
        let _ = handshake;
        None
    }
}

/// A segment a connection sends, as [`Segments::sent`] sees it.
#[derive(Clone, Copy, Debug)]
pub struct Sent<'a> {
    /// Its sequence number.
    pub seq: u32,
    /// Its data.
    pub payload: &'a [u8],
    /// Whether it carries a FIN.
    pub fin: bool,
    /// Its acknowledgment number.
    pub ack: Option<u32>,
}

/// A segment a connection took, in its receive window, as
/// [`Segments::received`] sees it.
#[derive(Clone, Copy, Debug)]
pub struct Received<'a> {
    /// Its sequence number.
    pub seq: u32,
    /// Its data, all of it, as sent.
    pub payload: &'a [u8],
    /// Whether it carries a FIN.
    pub fin: bool,
    /// Its options, in order, up to the first malformed one.
    pub options: &'a [TcpOption],
}

/// Options a connection carries on every segment after its handshake,
/// beside the endpoint's own, from [`Answer::segments`]: what a protocol
/// over TCP, such as Multipath TCP, puts on each segment.
pub trait Segments: Send {
    /// The most option bytes [`sent`](Segments::sent) gives one segment,
    /// at most [`SEGMENT_OPTIONS_ROOM`]. Each segment with data leaves this
    /// much room, so it carries that much less data.
    fn room(&self) -> usize;

    /// The options for `segment`, which is about to be sent: any segment
    /// but a RST, retransmissions included. Options that take more than
    /// [`room`](Segments::room) bytes, or would not read back as written,
    /// are not sent.
    fn sent(&mut self, segment: &Sent<'_>) -> Vec<TcpOption>;

    /// Sees an accepted segment, including the handshake ACK, before its
    /// data can be read, and chooses whether to acknowledge or reset it.
    fn received(&mut self, segment: &Received<'_>) -> SegmentVerdict;

    /// Validates and orders contiguous bytes before the application reads them.
    fn arrived(&mut self, seq: u32, data: &[u8], out: &mut Vec<u8>) -> SegmentVerdict {
        let _ = seq;
        out.extend_from_slice(data);
        SegmentVerdict::Take
    }

    /// The options for a RST the connection sends with none of its own,
    /// such as when the server resets it, as an MPTCP host puts MP_TCPRST
    /// on every RST of a subflow (RFC 8684 section 3.6). Default none.
    fn reset(&mut self) -> Vec<TcpOption> {
        Vec::new()
    }
}

/// The action requested by the protocol carried over a TCP connection.
pub enum SegmentVerdict {
    /// Accept the segment.
    Take,
    /// Send an immediate ACK.
    Acknowledge,
    /// Reset with these TCP options.
    Reset(Vec<TcpOption>),
}

impl SegmentVerdict {
    fn on_wire(self) -> stcp::Verdict {
        match self {
            Self::Take => stcp::Verdict::Take,
            Self::Acknowledge => stcp::Verdict::Acknowledge,
            Self::Reset(options) => stcp::Verdict::Reset(encode(&options).unwrap_or_default()),
        }
    }
}

/// The option bytes a [`Segments`] can add to one segment: what the 40
/// bytes of option space leave beside timestamps.
pub const SEGMENT_OPTIONS_ROOM: usize = stcp::SEGMENT_OPTIONS_ROOM;

/// A [`Segments`] as smoltcp asks for it.
struct SegmentsOnWire(Box<dyn Segments>);

impl stcp::SegmentOptions for SegmentsOnWire {
    fn room(&self) -> usize {
        self.0.room()
    }

    fn sent(&mut self, segment: &stcp::Outgoing<'_>, out: &mut Vec<u8>) {
        let options = self.0.sent(&Sent {
            seq: segment.seq,
            payload: segment.payload,
            fin: segment.fin,
            ack: segment.ack,
        });
        let wire: Option<Vec<_>> = options.iter().map(TcpOption::to_wire).collect();
        let room = self.0.room().min(SEGMENT_OPTIONS_ROOM);
        if let Some(bytes) = wire.and_then(|w| stcp::encode_options_within(&w, room).ok()) {
            out.extend_from_slice(&bytes);
        }
    }

    fn received(&mut self, segment: &stcp::Incoming<'_>) -> stcp::Verdict {
        let mut options = Vec::new();
        for option in smoltcp::wire::TcpOptions::new(segment.options) {
            match option {
                Ok(option) => options.extend(TcpOption::from_wire(option)),
                Err(_) => break,
            }
        }
        self.0
            .received(&Received {
                seq: segment.seq,
                payload: segment.payload,
                fin: segment.fin,
                options: &options,
            })
            .on_wire()
    }

    fn arrived(&mut self, seq: u32, data: &[u8], out: &mut Vec<u8>) -> stcp::Verdict {
        self.0.arrived(seq, data, out).on_wire()
    }

    fn reset(&mut self, out: &mut Vec<u8>) {
        out.extend(encode(&self.0.reset()).unwrap_or_default());
    }
}

impl<F: Fn(&Syn<'_>) -> SynAnswer + Send> Answer for F {
    fn syn(&self, syn: &Syn<'_>) -> SynAnswer {
        self(syn)
    }
}

/// One arriving segment, as much as a reset in answer to it needs.
#[derive(Clone, Copy)]
struct Arrived {
    /// Its source.
    from: SocketAddr,
    /// Its destination.
    to: SocketAddr,
    seq: u32,
    /// Its acknowledgment number, when the ACK flag is set.
    ack: Option<u32>,
    /// SEG.LEN: its payload bytes, plus one each for SYN and FIN.
    len: u32,
    /// Its payload bytes.
    payload: usize,
}

impl Arrived {
    /// `t`, a segment from `from` to `to` that smoltcp parsed, with
    /// `payload` bytes of data.
    fn of(from: SocketAddr, to: SocketAddr, t: &[u8], payload: usize) -> Arrived {
        let flags = t[13];
        Arrived {
            from,
            to,
            seq: u32::from_be_bytes([t[4], t[5], t[6], t[7]]),
            ack: (flags & 0x10 != 0).then(|| u32::from_be_bytes([t[8], t[9], t[10], t[11]])),
            len: payload as u32 + u32::from(flags & 0x02 != 0) + u32::from(flags & 0x01 != 0),
            payload,
        }
    }

    /// The RST that answers this segment when it may not open or join a
    /// connection (RFC 9293 section 3.10.7.1): with the sequence number
    /// the segment acknowledged, or with sequence number 0 and an ACK of
    /// the segment when it had no ACK. It has window 0 and `options`, whole
    /// options from [`encode`], as its only options, as a Linux host sends
    /// one (tcp_v4_send_reset).
    fn reset(&self, options: &[u8]) -> Vec<u8> {
        let (seq, ack) = match self.ack {
            Some(ack) => (ack, None),
            None => (0, Some(self.seq.wrapping_add(self.len))),
        };
        segment(self.to, self.from, seq, ack, 0x04, 0, options)
    }
}

/// A TCP segment with no payload from `from` to `to`, in an IP packet with
/// the header [`packet`](fictionet::stdlib::network::ip::packet) writes.
/// `flags` gets ACK added when there is an `ack`, and `options` are whole
/// options, padded here with End of Option List.
fn segment(
    from: SocketAddr,
    to: SocketAddr,
    seq: u32,
    ack: Option<u32>,
    flags: u8,
    window: u16,
    options: &[u8],
) -> Vec<u8> {
    let area = options.len().div_ceil(4) * 4;
    let mut t = vec![0; 20 + area];
    t[0..2].copy_from_slice(&from.port().to_be_bytes());
    t[2..4].copy_from_slice(&to.port().to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.unwrap_or(0).to_be_bytes());
    t[12] = ((20 + area) / 4) as u8 * 16;
    t[13] = flags | if ack.is_some() { 0x10 } else { 0 };
    t[14..16].copy_from_slice(&window.to_be_bytes());
    t[20..20 + options.len()].copy_from_slice(options);
    let sum = transport_checksum(from.ip(), to.ip(), TCP, &t);
    t[16..18].copy_from_slice(&sum.to_be_bytes());
    fictionet::stdlib::network::ip::packet(from.ip(), to.ip(), TCP, &t).0
}

/// The peer MSS values a SYN cookie can keep, as Linux's (msstab): the
/// largest at most the peer's is kept. IPv4, then IPv6.
const COOKIE_MSS: [[u16; 4]; 2] = [[536, 1300, 1440, 1460], [1220, 1420, 1440, 8940]];

/// An HMAC-SHA256 key of 32 bytes from the run's random stream.
fn secret(fcx: &Cx) -> ring::hmac::Key {
    let mut key = [0; 32];
    fcx.fill_random(&mut key);
    ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key)
}

/// Appends the address and port of each of `ends`.
fn put_ends(message: &mut Vec<u8>, ends: [SocketAddr; 2]) {
    for end in ends {
        match end.ip() {
            IpAddr::V4(a) => message.extend_from_slice(&a.octets()),
            IpAddr::V6(a) => message.extend_from_slice(&a.octets()),
        }
        message.extend_from_slice(&end.port().to_be_bytes());
    }
}

/// The key of an endpoint's initial sequence numbers.
struct Sequences(ring::hmac::Key);

impl Sequences {
    /// The initial sequence number of a connection from `local` to
    /// `remote` that starts at `now`, as RFC 6528 section 3 has it: the
    /// first 32 bits of an HMAC-SHA256 of the endpoints, plus a clock that
    /// ticks every 4 microseconds. A peer learns nothing from its own
    /// connections' numbers about those of another address or port, and
    /// a new connection on the same endpoints starts past the old one.
    fn initial(&self, local: SocketAddr, remote: SocketAddr, now: smoltcp::time::Instant) -> u32 {
        let mut message = Vec::with_capacity(36);
        put_ends(&mut message, [local, remote]);
        let tag = ring::hmac::sign(&self.0, &message);
        let t = tag.as_ref();
        let clock = (now.total_micros().max(0) as u64 / 4) as u32;
        u32::from_be_bytes([t[0], t[1], t[2], t[3]]).wrapping_add(clock)
    }
}

/// The key of an endpoint's SYN cookies, drawn apart from the key of its
/// initial sequence numbers.
struct Cookies(ring::hmac::Key);

impl Cookies {
    /// A cookie for a SYN from `remote` to `local` with sequence number
    /// `irs`, made in `minute` and keeping the peer's MSS as index `mss`
    /// of [`COOKIE_MSS`] (RFC 4987 section 3.6). Its low 2 bits hold `mss`,
    /// the next 5 the low bits of `minute`, and the top 25 an HMAC-SHA256
    /// of all of these, so a peer cannot make one.
    fn make(&self, local: SocketAddr, remote: SocketAddr, irs: u32, minute: u64, mss: u8) -> u32 {
        let mut message = Vec::with_capacity(48);
        put_ends(&mut message, [local, remote]);
        message.extend_from_slice(&irs.to_be_bytes());
        message.extend_from_slice(&minute.to_be_bytes());
        message.push(mss);
        let tag = ring::hmac::sign(&self.0, &message);
        let t = tag.as_ref();
        (u32::from_be_bytes([t[0], t[1], t[2], t[3]]) & !0x7f)
            | ((minute as u32 & 0x1f) << 2)
            | u32::from(mss)
    }

    /// The peer's MSS, if `cookie` is one [`make`](Cookies::make) gave for
    /// this SYN in this minute or the one before, as Linux takes one up to
    /// two minutes old (MAX_SYNCOOKIE_AGE).
    fn check(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        irs: u32,
        cookie: u32,
        minute: u64,
    ) -> Option<u16> {
        let mss = (cookie & 3) as u8;
        let made = [minute, minute.wrapping_sub(1)]
            .into_iter()
            .find(|m| (*m as u32 & 0x1f) == (cookie >> 2) & 0x1f)?;
        (self.make(local, remote, irs, made, mss) == cookie)
            .then(|| COOKIE_MSS[usize::from(local.is_ipv6())][usize::from(mss)])
    }
}

/// The index in [`COOKIE_MSS`] of the largest MSS at most `mss`, the
/// peer's: the smallest when it sent none or one below them all.
fn cookie_mss(v6: bool, mss: Option<u16>) -> u8 {
    let table = COOKIE_MSS[usize::from(v6)];
    let mss = mss.unwrap_or(0);
    table.iter().rposition(|&m| m <= mss).unwrap_or(0) as u8
}

/// The minute of the SYN cookie clock at `now`.
fn cookie_minute(now: smoltcp::time::Instant) -> u64 {
    now.total_micros().max(0) as u64 / 60_000_000
}

/// Starts TCP for a machine with address `addr`, on the TCP packets of
/// `inner`.
///
/// Starts a background task and returns immediately with an [`Endpoint`].
/// The task takes TCP packets sent to `addr` and drops the rest. A
/// connection attempt to a port with no listener gets a RST, because that
/// is part of TCP's job. Everything it sends goes into `inner`.
///
/// The task stops when the caller's [region](fictionet::Cx#regions) is
/// cancelled or `inner` closes. The endpoint's listeners and connections
/// then fail with [`ConnError::Closed`].
///
/// Each connection has 256 KiB buffers each way, a 1,500-byte MTU, no
/// Nagle delay, and Reno congestion control. Each listening port holds up
/// to the default [`backlog`](Options::backlog) of connections not yet
/// accepted, including handshakes, and answers further SYNs with SYN
/// cookies. A handshake whose last ACK has not come 63 seconds after its
/// SYN is dropped without a RST, as Linux drops it. [`endpoint_with`]
/// takes other buffer sizes and backlogs, subject to the maximum and
/// per-peer limits described in [`Options::backlog`]. Buffer memory is used only
/// as data passes through: once a connection's buffers are empty, their
/// pages go back to the system within about two seconds, though the
/// connection stays open, and closing frees them. A connection gives up with
/// [`ConnError::TimedOut`] when the peer has not answered for two minutes:
/// a SYN, data that is not acknowledged, or a keepalive (sent after 45
/// seconds of quiet). A connection whose handle was dropped finishes
/// closing in the background, and is given up when the peer has sent
/// nothing for one minute. Once the peer has acknowledged its FIN, it is
/// forgotten one minute later, whatever the peer sends, as Linux forgets
/// one in FIN-WAIT-2 (`tcp_fin_timeout`). ICMPv4
/// destination-unreachable messages can fail a pending connect; see
/// [`Endpoint::connect`]. Other ICMP messages are dropped. Established
/// connections ignore ICMP, and there is no path MTU discovery.
///
/// A dropped connection that reaches TIME-WAIT releases items kept with
/// [`TcpConnection::hold_until_gone`], including connection counts, and
/// makes its [`GoneWatch`] ready. Only transport recovery state stays:
/// its socket, tuple, buffers and outgoing port remain until smoltcp's
/// ten-second transport timer expires. Retransmitted FINs get ACKs and
/// restart that timer. An endpoint retains at most 1,024 such sockets.
/// Past that cap, housekeeping forgets them in the order it first saw
/// them as TIME-WAIT orphans, so later packets for those tuples may get
/// RSTs. Live handles and sockets still closing are not evicted. At the
/// default buffer size, the cap retains up to 512 MiB of buffer address
/// space; empty pages can be released on native builds, while browser
/// buffers use the heap. Larger buffers increase this bound.
#[track_caller]
pub fn endpoint(fcx: &Cx, inner: impl Interface, addr: IpAddr) -> Endpoint {
    endpoint_with(fcx, inner, addr, Options::default())
}

/// Settings for [`endpoint_with`]. The default is what [`endpoint`] uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    buffer: usize,
    backlog: usize,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            buffer: BUFFER,
            backlog: BACKLOG,
        }
    }
}

impl Options {
    /// Sets the size of each connection's receive buffer and of its send
    /// buffer, in bytes. The default is 256 KiB. Sizes below 4 KiB or above
    /// 64 MiB are raised or lowered to those limits.
    ///
    /// The buffers bound how fast one connection can go over a link with
    /// delay. The receive buffer is the window: the most the peer may send
    /// before this side acknowledges it. The send buffer holds what this
    /// side has sent until the peer acknowledges it. Either way, a
    /// connection carries at most one buffer of data per round trip, so its
    /// rate is at most the buffer size divided by the round-trip time. With
    /// 256 KiB that is about 13 MB/s at a 20 ms round trip, and 2.6 MB/s at
    /// 100 ms. Both ends need the larger buffer: a sender is held to the
    /// smaller of its own send buffer and the receiver's window.
    ///
    /// On a link with 10 ms of delay each way, one connection moving 16 MiB
    /// ran at a median of 9.2 MB/s with 256 KiB buffers at both ends, and
    /// 27 MB/s with 1 MiB buffers. With 50 ms each way, moving 8 MiB, it
    /// ran at 1.9 and 3.9 MB/s. These come from the `delay` group of the performance
    /// suite, described in `CONTRIBUTING.md`.
    ///
    /// Larger buffers cost memory only as data passes through them, but they
    /// let each connection put more packets in flight at once. Interfaces
    /// with a size limit on the way, such as those of
    /// [`split_protocols`](fictionet::stdlib::network::ip::split_protocols), drop what
    /// does not fit, and TCP then sends it again.
    pub fn buffer(self, bytes: usize) -> Options {
        Options {
            buffer: bytes.clamp(MIN_BUFFER, MAX_BUFFER),
            ..self
        }
    }

    /// Sets how many connections each listening port holds that have
    /// arrived but not been accepted yet: handshakes under way, and
    /// connections waiting for [`Listener::accept`]. The default is 4,096.
    /// Values below 1 or above 65,536 are raised or lowered to those
    /// limits. At most 256 attempts from one peer address keep handshake
    /// state, whatever the backlog. Further SYNs from that address get
    /// cookies, so spoofed attempts cannot shut out a real peer.
    ///
    /// Past the backlog, a SYN gets a SYN cookie (RFC 4987 section 3.6), as
    /// from Linux with a full SYN queue: a SYN-ACK whose sequence number
    /// holds what the handshake needs, so the endpoint keeps nothing for
    /// the attempt until the ACK that returns the cookie. The SYN-ACK
    /// carries a Maximum Segment Size and what the listener's
    /// [`Answer::syn`] adds, and nothing else. So such a connection has no
    /// window scaling, SACK, timestamps or ECN, and its [`Handshake`] has
    /// no SYN options. Linux sends the same SYN-ACK to a SYN without
    /// timestamps. To one with them, it also sends timestamps, SACK and
    /// Window Scale, keeping their settings in the timestamp value.
    /// When the connections waiting for `accept` alone fill the backlog,
    /// SYNs and ACKs that return cookies are dropped, as Linux drops them
    /// with a full accept queue.
    ///
    /// Each connection in the backlog has its buffers from its first SYN.
    /// Their pages cost memory only once data arrives, but each connection
    /// holds one memory mapping, and Linux allows a process 65,530 of them
    /// by default (`vm.max_map_count`). Spoofed SYNs from many addresses
    /// fill the backlog of every port they reach, so a world with many
    /// listening ports may want a smaller one.
    pub fn backlog(self, connections: usize) -> Options {
        Options {
            backlog: connections.clamp(1, MAX_BACKLOG),
            ..self
        }
    }
}

/// Starts TCP for a machine, as [`endpoint`] does, with other
/// [`Options`].
///
/// This one gives every connection 1 MiB buffers, for fast transfers over
/// a link with delay:
///
/// ```
/// # use fictionet::{Cx, End, Result};
/// # use fictionet::stdlib::network::tcp;
/// # fn machine(fcx: &Cx, tcp_packets: End) -> Result {
/// let options = tcp::Options::default().buffer(1 << 20);
/// let machine = tcp::endpoint_with(fcx, tcp_packets, "10.0.0.1".parse()?, options);
/// # drop(machine);
/// # Ok(())
/// # }
/// ```
#[track_caller]
pub fn endpoint_with(fcx: &Cx, inner: impl Interface, addr: IpAddr, options: Options) -> Endpoint {
    let (endpoint, task) = prepare_endpoint(fcx, inner, addr, options);
    task.start(fcx);
    endpoint
}

/// A TCP endpoint's driver, ready to start with its task name.
/// Dropping it discards the driver without starting a task.
pub struct Prepared<F> {
    task: F,
}

impl<F: Future<Output = fictionet::Result> + Send + 'static> Prepared<F> {
    /// Starts the endpoint in the context used to prepare it.
    #[track_caller]
    pub fn start(self, fcx: &Cx) {
        fcx.spawn(move |_| self.task);
    }
}

/// Builds a TCP endpoint and its driver without starting a task.
/// Listeners can be opened before the driver starts. Call [`Prepared::start`]
/// with `fcx` to run the endpoint, or drop the driver and all its handles to
/// discard the preparation. Uses `fcx` for the clock and randomness.
pub fn prepare_endpoint(
    fcx: &Cx,
    inner: impl Interface,
    addr: IpAddr,
    options: Options,
) -> (
    Endpoint,
    Prepared<impl Future<Output = fictionet::Result> + Send + 'static>,
) {
    let mut dev = Dev::default();
    let sequences = Sequences(secret(fcx));
    let config = Config {
        initial_seq: Box::new(move |local, remote, now| {
            sequences.initial(local.into(), remote.into(), now)
        }),
        ip_addr: addr.into(),
    };
    let iface = Iface::new(config, &mut dev, smol_now(fcx));
    let shared = Arc::new(Shared {
        addr,
        state: Mutex::new(State {
            iface,
            sockets: SocketSet::new(Vec::new()),
            handles: BTreeMap::new(),
            next_id: 0,
            slots: 0,
            pages: HashMap::new(),
            dirty: HashSet::new(),
            next_release: None,
            dev,
            listeners: BTreeMap::new(),
            conns: BTreeMap::new(),
            by_tuple: HashMap::new(),
            ports: HashMap::new(),
            next_port: EPHEMERAL
                + fictionet::Entropy::random_below(fcx, 65536 - EPHEMERAL as u64) as u16,
            orphans: Vec::new(),
            touched: Vec::new(),
            time_wait: VecDeque::new(),
            stopped: false,
            driver: None,
            buffer: options.buffer,
            backlog: options.backlog,
            isolated_peer: None,
            cookies: Cookies(secret(fcx)),
        }),
    });
    let driver = shared.clone();
    let fcx = fcx.clone();
    let task = async move {
        drive(&fcx, &driver, inner).await;
        driver.stop();
        Ok(())
    };
    (Endpoint { shared }, Prepared { task })
}

fn smol_now(fcx: &Cx) -> smoltcp::time::Instant {
    smoltcp::time::Instant::from_micros(fcx.now().since_start().as_micros() as i64)
}

/// The packets going into and out of smoltcp.
#[derive(Default)]
struct Dev {
    rx: Option<Vec<u8>>,
    tx: Vec<Vec<u8>>,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut Vec<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0; len];
        let r = f(&mut buf);
        self.0.push(buf);
        r
    }
}

impl Device for Dev {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: smoltcp::time::Instant) -> Option<(Rx, Tx<'_>)> {
        if self.tx.len() >= EGRESS_PACKETS {
            return None;
        }
        let p = self.rx.take()?;
        Some((Rx(p), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Tx<'_>> {
        (self.tx.len() < EGRESS_PACKETS).then_some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            max_transmission_unit: MTU,
        }
    }
}

struct Shared {
    addr: IpAddr,
    state: Mutex<State>,
}

/// A socket's name inside [`State`]. smoltcp's handles are slot numbers
/// that change when the socket set is compacted; these never change.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
struct Id(u64);

/// Compact the socket set when at least this many slots exist and at most
/// a quarter of them hold a socket. smoltcp walks every slot, empty or
/// not, on every packet, and its slot list never shrinks by itself.
const COMPACT_SLOTS: usize = 256;

struct State {
    iface: Iface,
    sockets: SocketSet<'static>,
    /// Each socket's slot in `sockets`, ordered by SDK ID for compaction.
    handles: BTreeMap<Id, SocketHandle>,
    next_id: u64,
    /// Slots in `sockets`, empty ones included: the most sockets it held
    /// at once since it was made.
    slots: usize,
    /// The buffers of each socket that has its own pages. Declared after
    /// `sockets`, so they outlive the sockets that borrow them.
    pages: HashMap<Id, Pages>,
    /// Sockets whose buffers may hold pages that could be given back.
    dirty: HashSet<Id>,
    /// When `dirty` is next looked at.
    next_release: Option<smoltcp::time::Instant>,
    dev: Dev,
    /// Listener maintenance and shutdown wake in ascending port order.
    listeners: BTreeMap<u16, Listen>,
    /// Every socket that is or was a connection, in SDK ID order for aborts.
    conns: BTreeMap<Id, Conn>,
    /// Connections by (local, remote), to note RSTs and FINs.
    by_tuple: HashMap<(SocketAddr, SocketAddr), Id>,
    /// Local ports in use by listeners (counted once) and connections.
    ports: HashMap<u16, usize>,
    next_port: u16,
    /// Connections whose handle was dropped, removed once they close.
    orphans: Vec<Id>,
    /// Handshakes that may have left SYN-RECEIVED since housekeeping last
    /// looked: those a segment reached, and those aborted. Only a segment
    /// or an abort moves a handshake on, so housekeeping looks at these
    /// alone, however many handshakes wait.
    touched: Vec<Id>,
    /// Retired orphans, in the order housekeeping first saw TIME-WAIT.
    time_wait: VecDeque<Id>,
    stopped: bool,
    /// The driver task, woken when a handle has work for it.
    driver: Option<Waker>,
    /// Each new socket's receive and send buffer, in bytes.
    buffer: usize,
    /// Connections per listening port not accepted yet: [`Options::backlog`].
    backlog: usize,
    /// The key of this endpoint's SYN cookies.
    cookies: Cookies,
    /// Sources whose ownership the enclosing network verifies.
    isolated_peer: Option<Box<dyn Fn(IpAddr) -> bool + Send>>,
}

/// One listening port.
#[derive(Default)]
struct Listen {
    /// Sockets in LISTEN, waiting for a SYN.
    idle: Vec<Id>,
    /// Sockets that got a SYN and wait for the handshake to finish, each
    /// with when it is given up ([`Conn::gives_up`]), soonest first. So the
    /// handshakes due to be dropped are found without looking at the rest.
    embryonic: BTreeSet<(smoltcp::time::Instant, Id)>,
    /// Connections ready for `accept`.
    ready: VecDeque<Id>,
    /// How many of `embryonic` and `ready` each peer address has.
    per_peer: HashMap<IpAddr, usize>,
    waker: Option<Waker>,
    /// Its say in its handshakes: [`Listener::answer`].
    answer: Option<Box<dyn Answer>>,
}

impl Listen {
    /// Where handshake `h` is in `embryonic`, if it is there.
    fn embryo(&self, h: Id, conns: &BTreeMap<Id, Conn>) -> Option<(smoltcp::time::Instant, Id)> {
        let key = (conns.get(&h)?.gives_up?, h);
        self.embryonic.contains(&key).then_some(key)
    }

    /// Takes handshake `h` out of `embryonic`. Returns whether it was there.
    fn hatch(&mut self, h: Id, conns: &BTreeMap<Id, Conn>) -> bool {
        self.embryo(h, conns)
            .is_some_and(|key| self.embryonic.remove(&key))
    }

    /// Takes back a socket that left `embryonic` because a RST returned it
    /// from SYN-RECEIVED to LISTEN, and forgets its connection. One spare
    /// listening socket is enough (`ingress` makes one when there is none),
    /// and every socket costs a little on every packet, so a burst of SYNs
    /// must not leave a pool behind. Returns whether the socket is kept as
    /// the spare; otherwise the caller removes it.
    fn relisten(
        &mut self,
        h: Id,
        conns: &mut BTreeMap<Id, Conn>,
        by_tuple: &mut HashMap<(SocketAddr, SocketAddr), Id>,
    ) -> bool {
        if let Some(c) = conns.remove(&h) {
            by_tuple.remove(&(c.local, c.remote));
            self.left(c.remote.ip());
        }
        let spare = self.idle.is_empty();
        if spare {
            self.idle.push(h);
        }
        spare
    }

    /// One connection from `peer` left `embryonic` or `ready` for good.
    fn left(&mut self, peer: IpAddr) {
        if let Some(n) = self.per_peer.get_mut(&peer) {
            *n -= 1;
            if *n == 0 {
                self.per_peer.remove(&peer);
            }
        }
    }
}

struct Conn {
    local: SocketAddr,
    remote: SocketAddr,
    /// ECN was offered in the SYN.
    ecn: bool,
    /// Echo congestion until the peer acknowledges it with CWR.
    congestion_echo: bool,
    /// A RST arrived for this connection, or this side aborted it.
    rst: bool,
    /// A FIN arrived for this connection.
    fin: bool,
    /// This side called shutdown.
    shut: bool,
    /// The handle was dropped: the connection is in `orphans`.
    orphaned: bool,
    /// The handle was dropped and only TIME-WAIT recovery state remains.
    retired: bool,
    /// This side connected, so it holds its local port.
    side: Side,
    /// Our initial sequence number, from the SYN sent for this attempt.
    iss: Option<u32>,
    /// An ICMPv4 destination-unreachable code for this pending connect.
    unreachable: Option<u8>,
    /// What the handshake carried, for a connection a listener took.
    handshake: Handshake,
    /// When a handshake still waiting for its last ACK is dropped, or when
    /// an orphan in FIN-WAIT-2 is forgotten.
    gives_up: Option<smoltcp::time::Instant>,
    /// Kept until retirement or socket removal, after handle drop too: see
    /// [`TcpConnection::hold_until_gone`].
    held: Vec<Box<dyn std::any::Any + Send>>,
    /// Woken when a RST arrives or this side aborts, when the endpoint
    /// stops, and on retirement or socket removal: see [`GoneWatch`].
    gone: Vec<Waker>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.wake_gone();
    }
}

impl Conn {
    fn new(local: SocketAddr, remote: SocketAddr, side: Side) -> Conn {
        Conn {
            local,
            remote,
            ecn: false,
            congestion_echo: false,
            rst: false,
            fin: false,
            shut: false,
            orphaned: false,
            retired: false,
            side,
            iss: None,
            unreachable: None,
            handshake: Handshake::default(),
            gives_up: None,
            held: Vec::new(),
            gone: Vec::new(),
        }
    }

    fn wake_gone(&mut self) {
        for w in self.gone.drain(..) {
            w.wake();
        }
    }
}

fictionet::cfg_std! { items {
/// A socket's two buffers, in an anonymous mapping of their own.
///
/// smoltcp buffers are fixed slices. Taking them from the heap would keep
/// their pages after the connection goes quiet or closes: the allocator
/// zeroes fresh chunks (so even an idle connection costs its full 512
/// KiB) and keeps freed memory. With a mapping of its own, a page costs
/// memory only once it is written, the pages of an empty buffer can be
/// given back while the connection stays open ([`Pages::release`]), and
/// closing returns all of it.
#[cfg(not(target_arch = "wasm32"))]
struct Pages {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: `Pages` owns its mapping; the raw pointer is only an address.
// Every access goes through the endpoint's mutex.
#[cfg(not(target_arch = "wasm32"))]
unsafe impl Send for Pages {}

#[cfg(not(target_arch = "wasm32"))]
impl Pages {
    /// Maps two buffers of `buffer` bytes, or `None` if the system says no.
    fn map(buffer: usize) -> Option<Pages> {
        let len = 2 * buffer;
        // SAFETY: a fresh private anonymous mapping; no existing memory is
        // touched.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        (ptr != libc::MAP_FAILED).then_some(Pages {
            ptr: ptr.cast(),
            len,
        })
    }

    /// The receive and send halves.
    ///
    /// SAFETY: the caller hands each half to exactly one socket, and
    /// removes that socket before the `Pages` is dropped.
    unsafe fn halves(&self) -> (&'static mut [u8], &'static mut [u8]) {
        // SAFETY: the mapping is `len` bytes, readable and writable, and
        // the two halves do not overlap.
        let half = self.len / 2;
        unsafe {
            (
                std::slice::from_raw_parts_mut(self.ptr, half),
                std::slice::from_raw_parts_mut(self.ptr.add(half), half),
            )
        }
    }

    /// Gives the pages of both halves back to the system. They read as
    /// zeros after, and cost memory again only once written.
    ///
    /// SAFETY: the socket that holds the halves (see [`Pages::halves`])
    /// must hold nothing in them: no bytes to read, none to send or
    /// resend, and an empty receive assembler. Check `recv_queue`,
    /// `send_queue`, and `has_pending_recv`. Its buffers are
    /// `&'static mut` slices of this mapping, and this changes their bytes
    /// behind them.
    unsafe fn release(&self) {
        // SAFETY: the range is this mapping. MADV_DONTNEED on a private
        // anonymous mapping only makes its pages read as zeros, and the
        // caller has checked that the socket holds no data in them.
        unsafe { libc::madvise(self.ptr.cast(), self.len, libc::MADV_DONTNEED) };
    }

    /// How many of the pages are in memory now.
    #[cfg(test)]
    fn resident(&self) -> usize {
        let page = 4096;
        let mut v = vec![0u8; self.len.div_ceil(page)];
        // SAFETY: `v` has one byte per page of the mapping.
        unsafe { libc::mincore(self.ptr.cast(), self.len, v.as_mut_ptr().cast()) };
        v.iter().filter(|b| *b & 1 != 0).count()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for Pages {
    fn drop(&mut self) {
        // SAFETY: this unmaps exactly the mapping made in `map`, after the
        // socket that borrowed it was removed.
        unsafe { libc::munmap(self.ptr.cast(), self.len) };
    }
}

/// A browser has no `mmap`, so there every socket's buffers come from the
/// heap and no `Pages` is ever made.
#[cfg(target_arch = "wasm32")]
enum Pages {}

#[cfg(target_arch = "wasm32")]
impl Pages {
    fn map(_buffer: usize) -> Option<Pages> {
        None
    }

    /// SAFETY: as on a host; no `Pages` exists to call it on.
    unsafe fn halves(&self) -> (&'static mut [u8], &'static mut [u8]) {
        match *self {}
    }

    /// SAFETY: as on a host; no `Pages` exists to call it on.
    unsafe fn release(&self) {
        match *self {}
    }
}

} else {
enum Pages {}

impl Pages {
    fn map(_buffer: usize) -> Option<Pages> {
        None
    }

    /// SAFETY: as on a host; no `Pages` exists to call it on.
    unsafe fn halves(&self) -> (&'static mut [u8], &'static mut [u8]) {
        match *self {}
    }

    /// SAFETY: as on a host; no `Pages` exists to call it on.
    unsafe fn release(&self) {
        match *self {}
    }
}

}
}

/// A socket with two buffers of `buffer` bytes.
fn new_socket(buffer: usize) -> (stcp::Socket<'static>, Option<Pages>) {
    let pages = Pages::map(buffer);
    let mut s = match &pages {
        Some(p) => {
            // SAFETY: the halves go to this one socket, and `State` removes
            // it before dropping the pages (`State::remove_socket`, and
            // field order for the whole state).
            let (rx, tx) = unsafe { p.halves() };
            stcp::Socket::new(stcp::SocketBuffer::new(rx), stcp::SocketBuffer::new(tx))
        }
        None => stcp::Socket::new(
            stcp::SocketBuffer::new(vec![0; buffer]),
            stcp::SocketBuffer::new(vec![0; buffer]),
        ),
    };
    s.set_tsval_generator(Some(|now| (now.total_micros() / 1000) as u32));
    s.set_nagle_enabled(false);
    s.set_timeout(Some(TIMEOUT.into()));
    s.set_keep_alive(Some(KEEPALIVE.into()));
    (s, pages)
}

impl State {
    fn kick(&mut self) {
        if let Some(w) = self.driver.take() {
            w.wake();
        }
    }

    /// Adds a socket made by [`new_socket`].
    fn add_socket(&mut self, (s, pages): (stcp::Socket<'static>, Option<Pages>)) -> Id {
        let h = Id(self.next_id);
        self.next_id += 1;
        self.handles.insert(h, self.sockets.add(s));
        self.slots = self.slots.max(self.handles.len());
        if let Some(p) = pages {
            self.pages.insert(h, p);
        }
        h
    }

    /// Removes a socket, then unmaps its buffers.
    fn remove_socket(&mut self, h: Id) {
        let slot = self.handles.remove(&h).expect("a socket has a slot");
        self.sockets.remove(slot);
        self.pages.remove(&h);
        self.dirty.remove(&h);
    }

    /// Notes that a socket's buffers may have pages to give back later.
    fn soiled(&mut self, h: Id) {
        if self.pages.contains_key(&h) {
            self.dirty.insert(h);
        }
    }

    /// Gives back the pages of every noted socket whose buffers are now
    /// empty. Sockets that still hold data stay noted.
    fn release_quiet(&mut self) {
        let dirty: Vec<Id> = self.dirty.iter().copied().collect();
        for h in dirty {
            let s = self.get(h);
            let (rq, sq) = (s.recv_queue(), s.send_queue());
            if rq == 0 && sq == 0 && !s.has_pending_recv() {
                // SAFETY: the socket holds nothing in its buffers, as just
                // checked: nothing to read or send, and nothing out of order.
                unsafe { self.pages[&h].release() };
                self.dirty.remove(&h);
            }
        }
    }

    fn sock(&mut self, h: Id) -> &mut stcp::Socket<'static> {
        self.sockets.get_mut(self.handles[&h])
    }

    fn get(&self, h: Id) -> &stcp::Socket<'static> {
        self.sockets.get(self.handles[&h])
    }

    /// Moves every socket into a new set without empty slots, once most
    /// slots are empty. Sockets keep their [`Id`], their state and their
    /// buffers. The new set scans sockets in ascending SDK socket ID order.
    fn compact(&mut self) {
        if self.slots < COMPACT_SLOTS || self.handles.len() * 4 > self.slots {
            return;
        }
        let mut sockets = SocketSet::new(Vec::with_capacity(self.handles.len()));
        for slot in self.handles.values_mut() {
            *slot = sockets.add(self.sockets.remove(*slot));
        }
        self.sockets = sockets;
        self.slots = self.handles.len();
    }

    fn take_port(&mut self, port: u16) {
        *self.ports.entry(port).or_default() += 1;
    }

    fn free_port(&mut self, port: u16) {
        if let Some(n) = self.ports.get_mut(&port) {
            *n -= 1;
            if *n == 0 {
                self.ports.remove(&port);
            }
        }
    }

    /// Forgets a connection socket entirely.
    fn remove_conn(&mut self, h: Id) {
        if let Some(c) = self.conns.remove(&h) {
            self.by_tuple.remove(&(c.local, c.remote));
            if c.side == Side::Client {
                self.free_port(c.local.port());
            }
        }
        self.remove_socket(h);
    }

    /// Sends the FIN after every queued byte is acknowledged.
    /// This preserves the endpoint's shutdown packet order.
    fn close_if_drained(&mut self, h: Id) {
        if self.conns[&h].shut && self.get(h).send_queue() == 0 {
            self.sock(h).close();
        }
    }

    /// Resets the connection and wakes its waiters, keeping the socket
    /// until its RST can be sent.
    fn abort(&mut self, h: Id) {
        let c = self.conns.get_mut(&h).unwrap();
        c.rst = true;
        c.wake_gone();
        self.sock(h).abort();
        self.touched.push(h);
    }

    /// Hands a socket whose handle is gone to the driver, which removes it
    /// once it has closed. Unread data means the application lost bytes,
    /// so the peer gets a RST, as from a kernel.
    fn orphan(&mut self, h: Id, abort: bool) {
        if self.stopped {
            self.remove_conn(h);
            return;
        }
        if abort || self.get(h).can_recv() {
            self.abort(h);
        } else {
            self.conns.get_mut(&h).unwrap().shut = true;
            self.close_if_drained(h);
        }
        // An orphan should not live on keepalives. A peer that never
        // closes its side keeps it only for a minute, as Linux does
        // (tcp_fin_timeout): see `expire_orphans`.
        let s = self.sock(h);
        s.set_keep_alive(None);
        s.set_timeout(Some(ORPHAN_TIMEOUT.into()));
        self.conns.get_mut(&h).unwrap().orphaned = true;
        self.orphans.push(h);
        self.kick();
    }

    /// Why a connection can no longer carry bytes, once its socket closed.
    fn closed_reason(&self, h: Id) -> ConnError {
        let c = &self.conns[&h];
        if self.stopped {
            ConnError::Closed
        } else if let Some(code) = c.unreachable {
            ConnError::Unreachable(code)
        } else if c.rst {
            ConnError::Reset
        } else {
            ConnError::TimedOut
        }
    }

    /// Records the sequence number of an outgoing SYN, for ICMP checks, or
    /// of a SYN-ACK, for the connection's [`Handshake`].
    fn sent(&mut self, packet: &mut [u8]) {
        let Some(ip) = Header::parse_whole(packet) else {
            return;
        };
        let t = ip.payload(packet);
        if ip.protocol != TCP || t.len() < 20 {
            return;
        }
        let local = SocketAddr::new(ip.src, u16::from_be_bytes([t[0], t[1]]));
        let remote = SocketAddr::new(ip.dst, u16::from_be_bytes([t[2], t[3]]));
        if let Some(h) = self.by_tuple.get(&(local, remote)) {
            let c = self.conns.get_mut(h).unwrap();
            let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
            match (c.side, t[13] & 0x12) {
                (Side::Client, 0x02) => {
                    c.iss.get_or_insert(seq);
                }
                (Side::Server, 0x12) => c.handshake.iss = seq,
                _ => {}
            }
            if c.ecn && t[13] & 0x04 == 0 && (t[13] & 0x12 == 0x12 || c.congestion_echo) {
                let t = &mut packet[ip.payload];
                t[13] |= 0x40;
                t[16..18].fill(0);
                let sum = transport_checksum(local.ip(), remote.ip(), TCP, t);
                t[16..18].copy_from_slice(&sum.to_be_bytes());
            }
        }
    }

    /// Only the quoted, still-pending attempt can be failed by ICMPv4.
    fn unreachable(&mut self, message: &[u8]) {
        if message.len() < 8
            || message[0] != 3
            || message[1] == 4
            || message[1] > 15
            || checksum(message) != 0
        {
            return;
        }
        let quoted = &message[8..];
        let Some(ip) = Header::parse_truncated(quoted) else {
            return;
        };
        if !ip.src.is_ipv4()
            || ip.protocol != TCP
            || ip.fragment.is_some()
            || !Ipv4Packet::new_unchecked(quoted).verify_checksum()
        {
            return;
        }
        let t = ip.payload(quoted);
        let total = u16::from_be_bytes([quoted[2], quoted[3]]) as usize;
        // The minimum ICMP quote has only the ports and sequence number.
        if t.len() < 8 || total < ip.payload.start + 20 || (t.len() >= 14 && t[13] & 0x17 != 2) {
            return;
        }
        if quoted.len() >= total
            && TcpRepr::parse(&TcpPacket::new_unchecked(t), &ip.src.into(), &ip.dst.into()).is_err()
        {
            return;
        }
        let local = SocketAddr::new(ip.src, u16::from_be_bytes([t[0], t[1]]));
        let remote = SocketAddr::new(ip.dst, u16::from_be_bytes([t[2], t[3]]));
        let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
        let Some(&h) = self.by_tuple.get(&(local, remote)) else {
            return;
        };
        let c = &self.conns[&h];
        if c.side != Side::Client
            || c.iss != Some(seq)
            || !matches!(
                self.get(h).state(),
                TcpState::SynSent | TcpState::SynReceived
            )
        {
            return;
        }
        self.conns.get_mut(&h).unwrap().unreachable = Some(message[1]);
        self.abort(h);
    }

    /// Feeds one packet from the interface into smoltcp. Returns whether it was
    /// a TCP segment for this endpoint that carried data.
    fn ingress(&mut self, addr: IpAddr, now: smoltcp::time::Instant, packet: Vec<u8>) -> bool {
        let Some(ip) = Header::parse_whole(&packet) else {
            return false;
        };
        if ip.dst != addr {
            return false;
        }
        if ip.protocol == ICMP && addr.is_ipv4() {
            if Ipv4Packet::new_unchecked(&packet).verify_checksum() {
                self.unreachable(ip.payload(&packet));
            }
            return false;
        }
        if ip.protocol != TCP || ip.payload.len() < 20 {
            return false;
        }
        // smoltcp takes TCP only right after the IPv6 header. `parse_whole` has
        // checked the extension headers in between, so they are taken out,
        // as `split_protocols` does before packets get here.
        if ip.payload.start != 40 && ip.dst.is_ipv6() {
            return match strip_extension_headers(&packet) {
                Ok(Some(stripped)) => self.ingress(addr, now, stripped),
                _ => false,
            };
        }
        // Validate before a rejected packet can change connection bookkeeping.
        if ip.src.is_ipv4() && !Ipv4Packet::new_unchecked(&packet).verify_checksum() {
            return false;
        }
        let t = &packet[ip.payload.clone()];
        let Ok(repr) = TcpRepr::parse(&TcpPacket::new_unchecked(t), &ip.src.into(), &ip.dst.into())
        else {
            return false;
        };
        // A host discards what comes from an address that is not one
        // host's (RFC 1122 section 3.2.1.3), as smoltcp does on its own
        // path. The SYN cookies and refusals here answer before smoltcp
        // sees the segment, so the check comes first.
        if !unicast(ip.src) {
            return false;
        }
        let data = !repr.payload.is_empty();
        let src = SocketAddr::new(ip.src, u16::from_be_bytes([t[0], t[1]]));
        let dst = SocketAddr::new(ip.dst, u16::from_be_bytes([t[2], t[3]]));
        let arrived = Arrived::of(src, dst, t, repr.payload.len());
        let flags = t[13];
        let congestion = if ip.src.is_ipv4() {
            packet[1] & 3 == 3
        } else {
            packet[1] >> 4 & 3 == 3
        };
        let (syn, rst, ack) = (flags & 6 == 2, flags & 4 != 0, flags & 16 != 0);
        let new =
            !self.by_tuple.contains_key(&(dst, src)) && self.listeners.contains_key(&dst.port());
        // A SYN for a listener that smoltcp is to take: its options, and
        // what the listener's answer adds to the SYN-ACK.
        let mut attempt = None;
        if new && syn && !ack {
            let Some(taken) = self.attempt(arrived, t, now) else {
                return false;
            };
            attempt = Some(taken);
        }
        if new && ack && !syn && !rst && !self.take_cookie(arrived, now) {
            return false;
        }
        let handle = self.by_tuple.get(&(dst, src)).copied();
        let before = handle.map(|h| self.get(h).state());
        // The options of an ACK that may complete a handshake.
        let completing = (before == Some(TcpState::SynReceived)).then(|| segment_options(t));
        // A listening socket in an earlier slot must not take a SYN for
        // a tuple that already belongs to a connection.
        let mut idle = Vec::new();
        if syn
            && !ack
            && handle.is_some()
            && let Some(listener) = self.listeners.get(&dst.port())
        {
            for &id in &listener.idle {
                idle.push((id, self.sockets.remove(self.handles[&id])));
            }
        }
        self.dev.rx = Some(packet);
        self.iface
            .poll_ingress_single(now, &mut self.dev, &mut self.sockets);
        let consumed = self.dev.rx.is_none();
        self.dev.rx = None;
        for (id, socket) in idle {
            self.handles.insert(id, self.sockets.add(socket));
        }
        if let Some(h) = handle {
            if let Some(c) = self.conns.get_mut(&h)
                && c.ecn
            {
                if flags & 0x80 != 0 {
                    c.congestion_echo = false;
                }
                if congestion {
                    c.congestion_echo = true;
                }
            }
            if before == Some(TcpState::SynReceived) {
                self.touched.push(h);
            }
            let s = self.get(h);
            let after = s.state();
            if consumed && data && (s.recv_queue() != 0 || s.has_pending_recv()) {
                self.soiled(h);
            }
            let c = self.conns.get_mut(&h).unwrap();
            if (rst || after == TcpState::Closed)
                && before != Some(after)
                && matches!(after, TcpState::Closed | TcpState::Listen)
            {
                c.rst = true;
                c.held.clear();
                c.wake_gone();
            }
            if flags & 1 != 0
                && before != Some(after)
                && matches!(
                    after,
                    TcpState::CloseWait | TcpState::Closing | TcpState::TimeWait
                )
            {
                c.fin = true;
                // ACK an accepted FIN immediately, even if the application
                // drops its handle after reading EOF.
                self.sockets.get_mut(self.handles[&h]).set_ack_delay(None);
            }
            self.close_if_drained(h);
            // A RST in SYN-RECEIVED put the socket back in LISTEN. It is
            // taken back now: a later SYN in the same batch may land on it,
            // and must not find it still named for the old peer.
            if after == TcpState::Listen
                && let Some(l) = self.listeners.get_mut(&dst.port())
                && l.hatch(h, &self.conns)
                && !l.relisten(h, &mut self.conns, &mut self.by_tuple)
            {
                self.remove_socket(h);
            }
            if let Some(ack) = completing
                && !matches!(
                    after,
                    TcpState::SynReceived | TcpState::Listen | TcpState::Closed
                )
                && self.conns[&h].side == Side::Server
            {
                self.completed(h, arrived, ack);
            }
        }
        if let Some((syn, added)) = attempt {
            // At most one idle socket took the SYN.
            let l = self.listeners.get_mut(&dst.port()).unwrap();
            let (sockets, handles) = (&self.sockets, &self.handles);
            if let Some(i) = l
                .idle
                .iter()
                .position(|&h| sockets.get(handles[&h]).state() == TcpState::SynReceived)
            {
                let h = l.idle.swap_remove(i);
                let gives_up = now + HANDSHAKE_TIMEOUT.into();
                l.embryonic.insert((gives_up, h));
                let s = self.sockets.get(self.handles[&h]);
                let local = s.local_endpoint().map(SocketAddr::from).unwrap_or(dst);
                let remote = s.remote_endpoint().map(SocketAddr::from).unwrap_or(src);
                *l.per_peer.entry(remote.ip()).or_default() += 1;
                let wire: Vec<_> = added.iter().filter_map(TcpOption::to_wire).collect();
                self.sock(h)
                    .set_syn_options(&wire)
                    .expect("`attempt` checked that the answer can be sent");
                let mut conn = Conn::new(local, remote, Side::Server);
                conn.ecn = flags & 0xc0 == 0xc0;
                conn.handshake.syn = Some(syn);
                conn.handshake.syn_ack = Some(added.into());
                conn.handshake.irs = arrived.seq;
                conn.gives_up = Some(gives_up);
                self.conns.insert(h, conn);
                self.by_tuple.insert((local, remote), h);
            }
        }
        data
    }

    /// Answers a SYN for a listening port that no connection has. Returns
    /// its options, and what the listener's [`Answer::syn`] adds to the
    /// SYN-ACK, when smoltcp is to take it; a listening socket is ready to.
    /// Otherwise the SYN has been dropped, refused with a RST, or answered
    /// with a SYN cookie here, and smoltcp never sees it.
    fn attempt(
        &mut self,
        arrived: Arrived,
        t: &[u8],
        now: smoltcp::time::Instant,
    ) -> Option<(Arc<[TcpOption]>, Vec<TcpOption>)> {
        let (src, dst) = (arrived.from, arrived.to);
        let l = &self.listeners[&dst.port()];
        let peer_full = l
            .per_peer
            .get(&src.ip())
            .is_some_and(|&n| n >= BACKLOG_PER_PEER);
        if l.ready.len() >= self.backlog
            || (peer_full
                && self
                    .isolated_peer
                    .as_ref()
                    .is_some_and(|isolated| isolated(src.ip())))
        {
            return None;
        }
        let syn = segment_options(t);
        let cookie = l.embryonic.len() + l.ready.len() >= self.backlog || peer_full;
        let asked = Syn {
            options: &syn,
            from: src,
            seq: arrived.seq,
            cookie,
        };
        let added = match l.answer.as_ref().map(|answer| answer.syn(&asked)) {
            None => Vec::new(),
            Some(SynAnswer::Accept(added)) => added,
            Some(SynAnswer::Refuse(refusal)) => {
                // Options that cannot be sent leave a plain RST.
                let options = encode(&refusal).unwrap_or_default();
                self.dev.tx.push(arrived.reset(&options));
                return None;
            }
        };
        let Some(encoded) = encode(&added) else {
            self.dev.tx.push(arrived.reset(&[]));
            return None;
        };
        if cookie {
            let peer_mss = syn.iter().find_map(|o| match o {
                TcpOption::MaxSegmentSize(mss) => Some(*mss),
                _ => None,
            });
            let mss = cookie_mss(dst.is_ipv6(), peer_mss);
            let iss = self
                .cookies
                .make(dst, src, arrived.seq, cookie_minute(now), mss);
            let own_mss = MTU - if dst.is_ipv6() { 40 } else { 20 } - 20;
            let mut options = vec![2, 4];
            options.extend_from_slice(&(own_mss as u16).to_be_bytes());
            options.extend_from_slice(&encoded);
            let window = self.buffer.min(usize::from(u16::MAX)) as u16;
            let ack = arrived.seq.wrapping_add(1);
            self.dev
                .tx
                .push(segment(dst, src, iss, Some(ack), 0x02, window, &options));
            return None;
        }
        if l.idle.is_empty() {
            let mut s = new_socket(self.buffer);
            s.0.listen(dst.port()).expect("a new socket can listen");
            let h = self.add_socket(s);
            self.listeners.get_mut(&dst.port()).unwrap().idle.push(h);
        }
        for &h in &self.listeners[&dst.port()].idle {
            self.sockets
                .get_mut(self.handles[&h])
                .set_tsval_generator(Some(|now| (now.total_micros() / 1000) as u32));
        }
        Some((syn, added))
    }

    /// Takes an ACK for a listening port that no connection has. When it
    /// returns a SYN cookie this endpoint made, a connection opens for it in
    /// SYN-RECEIVED, which the ACK then completes. Returns whether to go on
    /// with the ACK: not when it returns a cookie but the connections
    /// waiting for `accept` fill the backlog.
    fn take_cookie(&mut self, arrived: Arrived, now: smoltcp::time::Instant) -> bool {
        let (src, dst) = (arrived.from, arrived.to);
        let Some(ack) = arrived.ack else {
            return true;
        };
        let (irs, iss) = (arrived.seq.wrapping_sub(1), ack.wrapping_sub(1));
        let Some(mss) = self.cookies.check(dst, src, irs, iss, cookie_minute(now)) else {
            return true;
        };
        let l = &self.listeners[&dst.port()];
        if l.ready.len() >= self.backlog
            || (l
                .per_peer
                .get(&src.ip())
                .is_some_and(|&n| n >= BACKLOG_PER_PEER)
                && self
                    .isolated_peer
                    .as_ref()
                    .is_some_and(|isolated| isolated(src.ip())))
        {
            return false;
        }
        let mut s = new_socket(self.buffer);
        s.0.listen(dst.port()).expect("a new socket can listen");
        s.0.accept_syn_cookie(dst.into(), src.into(), irs, iss, mss, now);
        let h = self.add_socket(s);
        let l = self.listeners.get_mut(&dst.port()).unwrap();
        let gives_up = now + HANDSHAKE_TIMEOUT.into();
        l.embryonic.insert((gives_up, h));
        *l.per_peer.entry(src.ip()).or_default() += 1;
        let mut conn = Conn::new(dst, src, Side::Server);
        conn.gives_up = Some(gives_up);
        conn.handshake.origin = HandshakeOrigin::Cookie;
        (conn.handshake.irs, conn.handshake.iss) = (irs, iss);
        self.conns.insert(h, conn);
        self.by_tuple.insert((dst, src), h);
        true
    }

    /// The ACK `arrived`, with options `ack`, completed the handshake of
    /// `h`, a connection a listener took. Its listener's [`Answer::ack`]
    /// says whether it stays. One it takes waits for `accept` from now on,
    /// so the next ACK that returns a SYN cookie counts it. One it refuses
    /// gets a RST in answer to that ACK and is forgotten at once.
    fn completed(&mut self, h: Id, arrived: Arrived, ack: Arc<[TcpOption]>) {
        let port = arrived.to.port();
        let l = self.listeners.get_mut(&port).expect("a listener");
        l.hatch(h, &self.conns);
        let c = self.conns.get_mut(&h).expect("a connection");
        c.gives_up = None;
        c.handshake.ack = ack;
        c.handshake.ack_payload = arrived.payload;
        // A SYN cookie's: what the listener kept of the SYN, if anything.
        if c.handshake.syn_ack.is_none()
            && let Some(kept) = l
                .answer
                .as_ref()
                .and_then(|a| a.cookie(arrived.from, &c.handshake))
        {
            c.handshake.syn = Some(kept.syn);
            c.handshake.syn_ack = Some(kept.syn_ack);
        }
        let handshake = &self.conns[&h].handshake;
        let answer = l
            .answer
            .as_ref()
            .map_or(AckAnswer::Accept, |a| a.ack(handshake));
        match answer {
            AckAnswer::Accept => {
                if let Some(segments) = l.answer.as_ref().and_then(|a| a.segments(handshake)) {
                    let wire: Vec<_> = handshake
                        .ack
                        .iter()
                        .filter_map(TcpOption::to_wire)
                        .collect();
                    let options = stcp::encode_options_within(&wire, 40)
                        .expect("received handshake options fit a TCP header");
                    let s = self.sockets.get_mut(self.handles[&h]);
                    s.set_segment_options(Box::new(SegmentsOnWire(segments)));
                    s.process_handshake_data(handshake.irs.wrapping_add(1), &options);
                }
                l.ready.push_back(h);
                if let Some(w) = l.waker.take() {
                    w.wake();
                }
                return;
            }
            AckAnswer::Refuse(refusal) => {
                // Options that cannot be sent leave a plain RST.
                let options = encode(&refusal).unwrap_or_default();
                self.dev.tx.push(arrived.reset(&options));
            }
            AckAnswer::Drop => {}
        }
        if let Some(c) = self.conns.remove(&h) {
            self.by_tuple.remove(&(c.local, c.remote));
            l.left(c.remote.ip());
        }
        self.remove_socket(h);
    }

    /// Drops the handshakes still waiting for their last ACK
    /// [`HANDSHAKE_TIMEOUT`] after their SYN, without a RST.
    fn expire_handshakes(&mut self, now: smoltcp::time::Instant) {
        let mut gone = Vec::new();
        for l in self.listeners.values_mut() {
            // Only those due, soonest first. One that left SYN-RECEIVED
            // is housekeeping's.
            let due: Vec<_> = l
                .embryonic
                .range(..=(now, Id(u64::MAX)))
                .copied()
                .filter(|&(_, h)| {
                    self.sockets.get(self.handles[&h]).state() == TcpState::SynReceived
                })
                .collect();
            for key @ (_, h) in due {
                l.embryonic.remove(&key);
                if let Some(c) = self.conns.remove(&h) {
                    self.by_tuple.remove(&(c.local, c.remote));
                    l.left(c.remote.ip());
                }
                gone.push(h);
            }
        }
        for h in gone {
            self.remove_socket(h);
        }
    }

    /// Forgets each orphan [`ORPHAN_TIMEOUT`] after it entered FIN-WAIT-2,
    /// whatever its peer sends meanwhile, without a RST, as Linux forgets
    /// one `tcp_fin_timeout` after (tcp_time_wait with TCP_FIN_WAIT2).
    /// Later segments from the peer get a RST, as there is no connection.
    /// Otherwise a peer that acknowledges the FIN and then sends an ACK
    /// now and then would keep the connection forever.
    fn expire_orphans(&mut self, now: smoltcp::time::Instant) {
        let mut i = 0;
        while i < self.orphans.len() {
            let h = self.orphans[i];
            let fin_wait_2 = self.get(h).state() == TcpState::FinWait2;
            let Some(c) = self.conns.get_mut(&h) else {
                i += 1;
                continue;
            };
            match (fin_wait_2, c.gives_up) {
                (true, Some(at)) if at <= now => {
                    self.orphans.swap_remove(i);
                    self.remove_conn(h);
                    continue;
                }
                (true, None) => c.gives_up = Some(now + ORPHAN_TIMEOUT.into()),
                (true, Some(_)) => {}
                (false, _) => c.gives_up = None,
            }
            i += 1;
        }
    }

    /// When the next handshake waiting for its last ACK is due to be
    /// dropped, or the next orphan in FIN-WAIT-2 forgotten.
    fn next_expiry(&self) -> Option<smoltcp::time::Instant> {
        let handshakes = self
            .listeners
            .values()
            .filter_map(|l| l.embryonic.first().map(|&(at, _)| at));
        let orphans = self
            .orphans
            .iter()
            .filter_map(|h| self.conns.get(h)?.gives_up);
        handshakes.chain(orphans).min()
    }

    /// Moves finished handshakes to the accept queues and removes orphans
    /// that have closed.
    fn housekeeping(&mut self) {
        let mut woken = Vec::new();
        let mut gone = Vec::new();
        // Handshakes still to be looked at next turn.
        let mut later = Vec::new();
        for h in std::mem::take(&mut self.touched) {
            let Some(c) = self.conns.get(&h) else {
                continue;
            };
            let Some(l) = self.listeners.get_mut(&c.local.port()) else {
                continue;
            };
            let Some(key) = l.embryo(h, &self.conns) else {
                continue;
            };
            let s = self.sockets.get(self.handles[&h]);
            match s.state() {
                TcpState::SynReceived => {}
                // An aborted socket keeps its endpoint until smoltcp sends
                // its RST, which the output allowance may leave for the
                // next turn.
                TcpState::Closed if s.remote_endpoint().is_some() => later.push(h),
                // `ingress` takes back a socket a RST returns to LISTEN.
                TcpState::Listen => {
                    l.embryonic.remove(&key);
                    if !l.relisten(h, &mut self.conns, &mut self.by_tuple) {
                        gone.push(h);
                    }
                }
                TcpState::Closed | TcpState::TimeWait => {
                    l.embryonic.remove(&key);
                    if let Some(c) = self.conns.remove(&h) {
                        self.by_tuple.remove(&(c.local, c.remote));
                        l.left(c.remote.ip());
                    }
                    gone.push(h);
                }
                _ => {
                    l.embryonic.remove(&key);
                    l.ready.push_back(h);
                    woken.extend(l.waker.take());
                }
            }
        }
        self.touched = later;
        for h in gone {
            self.remove_socket(h);
        }
        let mut i = 0;
        while i < self.orphans.len() {
            let h = self.orphans[i];
            let state = self.get(h).state();
            if state == TcpState::Closed && self.get(h).remote_endpoint().is_none() {
                // An aborted socket is already CLOSED, but keeps its
                // endpoint until smoltcp sends the RST. The output
                // allowance may leave that packet for the next turn.
                self.orphans.swap_remove(i);
                self.remove_conn(h);
            } else {
                // smoltcp owns the explicit TIME-WAIT expiry and exposes
                // it through poll_at. Retransmitted FINs restart its ten-
                // second timer; egress moves the socket to CLOSED at expiry.
                // The orphan timeout must not interrupt that with a RST.
                if state == TcpState::TimeWait && !self.conns[&h].retired {
                    self.sock(h).set_timeout(None);
                    let c = self.conns.get_mut(&h).unwrap();
                    c.retired = true;
                    c.held.clear();
                    woken.append(&mut c.gone);
                    self.time_wait.push_back(h);
                }
                i += 1;
            }
        }
        self.time_wait.retain(|h| self.conns.contains_key(h));
        if self.time_wait.len() > MAX_TIME_WAIT {
            while self.time_wait.len() > MAX_TIME_WAIT {
                let h = self.time_wait.pop_front().unwrap();
                self.remove_conn(h);
            }
            self.orphans.retain(|h| self.conns.contains_key(h));
        }
        self.compact();
        for w in woken {
            w.wake();
        }
    }
}

impl Shared {
    /// The endpoint stopped: every wait ends with an error.
    fn stop(&self) {
        let mut st = self.state.lock();
        st.stopped = true;
        let mut wakers: Vec<Waker> = st
            .listeners
            .values_mut()
            .filter_map(|l| l.waker.take())
            .collect();
        wakers.extend(st.driver.take());
        // Aborting wakes each socket's reader and writer.
        let handles: Vec<Id> = st.conns.keys().copied().collect();
        for h in handles {
            wakers.append(&mut st.conns.get_mut(&h).unwrap().gone);
            st.sock(h).abort();
        }
        for h in std::mem::take(&mut st.orphans) {
            st.remove_conn(h);
        }
        st.time_wait.clear();
        drop(st);
        for w in wakers {
            w.wake();
        }
    }
}

/// The endpoint's one task: packets in, smoltcp, packets out, timers.
async fn drive(fcx: &Cx, shared: &Shared, mut inner: impl Interface) {
    let mut timer = fictionet::Timer::new(fcx);
    let mut batch: VecDeque<Vec<u8>> = VecDeque::with_capacity(64);
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut closed = false;
    poll_fn(|cx| {
        if fcx.is_cancelled() {
            return Poll::Ready(());
        }
        let received;
        let exhausted;
        while batch.len() < 64 && !closed {
            match inner.poll_recv(fcx, cx) {
                Poll::Ready(Ok(p)) => batch.push_back(p.0),
                Poll::Ready(Err(_)) => {
                    closed = true;
                    break;
                }
                Poll::Pending => break,
            }
        }
        let next = {
            let mut st = shared.state.lock();
            match &st.driver {
                Some(w) if w.will_wake(cx.waker()) => {}
                _ => st.driver = Some(cx.waker().clone()),
            }
            let now = smol_now(fcx);
            st.iface.poll_maintenance(now);
            received = batch.len();
            let st = &mut *st;
            // Before egress, so a handshake given up sends nothing more.
            st.expire_handshakes(now);
            // Stop consuming input when the output queue is full.
            while st.dev.tx.len() < EGRESS_PACKETS {
                let Some(p) = batch.pop_front() else { break };
                // After a packet with data, egress immediately, so smoltcp can
                // ACK every second segment as it means to. With one egress
                // per batch, a whole window of data got one ACK. The
                // sender's slow start grows by one segment per ACK, so its
                // window then grew by one segment per round trip. Pure ACKs
                // are still handled as a batch.
                if st.ingress(shared.addr, now, p) {
                    st.iface.poll_egress(now, &mut st.dev, &mut st.sockets);
                }
            }
            while st.iface.poll_egress(now, &mut st.dev, &mut st.sockets)
                != smoltcp::iface::PollResult::None
            {}
            st.expire_orphans(now);
            st.housekeeping();
            exhausted = st.dev.tx.len() >= EGRESS_PACKETS || !batch.is_empty();
            std::mem::swap(&mut out, &mut st.dev.tx);
            for p in &mut out {
                st.sent(p);
            }
            if st.dirty.is_empty() {
                st.next_release = None;
            } else {
                match st.next_release {
                    Some(at) if at <= now => {
                        st.release_quiet();
                        st.next_release =
                            (!st.dirty.is_empty()).then(|| now + RELEASE_EVERY.into());
                    }
                    Some(_) => {}
                    None => st.next_release = Some(now + RELEASE_EVERY.into()),
                }
            }
            let at = st.iface.poll_at(now, &st.sockets);
            [at, st.next_release, st.next_expiry()]
                .into_iter()
                .flatten()
                .min()
        };
        for p in out.drain(..) {
            inner.send(Packet(p));
        }
        if closed && batch.is_empty() {
            return Poll::Ready(());
        }
        if received == 64 || exhausted {
            // Maybe more is waiting: give the rest of the run a turn, then
            // come back.
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let deadline = next.map(|t| {
            Instant::from_since_start(Duration::from_micros(t.total_micros().max(0) as u64))
        });
        match deadline {
            None => timer.clear(),
            Some(d) => {
                if timer.poll_until(cx, d).is_ready() {
                    // A timer is due, or the region was cancelled. Come back
                    // next turn, so a timer that keeps asking to run now
                    // cannot hold the thread.
                    timer.clear();
                    cx.waker().wake_by_ref();
                }
            }
        }
        Poll::Pending
    })
    .await
}

/// One machine's TCP, made by [`endpoint`].
///
/// An `Endpoint` is a handle to the endpoint's task. Clones share the same
/// machine.
#[derive(Clone)]
pub struct Endpoint {
    shared: Arc<Shared>,
}

impl Endpoint {
    /// Retains per-source flood limits only where the network prevents spoofing.
    pub(crate) fn limit_isolated_peers(&self, isolated: impl Fn(IpAddr) -> bool + Send + 'static) {
        self.shared.state.lock().isolated_peer = Some(Box::new(isolated));
    }

    /// The machine's address.
    pub fn addr(&self) -> IpAddr {
        self.shared.addr
    }

    /// Ends every connection with a peer whose address `which` accepts
    /// immediately, discarding what was still to be sent to it. Handles see
    /// [`ConnError::Reset`]. For peers that are gone for good, whose
    /// addresses someone else may take next. `which` runs with the endpoint
    /// locked.
    pub fn abort_peers(&self, which: impl Fn(IpAddr) -> bool) {
        let mut st = self.shared.state.lock();
        let hs: Vec<Id> = st
            .conns
            .iter()
            .filter(|(_, c)| which(c.remote.ip()))
            .map(|(h, _)| *h)
            .collect();
        if hs.is_empty() {
            return;
        }
        for h in hs {
            st.abort(h);
        }
        st.kick();
    }

    /// Listens on `port`.
    ///
    /// Fails if `port` is 0, if something already listens there, or if an
    /// outgoing connection uses the port. Dropping the listener frees the
    /// port.
    pub fn listen(&self, port: u16) -> Result<Listener, Error> {
        let mut st = self.shared.state.lock();
        if port == 0 {
            return Err(fictionet::Error::msg("TCP port 0 cannot be listened on"));
        }
        if st.listeners.contains_key(&port) || st.ports.contains_key(&port) {
            return Err(fictionet::Error::msg(format!(
                "TCP port {port} is already in use on {}",
                self.shared.addr
            )));
        }
        st.listeners.insert(port, Listen::default());
        st.take_port(port);
        Ok(Listener {
            shared: self.shared.clone(),
            port,
            wait: CancelWait::default(),
        })
    }

    /// Opens a connection from this machine to `to`.
    ///
    /// Fails with [`ConnError::Refused`] if the other side answers with a
    /// RST. It also fails with `Refused` immediately, without sending
    /// anything, if `to` has port 0, an
    /// unspecified address, or not the same IP version as this machine's
    /// address, or if every local port from 49152 up is taken. Fails with
    /// [`ConnError::TimedOut`] if nothing answers for two minutes, and with
    /// [`ConnError::Closed`] once the endpoint has stopped.
    ///
    /// An ICMPv4 destination-unreachable message (type 3, codes 0 through
    /// 15, except 4) fails with [`ConnError::Unreachable`] only when it
    /// quotes this attempt's local and remote addresses, ports, and emitted
    /// SYN sequence number. A quote may contain just the IP header and eight
    /// TCP bytes. Code 4 (fragmentation needed) is ignored; there is no path
    /// MTU discovery. Malformed, unrelated, and stale quotes are ignored.
    /// ICMP does not affect an established connection.
    pub async fn connect(&self, fcx: &Cx, to: SocketAddr) -> Result<TcpConnection, ConnError> {
        if fcx.is_cancelled() {
            return Err(ConnError::Cancelled);
        }
        let addr = self.shared.addr;
        if to.port() == 0 || to.is_ipv4() != addr.is_ipv4() || to.ip().is_unspecified() {
            return Err(ConnError::Refused);
        }
        let conn = {
            let mut st = self.shared.state.lock();
            if st.stopped {
                return Err(ConnError::Closed);
            }
            let mut port = None;
            for _ in 0..(65536 - EPHEMERAL as u32) {
                let p = st.next_port;
                st.next_port = if p == u16::MAX { EPHEMERAL } else { p + 1 };
                if !st.ports.contains_key(&p) {
                    port = Some(p);
                    break;
                }
            }
            // Every ephemeral port is taken: the kernel says EADDRNOTAVAIL.
            let Some(port) = port else {
                return Err(ConnError::Refused);
            };
            let local = SocketAddr::new(addr, port);
            let mut s = new_socket(st.buffer);
            let st = &mut *st;
            if s.0.connect(st.iface.context(), to, local).is_err() {
                return Err(ConnError::Refused);
            }
            let h = st.add_socket(s);
            st.conns.insert(h, Conn::new(local, to, Side::Client));
            st.by_tuple.insert((local, to), h);
            st.take_port(port);
            st.kick();
            TcpConnection {
                shared: self.shared.clone(),
                handle: h,
                local,
                remote: to,
                handshake: None,
                read_wait: CancelWait::default(),
                write_wait: CancelWait::default(),
            }
        };
        let mut wait = CancelWait::default();
        poll_fn(|cx| {
            if fcx.is_cancelled() {
                return Poll::Ready(Err(ConnError::Cancelled));
            }
            {
                let mut st = conn.shared.state.lock();
                if st.stopped {
                    return Poll::Ready(Err(ConnError::Closed));
                }
                let s = st.sock(conn.handle);
                match s.state() {
                    TcpState::SynSent | TcpState::SynReceived => s.register_send_waker(cx.waker()),
                    TcpState::Closed => {
                        return Poll::Ready(Err(match st.closed_reason(conn.handle) {
                            ConnError::Reset => ConnError::Refused,
                            e => e,
                        }));
                    }
                    _ => return Poll::Ready(Ok(())),
                }
            }
            if fcx.register_cancel(cx.waker(), &mut wait) {
                return Poll::Ready(Err(ConnError::Cancelled));
            }
            Poll::Pending
        })
        .await?;
        Ok(conn)
    }
}

/// Waits for incoming connections on one port.
pub struct Listener {
    shared: Arc<Shared>,
    port: u16,
    wait: CancelWait,
}

impl Listener {
    /// Answers each connection attempt from now on with `answer`.
    ///
    /// [`Answer::syn`] sees each SYN's options. [`SynAnswer::Accept`] adds
    /// options to the SYN-ACK and its retransmissions, after the endpoint's
    /// own (Maximum Segment Size, and SACK-Permitted, Timestamps and Window
    /// Scale when the SYN offered them), or after the Maximum Segment Size
    /// of a SYN cookie. [`SynAnswer::Refuse`] resets the attempt.
    ///
    /// [`Answer::ack`] sees the [`Handshake`] when the ACK that completes it
    /// arrives. [`AckAnswer::Refuse`] resets the connection then, and
    /// [`AckAnswer::Drop`] forgets it without a word. An accepted
    /// connection keeps its handshake ([`TcpConnection::handshake`]), and
    /// from then on carries the options of [`Answer::segments`] on each
    /// segment but a RST.
    ///
    /// A refusal's RST answers the segment refused, as RFC 9293 section
    /// 3.10.7.1 forms a reset, with window 0 and the refusal's options as
    /// its only options, as a Linux host sends one. The options either
    /// returns must fit in [`SYN_OPTIONS_ROOM`] bytes and read back as
    /// written: an [`Unknown`](TcpOption::Unknown) option may not have kind
    /// 0 or 1 or the bytes of a known option, and SACK has one to four
    /// blocks. Otherwise an accepted attempt gets a RST, and a refusal a RST
    /// without them.
    pub fn answer(&mut self, answer: Box<dyn Answer>) {
        let mut st = self.shared.state.lock();
        st.listeners
            .get_mut(&self.port)
            .expect("a listener has its port")
            .answer = Some(answer);
    }

    /// Waits for the next connection.
    ///
    /// Returns early with [`ConnError::Cancelled`] if `fcx`'s
    /// [region](fictionet::Cx#regions) is cancelled, and fails with
    /// [`ConnError::Closed`] once the endpoint has stopped.
    ///
    /// Each listening port holds up to its configured backlog of connections
    /// waiting for `accept`, counting those still in their handshake. See
    /// [`Options::backlog`] for the default, maximum and separate per-peer
    /// limit. Past the backlog, or past a peer's own limit, connection
    /// attempts get SYN cookies. A peer at its limit whose address the
    /// network keeps from being spoofed, such as an attached sandbox, has
    /// its SYNs dropped instead, until some of its connections are accepted
    /// or give up.
    pub async fn accept(&mut self, fcx: &Cx) -> Result<TcpConnection, ConnError> {
        let port = self.port;
        let shared = &self.shared;
        let wait = &mut self.wait;
        poll_fn(|cx| {
            if fcx.is_cancelled() {
                return Poll::Ready(Err(ConnError::Cancelled));
            }
            {
                let mut st = shared.state.lock();
                if st.stopped {
                    return Poll::Ready(Err(ConnError::Closed));
                }
                let l = st
                    .listeners
                    .get_mut(&port)
                    .expect("a listener has its port");
                if let Some(h) = l.ready.pop_front() {
                    let c = &st.conns[&h];
                    let (local, remote) = (c.local, c.remote);
                    let handshake = Some(c.handshake.clone());
                    st.listeners
                        .get_mut(&port)
                        .expect("a listener has its port")
                        .left(remote.ip());
                    return Poll::Ready(Ok(TcpConnection {
                        shared: shared.clone(),
                        handle: h,
                        local,
                        remote,
                        handshake,
                        read_wait: CancelWait::default(),
                        write_wait: CancelWait::default(),
                    }));
                }
                match &l.waker {
                    Some(w) if w.will_wake(cx.waker()) => {}
                    _ => l.waker = Some(cx.waker().clone()),
                }
            }
            if fcx.register_cancel(cx.waker(), wait) {
                return Poll::Ready(Err(ConnError::Cancelled));
            }
            Poll::Pending
        })
        .await
    }
}

impl fictionet::stdlib::network::Accept for Listener {
    type Conn = TcpConnection;

    async fn accept(&mut self, fcx: &Cx) -> Result<Self::Conn, ConnError> {
        Listener::accept(self, fcx).await
    }
}

impl fictionet::stdlib::network::Accepted for TcpConnection {
    fn local_addr(&self) -> SocketAddr {
        TcpConnection::local_addr(self)
    }

    fn peer_addr(&self) -> SocketAddr {
        TcpConnection::peer_addr(self)
    }

    fn handshake(&self) -> Option<Handshake> {
        TcpConnection::handshake(self).cloned()
    }

    fn reset(self) {
        TcpConnection::reset(self);
    }

    fn hold_until_gone<T: Send + 'static>(&self, item: T) {
        TcpConnection::hold_until_gone(self, Box::new(item));
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let mut st = self.shared.state.lock();
        let Some(l) = st.listeners.remove(&self.port) else {
            return;
        };
        st.free_port(self.port);
        for h in l.idle {
            st.remove_socket(h);
        }
        // Connections that never reached accept are reset.
        for h in l.embryonic.into_iter().map(|(_, h)| h).chain(l.ready) {
            st.orphan(h, true);
        }
    }
}

/// One TCP connection. Implements [`Connection`].
///
/// Dropping it closes the connection: a FIN after the bytes already
/// written, or a RST if bytes it received were never read.
pub struct TcpConnection {
    shared: Arc<Shared>,
    handle: Id,
    local: SocketAddr,
    remote: SocketAddr,
    handshake: Option<Handshake>,
    read_wait: CancelWait,
    write_wait: CancelWait,
}

impl TcpConnection {
    /// The other side's address and port.
    pub fn peer_addr(&self) -> SocketAddr {
        self.remote
    }

    /// This side's address and port.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// What the handshake that opened the connection carried, for one a
    /// listener accepted. `None` for one this side opened.
    pub fn handshake(&self) -> Option<&Handshake> {
        self.handshake.as_ref()
    }

    /// Closes the connection with a RST immediately and wakes disappearance
    /// watches. Its socket stays until the RST can be sent, without waiting
    /// for the peer.
    ///
    /// Dropping a connection whose received bytes were all read closes it
    /// with a FIN instead. Its connection counts stay until the peer has
    /// finished closing too, or has sent nothing for a minute. Reaching
    /// TIME-WAIT releases those counts; only bounded transport recovery
    /// state stays (see [`endpoint`]). A server that must bound how many
    /// closing sockets a peer can hold, such as one that turns connections
    /// away past a limit, resets each connection it is done with.
    pub fn reset(self) {
        let mut st = self.shared.state.lock();
        st.abort(self.handle);
        st.kick();
    }

    /// A watch that says when this connection has been reset, by either
    /// side, is gone, or its endpoint has stopped, without reading from it.
    /// For a server that is not reading, such as HTTP/1.1 while a handler works.
    pub fn gone_watch(&self) -> GoneWatch {
        GoneWatch {
            shared: self.shared.clone(),
            handle: self.handle,
        }
    }

    /// Keeps `item` until the connection is gone, which may be
    /// after this handle is dropped: closing waits for the peer (FIN-WAIT,
    /// LAST-ACK) until it has sent nothing for a minute. A socket that reaches
    /// TIME-WAIT after handle drop releases its items immediately. Only
    /// transport recovery state stays as described in [`endpoint`]. Limits
    /// that count connections hold their count here, so a peer that never
    /// finishes closing cannot open more past the limit. Each call keeps
    /// one more item.
    pub fn hold_until_gone(&self, item: Box<dyn std::any::Any + Send>) {
        self.gone_watch().hold_until_gone(item);
    }
}

/// Says when a connection has been reset, is gone, or its endpoint has
/// stopped, without reading from it. See [`TcpConnection::gone_watch`].
/// A dropped connection is gone once it reaches TIME-WAIT, even while
/// its transport recovery state stays to ACK retransmitted FINs.
#[derive(Clone)]
pub struct GoneWatch {
    shared: Arc<Shared>,
    handle: Id,
}

impl GoneWatch {
    /// Ready once the connection was reset, is gone, or its endpoint stopped.
    pub fn poll_gone(&self, cx: &mut Context<'_>) -> Poll<()> {
        poll_gone(&self.shared, self.handle, cx)
    }

    /// Resets the connection, as [`TcpConnection::reset`] does, after the
    /// connection itself was handed on. Wakes disappearance watches even
    /// while the connection handle is retained. Reads and writes on that
    /// handle report [`ConnError::Reset`]. Does nothing after the dropped
    /// connection reaches TIME-WAIT and is retired by housekeeping.
    pub fn reset(&self) {
        let mut st = self.shared.state.lock();
        if st.conns.get(&self.handle).is_some_and(|c| !c.retired) {
            st.abort(self.handle);
            st.kick();
        }
    }

    /// Sets how long the connection may sit idle before this side sends a
    /// keepalive, and how often it sends one after that, as a socket's
    /// SO_KEEPALIVE and TCP_KEEPIDLE do. `None` sends none. A connection
    /// starts with one every 45 seconds, so a peer that is gone is noticed;
    /// a Linux server sends none unless it asked for them, and then the
    /// first after two hours. Works after the connection itself was handed
    /// on. Does nothing once its handle was dropped.
    pub fn set_keep_alive(&self, interval: Option<Duration>) {
        let mut st = self.shared.state.lock();
        if st.conns.get(&self.handle).is_some_and(|c| !c.orphaned) {
            st.sock(self.handle)
                .set_keep_alive(interval.map(Into::into));
            st.kick();
        }
    }

    /// Keeps `item` until the connection is gone: see
    /// [`TcpConnection::hold_until_gone`]. Works after the connection
    /// itself was handed on, such as boxed behind TLS. Drops `item`
    /// immediately if the connection has already retired into TIME-WAIT.
    pub fn hold_until_gone(&self, item: Box<dyn std::any::Any + Send>) {
        let mut st = self.shared.state.lock();
        match st.conns.get_mut(&self.handle) {
            Some(c) if !c.retired => c.held.push(item),
            _ => drop(item),
        }
    }
}

/// Ready once the connection `handle` was reset, or is gone.
fn poll_gone(shared: &Shared, handle: Id, cx: &mut Context<'_>) -> Poll<()> {
    let mut st = shared.state.lock();
    if st.stopped {
        return Poll::Ready(());
    }
    match st.conns.get_mut(&handle) {
        None => Poll::Ready(()),
        Some(c) if c.rst || c.retired => Poll::Ready(()),
        Some(c) => {
            if !c.gone.iter().any(|w| w.will_wake(cx.waker())) {
                c.gone.push(cx.waker().clone());
            }
            Poll::Pending
        }
    }
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        let mut st = self.shared.state.lock();
        let h = self.handle;
        st.orphan(h, false);
    }
}

impl Connection for TcpConnection {
    fn poll_read(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        if fcx.is_cancelled() {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
        {
            let mut st = self.shared.state.lock();
            if st.stopped {
                return Poll::Ready(Err(ConnError::Closed));
            }
            let h = self.handle;
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            match st.sock(h).recv_slice(buf) {
                Ok(0) => st.sock(h).register_recv_waker(cx.waker()),
                Ok(n) => {
                    st.kick();
                    return Poll::Ready(Ok(n));
                }
                Err(stcp::RecvError::Finished) => return Poll::Ready(Ok(0)),
                Err(stcp::RecvError::InvalidState) => {
                    let c = &st.conns[&h];
                    if c.fin && !c.rst {
                        return Poll::Ready(Ok(0));
                    }
                    return Poll::Ready(Err(st.closed_reason(h)));
                }
            }
        }
        if fcx.register_cancel(cx.waker(), &mut self.read_wait) {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
        Poll::Pending
    }

    fn poll_write(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, ConnError>> {
        if fcx.is_cancelled() {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
        {
            let mut st = self.shared.state.lock();
            if st.stopped {
                return Poll::Ready(Err(ConnError::Closed));
            }
            let h = self.handle;
            if st.conns[&h].shut {
                return Poll::Ready(Err(ConnError::Closed));
            }
            if data.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let s = st.sock(h);
            match s.state() {
                TcpState::Established | TcpState::CloseWait => match s.send_slice(data) {
                    Ok(0) => s.register_send_waker(cx.waker()),
                    Ok(n) => {
                        st.soiled(h);
                        st.kick();
                        return Poll::Ready(Ok(n));
                    }
                    Err(_) => return Poll::Ready(Err(st.closed_reason(h))),
                },
                TcpState::Closed => return Poll::Ready(Err(st.closed_reason(h))),
                // The FIN went out already.
                _ => return Poll::Ready(Err(ConnError::Closed)),
            }
        }
        if fcx.register_cancel(cx.waker(), &mut self.write_wait) {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
        Poll::Pending
    }

    /// Sends a FIN once the peer has acknowledged every byte already written.
    /// Returns immediately. A cancel does not stop it.
    fn poll_shutdown(&mut self, _fcx: &Cx, _cx: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        let mut st = self.shared.state.lock();
        if st.stopped {
            return Poll::Ready(Err(ConnError::Closed));
        }
        let h = self.handle;
        if st.sock(h).state() == TcpState::Closed && !st.conns[&h].shut {
            return Poll::Ready(Err(st.closed_reason(h)));
        }
        st.conns.get_mut(&h).unwrap().shut = true;
        st.close_if_drained(h);
        st.kick();
        Poll::Ready(Ok(()))
    }
    fn poll_gone(&self, cx: &mut Context<'_>) -> Poll<()> {
        poll_gone(&self.shared, self.handle, cx)
    }
}

fictionet::cfg_std! {
#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::network::ConnectionExt;
    use fictionet::stdlib::network::ip::{set_header_checksum, transport_checksum};
    use fictionet::stdlib::test_support::rounds;
    use fictionet::{InterfaceExt, Seed, block_on, lab, pair, run};

    /// Sets the IP length fields and the checksums of a TCP packet that ends at
    /// `packet.len()` and whose TCP header starts at `tcp_at`.
    fn fix_lengths(packet: &mut [u8], tcp_at: usize, src: IpAddr, dst: IpAddr) {
        let len = packet.len();
        if src.is_ipv4() {
            packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
            let ihl = (packet[0] & 15) as usize * 4;
            set_header_checksum(&mut packet[..ihl]);
        } else {
            packet[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
        }
        packet[tcp_at + 16..tcp_at + 18].copy_from_slice(&[0, 0]);
        let sum = transport_checksum(src, dst, TCP, &packet[tcp_at..]);
        packet[tcp_at + 16..tcp_at + 18].copy_from_slice(&sum.to_be_bytes());
    }

    #[test]
    fn device_output_yields_and_preserves_waiting_input() {
        let mut dev = Dev::default();
        let now = smoltcp::time::Instant::from_micros(0);
        for _ in 0..EGRESS_PACKETS {
            dev.transmit(now).unwrap().consume(MTU, |_| {});
        }
        assert!(dev.transmit(now).is_none());
        dev.rx = Some(vec![1, 2, 3]);
        assert!(dev.receive(now).is_none());
        assert_eq!(dev.rx.as_deref(), Some([1, 2, 3].as_slice()));
        dev.tx.clear();
        let (rx, tx) = dev.receive(now).unwrap();
        rx.consume(|p| assert_eq!(p, [1, 2, 3]));
        tx.consume(40, |_| {});
        assert_eq!(dev.tx.len(), 1);
    }

    #[test]
    fn orphan_waits_for_reset_when_output_is_full() {
        block_on(run(Seed::random(), |fcx| async move {
            let (_raw, side) = pair();
            let local: SocketAddr = "10.0.0.1:80".parse().unwrap();
            let peer: SocketAddr = "10.0.0.2:1234".parse().unwrap();
            let ep = endpoint(&fcx, side, local.ip());
            let _listener = ep.listen(local.port())?;
            let now = smol_now(&fcx);
            let mut st = ep.shared.state.lock();
            st.ingress(local.ip(), now, segment(peer, local, 100, 0, 2).0);
            let syn_ack = egress(&mut st, now);
            let t = Header::parse_whole(&syn_ack[0]).unwrap().payload(&syn_ack[0]);
            let ack = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
            st.ingress(local.ip(), now, segment(peer, local, 101, ack, 16).0);
            st.housekeeping();
            let h = st.listeners.get_mut(&80).unwrap().ready.pop_front().unwrap();
            st.orphan(h, true);
            for _ in 0..EGRESS_PACKETS {
                st.dev.transmit(now).unwrap().consume(40, |_| {});
            }
            let st = &mut *st;
            st.iface.poll_egress(now, &mut st.dev, &mut st.sockets);
            st.housekeeping();
            assert!(st.conns.contains_key(&h), "unsent reset must keep its socket");
            st.dev.tx.clear();
            let packets = egress(st, now);
            assert_eq!(packets.len(), 1);
            let t = Header::parse_whole(&packets[0]).unwrap().payload(&packets[0]);
            assert_eq!(t[13] & 4, 4);
            st.housekeeping();
            assert!(!st.conns.contains_key(&h));
            Ok(())
        })).unwrap();
    }

    /// Handshakes a connection. Returns its socket and next send sequence.
    fn established(
        st: &mut State,
        now: smoltcp::time::Instant,
        local: SocketAddr,
        peer: SocketAddr,
    ) -> (Id, u32) {
        st.ingress(local.ip(), now, segment(peer, local, 100, 0, 2).0);
        let syn_ack = egress(st, now);
        let t = Header::parse_whole(&syn_ack[0]).unwrap().payload(&syn_ack[0]);
        let ack = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
        st.ingress(local.ip(), now, segment(peer, local, 101, ack, 16).0);
        st.housekeeping();
        let l = st.listeners.get_mut(&local.port()).unwrap();
        let h = l.ready.pop_front().unwrap();
        l.left(peer.ip());
        (h, ack)
    }

    /// Handshakes and actively closes a connection, leaving its final ACK
    /// for egress. Returns the dropped socket and the peer's FIN.
    fn time_wait(
        st: &mut State,
        now: smoltcp::time::Instant,
        local: SocketAddr,
        peer: SocketAddr,
    ) -> (Id, Packet) {
        let (h, ack) = established(st, now, local, peer);
        st.sock(h).close();
        let fin = egress(st, now);
        assert_eq!(Header::parse_whole(&fin[0]).unwrap().payload(&fin[0])[13], 0x11);
        let peer_fin = segment(peer, local, 101, ack.wrapping_add(1), 0x11);
        st.ingress(local.ip(), now, peer_fin.0.clone());
        assert_eq!(st.get(h).state(), TcpState::TimeWait);
        st.orphan(h, false);
        (h, peer_fin)
    }

    #[test]
    fn time_wait_survives_full_output_and_expires_after_retransmission() {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (_raw, side) = pair();
            let local: SocketAddr = "10.0.0.1:80".parse()?;
            let peer: SocketAddr = "10.0.0.2:1234".parse()?;
            let ep = endpoint(&fcx, side, local.ip());
            let _listener = ep.listen(local.port())?;
            let now = smol_now(&fcx);
            let mut st = ep.shared.state.lock();
            let (h, fin) = time_wait(&mut st, now, local, peer);
            drop(st);
            let watch = GoneWatch { shared: ep.shared.clone(), handle: h };
            let held = Arc::new(());
            watch.hold_until_gone(Box::new(held.clone()));
            let log = Arc::new(Mutex::new(Vec::new()));
            let waker = Waker::from(Arc::new(WakeLog(0, log.clone())));
            assert!(watch.poll_gone(&mut Context::from_waker(&waker)).is_pending());
            let mut st = ep.shared.state.lock();
            while st.dev.tx.len() < EGRESS_PACKETS {
                st.dev.transmit(now).unwrap().consume(40, |_| {});
            }
            let later = now + smoltcp::time::Duration::from_millis(20);
            {
                let st = &mut *st;
                st.iface.poll_egress(later, &mut st.dev, &mut st.sockets);
            }
            st.housekeeping();
            assert!(st.conns.contains_key(&h), "full egress must retain TIME-WAIT");
            assert_eq!(Arc::strong_count(&held), 1);
            assert_eq!(*log.lock(), [0]);
            drop(st);
            assert!(watch.poll_gone(&mut Context::from_waker(&waker)).is_ready());
            watch.reset();
            watch.hold_until_gone(Box::new(held.clone()));
            assert_eq!(Arc::strong_count(&held), 1);
            let mut st = ep.shared.state.lock();
            let st = &mut *st;
            assert_eq!(st.get(h).state(), TcpState::TimeWait);
            st.dev.tx.clear();
            let packets = egress(st, later);
            assert_eq!(packets.len(), 1);
            let t = Header::parse_whole(&packets[0]).unwrap().payload(&packets[0]);
            assert_eq!(t[13], 0x10);
            assert_eq!(u32::from_be_bytes(t[8..12].try_into().unwrap()), 102);
            // FINs near expiry restart the ten-second timer, even past the
            // orphan timeout for sockets that have not reached TIME-WAIT.
            for seconds in [9, 18, 27, 36, 45, 54, 63] {
                let retry = now + smoltcp::time::Duration::from_secs(seconds);
                st.ingress(local.ip(), retry, fin.0.clone());
                let packets = egress(st, retry);
                assert_eq!(packets.len(), 1);
                let t = Header::parse_whole(&packets[0]).unwrap().payload(&packets[0]);
                assert_eq!(t[13], 0x10);
            }
            let before = now + smoltcp::time::Duration::from_secs(72);
            assert!(egress(st, before).is_empty());
            st.housekeeping();
            assert!(st.conns.contains_key(&h));
            let expiry = now + smoltcp::time::Duration::from_secs(73);
            assert!(egress(st, expiry).is_empty());
            st.housekeeping();
            assert!(!st.conns.contains_key(&h));
            assert!(!st.handles.contains_key(&h));
            assert!(!st.pages.contains_key(&h));
            assert!(!st.by_tuple.contains_key(&(local, peer)));
            assert!(!st.orphans.contains(&h));
            assert!(st.time_wait.is_empty());
            assert_eq!(Arc::strong_count(&held), 1);
            Ok(())
        })).unwrap();
    }

    #[test]
    fn time_wait_overflow_evicts_the_oldest_dropped_connections() {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (_raw, side) = pair();
            let local: SocketAddr = "10.0.0.1:80".parse()?;
            let peer: IpAddr = "10.0.0.2".parse()?;
            let ep = endpoint_with(&fcx, side, local.ip(), Options::default().buffer(MIN_BUFFER));
            let _listener = ep.listen(local.port())?;
            let now = smol_now(&fcx);
            let mut st = ep.shared.state.lock();
            let (kept, _) = time_wait(&mut st, now, local, SocketAddr::new(peer, 1000));
            // Model a TIME-WAIT socket whose application still holds it.
            st.orphans.clear();
            egress(&mut st, now);
            let recent_peer = SocketAddr::new(peer, 1001);
            let (recent, ack) = established(&mut st, now, local, recent_peer);
            let mut dropped = Vec::new();
            for port in 1002..1002 + MAX_TIME_WAIT as u16 {
                let (h, _) = time_wait(&mut st, now, local, SocketAddr::new(peer, port));
                dropped.push(h);
                egress(&mut st, now);
                st.housekeeping();
            }
            // The older connection enters TIME-WAIT last. Evict by entry
            // order, even when the orphan list has been rearranged.
            st.orphans.reverse();
            let later = now + smoltcp::time::Duration::from_secs(1);
            st.sock(recent).close();
            assert_eq!(egress(&mut st, later).len(), 1);
            let fin = segment(recent_peer, local, 101, ack.wrapping_add(1), 0x11);
            st.ingress(local.ip(), later, fin.0);
            assert_eq!(st.get(recent).state(), TcpState::TimeWait);
            st.orphan(recent, false);
            egress(&mut st, later);
            st.housekeeping();
            assert_eq!(st.orphans.len(), MAX_TIME_WAIT);
            assert_eq!(st.time_wait.len(), MAX_TIME_WAIT);
            assert!(st.conns.contains_key(&kept));
            assert!(st.conns.contains_key(&recent));
            assert!(!st.conns.contains_key(&dropped[0]));
            assert!(!st.handles.contains_key(&dropped[0]));
            assert!(!st.by_tuple.contains_key(&(local, SocketAddr::new(peer, 1002))));
            assert!(dropped[1..].iter().all(|h| st.conns.contains_key(h)));
            // Eviction itself emits nothing. Normal expiry frees the rest.
            assert!(egress(&mut st, later).is_empty());
            let expiry = later + smoltcp::time::Duration::from_secs(10);
            assert!(egress(&mut st, expiry).is_empty());
            st.housekeeping();
            assert!(st.orphans.is_empty());
            assert!(st.time_wait.is_empty());
            assert_eq!(st.conns.len(), 1);
            assert!(st.conns.contains_key(&kept));
            Ok(())
        })).unwrap();
    }

    struct WakeLog(u16, Arc<Mutex<Vec<u16>>>);
    impl std::task::Wake for WakeLog {
        fn wake(self: Arc<Self>) {
            self.1.lock().push(self.0);
        }
    }

    #[test]
    fn local_reset_wakes_watches_before_rst_egress() {
        for reset in 0..3 {
            block_on(lab(Seed::from_u64(1), move |fcx| async move {
                let (a, b) = pair();
                let server = endpoint(&fcx, a, "10.0.0.1".parse().unwrap());
                let client = endpoint(&fcx, b, "10.0.0.2".parse().unwrap());
                let mut listener = server.listen(80)?;
                let _client = client.connect(&fcx, "10.0.0.1:80".parse().unwrap()).await?;
                let conn = listener.accept(&fcx).await?;
                let h = conn.handle;
                let watches = [conn.gone_watch(), conn.gone_watch()];
                let log = Arc::new(Mutex::new(Vec::new()));
                for (i, watch) in watches.iter().enumerate() {
                    let waker = Waker::from(Arc::new(WakeLog(i as u16, log.clone())));
                    assert!(watch.poll_gone(&mut Context::from_waker(&waker)).is_pending());
                }
                let mut conn = Some(conn);
                match reset {
                    0 => watches[0].reset(),
                    1 => conn.take().unwrap().reset(),
                    _ => server.abort_peers(|peer| peer == client.addr()),
                }
                assert_eq!(*log.lock(), [0, 1]);
                let cx = &mut Context::from_waker(Waker::noop());
                for watch in &watches {
                    assert!(watch.poll_gone(cx).is_ready());
                }
                if let Some(conn) = &mut conn {
                    assert!(matches!(
                        conn.poll_read(&fcx, cx, &mut [0]),
                        Poll::Ready(Err(ConnError::Reset))
                    ));
                    assert!(matches!(
                        conn.poll_write(&fcx, cx, b"x"),
                        Poll::Ready(Err(ConnError::Reset))
                    ));
                }
                let now = smol_now(&fcx);
                {
                    let mut st = server.shared.state.lock();
                    st.dev.tx.clear();
                    for _ in 0..EGRESS_PACKETS {
                        st.dev.transmit(now).unwrap().consume(40, |_| {});
                    }
                    let st = &mut *st;
                    st.iface.poll_egress(now, &mut st.dev, &mut st.sockets);
                    st.housekeeping();
                    assert!(st.conns.contains_key(&h), "unsent reset must keep its socket");
                    assert!(st.get(h).remote_endpoint().is_some());
                    st.dev.tx.clear();
                    let packets = egress(st, now);
                    assert_eq!(packets.len(), 1);
                    let t = Header::parse_whole(&packets[0]).unwrap().payload(&packets[0]);
                    assert_eq!(t[13] & 4, 4);
                    st.housekeeping();
                    assert_eq!(st.conns.contains_key(&h), conn.is_some());
                }
                drop(conn);
                let mut st = server.shared.state.lock();
                st.housekeeping();
                assert!(!st.conns.contains_key(&h));
                drop(st);
                fcx.cancel();
                Ok(())
            })).unwrap();
        }
    }

    #[test]
    fn stop_wakes_watches_with_retained_connection() {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (a, b) = pair();
            let server = endpoint(&fcx, a, "10.0.0.1".parse().unwrap());
            let client = endpoint(&fcx, b, "10.0.0.2".parse().unwrap());
            let mut listener = server.listen(80)?;
            let _client = client.connect(&fcx, "10.0.0.1:80".parse().unwrap()).await?;
            let mut conn = listener.accept(&fcx).await?;
            let watches = [conn.gone_watch(), conn.gone_watch()];
            let log = Arc::new(Mutex::new(Vec::new()));
            for (i, watch) in watches.iter().enumerate() {
                let waker = Waker::from(Arc::new(WakeLog(i as u16, log.clone())));
                assert!(watch.poll_gone(&mut Context::from_waker(&waker)).is_pending());
            }
            server.shared.stop();
            assert_eq!(*log.lock(), [0, 1]);
            let cx = &mut Context::from_waker(Waker::noop());
            for watch in &watches {
                assert!(watch.poll_gone(cx).is_ready());
            }
            assert!(matches!(
                conn.poll_read(&fcx, cx, &mut [0]),
                Poll::Ready(Err(ConnError::Closed))
            ));
            assert!(matches!(
                conn.poll_write(&fcx, cx, b"x"),
                Poll::Ready(Err(ConnError::Closed))
            ));
            assert!(server.shared.state.lock().conns.contains_key(&conn.handle));
            fcx.cancel();
            Ok(())
        })).unwrap();
    }

    #[test]
    fn stop_wakes_listeners_in_port_order() {
        block_on(run(fictionet::Seed::random(), |fcx| async move {
            let (_raw, side) = pair();
            let ep = endpoint(&fcx, side, "10.0.0.1".parse().unwrap());
            let log = Arc::new(Mutex::new(Vec::new()));
            let mut listeners = Vec::new();
            for port in [9000, 80, 443, 22, 8080] {
                listeners.push(ep.listen(port)?);
                ep.shared
                    .state
                    .lock()
                    .listeners
                    .get_mut(&port)
                    .unwrap()
                    .waker = Some(Waker::from(Arc::new(WakeLog(port, log.clone()))));
            }
            ep.shared.stop();
            assert_eq!(*log.lock(), [22, 80, 443, 8080, 9000]);
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }

    #[test]
    fn abort_peers_wakes_connections_in_socket_order() {
        block_on(run(fictionet::Seed::random(), |fcx| async move {
            let (_raw, side) = pair();
            let ep = endpoint(&fcx, side, "10.0.0.1".parse().unwrap());
            let log = Arc::new(Mutex::new(Vec::new()));
            {
                let mut st = ep.shared.state.lock();
                for port in [9000, 80, 443, 22, 8080] {
                    let id = st.add_socket(new_socket(MIN_BUFFER));
                    let mut conn = Conn::new(
                        "10.0.0.1:80".parse().unwrap(),
                        SocketAddr::new("10.0.0.2".parse().unwrap(), port),
                        Side::Server,
                    );
                    conn.gone
                        .push(Waker::from(Arc::new(WakeLog(port, log.clone()))));
                    st.conns.insert(id, conn);
                }
            }
            let peer: IpAddr = "10.0.0.2".parse().unwrap();
            ep.abort_peers(|p| p == peer);
            assert_eq!(*log.lock(), [9000, 80, 443, 22, 8080]);
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }

    #[test]
    fn compaction_keeps_socket_id_scan_order() {
        block_on(run(fictionet::Seed::random(), |fcx| async move {
            let (_raw, side) = pair();
            let ep = endpoint(&fcx, side, "10.0.0.1".parse().unwrap());
            let mut st = ep.shared.state.lock();
            let mut ids = Vec::new();
            for _ in 0..COMPACT_SLOTS {
                ids.push(st.add_socket(new_socket(MIN_BUFFER)));
            }
            let kept = [ids[3], ids[17], ids[93], ids[201]];
            for id in ids {
                if !kept.contains(&id) {
                    st.remove_socket(id);
                }
            }
            // Reuse a low storage slot with a newer SDK ID.
            let newest = st.add_socket(new_socket(MIN_BUFFER));
            assert!(st.slots >= COMPACT_SLOTS);
            st.compact();
            assert_eq!(st.slots, 5);
            let scan: Vec<_> = st
                .sockets
                .iter()
                .map(|(slot, _)| *st.handles.iter().find(|(_, h)| **h == slot).unwrap().0)
                .collect();
            assert_eq!(scan, [kept[0], kept[1], kept[2], kept[3], newest]);
            drop(st);
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }

    /// Resident pages of every socket's buffers on `e`.
    fn resident(e: &Endpoint) -> usize {
        let st = e.shared.state.lock();
        st.pages.values().map(Pages::resident).sum()
    }

    fn pattern(n: usize, salt: u8) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt))
            .collect()
    }

    /// A TCP segment from `src` to `dst` with no options.
    fn segment(src: SocketAddr, dst: SocketAddr, seq: u32, ack: u32, flags: u8) -> Packet {
        data_segment(src, dst, seq, ack, flags, &[])
    }

    fn data_segment(
        src: SocketAddr,
        dst: SocketAddr,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Packet {
        let mut t = vec![0u8; 20];
        t.extend_from_slice(payload);
        t[0..2].copy_from_slice(&src.port().to_be_bytes());
        t[2..4].copy_from_slice(&dst.port().to_be_bytes());
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        t[8..12].copy_from_slice(&ack.to_be_bytes());
        t[12] = 5 << 4;
        t[13] = flags;
        t[14..16].copy_from_slice(&65535u16.to_be_bytes());
        let sum = transport_checksum(src.ip(), dst.ip(), TCP, &t);
        t[16..18].copy_from_slice(&sum.to_be_bytes());
        fictionet::stdlib::network::ip::packet(src.ip(), dst.ip(), TCP, &t)
    }

    /// Drives the stack at one fixed time, without running its background task.
    fn egress(st: &mut State, now: smoltcp::time::Instant) -> Vec<Vec<u8>> {
        while st.iface.poll_egress(now, &mut st.dev, &mut st.sockets)
            != smoltcp::iface::PollResult::None
        {}
        let mut packets = std::mem::take(&mut st.dev.tx);
        for p in &mut packets {
            st.sent(p);
        }
        packets
    }

    #[test]
    fn icmp_requires_the_current_syn_and_a_valid_quote() {
        use fictionet::stdlib::network::{icmp, ip};

        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (_raw, side) = pair();
            let local: SocketAddr = "10.0.0.1:49152".parse().unwrap();
            let peer: SocketAddr = "10.0.0.2:80".parse().unwrap();
            let ep = endpoint(&fcx, side, local.ip());
            let mut st = ep.shared.state.lock();
            let mut previous = None;
            for (attempt, options) in [false, true].into_iter().enumerate() {
                // The second attempt comes a millisecond later. Its initial
                // sequence number then differs from the first's, which on
                // the same endpoints at the same instant it would not
                // (RFC 6528).
                let now = smol_now(&fcx) + smoltcp::time::Duration::from_millis(attempt as u64);
                st.iface.poll_maintenance(now);
                let mut socket = new_socket(MIN_BUFFER);
                socket.0.connect(st.iface.context(), peer, local).unwrap();
                let h = st.add_socket(socket);
                st.conns.insert(h, Conn::new(local, peer, Side::Client));
                st.by_tuple.insert((local, peer), h);
                st.take_port(local.port());
                let syn = egress(&mut st, now).remove(0);
                if let Some(old) = previous.take() {
                    // The same local port and peer now belong to a new attempt.
                    st.ingress(local.ip(), now, old);
                    assert_eq!(st.get(h).state(), TcpState::SynSent);
                }
                let fragmentation_needed =
                    icmp::error(&syn, "10.0.0.254".parse().unwrap(), 3, 4, 1400).unwrap();
                st.ingress(local.ip(), now, fragmentation_needed.0);
                assert_eq!(st.get(h).state(), TcpState::SynSent, "fragmentation needed");
                let error = icmp::host_unreachable(&syn, "10.0.0.254".parse().unwrap()).unwrap().0;
                for fault in [
                    "outer_ip", "icmp_checksum", "type", "code", "destination", "version",
                    "quoted_ip", "protocol", "fragment", "local_ip", "remote_ip",
                    "local_port", "remote_port", "sequence", "flags", "tcp_checksum", "length",
                ] {
                    let mut p = error.clone();
                    match fault {
                        "outer_ip" => p[10] ^= 1,
                        "icmp_checksum" => p[22] ^= 1,
                        "type" => p[20] = 11,
                        "code" => p[21] = 16,
                        "destination" => p[19] ^= 1,
                        "version" => p[28] = 0x65,
                        "quoted_ip" => p[38] ^= 1,
                        "protocol" => p[37] = 17,
                        "fragment" => p[35] = 1,
                        "local_ip" => p[43] ^= 1,
                        "remote_ip" => p[47] ^= 1,
                        "local_port" => p[49] ^= 1,
                        "remote_port" => p[51] ^= 1,
                        "sequence" => p[55] ^= 1,
                        "flags" => p[61] = 0x10,
                        "tcp_checksum" => p[64] ^= 1,
                        "length" => p[31] = 28,
                        _ => unreachable!(),
                    }
                    if matches!(fault, "local_ip" | "remote_ip" | "local_port" | "remote_port" | "sequence") {
                        // The minimum quote has no TCP checksum to mask a tuple mismatch.
                        p.truncate(56);
                        p[2..4].copy_from_slice(&56u16.to_be_bytes());
                    }
                    // Keep unrelated checksums valid so each rejection is tested.
                    if !matches!(fault, "outer_ip" | "icmp_checksum" | "quoted_ip" | "version") {
                        ip::set_header_checksum(&mut p[28..48]);
                        ip::set_header_checksum(&mut p[..20]);
                    }
                    if fault != "icmp_checksum" {
                        p[22..24].fill(0);
                        let sum = checksum(&p[20..]);
                        p[22..24].copy_from_slice(&sum.to_be_bytes());
                    }
                    st.ingress(local.ip(), now, p);
                    assert_eq!(st.get(h).state(), TcpState::SynSent, "{fault}");
                }
                // A truncated quote must contain all eight identity bytes.
                for len in 0..28 {
                    let mut message = vec![3, 1, 0, 0, 0, 0, 0, 0];
                    message.extend_from_slice(&syn[..len]);
                    let sum = checksum(&message);
                    message[2..4].copy_from_slice(&sum.to_be_bytes());
                    let p = ip::packet(peer.ip(), local.ip(), ICMP, &message);
                    st.ingress(local.ip(), now, p.0);
                    assert_eq!(st.get(h).state(), TcpState::SynSent, "quote length {len}");
                }
                // Also accept the minimum quote with IPv4 options.
                let mut valid = error.clone();
                if options {
                    valid.splice(48..48, [1; 4]);
                    valid[28] = 0x46;
                    let total = u16::from_be_bytes([valid[30], valid[31]]) + 4;
                    valid[30..32].copy_from_slice(&total.to_be_bytes());
                    ip::set_header_checksum(&mut valid[28..52]);
                    valid.truncate(60);
                    valid[2..4].copy_from_slice(&60u16.to_be_bytes());
                    ip::set_header_checksum(&mut valid[..20]);
                    valid[22..24].fill(0);
                    let sum = checksum(&valid[20..]);
                    valid[22..24].copy_from_slice(&sum.to_be_bytes());
                }
                st.ingress(local.ip(), now, valid);
                assert_eq!(st.get(h).state(), TcpState::Closed);
                assert_eq!(st.closed_reason(h), ConnError::Unreachable(1));
                previous = Some(error);
                st.remove_conn(h);
            }
            drop(st);
            fcx.cancel();
            Ok(())
        })).unwrap();
    }

    #[test]
    fn syn_rst_does_not_prepare_a_listening_socket() {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (_raw, side) = pair();
            let local: SocketAddr = "10.0.0.1:80".parse()?;
            let peer: SocketAddr = "10.0.0.2:1234".parse()?;
            let ep = endpoint(&fcx, side, local.ip());
            let _listener = ep.listen(local.port())?;
            let now = smol_now(&fcx);
            let mut st = ep.shared.state.lock();
            st.ingress(local.ip(), now, segment(peer, local, 7, 0, 0x02).0);
            egress(&mut st, now);
            assert!(st.listeners[&80].idle.is_empty());
            let count = st.sockets.iter().count();
            let other = SocketAddr::new(peer.ip(), peer.port() + 1);
            st.ingress(local.ip(), now, segment(other, local, 7, 0, 0x06).0);
            assert_eq!(st.sockets.iter().count(), count);
            assert!(st.listeners[&80].idle.is_empty());
            assert!(!st.by_tuple.contains_key(&(local, other)));
            assert!(egress(&mut st, now).is_empty());
            drop(st);
            fcx.cancel();
            Ok(())
        })).unwrap();
    }

    #[test]
    fn rejected_syn_acks_leave_handshake_bookkeeping_unchanged() {
        rejected_syn_acks(false);
    }

    #[test]
    fn unsolicited_syn_acks_leave_established_bookkeeping_unchanged() {
        rejected_syn_acks(true);
    }

    fn rejected_syn_acks(established: bool) {
        for (local, peer) in [
            ("10.0.0.1:1234", "10.0.0.2:80"),
            ("[fd00::1]:1234", "[fd00::2]:80"),
        ] {
            let local: SocketAddr = local.parse().unwrap();
            let peer: SocketAddr = peer.parse().unwrap();
            block_on(lab(Seed::from_u64(1), |fcx| async move {
                let (_raw, side) = pair();
                let ep = endpoint_with(&fcx, side, local.ip(), Options::default().buffer(MIN_BUFFER));
                let now = smol_now(&fcx);
                let mut st = ep.shared.state.lock();
                let mut s = new_socket(MIN_BUFFER);
                s.0.connect(st.iface.context(), peer, local).unwrap();
                let h = st.add_socket(s);
                st.conns.insert(h, Conn::new(local, peer, Side::Client));
                st.by_tuple.insert((local, peer), h);
                let packets = egress(&mut st, now);
                let t = Header::parse_whole(&packets[0]).unwrap().payload(&packets[0]);
                let ack = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
                let irs = u32::MAX - 3;
                if established {
                    st.ingress(local.ip(), now, segment(peer, local, irs, ack, 0x12).0);
                    egress(&mut st, now);
                    assert_eq!(st.get(h).state(), TcpState::Established);
                }
                let before = st.get(h).state();
                for fault in [
                    "empty_checksum", "checksum", "ack", "offset", "options", "flags", "ip", "none",
                ] {
                    // A SYN-ACK whose options end at a malformed one is
                    // taken with those before it, as Linux takes it.
                    if matches!(fault, "none" | "flags" | "options") && !established
                        || fault == "ip" && local.is_ipv6()
                    {
                        continue;
                    }
                    // This origin would put the receive edge at the first real byte.
                    let seq = irs.wrapping_sub(MIN_BUFFER as u32);
                    let mut p = segment(peer, local, seq, ack, 0x12).0;
                    let tcp_at = Header::parse_whole(&p).unwrap().payload.start;
                    if !matches!(fault, "empty_checksum" | "none") {
                        p.extend_from_slice(b"ignored");
                    }
                    match fault {
                        "ack" => p[tcp_at + 8..tcp_at + 12]
                            .copy_from_slice(&ack.wrapping_add(1).to_be_bytes()),
                        "offset" => p[tcp_at + 12] = 4 << 4,
                        "options" => {
                            p[tcp_at + 12] = 6 << 4;
                            p[tcp_at + 20..tcp_at + 24].copy_from_slice(&[2, 1, 0, 0]);
                        }
                        "flags" => p[tcp_at + 13] |= 4,
                        _ => {}
                    }
                    fix_lengths(&mut p, tcp_at, peer.ip(), local.ip());
                    if matches!(fault, "empty_checksum" | "checksum") {
                        p[tcp_at + 16] ^= 1;
                    } else if fault == "ip" {
                        p[10] ^= 1;
                    }
                    st.ingress(local.ip(), now, p);
                    assert_eq!(st.get(h).state(), before, "{fault}");
                    assert_eq!(st.get(h).recv_queue(), 0, "{fault}");
                    assert!(!st.get(h).has_pending_recv(), "{fault}");
                    assert!(!st.dirty.contains(&h), "{fault}");
                    egress(&mut st, now);
                }
                if !established {
                    st.ingress(local.ip(), now, segment(peer, local, irs, ack, 0x12).0);
                    egress(&mut st, now);
                }
                assert_eq!(st.get(h).state(), TcpState::Established);
                // Out-of-order data crosses zero. Releasing quiet pages must
                // preserve it until the gap fills.
                let expected = b"abcdefgh";
                for begin in [4usize, 0] {
                    let seq = irs.wrapping_add(1).wrapping_add(begin as u32);
                    let mut p = segment(peer, local, seq, ack, 0x10).0;
                    let tcp_at = Header::parse_whole(&p).unwrap().payload.start;
                    p.extend_from_slice(&expected[begin..begin + 4]);
                    fix_lengths(&mut p, tcp_at, peer.ip(), local.ip());
                    st.ingress(local.ip(), now, p);
                    egress(&mut st, now);
                    st.release_quiet();
                }
                let mut got = [0; 8];
                assert_eq!(st.sock(h).recv_slice(&mut got).unwrap(), expected.len());
                assert_eq!(&got, expected);
                if !established {
                    let local = SocketAddr::new(local.ip(), local.port() + 1);
                    let mut s = new_socket(MIN_BUFFER);
                    s.0.connect(st.iface.context(), peer, local).unwrap();
                    let h = st.add_socket(s);
                    st.conns.insert(h, Conn::new(local, peer, Side::Client));
                    st.by_tuple.insert((local, peer), h);
                    let packets = egress(&mut st, now);
                    let t = Header::parse_whole(&packets[0]).unwrap().payload(&packets[0]);
                    let ack = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
                    let seq = irs.wrapping_sub(MIN_BUFFER as u32);
                    let mut p = segment(peer, local, seq, ack, 0x16).0;
                    let tcp_at = Header::parse_whole(&p).unwrap().payload.start;
                    p.extend_from_slice(b"ignored");
                    fix_lengths(&mut p, tcp_at, peer.ip(), local.ip());
                    // RFC 9293 section 3.10.7.3 accepts RST with an acceptable ACK in SYN-SENT.
                    st.ingress(local.ip(), now, p);
                    assert_eq!(st.get(h).state(), TcpState::Closed);
                    assert_eq!(st.closed_reason(h), ConnError::Reset);
                    assert_eq!(st.get(h).recv_queue(), 0, "flags");
                    assert!(!st.get(h).has_pending_recv(), "flags");
                    assert!(!st.dirty.contains(&h), "flags");
                    assert!(egress(&mut st, now).is_empty());
                }
                drop(st);
                fcx.cancel();
                Ok(())
            }))
            .unwrap();
        }
    }

    #[test]
    fn simultaneous_open_records_the_accepted_syn_origin() {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (_raw, side) = pair();
            let local: SocketAddr = "10.0.0.1:1234".parse()?;
            let peer: SocketAddr = "10.0.0.2:80".parse()?;
            let ep = endpoint(&fcx, side, local.ip());
            let now = smol_now(&fcx);
            let mut st = ep.shared.state.lock();
            let mut s = new_socket(MIN_BUFFER);
            s.0.connect(st.iface.context(), peer, local).unwrap();
            let h = st.add_socket(s);
            st.conns.insert(h, Conn::new(local, peer, Side::Client));
            st.by_tuple.insert((local, peer), h);
            egress(&mut st, now);
            st.ingress(local.ip(), now, segment(peer, local, u32::MAX, 0, 0x02).0);
            assert_eq!(st.get(h).state(), TcpState::SynReceived);
            let packets = egress(&mut st, now);
            let t = Header::parse_whole(&packets[0]).unwrap().payload(&packets[0]);
            assert_eq!(t[13], 0x12);
            assert_eq!(u32::from_be_bytes(t[8..12].try_into().unwrap()), 0);
            drop(st);
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }

    #[test]
    fn a_window_update_after_shutdown_retransmits_refused_data() {
        for drop_handle in [false, true] {
            window_reopens(drop_handle, b"abcdefghijkl");
        }
    }

    #[test]
    fn a_window_update_retransmits_the_last_unacked_bytes() {
        window_reopens(false, b"abcdefgh");
    }

    #[test]
    fn far_future_ack_does_not_free_send_buffer() {
        ack_window_boundary(7);
    }

    #[test]
    fn wraparound_window_boundary() {
        ack_window_boundary(u32::MAX - MIN_BUFFER as u32 / 2);
    }

    #[test]
    fn a_rejected_ack_does_not_free_send_buffer() {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (_raw, side) = pair();
            let local: SocketAddr = "10.0.0.1:80".parse()?;
            let peer: SocketAddr = "10.0.0.2:1234".parse()?;
            let ep = endpoint(&fcx, side, local.ip());
            let _listener = ep.listen(local.port())?;
            let now = smol_now(&fcx);
            let mut st = ep.shared.state.lock();
            // No window has been advertised for this tuple.
            st.ingress(local.ip(), now, segment(peer, local, 102, 100, 0x10).0);
            let packets = egress(&mut st, now);
            assert_eq!(packets.len(), 1);
            assert_eq!(Header::parse_whole(&packets[0]).unwrap().payload(&packets[0])[13], 4);
            assert!(!st.by_tuple.contains_key(&(local, peer)));
            let (h, start) = established(&mut st, now, local, peer);
            assert_eq!(st.sock(h).send_slice(b"abcdefgh").unwrap(), 8);
            egress(&mut st, now);
            for (seq, corrupt) in [(102, true), (100, false)] {
                let mut p = segment(peer, local, seq, start.wrapping_add(4), 0x10).0;
                if corrupt {
                    p[36] ^= 1;
                }
                st.ingress(local.ip(), now, p);
                assert_eq!(st.get(h).send_queue(), 8);
                assert_eq!(st.get(h).recv_queue(), 0);
                let packets = egress(&mut st, now);
                if corrupt {
                    assert!(packets.is_empty());
                } else {
                    assert_eq!(packets.len(), 1);
                    let t = Header::parse_whole(&packets[0]).unwrap().payload(&packets[0]);
                    assert_eq!(u32::from_be_bytes(t[8..12].try_into().unwrap()), 101);
                }
            }
            st.ingress(local.ip(), now, segment(peer, local, 101, start.wrapping_add(4), 0x10).0);
            assert_eq!(st.get(h).send_queue(), 4);
            drop(st);
            fcx.cancel();
            Ok(())
        })).unwrap();
    }

    /// Bytes the peer sent before its FIN were acknowledged, so they stay
    /// readable after TIME-WAIT ends, as a kernel keeps them until the
    /// application closes the socket. The application reads them, then
    /// end of stream.
    #[test]
    fn unread_bytes_outlive_time_wait() {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (_raw, side) = pair();
            let local: SocketAddr = "10.0.0.1:80".parse()?;
            let peer: SocketAddr = "10.0.0.2:1234".parse()?;
            let ep = endpoint(&fcx, side, local.ip());
            let _listener = ep.listen(local.port())?;
            let now = smol_now(&fcx);
            let mut conn = {
                let mut st = ep.shared.state.lock();
                let (h, ack) = established(&mut st, now, local, peer);
                let conn = TcpConnection {
                    shared: ep.shared.clone(),
                    handle: h,
                    local,
                    remote: peer,
                    handshake: None,
                    read_wait: CancelWait::default(),
                    write_wait: CancelWait::default(),
                };
                // This side shuts down first; the peer answers with its last
                // bytes, its FIN and the ACK of this side's FIN.
                st.conns.get_mut(&h).unwrap().shut = true;
                st.close_if_drained(h);
                egress(&mut st, now);
                let mut last = segment(peer, local, 101, ack.wrapping_add(1), 0x19).0;
                last.extend_from_slice(b"last words");
                fix_lengths(&mut last, 20, peer.ip(), local.ip());
                st.ingress(local.ip(), now, last);
                assert_eq!(st.get(h).state(), TcpState::TimeWait);
                assert_eq!(st.get(h).recv_queue(), 10);
                egress(&mut st, now);
                // The application reads only after TIME-WAIT is over.
                egress(&mut st, now + smoltcp::time::Duration::from_secs(11));
                st.housekeeping();
                conn
            };
            let mut buf = [0; 32];
            let n = conn.read(&fcx, &mut buf).await?;
            assert_eq!(&buf[..n], b"last words");
            assert_eq!(conn.read(&fcx, &mut buf).await?, 0);
            drop(conn);
            fcx.cancel();
            Ok(())
        })).unwrap();
    }

    #[test]
    fn client_advertised_window_uses_negotiated_scale() {
        for scaled in [false, true] {
            block_on(lab(Seed::from_u64(1), move |fcx| async move {
                let (_raw, side) = pair();
                let local: SocketAddr = "10.0.0.1:1234".parse()?;
                let peer: SocketAddr = "10.0.0.2:80".parse()?;
                let ep = endpoint(&fcx, side, local.ip());
                let now = smol_now(&fcx);
                let mut st = ep.shared.state.lock();
                let mut socket = new_socket(BUFFER);
                socket.0.connect(st.iface.context(), peer, local).unwrap();
                let h = st.add_socket(socket);
                st.conns.insert(h, Conn::new(local, peer, Side::Client));
                st.by_tuple.insert((local, peer), h);
                let packets = egress(&mut st, now);
                let t = Header::parse_whole(&packets[0]).unwrap().payload(&packets[0]);
                assert_eq!(TcpPacket::new_unchecked(t).options_summary().unwrap().window_scale, Some(3));
                assert_eq!(t[13] & 16, 0, "a SYN has no ACK");
                let start = st.conns[&h].iss.unwrap().wrapping_add(1);
                let mut p = segment(peer, local, 7, start, 0x12).0;
                if scaled {
                    p[32] = 6 << 4;
                    p.extend_from_slice(&[1, 3, 3, 7]);
                    fix_lengths(&mut p, 20, peer.ip(), local.ip());
                }
                st.ingress(local.ip(), now, p);
                assert_eq!(st.get(h).state(), TcpState::Established);
                let packets = egress(&mut st, now);
                let t = Header::parse_whole(&packets[0])
                    .unwrap()
                    .payload(&packets[0]);
                let shift = if scaled { 3 } else { 0 };
                let win = (u16::from_be_bytes([t[14], t[15]]) as u32) << shift;
                assert_eq!(win, if scaled { BUFFER as u32 } else { 65535 });
                assert_eq!(u32::from_be_bytes(t[8..12].try_into().unwrap()).wrapping_add(win), 8 + win);
                drop(st);
                fcx.cancel();
                Ok(())
            }))
            .unwrap();
        }
    }

    #[test]
    fn legitimate_rounded_window_recovery() {
        for irs in [7u32, u32::MAX - BUFFER as u32 / 2] {
            block_on(lab(Seed::from_u64(1), move |fcx| async move {
                let (_raw, side) = pair();
                let local: SocketAddr = "10.0.0.1:80".parse()?;
                let peer: SocketAddr = "10.0.0.2:1234".parse()?;
                let ep = endpoint(&fcx, side, local.ip());
                let _listener = ep.listen(local.port())?;
                let now = smol_now(&fcx);
                let mut st = ep.shared.state.lock();
                let mut syn = segment(peer, local, irs, 0, 0x02).0;
                syn[32] = 6 << 4;
                syn.extend_from_slice(&[1, 3, 3, 7]);
                fix_lengths(&mut syn, 20, peer.ip(), local.ip());
                st.ingress(local.ip(), now, syn);
                let syn_ack = egress(&mut st, now).remove(0);
                let t = Header::parse_whole(&syn_ack).unwrap().payload(&syn_ack);
                let start = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
                let origin = irs.wrapping_add(1);
                let h = st.by_tuple[&(local, peer)];
                assert_eq!(TcpPacket::new_unchecked(t).options_summary().unwrap().window_scale, Some(3));
                assert_eq!(u32::from_be_bytes(t[8..12].try_into().unwrap()).wrapping_add(u16::from_be_bytes([t[14], t[15]]) as u32), origin.wrapping_add(65535));
                st.ingress(local.ip(), now, segment(peer, local, origin, start, 0x10).0);
                st.sock(h).set_ack_delay(None);
                assert_eq!(st.sock(h).send_slice(b"abcdefgh").unwrap(), 8);
                let sent = egress(&mut st, now);
                assert!(sent.iter().any(|p| {
                    let t = Header::parse_whole(p).unwrap().payload(p);
                    &t[((t[12] >> 4) as usize) * 4..] == b"abcdefgh"
                }));
                let edge = origin.wrapping_add(BUFFER as u32);
                let t = Header::parse_whole(&sent[0]).unwrap().payload(&sent[0]);
                assert_eq!(u32::from_be_bytes(t[8..12].try_into().unwrap()).wrapping_add((u16::from_be_bytes([t[14], t[15]]) as u32) << 3), edge);
                let expected = pattern(BUFFER, 7);
                let incoming = |begin: usize, end: usize, ack: u32| {
                    let mut p =
                        segment(peer, local, origin.wrapping_add(begin as u32), ack, 0x10).0;
                    p.extend_from_slice(&expected[begin..end]);
                    fix_lengths(&mut p, 20, peer.ip(), local.ip());
                    p
                };
                // Fill to the advertised edge out of order, leaving two
                // bytes missing. Then advance the ACK by just one byte.
                for begin in (2..BUFFER).step_by(1024) {
                    st.ingress(
                        local.ip(),
                        now,
                        incoming(begin, (begin + 1024).min(BUFFER), start),
                    );
                    egress(&mut st, now);
                }
                assert_eq!(st.get(h).recv_queue(), 0);
                st.ingress(local.ip(), now, incoming(0, 1, start));
                let sent = egress(&mut st, now);
                let t = Header::parse_whole(sent.last().unwrap())
                    .unwrap()
                    .payload(sent.last().unwrap());
                let ack = u32::from_be_bytes(t[8..12].try_into().unwrap());
                let win = (u16::from_be_bytes([t[14], t[15]]) as u32) << 3;
                assert_eq!(ack, origin.wrapping_add(1));
                assert_eq!(ack.wrapping_add(win), edge.wrapping_sub(7));
                assert_eq!(st.get(h).recv_queue(), 1);
                // The peer is at the old edge. An ACK outside our send
                // range must still be rejected even at that sequence.
                st.ingress(
                    local.ip(),
                    now,
                    segment(peer, local, edge, start.wrapping_add(9), 0x10).0,
                );
                assert_eq!(st.get(h).send_queue(), 8);
                st.ingress(
                    local.ip(),
                    now,
                    segment(peer, local, edge, start.wrapping_add(4), 0x10).0,
                );
                assert_eq!(
                    st.get(h).send_queue(),
                    4,
                    "the rounded window must not strand ACKs"
                );
                st.ingress(local.ip(), now, incoming(1, 2, start.wrapping_add(4)));
                assert_eq!(
                    st.get(h).recv_queue(),
                    BUFFER,
                    "the hole's retransmission must be accepted"
                );
                let mut got = vec![0; BUFFER];
                assert_eq!(st.sock(h).recv_slice(&mut got).unwrap(), BUFFER);
                assert_eq!(got, expected);
                let sent = egress(&mut st, now);
                let t = Header::parse_whole(sent.last().unwrap()).unwrap().payload(sent.last().unwrap());
                assert_eq!(u32::from_be_bytes(t[8..12].try_into().unwrap()).wrapping_add((u16::from_be_bytes([t[14], t[15]]) as u32) << 3), edge.wrapping_add(BUFFER as u32));
                drop(st);
                fcx.cancel();
                Ok(())
            }))
            .unwrap();
        }
    }

    fn ack_window_boundary(irs: u32) {
        for reopened in [false, true] {
            block_on(lab(Seed::from_u64(1), move |fcx| async move {
                let (_raw, side) = pair();
                let local: SocketAddr = "10.0.0.1:80".parse()?;
                let peer: SocketAddr = "10.0.0.2:1234".parse()?;
                let ep = endpoint_with(
                    &fcx,
                    side,
                    local.ip(),
                    Options::default().buffer(MIN_BUFFER),
                );
                let _listener = ep.listen(local.port())?;
                let now = smol_now(&fcx);
                let mut st = ep.shared.state.lock();
                st.ingress(local.ip(), now, segment(peer, local, irs, 0, 0x02).0);
                let syn_ack = egress(&mut st, now).remove(0);
                let t = Header::parse_whole(&syn_ack).unwrap().payload(&syn_ack);
                let start = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
                let rcv_nxt = irs.wrapping_add(1);
                let edge = rcv_nxt.wrapping_add(u16::from_be_bytes([t[14], t[15]]) as u32);
                assert_eq!(edge, rcv_nxt.wrapping_add(MIN_BUFFER as u32));
                st.ingress(
                    local.ip(),
                    now,
                    segment(peer, local, rcv_nxt, start, 0x10).0,
                );
                let h = st.by_tuple[&(local, peer)];
                assert_eq!(st.get(h).state(), TcpState::Established);
                assert_eq!(
                    st.sock(h).send_slice(&vec![0x5a; MIN_BUFFER]).unwrap(),
                    MIN_BUFFER
                );
                let sent = egress(&mut st, now);
                assert!(sent.iter().any(|p| {
                    let t = Header::parse_whole(p).unwrap().payload(p);
                    t.len() - ((t[12] >> 4) as usize) * 4 >= 4
                }));
                if reopened {
                    let mut p = segment(peer, local, rcv_nxt, start, 0x10).0;
                    p[34..36].copy_from_slice(&0u16.to_be_bytes());
                    fix_lengths(&mut p, 20, peer.ip(), local.ip());
                    st.ingress(local.ip(), now, p);
                    egress(&mut st, now);
                }
                for seq in [rcv_nxt.wrapping_add(10_000_000), edge.wrapping_add(1), edge] {
                    let p = segment(peer, local, seq, start.wrapping_add(4), 0x10).0;
                    st.ingress(local.ip(), now, p);
                    let accepted = seq == edge;
                    assert_eq!(
                        st.get(h).send_queue(),
                        MIN_BUFFER - if accepted { 4 } else { 0 },
                        "seq={seq}, edge={edge}, reopened={reopened}"
                    );
                    if !accepted && reopened {
                        assert!(
                            egress(&mut st, now).iter().all(|p| {
                                let t = Header::parse_whole(p).unwrap().payload(p);
                                t.len() == ((t[12] >> 4) as usize) * 4
                            }),
                            "an out-of-window ACK must not reopen the send window"
                        );
                    }
                }
                drop(st);
                fcx.cancel();
                Ok(())
            }))
            .unwrap();
        }
    }

    #[test]
    fn sack_ack_ahead_without_advertised_window_is_unchanged() {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (_raw, side) = pair();
            let local: SocketAddr = "10.0.0.1:80".parse()?;
            let peer: SocketAddr = "10.0.0.2:1234".parse()?;
            let ep = endpoint(&fcx, side, local.ip());
            let _listener = ep.listen(local.port())?;
            let now = smol_now(&fcx);
            let mut st = ep.shared.state.lock();
            let mut p = segment(peer, local, 9, 100, 0x10).0;
            p[32] = 8 << 4;
            p[34..36].copy_from_slice(&456u16.to_be_bytes());
            p.extend_from_slice(&[5, 10, 0, 0, 0, 104, 0, 0, 0, 105, 0, 0]);
            fix_lengths(&mut p, 20, peer.ip(), local.ip());
            st.ingress(local.ip(), now, p);
            assert!(!st.by_tuple.contains_key(&(local, peer)));
            let packets = egress(&mut st, now);
            assert_eq!(packets.len(), 1);
            let t = Header::parse_whole(&packets[0]).unwrap().payload(&packets[0]);
            assert_eq!(t[13], 4);
            assert_eq!(u32::from_be_bytes(t[4..8].try_into().unwrap()), 100);
            assert_eq!(transport_checksum(local.ip(), peer.ip(), TCP, t), 0);
            drop(st);
            fcx.cancel();
            Ok(())
        })).unwrap();
    }

    #[test]
    fn sack_acks_preserve_zero_window_changes() {
        for (old, win) in [(123u16, 0u16), (0, 123), (123, 456)] {
            block_on(lab(Seed::from_u64(1), |fcx| async move {
                let (_raw, side) = pair();
                let local: SocketAddr = "10.0.0.1:80".parse()?;
                let peer: SocketAddr = "10.0.0.2:1234".parse()?;
                let ep = endpoint(&fcx, side, local.ip());
                let _listener = ep.listen(local.port())?;
                let now = smol_now(&fcx);
                let mut st = ep.shared.state.lock();
                let mut syn = segment(peer, local, 7, 0, 2).0;
                syn[32] = 6 << 4;
                syn.extend_from_slice(&[4, 2, 0, 0]);
                fix_lengths(&mut syn, 20, peer.ip(), local.ip());
                st.ingress(local.ip(), now, syn);
                let packets = egress(&mut st, now);
                let t = Header::parse_whole(&packets[0]).unwrap().payload(&packets[0]);
                assert!(TcpPacket::new_unchecked(t).options_summary().unwrap().sack_permitted);
                let start = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
                st.ingress(local.ip(), now, segment(peer, local, 8, start, 16).0);
                let h = st.by_tuple[&(local, peer)];
                let ack = |window: u16, sack: bool| {
                    let mut p = segment(peer, local, 8, start, 16).0;
                    p[34..36].copy_from_slice(&window.to_be_bytes());
                    if sack {
                        p[32] = 8 << 4;
                        p.extend_from_slice(&[5, 10]);
                        p.extend_from_slice(&start.wrapping_add(4).to_be_bytes());
                        p.extend_from_slice(&start.wrapping_add(5).to_be_bytes());
                        p.extend_from_slice(&[0, 0]);
                    }
                    fix_lengths(&mut p, 20, peer.ip(), local.ip());
                    p
                };
                st.ingress(local.ip(), now, ack(old, false));
                assert_eq!(st.sock(h).send_slice(b"abcdefgh").unwrap(), 8);
                let packets = egress(&mut st, now);
                assert_eq!(packets.len(), usize::from(old != 0));
                if old != 0 {
                    let t = Header::parse_whole(&packets[0]).unwrap().payload(&packets[0]);
                    assert_eq!(&t[((t[12] >> 4) as usize) * 4..], b"abcdefgh");
                }
                for i in 0..3 {
                    // Changing nonzero windows still count toward fast retransmit.
                    st.ingress(local.ip(), now, ack(if win == 456 { win - i } else { win }, true));
                    let packets = egress(&mut st, now);
                    let sends = old == 0 && i == 0 || old != 0 && win != 0 && i == 2;
                    assert_eq!(packets.len(), usize::from(sends));
                    for p in packets {
                        let t = Header::parse_whole(&p).unwrap().payload(&p);
                        assert_eq!(u32::from_be_bytes(t[4..8].try_into().unwrap()), start);
                        assert_eq!(&t[((t[12] >> 4) as usize) * 4..], b"abcdefgh");
                        assert_eq!(transport_checksum(local.ip(), peer.ip(), TCP, t), 0);
                    }
                }
                assert_eq!(st.get(h).send_queue(), 8);
                drop(st);
                fcx.cancel();
                Ok(())
            })).unwrap();
        }
    }

    #[test]
    fn payload_at_buffer_end_preserves_data_and_defers_fin() {
        for (local, peer) in [
            ("10.0.0.1:80", "10.0.0.2:1234"),
            ("[fd00::1]:80", "[fd00::2]:1234"),
        ] {
            let local: SocketAddr = local.parse().unwrap();
            let peer: SocketAddr = peer.parse().unwrap();
            for (offset, keep) in [(-10i32, 10usize), (0, 0), (10, 0), (-20, 20)] {
                block_on(lab(Seed::from_u64(1), |fcx| async move {
                    let (_raw, side) = pair();
                    let ep = endpoint_with(&fcx, side, local.ip(), Options::default().buffer(MIN_BUFFER));
                    let _listener = ep.listen(local.port())?;
                    let now = smol_now(&fcx);
                    let mut st = ep.shared.state.lock();
                    let irs = u32::MAX - MIN_BUFFER as u32;
                    let origin = irs.wrapping_add(1);
                    st.ingress(local.ip(), now, segment(peer, local, irs, 0, 2).0);
                    let packets = egress(&mut st, now);
                    let t = Header::parse_whole(&packets[0]).unwrap().payload(&packets[0]);
                    let start = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
                    st.ingress(local.ip(), now, segment(peer, local, origin, start, 16).0);
                    let h = st.by_tuple[&(local, peer)];
                    st.sock(h).set_ack_delay(None);
                    let expected = pattern(MIN_BUFFER + 49, 7);
                    let incoming = |begin: usize, end: usize, fin: bool| {
                        let mut p = segment(peer, local, origin.wrapping_add(begin as u32), start, 16 | u8::from(fin)).0;
                        let tcp_at = Header::parse_whole(&p).unwrap().payload.start;
                        p.extend_from_slice(&expected[begin..end]);
                        fix_lengths(&mut p, tcp_at, peer.ip(), local.ip());
                        p
                    };
                    st.ingress(local.ip(), now, incoming(0, 19, false));
                    egress(&mut st, now);
                    let mut prefix = [0; 19];
                    assert_eq!(st.sock(h).recv_slice(&mut prefix).unwrap(), 19);
                    assert_eq!(prefix, expected[..19]);
                    // A duplicate elicits the window opened by the read.
                    st.ingress(local.ip(), now, incoming(0, 19, false));
                    egress(&mut st, now);
                    let edge = 19 + MIN_BUFFER;
                    let begin = edge.checked_add_signed(offset as isize).unwrap();
                    let p = incoming(begin, begin + 20, true);
                    let mut bad = p.clone();
                    let tcp_at = Header::parse_whole(&bad).unwrap().payload.start;
                    bad[tcp_at + 16] ^= 1;
                    st.ingress(local.ip(), now, bad);
                    assert!(egress(&mut st, now).is_empty());
                    assert_eq!(st.get(h).recv_queue(), 0);
                    assert!(!st.get(h).has_pending_recv());
                    assert!(!st.conns[&h].fin);
                    st.ingress(local.ip(), now, p);
                    assert_eq!(st.get(h).recv_queue(), 0);
                    assert_eq!(st.get(h).has_pending_recv(), keep != 0);
                    assert_eq!(st.get(h).state(), TcpState::Established);
                    assert!(!st.conns[&h].fin);
                    let packets = egress(&mut st, now);
                    assert_eq!(packets.len(), 1);
                    let t = Header::parse_whole(&packets[0]).unwrap().payload(&packets[0]);
                    assert_eq!(u32::from_be_bytes(t[8..12].try_into().unwrap()), origin.wrapping_add(19));
                    assert_eq!(transport_checksum(local.ip(), peer.ip(), TCP, t), 0);
                    let gap_end = edge - keep;
                    for at in (19..gap_end).step_by(1024) {
                        st.ingress(local.ip(), now, incoming(at, (at + 1024).min(gap_end), false));
                        egress(&mut st, now);
                    }
                    let mut got = vec![0; MIN_BUFFER];
                    assert_eq!(st.sock(h).recv_slice(&mut got).unwrap(), MIN_BUFFER);
                    assert_eq!(got, expected[19..edge]);
                    assert!(!st.conns[&h].fin);
                    egress(&mut st, now);
                    // The discarded tail and FIN fit after the application reads.
                    st.ingress(local.ip(), now, incoming(edge, begin + 20, true));
                    let packets = egress(&mut st, now);
                    assert_eq!(packets.len(), 1);
                    let t = Header::parse_whole(&packets[0]).unwrap().payload(&packets[0]);
                    assert_eq!(u32::from_be_bytes(t[8..12].try_into().unwrap()), origin.wrapping_add((begin + 21) as u32));
                    assert_eq!(transport_checksum(local.ip(), peer.ip(), TCP, t), 0);
                    let mut tail = [0; 30];
                    if begin + 20 != edge {
                        let len = st.sock(h).recv_slice(&mut tail).unwrap();
                        assert_eq!(len, begin + 20 - edge);
                        assert_eq!(&tail[..len], &expected[edge..begin + 20]);
                    }
                    assert_eq!(st.sock(h).recv_slice(&mut tail), Err(stcp::RecvError::Finished));
                    assert!(st.conns[&h].fin);
                    drop(st);
                    fcx.cancel();
                    Ok(())
                })).unwrap();
            }
        }
    }

    #[test]
    fn scaled_syn_ack_data_crossing_buffer_end() {
        scaled_syn_ack_buffer_end(false);
    }

    #[test]
    fn scaled_syn_ack_data_past_buffer_end() {
        scaled_syn_ack_buffer_end(true);
    }

    fn scaled_syn_ack_buffer_end(read_as_received: bool) {
        for (local, peer) in [
            ("10.0.0.1:80", "10.0.0.2:1234"),
            ("[fd00::1]:80", "[fd00::2]:1234"),
        ] {
            let local: SocketAddr = local.parse().unwrap();
            let peer: SocketAddr = peer.parse().unwrap();
            let result = block_on(run(fictionet::Seed::random(), move |fcx| async move {
                let (side, _raw) = pair();
                let server = endpoint_with(&fcx, side, local.ip(), Options::default());
                let mut listener = server.listen(local.port())?;
                let now = smoltcp::time::Instant::from_millis(100);
                let tcp_at = if local.is_ipv4() { 20 } else { 40 };
                // Cross sequence number zero while filling the buffer.
                let irs = u32::MAX - 131072;
                let start = {
                    let mut syn = segment(peer, local, irs, 0, 0x02).0;
                    syn[tcp_at + 12] = 6 << 4;
                    syn.extend_from_slice(&[1, 3, 3, 7]);
                    fix_lengths(&mut syn, tcp_at, peer.ip(), local.ip());
                    let mut st = server.shared.state.lock();
                    st.ingress(local.ip(), now, syn);
                    let packets = egress(&mut st, now);
                    let t = Header::parse_whole(&packets[0])
                        .unwrap()
                        .payload(&packets[0]);
                    assert_eq!(t[13], 0x12);
                    let start = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
                    st.ingress(
                        local.ip(),
                        now,
                        segment(peer, local, irs.wrapping_add(1), start, 0x10).0,
                    );
                    st.housekeeping();
                    egress(&mut st, now);
                    start
                };
                let mut conn = listener.accept(&fcx).await?;
                let capacity = server.shared.state.lock().get(conn.handle).recv_capacity();
                assert_eq!(capacity, 256 * 1024);
                // Vary the pattern across buffer laps so overwritten bytes differ.
                let expected: Vec<u8> = (0..(capacity + 4096).div_ceil(997))
                    .flat_map(|i| pattern(997, i as u8))
                    .collect();
                let incoming = |begin: usize, end: usize| {
                    let seq = irs.wrapping_add(1).wrapping_add(begin as u32);
                    let mut p = segment(peer, local, seq, start, 0x10).0;
                    p.extend_from_slice(&expected[begin..end]);
                    fix_lengths(&mut p, tcp_at, peer.ip(), local.ip());
                    let mut st = server.shared.state.lock();
                    st.ingress(local.ip(), now, p);
                    egress(&mut st, now);
                };
                let ahead = if read_as_received {
                    capacity + 37
                } else {
                    capacity - 37
                };
                incoming(ahead, ahead + 100);
                let mut got = vec![0; expected.len()];
                let mut read = 0;
                let first_end = if read_as_received {
                    expected.len()
                } else {
                    ahead
                };
                for begin in (0..first_end).step_by(1024) {
                    let end = (begin + 1024).min(first_end);
                    incoming(begin, end);
                    if read_as_received {
                        while read < end {
                            let n = conn.read(&fcx, &mut got[read..end]).await?;
                            assert!(n > 0);
                            read += n;
                        }
                        assert_eq!(
                            got[..end],
                            expected[..end],
                            "stream differs at offset {begin}"
                        );
                    }
                }
                if !read_as_received {
                    while read < capacity {
                        let n = conn.read(&fcx, &mut got[read..capacity]).await?;
                        assert!(n > 0);
                        read += n;
                    }
                    assert_eq!(got[..capacity], expected[..capacity]);
                    // Resend the trimmed tail once application reads make room.
                    egress(&mut server.shared.state.lock(), now);
                    incoming(capacity, expected.len());
                    while read < expected.len() {
                        let n = conn.read(&fcx, &mut got[read..]).await?;
                        assert!(n > 0);
                        read += n;
                    }
                }
                assert_eq!(got, expected);
                Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
            }));
            assert_eq!(result.unwrap_err().to_string(), "done");
        }
    }

    fn window_reopens(drop_handle: bool, data: &'static [u8]) {
        let result = block_on(run(fictionet::Seed::random(), move |fcx| async move {
            let (side, _raw) = pair();
            let local: SocketAddr = "10.0.0.1:80".parse().unwrap();
            let peer: SocketAddr = "10.0.0.2:1234".parse().unwrap();
            let server = endpoint(&fcx, side, local.ip());
            let mut listener = server.listen(local.port())?;
            let now = smoltcp::time::Instant::from_millis(100);
            let incoming = |seq, ack, flags, win: u16| {
                let mut p = segment(peer, local, seq, ack, flags).0;
                p[34..36].copy_from_slice(&win.to_be_bytes());
                fix_lengths(&mut p, 20, peer.ip(), local.ip());
                p
            };
            let start = {
                let mut st = server.shared.state.lock();
                st.ingress(local.ip(), now, incoming(7, 0, 0x02, 8));
                let packets = egress(&mut st, now);
                let t = Header::parse_whole(&packets[0])
                    .unwrap()
                    .payload(&packets[0]);
                assert_eq!(t[13], 0x12);
                let start = u32::from_be_bytes(t[4..8].try_into().unwrap()).wrapping_add(1);
                // The peer closes its send half before reading the reply.
                st.ingress(local.ip(), now, incoming(8, start, 0x11, 8));
                st.housekeeping();
                egress(&mut st, now);
                start
            };
            let mut conn = listener.accept(&fcx).await?;
            let h = conn.handle;
            conn.write_all(&fcx, data).await?;
            if drop_handle {
                drop(conn);
            } else {
                conn.shutdown(&fcx).await?;
                assert_eq!(conn.write_all(&fcx, b"late").await, Err(ConnError::Closed));
            }
            let mut st = server.shared.state.lock();
            let sent = egress(&mut st, now);
            assert!(sent.iter().any(|p| {
                let t = Header::parse_whole(p).unwrap().payload(p);
                t[((t[12] >> 4) as usize) * 4..] == data[..8]
            }));
            // Only the first four bytes arrived. The other four were sent
            // on a stale window and refused after the window closed.
            st.ingress(local.ip(), now, incoming(9, start.wrapping_add(4), 0x10, 0));
            assert_eq!(st.get(h).send_queue(), data.len() - 4);
            egress(&mut st, now);
            st.ingress(
                local.ip(),
                now,
                incoming(9, start.wrapping_add(4), 0x10, 32768),
            );
            let sent = egress(&mut st, now);
            drop(st);
            assert!(
                sent.iter().any(|p| {
                    let t = Header::parse_whole(p).unwrap().payload(p);
                    u32::from_be_bytes(t[4..8].try_into().unwrap()) == start.wrapping_add(4)
                        && t[((t[12] >> 4) as usize) * 4..].starts_with(b"efgh")
                }),
                "the refused bytes must be retransmitted when the window opens"
            );
            // The FIN follows the data's ACK, so a hole cannot hide it.
            assert!(
                sent.iter()
                    .all(|p| Header::parse_whole(p).unwrap().payload(p)[13] & 1 == 0)
            );
            let end = start.wrapping_add(data.len() as u32);
            let mut st = server.shared.state.lock();
            st.ingress(local.ip(), now, incoming(9, end, 0x10, 32768));
            let sent = egress(&mut st, now);
            assert!(
                sent.iter().any(|p| {
                    let t = Header::parse_whole(p).unwrap().payload(p);
                    t[13] & 1 != 0 && u32::from_be_bytes(t[4..8].try_into().unwrap()) == end
                }),
                "all data was acknowledged, so the FIN must follow"
            );
            st.ingress(
                local.ip(),
                now,
                incoming(9, end.wrapping_add(1), 0x10, 32768),
            );
            assert_eq!(st.get(h).state(), TcpState::Closed);
            drop(st);
            Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }

    /// A listening port holds at most its backlog of connections not
    /// accepted yet. Further SYNs get SYN cookies, until the connections
    /// waiting for accept alone fill the backlog: then SYNs, and ACKs that
    /// return cookies, are dropped until accept takes one.
    #[test]
    fn syns_past_the_backlog_get_cookies_until_accept_falls_behind() {
        assert_eq!(Options::default().backlog, 4096);
        assert_eq!(
            (
                Options::default().backlog(0).backlog,
                Options::default().backlog(1 << 20).backlog
            ),
            (1, MAX_BACKLOG)
        );
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (mut raw, side) = pair();
            let server = endpoint_with(
                &fcx,
                side,
                "10.0.0.1".parse().unwrap(),
                Options::default().backlog(4),
            );
            let mut listener = server.listen(80)?;
            let to: SocketAddr = "10.0.0.1:80".parse().unwrap();
            let from = |port| SocketAddr::new("10.0.0.2".parse().unwrap(), port);
            for port in 1000..1010u16 {
                raw.send(segment(from(port), to, 7, 0, 0x02));
            }
            let mut iss = BTreeMap::new();
            while iss.len() < 10 {
                let p = raw.recv(&fcx).await?;
                let t = Header::parse_whole(&p.0).unwrap().payload(&p.0).to_vec();
                assert_eq!(t[13], 0x12, "a SYN-ACK");
                let port = u16::from_be_bytes([t[2], t[3]]);
                iss.insert(port, u32::from_be_bytes([t[4], t[5], t[6], t[7]]));
            }
            for (&port, &iss) in &iss {
                raw.send(segment(from(port), to, 8, iss.wrapping_add(1), 0x10));
            }
            /// Whether a second passes with nothing from the endpoint.
            async fn quiet(fcx: &Cx, raw: &mut crate::End) -> bool {
                let deadline = fcx.now() + Duration::from_secs(1);
                fcx.race(Some(deadline), raw.recv(fcx)).await.is_err()
            }
            assert!(
                quiet(&fcx, &mut raw).await,
                "cookie ACKs past a full queue are dropped"
            );
            assert_eq!(server.shared.state.lock().listeners[&80].ready.len(), 4);
            raw.send(segment(from(2000), to, 7, 0, 0x02));
            assert!(
                quiet(&fcx, &mut raw).await,
                "a SYN to a full queue is dropped"
            );

            let first = listener.accept(&fcx).await?;
            assert_eq!(first.peer_addr().port(), 1000);
            raw.send(segment(from(1009), to, 8, iss[&1009].wrapping_add(1), 0x10));
            let mut ports = Vec::new();
            for _ in 0..4 {
                ports.push(listener.accept(&fcx).await?.peer_addr().port());
            }
            assert_eq!(ports, [1001, 1002, 1003, 1009]);
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }

    #[test]
    fn spoofed_syns_cannot_block_a_real_peer_cookie_handshake() {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (_raw, side) = pair();
            let local: SocketAddr = "10.0.0.1:80".parse()?;
            let peer = |port| SocketAddr::new("10.0.0.2".parse().unwrap(), port);
            let server = endpoint(&fcx, side, local.ip());
            let mut listener = server.listen(local.port())?;
            let now = smol_now(&fcx);
            {
                let mut st = server.shared.state.lock();
                for port in 1000..1000 + BACKLOG_PER_PEER as u16 {
                    st.ingress(local.ip(), now, segment(peer(port), local, 7, 0, 0x02).0);
                    egress(&mut st, now);
                }
                st.ingress(local.ip(), now, segment(peer(9000), local, 0, 0, 0x02).0);
                let packets = egress(&mut st, now);
                assert_eq!(packets.len(), 1);
                let t = Header::parse_whole(&packets[0]).unwrap().payload(&packets[0]);
                assert_eq!(t[13], 0x12);
                let iss = u32::from_be_bytes(t[4..8].try_into().unwrap());
                assert_eq!(st.listeners[&80].embryonic.len(), BACKLOG_PER_PEER);
                st.ingress(local.ip(), now, segment(peer(9000), local, 1, iss.wrapping_add(1), 0x10).0);
                assert_eq!(st.listeners[&80].ready.len(), 1);
            }
            let accepted = listener.accept(&fcx).await?;
            let handshake = accepted.handshake().unwrap();
            assert_eq!(handshake.origin, HandshakeOrigin::Cookie);
            assert_eq!(handshake.irs, 0);
            assert!(handshake.syn.is_none());
            fcx.cancel();
            Ok(())
        })).unwrap();
    }

    /// A burst of handshakes that the peer resets in SYN-RECEIVED leaves
    /// at most one spare listening socket, not one per SYN.
    #[test]
    fn a_burst_of_reset_handshakes_leaves_no_pool_of_sockets() {
        let result = block_on(run(fictionet::Seed::random(), |fcx| async move {
            let (mut raw, side) = pair();
            let server = endpoint(&fcx, side, "10.0.0.1".parse().unwrap());
            let _listener = server.listen(80)?;
            let to: SocketAddr = "10.0.0.1:80".parse().unwrap();
            for port in 1000..1250u16 {
                raw.send(segment(
                    SocketAddr::new("10.0.0.2".parse().unwrap(), port),
                    to,
                    7,
                    0,
                    0x02,
                ));
            }
            let mut acks = 0;
            while acks < 250 {
                let p = raw.recv(&fcx).await?;
                let ip = Header::parse_whole(&p.0).unwrap();
                let t = ip.payload(&p.0);
                assert_eq!(t[13], 0x12, "a SYN-ACK");
                let port = u16::from_be_bytes([t[2], t[3]]);
                let isn = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
                let from = SocketAddr::new("10.0.0.2".parse().unwrap(), port);
                raw.send(segment(from, to, 8, isn.wrapping_add(1), 0x04));
                acks += 1;
            }
            fcx.sleep(Duration::from_millis(100)).await?;
            let st = server.shared.state.lock();
            let l = &st.listeners[&80];
            assert!(l.embryonic.is_empty() && l.ready.is_empty());
            assert!(
                l.idle.len() <= 1,
                "{} spare listening sockets",
                l.idle.len()
            );
            assert!(st.sockets.iter().count() <= 1);
            drop(st);
            Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }

    /// SYNs from many addresses that never answer the SYN-ACK, as spoofed
    /// ones do, are forgotten once the handshake times out: no connection,
    /// socket or per-peer count is left behind for any of them.
    #[test]
    fn unanswered_syns_from_many_addresses_leave_nothing_behind() {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (mut raw, side) = pair();
            let server = endpoint(&fcx, side, "10.0.0.1".parse().unwrap());
            let _listener = server.listen(80)?;
            let to: SocketAddr = "10.0.0.1:80".parse().unwrap();
            let sources = 1000u32;
            for n in 0..sources {
                let from = std::net::Ipv4Addr::from(0x0b00_0000 + n);
                raw.send(segment(SocketAddr::new(from.into(), 4000), to, 7, 0, 0x02));
            }
            let mut syn_acks = 0;
            while syn_acks < sources {
                let p = raw.recv(&fcx).await?;
                let t = Header::parse_whole(&p.0).unwrap().payload(&p.0).to_vec();
                assert_eq!(t[13], 0x12, "a SYN-ACK");
                syn_acks += 1;
            }
            {
                let st = server.shared.state.lock();
                let l = &st.listeners[&80];
                assert_eq!(l.embryonic.len(), sources as usize);
                assert_eq!(l.per_peer.len(), sources as usize);
            }
            // The SYN-ACKs are sent again, unanswered, until the timeout.
            fcx.spawn(move |fcx| async move { while raw.recv(&fcx).await.is_ok() {} Ok(()) });
            fcx.sleep(TIMEOUT + Duration::from_secs(5)).await?;
            let st = server.shared.state.lock();
            let l = &st.listeners[&80];
            assert!(l.embryonic.is_empty() && l.ready.is_empty());
            assert!(l.per_peer.is_empty(), "{} peers kept", l.per_peer.len());
            assert!(st.conns.is_empty(), "{} connections kept", st.conns.len());
            assert!(st.by_tuple.is_empty());
            assert!(st.handles.len() <= 1, "{} sockets kept", st.handles.len());
            drop(st);
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }

    /// Handshakes wait in the order their SYNs came, and each is dropped
    /// [`HANDSHAKE_TIMEOUT`] after its own SYN; the next one due is the
    /// endpoint's next timer. Housekeeping looks only at those a segment
    /// reached: one completed among many waiting is accepted, and nothing
    /// is left for it to look at once the turn is over.
    #[test]
    fn handshakes_wait_and_expire_in_the_order_they_came() {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (mut raw, side) = pair();
            let server = endpoint(&fcx, side, "10.0.0.1".parse().unwrap());
            let mut listener = server.listen(80)?;
            let to: SocketAddr = "10.0.0.1:80".parse().unwrap();
            let from = |n: u32| SocketAddr::new(std::net::Ipv4Addr::from(0x0b00_0000 + n).into(), 4000);
            let start = fcx.now();
            // Two batches of SYNs, ten seconds apart, each answered.
            let mut isn = HashMap::new();
            for batch in 0..2u32 {
                for n in 0..100 {
                    raw.send(segment(from(batch * 100 + n), to, 7, 0, 0x02));
                }
                while isn.len() < (batch as usize + 1) * 100 {
                    let p = raw.recv(&fcx).await?;
                    let ip = Header::parse_whole(&p.0).unwrap();
                    let t = ip.payload(&p.0);
                    if t[13] == 0x12 {
                        isn.insert(ip.dst, u32::from_be_bytes([t[4], t[5], t[6], t[7]]));
                    }
                }
                if batch == 0 {
                    fcx.sleep(Duration::from_secs(10)).await?;
                }
            }
            let due = |st: &State| {
                let l = &st.listeners[&80];
                let first = l.embryonic.first().unwrap();
                (l.embryonic.len(), first.0, st.touched.len())
            };
            {
                let st = server.shared.state.lock();
                let (waiting, next, touched) = due(&st);
                assert_eq!(waiting, 200);
                assert_eq!(touched, 0, "nothing left to look at");
                assert_eq!(st.next_expiry(), Some(next));
            }
            // One of the second batch completes, among 199 waiting.
            let late = from(150);
            raw.send(segment(late, to, 8, isn[&late.ip()].wrapping_add(1), 0x10));
            let conn = listener.accept(&fcx).await?;
            assert_eq!(conn.peer_addr(), late);
            fcx.spawn(move |fcx| async move { while raw.recv(&fcx).await.is_ok() {} Ok(()) });
            // The first batch goes 63 seconds after its SYNs, the second
            // ten seconds later.
            fcx.sleep_until(start + HANDSHAKE_TIMEOUT + Duration::from_secs(5)).await?;
            {
                let st = server.shared.state.lock();
                let (waiting, _, touched) = due(&st);
                assert_eq!(waiting, 99);
                assert_eq!(touched, 0);
            }
            fcx.sleep_until(start + HANDSHAKE_TIMEOUT + Duration::from_secs(15)).await?;
            let st = server.shared.state.lock();
            assert!(st.listeners[&80].embryonic.is_empty());
            assert_eq!(st.next_expiry(), None);
            drop(st);
            drop(conn);
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }

    /// A SYN from an address that cannot be one host's (unspecified,
    /// multicast or the limited broadcast) gets nothing back, whether the
    /// listener would refuse it or the backlog is full and it would get a
    /// SYN cookie.
    #[test]
    fn syns_from_no_host_s_address_get_nothing() {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (mut raw, side) = pair();
            let server = endpoint_with(
                &fcx,
                side,
                "10.0.0.1".parse().unwrap(),
                Options::default().backlog(1),
            );
            let mut refusing = server.listen(80)?;
            refusing.answer(Box::new(|_: &Syn<'_>| SynAnswer::Refuse(Vec::new())));
            let _cookies = server.listen(81)?;
            let martians = ["0.0.0.0", "224.0.0.1", "239.1.2.3", "255.255.255.255"];
            // The backlog of port 81 is full.
            raw.send(segment("10.0.0.9:4000".parse().unwrap(), "10.0.0.1:81".parse().unwrap(), 7, 0, 0x02));
            let p = raw.recv(&fcx).await?;
            assert_eq!(Header::parse_whole(&p.0).unwrap().payload(&p.0)[13], 0x12);
            for port in [80, 81] {
                let to = SocketAddr::new("10.0.0.1".parse().unwrap(), port);
                for (n, src) in martians.iter().enumerate() {
                    let from = SocketAddr::new(src.parse().unwrap(), 4000 + n as u16);
                    raw.send(segment(from, to, 7, 0, 0x02));
                }
            }
            // Shorter than the second before the first SYN-ACK is sent again.
            let quiet = fcx.race(Some(fcx.now() + Duration::from_millis(500)), raw.recv(&fcx)).await;
            assert!(quiet.is_err(), "an answer: {quiet:?}");
            // A host's address gets the RST and the SYN cookie.
            for port in [80, 81] {
                let to = SocketAddr::new("10.0.0.1".parse().unwrap(), port);
                raw.send(segment("10.0.0.8:4000".parse().unwrap(), to, 7, 0, 0x02));
                let p = raw.recv(&fcx).await?;
                let flags = Header::parse_whole(&p.0).unwrap().payload(&p.0)[13];
                assert_eq!(flags, if port == 80 { 0x14 } else { 0x12 });
            }
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }

    /// After many connections come and go, the socket set is rebuilt
    /// without its empty slots, and a connection that stayed open keeps
    /// working.
    #[test]
    fn the_socket_set_shrinks_after_a_crowd_leaves() {
        let result = block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (a, b) = pair();
            let server = endpoint(&fcx, a, "10.0.0.1".parse().unwrap());
            let client = endpoint(&fcx, b, "10.0.0.2".parse().unwrap());
            let mut listener = server.listen(80)?;
            let mut keep_c = client.connect(&fcx, "10.0.0.1:80".parse().unwrap()).await?;
            let mut keep_s = listener.accept(&fcx).await?;
            let mut crowd = Vec::new();
            for _ in 0..400 {
                let c = client.connect(&fcx, "10.0.0.1:80".parse().unwrap()).await?;
                let s = listener.accept(&fcx).await?;
                crowd.push((c, s));
            }
            assert!(server.shared.state.lock().slots >= 401);
            drop(crowd);
            let deadline = fcx.now() + Duration::from_secs(11);
            while ![&server, &client].iter().all(|e| {
                let st = e.shared.state.lock();
                st.handles.len() <= 3 && st.slots < COMPACT_SLOTS
            }) {
                assert!(fcx.now() < deadline, "closed connections kept socket slots");
                fcx.sleep(Duration::from_millis(5)).await?;
            }
            for e in [&server, &client] {
                let st = e.shared.state.lock();
                assert!(st.handles.len() <= 3, "{} sockets left", st.handles.len());
                // Compacted on the way down: fewer than 256 slots remain,
                // not the 401 it had.
                assert!(st.slots < COMPACT_SLOTS, "{} slots left", st.slots);
                assert_eq!(st.sockets.iter().count(), st.handles.len());
            }
            let size = rounds(1 << 20);
            let data = pattern(size, 9);
            let writer = {
                let data = data.clone();
                fcx.spawn(move |fcx| async move {
                    keep_s.write_all(&fcx, &data).await?;
                    Ok(())
                })
            };
            let mut got = vec![0u8; size];
            let mut at = 0;
            while at < got.len() {
                at += keep_c.read(&fcx, &mut got[at..]).await?;
            }
            writer.join(&fcx).await?;
            assert!(got == data, "the connection that stayed open still works");
            Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }

    /// A connection whose handle is dropped waits for the peer for at most
    /// a minute, not the two minutes of an open one.
    #[test]
    fn a_dropped_connection_waits_a_minute_at_most() {
        let result = block_on(run(fictionet::Seed::random(), |fcx| async move {
            let (a, b) = pair();
            let server = endpoint(&fcx, a, "10.0.0.1".parse().unwrap());
            let client = endpoint(&fcx, b, "10.0.0.2".parse().unwrap());
            let mut listener = server.listen(80)?;
            let _c = client.connect(&fcx, "10.0.0.1:80".parse().unwrap()).await?;
            let s = listener.accept(&fcx).await?;
            let h = s.handle;
            assert_eq!(
                server.shared.state.lock().get(h).timeout(),
                Some(TIMEOUT.into())
            );
            drop(s);
            fcx.sleep(Duration::from_millis(50)).await?;
            let st = server.shared.state.lock();
            assert_eq!(
                st.get(h).state(),
                TcpState::FinWait2,
                "the client never closes its side"
            );
            assert_eq!(st.get(h).timeout(), Some(ORPHAN_TIMEOUT.into()));
            drop(st);
            Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }

    /// A dropped connection whose peer acknowledged its FIN is forgotten a
    /// minute later, though the peer keeps sending ACKs: nothing the peer
    /// sends keeps it in FIN-WAIT-2.
    #[test]
    fn an_orphan_in_fin_wait_2_goes_a_minute_after_whatever_the_peer_sends() {
        let result = block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (mut raw, side) = pair();
            let server = endpoint(&fcx, side, "10.0.0.1".parse().unwrap());
            let mut listener = server.listen(80)?;
            let to: SocketAddr = "10.0.0.1:80".parse().unwrap();
            let peer: SocketAddr = "10.0.0.2:3000".parse().unwrap();
            raw.send(segment(peer, to, 7, 0, 0x02));
            let isn = syn_ack_isn(&mut raw, &fcx, 3000).await;
            raw.send(segment(peer, to, 8, isn.wrapping_add(1), 0x10));
            let conn = listener.accept(&fcx).await?;
            drop(conn);
            loop {
                let p = raw.recv(&fcx).await?;
                let t = Header::parse_whole(&p.0).unwrap().payload(&p.0).to_vec();
                if t[13] & 0x01 != 0 {
                    break;
                }
            }
            let acked = isn.wrapping_add(2);
            raw.send(segment(peer, to, 8, acked, 0x10));
            fcx.sleep(Duration::from_millis(10)).await?;
            let open = |server: &Endpoint| {
                let st = server.shared.state.lock();
                st.conns.values().any(|c| c.remote == peer)
            };
            assert!(open(&server), "FIN-WAIT-2 for now");
            // A bare ACK every 50 seconds, for two and a half minutes.
            for _ in 0..3 {
                fcx.sleep(Duration::from_secs(50)).await?;
                raw.send(segment(peer, to, 8, acked, 0x10));
            }
            fcx.sleep(Duration::from_millis(10)).await?;
            assert!(!open(&server), "forgotten a minute after FIN-WAIT-2");
            // Data now gets a RST: there is no connection.
            raw.send(data_segment(peer, to, 8, acked, 0x18, b"x"));
            let p = raw.recv(&fcx).await?;
            let t = Header::parse_whole(&p.0).unwrap().payload(&p.0).to_vec();
            assert_eq!(t[13] & 0x04, 0x04, "a RST");
            Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }

    /// The SYN-ACK a peer gets for one connection does not depend on what
    /// other connections were opened before it, so the numbers a peer sees
    /// on its own connections tell it nothing about another's. It depends
    /// on the endpoints, the clock and the endpoint's secret.
    #[test]
    fn initial_sequence_numbers_tell_nothing_of_other_connections() {
        let to: SocketAddr = "10.0.0.1:80".parse().unwrap();
        let isn_of = |seed: u64, before: u16, at_secs: u64, peer: SocketAddr| {
            let seen = Arc::new(Mutex::new(None));
            let out = seen.clone();
            let result = block_on(lab(Seed::from_u64(seed), move |fcx| async move {
                let (mut raw, side) = pair();
                let server = endpoint(&fcx, side, to.ip());
                let _listener = server.listen(80)?;
                for port in 0..before {
                    let other = SocketAddr::new(peer.ip(), 40_000 + port);
                    raw.send(segment(other, to, 7, 0, 0x02));
                    syn_ack_isn(&mut raw, &fcx, other.port()).await;
                }
                fcx.sleep_until(Instant::from_since_start(Duration::from_secs(at_secs)))
                    .await?;
                raw.send(segment(peer, to, 7, 0, 0x02));
                *seen.lock() = Some(syn_ack_isn(&mut raw, &fcx, peer.port()).await);
                Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
            }));
            assert_eq!(result.unwrap_err().to_string(), "done");
            out.lock().expect("a SYN-ACK")
        };
        let peer: SocketAddr = "10.0.0.2:3000".parse().unwrap();
        let alone = isn_of(1, 0, 5, peer);
        assert_eq!(isn_of(1, 3, 5, peer), alone, "others' SYNs change nothing");
        // The clock adds one every 4 microseconds.
        assert_eq!(isn_of(1, 0, 6, peer), alone.wrapping_add(250_000));
        // Another address, port or secret gets an unrelated number.
        let other = "10.0.0.3:3000".parse().unwrap();
        assert_ne!(isn_of(1, 0, 5, other), alone);
        assert_ne!(isn_of(1, 0, 5, "10.0.0.2:3001".parse().unwrap()), alone);
        assert_ne!(isn_of(2, 0, 5, peer), alone);
    }

    #[test]
    fn options_set_the_buffers_of_every_connection() {
        assert_eq!(Options::default().buffer(1).buffer, MIN_BUFFER);
        assert_eq!(Options::default().buffer(usize::MAX).buffer, MAX_BUFFER);
        for size in [MIN_BUFFER, 1 << 20] {
            let result = block_on(run(fictionet::Seed::random(), move |fcx| async move {
                let (a, b) = pair();
                let options = Options::default().buffer(size);
                let server = endpoint_with(&fcx, a, "10.0.0.1".parse().unwrap(), options);
                let client = endpoint_with(&fcx, b, "10.0.0.2".parse().unwrap(), options);
                let mut listener = server.listen(80)?;
                let mut c = client.connect(&fcx, "10.0.0.1:80".parse().unwrap()).await?;
                let mut s = listener.accept(&fcx).await?;
                for (ep, h) in [(&server, s.handle), (&client, c.handle)] {
                    let st = ep.shared.state.lock();
                    assert_eq!(st.get(h).recv_capacity(), size);
                    assert_eq!(st.get(h).send_capacity(), size);
                }
                // 3 MiB arrive unchanged, through buffers smaller and larger
                // than the default.
                let data = pattern(3 << 20, 7);
                let sent = data.clone();
                let writer =
                    fcx.spawn(move |fcx| async move { Ok(s.write_all(&fcx, &sent).await?) });
                let mut got = vec![0u8; data.len()];
                let mut at = 0;
                while at < got.len() {
                    at += c.read(&fcx, &mut got[at..]).await?;
                }
                assert!(
                    got == data,
                    "the data came through unchanged with {size}-byte buffers"
                );
                writer.join(&fcx).await?;
                Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
            }));
            assert_eq!(result.unwrap_err().to_string(), "done");
        }
    }

    #[test]
    fn quiet_connections_give_their_buffer_pages_back() {
        let result = block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (a, b) = pair();
            let server = endpoint(&fcx, a, "10.0.0.1".parse().unwrap());
            let client = endpoint(&fcx, b, "10.0.0.2".parse().unwrap());
            let mut listener = server.listen(80)?;
            let mut c = client.connect(&fcx, "10.0.0.1:80".parse().unwrap()).await?;
            let mut s = listener.accept(&fcx).await?;
            // A fresh connection costs (almost) no pages.
            assert!(resident(&server) <= 4, "{}", resident(&server));

            let size = rounds(1 << 20);
            for round in 0..2u8 {
                // Transfers in both directions fill the 256 KiB buffers.
                let down = pattern(size, round);
                let up = pattern(size, round + 100);
                let slot = Arc::new(Mutex::new(None));
                let writer = {
                    let (down, slot) = (down.clone(), slot.clone());
                    fcx.spawn(move |fcx| async move {
                        s.write_all(&fcx, &down).await?;
                        let mut got = vec![0u8; size];
                        let mut at = 0;
                        while at < got.len() {
                            at += s.read(&fcx, &mut got[at..]).await?;
                        }
                        *slot.lock() = Some((s, got));
                        Ok(())
                    })
                };
                let mut got = vec![0u8; size];
                let mut at = 0;
                while at < got.len() {
                    at += c.read(&fcx, &mut got[at..]).await?;
                }
                assert!(
                    got == down,
                    "the download came through unchanged in round {round}"
                );
                c.write_all(&fcx, &up).await?;
                writer.join(&fcx).await?;
                let (back, got_up) = slot.lock().take().unwrap();
                s = back;
                assert!(
                    got_up == up,
                    "the upload came through unchanged in round {round}"
                );
                // Both sides wrote whole buffers.
                assert!(resident(&server) >= 64, "{}", resident(&server));
                // Once the connection is quiet, its pages go back, while it
                // stays open.
                let deadline = fcx.now() + 3 * RELEASE_EVERY;
                while resident(&server) != 0 || resident(&client) != 0 {
                    assert!(
                        fcx.now() < deadline,
                        "quiet connections kept buffer pages: server {}, client {}",
                        resident(&server),
                        resident(&client)
                    );
                    fcx.sleep(Duration::from_millis(50)).await?;
                }
                assert_eq!(resident(&server), 0);
                assert_eq!(resident(&client), 0);
            }
            drop((c, s));
            // Err ends the run, and with it the endpoints' drivers.
            Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }

    async fn syn_ack_isn(raw: &mut fictionet::End, fcx: &Cx, port: u16) -> u32 {
        loop {
            let p = raw.recv(fcx).await.unwrap();
            let t = Header::parse_whole(&p.0).unwrap().payload(&p.0).to_vec();
            if t[13] == 0x12 && u16::from_be_bytes([t[2], t[3]]) == port {
                return u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
            }
        }
    }

    #[test]
    fn retransmitted_syn_reuses_the_existing_socket() {
        let result = block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (mut raw, side) = pair();
            let server = endpoint(&fcx, side, "10.0.0.1".parse().unwrap());
            let _listener = server.listen(80)?;
            let to: SocketAddr = "10.0.0.1:80".parse().unwrap();
            let p1: SocketAddr = "10.0.0.2:1000".parse().unwrap();
            let p2: SocketAddr = "10.0.0.2:2000".parse().unwrap();
            raw.send(segment(p1, to, 7, 0, 0x02));
            let isn1 = syn_ack_isn(&mut raw, &fcx, 1000).await;
            raw.send(segment(p2, to, 7, 0, 0x02));
            let _isn2 = syn_ack_isn(&mut raw, &fcx, 2000).await;
            // Reset the first handshake: its socket goes back to LISTEN and
            // becomes the spare.
            raw.send(segment(p1, to, 8, isn1.wrapping_add(1), 0x04));
            fcx.sleep(Duration::from_millis(100)).await?;
            // The peer retransmits its SYN for p2.
            raw.send(segment(p2, to, 7, 0, 0x02));
            fcx.sleep(Duration::from_millis(100)).await?;
            let st = server.shared.state.lock();
            let for_p2 = st.conns.values().filter(|c| c.remote == p2).count();
            drop(st);
            assert_eq!(for_p2, 1, "one socket per tuple");
            Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }

    #[test]
    fn out_of_window_rst_keeps_the_connection_open() {
        let result = block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (mut raw, side) = pair();
            let server = endpoint(&fcx, side, "10.0.0.1".parse().unwrap());
            let mut listener = server.listen(80)?;
            let to: SocketAddr = "10.0.0.1:80".parse().unwrap();
            let peer: SocketAddr = "10.0.0.2:3000".parse().unwrap();
            raw.send(segment(peer, to, 7, 0, 0x02));
            let isn = syn_ack_isn(&mut raw, &fcx, 3000).await;
            raw.send(segment(peer, to, 8, isn.wrapping_add(1), 0x10));
            let conn = listener.accept(&fcx).await?;
            // A RST far outside the receive window.
            raw.send(segment(peer, to, 8u32.wrapping_add(0x4000_0000), 0, 0x04));
            fcx.sleep(Duration::from_millis(50)).await?;
            let gone = std::future::poll_fn(|cx| Poll::Ready(conn.poll_gone(cx).is_ready())).await;
            let state = {
                let st = server.shared.state.lock();
                st.get(conn.handle).state()
            };
            assert_eq!(state, TcpState::Established);
            assert!(!gone, "an out-of-window RST was taken as a reset");
            Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }
    #[test]
    fn rejected_fin_does_not_mark_the_receive_side_closed() {
        let result = block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (mut raw, side) = pair();
            let server = endpoint(&fcx, side, "10.0.0.1".parse()?);
            let mut listener = server.listen(80)?;
            let to: SocketAddr = "10.0.0.1:80".parse()?;
            let peer: SocketAddr = "10.0.0.2:3000".parse()?;
            raw.send(segment(peer, to, 7, 0, 0x02));
            let isn = syn_ack_isn(&mut raw, &fcx, 3000).await;
            raw.send(segment(peer, to, 8, isn.wrapping_add(1), 0x10));
            let conn = listener.accept(&fcx).await?;
            raw.send(segment(
                peer,
                to,
                8u32.wrapping_add(0x4000_0000),
                isn.wrapping_add(1),
                0x11,
            ));
            fcx.sleep(Duration::from_millis(50)).await?;
            let (state, fin) = {
                let st = server.shared.state.lock();
                let state = st.get(conn.handle).state();
                let c = &st.conns[&conn.handle];
                (state, c.fin)
            };
            assert_eq!(state, TcpState::Established);
            assert!(!fin);
            Err::<(), fictionet::Error>(fictionet::Error::msg("done"))
        }));
        assert_eq!(result.unwrap_err().to_string(), "done");
    }

    /// The SYN-ACK `local` sent to `peer`, by its sequence number.
    fn syn_ack_to(packets: &[Vec<u8>], peer: SocketAddr) -> u32 {
        packets
            .iter()
            .find_map(|p| {
                let ip = Header::parse_whole(p).unwrap();
                let t = ip.payload(p);
                let to = SocketAddr::new(ip.dst, u16::from_be_bytes([t[2], t[3]]));
                (to == peer && t[13] == 0x12).then(|| u32::from_be_bytes(t[4..8].try_into().unwrap()))
            })
            .expect("a SYN-ACK to the peer")
    }

    #[test]
    fn a_handshake_reset_in_one_batch_does_not_lend_its_socket_to_another_peer() {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (_raw, side) = pair();
            let local: SocketAddr = "10.0.0.1:80".parse()?;
            let first: SocketAddr = "10.0.0.2:1000".parse()?;
            let second: SocketAddr = "10.0.0.3:2000".parse()?;
            let ep = endpoint(&fcx, side, local.ip());
            let _listener = ep.listen(local.port())?;
            let now = smol_now(&fcx);
            let mut st = ep.shared.state.lock();
            // One batch: housekeeping runs only after all three packets.
            st.ingress(local.ip(), now, segment(first, local, 100, 0, 0x02).0);
            st.ingress(local.ip(), now, segment(first, local, 101, 0, 0x04).0);
            st.ingress(local.ip(), now, segment(second, local, 500, 0, 0x02).0);
            let isn = syn_ack_to(&egress(&mut st, now), second);
            st.ingress(local.ip(), now, segment(second, local, 501, isn.wrapping_add(1), 0x10).0);
            st.housekeeping();
            for (&h, c) in &st.conns {
                if let Some(remote) = st.get(h).remote_endpoint() {
                    assert_eq!(c.remote, SocketAddr::from(remote), "the peer its socket talks to");
                }
            }
            let l = &st.listeners[&80];
            let h = *l.ready.front().expect("the second peer's connection is ready");
            assert_eq!(st.conns[&h].remote, second);
            assert_eq!(st.by_tuple.get(&(local, second)), Some(&h));
            assert_eq!(l.per_peer.get(&second.ip()), Some(&1));
            assert_eq!(l.per_peer.get(&first.ip()), None);
            drop(st);
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }

    #[test]
    fn a_handshake_restarted_in_one_batch_is_not_reported_reset() {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (_raw, side) = pair();
            let local: SocketAddr = "10.0.0.1:80".parse()?;
            let peer: SocketAddr = "10.0.0.2:1000".parse()?;
            let ep = endpoint(&fcx, side, local.ip());
            let _listener = ep.listen(local.port())?;
            let now = smol_now(&fcx);
            let mut st = ep.shared.state.lock();
            // The peer resets its handshake and starts again, in one batch.
            st.ingress(local.ip(), now, segment(peer, local, 100, 0, 0x02).0);
            st.ingress(local.ip(), now, segment(peer, local, 101, 0, 0x04).0);
            st.ingress(local.ip(), now, segment(peer, local, 300, 0, 0x02).0);
            let isn = syn_ack_to(&egress(&mut st, now), peer);
            st.ingress(local.ip(), now, segment(peer, local, 301, isn.wrapping_add(1), 0x10).0);
            st.housekeeping();
            let h = *st.listeners[&80].ready.front().expect("the new handshake finished");
            assert_eq!(st.get(h).state(), TcpState::Established);
            drop(st);
            let watch = GoneWatch { shared: ep.shared.clone(), handle: h };
            assert!(
                watch.poll_gone(&mut Context::from_waker(Waker::noop())).is_pending(),
                "an established connection is not gone"
            );
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }

    #[test]
    fn bytes_after_the_peers_fin_are_not_read() {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (_raw, side) = pair();
            let local: SocketAddr = "10.0.0.1:80".parse()?;
            let peer: SocketAddr = "10.0.0.2:1234".parse()?;
            let ep = endpoint(&fcx, side, local.ip());
            let _listener = ep.listen(local.port())?;
            let now = smol_now(&fcx);
            let mut st = ep.shared.state.lock();
            let (h, ack) = established(&mut st, now, local, peer);
            st.ingress(local.ip(), now, segment(peer, local, 101, ack, 0x11).0);
            assert_eq!(st.get(h).state(), TcpState::CloseWait);
            egress(&mut st, now);
            let mut buf = [0; 8];
            assert_eq!(st.sock(h).recv_slice(&mut buf), Err(stcp::RecvError::Finished));
            // The peer sends more after its FIN, next in sequence.
            let mut late = segment(peer, local, 102, ack, 0x18).0;
            late.extend_from_slice(b"late");
            fix_lengths(&mut late, 20, peer.ip(), local.ip());
            st.ingress(local.ip(), now, late);
            assert_eq!(st.get(h).recv_queue(), 0, "bytes after the FIN entered the stream");
            assert_eq!(st.sock(h).recv_slice(&mut buf), Err(stcp::RecvError::Finished));
            drop(st);
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }

    #[test]
    fn closing_in_syn_received_waits_for_the_fin_to_be_acknowledged() {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (_raw, side) = pair();
            let local: SocketAddr = "10.0.0.1:49152".parse()?;
            let peer: SocketAddr = "10.0.0.2:80".parse()?;
            let ep = endpoint(&fcx, side, local.ip());
            let now = smol_now(&fcx);
            let mut st = ep.shared.state.lock();
            let mut s = new_socket(MIN_BUFFER);
            s.0.connect(st.iface.context(), peer, local).unwrap();
            let h = st.add_socket(s);
            st.conns.insert(h, Conn::new(local, peer, Side::Client));
            st.by_tuple.insert((local, peer), h);
            egress(&mut st, now);
            let iss = st.conns[&h].iss.unwrap();
            // Simultaneous open: the peer's own SYN crosses ours.
            st.ingress(local.ip(), now, segment(peer, local, 7, 0, 0x02).0);
            assert_eq!(st.get(h).state(), TcpState::SynReceived);
            egress(&mut st, now);
            // The connect is abandoned, which drops its connection.
            st.orphan(h, false);
            assert_eq!(st.get(h).state(), TcpState::FinWait1);
            assert!(egress(&mut st, now).iter().all(|p| {
                Header::parse_whole(p).unwrap().payload(p)[13] & 1 == 0
            }));
            // The peer acknowledges our SYN, not a FIN it never saw.
            st.ingress(local.ip(), now, segment(peer, local, 8, iss.wrapping_add(1), 0x10).0);
            assert_eq!(st.get(h).state(), TcpState::FinWait1, "only our SYN was acknowledged");
            let sent = egress(&mut st, now);
            assert!(
                sent.iter().any(|p| {
                    let t = Header::parse_whole(p).unwrap().payload(p);
                    t[13] & 1 != 0
                        && u32::from_be_bytes(t[4..8].try_into().unwrap()) == iss.wrapping_add(1)
                }),
                "the FIN follows the SYN"
            );
            drop(st);
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }

    #[test]
    fn a_reused_listening_socket_forgets_the_previous_peers_mss() {
        block_on(lab(Seed::from_u64(1), |fcx| async move {
            let (_raw, side) = pair();
            let local: SocketAddr = "10.0.0.1:80".parse()?;
            let first: SocketAddr = "10.0.0.2:1000".parse()?;
            let second: SocketAddr = "10.0.0.3:2000".parse()?;
            let ep = endpoint(&fcx, side, local.ip());
            let _listener = ep.listen(local.port())?;
            let now = smol_now(&fcx);
            let mut st = ep.shared.state.lock();
            // The first peer offers a 1460-byte MSS, then resets its handshake.
            let mut syn = segment(first, local, 100, 0, 0x02).0;
            syn[32] = 6 << 4;
            syn.extend_from_slice(&[2, 4, 0x05, 0xb4]);
            fix_lengths(&mut syn, 20, first.ip(), local.ip());
            st.ingress(local.ip(), now, syn);
            egress(&mut st, now);
            st.ingress(local.ip(), now, segment(first, local, 101, 0, 0x04).0);
            st.housekeeping();
            let spare = st.listeners[&80].idle.clone();
            assert_eq!(spare.len(), 1, "the reset socket is the spare");
            // The second peer sends no MSS option: RFC 9293 says 536 then.
            st.ingress(local.ip(), now, segment(second, local, 500, 0, 0x02).0);
            let isn = syn_ack_to(&egress(&mut st, now), second);
            st.ingress(local.ip(), now, segment(second, local, 501, isn.wrapping_add(1), 0x10).0);
            st.housekeeping();
            let h = *st.listeners[&80].ready.front().expect("the second connection");
            assert_eq!(h, spare[0], "the spare socket served the second peer");
            assert_eq!(st.sock(h).send_slice(&[0x5a; 2000]).unwrap(), 2000);
            let sent = egress(&mut st, now);
            let largest = sent
                .iter()
                .map(|p| {
                    let t = Header::parse_whole(p).unwrap().payload(p);
                    t.len() - ((t[12] >> 4) as usize) * 4
                })
                .max()
                .unwrap();
            assert!(largest > 0);
            assert!(largest <= 536, "sent a {largest}-byte segment to a peer that offered no MSS");
            drop(st);
            fcx.cancel();
            Ok(())
        }))
        .unwrap();
    }
}

}
