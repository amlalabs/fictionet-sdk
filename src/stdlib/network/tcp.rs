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
//! The protocol itself is [`TcpLayer`], a
//! [layer](fictionet::stdlib::layer) with whole IP packets below and one
//! byte-stream child per connection above, which runs the smoltcp TCP
//! stack with no I/O of its own. An endpoint is one background task that
//! feeds it packets and sends what it gives back, and its listeners and
//! connections send it commands and read the events it gives up. The
//! interface an endpoint takes comes from
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
use fictionet::stdlib::layer::{
    Admit, Budget, ByteStream, Child, ChildId, Chunk, Datagram, Driver, Env, Layer, MessageCommand,
    MessageEvent, Messages, MuxCommand, MuxEvent, Observe, PacketCommand, PacketEvent,
    StreamCommand, StreamEvent,
};
use fictionet::stdlib::network::ip::{
    Header, Ipv4Option, Ipv4Reply, checksum, encode_ipv4_options, ipv4_options,
    protocol::{ICMP, TCP},
    transport_checksum,
};
use fictionet::stdlib::network::packet::{Ingress, IpLayer, IpPacket, IpReport};
use fictionet::stdlib::network::transport::{
    Request, TcpControl, TcpNotice, TcpOpening, TcpOrigin,
};
use fictionet::stdlib::network::{ConnError, Connection};
use fictionet::time::{Duration, Instant};
use fictionet::{Cx, Entropy, Error, Interface, Packet};

mod engine;

pub use engine::TcpLayer;
use engine::Verdict;

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
/// Idle connections send a keepalive this often, so a peer that is gone is
/// noticed within `TIMEOUT`.
const KEEPALIVE: Duration = Duration::from_secs(45);
/// Connections per port that have arrived but not been accepted yet,
/// unless [`Options::backlog`] says otherwise. Further attempts use the
/// configured cookie codec, when present.
const BACKLOG: usize = 4096;
/// The largest backlog [`Options::backlog`] allows.
const MAX_BACKLOG: usize = 65_536;
/// Of those, at most this many from one peer address. More attempts from
/// that address use the configured cookie codec, or are dropped. A peer
/// whose address cannot be spoofed always has further attempts dropped.
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
    /// a Length its RFC does not define: the bytes
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

/// An option's decoded value and its original wire bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OptionRead<'a> {
    /// A complete option, including its Kind and Length bytes when present.
    Option {
        /// The original bytes, without re-encoding or normalization.
        bytes: &'a [u8],
        /// The decoded option. Known kinds with unsupported lengths are unknown.
        value: TcpOption,
    },
    /// End of Option List, followed by uninterpreted header padding.
    End {
        /// The one-byte End of Option List marker.
        bytes: &'a [u8],
        /// Every remaining byte in the option area.
        padding: &'a [u8],
    },
    /// A missing or invalid length, ending the walk.
    Malformed {
        /// The malformed option and every byte after it.
        bytes: &'a [u8],
    },
}

/// Reads a TCP header's option area, preserving every original byte.
/// Stops after End of Option List or the first malformed option. The same
/// parser reads the options used by the TCP endpoint and [`options`].
pub fn read_options(mut bytes: &[u8]) -> impl Iterator<Item = OptionRead<'_>> {
    std::iter::from_fn(move || {
        if bytes.is_empty() {
            return None;
        }
        let original = bytes;
        Some(match WireOption::parse(original) {
            Ok((remaining, option)) => {
                let consumed = &original[..original.len() - remaining.len()];
                match TcpOption::from_wire(option) {
                    Some(value) => {
                        bytes = remaining;
                        OptionRead::Option {
                            bytes: consumed,
                            value,
                        }
                    }
                    None => {
                        bytes = &[];
                        OptionRead::End {
                            bytes: consumed,
                            padding: remaining,
                        }
                    }
                }
            }
            Err(_) => {
                bytes = &[];
                OptionRead::Malformed { bytes: original }
            }
        })
    })
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
    /// IPv4 options on the first SYN; absent for IPv6 or an unretained cookie.
    pub syn_ipv4: Option<Arc<[Ipv4Option]>>,
    /// IPv4 options selected for its SYN-ACK, before wire padding.
    pub syn_ack_ipv4: Option<Arc<[Ipv4Option]>>,
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
    /// IPv4 options in wire order; empty for IPv6.
    pub ipv4_options: &'a [Ipv4Option],
    /// The listener address and port.
    pub to: SocketAddr,
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
    /// Retained IPv4 SYN options, or none for IPv6 or missing state.
    pub syn_ipv4: Option<Arc<[Ipv4Option]>>,
    /// Retained IPv4 SYN-ACK options, or none for IPv6 or missing state.
    pub syn_ack_ipv4: Option<Arc<[Ipv4Option]>>,
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
    /// as requested by the listener. The connection never reaches `accept`.
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
    /// backlog a configured codec can issue a SYN cookie without keeping state (see
    /// [`Options::backlog`]), so each copy of the SYN asks again, and an
    /// answer that draws something new, such as a key, gives each copy a
    /// different one.
    fn syn(&self, syn: &Syn<'_>) -> SynAnswer;

    /// IPv4 options and an optional source-route hop for an accepted SYN-ACK.
    /// Called only for IPv4, after `syn` accepts. Retransmissions of a retained
    /// SYN use the original reply unless [`Self::retransmit_ipv4_options`]
    /// refreshes it. `None` drops the SYN without an answer.
    /// The default sends no IPv4 options.
    fn ipv4_options(&self, syn: &Syn<'_>) -> Option<Ipv4Reply> {
        let _ = syn;
        Some(Ipv4Reply::default())
    }

    /// Refreshes IPv4 options when a retained SYN-ACK is sent again, whether
    /// prompted by another SYN or by its retransmission timer. The handshake
    /// retains the first SYN and first reply; this changes only the emitted
    /// options, not the source-route next hop. `None` or options that cannot
    /// be encoded leave the original reply unchanged. The default retains it.
    fn retransmit_ipv4_options(&self, handshake: &Handshake) -> Option<Vec<Ipv4Option>> {
        let _ = handshake;
        None
    }

    /// What the SYN and SYN-ACK of `handshake`, answered with a SYN cookie,
    /// carried, if this listener kept that itself when it answered the SYN,
    /// such as MP_JOIN authentication state (RFC 8684 section 3.2). Asked
    /// once, when the ACK that returns the cookie arrives from `from`, before
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

/// Stateless handshake input. The key belongs to this endpoint only.
pub struct CookieInput<'a> {
    /// Endpoint secret, independent of initial sequence numbers.
    pub key: &'a [u8; 32],
    /// Local address and port.
    pub local: SocketAddr,
    /// Remote address and port.
    pub remote: SocketAddr,
    /// Initial remote sequence number.
    pub sequence: u32,
    /// Time since the world started.
    pub now: Duration,
    /// Options from the incoming segment.
    pub options: &'a [TcpOption],
    /// Whether the SYN requested ECN negotiation.
    pub ecn: bool,
}

/// Options recovered from a validated SYN cookie.
#[derive(Clone, Copy, Debug)]
pub struct CookieState {
    /// Remote maximum segment size.
    pub mss: u16,
    /// Remote receive window scale.
    pub scale: Option<u8>,
    /// Whether selective acknowledgments were negotiated.
    pub sack: bool,
    /// Whether ECN was negotiated.
    pub ecn: bool,
    /// Local timestamp offset and latest remote timestamp.
    pub timestamp: Option<(u32, u32)>,
}

/// A stateless SYN-ACK produced by a world's cookie codec.
pub struct CookieReply {
    /// Authenticated initial sequence number.
    pub sequence: u32,
    /// Options after MSS, including any codec-specific padding.
    pub options: Vec<TcpOption>,
    /// Whether to acknowledge an ECN request in the SYN-ACK.
    pub ecn: bool,
}

/// Encoding and validation of stateless handshakes (RFC 4987).
/// Implementations must authenticate the tuple, sequence and expiry.
pub trait SynCookies: Send + Sync + std::fmt::Debug {
    /// Issues a sequence number, options after MSS, and ECN negotiation.
    fn issue(&self, input: &CookieInput<'_>) -> CookieReply;
    /// Validates a returned sequence number and recovers negotiated options.
    fn validate(&self, input: &CookieInput<'_>, cookie: u32) -> Option<CookieState>;
}

/// What answers a segment for a port with no listener and no connection:
/// [`Settings::closed_port`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClosedPort {
    /// A RST, as RFC 9293 section 3.10.7.1 says of the CLOSED state. A
    /// segment that is itself a RST gets nothing. The default.
    #[default]
    Reset,
    /// Nothing. The segment is dropped, as a host behind a firewall that
    /// drops rather than rejects looks from outside.
    Silent,
}

/// What a SYN from source port 0 gets: [`Settings::source_port_zero`].
/// Port 0 is reserved (RFC 6335), but TCP itself gives it no meaning, so
/// stacks differ.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SourcePortZero {
    /// The same as a SYN from any other port: it is matched against the
    /// listeners, and a connection it makes goes to `accept`. The default.
    #[default]
    Accept,
    /// Nothing. The SYN is dropped before any listener is looked for, so
    /// neither a SYN-ACK nor a RST goes back.
    Drop,
    /// The handshake runs to the end, and the connection is then closed as
    /// an application that found no usable peer address would close it:
    /// with a FIN, or a RST if the last ACK carried data. It never reaches
    /// `accept`. A SYN for a port with no listener still gets what
    /// [`Settings::closed_port`] says.
    CloseAfterHandshake,
}

/// Transport choices for an endpoint. Core defaults use the buffer window,
/// compact options, and a four minute TIME-WAIT (RFC 9293).
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    /// Socket window, option layout, TIME-WAIT and handshake choices.
    pub socket: SocketSettings,
    /// Stateless handshake codec. With none, a full SYN queue drops new SYNs.
    pub cookies: Option<&'static dyn SynCookies>,
    /// Optional pending connection limit for each peer address on a port.
    /// `None` uses only the port's total backlog limit.
    pub backlog_per_peer: Option<usize>,
    /// Whether an ECN-capable SYN may negotiate ECN, given its IP ECN bits
    /// and TCP reserved bits.
    pub ecn_syn: fn(u8, u8) -> bool,
    /// Initial identification for each IPv4 socket; subsequent packets
    /// increment it. With none, packets use identification zero.
    pub ipv4_id: Option<fn(&dyn Entropy) -> u16>,
    /// Timestamp offset derived from the endpoint secret and address pair.
    pub timestamp_offset: Option<TimestampOffset>,
    /// Timestamp clock; the configured address-pair offset is added separately.
    pub timestamp_clock: Option<smoltcp::wire::TcpTimestampGenerator>,
    /// Time without a peer response before giving up a connection.
    pub timeout: Option<Duration>,
    /// Idle interval before sending keepalive probes; `None` disables them.
    pub keep_alive: Option<Duration>,
    /// How long an incomplete handshake may occupy the backlog.
    pub handshake_timeout: Duration,
    /// How long a detached connection may remain in FIN-WAIT-2.
    pub orphan_timeout: Duration,
    /// Answer a SYN with a reset when the accept queue is full.
    pub reset_full_queue: bool,
    /// Accept the valid prefix of a malformed option list. Otherwise, answer
    /// illegal option lengths with a reset, as suggested by RFC 9293 section 3.1.
    pub ignore_malformed_options: bool,
    /// What answers a segment for a port with no listener and no
    /// connection. Default a RST.
    pub closed_port: ClosedPort,
    /// What a SYN from source port 0 gets. Default the same as any other.
    pub source_port_zero: SourcePortZero,
}

/// Derives a timestamp offset from an endpoint secret and its local and
/// remote addresses, in that order.
pub type TimestampOffset = fn(&[u8; 32], IpAddr, IpAddr) -> u32;

impl Default for Settings {
    fn default() -> Self {
        Self {
            socket: SocketSettings::default(),
            cookies: None,
            backlog_per_peer: Some(BACKLOG_PER_PEER),
            ecn_syn: |_, _| true,
            ipv4_id: None,
            timestamp_offset: None,
            timestamp_clock: Some(|now| (now.total_micros() / 1000) as u32),
            timeout: Some(TIMEOUT),
            keep_alive: Some(KEEPALIVE),
            handshake_timeout: TIMEOUT,
            orphan_timeout: TIMEOUT,
            reset_full_queue: false,
            ignore_malformed_options: false,
            closed_port: ClosedPort::Reset,
            source_port_zero: SourcePortZero::Accept,
        }
    }
}

/// TCP socket settings and option layout, independent of an operating system.
pub use smoltcp::socket::tcp::{KeepAlivePayload, Settings as SocketSettings};
pub use smoltcp::wire::{OptionLayout, OptionOrder};

/// Starts TCP for a machine with address `addr`, on the TCP packets of
/// `inner`.
///
/// Starts a background task and returns immediately with an [`Endpoint`].
/// The task takes TCP packets sent to `addr` and drops the rest. A
/// connection attempt to a port with no listener gets a RST, because that
/// is part of TCP's job; [`Settings::closed_port`] can make it silent
/// instead, and [`Settings::source_port_zero`] says what a SYN from port 0
/// gets. Everything it sends goes into `inner`.
///
/// The task stops when the caller's [region](fictionet::Cx#regions) is
/// cancelled or `inner` closes. The endpoint's listeners and connections
/// then fail with [`ConnError::Closed`].
///
/// Each connection has 256 KiB buffers each way, a 1,500-byte MTU, no
/// Nagle delay, and Reno congestion control. Each listening port holds up
/// to the default [`backlog`](Options::backlog) of connections not yet
/// accepted, including handshakes. Further SYNs are dropped unless a world
/// supplies [`Settings::cookies`]. Incomplete handshakes expire after
/// [`Settings::handshake_timeout`]. [`endpoint_with`] takes other settings,
/// buffer sizes and backlogs, subject to the maximum and
/// per-peer limits described in [`Options::backlog`]. Buffer memory is used only
/// as data passes through: once a connection's buffers are empty, their
/// pages go back to the system within about two seconds, though the
/// connection stays open, and closing frees them. A connection gives up with
/// [`ConnError::TimedOut`] when the peer has not answered for two minutes:
/// a SYN, data that is not acknowledged, or a keepalive (sent after 45
/// seconds of quiet). A connection whose handle was dropped finishes
/// closing in the background, and is given up when the peer has sent
/// nothing for [`Settings::orphan_timeout`]. Once the peer acknowledges its
/// FIN, that same limit bounds FIN-WAIT-2, regardless of later ACKs. ICMPv4
/// destination-unreachable messages can fail a pending connect; see
/// [`Endpoint::connect`]. Other ICMP messages are dropped. Established
/// connections ignore ICMP, and there is no path MTU discovery.
///
/// A dropped connection that reaches TIME-WAIT releases items kept with
/// [`TcpConnection::hold_until_gone`], including connection counts, and
/// makes its [`GoneWatch`] ready. Only transport recovery state stays:
/// its socket, tuple, buffers and outgoing port remain until smoltcp's
/// configured TIME-WAIT timer expires. Retransmitted FINs get ACKs and
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
#[derive(Clone, Copy, Debug)]
pub struct Options {
    settings: Settings,
    buffer: usize,
    backlog: usize,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            settings: Settings::default(),
            buffer: BUFFER,
            backlog: BACKLOG,
        }
    }
}

impl Options {
    /// Uses transport choices supplied by the world.
    pub fn settings(self, settings: Settings) -> Self {
        Self { settings, ..self }
    }

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
    /// limits. By default at most 256 attempts from one peer address keep
    /// handshake state; [`Settings::backlog_per_peer`] changes that limit.
    /// A configured cookie codec can answer
    /// further SYNs without allocating connection state.
    ///
    /// Past the backlog, a SYN is dropped unless [`Settings::cookies`]
    /// supplies a stateless handshake codec (RFC 4987 section 3.6).
    /// The codec determines which negotiated options survive. When the
    /// accept queue is full, [`Settings::reset_full_queue`] selects whether
    /// a new SYN gets a reset; otherwise it is dropped.
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
    let tcp = TcpLayer::new(addr, options, fcx, fcx.now());
    let entropy: Arc<dyn Entropy> = Arc::new(fcx.clone());
    let shared = Arc::new(Shared {
        addr,
        state: Mutex::new(Host {
            fcx: fcx.clone(),
            ip: IpLayer::host(),
            held: None,
            tcp: Driver::new(tcp, entropy, Budget::unlimited(), fcx.now()),
            budget: Budget::unlimited(),
            routes: Routes::default(),
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

/// A command for the engine.
type Command = MuxCommand<ByteStream, Messages<TcpNotice, TcpControl>>;
/// An event from the engine.
type Event = MuxEvent<ByteStream, Messages<TcpNotice, TcpControl>, TcpOpening>;

/// One machine's TCP behind its handles.
struct Shared {
    addr: IpAddr,
    state: Mutex<Host>,
}

/// The engine, the IP layer that reads the packets it takes, and what the
/// handles wait for. The endpoint's task feeds packets through it; the
/// handles send it commands. Neither touches a socket.
struct Host {
    /// The endpoint's context: its clock and its entropy.
    fcx: Cx,
    /// Reads raw packets into whole, checked ones.
    ip: IpLayer,
    /// A packet the IP layer read that the engine had no room for yet.
    held: Option<IpPacket>,
    tcp: Driver<TcpLayer>,
    budget: Budget,
    routes: Routes,
}

/// What the handles wait for, and where the engine's events go.
#[derive(Default)]
struct Routes {
    stopped: bool,
    /// The endpoint's task, woken when a handle has work for it.
    driver: Option<Waker>,
    /// Each child a handle has, or will have once accepted.
    links: BTreeMap<ChildId, Link>,
    listeners: BTreeMap<u16, Accepting>,
    /// What waits for each connection to be gone: [`GoneWatch`].
    watches: BTreeMap<ChildId, Vec<Waker>>,
    /// The child of each connect still under way.
    requests: HashMap<Request, ChildId>,
    /// Connects that failed, until their caller looks.
    failed: HashMap<Request, ConnError>,
    next_request: u64,
    /// What the last listen got.
    listening: Option<TcpNotice>,
    refused: Option<Arc<dyn Fn(SocketAddr, SocketAddr) + Send + Sync>>,
    refusals: Vec<(SocketAddr, SocketAddr)>,
    /// Children accepted for a listener that is gone, to be reset.
    strays: Vec<Child>,
}

/// One connection a handle has.
struct Link {
    child: Child,
    local: SocketAddr,
    remote: SocketAddr,
    handshake: Option<Handshake>,
    /// Bytes that came up and were not read yet.
    inbox: VecDeque<Chunk>,
    /// Bytes asked for that have not come up yet.
    asked: u64,
    /// Bytes the send buffer has room for.
    credit: u64,
    /// This side ended its stream.
    shut: bool,
    read: Option<Waker>,
    write: Option<Waker>,
}

impl Link {
    fn new(child: Child, opening: &TcpOpening) -> Link {
        Link {
            child,
            local: opening.local,
            remote: opening.remote,
            handshake: match &opening.origin {
                TcpOrigin::Accepted(handshake) => Some(handshake.clone()),
                TcpOrigin::Connected(_) => None,
            },
            inbox: VecDeque::new(),
            asked: 0,
            credit: 0,
            shut: false,
            read: None,
            write: None,
        }
    }

    fn wake(&mut self) {
        for w in [self.read.take(), self.write.take()].into_iter().flatten() {
            w.wake();
        }
    }
}

/// One listening port's accepted connections.
#[derive(Default)]
struct Accepting {
    /// Children accepted that no `accept` took yet.
    queue: VecDeque<ChildId>,
    /// An accept was asked for and has not opened a child yet.
    asked: bool,
    waker: Option<Waker>,
}

impl Routes {
    /// Delivers one event from the engine to whatever waits for it.
    fn route(&mut self, event: Event) {
        match event {
            MuxEvent::Opened(child, opening, _) => {
                let id = child.id();
                match opening.origin {
                    TcpOrigin::Accepted(_) => {
                        let Some(l) = self.listeners.get_mut(&opening.local.port()) else {
                            return self.strays.push(child);
                        };
                        l.queue.push_back(id);
                        l.asked = false;
                        if let Some(w) = l.waker.take() {
                            w.wake();
                        }
                    }
                    TcpOrigin::Connected(request) => {
                        self.requests.insert(request, id);
                    }
                }
                self.links.insert(id, Link::new(child, &opening));
            }
            MuxEvent::Child(id, event) => {
                let Some(link) = self.links.get_mut(&id) else {
                    return;
                };
                let waiting = match event {
                    StreamEvent::Data(chunk) => {
                        link.asked = link.asked.saturating_sub(chunk.len() as u64);
                        link.inbox.push_back(chunk);
                        [link.read.take(), None]
                    }
                    StreamEvent::Ended => [link.read.take(), None],
                    StreamEvent::Reset => [link.read.take(), link.write.take()],
                    StreamEvent::Written(_) => [None, None],
                };
                for w in waiting.into_iter().flatten() {
                    w.wake();
                }
            }
            MuxEvent::Credit(id, units) => {
                if let Some(link) = self.links.get_mut(&id) {
                    link.credit += units;
                    if let Some(w) = link.write.take() {
                        w.wake();
                    }
                }
            }
            MuxEvent::Closed(id) => {
                if let Some(mut link) = self.links.remove(&id) {
                    link.wake();
                }
            }
            MuxEvent::Control(MessageEvent::Ended) => {}
            MuxEvent::Control(MessageEvent::Message(notice)) => match notice {
                TcpNotice::Listening { .. } | TcpNotice::ListenFailed { .. } => {
                    self.listening = Some(notice);
                }
                TcpNotice::ConnectFailed { request, error } => {
                    self.failed.insert(request, error);
                    if let Some(id) = self.requests.remove(&request)
                        && let Some(mut link) = self.links.remove(&id)
                    {
                        link.wake();
                    }
                }
                TcpNotice::Refused { peer, local } => {
                    if self.refused.is_some() {
                        self.refusals.push((peer, local));
                    }
                }
                TcpNotice::Gone(id) => {
                    for w in self.watches.remove(&id).into_iter().flatten() {
                        w.wake();
                    }
                }
            },
        }
    }

    /// Copies what came up for `id` into `buf`, if anything did.
    fn read(&mut self, id: ChildId, buf: &mut [u8]) -> Option<usize> {
        let link = self.links.get_mut(&id)?;
        let mut n = 0;
        while n < buf.len()
            && let Some(chunk) = link.inbox.front_mut()
        {
            let take = chunk.len().min(buf.len() - n);
            buf[n..n + take].copy_from_slice(&chunk[..take]);
            chunk.advance(take);
            n += take;
            if chunk.is_empty() {
                link.inbox.pop_front();
            }
        }
        (n > 0).then_some(n)
    }
}

/// Reports of the IP layer, which nothing reads.
struct Quiet;

impl Observe<IpReport> for Quiet {
    fn observe(&mut self, _: IpReport) {}
}

impl Host {
    fn engine(&mut self) -> &mut TcpLayer {
        self.tcp.layer_mut()
    }

    fn engine_ref(&self) -> &TcpLayer {
        self.tcp.layer()
    }

    /// Reads the clock.
    fn tick(&mut self) {
        let now = self.fcx.now();
        self.tcp.set_now(now);
    }

    /// Wakes the endpoint's task.
    fn kick(&mut self) {
        if let Some(w) = self.routes.driver.take() {
            w.wake();
        }
    }

    /// Gives the engine `command`, routes what it says back, and wakes the
    /// endpoint's task if the engine has something to send or do. Returns
    /// whether the engine took the command.
    fn command(&mut self, command: Command) -> bool {
        self.tick();
        let taken = match self.tcp.command(command) {
            Ok(admit) => matches!(admit, Admit::Taken),
            Err(never) => match never {},
        };
        self.pump();
        if self.engine_ref().busy() {
            self.kick();
        }
        taken
    }

    fn control(&mut self, control: TcpControl) {
        self.command(MuxCommand::control(MessageCommand::Send(control)));
    }

    /// Routes every event the engine has, and resets the children
    /// accepted for nobody.
    fn pump(&mut self) {
        loop {
            let Host { tcp, routes, .. } = self;
            let moved = tcp.send_above(|event| {
                routes.route(event);
                Admit::Taken
            });
            let strays = std::mem::take(&mut routes.strays);
            if strays.is_empty() && !moved {
                return;
            }
            for child in strays {
                let abort =
                    MuxCommand::control(MessageCommand::Send(TcpControl::Abort(child.id())));
                for command in [abort, child.close()] {
                    if let Err(never) = tcp.command(command) {
                        match never {}
                    }
                }
            }
        }
    }

    /// One turn of the endpoint's task: takes in what of `batch` the
    /// engine has room for, steps it, and puts what it sends in `out`.
    /// Returns whether to come back without waiting.
    fn visit(&mut self, batch: &mut VecDeque<Vec<u8>>, out: &mut Vec<Vec<u8>>) -> bool {
        self.tick();
        let now = self.tcp.now();
        if self.ip.deadline().is_some_and(|(at, ())| at <= now) {
            let mut quiet = Quiet;
            let mut env = Env::new(now, &self.fcx, &self.budget, &mut quiet);
            if let Err(never) = self.ip.on_timer(&mut env, ()) {
                match never {}
            }
        }
        loop {
            if let Some(packet) = self.held.take() {
                match self.tcp.deliver(PacketEvent::Packet(packet)) {
                    Ok(Admit::Blocked(PacketEvent::Packet(packet))) => {
                        self.held = Some(packet);
                        break;
                    }
                    Ok(_) => {}
                    Err(never) => match never {},
                }
            }
            let Some(raw) = batch.pop_front() else {
                break;
            };
            let mut quiet = Quiet;
            let mut env = Env::new(now, &self.fcx, &self.budget, &mut quiet);
            let raw = PacketEvent::Packet(Datagram::new(Chunk::new(raw), Ingress::default()));
            match self.ip.on_event(&mut env, raw) {
                Ok(Admit::Blocked(PacketEvent::Packet(raw))) => {
                    batch.push_front(raw.into_parts().0.into_vec());
                    break;
                }
                Ok(_) => {}
                Err(never) => match never {},
            }
            while let Some(command) = self.ip.take_command() {
                if let PacketCommand::Send(answer) = command {
                    out.push(answer.into_vec());
                }
            }
            if let Some(PacketEvent::Packet(packet)) = self.ip.take_event() {
                self.held = Some(packet);
            }
        }
        if let Err(never) = self.tcp.run() {
            match never {}
        }
        self.tcp.send_below(|command| {
            if let PacketCommand::Send(packet) = command {
                out.push(packet.into_vec());
            }
            Admit::Taken
        });
        self.pump();
        self.tcp.exhausted() || self.held.is_some() || self.engine_ref().saturated()
    }

    /// When the engine or the IP layer next needs time.
    fn deadline(&self) -> Option<Instant> {
        let ip = self.ip.deadline().map(|(at, ())| at);
        [self.tcp.deadline(), ip].into_iter().flatten().min()
    }

    /// The endpoint stopped: every wait ends with an error. Waits for
    /// bytes end at once; the wakers returned are the rest, for after the
    /// lock: listeners in port order, the task, then disappearance watches
    /// in socket order.
    fn stop(&mut self) -> Vec<Waker> {
        self.routes.stopped = true;
        for link in self.routes.links.values_mut() {
            link.wake();
        }
        let mut wakers: Vec<Waker> = self
            .routes
            .listeners
            .values_mut()
            .filter_map(|l| l.waker.take())
            .collect();
        wakers.extend(self.routes.driver.take());
        for id in self.engine_ref().child_ids() {
            wakers.extend(self.routes.watches.remove(&id).into_iter().flatten());
        }
        wakers.extend(
            std::mem::take(&mut self.routes.watches)
                .into_values()
                .flatten(),
        );
        self.engine().stop();
        self.pump();
        wakers
    }

    /// Hands over the next connection `port`'s listener accepted.
    fn accepted(&mut self, shared: &Arc<Shared>, port: u16) -> Option<TcpConnection> {
        let id = self.routes.listeners.get_mut(&port)?.queue.pop_front()?;
        let link = &self.routes.links[&id];
        Some(TcpConnection {
            shared: shared.clone(),
            id,
            local: link.local,
            remote: link.remote,
            handshake: link.handshake.clone(),
            abort: false,
            read_wait: CancelWait::default(),
            write_wait: CancelWait::default(),
        })
    }
}

/// The tests reach into the engine through its host.
#[cfg(test)]
impl std::ops::Deref for Host {
    type Target = TcpLayer;

    fn deref(&self) -> &TcpLayer {
        self.tcp.layer()
    }
}

#[cfg(test)]
impl std::ops::DerefMut for Host {
    fn deref_mut(&mut self) -> &mut TcpLayer {
        self.tcp.layer_mut()
    }
}

impl Shared {
    /// The endpoint stopped: every wait ends with an error.
    fn stop(&self) {
        let wakers = self.state.lock().stop();
        for w in wakers {
            w.wake();
        }
    }
}

/// The endpoint's one task: packets in, the engine, packets out, timers.
async fn drive(fcx: &Cx, shared: &Shared, mut inner: impl Interface) {
    let mut timer = fictionet::Timer::new(fcx);
    let mut batch: VecDeque<Vec<u8>> = VecDeque::with_capacity(64);
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut closed = false;
    poll_fn(|cx| {
        if fcx.is_cancelled() {
            return Poll::Ready(());
        }
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
        let received = batch.len();
        let (exhausted, next, old_driver, refused, refusals) = {
            let mut host = shared.state.lock();
            let old_driver = match &host.routes.driver {
                Some(w) if w.will_wake(cx.waker()) => None,
                _ => host.routes.driver.replace(cx.waker().clone()),
            };
            let exhausted = host.visit(&mut batch, &mut out) || !batch.is_empty();
            (
                exhausted,
                host.deadline(),
                old_driver,
                host.routes.refused.clone(),
                std::mem::take(&mut host.routes.refusals),
            )
        };
        drop(old_driver);
        if let Some(refused) = refused {
            for (peer, local) in refusals {
                refused(peer, local);
            }
        }
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
        match next {
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

/// A connect under way, given up when its future is dropped.
struct Connecting<'a> {
    shared: &'a Shared,
    id: ChildId,
    request: Request,
    done: bool,
}

impl Drop for Connecting<'_> {
    fn drop(&mut self) {
        let mut host = self.shared.state.lock();
        host.routes.requests.remove(&self.request);
        host.routes.failed.remove(&self.request);
        if !self.done
            && let Some(link) = host.routes.links.remove(&self.id)
        {
            host.command(link.child.close());
        }
    }
}

impl Endpoint {
    pub(crate) fn on_refused(&self, observe: Arc<dyn Fn(SocketAddr, SocketAddr) + Send + Sync>) {
        let previous = self.shared.state.lock().routes.refused.replace(observe);
        drop(previous);
    }

    /// Retains per-source flood limits only where the network prevents spoofing.
    pub(crate) fn limit_isolated_peers(&self, isolated: impl Fn(IpAddr) -> bool + Send + 'static) {
        self.shared
            .state
            .lock()
            .engine()
            .limit_isolated_peers(isolated);
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
        let mut host = self.shared.state.lock();
        let peers: BTreeSet<IpAddr> = host
            .engine_ref()
            .peers()
            .into_iter()
            .filter(|peer| which(*peer))
            .collect();
        if peers.is_empty() {
            return;
        }
        host.control(TcpControl::AbortPeers(Box::new(move |peer| {
            peers.contains(&peer)
        })));
    }

    /// Listens on the literal wire `port`, including zero.
    ///
    /// Fails if something already listens there, or if an outgoing
    /// connection uses the port. Dropping the listener frees the port.
    pub fn listen(&self, port: u16) -> Result<Listener, Error> {
        let mut host = self.shared.state.lock();
        host.routes.listening = None;
        host.control(TcpControl::Listen {
            port,
            backlog: None,
            answer: None,
        });
        if !matches!(host.routes.listening, Some(TcpNotice::Listening { .. })) {
            return Err(fictionet::Error::msg(format!(
                "TCP port {port} is already in use on {}",
                self.shared.addr
            )));
        }
        host.routes.listeners.insert(port, Accepting::default());
        Ok(Listener {
            shared: self.shared.clone(),
            port,
            wait: CancelWait::default(),
        })
    }

    /// Opens a connection from this machine to `to`.
    ///
    /// The destination port is literal, including zero. The local port is
    /// selected from the ephemeral range.
    ///
    /// Fails with [`ConnError::Refused`] if the other side answers with a
    /// RST. It also fails with `Refused` immediately, without sending
    /// anything, if `to` has an unspecified address, or not the same IP
    /// version as this machine's address, or if every local port from 49152
    /// up is taken. Fails with
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
        let (request, id, local) = {
            let mut host = self.shared.state.lock();
            let request = Request(host.routes.next_request);
            host.routes.next_request += 1;
            host.control(TcpControl::Connect {
                request,
                remote: to,
            });
            if let Some(error) = host.routes.failed.remove(&request) {
                return Err(error);
            }
            let Some(&id) = host.routes.requests.get(&request) else {
                return Err(ConnError::Closed);
            };
            (request, id, host.routes.links[&id].local)
        };
        let mut pending = Connecting {
            shared: &self.shared,
            id,
            request,
            done: false,
        };
        let mut wait = CancelWait::default();
        poll_fn(|cx| {
            if fcx.is_cancelled() {
                return Poll::Ready(Err(ConnError::Cancelled));
            }
            let old = {
                let mut host = self.shared.state.lock();
                if host.routes.stopped {
                    return Poll::Ready(Err(ConnError::Closed));
                }
                if let Some(error) = host.routes.failed.remove(&request) {
                    return Poll::Ready(Err(error));
                }
                match host.engine_ref().connect_verdict(id) {
                    Verdict::Done => return Poll::Ready(Ok(())),
                    Verdict::Failed(error) => return Poll::Ready(Err(error)),
                    Verdict::Wait => {}
                }
                let Some(link) = host.routes.links.get_mut(&id) else {
                    return Poll::Ready(Err(ConnError::Closed));
                };
                match &link.write {
                    Some(w) if w.will_wake(cx.waker()) => None,
                    _ => link.write.replace(cx.waker().clone()),
                }
            };
            drop(old);
            if fcx.register_cancel(cx.waker(), &mut wait) {
                return Poll::Ready(Err(ConnError::Cancelled));
            }
            Poll::Pending
        })
        .await?;
        pending.done = true;
        drop(pending);
        Ok(TcpConnection {
            shared: self.shared.clone(),
            id,
            local,
            remote: to,
            handshake: None,
            abort: false,
            read_wait: CancelWait::default(),
            write_wait: CancelWait::default(),
        })
    }
}

/// Waits for incoming connections on one port.
pub struct Listener {
    shared: Arc<Shared>,
    port: u16,
    wait: CancelWait,
}

impl Listener {
    /// Sets this port's limit of connections not accepted yet, including
    /// incomplete handshakes. Uses the bounds of [`Options::backlog`].
    /// Existing connections remain when the limit is lowered.
    pub fn backlog(&mut self, connections: usize) {
        self.shared.state.lock().control(TcpControl::Backlog {
            port: self.port,
            backlog: connections,
        });
    }

    /// Answers each connection attempt from now on with `answer`.
    ///
    /// [`Answer::syn`] sees each SYN's options. [`SynAnswer::Accept`] adds
    /// options to the SYN-ACK and its retransmissions, after the endpoint's
    /// own (Maximum Segment Size, and SACK-Permitted, Timestamps and Window
    /// Scale when the SYN offered them), or after the options supplied by
    /// the SYN cookie codec. [`SynAnswer::Refuse`] resets the attempt.
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
    /// its only options. The options either returns must fit in [`SYN_OPTIONS_ROOM`] bytes and read back as
    /// written: an [`Unknown`](TcpOption::Unknown) option may not have kind
    /// 0 or 1 or the bytes of a known option, and SACK has one to four
    /// blocks. Otherwise an accepted attempt gets a RST, and a refusal a RST
    /// without them.
    pub fn answer(&mut self, answer: Box<dyn Answer>) {
        self.shared.state.lock().control(TcpControl::Answer {
            port: self.port,
            answer,
        });
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
    /// attempts use [`Settings::cookies`] when present. A peer at its limit whose address the
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
            let old = {
                let mut host = shared.state.lock();
                if host.routes.stopped {
                    return Poll::Ready(Err(ConnError::Closed));
                }
                if let Some(conn) = host.accepted(shared, port) {
                    return Poll::Ready(Ok(conn));
                }
                let l = host
                    .routes
                    .listeners
                    .get_mut(&port)
                    .expect("a listener has its port");
                if !l.asked {
                    l.asked = true;
                    host.control(TcpControl::Accept { port, count: 1 });
                    if let Some(conn) = host.accepted(shared, port) {
                        return Poll::Ready(Ok(conn));
                    }
                }
                let l = host
                    .routes
                    .listeners
                    .get_mut(&port)
                    .expect("a listener has its port");
                match &l.waker {
                    Some(w) if w.will_wake(cx.waker()) => None,
                    _ => l.waker.replace(cx.waker().clone()),
                }
            };
            drop(old);
            if fcx.register_cancel(cx.waker(), wait) {
                return Poll::Ready(Err(ConnError::Cancelled));
            }
            Poll::Pending
        })
        .await
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let mut host = self.shared.state.lock();
        let Some(l) = host.routes.listeners.remove(&self.port) else {
            return;
        };
        host.control(TcpControl::Unlisten { port: self.port });
        // Connections that never reached accept are reset.
        for id in l.queue {
            if let Some(link) = host.routes.links.remove(&id) {
                host.control(TcpControl::Abort(id));
                host.command(link.child.close());
            }
        }
    }
}

/// One TCP connection. Implements [`Connection`].
///
/// Dropping it closes the connection: a FIN after the bytes already
/// written, or a RST if bytes it received were never read.
pub struct TcpConnection {
    shared: Arc<Shared>,
    id: ChildId,
    local: SocketAddr,
    remote: SocketAddr,
    handshake: Option<Handshake>,
    /// Reset rather than close it when dropped.
    abort: bool,
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
    /// finished closing too, or [`Settings::orphan_timeout`] expires. Reaching
    /// TIME-WAIT releases those counts; only bounded transport recovery
    /// state stays (see [`endpoint`]). A server that must bound how many
    /// closing sockets a peer can hold, such as one that turns connections
    /// away past a limit, resets each connection it is done with.
    pub fn reset(mut self) {
        self.abort = true;
    }

    /// A watch that says when this connection has been reset, by either
    /// side, is gone, or its endpoint has stopped, without reading from it.
    /// For a server that is not reading, such as HTTP/1.1 while a handler works.
    pub fn gone_watch(&self) -> GoneWatch {
        GoneWatch {
            shared: self.shared.clone(),
            id: self.id,
        }
    }

    /// Keeps `item` until the connection is gone, which may be
    /// after this handle is dropped: closing waits for the peer (FIN-WAIT,
    /// LAST-ACK) until [`Settings::orphan_timeout`] expires. A socket that reaches
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
    id: ChildId,
}

impl GoneWatch {
    /// Ready once the connection was reset, is gone, or its endpoint stopped.
    pub fn poll_gone(&self, cx: &mut Context<'_>) -> Poll<()> {
        poll_gone(&self.shared, self.id, cx)
    }

    /// Resets the connection, as [`TcpConnection::reset`] does, after the
    /// connection itself was handed on. Wakes disappearance watches even
    /// while the connection handle is retained. Reads and writes on that
    /// handle report [`ConnError::Reset`]. Does nothing after the dropped
    /// connection reaches TIME-WAIT and is retired by housekeeping.
    pub fn reset(&self) {
        self.shared.state.lock().control(TcpControl::Abort(self.id));
    }

    /// Sets how long the connection may sit idle before this side sends a
    /// keepalive, and how often it sends one after that, as a socket's
    /// SO_KEEPALIVE and TCP_KEEPIDLE do. `None` sends none. A connection
    /// starts with one every 45 seconds, so a peer that is gone is noticed;
    /// this interval is a world setting. Works after the connection itself
    /// was handed on. Does nothing once its handle was dropped.
    pub fn set_keep_alive(&self, interval: Option<Duration>) {
        self.shared.state.lock().control(TcpControl::KeepAlive {
            child: self.id,
            interval,
        });
    }

    /// Keeps `item` until the connection is gone: see
    /// [`TcpConnection::hold_until_gone`]. Works after the connection
    /// itself was handed on, such as boxed behind TLS. Drops `item`
    /// immediately if the connection has already retired into TIME-WAIT.
    pub fn hold_until_gone(&self, item: Box<dyn std::any::Any + Send>) {
        self.shared.state.lock().control(TcpControl::Hold {
            child: self.id,
            item,
        });
    }
}

impl super::transport::Retirement for GoneWatch {
    fn poll_gone(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.poll_gone(cx)
    }

    fn reset(&self) {
        self.reset();
    }

    fn hold_until_gone(&self, item: Box<dyn std::any::Any + Send>) {
        self.hold_until_gone(item);
    }

    fn set_keep_alive(&self, interval: Option<Duration>) {
        self.set_keep_alive(interval);
    }
}

/// Ready once the connection of child `id` was reset, or is gone.
fn poll_gone(shared: &Shared, id: ChildId, cx: &mut Context<'_>) -> Poll<()> {
    let mut host = shared.state.lock();
    if host.routes.stopped || host.engine_ref().gone(id) {
        return Poll::Ready(());
    }
    let watches = host.routes.watches.entry(id).or_default();
    if !watches.iter().any(|w| w.will_wake(cx.waker())) {
        watches.push(cx.waker().clone());
    }
    Poll::Pending
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        let mut host = self.shared.state.lock();
        let Some(link) = host.routes.links.remove(&self.id) else {
            return;
        };
        // Bytes that came up unread are lost, so the peer gets a RST.
        if self.abort || !link.inbox.is_empty() {
            host.control(TcpControl::Abort(self.id));
        }
        host.command(link.child.close());
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
        let old = {
            let mut host = self.shared.state.lock();
            if host.routes.stopped {
                return Poll::Ready(Err(ConnError::Closed));
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if let Some(n) = host.routes.read(self.id, buf) {
                return Poll::Ready(Ok(n));
            }
            // Ask for as many bytes as this read takes. They come up from
            // the receive buffer, which opens the window by as much.
            let link = host.routes.links.get_mut(&self.id).expect("a live link");
            if link.asked == 0 {
                link.asked = buf.len() as u64;
                let grant = link.child.grant(buf.len() as u64);
                host.command(grant);
                if let Some(n) = host.routes.read(self.id, buf) {
                    return Poll::Ready(Ok(n));
                }
            }
            match host.engine().read_verdict(self.id) {
                Verdict::Done => return Poll::Ready(Ok(0)),
                Verdict::Failed(error) => return Poll::Ready(Err(error)),
                Verdict::Wait => {}
            }
            let link = host.routes.links.get_mut(&self.id).expect("a live link");
            match &link.read {
                Some(w) if w.will_wake(cx.waker()) => None,
                _ => link.read.replace(cx.waker().clone()),
            }
        };
        drop(old);
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
        let old = {
            let mut host = self.shared.state.lock();
            if host.routes.stopped {
                return Poll::Ready(Err(ConnError::Closed));
            }
            let link = host.routes.links.get_mut(&self.id).expect("a live link");
            if link.shut {
                return Poll::Ready(Err(ConnError::Closed));
            }
            if data.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if link.credit > 0 {
                let n = (link.credit as usize).min(data.len());
                link.credit -= n as u64;
                let write = link
                    .child
                    .send(StreamCommand::Write(Chunk::new(data[..n].to_vec())));
                if host.command(write) {
                    return Poll::Ready(Ok(n));
                }
                if let Some(link) = host.routes.links.get_mut(&self.id) {
                    link.credit = 0;
                }
            }
            if let Verdict::Failed(error) = host.engine_ref().write_verdict(self.id) {
                return Poll::Ready(Err(error));
            }
            let link = host.routes.links.get_mut(&self.id).expect("a live link");
            match &link.write {
                Some(w) if w.will_wake(cx.waker()) => None,
                _ => link.write.replace(cx.waker().clone()),
            }
        };
        drop(old);
        if fcx.register_cancel(cx.waker(), &mut self.write_wait) {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
        Poll::Pending
    }

    /// Sends a FIN once the peer has acknowledged every byte already written.
    /// Returns immediately. A cancel does not stop it.
    fn poll_shutdown(&mut self, _fcx: &Cx, _cx: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        let mut host = self.shared.state.lock();
        if host.routes.stopped {
            return Poll::Ready(Err(ConnError::Closed));
        }
        if host.routes.links[&self.id].shut {
            return Poll::Ready(Ok(()));
        }
        if let Some(error) = host.engine_ref().end_verdict(self.id) {
            return Poll::Ready(Err(error));
        }
        let link = host.routes.links.get_mut(&self.id).expect("a live link");
        link.shut = true;
        let end = link.child.send(StreamCommand::End);
        host.command(end);
        Poll::Ready(Ok(()))
    }

    fn poll_gone(&self, cx: &mut Context<'_>) -> Poll<()> {
        poll_gone(&self.shared, self.id, cx)
    }
}
