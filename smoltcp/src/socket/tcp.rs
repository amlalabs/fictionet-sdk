use core::fmt::Display;

use core::task::Waker;
use core::{fmt, mem};

use crate::iface::Context;
use crate::socket::PollAt;
use crate::socket::WakerRegistration;
use crate::storage::Assembler;
use crate::time::{Duration, Instant};
use crate::wire::{
    IpAddress, IpEndpoint, IpListenEndpoint, IpProtocol, IpRepr, TCP_HEADER_LEN,
    TCP_OPTIONS_MAX_LEN, TcpControl, TcpOption, TcpOptions, TcpRepr, TcpSeqNumber,
    TcpTimestampGenerator, TcpTimestampRepr,
};

mod reno;
mod rx;
#[cfg(kani)]
#[path = "../../../verification/tcp-store/kani/mod.rs"]
mod store_proofs;
#[cfg(test)]
mod store_tests;
mod tx;

pub use self::rx::SEGMENTS;

/// The bytes a socket's stores allocate when it is made, for the places of
/// the chunks they retain, [`SEGMENTS`] each way: all a connection holds
/// beside the chunks themselves, which carry their own charges.
pub const PLACES: usize =
    SEGMENTS * (2 * mem::size_of::<Chunk>() + mem::size_of::<(usize, Chunk)>());
use self::rx::RxStore;
use self::tx::TxStore;
pub use self::tx::{HEADROOM, Piece};
use fictionet_buf::{Budget, Chunk, Pool};

/// Which due segments an emitter has storage to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchMode {
    /// Application data and control traffic.
    All,
    /// Control traffic only, including one-byte window probes.
    Control,
}

/// Error returned by [`Socket::listen`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ListenError {
    InvalidState,
}

impl Display for ListenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ListenError::InvalidState => write!(f, "invalid state"),
        }
    }
}

impl core::error::Error for ListenError {}

/// Error returned by [`Socket::connect`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ConnectError {
    InvalidState,
    Unaddressable,
}

impl Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ConnectError::InvalidState => write!(f, "invalid state"),
            ConnectError::Unaddressable => write!(f, "unaddressable destination"),
        }
    }
}

impl core::error::Error for ConnectError {}

/// Why [`Socket::push`] refused a chunk, which it hands back.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SendError {
    /// The connection may not send: not yet open, or closed for sending.
    InvalidState,
    /// The send buffer has no room for all of it, or a block it needs to
    /// gather it was refused by the budget.
    Full,
}

impl Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SendError::InvalidState => write!(f, "invalid state"),
            SendError::Full => write!(f, "no room"),
        }
    }
}

impl core::error::Error for SendError {}

/// Error returned by [`Socket::recv`]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RecvError {
    InvalidState,
    Finished,
}

impl Display for RecvError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RecvError::InvalidState => write!(f, "invalid state"),
            RecvError::Finished => write!(f, "operation finished"),
        }
    }
}

impl core::error::Error for RecvError {}

/// Error returned by [`Socket::set_syn_options`], [`encode_options`] and
/// [`encode_options_within`].
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SynOptionsError {
    /// They take more bytes than there is room for: [`SYN_OPTIONS_ROOM`]
    /// for a SYN.
    TooLong,
    /// One would not read back as itself: End of Option List, an unknown
    /// kind 0 or 1, or the bytes of a known option written as unknown.
    Unreadable,
}

impl Display for SynOptionsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SynOptionsError::TooLong => write!(f, "options do not fit in a SYN"),
            SynOptionsError::Unreadable => write!(f, "an option would not read back as written"),
        }
    }
}

impl core::error::Error for SynOptionsError {}

/// Encodes options for a SYN, SYN-ACK or RST, checking that they fit in
/// [`SYN_OPTIONS_ROOM`] and read back as themselves: whole options, with
/// no End of Option List and no padding.
pub fn encode_options(options: &[TcpOption]) -> Result<Vec<u8>, SynOptionsError> {
    encode_options_within(options, SYN_OPTIONS_ROOM)
}

/// Encodes options as [`encode_options`] does, checking that they fit in
/// `room` bytes, such as [`SEGMENT_OPTIONS_ROOM`].
pub fn encode_options_within(
    options: &[TcpOption],
    room: usize,
) -> Result<Vec<u8>, SynOptionsError> {
    let len: usize = options.iter().map(TcpOption::buffer_len).sum();
    if len > room {
        return Err(SynOptionsError::TooLong);
    }
    let mut encoded = vec![0; len];
    let mut rest = &mut encoded[..];
    for option in options {
        rest = option.emit(rest);
    }
    if !TcpOptions::new(&encoded)
        .map(|o| o.ok())
        .eq(options.iter().map(|&o| Some(o)))
    {
        return Err(SynOptionsError::Unreadable);
    }
    Ok(encoded)
}

/// The option bytes a SYN or SYN-ACK always has room for beside the
/// socket's own: Maximum Segment Size (4), SACK-Permitted with
/// Timestamps (12) and Window Scale after a No-Operation (4) leave 20 of
/// the 40.
pub const SYN_OPTIONS_ROOM: usize = TCP_OPTIONS_MAX_LEN - 20;

/// The state of a TCP socket, according to [RFC 793].
///
/// [RFC 793]: https://tools.ietf.org/html/rfc793
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/// RFC 6298: (2.1) Until a round-trip time (RTT) measurement has been made for a
/// segment sent between the sender and receiver, the sender SHOULD
/// set RTO <- 1 second,
const RTTE_INITIAL_RTO: u32 = 1000;

// Minimum "safety margin" for the RTO that kicks in when the
// variance gets very low.
const RTTE_MIN_MARGIN: u32 = 5;

/// K, according to RFC 6298
const RTTE_K: u32 = 4;

// RFC 6298 (2.4): Whenever RTO is computed, if it is less than 1 second, then the
// RTO SHOULD be rounded up to 1 second.
const RTTE_MIN_RTO: u32 = 1000;

// RFC 6298 (2.5) A maximum value MAY be placed on RTO provided it is at least 60
// seconds
const RTTE_MAX_RTO: u32 = 60_000;

#[derive(Debug, Clone, Copy)]
struct RttEstimator {
    /// true if we have made at least one rtt measurement.
    have_measurement: bool,
    /// Smoothed RTT
    srtt: u32,
    /// RTT variance.
    rttvar: u32,
    /// Retransmission Time-Out
    rto: u32,
    timestamp: Option<(Instant, TcpSeqNumber)>,
    max_seq_sent: Option<TcpSeqNumber>,
    rto_count: u8,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self {
            have_measurement: false,
            srtt: 0,   // ignored, will be overwritten on first measurement.
            rttvar: 0, // ignored, will be overwritten on first measurement.
            rto: RTTE_INITIAL_RTO,
            timestamp: None,
            max_seq_sent: None,
            rto_count: 0,
        }
    }
}

impl RttEstimator {
    fn retransmission_timeout(&self) -> Duration {
        Duration::from_millis(self.rto as _)
    }

    fn sample(&mut self, new_rtt: u32) {
        if self.have_measurement {
            // RFC 6298 (2.3) When a subsequent RTT measurement R' is made, a host MUST set (...)
            let diff = self.srtt.abs_diff(new_rtt) as u64;
            self.rttvar = (self.rttvar as u64 * 3 + diff).div_ceil(4) as u32;
            self.srtt = (self.srtt as u64 * 7 + new_rtt as u64).div_ceil(8) as u32;
        } else {
            // RFC 6298 (2.2) When the first RTT measurement R is made, the host MUST set (...)
            self.have_measurement = true;
            self.srtt = new_rtt;
            self.rttvar = new_rtt / 2;
        }

        // RFC 6298 (2.2), (2.3)
        let margin = (RTTE_MIN_MARGIN as u64).max(self.rttvar as u64 * RTTE_K as u64);
        self.rto =
            (self.srtt as u64 + margin).clamp(RTTE_MIN_RTO as u64, RTTE_MAX_RTO as u64) as u32;

        self.rto_count = 0;
    }

    fn on_send(&mut self, timestamp: Instant, seq: TcpSeqNumber) {
        if self
            .max_seq_sent
            .map(|max_seq_sent| seq > max_seq_sent)
            .unwrap_or(true)
        {
            self.max_seq_sent = Some(seq);
            if self.timestamp.is_none() {
                self.timestamp = Some((timestamp, seq));
            }
        }
    }

    fn on_ack(&mut self, timestamp: Instant, seq: TcpSeqNumber) {
        if let Some((sent_timestamp, sent_seq)) = self.timestamp
            && seq >= sent_seq
        {
            self.sample(
                u32::try_from((timestamp - sent_timestamp).total_millis()).unwrap_or(u32::MAX),
            );
            self.timestamp = None;
        }
    }

    fn on_rto(&mut self) {
        // RFC 6298 (5.5) The host MUST set RTO <- RTO * 2 ("back off the timer").  The
        // maximum value discussed in (2.5) above may be used to provide
        // an upper bound to this doubling operation.
        self.rto = (self.rto * 2).min(RTTE_MAX_RTO);

        // RFC 6298: a TCP implementation MAY clear SRTT and RTTVAR after
        // backing off the timer multiple times as it is likely that the current
        // SRTT and RTTVAR are bogus in this situation.  Once SRTT and RTTVAR
        // are cleared, they should be initialized with the next RTT sample
        // taken per (2.2) rather than using (2.3).
        self.rto_count += 1;
        if self.rto_count >= 3 {
            self.rto_count = 0;
            self.have_measurement = false;
        }
    }

    fn on_retransmit(&mut self) {
        self.timestamp = None;
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Timer {
    Idle {
        keep_alive_at: Option<Instant>,
    },
    Retransmit {
        expires_at: Instant,
    },
    FastRetransmit,
    ZeroWindowProbe {
        expires_at: Instant,
        delay: Duration,
    },
    Close {
        expires_at: Instant,
    },
}

const ACK_DELAY_DEFAULT: Duration = Duration::from_millis(10);
#[cfg(test)]
const CLOSE_DELAY: Duration = Duration::from_secs(240);

impl Timer {
    fn new() -> Timer {
        Timer::Idle {
            keep_alive_at: None,
        }
    }

    fn should_keep_alive(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::Idle {
                keep_alive_at: Some(keep_alive_at),
            } if timestamp >= keep_alive_at => true,
            _ => false,
        }
    }

    fn should_retransmit(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::Retransmit { expires_at } if timestamp >= expires_at => true,
            Timer::FastRetransmit => true,
            _ => false,
        }
    }

    fn should_close(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::Close { expires_at } if timestamp >= expires_at => true,
            _ => false,
        }
    }

    fn should_zero_window_probe(&self, timestamp: Instant) -> bool {
        match *self {
            Timer::ZeroWindowProbe { expires_at, .. } if timestamp >= expires_at => true,
            _ => false,
        }
    }

    fn poll_at(&self) -> PollAt {
        match *self {
            Timer::Idle {
                keep_alive_at: Some(keep_alive_at),
            } => PollAt::Time(keep_alive_at),
            Timer::Idle {
                keep_alive_at: None,
            } => PollAt::Ingress,
            Timer::ZeroWindowProbe { expires_at, .. } => PollAt::Time(expires_at),
            Timer::Retransmit { expires_at, .. } => PollAt::Time(expires_at),
            Timer::FastRetransmit => PollAt::Now,
            Timer::Close { expires_at } => PollAt::Time(expires_at),
        }
    }

    fn set_for_idle(&mut self, timestamp: Instant, interval: Option<Duration>) {
        *self = Timer::Idle {
            keep_alive_at: interval.map(|interval| timestamp + interval),
        }
    }

    fn set_keep_alive(&mut self) {
        if let Timer::Idle { keep_alive_at } = self
            && keep_alive_at.is_none()
        {
            *keep_alive_at = Some(Instant::from_millis(0))
        }
    }

    fn rewind_keep_alive(&mut self, timestamp: Instant, interval: Option<Duration>) {
        if let Timer::Idle { keep_alive_at } = self {
            *keep_alive_at = interval.map(|interval| timestamp + interval)
        }
    }

    fn set_for_retransmit(&mut self, timestamp: Instant, delay: Duration) {
        match *self {
            Timer::Idle { .. }
            | Timer::FastRetransmit
            | Timer::Retransmit { .. }
            | Timer::ZeroWindowProbe { .. } => {
                *self = Timer::Retransmit {
                    expires_at: timestamp + delay,
                }
            }
            Timer::Close { .. } => (),
        }
    }

    fn set_for_fast_retransmit(&mut self) {
        *self = Timer::FastRetransmit
    }

    fn set_for_close(&mut self, timestamp: Instant, delay: Duration) {
        *self = Timer::Close {
            expires_at: timestamp + delay,
        }
    }

    fn set_for_zero_window_probe(&mut self, timestamp: Instant, delay: Duration) {
        *self = Timer::ZeroWindowProbe {
            expires_at: timestamp + delay,
            delay,
        }
    }

    fn rewind_zero_window_probe(&mut self, timestamp: Instant) {
        if let Timer::ZeroWindowProbe { mut delay, .. } = *self {
            delay = (delay * 2).min(Duration::from_millis(RTTE_MAX_RTO as _));
            *self = Timer::ZeroWindowProbe {
                expires_at: timestamp + delay,
                delay,
            }
        }
    }

    fn is_idle(&self) -> bool {
        matches!(self, Timer::Idle { .. })
    }

    fn is_zero_window_probe(&self) -> bool {
        matches!(self, Timer::ZeroWindowProbe { .. })
    }

    fn is_retransmit(&self) -> bool {
        matches!(self, Timer::Retransmit { .. } | Timer::FastRetransmit)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum AckDelayTimer {
    Idle,
    Waiting(Instant),
    Immediate,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct Tuple {
    local: IpEndpoint,
    remote: IpEndpoint,
}

/// A Transmission Control Protocol socket.
///
/// A TCP socket may passively listen for connections or actively connect to another endpoint.
/// Note that, for listening sockets, there is no "backlog"; to be able to simultaneously
/// accept several connections, as many sockets must be allocated, or any new connection
/// attempts will be reset.
#[derive(Debug)]
pub struct Socket {
    state: State,
    timer: Timer,
    rtte: RttEstimator,
    assembler: Assembler,
    rx: RxStore,
    rx_fin_received: bool,
    tx: TxStore,
    /// Interval after which, if no inbound packets are received, the connection is aborted.
    timeout: Option<Duration>,
    /// Interval at which keep-alive packets will be sent.
    keep_alive: Option<Duration>,
    /// The time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    hop_limit: Option<u8>,
    /// Address passed to listen(). Listen address is set when listen() is called and
    /// used every time the socket is reset back to the LISTEN state.
    listen_endpoint: Option<IpListenEndpoint>,
    /// Current 4-tuple (local and remote endpoints).
    tuple: Option<Tuple>,
    /// The sequence number corresponding to the beginning of the transmit buffer.
    /// I.e. an ACK(local_seq_no+n) packet removes n bytes from the transmit buffer.
    local_seq_no: TcpSeqNumber,
    /// The sequence number corresponding to the beginning of the receive buffer.
    /// I.e. userspace reading n bytes adds n to remote_seq_no.
    remote_seq_no: TcpSeqNumber,
    /// The next sequence number to transmit or retransmit.
    remote_last_seq: TcpSeqNumber,
    /// The highest sequence number sent, including probes and control flags.
    local_seq_max: TcpSeqNumber,
    /// The last acknowledgement number sent.
    /// I.e. in an idle socket, remote_seq_no+rx.len().
    remote_last_ack: Option<TcpSeqNumber>,
    /// The last window length sent.
    remote_last_win: u16,
    /// The furthest receive window edge.
    remote_win_end: Option<TcpSeqNumber>,
    /// The sending window scaling factor advertised to remotes which support RFC 1323.
    /// It is zero if the window <= 64KiB and/or the remote does not support it.
    remote_win_shift: u8,
    /// The remote window size, relative to local_seq_no
    /// I.e. we're allowed to send octets until local_seq_no+remote_win_len
    remote_win_len: usize,
    /// The receive window scaling factor for remotes which support RFC 1323, None if unsupported.
    remote_win_scale: Option<u8>,
    /// Whether or not the remote supports selective ACK as described in RFC 2018.
    remote_has_sack: bool,
    /// The maximum number of data octets that the remote side may receive.
    remote_mss: usize,
    /// The timestamp of the last packet received.
    remote_last_ts: Option<Instant>,
    /// The sequence number of the last packet received, used for sACK
    local_rx_last_seq: Option<TcpSeqNumber>,
    /// The ACK number of the last packet received.
    local_rx_last_ack: Option<TcpSeqNumber>,
    /// The number of packets received directly after
    /// each other which have the same ACK number.
    local_rx_dup_acks: u8,
    /// If a fast retransmit needs to occur
    pending_fast_retransmit: bool,
    /// Whether `close` left SYN-RECEIVED before the remote acknowledged our
    /// SYN. Until it does, the SYN still holds its sequence number in
    /// FIN-WAIT-1 or CLOSING, and the FIN waits behind it.
    closed_before_syn_ack: bool,

    /// Duration for Delayed ACK. If None no ACKs will be delayed.
    ack_delay: Option<Duration>,
    /// Delayed ack timer. If set, packets containing exclusively
    /// ACK or window updates (ie, no data) won't be sent until expiry.
    ack_delay_timer: AckDelayTimer,

    /// Used for rate-limiting: No more challenge ACKs will be sent until this instant.
    challenge_ack_timer: Instant,

    /// Nagle's Algorithm enabled.
    nagle: bool,

    /// The congestion control algorithm.
    congestion_controller: reno::Reno,

    /// Configured timestamp clock, retained when a peer declines timestamps.
    tsval_generator: Option<TcpTimestampGenerator>,
    /// Whether negotiation permits using the configured clock.
    timestamps_enabled: bool,
    timestamp_offset: u32,
    /// Private identification counter, when configured by the endpoint.
    ipv4_identification: Option<u16>,
    settings: Settings,

    /// 0 if not seen or timestamp not enabled
    last_remote_tsval: u32,

    /// Options added to this connection's SYN or SYN-ACK, encoded: see
    /// [`Socket::set_syn_options`].
    syn_options: Vec<u8>,
    syn_ipv4_options: crate::wire::Ipv4OptionBytes,
    syn_ipv4_destination: Option<core::net::Ipv4Addr>,

    /// What adds options to this connection's other segments: see
    /// [`Socket::set_segment_options`].
    segment_options: Option<SegmentOptionsBox>,
    /// The options it gave the segment being sent.
    segment_extra: Vec<u8>,
    /// It asked for an ACK, which the next segment sent carries.
    ack_asked: bool,
    /// The options of the RST it asked for, encoded. `None` when the
    /// connection was aborted without any: the RST then carries what
    /// [`SegmentOptions::reset`] gives.
    rst_options: Option<Vec<u8>>,

    rx_waker: WakerRegistration,

    tx_waker: WakerRegistration,
}

const DEFAULT_MSS: usize = 536;

/// Payload on a keep-alive probe, both forms permitted by RFC 1122 section 4.2.3.6.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepAlivePayload {
    /// Send only the acknowledgment with the preceding sequence number.
    Empty,
    /// Include one garbage byte for peers that require it.
    OneByte,
}

/// Transport choices supplied by the world.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Order and padding of emitted options.
    pub layout: crate::wire::OptionLayout,
    /// Initial unscaled receive window, or the available buffer space.
    pub syn_window: Option<u16>,
    /// Initial window when timestamps were negotiated.
    pub syn_window_with_timestamps: Option<u16>,
    /// Advertised receive scale, or a scale derived from the buffer size.
    pub window_scale: Option<u8>,
    /// TIME-WAIT duration, normally twice the maximum segment lifetime.
    pub time_wait: Duration,
    /// Send the SYN-ACK again when the original SYN is repeated.
    pub repeat_syn_ack: bool,
    /// Lower bound on a peer MSS, with room for options and payload.
    pub minimum_mss: u16,
    /// Full segments of new data that trigger an immediate ACK.
    pub ack_segments: u8,
    /// ACK at the threshold, rather than only after exceeding it.
    pub ack_inclusive: bool,
    /// Window growth ratio that triggers an immediate window update.
    pub window_update_ratio: u16,
    /// Minimum interval between challenge acknowledgments on one socket.
    pub challenge_ack_interval: Duration,
    /// Whether keep-alive probes include a garbage byte.
    pub keep_alive_payload: KeepAlivePayload,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            layout: crate::wire::OptionLayout::default(),
            syn_window: None,
            syn_window_with_timestamps: None,
            window_scale: None,
            time_wait: Duration::from_secs(240),
            repeat_syn_ack: false,
            minimum_mss: MIN_REMOTE_MSS as u16,
            ack_segments: 2,
            ack_inclusive: true,
            window_update_ratio: 2,
            challenge_ack_interval: Duration::from_secs(1),
            keep_alive_payload: KeepAlivePayload::OneByte,
        }
    }
}

/// Enough room for the largest option area and at least one payload byte.
const MIN_REMOTE_MSS: usize = TCP_OPTIONS_MAX_LEN + 1;

/// The most option bytes a [`SegmentOptions`] may add to one segment: what
/// the 40 bytes of option space leave beside timestamps (10 bytes, padded
/// to 12).
pub const SEGMENT_OPTIONS_ROOM: usize = TCP_OPTIONS_MAX_LEN - 12;

/// A segment a socket sends once its handshake is done, as
/// [`SegmentOptions::sent`] sees it.
#[derive(Debug, Clone, Copy)]
pub struct Outgoing<'a> {
    /// Its sequence number.
    pub seq: u32,
    /// Its data. A keep-alive's one garbage byte is not shown.
    pub payload: &'a [u8],
    /// Whether it carries a FIN.
    pub fin: bool,
    /// Its acknowledgment number.
    pub ack: Option<u32>,
}

/// A segment a socket took once its handshake was done: one in the receive
/// window, as [`SegmentOptions::received`] sees it.
#[derive(Debug, Clone, Copy)]
pub struct Incoming<'a> {
    /// Its sequence number.
    pub seq: u32,
    /// Its data, all of it, as sent.
    pub payload: &'a [u8],
    /// Whether it carries a FIN.
    pub fin: bool,
    /// Its options, as they are on the wire.
    pub options: &'a [u8],
}

/// Options a connection carries on every segment after its handshake,
/// beside the socket's own, such as the DSS option of a Multipath TCP
/// connection (RFC 8684 section 3.3). Set with
/// [`Socket::set_segment_options`].
pub trait SegmentOptions: Send {
    /// The most bytes of options [`sent`](SegmentOptions::sent) writes for
    /// one segment, at most [`SEGMENT_OPTIONS_ROOM`]. Every segment with
    /// data leaves this much room.
    fn room(&self) -> usize;

    /// Writes the options for `segment`, which is about to be sent, into
    /// `out`, which is empty: whole options with no End of Option List,
    /// at most [`room`](SegmentOptions::room) bytes. More than that are
    /// not sent. Called for every segment but a RST, retransmissions
    /// included.
    fn sent(&mut self, segment: &Outgoing<'_>, out: &mut Vec<u8>);

    /// Sees a segment the socket took, in any order, before its data can
    /// be read, and says what the socket does with it.
    fn received(&mut self, segment: &Incoming<'_>) -> Verdict;

    /// Sees `data`, bytes that just became contiguous from subflow
    /// sequence number `seq`, before they can be read, and may change them
    /// into application bytes in place: edit them
    /// ([`Chunk::make_mut`], charged to `budget`, which copies only a
    /// shared chunk), or put other bytes in their place, fewer while it
    /// holds some back until a mapping can be validated. What is left in
    /// `data` is what the application reads, and must fit the receive
    /// window. The default leaves the bytes as they are and copies nothing.
    fn arrived(&mut self, seq: u32, data: &mut Chunk, budget: &Budget) -> Verdict {
        let _ = (seq, data, budget);
        Verdict::Take
    }

    /// Writes the options for a RST the socket sends with none of its own:
    /// when it is aborted, or must reset for a reason of its own. Whole
    /// options with no End of Option List, as an MPTCP host puts MP_TCPRST
    /// on every RST of a subflow (RFC 8684 section 3.6). Default none.
    fn reset(&mut self, out: &mut Vec<u8>) {
        let _ = out;
    }
}

/// What a socket does with a segment its [`SegmentOptions`] saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Goes on as usual.
    Take,
    /// Acknowledges the segment at once, though it may carry no data, as
    /// an MPTCP host acknowledges a DATA_FIN (RFC 8684 section 3.3.3).
    Acknowledge,
    /// Resets the connection with a RST that carries these whole options,
    /// encoded, as an MPTCP host resets a subflow with MP_TCPRST (RFC 8684
    /// section 3.6). Nothing more of the segment is taken.
    Reset(Vec<u8>),
}

impl Verdict {
    /// What the socket does when this was said of some bytes of a segment
    /// and `then` of the bytes after: a reset outranks an acknowledgement,
    /// which outranks going on.
    fn and(self, then: Verdict) -> Verdict {
        match (self, then) {
            (reset @ Verdict::Reset(_), _) | (_, reset @ Verdict::Reset(_)) => reset,
            (Verdict::Acknowledge, _) | (_, Verdict::Acknowledge) => Verdict::Acknowledge,
            (Verdict::Take, Verdict::Take) => Verdict::Take,
        }
    }
}

/// A boxed [`SegmentOptions`], so that the socket can print itself.
struct SegmentOptionsBox(Box<dyn SegmentOptions>);

impl fmt::Debug for SegmentOptionsBox {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SegmentOptions")
            .field("room", &self.0.room())
            .finish()
    }
}

impl Socket {
    /// A socket whose receive window is `rx_capacity` bytes and whose send
    /// buffer holds `tx_capacity`. It retains the chunks segments and
    /// writes come in, at most [`SEGMENTS`] each way, and charges the
    /// blocks it takes to gather short pieces to `budget`. `pool` is the
    /// endpoint's shared pool of 2048-byte packet slots; idle sockets keep
    /// no blocks, and released gathering blocks recycle into that pool.
    pub fn new(rx_capacity: usize, tx_capacity: usize, budget: Budget, pool: &Pool) -> Socket {
        assert_eq!(pool.slot(), rx::SLOT, "TCP stores use packet-sized slots");
        let rx = RxStore::new(rx_capacity, budget.clone(), pool);
        let tx = TxStore::new(tx_capacity, budget, pool);

        if rx_capacity > (1 << 30) {
            panic!("receiving buffer too large, cannot exceed 1 GiB")
        }
        let rx_cap_log2 = mem::size_of::<usize>() * 8 - rx_capacity.leading_zeros() as usize;

        Socket {
            state: State::Closed,
            timer: Timer::new(),
            rtte: RttEstimator::default(),
            assembler: Assembler::new(),
            tx,
            rx,
            rx_fin_received: false,
            timeout: None,
            keep_alive: None,
            hop_limit: None,
            listen_endpoint: None,
            tuple: None,
            local_seq_no: TcpSeqNumber::default(),
            remote_seq_no: TcpSeqNumber::default(),
            remote_last_seq: TcpSeqNumber::default(),
            local_seq_max: TcpSeqNumber::default(),
            remote_last_ack: None,
            remote_last_win: 0,
            remote_win_end: None,
            remote_win_len: 0,
            remote_win_shift: rx_cap_log2.saturating_sub(16).min(14) as u8,
            remote_win_scale: None,
            remote_has_sack: false,
            remote_mss: DEFAULT_MSS,
            remote_last_ts: None,
            local_rx_last_ack: None,
            local_rx_last_seq: None,
            local_rx_dup_acks: 0,
            pending_fast_retransmit: false,
            closed_before_syn_ack: false,
            ack_delay: Some(ACK_DELAY_DEFAULT),
            ack_delay_timer: AckDelayTimer::Idle,
            challenge_ack_timer: Instant::from_secs(0),
            nagle: true,
            tsval_generator: None,
            timestamps_enabled: true,
            timestamp_offset: 0,
            ipv4_identification: None,
            settings: Settings::default(),
            last_remote_tsval: 0,
            congestion_controller: reno::Reno::new(),
            syn_options: Vec::new(),
            syn_ipv4_options: crate::wire::Ipv4OptionBytes::EMPTY,
            syn_ipv4_destination: None,
            segment_options: None,
            segment_extra: Vec::new(),
            ack_asked: false,
            rst_options: None,

            rx_waker: WakerRegistration::new(),

            tx_waker: WakerRegistration::new(),
        }
    }

    /// Enable or disable TCP Timestamp. The generator receives the stack clock.
    pub fn set_tsval_generator(&mut self, generator: Option<TcpTimestampGenerator>) {
        self.tsval_generator = generator;
        self.timestamps_enabled = true;
    }

    /// Sets the transport choices before starting a connection.
    pub fn set_settings(&mut self, settings: Settings) {
        self.settings = settings;
        if let Some(scale) = settings.window_scale {
            self.remote_win_shift = scale.min(14);
        }
    }

    /// Keeps an offset for this connection's timestamp clock.
    pub fn set_timestamp_offset(&mut self, offset: u32) {
        self.timestamp_offset = offset;
    }

    /// Uses a private IPv4 identification counter for this socket.
    /// Passive SYN and TIME-WAIT replies carry identification zero.
    pub fn set_ipv4_identification(&mut self, initial: u16) {
        self.ipv4_identification = Some(initial);
    }

    fn identify_ipv4(&self, ip: &mut IpRepr) {
        if !matches!(
            self.state,
            State::Listen | State::SynReceived | State::TimeWait
        ) && let (Some(id), IpRepr::Ipv4(ip)) = (self.ipv4_identification, ip)
        {
            ip.identification = id;
        }
    }

    fn advance_ipv4_identification(&mut self, ip: &IpRepr) {
        if !matches!(
            self.state,
            State::Listen | State::SynReceived | State::TimeWait
        ) && matches!(ip, IpRepr::Ipv4(_))
            && let Some(id) = &mut self.ipv4_identification
        {
            *id = id.wrapping_add(1);
        }
    }

    /// Restores options negotiated by a stateless handshake.
    pub fn restore_cookie_options(
        &mut self,
        scale: Option<u8>,
        sack: bool,
        timestamp: Option<(TcpTimestampGenerator, u32, u32)>,
    ) {
        self.remote_win_scale = scale.map(|s| s.min(14));
        self.remote_win_shift = if scale.is_some() {
            self.settings.window_scale.unwrap_or_else(|| {
                (usize::BITS - self.rx.capacity().leading_zeros())
                    .saturating_sub(16)
                    .min(14) as u8
            })
        } else {
            0
        };
        self.remote_has_sack = sack;
        let window = if timestamp.is_some() {
            self.settings
                .syn_window_with_timestamps
                .or(self.settings.syn_window)
        } else {
            self.settings.syn_window
        };
        let window = window.unwrap_or_else(|| u16::try_from(self.rx.window()).unwrap_or(u16::MAX));
        self.remote_win_end = Some(self.remote_seq_no + usize::from(window));
        self.remote_last_win = window >> self.remote_win_shift;

        if let Some((generator, offset, remote)) = timestamp {
            self.tsval_generator = Some(generator);
            self.timestamps_enabled = true;
            self.timestamp_offset = offset;
            self.last_remote_tsval = remote;
        }
    }

    /// Return whether TCP Timestamp is enabled.
    pub fn timestamp_enabled(&self) -> bool {
        self.timestamp_generator().is_some()
    }

    fn timestamp_generator(&self) -> Option<TcpTimestampGenerator> {
        self.tsval_generator.filter(|_| self.timestamps_enabled)
    }

    /// Set IPv4 options on SYN segments, including retransmissions. The optional
    /// destination is the next source-route hop; TCP checksums retain the peer.
    pub fn set_syn_ipv4_options(
        &mut self,
        options: &[crate::wire::Ipv4Option],
        destination: Option<core::net::Ipv4Addr>,
    ) -> Result<(), crate::wire::Ipv4OptionsError> {
        let bytes = crate::wire::encode_ipv4_options(options)?;
        self.syn_ipv4_options = crate::wire::Ipv4OptionBytes::new(&bytes);
        self.syn_ipv4_destination = destination;
        Ok(())
    }

    /// Adds `options` to this connection's SYN or SYN-ACK, and to every
    /// retransmission of it, after the socket's own options. Set them
    /// once the connection exists: after [`connect`](Socket::connect), or
    /// once a SYN has moved a listening socket to SYN-RECEIVED. The socket
    /// drops them when it forgets the connection.
    ///
    /// Fails, changing nothing, if they take more than
    /// [`SYN_OPTIONS_ROOM`] bytes or one would not read back as written.
    pub fn set_syn_options(&mut self, options: &[TcpOption]) -> Result<(), SynOptionsError> {
        self.syn_options = encode_options(options)?;
        Ok(())
    }

    /// Has `options` add options to every segment this connection sends
    /// from now on but its SYN and RSTs, and see every segment it takes.
    /// Set it once the handshake is done. The socket drops it when it
    /// forgets the connection.
    pub fn set_segment_options(&mut self, options: Box<dyn SegmentOptions>) {
        self.segment_options = Some(SegmentOptionsBox(options));
    }

    /// Applies newly installed options to data carried by the handshake ACK.
    /// The bytes are shown in the chunks they arrived in, each from the
    /// sequence number it starts at.
    pub fn process_handshake_data(&mut self, seq: u32, options: &[u8]) {
        let Some(hook) = self.segment_options.as_mut() else {
            return;
        };
        let mut at = seq;
        let mut verdict = Verdict::Take;
        let mut shown = false;
        for chunk in self.rx.unread() {
            let said = hook.0.received(&Incoming {
                seq: at,
                payload: chunk,
                fin: false,
                options,
            });
            verdict = verdict.and(said);
            shown = true;
            at = at.wrapping_add(chunk.len() as u32);
            if matches!(verdict, Verdict::Reset(_)) {
                break;
            }
        }
        // A handshake ACK with no data is shown too, as the segment it is.
        if !shown {
            verdict = hook.0.received(&Incoming {
                seq,
                payload: &[],
                fin: false,
                options,
            });
        }
        if self.heed(verdict) {
            return;
        }
        let Some(hook) = self.segment_options.as_mut() else {
            return;
        };
        let read = self.rx.len();
        let mut at = seq;
        let mut verdict = Verdict::Take;
        self.rx.rewrite(|mut chunk, budget| {
            let start = at;
            at = at.wrapping_add(chunk.len() as u32);
            if !matches!(verdict, Verdict::Reset(_)) {
                let said = hook.0.arrived(start, &mut chunk, budget);
                verdict = verdict.clone().and(said);
            }
            chunk
        });
        // What the options keep in place of the bytes moves the sequence
        // number of the next byte expected no further than they did.
        self.remote_seq_no += read;
        self.remote_seq_no = self.remote_seq_no - self.rx.len();
        self.heed(verdict);
    }

    /// Resets the connection, as [`abort`](Socket::abort) does, with a RST
    /// that carries `options`, whole options encoded with
    /// [`encode_options`].
    pub fn abort_with(&mut self, options: Vec<u8>) {
        self.rst_options = Some(options);
        self.abort();
    }

    /// Shows the segment options the bytes that just became contiguous,
    /// the first `contiguous` bytes waiting, from sequence number `seq`,
    /// chunk by chunk, and readies what they keep of each for reading. A
    /// chunk the options edit is edited in place, or copied once when
    /// shared; one they hold back is dropped, so the bytes received out of
    /// order after them keep their offsets, and the sequence number of the
    /// next byte expected stays where it was.
    fn arrived(&mut self, seq: TcpSeqNumber, contiguous: usize) -> Verdict {
        let mut taken = 0;
        let mut kept = 0;
        let mut verdict = Verdict::Take;
        while taken < contiguous {
            let mut chunk = self
                .rx
                .take_contiguous()
                .expect("the assembler's contiguous bytes are held");
            let at = seq + taken;
            taken += chunk.len();
            if matches!(verdict, Verdict::Reset(_)) {
                // The connection resets: nothing after is made readable.
                continue;
            }
            if let Some(options) = self.segment_options.as_mut() {
                let said = options.0.arrived(at.0 as u32, &mut chunk, self.rx.budget());
                verdict = verdict.and(said);
            }
            kept += chunk.len();
            self.rx.commit(chunk);
        }
        debug_assert_eq!(taken, contiguous);
        if kept == contiguous {
            return verdict;
        }
        self.remote_seq_no += contiguous;
        self.remote_seq_no = self.remote_seq_no - kept;
        let after = self.assembler.iter_data().last().map_or(0, |(_, end)| end);
        if self.rx.len() + after > self.rx.capacity()
            && let Some(options) = self.segment_options.as_mut()
        {
            let mut reset = Vec::new();
            options.0.reset(&mut reset);
            return Verdict::Reset(reset);
        }
        verdict
    }

    /// Acts on what the segment options said of a segment. Returns whether
    /// the socket reset the connection.
    fn heed(&mut self, verdict: Verdict) -> bool {
        match verdict {
            Verdict::Take => false,
            Verdict::Acknowledge => {
                self.ack_asked = true;
                false
            }
            Verdict::Reset(options) => {
                self.abort_with(options);
                true
            }
        }
    }

    /// Takes up a handshake that a listener answered without keeping any
    /// state: a SYN with sequence number `irs` from `remote` to `local`,
    /// answered by a SYN-ACK with sequence number `iss` that echoed
    /// nothing but a Maximum Segment Size, as a SYN cookie does (RFC 4987
    /// section 3.6). `remote_mss` is the peer's MSS as the cookie kept it,
    /// and `now` the time. The socket must be listening on `local`'s port.
    /// It is left in SYN-RECEIVED as if it had sent that SYN-ACK, with no
    /// window scaling, SACK or timestamps, so the ACK that returns the
    /// cookie, processed next, establishes the connection. The window it
    /// advertised is the receive buffer's capacity, at most 65,535.
    pub fn accept_syn_cookie(
        &mut self,
        local: IpEndpoint,
        remote: IpEndpoint,
        irs: u32,
        iss: u32,
        remote_mss: u16,
        now: Instant,
    ) {
        debug_assert_eq!(self.state, State::Listen);
        let (irs, iss) = (TcpSeqNumber(irs as i32), TcpSeqNumber(iss as i32));
        self.remote_mss =
            (remote_mss as usize).max(usize::from(self.settings.minimum_mss).max(MIN_REMOTE_MSS));
        self.congestion_controller.set_mss(self.remote_mss);
        self.remote_has_sack = false;
        self.remote_win_scale = None;
        self.remote_win_shift = 0;
        self.timestamps_enabled = false;
        self.tuple = Some(Tuple { local, remote });
        self.local_seq_no = iss;
        self.remote_seq_no = irs + 1;
        self.remote_last_seq = iss + 1;
        self.local_seq_max = iss + 1;
        self.remember_window(Some(irs + 1), self.scaled_window());
        self.set_state(State::SynReceived);
        self.timer.set_for_idle(now, self.keep_alive);
    }

    /// Register a waker for receive operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `recv` method calls, such as receiving data, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `recv` has
    ///   necessarily changed.
    ///
    /// Returns the displaced waker so an owner can drop it after unlocking.
    #[must_use = "drop the displaced waker after releasing the socket lock"]
    pub fn register_recv_waker(&mut self, waker: &Waker) -> Option<Waker> {
        self.rx_waker.register(waker)
    }

    /// Register a waker for send operations.
    ///
    /// The waker is woken on state changes that might affect the return value
    /// of `send` method calls, such as space becoming available in the transmit
    /// buffer, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously registered,
    ///   it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again to receive more wakes.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `send` has
    ///   necessarily changed.
    ///
    /// Returns the displaced waker so an owner can drop it after unlocking.
    #[must_use = "drop the displaced waker after releasing the socket lock"]
    pub fn register_send_waker(&mut self, waker: &Waker) -> Option<Waker> {
        self.tx_waker.register(waker)
    }

    /// Return the timeout duration.
    ///
    /// See also the [set_timeout](#method.set_timeout) method.
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Return the current window field value, including scaling according to RFC 1323.
    ///
    /// Used in internal calculations as well as packet generation.
    #[inline]
    fn scaled_window(&self) -> u16 {
        u16::try_from(self.rx.window() >> self.remote_win_shift).unwrap_or(u16::MAX)
    }

    /// Return the scaled window remaining to the furthest advertised edge.
    /// Received data consumes this window even before it is acknowledged.
    #[inline]
    fn last_scaled_window(&self) -> Option<u16> {
        let window_end = self.remote_win_end?;
        let next_ack = self.remote_seq_no + self.rx.len();
        let last_win_adjusted = window_end.max(next_ack) - next_ack;

        Some(u16::try_from(last_win_adjusted >> self.remote_win_shift).unwrap_or(u16::MAX))
    }

    fn receive_window_end(&self) -> TcpSeqNumber {
        let start = self.remote_seq_no + self.rx.len();
        self.remote_win_end
            .unwrap_or(start)
            .min(self.remote_seq_no + self.rx.capacity())
            .max(start)
    }

    fn remember_window(&mut self, ack: Option<TcpSeqNumber>, window: u16) {
        self.remote_last_ack = ack;
        self.remote_last_win = window;
        if let Some(ack) = ack {
            let end = (ack + ((window as usize) << self.remote_win_shift))
                .min(self.remote_seq_no + self.rx.capacity());
            self.remote_win_end = Some(self.remote_win_end.map_or(end, |old| old.max(end)));
        }
    }

    /// Set the timeout duration.
    ///
    /// A socket with a timeout duration set will abort the connection if either of the following
    /// occurs:
    ///
    ///   * After a [connect](#method.connect) call, the remote endpoint does not respond within
    ///     the specified duration;
    ///   * After establishing a connection, there is data in the transmit buffer and the remote
    ///     endpoint exceeds the specified duration between any two packets it sends;
    ///   * After enabling [keep-alive](#method.set_keep_alive), the remote endpoint exceeds
    ///     the specified duration between any two packets it sends.
    pub fn set_timeout(&mut self, duration: Option<Duration>) {
        self.timeout = duration
    }

    /// Set the ACK delay duration.
    ///
    /// By default, the ACK delay is set to 10ms.
    pub fn set_ack_delay(&mut self, duration: Option<Duration>) {
        self.ack_delay = duration
    }

    /// Enable or disable Nagle's Algorithm.
    ///
    /// Also known as "tinygram prevention". By default, it is enabled.
    /// Disabling it is equivalent to Linux's TCP_NODELAY flag.
    ///
    /// When enabled, Nagle's Algorithm prevents sending segments smaller than MSS if
    /// there is data in flight (sent but not acknowledged). In other words, it ensures
    /// at most only one segment smaller than MSS is in flight at a time.
    ///
    /// It ensures better network utilization by preventing sending many very small packets,
    /// at the cost of increased latency in some situations, particularly when the remote peer
    /// has ACK delay enabled.
    pub fn set_nagle_enabled(&mut self, enabled: bool) {
        self.nagle = enabled
    }

    /// Set the keep-alive interval.
    ///
    /// An idle socket with a keep-alive interval set will transmit a "keep-alive ACK" packet
    /// every time it receives no communication during that interval. As a result, three things
    /// may happen:
    ///
    ///   * The remote endpoint is fine and answers with an ACK packet.
    ///   * The remote endpoint has rebooted and answers with an RST packet.
    ///   * The remote endpoint has crashed and does not answer.
    ///
    /// The keep-alive functionality together with the timeout functionality allows to react
    /// to these error conditions.
    pub fn set_keep_alive(&mut self, interval: Option<Duration>) {
        self.keep_alive = interval;
        if self.keep_alive.is_some() {
            // If the connection is idle and we've just set the option, it would not take effect
            // until the next packet, unless we wind up the timer explicitly.
            self.timer.set_keep_alive();
        }
    }

    /// Starts the configured idle interval at `timestamp` for an established
    /// socket whose keep-alive setting changed outside packet processing.
    pub fn restart_keep_alive(&mut self, timestamp: Instant) {
        self.timer.rewind_keep_alive(timestamp, self.keep_alive);
    }

    /// Return the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// See also the [set_hop_limit](#method.set_hop_limit) method
    pub fn hop_limit(&self) -> Option<u8> {
        self.hop_limit
    }

    /// Set the time-to-live (IPv4) or hop limit (IPv6) value used in outgoing packets.
    ///
    /// A socket without an explicitly set hop limit value uses the default [IANA recommended]
    /// value (64).
    ///
    /// # Panics
    ///
    /// This function panics if a hop limit value of 0 is given. See [RFC 1122 § 3.2.1.7].
    ///
    /// [IANA recommended]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
    /// [RFC 1122 § 3.2.1.7]: https://tools.ietf.org/html/rfc1122#section-3.2.1.7
    pub fn set_hop_limit(&mut self, hop_limit: Option<u8>) {
        // A host MUST NOT send a datagram with a hop limit value of 0
        if let Some(0) = hop_limit {
            panic!("the time-to-live value of a packet must not be zero")
        }

        self.hop_limit = hop_limit
    }

    /// Return the local endpoint, or None if not connected.
    #[inline]
    pub fn local_endpoint(&self) -> Option<IpEndpoint> {
        Some(self.tuple?.local)
    }

    /// Return the remote endpoint, or None if not connected.
    #[inline]
    pub fn remote_endpoint(&self) -> Option<IpEndpoint> {
        Some(self.tuple?.remote)
    }

    /// Return the connection state, in terms of the TCP state machine.
    #[inline]
    pub fn state(&self) -> State {
        self.state
    }

    fn reset(&mut self) {
        self.rx.clear();
        self.rx_fin_received = false;
        self.forget_connection();
    }

    /// Closes the socket and forgets its connection, but keeps the bytes
    /// the application has not read, and the peer's FIN after them. Those
    /// bytes were acknowledged, so they stay readable until read.
    fn forget_connection(&mut self) {
        let rx_cap_log2 = mem::size_of::<usize>() * 8 - self.rx.capacity().leading_zeros() as usize;

        self.state = State::Closed;
        self.timer = Timer::new();
        self.rtte = RttEstimator::default();
        self.assembler = Assembler::new();
        self.tx.clear();
        self.listen_endpoint = None;
        self.tuple = None;
        self.local_seq_no = TcpSeqNumber::default();
        self.remote_seq_no = TcpSeqNumber::default();
        self.remote_last_seq = TcpSeqNumber::default();
        self.local_seq_max = TcpSeqNumber::default();
        self.remote_last_ack = None;
        self.remote_last_win = 0;
        self.remote_win_end = None;
        self.remote_win_len = 0;
        self.remote_win_scale = None;
        self.remote_win_shift = self
            .settings
            .window_scale
            .unwrap_or(rx_cap_log2.saturating_sub(16).min(14) as u8)
            .min(14);
        self.remote_mss = DEFAULT_MSS;
        self.remote_last_ts = None;
        self.timestamps_enabled = true;
        self.remote_has_sack = false;
        self.local_rx_last_seq = None;
        self.local_rx_last_ack = None;
        self.local_rx_dup_acks = 0;
        self.pending_fast_retransmit = false;
        self.ack_delay_timer = AckDelayTimer::Idle;
        self.challenge_ack_timer = Instant::from_secs(0);
        self.closed_before_syn_ack = false;
        self.last_remote_tsval = 0;
        self.congestion_controller = reno::Reno::new();
        self.syn_options = Vec::new();
        self.syn_ipv4_options = crate::wire::Ipv4OptionBytes::EMPTY;
        self.syn_ipv4_destination = None;
        self.segment_options = None;
        self.ack_asked = false;
        self.rst_options = None;

        {
            self.rx_waker.wake();
            self.tx_waker.wake();
        }
    }

    /// Start listening on the given endpoint.
    ///
    /// Every port is a literal wire port, including zero. An already open
    /// socket must still be listening on this endpoint.
    pub fn listen<T>(&mut self, local_endpoint: T) -> Result<(), ListenError>
    where
        T: Into<IpListenEndpoint>,
    {
        let local_endpoint = local_endpoint.into();
        if self.is_open() {
            // Listening again on the same endpoint preserves pending connections.
            if matches!(self.state, State::Listen) && self.listen_endpoint == Some(local_endpoint) {
                return Ok(());
            } else {
                return Err(ListenError::InvalidState);
            }
        }

        self.reset();
        self.listen_endpoint = Some(local_endpoint);
        self.tuple = None;
        self.set_state(State::Listen);
        Ok(())
    }

    /// Connect to a given endpoint.
    ///
    /// Both endpoints must specify an address. Ports are literal wire ports,
    /// including zero.
    /// Returns an error if the socket is already open or either endpoint is invalid.
    ///
    /// ```no_run
    /// # use smoltcp::socket::tcp::Socket;
    /// # use fictionet_buf::{Budget, Pool};
    /// # use smoltcp::iface::Context;
    /// #
    /// # fn get_ephemeral_port() -> u16 {
    /// #     49152
    /// # }
    /// #
    /// # let budget = Budget::unlimited();
    /// # let pool = Pool::new(&budget, 2048, 64);
    /// # let mut socket = Socket::new(1200, 1200, budget, &pool);
    /// #
    /// # let mut context: Context = todo!();
    /// #
    /// socket.connect(
    ///     &mut context,
    ///     ("10.0.0.1".parse::<core::net::IpAddr>().unwrap(), 80),
    ///     ("10.0.0.2".parse::<core::net::IpAddr>().unwrap(), get_ephemeral_port())
    /// ).unwrap();
    /// ```
    pub fn connect<T, U>(
        &mut self,
        cx: &mut Context,
        remote_endpoint: T,
        local_endpoint: U,
    ) -> Result<(), ConnectError>
    where
        T: Into<IpEndpoint>,
        U: Into<IpEndpoint>,
    {
        let remote_endpoint: IpEndpoint = remote_endpoint.into();
        let local_endpoint: IpEndpoint = local_endpoint.into();

        if self.is_open() {
            return Err(ConnectError::InvalidState);
        }
        if remote_endpoint.addr.is_unspecified() {
            return Err(ConnectError::Unaddressable);
        }
        if local_endpoint.addr.is_unspecified() {
            return Err(ConnectError::Unaddressable);
        }

        if local_endpoint.addr.version() != remote_endpoint.addr.version() {
            return Err(ConnectError::Unaddressable);
        }

        self.reset();
        self.tuple = Some(Tuple {
            local: local_endpoint,
            remote: remote_endpoint,
        });
        self.set_state(State::SynSent);

        let seq = cx.initial_seq(local_endpoint, remote_endpoint);
        self.local_seq_no = seq;
        self.remote_last_seq = seq;
        self.local_seq_max = seq;
        Ok(())
    }

    /// Close the transmit half of the full-duplex connection.
    ///
    /// Note that there is no corresponding function for the receive half of the full-duplex
    /// connection; only the remote end can close it. If you no longer wish to receive any
    /// data and would like to reuse the socket right away, use [abort](#method.abort).
    pub fn close(&mut self) {
        match self.state {
            // In the LISTEN state there is no established connection.
            State::Listen => self.set_state(State::Closed),
            // RFC 9293 section 3.10.4 closes SYN-SENT without sending a reset.
            State::SynSent => {
                self.tuple = None;
                self.set_state(State::Closed);
            }
            // In the SYN-RECEIVED, ESTABLISHED and CLOSE-WAIT states the transmit half
            // of the connection is open, and needs to be explicitly closed with a FIN.
            // A SYN not yet acknowledged goes first; the FIN follows its ACK.
            State::SynReceived => {
                self.set_state(State::FinWait1);
                self.closed_before_syn_ack = true;
            }
            State::Established => {
                self.start_talking();
                self.set_state(State::FinWait1);
            }
            State::CloseWait => {
                self.start_talking();
                self.set_state(State::LastAck);
            }
            // In the FIN-WAIT-1, FIN-WAIT-2, CLOSING, LAST-ACK, TIME-WAIT and CLOSED states,
            // the transmit half of the connection is already closed, and no further
            // action is needed.
            State::FinWait1
            | State::FinWait2
            | State::Closing
            | State::TimeWait
            | State::LastAck
            | State::Closed => (),
        }
    }

    /// The local endpoint is about to send its FIN. On a socket with nothing
    /// to send, which may have been quiet for long, the timeout then counts
    /// from the FIN, as it counts from the first data queued on such a
    /// socket, and not from the last packet received.
    fn start_talking(&mut self) {
        if self.tx.is_empty() {
            self.remote_last_ts = None;
        }
    }

    /// Aborts the connection, if any.
    ///
    /// This function instantly closes the socket. One reset packet will be sent to the remote
    /// endpoint.
    ///
    /// In terms of the TCP state machine, the socket may be in any state and is moved to
    /// the `CLOSED` state.
    pub fn abort(&mut self) {
        self.set_state(State::Closed);
    }

    /// Whether the SYN this socket sent still waits for its acknowledgement.
    fn syn_unacked(&self) -> bool {
        match self.state {
            State::SynSent | State::SynReceived => true,
            State::FinWait1 | State::Closing => self.closed_before_syn_ack,
            _ => false,
        }
    }

    fn is_open(&self) -> bool {
        !matches!(self.state, State::Closed | State::TimeWait)
    }

    fn may_send(&self) -> bool {
        matches!(self.state, State::Established | State::CloseWait)
    }

    fn may_recv(&self) -> bool {
        matches!(
            self.state,
            State::Established | State::FinWait1 | State::FinWait2
        ) || self.can_recv()
    }

    /// Return the maximum number of bytes inside the recv buffer.
    #[inline]
    pub fn recv_capacity(&self) -> usize {
        self.rx.capacity()
    }

    /// Return the maximum number of bytes inside the transmit buffer.
    #[inline]
    pub fn send_capacity(&self) -> usize {
        self.tx.capacity()
    }

    /// Check whether the receive buffer is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        !self.rx.is_empty()
    }

    /// Queues all of `chunk` to send, retaining it until the peer
    /// acknowledges it, or none of it: refused, with the chunk back, when
    /// the connection may not send or the send buffer has no room for all
    /// of it. A chunk of at least 128 bytes is kept as it is, so a chunk
    /// with [`HEADROOM`] that fits a segment can go out with no copy.
    pub fn push(&mut self, chunk: Chunk) -> Result<(), (SendError, Chunk)> {
        if !self.may_send() {
            return Err((SendError::InvalidState, chunk));
        }

        let old_length = self.tx.len();
        let size = chunk.len();
        self.tx
            .push(chunk)
            .map_err(|chunk| (SendError::Full, chunk))?;
        if size > 0 {
            // Start the send timeout when queued data first leaves an idle socket.
            if old_length == 0 {
                self.remote_last_ts = None
            }

            // if remote win is zero and we go from having no data to some data pending to
            // send, start the zero window probe timer.
            if self.remote_win_len == 0 && self.timer.is_idle() {
                let delay = self.rtte.retransmission_timeout();

                // We don't have access to the current time here, so use Instant::ZERO instead.
                // this will cause the first ZWP to be sent immediately, but that's okay.
                self.timer.set_for_zero_window_probe(Instant::ZERO, delay);
            }
        }
        Ok(())
    }

    fn recv_error_check(&mut self) -> Result<(), RecvError> {
        // Receive data only after the handshake; TCP Fast Open is not supported.
        if !self.may_recv() {
            if self.rx_fin_received {
                return Err(RecvError::Finished);
            }
            return Err(RecvError::InvalidState);
        }

        Ok(())
    }

    /// Takes up to `most` bytes received in order, as the chunk they
    /// arrived in or a piece of it, with no copy: at most one chunk's bytes
    /// at a time. `None` when nothing is ready yet.
    ///
    /// This function errors if the receive half of the connection is not open.
    ///
    /// After FIN and buffered data, returns [`RecvError::Finished`].
    /// Other closed states return [`RecvError::InvalidState`].
    pub fn pop(&mut self, most: usize) -> Result<Option<Chunk>, RecvError> {
        self.recv_error_check()?;
        let chunk = self.rx.pop(most);
        if let Some(chunk) = &chunk {
            self.remote_seq_no += chunk.len();
        }
        Ok(chunk)
    }

    /// Return the amount of octets queued in the transmit buffer.
    ///
    /// Note that the Berkeley sockets interface does not have an equivalent of this API.
    pub fn send_queue(&self) -> usize {
        self.tx.len()
    }

    /// Number of octets transmitted but not yet ACKed.
    fn flight_size(&self) -> usize {
        self.remote_last_seq - self.local_seq_no
    }

    fn cwnd_remaining(&self) -> usize {
        self.congestion_controller
            .window()
            .saturating_sub(self.flight_size())
    }

    /// Return all queued receive bytes, including bytes across the ring boundary.
    pub fn recv_queue(&self) -> usize {
        self.rx.len()
    }

    /// The memory the chunks the socket retains keep alive, received and
    /// queued to send, counting a backing once for every chunk that holds
    /// it: none on a connection with nothing to read, send or reassemble.
    pub fn held(&self) -> usize {
        self.rx.held() + self.tx.held()
    }

    /// Whether received data is waiting for a gap to fill before it can be read.
    /// These bytes are not included in [`Self::recv_queue`].
    pub fn has_pending_recv(&self) -> bool {
        !self.assembler.is_empty()
    }

    fn set_state(&mut self, state: State) {
        self.state = state;

        {
            // Wake all tasks waiting. Even if we haven't received/sent data, this
            // is needed because return values of functions may change depending on the state.
            // For example, a pending read has to fail with an error if the socket is closed.
            self.rx_waker.wake();
            self.tx_waker.wake();
        }
    }

    fn reply(ip_repr: &IpRepr, repr: &TcpRepr) -> (IpRepr, TcpRepr<'static>) {
        let reply_repr = TcpRepr {
            src_port: repr.dst_port,
            dst_port: repr.src_port,
            control: TcpControl::None,
            seq_number: TcpSeqNumber(0),
            ack_number: None,
            window_len: 0,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            extra: &[],
            layout: crate::wire::OptionLayout {
                order: crate::wire::OptionOrder::WindowBeforeSack,
                align: false,
            },
            timestamp: None,
            payload: &[],
        };
        let ip_reply_repr = IpRepr::new(
            ip_repr.dst_addr(),
            ip_repr.src_addr(),
            IpProtocol::Tcp,
            reply_repr.buffer_len(),
            64,
        );
        (ip_reply_repr, reply_repr)
    }

    pub fn rst_reply(ip_repr: &IpRepr, repr: &TcpRepr) -> (IpRepr, TcpRepr<'static>) {
        debug_assert!(repr.control != TcpControl::Rst);

        let (ip_reply_repr, mut reply_repr) = Self::reply(ip_repr, repr);

        // A reset acknowledges segments that arrive without an ACK.
        reply_repr.control = TcpControl::Rst;
        reply_repr.seq_number = repr.ack_number.unwrap_or_default();
        if repr.ack_number.is_none() {
            reply_repr.ack_number = Some(repr.seq_number + repr.segment_len());
        }

        (ip_reply_repr, reply_repr)
    }

    fn ack_reply(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
    ) -> (IpRepr, TcpRepr<'static>) {
        let (mut ip_reply_repr, mut reply_repr) = Self::reply(ip_repr, repr);
        reply_repr.timestamp = TcpTimestampRepr::generate_reply_with_tsval(
            self.timestamp_generator(),
            self.last_remote_tsval,
            cx.now(),
        )
        .map(|mut ts| {
            ts.tsval = ts.tsval.wrapping_add(self.timestamp_offset);
            ts
        });
        reply_repr.layout = self.settings.layout;

        // From RFC 793:
        // [...] an empty acknowledgment segment containing the current send-sequence number
        // and an acknowledgment indicating the next sequence number expected
        // to be received.
        reply_repr.seq_number = self.send_next();
        reply_repr.ack_number = Some(self.remote_seq_no + self.rx.len());

        // From RFC 1323:
        // The window field [...] of every outgoing segment, with the exception of SYN
        // segments, is right-shifted by [advertised scale value] bits[...]
        reply_repr.window_len = self.scaled_window();
        self.remember_window(reply_repr.ack_number, reply_repr.window_len);

        // If the remote supports selective acknowledgement, add the option to the outgoing
        // segment.
        if self.remote_has_sack {
            // RFC 2018: The first SACK block (i.e., the one immediately following the kind and
            // length fields in the option) MUST specify the contiguous block of data containing
            // the segment which triggered this ACK, unless that segment advanced the
            // Acknowledgment Number field in the header.
            reply_repr.sack_ranges[0] = None;

            let ack = reply_repr.ack_number.unwrap_or(TcpSeqNumber(0));

            if let Some(last_seg_seq) = self.local_rx_last_seq {
                reply_repr.sack_ranges[0] = self
                    .assembler
                    .iter_data()
                    .map(|(left, right)| (ack + left, ack + right))
                    .find(|&(left, right)| left <= last_seg_seq && right >= last_seg_seq)
                    .map(|(left, right)| (left.0 as u32, right.0 as u32));
            }

            if reply_repr.sack_ranges[0].is_none() {
                // The matching segment was removed from the assembler, meaning the acknowledgement
                // number has advanced, or there was no previous sACK.
                //
                // While the RFC says we SHOULD keep a list of reported sACK ranges, and iterate
                // through those, that is currently infeasible. Instead, we offer the range with
                // the lowest sequence number (if one exists) to hint at what segments would
                // most quickly advance the acknowledgement number.
                reply_repr.sack_ranges[0] = self
                    .assembler
                    .iter_data()
                    .map(|(left, right)| (ack + left, ack + right))
                    .next()
                    .map(|(left, right)| (left.0 as u32, right.0 as u32));
            }
        }

        // Since the sACK option may have changed the length of the payload, update that.
        ip_reply_repr.set_payload_len(reply_repr.buffer_len());
        self.identify_ipv4(&mut ip_reply_repr);
        self.advance_ipv4_identification(&ip_reply_repr);
        (ip_reply_repr, reply_repr)
    }

    /// The sequence number of a segment that occupies no sequence space:
    /// the highest one sent, which the peer may already have. An RTO rewinds
    /// `remote_last_seq` for retransmission, and a peer that has the
    /// rewound bytes finds that number behind its window.
    fn send_next(&self) -> TcpSeqNumber {
        self.local_seq_max
    }

    fn challenge_ack_reply(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
    ) -> Option<(IpRepr, TcpRepr<'static>)> {
        if cx.now() < self.challenge_ack_timer {
            return None;
        }

        self.challenge_ack_timer = cx.now() + self.settings.challenge_ack_interval;

        Some(self.ack_reply(cx, ip_repr, repr))
    }

    pub fn accepts(&self, _cx: &mut Context, ip_repr: &IpRepr, repr: &TcpRepr) -> bool {
        if self.state == State::Closed {
            return false;
        }

        // If we're still listening for SYNs and the packet has an ACK or a RST,
        // it cannot be destined to this socket, but another one may well listen
        // on the same local endpoint.
        if self.state == State::Listen
            && (repr.ack_number.is_some() || repr.control == TcpControl::Rst)
        {
            return false;
        }

        if let Some(tuple) = &self.tuple {
            // Reject packets not matching the 4-tuple
            ip_repr.dst_addr() == tuple.local.addr
                && repr.dst_port == tuple.local.port
                && ip_repr.src_addr() == tuple.remote.addr
                && repr.src_port == tuple.remote.port
        } else if let Some(endpoint) = self.listen_endpoint {
            // We're listening, reject packets not matching the listen endpoint.
            let addr_ok = match endpoint.addr {
                Some(addr) => ip_repr.dst_addr() == addr,
                None => true,
            };
            addr_ok && repr.dst_port == endpoint.port
        } else {
            false
        }
    }

    fn segment_in_window(
        repr: &TcpRepr,
        window_start: TcpSeqNumber,
        window_end: TcpSeqNumber,
    ) -> bool {
        let segment_start = repr.seq_number;
        let segment_end =
            segment_start + repr.payload.len() + usize::from(repr.control == TcpControl::Fin);
        match (segment_start == segment_end, window_start == window_end) {
            (true, _) if segment_end == window_start - 1 => false,
            (true, true) => window_start == segment_start,
            (true, false) => {
                // A peer that filled the window sends its next ACK at the right edge.
                window_start <= segment_start
                    && (segment_start < window_end
                        || (segment_start == window_end
                            && repr.control.quash_psh() == TcpControl::None))
            }
            // A segment at the start of a closed window, such as a probe, is
            // acceptable for its ACK and window; its text is dropped. RFC 9293
            // section 3.10.7.4 asks that valid ACKs be accepted in a zero window.
            (false, true) => segment_start == window_start,
            (false, false) => {
                (window_start <= segment_start && segment_start < window_end)
                    || (window_start < segment_end && segment_end <= window_end)
            }
        }
    }

    /// Takes a segment: `repr`, whose options are `options` as they
    /// are on the wire, and whose payload is `payload`, the same bytes as
    /// `repr.payload` in the chunk they arrived in. The bytes the socket
    /// keeps are pieces of that chunk, not copies.
    pub fn process(
        &mut self,
        cx: &mut Context,
        ip_repr: &IpRepr,
        repr: &TcpRepr,
        options: &[u8],
        payload: &Chunk,
    ) -> Option<(IpRepr, TcpRepr<'static>)> {
        debug_assert!(self.accepts(cx, ip_repr, repr));
        debug_assert!(**payload == *repr.payload, "the payload is the segment's");
        let arrived_in = payload;

        if self.settings.repeat_syn_ack
            && self.state == State::SynReceived
            && repr.control == TcpControl::Syn
            && repr.ack_number.is_none()
            && repr.seq_number + 1 == self.remote_seq_no
        {
            self.remote_last_seq = self.local_seq_no;
            self.timer.set_for_idle(cx.now(), self.keep_alive);
            return None;
        }
        if repr.control == TcpControl::Syn && !matches!(self.state, State::Listen | State::SynSent)
        {
            return self.challenge_ack_reply(cx, ip_repr, repr);
        }

        // Consider how much the sequence number space differs from the transmit buffer space.
        // A SYN not yet acknowledged sits before the data.
        let sent_syn = self.syn_unacked();
        // In FIN-WAIT-1, LAST-ACK, or CLOSING, we've just sent a FIN.
        let sent_fin = matches!(
            self.state,
            State::FinWait1 | State::LastAck | State::Closing
        );

        // Reject unacceptable acknowledgements.
        match (self.state, repr.control, repr.ack_number) {
            // An RST received in response to initial SYN is acceptable if it acknowledges
            // the initial SYN.
            (State::SynSent, TcpControl::Rst, None) => {
                return None;
            }
            (State::SynSent, TcpControl::Rst, Some(ack_number)) => {
                if !self.acknowledges_syn(ack_number) {
                    return None;
                }
            }
            // Any other RST need only have a valid sequence number.
            (_, TcpControl::Rst, _) => (),
            // The initial SYN cannot contain an acknowledgement.
            (State::Listen, _, None) => (),
            // This case is handled in `accepts()`.
            (State::Listen, _, Some(_)) => unreachable!(),
            // SYN|ACK in the SYN-SENT state must have the exact ACK number.
            (State::SynSent, TcpControl::Syn, Some(ack_number)) => {
                if !self.acknowledges_syn(ack_number) {
                    return Some(Self::rst_reply(ip_repr, repr));
                }
            }
            // TCP simultaneous open.
            // This is required by RFC 9293, which states "A TCP implementation MUST support
            // simultaneous open attempts (MUST-10)."
            (State::SynSent, TcpControl::Syn, None) => (),
            // ACKs in the SYN-SENT state are invalid.
            (State::SynSent, TcpControl::None, Some(ack_number)) => {
                // Ignore an ACK of our SYN without the peer's SYN.
                if self.acknowledges_syn(ack_number) {
                    return None;
                }

                return Some(Self::rst_reply(ip_repr, repr));
            }
            // Anything else in the SYN-SENT state is invalid.
            (State::SynSent, _, _) => {
                return None;
            }
            // Every packet after the initial SYN must be an acknowledgement.
            (_, _, None) => {
                return None;
            }
            // ACK in the SYN-RECEIVED state must have the exact ACK number, or we RST it.
            (State::SynReceived, _, Some(ack_number)) => {
                if !self.acknowledges_syn(ack_number) {
                    return Some(Self::rst_reply(ip_repr, repr));
                }
            }
            // Every acknowledgement must be for transmitted but unacknowledged data.
            (_, _, Some(ack_number)) => {
                if ack_number >= self.local_seq_no && ack_number > self.local_seq_max {
                    return self.challenge_ack_reply(cx, ip_repr, repr);
                }
            }
        }

        let window_start = self.remote_seq_no + self.rx.len();
        let window_end = self.receive_window_end();
        let segment_start = repr.seq_number;
        let segment_end = repr.seq_number + repr.payload.len();

        if repr.control == TcpControl::Rst
            && self.state != State::SynSent
            && segment_start != window_start
        {
            return if window_start <= segment_start && segment_start < window_end {
                self.challenge_ack_reply(cx, ip_repr, repr)
            } else {
                None
            };
        }

        // Text sent into a closed window, such as a zero-window probe's, is
        // dropped; the segment counts for its ACK and is answered with one.
        let mut dropped_probe = false;
        let (payload_range, payload_offset) = match self.state {
            _ if repr.control == TcpControl::Rst => (0..0, 0),
            // In LISTEN and SYN-SENT states, we have not yet synchronized with the remote end.
            State::Listen | State::SynSent => (0..0, 0),
            _ => {
                if Self::segment_in_window(repr, window_start, window_end) {
                    let overlap_start = window_start.max(segment_start);
                    let overlap_end = window_end.min(segment_end);

                    // the checks done above imply this.
                    debug_assert!(overlap_start <= overlap_end);

                    self.local_rx_last_seq = Some(repr.seq_number);
                    dropped_probe = window_start == window_end && !repr.payload.is_empty();

                    if self.rx_fin_received {
                        // RFC 9293 section 3.10.7.4: the remote sends nothing after its
                        // FIN, so the text of a segment past it is ignored.
                        (0..0, 0)
                    } else {
                        (
                            overlap_start - segment_start..overlap_end - segment_start,
                            overlap_start - window_start,
                        )
                    }
                } else {
                    // If we're in the TIME-WAIT state, restart the TIME-WAIT timeout, since
                    // the remote end may not have realized we've closed the connection.
                    if self.state == State::TimeWait {
                        self.timer.set_for_close(cx.now(), self.settings.time_wait);
                    }

                    // ACK data and FIN retransmissions per RFC 9293 sections 3.10.7.4 and
                    // 3.8.6.1; rate-limit other challenges per RFC 5961 sections 4.2 and 7.
                    if !repr.payload.is_empty()
                        && matches!(
                            repr.control,
                            TcpControl::None | TcpControl::Psh | TcpControl::Fin
                        )
                    {
                        return Some(self.ack_reply(cx, ip_repr, repr));
                    }

                    return self.challenge_ack_reply(cx, ip_repr, repr);
                }
            }
        };
        let payload = &repr.payload[payload_range.clone()];

        // Compute the amount of acknowledged octets, removing the SYN and FIN bits
        // from the sequence space.
        let mut ack_len = 0;
        let mut ack_of_fin = false;
        let mut ack_all = false;
        if repr.control != TcpControl::Rst
            && let Some(ack_number) = repr.ack_number
        {
            // Sequence number corresponding to the first byte in `tx`.
            // This normally equals `local_seq_no`, but is 1 higher if we have sent a SYN,
            // as the SYN occupies 1 sequence number "before" the data.
            let tx_start_seq = self.local_seq_no + (sent_syn as usize);

            if ack_number >= tx_start_seq {
                ack_len = ack_number - tx_start_seq;

                // We could've sent data before the FIN, so only remove FIN from the sequence
                // space if all of that data is acknowledged.
                if sent_fin && self.tx.len() + 1 == ack_len {
                    ack_len -= 1;

                    ack_of_fin = true;
                }

                ack_all = self.remote_last_seq <= ack_number;
            }
        }

        // Disregard control flags we don't care about or shouldn't act on yet.
        let mut control = repr.control;
        control = control.quash_psh();

        // Ignore a FIN past a gap or outside the receive window.
        if control == TcpControl::Fin && (window_start < segment_start || segment_end > window_end)
        {
            control = TcpControl::None;
        }

        // Apply the acknowledgement now, but accept a FIN only after its
        // payload has been retained. A refused allocation must leave the
        // receive side open for a retransmission.
        let state_control = if control == TcpControl::Fin {
            TcpControl::None
        } else {
            control
        };
        match (self.state, state_control) {
            // RSTs are not accepted in the LISTEN state.
            (State::Listen, TcpControl::Rst) => return None,

            // RSTs in SYN-RECEIVED flip the socket back to the LISTEN state.
            // Here we need to additionally check `listen_endpoint`, because we want to make sure
            // that SYN-RECEIVED was actually converted from the LISTEN state (another possible
            // reason is TCP simultaneous open).
            // Nothing of the old peer's connection carries over to the next one.
            (State::SynReceived, TcpControl::Rst) if self.listen_endpoint.is_some() => {
                let listen_endpoint = self.listen_endpoint;
                self.reset();
                self.listen_endpoint = listen_endpoint;
                self.set_state(State::Listen);
                return None;
            }

            // RSTs in any other state close the socket.
            (_, TcpControl::Rst) => {
                self.set_state(State::Closed);
                self.tuple = None;
                return None;
            }

            // SYN packets in the LISTEN state change it to SYN-RECEIVED.
            (State::Listen, TcpControl::Syn) => {
                self.negotiate_options(repr);

                let local = IpEndpoint::new(ip_repr.dst_addr(), repr.dst_port);
                let remote = IpEndpoint::new(ip_repr.src_addr(), repr.src_port);
                self.tuple = Some(Tuple { local, remote });
                self.local_seq_no = cx.initial_seq(local, remote);
                self.remote_seq_no = repr.seq_number + 1;
                self.remote_last_seq = self.local_seq_no;
                self.local_seq_max = self.local_seq_no;
                self.set_state(State::SynReceived);
                self.timer.set_for_idle(cx.now(), self.keep_alive);
            }

            // ACK packets in the SYN-RECEIVED state change it to ESTABLISHED.
            (State::SynReceived, TcpControl::None) => {
                self.set_state(State::Established);
            }

            // SYN|ACK packets in the SYN-SENT state change it to ESTABLISHED.
            // SYN packets in the SYN-SENT state change it to SYN-RECEIVED.
            (State::SynSent, TcpControl::Syn) => {
                self.negotiate_options(repr);

                // Our SYN may not have gone out yet; if not, the SYN|ACK is
                // still to send. The ACK below moves past a SYN it acknowledges.
                self.remote_seq_no = repr.seq_number + 1;
                self.remote_last_ack = Some(repr.seq_number);
                self.remote_win_end = Some(
                    self.remote_seq_no
                        + ((self.remote_last_win as usize) << self.remote_win_shift)
                            .min(self.rx.capacity()),
                );

                if repr.ack_number.is_some() {
                    self.set_state(State::Established);
                } else {
                    self.set_state(State::SynReceived);
                }
            }

            (State::Established, TcpControl::None) => {}

            // ACK packets in FIN-WAIT-1 state change it to FIN-WAIT-2, if we've already
            // sent everything in the transmit buffer. If not, they reset the retransmit timer.
            (State::FinWait1, TcpControl::None) => {
                if ack_of_fin {
                    self.set_state(State::FinWait2);
                }
            }

            (State::FinWait2, TcpControl::None) => {}

            // ACK packets in CLOSING state change it to TIME-WAIT.
            (State::Closing, TcpControl::None) => {
                if ack_of_fin {
                    self.set_state(State::TimeWait);
                    self.timer.set_for_close(cx.now(), self.settings.time_wait);
                }
            }

            (State::CloseWait, TcpControl::None) => {}

            // ACK packets in LAST-ACK state change it to CLOSED.
            (State::LastAck, TcpControl::None) => {
                if ack_of_fin {
                    // Clear the remote endpoint, or we'll send an RST there.
                    self.set_state(State::Closed);
                    self.tuple = None;
                }
            }

            _ => {
                return None;
            }
        }

        // Update remote state.
        self.remote_last_ts = Some(cx.now());

        if let Some(segment_options) = self.segment_options.as_mut() {
            let verdict = segment_options.0.received(&Incoming {
                seq: repr.seq_number.0 as u32,
                payload: repr.payload,
                fin: control == TcpControl::Fin,
                options,
            });
            if self.heed(verdict) {
                return None;
            }
        }

        // RFC 1323: The window field (SEG.WND) in the header of every incoming segment, with the
        // exception of SYN segments, is left-shifted by Snd.Wind.Scale bits before updating SND.WND.
        let scale = match repr.control {
            TcpControl::Syn => 0,
            _ => self.remote_win_scale.unwrap_or(0),
        };
        let old_ack = repr.ack_number.is_some_and(|ack| ack < self.local_seq_no);
        let new_remote_win_len = if old_ack {
            self.remote_win_len
        } else {
            (repr.window_len as usize) << (scale as usize)
        };
        let is_duplicate_ack = self.is_duplicate_ack(repr, new_remote_win_len);
        let window_reopened = self.remote_win_len == 0 && new_remote_win_len != 0;
        self.remote_win_len = new_remote_win_len;

        self.congestion_controller
            .set_remote_window(new_remote_win_len);

        if ack_len > 0 {
            // Dequeue acknowledged octets.
            debug_assert!(self.tx.len() >= ack_len);

            self.tx.ack(ack_len);

            // There's new room available in tx, wake the waiting task if any.

            self.tx_waker.wake();
        }

        if let Some(ack_number) = repr.ack_number.filter(|_| !old_ack) {
            if is_duplicate_ack {
                self.local_rx_dup_acks = self.local_rx_dup_acks.saturating_add(1);
                if self.local_rx_dup_acks == 3 {
                    self.timer.set_for_fast_retransmit();
                }
                self.congestion_controller.on_dup_ack(self.remote_mss);
            } else {
                self.local_rx_dup_acks = 0;
                self.local_rx_last_ack = Some(ack_number);
                self.rtte.on_ack(cx.now(), ack_number);
                self.congestion_controller.on_ack(ack_len);
            }

            if sent_syn && ack_number > self.local_seq_no {
                self.closed_before_syn_ack = false;
            }
            self.local_seq_no = ack_number;

            // Skip retransmissions of bytes already acknowledged.
            if self.remote_last_seq < self.local_seq_no {
                self.remote_last_seq = self.local_seq_no
            }

            // Retry data the peer may have refused when its window closed.
            // Keep the running retransmission timer and congestion window.
            if window_reopened && !self.tx.is_empty() && self.local_seq_no < self.remote_last_seq {
                self.pending_fast_retransmit = true;
            }
        }

        // update last remote tsval
        if let Some(timestamp) = repr.timestamp {
            self.last_remote_tsval = timestamp.tsval;
        }

        self.update_ack_timer(cx.now(), ack_len, ack_all);

        let payload_len = payload.len();
        if payload_len == 0 {
            if control == TcpControl::Fin {
                self.receive_fin(cx.now());
            }
            return dropped_probe.then(|| self.ack_reply(cx, ip_repr, repr));
        }

        let assembler_was_empty = self.assembler.is_empty();

        // Try adding payload octets to the assembler, then keeping the
        // pieces of the segment's chunk the store does not hold yet. A
        // store with no room refuses the segment as the assembler does
        // when it has too many holes: the assembler is put back.
        let assembled = self.assembler.clone();
        let Ok(contig_len) = self
            .assembler
            .add_then_remove_front(payload_offset, payload_len)
        else {
            return Some(self.ack_reply(cx, ip_repr, repr));
        };
        if self
            .rx
            .insert(payload_offset, &arrived_in.slice(payload_range))
            .is_err()
        {
            self.assembler = assembled;
            return Some(self.ack_reply(cx, ip_repr, repr));
        }

        if control == TcpControl::Fin {
            self.receive_fin(cx.now());
        }
        if contig_len != 0 {
            // Enqueue the contiguous data octets in front of the buffer, those
            // the segment options keep.
            let verdict = self.arrived(window_start, contig_len);

            // There's new data in rx, notify waiting task if any.

            self.rx_waker.wake();
            if self.heed(verdict) {
                return None;
            }
        }

        // Handle delayed acks
        if let Some(ack_delay) = self.ack_delay
            && self.ack_to_transmit()
        {
            self.ack_delay_timer = match self.ack_delay_timer {
                AckDelayTimer::Idle => AckDelayTimer::Waiting(cx.now() + ack_delay),
                AckDelayTimer::Waiting(_)
                    if self.immediate_ack_to_transmit(
                        ip_repr.payload_len() - TCP_HEADER_LEN - repr.payload.len(),
                    ) =>
                {
                    AckDelayTimer::Immediate
                }
                timer @ AckDelayTimer::Waiting(_) => timer,
                AckDelayTimer::Immediate => AckDelayTimer::Immediate,
            };
        }

        // Per RFC 5681, we should send an immediate ACK when either:
        //  1) an out-of-order segment is received, or
        //  2) a segment arrives that fills in all or part of a gap in sequence space.
        if !self.assembler.is_empty() || !assembler_was_empty {
            // Note that we change the transmitter state here.
            // This is fine because smoltcp assumes that it can always transmit zero or one
            // packets for every packet it receives.
            Some(self.ack_reply(cx, ip_repr, repr))
        } else {
            None
        }
    }

    /// Consumes the FIN's sequence number once all preceding text has
    /// been retained. Acknowledgement processing may already have moved
    /// FIN-WAIT-1 to FIN-WAIT-2 or SYN-RECEIVED to ESTABLISHED.
    fn receive_fin(&mut self, now: Instant) {
        let state = match self.state {
            State::Established => State::CloseWait,
            State::FinWait1 => State::Closing,
            State::FinWait2 => {
                self.timer.set_for_close(now, self.settings.time_wait);
                State::TimeWait
            }
            _ => return,
        };
        self.remote_seq_no += 1;
        self.rx_fin_received = true;
        self.set_state(state);
    }

    fn negotiate_options(&mut self, repr: &TcpRepr) {
        // A zero MSS leaves the default in place.
        if let Some(mss) = repr.max_seg_size.filter(|&mss| mss != 0) {
            self.remote_mss =
                (mss as usize).max(usize::from(self.settings.minimum_mss).max(MIN_REMOTE_MSS));
            self.congestion_controller.set_mss(self.remote_mss);
        }
        self.remote_has_sack = repr.sack_permitted;
        self.remote_win_scale = repr.window_scale;
        if self.remote_win_scale.is_none() {
            self.remote_win_shift = 0;
        }
        if repr.timestamp.is_none() {
            self.timestamps_enabled = false;
        }
    }

    fn acknowledges_syn(&self, ack: TcpSeqNumber) -> bool {
        ack == self.local_seq_no + 1 && ack <= self.local_seq_max
    }

    fn update_ack_timer(&mut self, timestamp: Instant, ack_len: usize, ack_all: bool) {
        match self.timer {
            Timer::Retransmit { .. } | Timer::FastRetransmit => {
                if ack_all {
                    // RFC 6298: (5.2) ACK of all outstanding data turn off the retransmit timer.
                    self.timer.set_for_idle(timestamp, self.keep_alive);
                } else if ack_len > 0 {
                    // (5.3) ACK of new data in ESTABLISHED state restart the retransmit timer.
                    let rto = self.rtte.retransmission_timeout();
                    self.timer.set_for_retransmit(timestamp, rto);
                }
            }
            Timer::Idle { .. } => {
                // Accepted packets refresh the keep-alive timer.
                self.timer.set_for_idle(timestamp, self.keep_alive);
            }
            _ => {}
        }

        // Probe queued data without replacing an active retransmission timer.
        if self.remote_win_len == 0
            && !self.tx.is_empty()
            && (self.timer.is_idle() || self.timer.is_zero_window_probe() && ack_len > 0)
        {
            let delay = self.rtte.retransmission_timeout();

            self.timer.set_for_zero_window_probe(timestamp, delay);
        }
        if self.remote_win_len != 0 && self.timer.is_zero_window_probe() {
            self.timer.set_for_idle(timestamp, self.keep_alive);
        }
    }

    fn is_duplicate_ack(&self, repr: &TcpRepr, window: usize) -> bool {
        let Some(ack) = repr.ack_number else {
            return false;
        };
        let sack = self.remote_has_sack && repr.sack_ranges.iter().any(Option::is_some);
        repr.control.quash_psh() == TcpControl::None
            && repr.payload.is_empty()
            && !self.tx.is_empty()
            && ack == self.local_seq_no
            && ack < self.remote_last_seq
            && (sack || self.local_rx_last_ack == Some(ack))
            && (window == self.remote_win_len || sack && window != 0 && self.remote_win_len != 0)
    }

    /// Whether the socket waits for the remote endpoint to answer what it
    /// sent: its SYN or SYN-ACK, data, its FIN, or, with keep-alive on, a
    /// keep-alive. Only then does the timeout run, as
    /// [`set_timeout`](Socket::set_timeout) says. An idle connection
    /// with neither has no unacknowledged data (RFC 9293 section 3.9.1.2).
    fn waits_for_answer(&self) -> bool {
        match self.state {
            State::SynSent
            | State::SynReceived
            | State::FinWait1
            | State::Closing
            | State::LastAck => true,
            State::Established | State::CloseWait => {
                !self.tx.is_empty() || self.keep_alive.is_some()
            }
            State::FinWait2 => self.keep_alive.is_some(),
            State::Listen | State::TimeWait | State::Closed => false,
        }
    }

    fn timed_out(&self, timestamp: Instant) -> bool {
        match (self.remote_last_ts, self.timeout) {
            (Some(remote_last_ts), Some(timeout)) => {
                self.waits_for_answer() && timestamp >= remote_last_ts + timeout
            }
            (_, _) => false,
        }
    }

    fn seq_to_transmit(&self, cx: &mut Context, mode: DispatchMode) -> bool {
        // Fast retransmits should always send, even if later congestion checks would disallow
        if mode == DispatchMode::All && self.pending_fast_retransmit && !self.tx.is_empty() {
            return true;
        }

        let ip_header_len = match self.tuple.unwrap().local.addr {
            IpAddress::Ipv4(_) => crate::wire::IPV4_HEADER_LEN,

            IpAddress::Ipv6(_) => crate::wire::IPV6_HEADER_LEN,
        };

        // The effective max segment size, taking into account the options and the local and remote limits.
        let options_len = if self.timestamp_enabled() { 12 } else { 0 };

        let local_mss = cx.ip_mtu() - ip_header_len - TCP_HEADER_LEN;
        let effective_mss = local_mss.min(self.remote_mss).saturating_sub(options_len);

        // Have we sent data that hasn't been ACKed yet?
        let data_in_flight = self.remote_last_seq != self.local_seq_no;

        // If we want to send a SYN and we haven't done so, do it!
        if self.syn_unacked() && !data_in_flight {
            return true;
        }

        // max sequence number we can send.
        let max_send_seq = self.local_seq_no + core::cmp::min(self.remote_win_len, self.tx.len());

        // Max amount of octets we can send.
        let capped_send_seq = if max_send_seq >= self.remote_last_seq {
            max_send_seq - self.remote_last_seq
        } else {
            0
        };

        // compare max bytes allowed by cwnd with max bytes allowed by remote
        let max_send = capped_send_seq.min(self.cwnd_remaining());

        // Can we send at least 1 octet?
        let mut can_send = mode == DispatchMode::All && max_send != 0;
        // Can we send at least 1 full segment?
        let can_send_full = max_send >= effective_mss;

        // Do we have to send a FIN?
        let want_fin = match self.state {
            State::FinWait1 => true,
            State::Closing => true,
            State::LastAck => true,
            _ => false,
        };

        // If we're applying the Nagle algorithm we don't want to send more
        // until one of:
        // * There's no data in flight
        // * We can send a full packet
        // * We have all the data we'll ever send (we're closing send)
        if self.nagle && data_in_flight && !can_send_full && !want_fin {
            can_send = false;
        }

        // Can we actually send the FIN? We can send it if:
        // 1. We have unsent data that fits in the remote window.
        // 2. We have no unsent data.
        // This condition matches only if #2, because #1 is already covered by can_data and we're ORing them.
        let can_fin = want_fin && self.remote_last_seq == self.local_seq_no + self.tx.len();

        can_send || can_fin
    }

    fn delayed_ack_expired(&self, timestamp: Instant) -> bool {
        match self.ack_delay_timer {
            AckDelayTimer::Idle => true,
            AckDelayTimer::Waiting(t) => t <= timestamp,
            AckDelayTimer::Immediate => true,
        }
    }

    fn ack_to_transmit(&self) -> bool {
        if let Some(remote_last_ack) = self.remote_last_ack {
            remote_last_ack < self.remote_seq_no + self.rx.len()
        } else {
            false
        }
    }

    /// Return whether to send ACK immediately due to the amount of unacknowledged data.
    ///
    /// RFC 9293 states "An ACK SHOULD be generated for at least every second full-sized segment or
    /// 2*RMSS bytes of new data (where RMSS is the MSS specified by the TCP endpoint receiving the
    /// segments to be acknowledged, or the default value if not specified) (SHLD-19)."
    ///
    fn immediate_ack_to_transmit(&self, options_len: usize) -> bool {
        if let Some(remote_last_ack) = self.remote_last_ack {
            // Options reduce a full segment's payload (RFC 6691 section 2).
            // Waiting for two unadjusted MSS values can stall a sender after
            // two full segments, contrary to RFC 5681 section 4.2.
            let threshold = self
                .remote_mss
                .saturating_sub(options_len)
                .max(1)
                .saturating_mul(usize::from(self.settings.ack_segments.max(1)));
            let threshold = threshold.saturating_sub(usize::from(self.settings.ack_inclusive));
            remote_last_ack + threshold < self.remote_seq_no + self.rx.len()
        } else {
            false
        }
    }

    /// Return whether we should send ACK immediately due to significant window updates.
    ///
    /// The world selects the growth ratio that warrants an update.
    fn window_to_update(&self) -> bool {
        match self.state {
            State::SynSent
            | State::SynReceived
            | State::Established
            | State::FinWait1
            | State::FinWait2 => {
                let new_win = self.scaled_window();
                if let Some(last_win) = self.last_scaled_window() {
                    new_win > 0 && new_win / self.settings.window_update_ratio.max(1) >= last_win
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn start_retransmit(&mut self, timestamp: Instant) {
        let probe_delay = self.rtte.retransmission_timeout();
        let in_flight = self.flight_size();
        if let Timer::Retransmit { .. } = self.timer {
            // An RTO restarts transmission at the oldest unacknowledged byte.
            self.congestion_controller.on_rto(in_flight);
            self.remote_last_seq = self.local_seq_no;
            self.rtte.on_rto();
        } else {
            // Fast retransmit resends only the oldest segment.
            self.congestion_controller.on_loss(in_flight);
            self.pending_fast_retransmit = true;
        }

        // Disarm the expired timer so a blocked sender does not spin.
        self.timer.set_for_idle(timestamp, self.keep_alive);
        if self.remote_win_len == 0 && !self.tx.is_empty() {
            self.remote_last_seq = self.local_seq_no;
            self.pending_fast_retransmit = false;
            self.timer = Timer::ZeroWindowProbe {
                expires_at: timestamp,
                delay: probe_delay,
            };
        }
        self.rtte.on_retransmit();
    }

    /// Makes `repr` our SYN, or our SYN|ACK once the remote's SYN arrived.
    fn fill_syn(&self, repr: &mut TcpRepr) {
        repr.control = TcpControl::Syn;
        repr.seq_number = self.local_seq_no;
        // window len must NOT be scaled in SYNs.
        repr.window_len = if repr.timestamp.is_some() {
            self.settings
                .syn_window_with_timestamps
                .or(self.settings.syn_window)
        } else {
            self.settings.syn_window
        }
        .unwrap_or_else(|| u16::try_from(self.rx.window()).unwrap_or(u16::MAX));
        if self.state == State::SynSent {
            repr.ack_number = None;
            repr.window_scale = Some(self.remote_win_shift);
            repr.sack_permitted = true;
        } else {
            repr.sack_permitted = self.remote_has_sack;
            repr.window_scale = self.remote_win_scale.map(|_| self.remote_win_shift);
        }
    }

    /// Sends what is due, if anything: `emit` gets the segment, whose
    /// payload, when it has one from the send buffer, is the [`Piece`]
    /// beside it rather than `repr.payload`, which is then empty. The IP
    /// representation counts the piece in its payload length. Control
    /// mode leaves ordinary text queued while ACKs and window updates
    /// can pass it; a one-byte window probe is marked on its piece.
    pub fn dispatch<F, E>(&mut self, cx: &mut Context, mode: DispatchMode, emit: F) -> Result<(), E>
    where
        F: FnOnce(&mut Context, (IpRepr, TcpRepr, Option<Piece<'_>>)) -> Result<(), E>,
    {
        let Some(tuple) = self.tuple else {
            return Ok(());
        };

        if self.remote_last_ts.is_none() {
            // We get here in exactly two cases:
            //  1) This socket just transitioned into SYN-SENT.
            //  2) This socket had an empty transmit buffer and some data was added there.
            // Both are similar in that the socket has been quiet for an indefinite
            // period of time, it isn't anymore, and the local endpoint is talking.
            // So, we start counting the timeout not from the last received packet
            // but from the first transmitted one.
            self.remote_last_ts = Some(cx.now());
        }

        // Check if any state needs to be changed because of a timer.
        if self.timed_out(cx.now()) {
            // If a timeout expires, we should abort the connection.
            self.set_state(State::Closed);
        } else if self.timer.should_retransmit(cx.now()) {
            self.start_retransmit(cx.now());
        }

        let should_send = self.seq_to_transmit(cx, mode)
            || self.ack_to_transmit() && self.delayed_ack_expired(cx.now())
            || self.window_to_update()
            || self.ack_asked
            || self.state == State::Closed
            || self.timer.should_keep_alive(cx.now())
            || self.timer.should_zero_window_probe(cx.now());
        if !should_send {
            if self.timer.should_close(cx.now()) {
                self.forget_connection();
            }
            return Ok(());
        }

        // Construct the lowered IP representation.
        // We might need this to calculate the MSS, so do it early.
        let mut ip_repr = IpRepr::new(
            tuple.local.addr,
            tuple.remote.addr,
            IpProtocol::Tcp,
            0,
            self.hop_limit.unwrap_or(64),
        );

        // Construct the basic TCP representation, an empty ACK packet.
        // We'll adjust this to be more specific as needed.
        let mut repr = TcpRepr {
            src_port: tuple.local.port,
            dst_port: tuple.remote.port,
            control: TcpControl::None,
            seq_number: self.remote_last_seq,
            ack_number: Some(self.remote_seq_no + self.rx.len()),
            window_len: self.scaled_window(),
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            extra: &[],
            layout: crate::wire::OptionLayout {
                order: crate::wire::OptionOrder::WindowBeforeSack,
                align: false,
            },
            timestamp: TcpTimestampRepr::generate_reply_with_tsval(
                self.timestamp_generator(),
                self.last_remote_tsval,
                cx.now(),
            ),
            payload: &[],
        };

        repr.layout = self.settings.layout;
        if let Some(ts) = &mut repr.timestamp {
            ts.tsval = ts.tsval.wrapping_add(self.timestamp_offset);
        }
        let mut is_zero_window_probe = false;
        // Where the payload starts in the send buffer, when it comes from there.
        let mut payload_at = None;

        match self.state {
            // We transmit an RST in the CLOSED state. If we ended up in the CLOSED state
            // with a specified endpoint, it means that the socket was aborted.
            State::Closed => {
                repr.control = TcpControl::Rst;
            }

            // We never transmit anything in the LISTEN state.
            State::Listen => return Ok(()),

            // We transmit a SYN in the SYN-SENT state.
            // We transmit a SYN|ACK in the SYN-RECEIVED state, and after a close there
            // until the remote acknowledges it.
            State::SynSent | State::SynReceived => self.fill_syn(&mut repr),
            State::FinWait1 | State::Closing if self.closed_before_syn_ack => {
                self.fill_syn(&mut repr)
            }

            // We transmit data in all states where we may have data in the buffer,
            // or the transmit half of the connection is still open.
            State::Established
            | State::FinWait1
            | State::Closing
            | State::CloseWait
            | State::LastAck => {
                // Extract as much data as the remote side can receive in this packet
                // from the transmit buffer.

                // Maximum size we're allowed to send. This can be limited by 4 factors:
                // 1. remote window
                // 2. MSS the remote is willing to accept, probably determined by their MTU
                // 3. MSS we can send, determined by our MTU.
                // 4. Our congestion window
                let room = self
                    .segment_options
                    .as_ref()
                    .map_or(0, |o| o.0.room().min(SEGMENT_OPTIONS_ROOM));
                let options_len = repr.header_len() - TCP_HEADER_LEN + room;
                let local_mss = cx.ip_mtu() - ip_repr.header_len() - TCP_HEADER_LEN;
                let effective_mss = local_mss.min(self.remote_mss).saturating_sub(options_len);

                let probe_due =
                    self.remote_win_len == 0 && self.timer.should_zero_window_probe(cx.now());
                let offset = if mode == DispatchMode::Control && !probe_due {
                    // A pending ACK or window update may use the control
                    // reserve while queued data waits for memory. FIN is
                    // allowed below only once all prior text was sent.
                    self.flight_size()
                } else if self.pending_fast_retransmit && mode == DispatchMode::All {
                    let size = effective_mss.min(self.tx.len());
                    repr.seq_number = self.local_seq_no;
                    repr.payload = self.tx.bytes(0, size);
                    payload_at = Some(0);

                    0
                } else {
                    // Right edge of window, ie the max sequence number we're allowed to send.
                    let win_right_edge = self.local_seq_no + self.remote_win_len;

                    // Max amount of octets we're allowed to send according to the remote window.
                    let mut win_limit = if win_right_edge >= self.remote_last_seq {
                        win_right_edge - self.remote_last_seq
                    } else {
                        // This can happen if we've sent some data and later the remote side
                        // has shrunk its window so that data is no longer inside the window.
                        // This should be very rare and is strongly discouraged by the RFCs,
                        // but it does happen in practice.
                        // http://www.tcpipguide.com/free/t_TCPWindowManagementIssues.htm
                        0
                    };

                    // To send a zero-window-probe, force the window limit to at least 1 byte.
                    if win_limit == 0 && self.timer.should_zero_window_probe(cx.now()) {
                        win_limit = 1;
                        is_zero_window_probe = true;
                    }

                    let size = if is_zero_window_probe {
                        // Zero-window probes are exempt from the congestion window: they
                        // are sent precisely when normal transmission is impossible, and
                        // an empty segment elicits no reply, so capping the probe to a
                        // zero length would stall the connection if a window update from
                        // the remote got lost.
                        win_limit.min(effective_mss)
                    } else {
                        win_limit.min(effective_mss).min(self.cwnd_remaining())
                    };

                    let offset = self.flight_size();
                    repr.payload = self.tx.bytes(offset, size);
                    payload_at = Some(offset);

                    offset
                };

                // If we've sent everything we had in the buffer, follow it with the PSH or FIN
                // flags, depending on whether the transmit half of the connection is open.
                if offset + repr.payload.len() == self.tx.len() {
                    match self.state {
                        State::FinWait1 | State::LastAck | State::Closing
                            if !is_zero_window_probe =>
                        {
                            repr.control = TcpControl::Fin
                        }
                        State::Established | State::CloseWait if !repr.payload.is_empty() => {
                            repr.control = TcpControl::Psh
                        }
                        _ => (),
                    }
                }
            }

            // In FIN-WAIT-2 and TIME-WAIT states we may only transmit ACKs for incoming data or FIN
            State::FinWait2 | State::TimeWait => {}
        }

        // There might be more than one reason to send a packet. E.g. the keep-alive timer
        // has expired, and we also have data in transmit buffer. Since any packet that occupies
        // sequence space will elicit an ACK, we only need to send an explicit packet if we
        // couldn't fill the sequence space with anything.

        if repr.segment_len() == 0 {
            repr.seq_number = self.send_next();
        }

        let is_keep_alive = if self.timer.should_keep_alive(cx.now()) && repr.is_empty() {
            repr.seq_number = repr.seq_number - 1;
            payload_at = None;
            repr.payload = match self.settings.keep_alive_payload {
                KeepAlivePayload::Empty => &[],
                KeepAlivePayload::OneByte => b"\x00",
            };
            true
        } else {
            false
        };

        if repr.control == TcpControl::Syn {
            if let IpRepr::Ipv4(ip) = &mut ip_repr {
                ip.options = self.syn_ipv4_options;
                ip.wire_dst = self.syn_ipv4_destination;
            }
            // Fill the MSS option. See RFC 6691 for an explanation of this calculation.
            let max_segment_size = cx.ip_mtu()
                - if matches!(ip_repr, IpRepr::Ipv4(_)) {
                    20
                } else {
                    40
                }
                - TCP_HEADER_LEN;
            repr.max_seg_size = Some(max_segment_size as u16);
            repr.extra = &self.syn_options;
        } else if repr.control == TcpControl::Rst {
            if let Some(options) = &self.rst_options {
                repr.extra = options;
            } else if let Some(options) = self.segment_options.as_mut() {
                self.segment_extra.clear();
                options.0.reset(&mut self.segment_extra);
                if self.segment_extra.len() > TCP_OPTIONS_MAX_LEN {
                    self.segment_extra.clear();
                }
                repr.extra = &self.segment_extra;
            }
        } else if let Some(options) = self.segment_options.as_mut() {
            let segment = Outgoing {
                seq: repr.seq_number.0 as u32,
                payload: if is_keep_alive { &[] } else { repr.payload },
                fin: repr.control == TcpControl::Fin,
                ack: repr.ack_number.map(|a| a.0 as u32),
            };
            self.segment_extra.clear();
            options.0.sent(&segment, &mut self.segment_extra);
            let room = options.0.room().min(SEGMENT_OPTIONS_ROOM);
            if self.segment_extra.len() > room {
                self.segment_extra.clear();
            }
            repr.extra = &self.segment_extra;
        }

        // Advance send state only after the emitter accepts the packet.
        ip_repr.set_payload_len(repr.buffer_len());
        self.identify_ipv4(&mut ip_repr);
        let increment_id = !matches!(
            self.state,
            State::Listen | State::SynReceived | State::TimeWait
        ) && matches!(ip_repr, IpRepr::Ipv4(_));
        let (seq_number, segment_len) = (repr.seq_number, repr.segment_len());
        let (ack_number, window_len) = (repr.ack_number, repr.window_len);
        // The options are copied out so that the segment handed on borrows
        // nothing of the socket but the piece of its send buffer.
        let mut extra = [0; TCP_OPTIONS_MAX_LEN];
        extra[..repr.extra.len()].copy_from_slice(repr.extra);
        let extra = &extra[..repr.extra.len()];
        let (repr, mut piece) = match payload_at {
            Some(offset) => {
                let len = repr.payload.len();
                (repr.with_parts(extra, &[]), self.tx.piece(offset, len))
            }
            None => {
                let probe: &'static [u8] = match self.settings.keep_alive_payload {
                    KeepAlivePayload::OneByte if is_keep_alive => b"\x00",
                    _ => &[],
                };
                debug_assert_eq!(repr.payload, probe, "only a probe's payload is not stored");
                (repr.with_parts(extra, probe), None)
            }
        };
        if let Some(piece) = &mut piece {
            piece.probe = is_zero_window_probe;
        }
        let retransmitted_data =
            piece.is_some() && !is_zero_window_probe && seq_number < self.local_seq_max;
        if let Err(error) = emit(cx, (ip_repr, repr, piece)) {
            // A retained packet can become unique without releasing its
            // backing's charge, so memory wakeups alone cannot retry it.
            // Keep a future RTO after a refused retransmission, without
            // starting one for text that has never left the socket.
            if retransmitted_data && !self.timer.is_retransmit() {
                self.timer
                    .set_for_retransmit(cx.now(), self.rtte.retransmission_timeout());
            }
            return Err(error);
        }
        if increment_id && let Some(id) = &mut self.ipv4_identification {
            *id = id.wrapping_add(1);
        }

        if mode == DispatchMode::All {
            self.pending_fast_retransmit = false;
        }
        self.local_seq_max = self.local_seq_max.max(seq_number + segment_len);

        // We've sent something, whether useful data or a keep-alive packet, so rewind
        // the keep-alive timer.
        self.timer.rewind_keep_alive(cx.now(), self.keep_alive);

        self.ack_delay_timer = AckDelayTimer::Idle;
        self.ack_asked = false;

        // Leave the rest of the state intact if sending a zero-window probe.
        if is_zero_window_probe {
            self.timer.rewind_zero_window_probe(cx.now());
            return Ok(());
        }

        // Leave the rest of the state intact if sending a keep-alive packet, since those
        // carry a fake segment.
        if is_keep_alive {
            return Ok(());
        }

        // We've sent a packet successfully, so we can update the internal state now.
        // Use max() so a fast-retransmit segment (whose seq_number is local_seq_no, well
        // behind the current frontier) doesn't rewind the tracked "highest sent" sequence.
        // A segment with no sequence space sits at `send_next()` and moves nothing.
        let segment_end = seq_number + segment_len;
        self.remember_window(ack_number, window_len);

        if segment_len > 0 {
            self.remote_last_seq = self.remote_last_seq.max(segment_end);
            self.rtte.on_send(cx.now(), segment_end);
        }

        if segment_len > 0 && !self.timer.is_retransmit() {
            // RFC 6298 (5.1) Every time a packet containing data is sent (including a
            // retransmission), if the timer is not running, start it running
            // so that it will expire after RTO seconds.
            let rto = self.rtte.retransmission_timeout();
            self.timer.set_for_retransmit(cx.now(), rto);
        }

        if self.state == State::Closed {
            // When aborting a connection, forget about it after sending a single RST packet.
            self.tuple = None;

            {
                // Wake tx now so that async users can wait for the RST to be sent
                self.tx_waker.wake();
            }
        }

        Ok(())
    }

    #[allow(clippy::if_same_then_else)]
    /// The next useful poll when the emitter can send `mode` traffic.
    pub fn poll_at(&self, cx: &mut Context, mode: DispatchMode) -> PollAt {
        // The logic here mirrors the beginning of dispatch() closely.
        if self.tuple.is_none() {
            // No one to talk to, nothing to transmit.
            PollAt::Ingress
        } else if self.remote_last_ts.is_none() {
            // Socket stopped being quiet recently, we need to acquire a timestamp.
            PollAt::Now
        } else if self.state == State::Closed {
            // Socket was aborted, we have an RST packet to transmit.
            PollAt::Now
        } else if self.seq_to_transmit(cx, mode) {
            // We have a data or flag packet to transmit.
            PollAt::Now
        } else if self.window_to_update() {
            // The receive window has been raised significantly.
            PollAt::Now
        } else if self.ack_asked {
            // The segment options asked for an ACK.
            PollAt::Now
        } else {
            let want_ack = self.ack_to_transmit();

            let delayed_ack_poll_at = match (want_ack, self.ack_delay_timer) {
                (false, _) => PollAt::Ingress,
                (true, AckDelayTimer::Idle) => PollAt::Now,
                (true, AckDelayTimer::Waiting(t)) => PollAt::Time(t),
                (true, AckDelayTimer::Immediate) => PollAt::Now,
            };

            let timeout_poll_at = match (self.remote_last_ts, self.timeout) {
                // If we're waiting for an answer, we need to poll at the moment
                // when the timeout would expire.
                (Some(remote_last_ts), Some(timeout)) if self.waits_for_answer() => {
                    PollAt::Time(remote_last_ts + timeout)
                }
                // Otherwise we have no timeout.
                (_, _) => PollAt::Ingress,
            };

            // We wait for the earliest of our timers to fire.
            *[self.timer.poll_at(), timeout_poll_at, delayed_ack_poll_at]
                .iter()
                .min()
                .unwrap_or(&PollAt::Ingress)
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::wire::IpRepr;
    use std::ops::{Deref, DerefMut};
    use std::vec::Vec;

    fn pool() -> Pool {
        Pool::new(&Budget::unlimited(), rx::SLOT, SEGMENTS)
    }

    #[cfg(kani)]
    include!("../../../verification/tcp-port-zero/SocketProof.rs");

    // =========================================================================================//
    // Constants
    // =========================================================================================//

    const LOCAL_PORT: u16 = 80;
    const REMOTE_PORT: u16 = 49500;
    const LISTEN_END: IpListenEndpoint = IpListenEndpoint {
        addr: None,
        port: LOCAL_PORT,
    };
    const TUPLE: Tuple = Tuple {
        local: LOCAL_END,
        remote: REMOTE_END,
    };
    // Every connection's initial sequence number in the tests: see
    // `crate::tests::setup`.
    pub(crate) const LOCAL_SEQ: TcpSeqNumber = TcpSeqNumber(-34801502);
    const REMOTE_SEQ: TcpSeqNumber = TcpSeqNumber(-10001);

    use crate::wire::Ipv4Address as IpvXAddress;
    use crate::wire::Ipv4Repr as IpvXRepr;
    use IpRepr::Ipv4 as IpReprIpvX;

    const LOCAL_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 1);
    const REMOTE_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 2);
    const OTHER_ADDR: IpvXAddress = IpvXAddress::new(192, 168, 1, 3);

    const BASE_MSS: u16 = 1460;

    const LOCAL_END: IpEndpoint = IpEndpoint {
        addr: IpAddress::Ipv4(LOCAL_ADDR),
        port: LOCAL_PORT,
    };
    const REMOTE_END: IpEndpoint = IpEndpoint {
        addr: IpAddress::Ipv4(REMOTE_ADDR),
        port: REMOTE_PORT,
    };

    const SEND_IP_TEMPL: IpRepr = IpReprIpvX(IpvXRepr {
        identification: 0,
        options: crate::wire::Ipv4OptionBytes::EMPTY,
        wire_dst: None,
        src_addr: LOCAL_ADDR,
        dst_addr: REMOTE_ADDR,
        next_header: IpProtocol::Tcp,
        payload_len: 20,
        hop_limit: 64,
    });
    const SEND_TEMPL: TcpRepr<'static> = TcpRepr {
        src_port: REMOTE_PORT,
        dst_port: LOCAL_PORT,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(0),
        ack_number: Some(TcpSeqNumber(0)),
        window_len: 256,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        extra: &[],
        layout: crate::wire::OptionLayout {
            order: crate::wire::OptionOrder::WindowBeforeSack,
            align: false,
        },
        timestamp: None,
        payload: &[],
    };
    const RECV_TEMPL: TcpRepr<'static> = TcpRepr {
        src_port: LOCAL_PORT,
        dst_port: REMOTE_PORT,
        control: TcpControl::None,
        seq_number: TcpSeqNumber(0),
        ack_number: Some(TcpSeqNumber(0)),
        window_len: 64,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        extra: &[],
        layout: crate::wire::OptionLayout {
            order: crate::wire::OptionOrder::WindowBeforeSack,
            align: false,
        },
        timestamp: None,
        payload: &[],
    };

    // =========================================================================================//
    // Helper functions
    // =========================================================================================//

    struct TestSocket {
        socket: Socket,
        cx: Context,
    }

    impl Deref for TestSocket {
        type Target = Socket;
        fn deref(&self) -> &Self::Target {
            &self.socket
        }
    }

    impl DerefMut for TestSocket {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.socket
        }
    }

    #[track_caller]
    fn send(
        socket: &mut TestSocket,
        timestamp: Instant,
        repr: &TcpRepr,
    ) -> Option<TcpRepr<'static>> {
        socket.cx.set_now(timestamp);

        let ip_repr = IpReprIpvX(IpvXRepr {
            identification: 0,
            options: crate::wire::Ipv4OptionBytes::EMPTY,
            wire_dst: None,
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: repr.buffer_len(),
            hop_limit: 64,
        });

        assert!(socket.socket.accepts(&mut socket.cx, &ip_repr, repr));

        let payload = Chunk::unpaid(repr.payload.to_vec());
        socket
            .socket
            .process(&mut socket.cx, &ip_repr, repr, &[], &payload)
            .map(|(_, repr)| repr)
    }
    #[track_caller]
    fn recv<F>(socket: &mut TestSocket, timestamp: Instant, mut f: F)
    where
        F: FnMut(Result<TcpRepr, ()>),
    {
        socket.cx.set_now(timestamp);

        let mut sent = 0;
        let result = socket.socket.dispatch(
            &mut socket.cx,
            DispatchMode::All,
            |_, (ip_repr, tcp_repr, piece)| {
                // The segment as the wire carries it: the piece's bytes are
                // its payload.
                let stored = piece.as_ref().map(|p| p.bytes().to_vec());
                let tcp_repr = match &stored {
                    Some(payload) => TcpRepr {
                        payload,
                        ..tcp_repr
                    },
                    None => tcp_repr,
                };
                assert_eq!(
                    match ip_repr {
                        IpRepr::Ipv4(repr) => repr.next_header,
                        IpRepr::Ipv6(repr) => repr.next_header,
                    },
                    IpProtocol::Tcp
                );
                assert_eq!(ip_repr.src_addr(), LOCAL_ADDR.into());
                assert_eq!(ip_repr.dst_addr(), REMOTE_ADDR.into());
                assert_eq!(ip_repr.payload_len(), tcp_repr.buffer_len());

                sent += 1;
                f(Ok(tcp_repr));
                Ok(())
            },
        );
        match result {
            Ok(()) => assert_eq!(sent, 1, "Exactly one packet should be sent"),
            Err(e) => f(Err(e)),
        }
    }

    #[track_caller]
    fn recv_nothing(socket: &mut TestSocket, timestamp: Instant) {
        socket.cx.set_now(timestamp);

        let mut fail = false;
        let result: Result<(), ()> =
            socket
                .socket
                .dispatch(&mut socket.cx, DispatchMode::All, |_, _| {
                    fail = true;
                    Ok(())
                });
        if fail {
            panic!("Should not send a packet")
        }

        assert_eq!(result, Ok(()))
    }

    #[collapse_debuginfo(yes)]
    macro_rules! send {
        ($socket:ident, $repr:expr) =>
            (send!($socket, time 0, $repr));
        ($socket:ident, $repr:expr, $result:expr) =>
            (send!($socket, time 0, $repr, $result));
        ($socket:ident, time $time:expr, $repr:expr) =>
            (send!($socket, time $time, $repr, None));
        ($socket:ident, time $time:expr, $repr:expr, $result:expr) =>
            (assert_eq!(send(&mut $socket, Instant::from_millis($time), &$repr), $result));
    }

    #[collapse_debuginfo(yes)]
    macro_rules! recv {
        ($socket:ident, [$( $repr:expr ),*]) => ({
            $( recv!($socket, Ok($repr)); )*
            recv_nothing!($socket)
        });
        ($socket:ident, time $time:expr, [$( $repr:expr ),*]) => ({
            $( recv!($socket, time $time, Ok($repr)); )*
            recv_nothing!($socket, time $time)
        });
        ($socket:ident, $result:expr) =>
            (recv!($socket, time 0, $result));
        ($socket:ident, time $time:expr, $result:expr) =>
            (recv(&mut $socket, Instant::from_millis($time), |result| {
                // Most of the time we don't care about the PSH flag.
                let result = result.map(|mut repr| {
                    repr.control = repr.control.quash_psh();
                    repr
                });
                assert_eq!(result, $result)
            }));
        ($socket:ident, time $time:expr, $result:expr, exact) =>
            (recv(&mut $socket, Instant::from_millis($time), |repr| assert_eq!(repr, $result)));
    }

    #[collapse_debuginfo(yes)]
    macro_rules! recv_nothing {
        ($socket:ident) => (recv_nothing!($socket, time 0));
        ($socket:ident, time $time:expr) => (recv_nothing(&mut $socket, Instant::from_millis($time)));
    }

    #[collapse_debuginfo(yes)]
    macro_rules! sanity {
        ($socket1:expr, $socket2:expr) => {{
            let (s1, s2) = ($socket1, $socket2);
            assert_eq!(s1.state, s2.state, "state");
            assert_eq!(s1.tuple, s2.tuple, "tuple");
            assert_eq!(s1.local_seq_no, s2.local_seq_no, "local_seq_no");
            assert_eq!(s1.remote_seq_no, s2.remote_seq_no, "remote_seq_no");
            assert_eq!(s1.remote_last_seq, s2.remote_last_seq, "remote_last_seq");
            assert_eq!(s1.remote_last_ack, s2.remote_last_ack, "remote_last_ack");
            assert_eq!(s1.remote_last_win, s2.remote_last_win, "remote_last_win");
            assert_eq!(s1.remote_win_len, s2.remote_win_len, "remote_win_len");
            assert_eq!(s1.timer, s2.timer, "timer");
        }};
    }

    fn socket() -> TestSocket {
        socket_with_buffer_sizes(64, 64)
    }

    fn socket_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut socket = Socket::new(rx_len, tx_len, Budget::unlimited(), &pool());
        socket.set_ack_delay(None);
        TestSocket {
            socket,
            cx: crate::tests::context(),
        }
    }

    /// The byte-slice reads and writes the tests were written with, over
    /// the chunks the socket takes and gives.
    impl Socket {
        /// Queues as many of `data` as the send buffer has room for, in a
        /// chunk of their own.
        fn send_slice(&mut self, data: &[u8]) -> Result<usize, SendError> {
            let n = data.len().min(self.tx.window());
            match self.push(Chunk::unpaid(data[..n].to_vec())) {
                Ok(()) => Ok(n),
                Err((error, _)) => Err(error),
            }
        }

        /// Reads into `data` as many bytes as are ready and fit.
        fn recv_slice(&mut self, data: &mut [u8]) -> Result<usize, RecvError> {
            self.recv_error_check()?;
            let mut n = 0;
            while n < data.len() && self.can_recv() {
                let Some(chunk) = self.pop(data.len() - n)? else {
                    break;
                };
                data[n..n + chunk.len()].copy_from_slice(&chunk);
                n += chunk.len();
            }
            Ok(n)
        }

        /// Shows `f` the bytes of the first ready chunk, and takes as many
        /// as it says.
        fn recv<R>(&mut self, f: impl FnOnce(&mut [u8]) -> (usize, R)) -> Result<R, RecvError> {
            self.recv_error_check()?;
            let mut bytes = self.rx.unread().next().map_or(Vec::new(), |c| c.to_vec());
            let (n, result) = f(&mut bytes);
            if n > 0 {
                self.pop(n)?;
            }
            Ok(result)
        }
    }

    fn socket_syn_received_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_with_buffer_sizes(tx_len, rx_len);
        s.state = State::SynReceived;
        s.tuple = Some(TUPLE);
        s.local_seq_no = LOCAL_SEQ;
        s.remote_seq_no = REMOTE_SEQ + 1;
        s.remote_last_seq = LOCAL_SEQ;
        s.local_seq_max = LOCAL_SEQ + 1;
        s.remote_win_len = 256;
        s
    }

    fn socket_syn_received() -> TestSocket {
        socket_syn_received_with_buffer_sizes(64, 64)
    }

    fn socket_syn_sent_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_with_buffer_sizes(tx_len, rx_len);
        s.state = State::SynSent;
        s.tuple = Some(TUPLE);
        s.local_seq_no = LOCAL_SEQ;
        s.remote_last_seq = LOCAL_SEQ;
        s.local_seq_max = LOCAL_SEQ + 1;
        s
    }

    fn socket_syn_sent() -> TestSocket {
        socket_syn_sent_with_buffer_sizes(64, 64)
    }

    fn socket_established_with_buffer_sizes(tx_len: usize, rx_len: usize) -> TestSocket {
        let mut s = socket_syn_received_with_buffer_sizes(tx_len, rx_len);
        s.state = State::Established;
        s.local_seq_no = LOCAL_SEQ + 1;
        s.remote_last_seq = LOCAL_SEQ + 1;
        s.local_seq_max = s.remote_last_seq;
        s.remote_last_ack = Some(REMOTE_SEQ + 1);
        s.remote_last_win = s.scaled_window();
        s.remote_win_end =
            Some(REMOTE_SEQ + 1 + ((s.remote_last_win as usize) << s.remote_win_shift));
        s
    }

    fn socket_established() -> TestSocket {
        socket_established_with_buffer_sizes(64, 64)
    }

    fn socket_fin_wait_1() -> TestSocket {
        let mut s = socket_established();
        s.state = State::FinWait1;
        s
    }

    fn socket_fin_wait_2() -> TestSocket {
        let mut s = socket_fin_wait_1();
        s.state = State::FinWait2;
        s.local_seq_no = LOCAL_SEQ + 1 + 1;
        s.remote_last_seq = LOCAL_SEQ + 1 + 1;
        s.local_seq_max = s.remote_last_seq;
        s
    }

    fn socket_closing() -> TestSocket {
        let mut s = socket_fin_wait_1();
        s.state = State::Closing;
        s.remote_last_seq = LOCAL_SEQ + 1 + 1;
        s.local_seq_max = s.remote_last_seq;
        s.remote_seq_no = REMOTE_SEQ + 1 + 1;
        s.timer = Timer::Retransmit {
            expires_at: Instant::from_millis(1000),
        };
        s
    }

    fn socket_time_wait(from_closing: bool) -> TestSocket {
        let mut s = socket_fin_wait_2();
        s.state = State::TimeWait;
        s.remote_seq_no = REMOTE_SEQ + 1 + 1;
        if from_closing {
            s.remote_last_ack = Some(REMOTE_SEQ + 1 + 1);
        }
        s.timer = Timer::Close {
            expires_at: Instant::from_secs(1) + CLOSE_DELAY,
        };
        s
    }

    fn socket_close_wait() -> TestSocket {
        let mut s = socket_established();
        s.state = State::CloseWait;
        s.remote_seq_no = REMOTE_SEQ + 1 + 1;
        s.remote_last_ack = Some(REMOTE_SEQ + 1 + 1);
        s
    }

    fn socket_last_ack() -> TestSocket {
        let mut s = socket_close_wait();
        s.state = State::LastAck;
        s
    }

    fn socket_recved() -> TestSocket {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
        s
    }

    // =========================================================================================//
    // Tests for the CLOSED state.
    // =========================================================================================//
    #[test]
    fn test_closed_reject() {
        let mut s = socket();
        assert_eq!(s.state, State::Closed);

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_closed_reject_after_listen() {
        let mut s = socket();
        s.listen(LOCAL_END).unwrap();
        s.close();

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_closed_close() {
        let mut s = socket();
        s.close();
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the LISTEN state.
    // =========================================================================================//
    fn socket_listen() -> TestSocket {
        let mut s = socket();
        s.state = State::Listen;
        s.listen_endpoint = Some(LISTEN_END);
        s
    }

    #[test]
    fn test_listen_sack_option() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                sack_permitted: false,
                ..SEND_TEMPL
            }
        );
        assert!(!s.remote_has_sack);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );

        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                sack_permitted: true,
                ..SEND_TEMPL
            }
        );
        assert!(s.remote_has_sack);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_listen_syn_win_scale_buffers() {
        for (buffer_size, shift_amt) in &[
            (64, 0),
            (128, 0),
            (1024, 0),
            (65535, 0),
            (65536, 1),
            (65537, 1),
            (131071, 1),
            (131072, 2),
            (524287, 3),
            (524288, 4),
            (655350, 4),
            (1048576, 5),
        ] {
            let mut s = socket_with_buffer_sizes(64, *buffer_size);
            s.state = State::Listen;
            s.listen_endpoint = Some(LISTEN_END);
            assert_eq!(s.remote_win_shift, *shift_amt);
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: REMOTE_SEQ,
                    ack_number: None,
                    window_scale: Some(0),
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.remote_win_shift, *shift_amt);
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: Some(REMOTE_SEQ + 1),
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(*shift_amt),
                    window_len: u16::try_from(*buffer_size).unwrap_or(u16::MAX),
                    ..RECV_TEMPL
                }]
            );
        }
    }

    #[test]
    fn test_listen_syn_tiny_mss_is_clamped() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(10),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynReceived);
        assert_eq!(s.remote_mss, MIN_REMOTE_MSS);
    }

    #[test]
    fn test_listen_syn_zero_mss_is_ignored() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynReceived);
        assert_eq!(s.remote_mss, DEFAULT_MSS);
    }

    #[test]
    fn test_listen_handshake() {
        let mut s = socket();
        s.listen(LOCAL_PORT).unwrap();
        assert_eq!(s.state(), State::Listen);
        assert_eq!(s.listen_endpoint, Some(LISTEN_END));
        assert_eq!(s.local_endpoint(), None);
        assert_eq!(s.remote_endpoint(), None);
        assert_eq!(s.send_slice(b"x"), Err(SendError::InvalidState));
        assert!(!s.can_recv());
        recv_nothing!(s);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"hello",
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        assert_eq!(s.local_endpoint(), Some(LOCAL_END));
        assert_eq!(s.remote_endpoint(), Some(REMOTE_END));
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 6),
                window_len: 59,
                ..RECV_TEMPL
            }]
        );
        let mut bytes = [0; 5];
        assert_eq!(s.recv_slice(&mut bytes), Ok(5));
        assert_eq!(&bytes, b"hello");
    }

    #[test]
    fn literal_port_listeners_match_syn_and_survive_reset() {
        for port in [0, 1, u16::MAX] {
            let mut s = socket();
            let local = IpListenEndpoint { port, ..LISTEN_END };
            s.listen(local).unwrap();
            let syn = TcpRepr {
                dst_port: port,
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            };
            assert!(s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &syn));
            assert!(!s.socket.accepts(
                &mut s.cx,
                &SEND_IP_TEMPL,
                &TcpRepr {
                    dst_port: port.wrapping_add(1),
                    ..syn
                }
            ));
            send!(s, syn);
            let reset = TcpRepr {
                dst_port: port,
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ),
                ..SEND_TEMPL
            };
            send!(s, reset);
            assert!(matches!(s.state, State::Listen));
            assert!(s.tuple.is_none());
            assert!(s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &syn));
        }
    }

    #[test]
    fn test_listen_twice() {
        let mut s = socket();
        assert_eq!(s.listen(80), Ok(()));
        // multiple calls to listen are okay if its the same local endpoint and the state is still in listening
        assert_eq!(s.listen(80), Ok(()));
        s.set_state(State::SynReceived); // state change, simulate incoming connection
        assert_eq!(s.listen(80), Err(ListenError::InvalidState));
    }

    #[test]
    fn test_listen_syn() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        sanity!(s, socket_syn_received());
    }

    #[test]
    fn test_listen_syn_reject_ack() {
        let mut s = socket_listen();

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ),
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));

        assert_eq!(s.state, State::Listen);
    }

    fn reset_with_flags(
        seq: TcpSeqNumber,
        ack: Option<TcpSeqNumber>,
        flags: u8,
    ) -> TcpRepr<'static> {
        let repr = TcpRepr {
            control: TcpControl::Rst,
            seq_number: seq,
            ack_number: ack,
            ..SEND_TEMPL
        };
        let mut bytes = [0; 20];
        let mut packet = crate::wire::TcpPacket::new_unchecked(&mut bytes);
        repr.emit(&mut packet, &REMOTE_ADDR.into(), &LOCAL_ADDR.into());
        packet.set_syn(flags & 2 != 0);
        packet.set_fin(flags & 1 != 0);
        packet.fill_checksum(&REMOTE_ADDR.into(), &LOCAL_ADDR.into());
        let packet = crate::wire::TcpPacket::new_unchecked(&bytes);
        let parsed = TcpRepr::parse(&packet, &REMOTE_ADDR.into(), &LOCAL_ADDR.into()).unwrap();
        TcpRepr {
            payload: &[],
            extra: &[],
            ..parsed
        }
    }

    #[test]
    fn test_listen_syn_rst() {
        for ack in [None, Some(LOCAL_SEQ + 1)] {
            let mut s = socket_listen();
            let rst = reset_with_flags(REMOTE_SEQ, ack, 2);
            assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &rst));
            assert_eq!(s.state(), State::Listen);
            recv!(s, []);
        }
    }

    #[test]
    fn test_listen_rst() {
        let mut s = socket_listen();
        let tcp_repr = TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
        assert_eq!(s.state, State::Listen);
    }

    #[test]
    fn test_listen_close() {
        let mut s = socket_listen();
        s.close();
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the SYN-RECEIVED state.
    // =========================================================================================//

    #[test]
    fn test_syn_received_ack() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        sanity!(s, socket_established());
    }

    #[test]
    fn test_syn_received_ack_too_low() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ), // wrong
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::SynReceived);
    }

    #[test]
    fn test_syn_received_ack_too_high() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2), // wrong
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 2,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::SynReceived);
    }

    #[test]
    fn test_syn_received_fin() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6 + 1),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::CloseWait);

        let mut s2 = socket_close_wait();
        s2.remote_last_ack = Some(REMOTE_SEQ + 1 + 6 + 1);
        s2.remote_last_win = 58;
        sanity!(s, s2);
    }

    #[test]
    fn test_syn_received_rst() {
        let mut s = socket_syn_received();
        s.listen_endpoint = Some(LISTEN_END);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Listen);
        assert_eq!(s.listen_endpoint, Some(LISTEN_END));
        assert_eq!(s.tuple, None);
    }

    /// An MPTCP MP_CAPABLE option as a listener answers with it (RFC 8684
    /// section 3.1): kind 30, length 12, version 1, flag H, an 8-byte key.
    const MP_CAPABLE: TcpOption<'static> = TcpOption::Unknown {
        kind: 30,
        data: &[0x01, 0x01, 1, 2, 3, 4, 5, 6, 7, 8],
    };
    const MP_CAPABLE_BYTES: &[u8] = &[30, 12, 0x01, 0x01, 1, 2, 3, 4, 5, 6, 7, 8];

    #[test]
    fn test_syn_options_ride_the_syn_ack_and_its_retransmission() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        s.set_syn_options(&[TcpOption::NoOperation, MP_CAPABLE])
            .unwrap();
        let syn_ack = TcpRepr {
            control: TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            extra: &[1, 30, 12, 0x01, 0x01, 1, 2, 3, 4, 5, 6, 7, 8],
            ..RECV_TEMPL
        };
        recv!(s, time 50, Ok(syn_ack));
        recv!(s, time 1050, Ok(syn_ack));
    }

    #[test]
    fn test_syn_options_ride_the_syn() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        s.set_syn_options(&[MP_CAPABLE]).unwrap();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                extra: MP_CAPABLE_BYTES,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_syn_options_end_with_the_connection() {
        let mut s = socket_syn_received();
        s.listen_endpoint = Some(LISTEN_END);
        s.set_syn_options(&[MP_CAPABLE]).unwrap();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                extra: MP_CAPABLE_BYTES,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Listen);
        // The next peer's SYN-ACK carries none of them.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        recv(&mut s, Instant::from_millis(0), |repr| {
            let repr = repr.unwrap();
            assert_eq!(repr.control, TcpControl::Syn);
            assert_eq!(repr.ack_number, Some(REMOTE_SEQ + 1));
            assert_eq!(repr.extra, &[]);
        });
    }

    /// What a [`SegmentOptions`] in a test was asked: each segment sent, as
    /// (seq, payload, fin, ack), and each one taken, as (seq, payload,
    /// fin, options).
    #[derive(Default)]
    struct Seen {
        sent: Vec<(u32, Vec<u8>, bool, Option<u32>)>,
        received: Vec<(u32, Vec<u8>, bool, Vec<u8>)>,
    }

    /// Adds an option of kind 253 holding the segment's sequence number,
    /// and three bytes past its room when `overflow`.
    struct Stamp {
        seen: std::sync::Arc<std::sync::Mutex<Seen>>,
        overflow: bool,
    }

    impl SegmentOptions for Stamp {
        fn room(&self) -> usize {
            8
        }

        fn sent(&mut self, segment: &Outgoing<'_>, out: &mut Vec<u8>) {
            self.seen.lock().unwrap().sent.push((
                segment.seq,
                segment.payload.to_vec(),
                segment.fin,
                segment.ack,
            ));
            out.extend_from_slice(&[253, 6]);
            out.extend_from_slice(&segment.seq.to_be_bytes());
            if self.overflow {
                out.extend_from_slice(&[1, 1, 1]);
            }
        }

        fn received(&mut self, segment: &Incoming<'_>) -> Verdict {
            self.seen.lock().unwrap().received.push((
                segment.seq,
                segment.payload.to_vec(),
                segment.fin,
                segment.options.to_vec(),
            ));
            Verdict::Take
        }
    }

    /// Asks for an ACK of each segment that carries an option of kind
    /// 254, and adds an option of kind 253 to each segment sent.
    struct AskOn254;

    impl SegmentOptions for AskOn254 {
        fn room(&self) -> usize {
            4
        }

        fn sent(&mut self, _: &Outgoing<'_>, out: &mut Vec<u8>) {
            out.extend_from_slice(&[253, 2]);
        }

        fn received(&mut self, segment: &Incoming<'_>) -> Verdict {
            if segment.options.first() == Some(&254) {
                Verdict::Acknowledge
            } else {
                Verdict::Take
            }
        }
    }

    /// A segment with no data whose options ask for an ACK gets one at
    /// once, carrying the segment options; one that does not ask gets
    /// none.
    #[test]
    fn test_segment_options_can_ask_for_an_ack() {
        let mut s = socket_established();
        s.set_segment_options(Box::new(AskOn254));
        let ip_repr = IpReprIpvX(IpvXRepr {
            identification: 0,
            options: crate::wire::Ipv4OptionBytes::EMPTY,
            wire_dst: None,
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: 0,
            hop_limit: 64,
        });
        let take = |s: &mut TestSocket, options: &[u8]| {
            let repr = TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            };
            s.socket.process(
                &mut s.cx,
                &ip_repr,
                &repr,
                options,
                &Chunk::unpaid(repr.payload.to_vec()),
            )
        };
        assert_eq!(take(&mut s, &[1, 1, 1, 1]), None);
        recv_nothing!(s);
        assert_eq!(take(&mut s, &[254, 2, 1, 1]), None);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                extra: &[253, 2],
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s);
    }

    fn stamped(s: &mut TestSocket, overflow: bool) -> std::sync::Arc<std::sync::Mutex<Seen>> {
        let seen = std::sync::Arc::default();
        s.set_segment_options(Box::new(Stamp {
            seen: std::sync::Arc::clone(&seen),
            overflow,
        }));
        seen
    }

    /// Segment options ride every segment after the handshake, data or
    /// not, and each data segment leaves room for them.
    #[test]
    fn test_segment_options_ride_every_segment_and_take_room() {
        let mut s = socket_established_with_buffer_sizes(256, 64);
        s.remote_mss = 100;
        let seen = stamped(&mut s, false);
        s.send_slice(&[7; 150]).unwrap();
        let stamp = |seq: TcpSeqNumber| {
            let mut bytes = vec![253, 6];
            bytes.extend_from_slice(&(seq.0 as u32).to_be_bytes());
            bytes
        };
        let first = stamp(LOCAL_SEQ + 1);
        let second = stamp(LOCAL_SEQ + 1 + 92);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                extra: &first,
                payload: &[7; 92],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 92),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 92,
                ack_number: Some(REMOTE_SEQ + 1),
                extra: &second,
                payload: &[7; 58],
                ..RECV_TEMPL
            }]
        );
        s.close();
        let fin = stamp(LOCAL_SEQ + 1 + 150);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1 + 150,
                ack_number: Some(REMOTE_SEQ + 1),
                extra: &fin,
                ..RECV_TEMPL
            }]
        );
        let seen = seen.lock().unwrap();
        let ack = Some((REMOTE_SEQ + 1).0 as u32);
        assert_eq!(
            seen.sent,
            [
                ((LOCAL_SEQ + 1).0 as u32, vec![7; 92], false, ack),
                ((LOCAL_SEQ + 1 + 92).0 as u32, vec![7; 58], false, ack),
                ((LOCAL_SEQ + 1 + 150).0 as u32, vec![], true, ack),
            ]
        );
    }

    /// Options past the room are not sent, and a RST carries none.
    #[test]
    fn test_segment_options_past_their_room_are_dropped() {
        let mut s = socket_established();
        let seen = stamped(&mut s, true);
        s.send_slice(b"abc").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: b"abc",
                ..RECV_TEMPL
            }]
        );
        s.abort();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 1 + 3,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(seen.lock().unwrap().sent.len(), 1);
    }

    /// Keeps every byte but `x`, and resets the connection with an option
    /// of kind 252 when a segment carries `!`.
    struct DropX;

    impl SegmentOptions for DropX {
        fn room(&self) -> usize {
            0
        }

        fn sent(&mut self, _: &Outgoing<'_>, _: &mut Vec<u8>) {}

        fn received(&mut self, segment: &Incoming<'_>) -> Verdict {
            if segment.payload.contains(&b'!') {
                Verdict::Reset(vec![252, 2])
            } else {
                Verdict::Take
            }
        }

        fn arrived(&mut self, _: u32, data: &mut Chunk, _: &Budget) -> Verdict {
            *data = Chunk::unpaid(
                data.iter()
                    .copied()
                    .filter(|byte| *byte != b'x')
                    .collect::<Vec<u8>>(),
            );
            Verdict::Take
        }
    }

    /// Bytes the segment options drop are acknowledged and never read,
    /// whether they came in order or filled a gap, and bytes that came
    /// after the gap stay where they belong.
    #[test]
    fn test_segment_options_choose_the_bytes_read() {
        let mut s = socket_established();
        s.set_segment_options(Box::new(DropX));
        // Out of order: kept aside until the gap fills.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 4,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"exgh"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: 64,
                sack_ranges: [None, None, None],
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 8,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"ij"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: 64,
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"axcd"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 10),
                window_len: 56,
                ..RECV_TEMPL
            })
        );
        let mut read = [0; 16];
        let n = s.recv_slice(&mut read).unwrap();
        assert_eq!(&read[..n], b"acdeghij");
        // A later byte goes on from there.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 10,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"xk"[..],
                ..SEND_TEMPL
            }
        );
        let n = s.recv_slice(&mut read).unwrap();
        assert_eq!(&read[..n], b"k");
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 12),
                window_len: 64,
                ..RECV_TEMPL
            }]
        );
    }

    /// A segment the segment options reset on is not taken: the connection
    /// closes, and its RST carries the options they gave.
    #[test]
    fn test_segment_options_can_reset() {
        let mut s = socket_established();
        s.set_segment_options(Box::new(DropX));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"no!"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
        assert_eq!(s.recv_queue(), 0);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                extra: &[252, 2],
                ..RECV_TEMPL
            }]
        );
    }

    /// Segment options see each segment the socket takes, with its wire
    /// options, and none it refuses; the socket drops them with the
    /// connection.
    #[test]
    fn test_segment_options_see_segments_taken() {
        let mut s = socket_established();
        let seen = stamped(&mut s, false);
        let ip_repr = IpReprIpvX(IpvXRepr {
            identification: 0,
            options: crate::wire::Ipv4OptionBytes::EMPTY,
            wire_dst: None,
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: 0,
            hop_limit: 64,
        });
        let take = |s: &mut TestSocket, seq: TcpSeqNumber, control, payload: &[u8]| {
            let repr = TcpRepr {
                control,
                seq_number: seq,
                ack_number: Some(LOCAL_SEQ + 1),
                payload,
                ..SEND_TEMPL
            };
            s.socket.process(
                &mut s.cx,
                &ip_repr,
                &repr,
                &[1, 1, 253, 4, 0xab, 0xcd],
                &Chunk::unpaid(repr.payload.to_vec()),
            )
        };
        take(&mut s, REMOTE_SEQ + 1, TcpControl::Psh, b"hi");
        // Out of the window: refused with an ACK, and not seen.
        take(&mut s, REMOTE_SEQ + 1 + 1000, TcpControl::None, b"no");
        take(&mut s, REMOTE_SEQ + 1 + 2, TcpControl::Fin, b"");
        let options = vec![1, 1, 253, 4, 0xab, 0xcd];
        assert_eq!(
            seen.lock().unwrap().received,
            [
                (
                    (REMOTE_SEQ + 1).0 as u32,
                    b"hi".to_vec(),
                    false,
                    options.clone()
                ),
                ((REMOTE_SEQ + 1 + 2).0 as u32, vec![], true, options),
            ]
        );
        s.reset();
        assert!(s.segment_options.is_none());
    }

    /// A handshake answered with a SYN cookie: the ACK that returns it
    /// establishes the connection, with the MSS the cookie kept and none
    /// of the options a SYN cookie cannot keep, and data on that ACK is
    /// taken.
    #[test]
    fn test_accept_syn_cookie_then_its_ack_establishes() {
        let mut s = socket_listen();
        let iss = TcpSeqNumber(0x1234_5678);
        s.socket.accept_syn_cookie(
            LOCAL_END,
            REMOTE_END,
            REMOTE_SEQ.0 as u32,
            iss.0 as u32,
            1300,
            Instant::ZERO,
        );
        assert_eq!(s.state, State::SynReceived);
        assert_eq!(s.remote_mss, 1300);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(iss + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_win_scale, None);
        assert!(!s.remote_has_sack);
        assert_eq!(s.local_seq_no, iss + 1);
        assert_eq!(s.recv_queue(), 6);
        recv!(
            s,
            [TcpRepr {
                seq_number: iss + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
    }

    /// An ACK that does not acknowledge the cookie's SYN-ACK does not
    /// establish the connection.
    #[test]
    fn test_accept_syn_cookie_wants_its_own_ack() {
        let mut s = socket_listen();
        let iss = TcpSeqNumber(0x1234_5678);
        s.socket.accept_syn_cookie(
            LOCAL_END,
            REMOTE_END,
            REMOTE_SEQ.0 as u32,
            iss.0 as u32,
            1460,
            Instant::ZERO,
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(iss + 2),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: iss + 2,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_ne!(s.state, State::Established);
    }

    #[test]
    fn test_encode_options_checks_room_and_reading() {
        assert_eq!(encode_options(&[MP_CAPABLE]).unwrap(), MP_CAPABLE_BYTES);
        let too_long = TcpOption::Unknown {
            kind: 253,
            data: &[0; SYN_OPTIONS_ROOM][..SYN_OPTIONS_ROOM - 1],
        };
        assert_eq!(encode_options(&[too_long]), Err(SynOptionsError::TooLong));
        assert_eq!(
            encode_options(&[TcpOption::EndOfList]),
            Err(SynOptionsError::Unreadable)
        );
    }

    #[test]
    fn test_syn_options_that_cannot_be_sent_are_refused() {
        let mut s = socket_syn_received();
        s.set_syn_options(&[MP_CAPABLE]).unwrap();
        let unchanged = s.syn_options.clone();
        let room = |n: usize| TcpOption::Unknown {
            kind: 253,
            data: &[0; SYN_OPTIONS_ROOM][..n - 2],
        };
        s.set_syn_options(&[room(SYN_OPTIONS_ROOM)]).unwrap();
        s.set_syn_options(&[MP_CAPABLE]).unwrap();
        for (options, error) in [
            (&[room(SYN_OPTIONS_ROOM + 1)][..], SynOptionsError::TooLong),
            (&[MP_CAPABLE, MP_CAPABLE][..], SynOptionsError::TooLong),
            (&[TcpOption::EndOfList][..], SynOptionsError::Unreadable),
            (
                &[TcpOption::EndOfList, MP_CAPABLE][..],
                SynOptionsError::Unreadable,
            ),
            (
                &[TcpOption::Unknown { kind: 0, data: &[] }][..],
                SynOptionsError::Unreadable,
            ),
            (
                &[TcpOption::Unknown {
                    kind: 1,
                    data: &[7],
                }][..],
                SynOptionsError::Unreadable,
            ),
            // These bytes read back as a Maximum Segment Size.
            (
                &[TcpOption::Unknown {
                    kind: 2,
                    data: &[5, 0xb4],
                }][..],
                SynOptionsError::Unreadable,
            ),
            // A gap among the SACK blocks closes up when written.
            (
                &[TcpOption::SackRange([
                    Some((1, 2)),
                    None,
                    Some((3, 4)),
                    None,
                ])][..],
                SynOptionsError::Unreadable,
            ),
        ] {
            assert_eq!(s.set_syn_options(options), Err(error), "{options:?}");
            assert_eq!(s.syn_options, unchanged);
        }
        // A known kind of another length reads back as itself, unknown.
        let odd_mss = TcpOption::Unknown {
            kind: 2,
            data: &[5, 0xb4, 0],
        };
        s.set_syn_options(&[odd_mss]).unwrap();
        assert_eq!(s.syn_options, [2, 5, 5, 0xb4, 0]);
    }

    /// A SYN-ACK with every option the socket adds and the most extra
    /// options it takes fills the whole header.
    #[test]
    fn test_syn_options_fill_the_header_beside_every_own_option() {
        let mut s = socket_listen();
        s.set_tsval_generator(Some(|_| 7));
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                window_scale: Some(0),
                sack_permitted: true,
                timestamp: Some(TcpTimestampRepr::new(9, 0)),
                ..SEND_TEMPL
            }
        );
        let data = [0xee; SYN_OPTIONS_ROOM - 2];
        s.set_syn_options(&[TcpOption::Unknown {
            kind: 253,
            data: &data,
        }])
        .unwrap();
        recv(&mut s, Instant::from_millis(0), |repr| {
            let repr = repr.unwrap();
            let mut bytes = vec![0; repr.buffer_len()];
            repr.emit(
                &mut crate::wire::TcpPacket::new_unchecked(&mut bytes),
                &LOCAL_ADDR.into(),
                &REMOTE_ADDR.into(),
            );
            let packet = crate::wire::TcpPacket::new_unchecked(&bytes[..]);
            assert_eq!(packet.header_len(), 60);
            let options: Vec<_> = packet.options_iter().unwrap().collect();
            assert_eq!(
                options,
                [
                    Ok(TcpOption::MaxSegmentSize(BASE_MSS)),
                    Ok(TcpOption::WindowScale(0)),
                    Ok(TcpOption::SackPermitted),
                    Ok(TcpOption::TimeStamp { tsval: 7, tsecr: 9 }),
                    Ok(TcpOption::Unknown {
                        kind: 253,
                        data: &data,
                    }),
                ]
            );
            assert_eq!(
                TcpRepr::parse(&packet, &LOCAL_ADDR.into(), &REMOTE_ADDR.into()),
                Ok(TcpRepr { extra: &[], ..repr })
            );
        });
    }

    #[test]
    fn test_syn_received_no_window_scaling() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: None,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_scale: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.remote_win_shift, 0);
        assert_eq!(s.remote_win_scale, None);
    }

    #[test]
    fn test_syn_received_window_scaling() {
        for scale in 0..14 {
            let mut s = socket_listen();
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: REMOTE_SEQ,
                    ack_number: None,
                    window_scale: Some(scale),
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.state(), State::SynReceived);
            assert_eq!(s.tuple, Some(TUPLE));
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: Some(REMOTE_SEQ + 1),
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(0),
                    ..RECV_TEMPL
                }]
            );
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    window_scale: None,
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.remote_win_scale, Some(scale));
        }
    }

    #[test]
    fn test_syn_received_close() {
        let mut s = socket_syn_received();
        s.close();
        assert_eq!(s.state, State::FinWait1);
    }

    // =========================================================================================//
    // Tests for the SYN-SENT state.
    // =========================================================================================//

    #[test]
    fn test_connect_validation() {
        let mut s = socket();
        assert_eq!(
            s.socket
                .connect(&mut s.cx, REMOTE_END, (IpvXAddress::UNSPECIFIED, 0)),
            Err(ConnectError::Unaddressable)
        );
        assert_eq!(
            s.socket
                .connect(&mut s.cx, REMOTE_END, (IpvXAddress::UNSPECIFIED, 1024)),
            Err(ConnectError::Unaddressable)
        );
        assert_eq!(
            s.socket
                .connect(&mut s.cx, (IpvXAddress::UNSPECIFIED, 0), LOCAL_END),
            Err(ConnectError::Unaddressable)
        );
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END)
            .expect("Connect failed with valid parameters");
        assert_eq!(s.tuple, Some(TUPLE));
    }

    #[test]
    fn literal_ports_in_simultaneous_open_close_on_reset() {
        for (local_port, remote_port) in [(0, 0), (0, u16::MAX), (u16::MAX, 0)] {
            let mut s = socket();
            let local = IpEndpoint {
                port: local_port,
                ..LOCAL_END
            };
            let remote = IpEndpoint {
                port: remote_port,
                ..REMOTE_END
            };
            s.socket.connect(&mut s.cx, remote, local).unwrap();
            assert_eq!(s.local_endpoint(), Some(local));
            assert_eq!(s.remote_endpoint(), Some(remote));
            let syn = TcpRepr {
                src_port: remote_port,
                dst_port: local_port,
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            };
            send!(s, syn);
            assert!(matches!(s.state, State::SynReceived));
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Rst,
                    seq_number: REMOTE_SEQ + 1,
                    ..syn
                }
            );
            assert!(matches!(s.state, State::Closed));
            assert!(s.tuple.is_none());
        }
    }

    #[test]
    fn test_connect() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tuple, Some(TUPLE));
    }

    #[test]
    fn test_connect_synack_tiny_mss_is_clamped() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(10),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_mss, MIN_REMOTE_MSS);
    }

    #[test]
    fn test_connect_synack_zero_mss_is_ignored() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(0),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_mss, DEFAULT_MSS);
    }

    #[test]
    fn test_connect_specified_local() {
        let mut s = socket();
        assert_eq!(
            s.socket.connect(&mut s.cx, REMOTE_END, (REMOTE_ADDR, 80)),
            Ok(())
        );
    }

    #[test]
    fn test_connect_twice() {
        let mut s = socket();
        assert_eq!(s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END), Ok(()));
        assert_eq!(
            s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END),
            Err(ConnectError::InvalidState)
        );
    }

    #[test]
    fn test_connect_handshake() {
        let mut s = socket();
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        assert_eq!(s.state(), State::SynSent);
        assert_eq!(s.local_endpoint(), Some(LOCAL_END));
        assert_eq!(s.remote_endpoint(), Some(REMOTE_END));
        assert_eq!(s.send_slice(b"x"), Err(SendError::InvalidState));
        assert!(!s.can_recv());
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.send_slice(b"hello"), Ok(5));
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: b"hello",
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.send_queue(), 0);
        recv_nothing!(s, time 1000);
    }

    #[test]
    fn test_syn_sent_syn_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s, time 1000);
        assert_eq!(s.state, State::Established);
        sanity!(s, socket_established());
    }

    #[test]
    fn test_syn_sent_syn_received_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );

        // A SYN packet changes the SYN-SENT state to SYN-RECEIVED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynReceived);

        // The socket will then send a SYN|ACK packet.
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s);

        // The socket may retransmit the SYN|ACK packet.
        recv!(
            s,
            time 1001,
            Ok(TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                ..RECV_TEMPL
            })
        );

        // An ACK packet changes the SYN-RECEIVED state to ESTABLISHED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        sanity!(s, socket_established());
    }

    /// When both ends open at once, the peer's SYN can arrive before this
    /// socket has sent its own, and the peer can repeat it before this
    /// socket gets to send. The socket must still send its SYN|ACK, or
    /// neither end ever completes the handshake.
    #[test]
    fn test_syn_sent_peer_syn_before_own_syn() {
        let mut s = socket();
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        let syn = TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS - 80),
            window_scale: Some(0),
            ..SEND_TEMPL
        };
        send!(s, syn);
        assert_eq!(s.state, State::SynReceived);
        // The repeated SYN draws an ACK, and nothing else.
        let _ = send(&mut s, Instant::from_millis(0), &syn);
        let mut syn_ack = false;
        for t in (0..=60_000).step_by(100) {
            s.cx.set_now(Instant::from_millis(t));
            let _ = s
                .socket
                .dispatch(&mut s.cx, DispatchMode::All, |_, (_, repr, _)| {
                    syn_ack |= repr.control == TcpControl::Syn
                        && repr.seq_number == LOCAL_SEQ
                        && repr.ack_number == Some(REMOTE_SEQ + 1);
                    Ok::<(), ()>(())
                });
        }
        assert!(syn_ack, "no SYN|ACK within a minute");
    }

    #[test]
    fn test_syn_sent_syn_ack_not_incremented() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ), // WRONG
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_syn_received_rst() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );

        // A SYN packet changes the SYN-SENT state to SYN-RECEIVED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynReceived);

        // A RST packet changes the SYN-RECEIVED state to CLOSED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_syn_sent_syn_rst() {
        for ack in [
            None,
            Some(LOCAL_SEQ),
            Some(LOCAL_SEQ + 1),
            Some(LOCAL_SEQ + 2),
        ] {
            let mut s = socket_syn_sent();
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: None,
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(0),
                    sack_permitted: true,
                    ..RECV_TEMPL
                }]
            );
            send!(s, reset_with_flags(REMOTE_SEQ, ack, 2));
            assert_eq!(
                s.state(),
                if ack == Some(LOCAL_SEQ + 1) {
                    State::Closed
                } else {
                    State::SynSent
                }
            );
            recv!(s, []);
        }
    }

    #[test]
    fn test_syn_sent_close() {
        let mut s = socket_syn_sent();
        // RFC 9293 section 3.10.4 closes an active open without sending a segment.
        s.close();
        assert_eq!(s.state(), State::Closed);
        recv!(s, []);
    }

    #[test]
    fn test_syn_sent_rst() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_syn_sent_rst_no_ack() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_rst_bad_ack() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: Some(TcpSeqNumber(1234)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None, // Unexpected
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1), // Correct
                ..SEND_TEMPL
            }
        );

        // It should trigger no response and change no state
        recv!(s, []);
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack_seq_1() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ), // WRONG
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ, // matching the ack_number of the unexpected ack
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );

        // It should trigger a RST, and change no state
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack_seq_2() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 123456), // WRONG
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 123456, // matching the ack_number of the unexpected ack
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );

        // It should trigger a RST, and change no state
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_sack_option() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                sack_permitted: true,
                ..SEND_TEMPL
            }
        );
        assert!(s.remote_has_sack);

        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                sack_permitted: false,
                ..SEND_TEMPL
            }
        );
        assert!(!s.remote_has_sack);
    }

    #[test]
    fn test_syn_sent_win_scale_buffers() {
        for (buffer_size, shift_amt) in &[
            (64, 0),
            (128, 0),
            (1024, 0),
            (65535, 0),
            (65536, 1),
            (65537, 1),
            (131071, 1),
            (131072, 2),
            (524287, 3),
            (524288, 4),
            (655350, 4),
            (1048576, 5),
        ] {
            let mut s = socket_with_buffer_sizes(64, *buffer_size);
            s.local_seq_no = LOCAL_SEQ;
            assert_eq!(s.remote_win_shift, *shift_amt);
            s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: None,
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(*shift_amt),
                    window_len: u16::try_from(*buffer_size).unwrap_or(u16::MAX),
                    sack_permitted: true,
                    ..RECV_TEMPL
                }]
            );
        }
    }

    #[test]
    fn test_syn_sent_syn_ack_no_window_scaling() {
        let mut s = socket_syn_sent_with_buffer_sizes(1048576, 1048576);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                // scaling does NOT apply to the window value in SYN packets
                window_len: 65535,
                window_scale: Some(5),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.remote_win_shift, 5);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: None,
                window_len: 42,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_win_shift, 0);
        assert_eq!(s.remote_win_scale, None);
        assert_eq!(s.remote_win_len, 42);
    }

    #[test]
    fn test_syn_sent_syn_ack_window_scaling() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(7),
                window_len: 42,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_win_scale, Some(7));
        // scaling does NOT apply to the window value in SYN packets
        assert_eq!(s.remote_win_len, 42);
    }

    // =========================================================================================//
    // Tests for the ESTABLISHED state.
    // =========================================================================================//

    #[test]
    fn test_established_recv() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
        let mut bytes = [0; 6];
        assert_eq!(s.recv_slice(&mut bytes), Ok(6));
        assert_eq!(&bytes, b"abcdef");
    }

    #[test]
    fn receive_window_holds_small_segments_until_the_application_reads() {
        for capacity in [256 * 1024, 2 * 1024 * 1024] {
            let mut s = socket_established_with_buffer_sizes(64, capacity);
            let stream: Vec<u8> = (0..capacity)
                .map(|offset| (offset ^ (offset >> 8)) as u8)
                .collect();
            let mut accepted = 0;
            for payload in stream.chunks(usize::from(BASE_MSS)) {
                send(
                    &mut s,
                    Instant::ZERO,
                    &TcpRepr {
                        seq_number: REMOTE_SEQ + 1 + accepted,
                        ack_number: Some(LOCAL_SEQ + 1),
                        payload,
                        ..SEND_TEMPL
                    },
                );
                accepted += payload.len();
                assert_eq!(s.recv_queue(), accepted);
                assert_eq!(s.rx.window(), capacity - accepted);
                assert!(s.assembler.is_empty());
            }
            let mut delivered = Vec::new();
            while s.can_recv() {
                s.recv(|bytes| {
                    delivered.extend_from_slice(bytes);
                    (bytes.len(), ())
                })
                .unwrap();
                assert_eq!(s.rx.window(), delivered.len());
            }
            assert_eq!(delivered, stream);
        }
    }

    #[test]
    fn send_window_admits_small_writes_until_its_byte_capacity() {
        for capacity in [256 * 1024, 2 * 1024 * 1024] {
            let mut s = socket_established_with_buffer_sizes(capacity, 64);
            let stream: Vec<u8> = (0..capacity)
                .map(|offset| (offset ^ (offset >> 8)) as u8)
                .collect();
            let mut queued = 0;
            for bytes in stream.chunks(usize::from(BASE_MSS)) {
                assert_eq!(s.send_slice(bytes), Ok(bytes.len()));
                queued += bytes.len();
                assert_eq!(s.send_queue(), queued);
                assert_eq!(s.tx.window(), capacity - queued);
            }
            let mut offset = 0;
            while offset < stream.len() {
                let bytes = s.tx.bytes(offset, stream.len() - offset);
                assert!(!bytes.is_empty());
                assert_eq!(bytes, &stream[offset..offset + bytes.len()]);
                offset += bytes.len();
            }
        }
    }

    #[test]
    fn test_recv_slice_partial_buffer() {
        const BUF_SIZE: usize = 10;

        let send_buf = b"0123456";

        let mut s = socket_established_with_buffer_sizes(BUF_SIZE, BUF_SIZE);

        // Populate the recv buffer
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &send_buf[..],
                ..SEND_TEMPL
            }
        );

        let mut recv_buf = [0u8; BUF_SIZE];
        assert_eq!(s.recv_slice(&mut recv_buf), Ok(7));
        assert_eq!(&recv_buf[..7], b"0123456");
    }

    #[test]
    fn test_recv_slice_buffer_wrap() {
        const BUF_SIZE: usize = 10;

        let send_buf = b"0123456789";

        let mut s = socket_established_with_buffer_sizes(BUF_SIZE, BUF_SIZE);

        s.rx.commit(Chunk::unpaid(send_buf[..8].to_vec()));
        let mut prefix = [0; 6];
        assert_eq!(s.recv_slice(&mut prefix), Ok(6));
        assert_eq!(&prefix, b"012345");
        s.rx.commit(Chunk::unpaid(send_buf[..5].to_vec()));

        let mut recv_buf = [0u8; BUF_SIZE];
        assert_eq!(s.recv_slice(&mut recv_buf), Ok(7));
        assert_eq!(&recv_buf[..7], b"6701234");
    }

    #[test]
    fn test_pending_recv_waits_for_gap() {
        let mut s = socket_established();
        assert!(!s.has_pending_recv());
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 5,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"efgh",
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.recv_queue(), 0);
        assert!(s.has_pending_recv());
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"abcd",
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 9),
                window_len: 56,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.recv_queue(), 8);
        assert!(!s.has_pending_recv());
        let mut data = [0; 8];
        assert_eq!(s.recv_slice(&mut data).unwrap(), 8);
        assert_eq!(&data, b"abcdefgh");
        assert!(!s.has_pending_recv());
    }

    fn setup_rfc2018_cases() -> (TestSocket, Vec<u8>) {
        // This is a utility function used by the tests for RFC 2018 cases. It configures a socket
        // in a particular way suitable for those cases.
        //
        // RFC 2018: Assume the left window edge is 5000 and that the data transmitter sends [...]
        // segments, each containing 500 data bytes.
        let mut s = socket_established_with_buffer_sizes(4000, 4000);
        s.remote_has_sack = true;

        // create a segment that is 500 bytes long
        let mut segment: Vec<u8> = Vec::with_capacity(500);

        // move the last ack to 5000 by sending ten of them
        for _ in 0..50 {
            segment.extend_from_slice(b"abcdefghij")
        }
        for offset in (0..5000).step_by(500) {
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + offset,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &segment,
                    ..SEND_TEMPL
                }
            );
            recv!(
                s,
                [TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1 + offset + 500),
                    window_len: 3500,
                    ..RECV_TEMPL
                }]
            );
            s.recv(|data| {
                assert_eq!(data.len(), 500);
                assert_eq!(data, segment.as_slice());
                (500, ())
            })
            .unwrap();
        }
        assert_eq!(s.remote_last_win, 3500);
        (s, segment)
    }

    #[test]
    fn test_established_rfc2018_cases() {
        // This test case verifies the exact scenarios described on pages 8-9 of RFC 2018. Please
        // ensure its behavior does not deviate from those scenarios.

        let (mut s, segment) = setup_rfc2018_cases();
        // RFC 2018:
        //
        // Case 2: The first segment is dropped but the remaining 7 are received.
        //
        // Upon receiving each of the last seven packets, the data receiver will return a TCP ACK
        // segment that acknowledges sequence number 5000 and contains a SACK option specifying one
        // block of queued data:
        //
        //   Triggering   ACK      Left Edge  Right Edge
        //   Segment
        //
        //   5000         (lost)
        //   5500         5000     5500       6000
        //   6000         5000     5500       6500
        //   6500         5000     5500       7000
        //   7000         5000     5500       7500
        //   7500         5000     5500       8000
        //   8000         5000     5500       8500
        //   8500         5000     5500       9000
        //
        for offset in (500..3500).step_by(500) {
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + offset + 5000,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &segment,
                    ..SEND_TEMPL
                },
                Some(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1 + 5000),
                    window_len: 4000,
                    sack_ranges: [
                        Some((
                            REMOTE_SEQ.0 as u32 + 1 + 5500,
                            REMOTE_SEQ.0 as u32 + 1 + 5500 + offset as u32
                        )),
                        None,
                        None
                    ],
                    ..RECV_TEMPL
                })
            );
        }
    }

    #[test]
    fn test_established_sack_no_overflow_on_near_max_seqnumber() {
        let mut s = socket_established();
        s.remote_has_sack = true;
        s.remote_seq_no = TcpSeqNumber(-4);
        s.remote_last_ack = Some(TcpSeqNumber(-4));
        s.remote_win_end = Some(TcpSeqNumber(-4) + 64);

        // Send an out-of-order segment 10 bytes past the expected sequence,
        // creating a 10-byte hole at the front of the assembler.
        send!(
            s,
            TcpRepr {
                seq_number: TcpSeqNumber(-4 + 10),
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"AAAAAAAAAA"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(TcpSeqNumber(-4)),
                window_len: 64,
                sack_ranges: [
                    Some(((-4_i32 + 10) as u32, (-4_i32 + 20) as u32,)),
                    None,
                    None,
                ],
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_established_sliding_window_recv() {
        let mut s = socket_established_with_buffer_sizes(64, 262143);
        assert_eq!(s.rx.len(), 0);
        s.remote_win_scale = Some(0);

        // Create a TCP segment that will mostly fill an IP frame.
        let mut segment: Vec<u8> = Vec::with_capacity(1400);
        for _ in 0..100 {
            segment.extend_from_slice(b"abcdefghijklmn")
        }
        assert_eq!(segment.len(), 1400);

        // Send the frame
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            }
        );

        // Ensure that the received window size is shifted right by 2.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1400),
                window_len: 65185,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send() {
        let mut s = socket_established();
        // First roundtrip after establishing.
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.tx.len(), 6);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx.len(), 0);
        // Second roundtrip.
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx.len(), 0);
    }

    #[test]
    fn test_established_send_no_ack_send() {
        let mut s = socket_established();
        s.set_nagle_enabled(false);
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send_buf_gt_win() {
        let mut data = [0; 32];
        for (i, elem) in data.iter_mut().enumerate() {
            *elem = i as u8
        }

        let mut s = socket_established();
        s.remote_win_len = 16;
        s.send_slice(&data[..]).unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &data[0..16],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send_window_shrink() {
        let mut s = socket_established();

        // 6 octets fit on the remote side's window, so we send them.
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.tx.len(), 6);

        println!(
            "local_seq_no={:?} remote_win_len={} remote_last_seq={:?}",
            s.local_seq_no, s.remote_win_len, s.remote_last_seq
        );

        // - Peer doesn't ack them yet
        // - Sends data so we need to reply with an ACK
        // - ...AND and sends a window announcement that SHRINKS the window, so data we've
        //   previously sent is now outside the window. Yes, this is allowed by TCP.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 3,
                payload: &b"xyzxyz"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx.len(), 6);

        println!(
            "local_seq_no={:?} remote_win_len={} remote_last_seq={:?}",
            s.local_seq_no, s.remote_win_len, s.remote_last_seq
        );

        // More data should not get sent since it doesn't fit in the window
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 64 - 6,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_receive_partially_outside_window() {
        let mut s = socket_established();

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();

        // Peer decides to retransmit (perhaps because the ACK was lost)
        // and also pushed data.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"def");
            (3, ())
        })
        .unwrap();
    }

    #[test]
    fn test_established_receive_partially_outside_window_fin() {
        let mut s = socket_established();

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();

        // Peer decides to retransmit (perhaps because the ACK was lost)
        // and also pushed data, and sent a FIN.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                control: TcpControl::Fin,
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"def");
            (3, ())
        })
        .unwrap();

        // We should accept the FIN, because even though the last packet was partially
        // outside the receive window, there is no hole after adding its data to the assembler.
        assert_eq!(s.state, State::CloseWait);
    }

    #[test]
    fn test_established_send_wrap() {
        let mut s = socket_established();
        let local_seq_start = TcpSeqNumber(i32::MAX - 1);
        s.local_seq_no = local_seq_start + 1;
        s.remote_last_seq = local_seq_start + 1;
        s.local_seq_max = s.remote_last_seq;
        s.send_slice(b"abc").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: local_seq_start + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_no_ack() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_established_bad_ack() {
        let mut s = socket_established();
        // Already acknowledged data.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(TcpSeqNumber(LOCAL_SEQ.0 - 1)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        // Data not yet transmitted.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 10),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
    }

    #[test]
    fn test_established_bad_seq() {
        let mut s = socket_established();
        // Data outside of receive window.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);

        // Challenge ACKs are rate-limited, we don't get a second one immediately.
        send!(
            s,
            time 100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );

        // If we wait a bit, we do get a new one.
        send!(
            s,
            time 2000,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_old_data_ack_not_rate_limited() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
        s.recv(|data| {
            assert_eq!(data, b"abcdef");
            (6, ())
        })
        .unwrap();
        // The remote retransmits data we already acknowledged, e.g. because
        // the ACK above was lost. Each retransmission must elicit a duplicate
        // ACK, even within the challenge ACK rate limit window: withholding it
        // strands the remote in retransmission backoff.
        send!(
            s,
            time 100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            time 200,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_bad_seq_rst_dropped_silently() {
        let mut s = socket_established();
        // Out-of-window RSTs are silently dropped, per RFC 9293 (3.10.7.4)
        // and RFC 5961 (3.2): no challenge ACK, no state change.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);

        // A payload doesn't make it eligible for the data segment exemption
        // from challenge ACK rate limiting either: still no reply.
        send!(
            s,
            time 100,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
    }

    #[test]
    fn test_bad_seq_syn_with_data_rate_limited() {
        let mut s = socket_established();
        // An out-of-window SYN carrying data must not be exempt from challenge
        // ACK rate limiting: RFC 5961 (4.2) says challenge ACKs sent in
        // response to SYNs should be throttled.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );

        // The second one within the rate limit window gets no reply.
        send!(
            s,
            time 100,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
    }

    #[test]
    fn test_established_options_reduce_payload_when_local_mss_limited() {
        const EFFECTIVE_MSS: usize = 64;

        // construct socket where remote MSS is less than local MSS
        let mut s = socket_established();
        s.set_tsval_generator(Some(|_| 1));
        s.remote_mss = EFFECTIVE_MSS;

        // Payload should contain 12 bytes less due to timestamp
        s.send_slice(&[0; EFFECTIVE_MSS]).unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; EFFECTIVE_MSS - 12],
                timestamp: Some(TcpTimestampRepr::new(1, 0)),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_options_reduce_payload_when_remote_mss_limited() {
        const EFFECTIVE_MSS: usize = BASE_MSS as usize;

        // construct socket where remote MSS is more than local MSS
        let mut s = socket_established_with_buffer_sizes(EFFECTIVE_MSS, 64);
        s.set_tsval_generator(Some(|_| 1));
        s.remote_mss = 9999;
        s.remote_win_len = 9999;

        // Payload should contain 12 bytes less due to timestamp
        s.send_slice(&[0; EFFECTIVE_MSS]).unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; EFFECTIVE_MSS - 12],
                timestamp: Some(TcpTimestampRepr::new(1, 0)),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_tiny_mss_with_options_makes_progress() {
        // Connect with timestamps enabled to a remote advertising an absurdly
        // small MSS. Without the MIN_SND_MSS clamp, an MSS smaller than the
        // options length would result in an effective MSS of zero, sending
        // empty segments in a loop without ever making progress.
        let mut s = socket();
        s.set_tsval_generator(Some(|_| 1));
        s.local_seq_no = LOCAL_SEQ;
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                timestamp: Some(TcpTimestampRepr::new(1, 0)),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(10),
                window_scale: Some(0),
                timestamp: Some(TcpTimestampRepr::new(500, 1)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_mss, MIN_REMOTE_MSS);

        s.send_slice(&[0; 64]).unwrap();
        recv!(
            s,
            [
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &[0; MIN_REMOTE_MSS - 12],
                    timestamp: Some(TcpTimestampRepr::new(1, 500)),
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + (MIN_REMOTE_MSS - 12),
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &[0; MIN_REMOTE_MSS - 12],
                    timestamp: Some(TcpTimestampRepr::new(1, 500)),
                    ..RECV_TEMPL
                }
            ]
        );
    }

    #[test]
    fn test_established_fin() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::CloseWait);
        sanity!(s, socket_close_wait());
    }

    #[test]
    fn test_established_fin_after_missing() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"123456"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::Established);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6 + 6),
                window_len: 52,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::Established);
    }

    #[test]
    fn test_established_send_fin() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_rst() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_rst_no_ack() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        sanity!(s, socket_fin_wait_1());
    }

    #[test]
    fn test_established_abort() {
        let mut s = socket_established();
        s.abort();
        assert_eq!(s.state, State::Closed);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_rst_bad_seq() {
        let mut s = socket_established();
        // Out-of-window RSTs are dropped silently, per RFC 9293 (3.10.7.4)
        // and RFC 5961 (3.2).
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ, // Wrong seq
                ack_number: None,
                ..SEND_TEMPL
            }
        );

        assert_eq!(s.state, State::Established);

        // An in-window RST still resets the connection.
        send!(
            s,
            time 2000,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1, // Correct seq
                ack_number: None,
                ..SEND_TEMPL
            }
        );

        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_bad_seq_challenge_ack_updated() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ, // Wrong seq
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );

        assert_eq!(s.state, State::Established);

        // Send something to advance seq by 1
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1, // correct seq
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        // A challenge ACK reflects received data before dispatch runs.
        send!(
            s,
            time 2000,
            TcpRepr {
                seq_number: REMOTE_SEQ, // Wrong seq
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2), // this has changed
                window_len: 63,
                ..RECV_TEMPL
            })
        );
    }

    // =========================================================================================//
    // Tests for the FIN-WAIT-1 state.
    // =========================================================================================//

    #[test]
    fn test_fin_wait_1_fin_ack() {
        let mut s = socket_fin_wait_1();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        sanity!(s, socket_fin_wait_2());
    }

    #[test]
    fn test_fin_wait_1_fin_fin() {
        let mut s = socket_fin_wait_1();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);
        sanity!(s, socket_closing());
    }

    #[test]
    fn test_fin_wait_1_fin_with_data_queued() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef123456").unwrap();
        s.close();
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait1);
    }

    #[test]
    fn test_fin_wait_1_recv() {
        let mut s = socket_fin_wait_1();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait1);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
    }

    #[test]
    fn test_fin_wait_1_close() {
        let mut s = socket_fin_wait_1();
        s.close();
        assert_eq!(s.state, State::FinWait1);
    }

    // =========================================================================================//
    // Tests for the FIN-WAIT-2 state.
    // =========================================================================================//

    #[test]
    fn test_fin_wait_2_fin() {
        let mut s = socket_fin_wait_2();
        send!(s, time 1_000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::TimeWait);
        sanity!(s, socket_time_wait(false));
    }

    #[test]
    fn test_fin_wait_2_recv() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_fin_wait_2_close() {
        let mut s = socket_fin_wait_2();
        s.close();
        assert_eq!(s.state, State::FinWait2);
    }

    // =========================================================================================//
    // Tests for the CLOSING state.
    // =========================================================================================//

    #[test]
    fn test_closing_ack_fin() {
        let mut s = socket_closing();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(s, time 1_000, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::TimeWait);
        sanity!(s, socket_time_wait(true));
    }

    #[test]
    fn test_closing_close() {
        let mut s = socket_closing();
        s.close();
        assert_eq!(s.state, State::Closing);
    }

    // =========================================================================================//
    // Tests for the TIME-WAIT state.
    // =========================================================================================//

    #[test]
    fn test_time_wait_from_fin_wait_2_ack() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_time_wait_from_closing_no_ack() {
        let mut s = socket_time_wait(true);
        recv!(s, []);
    }

    #[test]
    fn test_time_wait_close() {
        let mut s = socket_time_wait(false);
        s.close();
        assert_eq!(s.state, State::TimeWait);
    }

    #[test]
    fn test_time_wait_retransmit() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(s, time 5_000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(
            s.timer,
            Timer::Close {
                expires_at: Instant::from_secs(5) + CLOSE_DELAY
            }
        );
    }

    #[test]
    fn test_time_wait_timeout() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::TimeWait);
        recv_nothing!(s, time 240_999);
        assert_eq!(s.state, State::TimeWait);
        recv_nothing!(s, time 241_000);
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the CLOSE-WAIT state.
    // =========================================================================================//

    #[test]
    fn test_close_wait_ack() {
        let mut s = socket_close_wait();
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_close_wait_close() {
        let mut s = socket_close_wait();
        s.close();
        assert_eq!(s.state, State::LastAck);
        sanity!(s, socket_last_ack());
    }

    // =========================================================================================//
    // Tests for the LAST-ACK state.
    // =========================================================================================//
    #[test]
    fn test_last_ack_fin_ack() {
        let mut s = socket_last_ack();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::LastAck);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_last_ack_ack_not_of_fin() {
        let mut s = socket_last_ack();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::LastAck);

        // A duplicate ACK leaves the FIN outstanding.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::LastAck);

        // ACK received of fin: socket should change to Closed.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_last_ack_window_reopens_with_queued_data() {
        let mut s = socket_close_wait();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 2,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );
        s.send_slice(b"abcd").unwrap();
        s.close();
        recv_nothing!(s);
        send!(s, time 100, TcpRepr {
            seq_number: REMOTE_SEQ + 2,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        recv!(s, time 100, [TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 2),
            payload: b"abcd",
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_last_ack_duplicate_acks_retransmit_data() {
        let mut s = socket_close_wait();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 2,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        s.send_slice(b"abcd").unwrap();
        s.close();
        let data = TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 2),
            payload: b"abcd",
            ..RECV_TEMPL
        };
        recv!(s, [data]);
        for time in 1..=3 {
            send!(s, time time, TcpRepr {
                seq_number: REMOTE_SEQ + 2,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            });
        }
        recv!(s, time 3, [data]);
    }

    // A duplicate ACK leaves the FIN outstanding.
    #[test]
    fn test_last_ack_duplicate_ack_keeps_fin_outstanding() {
        let mut s = socket_last_ack();
        // Trigger dispatch so our FIN is sent and remote_last_seq advances.
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::LastAck);

        // The remote repeats SND.UNA without acknowledging the FIN.
        let challenge = send(
            &mut s,
            Instant::from_millis(0),
            &TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
        );
        assert_eq!(challenge, None);
        // State must remain LAST-ACK: we have not received the FIN ACK.
        assert_eq!(s.state, State::LastAck);

        // The FIN ACK closes the connection.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    // A partial ACK in LAST-ACK (ack_len > 0 but not FIN ACK) advances SND.UNA
    // without a challenge ACK; the FIN will be retransmitted by the timer.
    #[test]
    fn test_last_ack_partial_ack_no_challenge_ack() {
        // Build a LAST-ACK socket that has one byte of data still unacknowledged
        // before the FIN.  We manually wire the state so we can send a partial ACK.
        let mut s = socket_last_ack();
        // Push one byte into the tx buffer to simulate data that preceded the FIN.
        s.tx.push(Chunk::unpaid(b"x".to_vec())).unwrap();
        // Mark it as already sent (remote_last_seq is past the data byte and the FIN).
        s.remote_last_seq = LOCAL_SEQ + 1 + 1 + 1; // data(1) + FIN(1)
        s.local_seq_max = s.remote_last_seq;

        // Remote ACKs just the data byte, not the FIN (partial ACK).
        // ack_number = local_seq_no + 1  =>  ack_len = 1, ack_of_fin = false.
        // Per RFC 9293, a valid partial ACK should advance SND.UNA normally;
        // no challenge ACK should be emitted.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1), // acks the data byte, not FIN
                ..SEND_TEMPL
            }
        );
        // State remains LAST-ACK; FIN retransmission is handled by the timer.
        assert_eq!(s.state, State::LastAck);
        // SND.UNA has advanced to the partial ACK number.
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1 + 1);
    }

    #[test]
    fn test_last_ack_close() {
        let mut s = socket_last_ack();
        s.close();
        assert_eq!(s.state, State::LastAck);
    }

    // =========================================================================================//
    // Tests for transitioning through multiple states.
    // =========================================================================================//

    #[test]
    fn test_listen() {
        let mut s = socket();
        s.listen(LISTEN_END).unwrap();
        assert_eq!(s.state, State::Listen);
    }

    #[test]
    fn test_three_way_handshake() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_remote_close() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        s.close();
        assert_eq!(s.state, State::LastAck);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_local_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_simultaneous_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                // due to reordering, this is logically located...
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        // ... at this point
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_simultaneous_close_combined_fin_ack() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_simultaneous_close_raced() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);

        // Socket receives FIN before it has a chance to send its own FIN
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);

        // FIN + ack-of-FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::Closing);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_simultaneous_close_raced_with_data() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state, State::FinWait1);

        // Socket receives FIN before it has a chance to send its own data+FIN
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);

        // data + FIN + ack-of-FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::Closing);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_fin_with_data() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        )
    }

    #[test]
    fn test_mutual_close_with_data_1() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_mutual_close_with_data_2() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::TimeWait);
    }

    // =========================================================================================//
    // Tests for retransmission on packet loss.
    // =========================================================================================//

    #[test]
    fn test_duplicate_seq_ack() {
        let mut s = socket_recved();
        // remote retransmission
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_data_retransmit() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 1050);
        recv!(s, time 2000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_congestion_window_limits_data_in_flight() {
        let mut s = socket_established_with_buffer_sizes(8192, 64);
        s.remote_win_len = 65535;
        s.remote_mss = 1024;

        let data = [b'x'; 8192];
        s.send_slice(&data[..]).unwrap();

        // Reno's initial congestion window is 2048 bytes: only two
        // 1024-byte segments may be in flight, the rest must wait for ACKs.
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1024,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 0);

        // ACKing one segment frees congestion window space and grows
        // cwnd (slow start), allowing further segments out.
        send!(s, time 10, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1024),
            window_len: 65535,
            ..SEND_TEMPL
        });
        recv!(s, time 10, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 2048,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_congestion_window_doesnt_limit_fast_retransmit() {
        let mut s = socket_established_with_buffer_sizes(8192, 64);
        s.remote_win_len = 65535;
        s.remote_mss = 1024;

        // Normal ACK of previously received segment
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 65535,
            ..SEND_TEMPL
        });

        let data = [b'x'; 8192];
        s.send_slice(&data[..]).unwrap();

        // Reno's initial congestion window is 2048 bytes, allowing 2 segments
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));

        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1024,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 0);

        // Send three duplicate ACKS, treating the first segment as lost
        send!(s, time 10, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 65535,
            ..SEND_TEMPL
        });
        send!(s, time 10, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 65535,
            ..SEND_TEMPL
        });
        send!(s, time 10, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 65535,
            ..SEND_TEMPL
        });

        // A fast retrnasmit should be sent and not be blocked by congestion control
        recv!(s, time 20, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_data_retransmit_bursts() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        recv_nothing!(s, time 0);

        recv_nothing!(s, time 50);

        recv!(s, time 1000, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 1500, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        recv_nothing!(s, time 1550);
    }

    #[test]
    fn test_data_retransmit_bursts_half_ack() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        // Acknowledge the first packet
        send!(s, time 5, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        // The second packet should be re-sent.
        recv!(s, time 1500, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);

        recv_nothing!(s, time 1550);
    }

    #[test]
    fn test_retransmit_timer_restart_on_partial_ack() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        // Acknowledge the first packet
        send!(s, time 600, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        // The ACK of the first packet should restart the retransmit timer and delay a retransmission.
        recv_nothing!(s, time 2399);
        // The second packet should be re-sent.
        recv!(s, time 2400, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
    }

    #[test]
    fn test_data_retransmit_bursts_half_ack_close() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef012345").unwrap();
        s.close();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        // Acknowledge the first packet
        send!(s, time 5, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        // The second packet should be re-sent.
        recv!(s, time 1500, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);

        recv_nothing!(s, time 1550);
    }

    #[test]
    fn test_send_data_after_syn_ack_retransmit() {
        let mut s = socket_syn_received();
        recv!(s, time 50, Ok(TcpRepr {
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }));
        recv!(s, time 1050, Ok(TcpRepr { // retransmit
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        )
    }

    #[test]
    fn test_established_retransmit_for_dup_ack() {
        let mut s = socket_established();
        // Duplicate ACKs do not replace the retransmission timer
        s.send_slice(b"abc").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
        // Retransmit timer is on because all data was sent
        assert_eq!(s.tx.len(), 3);
        // ACK nothing new
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Retransmit
        recv!(s, time 4000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_retransmit_reset_after_ack() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_queue_during_retransmission() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef123456ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        })); // this one is dropped
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        })); // this one is received
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        })); // also dropped
        recv!(s, time 3000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        })); // retransmission
        send!(s, time 3005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            ..SEND_TEMPL
        }); // acknowledgement of both segments
        recv!(s, time 3010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        })); // retransmission of only unacknowledged data
    }

    #[test]
    fn test_close_wait_retransmit_reset_after_ack() {
        let mut s = socket_close_wait();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_fin_wait_1_retransmit_reset_after_ack() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        s.close();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_fast_retransmit_after_triple_duplicate_ack() {
        let mut s = socket_established();
        s.remote_mss = 3;

        // Normal ACK of previously received segment
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // Send a long string of text divided into several packets
        // because of previously received "window_len"
        s.send_slice(b"aaaBBBcccDDDeeeFFF").unwrap();

        // This packet is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"aaa"[..],
            ..RECV_TEMPL
        }));

        // These packets arrive
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 3,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"BBB"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (3 * 2),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ccc"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1015, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (3 * 3),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"DDD"[..],
            ..RECV_TEMPL
        }));

        // Duplicate ACKs trigger fast rentramsit after 3rd successive one
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1055, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1060, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // Fast retransmit should have triggered
        recv!(s, time 1100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"aaa"[..],
            ..RECV_TEMPL
        }));

        // Transmission should continue as normal after re-transitting the first segment
        recv!(s, time 1105, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (3 * 4),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"eee"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1110, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (3 * 5),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"FFF"[..],
            ..RECV_TEMPL
        }));

        // ACK all received segments
        send!(s, time 1120, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (3 * 5)),
            ..SEND_TEMPL
        });
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection_with_data() {
        let mut s = socket_established();

        s.send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // Normal ACK of previously received segment
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // First duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Second duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );

        assert_eq!(s.local_rx_dup_acks, 2, "duplicate ACK counter is not set");

        // This packet has content, hence should not be detected
        // as a duplicate ACK and should reset the duplicate ACK count
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"xxxxxx"[..],
                ..SEND_TEMPL
            }
        );

        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 3,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when receiving data"
        );
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection_with_window_update() {
        let mut s = socket_established();

        s.send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // Normal ACK of previously received segment
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // First duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Second duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );

        assert_eq!(s.local_rx_dup_acks, 2, "duplicate ACK counter is not set");

        // This packet has a window update, hence should not be detected
        // as a duplicate ACK and should reset the duplicate ACK count
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 400,
                ..SEND_TEMPL
            }
        );

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when receiving a window update"
        );
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection() {
        let mut s = socket_established();
        s.remote_mss = 6;

        // Normal ACK of previously received segment
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // First duplicate, should not be counted as there is nothing to resend
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is set but wound not transmit data"
        );

        // Send a long string of text divided into several packets
        // because of small remote_mss
        s.send_slice(b"xxxxxxyyyyyywwwwwwzzzzzz").unwrap();

        // This packet is reordered in network
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"xxxxxx"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"yyyyyy"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 2),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"wwwwww"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1015, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 3),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"zzzzzz"[..],
            ..RECV_TEMPL
        }));

        // First duplicate ACK
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Second duplicate ACK
        send!(s, time 1055, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Reordered packet arrives which should reset duplicate ACK count
        send!(s, time 1060, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (6 * 3)),
            ..SEND_TEMPL
        });

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when receiving ACK which updates send window"
        );

        // ACK all received segments
        send!(s, time 1120, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (6 * 4)),
            ..SEND_TEMPL
        });
    }

    #[test]
    fn test_fast_retransmit_dup_acks_counter() {
        let mut s = socket_established();

        s.send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // A lot of retransmits happen here
        s.local_rx_dup_acks = u8::MAX - 1;

        // Send 3 more ACKs, which could overflow local_rx_dup_acks,
        // but intended behaviour is that we saturate the bounds
        // of local_rx_dup_acks
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(
            s.local_rx_dup_acks,
            u8::MAX,
            "duplicate ACK count should not overflow but saturate"
        );
    }

    #[test]
    fn test_fast_retransmit_zero_window() {
        let mut s = socket_established();

        send!(s, time 1000, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        s.send_slice(b"abc").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // 3 dup acks
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0, // boom
            ..SEND_TEMPL
        });

        // even though we're in "fast retransmit", we shouldn't
        // force-send anything because the remote's window is full.
        recv_nothing!(s);
    }

    #[test]
    fn test_retransmit_exponential_backoff() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));

        let expected_retransmission_instant = s.rtte.retransmission_timeout().total_millis() as i64;
        recv_nothing!(s, time expected_retransmission_instant - 1);
        recv!(s, time expected_retransmission_instant, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));

        // "current time" is expected_retransmission_instant, and we want to wait 2 * retransmission timeout
        let expected_retransmission_instant = 3 * expected_retransmission_instant;

        recv_nothing!(s, time expected_retransmission_instant - 1);
        recv!(s, time expected_retransmission_instant, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_data_retransmit_ack_more_than_expected() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"aaaaaabbbbbbcccccc").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"aaaaaa"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"bbbbbb"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 12,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"cccccc"[..],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 0);

        recv_nothing!(s, time 50);

        // retransmit timer expires, we want to retransmit all 3 packets
        // but we only manage to retransmit 2 (due to e.g. lack of device buffer space)
        assert!(s.timer.is_retransmit());
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"aaaaaa"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"bbbbbb"[..],
            ..RECV_TEMPL
        }));

        // ack first packet.
        send!(
            s,
            time 3000,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );

        // this should keep retransmit timer on, because there's
        // still unacked data.
        assert!(s.timer.is_retransmit());

        // ack all three packets.
        // This might confuse the TCP stack because after the retransmit
        // it "thinks" the 3rd packet hasn't been transmitted yet, but it is getting acked.
        send!(
            s,
            time 3000,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 18),
                ..SEND_TEMPL
            }
        );

        // this should exit retransmit mode.
        assert!(!s.timer.is_retransmit());
        // and consider all data ACKed.
        assert!(s.tx.is_empty());
        recv_nothing!(s, time 5000);
    }

    #[test]
    fn test_retransmit_fin() {
        let mut s = socket_established();
        s.close();
        recv!(s, time 0, Ok(TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));

        recv_nothing!(s, time 999);
        recv!(s, time 1000, Ok(TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_retransmit_fin_wait() {
        let mut s = socket_fin_wait_1();
        // we send FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        // remote also sends FIN, does NOT ack ours.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // we ack it
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::None,
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]
        );

        // we haven't got an ACK for our FIN, we should retransmit.
        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]
        );
    }

    // =========================================================================================//
    // Tests for window management.
    // =========================================================================================//

    #[test]
    fn test_maximum_segment_size() {
        let mut s = socket_listen();
        s.tx = TxStore::new(32767, Budget::unlimited(), &pool());
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(1000),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 32767,
                ..SEND_TEMPL
            }
        );
        s.send_slice(&[0; 1200][..]).unwrap();
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; 1000][..],
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_recv_out_of_recv_win() {
        let mut s = socket_established();
        s.settings.ack_segments = 1;
        s.settings.ack_inclusive = false;
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        s.remote_mss = 32;

        // No ACKs are sent due to the ACK delay.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 32],
                ..SEND_TEMPL
            }
        );
        recv_nothing!(s);

        // RMSS+1 bytes of data has been received, so ACK is sent without delay.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 33,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 1],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 34),
                window_len: 31,
                ..RECV_TEMPL
            })
        );

        // This frees up a byte in the receive buffer. However, the remote shouldn't be aware of
        // this since no ACKs are sent.
        s.recv_slice(&mut [0; 1]).unwrap();
        recv_nothing!(s);

        // Now, if the remote wants to send one byte outside of the receive window that we
        // previously advertised, it should not succeed.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 34,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; 32],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 65),
                window_len: 1, // The last byte isn't accepted.
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_close_wait_no_window_update() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[1, 2, 3, 4],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);

        // we ack the FIN, with the reduced window size.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 6),
                window_len: 60,
                ..RECV_TEMPL
            })
        );

        let rx_buf = &mut [0; 32];
        assert_eq!(s.recv_slice(rx_buf), Ok(4));

        // check that we do NOT send a window update even if it has changed.
        recv_nothing!(s);
    }

    #[test]
    fn test_time_wait_no_window_update() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                payload: &[1, 2, 3, 4],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);

        // we ack the FIN, with the reduced window size.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 6),
                window_len: 60,
                ..RECV_TEMPL
            })
        );

        let rx_buf = &mut [0; 32];
        assert_eq!(s.recv_slice(rx_buf), Ok(4));

        // check that we do NOT send a window update even if it has changed.
        recv_nothing!(s);
    }

    // =========================================================================================//
    // Tests for flow control.
    // =========================================================================================//

    #[test]
    fn test_psh_transmit() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }), exact);
    }

    #[test]
    fn test_psh_receive() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_ack() {
        let mut s = socket_established();
        s.rx = RxStore::new(6, Budget::unlimited(), &pool());
        s.assembler = Assembler::new();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"123456"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_zero_window_ack_not_rate_limited() {
        let mut s = socket_established();
        s.rx = RxStore::new(6, Budget::unlimited(), &pool());
        s.assembler = Assembler::new();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"123456"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        // The remote retransmits into the zero window again within a second,
        // e.g. because the ACK above was lost. The ACK must not be withheld by
        // challenge ACK rate limiting: it is the remote's only way to learn
        // the window state, and a data segment cannot cause an ACK loop.
        send!(
            s,
            time 100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"123456"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_zero_window_fin() {
        let mut s = socket_established();
        s.rx = RxStore::new(6, Budget::unlimited(), &pool());
        s.assembler = Assembler::new();
        s.ack_delay = None;

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );

        // Even though the sequence space for the FIN itself is outside the window,
        // it is not data, so FIN must be accepted when window full.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[],
                control: TcpControl::Fin,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);

        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 7),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_ack_on_window_growth() {
        let mut s = socket_established_with_buffer_sizes(64, 6);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s, time 0);
        s.recv(|buffer| {
            assert_eq!(&buffer[..3], b"abc");
            (3, ())
        })
        .unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 3,
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 0);
        s.recv(|buffer| {
            assert_eq!(buffer, b"def");
            (buffer.len(), ())
        })
        .unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 6),
            window_len: 6,
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_window_update_with_delay_ack() {
        let mut s = socket_established_with_buffer_sizes(6, 6);
        s.ack_delay = Some(Duration::from_millis(10));

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 5);

        s.recv(|buffer| {
            assert_eq!(&buffer[..2], b"ab");
            (2, ())
        })
        .unwrap();
        recv!(
            s,
            time 5,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 2,
                ..RECV_TEMPL
            })
        );

        s.recv(|buffer| {
            assert_eq!(&buffer[..1], b"c");
            (1, ())
        })
        .unwrap();
        recv_nothing!(s, time 5);

        s.recv(|buffer| {
            assert_eq!(&buffer[..1], b"d");
            (1, ())
        })
        .unwrap();
        recv!(
            s,
            time 5,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 4,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_fill_peer_window() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        recv!(
            s,
            [
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"abcdef"[..],
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + 6,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"123456"[..],
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + 6 + 6,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"!@#$%^"[..],
                    ..RECV_TEMPL
                }
            ]
        );
    }

    #[test]
    fn test_announce_window_after_read() {
        let mut s = socket_established_with_buffer_sizes(64, 6);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 3,
                ..RECV_TEMPL
            }]
        );
        // Test that `dispatch` updates `remote_last_win`
        assert_eq!(s.remote_last_win, s.rx.window() as u16);
        s.recv(|buffer| (buffer.len(), ())).unwrap();
        assert!(s.window_to_update());
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 6,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.remote_last_win, s.rx.window() as u16);
        // Provoke immediate ACK to test that `process` updates `remote_last_win`
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"def"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 6,
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 9),
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.remote_last_win, s.rx.window() as u16);
        s.recv(|buffer| (buffer.len(), ())).unwrap();
        assert!(s.window_to_update());
    }

    // =========================================================================================//
    // Tests for zero-window probes.
    // =========================================================================================//

    #[test]
    fn test_sack_duplicates_with_changing_windows() {
        for sack in [false, true] {
            let mut s = socket_established();
            s.remote_has_sack = sack;
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    ..SEND_TEMPL
                }
            );
            s.send_slice(b"abcdefgh").unwrap();
            let data = TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: b"abcdefgh",
                ..RECV_TEMPL
            };
            recv!(s, [data]);
            for time in 1..=3 {
                send!(s, time time, TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    window_len: 256 - time as u16,
                    sack_ranges: [Some(((LOCAL_SEQ + 5).0 as u32, (LOCAL_SEQ + 9).0 as u32)), None, None],
                    ..SEND_TEMPL
                });
            }
            if sack {
                recv!(s, time 3, [data]);
            } else {
                recv_nothing!(s, time 3);
            }
        }
        let mut s = socket_established();
        s.remote_has_sack = true;
        s.send_slice(b"abcdefgh").unwrap();
        let data = TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"abcdefgh",
            ..RECV_TEMPL
        };
        recv!(s, [data]);
        for (time, window) in [256, 256, 0, 256, 256, 256, 256].into_iter().enumerate() {
            let at = (time + 1) as i64;
            send!(s, time at, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: window,
                sack_ranges: [Some(((LOCAL_SEQ + 5).0 as u32, (LOCAL_SEQ + 9).0 as u32)), None, None],
                ..SEND_TEMPL
            });
            if time == 3 {
                recv!(s, time at, [data]);
            }
            if time < 6 {
                recv_nothing!(s, time at);
            }
        }
        recv!(s, time 7, [data]);
    }

    #[test]
    fn test_duplicate_acks_keep_fin_retransmission_timer() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        s.close();
        let fin = TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        };
        recv!(s, [fin]);
        for time in 1..=3 {
            send!(s, time time, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            });
        }
        recv_nothing!(s, time 3);
        recv_nothing!(s, time 999);
        recv!(s, time 1000, [fin]);
    }

    #[test]
    fn test_fast_retransmit_retries_failed_emit() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        s.send_slice(b"abcd").unwrap();
        let data = TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"abcd",
            ..RECV_TEMPL
        };
        recv!(s, [data]);
        for time in 1..=3 {
            send!(s, time time, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            });
        }
        let TestSocket { socket, cx } = &mut s;
        assert_eq!(
            socket.dispatch(cx, DispatchMode::All, |_, (_, repr, piece)| {
                assert_eq!(repr.seq_number, data.seq_number);
                assert_eq!(
                    piece.map(|p| p.bytes().to_vec()),
                    Some(data.payload.to_vec())
                );
                Err(())
            }),
            Err(())
        );
        recv!(s, time 3, [data]);
    }

    /// A packet leaving the wire can make its retained backing writable
    /// without releasing a budget charge. A refused retransmission still
    /// needs a future timer to notice that change.
    #[test]
    fn a_shared_retransmission_keeps_a_future_retry_without_a_memory_wake() {
        for fast in [false, true] {
            let mut s = socket_established_with_buffer_sizes(2 * rx::SMALL, 64);
            let bytes: Vec<_> = (0..rx::SMALL).map(|i| i as u8).collect();
            let budget = Budget::new(HEADROOM + bytes.len());
            let mut chunk = Chunk::block(&budget, HEADROOM, budget.limit()).unwrap();
            chunk.extend_within(&bytes).unwrap();
            s.push(chunk).unwrap();
            let mut original = None;
            s.socket
                .dispatch(&mut s.cx, DispatchMode::All, |_, (_, _, piece)| {
                    original = piece.unwrap().in_place(40, |packet| packet[..40].fill(0));
                    assert!(original.is_some());
                    Ok::<_, ()>(())
                })
                .unwrap();
            if fast {
                s.timer.set_for_fast_retransmit();
            } else {
                let PollAt::Time(deadline) = s.timer.poll_at() else {
                    panic!("the original transmission armed a timer");
                };
                s.cx.set_now(deadline);
            }
            let refused = s
                .socket
                .dispatch(&mut s.cx, DispatchMode::All, |_, (_, _, piece)| {
                    let mut piece = piece.unwrap();
                    assert!(piece.in_place(40, |_| ()).is_none());
                    assert!(Chunk::copy_of(&budget, piece.bytes()).is_none());
                    Err(())
                });
            assert_eq!(refused, Err(()));
            s.socket
                .dispatch(&mut s.cx, DispatchMode::Control, |_, _| -> Result<(), ()> {
                    panic!("no control traffic is due");
                })
                .unwrap();
            let PollAt::Time(retry) = s.socket.poll_at(&mut s.cx, DispatchMode::Control) else {
                panic!("a refused retransmission must retain a future retry");
            };
            assert!(retry > s.cx.now());
            let used = budget.used();
            drop(original);
            assert_eq!(budget.used(), used);
            s.cx.set_now(retry);
            let mut resent = None;
            s.socket
                .dispatch(&mut s.cx, DispatchMode::All, |_, (_, _, piece)| {
                    resent = piece.unwrap().in_place(40, |packet| packet[..40].fill(0));
                    Ok::<_, ()>(())
                })
                .unwrap();
            assert!(resent.unwrap().ends_with(&bytes));
            assert_eq!(budget.used(), used);
        }
    }

    /// A failed data allocation cannot hide an acknowledgement behind
    /// queued text, including text that must precede a local FIN.
    #[test]
    fn control_dispatch_acknowledges_without_sending_queued_text() {
        for closing in [false, true] {
            let mut s = socket_established();
            let incoming = [1, 2, 3];
            let before_receive = s.remote_seq_no;
            let acknowledgement = s.local_seq_no;
            send!(
                s,
                TcpRepr {
                    seq_number: before_receive,
                    ack_number: Some(acknowledgement),
                    payload: &incoming,
                    ..SEND_TEMPL
                }
            );
            let bytes: Vec<_> = (0..24).collect();
            s.push(Chunk::unpaid(bytes.clone())).unwrap();
            if closing {
                s.close();
            }
            let before_send = s.remote_last_seq;
            let result = s
                .socket
                .dispatch(&mut s.cx, DispatchMode::All, |_, (_, _, piece)| {
                    assert!(piece.is_some());
                    Err(())
                });
            assert_eq!(result, Err(()));
            s.pending_fast_retransmit = true;
            let mut emitted = false;
            s.socket
                .dispatch(&mut s.cx, DispatchMode::Control, |_, (_, repr, piece)| {
                    assert!(piece.is_none());
                    assert!(repr.payload.is_empty());
                    assert_eq!(repr.control, TcpControl::None);
                    assert_eq!(repr.ack_number, Some(before_receive + incoming.len()));
                    emitted = true;
                    Ok::<_, ()>(())
                })
                .unwrap();
            assert!(emitted);
            assert_eq!(s.remote_last_seq, before_send);
            assert_eq!(s.send_queue(), bytes.len());
            assert!(s.pending_fast_retransmit);
            let mut sent = Vec::new();
            s.socket
                .dispatch(&mut s.cx, DispatchMode::All, |_, (_, repr, piece)| {
                    sent.extend_from_slice(piece.unwrap().bytes());
                    assert_eq!(repr.control == TcpControl::Fin, closing);
                    Ok::<_, ()>(())
                })
                .unwrap();
            assert_eq!(sent, bytes);
        }
    }

    #[test]
    fn control_dispatch_identifies_one_byte_window_probes() {
        for mode in [DispatchMode::All, DispatchMode::Control] {
            let mut s = socket_established();
            let bytes: Vec<_> = (0..24).collect();
            s.push(Chunk::unpaid(bytes.clone())).unwrap();
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    window_len: 0,
                    ..SEND_TEMPL
                }
            );
            s.cx.set_now(Instant::from_millis(1000));
            let before_send = s.remote_last_seq;
            let mut emitted = false;
            s.socket
                .dispatch(&mut s.cx, mode, |_, (_, repr, piece)| {
                    let piece = piece.unwrap();
                    assert!(piece.is_probe());
                    assert_eq!(piece.bytes(), &bytes[..1]);
                    assert_ne!(repr.control, TcpControl::Fin);
                    emitted = true;
                    Ok::<_, ()>(())
                })
                .unwrap();
            assert!(emitted);
            assert_eq!(s.remote_last_seq, before_send);
            assert_eq!(s.send_queue(), bytes.len());
            assert!(!s.timer.should_zero_window_probe(s.cx.now()));
        }
    }

    #[test]
    fn control_poll_waits_for_delayed_ack_instead_of_queued_data() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        s.push(Chunk::unpaid(vec![1; 24])).unwrap();
        assert_eq!(
            s.socket
                .dispatch(&mut s.cx, DispatchMode::All, |_, _| Err(())),
            Err(())
        );
        assert_eq!(
            s.socket.poll_at(&mut s.cx, DispatchMode::Control),
            PollAt::Ingress
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[1, 2, 3],
                ..SEND_TEMPL
            }
        );
        let PollAt::Time(deadline) = s.socket.poll_at(&mut s.cx, DispatchMode::Control) else {
            panic!("the delayed acknowledgement has a deadline");
        };
        assert!(deadline > s.cx.now());
        assert_eq!(s.socket.poll_at(&mut s.cx, DispatchMode::All), PollAt::Now);
        s.cx.set_now(deadline);
        let mut emitted = false;
        s.socket
            .dispatch(&mut s.cx, DispatchMode::Control, |_, (_, _, piece)| {
                assert!(piece.is_none());
                emitted = true;
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(emitted);
        assert_eq!(
            s.socket.poll_at(&mut s.cx, DispatchMode::Control),
            PollAt::Ingress
        );
    }

    #[test]
    fn control_dispatch_probe_keeps_fin_until_the_window_reopens() {
        for mode in [DispatchMode::All, DispatchMode::Control] {
            let mut s = socket_established();
            let bytes = [7];
            s.push(Chunk::unpaid(bytes.to_vec())).unwrap();
            s.close();
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    window_len: 0,
                    ..SEND_TEMPL
                }
            );
            s.cx.set_now(Instant::from_millis(1000));
            let mut probe = false;
            s.socket
                .dispatch(&mut s.cx, mode, |_, (_, repr, piece)| {
                    let piece = piece.unwrap();
                    assert!(piece.is_probe());
                    assert_eq!(piece.bytes(), &bytes);
                    assert_ne!(repr.control, TcpControl::Fin);
                    probe = true;
                    Ok::<_, ()>(())
                })
                .unwrap();
            assert!(probe);
            send!(s, time 1001, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 16,
                ..SEND_TEMPL
            });
            let mut finished = false;
            s.socket
                .dispatch(&mut s.cx, DispatchMode::All, |_, (_, repr, piece)| {
                    assert_eq!(piece.unwrap().bytes(), &bytes);
                    assert_eq!(repr.control, TcpControl::Fin);
                    finished = true;
                    Ok::<_, ()>(())
                })
                .unwrap();
            assert!(finished);
        }
    }

    #[test]
    fn control_dispatch_can_finish_or_reset_while_data_is_retained() {
        for reset in [false, true] {
            let mut s = socket_established();
            s.push(Chunk::unpaid(vec![1; 24])).unwrap();
            s.socket
                .dispatch(&mut s.cx, DispatchMode::All, |_, _| Ok::<_, ()>(()))
                .unwrap();
            let queued = s.send_queue();
            if reset {
                s.abort();
            } else {
                s.close();
            }
            let mut emitted = false;
            s.socket
                .dispatch(&mut s.cx, DispatchMode::Control, |_, (_, repr, piece)| {
                    assert!(piece.is_none());
                    assert_eq!(
                        repr.control,
                        if reset {
                            TcpControl::Rst
                        } else {
                            TcpControl::Fin
                        }
                    );
                    emitted = true;
                    Ok::<_, ()>(())
                })
                .unwrap();
            assert!(emitted);
            assert_eq!(s.send_queue(), queued);
        }
    }

    #[test]
    fn test_ack_cannot_free_unsent_data() {
        let mut s = socket_established();
        assert_eq!(s.send_slice(&[b'x'; 64]), Ok(64));
        let ack = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 65),
            ..SEND_TEMPL
        };
        let challenge = TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        };
        send!(s, ack, Some(challenge));
        assert_eq!(s.send_slice(b"y"), Ok(0));
        send!(s, time 999, ack);
        send!(s, time 1000, ack, Some(challenge));
        recv!(s, time 1000, [TcpRepr {
            payload: &[b'x'; 64],
            ..challenge
        }]);
    }

    #[test]
    fn test_handshake_ack_requires_sent_syn() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 1,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.send_slice(b"x"), Ok(1));

        let mut s = socket();
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynSent);
        let syn_ack = TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        };
        send!(
            s,
            syn_ack,
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 1,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(s, syn_ack);
        assert_eq!(s.state(), State::Established);
    }

    #[test]
    fn test_ack_cannot_ack_unsent_fin() {
        let mut s = socket_established();
        s.close();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::FinWait2);
    }

    #[test]
    fn test_ack_bound_survives_retransmission() {
        let mut s = socket_established();
        s.remote_mss = 4;
        s.remote_win_len = 8;
        s.send_slice(b"abcdefghijkl").unwrap();
        for (offset, data) in [(0, &b"abcd"[..]), (4, &b"efgh"[..])] {
            recv!(
                s,
                Ok(TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + offset,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: data,
                    ..RECV_TEMPL
                })
            );
        }
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"abcd",
            ..RECV_TEMPL
        }));
        send!(s, time 1001, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 13),
            ..SEND_TEMPL
        }, Some(TcpRepr {
            // The challenge ACK carries the highest sequence number sent.
            seq_number: LOCAL_SEQ + 9,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        send!(s, time 1002, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 9),
            ..SEND_TEMPL
        });
        assert_eq!(s.send_queue(), 4);
        recv!(s, time 1002, [TcpRepr {
            seq_number: LOCAL_SEQ + 9,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"ijkl",
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_reset_reply_acknowledges_segment_without_ack() {
        for control in [
            TcpControl::None,
            TcpControl::Psh,
            TcpControl::Syn,
            TcpControl::Fin,
        ] {
            for payload in [&b""[..], &b"abc"[..]] {
                let incoming = TcpRepr {
                    control,
                    seq_number: TcpSeqNumber(-2),
                    ack_number: None,
                    payload,
                    ..SEND_TEMPL
                };
                let (_, reply) = Socket::rst_reply(&SEND_IP_TEMPL, &incoming);
                assert_eq!(
                    reply,
                    TcpRepr {
                        control: TcpControl::Rst,
                        seq_number: TcpSeqNumber(0),
                        ack_number: Some(incoming.seq_number + incoming.segment_len()),
                        window_len: 0,
                        ..RECV_TEMPL
                    }
                );
                let incoming = TcpRepr {
                    ack_number: Some(LOCAL_SEQ),
                    ..incoming
                };
                let (_, reply) = Socket::rst_reply(&SEND_IP_TEMPL, &incoming);
                assert_eq!(
                    reply,
                    TcpRepr {
                        control: TcpControl::Rst,
                        seq_number: LOCAL_SEQ,
                        ack_number: None,
                        window_len: 0,
                        ..RECV_TEMPL
                    }
                );
            }
        }
    }

    #[test]
    fn test_established_combined_reset_flags() {
        for flags in [1, 2, 3] {
            for offset in [0, 1, 2, 64, 65] {
                for ack in [None, Some(LOCAL_SEQ + 1)] {
                    let mut s = socket_established();
                    let rst = reset_with_flags(REMOTE_SEQ + offset, ack, flags);
                    let reply = if (2..65).contains(&offset) {
                        Some(TcpRepr {
                            seq_number: LOCAL_SEQ + 1,
                            ack_number: Some(REMOTE_SEQ + 1),
                            ..RECV_TEMPL
                        })
                    } else {
                        None
                    };
                    send!(s, rst, reply);
                    assert_eq!(
                        s.state(),
                        if offset == 1 {
                            State::Closed
                        } else {
                            State::Established
                        }
                    );
                    recv!(s, []);
                }
            }
        }
    }

    #[test]
    fn test_in_window_reset_requires_exact_sequence() {
        let mut s = socket_established();
        let rst = TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ + 2,
            ack_number: None,
            ..SEND_TEMPL
        };
        let challenge = TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        };
        send!(s, rst, Some(challenge));
        assert!(s.may_send());
        send!(s, time 999, rst);
        send!(s, time 1000, rst, Some(challenge));
        send!(s, time 1001, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ..rst
        });
        assert!(!s.is_open());
    }

    #[test]
    fn test_synchronized_syn_challenges_any_sequence() {
        for state in [
            State::SynReceived,
            State::Established,
            State::FinWait1,
            State::FinWait2,
            State::Closing,
            State::CloseWait,
            State::LastAck,
            State::TimeWait,
        ] {
            for ack in [None, Some(LOCAL_SEQ + 1)] {
                for seq in [REMOTE_SEQ, REMOTE_SEQ + 1, REMOTE_SEQ + 2, REMOTE_SEQ + 100] {
                    let mut s = socket_established();
                    s.state = state;
                    let syn = TcpRepr {
                        control: TcpControl::Syn,
                        seq_number: seq,
                        ack_number: ack,
                        ..SEND_TEMPL
                    };
                    let challenge = TcpRepr {
                        seq_number: LOCAL_SEQ + 1,
                        ack_number: Some(REMOTE_SEQ + 1),
                        ..RECV_TEMPL
                    };
                    send!(s, syn, Some(challenge));
                    send!(s, time 999, syn);
                    send!(s, time 1000, syn, Some(challenge));
                    assert_eq!(s.state(), state);
                }
            }
        }
    }

    #[test]
    fn test_gib_receive_buffer_window_scale() {
        let mut s = socket_with_buffer_sizes(64, 1 << 30);
        for _ in 0..2 {
            s.state = State::Listen;
            s.listen_endpoint = Some(LISTEN_END);
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: REMOTE_SEQ,
                    ack_number: None,
                    window_scale: Some(0),
                    ..SEND_TEMPL
                }
            );
            let isn = s.local_seq_no;
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: isn,
                    ack_number: Some(REMOTE_SEQ + 1),
                    window_len: u16::MAX,
                    window_scale: Some(14),
                    max_seg_size: Some(BASE_MSS),
                    ..RECV_TEMPL
                }]
            );
            s.reset();
        }
    }

    #[test]
    fn test_zero_window_reopens_with_lost_data() {
        let mut s = socket_established();
        s.send_slice(b"abcdefgh").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: b"abcdefgh",
                ..RECV_TEMPL
            }]
        );
        send!(s, time 100, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 5),
            window_len: 0,
            ..SEND_TEMPL
        });
        send!(s, time 200, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 5),
            ..SEND_TEMPL
        });
        recv!(s, time 200, [TcpRepr {
            seq_number: LOCAL_SEQ + 5,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"efgh",
            ..RECV_TEMPL
        }]);
        recv_nothing!(s, time 1099);
        recv!(s, time 1100, [TcpRepr {
            seq_number: LOCAL_SEQ + 5,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"efgh",
            ..RECV_TEMPL
        }]);
    }

    #[test]
    fn test_zero_window_after_rto_keeps_probing() {
        let mut s = socket_established();
        s.send_slice(b"abcd").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: b"abcd",
                ..RECV_TEMPL
            }]
        );
        send!(s, time 100, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        });
        recv_nothing!(s, time 999);
        recv!(s, time 1000, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"a",
            ..RECV_TEMPL
        }]);
        recv_nothing!(s, time 2999);
        recv!(s, time 3000, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: b"a",
            ..RECV_TEMPL
        }]);
    }

    /// The segment `s` sends at `now`, if any, with its payload copied out.
    fn sent_at(s: &mut TestSocket, now: Instant) -> Option<(IpRepr, TcpRepr<'static>)> {
        s.cx.set_now(now);
        let mut sent = None;
        let _ = s
            .socket
            .dispatch(&mut s.cx, DispatchMode::All, |_, (ip, tcp, piece)| {
                let payload: &'static [u8] =
                    Vec::leak(piece.map_or(tcp.payload.to_vec(), |p| p.bytes().to_vec()));
                let extra: &'static [u8] = Vec::leak(tcp.extra.to_vec());
                sent = Some((
                    ip,
                    TcpRepr {
                        payload,
                        extra,
                        ..tcp
                    },
                ));
                Ok::<(), ()>(())
            });
        sent
    }

    /// Gives `to` a segment, and gives `from` the reply `to` sends at once.
    fn deliver(
        from: &mut TestSocket,
        to: &mut TestSocket,
        now: Instant,
        (ip, tcp): (IpRepr, TcpRepr<'static>),
    ) {
        to.cx.set_now(now);
        from.cx.set_now(now);
        if to.socket.accepts(&mut to.cx, &ip, &tcp)
            && let Some((ip, tcp)) = to.socket.process(
                &mut to.cx,
                &ip,
                &tcp,
                &[],
                &Chunk::unpaid(tcp.payload.to_vec()),
            )
            && from.socket.accepts(&mut from.cx, &ip, &tcp)
        {
            from.socket.process(
                &mut from.cx,
                &ip,
                &tcp,
                &[],
                &Chunk::unpaid(tcp.payload.to_vec()),
            );
        }
    }

    /// Lets two sockets talk at `now`, with no loss, until both are quiet.
    fn exchange(a: &mut TestSocket, b: &mut TestSocket, now: Instant) {
        for _ in 0..64 {
            let from_a = sent_at(a, now);
            let quiet_a = from_a.is_none();
            if let Some(segment) = from_a {
                deliver(a, b, now, segment);
            }
            let from_b = sent_at(b, now);
            let quiet_b = from_b.is_none();
            if let Some(segment) = from_b {
                deliver(b, a, now, segment);
            }
            if quiet_a && quiet_b {
                return;
            }
        }
    }

    /// Two sockets whose windows are both closed probe each other at the
    /// same moment, and both applications read while the probes are on
    /// their way, in order on each path. Each probe carries a byte, which
    /// the other side, its window now open, takes in. The transfer must go
    /// on: each side's later segments must be acceptable to a peer that
    /// has its probe byte, so the window updates and ACKs get through.
    #[test]
    fn test_crossing_zero_window_probes_keep_the_transfer_going() {
        let mut a = socket_with_buffer_sizes(64, 16);
        let mut b = socket_with_buffer_sizes(64, 16);
        a.listen(LISTEN_END).unwrap();
        b.socket.connect(&mut b.cx, LOCAL_END, REMOTE_END).unwrap();
        exchange(&mut a, &mut b, Instant::from_millis(0));
        assert_eq!((a.state, b.state), (State::Established, State::Established));

        // Each side sends more than the other can hold.
        assert_eq!(a.send_slice(&[1; 32]), Ok(32));
        assert_eq!(b.send_slice(&[2; 32]), Ok(32));
        exchange(&mut a, &mut b, Instant::from_millis(0));
        assert_eq!((a.recv_queue(), b.recv_queue()), (16, 16));

        // Both probes leave before either arrives.
        let now = Instant::from_millis(1000);
        let probe_a = sent_at(&mut a, now).unwrap();
        let probe_b = sent_at(&mut b, now).unwrap();
        assert_eq!((probe_a.1.payload.len(), probe_b.1.payload.len()), (1, 1));
        // Both applications read before the probes arrive.
        let mut got_a = Vec::new();
        let mut got_b = Vec::new();
        let mut buf = [0; 64];
        let n = a.recv_slice(&mut buf).unwrap();
        got_a.extend_from_slice(&buf[..n]);
        let n = b.recv_slice(&mut buf).unwrap();
        got_b.extend_from_slice(&buf[..n]);
        let update_a = sent_at(&mut a, now).unwrap();
        let update_b = sent_at(&mut b, now).unwrap();
        // Each way, the probe arrives first, then the window update.
        deliver(&mut a, &mut b, now, probe_a);
        deliver(&mut b, &mut a, now, probe_b);
        deliver(&mut a, &mut b, now, update_a);
        deliver(&mut b, &mut a, now, update_b);

        // A lossless network and readers that keep up from here on.
        for t in (1000..=600_000).step_by(100) {
            exchange(&mut a, &mut b, Instant::from_millis(t));
            while let Ok(n @ 1..) = a.recv_slice(&mut buf) {
                got_a.extend_from_slice(&buf[..n]);
            }
            while let Ok(n @ 1..) = b.recv_slice(&mut buf) {
                got_b.extend_from_slice(&buf[..n]);
            }
        }
        assert_eq!(got_a, [2; 32]);
        assert_eq!(got_b, [1; 32]);
    }

    /// One socket's window is closed, its application does not read, and
    /// the other socket has a probe byte out that the closed window
    /// dropped. Data the closed side sends must still be acknowledged, or
    /// an application that writes before it reads never gets to read. The
    /// probes carry the ACKs into the closed window.
    #[test]
    fn test_acks_reach_a_closed_window() {
        let mut a = socket_with_buffer_sizes(64, 64);
        let mut b = socket_with_buffer_sizes(64, 16);
        a.set_nagle_enabled(false);
        b.set_nagle_enabled(false);
        a.listen(LISTEN_END).unwrap();
        b.socket.connect(&mut b.cx, LOCAL_END, REMOTE_END).unwrap();
        exchange(&mut a, &mut b, Instant::from_millis(0));
        assert_eq!(a.send_slice(&[1; 32]), Ok(32));
        exchange(&mut a, &mut b, Instant::from_millis(0));
        assert_eq!(b.recv_queue(), 16);
        // The probes into the closed window drop their byte.
        for t in (100..=3000).step_by(100) {
            exchange(&mut a, &mut b, Instant::from_millis(t));
        }
        // The closed side sends, and never reads.
        assert_eq!(b.send_slice(&[2; 10]), Ok(10));
        let mut buf = [0; 64];
        for t in (3000..=600_000).step_by(100) {
            exchange(&mut a, &mut b, Instant::from_millis(t));
            while let Ok(1..) = a.recv_slice(&mut buf) {}
        }
        assert_eq!(b.send_queue(), 0);
    }

    /// Two sockets send each other two segments at once, and all the ACKs
    /// are lost. Both retransmission timers fire before either
    /// retransmission arrives, and each resends only its first segment.
    /// The transfer must still finish once the network delivers
    /// everything: each side's later segments must be acceptable to a peer
    /// that has both its segments, so the ACKs get through.
    #[test]
    fn test_crossing_retransmissions_keep_the_transfer_going() {
        let mut a = socket_with_buffer_sizes(4096, 4096);
        let mut b = socket_with_buffer_sizes(4096, 4096);
        a.set_nagle_enabled(false);
        b.set_nagle_enabled(false);
        a.listen(LISTEN_END).unwrap();
        b.socket.connect(&mut b.cx, LOCAL_END, REMOTE_END).unwrap();
        exchange(&mut a, &mut b, Instant::from_millis(0));
        assert_eq!((a.state, b.state), (State::Established, State::Established));

        // The data crosses and arrives; the ACKs are lost.
        let now = Instant::from_millis(0);
        assert_eq!(a.send_slice(&[1; 2000]), Ok(2000));
        assert_eq!(b.send_slice(&[2; 2000]), Ok(2000));
        let data_a: Vec<_> = core::iter::from_fn(|| sent_at(&mut a, now)).collect();
        let data_b: Vec<_> = core::iter::from_fn(|| sent_at(&mut b, now)).collect();
        assert_eq!((data_a.len(), data_b.len()), (2, 2));
        for (ip, tcp) in data_a {
            b.cx.set_now(now);
            b.socket.process(
                &mut b.cx,
                &ip,
                &tcp,
                &[],
                &Chunk::unpaid(tcp.payload.to_vec()),
            );
        }
        for (ip, tcp) in data_b {
            a.cx.set_now(now);
            a.socket.process(
                &mut a.cx,
                &ip,
                &tcp,
                &[],
                &Chunk::unpaid(tcp.payload.to_vec()),
            );
        }
        while sent_at(&mut a, now).is_some() {}
        while sent_at(&mut b, now).is_some() {}

        // Both retransmissions leave before either arrives.
        let now = Instant::from_millis(1000);
        let again_a = sent_at(&mut a, now).unwrap();
        let again_b = sent_at(&mut b, now).unwrap();
        assert!(again_a.1.payload.len() < 2000 && again_b.1.payload.len() < 2000);
        deliver(&mut a, &mut b, now, again_a);
        deliver(&mut b, &mut a, now, again_b);

        // A lossless network from here on.
        for t in (1000..=600_000).step_by(100) {
            exchange(&mut a, &mut b, Instant::from_millis(t));
        }
        assert_eq!((a.send_queue(), b.send_queue()), (0, 0));
    }

    #[test]
    fn test_zero_window_probe_enter_on_win_update() {
        let mut s = socket_established();

        assert!(!s.timer.is_zero_window_probe());

        s.send_slice(b"abcdef123456!@#$%^").unwrap();

        assert!(!s.timer.is_zero_window_probe());

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        assert!(s.timer.is_zero_window_probe());
    }

    #[test]
    fn test_zero_window_probe_enter_on_send() {
        let mut s = socket_established();

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        assert!(!s.timer.is_zero_window_probe());

        s.send_slice(b"abcdef123456!@#$%^").unwrap();

        assert!(s.timer.is_zero_window_probe());
    }

    #[test]
    fn test_zero_window_probe_exit() {
        let mut s = socket_established();

        s.send_slice(b"abcdef123456!@#$%^").unwrap();

        assert!(!s.timer.is_zero_window_probe());

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        assert!(s.timer.is_zero_window_probe());

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 6,
                ..SEND_TEMPL
            }
        );

        assert!(!s.timer.is_zero_window_probe());
    }

    #[test]
    fn test_zero_window_probe_exit_ack() {
        let mut s = socket_established();

        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        send!(
            s,
            time 1010,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                window_len: 6,
                ..SEND_TEMPL
            }
        );

        recv!(
            s,
            time 1010,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"bcdef1"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_probe_not_capped_by_cwnd() {
        let mut s = socket_established_with_buffer_sizes(8192, 64);
        s.remote_win_len = 65535;
        s.remote_mss = 1024;

        let data = [b'x'; 4096];
        s.send_slice(&data[..]).unwrap();

        // Reno's initial cwnd is 2048: two segments fill the congestion window
        // exactly, leaving cwnd_remaining() == 0.
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1024,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1024],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 0);

        // The remote closes its window without acknowledging anything new, so
        // no congestion window space is freed either.
        send!(s, time 10, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0,
            ..SEND_TEMPL
        });

        // Arm the probe timer. (Set directly because the ACK above carries no
        // new data; in real traffic this state is reached e.g. when the
        // controller shrinks cwnd below the flight size while probing.)
        s.timer
            .set_for_zero_window_probe(Instant::from_millis(10), Duration::from_millis(100));

        // The probe must carry 1 byte of data past the window edge even though
        // the congestion window is exhausted: an empty probe occupies no
        // sequence space and elicits no reply, so the connection would stall
        // if the remote's window update got lost.
        recv!(s, time 110, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 2048,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &data[..1],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_zero_window_probe_backoff_nack_reply() {
        let mut s = socket_established();
        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            time 1100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            time 3100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 6999);
        recv!(
            s,
            time 7000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_probe_backoff_no_reply() {
        let mut s = socket_established();
        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_probe_shift() {
        let mut s = socket_established();

        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        // ack the ZWP byte, but still advertise zero window.
        // this should restart the ZWP timer.
        send!(
            s,
            time 3100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        // ZWP should be sent at 3100+1000 = 4100
        recv_nothing!(s, time 4099);
        recv!(
            s,
            time 4100,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"b"[..],
                ..RECV_TEMPL
            }]
        );
    }

    // =========================================================================================//
    // Tests for timeouts.
    // =========================================================================================//

    #[test]
    fn test_listen_timeout() {
        let mut s = socket_listen();
        s.set_timeout(Some(Duration::from_millis(100)));
        assert_eq!(
            s.socket.poll_at(&mut s.cx, DispatchMode::All),
            PollAt::Ingress
        );
    }

    #[test]
    fn test_connect_timeout() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        s.set_timeout(Some(Duration::from_millis(100)));
        recv!(s, time 150, Ok(TcpRepr {
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::SynSent);
        assert_eq!(
            s.socket.poll_at(&mut s.cx, DispatchMode::All),
            PollAt::Time(Instant::from_millis(250))
        );
        recv!(s, time 250, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(TcpSeqNumber(0)),
            window_scale: None,
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_timeout() {
        let mut s = socket_established();
        s.set_timeout(Some(Duration::from_millis(2000)));
        recv_nothing!(s, time 250);
        // Idle, with no keep-alive: it waits for nothing.
        assert_eq!(
            s.socket.poll_at(&mut s.cx, DispatchMode::All),
            PollAt::Ingress
        );
        s.send_slice(b"abcdef").unwrap();
        assert_eq!(s.socket.poll_at(&mut s.cx, DispatchMode::All), PollAt::Now);
        recv!(s, time 255, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        assert_eq!(
            s.socket.poll_at(&mut s.cx, DispatchMode::All),
            PollAt::Time(Instant::from_millis(1255))
        );
        recv!(s, time 1255, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        assert_eq!(
            s.socket.poll_at(&mut s.cx, DispatchMode::All),
            PollAt::Time(Instant::from_millis(2255))
        );
        recv!(s, time 2255, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_keep_alive_timeout() {
        let mut s = socket_established();
        s.set_keep_alive(Some(Duration::from_millis(50)));
        s.set_timeout(Some(Duration::from_millis(100)));
        recv!(s, time 100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 100);
        assert_eq!(
            s.socket.poll_at(&mut s.cx, DispatchMode::All),
            PollAt::Time(Instant::from_millis(150))
        );
        send!(s, time 105, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(
            s.socket.poll_at(&mut s.cx, DispatchMode::All),
            PollAt::Time(Instant::from_millis(155))
        );
        recv!(s, time 155, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 155);
        assert_eq!(
            s.socket.poll_at(&mut s.cx, DispatchMode::All),
            PollAt::Time(Instant::from_millis(205))
        );
        recv_nothing!(s, time 200);
        recv!(s, time 205, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 205);
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_fin_wait_1_timeout() {
        let mut s = socket_fin_wait_1();
        s.set_timeout(Some(Duration::from_millis(1000)));
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        recv!(s, time 1100, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_last_ack_timeout() {
        let mut s = socket_last_ack();
        s.set_timeout(Some(Duration::from_millis(1000)));
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        recv!(s, time 1100, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    /// An idle connection with nothing to send and no keep-alive waits for
    /// no answer, so it does not time out however long the peer is quiet,
    /// per RFC 9293 section 3.9.1.2. With keep-alive on it does.
    #[test]
    fn test_idle_without_keep_alive_does_not_time_out() {
        let mut s = socket_established();
        s.set_timeout(Some(Duration::from_millis(1000)));
        s.remote_last_ts = Some(Instant::from_millis(100));
        recv_nothing!(s, time 60_000);
        assert_eq!(s.state, State::Established);
        s.set_keep_alive(Some(Duration::from_millis(500)));
        recv!(s, time 60_000, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    /// Closing a socket that was quiet for longer than its timeout sends a
    /// FIN, not a RST: the timeout counts from the FIN.
    #[test]
    fn test_close_after_a_quiet_spell_sends_fin() {
        let mut s = socket_established();
        s.set_timeout(Some(Duration::from_millis(1000)));
        s.remote_last_ts = Some(Instant::from_millis(100));
        s.close();
        recv!(s, time 5000, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::FinWait1);
        assert_eq!(s.remote_last_ts, Some(Instant::from_millis(5000)));
    }

    #[test]
    fn test_closed_timeout() {
        let mut s = socket_established();
        s.set_timeout(Some(Duration::from_millis(200)));
        s.remote_last_ts = Some(Instant::from_millis(100));
        s.abort();
        assert_eq!(s.socket.poll_at(&mut s.cx, DispatchMode::All), PollAt::Now);
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(
            s.socket.poll_at(&mut s.cx, DispatchMode::All),
            PollAt::Ingress
        );
    }

    // =========================================================================================//
    // Tests for keep-alive.
    // =========================================================================================//

    #[test]
    fn test_responds_to_keep_alive() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_sends_keep_alive() {
        let mut s = socket_established();
        s.set_keep_alive(Some(Duration::from_millis(100)));

        // drain the forced keep-alive packet
        assert_eq!(s.socket.poll_at(&mut s.cx, DispatchMode::All), PollAt::Now);
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        assert_eq!(
            s.socket.poll_at(&mut s.cx, DispatchMode::All),
            PollAt::Time(Instant::from_millis(100))
        );
        recv_nothing!(s, time 95);
        recv!(s, time 100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        assert_eq!(
            s.socket.poll_at(&mut s.cx, DispatchMode::All),
            PollAt::Time(Instant::from_millis(200))
        );
        recv_nothing!(s, time 195);
        recv!(s, time 200, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        send!(s, time 250, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(
            s.socket.poll_at(&mut s.cx, DispatchMode::All),
            PollAt::Time(Instant::from_millis(350))
        );
        recv_nothing!(s, time 345);
        recv!(s, time 350, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"\x00"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_keep_alive_restart_and_empty_payload() {
        let mut s = socket_established();
        send!(s, time 50, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        s.settings.keep_alive_payload = KeepAlivePayload::Empty;
        s.set_keep_alive(Some(Duration::from_millis(100)));
        s.restart_keep_alive(Instant::from_millis(50));
        assert_eq!(
            s.socket.poll_at(&mut s.cx, DispatchMode::All),
            PollAt::Time(Instant::from_millis(150))
        );
        recv_nothing!(s, time 149);
        recv!(s, time 150, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload: &[],
            ..RECV_TEMPL
        }));
        send!(s, time 175, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(
            s.socket.poll_at(&mut s.cx, DispatchMode::All),
            PollAt::Time(Instant::from_millis(275))
        );
        s.set_keep_alive(None);
        s.restart_keep_alive(Instant::from_millis(200));
        recv_nothing!(s, time 275);
    }

    // =========================================================================================//
    // Tests for time-to-live configuration.
    // =========================================================================================//

    #[test]
    fn test_set_hop_limit() {
        let mut s = socket_syn_received();

        s.set_hop_limit(Some(0x2a));
        assert_eq!(
            s.socket
                .dispatch(&mut s.cx, DispatchMode::All, |_, (ip_repr, _, _)| {
                    assert_eq!(
                        match ip_repr {
                            IpRepr::Ipv4(repr) => repr.hop_limit,
                            IpRepr::Ipv6(repr) => repr.hop_limit,
                        },
                        0x2a
                    );
                    Ok::<_, ()>(())
                }),
            Ok(())
        );

        // Reset preserves user settings.
        s.reset();
        assert_eq!(s.hop_limit(), Some(0x2a));
    }

    #[test]
    #[should_panic(expected = "the time-to-live value of a packet must not be zero")]
    fn test_set_hop_limit_zero() {
        let mut s = socket_syn_received();
        s.set_hop_limit(Some(0));
    }

    // =========================================================================================//
    // Tests for reassembly.
    // =========================================================================================//

    #[test]
    fn test_out_of_order() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"def"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        s.recv(|buffer| {
            assert_eq!(buffer, b"");
            (buffer.len(), ())
        })
        .unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            })
        );
        s.recv(|buffer| {
            assert_eq!(buffer, b"abcdef");
            (buffer.len(), ())
        })
        .unwrap();
    }

    #[test]
    fn test_buffer_wraparound_rx() {
        let mut s = socket_established();
        s.rx = RxStore::new(6, Budget::unlimited(), &pool());
        s.assembler = Assembler::new();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        s.recv(|buffer| {
            assert_eq!(buffer, b"abc");
            (buffer.len(), ())
        })
        .unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"defghi"[..],
                ..SEND_TEMPL
            }
        );
        let mut data = [0; 6];
        assert_eq!(s.recv_slice(&mut data[..]), Ok(6));
        assert_eq!(data, &b"defghi"[..]);
    }

    /// A segment never takes bytes from two chunks, as one never crossed
    /// the ring's end, and short writes gather in one chunk.
    #[test]
    fn a_segment_stops_at_a_chunk_and_short_writes_gather() {
        let mut s = socket_established();
        s.set_nagle_enabled(false);
        s.tx = TxStore::new(1024, Budget::unlimited(), &pool());

        let long = [b'y'; 200];
        assert_eq!(s.send_slice(&long), Ok(200));
        assert_eq!(s.send_slice(b"abc"), Ok(3));
        assert_eq!(s.send_slice(b"def"), Ok(3));
        assert_eq!(s.tx.descriptors(), 2);
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &long[..],
                ..RECV_TEMPL
            })
        );
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 200,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            })
        );
    }

    // =========================================================================================//
    // Tests for graceful vs ungraceful rx close
    // =========================================================================================//

    #[test]
    fn a_refused_payload_does_not_accept_its_fin() {
        for state in [State::Established, State::FinWait1, State::FinWait2] {
            let mut s = match state {
                State::Established => socket_established(),
                State::FinWait1 => socket_fin_wait_1(),
                State::FinWait2 => socket_fin_wait_2(),
                _ => unreachable!(),
            };
            let budget = Budget::new(4096);
            s.rx = RxStore::new(64, budget.clone(), &pool());
            let held = budget.charge(budget.limit()).unwrap();
            let before = s.remote_seq_no;
            let bytes: Vec<u8> = (0..32).collect();
            let segment = TcpRepr {
                control: TcpControl::Fin,
                seq_number: before,
                ack_number: Some(s.local_seq_no),
                payload: &bytes,
                ..SEND_TEMPL
            };
            let reply = send(&mut s, Instant::from_millis(0), &segment).unwrap();
            assert_eq!(reply.ack_number, Some(before));
            assert_eq!(s.state, state);
            assert!(!s.rx_fin_received);
            assert!(s.pop(64).unwrap().is_none());
            drop(held);
            send(&mut s, Instant::from_millis(1), &segment);
            let mut read = Vec::new();
            while let Ok(Some(chunk)) = s.pop(64) {
                read.extend_from_slice(&chunk);
            }
            assert_eq!(read, bytes);
            assert_eq!(s.pop(64), Err(RecvError::Finished));
            assert_eq!(s.remote_seq_no, before + bytes.len() + 1);
        }
    }

    #[test]
    fn test_rx_close_fin() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::Finished));
    }

    #[test]
    fn test_rx_close_fin_in_fin_wait_1() {
        let mut s = socket_fin_wait_1();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::Finished));
    }

    #[test]
    fn test_rx_close_fin_in_fin_wait_2() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::Finished));
    }

    #[test]
    fn test_rx_close_fin_with_hole() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"ghi"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 61,
                ..RECV_TEMPL
            })
        );
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        s.recv(|data| {
            assert_eq!(data, b"");
            (0, ())
        })
        .unwrap();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 9,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 64,
                ..RECV_TEMPL
            })
        );
        // Only a reset at the gap closes the receive side.
        assert_eq!(s.recv(|_| (0, ())), Ok(()));
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::InvalidState));
    }

    #[test]
    fn test_rx_close_rst() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::InvalidState));
    }

    #[test]
    fn test_rx_close_rst_with_hole() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"ghi"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 61,
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 9,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                window_len: 61,
                ..RECV_TEMPL
            })
        );
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Ok(()));
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::InvalidState));
    }

    // =========================================================================================//
    // Tests for delayed ACK
    // =========================================================================================//

    #[test]
    fn test_delayed_ack() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        // After 10ms, it is sent.
        recv!(s, time 11, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            window_len: 61,
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_two_full_segments_with_options_are_acked_without_delay() {
        for timestamps in [false, true] {
            let mut s = socket_established();
            s.remote_mss = 32;
            s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
            let timestamp = timestamps.then_some(TcpTimestampRepr::new(500, 0));
            if timestamps {
                s.set_tsval_generator(Some(|_| 1));
            }
            // Include an unknown option as well: all header bytes reduce the
            // payload, regardless of whether the receiver understands them.
            let extra = [253, 4, 0, 0];
            let count = if timestamps { 16 } else { 28 };
            let payload = vec![42; count];
            for index in 0..2 {
                send!(
                    s,
                    TcpRepr {
                        seq_number: REMOTE_SEQ + 1 + index * count,
                        ack_number: Some(LOCAL_SEQ + 1),
                        timestamp,
                        extra: &extra,
                        payload: &payload,
                        ..SEND_TEMPL
                    }
                );
                if index == 0 {
                    recv_nothing!(s);
                }
            }
            recv!(
                s,
                [TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1 + 2 * count),
                    window_len: (64 - 2 * count) as u16,
                    timestamp: timestamps.then_some(TcpTimestampRepr::new(1, 500)),
                    ..RECV_TEMPL
                }]
            );
        }
    }

    #[test]
    fn test_delayed_ack_win() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        // Reading the data off the buffer should cause a window update.
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();

        // However, no ACK or window update is immediately sent.
        recv_nothing!(s);

        // After 10ms, it is sent.
        recv!(s, time 11, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_delayed_ack_reply() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();

        s.send_slice(&b"xyz"[..]).unwrap();

        // Writing data to the socket causes ACK to not be delayed,
        // because it is immediately sent with the data.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                payload: &b"xyz"[..],
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_default_ack_threshold_is_two_full_segments() {
        let mut s = socket_established_with_buffer_sizes(DEFAULT_MSS * 4, DEFAULT_MSS * 4);
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; DEFAULT_MSS],
                ..SEND_TEMPL
            }
        );
        recv_nothing!(s);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + DEFAULT_MSS,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; DEFAULT_MSS],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 2 * DEFAULT_MSS),
                window_len: (2 * DEFAULT_MSS) as u16,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_delayed_ack_every_rmss() {
        let mut s = socket_established_with_buffer_sizes(DEFAULT_MSS * 2, DEFAULT_MSS * 2);
        s.settings.ack_segments = 1;
        s.settings.ack_inclusive = false;
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; DEFAULT_MSS - 1],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + (DEFAULT_MSS - 1),
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + DEFAULT_MSS,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        // RMSS+1 bytes of data has been received, so ACK is sent without delay.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + (DEFAULT_MSS + 1)),
                window_len: (DEFAULT_MSS - 1) as u16,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_delayed_ack_every_rmss_or_more() {
        let mut s = socket_established_with_buffer_sizes(DEFAULT_MSS * 2, DEFAULT_MSS * 2);
        s.settings.ack_segments = 1;
        s.settings.ack_inclusive = false;
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; DEFAULT_MSS],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + DEFAULT_MSS,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + (DEFAULT_MSS + 1),
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"b"[..],
                ..SEND_TEMPL
            }
        );

        // RMSS+2 bytes of data has been received, so ACK is sent without delay.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + (DEFAULT_MSS + 2)),
                window_len: (DEFAULT_MSS - 2) as u16,
                ..RECV_TEMPL
            })
        );
    }

    // =========================================================================================//
    // Tests for Nagle's Algorithm
    // =========================================================================================//

    #[test]
    fn test_nagle() {
        let mut s = socket_established();
        s.remote_mss = 6;

        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );

        // If there's data in flight, full segments get sent.
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );

        s.send_slice(b"aaabbbccc").unwrap();
        // If there's data in flight, not-full segments don't get sent.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"aaabbb"[..],
                ..RECV_TEMPL
            }]
        );

        // Data gets ACKd, so there's no longer data in flight
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 6 + 6),
                ..SEND_TEMPL
            }
        );

        // Now non-full segment gets sent.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 6 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"ccc"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_nagle_works_with_reduced_payload_from_options() {
        const EFFECTIVE_MSS: usize = 64;

        let mut s = socket_established_with_buffer_sizes(256, 64);
        s.set_nagle_enabled(true);
        s.set_tsval_generator(Some(|_| 1));
        s.remote_mss = EFFECTIVE_MSS;

        // Send small segment to "arm" Nagle's
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                timestamp: Some(TcpTimestampRepr::new(1, 0)),
                ..RECV_TEMPL
            }]
        );

        // A full segment (once options are accounted for) should not be delayed and contain 12 bytes less due to timestamp
        s.send_slice(&[0; EFFECTIVE_MSS - 12]).unwrap();
        recv!(
            s,
            time 0,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; EFFECTIVE_MSS - 12],
                timestamp: Some(TcpTimestampRepr::new(1, 0)),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_final_packet_in_stream_doesnt_wait_for_nagle() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef0").unwrap();
        s.socket.close();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"0"[..],
            ..RECV_TEMPL
        }), exact);
    }

    // =========================================================================================//
    // Tests for packet filtering.
    // =========================================================================================//

    #[test]
    fn test_doesnt_accept_wrong_port() {
        let mut s = socket_established();
        s.rx = RxStore::new(6, Budget::unlimited(), &pool());
        s.assembler = Assembler::new();

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            dst_port: LOCAL_PORT + 1,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            src_port: REMOTE_PORT + 1,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_doesnt_accept_wrong_ip() {
        let mut s = socket_established();

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        };

        let ip_repr = IpReprIpvX(IpvXRepr {
            identification: 0,
            options: crate::wire::Ipv4OptionBytes::EMPTY,
            wire_dst: None,
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(s.socket.accepts(&mut s.cx, &ip_repr, &tcp_repr));

        let ip_repr_wrong_src = IpReprIpvX(IpvXRepr {
            identification: 0,
            options: crate::wire::Ipv4OptionBytes::EMPTY,
            wire_dst: None,
            src_addr: OTHER_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(!s.socket.accepts(&mut s.cx, &ip_repr_wrong_src, &tcp_repr));

        let ip_repr_wrong_dst = IpReprIpvX(IpvXRepr {
            identification: 0,
            options: crate::wire::Ipv4OptionBytes::EMPTY,
            wire_dst: None,
            src_addr: REMOTE_ADDR,
            dst_addr: OTHER_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(!s.socket.accepts(&mut s.cx, &ip_repr_wrong_dst, &tcp_repr));
    }

    // =========================================================================================//
    // Timer tests
    // =========================================================================================//

    #[test]
    fn test_timer_retransmit() {
        const RTO: Duration = Duration::from_millis(100);
        let mut r = Timer::new();
        assert!(!r.should_retransmit(Instant::from_secs(1)));
        r.set_for_retransmit(Instant::from_millis(1000), RTO);
        assert!(!r.should_retransmit(Instant::from_millis(1000)));
        assert!(!r.should_retransmit(Instant::from_millis(1050)));
        assert!(r.should_retransmit(Instant::from_millis(1101)));
        r.set_for_retransmit(Instant::from_millis(1101), RTO);
        assert!(!r.should_retransmit(Instant::from_millis(1101)));
        assert!(!r.should_retransmit(Instant::from_millis(1150)));
        assert!(!r.should_retransmit(Instant::from_millis(1200)));
        assert!(r.should_retransmit(Instant::from_millis(1301)));
        r.set_for_idle(Instant::from_millis(1301), None);
        assert!(!r.should_retransmit(Instant::from_millis(1350)));
    }

    #[test]
    fn test_rtt_estimator() {
        let mut r = RttEstimator::default();

        let rtos = &[
            6000, 5000, 4252, 3692, 3272, 2956, 2720, 2540, 2408, 2308, 2232, 2176, 2132, 2100,
            2076, 2060, 2048, 2036, 2028, 2024, 2020, 2016, 2012, 2012,
        ];

        for &rto in rtos {
            r.sample(2000);
            assert_eq!(r.retransmission_timeout(), Duration::from_millis(rto));
        }
    }

    // =========================================================================================//
    // Timestamp tests
    // =========================================================================================//

    #[test]
    fn test_tsval_established_connection() {
        let mut s = socket_established();
        s.set_tsval_generator(Some(|_| 1));

        assert!(s.timestamp_enabled());

        // First roundtrip after establishing.
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                timestamp: Some(TcpTimestampRepr::new(1, 0)),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.tx.len(), 6);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                timestamp: Some(TcpTimestampRepr::new(500, 1)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx.len(), 0);
        // Second roundtrip.
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                timestamp: Some(TcpTimestampRepr::new(1, 500)),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx.len(), 0);
    }

    #[test]
    fn a_reset_listener_negotiates_timestamps_with_the_next_peer() {
        let mut s = socket_listen();
        s.set_tsval_generator(Some(|_| 7));
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert!(!s.timestamp_enabled());
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Listen);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ + 100,
                ack_number: None,
                timestamp: Some(TcpTimestampRepr::new(9, 0)),
                ..SEND_TEMPL
            }
        );
        assert!(s.timestamp_enabled());
        recv(&mut s, Instant::from_millis(0), |reply| {
            let timestamp = reply.unwrap().timestamp.unwrap();
            assert_eq!(timestamp.tsecr, 9);
        });
    }

    #[test]
    fn test_tsval_disabled_in_remote_client() {
        let mut s = socket_listen();
        s.set_tsval_generator(Some(|_| 1));
        assert!(s.timestamp_enabled());
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        assert!(!s.timestamp_enabled());
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_tsval_disabled_in_local_server() {
        let mut s = socket_listen();
        // s.set_timestamp(false); // commented to alert if the default state changes
        assert!(!s.timestamp_enabled());
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                timestamp: Some(TcpTimestampRepr::new(500, 0)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        assert!(!s.timestamp_enabled());
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_tsval_disabled_in_remote_server() {
        let mut s = socket();
        s.set_tsval_generator(Some(|_| 1));
        assert!(s.timestamp_enabled());
        s.local_seq_no = LOCAL_SEQ;
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                timestamp: Some(TcpTimestampRepr::new(1, 0)),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                timestamp: None,
                ..SEND_TEMPL
            }
        );
        assert!(!s.timestamp_enabled());
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                timestamp: None,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_tsval_disabled_in_local_client() {
        let mut s = socket();
        // s.set_timestamp(false); // commented to alert if the default state changes
        assert!(!s.timestamp_enabled());
        s.local_seq_no = LOCAL_SEQ;
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                timestamp: Some(TcpTimestampRepr::new(500, 0)),
                ..SEND_TEMPL
            }
        );
        assert!(!s.timestamp_enabled());
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                timestamp: None,
                ..RECV_TEMPL
            }]
        );
    }

    fn scaled_handshake(active: bool) -> TestSocket {
        let mut s = socket_with_buffer_sizes(64, 256 * 1024);
        if active {
            s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: None,
                    window_len: 65535,
                    window_scale: Some(3),
                    max_seg_size: Some(BASE_MSS),
                    sack_permitted: true,
                    ..RECV_TEMPL
                }]
            );
        } else {
            s.listen(LOCAL_END).unwrap();
        }
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: active.then_some(LOCAL_SEQ + 1),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        if !active {
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: Some(REMOTE_SEQ + 1),
                    window_len: 65535,
                    window_scale: Some(3),
                    max_seg_size: Some(BASE_MSS),
                    ..RECV_TEMPL
                }]
            );
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    ..SEND_TEMPL
                }
            );
        }
        s
    }

    #[test]
    fn test_listen_scaled_handshake_no_window_update() {
        let mut s = scaled_handshake(false);
        assert_eq!(s.state, State::Established);
        recv_nothing!(s);
    }

    #[test]
    fn test_connect_scaled_handshake_no_window_update() {
        let mut s = scaled_handshake(true);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: 32768,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::Established);
        recv_nothing!(s);
    }

    #[test]
    fn test_scaled_handshake_reopens_window_after_read() {
        for active in [false, true] {
            let mut s = scaled_handshake(active);
            let capacity = s.rx.capacity();
            let data = vec![42; capacity];
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &data,
                    ..SEND_TEMPL
                }
            );
            recv!(
                s,
                [TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1 + capacity),
                    window_len: 0,
                    ..RECV_TEMPL
                }]
            );
            let mut bytes = vec![0; capacity];
            assert_eq!(s.recv_slice(&mut bytes), Ok(capacity));
            assert_eq!(bytes, data);
            recv!(
                s,
                [TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1 + capacity),
                    window_len: 32768,
                    ..RECV_TEMPL
                }]
            );
        }
    }

    #[test]
    fn test_listen_scaled_handshake_keeps_payload_within_buffer() {
        let mut s = scaled_handshake(false);
        let capacity = s.rx.capacity();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + capacity - 4,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"abcdefghij",
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: 32768,
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &vec![42; capacity - 4],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + capacity),
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        let mut bytes = vec![0; capacity];
        assert_eq!(s.recv_slice(&mut bytes), Ok(capacity));
        assert!(bytes[..capacity - 4].iter().all(|b| *b == 42));
        assert_eq!(&bytes[capacity - 4..], b"abcd");
        assert_eq!(s.recv_slice(&mut [0; 1]), Ok(0));
    }

    fn syn_window_rejects_excess(active: bool, offset: usize) {
        let mut s = scaled_handshake(active);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + offset,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"0123456789",
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: 32768,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.recv_slice(&mut [0; 10]), Ok(0));
    }

    #[test]
    fn test_listen_syn_window_crossing_buffer_end() {
        syn_window_rejects_excess(false, 256 * 1024 - 4);
    }

    #[test]
    fn test_listen_syn_window_past_buffer_end() {
        syn_window_rejects_excess(false, 256 * 1024 + 4);
    }

    #[test]
    fn test_connect_syn_window_crossing_buffer_end() {
        syn_window_rejects_excess(true, 256 * 1024 - 4);
    }

    #[test]
    fn test_connect_syn_window_past_buffer_end() {
        syn_window_rejects_excess(true, 256 * 1024 + 4);
    }

    #[test]
    fn test_fin_at_receive_window_edge() {
        for len in [64, 65] {
            let mut s = socket_established();
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Fin,
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: &vec![42; len],
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.last_scaled_window(), Some(0));
            recv!(
                s,
                [TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 65 + usize::from(len == 64)),
                    window_len: 0,
                    ..RECV_TEMPL
                }]
            );
            let mut bytes = [0; 64];
            assert_eq!(s.recv_slice(&mut bytes), Ok(64));
            assert_eq!(bytes, [42; 64]);
            if len == 64 {
                assert_eq!(s.recv_slice(&mut bytes), Err(RecvError::Finished));
                recv_nothing!(s);
                continue;
            }
            assert_eq!(s.recv_slice(&mut bytes), Ok(0));
            recv!(
                s,
                [TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 65),
                    ..RECV_TEMPL
                }]
            );
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Fin,
                    seq_number: REMOTE_SEQ + 65,
                    ack_number: Some(LOCAL_SEQ + 1),
                    ..SEND_TEMPL
                }
            );
            recv!(
                s,
                [TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 66),
                    ..RECV_TEMPL
                }]
            );
            assert_eq!(s.recv_slice(&mut bytes), Err(RecvError::Finished));
        }
    }

    #[test]
    fn test_scaled_window_keeps_bytes_from_furthest_advertised_edge() {
        let mut s = socket_established_with_buffer_sizes(64, 256 * 1024);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"x",
                ..SEND_TEMPL
            }
        );
        recv!(s, time 20, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 2),
            window_len: 32767,
            ..RECV_TEMPL
        }]);
        send!(s, time 30, TcpRepr {
            seq_number: REMOTE_SEQ + 2,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: b"y",
            ..SEND_TEMPL
        });
        recv!(s, time 30, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 3),
            window_len: 32767,
            ..RECV_TEMPL
        }]);
        let capacity = 256 * 1024;
        send!(s, time 40, TcpRepr {
            seq_number: REMOTE_SEQ + capacity,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: b"z",
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 3),
            window_len: 32767,
            ..RECV_TEMPL
        }));
        let data = vec![7; capacity - 3];
        send!(s, time 50, TcpRepr {
            seq_number: REMOTE_SEQ + 3,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &data,
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + capacity + 1),
            window_len: 0,
            ..RECV_TEMPL
        }));
        let mut bytes = vec![0; capacity];
        assert_eq!(s.recv_slice(&mut bytes), Ok(capacity));
        assert_eq!(&bytes[..2], b"xy");
        assert_eq!(&bytes[2..capacity - 1], data.as_slice());
        assert_eq!(bytes[capacity - 1], b'z');
    }

    #[test]
    fn test_fill_furthest_advertised_window_acknowledges_and_reads_all_data() {
        let capacity = 256 * 1024;
        let mut s = socket_established_with_buffer_sizes(64, capacity);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"x",
                ..SEND_TEMPL
            }
        );
        recv!(s, time 20, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 2),
            window_len: 32767,
            ..RECV_TEMPL
        }]);
        let data = vec![7; capacity - 1];
        send!(s, time 30, TcpRepr {
            seq_number: REMOTE_SEQ + 2,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &data,
            ..SEND_TEMPL
        });
        assert_eq!(s.recv_queue(), capacity);
        assert_eq!(s.socket.poll_at(&mut s.cx, DispatchMode::All), PollAt::Now);
        recv!(s, time 30, [TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + capacity),
            window_len: 0,
            ..RECV_TEMPL
        }]);
        let mut bytes = vec![0; capacity];
        assert_eq!(s.recv_slice(&mut bytes), Ok(capacity));
        assert_eq!(bytes[0], b'x');
        assert_eq!(&bytes[1..], data.as_slice());
        assert_eq!(s.recv_slice(&mut [0; 1]), Ok(0));
    }

    #[test]
    fn test_rounded_window_accepts_previous_edge() {
        let mut s = socket_established_with_buffer_sizes(64, 256 * 1024);
        s.send_slice(b"abc").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                window_len: 32768,
                payload: b"abc",
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"x",
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 4,
                ack_number: Some(REMOTE_SEQ + 2),
                window_len: 32767,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256 * 1024,
                ack_number: Some(LOCAL_SEQ + 4),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.send_queue(), 0);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 256 * 1024,
                ack_number: Some(LOCAL_SEQ + 4),
                payload: b"z",
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 4,
                ack_number: Some(REMOTE_SEQ + 2),
                window_len: 32767,
                ..RECV_TEMPL
            })
        );
        for offset in (1..256 * 1024 - 1).step_by(4096) {
            let end = (offset + 4096).min(256 * 1024 - 1);
            let reply = send(
                &mut s,
                Instant::ZERO,
                &TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + offset,
                    ack_number: Some(LOCAL_SEQ + 4),
                    payload: &vec![42; end - offset],
                    ..SEND_TEMPL
                },
            )
            .unwrap();
            assert_eq!(
                reply.ack_number,
                Some(REMOTE_SEQ + 1 + end + usize::from(end == 256 * 1024 - 1))
            );
        }
        let mut bytes = vec![0; 256 * 1024];
        assert_eq!(s.recv_slice(&mut bytes), Ok(bytes.len()));
        assert_eq!(bytes[0], b'x');
        assert!(bytes[1..bytes.len() - 1].iter().all(|b| *b == 42));
        assert_eq!(bytes[bytes.len() - 1], b'z');
    }

    #[test]
    fn test_old_ack_keeps_payload_and_fin() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: b"abcdef",
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 4),
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"xyz",
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 7,
                ack_number: Some(REMOTE_SEQ + 5),
                window_len: 61,
                ..RECV_TEMPL
            }]
        );
        let mut bytes = [0; 3];
        assert_eq!(s.recv_slice(&mut bytes), Ok(3));
        assert_eq!(&bytes, b"xyz");
        assert_eq!(s.recv_slice(&mut bytes), Err(RecvError::Finished));
        assert_eq!(s.send_queue(), 3);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 5,
                ack_number: Some(LOCAL_SEQ + 7),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.send_queue(), 0);
    }

    #[test]
    fn test_full_assembler_sends_duplicate_ack() {
        let mut s = socket_established();
        for offset in [1, 3, 5, 7, 9] {
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1 + offset,
                    ack_number: Some(LOCAL_SEQ + 1),
                    payload: b"x",
                    ..SEND_TEMPL
                },
                Some(TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    ..RECV_TEMPL
                })
            );
        }
        assert_eq!(s.recv_slice(&mut [0; 10]), Ok(0));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"abcdefghij",
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 11),
                window_len: 54,
                ..RECV_TEMPL
            })
        );
        let mut bytes = [0; 10];
        assert_eq!(s.recv_slice(&mut bytes), Ok(10));
        // Where the segment overlaps bytes already held out of order, the
        // first copy stays: the store keeps only the bytes it lacked. The
        // fifth out-of-order byte found the assembler full and was dropped.
        assert_eq!(&bytes, b"axcxexgxij");
    }

    #[test]
    fn test_long_round_trip_samples() {
        let mut s = socket_established();
        for (n, now) in [0, 700_000_000, 2_900_000_000i64].into_iter().enumerate() {
            s.send_slice(b"x").unwrap();
            recv!(s, time now, [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + n,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: b"x",
                ..RECV_TEMPL
            }]);
            send!(s, time now + 700_000_000, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2 + n),
                ..SEND_TEMPL
            });
        }
    }

    #[test]
    fn test_round_trip_variance_overflow() {
        let mut s = socket_established();
        let mut now = 0;
        for (n, delay) in [700_000_000, 2_200_000_000i64].into_iter().enumerate() {
            s.send_slice(b"x").unwrap();
            recv!(s, time now, [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + n,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: b"x",
                ..RECV_TEMPL
            }]);
            send!(s, time now + delay, TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2 + n),
                ..SEND_TEMPL
            });
            now += delay;
        }
    }

    #[test]
    fn test_round_trip_margin_overflow() {
        let mut s = socket_established();
        s.send_slice(b"x").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: b"x",
                ..RECV_TEMPL
            }]
        );
        send!(s, time 2_200_000_000i64, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 2),
            ..SEND_TEMPL
        });
    }

    #[test]
    fn test_retransmitted_payload_with_new_fin() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"abc",
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 4),
                window_len: 61,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: b"abc",
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 5),
                window_len: 61,
                ..RECV_TEMPL
            }]
        );
        let mut bytes = [0; 3];
        assert_eq!(s.recv_slice(&mut bytes), Ok(3));
        assert_eq!(&bytes, b"abc");
        assert_eq!(s.recv_slice(&mut bytes), Err(RecvError::Finished));
    }

    #[test]
    fn test_recv_slice_closed() {
        let mut s = socket();
        assert_eq!(s.recv_slice(&mut [0; 1]), Err(RecvError::InvalidState));
    }

    #[test]
    fn test_recv_slice_finished() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.recv_slice(&mut [0; 1]), Err(RecvError::Finished));
    }
}
