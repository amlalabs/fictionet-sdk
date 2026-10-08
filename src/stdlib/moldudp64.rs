//! MoldUDP64 1.0: downstream and request packets, a message block framer,
//! and caller-driven gap recovery for receivers and re-request servers,
//! with no I/O and no clocks.
//!
//! MoldUDP64 is Nasdaq's sequenced multicast protocol. A transmitter sends
//! each downstream packet once to every listener; a listener that misses
//! one sends a request packet to a re-request server, which answers by
//! unicast with the missing messages. This module follows the
//! [MoldUDP64 Protocol Specification V 1.00](https://www.nasdaqtrader.com/content/technicalsupport/specifications/dataproducts/moldudp64.pdf).
//! Section names below are that document's.
//!
//! A [`Downstream`] packet is a 20-byte header (session, the sequence
//! number of its first message, message count) and message blocks, each a
//! two-byte length and data. A count of zero is a heartbeat and 0xFFFF is
//! end of session; both carry the next expected sequence number
//! ("Heartbeats", "End of Session"). A [`Request`] names a session, a
//! first sequence number and a count ("Request Packet"). Both are UDP
//! datagrams, read and written whole through [`Wire`]. [`Blocks`] reads
//! the same length-prefixed message blocks from a byte stream, the layout
//! of Nasdaq's binary ITCH files.
//!
//! [`Receiver`] is the listener's flowchart ("Receiver Example"): it
//! tracks the next expected sequence number, says which messages of each
//! packet to process, detects gaps, and asks for them again with one
//! request at a time, retried on a timer a bounded number of times.
//! [`Retransmitter`] is a re-request server: it keeps a bounded store of
//! recent messages and answers each request with one packet of the
//! messages that fit.
//!
//! ```
//! use fictionet::stdlib::session::Action;
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::moldudp64::{
//!     Downstream, Event, Receiver, ReceiverConfig, Retransmitter, Session, StoreConfig,
//! };
//!
//! let session = Session::left_padded("20261006")?;
//! let mut server = Retransmitter::new(session, 1, StoreConfig::default())?;
//! for message in [&b"one"[..], b"two", b"three"] {
//!     server.push(message)?;
//! }
//! let mut receiver = Receiver::new(ReceiverConfig::default())?;
//!
//! // The listener sees message 1, then message 3: message 2 was lost.
//! let first = server.packet(1, 1).unwrap();
//! let third = Downstream::parse(&server.packet(3, 1).unwrap().to_bytes()?)?;
//! receiver.receive(&first, 0)?;
//! let actions = receiver.receive(&third, 5)?;
//! let Some(Action::Send(request)) = actions.last() else { panic!() };
//! assert_eq!((request.sequence, request.count), (2, 2));
//!
//! // The re-request server answers; the listener catches up.
//! let answer = server.answer(request).unwrap();
//! let actions = receiver.receive(&answer, 6)?;
//! assert_eq!(actions, [Action::Event(Event::Deliver { sequence: 2, skip: 0, count: 2 })]);
//! assert_eq!(receiver.expected(), Some(4));
//! # Ok::<(), fictionet::stdlib::moldudp64::Error>(())
//! ```

use fictionet::stdlib::session::Action;
use fictionet::stdlib::codec::{Decode, Step, Wire};
use std::collections::VecDeque;
use std::fmt;

/// Bytes in the session field ("Header").
pub const SESSION_LENGTH: usize = 10;
/// Bytes in a downstream packet header and in a request packet.
pub const HEADER_LENGTH: usize = 20;
/// Bytes in a message block's length field ("Message Block").
pub const BLOCK_PREFIX: usize = 2;
/// The longest message a block can carry.
pub const MAX_MESSAGE: usize = u16::MAX as usize;
/// The message count that marks end of session ("End of Session").
pub const END_OF_SESSION: u16 = 0xFFFF;
/// The most messages one packet can carry: every count but 0xFFFF.
pub const MAX_MESSAGES: usize = END_OF_SESSION as usize - 1;
/// The largest packet read or written: the largest UDP payload over IPv6
/// without jumbograms.
pub const MAX_PACKET_SIZE: usize = 65_527;
/// The default packet size of a [`Retransmitter`]: an Ethernet MTU of
/// 1500 bytes less IPv4 and UDP headers.
pub const DEFAULT_PACKET_SIZE: usize = 1_472;
/// The default most messages a [`Receiver`] asks for in one request.
pub const DEFAULT_REQUEST_COUNT: u16 = 512;
/// The default time a [`Receiver`] waits for an answer before asking again.
pub const DEFAULT_RETRY_MS: u64 = 250;
/// The default number of times a [`Receiver`] asks for the same messages
/// before it reports them lost.
pub const DEFAULT_REQUEST_ATTEMPTS: u32 = 8;
/// The most times a [`Receiver`] may be configured to ask.
pub const MAX_REQUEST_ATTEMPTS: u32 = 1_000;
/// The longest timer a [`Receiver`] accepts: one day.
pub const MAX_TIMER_MS: u64 = 86_400_000;
/// The default number of messages a [`Retransmitter`] keeps.
pub const DEFAULT_STORE_MESSAGES: usize = 1 << 20;
/// The default message bytes a [`Retransmitter`] keeps.
pub const DEFAULT_STORE_BYTES: usize = 64 << 20;
/// The most messages a [`Retransmitter`] may be configured to keep.
pub const MAX_STORE_MESSAGES: usize = 1 << 26;
/// The most message bytes a [`Retransmitter`] may be configured to keep.
pub const MAX_STORE_BYTES: usize = 1 << 30;

/// Why bytes, a value or an operation were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The packet is shorter than its header, its message blocks overrun
    /// it, or bytes follow the last block.
    Length,
    /// A packet over [`MAX_PACKET_SIZE`] or a configured packet size, or a
    /// message over [`MAX_MESSAGE`] or the space a packet leaves.
    TooLong,
    /// A packet with messages must carry 1 to [`MAX_MESSAGES`] of them.
    Count,
    /// A session byte outside printable ASCII, or text longer than the
    /// field.
    Field,
    /// A sequence number would pass `u64::MAX`.
    Sequence,
    /// A time earlier than one already passed in.
    Time,
    /// A configuration value outside its named limits.
    Config,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Length => "MoldUDP64 packet length is wrong",
            Error::TooLong => "MoldUDP64 packet or message is too long",
            Error::Count => "MoldUDP64 message count is invalid",
            Error::Field => "MoldUDP64 session field is invalid",
            Error::Sequence => "MoldUDP64 sequence number is exhausted",
            Error::Time => "time went backwards",
            Error::Config => "MoldUDP64 configuration is out of range",
        })
    }
}
impl std::error::Error for Error {}

/// A session name: ten bytes of printable ASCII, spaces included.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Session([u8; SESSION_LENGTH]);
impl Session {
    /// The field's exact bytes. Refuses a byte outside 0x20..=0x7e.
    pub fn new(bytes: [u8; SESSION_LENGTH]) -> Result<Self, Error> {
        if bytes.iter().all(|b| (0x20..=0x7e).contains(b)) {
            Ok(Self(bytes))
        } else {
            Err(Error::Field)
        }
    }
    /// `text` padded on the left with spaces.
    pub fn left_padded(text: &str) -> Result<Self, Error> {
        let pad = SESSION_LENGTH.checked_sub(text.len()).ok_or(Error::Field)?;
        let mut bytes = [b' '; SESSION_LENGTH];
        bytes
            .get_mut(pad..)
            .ok_or(Error::Field)?
            .copy_from_slice(text.as_bytes());
        Self::new(bytes)
    }
    /// The field's bytes, padding included.
    pub fn as_bytes(&self) -> &[u8; SESSION_LENGTH] {
        &self.0
    }
    /// The text without leading or trailing spaces.
    pub fn trimmed(&self) -> &str {
        // Every byte is printable ASCII, so this is valid UTF-8.
        std::str::from_utf8(&self.0)
            .unwrap_or_default()
            .trim_matches(' ')
    }
}
impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", std::str::from_utf8(&self.0).unwrap_or_default())
    }
}

/// Reads the shared 20-byte header: session, sequence number, count.
fn header(b: &[u8]) -> Result<(Session, u64, u16, &[u8]), Error> {
    let (head, rest) = b.split_at_checked(HEADER_LENGTH).ok_or(Error::Length)?;
    let (session, numbers) = head.split_at(SESSION_LENGTH);
    let (sequence, count) = numbers.split_at(8);
    let session = Session::new(session.try_into().map_err(|_| Error::Length)?)?;
    let sequence = u64::from_be_bytes(sequence.try_into().map_err(|_| Error::Length)?);
    let count = u16::from_be_bytes(count.try_into().map_err(|_| Error::Length)?);
    Ok((session, sequence, count, rest))
}
fn write_header(session: &Session, sequence: u64, count: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(session.as_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
}

/// What a downstream packet carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    /// 1 to [`MAX_MESSAGES`] messages, numbered from the packet's sequence
    /// number. A message may be empty ("Message Data").
    Messages(Vec<Vec<u8>>),
    /// Count 0: no messages; the sequence number is the next expected one.
    Heartbeat,
    /// Count 0xFFFF: the session is over; the sequence number is the next
    /// expected one, and re-requests may still be made.
    EndOfSession,
}

/// A downstream packet, from a transmitter or a re-request server
/// ("Downstream Packet").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Downstream {
    /// The session this packet belongs to.
    pub session: Session,
    /// The first message's sequence number, or for a heartbeat or end of
    /// session the next expected one.
    pub sequence: u64,
    /// The messages, or which marker this is.
    pub body: Body,
}
impl Downstream {
    /// The messages carried; empty for a heartbeat or end of session.
    pub fn messages(&self) -> &[Vec<u8>] {
        match &self.body {
            Body::Messages(m) => m,
            Body::Heartbeat | Body::EndOfSession => &[],
        }
    }
    /// The sequence number after this packet's messages: the next expected
    /// one once it is processed.
    pub fn next_sequence(&self) -> Option<u64> {
        self.sequence
            .checked_add(u64::try_from(self.messages().len()).ok()?)
    }
    /// Bytes the packet takes on the wire.
    pub fn wire_len(&self) -> usize {
        self.messages().iter().fold(HEADER_LENGTH, |n, m| {
            n.saturating_add(BLOCK_PREFIX).saturating_add(m.len())
        })
    }
}
impl Wire for Downstream {
    type ParseError = Error;
    type WriteError = Error;
    /// Reads one whole datagram. Refuses one over [`MAX_PACKET_SIZE`], and
    /// messages whose last sequence number would pass `u64::MAX`.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() > MAX_PACKET_SIZE {
            return Err(Error::TooLong);
        }
        let (session, sequence, count, mut rest) = header(b)?;
        let body = match count {
            0 => Body::Heartbeat,
            END_OF_SESSION => Body::EndOfSession,
            n => {
                // Each block takes at least two bytes, so the capacity is
                // bounded by the datagram.
                let n = usize::from(n);
                let mut messages = Vec::with_capacity(n.min(rest.len() / BLOCK_PREFIX));
                for _ in 0..n {
                    let (len, after) = rest.split_at_checked(BLOCK_PREFIX).ok_or(Error::Length)?;
                    let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
                    let (data, after) = after.split_at_checked(len).ok_or(Error::Length)?;
                    messages.push(data.to_vec());
                    rest = after;
                }
                sequence.checked_add(n as u64).ok_or(Error::Sequence)?;
                Body::Messages(messages)
            }
        };
        if !rest.is_empty() {
            return Err(Error::Length);
        }
        Ok(Self {
            session,
            sequence,
            body,
        })
    }
    /// Writes one datagram. Refuses an empty message list, more than
    /// [`MAX_MESSAGES`], a message over [`MAX_MESSAGE`], a packet over
    /// [`MAX_PACKET_SIZE`], and messages past `u64::MAX`.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let count = match &self.body {
            Body::Heartbeat => 0,
            Body::EndOfSession => END_OF_SESSION,
            Body::Messages(m) => {
                if m.is_empty() || m.len() > MAX_MESSAGES {
                    return Err(Error::Count);
                }
                if m.iter().any(|m| m.len() > MAX_MESSAGE) {
                    return Err(Error::TooLong);
                }
                self.next_sequence().ok_or(Error::Sequence)?;
                u16::try_from(m.len()).map_err(|_| Error::Count)?
            }
        };
        let len = self.wire_len();
        if len > MAX_PACKET_SIZE {
            return Err(Error::TooLong);
        }
        out.reserve(len);
        write_header(&self.session, self.sequence, count, out);
        for m in self.messages() {
            // Checked above: every message fits a u16 length.
            out.extend_from_slice(&(m.len() as u16).to_be_bytes());
            out.extend_from_slice(m);
        }
        Ok(())
    }
}

/// A request for messages again, sent to a re-request server ("Request
/// Packet"). Always 20 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    /// The session the messages belong to.
    pub session: Session,
    /// The first sequence number requested.
    pub sequence: u64,
    /// How many messages to send again.
    pub count: u16,
}
impl Wire for Request {
    type ParseError = Error;
    type WriteError = Error;
    fn parse(b: &[u8]) -> Result<Self, Error> {
        let (session, sequence, count, rest) = header(b)?;
        if !rest.is_empty() {
            return Err(Error::Length);
        }
        Ok(Self {
            session,
            sequence,
            count,
        })
    }
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.reserve(HEADER_LENGTH);
        write_header(&self.session, self.sequence, self.count, out);
        Ok(())
    }
}

/// Reads message blocks (a two-byte big-endian length, then data) from a
/// byte stream, without holding input. Each item is one message. This is
/// the block layout of a downstream packet, and of Nasdaq's binary ITCH
/// files.
///
/// ```
/// use fictionet::stdlib::codec::{finish, pump, Stream};
/// use fictionet::stdlib::moldudp64::Blocks;
///
/// let mut stream = Stream::new(Blocks);
/// let mut messages = Vec::new();
/// pump(&mut stream, &[0, 2, b'h', b'i', 0], |m| messages.push(m))?;
/// pump(&mut stream, &[0], |m| messages.push(m))?;
/// finish(&mut stream, |m| messages.push(m))?;
/// assert_eq!(messages, [b"hi".to_vec(), Vec::new()]);
/// # Ok::<(), fictionet::stdlib::codec::Fail<fictionet::stdlib::moldudp64::Error>>(())
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Blocks;
impl Decode for Blocks {
    type Item = Vec<u8>;
    type Error = Error;
    const NAME: &'static str = "MoldUDP64 message blocks";
    fn capacity(&self) -> usize {
        BLOCK_PREFIX + MAX_MESSAGE
    }
    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Vec<u8>>, Error> {
        let Some((len, rest)) = input.split_at_checked(BLOCK_PREFIX) else {
            return Ok(Step::Need);
        };
        let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
        Ok(match rest.get(..len) {
            Some(data) => Step::Item(data.to_vec(), BLOCK_PREFIX + len),
            None => Step::Need,
        })
    }
}

/// How a [`Receiver`] recovers lost messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiverConfig {
    /// The session to follow. `None` takes the first packet's session
    /// ("Receiver Example", step 2).
    pub session: Option<Session>,
    /// The next expected sequence number, when restarting. `None` takes
    /// the first packet's sequence number.
    pub next: Option<u64>,
    /// The most messages one request asks for, at least 1.
    pub request_count: u16,
    /// How long to wait for an answer before asking again, in milliseconds.
    pub retry_ms: u64,
    /// How many times to ask for the same messages, 1 to
    /// [`MAX_REQUEST_ATTEMPTS`], before reporting them lost.
    pub attempts: u32,
}
impl Default for ReceiverConfig {
    fn default() -> Self {
        Self {
            session: None,
            next: None,
            request_count: DEFAULT_REQUEST_COUNT,
            retry_ms: DEFAULT_RETRY_MS,
            attempts: DEFAULT_REQUEST_ATTEMPTS,
        }
    }
}

/// What a [`Receiver`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// Process `count` messages of the packet passed in, from index `skip`.
    /// The first of them has sequence number `sequence`.
    Deliver {
        /// The sequence number of `messages()[skip]`.
        sequence: u64,
        /// Messages at the start of the packet already processed.
        skip: usize,
        /// Messages to process.
        count: usize,
    },
    /// The packet passed in is ahead of the next expected message; its
    /// messages are dropped and the gap is requested.
    Gap {
        /// The next expected sequence number.
        expected: u64,
        /// The packet's sequence number.
        received: u64,
    },
    /// The packet belongs to another session and was ignored. The
    /// specification's receiver aborts and reports this ("Receiver
    /// Example", step 3); the caller decides.
    SessionMismatch(Session),
    /// These messages were asked for [`ReceiverConfig::attempts`] times
    /// without an answer. The receiver skipped past them.
    Lost {
        /// The first lost sequence number.
        sequence: u64,
        /// How many were lost.
        count: u64,
    },
    /// Every message of the ended session has been processed. Reported once.
    EndOfSession {
        /// The sequence number after the session's last message.
        next: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Pending {
    request: Request,
    sent: u64,
    attempts: u32,
}

/// A MoldUDP64 listener's sequencing, without I/O.
///
/// Pass every downstream packet, multicast or unicast answer, to
/// [`receive`](Self::receive), process the messages each
/// [`Event::Deliver`] names, send every [`Action::Send`] request, and call
/// [`tick`](Self::tick) at least every [`ReceiverConfig::retry_ms`].
///
/// Packets ahead of the next expected message are dropped, as in the
/// specification's flowchart; the gap and their messages are requested
/// again. One request is outstanding at a time and asks for at most
/// [`ReceiverConfig::request_count`] messages. When an answer moves the
/// next expected number, the next request goes out at once; otherwise
/// the request is repeated every `retry_ms`, up to
/// [`ReceiverConfig::attempts`] times, and then reported
/// [`Lost`](Event::Lost). State is a fixed size. An `Err` leaves the
/// receiver unchanged.
#[derive(Clone, Copy, Debug)]
pub struct Receiver {
    config: ReceiverConfig,
    session: Option<Session>,
    expected: Option<u64>,
    high: u64,
    pending: Option<Pending>,
    end: Option<u64>,
    ended: bool,
    now: u64,
}
impl Receiver {
    /// A receiver. Refuses a zero request count and timers or attempts
    /// outside their named limits.
    pub fn new(config: ReceiverConfig) -> Result<Self, Error> {
        if config.request_count == 0
            || !(1..=MAX_TIMER_MS).contains(&config.retry_ms)
            || !(1..=MAX_REQUEST_ATTEMPTS).contains(&config.attempts)
        {
            return Err(Error::Config);
        }
        Ok(Self {
            config,
            session: config.session,
            expected: config.next,
            high: config.next.unwrap_or(0),
            pending: None,
            end: None,
            ended: false,
            now: 0,
        })
    }
    /// The session followed, once known.
    pub fn session(&self) -> Option<Session> {
        self.session
    }
    /// The next expected sequence number, once known. Persist it to restart.
    pub fn expected(&self) -> Option<u64> {
        self.expected
    }
    /// The highest sequence number known to exist, plus one.
    pub fn high(&self) -> u64 {
        self.high
    }
    /// The outstanding request, if any.
    pub fn pending(&self) -> Option<Request> {
        self.pending.map(|p| p.request)
    }
    /// Handles one downstream packet.
    pub fn receive(&mut self, packet: &Downstream, now_ms: u64) -> Result<Vec<Action<Request, Event>>, Error> {
        let mut s = *self;
        s.advance(now_ms)?;
        let session = *s.session.get_or_insert(packet.session);
        if session != packet.session {
            *self = s;
            return Ok(vec![Action::Event(Event::SessionMismatch(packet.session))]);
        }
        let first = packet.sequence;
        let next = packet.next_sequence().ok_or(Error::Sequence)?;
        let expected = *s.expected.get_or_insert(first);
        s.high = s.high.max(next);
        // An End of Session below the next expected message is stale: the
        // session's messages already run past it.
        if packet.body == Body::EndOfSession && first >= expected {
            s.end = Some(s.end.map_or(first, |e| e.max(first)));
        }
        let mut actions = Vec::new();
        if first > expected {
            actions.push(Action::Event(Event::Gap {
                expected,
                received: first,
            }));
        } else if next > expected {
            let skip = usize::try_from(expected - first).map_err(|_| Error::Sequence)?;
            let count = packet.messages().len().saturating_sub(skip);
            actions.push(Action::Event(Event::Deliver {
                sequence: expected,
                skip,
                count,
            }));
            s.expected = Some(next);
        }
        s.recover(&mut actions);
        *self = s;
        Ok(actions)
    }
    /// Runs the retry timer.
    pub fn tick(&mut self, now_ms: u64) -> Result<Vec<Action<Request, Event>>, Error> {
        let mut s = *self;
        s.advance(now_ms)?;
        let mut actions = Vec::new();
        s.recover(&mut actions);
        *self = s;
        Ok(actions)
    }
    fn advance(&mut self, now: u64) -> Result<(), Error> {
        if now < self.now {
            return Err(Error::Time);
        }
        self.now = now;
        Ok(())
    }
    fn recover(&mut self, actions: &mut Vec<Action<Request, Event>>) {
        let (Some(session), Some(expected)) = (self.session, self.expected) else {
            return;
        };
        if self.high <= expected {
            self.pending = None;
        } else {
            match self.pending {
                // An answer arrived: ask for what is still missing.
                Some(p) if expected > p.request.sequence => {
                    self.request(session, expected, actions)
                }
                None => self.request(session, expected, actions),
                Some(p) if self.now.saturating_sub(p.sent) >= self.config.retry_ms => {
                    if p.attempts >= self.config.attempts {
                        let count = u64::from(p.request.count);
                        actions.push(Action::Event(Event::Lost {
                            sequence: expected,
                            count,
                        }));
                        let after = expected.saturating_add(count);
                        self.expected = Some(after);
                        self.pending = None;
                        if self.high > after {
                            self.request(session, after, actions);
                        }
                    } else {
                        self.pending = Some(Pending {
                            sent: self.now,
                            attempts: p.attempts.saturating_add(1),
                            ..p
                        });
                        actions.push(Action::Send(p.request));
                    }
                }
                Some(_) => {}
            }
        }
        let expected = self.expected.unwrap_or(expected);
        if let Some(end) = self.end
            && !self.ended
            && expected >= end
        {
            self.ended = true;
            actions.push(Action::Event(Event::EndOfSession { next: end }));
        }
    }
    fn request(&mut self, session: Session, from: u64, actions: &mut Vec<Action<Request, Event>>) {
        let missing = self.high.saturating_sub(from);
        let count = u16::try_from(missing)
            .unwrap_or(u16::MAX)
            .min(self.config.request_count);
        let request = Request {
            session,
            sequence: from,
            count,
        };
        self.pending = Some(Pending {
            request,
            sent: self.now,
            attempts: 1,
        });
        actions.push(Action::Send(request));
    }
}

/// The limits of a [`Retransmitter`]'s store and packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreConfig {
    /// The largest packet sent, from [`HEADER_LENGTH`] plus one empty
    /// block up to [`MAX_PACKET_SIZE`]. A message must fit in one packet.
    pub packet_size: usize,
    /// The most messages kept, 1 to [`MAX_STORE_MESSAGES`].
    pub max_messages: usize,
    /// The most message bytes kept, 1 to [`MAX_STORE_BYTES`].
    pub max_bytes: usize,
}
impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            packet_size: DEFAULT_PACKET_SIZE,
            max_messages: DEFAULT_STORE_MESSAGES,
            max_bytes: DEFAULT_STORE_BYTES,
        }
    }
}

/// A re-request server for one session, without I/O.
///
/// [`push`](Self::push) numbers and keeps each message the transmitter
/// sends; the oldest are dropped past [`StoreConfig::max_messages`] or
/// [`StoreConfig::max_bytes`]. [`answer`](Self::answer) turns a request
/// into one packet holding as many of the requested messages, from the
/// first requested, as fit in [`StoreConfig::packet_size`] ("Request
/// Packet"). [`packet`](Self::packet), [`heartbeat`](Self::heartbeat) and
/// [`end_of_session`](Self::end_of_session) build the transmitter's own
/// packets from the same store.
#[derive(Clone, Debug)]
pub struct Retransmitter {
    session: Session,
    config: StoreConfig,
    first: u64,
    messages: VecDeque<Vec<u8>>,
    bytes: usize,
}
impl Retransmitter {
    /// An empty store whose first message will have sequence number `first`.
    pub fn new(session: Session, first: u64, config: StoreConfig) -> Result<Self, Error> {
        if !(HEADER_LENGTH + BLOCK_PREFIX..=MAX_PACKET_SIZE).contains(&config.packet_size)
            || !(1..=MAX_STORE_MESSAGES).contains(&config.max_messages)
            || !(1..=MAX_STORE_BYTES).contains(&config.max_bytes)
        {
            return Err(Error::Config);
        }
        Ok(Self {
            session,
            config,
            first,
            messages: VecDeque::new(),
            bytes: 0,
        })
    }
    /// The session served.
    pub fn session(&self) -> Session {
        self.session
    }
    /// The sequence number of the oldest message kept.
    pub fn first_sequence(&self) -> u64 {
        self.first
    }
    /// The sequence number the next pushed message gets.
    pub fn next_sequence(&self) -> u64 {
        // `push` refuses a message whose number would overflow.
        self.first.saturating_add(self.messages.len() as u64)
    }
    /// Message bytes kept.
    pub fn held(&self) -> usize {
        self.bytes
    }
    /// The largest message a packet of [`StoreConfig::packet_size`] holds.
    pub fn max_message(&self) -> usize {
        (self.config.packet_size - HEADER_LENGTH - BLOCK_PREFIX).min(MAX_MESSAGE)
    }
    /// Keeps `message` and returns its sequence number. Refuses a message
    /// over [`max_message`](Self::max_message) or
    /// [`StoreConfig::max_bytes`], and a sequence number past `u64::MAX`.
    pub fn push(&mut self, message: &[u8]) -> Result<u64, Error> {
        if message.len() > self.max_message() || message.len() > self.config.max_bytes {
            return Err(Error::TooLong);
        }
        let sequence = self.next_sequence();
        sequence.checked_add(1).ok_or(Error::Sequence)?;
        while self.messages.len() >= self.config.max_messages
            || self.bytes.saturating_add(message.len()) > self.config.max_bytes
        {
            let Some(old) = self.messages.pop_front() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(old.len());
            self.first = self.first.saturating_add(1);
        }
        self.messages.push_back(message.to_vec());
        self.bytes = self.bytes.saturating_add(message.len());
        Ok(sequence)
    }
    /// A packet of up to `count` kept messages from `sequence`, as many as
    /// fit in one packet. `None` when `sequence` is not kept or `count` is 0.
    pub fn packet(&self, sequence: u64, count: u16) -> Option<Downstream> {
        let start = usize::try_from(sequence.checked_sub(self.first)?).ok()?;
        if start >= self.messages.len() {
            return None;
        }
        let mut size = HEADER_LENGTH;
        let mut messages = Vec::new();
        for m in self.messages.range(start..).take(usize::from(count)) {
            let after = size.saturating_add(BLOCK_PREFIX).saturating_add(m.len());
            if after > self.config.packet_size {
                break;
            }
            size = after;
            messages.push(m.clone());
        }
        if messages.is_empty() {
            return None;
        }
        Some(Downstream {
            session: self.session,
            sequence,
            body: Body::Messages(messages),
        })
    }
    /// The answer to `request`: [`packet`](Self::packet) for this session,
    /// `None` for another session or messages not kept.
    pub fn answer(&self, request: &Request) -> Option<Downstream> {
        if request.session != self.session {
            return None;
        }
        self.packet(request.sequence, request.count)
    }
    /// A heartbeat carrying the next sequence number ("Heartbeats").
    pub fn heartbeat(&self) -> Downstream {
        Downstream {
            session: self.session,
            sequence: self.next_sequence(),
            body: Body::Heartbeat,
        }
    }
    /// An end of session packet carrying the next sequence number ("End of
    /// Session"). Send it a few times in place of heartbeats, and keep
    /// answering requests while it is sent.
    pub fn end_of_session(&self) -> Downstream {
        Downstream {
            session: self.session,
            sequence: self.next_sequence(),
            body: Body::EndOfSession,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{
        Fail, Lcg,
        contract::{check_decode, check_decode_with_alloc_limit, check_wire, check_wire_value},
        test_support::{decode_all, mutate},
    };

    fn session() -> Session {
        Session::left_padded("SESSION1").unwrap()
    }
    fn packet(sequence: u64, messages: &[&[u8]]) -> Downstream {
        Downstream {
            session: session(),
            sequence,
            body: Body::Messages(messages.iter().map(|m| m.to_vec()).collect()),
        }
    }
    fn heartbeat(sequence: u64) -> Downstream {
        Downstream {
            session: session(),
            sequence,
            body: Body::Heartbeat,
        }
    }

    // Layouts from "Downstream Packet", "Message Block", "Heartbeats",
    // "End of Session" and "Request Packet".
    #[test]
    fn exact_bytes() {
        let mut expected = b"  SESSION1".to_vec();
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 0x02]);
        expected.extend_from_slice(&[0, 2]);
        expected.extend_from_slice(&[0, 3, b'a', b'b', b'c']);
        expected.extend_from_slice(&[0, 0]);
        let p = packet(0x102, &[b"abc", b""]);
        assert_eq!(p.to_bytes().unwrap(), expected);
        assert_eq!(Downstream::parse(&expected).unwrap(), p);
        assert_eq!(p.wire_len(), expected.len());

        let mut hb = b"  SESSION1".to_vec();
        hb.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 7, 0, 0]);
        assert_eq!(heartbeat(7).to_bytes().unwrap(), hb);
        let mut eos = hb.clone();
        eos[18] = 0xff;
        eos[19] = 0xff;
        let end = Downstream {
            body: Body::EndOfSession,
            ..heartbeat(7)
        };
        assert_eq!(end.to_bytes().unwrap(), eos);
        assert_eq!(Downstream::parse(&eos).unwrap(), end);

        let request = Request {
            session: session(),
            sequence: 9,
            count: 3,
        };
        let mut rq = b"  SESSION1".to_vec();
        rq.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 9, 0, 3]);
        assert_eq!(request.to_bytes().unwrap(), rq);
        assert_eq!(Request::parse(&rq).unwrap(), request);
    }

    #[test]
    fn refuses_bad_packets() {
        let good = packet(1, &[b"abc"]).to_bytes().unwrap();
        assert_eq!(Downstream::parse(&good[..19]), Err(Error::Length));
        assert_eq!(
            Downstream::parse(&good[..good.len() - 1]),
            Err(Error::Length)
        );
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(Downstream::parse(&trailing), Err(Error::Length));
        let mut hb = heartbeat(1).to_bytes().unwrap();
        hb.push(0);
        assert_eq!(Downstream::parse(&hb), Err(Error::Length));
        let mut bad = good.clone();
        bad[0] = 0;
        assert_eq!(Downstream::parse(&bad), Err(Error::Field));
        assert_eq!(
            Downstream::parse(&vec![b' '; MAX_PACKET_SIZE + 1]),
            Err(Error::TooLong)
        );
        assert_eq!(Request::parse(&good), Err(Error::Length));
        let overflow = packet(u64::MAX, &[b"a"]);
        assert_eq!(overflow.to_bytes(), Err(Error::Sequence));
        let mut b = overflow.clone();
        b.sequence = 1;
        let mut bytes = b.to_bytes().unwrap();
        bytes[10..18].copy_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(Downstream::parse(&bytes), Err(Error::Sequence));
        // u64::MAX - 1 plus one message ends exactly at u64::MAX.
        check_wire_value(&packet(u64::MAX - 1, &[b"a"]));
        for refused in [
            packet(1, &[]),
            packet(1, &[&vec![0; MAX_MESSAGE + 1]]),
            Downstream {
                body: Body::Messages(vec![Vec::new(); MAX_MESSAGES + 1]),
                ..heartbeat(1)
            },
            packet(1, &[&vec![0; 40_000], &vec![0; 40_000]]),
        ] {
            check_wire_value(&refused);
            assert!(refused.to_bytes().is_err());
        }
        check_wire_value(&packet(1, &[&vec![0; MAX_PACKET_SIZE - 22]]));
        assert_eq!(Session::left_padded("ELEVEN CHAR"), Err(Error::Field));
    }

    #[test]
    fn round_trips() {
        for p in [
            packet(1, &[b"x"]),
            packet(5, &[b"", b"", b"abc"]),
            heartbeat(0),
            Downstream {
                body: Body::EndOfSession,
                ..heartbeat(u64::MAX)
            },
        ] {
            check_wire_value(&p);
            check_wire::<Downstream>(&p.to_bytes().unwrap());
        }
        check_wire_value(&Request {
            session: session(),
            sequence: u64::MAX,
            count: u16::MAX,
        });
    }

    #[test]
    fn blocks_follow_the_contract() {
        let mut bytes = Vec::new();
        for m in [&b"abc"[..], b"", &[0xff; 300]] {
            bytes.extend_from_slice(&(m.len() as u16).to_be_bytes());
            bytes.extend_from_slice(m);
        }
        check_decode(|| Blocks, &bytes);
        check_decode_with_alloc_limit(|| Blocks, &bytes, 2 * (MAX_MESSAGE + 2));
        let (items, failure) = decode_all(|| Blocks, &bytes);
        assert!(failure.is_none());
        assert_eq!(items, [b"abc".to_vec(), Vec::new(), vec![0xff; 300]]);
        let (_, failure) = decode_all(|| Blocks, &[0, 5, 1]);
        assert_eq!(failure, Some(Fail::Truncated { unread: 3 }));
        // A downstream packet's blocks read the same through Blocks.
        let p = packet(1, &[b"one", b"two"]).to_bytes().unwrap();
        let (items, _) = decode_all(|| Blocks, &p[HEADER_LENGTH..]);
        assert_eq!(items, [b"one".to_vec(), b"two".to_vec()]);
    }

    #[test]
    fn mutated_packets_keep_the_contract() {
        let bases = [
            packet(3, &[b"abc", b"", b"defg"]).to_bytes().unwrap(),
            heartbeat(4).to_bytes().unwrap(),
        ];
        let mut rng = Lcg::new(0x4d01d);
        for _ in 0..400 {
            let mut bytes = bases[rng.index(2)].clone();
            for _ in 0..=rng.below(4) {
                mutate(&mut rng, &mut bytes);
            }
            check_wire::<Downstream>(&bytes);
            check_wire::<Request>(&bytes);
            check_decode(|| Blocks, &bytes);
            if let Ok(p) = Downstream::parse(&bytes) {
                let mut r = Receiver::new(ReceiverConfig::default()).unwrap();
                let _ = r.receive(&p, 0).unwrap();
            }
        }
    }

    fn sends(actions: &[Action<Request, Event>]) -> Vec<Request> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Send(r) => Some(*r),
                Action::Event(_) => None,
            })
            .collect()
    }

    #[test]
    fn in_order_delivery_and_duplicates() {
        let mut r = Receiver::new(ReceiverConfig::default()).unwrap();
        assert_eq!(
            r.receive(&packet(10, &[b"a", b"b"]), 0).unwrap(),
            [Action::Event(Event::Deliver {
                sequence: 10,
                skip: 0,
                count: 2
            })]
        );
        assert_eq!(r.session(), Some(session()));
        assert_eq!(r.expected(), Some(12));
        // Overlap: only the new message is delivered.
        assert_eq!(
            r.receive(&packet(11, &[b"b", b"c"]), 1).unwrap(),
            [Action::Event(Event::Deliver {
                sequence: 12,
                skip: 1,
                count: 1
            })]
        );
        // A whole duplicate and a current heartbeat do nothing.
        assert!(r.receive(&packet(10, &[b"a"]), 2).unwrap().is_empty());
        assert!(r.receive(&heartbeat(13), 3).unwrap().is_empty());
        assert_eq!(r.expected(), Some(13));
        assert_eq!(r.pending(), None);
    }

    #[test]
    fn gap_is_requested_and_filled() {
        let mut r = Receiver::new(ReceiverConfig {
            next: Some(1),
            ..ReceiverConfig::default()
        })
        .unwrap();
        let actions = r.receive(&packet(4, &[b"d", b"e"]), 0).unwrap();
        assert_eq!(
            actions,
            [
                Action::Event(Event::Gap {
                    expected: 1,
                    received: 4
                }),
                Action::Send(Request {
                    session: session(),
                    sequence: 1,
                    count: 5
                })
            ]
        );
        // More live packets ahead do not send another request.
        let actions = r.receive(&packet(6, &[b"f"]), 10).unwrap();
        assert!(sends(&actions).is_empty());
        // A partial answer: the follow-up asks for the rest at once.
        let actions = r.receive(&packet(1, &[b"a", b"b"]), 20).unwrap();
        assert_eq!(
            actions,
            [
                Action::Event(Event::Deliver {
                    sequence: 1,
                    skip: 0,
                    count: 2
                }),
                Action::Send(Request {
                    session: session(),
                    sequence: 3,
                    count: 4
                })
            ]
        );
        let actions = r
            .receive(&packet(3, &[b"c", b"d", b"e", b"f"]), 30)
            .unwrap();
        assert_eq!(
            actions,
            [Action::Event(Event::Deliver {
                sequence: 3,
                skip: 0,
                count: 4
            })]
        );
        assert_eq!(r.pending(), None);
        assert_eq!(r.expected(), Some(7));
    }

    #[test]
    fn heartbeat_reveals_a_gap_and_requests_are_bounded() {
        let mut r = Receiver::new(ReceiverConfig {
            request_count: 100,
            ..ReceiverConfig::default()
        })
        .unwrap();
        let _ = r.receive(&packet(1, &[b"a"]), 0).unwrap();
        let actions = r.receive(&heartbeat(1_000_000), 1).unwrap();
        assert_eq!(
            sends(&actions),
            [Request {
                session: session(),
                sequence: 2,
                count: 100
            }]
        );
    }

    #[test]
    fn retries_then_reports_lost() {
        let mut r = Receiver::new(ReceiverConfig {
            next: Some(1),
            retry_ms: 100,
            attempts: 3,
            request_count: 2,
            ..ReceiverConfig::default()
        })
        .unwrap();
        let first = sends(&r.receive(&packet(4, &[b"d"]), 0).unwrap());
        assert_eq!(first.len(), 1);
        assert!(r.tick(99).unwrap().is_empty());
        assert_eq!(sends(&r.tick(100).unwrap()), first);
        assert_eq!(sends(&r.tick(200).unwrap()), first);
        let actions = r.tick(300).unwrap();
        assert_eq!(
            actions,
            [
                Action::Event(Event::Lost {
                    sequence: 1,
                    count: 2
                }),
                Action::Send(Request {
                    session: session(),
                    sequence: 3,
                    count: 2
                })
            ]
        );
        assert_eq!(r.expected(), Some(3));
        assert_eq!(r.tick(299), Err(Error::Time));
        assert_eq!(r.expected(), Some(3));
    }

    #[test]
    fn session_mismatch_and_end_of_session() {
        let mut r = Receiver::new(ReceiverConfig {
            session: Some(session()),
            ..ReceiverConfig::default()
        })
        .unwrap();
        let other = Downstream {
            session: Session::left_padded("OTHER").unwrap(),
            ..packet(1, &[b"x"])
        };
        assert_eq!(
            r.receive(&other, 0).unwrap(),
            [Action::Event(Event::SessionMismatch(other.session))]
        );
        assert_eq!(r.expected(), None);
        let _ = r.receive(&packet(1, &[b"a"]), 1).unwrap();
        let end = Downstream {
            body: Body::EndOfSession,
            ..heartbeat(3)
        };
        let actions = r.receive(&end, 2).unwrap();
        assert_eq!(sends(&actions).len(), 1);
        assert!(!actions.contains(&Action::Event(Event::EndOfSession { next: 3 })));
        let actions = r.receive(&packet(2, &[b"b"]), 3).unwrap();
        assert_eq!(
            actions.last(),
            Some(&Action::Event(Event::EndOfSession { next: 3 }))
        );
        assert!(r.receive(&end, 4).unwrap().is_empty());
    }

    #[test]
    fn stale_end_of_session_is_ignored() {
        let mut r = Receiver::new(ReceiverConfig::default()).unwrap();
        let _ = r.receive(&packet(1, &[b"a", b"b", b"c"]), 0).unwrap();
        assert_eq!(r.expected(), Some(4));
        // An End of Session marking 2 is below the messages already seen.
        let stale = Downstream {
            body: Body::EndOfSession,
            ..heartbeat(2)
        };
        assert!(r.receive(&stale, 1).unwrap().is_empty());
        let actions = r.receive(&packet(4, &[b"d"]), 2).unwrap();
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::Event(Event::EndOfSession { .. })))
        );
        // The real one still ends the session.
        let end = Downstream {
            body: Body::EndOfSession,
            ..heartbeat(5)
        };
        assert_eq!(
            r.receive(&end, 3).unwrap(),
            [Action::Event(Event::EndOfSession { next: 5 })]
        );
    }

    #[test]
    fn config_limits() {
        for config in [
            ReceiverConfig {
                request_count: 0,
                ..ReceiverConfig::default()
            },
            ReceiverConfig {
                retry_ms: 0,
                ..ReceiverConfig::default()
            },
            ReceiverConfig {
                attempts: MAX_REQUEST_ATTEMPTS + 1,
                ..ReceiverConfig::default()
            },
        ] {
            assert_eq!(Receiver::new(config).err(), Some(Error::Config));
        }
        for config in [
            StoreConfig {
                packet_size: HEADER_LENGTH + 1,
                ..StoreConfig::default()
            },
            StoreConfig {
                max_messages: 0,
                ..StoreConfig::default()
            },
            StoreConfig {
                max_bytes: MAX_STORE_BYTES + 1,
                ..StoreConfig::default()
            },
        ] {
            assert_eq!(
                Retransmitter::new(session(), 1, config).err(),
                Some(Error::Config)
            );
        }
    }

    #[test]
    fn retransmitter_answers_from_a_bounded_store() {
        let mut s = Retransmitter::new(
            session(),
            1,
            StoreConfig {
                packet_size: HEADER_LENGTH + 3 * (BLOCK_PREFIX + 4),
                max_messages: 5,
                max_bytes: 18,
            },
        )
        .unwrap();
        assert_eq!(s.max_message(), 16);
        assert_eq!(s.push(&[0; 17]), Err(Error::TooLong));
        for i in 0..6u8 {
            assert_eq!(s.push(&[i; 4]).unwrap(), u64::from(i) + 1);
        }
        // 24 bytes pushed, 18 kept: the oldest two are gone.
        assert_eq!(s.first_sequence(), 3);
        assert_eq!(s.next_sequence(), 7);
        assert_eq!(s.held(), 16);
        let request = Request {
            session: session(),
            sequence: 3,
            count: 10,
        };
        let answer = s.answer(&request).unwrap();
        // Only three blocks fit.
        assert_eq!(answer.sequence, 3);
        assert_eq!(answer.messages(), [vec![2; 4], vec![3; 4], vec![4; 4]]);
        assert!(answer.wire_len() <= HEADER_LENGTH + 18);
        check_wire_value(&answer);
        assert_eq!(
            s.answer(&Request {
                sequence: 2,
                ..request
            }),
            None
        );
        assert_eq!(
            s.answer(&Request {
                sequence: 7,
                ..request
            }),
            None
        );
        // A request past the store, from the network, is not kept.
        assert_eq!(
            s.answer(&Request {
                sequence: 8,
                ..request
            }),
            None
        );
        assert_eq!(s.packet(u64::MAX, 1), None);
        assert_eq!(
            s.answer(&Request {
                count: 0,
                ..request
            }),
            None
        );
        assert_eq!(
            s.answer(&Request {
                session: Session::left_padded("X").unwrap(),
                ..request
            }),
            None
        );
        assert_eq!(s.heartbeat().sequence, 7);
        assert_eq!(s.end_of_session().body, Body::EndOfSession);
        // The message-count limit evicts too.
        for _ in 0..10 {
            s.push(&[]).unwrap();
        }
        assert_eq!(s.next_sequence() - s.first_sequence(), 5);
        let mut full = Retransmitter::new(session(), u64::MAX - 1, StoreConfig::default()).unwrap();
        assert_eq!(full.push(b"a").unwrap(), u64::MAX - 1);
        assert_eq!(full.push(b"b"), Err(Error::Sequence));
    }

    #[test]
    fn receiver_recovers_over_a_lossy_link() {
        let mut rng = Lcg::new(0x60d);
        for _ in 0..50 {
            let mut server = Retransmitter::new(session(), 1, StoreConfig::default()).unwrap();
            let mut r = Receiver::new(ReceiverConfig {
                next: Some(1),
                ..ReceiverConfig::default()
            })
            .unwrap();
            let mut got = Vec::new();
            let mut now = 0;
            let deliver = |p: &Downstream, actions: &[Action<Request, Event>], got: &mut Vec<Vec<u8>>| {
                for a in actions {
                    if let Action::Event(Event::Deliver { skip, count, .. }) = a {
                        got.extend_from_slice(&p.messages()[*skip..*skip + *count]);
                    }
                }
            };
            for i in 0..200u32 {
                now += 10;
                let seq = server.push(&i.to_be_bytes()).unwrap();
                let live = server.packet(seq, 1).unwrap();
                let mut requests = Vec::new();
                if rng.below(4) != 0 {
                    let actions = r.receive(&live, now).unwrap();
                    deliver(&live, &actions, &mut got);
                    requests.extend(sends(&actions));
                }
                requests.extend(sends(&r.tick(now).unwrap()));
                while let Some(request) = requests.pop() {
                    assert!(request.count <= DEFAULT_REQUEST_COUNT);
                    if rng.below(3) == 0 {
                        continue;
                    }
                    if let Some(answer) = server.answer(&request) {
                        let actions = r.receive(&answer, now).unwrap();
                        deliver(&answer, &actions, &mut got);
                        requests.extend(sends(&actions));
                    }
                }
            }
            // Drain with a reliable link.
            let hb = server.heartbeat();
            let mut requests = sends(&r.receive(&hb, now).unwrap());
            for _ in 0..1000 {
                now += DEFAULT_RETRY_MS;
                requests.extend(sends(&r.tick(now).unwrap()));
                let Some(request) = requests.pop() else { break };
                let answer = server.answer(&request).unwrap();
                let actions = r.receive(&answer, now).unwrap();
                deliver(&answer, &actions, &mut got);
                requests.extend(sends(&actions));
            }
            let want: Vec<Vec<u8>> = (0..200u32).map(|i| i.to_be_bytes().to_vec()).collect();
            // Nothing is reported lost with eight attempts at one in three.
            assert_eq!(got.len(), want.len());
            assert_eq!(got, want);
        }
    }
}
