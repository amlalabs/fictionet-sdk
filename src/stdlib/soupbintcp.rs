//! SoupBinTCP 3.0: packets, a framer, and caller-driven client and server
//! sessions, with no I/O and no clocks.
//!
//! SoupBinTCP is Nasdaq's point-to-point session protocol over TCP. A
//! server streams sequenced messages (ITCH, OUCH and similar feeds) to one
//! client and a client sends unsequenced messages back. After a broken
//! connection the client logs in again with its session and next sequence
//! number, and the server carries on from there. This module follows the
//! [SoupBinTCP 3.00 specification](https://www.nasdaqtrader.com/content/technicalsupport/specifications/dataproducts/soupbintcp.pdf).
//! Section numbers below are that document's.
//!
//! Every packet is a two-byte big-endian length, one type byte and a payload
//! (1.1). The length counts the type byte and the payload. [`Packet`] is one
//! whole packet, length prefix included, read and written through
//! [`Wire`]. [`Packets`] reads packets from a byte stream for a
//! [`Stream`](fictionet::stdlib::codec::Stream). A packet that frames but
//! does not parse is an item (`Err`), so a session can close the
//! connection as it chooses.
//!
//! [`Client`] and [`Server`] are the session rules: login (1.2, 2.2.1,
//! 2.3.1), heartbeats once a side has sent nothing for one second and an
//! idle timeout of 15 seconds without input (1.3), implied sequence numbers
//! of sequenced data (2.2.3), logout (2.3.4) and end of session (1.4,
//! 2.2.5). Time is milliseconds from a monotonic clock the caller reads.
//! Each operation returns the [`Action`]s to perform, in order: packets to
//! write, then events.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::soupbintcp::{
//!     Action, Alpha, Client, Event, Login, Packet, Packets, Server, Timers,
//! };
//!
//! let login = Login {
//!     username: Alpha::right_padded("ALICE")?,
//!     password: Alpha::right_padded("SECRET")?,
//!     session: Alpha::blank(),
//!     sequence: 1,
//! };
//! let mut client = Client::new(login, Timers::default(), 0)?;
//! let mut server = Server::new(Timers::default(), 0)?;
//!
//! // The client's login request crosses the wire as bytes.
//! let mut wire = Vec::new();
//! for action in client.start(0)? {
//!     if let Action::Send(packet) = action {
//!         packet.write(&mut wire)?;
//!     }
//! }
//! let mut frames = Stream::new(Packets::default());
//! assert_eq!(frames.push(&wire), wire.len());
//! let frame = frames.next().unwrap().unwrap();
//! let actions = server.receive_frame(&frame, 10)?;
//! assert!(matches!(&actions[..], [Action::Event(Event::LoginRequested(_))]));
//!
//! // World code checks the credentials and picks the session.
//! let session = Alpha::left_padded("20261006")?;
//! for action in server.accept(session, 1, 10)? {
//!     if let Action::Send(packet) = action {
//!         client.receive(&packet, 20)?;
//!     }
//! }
//! let data = server.send(b"hello", 30)?;
//! let events = client.receive(&data, 40)?;
//! assert_eq!(events, [Action::Event(Event::Sequenced { sequence: 1 })]);
//! assert_eq!(client.next_sequence(), 2);
//!
//! // A second of silence: the server owes a heartbeat.
//! assert_eq!(server.tick(1030)?, [Action::Send(Packet::ServerHeartbeat)]);
//! # Ok::<(), fictionet::stdlib::soupbintcp::Error>(())
//! ```

use fictionet::stdlib::codec::{Decode, Step, Wire};
use std::fmt;

/// Bytes in the length prefix.
pub const LENGTH_PREFIX: usize = 2;
/// The most payload bytes one packet can carry: the length field counts
/// the type byte, and holds at most 65535.
pub const MAX_PAYLOAD: usize = u16::MAX as usize - 1;
/// The largest packet, length prefix included.
pub const MAX_PACKET: usize = LENGTH_PREFIX + 1 + MAX_PAYLOAD;
/// Bytes in a session field (2.2.1, 2.3.1).
pub const SESSION_LENGTH: usize = 10;
/// Bytes in the login username field (2.3.1).
pub const USERNAME_LENGTH: usize = 6;
/// Bytes in the login password field (2.3.1).
pub const PASSWORD_LENGTH: usize = 10;
/// ASCII digits in a sequence number field (2.2.1, 2.3.1).
pub const SEQUENCE_LENGTH: usize = 20;
/// Silence on the sending side after which a heartbeat is due (1.3).
pub const HEARTBEAT_INTERVAL_MS: u64 = 1000;
/// Silence on the receiving side after which the link is down (1.3).
pub const IDLE_TIMEOUT_MS: u64 = 15_000;
/// Time allowed between connecting and completing login (2.3.1).
pub const LOGIN_TIMEOUT_MS: u64 = 30_000;
/// The longest timer a session accepts: one day.
pub const MAX_TIMER_MS: u64 = 86_400_000;

/// Why bytes, a value or a session operation were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The length prefix disagrees with the bytes, or with the fixed size
    /// of the packet's type.
    Length,
    /// A payload is longer than [`MAX_PAYLOAD`] or a [`Packets`] limit.
    TooLong,
    /// An unknown packet type byte.
    Type(u8),
    /// An alphanumeric field has a byte outside printable ASCII, or text
    /// longer than the field.
    Field,
    /// A numeric field is not digits padded with spaces, or does not fit
    /// in 64 bits.
    Number,
    /// An unknown login reject code (2.2.2).
    Reason(u8),
    /// The session's state does not allow this operation.
    State,
    /// A time earlier than one already passed in.
    Time,
    /// A sequence number would pass `u64::MAX`.
    Sequence,
    /// A timer is zero or longer than [`MAX_TIMER_MS`].
    Config,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Length => f.write_str("SoupBinTCP packet length is wrong"),
            Error::TooLong => f.write_str("SoupBinTCP payload is too long"),
            Error::Type(t) => write!(f, "unknown SoupBinTCP packet type {t:#04x}"),
            Error::Field => f.write_str("SoupBinTCP alphanumeric field is invalid"),
            Error::Number => f.write_str("SoupBinTCP numeric field is invalid"),
            Error::Reason(r) => write!(f, "unknown SoupBinTCP reject code {r:#04x}"),
            Error::State => f.write_str("SoupBinTCP session state does not allow this"),
            Error::Time => f.write_str("time went backwards"),
            Error::Sequence => f.write_str("SoupBinTCP sequence number is exhausted"),
            Error::Config => f.write_str("SoupBinTCP timer is out of range"),
        }
    }
}
impl std::error::Error for Error {}

/// A fixed-width alphanumeric field: `N` bytes of printable ASCII,
/// spaces included. Padding is part of the value, so fields round-trip
/// byte for byte.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Alpha<const N: usize>([u8; N]);
impl<const N: usize> Alpha<N> {
    /// All spaces. A blank requested session asks for the active one (2.3.1).
    pub fn blank() -> Self {
        Self([b' '; N])
    }
    /// The field's exact bytes. Refuses a byte outside 0x20..=0x7e.
    pub fn new(bytes: [u8; N]) -> Result<Self, Error> {
        if bytes.iter().all(|b| (0x20..=0x7e).contains(b)) {
            Ok(Self(bytes))
        } else {
            Err(Error::Field)
        }
    }
    /// `text` padded on the left with spaces, as a session ID is (2.2.1).
    pub fn left_padded(text: &str) -> Result<Self, Error> {
        let pad = N.checked_sub(text.len()).ok_or(Error::Field)?;
        let mut bytes = [b' '; N];
        bytes
            .get_mut(pad..)
            .ok_or(Error::Field)?
            .copy_from_slice(text.as_bytes());
        Self::new(bytes)
    }
    /// `text` padded on the right with spaces, as a username and password
    /// are (2.3.1).
    pub fn right_padded(text: &str) -> Result<Self, Error> {
        if text.len() > N {
            return Err(Error::Field);
        }
        let mut bytes = [b' '; N];
        bytes
            .get_mut(..text.len())
            .ok_or(Error::Field)?
            .copy_from_slice(text.as_bytes());
        Self::new(bytes)
    }
    /// The field's bytes, padding included.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
    /// The text without leading or trailing spaces.
    pub fn trimmed(&self) -> &str {
        // Every byte is printable ASCII, so this is valid UTF-8.
        std::str::from_utf8(&self.0)
            .unwrap_or_default()
            .trim_matches(' ')
    }
    /// Whether every byte is a space.
    pub fn is_blank(&self) -> bool {
        self.0.iter().all(|b| *b == b' ')
    }
    /// Whether two fields hold the same text, ignoring padding and ASCII
    /// case. Usernames and passwords compare this way (2.3.1).
    pub fn matches(&self, other: &Self) -> bool {
        self.trimmed().eq_ignore_ascii_case(other.trimmed())
    }
    /// Whether two fields hold the same text, ignoring padding only.
    /// Session IDs compare this way: the specification makes only
    /// usernames and passwords case-insensitive.
    pub fn same_text(&self, other: &Self) -> bool {
        self.trimmed() == other.trimmed()
    }
    fn read(b: &[u8]) -> Result<Self, Error> {
        Self::new(b.try_into().map_err(|_| Error::Length)?)
    }
}
impl<const N: usize> fmt::Debug for Alpha<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", std::str::from_utf8(&self.0).unwrap_or_default())
    }
}

/// Why a server refused a login (2.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// "A": the username and password do not match.
    NotAuthorized,
    /// "S": the requested session is invalid or not available.
    SessionNotAvailable,
}
impl RejectReason {
    /// The code byte on the wire.
    pub fn code(self) -> u8 {
        match self {
            RejectReason::NotAuthorized => b'A',
            RejectReason::SessionNotAvailable => b'S',
        }
    }
    /// The reason a code byte names.
    pub fn from_code(code: u8) -> Result<Self, Error> {
        match code {
            b'A' => Ok(RejectReason::NotAuthorized),
            b'S' => Ok(RejectReason::SessionNotAvailable),
            other => Err(Error::Reason(other)),
        }
    }
}

/// The fields of a Login Request Packet (2.3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Login {
    /// Username, padded on the right with spaces. Case-insensitive.
    pub username: Alpha<USERNAME_LENGTH>,
    /// Password, padded on the right with spaces. Case-insensitive.
    pub password: Alpha<PASSWORD_LENGTH>,
    /// The session to log into, or blank for the active session.
    pub session: Alpha<SESSION_LENGTH>,
    /// The next sequence number the client wants, or 0 for the most
    /// recently generated message.
    pub sequence: u64,
}

/// One SoupBinTCP packet. Numeric fields read leniently (left or right
/// padding, leading zeros, all blank as 0) and are written as the
/// specification shows them: digits padded on the left with spaces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    /// "+": human-readable text either side may send; ignored (2.1).
    Debug(Vec<u8>),
    /// "A": the server accepted a login (2.2.1).
    LoginAccepted {
        /// The session now logged into.
        session: Alpha<SESSION_LENGTH>,
        /// The sequence number of the next sequenced message to be sent.
        sequence: u64,
    },
    /// "J": the server refused a login and will close (2.2.2).
    LoginRejected(RejectReason),
    /// "S": one higher-level message with an implied sequence number (2.2.3).
    SequencedData(Vec<u8>),
    /// "H": the server has sent nothing for a second (2.2.4).
    ServerHeartbeat,
    /// "Z": the session has ended; no more messages will follow (2.2.5).
    EndOfSession,
    /// "L": the client's first packet on a connection (2.3.1).
    LoginRequest(Login),
    /// "U": one client message, not sequenced or recovered (2.3.2).
    UnsequencedData(Vec<u8>),
    /// "R": the client has sent nothing for a second (2.3.3).
    ClientHeartbeat,
    /// "O": the client asks the server to close (2.3.4).
    LogoutRequest,
}
impl Packet {
    /// The packet type byte.
    pub fn kind(&self) -> u8 {
        match self {
            Packet::Debug(_) => b'+',
            Packet::LoginAccepted { .. } => b'A',
            Packet::LoginRejected(_) => b'J',
            Packet::SequencedData(_) => b'S',
            Packet::ServerHeartbeat => b'H',
            Packet::EndOfSession => b'Z',
            Packet::LoginRequest(_) => b'L',
            Packet::UnsequencedData(_) => b'U',
            Packet::ClientHeartbeat => b'R',
            Packet::LogoutRequest => b'O',
        }
    }
    /// Payload bytes after the type byte.
    pub fn payload_len(&self) -> usize {
        match self {
            Packet::Debug(b) | Packet::SequencedData(b) | Packet::UnsequencedData(b) => b.len(),
            Packet::LoginAccepted { .. } => SESSION_LENGTH + SEQUENCE_LENGTH,
            Packet::LoginRejected(_) => 1,
            Packet::LoginRequest(_) => {
                USERNAME_LENGTH + PASSWORD_LENGTH + SESSION_LENGTH + SEQUENCE_LENGTH
            }
            Packet::ServerHeartbeat
            | Packet::EndOfSession
            | Packet::ClientHeartbeat
            | Packet::LogoutRequest => 0,
        }
    }
    /// Reads one type byte and payload, without the length prefix.
    pub fn parse_body(body: &[u8]) -> Result<Self, Error> {
        let (&kind, p) = body.split_first().ok_or(Error::Length)?;
        let fixed = |n: usize| {
            if p.len() == n {
                Ok(())
            } else {
                Err(Error::Length)
            }
        };
        Ok(match kind {
            b'+' => Packet::Debug(p.to_vec()),
            b'S' => Packet::SequencedData(p.to_vec()),
            b'U' => Packet::UnsequencedData(p.to_vec()),
            b'A' => {
                fixed(SESSION_LENGTH + SEQUENCE_LENGTH)?;
                let (session, sequence) = p.split_at(SESSION_LENGTH);
                Packet::LoginAccepted {
                    session: Alpha::read(session)?,
                    sequence: read_number(sequence)?,
                }
            }
            b'J' => {
                fixed(1)?;
                Packet::LoginRejected(RejectReason::from_code(p.first().copied().unwrap_or(0))?)
            }
            b'L' => {
                fixed(USERNAME_LENGTH + PASSWORD_LENGTH + SESSION_LENGTH + SEQUENCE_LENGTH)?;
                let (username, rest) = p.split_at(USERNAME_LENGTH);
                let (password, rest) = rest.split_at(PASSWORD_LENGTH);
                let (session, sequence) = rest.split_at(SESSION_LENGTH);
                Packet::LoginRequest(Login {
                    username: Alpha::read(username)?,
                    password: Alpha::read(password)?,
                    session: Alpha::read(session)?,
                    sequence: read_number(sequence)?,
                })
            }
            b'H' | b'Z' | b'R' | b'O' => {
                fixed(0)?;
                match kind {
                    b'H' => Packet::ServerHeartbeat,
                    b'Z' => Packet::EndOfSession,
                    b'R' => Packet::ClientHeartbeat,
                    _ => Packet::LogoutRequest,
                }
            }
            other => return Err(Error::Type(other)),
        })
    }
}

/// Reads a numeric ASCII field: optional spaces, digits, optional spaces.
/// An all-blank field reads as 0.
fn read_number(b: &[u8]) -> Result<u64, Error> {
    let digits = b
        .iter()
        .position(|c| *c != b' ')
        .map_or(&[][..], |start| b.get(start..).unwrap_or_default());
    let end = digits
        .iter()
        .position(|c| *c == b' ')
        .unwrap_or(digits.len());
    let (digits, pad) = digits.split_at(end);
    if pad.iter().any(|c| *c != b' ') {
        return Err(Error::Number);
    }
    digits.iter().try_fold(0u64, |n, c| {
        if !c.is_ascii_digit() {
            return Err(Error::Number);
        }
        n.checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(c - b'0')))
            .ok_or(Error::Number)
    })
}
fn write_number(n: u64, out: &mut Vec<u8>) {
    // u64::MAX has 20 digits, so this always fills the field exactly.
    out.extend_from_slice(format!("{n:>SEQUENCE_LENGTH$}").as_bytes());
}

impl Wire for Packet {
    type ParseError = Error;
    type WriteError = Error;
    /// Reads one whole packet, length prefix included.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        let (prefix, body) = b.split_at_checked(LENGTH_PREFIX).ok_or(Error::Length)?;
        let length = u16::from_be_bytes([prefix[0], prefix[1]]);
        if usize::from(length) != body.len() {
            return Err(Error::Length);
        }
        Packet::parse_body(body)
    }
    /// Writes one whole packet. Refuses a payload over [`MAX_PAYLOAD`].
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let payload = self.payload_len();
        if payload > MAX_PAYLOAD {
            return Err(Error::TooLong);
        }
        let length = u16::try_from(payload + 1).map_err(|_| Error::TooLong)?;
        out.reserve(LENGTH_PREFIX + 1 + payload);
        out.extend_from_slice(&length.to_be_bytes());
        out.push(self.kind());
        match self {
            Packet::Debug(b) | Packet::SequencedData(b) | Packet::UnsequencedData(b) => {
                out.extend_from_slice(b)
            }
            Packet::LoginAccepted { session, sequence } => {
                out.extend_from_slice(session.as_bytes());
                write_number(*sequence, out);
            }
            Packet::LoginRejected(reason) => out.push(reason.code()),
            Packet::LoginRequest(login) => {
                out.extend_from_slice(login.username.as_bytes());
                out.extend_from_slice(login.password.as_bytes());
                out.extend_from_slice(login.session.as_bytes());
                write_number(login.sequence, out);
            }
            Packet::ServerHeartbeat
            | Packet::EndOfSession
            | Packet::ClientHeartbeat
            | Packet::LogoutRequest => {}
        }
        Ok(())
    }
}

/// Reads packets from a byte stream without holding input.
///
/// Each item is one length-prefixed packet, parsed: `Err` for a packet
/// that frames but does not parse (an unknown type, a wrong fixed length,
/// a bad field), so the session can decide what to do. A length prefix
/// over the limit ends the stream with [`Error::TooLong`], read from the
/// prefix alone. A zero length prefix is an item, `Err(Error::Length)`.
///
/// ```
/// use fictionet::stdlib::codec::{finish, pump, Stream};
/// use fictionet::stdlib::soupbintcp::{Packet, Packets};
///
/// let mut stream = Stream::new(Packets::default());
/// let mut packets = Vec::new();
/// // A server heartbeat, then sequenced data "hi", split across reads.
/// pump(&mut stream, &[0, 1, b'H', 0, 3], |p| packets.push(p))?;
/// pump(&mut stream, &[b'S', b'h', b'i'], |p| packets.push(p))?;
/// finish(&mut stream, |p| packets.push(p))?;
/// assert_eq!(packets, [Ok(Packet::ServerHeartbeat), Ok(Packet::SequencedData(b"hi".to_vec()))]);
/// # Ok::<(), fictionet::stdlib::codec::Fail<fictionet::stdlib::soupbintcp::Error>>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packets {
    limit: usize,
}
impl Packets {
    /// A framer that accepts payloads up to `limit` bytes, at most
    /// [`MAX_PAYLOAD`].
    pub fn with_limit(limit: usize) -> Self {
        Self {
            limit: limit.min(MAX_PAYLOAD),
        }
    }
    /// The payload limit.
    pub fn limit(&self) -> usize {
        self.limit
    }
}
impl Default for Packets {
    /// Accepts every payload the length field can describe.
    fn default() -> Self {
        Self::with_limit(MAX_PAYLOAD)
    }
}
impl Decode for Packets {
    type Item = Result<Packet, Error>;
    type Error = Error;
    const NAME: &'static str = "SoupBinTCP";
    fn capacity(&self) -> usize {
        LENGTH_PREFIX + 1 + self.limit
    }
    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Self::Item>, Error> {
        let Some((prefix, rest)) = input.split_at_checked(LENGTH_PREFIX) else {
            return Ok(Step::Need);
        };
        let length = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
        if length > self.limit + 1 {
            return Err(Error::TooLong);
        }
        let Some(body) = rest.get(..length) else {
            return Ok(Step::Need);
        };
        Ok(Step::Item(Packet::parse_body(body), LENGTH_PREFIX + length))
    }
}

/// The timers a session runs on. [`Timers::default`] is the
/// specification's: heartbeats after one second, an idle timeout of 15
/// seconds (1.3), and 30 seconds to log in (2.3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timers {
    /// Sending silence after which a heartbeat goes out.
    pub heartbeat_ms: u64,
    /// Receiving silence, once logged in, after which the session closes.
    pub idle_timeout_ms: u64,
    /// Time from creation or [`Client::start`] to a completed login.
    pub login_timeout_ms: u64,
}
impl Default for Timers {
    fn default() -> Self {
        Self {
            heartbeat_ms: HEARTBEAT_INTERVAL_MS,
            idle_timeout_ms: IDLE_TIMEOUT_MS,
            login_timeout_ms: LOGIN_TIMEOUT_MS,
        }
    }
}
impl Timers {
    fn validate(&self) -> Result<(), Error> {
        let ok = |ms: u64| (1..=MAX_TIMER_MS).contains(&ms);
        if ok(self.heartbeat_ms) && ok(self.idle_timeout_ms) && ok(self.login_timeout_ms) {
            Ok(())
        } else {
            Err(Error::Config)
        }
    }
}

/// Why a session ended. The caller closes the connection after writing
/// any packets that came before this event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// The client sent a Logout Request (2.3.4).
    Logout,
    /// The server sent End of Session (2.2.5).
    EndOfSession,
    /// The server refused the login (2.2.2).
    Rejected,
    /// Login did not complete within [`Timers::login_timeout_ms`].
    LoginTimeout,
    /// Nothing arrived within [`Timers::idle_timeout_ms`] (1.3).
    IdleTimeout,
    /// The peer sent a packet that does not parse, or one its role or the
    /// session's state does not allow.
    Protocol,
}

/// What a session reports to its caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Client: the server accepted the login.
    LoggedIn {
        /// The session logged into. Persist it to log in again.
        session: Alpha<SESSION_LENGTH>,
        /// The sequence number of the next sequenced message.
        sequence: u64,
    },
    /// Client: the server refused the login. `Disconnected` follows.
    Rejected(RejectReason),
    /// Client: the packet passed in is sequenced message `sequence`.
    Sequenced {
        /// The message's implied sequence number.
        sequence: u64,
    },
    /// Server: a client asks to log in. Answer with [`Server::accept`] or
    /// [`Server::reject`].
    LoginRequested(Login),
    /// Server: the packet passed in carries a client message.
    Unsequenced,
    /// The session is over; close the connection.
    Disconnected(CloseReason),
}

/// A session's output, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// A packet to write to the connection, ready for [`Wire::write`].
    Send(Packet),
    /// A notification for the caller.
    Event(Event),
}

/// The common part of a session: state, the time of the last packet each
/// way, and the monotonic time guard.
#[derive(Clone, Copy, Debug)]
struct Clock {
    timers: Timers,
    now: u64,
    since: u64,
    received: u64,
    sent: u64,
}
impl Clock {
    fn new(timers: Timers, now: u64) -> Result<Self, Error> {
        timers.validate()?;
        Ok(Self {
            timers,
            now,
            since: now,
            received: now,
            sent: now,
        })
    }
    fn advance(&mut self, now: u64) -> Result<(), Error> {
        if now < self.now {
            return Err(Error::Time);
        }
        self.now = now;
        Ok(())
    }
    fn heartbeat_due(&self) -> bool {
        self.now.saturating_sub(self.sent) >= self.timers.heartbeat_ms
    }
    fn idle(&self) -> bool {
        self.now.saturating_sub(self.received) >= self.timers.idle_timeout_ms
    }
    fn login_expired(&self) -> bool {
        self.now.saturating_sub(self.since) >= self.timers.login_timeout_ms
    }
}

/// Where a [`Client`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientPhase {
    /// Created; [`Client::start`] sends the login request.
    Connected,
    /// Login request sent; waiting for the answer.
    LoginSent,
    /// Logged in; sequenced data flows.
    LoggedIn,
    /// The session is over; close the connection.
    Closed,
}

/// The client side of one SoupBinTCP connection, without I/O.
///
/// Pass every packet read from the connection to [`receive`](Self::receive)
/// (or each [`Packets`] item to [`receive_frame`](Self::receive_frame)),
/// call [`tick`](Self::tick) at least every few hundred milliseconds, and
/// write every [`Action::Send`] packet in order. Packets returned directly
/// ([`send`](Self::send), [`debug`](Self::debug)) must be written too:
/// the heartbeat timer counts them as sent. An `Err` leaves the session
/// unchanged.
///
/// After a broken connection, persist [`session`](Self::session) and
/// [`next_sequence`](Self::next_sequence) and log in again with a new
/// client (1.2).
#[derive(Clone, Copy, Debug)]
pub struct Client {
    login: Login,
    phase: ClientPhase,
    clock: Clock,
    session: Alpha<SESSION_LENGTH>,
    next: u64,
}
impl Client {
    /// A client that will log in with `login`. The login timer starts at
    /// [`start`](Self::start).
    pub fn new(login: Login, timers: Timers, now_ms: u64) -> Result<Self, Error> {
        Ok(Self {
            login,
            phase: ClientPhase::Connected,
            clock: Clock::new(timers, now_ms)?,
            session: login.session,
            next: login.sequence,
        })
    }
    /// Where the session is.
    pub fn phase(&self) -> ClientPhase {
        self.phase
    }
    /// The session requested, then the one the server accepted.
    pub fn session(&self) -> Alpha<SESSION_LENGTH> {
        self.session
    }
    /// The sequence number of the next sequenced message expected.
    pub fn next_sequence(&self) -> u64 {
        self.next
    }
    /// Sends the login request (2.3.1).
    pub fn start(&mut self, now_ms: u64) -> Result<Vec<Action>, Error> {
        let mut s = *self;
        s.clock.advance(now_ms)?;
        if s.phase != ClientPhase::Connected {
            return Err(Error::State);
        }
        s.phase = ClientPhase::LoginSent;
        s.clock.since = now_ms;
        s.clock.sent = now_ms;
        *self = s;
        Ok(vec![Action::Send(Packet::LoginRequest(self.login))])
    }
    /// Handles one packet from the server. A packet a server may not send,
    /// or one out of turn, closes the session with
    /// [`CloseReason::Protocol`]. Refuses a closed session.
    pub fn receive(&mut self, packet: &Packet, now_ms: u64) -> Result<Vec<Action>, Error> {
        let mut s = *self;
        s.clock.advance(now_ms)?;
        let actions = s.receive_inner(packet)?;
        *self = s;
        Ok(actions)
    }
    /// [`receive`](Self::receive) for a [`Packets`] item. A packet that did
    /// not parse closes the session with [`CloseReason::Protocol`].
    pub fn receive_frame(
        &mut self,
        frame: &Result<Packet, Error>,
        now_ms: u64,
    ) -> Result<Vec<Action>, Error> {
        match frame {
            Ok(packet) => self.receive(packet, now_ms),
            Err(_) => {
                let mut s = *self;
                s.clock.advance(now_ms)?;
                if s.phase == ClientPhase::Closed {
                    return Err(Error::State);
                }
                let actions = s.close(CloseReason::Protocol);
                *self = s;
                Ok(actions)
            }
        }
    }
    fn receive_inner(&mut self, packet: &Packet) -> Result<Vec<Action>, Error> {
        if self.phase == ClientPhase::Closed {
            return Err(Error::State);
        }
        self.clock.received = self.clock.now;
        match (self.phase, packet) {
            (_, Packet::Debug(_)) => Ok(Vec::new()),
            (ClientPhase::LoginSent, Packet::LoginAccepted { session, sequence }) => {
                // Sequence numbers start at 1 in every session (1.2).
                if *sequence == 0
                    || (!self.login.session.is_blank() && !self.login.session.same_text(session))
                {
                    return Ok(self.close(CloseReason::Protocol));
                }
                self.phase = ClientPhase::LoggedIn;
                self.session = *session;
                self.next = *sequence;
                // Heartbeats are owed from login on (1.3).
                self.clock.sent = self.clock.now;
                Ok(vec![Action::Event(Event::LoggedIn {
                    session: *session,
                    sequence: *sequence,
                })])
            }
            (ClientPhase::LoginSent, Packet::LoginRejected(reason)) => {
                let mut actions = vec![Action::Event(Event::Rejected(*reason))];
                actions.extend(self.close(CloseReason::Rejected));
                Ok(actions)
            }
            (ClientPhase::LoggedIn, Packet::SequencedData(_)) => {
                let sequence = self.next;
                self.next = sequence.checked_add(1).ok_or(Error::Sequence)?;
                Ok(vec![Action::Event(Event::Sequenced { sequence })])
            }
            (ClientPhase::LoggedIn, Packet::ServerHeartbeat) => Ok(Vec::new()),
            (ClientPhase::LoggedIn, Packet::EndOfSession) => {
                Ok(self.close(CloseReason::EndOfSession))
            }
            _ => Ok(self.close(CloseReason::Protocol)),
        }
    }
    /// An Unsequenced Data packet carrying `message` (2.3.2). Only once
    /// logged in. Refuses a message over [`MAX_PAYLOAD`].
    pub fn send(&mut self, message: &[u8], now_ms: u64) -> Result<Packet, Error> {
        self.outbound(now_ms, message, |m| Packet::UnsequencedData(m.to_vec()))
    }
    /// A Debug packet carrying `text` (2.1), in any state but closed.
    pub fn debug(&mut self, text: &[u8], now_ms: u64) -> Result<Packet, Error> {
        if text.len() > MAX_PAYLOAD {
            return Err(Error::TooLong);
        }
        if self.phase == ClientPhase::Closed {
            return Err(Error::State);
        }
        self.clock.advance(now_ms)?;
        self.clock.sent = now_ms;
        Ok(Packet::Debug(text.to_vec()))
    }
    fn outbound(
        &mut self,
        now_ms: u64,
        message: &[u8],
        make: impl FnOnce(&[u8]) -> Packet,
    ) -> Result<Packet, Error> {
        if message.len() > MAX_PAYLOAD {
            return Err(Error::TooLong);
        }
        if self.phase != ClientPhase::LoggedIn {
            return Err(Error::State);
        }
        self.clock.advance(now_ms)?;
        self.clock.sent = now_ms;
        Ok(make(message))
    }
    /// Sends a Logout Request and closes (2.3.4). Only once logged in.
    pub fn logout(&mut self, now_ms: u64) -> Result<Vec<Action>, Error> {
        if self.phase != ClientPhase::LoggedIn {
            return Err(Error::State);
        }
        self.clock.advance(now_ms)?;
        self.clock.sent = now_ms;
        let mut actions = vec![Action::Send(Packet::LogoutRequest)];
        actions.extend(self.close(CloseReason::Logout));
        Ok(actions)
    }
    /// Runs the timers: the login timeout, the idle timeout, and a client
    /// heartbeat after [`Timers::heartbeat_ms`] of sending nothing (1.3).
    /// A closed session returns nothing.
    pub fn tick(&mut self, now_ms: u64) -> Result<Vec<Action>, Error> {
        self.clock.advance(now_ms)?;
        Ok(match self.phase {
            ClientPhase::Connected | ClientPhase::Closed => Vec::new(),
            ClientPhase::LoginSent if self.clock.login_expired() => {
                self.close(CloseReason::LoginTimeout)
            }
            ClientPhase::LoginSent => Vec::new(),
            ClientPhase::LoggedIn if self.clock.idle() => self.close(CloseReason::IdleTimeout),
            ClientPhase::LoggedIn if self.clock.heartbeat_due() => {
                self.clock.sent = now_ms;
                vec![Action::Send(Packet::ClientHeartbeat)]
            }
            ClientPhase::LoggedIn => Vec::new(),
        })
    }
    fn close(&mut self, reason: CloseReason) -> Vec<Action> {
        self.phase = ClientPhase::Closed;
        vec![Action::Event(Event::Disconnected(reason))]
    }
}

/// Where a [`Server`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerPhase {
    /// Waiting for the client's login request.
    AwaitingLogin,
    /// A login request arrived; the caller must accept or reject it.
    LoginPending,
    /// Logged in; sequenced data flows.
    LoggedIn,
    /// The session is over; close the connection.
    Closed,
}

/// The server side of one SoupBinTCP connection, without I/O.
///
/// The caller owns the message store. On [`Event::LoginRequested`] it
/// checks the credentials, picks the session and the first sequence
/// number to send, and calls [`accept`](Self::accept). It then sends
/// every stored message from that number on with [`send`](Self::send),
/// which numbers them. Driving rules are those of [`Client`].
#[derive(Clone, Copy, Debug)]
pub struct Server {
    phase: ServerPhase,
    clock: Clock,
    session: Alpha<SESSION_LENGTH>,
    next: u64,
}
impl Server {
    /// A server for a connection accepted at `now_ms`. The login timer
    /// starts now.
    pub fn new(timers: Timers, now_ms: u64) -> Result<Self, Error> {
        Ok(Self {
            phase: ServerPhase::AwaitingLogin,
            clock: Clock::new(timers, now_ms)?,
            session: Alpha::blank(),
            next: 0,
        })
    }
    /// Where the session is.
    pub fn phase(&self) -> ServerPhase {
        self.phase
    }
    /// The accepted session; blank before login.
    pub fn session(&self) -> Alpha<SESSION_LENGTH> {
        self.session
    }
    /// The sequence number the next [`send`](Self::send) carries; 0 before
    /// login.
    pub fn next_sequence(&self) -> u64 {
        self.next
    }
    /// Handles one packet from the client. A packet a client may not send,
    /// or one out of turn, closes the session with
    /// [`CloseReason::Protocol`]. Refuses a closed session.
    pub fn receive(&mut self, packet: &Packet, now_ms: u64) -> Result<Vec<Action>, Error> {
        let mut s = *self;
        s.clock.advance(now_ms)?;
        if s.phase == ServerPhase::Closed {
            return Err(Error::State);
        }
        s.clock.received = now_ms;
        let actions = match (s.phase, packet) {
            (_, Packet::Debug(_)) => Vec::new(),
            (ServerPhase::AwaitingLogin, Packet::LoginRequest(login)) => {
                s.phase = ServerPhase::LoginPending;
                vec![Action::Event(Event::LoginRequested(*login))]
            }
            (ServerPhase::LoggedIn, Packet::UnsequencedData(_)) => {
                vec![Action::Event(Event::Unsequenced)]
            }
            (ServerPhase::LoggedIn, Packet::ClientHeartbeat) => Vec::new(),
            (ServerPhase::LoggedIn, Packet::LogoutRequest) => s.close(CloseReason::Logout),
            _ => s.close(CloseReason::Protocol),
        };
        *self = s;
        Ok(actions)
    }
    /// [`receive`](Self::receive) for a [`Packets`] item. A packet that did
    /// not parse closes the session with [`CloseReason::Protocol`].
    pub fn receive_frame(
        &mut self,
        frame: &Result<Packet, Error>,
        now_ms: u64,
    ) -> Result<Vec<Action>, Error> {
        match frame {
            Ok(packet) => self.receive(packet, now_ms),
            Err(_) => {
                let mut s = *self;
                s.clock.advance(now_ms)?;
                if s.phase == ServerPhase::Closed {
                    return Err(Error::State);
                }
                let actions = s.close(CloseReason::Protocol);
                *self = s;
                Ok(actions)
            }
        }
    }
    /// Accepts the pending login into `session`, with `sequence` the
    /// number of the next sequenced message to be sent (2.2.1). Sequence
    /// numbers start at 1 in each session (1.2); `sequence` must be at
    /// least 1.
    pub fn accept(
        &mut self,
        session: Alpha<SESSION_LENGTH>,
        sequence: u64,
        now_ms: u64,
    ) -> Result<Vec<Action>, Error> {
        if self.phase != ServerPhase::LoginPending {
            return Err(Error::State);
        }
        if sequence == 0 {
            return Err(Error::Sequence);
        }
        self.clock.advance(now_ms)?;
        self.phase = ServerPhase::LoggedIn;
        self.session = session;
        self.next = sequence;
        self.clock.sent = now_ms;
        // The idle timer starts at login: clients heartbeat once logged in.
        self.clock.received = now_ms;
        Ok(vec![Action::Send(Packet::LoginAccepted {
            session,
            sequence,
        })])
    }
    /// Refuses the pending login and closes (2.2.2).
    pub fn reject(&mut self, reason: RejectReason, now_ms: u64) -> Result<Vec<Action>, Error> {
        if self.phase != ServerPhase::LoginPending {
            return Err(Error::State);
        }
        self.clock.advance(now_ms)?;
        self.clock.sent = now_ms;
        let mut actions = vec![Action::Send(Packet::LoginRejected(reason))];
        actions.extend(self.close(CloseReason::Rejected));
        Ok(actions)
    }
    /// A Sequenced Data packet carrying message
    /// [`next_sequence`](Self::next_sequence) (2.2.3). Only once logged in.
    /// Refuses a message over [`MAX_PAYLOAD`].
    pub fn send(&mut self, message: &[u8], now_ms: u64) -> Result<Packet, Error> {
        if message.len() > MAX_PAYLOAD {
            return Err(Error::TooLong);
        }
        if self.phase != ServerPhase::LoggedIn {
            return Err(Error::State);
        }
        let next = self.next.checked_add(1).ok_or(Error::Sequence)?;
        self.clock.advance(now_ms)?;
        self.next = next;
        self.clock.sent = now_ms;
        Ok(Packet::SequencedData(message.to_vec()))
    }
    /// A Debug packet carrying `text` (2.1), in any state but closed.
    pub fn debug(&mut self, text: &[u8], now_ms: u64) -> Result<Packet, Error> {
        if text.len() > MAX_PAYLOAD {
            return Err(Error::TooLong);
        }
        if self.phase == ServerPhase::Closed {
            return Err(Error::State);
        }
        self.clock.advance(now_ms)?;
        self.clock.sent = now_ms;
        Ok(Packet::Debug(text.to_vec()))
    }
    /// Sends End of Session and closes (2.2.5). Only once logged in.
    pub fn end_session(&mut self, now_ms: u64) -> Result<Vec<Action>, Error> {
        if self.phase != ServerPhase::LoggedIn {
            return Err(Error::State);
        }
        self.clock.advance(now_ms)?;
        self.clock.sent = now_ms;
        let mut actions = vec![Action::Send(Packet::EndOfSession)];
        actions.extend(self.close(CloseReason::EndOfSession));
        Ok(actions)
    }
    /// Runs the timers: the login timeout, the idle timeout, and a server
    /// heartbeat after [`Timers::heartbeat_ms`] of sending nothing (1.3).
    /// A closed session returns nothing.
    pub fn tick(&mut self, now_ms: u64) -> Result<Vec<Action>, Error> {
        self.clock.advance(now_ms)?;
        Ok(match self.phase {
            ServerPhase::Closed => Vec::new(),
            ServerPhase::AwaitingLogin | ServerPhase::LoginPending => {
                if self.clock.login_expired() {
                    self.close(CloseReason::LoginTimeout)
                } else {
                    Vec::new()
                }
            }
            ServerPhase::LoggedIn if self.clock.idle() => self.close(CloseReason::IdleTimeout),
            ServerPhase::LoggedIn if self.clock.heartbeat_due() => {
                self.clock.sent = now_ms;
                vec![Action::Send(Packet::ServerHeartbeat)]
            }
            ServerPhase::LoggedIn => Vec::new(),
        })
    }
    fn close(&mut self, reason: CloseReason) -> Vec<Action> {
        self.phase = ServerPhase::Closed;
        vec![Action::Event(Event::Disconnected(reason))]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{
        Fail, Lcg, Stream,
        contract::{check_decode, check_decode_with_alloc_limit, check_wire, check_wire_value},
        test_support::{decode_all, mutate},
    };

    fn alpha<const N: usize>(text: &[u8; N]) -> Alpha<N> {
        Alpha::new(*text).unwrap()
    }
    fn login() -> Login {
        Login {
            username: Alpha::right_padded("ALICE").unwrap(),
            password: Alpha::right_padded("SECRET").unwrap(),
            session: Alpha::blank(),
            sequence: 1,
        }
    }
    fn session() -> Alpha<SESSION_LENGTH> {
        Alpha::left_padded("ABCDEFGHIJ").unwrap()
    }
    fn every_packet() -> Vec<Packet> {
        vec![
            Packet::Debug(b"host fictionet".to_vec()),
            Packet::LoginAccepted {
                session: session(),
                sequence: 42,
            },
            Packet::LoginRejected(RejectReason::NotAuthorized),
            Packet::LoginRejected(RejectReason::SessionNotAvailable),
            Packet::SequencedData(vec![0, 1, 2, b'\n', 0xff]),
            Packet::SequencedData(Vec::new()),
            Packet::ServerHeartbeat,
            Packet::EndOfSession,
            Packet::LoginRequest(login()),
            Packet::UnsequencedData(b"O order".to_vec()),
            Packet::ClientHeartbeat,
            Packet::LogoutRequest,
        ]
    }
    fn stream_of(packets: &[Packet]) -> Vec<u8> {
        let mut out = Vec::new();
        for p in packets {
            p.write(&mut out).unwrap();
        }
        out
    }

    // Exact layouts from SoupBinTCP 3.00, sections 2.1 through 2.3.4.
    #[test]
    fn exact_bytes_of_fixed_packets() {
        assert_eq!(Packet::ServerHeartbeat.to_bytes().unwrap(), [0, 1, b'H']);
        assert_eq!(Packet::EndOfSession.to_bytes().unwrap(), [0, 1, b'Z']);
        assert_eq!(Packet::ClientHeartbeat.to_bytes().unwrap(), [0, 1, b'R']);
        assert_eq!(Packet::LogoutRequest.to_bytes().unwrap(), [0, 1, b'O']);
        assert_eq!(
            Packet::LoginRejected(RejectReason::NotAuthorized)
                .to_bytes()
                .unwrap(),
            [0, 2, b'J', b'A']
        );
        assert_eq!(
            Packet::LoginRejected(RejectReason::SessionNotAvailable)
                .to_bytes()
                .unwrap(),
            [0, 2, b'J', b'S']
        );
        assert_eq!(
            Packet::Debug(b"hi".to_vec()).to_bytes().unwrap(),
            [0, 3, b'+', b'h', b'i']
        );
        assert_eq!(
            Packet::SequencedData(b"xyz".to_vec()).to_bytes().unwrap(),
            [0, 4, b'S', b'x', b'y', b'z']
        );
        assert_eq!(
            Packet::UnsequencedData(b"q".to_vec()).to_bytes().unwrap(),
            [0, 2, b'U', b'q']
        );
    }

    #[test]
    fn exact_bytes_of_login_packets() {
        // 2.2.1: length 31; session at offset 3, sequence at 13, both left
        // padded with spaces.
        let accepted = Packet::LoginAccepted {
            session: Alpha::left_padded("S1").unwrap(),
            sequence: 1,
        };
        let mut expected = vec![0, 31, b'A'];
        expected.extend_from_slice(b"        S1");
        expected.extend_from_slice(b"                   1");
        assert_eq!(accepted.to_bytes().unwrap(), expected);
        assert_eq!(Packet::parse(&expected).unwrap(), accepted);

        // 2.3.1: length 47; username at 3, password at 9, session at 19,
        // sequence at 29. Username and password padded on the right.
        let mut expected = vec![0, 47, b'L'];
        expected.extend_from_slice(b"ALICE ");
        expected.extend_from_slice(b"SECRET    ");
        expected.extend_from_slice(b"          ");
        expected.extend_from_slice(b"                   1");
        assert_eq!(expected.len(), 49);
        assert_eq!(Packet::LoginRequest(login()).to_bytes().unwrap(), expected);
        assert_eq!(
            Packet::parse(&expected).unwrap(),
            Packet::LoginRequest(login())
        );
    }

    #[test]
    fn numeric_fields_read_leniently_and_write_canonically() {
        let mut bytes = vec![0, 31, b'A'];
        bytes.extend_from_slice(b"        S1");
        for field in [
            b"00000000000000000007",
            b"7                   ",
            b"     7              ",
        ] {
            let mut b = bytes.clone();
            b.extend_from_slice(field);
            let p = Packet::parse(&b).unwrap();
            assert_eq!(
                p,
                Packet::LoginAccepted {
                    session: Alpha::left_padded("S1").unwrap(),
                    sequence: 7
                }
            );
            check_wire::<Packet>(&b);
        }
        let mut blank = bytes.clone();
        blank.extend_from_slice(&[b' '; 20]);
        assert!(matches!(
            Packet::parse(&blank),
            Ok(Packet::LoginAccepted { sequence: 0, .. })
        ));
        for bad in [
            &b"                 1 2"[..],
            b"                 -12",
            b"99999999999999999999",
        ] {
            let mut b = bytes.clone();
            b.extend_from_slice(bad);
            assert_eq!(Packet::parse(&b), Err(Error::Number));
        }
        let max = Packet::LoginAccepted {
            session: session(),
            sequence: u64::MAX,
        };
        check_wire_value(&max);
    }

    #[test]
    fn refuses_bad_packets() {
        assert_eq!(Packet::parse(&[]), Err(Error::Length));
        assert_eq!(Packet::parse(&[0]), Err(Error::Length));
        assert_eq!(Packet::parse(&[0, 0]), Err(Error::Length));
        assert_eq!(Packet::parse(&[0, 2, b'H']), Err(Error::Length));
        assert_eq!(Packet::parse(&[0, 2, b'H', 0]), Err(Error::Length));
        assert_eq!(Packet::parse(&[0, 1, b'H', 0]), Err(Error::Length));
        assert_eq!(Packet::parse(&[0, 1, b'Q']), Err(Error::Type(b'Q')));
        assert_eq!(Packet::parse(&[0, 2, b'J', b'X']), Err(Error::Reason(b'X')));
        let mut bad = Packet::LoginRequest(login()).to_bytes().unwrap();
        bad[3] = 0x07;
        assert_eq!(Packet::parse(&bad), Err(Error::Field));
        let long = Packet::SequencedData(vec![0; MAX_PAYLOAD + 1]);
        check_wire_value(&long);
        assert_eq!(long.to_bytes(), Err(Error::TooLong));
        let full = Packet::SequencedData(vec![7; MAX_PAYLOAD]);
        let bytes = full.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_PACKET);
        assert_eq!(&bytes[..2], &[0xff, 0xff]);
        check_wire_value(&full);
    }

    #[test]
    fn alpha_fields() {
        assert_eq!(Alpha::<4>::left_padded("ab").unwrap().as_bytes(), b"  ab");
        assert_eq!(Alpha::<4>::right_padded("ab").unwrap().as_bytes(), b"ab  ");
        assert_eq!(Alpha::<2>::left_padded("abc"), Err(Error::Field));
        assert_eq!(Alpha::<2>::right_padded("abc"), Err(Error::Field));
        assert_eq!(Alpha::<2>::right_padded("\u{e9}"), Err(Error::Field));
        assert!(Alpha::<3>::blank().is_blank());
        assert_eq!(alpha(b" x ").trimmed(), "x");
        assert!(alpha(b"Ab  ").matches(&alpha(b"  aB")));
        assert!(!alpha(b"Ab  ").matches(&alpha(b"  aC")));
    }

    #[test]
    fn every_packet_round_trips() {
        for p in every_packet() {
            check_wire_value(&p);
            let bytes = p.to_bytes().unwrap();
            assert_eq!(Packet::parse(&bytes).unwrap(), p);
            assert_eq!(bytes.len(), LENGTH_PREFIX + 1 + p.payload_len());
            check_wire::<Packet>(&bytes);
        }
    }

    #[test]
    fn frames_follow_the_contract() {
        let bytes = stream_of(&every_packet());
        check_decode(Packets::default, &bytes);
        check_decode_with_alloc_limit(|| Packets::with_limit(64), &bytes, 2 * (64 + 3));
        let (items, failure) = decode_all(Packets::default, &bytes);
        assert!(failure.is_none());
        assert_eq!(
            items,
            every_packet().into_iter().map(Ok).collect::<Vec<_>>()
        );
    }

    #[test]
    fn frames_pass_unparsed_packets_as_items() {
        let mut bytes = vec![0, 0, 0, 1, b'Q', 0, 2, b'H', 0];
        Packet::ServerHeartbeat.write(&mut bytes).unwrap();
        check_decode(Packets::default, &bytes);
        let (items, failure) = decode_all(Packets::default, &bytes);
        assert!(failure.is_none());
        assert_eq!(
            items,
            [
                Err(Error::Length),
                Err(Error::Type(b'Q')),
                Err(Error::Length),
                Ok(Packet::ServerHeartbeat)
            ]
        );
    }

    #[test]
    fn frames_refuse_over_limit_from_the_prefix() {
        let mut s = Stream::new(Packets::with_limit(4));
        assert_eq!(s.push(&[0, 6]), 2);
        assert_eq!(s.next(), Some(Err(Fail::Protocol(Error::TooLong))));
        let mut s = Stream::new(Packets::with_limit(4));
        assert_eq!(s.push(&[0, 5, b'S', 1, 2, 3, 4]), 7);
        assert_eq!(
            s.next(),
            Some(Ok(Ok(Packet::SequencedData(vec![1, 2, 3, 4]))))
        );
        let (_, failure) = decode_all(Packets::default, &[0, 3, b'S', 1]);
        assert_eq!(failure, Some(Fail::Truncated { unread: 4 }));
    }

    #[test]
    fn mutated_streams_keep_the_contract() {
        let base = stream_of(&every_packet());
        let mut rng = Lcg::new(0x500b);
        for _ in 0..300 {
            let mut bytes = base.clone();
            for _ in 0..=rng.below(4) {
                mutate(&mut rng, &mut bytes);
            }
            check_wire::<Packet>(&bytes);
            check_decode_with_alloc_limit(|| Packets::with_limit(256), &bytes, 2 * 259);
            let (items, _) = decode_all(Packets::default, &bytes);
            for item in items.into_iter().flatten() {
                check_wire_value(&item);
            }
        }
    }

    fn sends(actions: &[Action]) -> Vec<Packet> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Send(p) => {
                    check_wire_value(p);
                    Some(p.clone())
                }
                Action::Event(_) => None,
            })
            .collect()
    }
    fn pair() -> (Client, Server) {
        let mut client = Client::new(login(), Timers::default(), 0).unwrap();
        let mut server = Server::new(Timers::default(), 0).unwrap();
        let request = sends(&client.start(0).unwrap());
        assert_eq!(
            server.receive(&request[0], 0).unwrap(),
            [Action::Event(Event::LoginRequested(login()))]
        );
        assert_eq!(server.phase(), ServerPhase::LoginPending);
        let accepted = sends(&server.accept(session(), 5, 0).unwrap());
        assert_eq!(
            client.receive(&accepted[0], 0).unwrap(),
            [Action::Event(Event::LoggedIn {
                session: session(),
                sequence: 5
            })]
        );
        (client, server)
    }

    #[test]
    fn login_and_sequence_numbering() {
        let (mut client, mut server) = pair();
        assert_eq!(client.phase(), ClientPhase::LoggedIn);
        assert_eq!(server.next_sequence(), 5);
        for (i, msg) in [&b"a"[..], b"b", b"c"].iter().enumerate() {
            let p = server.send(msg, 10).unwrap();
            assert_eq!(p, Packet::SequencedData(msg.to_vec()));
            assert_eq!(
                client.receive(&p, 10).unwrap(),
                [Action::Event(Event::Sequenced {
                    sequence: 5 + i as u64
                })]
            );
        }
        assert_eq!(client.next_sequence(), 8);
        assert_eq!(server.next_sequence(), 8);
        assert_eq!(client.session(), session());
        let u = client.send(b"order", 11).unwrap();
        assert_eq!(
            server.receive(&u, 11).unwrap(),
            [Action::Event(Event::Unsequenced)]
        );
        // Debug packets are ignored by both sides (2.1).
        let d = server.debug(b"x", 12).unwrap();
        assert!(client.receive(&d, 12).unwrap().is_empty());
        let d = client.debug(b"y", 12).unwrap();
        assert!(server.receive(&d, 12).unwrap().is_empty());
    }

    #[test]
    fn heartbeats_after_one_second_of_silence() {
        let (mut client, mut server) = pair();
        assert!(server.tick(999).unwrap().is_empty());
        assert_eq!(
            server.tick(1000).unwrap(),
            [Action::Send(Packet::ServerHeartbeat)]
        );
        assert!(server.tick(1500).unwrap().is_empty());
        let _ = server.send(b"m", 1800).unwrap();
        assert!(server.tick(2700).unwrap().is_empty());
        assert_eq!(
            server.tick(2800).unwrap(),
            [Action::Send(Packet::ServerHeartbeat)]
        );
        assert!(client.tick(999).unwrap().is_empty());
        assert_eq!(
            client.tick(1000).unwrap(),
            [Action::Send(Packet::ClientHeartbeat)]
        );
        let _ = client.send(b"m", 1500).unwrap();
        assert!(client.tick(2499).unwrap().is_empty());
        assert_eq!(
            client.tick(2500).unwrap(),
            [Action::Send(Packet::ClientHeartbeat)]
        );
    }

    #[test]
    fn idle_timeout_after_fifteen_seconds() {
        let (mut client, mut server) = pair();
        assert!(
            client
                .receive(&Packet::ServerHeartbeat, 1000)
                .unwrap()
                .is_empty()
        );
        assert!(
            server
                .receive(&Packet::ClientHeartbeat, 2000)
                .unwrap()
                .is_empty()
        );
        let _ = client.tick(15_999).unwrap();
        assert_eq!(client.phase(), ClientPhase::LoggedIn);
        assert_eq!(
            client.tick(16_000).unwrap(),
            [Action::Event(Event::Disconnected(CloseReason::IdleTimeout))]
        );
        let _ = server.tick(16_999).unwrap();
        assert_eq!(server.phase(), ServerPhase::LoggedIn);
        assert_eq!(
            server.tick(17_000).unwrap(),
            [Action::Event(Event::Disconnected(CloseReason::IdleTimeout))]
        );
        assert_eq!(
            server.receive(&Packet::ClientHeartbeat, 17_001),
            Err(Error::State)
        );
        assert!(server.tick(20_000).unwrap().is_empty());
    }

    #[test]
    fn login_timeout_and_rejection() {
        let mut server = Server::new(Timers::default(), 100).unwrap();
        assert!(server.tick(30_099).unwrap().is_empty());
        assert_eq!(
            server.tick(30_100).unwrap(),
            [Action::Event(Event::Disconnected(
                CloseReason::LoginTimeout
            ))]
        );
        let mut client = Client::new(login(), Timers::default(), 0).unwrap();
        assert!(client.tick(50_000).unwrap().is_empty());
        let _ = client.start(50_000).unwrap();
        assert_eq!(
            client.tick(80_000).unwrap(),
            [Action::Event(Event::Disconnected(
                CloseReason::LoginTimeout
            ))]
        );

        let mut client = Client::new(login(), Timers::default(), 0).unwrap();
        let mut server = Server::new(Timers::default(), 0).unwrap();
        let request = sends(&client.start(0).unwrap());
        let _ = server.receive(&request[0], 1).unwrap();
        let actions = server.reject(RejectReason::NotAuthorized, 2).unwrap();
        assert_eq!(
            actions,
            [
                Action::Send(Packet::LoginRejected(RejectReason::NotAuthorized)),
                Action::Event(Event::Disconnected(CloseReason::Rejected))
            ]
        );
        assert_eq!(
            client.receive(&sends(&actions)[0], 3).unwrap(),
            [
                Action::Event(Event::Rejected(RejectReason::NotAuthorized)),
                Action::Event(Event::Disconnected(CloseReason::Rejected))
            ]
        );
        assert_eq!(client.phase(), ClientPhase::Closed);
    }

    #[test]
    fn logout_and_end_of_session() {
        let (mut client, mut server) = pair();
        let actions = client.logout(5).unwrap();
        assert_eq!(
            actions,
            [
                Action::Send(Packet::LogoutRequest),
                Action::Event(Event::Disconnected(CloseReason::Logout))
            ]
        );
        assert_eq!(
            server.receive(&Packet::LogoutRequest, 6).unwrap(),
            [Action::Event(Event::Disconnected(CloseReason::Logout))]
        );

        let (mut client, mut server) = pair();
        let actions = server.end_session(5).unwrap();
        assert_eq!(sends(&actions), [Packet::EndOfSession]);
        assert_eq!(
            client.receive(&Packet::EndOfSession, 6).unwrap(),
            [Action::Event(Event::Disconnected(
                CloseReason::EndOfSession
            ))]
        );
        assert_eq!(server.send(b"x", 7), Err(Error::State));
        assert_eq!(client.send(b"x", 7), Err(Error::State));
    }

    #[test]
    fn reconnect_with_session_and_next_sequence() {
        let (mut client, mut server) = pair();
        let p = server.send(b"m", 1).unwrap();
        let _ = client.receive(&p, 1).unwrap();
        let again = Login {
            session: client.session(),
            sequence: client.next_sequence(),
            ..login()
        };
        assert_eq!(again.sequence, 6);
        let mut client = Client::new(again, Timers::default(), 2).unwrap();
        let request = sends(&client.start(2).unwrap());
        let mut server = Server::new(Timers::default(), 2).unwrap();
        let [Action::Event(Event::LoginRequested(asked))] =
            &server.receive(&request[0], 2).unwrap()[..]
        else {
            panic!("expected a login request")
        };
        assert!(asked.session.matches(&session()));
        let accepted = sends(&server.accept(asked.session, asked.sequence, 3).unwrap());
        let _ = client.receive(&accepted[0], 3).unwrap();
        assert_eq!(client.next_sequence(), 6);

        // A server answering with a different session than requested is a
        // protocol fault.
        let mut client = Client::new(again, Timers::default(), 0).unwrap();
        let _ = client.start(0).unwrap();
        let other = Packet::LoginAccepted {
            session: Alpha::left_padded("OTHER").unwrap(),
            sequence: 1,
        };
        assert_eq!(
            client.receive(&other, 1).unwrap(),
            [Action::Event(Event::Disconnected(CloseReason::Protocol))]
        );
    }

    #[test]
    fn login_accepted_needs_the_exact_session_and_a_real_sequence() {
        let closed = [Action::Event(Event::Disconnected(CloseReason::Protocol))];
        let asking = Login {
            session: Alpha::left_padded("Sess1").unwrap(),
            ..login()
        };
        // Session IDs are case-sensitive; only usernames and passwords
        // are not (2.3.1).
        let mut client = Client::new(asking, Timers::default(), 0).unwrap();
        let _ = client.start(0).unwrap();
        let upper = Packet::LoginAccepted {
            session: Alpha::left_padded("SESS1").unwrap(),
            sequence: 1,
        };
        assert_eq!(client.receive(&upper, 1).unwrap(), closed);
        // Padding does not matter.
        let mut client = Client::new(asking, Timers::default(), 0).unwrap();
        let _ = client.start(0).unwrap();
        let padded = Packet::LoginAccepted {
            session: Alpha::new(*b"Sess1     ").unwrap(),
            sequence: 1,
        };
        assert!(matches!(
            client.receive(&padded, 1).unwrap()[..],
            [Action::Event(Event::LoggedIn { .. })]
        ));
        // Sequence numbers start at 1 (1.2): 0 is never the next one.
        let mut client = Client::new(login(), Timers::default(), 0).unwrap();
        let _ = client.start(0).unwrap();
        let zero = Packet::LoginAccepted {
            session: session(),
            sequence: 0,
        };
        assert_eq!(client.receive(&zero, 1).unwrap(), closed);
        assert_eq!(client.phase(), ClientPhase::Closed);
    }

    #[test]
    fn out_of_turn_packets_close_with_protocol() {
        // Sequenced data before login.
        let mut client = Client::new(login(), Timers::default(), 0).unwrap();
        let _ = client.start(0).unwrap();
        assert_eq!(
            client
                .receive(&Packet::SequencedData(Vec::new()), 1)
                .unwrap(),
            [Action::Event(Event::Disconnected(CloseReason::Protocol))]
        );
        // A client packet type from the server.
        let (mut client, mut server) = pair();
        assert_eq!(
            client.receive(&Packet::ClientHeartbeat, 1).unwrap(),
            [Action::Event(Event::Disconnected(CloseReason::Protocol))]
        );
        // Data before login, and a frame that does not parse.
        let mut fresh = Server::new(Timers::default(), 0).unwrap();
        assert_eq!(
            fresh
                .receive(&Packet::UnsequencedData(Vec::new()), 1)
                .unwrap(),
            [Action::Event(Event::Disconnected(CloseReason::Protocol))]
        );
        assert_eq!(
            server.receive_frame(&Err(Error::Type(b'Q')), 1).unwrap(),
            [Action::Event(Event::Disconnected(CloseReason::Protocol))]
        );
    }

    #[test]
    fn errors_leave_sessions_unchanged() {
        let (mut client, mut server) = pair();
        let _ = server.send(b"m", 100).unwrap();
        assert_eq!(server.send(b"m", 99), Err(Error::Time));
        assert_eq!(server.tick(99), Err(Error::Time));
        assert_eq!(server.next_sequence(), 6);
        assert_eq!(
            server.send(&vec![0; MAX_PAYLOAD + 1], 200),
            Err(Error::TooLong)
        );
        assert_eq!(server.next_sequence(), 6);
        assert_eq!(server.accept(session(), 1, 200), Err(Error::State));
        let _ = client.receive(&Packet::ServerHeartbeat, 100).unwrap();
        assert_eq!(
            client.receive(&Packet::SequencedData(Vec::new()), 50),
            Err(Error::Time)
        );
        assert_eq!(client.next_sequence(), 5);
        assert_eq!(client.start(200), Err(Error::State));
        assert_eq!(
            Timers {
                heartbeat_ms: 0,
                ..Timers::default()
            }
            .validate(),
            Err(Error::Config)
        );
        assert!(
            Server::new(
                Timers {
                    idle_timeout_ms: MAX_TIMER_MS + 1,
                    ..Timers::default()
                },
                0
            )
            .is_err()
        );
        let mut pending = Server::new(Timers::default(), 0).unwrap();
        let _ = pending.receive(&Packet::LoginRequest(login()), 0).unwrap();
        assert_eq!(pending.accept(session(), 0, 0), Err(Error::Sequence));
        assert_eq!(pending.phase(), ServerPhase::LoginPending);
    }

    #[test]
    fn sequence_exhaustion_is_refused() {
        let mut server = Server::new(Timers::default(), 0).unwrap();
        let _ = server.receive(&Packet::LoginRequest(login()), 0).unwrap();
        let _ = server.accept(session(), u64::MAX, 0).unwrap();
        assert_eq!(server.send(b"x", 0), Err(Error::Sequence));
        let mut client = Client::new(login(), Timers::default(), 0).unwrap();
        let _ = client.start(0).unwrap();
        let _ = client
            .receive(
                &Packet::LoginAccepted {
                    session: session(),
                    sequence: u64::MAX,
                },
                0,
            )
            .unwrap();
        assert_eq!(
            client.receive(&Packet::SequencedData(Vec::new()), 0),
            Err(Error::Sequence)
        );
        assert_eq!(client.phase(), ClientPhase::LoggedIn);
    }

    #[test]
    fn random_session_traffic_stays_consistent() {
        let mut rng = Lcg::new(7);
        let packets = every_packet();
        for _ in 0..200 {
            let (mut client, mut server) = pair();
            let mut now = 0;
            for _ in 0..32 {
                now += rng.below(3000);
                let p = &packets[rng.index(packets.len())];
                let before = client.next_sequence();
                match client.receive(p, now) {
                    Ok(actions) => {
                        assert!(actions.len() <= 2);
                        if matches!(p, Packet::SequencedData(_))
                            && client.phase() == ClientPhase::LoggedIn
                        {
                            assert_eq!(client.next_sequence(), before + 1);
                        }
                    }
                    Err(e) => assert_eq!(e, Error::State),
                }
                if let Ok(actions) = server.receive(p, now) {
                    assert!(actions.len() <= 2);
                }
                for a in client
                    .tick(now)
                    .unwrap()
                    .iter()
                    .chain(&server.tick(now).unwrap())
                {
                    if let Action::Send(p) = a {
                        check_wire_value(p);
                    }
                }
            }
        }
    }
}
