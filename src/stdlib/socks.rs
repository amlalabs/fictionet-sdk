//! SOCKS4, SOCKS4a and SOCKS5: reading and writing the handshake messages
//! and the UDP request header, with no I/O.
//!
//! SOCKS is how a client asks a proxy to open a connection for it. The
//! client connects to the proxy, usually on TCP port 1080, says where it
//! wants to go, and the proxy answers whether it got there. After that the
//! connection carries the tunneled bytes. SOCKS5 adds a choice of login
//! methods, IPv6 and domain addresses, inbound connections (BIND) and UDP
//! relaying (UDP ASSOCIATE). This module follows RFC 1928 (SOCKS5), RFC
//! 1929 (the username and password login), the SOCKS4 protocol document,
//! and its SOCKS4a extension, which lets the client send a domain name.
//!
//! Nothing here reads a socket. A world that plays a proxy feeds the bytes
//! it reads from a client's TCP connection to a [`ServerDecoder`], which
//! knows which stage of the handshake it is in. Each [`ClientMessage`] it
//! gives back is answered by writing a reply's bytes to the connection.
//! The world tells the decoder which login method it chose with
//! [`ServerDecoder::select`] and whether a login is good with
//! [`ServerDecoder::verified`]. Once the handshake is over, the rest of the
//! stream is tunnel data. A world that plays a client uses a
//! [`ClientDecoder`] the same way. Where a connection goes, and whether it
//! is allowed, is up to world code.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. Every length is bounded by a named limit, and a decoder never
//! holds more than [`MAX_BUFFERED`] bytes.
//!
//! New code uses [`ClientMessages`] or [`ServerMessages`] with
//! [`codec::Stream`]. Choose methods and verify authentication between
//! items, then hand off unread bytes with `swap` or `into_parts` after
//! `End`. Individual greeting, auth, request and reply types implement
//! [`Wire`] with exact parsing and transactional writing. The legacy
//! decoders and their `take_data` methods retain their original behavior.
//!
//! ```
//! use fictionet::stdlib::socks::{
//!     Address, ClientMessage, Command, Method, Reply, ReplyCode, Selection, ServerDecoder, ServerStage,
//! };
//! use std::net::Ipv4Addr;
//!
//! let mut decoder = ServerDecoder::new();
//! // A SOCKS5 greeting that offers one method: no login.
//! decoder.feed(&[5, 1, 0]);
//! let Some(Ok(ClientMessage::Greeting(greeting))) = decoder.next_message() else { panic!() };
//! assert_eq!(greeting.methods, [Method::NoAuth]);
//! assert_eq!(decoder.stage(), ServerStage::Selecting);
//! assert_eq!(Selection { method: Method::NoAuth }.to_bytes(), [5, 0]);
//! decoder.select(Method::NoAuth);
//!
//! // CONNECT to example.com port 80, and the first tunneled byte.
//! let mut request = vec![5, 1, 0, 3, 11];
//! request.extend_from_slice(b"example.com");
//! request.extend_from_slice(&[0, 80, b'G']);
//! decoder.feed(&request);
//! let Some(Ok(ClientMessage::Request(req))) = decoder.next_message() else { panic!() };
//! assert_eq!(req.command, Command::Connect);
//! assert_eq!(req.address, Address::Domain(b"example.com".to_vec()));
//! assert_eq!(req.port, 80);
//! assert_eq!(decoder.stage(), ServerStage::Done);
//! assert_eq!(decoder.take_data(), b"G");
//!
//! // The proxy connected from 10.0.0.1 port 4321.
//! let reply = Reply { code: ReplyCode::Succeeded, address: Address::Ipv4(Ipv4Addr::new(10, 0, 0, 1)), port: 4321 };
//! assert_eq!(reply.to_bytes(), [5, 0, 0, 1, 10, 0, 0, 1, 0x10, 0xe1]);
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::codec::{self, Step, Wire};

/// Why a SOCKS stream cannot find its next unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// A version, address type or field boundary is invalid.
    Protocol(Error),
    /// A unit exceeds the configured whole-message limit.
    TooLong,
    /// Bytes arrived before `select` or `verified` decided the next stage.
    DecisionRequired(ServerStage),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Protocol(e) => e.fmt(f),
            Self::TooLong => f.write_str("SOCKS unit exceeds its limit"),
            Self::DecisionRequired(s) => write!(f, "SOCKS decision required in {s:?}"),
        }
    }
}
impl core::error::Error for DecodeError {}

/// Why a SOCKS value cannot be read or written exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// The unit is malformed.
    Protocol(Error),
    /// The unit is incomplete.
    Truncated,
    /// Bytes follow the unit.
    Trailing,
    /// Encoding would clip a field or change a variant.
    Unrepresentable,
}
impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Protocol(e) => e.fmt(f),
            Self::Truncated => f.write_str("incomplete SOCKS unit"),
            Self::Trailing => f.write_str("bytes after the SOCKS unit"),
            Self::Unrepresentable => f.write_str("SOCKS value cannot be written unchanged"),
        }
    }
}
impl core::error::Error for WireError {}

macro_rules! socks_wire {
    ($($ty:ty),+ $(,)?) => {$(
        impl Wire for $ty {
            type ParseError = WireError;
            type WriteError = WireError;

            /// Reads exactly one unit, bounded by `MAX_MESSAGE`.
            fn parse(bytes: &[u8]) -> Result<Self, WireError> {
                let (value, used) = Self::parse(bytes)
                    .map_err(WireError::Protocol)?.ok_or(WireError::Truncated)?;
                if used != bytes.len() { return Err(WireError::Trailing); }
                Ok(value)
            }

            /// Appends a strict encoding. Leaves `out` unchanged on error.
            fn write(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
                let bytes = self.to_bytes();
                if <Self as Wire>::parse(&bytes).as_ref() != Ok(self) {
                    return Err(WireError::Unrepresentable);
                }
                out.extend_from_slice(&bytes);
                Ok(())
            }
        }
    )+};
}
socks_wire!(Greeting, Selection, AuthRequest, AuthReply, Request, Reply, Socks4Request, Socks4Reply);

fn sized_end(at: usize, len: usize) -> Result<usize, DecodeError> {
    at.checked_add(len).ok_or(DecodeError::TooLong)
}

// Finds framing without interpreting command and reserved fields. Those
// are per-unit failures once the endpoint establishes an exact boundary.
fn endpoint_end(b: &[u8], at: usize) -> Result<Option<usize>, DecodeError> {
    let Some(&kind) = b.get(at) else { return Ok(None) };
    Ok(Some(match kind {
        atyp::IPV4 => sized_end(at, 7)?,
        atyp::IPV6 => sized_end(at, 19)?,
        atyp::DOMAIN => {
            let Some(&n) = b.get(sized_end(at, 1)?) else {
                return Ok(None);
            };
            sized_end(sized_end(at, 4)?, usize::from(n))?
        }
        other => return Err(DecodeError::Protocol(Error::AddressType(other))),
    }))
}

#[derive(Clone, Debug, Default)]
struct Scan4 {
    pos: usize,
    user_end: Option<usize>,
}
impl Scan4 {
    fn length(&mut self, b: &[u8]) -> Result<Option<usize>, DecodeError> {
        let Some(&[a, c, d, e]) = b.get(4..8) else { return Ok(None) };
        let domain = [a, c, d] == [0, 0, 0] && e != 0;
        self.pos = self.pos.max(8);
        loop {
            let start = self.user_end.map_or(Ok(8), |n| sized_end(n, 1))?;
            let max = if self.user_end.is_some() { MAX_SOCKS4_DOMAIN } else { MAX_USER_ID };
            let field_end = sized_end(sized_end(start, max)?, 1)?;
            let end = b.len().min(field_end);
            let bytes = b.get(self.pos..end).unwrap_or_default();
            if let Some(n) = bytes.iter().position(|&v| v == 0) {
                let nul = sized_end(self.pos, n)?;
                self.pos = sized_end(nul, 1)?;
                if self.user_end.is_some() || !domain {
                    return Ok(Some(self.pos));
                }
                self.user_end = Some(nul);
            } else {
                self.pos = end;
                return if end == field_end {
                    Err(DecodeError::Protocol(Error::FieldTooLong))
                } else {
                    Ok(None)
                };
            }
        }
    }
}

/// Reads client greeting, authentication and request units without input ownership.
///
/// Use with [`codec::Stream`]. Call [`select`](Self::select) immediately
/// after a greeting item and [`verified`](Self::verified) after an auth
/// item. Until that decision, empty input returns [`Step::Need`], allowing
/// [`codec::pump`] and [`codec::try_pump`] to return to the world. With bytes
/// buffered, decoding instead fails with [`DecodeError::DecisionRequired`]
/// so it never stalls at capacity. Decide before decoding those bytes.
/// Complete malformed requests are `Err` items. Unknown framing and limits
/// are terminal errors. Both leave [`ServerStage::Failed`]. A request is
/// the last item; the next call returns [`Step::End`]. Unsupported selected
/// methods and refusal also end.
/// Use `Stream::swap` or `into_parts` for the unread tunnel bytes, and send
/// any input not accepted by `push` to the next decoder. EOF inside a unit
/// returns `Need` so the driver reports truncation.
#[derive(Clone, Debug)]
pub struct ClientMessages {
    stage: ServerStage,
    offered: MethodSet,
    limit: usize,
    scan4: Scan4,
}
impl ClientMessages {
    /// Starts at the greeting, with a whole-unit limit of [`MAX_MESSAGE`].
    pub fn new() -> Self {
        Self::with_limit(MAX_MESSAGE)
    }

    /// Sets the whole-unit limit, clamped to 8 through [`MAX_MESSAGE`].
    /// Counted units are refused from their length fields before the body.
    pub fn with_limit(limit: usize) -> Self {
        Self {
            stage: ServerStage::Greeting,
            offered: MethodSet::default(),
            limit: limit.clamp(8, MAX_MESSAGE),
            scan4: Scan4::default(),
        }
    }

    /// The current handshake stage.
    pub fn stage(&self) -> ServerStage {
        self.stage
    }

    /// The largest accepted unit, including its header.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Chooses an offered method between items. Returns false outside the
    /// selection stage or for a method that was not offered.
    pub fn select(&mut self, method: Method) -> bool {
        if self.stage != ServerStage::Selecting || !self.offered.allows(method) {
            return false;
        }
        self.stage = match Method::from_code(method.code()) {
            Method::NoAuth => ServerStage::Request,
            Method::UsernamePassword => ServerStage::Auth,
            Method::NoAcceptable => ServerStage::Closed,
            _ => ServerStage::Done,
        };
        true
    }

    /// Accepts or refuses authentication between items. Does nothing
    /// outside the verification stage. Refusal preserves unread bytes.
    pub fn verified(&mut self, good: bool) {
        if self.stage == ServerStage::Verifying {
            self.stage = if good { ServerStage::Request } else { ServerStage::Closed };
        }
    }
}
impl Default for ClientMessages {
    fn default() -> Self {
        Self::new()
    }
}
impl codec::Decode for ClientMessages {
    type Item = Result<ClientMessage, Error>;
    type Error = DecodeError;
    const NAME: &'static str = "SOCKS client units";
    fn capacity(&self) -> usize {
        self.limit
    }

    fn decode(&mut self, b: &[u8], _: bool) -> Result<Step<Self::Item>, DecodeError> {
        self.decode_unit(b)
            .inspect_err(|_| self.stage = ServerStage::Failed)
    }
}
impl ClientMessages {
    fn decode_unit(&mut self, b: &[u8]) -> Result<Step<Result<ClientMessage, Error>>, DecodeError> {
        match self.stage {
            ServerStage::Done | ServerStage::Closed | ServerStage::Failed => return Ok(Step::End),
            ServerStage::Selecting | ServerStage::Verifying if b.is_empty() => {
                return Ok(Step::Need);
            }
            ServerStage::Selecting | ServerStage::Verifying => {
                return Err(DecodeError::DecisionRequired(self.stage));
            }
            _ => {}
        }
        let Some(&first) = b.first() else { return Ok(Step::Need) };
        let v4 = self.stage == ServerStage::Greeting && first == VERSION_4;
        let version = if v4 {
            VERSION_4
        } else if self.stage == ServerStage::Auth {
            AUTH_VERSION
        } else {
            VERSION_5
        };
        check_version(b, version).map_err(DecodeError::Protocol)?;
        let end = if v4 {
            self.scan4.length(b.get(..self.limit).unwrap_or(b))?
        } else {
            match self.stage {
                ServerStage::Greeting => b
                    .get(1)
                    .map(|&n| sized_end(2, usize::from(n)))
                    .transpose()?,
                ServerStage::Auth => match b.get(1) {
                    Some(&n) => {
                        let at = sized_end(2, usize::from(n))?;
                        let header = sized_end(at, 1)?;
                        if header > self.limit {
                            return Err(DecodeError::TooLong);
                        }
                        b.get(at)
                            .map(|&p| sized_end(header, usize::from(p)))
                            .transpose()?
                    }
                    None => None,
                },
                _ => endpoint_end(b, 3)?,
            }
        };
        let Some(used) = end else {
            return if b.len() >= self.limit { Err(DecodeError::TooLong) } else { Ok(Step::Need) };
        };
        if used > self.limit {
            return Err(DecodeError::TooLong);
        }
        let Some(bytes) = b.get(..used) else { return Ok(Step::Need) };
        let item = if v4 {
            Socks4Request::parse(bytes).map(|v| v.map(|(m, _)| ClientMessage::Socks4(m)))
        } else {
            match self.stage {
                ServerStage::Greeting => Greeting::parse(bytes).map(|v| v.map(|(m, _)| ClientMessage::Greeting(m))),
                ServerStage::Auth => AuthRequest::parse(bytes).map(|v| v.map(|(m, _)| ClientMessage::Auth(m))),
                _ => Request::parse(bytes).map(|v| v.map(|(m, _)| ClientMessage::Request(m))),
            }
        }
        .and_then(|v| v.ok_or(Error::Truncated));
        self.stage = match &item {
            Ok(ClientMessage::Greeting(g)) => {
                self.offered = MethodSet::of(&g.methods);
                ServerStage::Selecting
            }
            Ok(ClientMessage::Auth(_)) => ServerStage::Verifying,
            Ok(_) => ServerStage::Done,
            Err(_) => ServerStage::Failed,
        };
        Ok(Step::Item(item, used))
    }
}

/// Reads proxy replies, then ends with unread tunnel bytes in the stream.
///
/// This is the input-free counterpart of [`ClientDecoder`]. BIND reads
/// both replies. Refusal and unsupported methods yield their last item,
/// then `End`. Bad complete units are items; framing and limits are errors.
/// Both kinds of error leave [`ClientStage::Failed`], preserving unread bytes.
#[derive(Clone, Debug)]
pub struct ServerMessages {
    stage: ClientStage,
    socks4: bool,
    bind: bool,
    offered: Option<MethodSet>,
    limit: usize,
}
impl ServerMessages {
    /// Reads a SOCKS5 selection, optional auth reply, and request replies.
    pub fn socks5(command: Command) -> Self {
        Self::with_limit(command, MAX_MESSAGE)
    }

    /// Reads SOCKS5 replies with a whole-unit limit clamped to 8 through
    /// [`MAX_MESSAGE`]. Declared endpoint lengths are checked before the body.
    pub fn with_limit(command: Command, limit: usize) -> Self {
        Self {
            stage: ClientStage::Selection,
            socks4: false,
            bind: command == Command::Bind,
            offered: None,
            limit: limit.clamp(8, MAX_MESSAGE),
        }
    }

    /// Also checks the selection against the first [`MAX_METHODS`] offers.
    pub fn socks5_offering(command: Command, methods: &[Method]) -> Self {
        Self { offered: Some(MethodSet::of(methods)), ..Self::socks5(command) }
    }

    /// Reads SOCKS4 or SOCKS4a replies, including BIND's second reply.
    pub fn socks4(command: Socks4Command) -> Self {
        Self {
            stage: ClientStage::Reply,
            socks4: true,
            bind: command == Socks4Command::Bind,
            offered: None,
            limit: MAX_MESSAGE,
        }
    }

    /// The largest accepted unit, including its header.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// The current reply stage.
    pub fn stage(&self) -> ClientStage {
        self.stage
    }
}
impl codec::Decode for ServerMessages {
    type Item = Result<ServerMessage, Error>;
    type Error = DecodeError;
    const NAME: &'static str = "SOCKS server units";
    fn capacity(&self) -> usize {
        self.limit
    }

    fn decode(&mut self, b: &[u8], _: bool) -> Result<Step<Self::Item>, DecodeError> {
        self.decode_unit(b)
            .inspect_err(|_| self.stage = ClientStage::Failed)
    }
}
impl ServerMessages {
    fn decode_unit(&mut self, b: &[u8]) -> Result<Step<Result<ServerMessage, Error>>, DecodeError> {
        if matches!(self.stage, ClientStage::Done | ClientStage::Closed | ClientStage::Failed) {
            return Ok(Step::End);
        }
        let version = if self.socks4 {
            VERSION_4_REPLY
        } else if self.stage == ClientStage::Auth {
            AUTH_VERSION
        } else {
            VERSION_5
        };
        check_version(b, version).map_err(DecodeError::Protocol)?;
        let used = match self.stage {
            ClientStage::Selection | ClientStage::Auth => 2,
            _ if self.socks4 => SOCKS4_REPLY_LEN,
            _ => match endpoint_end(b, 3)? {
                Some(n) => n,
                None => return Ok(Step::Need),
            },
        };
        if used > self.limit {
            return Err(DecodeError::TooLong);
        }
        let Some(bytes) = b.get(..used) else { return Ok(Step::Need) };
        let item = match self.stage {
            ClientStage::Selection => Selection::parse(bytes).map(|v| v.map(|(m, _)| ServerMessage::Selection(m))),
            ClientStage::Auth => AuthReply::parse(bytes).map(|v| v.map(|(m, _)| ServerMessage::Auth(m))),
            _ if self.socks4 => Socks4Reply::parse(bytes).map(|v| v.map(|(m, _)| ServerMessage::Socks4(m))),
            _ => Reply::parse(bytes).map(|v| v.map(|(m, _)| ServerMessage::Reply(m))),
        }
        .and_then(|v| v.ok_or(Error::Truncated))
        .and_then(|m| {
            if let ServerMessage::Selection(s) = &m
                && self.offered.is_some_and(|o| !o.allows(s.method))
            {
                return Err(Error::Method(s.method.code()));
            }
            Ok(m)
        });
        let reply_stage =
            if self.bind && self.stage == ClientStage::Reply { ClientStage::SecondReply } else { ClientStage::Done };
        self.stage = match &item {
            Ok(ServerMessage::Selection(s)) => match Method::from_code(s.method.code()) {
                Method::NoAuth => ClientStage::Reply,
                Method::UsernamePassword => ClientStage::Auth,
                Method::NoAcceptable => ClientStage::Closed,
                _ => ClientStage::Done,
            },
            Ok(ServerMessage::Auth(a)) if a.success() => ClientStage::Reply,
            Ok(ServerMessage::Reply(r)) if r.code.code() == ReplyCode::Succeeded.code() => reply_stage,
            Ok(ServerMessage::Socks4(r)) if r.code.code() == Socks4Code::Granted.code() => reply_stage,
            Ok(_) => ClientStage::Closed,
            Err(_) => ClientStage::Failed,
        };
        Ok(Step::Item(item, used))
    }
}

/// The TCP port SOCKS proxies listen on.
pub const PORT: u16 = 1080;
/// The version byte that starts every SOCKS5 message on the TCP stream.
pub const VERSION_5: u8 = 5;
/// The version byte that starts a SOCKS4 or SOCKS4a request.
pub const VERSION_4: u8 = 4;
/// The version byte that starts a SOCKS4 reply.
pub const VERSION_4_REPLY: u8 = 0;
/// The version byte of the username and password login (RFC 1929).
pub const AUTH_VERSION: u8 = 1;
/// The status an [`AuthReply`] sends for a good login.
pub const AUTH_SUCCESS: u8 = 0;

/// The most methods a greeting can offer.
pub const MAX_METHODS: usize = 255;
/// The longest domain name a SOCKS5 address can hold.
pub const MAX_DOMAIN: usize = 255;
/// The longest username a login can carry.
pub const MAX_USERNAME: usize = 255;
/// The longest password a login can carry.
pub const MAX_PASSWORD: usize = 255;
/// The longest user ID a SOCKS4 request may carry, before its zero byte.
pub const MAX_USER_ID: usize = 255;
/// The longest domain name a SOCKS4a request may carry, before its zero
/// byte.
pub const MAX_SOCKS4_DOMAIN: usize = 255;
/// The longest handshake message: a SOCKS4a request with the longest user
/// ID and domain, each followed by its zero byte.
pub const MAX_MESSAGE: usize = 8 + MAX_USER_ID + 1 + MAX_SOCKS4_DOMAIN + 1;
/// The longest UDP datagram [`UdpHeader::datagram`] writes: the most a UDP
/// datagram over IPv4 can carry.
pub const MAX_DATAGRAM: usize = 65_507;
/// The most bytes a decoder holds that have not been taken out. Bytes past
/// it are dropped, and the decoder fails with [`Error::Overflow`].
pub const MAX_BUFFERED: usize = 65_536;

/// Address type codes in SOCKS5 requests, replies and UDP headers.
pub mod atyp {
    /// An IPv4 address: four bytes.
    pub const IPV4: u8 = 0x01;
    /// A domain name: a length byte, then that many bytes, with no zero
    /// byte at the end.
    pub const DOMAIN: u8 = 0x03;
    /// An IPv6 address: sixteen bytes.
    pub const IPV6: u8 = 0x04;
}

/// Why bytes are not the SOCKS message expected. On a TCP stream, the
/// connection holds no more messages a reader can find, and a real proxy
/// closes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The first byte was not the version this message takes.
    Version(u8),
    /// A command this module does not know: not CONNECT, BIND or UDP
    /// ASSOCIATE in SOCKS5, or not CONNECT or BIND in SOCKS4.
    Command(u8),
    /// An address type that is not IPv4, IPv6 or a domain name.
    AddressType(u8),
    /// A reserved field was not zero.
    Reserved(u16),
    /// A SOCKS4 user ID or SOCKS4a domain ran past its limit with no zero
    /// byte to end it.
    FieldTooLong,
    /// A UDP datagram ended before its header did.
    Truncated,
    /// A decoder was fed more than [`MAX_BUFFERED`] bytes it could not
    /// take out.
    Overflow,
    /// The proxy chose a login method, with this code, that the client did
    /// not offer (RFC 1928 section 3). Only a [`ClientDecoder`] made with
    /// [`ClientDecoder::socks5_offering`] checks this.
    Method(u8),
}

impl Error {
    /// The SOCKS5 reply code a proxy answers a bad request with: command
    /// not supported, address type not supported, or general failure for
    /// the rest.
    pub fn reply_code(self) -> ReplyCode {
        match self {
            Error::Command(_) => ReplyCode::CommandNotSupported,
            Error::AddressType(_) => ReplyCode::AddressTypeNotSupported,
            _ => ReplyCode::GeneralFailure,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Version(v) => write!(f, "version byte {v} is not the one this message takes"),
            Error::Command(c) => write!(f, "unknown command {c}"),
            Error::AddressType(t) => write!(f, "unknown address type {t}"),
            Error::Reserved(r) => write!(f, "reserved field is {r}, not 0"),
            Error::FieldTooLong => f.write_str("SOCKS4 field has no zero byte within its limit"),
            Error::Truncated => f.write_str("UDP datagram ends inside its header"),
            Error::Overflow => write!(f, "more than {MAX_BUFFERED} bytes held"),
            Error::Method(m) => write!(f, "method {m} was not offered"),
        }
    }
}

impl std::error::Error for Error {}

/// A login method a SOCKS5 client offers and a proxy chooses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// 0x00: no login.
    NoAuth,
    /// 0x01: GSS-API (RFC 1961). This module does not read its messages.
    Gssapi,
    /// 0x02: username and password (RFC 1929).
    UsernamePassword,
    /// 0xFF: the proxy takes none of the methods offered.
    NoAcceptable,
    /// Any other code. An `Other` that holds one of the codes above is
    /// written as that code, and decoders treat it as the named method;
    /// readers never return one.
    Other(u8),
}

/// A set of method codes, such as the methods a greeting offered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct MethodSet([u64; 4]);

impl MethodSet {
    /// The set a greeting offering `methods` carries: the first
    /// [`MAX_METHODS`], as [`Greeting::to_bytes`] writes them.
    fn of(methods: &[Method]) -> MethodSet {
        let mut set = MethodSet::default();
        for m in methods.iter().take(MAX_METHODS) {
            let c = m.code();
            set.0[usize::from(c / 64)] |= 1 << (c % 64);
        }
        set
    }

    /// Whether `m` may answer a greeting that offered this set: one of
    /// them, or [`Method::NoAcceptable`].
    fn allows(&self, m: Method) -> bool {
        let c = m.code();
        c == Method::NoAcceptable.code() || self.0[usize::from(c / 64)] & (1 << (c % 64)) != 0
    }
}

impl Method {
    /// The method's code.
    pub fn code(self) -> u8 {
        match self {
            Method::NoAuth => 0x00,
            Method::Gssapi => 0x01,
            Method::UsernamePassword => 0x02,
            Method::NoAcceptable => 0xff,
            Method::Other(c) => c,
        }
    }

    /// The method for code `c`.
    pub fn from_code(c: u8) -> Method {
        match c {
            0x00 => Method::NoAuth,
            0x01 => Method::Gssapi,
            0x02 => Method::UsernamePassword,
            0xff => Method::NoAcceptable,
            c => Method::Other(c),
        }
    }
}

/// A SOCKS5 command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// 0x01: open a TCP connection to the address.
    Connect,
    /// 0x02: wait for one inbound TCP connection from the address.
    Bind,
    /// 0x03: relay UDP datagrams for the client.
    UdpAssociate,
}

impl Command {
    /// The command's code.
    pub fn code(self) -> u8 {
        match self {
            Command::Connect => 1,
            Command::Bind => 2,
            Command::UdpAssociate => 3,
        }
    }

    /// The command for code `c`, or [`Error::Command`].
    pub fn from_code(c: u8) -> Result<Command, Error> {
        match c {
            1 => Ok(Command::Connect),
            2 => Ok(Command::Bind),
            3 => Ok(Command::UdpAssociate),
            c => Err(Error::Command(c)),
        }
    }
}

/// A SOCKS5 address: where a request goes, or where a proxy is bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    /// An IPv4 address.
    Ipv4(Ipv4Addr),
    /// An IPv6 address.
    Ipv6(Ipv6Addr),
    /// A domain name, as the bytes sent. Nothing checks they are a valid
    /// name. Writers keep the first [`MAX_DOMAIN`] bytes.
    Domain(Vec<u8>),
}

impl Address {
    /// Writes the address type, the address and `port`.
    fn write(&self, port: u16, out: &mut Vec<u8>) {
        match self {
            Address::Ipv4(a) => {
                out.push(atyp::IPV4);
                out.extend_from_slice(&a.octets());
            }
            Address::Ipv6(a) => {
                out.push(atyp::IPV6);
                out.extend_from_slice(&a.octets());
            }
            Address::Domain(d) => {
                let d = &d[..d.len().min(MAX_DOMAIN)];
                out.push(atyp::DOMAIN);
                out.push(d.len() as u8);
                out.extend_from_slice(d);
            }
        }
        out.extend_from_slice(&port.to_be_bytes());
    }
}

impl From<IpAddr> for Address {
    fn from(ip: IpAddr) -> Address {
        match ip {
            IpAddr::V4(a) => Address::Ipv4(a),
            IpAddr::V6(a) => Address::Ipv6(a),
        }
    }
}

/// Reads an address type, address and port starting at `at`. It returns
/// `Ok(None)` if `b` ends first, and otherwise the address, the port and
/// where they end.
fn parse_endpoint(b: &[u8], at: usize) -> Result<Option<(Address, u16, usize)>, Error> {
    let Some(&kind) = b.get(at) else { return Ok(None) };
    let (start, len) = match kind {
        atyp::IPV4 => (at + 1, 4),
        atyp::IPV6 => (at + 1, 16),
        atyp::DOMAIN => {
            let Some(&n) = b.get(at + 1) else { return Ok(None) };
            (at + 2, usize::from(n))
        }
        t => return Err(Error::AddressType(t)),
    };
    let Some(end) = start.checked_add(len).and_then(|e| e.checked_add(2)) else { return Ok(None) };
    if b.len() < end {
        return Ok(None);
    }
    let raw = &b[start..start + len];
    let address = match kind {
        atyp::IPV4 => Address::Ipv4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])),
        atyp::IPV6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(raw);
            Address::Ipv6(Ipv6Addr::from(octets))
        }
        _ => Address::Domain(raw.to_vec()),
    };
    Ok(Some((address, be16(b, start + len), end)))
}

/// Checks the first byte of `b` is `version`, if it has come.
fn check_version(b: &[u8], version: u8) -> Result<(), Error> {
    match b.first() {
        Some(&v) if v != version => Err(Error::Version(v)),
        _ => Ok(()),
    }
}

/// The SOCKS5 greeting a client opens with: the login methods it offers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Greeting {
    /// The methods offered, in the order sent. Writers keep the first
    /// [`MAX_METHODS`]. RFC 1928 asks for at least one, but an empty list
    /// is read too, and a proxy answers it with [`Method::NoAcceptable`].
    pub methods: Vec<Method>,
}

impl Greeting {
    /// Reads the greeting at the start of `b`. It returns `Ok(None)` if
    /// `b` holds only part of one, and otherwise the greeting and how many
    /// bytes it took.
    pub fn parse(b: &[u8]) -> Result<Option<(Greeting, usize)>, Error> {
        check_version(b, VERSION_5)?;
        let Some(&n) = b.get(1) else { return Ok(None) };
        let end = 2 + usize::from(n);
        if b.len() < end {
            return Ok(None);
        }
        let methods = b[2..end].iter().map(|&c| Method::from_code(c)).collect();
        Ok(Some((Greeting { methods }, end)))
    }

    /// The greeting's bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let methods = &self.methods[..self.methods.len().min(MAX_METHODS)];
        let mut out = Vec::with_capacity(2 + methods.len());
        out.push(VERSION_5);
        out.push(methods.len() as u8);
        out.extend(methods.iter().map(|m| m.code()));
        out
    }
}

/// The SOCKS5 proxy's answer to a greeting: the method it chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    /// The method chosen, or [`Method::NoAcceptable`].
    pub method: Method,
}

impl Selection {
    /// Reads the selection at the start of `b`, as [`Greeting::parse`]
    /// does.
    pub fn parse(b: &[u8]) -> Result<Option<(Selection, usize)>, Error> {
        check_version(b, VERSION_5)?;
        match b.get(1) {
            Some(&m) => Ok(Some((Selection { method: Method::from_code(m) }, 2))),
            None => Ok(None),
        }
    }

    /// The selection's bytes.
    pub fn to_bytes(&self) -> [u8; 2] {
        [VERSION_5, self.method.code()]
    }
}

/// The username and password a client logs in with (RFC 1929).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthRequest {
    /// The username, as sent. Writers keep the first [`MAX_USERNAME`]
    /// bytes.
    pub username: Vec<u8>,
    /// The password, as sent. Writers keep the first [`MAX_PASSWORD`]
    /// bytes.
    pub password: Vec<u8>,
}

impl AuthRequest {
    /// Reads the login at the start of `b`, as [`Greeting::parse`] does.
    /// RFC 1929 asks for fields of at least one byte, but empty ones are
    /// read too.
    pub fn parse(b: &[u8]) -> Result<Option<(AuthRequest, usize)>, Error> {
        check_version(b, AUTH_VERSION)?;
        let Some(&ulen) = b.get(1) else { return Ok(None) };
        let ulen = usize::from(ulen);
        let Some(&plen) = b.get(2 + ulen) else { return Ok(None) };
        let end = 3 + ulen + usize::from(plen);
        if b.len() < end {
            return Ok(None);
        }
        let username = b[2..2 + ulen].to_vec();
        let password = b[3 + ulen..end].to_vec();
        Ok(Some((AuthRequest { username, password }, end)))
    }

    /// The login's bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let user = &self.username[..self.username.len().min(MAX_USERNAME)];
        let pass = &self.password[..self.password.len().min(MAX_PASSWORD)];
        let mut out = Vec::with_capacity(3 + user.len() + pass.len());
        out.push(AUTH_VERSION);
        out.push(user.len() as u8);
        out.extend_from_slice(user);
        out.push(pass.len() as u8);
        out.extend_from_slice(pass);
        out
    }
}

/// The proxy's answer to a login (RFC 1929).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthReply {
    /// [`AUTH_SUCCESS`] for a good login. Any other value is a failure,
    /// and the proxy closes the connection.
    pub status: u8,
}

impl AuthReply {
    /// Reads the answer at the start of `b`, as [`Greeting::parse`] does.
    pub fn parse(b: &[u8]) -> Result<Option<(AuthReply, usize)>, Error> {
        check_version(b, AUTH_VERSION)?;
        match b.get(1) {
            Some(&status) => Ok(Some((AuthReply { status }, 2))),
            None => Ok(None),
        }
    }

    /// Whether the login was good.
    pub fn success(self) -> bool {
        self.status == AUTH_SUCCESS
    }

    /// The answer's bytes.
    pub fn to_bytes(&self) -> [u8; 2] {
        [AUTH_VERSION, self.status]
    }
}

/// A SOCKS5 request: what the client asks the proxy to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// What to do.
    pub command: Command,
    /// For CONNECT, where to connect. For BIND, the server the inbound
    /// connection is expected from. For UDP ASSOCIATE, the address and port
    /// the client will send datagrams from. For BIND and UDP ASSOCIATE it
    /// may be all zeros when the client does not know it yet.
    pub address: Address,
    /// The port that goes with the address.
    pub port: u16,
}

impl Request {
    /// Reads the request at the start of `b`, as [`Greeting::parse`]
    /// does. A bad version, command or reserved byte is reported as soon
    /// as it comes.
    pub fn parse(b: &[u8]) -> Result<Option<(Request, usize)>, Error> {
        check_version(b, VERSION_5)?;
        let Some(&cmd) = b.get(1) else { return Ok(None) };
        let command = Command::from_code(cmd)?;
        let Some(&rsv) = b.get(2) else { return Ok(None) };
        if rsv != 0 {
            return Err(Error::Reserved(u16::from(rsv)));
        }
        Ok(parse_endpoint(b, 3)?.map(|(address, port, end)| (Request { command, address, port }, end)))
    }

    /// The request's bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![VERSION_5, self.command.code(), 0];
        self.address.write(self.port, &mut out);
        out
    }
}

/// The reply codes of a SOCKS5 reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyCode {
    /// 0x00: done.
    Succeeded,
    /// 0x01: the proxy failed.
    GeneralFailure,
    /// 0x02: the proxy's rules do not allow the connection.
    NotAllowed,
    /// 0x03: the network is unreachable.
    NetworkUnreachable,
    /// 0x04: the host is unreachable.
    HostUnreachable,
    /// 0x05: the host refused the connection.
    ConnectionRefused,
    /// 0x06: the TTL expired.
    TtlExpired,
    /// 0x07: the proxy does not support the command.
    CommandNotSupported,
    /// 0x08: the proxy does not support the address type.
    AddressTypeNotSupported,
    /// Any other code. An `Other` that holds one of the codes above is
    /// written as that code and reads back as the named variant.
    Other(u8),
}

impl ReplyCode {
    /// The reply code's number.
    pub fn code(self) -> u8 {
        match self {
            ReplyCode::Succeeded => 0,
            ReplyCode::GeneralFailure => 1,
            ReplyCode::NotAllowed => 2,
            ReplyCode::NetworkUnreachable => 3,
            ReplyCode::HostUnreachable => 4,
            ReplyCode::ConnectionRefused => 5,
            ReplyCode::TtlExpired => 6,
            ReplyCode::CommandNotSupported => 7,
            ReplyCode::AddressTypeNotSupported => 8,
            ReplyCode::Other(c) => c,
        }
    }

    /// The reply code for number `c`.
    pub fn from_code(c: u8) -> ReplyCode {
        match c {
            0 => ReplyCode::Succeeded,
            1 => ReplyCode::GeneralFailure,
            2 => ReplyCode::NotAllowed,
            3 => ReplyCode::NetworkUnreachable,
            4 => ReplyCode::HostUnreachable,
            5 => ReplyCode::ConnectionRefused,
            6 => ReplyCode::TtlExpired,
            7 => ReplyCode::CommandNotSupported,
            8 => ReplyCode::AddressTypeNotSupported,
            c => ReplyCode::Other(c),
        }
    }
}

/// A SOCKS5 reply: the proxy's answer to a request. A BIND gets two: one
/// when the proxy is listening and one when the inbound connection comes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// Whether the request succeeded, and if not, why.
    pub code: ReplyCode,
    /// For CONNECT, the proxy's own address on the new connection. For
    /// BIND, where it listens and then where the inbound connection came
    /// from. For UDP ASSOCIATE, where to send datagrams.
    pub address: Address,
    /// The port that goes with the address.
    pub port: u16,
}

impl Reply {
    /// Reads the reply at the start of `b`, as [`Request::parse`] does.
    pub fn parse(b: &[u8]) -> Result<Option<(Reply, usize)>, Error> {
        check_version(b, VERSION_5)?;
        let Some(&rep) = b.get(1) else { return Ok(None) };
        let Some(&rsv) = b.get(2) else { return Ok(None) };
        if rsv != 0 {
            return Err(Error::Reserved(u16::from(rsv)));
        }
        let code = ReplyCode::from_code(rep);
        Ok(parse_endpoint(b, 3)?.map(|(address, port, end)| (Reply { code, address, port }, end)))
    }

    /// A failure reply with code `code` and a zero IPv4 address and port,
    /// as a proxy sends before it closes the connection.
    pub fn failure(code: ReplyCode) -> Reply {
        Reply { code, address: Address::Ipv4(Ipv4Addr::UNSPECIFIED), port: 0 }
    }

    /// The reply's bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![VERSION_5, self.code.code(), 0];
        self.address.write(self.port, &mut out);
        out
    }
}

/// The header in front of each UDP datagram relayed through a UDP
/// ASSOCIATE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpHeader {
    /// The fragment number. 0 is a whole datagram. Proxies that do not
    /// reassemble fragments drop any other.
    pub fragment: u8,
    /// Where the datagram goes, or where it came from.
    pub address: Address,
    /// The port that goes with the address.
    pub port: u16,
}

impl UdpHeader {
    /// Reads the header of the UDP datagram `datagram`, and returns it
    /// with the payload after it.
    pub fn parse(datagram: &[u8]) -> Result<(UdpHeader, &[u8]), Error> {
        if datagram.len() < 3 {
            return Err(Error::Truncated);
        }
        let rsv = be16(datagram, 0);
        if rsv != 0 {
            return Err(Error::Reserved(rsv));
        }
        let fragment = datagram[2];
        match parse_endpoint(datagram, 3)? {
            Some((address, port, end)) => Ok((UdpHeader { fragment, address, port }, &datagram[end..])),
            None => Err(Error::Truncated),
        }
    }

    /// The header's bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![0, 0, self.fragment];
        self.address.write(self.port, &mut out);
        out
    }

    /// A whole datagram: the header, then `payload`. The payload is cut so
    /// the datagram is no longer than [`MAX_DATAGRAM`].
    pub fn datagram(&self, payload: &[u8]) -> Vec<u8> {
        let mut out = self.to_bytes();
        let room = MAX_DATAGRAM.saturating_sub(out.len());
        out.extend_from_slice(&payload[..payload.len().min(room)]);
        out
    }
}

/// A SOCKS4 command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Socks4Command {
    /// 1: open a TCP connection.
    Connect,
    /// 2: wait for one inbound TCP connection.
    Bind,
}

impl Socks4Command {
    /// The command's code.
    pub fn code(self) -> u8 {
        match self {
            Socks4Command::Connect => 1,
            Socks4Command::Bind => 2,
        }
    }

    /// The command for code `c`, or [`Error::Command`].
    pub fn from_code(c: u8) -> Result<Socks4Command, Error> {
        match c {
            1 => Ok(Socks4Command::Connect),
            2 => Ok(Socks4Command::Bind),
            c => Err(Error::Command(c)),
        }
    }
}

/// Where a SOCKS4 request goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Socks4Destination {
    /// An IPv4 address (SOCKS4). The addresses 0.0.0.1 to 0.0.0.255 mean
    /// a domain follows, so writers send an empty
    /// [`Socks4Destination::Domain`] in their place.
    Ip(Ipv4Addr),
    /// A domain name for the proxy to look up (SOCKS4a), as the bytes
    /// sent. Writers cut it at its first zero byte and keep at most
    /// [`MAX_SOCKS4_DOMAIN`] bytes.
    Domain(Vec<u8>),
}

/// A SOCKS4 or SOCKS4a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Socks4Request {
    /// What to do.
    pub command: Socks4Command,
    /// The destination port.
    pub port: u16,
    /// The destination.
    pub destination: Socks4Destination,
    /// The user ID, as sent. Writers cut it at its first zero byte and
    /// keep at most [`MAX_USER_ID`] bytes.
    pub user_id: Vec<u8>,
}

/// Finds the zero byte that ends a field starting at `from`, which may be
/// at most `max` bytes long. It returns `Ok(None)` if `b` ends first.
fn find_nul(b: &[u8], from: usize, max: usize) -> Result<Option<usize>, Error> {
    let window = b.get(from..).unwrap_or(&[]);
    let window = &window[..window.len().min(max + 1)];
    match window.iter().position(|&c| c == 0) {
        Some(i) => Ok(Some(from + i)),
        None if window.len() > max => Err(Error::FieldTooLong),
        None => Ok(None),
    }
}

/// Keeps the bytes of `field` before its first zero byte, at most `max`.
fn c_field(field: &[u8], max: usize) -> &[u8] {
    let end = field.iter().position(|&c| c == 0).unwrap_or(field.len());
    &field[..end.min(max)]
}

impl Socks4Request {
    /// Reads the request at the start of `b`, as [`Request::parse`] does.
    /// A destination of 0.0.0.1 to 0.0.0.255 means a SOCKS4a domain
    /// follows the user ID.
    pub fn parse(b: &[u8]) -> Result<Option<(Socks4Request, usize)>, Error> {
        check_version(b, VERSION_4)?;
        let Some(&cmd) = b.get(1) else { return Ok(None) };
        let command = Socks4Command::from_code(cmd)?;
        if b.len() < 8 {
            return Ok(None);
        }
        let port = be16(b, 2);
        let ip = Ipv4Addr::new(b[4], b[5], b[6], b[7]);
        let Some(nul) = find_nul(b, 8, MAX_USER_ID)? else { return Ok(None) };
        // Nothing is copied until the whole request has come.
        let (destination, used) = match ip.octets() {
            [0, 0, 0, x] if x != 0 => {
                let Some(end) = find_nul(b, nul + 1, MAX_SOCKS4_DOMAIN)? else { return Ok(None) };
                (Socks4Destination::Domain(b[nul + 1..end].to_vec()), end + 1)
            }
            _ => (Socks4Destination::Ip(ip), nul + 1),
        };
        let user_id = b[8..nul].to_vec();
        Ok(Some((Socks4Request { command, port, destination, user_id }, used)))
    }

    /// The request's bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![VERSION_4, self.command.code()];
        out.extend_from_slice(&self.port.to_be_bytes());
        let domain = match &self.destination {
            Socks4Destination::Ip(ip) => {
                out.extend_from_slice(&ip.octets());
                match ip.octets() {
                    [0, 0, 0, x] if x != 0 => Some(&[][..]),
                    _ => None,
                }
            }
            Socks4Destination::Domain(d) => {
                out.extend_from_slice(&[0, 0, 0, 1]);
                Some(c_field(d, MAX_SOCKS4_DOMAIN))
            }
        };
        out.extend_from_slice(c_field(&self.user_id, MAX_USER_ID));
        out.push(0);
        if let Some(d) = domain {
            out.extend_from_slice(d);
            out.push(0);
        }
        out
    }
}

/// The result codes of a SOCKS4 reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Socks4Code {
    /// 90: request granted.
    Granted,
    /// 91: request rejected or failed.
    Rejected,
    /// 92: rejected because the proxy cannot reach identd on the client.
    NoIdentd,
    /// 93: rejected because identd reports a different user ID.
    IdentdMismatch,
    /// Any other code. An `Other` that holds one of the codes above is
    /// written as that code and reads back as the named variant.
    Other(u8),
}

impl Socks4Code {
    /// The code's number.
    pub fn code(self) -> u8 {
        match self {
            Socks4Code::Granted => 90,
            Socks4Code::Rejected => 91,
            Socks4Code::NoIdentd => 92,
            Socks4Code::IdentdMismatch => 93,
            Socks4Code::Other(c) => c,
        }
    }

    /// The code for number `c`.
    pub fn from_code(c: u8) -> Socks4Code {
        match c {
            90 => Socks4Code::Granted,
            91 => Socks4Code::Rejected,
            92 => Socks4Code::NoIdentd,
            93 => Socks4Code::IdentdMismatch,
            c => Socks4Code::Other(c),
        }
    }
}

/// A SOCKS4 reply. A BIND gets two, as in SOCKS5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Socks4Reply {
    /// Whether the request was granted.
    pub code: Socks4Code,
    /// For BIND, the port the proxy listens on or the inbound connection
    /// came from. Ignored for CONNECT.
    pub port: u16,
    /// The address that goes with the port.
    pub ip: Ipv4Addr,
}

/// The length of a SOCKS4 reply.
pub const SOCKS4_REPLY_LEN: usize = 8;

impl Socks4Reply {
    /// Reads the reply at the start of `b`, as [`Greeting::parse`] does.
    /// Its first byte must be [`VERSION_4_REPLY`].
    pub fn parse(b: &[u8]) -> Result<Option<(Socks4Reply, usize)>, Error> {
        check_version(b, VERSION_4_REPLY)?;
        if b.len() < SOCKS4_REPLY_LEN {
            return Ok(None);
        }
        let reply = Socks4Reply {
            code: Socks4Code::from_code(b[1]),
            port: be16(b, 2),
            ip: Ipv4Addr::new(b[4], b[5], b[6], b[7]),
        };
        Ok(Some((reply, SOCKS4_REPLY_LEN)))
    }

    /// The reply's bytes.
    pub fn to_bytes(&self) -> [u8; SOCKS4_REPLY_LEN] {
        let [p0, p1] = self.port.to_be_bytes();
        let [a, b, c, d] = self.ip.octets();
        [VERSION_4_REPLY, self.code.code(), p0, p1, a, b, c, d]
    }
}

/// The bytes a decoder holds, with the bounds every decoder keeps.
#[derive(Clone, Debug, Default)]
struct Buffer {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped in `feed` once they are half the buffer, so taking out many
    /// small messages costs time in proportion to their bytes.
    start: usize,
    /// Bytes were dropped because [`MAX_BUFFERED`] were held.
    overflowed: bool,
}

impl Buffer {
    fn feed(&mut self, bytes: &[u8]) {
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let room = MAX_BUFFERED.saturating_sub(self.held().len());
        if bytes.len() > room {
            self.overflowed = true;
        }
        self.buf.extend_from_slice(&bytes[..bytes.len().min(room)]);
    }

    fn held(&self) -> &[u8] {
        self.buf.get(self.start..).unwrap_or(&[])
    }

    fn take(&mut self, n: usize) {
        self.start = self.start.saturating_add(n).min(self.buf.len());
    }

    fn take_all(&mut self) -> Vec<u8> {
        let out = self.held().to_vec();
        self.clear();
        out
    }

    fn clear(&mut self) {
        self.buf = Vec::new();
        self.start = 0;
    }
}

/// A message a client sends, read by a [`ServerDecoder`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientMessage {
    /// A SOCKS5 greeting. Answer it with a [`Selection`], then call
    /// [`ServerDecoder::select`].
    Greeting(Greeting),
    /// A username and password. Answer with an [`AuthReply`], then call
    /// [`ServerDecoder::verified`].
    Auth(AuthRequest),
    /// A SOCKS5 request. Answer with a [`Reply`].
    Request(Request),
    /// A SOCKS4 or SOCKS4a request. Answer with a [`Socks4Reply`].
    Socks4(Socks4Request),
}

/// Where [`ClientMessages`] or a [`ServerDecoder`] is in the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerStage {
    /// Waiting for the client's first message: a SOCKS5 greeting or a
    /// SOCKS4 request.
    Greeting,
    /// Waiting for the world to choose a method with
    /// [`ClientMessages::select`] or [`ServerDecoder::select`].
    Selecting,
    /// Waiting for a username and password.
    Auth,
    /// Waiting for the world to say whether the login is good with
    /// [`ClientMessages::verified`] or [`ServerDecoder::verified`].
    Verifying,
    /// Waiting for a SOCKS5 request.
    Request,
    /// The handshake is over, or went on with a method this module does
    /// not read. The bytes that follow are the world's, through
    /// [`codec::Stream::into_parts`] or [`ServerDecoder::take_data`].
    Done,
    /// The proxy refused the client and closes the connection. The stream
    /// decoder ends; the legacy decoder drops further fed bytes.
    Closed,
    /// The client broke the protocol, or decoding failed. No tunnel handoff
    /// is allowed. The stream reports the error once; the legacy decoder repeats it.
    Failed,
}

/// Reads what a SOCKS client sends, for a world that plays a proxy. Feed
/// it the bytes a connection reads, in order, and take messages out until
/// it has none.
/// New code uses [`ClientMessages`] with [`codec::Stream`].
#[derive(Clone, Debug)]
pub struct ServerDecoder {
    buf: Buffer,
    stage: ServerStage,
    /// The methods the client's greeting offered.
    offered: MethodSet,
    failed: Option<Error>,
}

impl Default for ServerDecoder {
    fn default() -> ServerDecoder {
        ServerDecoder::new()
    }
}

impl ServerDecoder {
    /// A decoder waiting for a client's first message.
    pub fn new() -> ServerDecoder {
        ServerDecoder { buf: Buffer::default(), stage: ServerStage::Greeting, offered: MethodSet::default(), failed: None }
    }

    /// Where the decoder is in the handshake.
    pub fn stage(&self) -> ServerStage {
        self.stage
    }

    /// Adds bytes read from the connection. Once the decoder has failed or
    /// closed, they are dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if !matches!(self.stage, ServerStage::Failed | ServerStage::Closed) {
            self.buf.feed(bytes);
        }
    }

    /// The next whole message, if one has come. It returns `None` when it
    /// needs more bytes or is waiting for the world, and keeps returning
    /// the same error once the stream has broken.
    pub fn next_message(&mut self) -> Option<Result<ClientMessage, Error>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        let held = self.buf.held();
        let parsed = match self.stage {
            ServerStage::Greeting => match held.first() {
                None => Ok(None),
                Some(&VERSION_4) => Socks4Request::parse(held).map(|m| m.map(|(r, n)| (ClientMessage::Socks4(r), n))),
                Some(_) => Greeting::parse(held).map(|m| m.map(|(g, n)| (ClientMessage::Greeting(g), n))),
            },
            ServerStage::Auth => AuthRequest::parse(held).map(|m| m.map(|(a, n)| (ClientMessage::Auth(a), n))),
            ServerStage::Request => Request::parse(held).map(|m| m.map(|(r, n)| (ClientMessage::Request(r), n))),
            _ => Ok(None),
        };
        match parsed {
            Ok(Some((message, used))) => {
                self.buf.take(used);
                self.stage = match &message {
                    ClientMessage::Greeting(g) => {
                        self.offered = MethodSet::of(&g.methods);
                        ServerStage::Selecting
                    }
                    ClientMessage::Auth(_) => ServerStage::Verifying,
                    ClientMessage::Request(_) | ClientMessage::Socks4(_) => ServerStage::Done,
                };
                Some(Ok(message))
            }
            Ok(None) if self.buf.overflowed && self.stage != ServerStage::Closed => {
                Some(Err(self.fail(Error::Overflow)))
            }
            Ok(None) => None,
            Err(e) => Some(Err(self.fail(e))),
        }
    }

    fn fail(&mut self, e: Error) -> Error {
        self.failed = Some(e);
        self.stage = ServerStage::Failed;
        self.buf.clear();
        e
    }

    /// Tells the decoder which method the proxy chose after a greeting:
    /// a login comes next for [`Method::UsernamePassword`], a request for
    /// [`Method::NoAuth`], nothing for [`Method::NoAcceptable`], and for
    /// any other method the stream is the world's. The method is judged by
    /// its code, the byte a [`Selection`] writes, so `Method::Other(2)`
    /// acts as [`Method::UsernamePassword`].
    ///
    /// It returns whether the decoder took the choice. RFC 1928 section 3
    /// lets the proxy choose only a method the greeting offered, or
    /// [`Method::NoAcceptable`]; for any other method, or in any stage but
    /// [`ServerStage::Selecting`], it does nothing and returns false.
    pub fn select(&mut self, method: Method) -> bool {
        if self.stage != ServerStage::Selecting || !self.offered.allows(method) {
            return false;
        }
        self.stage = match Method::from_code(method.code()) {
            Method::NoAuth => ServerStage::Request,
            Method::UsernamePassword => ServerStage::Auth,
            Method::NoAcceptable => ServerStage::Closed,
            Method::Gssapi | Method::Other(_) => ServerStage::Done,
        };
        if self.stage == ServerStage::Closed {
            self.buf.clear();
        }
        true
    }

    /// Tells the decoder whether a login was good: a request comes next if
    /// it was, and the connection closes if not. In any stage but
    /// [`ServerStage::Verifying`] it does nothing.
    pub fn verified(&mut self, good: bool) {
        if self.stage == ServerStage::Verifying {
            if good {
                self.stage = ServerStage::Request;
            } else {
                self.stage = ServerStage::Closed;
                self.buf.clear();
            }
        }
    }

    /// Takes out the bytes held after the handshake: the start of the
    /// tunneled stream. It returns nothing before [`ServerStage::Done`].
    /// If bytes were dropped past [`MAX_BUFFERED`], it returns nothing and
    /// the decoder fails with [`Error::Overflow`], so the stream it hands
    /// out never has a gap.
    /// New code uses [`ClientMessages`] and [`codec::Stream::into_parts`] or `swap`.
    pub fn take_data(&mut self) -> Vec<u8> {
        if self.stage != ServerStage::Done {
            return Vec::new();
        }
        if self.buf.overflowed {
            self.fail(Error::Overflow);
            return Vec::new();
        }
        self.buf.take_all()
    }

    /// How many bytes are held, not yet taken out.
    pub fn buffered(&self) -> usize {
        self.buf.held().len()
    }
}

/// A message a proxy sends, read by a [`ClientDecoder`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerMessage {
    /// The method the proxy chose.
    Selection(Selection),
    /// The answer to a login.
    Auth(AuthReply),
    /// A SOCKS5 reply.
    Reply(Reply),
    /// A SOCKS4 reply.
    Socks4(Socks4Reply),
}

/// Where [`ServerMessages`] or a [`ClientDecoder`] is in the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientStage {
    /// Waiting for the proxy's method selection.
    Selection,
    /// Waiting for the answer to a login.
    Auth,
    /// Waiting for the reply to the request.
    Reply,
    /// Waiting for a BIND's second reply, sent when the inbound connection
    /// comes.
    SecondReply,
    /// The handshake is over, or went on with a method this module does
    /// not read. The bytes that follow are the world's, through
    /// [`codec::Stream::into_parts`] or [`ClientDecoder::take_data`].
    Done,
    /// The proxy refused, and closes the connection. The stream decoder
    /// ends; the legacy decoder drops further fed bytes.
    Closed,
    /// The proxy broke the protocol, or decoding failed. No tunnel handoff
    /// is allowed. The stream reports the error once; the legacy decoder repeats it.
    Failed,
}

/// Reads what a SOCKS proxy sends, for a world that plays a client. Feed
/// it the bytes a connection reads, in order, and take messages out until
/// it has none.
/// New code uses [`ServerMessages`] with [`codec::Stream`].
#[derive(Clone, Debug)]
pub struct ClientDecoder {
    buf: Buffer,
    stage: ClientStage,
    socks4: bool,
    bind: bool,
    /// The methods the client offered, when the decoder checks the
    /// proxy's choice against them.
    offered: Option<MethodSet>,
    failed: Option<Error>,
}

impl ClientDecoder {
    /// A decoder for a SOCKS5 client that sent a greeting and will send a
    /// request with `command`. It takes whatever method the proxy chooses;
    /// [`ClientDecoder::socks5_offering`] also checks it was offered.
    pub fn socks5(command: Command) -> ClientDecoder {
        ClientDecoder {
            buf: Buffer::default(),
            stage: ClientStage::Selection,
            socks4: false,
            bind: command == Command::Bind,
            offered: None,
            failed: None,
        }
    }

    /// A decoder for a SOCKS5 client that sent a greeting offering
    /// `methods` and will send a request with `command`. If the proxy
    /// chooses a method not in `methods`, other than
    /// [`Method::NoAcceptable`], the decoder fails with [`Error::Method`].
    /// Only the first [`MAX_METHODS`] count, as a [`Greeting`] carries no
    /// more.
    pub fn socks5_offering(command: Command, methods: &[Method]) -> ClientDecoder {
        ClientDecoder { offered: Some(MethodSet::of(methods)), ..ClientDecoder::socks5(command) }
    }

    /// A decoder for a SOCKS4 client that sent a request with `command`.
    pub fn socks4(command: Socks4Command) -> ClientDecoder {
        ClientDecoder {
            buf: Buffer::default(),
            stage: ClientStage::Reply,
            socks4: true,
            bind: command == Socks4Command::Bind,
            offered: None,
            failed: None,
        }
    }

    /// Where the decoder is in the handshake.
    pub fn stage(&self) -> ClientStage {
        self.stage
    }

    /// Adds bytes read from the connection, as [`ServerDecoder::feed`]
    /// does.
    pub fn feed(&mut self, bytes: &[u8]) {
        if !matches!(self.stage, ClientStage::Failed | ClientStage::Closed) {
            self.buf.feed(bytes);
        }
    }

    /// The next whole message, as [`ServerDecoder::next_message`] gives.
    /// The decoder moves on by itself: after a selection to the login or
    /// the reply, after a failed login or reply to closed, and after the
    /// last reply to done.
    pub fn next_message(&mut self) -> Option<Result<ServerMessage, Error>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        let held = self.buf.held();
        let parsed = match self.stage {
            ClientStage::Selection => Selection::parse(held).map(|m| m.map(|(s, n)| (ServerMessage::Selection(s), n))),
            ClientStage::Auth => AuthReply::parse(held).map(|m| m.map(|(a, n)| (ServerMessage::Auth(a), n))),
            ClientStage::Reply | ClientStage::SecondReply if self.socks4 => {
                Socks4Reply::parse(held).map(|m| m.map(|(r, n)| (ServerMessage::Socks4(r), n)))
            }
            ClientStage::Reply | ClientStage::SecondReply => {
                Reply::parse(held).map(|m| m.map(|(r, n)| (ServerMessage::Reply(r), n)))
            }
            _ => Ok(None),
        };
        if let Ok(Some((ServerMessage::Selection(s), _))) = &parsed
            && let Some(offered) = self.offered
            && !offered.allows(s.method)
        {
            return Some(Err(self.fail(Error::Method(s.method.code()))));
        }
        match parsed {
            Ok(Some((message, used))) => {
                self.buf.take(used);
                let granted = match &message {
                    ServerMessage::Selection(s) => {
                        self.stage = match Method::from_code(s.method.code()) {
                            Method::NoAuth => ClientStage::Reply,
                            Method::UsernamePassword => ClientStage::Auth,
                            Method::NoAcceptable => ClientStage::Closed,
                            Method::Gssapi | Method::Other(_) => ClientStage::Done,
                        };
                        true
                    }
                    ServerMessage::Auth(a) => {
                        self.stage = ClientStage::Reply;
                        a.success()
                    }
                    ServerMessage::Reply(r) => {
                        self.next_reply_stage();
                        r.code.code() == ReplyCode::Succeeded.code()
                    }
                    ServerMessage::Socks4(r) => {
                        self.next_reply_stage();
                        r.code.code() == Socks4Code::Granted.code()
                    }
                };
                if !granted || self.stage == ClientStage::Closed {
                    self.stage = ClientStage::Closed;
                    self.buf.clear();
                }
                Some(Ok(message))
            }
            Ok(None) if self.buf.overflowed && self.stage != ClientStage::Closed => {
                Some(Err(self.fail(Error::Overflow)))
            }
            Ok(None) => None,
            Err(e) => Some(Err(self.fail(e))),
        }
    }

    fn next_reply_stage(&mut self) {
        self.stage =
            if self.bind && self.stage == ClientStage::Reply { ClientStage::SecondReply } else { ClientStage::Done };
    }

    fn fail(&mut self, e: Error) -> Error {
        self.failed = Some(e);
        self.stage = ClientStage::Failed;
        self.buf.clear();
        e
    }

    /// Takes out the bytes held after the handshake, as
    /// [`ServerDecoder::take_data`] does.
    /// New code uses [`ServerMessages`] and [`codec::Stream::into_parts`] or `swap`.
    pub fn take_data(&mut self) -> Vec<u8> {
        if self.stage != ClientStage::Done {
            return Vec::new();
        }
        if self.buf.overflowed {
            self.fail(Error::Overflow);
            return Vec::new();
        }
        self.buf.take_all()
    }

    /// How many bytes are held, not yet taken out.
    pub fn buffered(&self) -> usize {
        self.buf.held().len()
    }
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Address {
        Address::Ipv4(Ipv4Addr::new(a, b, c, d))
    }

    /// A sample of every message, with its bytes, for the prefix and round
    /// trip tests.
    fn samples() -> Vec<Vec<u8>> {
        let mut out = vec![
            Greeting { methods: vec![Method::NoAuth, Method::UsernamePassword] }.to_bytes(),
            Selection { method: Method::UsernamePassword }.to_bytes().to_vec(),
            AuthRequest { username: b"alice".to_vec(), password: b"secret".to_vec() }.to_bytes(),
            AuthReply { status: 0 }.to_bytes().to_vec(),
        ];
        for address in [v4(10, 0, 0, 1), Address::Ipv6(Ipv6Addr::LOCALHOST), Address::Domain(b"example.com".to_vec())] {
            for command in [Command::Connect, Command::Bind, Command::UdpAssociate] {
                out.push(Request { command, address: address.clone(), port: 443 }.to_bytes());
            }
            out.push(Reply { code: ReplyCode::Succeeded, address: address.clone(), port: 9 }.to_bytes());
        }
        out
    }

    fn sample_socks4() -> Vec<Socks4Request> {
        vec![
            Socks4Request {
                command: Socks4Command::Connect,
                port: 80,
                destination: Socks4Destination::Ip(Ipv4Addr::new(66, 102, 7, 99)),
                user_id: b"fred".to_vec(),
            },
            Socks4Request {
                command: Socks4Command::Bind,
                port: 21,
                destination: Socks4Destination::Domain(b"ftp.example.org".to_vec()),
                user_id: Vec::new(),
            },
        ]
    }

    #[test]
    fn rfc1928_greeting_and_selection() {
        // A client that offers no login and username/password.
        assert_eq!(
            Greeting::parse(&[5, 2, 0, 2]),
            Ok(Some((Greeting { methods: vec![Method::NoAuth, Method::UsernamePassword] }, 4)))
        );
        assert_eq!(Selection::parse(&[5, 2, 9]), Ok(Some((Selection { method: Method::UsernamePassword }, 2))));
        assert_eq!(Selection { method: Method::NoAcceptable }.to_bytes(), [5, 0xff]);
        assert_eq!(Greeting::parse(&[5, 0]), Ok(Some((Greeting { methods: vec![] }, 2))));
        for c in 0..=255u8 {
            assert_eq!(Method::from_code(c).code(), c);
            assert_eq!(ReplyCode::from_code(c).code(), c);
            assert_eq!(Socks4Code::from_code(c).code(), c);
        }
    }

    #[test]
    fn rfc1929_login() {
        let bytes = [1, 5, b'a', b'l', b'i', b'c', b'e', 3, b'p', b'w', b'd'];
        let (auth, used) = AuthRequest::parse(&bytes).unwrap().unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(auth, AuthRequest { username: b"alice".to_vec(), password: b"pwd".to_vec() });
        assert_eq!(auth.to_bytes(), bytes);
        assert_eq!(AuthReply::parse(&[1, 0]), Ok(Some((AuthReply { status: 0 }, 2))));
        assert!(!AuthReply { status: 1 }.success());
        assert_eq!(AuthReply::parse(&[5, 0]), Err(Error::Version(5)));
    }

    #[test]
    fn rfc1928_requests_and_replies() {
        // CONNECT 192.168.1.2 port 8080.
        let bytes = [5, 1, 0, 1, 192, 168, 1, 2, 0x1f, 0x90];
        let req = Request { command: Command::Connect, address: v4(192, 168, 1, 2), port: 8080 };
        assert_eq!(Request::parse(&bytes), Ok(Some((req.clone(), 10))));
        assert_eq!(req.to_bytes(), bytes);
        // UDP ASSOCIATE from [::1] port 53.
        let mut bytes = vec![5, 3, 0, 4];
        bytes.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        bytes.extend_from_slice(&[0, 53]);
        let req = Request { command: Command::UdpAssociate, address: Address::Ipv6(Ipv6Addr::LOCALHOST), port: 53 };
        assert_eq!(Request::parse(&bytes), Ok(Some((req, 22))));
        // A failure reply.
        assert_eq!(Reply::failure(ReplyCode::HostUnreachable).to_bytes(), [5, 4, 0, 1, 0, 0, 0, 0, 0, 0]);
        // A BIND reply with a domain.
        let bytes = [5, 0, 0, 3, 1, b'h', 0, 7];
        assert_eq!(
            Reply::parse(&bytes),
            Ok(Some((Reply { code: ReplyCode::Succeeded, address: Address::Domain(b"h".to_vec()), port: 7 }, 8)))
        );
    }

    #[test]
    fn udp_header() {
        let header = UdpHeader { fragment: 0, address: v4(8, 8, 8, 8), port: 53 };
        let datagram = header.datagram(b"query");
        assert_eq!(datagram, [0, 0, 0, 1, 8, 8, 8, 8, 0, 53, b'q', b'u', b'e', b'r', b'y']);
        assert_eq!(UdpHeader::parse(&datagram), Ok((header.clone(), &b"query"[..])));
        for n in 0..10 {
            assert_eq!(UdpHeader::parse(&datagram[..n]), Err(Error::Truncated), "{n} bytes");
        }
        assert_eq!(UdpHeader::parse(&datagram[..10]), Ok((header.clone(), &b""[..])));
        assert_eq!(UdpHeader::parse(&[0, 1, 0, 1, 0, 0, 0, 0, 0, 0]), Err(Error::Reserved(1)));
        assert_eq!(UdpHeader::parse(&[0, 0, 0, 2, 0, 0, 0, 0, 0, 0]), Err(Error::AddressType(2)));
        // The writer caps the datagram.
        let big = header.datagram(&vec![7; 100_000]);
        assert_eq!(big.len(), MAX_DATAGRAM);
        assert!(UdpHeader::parse(&big).is_ok());
    }

    #[test]
    fn socks4_examples() {
        // CONNECT 66.102.7.99 port 80 as user "fred".
        let bytes = [4, 1, 0, 80, 66, 102, 7, 99, b'f', b'r', b'e', b'd', 0];
        let req = &sample_socks4()[0];
        assert_eq!(Socks4Request::parse(&bytes), Ok(Some((req.clone(), 13))));
        assert_eq!(req.to_bytes(), bytes);
        // SOCKS4a: IP 0.0.0.1, then the user ID and the domain.
        let mut bytes = vec![4, 2, 0, 21, 0, 0, 0, 1, 0];
        bytes.extend_from_slice(b"ftp.example.org\0");
        let req = &sample_socks4()[1];
        assert_eq!(Socks4Request::parse(&bytes), Ok(Some((req.clone(), bytes.len()))));
        assert_eq!(req.to_bytes(), bytes);
        // Any 0.0.0.x with x not 0 starts a domain; 0.0.0.0 does not.
        assert_eq!(
            Socks4Request::parse(&[4, 1, 0, 1, 0, 0, 0, 9, 0, b'a', 0]).unwrap().unwrap().0.destination,
            Socks4Destination::Domain(b"a".to_vec())
        );
        assert_eq!(
            Socks4Request::parse(&[4, 1, 0, 1, 0, 0, 0, 0, 0]).unwrap().unwrap().0.destination,
            Socks4Destination::Ip(Ipv4Addr::UNSPECIFIED)
        );
        // Replies.
        let reply = Socks4Reply { code: Socks4Code::Granted, port: 0x1234, ip: Ipv4Addr::new(1, 2, 3, 4) };
        assert_eq!(reply.to_bytes(), [0, 90, 0x12, 0x34, 1, 2, 3, 4]);
        assert_eq!(Socks4Reply::parse(&reply.to_bytes()), Ok(Some((reply, 8))));
    }

    #[test]
    fn socks4_writers_keep_what_reads_back() {
        // An IP that looks like the SOCKS4a marker becomes an empty domain.
        let req = Socks4Request {
            command: Socks4Command::Connect,
            port: 1,
            destination: Socks4Destination::Ip(Ipv4Addr::new(0, 0, 0, 7)),
            user_id: vec![],
        };
        let (back, _) = Socks4Request::parse(&req.to_bytes()).unwrap().unwrap();
        assert_eq!(back.destination, Socks4Destination::Domain(vec![]));
        // Zero bytes cut the fields, and long fields are capped.
        let req = Socks4Request {
            command: Socks4Command::Connect,
            port: 1,
            destination: Socks4Destination::Domain(vec![b'x'; 900]),
            user_id: b"ab\0cd".to_vec(),
        };
        let (back, used) = Socks4Request::parse(&req.to_bytes()).unwrap().unwrap();
        assert_eq!(used, req.to_bytes().len());
        assert_eq!(back.user_id, b"ab");
        assert_eq!(back.destination, Socks4Destination::Domain(vec![b'x'; MAX_SOCKS4_DOMAIN]));
        let req = Socks4Request {
            command: Socks4Command::Bind,
            port: 1,
            destination: Socks4Destination::Domain(vec![]),
            user_id: vec![b'u'; 900],
        };
        let bytes = req.to_bytes();
        assert_eq!(bytes.len(), 8 + MAX_USER_ID + 2);
        assert!(Socks4Request::parse(&bytes).unwrap().is_some());
        let longest = Socks4Request {
            command: Socks4Command::Bind,
            port: 1,
            destination: Socks4Destination::Domain(vec![1; 900]),
            user_id: vec![1; 900],
        };
        assert_eq!(longest.to_bytes().len(), MAX_MESSAGE);
    }

    #[test]
    fn writers_cap_what_they_write() {
        let g = Greeting { methods: vec![Method::NoAuth; 1000] }.to_bytes();
        assert_eq!(g.len(), 2 + MAX_METHODS);
        assert_eq!(Greeting::parse(&g).unwrap().unwrap().0.methods.len(), MAX_METHODS);
        let a = AuthRequest { username: vec![b'u'; 300], password: vec![b'p'; 300] }.to_bytes();
        assert_eq!(a.len(), 3 + MAX_USERNAME + MAX_PASSWORD);
        let (back, _) = AuthRequest::parse(&a).unwrap().unwrap();
        assert_eq!(back.username.len(), MAX_USERNAME);
        let r = Request { command: Command::Connect, address: Address::Domain(vec![b'd'; 400]), port: 1 }.to_bytes();
        let (back, _) = Request::parse(&r).unwrap().unwrap();
        assert_eq!(back.address, Address::Domain(vec![b'd'; MAX_DOMAIN]));
    }

    #[test]
    fn errors() {
        assert_eq!(Greeting::parse(&[4, 1, 0]), Err(Error::Version(4)));
        assert_eq!(Selection::parse(&[0]), Err(Error::Version(0)));
        assert_eq!(AuthRequest::parse(&[5]), Err(Error::Version(5)));
        assert_eq!(Request::parse(&[5, 4]), Err(Error::Command(4)));
        assert_eq!(Request::parse(&[5, 1, 1]), Err(Error::Reserved(1)));
        assert_eq!(Request::parse(&[5, 1, 0, 2]), Err(Error::AddressType(2)));
        assert_eq!(Reply::parse(&[5, 0, 3]), Err(Error::Reserved(3)));
        assert_eq!(Reply::parse(&[5, 0, 0, 9]), Err(Error::AddressType(9)));
        assert_eq!(Reply::parse(&[4]), Err(Error::Version(4)));
        assert_eq!(Socks4Request::parse(&[5]), Err(Error::Version(5)));
        assert_eq!(Socks4Request::parse(&[4, 3]), Err(Error::Command(3)));
        assert_eq!(Socks4Reply::parse(&[4, 90]), Err(Error::Version(4)));
        // A user ID with no end.
        let mut long = vec![4, 1, 0, 80, 1, 2, 3, 4];
        long.extend_from_slice(&[b'u'; MAX_USER_ID]);
        assert_eq!(Socks4Request::parse(&long), Ok(None));
        long.push(b'u');
        assert_eq!(Socks4Request::parse(&long), Err(Error::FieldTooLong));
        // A SOCKS4a domain with no end.
        let mut long = vec![4, 1, 0, 80, 0, 0, 0, 1, 0];
        long.extend_from_slice(&[b'd'; MAX_SOCKS4_DOMAIN + 1]);
        assert_eq!(Socks4Request::parse(&long), Err(Error::FieldTooLong));
        // Reply codes for errors.
        assert_eq!(Error::Command(9).reply_code(), ReplyCode::CommandNotSupported);
        assert_eq!(Error::AddressType(9).reply_code(), ReplyCode::AddressTypeNotSupported);
        assert_eq!(Error::Reserved(1).reply_code(), ReplyCode::GeneralFailure);
        for e in [
            Error::Version(1),
            Error::Command(1),
            Error::AddressType(1),
            Error::Reserved(1),
            Error::FieldTooLong,
            Error::Truncated,
            Error::Overflow,
            Error::Method(1),
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn every_prefix_is_incomplete() {
        type Parser = fn(&[u8]) -> Result<Option<usize>, Error>;
        let parsers: [Parser; 8] = [
            |b| Greeting::parse(b).map(|m| m.map(|(_, n)| n)),
            |b| Selection::parse(b).map(|m| m.map(|(_, n)| n)),
            |b| AuthRequest::parse(b).map(|m| m.map(|(_, n)| n)),
            |b| AuthReply::parse(b).map(|m| m.map(|(_, n)| n)),
            |b| Request::parse(b).map(|m| m.map(|(_, n)| n)),
            |b| Reply::parse(b).map(|m| m.map(|(_, n)| n)),
            |b| Socks4Request::parse(b).map(|m| m.map(|(_, n)| n)),
            |b| Socks4Reply::parse(b).map(|m| m.map(|(_, n)| n)),
        ];
        let mut all = samples();
        all.extend(sample_socks4().iter().map(|r| r.to_bytes()));
        all.push(Socks4Reply { code: Socks4Code::Rejected, port: 0, ip: Ipv4Addr::UNSPECIFIED }.to_bytes().to_vec());
        let mut checked = 0;
        for bytes in &all {
            for parse in &parsers {
                // Only the parsers that read the whole message.
                if parse(bytes) != Ok(Some(bytes.len())) {
                    continue;
                }
                checked += 1;
                for n in 0..bytes.len() {
                    assert_eq!(parse(&bytes[..n]), Ok(None), "{bytes:?} cut to {n}");
                }
            }
        }
        assert!(checked >= all.len());
    }

    #[test]
    fn round_trips() {
        for bytes in samples() {
            if let Ok(Some((g, n))) = Greeting::parse(&bytes)
                && n == bytes.len() && bytes[1] as usize == g.methods.len() {
                    assert_eq!(g.to_bytes(), bytes);
                }
            if let Ok(Some((r, n))) = Request::parse(&bytes) {
                assert_eq!(n, bytes.len());
                assert_eq!(r.to_bytes(), bytes);
            }
            if let Ok(Some((r, n))) = Reply::parse(&bytes) {
                assert_eq!(n, bytes.len());
                assert_eq!(r.to_bytes(), bytes);
            }
        }
        for req in sample_socks4() {
            assert_eq!(Socks4Request::parse(&req.to_bytes()).unwrap().unwrap().0, req);
        }
    }

    #[test]
    fn server_decoder_with_login() {
        let mut d = ServerDecoder::new();
        assert_eq!(d.stage(), ServerStage::Greeting);
        // A client that sends everything at once.
        let mut stream = vec![5, 1, 2];
        stream.extend(AuthRequest { username: b"u".to_vec(), password: b"p".to_vec() }.to_bytes());
        stream.extend(Request { command: Command::Bind, address: v4(0, 0, 0, 0), port: 0 }.to_bytes());
        stream.extend_from_slice(b"tail");
        d.feed(&stream);
        assert_eq!(
            d.next_message(),
            Some(Ok(ClientMessage::Greeting(Greeting { methods: vec![Method::UsernamePassword] })))
        );
        assert_eq!(d.next_message(), None);
        assert_eq!(d.take_data(), b"");
        d.verified(true); // ignored: not verifying yet
        d.select(Method::UsernamePassword);
        assert_eq!(d.stage(), ServerStage::Auth);
        assert!(matches!(d.next_message(), Some(Ok(ClientMessage::Auth(_)))));
        assert_eq!(d.stage(), ServerStage::Verifying);
        assert_eq!(d.next_message(), None);
        d.verified(true);
        assert!(matches!(d.next_message(), Some(Ok(ClientMessage::Request(_)))));
        assert_eq!(d.stage(), ServerStage::Done);
        assert_eq!(d.next_message(), None);
        assert_eq!(d.buffered(), 4);
        d.feed(b"!");
        assert_eq!(d.take_data(), b"tail!");
    }

    #[test]
    fn server_decoder_refusals_and_failures() {
        let mut d = ServerDecoder::new();
        d.feed(&[5, 1, 0]);
        d.next_message().unwrap().unwrap();
        d.select(Method::NoAcceptable);
        assert_eq!(d.stage(), ServerStage::Closed);
        d.feed(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(d.next_message(), None);
        assert_eq!(d.buffered(), 0);

        let mut d = ServerDecoder::new();
        d.feed(&[5, 1, 2]);
        d.next_message().unwrap().unwrap();
        d.select(Method::UsernamePassword);
        d.feed(&[1, 0, 0]);
        d.next_message().unwrap().unwrap();
        d.verified(false);
        assert_eq!(d.stage(), ServerStage::Closed);

        let mut d = ServerDecoder::new();
        d.feed(&[5, 1, 1]);
        d.next_message().unwrap().unwrap();
        d.select(Method::Gssapi);
        assert_eq!(d.stage(), ServerStage::Done);

        let mut d = ServerDecoder::new();
        d.feed(&[7]);
        assert_eq!(d.next_message(), Some(Err(Error::Version(7))));
        d.feed(&[5, 1, 0]);
        assert_eq!(d.next_message(), Some(Err(Error::Version(7))));
        assert_eq!(d.stage(), ServerStage::Failed);
        assert_eq!(d.buffered(), 0);

        // A request with a command the proxy does not know.
        let mut d = ServerDecoder::new();
        d.feed(&[5, 1, 0, 5, 9]);
        d.next_message().unwrap().unwrap();
        d.select(Method::NoAuth);
        let e = d.next_message().unwrap().unwrap_err();
        assert_eq!(e.reply_code(), ReplyCode::CommandNotSupported);

        // Too many bytes while waiting for the world.
        let mut d = ServerDecoder::new();
        d.feed(&[5, 1, 0]);
        d.feed(&vec![0; MAX_BUFFERED]);
        assert!(matches!(d.next_message(), Some(Ok(ClientMessage::Greeting(_)))));
        assert_eq!(d.next_message(), Some(Err(Error::Overflow)));
    }

    #[test]
    fn server_decoder_socks4() {
        let mut d = ServerDecoder::new();
        let mut stream = sample_socks4()[1].to_bytes();
        stream.extend_from_slice(b"data");
        for b in &stream {
            d.feed(std::slice::from_ref(b));
        }
        assert_eq!(d.next_message(), Some(Ok(ClientMessage::Socks4(sample_socks4()[1].clone()))));
        assert_eq!(d.stage(), ServerStage::Done);
        assert_eq!(d.take_data(), b"data");
    }

    #[test]
    fn client_decoder() {
        // SOCKS5 BIND with a login: selection, login, two replies.
        let mut d = ClientDecoder::socks5(Command::Bind);
        let first = Reply { code: ReplyCode::Succeeded, address: v4(1, 1, 1, 1), port: 5000 };
        let second = Reply { code: ReplyCode::Succeeded, address: v4(2, 2, 2, 2), port: 6000 };
        let mut stream = vec![5, 2, 1, 0];
        stream.extend(first.to_bytes());
        stream.extend(second.to_bytes());
        stream.push(b'x');
        for b in &stream {
            d.feed(std::slice::from_ref(b));
        }
        assert_eq!(
            d.next_message(),
            Some(Ok(ServerMessage::Selection(Selection { method: Method::UsernamePassword })))
        );
        assert_eq!(d.stage(), ClientStage::Auth);
        assert_eq!(d.next_message(), Some(Ok(ServerMessage::Auth(AuthReply { status: 0 }))));
        assert_eq!(d.next_message(), Some(Ok(ServerMessage::Reply(first))));
        assert_eq!(d.stage(), ClientStage::SecondReply);
        assert_eq!(d.next_message(), Some(Ok(ServerMessage::Reply(second))));
        assert_eq!(d.stage(), ClientStage::Done);
        assert_eq!(d.take_data(), b"x");

        // A failed CONNECT closes.
        let mut d = ClientDecoder::socks5(Command::Connect);
        d.feed(&[5, 0]);
        d.feed(&Reply::failure(ReplyCode::ConnectionRefused).to_bytes());
        d.next_message().unwrap().unwrap();
        assert!(matches!(d.next_message(), Some(Ok(ServerMessage::Reply(_)))));
        assert_eq!(d.stage(), ClientStage::Closed);

        // A refused login closes, and so does no acceptable method.
        let mut d = ClientDecoder::socks5(Command::Connect);
        d.feed(&[5, 2, 1, 1]);
        d.next_message().unwrap().unwrap();
        d.next_message().unwrap().unwrap();
        assert_eq!(d.stage(), ClientStage::Closed);
        let mut d = ClientDecoder::socks5(Command::Connect);
        d.feed(&[5, 0xff]);
        d.next_message().unwrap().unwrap();
        assert_eq!(d.stage(), ClientStage::Closed);

        // SOCKS4 BIND, then a SOCKS4 rejection.
        let mut d = ClientDecoder::socks4(Socks4Command::Bind);
        let ok = Socks4Reply { code: Socks4Code::Granted, port: 1, ip: Ipv4Addr::new(3, 3, 3, 3) };
        d.feed(&ok.to_bytes());
        d.feed(&ok.to_bytes());
        assert_eq!(d.next_message(), Some(Ok(ServerMessage::Socks4(ok))));
        assert_eq!(d.stage(), ClientStage::SecondReply);
        assert_eq!(d.next_message(), Some(Ok(ServerMessage::Socks4(ok))));
        assert_eq!(d.stage(), ClientStage::Done);
        let mut d = ClientDecoder::socks4(Socks4Command::Connect);
        d.feed(&[0, 91, 0, 0, 0, 0, 0, 0]);
        d.next_message().unwrap().unwrap();
        assert_eq!(d.stage(), ClientStage::Closed);

        // A proxy that breaks the protocol.
        let mut d = ClientDecoder::socks5(Command::Connect);
        d.feed(&[4, 0]);
        assert_eq!(d.next_message(), Some(Err(Error::Version(4))));
        assert_eq!(d.stage(), ClientStage::Failed);
        assert_eq!(d.next_message(), Some(Err(Error::Version(4))));
    }

    /// A small deterministic generator, so the fuzz loop runs the same
    /// every time.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn below(&mut self, n: u32) -> u32 {
            self.next() % n
        }
    }

    fn drain_server(d: &mut ServerDecoder, out: &mut Vec<Result<ClientMessage, Error>>) {
        // A broken stream gives its error once here, however it was fed.
        if matches!(out.last(), Some(Err(_))) {
            return;
        }
        while let Some(m) = d.next_message() {
            let stop = m.is_err();
            if let Ok(ClientMessage::Greeting(g)) = &m {
                let method = if g.methods.contains(&Method::UsernamePassword) {
                    Method::UsernamePassword
                } else if g.methods.contains(&Method::NoAuth) {
                    Method::NoAuth
                } else {
                    Method::NoAcceptable
                };
                assert!(d.select(method));
            }
            if let Ok(ClientMessage::Auth(a)) = &m {
                d.verified(a.username != b"bad");
            }
            out.push(m);
            if stop {
                break;
            }
        }
    }

    fn drain_client(d: &mut ClientDecoder, out: &mut Vec<Result<ServerMessage, Error>>) {
        // A broken stream gives its error once here, however it was fed.
        if matches!(out.last(), Some(Err(_))) {
            return;
        }
        while let Some(m) = d.next_message() {
            let stop = m.is_err();
            out.push(m);
            if stop {
                break;
            }
        }
    }

    fn check_round_trips(b: &[u8]) {
        if let Ok(Some((m, n))) = Greeting::parse(b) {
            assert_eq!(m.to_bytes(), b[..n]);
        }
        if let Ok(Some((m, n))) = Selection::parse(b) {
            assert_eq!(m.to_bytes(), b[..n]);
        }
        if let Ok(Some((m, n))) = AuthRequest::parse(b) {
            assert_eq!(m.to_bytes(), b[..n]);
        }
        if let Ok(Some((m, n))) = AuthReply::parse(b) {
            assert_eq!(m.to_bytes(), b[..n]);
        }
        if let Ok(Some((m, n))) = Request::parse(b) {
            assert_eq!(m.to_bytes(), b[..n]);
        }
        if let Ok(Some((m, n))) = Reply::parse(b) {
            assert_eq!(m.to_bytes(), b[..n]);
        }
        if let Ok(Some((m, _))) = Socks4Request::parse(b) {
            let bytes = m.to_bytes();
            assert_eq!(Socks4Request::parse(&bytes), Ok(Some((m, bytes.len()))));
        }
        if let Ok(Some((m, n))) = Socks4Reply::parse(b) {
            assert_eq!(m.to_bytes(), b[..n]);
        }
        if let Ok((h, payload)) = UdpHeader::parse(b) {
            assert_eq!(h.datagram(payload), b);
        }
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg(0x50c4_5f00);
        let mut seeds = samples();
        seeds.extend(sample_socks4().iter().map(|r| r.to_bytes()));
        for round in 0..6000 {
            // Half the buffers are messages, joined and mutated; the rest
            // are random bytes with a likely first byte.
            let mut b = Vec::new();
            if round % 2 == 0 {
                for _ in 0..1 + rng.below(4) {
                    b.extend_from_slice(&seeds[rng.below(seeds.len() as u32) as usize]);
                }
                for _ in 0..rng.below(4) {
                    if b.is_empty() {
                        break;
                    }
                    let i = rng.below(b.len() as u32) as usize;
                    b[i] = rng.next() as u8;
                }
                b.truncate(rng.below(b.len() as u32 + 1) as usize + b.len() / 2);
            } else {
                let len = rng.below(80) as usize;
                b.extend((0..len).map(|_| [0u8, 1, 3, 4, 5, rng.next() as u8][rng.below(6) as usize]));
            }
            for start in 0..b.len().min(4) {
                check_round_trips(&b[start..]);
            }

            // The server decoder: all at once, and a byte at a time.
            let mut whole = ServerDecoder::new();
            whole.feed(&b);
            let mut got = Vec::new();
            drain_server(&mut whole, &mut got);
            let mut bytewise = ServerDecoder::new();
            let mut again = Vec::new();
            for byte in &b {
                bytewise.feed(std::slice::from_ref(byte));
                drain_server(&mut bytewise, &mut again);
            }
            assert_eq!(got, again, "{b:?}");
            assert_eq!(whole.stage(), bytewise.stage());
            assert_eq!(whole.take_data(), bytewise.take_data());
            assert!(whole.buffered() <= MAX_BUFFERED);

            // The client decoders.
            for make in [
                || ClientDecoder::socks5(Command::Connect),
                || ClientDecoder::socks5(Command::Bind),
                || ClientDecoder::socks4(Socks4Command::Bind),
            ] {
                let mut whole = make();
                whole.feed(&b);
                let mut got = Vec::new();
                drain_client(&mut whole, &mut got);
                let mut bytewise = make();
                let mut again = Vec::new();
                for byte in &b {
                    bytewise.feed(std::slice::from_ref(byte));
                    drain_client(&mut bytewise, &mut again);
                }
                assert_eq!(got, again, "{b:?}");
                assert_eq!(whole.stage(), bytewise.stage());
                assert_eq!(whole.take_data(), bytewise.take_data());
            }
        }
    }

    #[test]
    fn take_data_reports_overflow() {
        // Past MAX_BUFFERED in the data stage, take_data must not hand back
        // a stream with bytes missing from it.
        let mut d = ServerDecoder::new();
        d.feed(&[5, 1, 0x80]);
        d.next_message().unwrap().unwrap();
        d.select(Method::Other(0x80));
        d.feed(&vec![1; MAX_BUFFERED + 10]);
        assert_eq!(d.take_data(), b"");
        assert_eq!(d.stage(), ServerStage::Failed);
        assert_eq!(d.next_message(), Some(Err(Error::Overflow)));

        let mut d = ClientDecoder::socks5(Command::Connect);
        d.feed(&[5, 0x80]);
        d.next_message().unwrap().unwrap();
        assert_eq!(d.stage(), ClientStage::Done);
        d.feed(&vec![1; MAX_BUFFERED + 10]);
        assert_eq!(d.take_data(), b"");
        assert_eq!(d.stage(), ClientStage::Failed);
        assert_eq!(d.next_message(), Some(Err(Error::Overflow)));

        // Up to the limit, nothing is lost.
        let mut d = ClientDecoder::socks5(Command::Connect);
        d.feed(&[5, 0x80]);
        d.next_message().unwrap().unwrap();
        d.feed(&vec![1; MAX_BUFFERED]);
        assert_eq!(d.take_data().len(), MAX_BUFFERED);
        assert_eq!(d.stage(), ClientStage::Done);
    }

    #[test]
    fn codes_and_addresses_convert() {
        for c in 0..=255u8 {
            match Socks4Command::from_code(c) {
                Ok(cmd) => assert_eq!(cmd.code(), c),
                Err(e) => assert_eq!(e, Error::Command(c)),
            }
            if let Ok(cmd) = Command::from_code(c) {
                assert_eq!(cmd.code(), c);
            }
        }
        assert_eq!(Address::from(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))), v4(1, 2, 3, 4));
        assert_eq!(Address::from(IpAddr::V6(Ipv6Addr::LOCALHOST)), Address::Ipv6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn decoders_clone_mid_handshake() {
        let mut d = ServerDecoder::new();
        d.feed(&[5, 1, 0, 5, 1]);
        d.next_message().unwrap().unwrap();
        d.select(Method::NoAuth);
        let mut copy = d.clone();
        let rest = [0, 1, 127, 0, 0, 1, 0, 80];
        d.feed(&rest);
        copy.feed(&rest);
        assert_eq!(d.next_message(), copy.next_message());
        assert_eq!(d.stage(), ServerStage::Done);
        let c = ClientDecoder::socks5(Command::Bind);
        assert_eq!(c.clone().stage(), ClientStage::Selection);
    }

    #[test]
    fn buffer_stays_bounded_under_many_feeds() {
        // A world that never answers, fed far more than the limit in small
        // pieces: the decoder holds at most MAX_BUFFERED and fails once.
        let mut d = ServerDecoder::new();
        d.feed(&[5, 1, 0]);
        d.next_message().unwrap().unwrap();
        for _ in 0..1000 {
            d.feed(&[0; 1000]);
            assert!(d.buffered() <= MAX_BUFFERED);
            assert!(d.buf.buf.len() <= 2 * MAX_BUFFERED);
        }
        assert_eq!(d.next_message(), Some(Err(Error::Overflow)));
        assert_eq!(d.buffered(), 0);
        // In the data stage, taking bytes out as they come never overflows.
        let mut c = ClientDecoder::socks5(Command::Connect);
        c.feed(&[5, 0x80]);
        c.next_message().unwrap().unwrap();
        let mut total = 0;
        for _ in 0..1000 {
            c.feed(&[7; 1000]);
            total += c.take_data().len();
            assert!(c.buf.buf.len() <= 2 * MAX_BUFFERED);
        }
        assert_eq!(total, 1_000_000);
        assert_eq!(c.next_message(), None);
    }

    #[test]
    fn selection_must_be_one_offered() {
        // RFC 1928 section 3: the proxy selects one of the methods offered.
        let mut d = ServerDecoder::new();
        d.feed(&[5, 1, 2]);
        d.next_message().unwrap().unwrap();
        assert!(!d.select(Method::NoAuth));
        assert_eq!(d.stage(), ServerStage::Selecting);
        assert!(d.select(Method::UsernamePassword));
        assert_eq!(d.stage(), ServerStage::Auth);
        assert!(!d.select(Method::UsernamePassword));
        // Refusing every method is always allowed.
        let mut d = ServerDecoder::new();
        d.feed(&[5, 0]);
        d.next_message().unwrap().unwrap();
        assert!(!d.select(Method::NoAuth));
        assert!(d.select(Method::NoAcceptable));
        assert_eq!(d.stage(), ServerStage::Closed);

        // A client that offered only a login.
        let mut c = ClientDecoder::socks5_offering(Command::Connect, &[Method::UsernamePassword]);
        c.feed(&[5, 0]);
        assert_eq!(c.next_message(), Some(Err(Error::Method(0))));
        assert_eq!(c.stage(), ClientStage::Failed);
        let mut c = ClientDecoder::socks5_offering(Command::Connect, &[Method::UsernamePassword]);
        c.feed(&[5, 2]);
        assert!(matches!(c.next_message(), Some(Ok(ServerMessage::Selection(_)))));
        assert_eq!(c.stage(), ClientStage::Auth);
        let mut c = ClientDecoder::socks5_offering(Command::Connect, &[Method::UsernamePassword]);
        c.feed(&[5, 0xff]);
        assert!(matches!(c.next_message(), Some(Ok(ServerMessage::Selection(_)))));
        assert_eq!(c.stage(), ClientStage::Closed);
        // The plain constructor takes any method, as before.
        let mut c = ClientDecoder::socks5(Command::Connect);
        c.feed(&[5, 0]);
        assert!(matches!(c.next_message(), Some(Ok(_))));
        assert_eq!(c.stage(), ClientStage::Reply);
    }

    #[test]
    fn an_offer_past_max_methods_is_cut_as_the_greeting_is() {
        // The fuzz target's offer from crash-edfe37cd: 412 codes, as runs
        // of (code, count). Code 4 comes only at index 277, past what a
        // greeting carries, so neither side may take it.
        let runs: &[(u8, usize)] = &[
            (0xff, 73),
            (0xcc, 12),
            (0xff, 95),
            (0xcc, 7),
            (0x4d, 11),
            (0xcc, 8),
            (0x4d, 2),
            (0x3a, 1),
            (0x4d, 4),
            (0xee, 45),
            (0x4d, 11),
            (0xcc, 1),
            (0x4d, 1),
            (0x01, 1),
            (0x6c, 2),
            (0x00, 1),
            (0xff, 1),
            (0x00, 1),
            (0x04, 1),
            (0xff, 24),
            (0x01, 1),
            (0x00, 1),
            (0x2d, 12),
            (0xff, 4),
            (0x2d, 47),
            (0xf9, 1),
            (0xff, 1),
            (0x00, 5),
            (0x07, 1),
            (0x00, 6),
            (0xff, 26),
            (0x00, 5),
        ];
        let codes: Vec<u8> = runs.iter().flat_map(|&(c, n)| std::iter::repeat_n(c, n)).collect();
        assert_eq!(codes.len(), 412);
        let offered: Vec<Method> = codes.iter().map(|&c| Method::from_code(c)).collect();
        let chosen = Method::Other(4);

        let mut server = ServerDecoder::new();
        server.feed(&Greeting { methods: offered.clone() }.to_bytes());
        assert!(matches!(server.next_message(), Some(Ok(ClientMessage::Greeting(_)))));
        assert!(!server.select(chosen));

        let mut client = ClientDecoder::socks5_offering(Command::Connect, &offered);
        client.feed(&Selection { method: chosen }.to_bytes());
        assert_eq!(client.next_message(), Some(Err(Error::Method(4))));
    }

    #[test]
    fn other_codes_act_as_the_code_they_write() {
        // Other(2) is written as 2, username and password, so a login
        // comes next, not tunnel data.
        let mut d = ServerDecoder::new();
        d.feed(&[5, 1, 2]);
        d.next_message().unwrap().unwrap();
        assert_eq!(Selection { method: Method::Other(2) }.to_bytes(), [5, 2]);
        assert!(d.select(Method::Other(2)));
        assert_eq!(d.stage(), ServerStage::Auth);
        // Other(255) is written as "no acceptable methods", so it closes.
        let mut d = ServerDecoder::new();
        d.feed(&[5, 1, 0]);
        d.next_message().unwrap().unwrap();
        assert!(d.select(Method::Other(0xff)));
        assert_eq!(d.stage(), ServerStage::Closed);
        let mut d = ServerDecoder::new();
        d.feed(&[5, 1, 0]);
        d.next_message().unwrap().unwrap();
        assert!(d.select(Method::Other(0)));
        assert_eq!(d.stage(), ServerStage::Request);
    }

    #[test]
    fn socks4a_request_fed_a_byte_at_a_time() {
        // The longest SOCKS4a request, fed a byte at a time, reads once.
        let req = Socks4Request {
            command: Socks4Command::Connect,
            port: 80,
            destination: Socks4Destination::Domain(vec![b'd'; MAX_SOCKS4_DOMAIN]),
            user_id: vec![b'u'; MAX_USER_ID],
        };
        let bytes = req.to_bytes();
        assert_eq!(bytes.len(), MAX_MESSAGE);
        let mut d = ServerDecoder::new();
        for (i, b) in bytes.iter().enumerate() {
            d.feed(std::slice::from_ref(b));
            let m = d.next_message();
            if i + 1 < bytes.len() {
                assert_eq!(m, None, "byte {i}");
            } else {
                assert_eq!(m, Some(Ok(ClientMessage::Socks4(req.clone()))));
            }
        }
        // A complete user ID and part of the domain is not yet a request.
        assert_eq!(Socks4Request::parse(&bytes[..MAX_MESSAGE - 1]), Ok(None));
    }

    #[test]
    fn decoder_takes_many_bytes_in_linear_time() {
        let mut d = ServerDecoder::new();
        d.feed(&[5, 1, 0x80]);
        d.next_message().unwrap().unwrap();
        d.select(Method::Other(0x80));
        let started = std::time::Instant::now();
        let mut total = 0;
        for _ in 0..200_000 {
            d.feed(b"0123456789");
            total += d.take_data().len();
        }
        assert_eq!(total, 2_000_000);
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }
}
