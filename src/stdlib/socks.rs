//! SOCKS4, SOCKS4a and SOCKS5: reading and writing the handshake messages
//! and the UDP request header, with no I/O.
//!
//! Complete handshake values use `Wire`. `ClientMessages` and `ServerMessages`
//! decode each direction with caller-selected phases. These are handshake
//! readers, not a proxy session or `Service`. Connection establishment,
//! authentication decisions, and TCP or UDP relaying belong to the caller.
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
//! A world that plays a proxy pushes client bytes into
//! [`Stream<ClientMessages>`](fictionet::stdlib::codec::Stream). It answers each
//! [`ClientMessage`] and chooses the next phase with [`ClientMessages::select`]
//! or [`ClientMessages::verified`]. A client uses
//! [`Stream<ServerMessages>`](fictionet::stdlib::codec::Stream). After the last handshake
//! item, `swap` or `into_parts` hands unread bytes to the tunnel protocol.
//! While a decision is pending, input stays buffered up to the unit limit.
//! Choose the next phase before filling that allowance. Each reader checks
//! lengths against named limits. Where a connection goes is up to world code.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::socks::{
//!     Address, ClientMessage, Command, Method, Reply, ReplyCode, Selection, ClientMessages, ServerPhase,
//! };
//! use std::net::Ipv4Addr;
//!
//! let mut decoder = Stream::new(ClientMessages::new());
//! // A SOCKS5 greeting that offers one method: no login.
//! assert_eq!(decoder.push(&[5, 1, 0]), 3);
//! let Some(Ok(ClientMessage::Greeting(greeting))) = decoder.next().transpose().unwrap() else { panic!() };
//! assert_eq!(greeting.methods, [Method::NoAuth]);
//! assert_eq!(decoder.decoder().phase(), ServerPhase::Selecting);
//! assert_eq!(Selection { method: Method::NoAuth }.to_bytes().unwrap(), [5, 0]);
//! decoder.decoder().select(Method::NoAuth);
//!
//! // CONNECT to example.com port 80, and the first tunneled byte.
//! let mut request = vec![5, 1, 0, 3, 11];
//! request.extend_from_slice(b"example.com");
//! request.extend_from_slice(&[0, 80, b'G']);
//! assert_eq!(decoder.push(&request), request.len());
//! let Some(Ok(ClientMessage::Request(req))) = decoder.next().transpose().unwrap() else { panic!() };
//! assert_eq!(req.command, Command::Connect);
//! assert_eq!(req.address, Address::Domain(b"example.com".to_vec()));
//! assert_eq!(req.port, 80);
//! assert_eq!(decoder.decoder().phase(), ServerPhase::Done);
//! assert_eq!(decoder.unread(), b"G");
//!
//! // The proxy connected from 10.0.0.1 port 4321.
//! let reply = Reply { code: ReplyCode::Succeeded, address: Address::Ipv4(Ipv4Addr::new(10, 0, 0, 1)), port: 4321 };
//! assert_eq!(reply.to_bytes().unwrap(), [5, 0, 0, 1, 10, 0, 0, 1, 0x10, 0xe1]);
//! ```

use fictionet::stdlib::codec::be16;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use fictionet::stdlib::codec::{self, Step, Wire};

macro_rules! socks_wire {
    ($ty:ty, $read:literal, $refuse:literal, |$value:ident, $out:ident| $body:block) => {
        impl Wire for $ty {
            type ParseError = Error;
            type WriteError = Error;

            #[doc = $read]
            /// Refuses incomplete units, trailing bytes and malformed fields.
            fn parse(bytes: &[u8]) -> Result<Self, Error> {
                let (value, used) = Self::parse_prefix(bytes)?.ok_or(Error::Truncated)?;
                if used != bytes.len() {
                    return Err(Error::Trailing);
                }
                Ok(value)
            }

            #[doc = $refuse]
            /// Leaves `out` unchanged on error.
            fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                let $value = self;
                let mut bytes = Vec::new();
                let $out = &mut bytes;
                $body
                out.extend_from_slice(&bytes);
                Ok(())
            }
        }
    };
}

socks_wire!(Greeting, "Reads one SOCKS5 greeting. Empty method lists are accepted.",
    "Refuses more than `MAX_METHODS` methods and `Other` variants with named codes.", |value, out| {
    if value.methods.len() > MAX_METHODS || value.methods.iter().any(|m| Method::from_code(m.code()) != *m) {
        return Err(Error::Unwritable);
    }
    out.extend_from_slice(&[VERSION_5, value.methods.len() as u8]);
    out.extend(value.methods.iter().map(|m| m.code()));
});
socks_wire!(Selection, "Reads one SOCKS5 method selection.",
    "Refuses `Other` variants with named method codes.", |value, out| {
    if Method::from_code(value.method.code()) != value.method {
        return Err(Error::Unwritable);
    }
    out.extend_from_slice(&[VERSION_5, value.method.code()]);
});
socks_wire!(AuthRequest, "Reads one RFC 1929 login. Empty fields are accepted.",
    "Refuses usernames or passwords longer than 255 bytes.", |value, out| {
    if value.username.len() > MAX_USERNAME || value.password.len() > MAX_PASSWORD {
        return Err(Error::Unwritable);
    }
    out.extend_from_slice(&[AUTH_VERSION, value.username.len() as u8]);
    out.extend_from_slice(&value.username);
    out.push(value.password.len() as u8);
    out.extend_from_slice(&value.password);
});
socks_wire!(AuthReply, "Reads one RFC 1929 status. Any nonzero status means failure.",
    "Accepts every status byte; no values are refused.", |value, out| {
    out.extend_from_slice(&[AUTH_VERSION, value.status]);
});
socks_wire!(Request, "Reads one SOCKS5 request. Refuses unknown commands and nonzero reserved bytes.",
    "Refuses domain names longer than `MAX_DOMAIN` bytes.", |value, out| {
    out.extend_from_slice(&[VERSION_5, value.command.code(), 0]);
    Endpoint::from_address(&value.address, value.port)?.write(out)?;
});
socks_wire!(Reply, "Reads one SOCKS5 reply. Refuses nonzero reserved bytes.",
    "Refuses oversized domains and `Other` variants with named reply codes.", |value, out| {
    if ReplyCode::from_code(value.code.code()) != value.code {
        return Err(Error::Unwritable);
    }
    out.extend_from_slice(&[VERSION_5, value.code.code(), 0]);
    Endpoint::from_address(&value.address, value.port)?.write(out)?;
});
socks_wire!(Socks4Request, "Reads one SOCKS4 request. A 0.0.0.x address with nonzero x selects SOCKS4a. Refuses unknown commands and unterminated fields past their limits.",
    "Refuses SOCKS4a marker IPs, zero bytes in fields and fields longer than 255 bytes.", |value, out| {
    if value.user_id.len() > MAX_USER_ID || value.user_id.contains(&0) {
        return Err(Error::Unwritable);
    }
    let ip = match &value.destination {
        Socks4Destination::Ip(ip) => {
            if matches!(ip.octets(), [0, 0, 0, x] if x != 0) {
                return Err(Error::Unwritable);
            }
            ip.octets()
        }
        Socks4Destination::Domain(d) => {
            if d.len() > MAX_SOCKS4_DOMAIN || d.contains(&0) {
                return Err(Error::Unwritable);
            }
            [0, 0, 0, 1]
        }
    };
    out.extend_from_slice(&[VERSION_4, value.command.code()]);
    out.extend_from_slice(&value.port.to_be_bytes());
    out.extend_from_slice(&ip);
    out.extend_from_slice(&value.user_id);
    out.push(0);
    if let Socks4Destination::Domain(d) = &value.destination {
        out.extend_from_slice(d);
        out.push(0);
    }
});
socks_wire!(Socks4Reply, "Reads one eight-byte SOCKS4 reply. Refuses a nonzero version byte.",
    "Refuses `Other` variants with named reply codes.", |value, out| {
    if Socks4Code::from_code(value.code.code()) != value.code {
        return Err(Error::Unwritable);
    }
    out.extend_from_slice(&[VERSION_4_REPLY, value.code.code()]);
    out.extend_from_slice(&value.port.to_be_bytes());
    out.extend_from_slice(&value.ip.octets());
});

/// An address type, address and port, shared by SOCKS5 requests and replies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// The endpoint's address.
    pub address: Address,
    /// The endpoint's port.
    pub port: u16,
}
impl Endpoint {
    /// Copies an address and port into a wire endpoint. Refuses a domain
    /// longer than [`MAX_DOMAIN`] before copying it.
    pub fn from_address(address: &Address, port: u16) -> Result<Self, Error> {
        if matches!(address, Address::Domain(d) if d.len() > MAX_DOMAIN) {
            return Err(Error::Unwritable);
        }
        Ok(Self { address: address.clone(), port })
    }

    fn parse_prefix(b: &[u8]) -> Result<Option<(Self, usize)>, Error> {
        Ok(parse_endpoint(b, 0)?.map(|(address, port, used)| (Self { address, port }, used)))
    }
}
socks_wire!(Endpoint, "Reads one SOCKS5 endpoint. Refuses unknown address types.",
    "Refuses domain names longer than `MAX_DOMAIN` bytes.", |value, out| {
    match &value.address {
        Address::Ipv4(a) => { out.push(atyp::IPV4); out.extend_from_slice(&a.octets()); }
        Address::Ipv6(a) => { out.push(atyp::IPV6); out.extend_from_slice(&a.octets()); }
        Address::Domain(d) => {
            let len = u8::try_from(d.len()).map_err(|_| Error::Unwritable)?;
            out.extend_from_slice(&[atyp::DOMAIN, len]);
            out.extend_from_slice(d);
        }
    }
    out.extend_from_slice(&value.port.to_be_bytes());
});

fn sized_end(at: usize, len: usize) -> Result<usize, FrameError> {
    at.checked_add(len).ok_or(FrameError::TooLong)
}

// Finds framing without interpreting command and reserved fields. Those
// are per-unit failures once the endpoint establishes an exact boundary.
fn endpoint_end(b: &[u8], at: usize) -> Result<Option<usize>, FrameError> {
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
        other => return Err(FrameError::AddressType(other)),
    }))
}

#[derive(Clone, Debug, Default)]
struct Scan4 {
    pos: usize,
    user_end: Option<usize>,
}
impl Scan4 {
    fn length(&mut self, b: &[u8]) -> Result<Option<usize>, FrameError> {
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
                    Err(FrameError::FieldTooLong)
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
/// item. Until that decision, input below capacity returns [`Step::Need`],
/// allowing [`codec::pump`] and [`codec::try_pump`] to return to the world
/// with pipelined bytes buffered. At capacity, decoding fails with
/// [`FrameError::DecisionRequired`]. Decide before filling that allowance.
/// Complete malformed requests are `Err` items. Unknown framing and limits
/// are terminal errors. Both leave [`ServerPhase::Failed`]. A request is
/// the last item; the next call returns [`Step::End`]. Unsupported selected
/// methods and refusal also end.
/// Use `Stream::swap` or `into_parts` for the unread tunnel bytes, and send
/// any input not accepted by `push` to the next decoder. EOF inside a unit
/// returns `Need` so the driver reports truncation.
#[derive(Clone, Debug)]
pub struct ClientMessages {
    phase: ServerPhase,
    offered: MethodSet,
    limit: usize,
    scan4: Scan4,
}
impl ClientMessages {
    /// Starts at the greeting, with a whole-unit limit of [`MAX_MESSAGE`].
    pub fn new() -> Self {
        Self::with_limit(MAX_MESSAGE)
    }

    /// Sets the whole-unit limit, clamped to 10 through [`MAX_MESSAGE`].
    /// The floor fits a SOCKS5 IPv4 request.
    /// Counted units are refused from their length fields before the body.
    pub fn with_limit(limit: usize) -> Self {
        Self {
            phase: ServerPhase::Greeting,
            offered: MethodSet::default(),
            limit: limit.clamp(10, MAX_MESSAGE),
            scan4: Scan4::default(),
        }
    }

    /// The current handshake phase.
    pub fn phase(&self) -> ServerPhase {
        self.phase
    }

    /// The largest accepted unit, including its header.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Chooses an offered method between items. Returns false outside the
    /// selection phase or for a method that was not offered.
    pub fn select(&mut self, method: Method) -> bool {
        if self.phase != ServerPhase::Selecting || !self.offered.allows(method) {
            return false;
        }
        self.phase = match Method::from_code(method.code()) {
            Method::NoAuth => ServerPhase::Request,
            Method::UsernamePassword => ServerPhase::Auth,
            Method::NoAcceptable => ServerPhase::Closed,
            _ => ServerPhase::Done,
        };
        true
    }

    /// Accepts or refuses authentication between items. Does nothing
    /// outside the verification phase. Refusal preserves unread bytes.
    pub fn verified(&mut self, good: bool) {
        if self.phase == ServerPhase::Verifying {
            self.phase = if good { ServerPhase::Request } else { ServerPhase::Closed };
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
    type Error = FrameError;
    const NAME: &'static str = "SOCKS client units";
    fn capacity(&self) -> usize {
        self.limit
    }

    fn decode(&mut self, b: &[u8], _: bool) -> Result<Step<Self::Item>, FrameError> {
        self.decode_unit(b)
            .inspect_err(|_| self.phase = ServerPhase::Failed)
    }
}
impl ClientMessages {
    fn decode_unit(&mut self, b: &[u8]) -> Result<Step<Result<ClientMessage, Error>>, FrameError> {
        match self.phase {
            ServerPhase::Done | ServerPhase::Closed | ServerPhase::Failed => return Ok(Step::End),
            ServerPhase::Selecting | ServerPhase::Verifying if b.len() < self.limit => {
                return Ok(Step::Need);
            }
            ServerPhase::Selecting | ServerPhase::Verifying => {
                return Err(FrameError::DecisionRequired(self.phase));
            }
            _ => {}
        }
        let Some(&first) = b.first() else { return Ok(Step::Need) };
        let v4 = self.phase == ServerPhase::Greeting && first == VERSION_4;
        let version = if v4 {
            VERSION_4
        } else if self.phase == ServerPhase::Auth {
            AUTH_VERSION
        } else {
            VERSION_5
        };
        if let Some(&v) = b.first()
            && v != version
        {
            return Err(FrameError::Version(v));
        }
        let end = if v4 {
            self.scan4.length(b.get(..self.limit).unwrap_or(b))?
        } else {
            match self.phase {
                ServerPhase::Greeting => b
                    .get(1)
                    .map(|&n| sized_end(2, usize::from(n)))
                    .transpose()?,
                ServerPhase::Auth => match b.get(1) {
                    Some(&n) => {
                        let at = sized_end(2, usize::from(n))?;
                        let header = sized_end(at, 1)?;
                        if header > self.limit {
                            return Err(FrameError::TooLong);
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
            return if b.len() >= self.limit { Err(FrameError::TooLong) } else { Ok(Step::Need) };
        };
        if used > self.limit {
            return Err(FrameError::TooLong);
        }
        let Some(bytes) = b.get(..used) else { return Ok(Step::Need) };
        let item = if v4 {
            Socks4Request::parse_prefix(bytes).map(|v| v.map(|(m, _)| ClientMessage::Socks4(m)))
        } else {
            match self.phase {
                ServerPhase::Greeting => Greeting::parse_prefix(bytes).map(|v| v.map(|(m, _)| ClientMessage::Greeting(m))),
                ServerPhase::Auth => AuthRequest::parse_prefix(bytes).map(|v| v.map(|(m, _)| ClientMessage::Auth(m))),
                _ => Request::parse_prefix(bytes).map(|v| v.map(|(m, _)| ClientMessage::Request(m))),
            }
        };
        let item = match item {
            Ok(Some(value)) => Ok(value),
            Ok(None) => return Ok(Step::Need),
            Err(error) => Err(error),
        };
        self.phase = match &item {
            Ok(ClientMessage::Greeting(g)) => {
                self.offered = MethodSet::of(&g.methods);
                ServerPhase::Selecting
            }
            Ok(ClientMessage::Auth(_)) => ServerPhase::Verifying,
            Ok(_) => ServerPhase::Done,
            Err(_) => ServerPhase::Failed,
        };
        Ok(Step::Item(item, used))
    }
}

/// Reads proxy replies, then ends with unread tunnel bytes in the stream.
///
/// This owns no input; use it with [`codec::Stream`]. BIND reads
/// both replies. Refusal and unsupported methods yield their last item,
/// then `End`. Bad complete units are items; framing and limits are errors.
/// Both kinds of error leave [`ClientPhase::Failed`], preserving unread bytes.
#[derive(Clone, Debug)]
pub struct ServerMessages {
    phase: ClientPhase,
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

    /// Reads SOCKS5 replies with a whole-unit limit clamped to 10 through
    /// [`MAX_MESSAGE`]. The floor fits an IPv4 reply. Declared endpoint
    /// lengths are checked before the body.
    pub fn with_limit(command: Command, limit: usize) -> Self {
        Self {
            phase: ClientPhase::Selection,
            socks4: false,
            bind: command == Command::Bind,
            offered: None,
            limit: limit.clamp(10, MAX_MESSAGE),
        }
    }

    /// Also checks the selection against the first [`MAX_METHODS`] offers.
    pub fn socks5_offering(command: Command, methods: &[Method]) -> Self {
        Self { offered: Some(MethodSet::of(methods)), ..Self::socks5(command) }
    }

    /// Reads SOCKS4 or SOCKS4a replies, including BIND's second reply.
    pub fn socks4(command: Socks4Command) -> Self {
        Self::socks4_with_limit(command, MAX_MESSAGE)
    }

    /// Reads SOCKS4 replies with a limit clamped to [`SOCKS4_REPLY_LEN`]
    /// through [`MAX_MESSAGE`]. Each reply occupies exactly eight bytes.
    pub fn socks4_with_limit(command: Socks4Command, limit: usize) -> Self {
        Self {
            phase: ClientPhase::Reply,
            socks4: true,
            bind: command == Socks4Command::Bind,
            offered: None,
            limit: limit.clamp(SOCKS4_REPLY_LEN, MAX_MESSAGE),
        }
    }

    /// The largest accepted unit, including its header.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// The current reply phase.
    pub fn phase(&self) -> ClientPhase {
        self.phase
    }
}
impl codec::Decode for ServerMessages {
    type Item = Result<ServerMessage, Error>;
    type Error = FrameError;
    const NAME: &'static str = "SOCKS server units";
    fn capacity(&self) -> usize {
        self.limit
    }

    fn decode(&mut self, b: &[u8], _: bool) -> Result<Step<Self::Item>, FrameError> {
        self.decode_unit(b)
            .inspect_err(|_| self.phase = ClientPhase::Failed)
    }
}
impl ServerMessages {
    fn decode_unit(&mut self, b: &[u8]) -> Result<Step<Result<ServerMessage, Error>>, FrameError> {
        if matches!(self.phase, ClientPhase::Done | ClientPhase::Closed | ClientPhase::Failed) {
            return Ok(Step::End);
        }
        let version = if self.socks4 {
            VERSION_4_REPLY
        } else if self.phase == ClientPhase::Auth {
            AUTH_VERSION
        } else {
            VERSION_5
        };
        if let Some(&v) = b.first()
            && v != version
        {
            return Err(FrameError::Version(v));
        }
        let used = match self.phase {
            ClientPhase::Selection | ClientPhase::Auth => 2,
            _ if self.socks4 => SOCKS4_REPLY_LEN,
            _ => match endpoint_end(b, 3)? {
                Some(n) => n,
                None => return Ok(Step::Need),
            },
        };
        if used > self.limit {
            return Err(FrameError::TooLong);
        }
        let Some(bytes) = b.get(..used) else { return Ok(Step::Need) };
        let item = match self.phase {
            ClientPhase::Selection => Selection::parse_prefix(bytes).map(|v| v.map(|(m, _)| ServerMessage::Selection(m))),
            ClientPhase::Auth => AuthReply::parse_prefix(bytes).map(|v| v.map(|(m, _)| ServerMessage::Auth(m))),
            _ if self.socks4 => Socks4Reply::parse_prefix(bytes).map(|v| v.map(|(m, _)| ServerMessage::Socks4(m))),
            _ => Reply::parse_prefix(bytes).map(|v| v.map(|(m, _)| ServerMessage::Reply(m))),
        };
        let item = match item {
            Ok(Some(value)) => Ok(value),
            Ok(None) => return Ok(Step::Need),
            Err(error) => Err(error),
        }
        .and_then(|m| {
            if let ServerMessage::Selection(s) = &m
                && self.offered.is_some_and(|o| !o.allows(s.method))
            {
                return Err(Error::Method(s.method.code()));
            }
            Ok(m)
        });
        let reply_phase =
            if self.bind && self.phase == ClientPhase::Reply { ClientPhase::SecondReply } else { ClientPhase::Done };
        self.phase = match &item {
            Ok(ServerMessage::Selection(s)) => match Method::from_code(s.method.code()) {
                Method::NoAuth => ClientPhase::Reply,
                Method::UsernamePassword => ClientPhase::Auth,
                Method::NoAcceptable => ClientPhase::Closed,
                _ => ClientPhase::Done,
            },
            Ok(ServerMessage::Auth(a)) if a.success() => ClientPhase::Reply,
            Ok(ServerMessage::Reply(r)) if r.code.code() == ReplyCode::Succeeded.code() => reply_phase,
            Ok(ServerMessage::Socks4(r)) if r.code.code() == Socks4Code::Granted.code() => reply_phase,
            Ok(_) => ClientPhase::Closed,
            Err(_) => ClientPhase::Failed,
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
/// The longest [`UdpDatagram`], including its SOCKS header: the IPv6 UDP
/// payload maximum, 65,535 bytes minus the eight-byte UDP header.
pub const MAX_DATAGRAM: usize = 65_535 - 8;
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

/// Why bytes are not the SOCKS message expected, or a value cannot be
/// written exactly. On a TCP stream, the connection holds no more messages
/// a reader can find, and a real proxy closes it.
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
    /// The proxy chose a login method, with this code, that the client did
    /// not offer (RFC 1928 section 3). Only a [`ServerMessages`] made with
    /// [`ServerMessages::socks5_offering`] checks this.
    Method(u8),
    /// The unit is incomplete.
    Truncated,
    /// Bytes follow the unit.
    Trailing,
    /// A datagram exceeds [`MAX_DATAGRAM`].
    TooLong,
    /// Encoding would clip a field or change a variant.
    Unwritable,
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
            Error::Method(m) => write!(f, "method {m} was not offered"),
            Error::Truncated => f.write_str("incomplete SOCKS unit"),
            Error::Trailing => f.write_str("bytes after the SOCKS unit"),
            Error::TooLong => f.write_str("SOCKS datagram exceeds MAX_DATAGRAM"),
            Error::Unwritable => f.write_str("SOCKS value cannot be written unchanged"),
        }
    }
}

impl std::error::Error for Error {}

/// Why a SOCKS stream cannot find its next unit. It ends the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The first byte was not the version this message takes.
    Version(u8),
    /// An address type that is not IPv4, IPv6 or a domain name.
    AddressType(u8),
    /// A SOCKS4 user ID or SOCKS4a domain ran past its limit with no zero
    /// byte to end it.
    FieldTooLong,
    /// A unit exceeds the configured whole-message limit.
    TooLong,
    /// Input reached capacity before `select` or `verified` decided the next phase.
    DecisionRequired(ServerPhase),
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Version(v) => write!(f, "version byte {v} is not the one this message takes"),
            Self::AddressType(t) => write!(f, "unknown address type {t}"),
            Self::FieldTooLong => f.write_str("SOCKS4 field has no zero byte within its limit"),
            Self::TooLong => f.write_str("SOCKS unit exceeds its limit"),
            Self::DecisionRequired(s) => write!(f, "SOCKS decision required in {s:?}"),
        }
    }
}
impl core::error::Error for FrameError {}

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
    /// refused by writers. Readers return the named method.
    Other(u8),
}

/// A set of method codes, such as the methods a greeting offered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct MethodSet([u64; 4]);

impl MethodSet {
    /// The set a greeting offering `methods` carries: the first
    /// [`MAX_METHODS`], the wire limit.
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
    /// name. Writers refuse more than [`MAX_DOMAIN`] bytes.
    Domain(Vec<u8>),
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
    Ok(Some((address, be16(b, start + len).ok_or(Error::Truncated)?, end)))
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
    /// The methods offered, in the order sent. Writers refuse more than
    /// [`MAX_METHODS`]. RFC 1928 asks for at least one, but an empty list
    /// is read too, and a proxy answers it with [`Method::NoAcceptable`].
    pub methods: Vec<Method>,
}

impl Greeting {
    /// Reads the greeting at the start of `b`. It returns `Ok(None)` if
    /// `b` holds only part of one, and otherwise the greeting and how many
    /// bytes it took.
    fn parse_prefix(b: &[u8]) -> Result<Option<(Greeting, usize)>, Error> {
        check_version(b, VERSION_5)?;
        let Some(&n) = b.get(1) else { return Ok(None) };
        let end = 2 + usize::from(n);
        if b.len() < end {
            return Ok(None);
        }
        let methods = b[2..end].iter().map(|&c| Method::from_code(c)).collect();
        Ok(Some((Greeting { methods }, end)))
    }
}

/// The SOCKS5 proxy's answer to a greeting: the method it chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    /// The method chosen, or [`Method::NoAcceptable`].
    pub method: Method,
}

impl Selection {
    /// Reads the selection at the start of `b`. Returns `Ok(None)` for a partial unit.
    fn parse_prefix(b: &[u8]) -> Result<Option<(Selection, usize)>, Error> {
        check_version(b, VERSION_5)?;
        match b.get(1) {
            Some(&m) => Ok(Some((Selection { method: Method::from_code(m) }, 2))),
            None => Ok(None),
        }
    }
}

/// The username and password a client logs in with (RFC 1929).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthRequest {
    /// The username, as sent. Writers refuse more than [`MAX_USERNAME`]
    /// bytes.
    pub username: Vec<u8>,
    /// The password, as sent. Writers refuse more than [`MAX_PASSWORD`]
    /// bytes.
    pub password: Vec<u8>,
}

impl AuthRequest {
    /// Reads the login at the start of `b`. Returns `Ok(None)` for a partial unit.
    /// RFC 1929 asks for fields of at least one byte, but empty ones are
    /// read too.
    fn parse_prefix(b: &[u8]) -> Result<Option<(AuthRequest, usize)>, Error> {
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
}

/// The proxy's answer to a login (RFC 1929).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthReply {
    /// [`AUTH_SUCCESS`] for a good login. Any other value is a failure,
    /// and the proxy closes the connection.
    pub status: u8,
}

impl AuthReply {
    /// Reads the answer at the start of `b`. Returns `Ok(None)` for a partial unit.
    fn parse_prefix(b: &[u8]) -> Result<Option<(AuthReply, usize)>, Error> {
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
    /// Reads the request at the start of `b`. Returns `Ok(None)` for a partial
    /// unit. A bad version, command or reserved byte is reported as soon
    /// as it comes.
    fn parse_prefix(b: &[u8]) -> Result<Option<(Request, usize)>, Error> {
        check_version(b, VERSION_5)?;
        let Some(&cmd) = b.get(1) else { return Ok(None) };
        let command = Command::from_code(cmd)?;
        let Some(&rsv) = b.get(2) else { return Ok(None) };
        if rsv != 0 {
            return Err(Error::Reserved(u16::from(rsv)));
        }
        Ok(parse_endpoint(b, 3)?.map(|(address, port, end)| (Request { command, address, port }, end)))
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
    /// refused by writers. Readers return the named variant.
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
    /// Reads the reply at the start of `b`. Returns `Ok(None)` for a partial unit.
    fn parse_prefix(b: &[u8]) -> Result<Option<(Reply, usize)>, Error> {
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
    fn parse_prefix(bytes: &[u8]) -> Result<Option<(Self, usize)>, Error> {
        let Some(&[hi, lo, fragment]) = bytes.get(..3) else { return Ok(None) };
        let reserved = u16::from_be_bytes([hi, lo]);
        if reserved != 0 {
            return Err(Error::Reserved(reserved));
        }
        Ok(parse_endpoint(bytes, 3)?.map(|(address, port, used)| (Self { fragment, address, port }, used)))
    }

    /// Wraps this header and a payload as one wire datagram.
    pub fn datagram(self, payload: Vec<u8>) -> UdpDatagram {
        UdpDatagram { header: self, payload }
    }
}
socks_wire!(UdpHeader, "Reads one SOCKS5 UDP header. Refuses nonzero reserved bytes and unknown address types.",
    "Refuses domain names longer than `MAX_DOMAIN` bytes.", |value, out| {
    out.extend_from_slice(&[0, 0, value.fragment]);
    Endpoint::from_address(&value.address, value.port)?.write(out)?;
});

/// One relayed UDP datagram, including its SOCKS5 header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpDatagram {
    /// The relay header.
    pub header: UdpHeader,
    /// The application bytes.
    pub payload: Vec<u8>,
}
impl Wire for UdpDatagram {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a whole datagram. Refuses malformed or incomplete headers and
    /// datagrams longer than [`MAX_DATAGRAM`]. Payload bytes are opaque.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_DATAGRAM {
            return Err(Error::TooLong);
        }
        let (header, used) = UdpHeader::parse_prefix(bytes)?.ok_or(Error::Truncated)?;
        Ok(Self { header, payload: bytes[used..].to_vec() })
    }

    /// Refuses oversized domains and datagrams longer than [`MAX_DATAGRAM`].
    /// Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut bytes = Vec::new();
        self.header.write(&mut bytes)?;
        if bytes.len().checked_add(self.payload.len()).is_none_or(|n| n > MAX_DATAGRAM) {
            return Err(Error::Unwritable);
        }
        bytes.extend_from_slice(&self.payload);
        out.extend_from_slice(&bytes);
        Ok(())
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
    /// a domain follows, so writers refuse them as IP destinations.
    Ip(Ipv4Addr),
    /// A domain name for the proxy to look up (SOCKS4a), as the bytes
    /// sent. Writers refuse zero bytes or more than [`MAX_SOCKS4_DOMAIN`] bytes.
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
    /// The user ID, as sent. Writers refuse zero bytes or more than
    /// [`MAX_USER_ID`] bytes.
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

impl Socks4Request {
    /// Reads the request at the start of `b`. Returns `Ok(None)` for a partial unit.
    /// A destination of 0.0.0.1 to 0.0.0.255 means a SOCKS4a domain
    /// follows the user ID.
    fn parse_prefix(b: &[u8]) -> Result<Option<(Socks4Request, usize)>, Error> {
        check_version(b, VERSION_4)?;
        let Some(&cmd) = b.get(1) else { return Ok(None) };
        let command = Socks4Command::from_code(cmd)?;
        if b.len() < 8 {
            return Ok(None);
        }
        let port = be16(b, 2).ok_or(Error::Truncated)?;
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
    /// refused by writers. Readers return the named variant.
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
    /// Reads the reply at the start of `b`. Returns `Ok(None)` for a partial unit.
    /// Its first byte must be [`VERSION_4_REPLY`].
    fn parse_prefix(b: &[u8]) -> Result<Option<(Socks4Reply, usize)>, Error> {
        check_version(b, VERSION_4_REPLY)?;
        if b.len() < SOCKS4_REPLY_LEN {
            return Ok(None);
        }
        let reply = Socks4Reply {
            code: Socks4Code::from_code(b[1]),
            port: be16(b, 2).ok_or(Error::Truncated)?,
            ip: Ipv4Addr::new(b[4], b[5], b[6], b[7]),
        };
        Ok(Some((reply, SOCKS4_REPLY_LEN)))
    }
}

/// A message a client sends, read by a [`ClientMessages`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientMessage {
    /// A SOCKS5 greeting. Answer it with a [`Selection`], then call
    /// [`ClientMessages::select`].
    Greeting(Greeting),
    /// A username and password. Answer with an [`AuthReply`], then call
    /// [`ClientMessages::verified`].
    Auth(AuthRequest),
    /// A SOCKS5 request. Answer with a [`Reply`].
    Request(Request),
    /// A SOCKS4 or SOCKS4a request. Answer with a [`Socks4Reply`].
    Socks4(Socks4Request),
}

/// Where [`ClientMessages`] is in the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerPhase {
    /// Waiting for the client's first message: a SOCKS5 greeting or a
    /// SOCKS4 request.
    Greeting,
    /// Waiting for the world to choose a method with
    /// [`ClientMessages::select`].
    Selecting,
    /// Waiting for a username and password.
    Auth,
    /// Waiting for the world to say whether the login is good with
    /// [`ClientMessages::verified`].
    Verifying,
    /// Waiting for a SOCKS5 request.
    Request,
    /// The handshake is over, or went on with a method this module does
    /// not read. The bytes that follow are the world's, through
    /// [`codec::Stream::into_parts`].
    Done,
    /// The proxy refused the client and closes the connection. The stream
    /// decoder ends.
    Closed,
    /// The client broke the protocol, or decoding failed. No tunnel handoff
    /// is allowed. The stream reports the error once.
    Failed,
}

/// A message a proxy sends, read by a [`ServerMessages`].
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

/// Where [`ServerMessages`] is in the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientPhase {
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
    /// [`codec::Stream::into_parts`].
    Done,
    /// The proxy refused, and closes the connection. The stream decoder
    /// ends.
    Closed,
    /// The proxy broke the protocol, or decoding failed. No tunnel handoff
    /// is allowed. The stream reports the error once.
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{
        Decode, Fail, Lcg, Stream,
    };
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::{chunks, decode_all, mutate};

    fn request() -> Request {
        Request { command: Command::Connect, address: Address::Ipv4(Ipv4Addr::new(192, 168, 1, 2)), port: 8080 }
    }


    #[test]
    fn rfc1928_greeting_and_selection() {
        let greeting = Greeting { methods: vec![Method::NoAuth, Method::UsernamePassword] };
        assert_eq!(Greeting::parse(&[5, 2, 0, 2]), Ok(greeting.clone()));
        assert_eq!(greeting.to_bytes().unwrap(), [5, 2, 0, 2]);
        assert_eq!(Selection::parse(&[5, 2]), Ok(Selection { method: Method::UsernamePassword }));
        assert_eq!(Selection::parse(&[5, 2, 9]), Err(Error::Trailing));
        assert_eq!(Selection { method: Method::NoAcceptable }.to_bytes().unwrap(), [5, 0xff]);
        assert_eq!(Greeting::parse(&[5, 0]), Ok(Greeting { methods: vec![] }));
        for c in 0..=255u8 {
            assert_eq!(Method::from_code(c).code(), c);
            assert_eq!(ReplyCode::from_code(c).code(), c);
            assert_eq!(Socks4Code::from_code(c).code(), c);
            contract::check_wire_value(&Selection { method: Method::from_code(c) });
            contract::check_wire_value(&Selection { method: Method::Other(c) });
            contract::check_wire_value(&Reply::failure(ReplyCode::Other(c)));
            contract::check_wire_value(&Socks4Reply { code: Socks4Code::Other(c), port: 0, ip: Ipv4Addr::LOCALHOST });
            match Socks4Command::from_code(c) {
                Ok(cmd) => assert_eq!(cmd.code(), c),
                Err(e) => assert_eq!(e, Error::Command(c)),
            }
            if let Ok(cmd) = Command::from_code(c) { assert_eq!(cmd.code(), c); }
        }
        assert_eq!(Address::from(IpAddr::V4(Ipv4Addr::LOCALHOST)), Address::Ipv4(Ipv4Addr::LOCALHOST));
        assert_eq!(Address::from(IpAddr::V6(Ipv6Addr::LOCALHOST)), Address::Ipv6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn rfc1929_login() {
        let bytes = [1, 5, b'a', b'l', b'i', b'c', b'e', 3, b'p', b'w', b'd'];
        let auth = AuthRequest { username: b"alice".to_vec(), password: b"pwd".to_vec() };
        assert_eq!(AuthRequest::parse(&bytes), Ok(auth.clone()));
        assert_eq!(auth.to_bytes().unwrap(), bytes);
        assert_eq!(AuthRequest::parse(&[1, 0, 0]), Ok(AuthRequest { username: vec![], password: vec![] }));
        assert_eq!(AuthReply::parse(&[1, 0]), Ok(AuthReply { status: 0 }));
        assert!(!AuthReply { status: 1 }.success());
        assert_eq!(AuthReply::parse(&[5, 0]), Err(Error::Version(5)));
    }

    #[test]
    fn requests_replies_and_prefixes() {
        let bytes = [5, 1, 0, 1, 192, 168, 1, 2, 0x1f, 0x90];
        assert_eq!(Request::parse(&bytes), Ok(request()));
        assert_eq!(request().to_bytes().unwrap(), bytes);
        for address in [Address::Ipv4(Ipv4Addr::LOCALHOST), Address::Ipv6(Ipv6Addr::LOCALHOST), Address::Domain(b"h".to_vec()), Address::Domain(vec![])] {
            for command in [Command::Connect, Command::Bind, Command::UdpAssociate] {
                let req = Request { command, address: address.clone(), port: 53 };
                let bytes = req.to_bytes().unwrap();
                assert_eq!(Request::parse(&bytes), Ok(req));
                for n in 0..bytes.len() { assert_eq!(Request::parse(&bytes[..n]), Err(Error::Truncated)); }
                contract::check_wire::<Request>(&bytes);
            }
            let reply = Reply { code: ReplyCode::Succeeded, address, port: 9 };
            let bytes = reply.to_bytes().unwrap();
            assert_eq!(Reply::parse(&bytes), Ok(reply.clone()));
            for n in 0..bytes.len() { assert_eq!(Reply::parse(&bytes[..n]), Err(Error::Truncated)); }
            contract::check_wire_value(&reply);
        }
        assert_eq!(Reply::failure(ReplyCode::HostUnreachable).to_bytes().unwrap(), [5, 4, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(Reply::parse(&[5, 0, 0, 3, 1, b'h', 0, 7]), Ok(Reply { code: ReplyCode::Succeeded, address: Address::Domain(b"h".to_vec()), port: 7 }));
        for bytes in [vec![5, 2, 0, 2], vec![5, 2], vec![1, 1, b'u', 1, b'p'], vec![1, 0], vec![0, 90, 0, 0, 0, 0, 0, 0]] {
            macro_rules! prefixes {
                ($($ty:ty),+) => {$(if <$ty>::parse(&bytes).is_ok() {
                    for n in 0..bytes.len() { assert_eq!(<$ty>::parse(&bytes[..n]), Err(Error::Truncated)); }
                })+};
            }
            prefixes!(Greeting, Selection, AuthRequest, AuthReply, Socks4Reply);
        }
    }

    #[test]
    fn udp_datagrams() {
        let header = UdpHeader { fragment: 0, address: Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), port: 53 };
        let datagram = header.clone().datagram(b"query".to_vec());
        let bytes = datagram.to_bytes().unwrap();
        assert_eq!(bytes, [0, 0, 0, 1, 8, 8, 8, 8, 0, 53, b'q', b'u', b'e', b'r', b'y']);
        assert_eq!(UdpDatagram::parse(&bytes), Ok(datagram));
        for n in 0..10 { assert_eq!(UdpDatagram::parse(&bytes[..n]), Err(Error::Truncated)); }
        assert_eq!(UdpHeader::parse(&bytes[..10]), Ok(header.clone()));
        assert_eq!(UdpHeader::parse(&bytes), Err(Error::Trailing));
        assert_eq!(UdpDatagram::parse(&[0, 1, 0, 1, 0, 0, 0, 0, 0, 0]), Err(Error::Reserved(1)));
        assert_eq!(UdpDatagram::parse(&[0, 0, 0, 2]), Err(Error::AddressType(2)));
        let full = header.clone().datagram(vec![7; MAX_DATAGRAM - 10]);
        let bytes = full.to_bytes().unwrap();
        assert_eq!(bytes.len(), 65_527);
        assert_eq!(UdpDatagram::parse(&bytes), Ok(full.clone()));
        contract::check_wire_value(&full);
        assert_eq!(contract::check_refused(&header.datagram(vec![7; MAX_DATAGRAM - 9])), Error::Unwritable);
        assert_eq!(UdpDatagram::parse(&vec![0; MAX_DATAGRAM + 1]), Err(Error::TooLong));
        assert_eq!(Error::TooLong.to_string(), "SOCKS datagram exceeds MAX_DATAGRAM");
    }

    #[test]
    fn socks4_examples_and_limits() {
        let req = Socks4Request { command: Socks4Command::Connect, port: 80,
            destination: Socks4Destination::Ip(Ipv4Addr::new(66, 102, 7, 99)), user_id: b"fred".to_vec() };
        let bytes = [4, 1, 0, 80, 66, 102, 7, 99, b'f', b'r', b'e', b'd', 0];
        assert_eq!(Socks4Request::parse(&bytes), Ok(req.clone()));
        assert_eq!(req.to_bytes().unwrap(), bytes);
        for n in 0..bytes.len() { assert_eq!(Socks4Request::parse(&bytes[..n]), Err(Error::Truncated)); }
        let req = Socks4Request { command: Socks4Command::Bind, port: 21,
            destination: Socks4Destination::Domain(b"ftp.example.org".to_vec()), user_id: vec![] };
        let bytes = b"\x04\x02\x00\x15\x00\x00\x00\x01\x00ftp.example.org\0";
        for n in 0..bytes.len() { assert_eq!(Socks4Request::parse(&bytes[..n]), Err(Error::Truncated)); }
        assert_eq!(Socks4Request::parse(bytes), Ok(req.clone()));
        assert_eq!(req.to_bytes().unwrap(), bytes);
        assert_eq!(Socks4Request::parse(&[4, 1, 0, 1, 0, 0, 0, 9, 0, b'a', 0]).unwrap().destination, Socks4Destination::Domain(b"a".to_vec()));
        assert_eq!(Socks4Request::parse(&[4, 1, 0, 1, 0, 0, 0, 0, 0]).unwrap().destination, Socks4Destination::Ip(Ipv4Addr::UNSPECIFIED));
        let reply = Socks4Reply { code: Socks4Code::Granted, port: 0x1234, ip: Ipv4Addr::new(1, 2, 3, 4) };
        assert_eq!(reply.to_bytes().unwrap(), [0, 90, 0x12, 0x34, 1, 2, 3, 4]);
        contract::check_wire_value(&reply);
        let longest = Socks4Request { command: Socks4Command::Connect, port: 80,
            destination: Socks4Destination::Domain(vec![b'd'; MAX_SOCKS4_DOMAIN]), user_id: vec![b'u'; MAX_USER_ID] };
        let bytes = longest.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_MESSAGE);
        assert_eq!(Socks4Request::parse(&bytes[..MAX_MESSAGE - 1]), Err(Error::Truncated));
        contract::check_decode_with_alloc_limit(ClientMessages::new, &bytes, 2 * MAX_MESSAGE);
        assert_eq!(decode_all(ClientMessages::new, &bytes), (vec![Ok(ClientMessage::Socks4(longest))], None));
        for (prefix, max) in [(vec![4, 1, 0, 80, 1, 2, 3, 4], MAX_USER_ID), (vec![4, 1, 0, 80, 0, 0, 0, 1, 0], MAX_SOCKS4_DOMAIN)] {
            let mut bytes = prefix;
            bytes.extend(vec![b'x'; max]);
            assert_eq!(Socks4Request::parse(&bytes), Err(Error::Truncated));
            bytes.push(b'x');
            assert_eq!(Socks4Request::parse(&bytes), Err(Error::FieldTooLong));
        }
        for destination in [Socks4Destination::Ip(Ipv4Addr::new(0, 0, 0, 7)), Socks4Destination::Domain(vec![b'x'; 256]), Socks4Destination::Domain(b"a\0b".to_vec())] {
            assert_eq!(contract::check_refused(&Socks4Request { destination, ..req.clone() }), Error::Unwritable);
        }
        for user_id in [b"ab\0cd".to_vec(), vec![b'u'; 256]] { assert_eq!(contract::check_refused(&Socks4Request { user_id, ..req.clone() }), Error::Unwritable); }
    }

    #[test]
    fn requests_byte_at_a_time_are_bounded() {
        let request = Socks4Request { command: Socks4Command::Connect, port: 80,
            destination: Socks4Destination::Domain(vec![b'd'; MAX_SOCKS4_DOMAIN]), user_id: vec![b'u'; MAX_USER_ID] };
        let bytes = request.to_bytes().unwrap();
        let started = std::time::Instant::now();
        for _ in 0..2000 {
            let mut stream = Stream::new(ClientMessages::new());
            for (i, chunk) in chunks(&bytes, &[1]).enumerate() {
                assert_eq!(stream.push(chunk), 1);
                if i + 1 < bytes.len() { assert_eq!(stream.next(), None); }
                assert!(stream.buffered() <= MAX_MESSAGE);
            }
            assert_eq!(stream.next(), Some(Ok(Ok(ClientMessage::Socks4(request.clone())))));
            assert_eq!(stream.buffered(), 0);
        }
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    #[test]
    fn writers_refuse_changes() {
        assert_eq!(contract::check_refused(&Greeting { methods: vec![Method::NoAuth; MAX_METHODS + 1] }), Error::Unwritable);
        assert_eq!(contract::check_refused(&Greeting { methods: vec![Method::Other(0)] }), Error::Unwritable);
        assert_eq!(contract::check_refused(&AuthRequest { username: vec![0; 256], password: vec![] }), Error::Unwritable);
        assert_eq!(contract::check_refused(&AuthRequest { username: vec![], password: vec![0; 256] }), Error::Unwritable);
        assert_eq!(contract::check_refused(&Request { address: Address::Domain(vec![0; 256]), ..request() }), Error::Unwritable);
        assert_eq!(contract::check_refused(&Reply { address: Address::Domain(vec![0; 256]), ..Reply::failure(ReplyCode::GeneralFailure) }), Error::Unwritable);
        assert_eq!(contract::check_refused(&UdpHeader { fragment: 0, address: Address::Domain(vec![0; 256]), port: 0 }), Error::Unwritable);
        let greeting = Greeting { methods: vec![Method::NoAuth; MAX_METHODS] };
        assert!(greeting.to_bytes().is_ok());
        contract::check_wire_value(&greeting);
        let auth = AuthRequest { username: vec![0; MAX_USERNAME], password: vec![0; MAX_PASSWORD] };
        assert!(auth.to_bytes().is_ok());
        contract::check_wire_value(&auth);
        let request = Request { address: Address::Domain(vec![0; MAX_DOMAIN]), ..request() };
        assert!(request.to_bytes().is_ok());
        contract::check_wire_value(&request);
    }

    #[test]
    fn malformed_fields() {
        macro_rules! bad {
            ($ty:ty, $bytes:expr, $error:expr) => { assert_eq!(<$ty>::parse($bytes), Err($error)); };
        }
        bad!(Greeting, &[4, 1, 0], Error::Version(4));
        bad!(Selection, &[0], Error::Version(0));
        bad!(AuthRequest, &[5], Error::Version(5));
        bad!(Request, &[5, 4], Error::Command(4));
        bad!(Request, &[5, 1, 1], Error::Reserved(1));
        bad!(Request, &[5, 1, 0, 2], Error::AddressType(2));
        bad!(Reply, &[5, 0, 3], Error::Reserved(3));
        bad!(Reply, &[5, 0, 0, 9], Error::AddressType(9));
        bad!(Reply, &[4], Error::Version(4));
        bad!(Socks4Request, &[5], Error::Version(5));
        bad!(Socks4Request, &[4, 3], Error::Command(3));
        bad!(Socks4Reply, &[4, 90], Error::Version(4));
        assert_eq!(Error::Command(9).reply_code(), ReplyCode::CommandNotSupported);
        assert_eq!(Error::AddressType(9).reply_code(), ReplyCode::AddressTypeNotSupported);
        assert_eq!(Error::Reserved(1).reply_code(), ReplyCode::GeneralFailure);
        for e in [Error::Version(1), Error::Command(1), Error::AddressType(1), Error::Reserved(1), Error::FieldTooLong, Error::Method(1)] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn client_handshake_login_and_handoff() {
        let mut stream = Stream::new(ClientMessages::new());
        assert_eq!(stream.decoder().phase(), ServerPhase::Greeting);
        let auth = AuthRequest { username: b"u".to_vec(), password: b"p".to_vec() };
        let mut bytes = vec![5, 1, 2];
        auth.write(&mut bytes).unwrap();
        request().write(&mut bytes).unwrap();
        bytes.extend_from_slice(b"tail");
        assert_eq!(stream.push(&bytes), bytes.len());
        assert!(matches!(stream.next(), Some(Ok(Ok(ClientMessage::Greeting(_))))));
        assert_eq!(stream.next(), None);
        stream.decoder().verified(true);
        assert!(!stream.decoder().select(Method::NoAuth));
        assert!(stream.decoder().select(Method::UsernamePassword));
        assert_eq!(stream.next(), Some(Ok(Ok(ClientMessage::Auth(auth)))));
        assert_eq!(stream.decoder().phase(), ServerPhase::Verifying);
        assert_eq!(stream.next(), None);
        stream.decoder().verified(true);
        assert_eq!(stream.next(), Some(Ok(Ok(ClientMessage::Request(request())))));
        assert_eq!(stream.decoder().phase(), ServerPhase::Done);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.into_parts().0.unread(), b"tail");
    }

    #[test]
    fn selection_refusal_and_unknown_methods() {
        for (code, phase) in [(0, ServerPhase::Request), (2, ServerPhase::Auth), (1, ServerPhase::Done), (0x80, ServerPhase::Done), (0xff, ServerPhase::Closed)] {
            let mut d = ClientMessages::new();
            assert!(matches!(d.decode(&[5, 1, code], false), Ok(Step::Item(Ok(_), 3))));
            assert!(d.select(Method::Other(code)));
            assert_eq!(d.phase(), phase);
            assert!(!d.select(Method::NoAuth));
        }
        let mut d = ClientMessages::new();
        d.decode(&[5, 0], false).unwrap();
        assert!(!d.select(Method::NoAuth));
        assert!(d.select(Method::NoAcceptable));
        assert_eq!(d.decode(b"tunnel", false), Ok(Step::End));
        let mut d = ClientMessages::new();
        d.decode(&[5, 1, 2], false).unwrap();
        d.select(Method::UsernamePassword);
        d.decode(&[1, 0, 0], false).unwrap();
        d.verified(false);
        assert_eq!(d.phase(), ServerPhase::Closed);
        assert_eq!(d.decode(b"tail", false), Ok(Step::End));
        for (code, allowed, phase) in [(0, false, ClientPhase::Failed), (2, true, ClientPhase::Auth), (0xff, true, ClientPhase::Closed)] {
            let mut d = ServerMessages::socks5_offering(Command::Connect, &[Method::UsernamePassword]);
            let result = d.decode(&[5, code], false).unwrap();
            assert_eq!(matches!(result, Step::Item(Ok(_), 2)), allowed);
            if !allowed {
                assert_eq!(result, Step::Item(Err(Error::Method(0)), 2));
            }
            assert_eq!(d.phase(), phase);
        }
        // Offers past the wire limit cannot be written and do not authorize a selection.
        let mut offered = vec![Method::NoAuth; MAX_METHODS];
        offered.push(Method::Other(4));
        assert_eq!(contract::check_refused(&Greeting { methods: offered.clone() }), Error::Unwritable);
        let mut d = ServerMessages::socks5_offering(Command::Connect, &offered);
        assert_eq!(d.decode(&[5, 4], false), Ok(Step::Item(Err(Error::Method(4)), 2)));
    }

    #[test]
    fn replies_bind_and_refusals() {
        let first = Reply { code: ReplyCode::Succeeded, address: Address::Ipv4(Ipv4Addr::LOCALHOST), port: 5000 };
        let second = Reply { port: 6000, ..first.clone() };
        let mut bytes = vec![5, 2, 1, 0];
        first.write(&mut bytes).unwrap(); second.write(&mut bytes).unwrap(); bytes.push(b'x');
        let mut stream = Stream::new(ServerMessages::socks5(Command::Bind));
        assert_eq!(stream.push(&bytes), bytes.len());
        assert!(matches!(stream.next(), Some(Ok(Ok(ServerMessage::Selection(_))))));
        assert_eq!(stream.decoder().phase(), ClientPhase::Auth);
        assert_eq!(stream.next(), Some(Ok(Ok(ServerMessage::Auth(AuthReply { status: 0 })))));
        assert_eq!(stream.next(), Some(Ok(Ok(ServerMessage::Reply(first)))));
        assert_eq!(stream.decoder().phase(), ClientPhase::SecondReply);
        assert_eq!(stream.next(), Some(Ok(Ok(ServerMessage::Reply(second)))));
        assert_eq!(stream.decoder().phase(), ClientPhase::Done);
        assert_eq!(stream.into_parts().0.unread(), b"x");
        for bytes in [vec![5, 2, 1, 1], vec![5, 0xff], vec![5, 0, 5, 5, 0, 1, 0, 0, 0, 0, 0, 0]] {
            let mut s = Stream::new(ServerMessages::socks5(Command::Connect));
            codec::pump(&mut s, &bytes, |m| { m.unwrap(); }).unwrap();
            assert_eq!(s.decoder().phase(), ClientPhase::Closed);
        }
        let reply = Socks4Reply { code: Socks4Code::Granted, port: 1, ip: Ipv4Addr::LOCALHOST };
        let bytes = [reply.to_bytes().unwrap(), reply.to_bytes().unwrap()].concat();
        assert_eq!(decode_all(|| ServerMessages::socks4(Socks4Command::Bind), &bytes), (vec![Ok(ServerMessage::Socks4(reply)); 2], None));
        let mut d = ServerMessages::socks4(Socks4Command::Connect);
        d.decode(&[0, 91, 0, 0, 0, 0, 0, 0], false).unwrap();
        assert_eq!(d.phase(), ClientPhase::Closed);
    }

    #[test]
    fn errors_end_once_and_decisions_are_bounded() {
        let mut stream = Stream::new(ClientMessages::new());
        assert_eq!(stream.push(&[7]), 1);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(FrameError::Version(7)))));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.decoder().phase(), ServerPhase::Failed);
        let mut stream = Stream::new(ServerMessages::socks5(Command::Connect));
        assert_eq!(stream.push(&[4, 0]), 2);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(FrameError::Version(4)))));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.decoder().phase(), ClientPhase::Failed);
        let mut d = ClientMessages::new();
        d.decode(&[5, 1, 0], false).unwrap(); d.select(Method::NoAuth);
        let mut copy = d.clone();
        let bytes = request().to_bytes().unwrap();
        assert_eq!(d.decode(&bytes[..2], false), Ok(Step::Need));
        assert_eq!(d.decode(&bytes, false), copy.decode(&bytes, false));
        assert_eq!(d.phase(), ServerPhase::Done);
        let make = || { let mut d = ClientMessages::new(); d.decode(&[5, 1, 0], false).unwrap(); d };
        let bytes = vec![0; MAX_MESSAGE + 10];
        contract::check_decode_with_alloc_limit(make, &bytes, 2 * MAX_MESSAGE);
        assert_eq!(decode_all(make, &bytes).1, Some(Fail::Protocol(FrameError::DecisionRequired(ServerPhase::Selecting))));
    }

    #[test]
    fn generated_contracts() {
        let mut rng = Lcg::new(0x50c4_5f00);
        let seeds = [request().to_bytes().unwrap(), vec![5, 1, 2, 1, 0, 0], vec![4, 1, 0, 80, 1, 2, 3, 4, 0]];
        for _ in 0..512 {
            let mut bytes = if rng.coin() { seeds[rng.index(seeds.len())].clone() } else { rng.bytes(80) };
            mutate(&mut rng, &mut bytes);
            contract::check_decode_with_alloc_limit(ClientMessages::new, &bytes, 2 * MAX_MESSAGE);
            for make in [|| ServerMessages::socks5(Command::Connect), || ServerMessages::socks5(Command::Bind), || ServerMessages::socks4(Socks4Command::Bind)] {
                contract::check_decode_with_alloc_limit(make, &bytes, 2 * MAX_MESSAGE);
            }
            macro_rules! wires { ($($ty:ty),+) => {$(contract::check_wire::<$ty>(&bytes);)+}; }
            wires!(Greeting, Selection, AuthRequest, AuthReply, Request, Reply, Socks4Request, Socks4Reply, Endpoint, UdpHeader, UdpDatagram);
        }
    }
}
