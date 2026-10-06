//! NTP: reading and writing time packets, with no I/O.
//!
//! NTP (RFC 5905) is how a machine sets its clock. A client sends a small
//! UDP datagram to port 123, and the server answers with the time. Simple
//! clients (SNTP, RFC 4330) take that answer as it is. So a world that runs
//! the NTP server decides what time the agent's machine thinks it is.
//!
//! Every packet starts with the same 48-byte header. Times in it are
//! [`Timestamp`]s: seconds since 1900, and a binary fraction of a second.
//! This module reads and writes the header. Any extension fields, key ID or
//! MAC that follow it are kept as raw bytes in [`Packet::trailer`]. A
//! server with stratum 0 sends a four-letter "kiss code" in place of a
//! reference ID, such as `RATE` to tell a client to slow down; see
//! [`KissCode`].
//!
//! Nothing here reads a socket or a clock. A world that plays a time server
//! reads each datagram from its UDP socket, passes it to [`Packet::parse`],
//! and builds the answer with [`server_reply`], giving it the times it wants
//! to report. NTP runs over UDP, one packet per datagram, so there is no
//! stream decoder.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::ntp::{Mode, Packet, ServerInfo, Timestamp, server_reply};
//!
//! // A client asks for the time. Its own clock says 2023-11-14 22:13:20 UTC.
//! let request = Packet::client_request(Timestamp::from_unix(1_700_000_000, 0));
//! let bytes = request.to_bytes().unwrap();
//! assert_eq!(bytes.len(), 48);
//! assert_eq!(bytes[0], 0x23); // No leap warning, version 4, client mode.
//!
//! // The world answers that it is 2019-03-14 00:00:00.5 UTC.
//! let asked = Packet::parse(&bytes).unwrap();
//! let now = Timestamp::from_unix(1_552_521_600, 500_000_000);
//! let reply = server_reply(&asked, &ServerInfo::default(), now, now).unwrap();
//!
//! let answer = Packet::parse(&reply.to_bytes().unwrap()).unwrap();
//! assert_eq!(answer.mode, Mode::Server);
//! assert_eq!(answer.transmit.to_unix(), (1_552_521_600, 500_000_000));
//! // The client matches the reply to its request by this field.
//! assert_eq!(answer.origin, request.transmit);
//! ```

use fictionet::stdlib::codec::Wire;

/// The UDP port NTP servers listen on.
pub const PORT: u16 = 123;
/// The NTP version this module writes by default.
pub const VERSION: u8 = 4;
/// The length of the header every packet starts with.
pub const HEADER_LEN: usize = 48;
/// The most bytes after the header that a packet may carry here: the most
/// whole 4-byte words that fit in one UDP datagram over IPv4 (65,507 bytes)
/// after the header. Most packets carry nothing, or a MAC of 20 or 24
/// bytes. NTS (RFC 8915) packets carry extension fields that can run past
/// a kilobyte, and RFC 7822 sets no limit of its own. A longer datagram is
/// refused by readers and writers.
pub const MAX_TRAILER: usize = (65_507 - HEADER_LEN) / 4 * 4;
/// The longest packet: the header and the longest trailer.
pub const MAX_PACKET: usize = HEADER_LEN + MAX_TRAILER;
/// Seconds from 1900-01-01 00:00 UTC, where NTP time starts, to the Unix
/// epoch, 1970-01-01 00:00 UTC.
pub const UNIX_OFFSET: i64 = 2_208_988_800;
/// The Unix time [`Timestamp::to_unix`] reads timestamps around: the first
/// NTP era wrap, 2036-02-07 06:28:16 UTC. Timestamps are read as within
/// 2³¹ seconds (68 years) of it.
pub const ERA_PIVOT: i64 = (1 << 32) - UNIX_OFFSET;

/// The leap indicator: whether the last minute of today has a leap second.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Leap {
    /// No leap second.
    None,
    /// The last minute of the day has 61 seconds.
    AddSecond,
    /// The last minute of the day has 59 seconds.
    RemoveSecond,
    /// The server's clock is not set. A client should not use its time.
    /// Kiss-o'-death packets carry this too.
    Unsynchronized,
}

impl Leap {
    /// The two bits this leap indicator is written as.
    pub fn bits(self) -> u8 {
        match self {
            Leap::None => 0,
            Leap::AddSecond => 1,
            Leap::RemoveSecond => 2,
            Leap::Unsynchronized => 3,
        }
    }

    /// The leap indicator in the low two bits of `b`. Higher bits are
    /// ignored.
    pub fn from_bits(b: u8) -> Leap {
        match b & 3 {
            0 => Leap::None,
            1 => Leap::AddSecond,
            2 => Leap::RemoveSecond,
            _ => Leap::Unsynchronized,
        }
    }
}

/// What kind of packet this is. Modes 0 (reserved), 6 (control messages,
/// as `ntpq` sends) and 7 (private, as `ntpdc` sends) have other formats,
/// so this module does not read them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    /// A peer offering to synchronize with another (mode 1).
    SymmetricActive,
    /// A peer's answer to a symmetric active packet (mode 2).
    SymmetricPassive,
    /// A client asking for the time (mode 3).
    Client,
    /// A server's answer to a client (mode 4).
    Server,
    /// A server sending the time to everyone on a network (mode 5).
    Broadcast,
}

impl Mode {
    /// The mode's number, 1 to 5.
    pub fn bits(self) -> u8 {
        match self {
            Mode::SymmetricActive => 1,
            Mode::SymmetricPassive => 2,
            Mode::Client => 3,
            Mode::Server => 4,
            Mode::Broadcast => 5,
        }
    }

    /// The mode with number `b`, or `None` for 0, 6, 7 and anything past 7.
    pub fn from_bits(b: u8) -> Option<Mode> {
        match b {
            1 => Some(Mode::SymmetricActive),
            2 => Some(Mode::SymmetricPassive),
            3 => Some(Mode::Client),
            4 => Some(Mode::Server),
            5 => Some(Mode::Broadcast),
            _ => None,
        }
    }
}

/// An NTP timestamp: seconds since 1900-01-01 00:00 UTC, and a fraction of
/// a second in units of 2⁻³² s (about 0.23 ns).
///
/// The seconds field is 32 bits, so it wraps every 2³² seconds, about 136
/// years. Each span is an era. Era 0 began in 1900 and ends on 2036-02-07
/// 06:28:16 UTC, when era 1 begins. A packet does not say which era it
/// means, so a reader has to choose. [`Timestamp::to_unix`] reads a
/// timestamp as the time within 68 years of [`ERA_PIVOT`], which covers
/// 1968-01-20 to 2104-02-26, as RFC 4330 suggests. [`Timestamp::to_unix_near`]
/// reads it near any time the caller gives.
///
/// The all-zero timestamp means "unknown" in NTP, as in the origin of a
/// client's first request. [`Timestamp::ZERO`] names it.
///
/// Timestamps do not implement `Ord`. Their bits run backward at each era
/// wrap: a time one second into 2036's era 1 has smaller bits than one a
/// second before it. To order times, compare [`Timestamp::to_unix`] or
/// [`Timestamp::to_unix_near`]. For a sort key with no time meaning, use
/// [`Timestamp::to_bits`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Timestamp {
    /// Whole seconds since the start of the era.
    pub seconds: u32,
    /// The fraction of a second, in units of 2⁻³² s.
    pub fraction: u32,
}

impl Timestamp {
    /// The all-zero timestamp, which NTP uses for "no time".
    pub const ZERO: Timestamp = Timestamp { seconds: 0, fraction: 0 };

    /// The timestamp for `secs` seconds and `nanos` nanoseconds after the
    /// Unix epoch. Negative `secs` are before 1970. Nanoseconds of a second
    /// or more carry into the seconds. The seconds are taken modulo 2³², as
    /// NTP does, so a time in any era gets the right bits. The fraction is
    /// rounded to the nearest 2⁻³² s.
    pub fn from_unix(secs: i64, nanos: u32) -> Timestamp {
        let carry = i128::from(nanos / 1_000_000_000);
        let nanos = u64::from(nanos % 1_000_000_000);
        let ntp = i128::from(secs) + carry + i128::from(UNIX_OFFSET);
        // At most (10⁹ − 1) · 2³² + 5 · 10⁸, so this fits in a u64, and the
        // quotient stays below 2³².
        let fraction = ((nanos << 32) + 500_000_000) / 1_000_000_000;
        Timestamp { seconds: ntp.rem_euclid(1 << 32) as u32, fraction: fraction as u32 }
    }

    /// The time as whole seconds and nanoseconds after the Unix epoch,
    /// reading the era as described on [`Timestamp`]: within 68 years of
    /// [`ERA_PIVOT`], from 1968-01-20 to 2104-02-26. The nanoseconds are
    /// rounded to the nearest one and are always below 10⁹.
    pub fn to_unix(self) -> (i64, u32) {
        self.to_unix_near(ERA_PIVOT)
    }

    /// The time as seconds and nanoseconds after the Unix epoch, in the era
    /// that puts it closest to `pivot` (a Unix time, such as the caller's
    /// idea of now). The whole seconds are at least `pivot` − 2³¹ and below
    /// `pivot` + 2³¹. A fraction that rounds up to a whole second can take
    /// the result to `pivot` + 2³¹ itself. Near the ends of the `i64` range
    /// the seconds saturate.
    pub fn to_unix_near(self, pivot: i64) -> (i64, u32) {
        let era = 1i128 << 32;
        let base = i128::from(pivot) + i128::from(UNIX_OFFSET) - (1 << 31);
        let ntp = base + (i128::from(self.seconds) - base).rem_euclid(era);
        let nanos = (u64::from(self.fraction) * 1_000_000_000 + (1 << 31)) >> 32;
        // Rounding the largest fractions up reaches a whole second.
        let (ntp, nanos) = if nanos >= 1_000_000_000 { (ntp + 1, 0) } else { (ntp, nanos as u32) };
        let unix = ntp - i128::from(UNIX_OFFSET);
        (unix.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64, nanos)
    }

    /// Whether this is the all-zero "no time" timestamp.
    pub fn is_zero(self) -> bool {
        self == Timestamp::ZERO
    }

    /// The timestamp as one 64-bit number, seconds in the high half.
    pub fn to_bits(self) -> u64 {
        (u64::from(self.seconds) << 32) | u64::from(self.fraction)
    }

    /// The timestamp from one 64-bit number, seconds in the high half.
    pub fn from_bits(bits: u64) -> Timestamp {
        Timestamp { seconds: (bits >> 32) as u32, fraction: bits as u32 }
    }

    fn read(b: &[u8], i: usize) -> Timestamp {
        Timestamp { seconds: be32(b, i), fraction: be32(b, i + 4) }
    }
}

/// A kiss code: the four ASCII letters a stratum-0 server puts where the
/// reference ID goes, to tell a client something instead of the time. The
/// codes are those of RFC 5905, section 7.4. A client that gets `DENY` or
/// `RSTR` must stop asking this server, and one that gets `RATE` must ask
/// less often. Codes that start with `X` are for experiments, and a client
/// ignores those it does not know.
///
/// Construct named codes with [`KissCode::from_bytes`]. The writer refuses
/// `Other` values that name a defined code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KissCode {
    /// `ACST`: the association belongs to a unicast server.
    Acst,
    /// `AUTH`: server authentication failed.
    Auth,
    /// `AUTO`: Autokey sequence failed.
    Auto,
    /// `BCST`: the association belongs to a broadcast server.
    Bcst,
    /// `CRYP`: cryptographic authentication or identification failed.
    Cryp,
    /// `DENY`: access denied by a remote server.
    Deny,
    /// `DROP`: lost peer in symmetric mode.
    Drop,
    /// `RSTR`: access denied because of a local policy.
    Rstr,
    /// `INIT`: the association has not yet synchronized for the first time.
    Init,
    /// `MCST`: the association belongs to a dynamically discovered server.
    Mcst,
    /// `NKEY`: no key found.
    Nkey,
    /// `RATE`: the client is sending too often; it should slow down.
    Rate,
    /// `RMOT`: alteration of the association from a remote host running
    /// ntpdc.
    Rmot,
    /// `STEP`: a step change in system time has occurred, and the
    /// association has not yet resynchronized.
    Step,
    /// Any other four bytes.
    Other([u8; 4]),
}

impl KissCode {
    const NAMED: [(KissCode, [u8; 4]); 14] = [
        (KissCode::Acst, *b"ACST"),
        (KissCode::Auth, *b"AUTH"),
        (KissCode::Auto, *b"AUTO"),
        (KissCode::Bcst, *b"BCST"),
        (KissCode::Cryp, *b"CRYP"),
        (KissCode::Deny, *b"DENY"),
        (KissCode::Drop, *b"DROP"),
        (KissCode::Rstr, *b"RSTR"),
        (KissCode::Init, *b"INIT"),
        (KissCode::Mcst, *b"MCST"),
        (KissCode::Nkey, *b"NKEY"),
        (KissCode::Rate, *b"RATE"),
        (KissCode::Rmot, *b"RMOT"),
        (KissCode::Step, *b"STEP"),
    ];

    /// The kiss code written as these four bytes. A named code always
    /// comes back as its variant, never as [`KissCode::Other`].
    pub fn from_bytes(b: [u8; 4]) -> KissCode {
        KissCode::NAMED.iter().find(|(_, bytes)| *bytes == b).map_or(KissCode::Other(b), |(code, _)| *code)
    }

    /// The four bytes this kiss code is written as.
    fn octets(self) -> [u8; 4] {
        match self {
            KissCode::Other(b) => b,
            named => KissCode::NAMED.iter().find(|(code, _)| *code == named).map_or([0; 4], |(_, bytes)| *bytes),
        }
    }
}

impl std::fmt::Display for KissCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.octets() {
            if b.is_ascii_graphic() {
                write!(f, "{}", char::from(b))?;
            } else {
                write!(f, "\\x{b:02x}")?;
            }
        }
        Ok(())
    }
}

/// One NTP packet: the 48-byte header's fields, and whatever followed it.
///
/// [`Packet::parse`] followed by [`Packet::write`] gives back the same
/// bytes, since every field is kept as it was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// Whether a leap second is coming, or the clock is unset.
    pub leap: Leap,
    /// The NTP version, 1 to 7. 4 is current. The reader refuses 0, and the
    /// writer refuses values outside that range. [`server_reply`] and [`kiss_reply`]
    /// answer only versions 1 to 4.
    pub version: u8,
    /// What kind of packet this is.
    pub mode: Mode,
    /// How far the sender is from a reference clock. 1 is a server with
    /// its own clock (GPS, an atomic clock), 2 a server that sets its time
    /// from a stratum 1 server, and so on up to 15. 16 means unsynchronized.
    /// 0 marks a kiss-o'-death packet; see [`Packet::kiss_code`].
    pub stratum: u8,
    /// The longest interval between packets the sender wants, as a power
    /// of two in seconds (6 is 64 s).
    pub poll: i8,
    /// The precision of the sender's clock, as a power of two in seconds
    /// (−20 is about a microsecond).
    pub precision: i8,
    /// The round-trip delay to the reference clock, in NTP short format:
    /// seconds in the high 16 bits and a fraction in the low 16.
    pub root_delay: u32,
    /// The most error the sender may have relative to the reference clock,
    /// in NTP short format, like [`Packet::root_delay`].
    pub root_dispersion: u32,
    /// Which reference clock the sender uses. At stratum 1 it is four ASCII
    /// letters such as `GPS\0`. Above it is usually the IPv4 address of the
    /// upstream server. At stratum 0 it is a [`KissCode`].
    pub reference_id: [u8; 4],
    /// When the sender's clock was last set.
    pub reference: Timestamp,
    /// In a reply, the request's transmit time, copied back so the client
    /// can match the two. A simple SNTP client sends zero here. A full NTP
    /// client sends the transmit time of the last packet it got from the
    /// server.
    pub origin: Timestamp,
    /// When the server received the request.
    pub receive: Timestamp,
    /// When the sender sent this packet.
    pub transmit: Timestamp,
    /// The bytes after the header: extension fields (RFC 7822), or a key
    /// ID and MAC. They are kept raw. The reader requires a multiple of 4
    /// bytes, at most [`MAX_TRAILER`]. The writer enforces the same limits.
    pub trailer: Vec<u8>,
}

/// Why a datagram is not an NTP packet this module can read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// A fixed field has the wrong byte count.
    FieldLength {
        /// The required byte count.
        want: usize,
        /// The supplied byte count.
        got: usize,
    },
    /// The value cannot be written without changing it.
    Unwritable,
    /// The datagram was shorter than the 48-byte header. Holds its length.
    Short(usize),
    /// The datagram was longer than [`MAX_PACKET`]. Holds its length.
    Long(usize),
    /// The version field was 0.
    Version(u8),
    /// The mode was 0, 6 or 7, which have no header of this shape. Holds
    /// the mode.
    Mode(u8),
    /// The bytes after the header were not a multiple of 4, as extension
    /// fields and MACs always are. Holds how many there were.
    Trailer(usize),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::FieldLength { want, got } => write!(f, "{got} bytes, expected {want}"),
            ParseError::Unwritable => f.write_str("value cannot be written without changing it"),
            ParseError::Short(n) => write!(f, "{n} bytes, shorter than the {HEADER_LEN}-byte NTP header"),
            ParseError::Long(n) => write!(f, "{n} bytes, longer than the {MAX_PACKET} an NTP packet may have here"),
            ParseError::Version(v) => write!(f, "NTP version {v}, not 1 to 7"),
            ParseError::Mode(m) => write!(f, "NTP mode {m}, not 1 to 5"),
            ParseError::Trailer(n) => write!(f, "{n} bytes after the NTP header, not a multiple of 4"),
        }
    }
}

impl std::error::Error for ParseError {}

impl Packet {
    /// A version 4 client request sent at `transmit`, by the client's own
    /// clock. Every other field is zero, as a minimal SNTP client sends it
    /// (RFC 4330, section 5). The server copies `transmit` into its reply's
    /// origin. The NTP data minimization draft
    /// (draft-ietf-ntp-data-minimization) goes further: it puts a random
    /// number in `transmit` instead of the time, and sets `precision` to
    /// 0x20. A caller that wants that can pass a random [`Timestamp`] and
    /// set the field.
    pub fn client_request(transmit: Timestamp) -> Packet {
        Packet {
            leap: Leap::None,
            version: VERSION,
            mode: Mode::Client,
            stratum: 0,
            poll: 0,
            precision: 0,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: [0; 4],
            reference: Timestamp::ZERO,
            origin: Timestamp::ZERO,
            receive: Timestamp::ZERO,
            transmit,
            trailer: Vec::new(),
        }
    }

    /// The kiss code this packet carries, if it is a kiss-o'-death packet:
    /// one with stratum 0 that is not a client request. Otherwise `None`.
    /// Client requests often have stratum 0, since a simple client leaves
    /// it zero and an unsynchronized one sends 16 as 0, so they never carry
    /// a kiss.
    pub fn kiss_code(&self) -> Option<KissCode> {
        if self.stratum == 0 && self.mode != Mode::Client {
            Some(KissCode::from_bytes(self.reference_id))
        } else {
            None
        }
    }
}

/// How the world's time server describes itself in its replies. These are
/// the fields of a reply that do not depend on the request or on when it
/// came.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerInfo {
    /// The leap indicator to send.
    pub leap: Leap,
    /// The server's stratum, 1 to 15, or 16 for a server whose clock is not
    /// set. [`server_reply`] sends 16 and above as 0, as RFC 5905 does.
    /// 0 itself would make every reply a kiss-o'-death packet; use
    /// [`kiss_reply`] for that instead.
    pub stratum: u8,
    /// The precision of the server's clock, as a power of two in seconds.
    pub precision: i8,
    /// The round-trip delay to the reference clock, in NTP short format.
    pub root_delay: u32,
    /// The server's error bound, in NTP short format.
    pub root_dispersion: u32,
    /// The reference ID, such as `GPS\0` at stratum 1.
    pub reference_id: [u8; 4],
    /// When the server's clock was last set.
    pub reference: Timestamp,
}

impl Default for ServerInfo {
    /// A stratum 1 server with a GPS clock, precise to about a microsecond,
    /// with no leap second coming. Its reference time is zero; set it to a
    /// time shortly before the replies, as a real server's would be.
    fn default() -> ServerInfo {
        ServerInfo {
            leap: Leap::None,
            stratum: 1,
            precision: -20,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: *b"GPS\0",
            reference: Timestamp::ZERO,
        }
    }
}

/// Why [`server_reply`] or [`kiss_reply`] would not answer a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyError {
    /// The packet was not a request: neither a client's (mode 3) nor a
    /// symmetric active peer's (mode 1). Holds its mode. Replies and
    /// broadcasts get no answer.
    NotClient(Mode),
    /// The request's version was not 1 to 4, the versions RFC 4330 and RFC
    /// 5905 define. Holds it. A reply copies the request's version, so it
    /// would claim a protocol this module does not speak.
    Version(u8),
}

impl std::fmt::Display for ReplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplyError::NotClient(m) => write!(f, "NTP mode {} packet, not a request (mode 3 or 1)", m.bits()),
            ReplyError::Version(v) => write!(f, "NTP version {v} request, not 1 to 4"),
        }
    }
}

impl std::error::Error for ReplyError {}

/// The mode a reply to `request` takes: server (4) for a client request
/// (3), and symmetric passive (2) for a symmetric active peer (1), as RFC
/// 4330, section 5, says. Only versions 1 to 4 are answered.
fn reply_mode(request: &Packet) -> Result<Mode, ReplyError> {
    let mode = match request.mode {
        Mode::Client => Mode::Server,
        Mode::SymmetricActive => Mode::SymmetricPassive,
        other => return Err(ReplyError::NotClient(other)),
    };
    if !(1..=VERSION).contains(&request.version) {
        return Err(ReplyError::Version(request.version));
    }
    Ok(mode)
}

/// A server's reply to a request, as RFC 5905 builds it: mode 4 to a
/// client (mode 3), and mode 2 to a symmetric active peer (mode 1), as RFC
/// 4330 does so that clients such as Windows Time in symmetric active mode
/// get the time too. `receive` is when the request came in and `transmit`
/// when the reply goes out, both by the world's clock; a world that has no
/// reason to tell them apart can pass the same time twice. The reply uses
/// the request's version (1 to 4; others are refused) and poll, and copies
/// the request's transmit time into its origin so the client can match the
/// two. A stratum of 16 or more is sent as 0, as RFC 5905's `fast_xmit()`
/// does. The reply carries no trailer.
pub fn server_reply(
    request: &Packet,
    server: &ServerInfo,
    receive: Timestamp,
    transmit: Timestamp,
) -> Result<Packet, ReplyError> {
    let mode = reply_mode(request)?;
    Ok(Packet {
        leap: server.leap,
        version: request.version,
        mode,
        stratum: if server.stratum >= 16 { 0 } else { server.stratum },
        poll: request.poll,
        precision: server.precision,
        root_delay: server.root_delay,
        root_dispersion: server.root_dispersion,
        reference_id: server.reference_id,
        reference: server.reference,
        origin: request.transmit,
        receive,
        transmit,
        trailer: Vec::new(),
    })
}

/// A kiss-o'-death reply to a request: stratum 0, the leap indicator
/// unsynchronized, and `code` in the reference ID. It takes the mode and
/// version [`server_reply`] would. The request's transmit time goes into
/// all four timestamps, so the reply tells the client nothing about the
/// server's clock.
pub fn kiss_reply(request: &Packet, code: KissCode) -> Result<Packet, ReplyError> {
    let mode = reply_mode(request)?;
    let t = request.transmit;
    Ok(Packet {
        leap: Leap::Unsynchronized,
        version: request.version,
        mode,
        stratum: 0,
        poll: request.poll,
        precision: 0,
        root_delay: 0,
        root_dispersion: 0,
        reference_id: code.octets(),
        reference: t,
        origin: t,
        receive: t,
        transmit: t,
        trailer: Vec::new(),
    })
}

fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

impl Wire for Packet {
    type ParseError = ParseError;
    type WriteError = ParseError;

    /// Reads one NTP packet from a whole UDP datagram.
    /// Refuses invalid headers and lengths. Reads the whole input.
    fn parse(b: &[u8]) -> Result<Packet, ParseError> {
        if b.len() < HEADER_LEN {
            return Err(ParseError::Short(b.len()));
        }
        if b.len() > MAX_PACKET {
            return Err(ParseError::Long(b.len()));
        }
        let version = (b[0] >> 3) & 7;
        if version == 0 {
            return Err(ParseError::Version(version));
        }
        let mode = Mode::from_bits(b[0] & 7).ok_or(ParseError::Mode(b[0] & 7))?;
        let trailer = &b[HEADER_LEN..];
        if !trailer.len().is_multiple_of(4) {
            return Err(ParseError::Trailer(trailer.len()));
        }
        Ok(Packet {
            leap: Leap::from_bits(b[0] >> 6),
            version,
            mode,
            stratum: b[1],
            poll: b[2] as i8,
            precision: b[3] as i8,
            root_delay: be32(b, 4),
            root_dispersion: be32(b, 8),
            reference_id: [b[12], b[13], b[14], b[15]],
            reference: Timestamp::read(b, 16),
            origin: Timestamp::read(b, 24),
            receive: Timestamp::read(b, 32),
            transmit: Timestamp::read(b, 40),
            trailer: trailer.to_vec(),
        })
    }

    /// Appends the packet. Refuses versions outside 1 to 7, trailers above [`MAX_TRAILER`],
    /// and trailer lengths that are not multiples of four. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), ParseError> {
        if !(1..=7).contains(&self.version) || self.trailer.len() > MAX_TRAILER || !self.trailer.len().is_multiple_of(4) {
            return Err(ParseError::Unwritable);
        }
        let trailer = &self.trailer;
        let mut out = Vec::with_capacity(HEADER_LEN + trailer.len());
        out.push((self.leap.bits() << 6) | (self.version << 3) | self.mode.bits());
        out.push(self.stratum);
        out.push(self.poll as u8);
        out.push(self.precision as u8);
        out.extend_from_slice(&self.root_delay.to_be_bytes());
        out.extend_from_slice(&self.root_dispersion.to_be_bytes());
        out.extend_from_slice(&self.reference_id);
        self.reference.write(&mut out)?;
        self.origin.write(&mut out)?;
        self.receive.write(&mut out)?;
        self.transmit.write(&mut out)?;
        out.extend_from_slice(trailer);

        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for KissCode {
    type ParseError = ParseError;
    type WriteError = ParseError;

    /// Reads exactly four bytes. Refuses short or trailing input.
    fn parse(b: &[u8]) -> Result<Self, ParseError> {
        let bytes = b.try_into().map_err(|_| ParseError::FieldLength { want: 4, got: b.len() })?;
        Ok(Self::from_bytes(bytes))
    }

    /// Appends four bytes. Refuses an Other value that names a defined code.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), ParseError> {
        let bytes = self.octets();
        if Self::from_bytes(bytes) != *self {
            return Err(ParseError::Unwritable);
        }
        dst.extend_from_slice(&bytes);
        Ok(())
    }
}

impl Wire for Timestamp {
    type ParseError = ParseError;
    type WriteError = ParseError;

    /// Reads exactly eight bytes. Refuses short or trailing input.
    fn parse(b: &[u8]) -> Result<Self, ParseError> {
        if b.len() != 8 {
            return Err(ParseError::FieldLength { want: 8, got: b.len() });
        }
        Ok(Self::read(b, 0))
    }

    /// Appends seconds and fraction in network order. Refuses no values.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), ParseError> {
        dst.extend_from_slice(&self.seconds.to_be_bytes());
        dst.extend_from_slice(&self.fraction.to_be_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use fictionet::stdlib::codec::{contract, Lcg};
    use super::*;

    /// A server reply as an SNTP client might receive it: version 4,
    /// stratum 2, reference ID 192.0.2.1, and a 20-byte key ID and MAC.
    fn sample() -> Vec<u8> {
        let mut b = vec![
            0x24, 0x02, 0x06, 0xe9, // LI 0, v4, mode 4; stratum 2; poll 6; precision -23
            0x00, 0x00, 0x01, 0x80, // root delay 0x0180
            0x00, 0x00, 0x00, 0x40, // root dispersion 0x0040
            192, 0, 2, 1, // reference ID
        ];
        for t in [0xe8f0_0000_8000_0000u64, 0xe8f0_0010_0000_0001, 0xe8f0_0011_4000_0000, 0xe8f0_0011_4000_0100] {
            b.extend_from_slice(&t.to_be_bytes());
        }
        b.extend_from_slice(&[0x11; 20]);
        b
    }

    #[test]
    fn reads_every_header_field() {
        let p = Packet::parse(&sample()).unwrap();
        assert_eq!(p.leap, Leap::None);
        assert_eq!(p.version, 4);
        assert_eq!(p.mode, Mode::Server);
        assert_eq!(p.stratum, 2);
        assert_eq!(p.poll, 6);
        assert_eq!(p.precision, -23);
        assert_eq!(p.root_delay, 0x180);
        assert_eq!(p.root_dispersion, 0x40);
        assert_eq!(p.reference_id, [192, 0, 2, 1]);
        assert_eq!(p.reference, Timestamp { seconds: 0xe8f0_0000, fraction: 0x8000_0000 });
        assert_eq!(p.origin.to_bits(), 0xe8f0_0010_0000_0001);
        assert_eq!(p.receive.to_bits(), 0xe8f0_0011_4000_0000);
        assert_eq!(p.transmit.to_bits(), 0xe8f0_0011_4000_0100);
        assert_eq!(p.trailer, [0x11; 20]);
        assert_eq!(p.kiss_code(), None);
        assert_eq!(p.to_bytes().unwrap(), sample());
    }

    #[test]
    fn first_byte_layouts() {
        // The classic SNTP request byte: LI 0, version 3, client.
        let mut b = [0u8; 48];
        b[0] = 0x1b;
        let p = Packet::parse(&b).unwrap();
        assert_eq!((p.leap, p.version, p.mode), (Leap::None, 3, Mode::Client));
        // LI 3 (unsynchronized), version 4, server.
        b[0] = 0xe4;
        let p = Packet::parse(&b).unwrap();
        assert_eq!((p.leap, p.version, p.mode), (Leap::Unsynchronized, 4, Mode::Server));
        for bits in 0..4 {
            assert_eq!(Leap::from_bits(bits).bits(), bits);
        }
        for bits in 0..=255u8 {
            if let Some(m) = Mode::from_bits(bits) {
                assert_eq!(m.bits(), bits);
            } else {
                assert!(bits == 0 || bits >= 6);
            }
        }
    }

    #[test]
    fn timestamps_and_the_unix_epoch() {
        // RFC 5905, figure 4: 1970-01-01 is NTP second 2,208,988,800.
        assert_eq!(Timestamp::from_unix(0, 0), Timestamp { seconds: 2_208_988_800, fraction: 0 });
        assert_eq!(Timestamp { seconds: 2_208_988_800, fraction: 0 }.to_unix(), (0, 0));
        // Half a second is 2³¹ units.
        assert_eq!(Timestamp::from_unix(0, 500_000_000).fraction, 0x8000_0000);
        // Era 0 starts in 1900: Unix time -2,208,988,800. It falls outside
        // the default window, but a pivot near it reads it.
        assert_eq!(Timestamp::from_unix(-UNIX_OFFSET, 0), Timestamp::ZERO);
        assert_eq!(Timestamp::ZERO.to_unix_near(-UNIX_OFFSET), (-UNIX_OFFSET, 0));
        // With the default window, NTP second 0 is the start of era 1,
        // 2036-02-07 06:28:16 UTC.
        assert_eq!(Timestamp::ZERO.to_unix(), (ERA_PIVOT, 0));
        assert_eq!(ERA_PIVOT, 2_085_978_496);
        // The last second of era 0 and the first of era 1.
        assert_eq!(Timestamp::from_unix(ERA_PIVOT - 1, 0).seconds, u32::MAX);
        assert_eq!(Timestamp::from_unix(ERA_PIVOT, 0).seconds, 0);
        assert_eq!(Timestamp { seconds: u32::MAX, fraction: 0 }.to_unix(), (ERA_PIVOT - 1, 0));
        // The ends of the default window: 1968-01-20 03:14:08 and
        // 2104-02-26 09:42:23 UTC.
        assert_eq!(Timestamp { seconds: 0x8000_0000, fraction: 0 }.to_unix(), (-61_505_152, 0));
        assert_eq!(Timestamp { seconds: 0x7fff_ffff, fraction: 0 }.to_unix(), (4_233_462_143, 0));
        // Nanoseconds past a second carry.
        assert_eq!(Timestamp::from_unix(10, 2_500_000_000), Timestamp::from_unix(12, 500_000_000));
        // The largest fraction rounds up to the next second.
        assert_eq!(Timestamp { seconds: 2_208_988_800, fraction: u32::MAX }.to_unix(), (1, 0));
    }

    #[test]
    fn timestamps_round_trip() {
        for (secs, nanos) in [
            (0, 0),
            (1_700_000_000, 123_456_789),
            (-61_505_152, 999_999_999),
            (4_233_462_143, 1),
            (ERA_PIVOT, 999_999_999),
        ] {
            assert_eq!(Timestamp::from_unix(secs, nanos).to_unix(), (secs, nanos), "{secs}.{nanos:09}");
        }
        // Any era, read near a pivot in that era.
        let far = 9_000_000_000_000i64;
        assert_eq!(Timestamp::from_unix(far, 5).to_unix_near(far + 1_000_000), (far, 5));
        assert_eq!(Timestamp::from_unix(-far, 5).to_unix_near(-far), (-far, 5));
        // Extreme pivots saturate instead of overflowing.
        let (s, _) = Timestamp { seconds: u32::MAX, fraction: u32::MAX }.to_unix_near(i64::MAX);
        assert!(s > i64::MAX - (1 << 32));
        let (s, _) = Timestamp::ZERO.to_unix_near(i64::MIN);
        assert!(s < i64::MIN + (1 << 32));
        let t = Timestamp { seconds: 0xdead_beef, fraction: 0x1234_5678 };
        assert_eq!(Timestamp::from_bits(t.to_bits()), t);
    }

    #[test]
    fn client_request_and_server_reply() {
        let t1 = Timestamp::from_unix(1_700_000_000, 250_000_000);
        let req = Packet::client_request(t1);
        let bytes = req.to_bytes().unwrap();
        assert_eq!(bytes[0], 0x23);
        assert!(bytes[1..40].iter().all(|&b| b == 0));
        assert_eq!(&bytes[40..48], &t1.to_bits().to_be_bytes());
        assert_eq!(Packet::parse(&bytes).unwrap(), req);

        let server = ServerInfo {
            stratum: 2,
            reference_id: [192, 0, 2, 7],
            reference: Timestamp::from_unix(1_699_999_000, 0),
            ..ServerInfo::default()
        };
        let t2 = Timestamp::from_unix(1_700_000_000, 300_000_000);
        let t3 = Timestamp::from_unix(1_700_000_000, 300_100_000);
        let mut asked = Packet::parse(&bytes).unwrap();
        asked.poll = 6;
        let reply = server_reply(&asked, &server, t2, t3).unwrap();
        assert_eq!(reply.mode, Mode::Server);
        assert_eq!(reply.version, 4);
        assert_eq!(reply.stratum, 2);
        assert_eq!(reply.poll, 6);
        assert_eq!(reply.reference_id, [192, 0, 2, 7]);
        assert_eq!((reply.origin, reply.receive, reply.transmit), (t1, t2, t3));
        assert_eq!(Packet::parse(&reply.to_bytes().unwrap()).unwrap(), reply);
        assert_eq!(reply.to_bytes().unwrap()[0], 0x24);

        // A version 3 request gets a version 3 reply.
        asked.version = 3;
        assert_eq!(server_reply(&asked, &server, t2, t3).unwrap().to_bytes().unwrap()[0], 0x1c);
    }

    #[test]
    fn kiss_codes() {
        let req = Packet::client_request(Timestamp::from_unix(1_700_000_000, 0));
        let kod = kiss_reply(&req, KissCode::Rate).unwrap();
        let bytes = kod.to_bytes().unwrap();
        assert_eq!(&bytes[..2], &[0xe4, 0x00]);
        assert_eq!(&bytes[12..16], b"RATE");
        let back = Packet::parse(&bytes).unwrap();
        assert_eq!(back.kiss_code(), Some(KissCode::Rate));
        assert_eq!(back.receive, req.transmit);
        assert_eq!(back.transmit, req.transmit);
        for (code, bytes) in KissCode::NAMED {
            assert_eq!(KissCode::from_bytes(bytes), code);
            assert_eq!(code.to_bytes().unwrap(), bytes);
            assert_eq!(code.to_string(), std::str::from_utf8(&bytes).unwrap());
        }
        assert_eq!(KissCode::from_bytes(*b"XYZW"), KissCode::Other(*b"XYZW"));
        assert_eq!(KissCode::Other(*b"DENY").to_bytes(), Err(ParseError::Unwritable));
        assert_eq!(KissCode::Other(*b"GPS\0").to_string(), "GPS\\x00");
    }

    #[test]
    fn a_symmetric_active_peer_gets_a_symmetric_passive_reply() {
        // RFC 4330, section 5: mode 1 is answered with mode 2, so Windows
        // Time with its symmetric-active flag (0x4) gets the time too.
        let mut b = Packet::client_request(Timestamp::from_unix(1_700_000_000, 0)).to_bytes().unwrap();
        b[0] = 0x21; // LI 0, version 4, symmetric active.
        let req = Packet::parse(&b).unwrap();
        let t = Timestamp::from_unix(1_700_000_001, 0);
        let reply = server_reply(&req, &ServerInfo::default(), t, t).unwrap();
        assert_eq!(reply.mode, Mode::SymmetricPassive);
        assert_eq!(reply.origin, req.transmit);
        assert_eq!(reply.to_bytes().unwrap()[0], 0x22);
        let kod = kiss_reply(&req, KissCode::Rate).unwrap();
        assert_eq!(kod.mode, Mode::SymmetricPassive);
        assert_eq!(Packet::parse(&kod.to_bytes().unwrap()).unwrap().kiss_code(), Some(KissCode::Rate));
    }

    #[test]
    fn only_versions_1_to_4_get_replies() {
        // RFC 5905, appendix A.5.1, drops versions past its own, and RFC
        // 4330 defines versions 1 to 4. A reply must not claim version 5.
        let t = Timestamp::from_unix(1_700_000_001, 0);
        let mut b = Packet::client_request(t).to_bytes().unwrap();
        for v in 1..=7u8 {
            b[0] = (v << 3) | 3;
            let req = Packet::parse(&b).unwrap();
            assert_eq!(req.to_bytes().unwrap(), b);
            let r = server_reply(&req, &ServerInfo::default(), t, t);
            let k = kiss_reply(&req, KissCode::Deny);
            if v <= 4 {
                assert_eq!(r.unwrap().version, v);
                assert_eq!(k.unwrap().version, v);
            } else {
                assert_eq!(r, Err(ReplyError::Version(v)));
                assert_eq!(k, Err(ReplyError::Version(v)));
                assert!(!ReplyError::Version(v).to_string().is_empty());
            }
        }
        // A request built in code with version 0 is refused too.
        let mut req = Packet::client_request(t);
        req.version = 0;
        assert_eq!(server_reply(&req, &ServerInfo::default(), t, t), Err(ReplyError::Version(0)));
    }

    #[test]
    fn timestamps_order_by_time_through_unix() {
        // Two seconds apart across the 2036 wrap. The bits run backward
        // there, so chronological order goes through to_unix.
        let before = Timestamp::from_unix(ERA_PIVOT - 1, 0);
        let after = Timestamp::from_unix(ERA_PIVOT + 1, 0);
        assert!(after.to_bits() < before.to_bits());
        assert!(after.to_unix() > before.to_unix());
    }

    #[test]
    fn replies_only_to_requests() {
        let mut p = Packet::client_request(Timestamp::ZERO);
        for mode in [Mode::SymmetricPassive, Mode::Server, Mode::Broadcast] {
            p.mode = mode;
            let e = server_reply(&p, &ServerInfo::default(), Timestamp::ZERO, Timestamp::ZERO).unwrap_err();
            assert_eq!(e, ReplyError::NotClient(mode));
            assert_eq!(kiss_reply(&p, KissCode::Deny), Err(ReplyError::NotClient(mode)));
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn parse_errors() {
        let good = sample();
        assert_eq!(Packet::parse(&[]), Err(ParseError::Short(0)));
        assert_eq!(Packet::parse(&good[..47]), Err(ParseError::Short(47)));
        let long = vec![0x23; MAX_PACKET + 4];
        assert_eq!(Packet::parse(&long), Err(ParseError::Long(MAX_PACKET + 4)));
        let mut most = vec![0u8; MAX_PACKET];
        most[0] = 0x23;
        assert!(Packet::parse(&most).is_ok());
        let mut b = good.clone();
        b[0] = 0x04; // Version 0.
        assert_eq!(Packet::parse(&b), Err(ParseError::Version(0)));
        for m in [0u8, 6, 7] {
            b[0] = 0x20 | m;
            assert_eq!(Packet::parse(&b), Err(ParseError::Mode(m)));
        }
        let mut b = good.clone();
        b.push(0);
        assert_eq!(Packet::parse(&b), Err(ParseError::Trailer(21)));
        for e in [
            ParseError::Short(1),
            ParseError::Long(2000),
            ParseError::Version(0),
            ParseError::Mode(6),
            ParseError::Trailer(3),
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn every_truncated_prefix_is_refused_or_read() {
        let good = sample();
        for n in 0..good.len() {
            let r = Packet::parse(&good[..n]);
            if n < HEADER_LEN {
                assert_eq!(r, Err(ParseError::Short(n)), "{n} bytes");
            } else if !(n - HEADER_LEN).is_multiple_of(4) {
                assert_eq!(r, Err(ParseError::Trailer(n - HEADER_LEN)), "{n} bytes");
            } else {
                assert_eq!(r.unwrap().to_bytes().unwrap(), &good[..n], "{n} bytes");
            }
        }
    }

    #[test]
    fn writers_refuse_values_that_would_change() {
        let mut p = Packet::client_request(Timestamp::from_unix(5, 5));
        for version in [0, 8, 200] {
            p.version = version;
            assert_eq!(p.to_bytes(), Err(ParseError::Unwritable));
            contract::check_wire_value(&p);
        }
        p.version = 4;
        for len in [MAX_TRAILER + 5000, 23] {
            p.trailer = vec![9; len];
            assert_eq!(p.to_bytes(), Err(ParseError::Unwritable));
            contract::check_wire_value(&p);
        }
        p.trailer = vec![9; MAX_TRAILER];
        contract::check_wire_value(&p);
        assert_eq!(p.to_bytes().unwrap().len(), MAX_PACKET);
    }

    /// How far apart two timestamps are, going the short way round the era.
    fn gap(a: Timestamp, b: Timestamp) -> u64 {
        let (a, b) = (a.to_bits(), b.to_bits());
        a.wrapping_sub(b).min(b.wrapping_sub(a))
    }

    #[test]
    fn the_last_fraction_of_an_era_rounds_into_the_next() {
        // The last fraction of era 0 reads as the first second of era 1,
        // and writes back as NTP second 0. That is one unit away, not 2⁶⁴.
        let last = Timestamp { seconds: u32::MAX, fraction: u32::MAX };
        assert_eq!(last.to_unix(), (ERA_PIVOT, 0));
        let back = Timestamp::from_unix(ERA_PIVOT, 0);
        assert_eq!(back, Timestamp::ZERO);
        assert_eq!(gap(back, last), 1);
        // A plain difference of the bits, as the first fuzz target took,
        // calls these two 2⁶⁴ − 1 units apart.
        assert_eq!(back.to_bits().abs_diff(last.to_bits()), u64::MAX);
        // The last fraction of the default window rounds to its end,
        // pivot + 2³¹, which to_unix_near's bounds include.
        let top = Timestamp { seconds: 0x7fff_ffff, fraction: u32::MAX };
        assert_eq!(top.to_unix(), (ERA_PIVOT + (1 << 31), 0));
        assert_eq!(gap(Timestamp::from_unix(ERA_PIVOT + (1 << 31), 0), top), 1);
    }

    #[test]
    fn a_request_is_not_a_kiss() {
        // Simple clients send stratum 0, and an unsynchronized ntpd client
        // sends stratum 0 with INIT. Neither is a kiss-o'-death packet.
        let req = Packet::client_request(Timestamp::from_unix(1_700_000_000, 0));
        assert_eq!(req.kiss_code(), None);
        let mut init = req.clone();
        init.reference_id = *b"INIT";
        assert_eq!(init.kiss_code(), None);
        // The same fields in a server reply are a kiss.
        init.mode = Mode::Server;
        assert_eq!(init.kiss_code(), Some(KissCode::Init));
    }

    #[test]
    fn an_unsynchronized_server_sends_stratum_zero() {
        // RFC 5905, section 7.3 and fast_xmit(): stratum 16 or more goes
        // out as 0.
        let req = Packet::client_request(Timestamp::from_unix(1_700_000_000, 0));
        let t = Timestamp::from_unix(1_700_000_001, 0);
        for (stratum, sent) in [(1, 1), (15, 15), (16, 0), (17, 0), (255, 0)] {
            let server = ServerInfo { stratum, ..ServerInfo::default() };
            assert_eq!(server_reply(&req, &server, t, t).unwrap().stratum, sent, "{stratum}");
        }
    }

    #[test]
    fn long_extension_fields_are_read() {
        // NTS (RFC 8915) requests carry a cookie and placeholders for more,
        // and can run past a kilobyte. RFC 7822 sets no limit.
        let mut b = Packet::client_request(Timestamp::from_unix(1_700_000_000, 0)).to_bytes().unwrap();
        b.extend(std::iter::repeat_n(0xab, 1200));
        let p = Packet::parse(&b).unwrap();
        assert_eq!(p.trailer.len(), 1200);
        assert_eq!(p.to_bytes().unwrap(), b);
    }

    #[test]
    fn random_buffers() {
        let mut rng = Lcg::new(0x2545_f491_4f6c_dd1d);
        let mut read = 0;
        for i in 0..5000 {
            let len = match i % 4 {
                0 => HEADER_LEN + 4 * (rng.index(8)),
                1 => rng.index(64),
                2 => HEADER_LEN + rng.index(32),
                _ => rng.index(2100),
            };
            let mut b = vec![0; len];
            rng.fill(&mut b);
            if i % 2 == 0 && !b.is_empty() {
                // Often a readable first byte: version 1 to 7, mode 1 to 5.
                b[0] = (b[0] & 0xc0) | ((1 + rng.index(7) as u8) << 3) | (1 + rng.index(5) as u8);
            }
            contract::check_wire::<Packet>(&b);
            contract::check_wire::<Timestamp>(&b);
            contract::check_wire::<KissCode>(&b);
            if let Ok(p) = Packet::parse(&b) {
                read += 1;
                assert_eq!(p.to_bytes().unwrap(), b);
                let _ = p.kiss_code().map(|k| k.to_string());
                let (s, n) = p.transmit.to_unix();
                assert!(n < 1_000_000_000);
                let t = Timestamp::from_unix(s, n);
                // Nanoseconds are coarser than 2⁻³² s, so this comes back within a few units,
                // measured round the era: the last fraction of an era comes back as second 0.
                assert!(gap(t, p.transmit) <= 3, "{:?}", p.transmit);
                if let Ok(r) = server_reply(&p, &ServerInfo::default(), p.receive, p.reference) {
                    assert_eq!(Packet::parse(&r.to_bytes().unwrap()).unwrap(), r);
                }
                if let Ok(r) = kiss_reply(&p, KissCode::from_bytes(p.reference_id)) {
                    assert_eq!(Packet::parse(&r.to_bytes().unwrap()).unwrap(), r);
                }
            }
            let secs = (rng.next() << 32 | rng.next()) as i64;
            let nanos = rng.index(1_000_000_000) as u32;
            let t = Timestamp::from_unix(secs, nanos);
            assert_eq!(t.to_unix_near(secs), (secs, nanos));
            let _ = Timestamp::from_unix(secs, rng.next() as u32).to_unix_near(secs.wrapping_neg());
        }
        assert!(read > 1000, "{read}");
    }
}
