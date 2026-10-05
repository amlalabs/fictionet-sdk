//! SDP: reading and writing session descriptions, with no I/O.
//!
//! The Session Description Protocol says what a media session carries and
//! where: which streams (audio, video, data), on which ports, with which
//! codecs. It is not sent on its own. It rides as the body of a SIP
//! INVITE, an RTSP DESCRIBE reply, or a WebRTC offer and answer. A
//! description is a list of text lines, each a single letter, an `=`, and
//! a value, in an order the specification fixes. This module follows
//! RFC 8866, and RFC 8839 for ICE candidates.
//!
//! Nothing here reads a socket. A world that plays a SIP phone takes the
//! body of an INVITE, reads it with [`SessionDescription::parse`] (or a
//! [`Decoder`], fed as bytes come), picks the streams and codecs it will
//! take, and writes its answer with [`SessionDescription::to_bytes`].
//! Which codecs a world accepts, and what it does with the media, is up
//! to world code.
//!
//! Every reader checks the line order, each field's syntax and the size
//! limits below, because the agent can send any bytes it likes. Lines may
//! end with CRLF or a bare LF, as RFC 8866 asks parsers to accept. The
//! writer emits CRLF, puts lines in the order the RFC requires, and
//! refuses a description it cannot write so that it reads back the same.
//!
//! ```
//! use fictionet::stdlib::sdp::{Direction, SessionDescription};
//!
//! let offer = b"v=0\r\n\
//!     o=alice 2890844526 2890844526 IN IP4 198.51.100.1\r\n\
//!     s= \r\n\
//!     c=IN IP4 198.51.100.1\r\n\
//!     t=0 0\r\n\
//!     m=audio 49170 RTP/AVP 0 96\r\n\
//!     a=rtpmap:96 opus/48000/2\r\n\
//!     a=sendonly\r\n";
//! let offer = SessionDescription::parse(offer).unwrap();
//! let audio = &offer.media[0];
//! assert_eq!(audio.port, 49170);
//! assert_eq!(audio.formats, ["0", "96"]);
//! let opus = audio.rtpmap("96").unwrap();
//! assert_eq!((opus.encoding.as_str(), opus.clock_rate), ("opus", 48000));
//! assert_eq!(offer.direction(audio), Direction::SendOnly);
//!
//! // The answer: the same stream, which this side only receives.
//! let mut answer = offer.clone();
//! answer.origin.username = "bob".into();
//! answer.origin.address = "203.0.113.5".into();
//! answer.connection.as_mut().unwrap().address = "203.0.113.5".into();
//! let media = &mut answer.media[0];
//! media.port = 3456;
//! media.attributes.retain(|a| Direction::from_attribute(a).is_none());
//! media.attributes.push(Direction::RecvOnly.to_attribute());
//! let bytes = answer.to_bytes().unwrap();
//! assert!(bytes.starts_with(b"v=0\r\no=bob 2890844526 2890844526 IN IP4 203.0.113.5\r\n"));
//! assert!(bytes.ends_with(b"m=audio 3456 RTP/AVP 0 96\r\na=rtpmap:96 opus/48000/2\r\na=recvonly\r\n"));
//! assert_eq!(SessionDescription::parse(&bytes), Ok(answer));
//! ```

/// The media type SDP bodies carry, in a `Content-Type` header.
pub const MIME_TYPE: &str = "application/sdp";
/// The most bytes a description may hold, line endings included.
pub const MAX_LEN: usize = 128 * 1024;
/// The most lines a description may hold.
pub const MAX_LINES: usize = 4096;
/// The longest line, from its type letter to the last byte before its
/// line ending.
pub const MAX_LINE_LEN: usize = 4096;

/// One session description: the session-level lines, its time
/// descriptions and its media descriptions. Each field is named for the
/// line it comes from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionDescription {
    /// `o=`: who made the session, and its identifier and version.
    pub origin: Origin,
    /// `s=`: the session's name. A single space when it has none.
    pub name: String,
    /// `i=`: a description of the session.
    pub information: Option<String>,
    /// `u=`: a URI with more about the session.
    pub uri: Option<String>,
    /// `e=` lines: email addresses to contact.
    pub emails: Vec<String>,
    /// `p=` lines: phone numbers to contact.
    pub phones: Vec<String>,
    /// `c=`: where the media goes, for media descriptions without their
    /// own `c=` line.
    pub connection: Option<Connection>,
    /// `b=` lines: the session's bandwidth.
    pub bandwidths: Vec<Bandwidth>,
    /// `t=` lines, each with its `r=` and `z=` lines. A description needs
    /// at least one.
    pub times: Vec<Timing>,
    /// `k=`: an encryption key. RFC 8866 calls this line obsolete.
    pub key: Option<String>,
    /// `a=` lines at the session level.
    pub attributes: Vec<Attribute>,
    /// The media descriptions, each starting with an `m=` line.
    pub media: Vec<Media>,
}

/// The `o=` line: who made the session and which version this is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Origin {
    /// The user's login on the host that made the session, or `-`.
    pub username: String,
    /// A number that, with the username and address, names the session.
    pub session_id: u64,
    /// Raised each time the description changes.
    pub session_version: u64,
    /// The network type, usually `IN` (Internet).
    pub net_type: String,
    /// The address type, usually `IP4` or `IP6`.
    pub addr_type: String,
    /// The address or name of the host that made the session.
    pub address: String,
}

/// A `c=` line: where media is sent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Connection {
    /// The network type, usually `IN`.
    pub net_type: String,
    /// The address type, usually `IP4` or `IP6`.
    pub addr_type: String,
    /// The address, as written. A multicast address may carry `/ttl` and
    /// `/count` after it.
    pub address: String,
}

/// A `b=` line: how much bandwidth the session or a stream may use.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bandwidth {
    /// The bandwidth type, such as `CT`, `AS` or `TIAS`.
    pub kind: String,
    /// The amount, in kilobits per second for `CT` and `AS`.
    pub value: u64,
}

/// A time description: a `t=` line and the `r=` and `z=` lines after it.
/// Times are seconds since 1900, as NTP counts them, and 0 means
/// unbounded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Timing {
    /// When the session starts, or 0.
    pub start: u64,
    /// When the session stops, or 0.
    pub stop: u64,
    /// `r=` lines: how the session repeats.
    pub repeats: Vec<Repeat>,
    /// The `z=` line: changes of time zone offset the repeats follow. An
    /// empty list writes no line. A `z=` line needs at least one `r=`
    /// line before it, so zones without repeats cannot be written.
    pub zones: Vec<ZoneAdjustment>,
}

/// An `r=` line. The reader turns the `d`, `h`, `m` and `s` units into
/// seconds, and the writer writes plain seconds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Repeat {
    /// Seconds between repeats. Never 0.
    pub interval: u64,
    /// How many seconds each repeat lasts.
    pub duration: u64,
    /// When each repeat starts, in seconds after the start time. At least
    /// one.
    pub offsets: Vec<u64>,
}

/// One time and offset pair of a `z=` line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ZoneAdjustment {
    /// When the adjustment takes effect, in seconds since 1900.
    pub time: u64,
    /// The change in seconds, often negative.
    pub offset: i64,
}

/// A media description: an `m=` line and the lines after it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Media {
    /// The media type: `audio`, `video`, `text`, `application` or
    /// `message`.
    pub kind: String,
    /// The transport port. 0 means the stream is turned down.
    pub port: u16,
    /// How many ports from `port` the stream uses, when the line says.
    /// Never 0.
    pub port_count: Option<u16>,
    /// The transport protocol, such as `RTP/AVP` or `UDP/TLS/RTP/SAVPF`.
    pub proto: String,
    /// The formats offered, in order of preference. For RTP these are
    /// payload type numbers. At least one.
    pub formats: Vec<String>,
    /// `i=`: a title for the stream.
    pub information: Option<String>,
    /// `c=` lines for this stream.
    pub connections: Vec<Connection>,
    /// `b=` lines for this stream.
    pub bandwidths: Vec<Bandwidth>,
    /// `k=`: an encryption key. Obsolete.
    pub key: Option<String>,
    /// `a=` lines for this stream.
    pub attributes: Vec<Attribute>,
}

/// An `a=` line: a name, and a value after a colon if it has one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attribute {
    /// The attribute's name, such as `rtpmap` or `sendrecv`.
    pub name: String,
    /// Everything after the first colon, if there is one.
    pub value: Option<String>,
}

impl Attribute {
    /// An attribute with a value: `a=name:value`.
    pub fn new(name: &str, value: &str) -> Attribute {
        Attribute { name: name.to_string(), value: Some(value.to_string()) }
    }

    /// An attribute with no value: `a=name`.
    pub fn flag(name: &str) -> Attribute {
        Attribute { name: name.to_string(), value: None }
    }
}

/// Why bytes are not a session description, or why a description cannot
/// be written. Lines count from 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The description is longer than [`MAX_LEN`].
    TooLong,
    /// The description has more than [`MAX_LINES`] lines.
    TooManyLines,
    /// A line is longer than [`MAX_LINE_LEN`].
    LineTooLong {
        /// The line's number.
        line: usize,
    },
    /// A line does not start with a lowercase letter and `=`. An empty
    /// line is one.
    Malformed {
        /// The line's number.
        line: usize,
    },
    /// A line's type letter is not one SDP defines. RFC 8866 asks a parser
    /// to reject the whole description.
    UnknownType {
        /// The line's number.
        line: usize,
        /// The type letter.
        kind: char,
    },
    /// A line's value is not UTF-8. Other character sets, which
    /// `a=charset` can name, are not read.
    Encoding {
        /// The line's number.
        line: usize,
    },
    /// A line's value breaks the syntax of its type.
    Syntax {
        /// The line's number.
        line: usize,
        /// The type letter.
        kind: char,
    },
    /// A line comes where its type may not, such as a second `s=` or an
    /// `a=` before the first `t=`.
    Order {
        /// The line's number.
        line: usize,
        /// The type letter.
        kind: char,
    },
    /// A required line is missing: `v=`, `o=`, `s=` or `t=`, or a `c=`
    /// for a media description when the session has none.
    Missing(char),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::TooLong => write!(f, "description longer than {MAX_LEN} bytes"),
            Error::TooManyLines => write!(f, "description has more than {MAX_LINES} lines"),
            Error::LineTooLong { line } => write!(f, "line {line} is longer than {MAX_LINE_LEN} bytes"),
            Error::Malformed { line } => write!(f, "line {line} is not a type letter, '=' and a value"),
            Error::UnknownType { line, kind } => write!(f, "line {line} has unknown type '{kind}'"),
            Error::Encoding { line } => write!(f, "line {line} is not UTF-8"),
            Error::Syntax { line, kind } => write!(f, "line {line} is a malformed '{kind}=' line"),
            Error::Order { line, kind } => write!(f, "line {line}: '{kind}=' is not allowed here"),
            Error::Missing(kind) => write!(f, "required '{kind}=' line missing"),
        }
    }
}

impl std::error::Error for Error {}

// The order of lines. A stage is the rank of the last line read; a line
// may follow if its rank is higher, or the same and its type repeats.
const V: u8 = 1;
const O: u8 = 2;
const S: u8 = 3;
const I: u8 = 4;
const U: u8 = 5;
const E: u8 = 6;
const P: u8 = 7;
const C: u8 = 8;
const B: u8 = 9;
const T: u8 = 10;
const R: u8 = 11;
const Z: u8 = 12;
const K: u8 = 13;
const A: u8 = 14;
const M: u8 = 15;
const MI: u8 = 16;
const MC: u8 = 17;
const MB: u8 = 18;
const MK: u8 = 19;
const MA: u8 = 20;

/// The stage after a line of type `kind` at stage `cur`, or `None` if the
/// line may not come there.
fn next_stage(cur: u8, kind: u8) -> Option<u8> {
    let media = cur >= M;
    let (rank, repeats) = match (kind, media) {
        (b'v', _) => return (cur == 0).then_some(V),
        (b'o', _) => return (cur == V).then_some(O),
        (b's', _) => return (cur == O).then_some(S),
        (b'm', _) => return (cur >= T).then_some(M),
        (b't', false) => return (S..=Z).contains(&cur).then_some(T),
        (b'r', false) => return (cur == T || cur == R).then_some(R),
        (b'z', false) => return (cur == R).then_some(Z),
        (b'i', false) => (I, false),
        (b'u', false) => (U, false),
        (b'e', false) => (E, true),
        (b'p', false) => (P, true),
        (b'c', false) => (C, false),
        (b'b', false) => (B, true),
        (b'k', false) => (K, false),
        (b'a', false) => (A, true),
        (b'i', true) => (MI, false),
        (b'c', true) => (MC, true),
        (b'b', true) => (MB, true),
        (b'k', true) => (MK, false),
        (b'a', true) => (MA, true),
        _ => return None,
    };
    let floor = if media {
        M
    } else if rank >= K {
        T
    } else {
        S
    };
    (cur >= floor && (cur < rank || (cur == rank && repeats))).then_some(rank)
}

/// Reads a session description as its bytes come, a chunk at a time.
/// Feed it every byte of the body, then call [`Decoder::finish`]. It holds
/// at most one partial line, and stops reading at the first error.
#[derive(Debug, Default)]
pub struct Decoder {
    line: Vec<u8>,
    total: usize,
    lines: usize,
    stage: u8,
    desc: SessionDescription,
    failed: Option<Error>,
}

impl Decoder {
    /// A decoder that has read nothing.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Reads more of the description. After an error the rest is
    /// dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.failed.is_some() {
                return;
            }
            self.total += 1;
            if self.total > MAX_LEN {
                self.fail(Error::TooLong);
            } else if b == b'\n' {
                self.end_line();
            } else {
                self.line.push(b);
                // One more byte for a CR that may come before the LF.
                if self.line.len() > MAX_LINE_LEN + 1 {
                    self.fail(Error::LineTooLong { line: self.lines + 1 });
                }
            }
        }
    }

    /// The error that stopped the decoder, if one has.
    pub fn error(&self) -> Option<Error> {
        self.failed
    }

    /// Reads the last line, if it had no line ending, and returns the
    /// description.
    pub fn finish(mut self) -> Result<SessionDescription, Error> {
        if self.failed.is_none() && !self.line.is_empty() {
            self.end_line();
        }
        if let Some(e) = self.failed {
            return Err(e);
        }
        match self.stage {
            0 => return Err(Error::Missing('v')),
            V => return Err(Error::Missing('o')),
            O => return Err(Error::Missing('s')),
            s if s < T => return Err(Error::Missing('t')),
            _ => {}
        }
        let desc = self.desc;
        if desc.connection.is_none() && desc.media.iter().any(|m| m.connections.is_empty()) {
            return Err(Error::Missing('c'));
        }
        Ok(desc)
    }

    fn fail(&mut self, e: Error) {
        self.failed = Some(e);
        self.line = Vec::new();
    }

    fn end_line(&mut self) {
        let mut line = std::mem::take(&mut self.line);
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        self.lines += 1;
        let n = self.lines;
        if n > MAX_LINES {
            return self.fail(Error::TooManyLines);
        }
        if line.len() > MAX_LINE_LEN {
            return self.fail(Error::LineTooLong { line: n });
        }
        if let Err(e) = self.read_line(&line, n) {
            self.fail(e);
        }
        // Keep the buffer's room for the next line.
        line.clear();
        self.line = line;
    }

    fn read_line(&mut self, line: &[u8], n: usize) -> Result<(), Error> {
        let (&kind, rest) = line.split_first().ok_or(Error::Malformed { line: n })?;
        if !kind.is_ascii_lowercase() || rest.first() != Some(&b'=') {
            return Err(Error::Malformed { line: n });
        }
        let k = char::from(kind);
        if !b"vosiuepcbtrzkam".contains(&kind) {
            return Err(Error::UnknownType { line: n, kind: k });
        }
        let value = std::str::from_utf8(&rest[1..]).map_err(|_| Error::Encoding { line: n })?;
        let stage = next_stage(self.stage, kind).ok_or(Error::Order { line: n, kind: k })?;
        self.stage = stage;
        self.apply(stage, value).ok_or(Error::Syntax { line: n, kind: k })
    }

    /// Stores a line's value in the description, or `None` if it is
    /// malformed.
    fn apply(&mut self, stage: u8, value: &str) -> Option<()> {
        let d = &mut self.desc;
        match stage {
            V => (value == "0").then_some(())?,
            O => d.origin = parse_origin(value)?,
            S => d.name = text(value)?,
            I => d.information = Some(text(value)?),
            U => d.uri = Some(text(value)?),
            E => d.emails.push(text(value)?),
            P => d.phones.push(text(value)?),
            C => d.connection = Some(parse_connection(value)?),
            B => d.bandwidths.push(parse_bandwidth(value)?),
            T => {
                let (start, stop) = value.split_once(' ')?;
                d.times.push(Timing { start: number(start)?, stop: number(stop)?, ..Timing::default() });
            }
            R => d.times.last_mut()?.repeats.push(parse_repeat(value)?),
            Z => d.times.last_mut()?.zones = parse_zones(value)?,
            K => d.key = Some(text(value)?),
            A => d.attributes.push(parse_attribute(value)?),
            M => d.media.push(parse_media(value)?),
            _ => {
                let m = d.media.last_mut()?;
                match stage {
                    MI => m.information = Some(text(value)?),
                    MC => m.connections.push(parse_connection(value)?),
                    MB => m.bandwidths.push(parse_bandwidth(value)?),
                    MK => m.key = Some(text(value)?),
                    _ => m.attributes.push(parse_attribute(value)?),
                }
            }
        }
        Some(())
    }
}

fn parse_origin(value: &str) -> Option<Origin> {
    let mut it = value.split(' ');
    let o = Origin {
        username: non_ws(it.next()?)?,
        session_id: number(it.next()?)?,
        session_version: number(it.next()?)?,
        net_type: token(it.next()?)?,
        addr_type: token(it.next()?)?,
        address: non_ws(it.next()?)?,
    };
    it.next().is_none().then_some(o)
}

fn parse_connection(value: &str) -> Option<Connection> {
    let mut it = value.split(' ');
    let c = Connection { net_type: token(it.next()?)?, addr_type: token(it.next()?)?, address: non_ws(it.next()?)? };
    it.next().is_none().then_some(c)
}

fn parse_bandwidth(value: &str) -> Option<Bandwidth> {
    let (kind, n) = value.split_once(':')?;
    Some(Bandwidth { kind: token(kind)?, value: number(n)? })
}

fn parse_repeat(value: &str) -> Option<Repeat> {
    let mut it = value.split(' ');
    let interval = it.next()?;
    if interval.starts_with('0') {
        return None;
    }
    let interval = typed_time(interval)?;
    let duration = typed_time(it.next()?)?;
    let offsets = it.map(typed_time).collect::<Option<Vec<u64>>>()?;
    (!offsets.is_empty()).then_some(Repeat { interval, duration, offsets })
}

fn parse_zones(value: &str) -> Option<Vec<ZoneAdjustment>> {
    let mut it = value.split(' ');
    let mut zones = Vec::new();
    while let Some(time) = it.next() {
        let offset = it.next()?;
        let offset = match offset.strip_prefix('-') {
            Some(m) => 0i64.checked_sub_unsigned(typed_time(m)?)?,
            None => i64::try_from(typed_time(offset)?).ok()?,
        };
        zones.push(ZoneAdjustment { time: number(time)?, offset });
    }
    (!zones.is_empty()).then_some(zones)
}

fn parse_media(value: &str) -> Option<Media> {
    let mut it = value.split(' ');
    let kind = token(it.next()?)?;
    let port = it.next()?;
    let (port, port_count) = match port.split_once('/') {
        Some((p, n)) => (p, Some(n)),
        None => (port, None),
    };
    let port = u16::try_from(number(port)?).ok()?;
    let port_count = match port_count {
        Some(n) => Some(u16::try_from(number(n)?).ok().filter(|&n| n > 0)?),
        None => None,
    };
    let proto = it.next()?;
    if !proto.split('/').all(|t| token(t).is_some()) {
        return None;
    }
    let formats = it.map(token).collect::<Option<Vec<String>>>()?;
    if formats.is_empty() {
        return None;
    }
    Some(Media { kind, port, port_count, proto: proto.to_string(), formats, ..Media::default() })
}

fn parse_attribute(value: &str) -> Option<Attribute> {
    Some(match value.split_once(':') {
        Some((name, v)) => Attribute { name: token(name)?, value: Some(text(v)?) },
        None => Attribute { name: token(value)?, value: None },
    })
}

// Field syntax, shared by the reader and the writer.

/// `token`: one or more of the characters RFC 8866 allows in names.
fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`{|}~".contains(&b))
}

/// `non-ws-string`: visible characters, no spaces or controls.
fn is_non_ws(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| !c.is_ascii() || c.is_ascii_graphic())
}

/// `byte-string`: anything but NUL, CR and LF, at least one byte.
fn is_text(s: &str) -> bool {
    !s.is_empty() && !s.contains(['\0', '\r', '\n'])
}

/// `proto`: tokens joined by `/`.
fn is_proto(s: &str) -> bool {
    s.split('/').all(is_token)
}

fn token(s: &str) -> Option<String> {
    is_token(s).then(|| s.to_string())
}

fn non_ws(s: &str) -> Option<String> {
    is_non_ws(s).then(|| s.to_string())
}

fn text(s: &str) -> Option<String> {
    is_text(s).then(|| s.to_string())
}

/// One or more decimal digits that fit in a `u64`.
fn number(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// `zero-based-integer`: `0`, or digits with no leading zero, that fit
/// in a `u64`.
fn integer(s: &str) -> Option<u64> {
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    number(s)
}

/// `typed-time`: digits and an optional unit, in seconds.
fn typed_time(s: &str) -> Option<u64> {
    let (digits, unit) = match s.as_bytes().last()? {
        b'd' => (&s[..s.len() - 1], 86_400),
        b'h' => (&s[..s.len() - 1], 3_600),
        b'm' => (&s[..s.len() - 1], 60),
        b's' => (&s[..s.len() - 1], 1),
        _ => (s, 1),
    };
    number(digits)?.checked_mul(unit)
}

/// Writes lines, counting them and their bytes against the limits.
struct Writer {
    out: String,
    lines: usize,
}

impl Writer {
    fn line(&mut self, kind: char, ok: bool, value: &str) -> Result<(), Error> {
        self.lines += 1;
        let line = self.lines;
        if line > MAX_LINES {
            return Err(Error::TooManyLines);
        }
        if !ok {
            return Err(Error::Syntax { line, kind });
        }
        if value.len() + 2 > MAX_LINE_LEN {
            return Err(Error::LineTooLong { line });
        }
        if self.out.len() + value.len() + 4 > MAX_LEN {
            return Err(Error::TooLong);
        }
        self.out.push(kind);
        self.out.push('=');
        self.out.push_str(value);
        self.out.push_str("\r\n");
        Ok(())
    }

    fn connection(&mut self, c: &Connection) -> Result<(), Error> {
        let ok = is_token(&c.net_type) && is_token(&c.addr_type) && is_non_ws(&c.address);
        self.line('c', ok, &format!("{} {} {}", c.net_type, c.addr_type, c.address))
    }

    fn bandwidth(&mut self, b: &Bandwidth) -> Result<(), Error> {
        self.line('b', is_token(&b.kind), &format!("{}:{}", b.kind, b.value))
    }

    fn attribute(&mut self, a: &Attribute) -> Result<(), Error> {
        match &a.value {
            Some(v) => self.line('a', is_token(&a.name) && is_text(v), &format!("{}:{v}", a.name)),
            None => self.line('a', is_token(&a.name), &a.name),
        }
    }

    fn text(&mut self, kind: char, value: &str) -> Result<(), Error> {
        self.line(kind, is_text(value), value)
    }
}

impl SessionDescription {
    /// A description with the given origin and name, one `t=0 0` line
    /// (a session with no fixed start or end), and nothing else.
    pub fn new(origin: Origin, name: &str) -> SessionDescription {
        SessionDescription {
            origin,
            name: name.to_string(),
            times: vec![Timing::default()],
            ..SessionDescription::default()
        }
    }

    /// Reads a whole description, such as the body of a SIP message.
    pub fn parse(bytes: &[u8]) -> Result<SessionDescription, Error> {
        let mut d = Decoder::new();
        d.feed(bytes);
        d.finish()
    }

    /// The description's bytes, lines in the order RFC 8866 requires, each
    /// ending in CRLF. It fails, naming the line, if a field holds what
    /// its line's syntax does not allow, such as a space in a token or a
    /// line break in text, or if the result would break a size limit. It
    /// also fails if there is no time description, or a media description
    /// has no connection to use. Whatever it writes, [`parse`] reads back
    /// equal.
    ///
    /// [`parse`]: SessionDescription::parse
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.times.is_empty() {
            return Err(Error::Missing('t'));
        }
        if self.connection.is_none() && self.media.iter().any(|m| m.connections.is_empty()) {
            return Err(Error::Missing('c'));
        }
        let mut w = Writer { out: String::new(), lines: 0 };
        w.line('v', true, "0")?;
        let o = &self.origin;
        let ok = is_non_ws(&o.username) && is_token(&o.net_type) && is_token(&o.addr_type) && is_non_ws(&o.address);
        let value = format!(
            "{} {} {} {} {} {}",
            o.username, o.session_id, o.session_version, o.net_type, o.addr_type, o.address
        );
        w.line('o', ok, &value)?;
        w.text('s', &self.name)?;
        if let Some(i) = &self.information {
            w.text('i', i)?;
        }
        if let Some(u) = &self.uri {
            w.text('u', u)?;
        }
        for e in &self.emails {
            w.text('e', e)?;
        }
        for p in &self.phones {
            w.text('p', p)?;
        }
        if let Some(c) = &self.connection {
            w.connection(c)?;
        }
        for b in &self.bandwidths {
            w.bandwidth(b)?;
        }
        for t in &self.times {
            w.line('t', true, &format!("{} {}", t.start, t.stop))?;
            for r in &t.repeats {
                let mut value = format!("{} {}", r.interval, r.duration);
                for o in &r.offsets {
                    value.push(' ');
                    value.push_str(&o.to_string());
                }
                w.line('r', r.interval != 0 && !r.offsets.is_empty(), &value)?;
            }
            if !t.zones.is_empty() {
                let parts: Vec<String> = t.zones.iter().map(|z| format!("{} {}", z.time, z.offset)).collect();
                w.line('z', !t.repeats.is_empty(), &parts.join(" "))?;
            }
        }
        if let Some(k) = &self.key {
            w.text('k', k)?;
        }
        for a in &self.attributes {
            w.attribute(a)?;
        }
        for m in &self.media {
            let ok = is_token(&m.kind)
                && m.port_count != Some(0)
                && is_proto(&m.proto)
                && !m.formats.is_empty()
                && m.formats.iter().all(|f| is_token(f));
            let mut value = format!("{} {}", m.kind, m.port);
            if let Some(n) = m.port_count {
                value.push_str(&format!("/{n}"));
            }
            value.push(' ');
            value.push_str(&m.proto);
            for f in &m.formats {
                value.push(' ');
                value.push_str(f);
            }
            w.line('m', ok, &value)?;
            if let Some(i) = &m.information {
                w.text('i', i)?;
            }
            for c in &m.connections {
                w.connection(c)?;
            }
            for b in &m.bandwidths {
                w.bandwidth(b)?;
            }
            if let Some(k) = &m.key {
                w.text('k', k)?;
            }
            for a in &m.attributes {
                w.attribute(a)?;
            }
        }
        Ok(w.out.into_bytes())
    }

    /// The first session-level attribute named `name`.
    pub fn attribute(&self, name: &str) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.name == name)
    }

    /// Every session-level attribute named `name`, in order.
    pub fn attributes_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Attribute> + 'a {
        self.attributes.iter().filter(move |a| a.name == name)
    }

    /// The direction a stream flows: its own direction attribute, else
    /// the session's, else [`Direction::SendRecv`], as RFC 8866 says.
    pub fn direction(&self, media: &Media) -> Direction {
        media.direction().or_else(|| self.attributes.iter().find_map(Direction::from_attribute)).unwrap_or_default()
    }
}

impl Media {
    /// The first attribute named `name`.
    pub fn attribute(&self, name: &str) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.name == name)
    }

    /// Every attribute named `name`, in order.
    pub fn attributes_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Attribute> + 'a {
        self.attributes.iter().filter(move |a| a.name == name)
    }

    /// The direction attribute of this stream, if it has one.
    pub fn direction(&self) -> Option<Direction> {
        self.attributes.iter().find_map(Direction::from_attribute)
    }

    /// The well-formed `a=rtpmap` for `format`, if there is one.
    pub fn rtpmap(&self, format: &str) -> Option<RtpMap> {
        let payload = u8::try_from(integer(format)?).ok()?;
        self.attributes_named("rtpmap").filter_map(|a| RtpMap::from_attribute(a).ok()).find(|r| r.payload == payload)
    }

    /// The well-formed `a=fmtp` for `format`, if there is one.
    pub fn fmtp(&self, format: &str) -> Option<Fmtp> {
        self.attributes_named("fmtp").filter_map(|a| Fmtp::from_attribute(a).ok()).find(|f| f.format == format)
    }

    /// The well-formed `a=candidate` lines, in order. Malformed ones are
    /// skipped.
    pub fn candidates(&self) -> impl Iterator<Item = Candidate> + '_ {
        self.attributes_named("candidate").filter_map(|a| Candidate::from_attribute(a).ok())
    }
}

/// Why an attribute is not the kind a typed helper reads, or why the
/// helper's fields cannot be written as one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttributeError;

impl std::fmt::Display for AttributeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("malformed SDP attribute")
    }
}

impl std::error::Error for AttributeError {}

/// The value of an attribute named `name`, or an error.
fn value_of<'a>(a: &'a Attribute, name: &str) -> Result<&'a str, AttributeError> {
    match &a.value {
        Some(v) if a.name == name => Ok(v),
        _ => Err(AttributeError),
    }
}

fn check(ok: bool) -> Result<(), AttributeError> {
    if ok { Ok(()) } else { Err(AttributeError) }
}

/// The highest RTP payload type number.
pub const MAX_PAYLOAD_TYPE: u8 = 127;

/// `a=rtpmap:<payload type> <encoding>/<clock rate>[/<parameters>]`: what
/// an RTP payload type number means.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RtpMap {
    /// The payload type, 0 to [`MAX_PAYLOAD_TYPE`].
    pub payload: u8,
    /// The encoding name, such as `opus`, `PCMU` or `H264`.
    pub encoding: String,
    /// The RTP clock rate in Hz. Never 0.
    pub clock_rate: u32,
    /// Encoding parameters, such as the channel count for audio.
    pub params: Option<String>,
}

impl RtpMap {
    /// Reads an `rtpmap` attribute.
    pub fn from_attribute(a: &Attribute) -> Result<RtpMap, AttributeError> {
        let v = value_of(a, "rtpmap")?;
        let (pt, rest) = v.split_once(' ').ok_or(AttributeError)?;
        let mut parts = rest.splitn(3, '/');
        let encoding = parts.next().and_then(token).ok_or(AttributeError)?;
        let clock = parts.next().and_then(integer).filter(|&c| c > 0).ok_or(AttributeError)?;
        let params = match parts.next() {
            Some(p) => Some(non_ws(p).ok_or(AttributeError)?),
            None => None,
        };
        let payload = integer(pt).filter(|&p| p <= u64::from(MAX_PAYLOAD_TYPE)).ok_or(AttributeError)?;
        Ok(RtpMap {
            payload: payload as u8,
            encoding,
            clock_rate: u32::try_from(clock).map_err(|_| AttributeError)?,
            params,
        })
    }

    /// The `rtpmap` attribute. It fails if the payload type is over
    /// [`MAX_PAYLOAD_TYPE`], the clock rate is 0, or a field holds characters the syntax does
    /// not allow.
    pub fn to_attribute(&self) -> Result<Attribute, AttributeError> {
        check(self.payload <= MAX_PAYLOAD_TYPE && self.clock_rate > 0 && is_token(&self.encoding))?;
        let mut v = format!("{} {}/{}", self.payload, self.encoding, self.clock_rate);
        if let Some(p) = &self.params {
            check(is_non_ws(p))?;
            v.push('/');
            v.push_str(p);
        }
        Ok(Attribute { name: "rtpmap".to_string(), value: Some(v) })
    }
}

/// `a=fmtp:<format> <parameters>`: settings for one format, such as
/// `minptime=10;useinbandfec=1` for Opus.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fmtp {
    /// The format the settings are for, as in the `m=` line.
    pub format: String,
    /// The settings, as written.
    pub params: String,
}

impl Fmtp {
    /// Reads an `fmtp` attribute.
    pub fn from_attribute(a: &Attribute) -> Result<Fmtp, AttributeError> {
        let v = value_of(a, "fmtp")?;
        let (format, params) = v.split_once(' ').ok_or(AttributeError)?;
        check(is_token(format) && is_text(params))?;
        Ok(Fmtp { format: format.to_string(), params: params.to_string() })
    }

    /// The `fmtp` attribute. It fails if the format is not a token or the
    /// settings are empty or hold a line break.
    pub fn to_attribute(&self) -> Result<Attribute, AttributeError> {
        check(is_token(&self.format) && is_text(&self.params))?;
        Ok(Attribute { name: "fmtp".to_string(), value: Some(format!("{} {}", self.format, self.params)) })
    }

    /// The settings split at `;`, each a name and the value after its
    /// first `=`, with spaces around them trimmed. Most formats write
    /// them this way, though RFC 8866 does not require it.
    pub fn parameters(&self) -> Vec<(&str, Option<&str>)> {
        let mut out = Vec::new();
        for p in self.params.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            out.push(match p.split_once('=') {
                Some((k, v)) => (k.trim(), Some(v.trim())),
                None => (p, None),
            });
        }
        out
    }
}

/// Which way media flows, from the point of view of the side that wrote
/// the description.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Direction {
    /// `a=sendrecv`: both ways. The default.
    #[default]
    SendRecv,
    /// `a=sendonly`: this side sends.
    SendOnly,
    /// `a=recvonly`: this side receives.
    RecvOnly,
    /// `a=inactive`: neither way.
    Inactive,
}

impl Direction {
    /// The direction an attribute names, if it is one of the four, with
    /// no value.
    pub fn from_attribute(a: &Attribute) -> Option<Direction> {
        if a.value.is_some() {
            return None;
        }
        match a.name.as_str() {
            "sendrecv" => Some(Direction::SendRecv),
            "sendonly" => Some(Direction::SendOnly),
            "recvonly" => Some(Direction::RecvOnly),
            "inactive" => Some(Direction::Inactive),
            _ => None,
        }
    }

    /// The attribute's name.
    pub fn name(self) -> &'static str {
        match self {
            Direction::SendRecv => "sendrecv",
            Direction::SendOnly => "sendonly",
            Direction::RecvOnly => "recvonly",
            Direction::Inactive => "inactive",
        }
    }

    /// The direction the other side answers with: send becomes receive.
    pub fn reverse(self) -> Direction {
        match self {
            Direction::SendOnly => Direction::RecvOnly,
            Direction::RecvOnly => Direction::SendOnly,
            d => d,
        }
    }

    /// The attribute, with no value.
    pub fn to_attribute(self) -> Attribute {
        Attribute::flag(self.name())
    }
}

/// An ICE candidate's type.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum CandidateType {
    /// `host`: an address on the host itself. The default.
    #[default]
    Host,
    /// `srflx`: an address a STUN server saw, outside a NAT.
    ServerReflexive,
    /// `prflx`: an address a peer saw during checks.
    PeerReflexive,
    /// `relay`: an address on a TURN relay.
    Relay,
    /// Any other type, as written. The writer refuses a name that reads
    /// back as one of the four above, such as `host` or `HOST`.
    Other(String),
}

impl CandidateType {
    /// The type's name, as written after `typ`.
    pub fn as_str(&self) -> &str {
        match self {
            CandidateType::Host => "host",
            CandidateType::ServerReflexive => "srflx",
            CandidateType::PeerReflexive => "prflx",
            CandidateType::Relay => "relay",
            CandidateType::Other(s) => s,
        }
    }

    /// The type a name after `typ` gives. The four known names match in
    /// any case, as ABNF strings do.
    pub fn from_name(s: &str) -> CandidateType {
        let known = [
            ("host", CandidateType::Host),
            ("srflx", CandidateType::ServerReflexive),
            ("prflx", CandidateType::PeerReflexive),
            ("relay", CandidateType::Relay),
        ];
        for (name, kind) in known {
            if s.eq_ignore_ascii_case(name) {
                return kind;
            }
        }
        CandidateType::Other(s.to_string())
    }
}

/// The longest ICE foundation.
pub const MAX_FOUNDATION: usize = 32;
/// The highest ICE component ID.
pub const MAX_COMPONENT: u16 = 256;

/// `a=candidate:...`: an address ICE may try, as RFC 8839 writes it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Candidate {
    /// Groups candidates from the same interface and server. 1 to
    /// [`MAX_FOUNDATION`] letters, digits, `+` or `/`.
    pub foundation: String,
    /// The component: 1 for RTP, 2 for RTCP. 1 to [`MAX_COMPONENT`].
    pub component: u16,
    /// The transport, usually `UDP`.
    pub transport: String,
    /// The candidate's priority. Higher is tried first.
    pub priority: u32,
    /// The address, or a name.
    pub address: String,
    /// The port.
    pub port: u16,
    /// The candidate's type.
    pub kind: CandidateType,
    /// `raddr`: the address this one was derived from.
    pub related_address: Option<String>,
    /// `rport`: the port this one was derived from.
    pub related_port: Option<u16>,
    /// Further name and value pairs, such as `generation 0`, in order.
    /// Names are never `raddr` or `rport`, in any case.
    pub extensions: Vec<(String, String)>,
}

fn is_foundation(s: &str) -> bool {
    (1..=MAX_FOUNDATION).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// A port of 1 to 5 digits.
fn parse_port(s: &str) -> Option<u16> {
    if s.len() > 5 {
        return None;
    }
    u16::try_from(number(s)?).ok()
}

impl Candidate {
    /// Reads a `candidate` attribute. `raddr` and `rport` may come in
    /// either order, anywhere after the type. The keywords `typ`, `raddr`
    /// and `rport` match in any case.
    pub fn from_attribute(a: &Attribute) -> Result<Candidate, AttributeError> {
        Candidate::parse(value_of(a, "candidate")?).ok_or(AttributeError)
    }

    fn parse(v: &str) -> Option<Candidate> {
        let mut it = v.split(' ');
        let foundation = it.next().filter(|f| is_foundation(f))?.to_string();
        let component = it.next().filter(|c| c.len() <= 3).and_then(number)?;
        if component == 0 || component > u64::from(MAX_COMPONENT) {
            return None;
        }
        let transport = token(it.next()?)?;
        let priority = it.next().filter(|p| p.len() <= 10).and_then(number)?;
        let address = non_ws(it.next()?)?;
        let port = parse_port(it.next()?)?;
        if !it.next()?.eq_ignore_ascii_case("typ") {
            return None;
        }
        let kind = CandidateType::from_name(&token(it.next()?)?);
        let mut c = Candidate {
            foundation,
            component: component as u16,
            transport,
            priority: u32::try_from(priority).ok()?,
            address,
            port,
            kind,
            related_address: None,
            related_port: None,
            extensions: Vec::new(),
        };
        while let Some(name) = it.next() {
            let value = it.next()?;
            if name.eq_ignore_ascii_case("raddr") {
                c.related_address.is_none().then_some(())?;
                c.related_address = Some(non_ws(value)?);
            } else if name.eq_ignore_ascii_case("rport") {
                c.related_port.is_none().then_some(())?;
                c.related_port = Some(parse_port(value)?);
            } else {
                c.extensions.push((token(name)?, non_ws(value)?));
            }
        }
        Some(c)
    }

    /// The `candidate` attribute, with `raddr` and `rport` right after the
    /// type. It fails if a field is out of range or holds characters its
    /// syntax does not allow, the type is [`CandidateType::Other`] with a
    /// known type's name, or an extension is named `raddr` or `rport` in
    /// any case.
    pub fn to_attribute(&self) -> Result<Attribute, AttributeError> {
        check(
            is_foundation(&self.foundation)
                && (1..=MAX_COMPONENT).contains(&self.component)
                && is_token(&self.transport)
                && is_non_ws(&self.address)
                && is_token(self.kind.as_str())
                && CandidateType::from_name(self.kind.as_str()) == self.kind,
        )?;
        let mut v = format!(
            "{} {} {} {} {} {} typ {}",
            self.foundation,
            self.component,
            self.transport,
            self.priority,
            self.address,
            self.port,
            self.kind.as_str()
        );
        if let Some(a) = &self.related_address {
            check(is_non_ws(a))?;
            v.push_str(" raddr ");
            v.push_str(a);
        }
        if let Some(p) = self.related_port {
            v.push_str(&format!(" rport {p}"));
        }
        for (name, value) in &self.extensions {
            let related = name.eq_ignore_ascii_case("raddr") || name.eq_ignore_ascii_case("rport");
            check(is_token(name) && is_non_ws(value) && !related)?;
            v.push(' ');
            v.push_str(name);
            v.push(' ');
            v.push_str(value);
        }
        Ok(Attribute { name: "candidate".to_string(), value: Some(v) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example in RFC 8866, section 5.
    const RFC_EXAMPLE: &[u8] = b"v=0\r\n\
        o=jdoe 3724394400 3724394405 IN IP4 198.51.100.1\r\n\
        s=Call to John Smith\r\n\
        i=SDP Offer #1\r\n\
        u=http://www.jdoe.example.com/home.html\r\n\
        e=Jane Doe <jane@jdoe.example.com>\r\n\
        p=+1 617 555-6011\r\n\
        c=IN IP4 198.51.100.1\r\n\
        t=0 0\r\n\
        m=audio 49170 RTP/AVP 0\r\n\
        m=audio 49180 RTP/AVP 0\r\n\
        m=video 51372 RTP/AVP 99\r\n\
        c=IN IP6 2001:db8::2\r\n\
        a=rtpmap:99 h263-1998/90000\r\n";

    /// A description that uses every line type.
    const EVERY_LINE: &[u8] = b"v=0\r\n\
        o=- 1 2 IN IP6 2001:db8::1\r\n\
        s=All lines\r\n\
        i=info\r\n\
        u=http://example.com/\r\n\
        e=a@example.com\r\n\
        e=b@example.com\r\n\
        p=+1 555 0100\r\n\
        c=IN IP4 224.2.17.12/127/2\r\n\
        b=CT:128\r\n\
        b=AS:64\r\n\
        t=3730928400 3749680800\r\n\
        r=7d 1h 0 25h\r\n\
        r=604800 3600 0 90000\r\n\
        z=3730928400 -1h 3749680800 0\r\n\
        t=0 0\r\n\
        k=prompt\r\n\
        a=recvonly\r\n\
        a=tool:test 1.0\r\n\
        m=audio 49170/2 RTP/AVP 0 96\r\n\
        i=voice\r\n\
        c=IN IP4 198.51.100.7\r\n\
        c=IN IP4 198.51.100.8\r\n\
        b=AS:32\r\n\
        k=clear:secret\r\n\
        a=rtpmap:96 opus/48000/2\r\n\
        a=fmtp:96 minptime=10; useinbandfec=1\r\n\
        a=candidate:1 1 UDP 2130706431 203.0.113.141 8998 typ host\r\n\
        a=sendonly\r\n\
        m=application 0 UDP/DTLS/SCTP webrtc-datachannel\r\n";

    fn bytewise(b: &[u8]) -> Result<SessionDescription, Error> {
        let mut d = Decoder::new();
        for byte in b {
            d.feed(std::slice::from_ref(byte));
        }
        d.finish()
    }

    #[test]
    fn rfc_example() {
        let d = SessionDescription::parse(RFC_EXAMPLE).unwrap();
        assert_eq!(d.origin.username, "jdoe");
        assert_eq!(d.origin.session_id, 3724394400);
        assert_eq!(d.origin.session_version, 3724394405);
        assert_eq!(d.origin.address, "198.51.100.1");
        assert_eq!(d.name, "Call to John Smith");
        assert_eq!(d.information.as_deref(), Some("SDP Offer #1"));
        assert_eq!(d.uri.as_deref(), Some("http://www.jdoe.example.com/home.html"));
        assert_eq!(d.emails, ["Jane Doe <jane@jdoe.example.com>"]);
        assert_eq!(d.phones, ["+1 617 555-6011"]);
        assert_eq!(d.times, [Timing::default()]);
        assert_eq!(d.media.len(), 3);
        assert_eq!(d.media[1].port, 49180);
        let video = &d.media[2];
        assert_eq!((video.kind.as_str(), video.proto.as_str()), ("video", "RTP/AVP"));
        assert_eq!(video.connections[0].address, "2001:db8::2");
        let map = video.rtpmap("99").unwrap();
        assert_eq!(map, RtpMap { payload: 99, encoding: "h263-1998".into(), clock_rate: 90000, params: None });
        // Written back, it is the same bytes.
        assert_eq!(d.to_bytes().unwrap(), RFC_EXAMPLE);
        assert_eq!(bytewise(RFC_EXAMPLE), Ok(d));
    }

    #[test]
    fn rfc_direction_example() {
        let d = SessionDescription::parse(
            b"v=0\no=jdoe 3724395000 3724395001 IN IP6 2001:db8::1\ns=-\nc=IN IP6 2001:db8::1\nt=0 0\na=inactive\n\
              m=audio 49170 RTP/AVP 0\na=sendrecv\nm=audio 49180 RTP/AVP 0\nm=video 51372 RTP/AVP 99\n\
              a=rtpmap:99 h263-1998/90000\n",
        )
        .unwrap();
        let dirs: Vec<Direction> = d.media.iter().map(|m| d.direction(m)).collect();
        assert_eq!(dirs, [Direction::SendRecv, Direction::Inactive, Direction::Inactive]);
        let mut d2 = d.clone();
        d2.attributes.clear();
        assert_eq!(d2.direction(&d2.media[1]), Direction::SendRecv);
        assert_eq!(Direction::SendOnly.reverse(), Direction::RecvOnly);
        assert_eq!(Direction::Inactive.reverse(), Direction::Inactive);
        for dir in [Direction::SendRecv, Direction::SendOnly, Direction::RecvOnly, Direction::Inactive] {
            assert_eq!(Direction::from_attribute(&dir.to_attribute()), Some(dir));
        }
        assert_eq!(Direction::from_attribute(&Attribute::new("sendonly", "x")), None);
    }

    #[test]
    fn every_line_type() {
        let d = SessionDescription::parse(EVERY_LINE).unwrap();
        assert_eq!(d.emails.len(), 2);
        assert_eq!(d.connection.as_ref().unwrap().address, "224.2.17.12/127/2");
        assert_eq!(
            d.bandwidths,
            [Bandwidth { kind: "CT".into(), value: 128 }, Bandwidth { kind: "AS".into(), value: 64 }]
        );
        assert_eq!(d.times.len(), 2);
        // The RFC's two ways of writing the same repeat.
        let r = Repeat { interval: 604800, duration: 3600, offsets: vec![0, 90000] };
        assert_eq!(d.times[0].repeats, [r.clone(), r]);
        assert_eq!(
            d.times[0].zones,
            [ZoneAdjustment { time: 3730928400, offset: -3600 }, ZoneAdjustment { time: 3749680800, offset: 0 }]
        );
        assert_eq!(d.key.as_deref(), Some("prompt"));
        assert_eq!(d.attribute("tool").unwrap().value.as_deref(), Some("test 1.0"));
        let audio = &d.media[0];
        assert_eq!((audio.port, audio.port_count), (49170, Some(2)));
        assert_eq!(audio.formats, ["0", "96"]);
        assert_eq!(audio.information.as_deref(), Some("voice"));
        assert_eq!(audio.connections.len(), 2);
        assert_eq!(audio.key.as_deref(), Some("clear:secret"));
        assert_eq!(audio.direction(), Some(Direction::SendOnly));
        assert_eq!(d.direction(&d.media[1]), Direction::RecvOnly);
        let fmtp = audio.fmtp("96").unwrap();
        assert_eq!(fmtp.parameters(), [("minptime", Some("10")), ("useinbandfec", Some("1"))]);
        assert_eq!(audio.candidates().count(), 1);
        assert_eq!(d.media[1].formats, ["webrtc-datachannel"]);
        // A round trip: the writer uses seconds, so the bytes differ, but
        // the description reads back equal.
        let bytes = d.to_bytes().unwrap();
        assert_eq!(SessionDescription::parse(&bytes), Ok(d.clone()));
        assert_eq!(bytewise(EVERY_LINE), Ok(d));
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("r=604800 3600 0 90000\r\n"));
        assert!(text.contains("z=3730928400 -3600 3749680800 0\r\n"));
    }

    #[test]
    fn line_endings() {
        let lf: Vec<u8> = RFC_EXAMPLE.iter().copied().filter(|&b| b != b'\r').collect();
        let want = SessionDescription::parse(RFC_EXAMPLE).unwrap();
        assert_eq!(SessionDescription::parse(&lf), Ok(want.clone()));
        // No ending on the last line.
        assert_eq!(SessionDescription::parse(&RFC_EXAMPLE[..RFC_EXAMPLE.len() - 2]), Ok(want.clone()));
        assert_eq!(SessionDescription::parse(&RFC_EXAMPLE[..RFC_EXAMPLE.len() - 1]), Ok(want));
    }

    #[test]
    fn new_writes_the_minimum() {
        let origin = Origin {
            username: "-".into(),
            session_id: 1,
            session_version: 1,
            net_type: "IN".into(),
            addr_type: "IP4".into(),
            address: "192.0.2.1".into(),
        };
        let d = SessionDescription::new(origin, " ");
        let bytes = d.to_bytes().unwrap();
        assert_eq!(bytes, b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns= \r\nt=0 0\r\n");
        assert_eq!(SessionDescription::parse(&bytes), Ok(d));
    }

    fn err(b: &[u8]) -> Error {
        let Err(e) = SessionDescription::parse(b) else {
            panic!("parsed: {:?}", String::from_utf8_lossy(&b[..b.len().min(200)]))
        };
        assert_eq!(bytewise(b), Err(e));
        e
    }

    const HEAD: &str = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=x\r\n";

    fn with(rest: &str) -> Vec<u8> {
        format!("{HEAD}{rest}").into_bytes()
    }

    #[test]
    fn missing_lines() {
        assert_eq!(err(b""), Error::Missing('v'));
        assert_eq!(err(b"v=0\r\n"), Error::Missing('o'));
        assert_eq!(err(b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\n"), Error::Missing('s'));
        assert_eq!(err(HEAD.as_bytes()), Error::Missing('t'));
        assert_eq!(err(&with("c=IN IP4 1.2.3.4\r\n")), Error::Missing('t'));
        assert_eq!(err(&with("t=0 0\r\nm=audio 1 RTP/AVP 0\r\n")), Error::Missing('c'));
        assert!(SessionDescription::parse(&with("t=0 0\r\nm=audio 1 RTP/AVP 0\r\nc=IN IP4 1.2.3.4\r\n")).is_ok());
    }

    #[test]
    fn malformed_and_unknown_lines() {
        assert_eq!(err(b"v=0\r\n\r\n"), Error::Malformed { line: 2 });
        assert_eq!(err(b"V=0\r\n"), Error::Malformed { line: 1 });
        assert_eq!(err(b"v 0\r\n"), Error::Malformed { line: 1 });
        assert_eq!(err(b"v"), Error::Malformed { line: 1 });
        assert_eq!(err(b"=0"), Error::Malformed { line: 1 });
        assert_eq!(err(&with("t=0 0\r\nx=1\r\n")), Error::UnknownType { line: 5, kind: 'x' });
        // Unknown even where the line could not come.
        assert_eq!(err(b"y=0\r\n"), Error::UnknownType { line: 1, kind: 'y' });
    }

    #[test]
    fn encoding() {
        let mut b = with("i=");
        b.extend_from_slice(&[0xff, 0xfe, b'\r', b'\n']);
        assert_eq!(err(&b), Error::Encoding { line: 4 });
        // UTF-8 text is fine.
        assert!(SessionDescription::parse(&with("i=caf\u{e9}\r\nt=0 0\r\n")).is_ok());
    }

    #[test]
    fn syntax_errors() {
        let bad: &[(&str, usize, char)] = &[
            ("i=\0\r\nt=0 0\r\n", 4, 'i'),
            ("i=\r\nt=0 0\r\n", 4, 'i'),
            ("i=a\rb\r\nt=0 0\r\n", 4, 'i'),
            ("u=\r\n", 4, 'u'),
            ("e=\r\n", 4, 'e'),
            ("p=\r\n", 4, 'p'),
            ("c=IN IP4\r\n", 4, 'c'),
            ("c=IN IP4 1.2.3.4 x\r\n", 4, 'c'),
            ("c=I N IP4 1.2.3.4\r\n", 4, 'c'),
            ("c=IN IP4  1.2.3.4\r\n", 4, 'c'),
            ("b=AS\r\n", 4, 'b'),
            ("b=AS:x\r\n", 4, 'b'),
            ("b=A(S:1\r\n", 4, 'b'),
            ("b=AS:+1\r\n", 4, 'b'),
            ("b=AS:99999999999999999999\r\n", 4, 'b'),
            ("t=0\r\n", 4, 't'),
            ("t=0 0 0\r\n", 4, 't'),
            ("t=a 0\r\n", 4, 't'),
            ("t=0 0\r\nr=0 1 0\r\n", 5, 'r'),
            ("t=0 0\r\nr=1 1\r\n", 5, 'r'),
            ("t=0 0\r\nr=1x 1 0\r\n", 5, 'r'),
            ("t=0 0\r\nr=1 1 0h5\r\n", 5, 'r'),
            ("t=0 0\r\nr=99999999999999999d 1 0\r\n", 5, 'r'),
            ("t=0 0\r\nr=1 1 0\r\nz=1\r\n", 6, 'z'),
            ("t=0 0\r\nr=1 1 0\r\nz=1 -\r\n", 6, 'z'),
            ("t=0 0\r\nr=1 1 0\r\nz=1 9223372036854775808\r\n", 6, 'z'),
            ("t=0 0\r\nr=1 1 0\r\nz=-1 1\r\n", 6, 'z'),
            ("t=0 0\r\nk=\r\n", 5, 'k'),
            ("t=0 0\r\na=\r\n", 5, 'a'),
            ("t=0 0\r\na=x:\r\n", 5, 'a'),
            ("t=0 0\r\na=x y\r\n", 5, 'a'),
            ("t=0 0\r\nm=audio 1 RTP/AVP\r\n", 5, 'm'),
            ("t=0 0\r\nm=audio 65536 RTP/AVP 0\r\n", 5, 'm'),
            ("t=0 0\r\nm=audio 1/0 RTP/AVP 0\r\n", 5, 'm'),
            ("t=0 0\r\nm=audio 1/ RTP/AVP 0\r\n", 5, 'm'),
            ("t=0 0\r\nm=audio 1 RTP//AVP 0\r\n", 5, 'm'),
            ("t=0 0\r\nm=audio 1 RTP/AVP 0 \r\n", 5, 'm'),
            ("t=0 0\r\nm=audio 1 RTP/AVP 0\r\ni=\r\n", 6, 'i'),
            ("t=0 0\r\nm=audio 1 RTP/AVP 0\r\nc=IN\r\n", 6, 'c'),
            ("t=0 0\r\nm=audio 1 RTP/AVP 0\r\nb=x\r\n", 6, 'b'),
            ("t=0 0\r\nm=audio 1 RTP/AVP 0\r\nk=\r\n", 6, 'k'),
            ("t=0 0\r\nm=audio 1 RTP/AVP 0\r\na=:1\r\n", 6, 'a'),
        ];
        for &(rest, line, kind) in bad {
            assert_eq!(err(&with(rest)), Error::Syntax { line, kind }, "{rest:?}");
        }
        assert_eq!(err(b"v=1\r\n"), Error::Syntax { line: 1, kind: 'v' });
        assert_eq!(err(b"v=0\r\no=- 1 1 IN IP4\r\n"), Error::Syntax { line: 2, kind: 'o' });
        assert_eq!(err(b"v=0\r\no=- 1 1 IN IP4 a b\r\n"), Error::Syntax { line: 2, kind: 'o' });
        assert_eq!(err(b"v=0\r\no=- x 1 IN IP4 a\r\n"), Error::Syntax { line: 2, kind: 'o' });
        assert_eq!(err(b"v=0\r\no=- 1 1 IN IP4 a\r\ns=\r\n"), Error::Syntax { line: 3, kind: 's' });
    }

    #[test]
    fn order_errors() {
        let bad: &[(&str, usize, char)] = &[
            ("t=0 0\r\ns=y\r\n", 5, 's'),
            ("t=0 0\r\no=- 1 1 IN IP4 a\r\n", 5, 'o'),
            ("i=a\r\ni=b\r\n", 5, 'i'),
            ("u=a\r\ni=b\r\n", 5, 'i'),
            ("e=a\r\nu=b\r\n", 5, 'u'),
            ("p=a\r\ne=b\r\n", 5, 'e'),
            ("c=IN IP4 a\r\nc=IN IP4 b\r\n", 5, 'c'),
            ("b=AS:1\r\nc=IN IP4 a\r\n", 5, 'c'),
            ("a=x\r\n", 4, 'a'),
            ("k=prompt\r\n", 4, 'k'),
            ("m=audio 1 RTP/AVP 0\r\n", 4, 'm'),
            ("r=1 1 0\r\n", 4, 'r'),
            ("z=1 1\r\n", 4, 'z'),
            ("t=0 0\r\nb=AS:1\r\n", 5, 'b'),
            ("t=0 0\r\nz=1 1\r\n", 5, 'z'),
            ("t=0 0\r\nr=1 1 0\r\nz=1 1\r\nr=1 1 0\r\n", 7, 'r'),
            ("t=0 0\r\nr=1 1 0\r\nz=1 1\r\nz=1 1\r\n", 7, 'z'),
            ("t=0 0\r\nk=prompt\r\nt=0 0\r\n", 6, 't'),
            ("t=0 0\r\nk=prompt\r\nk=prompt\r\n", 6, 'k'),
            ("t=0 0\r\na=x\r\nk=prompt\r\n", 6, 'k'),
            ("t=0 0\r\na=x\r\nr=1 1 0\r\n", 6, 'r'),
            ("t=0 0\r\nm=audio 1 RTP/AVP 0\r\nt=0 0\r\n", 6, 't'),
            ("t=0 0\r\nm=audio 1 RTP/AVP 0\r\nu=a\r\n", 6, 'u'),
            ("t=0 0\r\nm=audio 1 RTP/AVP 0\r\ne=a\r\n", 6, 'e'),
            ("t=0 0\r\nm=audio 1 RTP/AVP 0\r\nr=1 1 0\r\n", 6, 'r'),
            ("t=0 0\r\nm=audio 1 RTP/AVP 0\r\nc=IN IP4 a\r\ni=x\r\n", 7, 'i'),
            ("t=0 0\r\nm=audio 1 RTP/AVP 0\r\nb=AS:1\r\nc=IN IP4 a\r\n", 7, 'c'),
            ("t=0 0\r\nm=audio 1 RTP/AVP 0\r\na=x\r\nb=AS:1\r\n", 7, 'b'),
            ("t=0 0\r\nm=audio 1 RTP/AVP 0\r\nk=a\r\nk=a\r\n", 7, 'k'),
        ];
        for &(rest, line, kind) in bad {
            assert_eq!(err(&with(rest)), Error::Order { line, kind }, "{rest:?}");
        }
        assert_eq!(err(b"o=- 1 1 IN IP4 a\r\n"), Error::Order { line: 1, kind: 'o' });
        assert_eq!(err(b"v=0\r\nv=0\r\n"), Error::Order { line: 2, kind: 'v' });
        assert_eq!(err(b"v=0\r\ns=x\r\n"), Error::Order { line: 2, kind: 's' });
    }

    #[test]
    fn limits() {
        // A line one byte too long, and one just short enough.
        let long = format!("t=0 0\r\na=x:{}\r\n", "y".repeat(MAX_LINE_LEN - 3));
        assert_eq!(err(&with(&long)), Error::LineTooLong { line: 5 });
        let fits = format!("t=0 0\r\na=x:{}\r\n", "y".repeat(MAX_LINE_LEN - 4));
        assert!(SessionDescription::parse(&with(&fits)).is_ok());
        // A long line is caught before its end comes.
        let mut d = Decoder::new();
        d.feed(&vec![b'a'; MAX_LINE_LEN + 2]);
        assert_eq!(d.error(), Some(Error::LineTooLong { line: 1 }));
        d.feed(b"\r\nv=0");
        assert_eq!(d.finish(), Err(Error::LineTooLong { line: 1 }));
        // Too many lines.
        let many = format!("t=0 0\r\n{}", "a=x\r\n".repeat(MAX_LINES));
        assert_eq!(err(&with(&many)), Error::TooManyLines);
        let exactly = format!("t=0 0\r\n{}", "a=x\r\n".repeat(MAX_LINES - 4));
        assert!(SessionDescription::parse(&with(&exactly)).is_ok());
        // Too many bytes.
        let line = format!("a=x:{}\r\n", "y".repeat(1000));
        let big = format!("t=0 0\r\n{}", line.repeat(MAX_LEN / line.len() + 1));
        assert_eq!(err(&with(&big)), Error::TooLong);
    }

    fn sample() -> SessionDescription {
        SessionDescription::parse(EVERY_LINE).unwrap()
    }

    #[test]
    fn writer_errors() {
        let check = |d: &SessionDescription, want: Error| {
            assert_eq!(d.to_bytes(), Err(want));
        };
        let mut d = sample();
        d.times.clear();
        check(&d, Error::Missing('t'));
        let mut d = sample();
        d.connection = None;
        d.media[1].connections.clear();
        check(&d, Error::Missing('c'));
        let mut d = sample();
        d.origin.username = "a b".into();
        check(&d, Error::Syntax { line: 2, kind: 'o' });
        let mut d = sample();
        d.origin.net_type = String::new();
        check(&d, Error::Syntax { line: 2, kind: 'o' });
        let mut d = sample();
        d.name = String::new();
        check(&d, Error::Syntax { line: 3, kind: 's' });
        let mut d = sample();
        d.information = Some("a\nb".into());
        check(&d, Error::Syntax { line: 4, kind: 'i' });
        let mut d = sample();
        d.uri = Some("\r".into());
        check(&d, Error::Syntax { line: 5, kind: 'u' });
        let mut d = sample();
        d.emails[1] = "\0".into();
        check(&d, Error::Syntax { line: 7, kind: 'e' });
        let mut d = sample();
        d.phones[0] = String::new();
        check(&d, Error::Syntax { line: 8, kind: 'p' });
        let mut d = sample();
        d.connection.as_mut().unwrap().address = "a b".into();
        check(&d, Error::Syntax { line: 9, kind: 'c' });
        let mut d = sample();
        d.bandwidths[0].kind = "A:S".into();
        check(&d, Error::Syntax { line: 10, kind: 'b' });
        let mut d = sample();
        d.times[0].repeats[0].interval = 0;
        check(&d, Error::Syntax { line: 13, kind: 'r' });
        let mut d = sample();
        d.times[0].repeats[1].offsets.clear();
        check(&d, Error::Syntax { line: 14, kind: 'r' });
        let mut d = sample();
        d.key = Some(String::new());
        check(&d, Error::Syntax { line: 17, kind: 'k' });
        let mut d = sample();
        d.attributes[1].name = "to ol".into();
        check(&d, Error::Syntax { line: 19, kind: 'a' });
        let mut d = sample();
        d.attributes[1].value = Some(String::new());
        check(&d, Error::Syntax { line: 19, kind: 'a' });
        for f in [
            |m: &mut Media| m.kind = String::new(),
            |m: &mut Media| m.port_count = Some(0),
            |m: &mut Media| m.proto = "RTP/".into(),
            |m: &mut Media| m.formats.clear(),
            |m: &mut Media| m.formats[0] = "0 1".into(),
        ] {
            let mut d = sample();
            f(&mut d.media[0]);
            check(&d, Error::Syntax { line: 20, kind: 'm' });
        }
        let mut d = sample();
        d.media[0].information = Some(String::new());
        check(&d, Error::Syntax { line: 21, kind: 'i' });
        let mut d = sample();
        d.media[0].connections[1].addr_type = "I P4".into();
        check(&d, Error::Syntax { line: 23, kind: 'c' });
        let mut d = sample();
        d.media[0].bandwidths[0].kind = String::new();
        check(&d, Error::Syntax { line: 24, kind: 'b' });
        let mut d = sample();
        d.media[0].key = Some("\n".into());
        check(&d, Error::Syntax { line: 25, kind: 'k' });
        let mut d = sample();
        d.media[0].attributes[0].name = "rtp:map".into();
        check(&d, Error::Syntax { line: 26, kind: 'a' });
    }

    #[test]
    fn writer_limits() {
        let mut d = sample();
        d.attributes.push(Attribute::new("x", &"y".repeat(MAX_LINE_LEN - 3)));
        assert_eq!(d.to_bytes().err(), Some(Error::LineTooLong { line: 20 }));
        let mut d = sample();
        d.attributes.push(Attribute::new("x", &"y".repeat(MAX_LINE_LEN - 4)));
        let bytes = d.to_bytes().unwrap();
        assert_eq!(SessionDescription::parse(&bytes), Ok(d));
        let mut d = sample();
        d.attributes.extend(std::iter::repeat_n(Attribute::flag("x"), MAX_LINES));
        assert_eq!(d.to_bytes().err(), Some(Error::TooManyLines));
        // As many lines as fit.
        let mut d = sample();
        let n = d.to_bytes().unwrap().iter().filter(|&&b| b == b'\n').count();
        d.attributes.extend(std::iter::repeat_n(Attribute::flag("x"), MAX_LINES - n));
        let bytes = d.to_bytes().unwrap();
        assert_eq!(SessionDescription::parse(&bytes), Ok(d));
        let mut d = sample();
        d.attributes.extend(std::iter::repeat_n(Attribute::new("x", &"y".repeat(2000)), MAX_LINES / 2));
        assert_eq!(d.to_bytes().err(), Some(Error::TooLong));
        // Exactly MAX_LEN bytes.
        let mut d = sample();
        let mut len = d.to_bytes().unwrap().len();
        // Each of these lines is 4002 bytes with its CRLF.
        while len + 4002 <= MAX_LEN {
            d.attributes.push(Attribute::new("x", &"y".repeat(3996)));
            len += 4002;
        }
        let rest = MAX_LEN - len;
        d.attributes.push(Attribute::new("x", &"y".repeat(rest - 6)));
        let bytes = d.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_LEN);
        assert_eq!(SessionDescription::parse(&bytes), Ok(d.clone()));
        d.attributes.push(Attribute::flag("x"));
        assert_eq!(d.to_bytes().err(), Some(Error::TooLong));
    }

    #[test]
    fn zone_offsets_round_trip() {
        let mut d = sample();
        d.times[1].zones = vec![
            ZoneAdjustment { time: 1, offset: i64::MIN },
            ZoneAdjustment { time: u64::MAX, offset: i64::MAX },
            ZoneAdjustment { time: 5, offset: -1 },
        ];
        d.times[1].repeats = vec![Repeat { interval: 1, duration: 0, offsets: vec![0] }];
        let bytes = d.to_bytes().unwrap();
        assert_eq!(SessionDescription::parse(&bytes), Ok(d));
    }

    #[test]
    fn rtpmap() {
        let a = Attribute::new("rtpmap", "96 opus/48000/2");
        let r = RtpMap::from_attribute(&a).unwrap();
        assert_eq!(r, RtpMap { payload: 96, encoding: "opus".into(), clock_rate: 48000, params: Some("2".into()) });
        assert_eq!(r.to_attribute(), Ok(a));
        for bad in [
            "96",
            "96 opus",
            "96 opus/x",
            "128 opus/8000",
            "96 op us/8000",
            "96 opus/8000/",
            "x opus/8000",
            "96 opus/4294967296",
        ] {
            assert_eq!(RtpMap::from_attribute(&Attribute::new("rtpmap", bad)), Err(AttributeError), "{bad}");
        }
        assert_eq!(RtpMap::from_attribute(&Attribute::new("fmtp", "96 opus/8000")), Err(AttributeError));
        assert_eq!(RtpMap::from_attribute(&Attribute::flag("rtpmap")), Err(AttributeError));
        let mut r = RtpMap { payload: 128, encoding: "PCMU".into(), clock_rate: 8000, params: None };
        assert_eq!(r.to_attribute(), Err(AttributeError));
        r.payload = 0;
        r.params = Some("a b".into());
        assert_eq!(r.to_attribute(), Err(AttributeError));
        r.params = None;
        r.encoding = "a/b".into();
        assert_eq!(r.to_attribute(), Err(AttributeError));
    }

    #[test]
    fn fmtp() {
        let a = Attribute::new("fmtp", "101 0-15");
        let f = Fmtp::from_attribute(&a).unwrap();
        assert_eq!(f.parameters(), [("0-15", None)]);
        assert_eq!(f.to_attribute(), Ok(a));
        let f = Fmtp { format: "97".into(), params: "profile-level-id=42e01f ; packetization-mode=1;".into() };
        let back = Fmtp::from_attribute(&f.to_attribute().unwrap()).unwrap();
        assert_eq!(back.parameters(), [("profile-level-id", Some("42e01f")), ("packetization-mode", Some("1"))]);
        assert_eq!(back, f);
        for bad in ["97", "97 ", "9:7 x"] {
            assert_eq!(Fmtp::from_attribute(&Attribute::new("fmtp", bad)), Err(AttributeError), "{bad}");
        }
        assert_eq!(Fmtp { format: "97".into(), params: String::new() }.to_attribute(), Err(AttributeError));
        assert_eq!(Fmtp { format: "9 7".into(), params: "x".into() }.to_attribute(), Err(AttributeError));
    }

    #[test]
    fn candidates() {
        // The examples in RFC 8839, section 5.1.
        let host = Attribute::new("candidate", "1 1 UDP 2130706431 203.0.113.141 8998 typ host");
        let c = Candidate::from_attribute(&host).unwrap();
        assert_eq!(c.kind, CandidateType::Host);
        assert_eq!((c.component, c.priority, c.port), (1, 2130706431, 8998));
        assert_eq!(c.to_attribute(), Ok(host));
        let srflx =
            Attribute::new("candidate", "2 1 UDP 1694498815 192.0.2.3 45664 typ srflx raddr 203.0.113.141 rport 8998");
        let c = Candidate::from_attribute(&srflx).unwrap();
        assert_eq!(c.kind, CandidateType::ServerReflexive);
        assert_eq!(c.related_address.as_deref(), Some("203.0.113.141"));
        assert_eq!(c.related_port, Some(8998));
        assert_eq!(c.to_attribute(), Ok(srflx));
        // As browsers write them, with extensions, rport first.
        let a = Attribute::new(
            "candidate",
            "842163049 1 udp 1677729535 198.51.100.4 54400 typ srflx rport 51472 raddr 10.0.0.2 generation 0 network-cost 999",
        );
        let c = Candidate::from_attribute(&a).unwrap();
        assert_eq!(c.extensions, [("generation".into(), "0".into()), ("network-cost".into(), "999".into())]);
        let back = c.to_attribute().unwrap();
        assert_eq!(Candidate::from_attribute(&back), Ok(c.clone()));
        for t in ["prflx", "relay", "other"] {
            let a = Attribute::new("candidate", &format!("a+/ 256 TCP 0 h 1 typ {t}"));
            let c = Candidate::from_attribute(&a).unwrap();
            assert_eq!(c.to_attribute(), Ok(a));
        }
        let bad = [
            "1 1 UDP 1 a 1 typ",
            "1 1 UDP 1 a 1 type host",
            "1 0 UDP 1 a 1 typ host",
            "1 257 UDP 1 a 1 typ host",
            "1 0001 UDP 1 a 1 typ host",
            "1 1 UDP 4294967296 a 1 typ host",
            "1 1 UDP 1 a 65536 typ host",
            "1 1 UDP 1 a 000001 typ host",
            "1-2 1 UDP 1 a 1 typ host",
            "123456789012345678901234567890123 1 UDP 1 a 1 typ host",
            "1 1 UDP 1 a 1 typ host raddr",
            "1 1 UDP 1 a 1 typ host raddr a raddr b",
            "1 1 UDP 1 a 1 typ host rport 1 rport 2",
            "1 1 UDP 1 a 1 typ host rport x",
            "1 1 UDP 1 a 1 typ host gen:x 1",
            "1 1 UDP 1 a 1 typ host  generation 0",
        ];
        for v in bad {
            assert_eq!(Candidate::from_attribute(&Attribute::new("candidate", v)), Err(AttributeError), "{v}");
        }
        let mut c2 = c.clone();
        c2.extensions.push(("raddr".into(), "x".into()));
        assert_eq!(c2.to_attribute(), Err(AttributeError));
        let mut c2 = c.clone();
        c2.component = 0;
        assert_eq!(c2.to_attribute(), Err(AttributeError));
        let mut c2 = c.clone();
        c2.kind = CandidateType::Other("a b".into());
        assert_eq!(c2.to_attribute(), Err(AttributeError));
        let mut c2 = c;
        c2.related_address = Some(String::new());
        assert_eq!(c2.to_attribute(), Err(AttributeError));
    }

    #[test]
    fn every_truncated_prefix() {
        for full in [RFC_EXAMPLE, EVERY_LINE] {
            let whole = SessionDescription::parse(full).unwrap();
            for n in 0..full.len() {
                let part = &full[..n];
                let got = SessionDescription::parse(part);
                assert_eq!(bytewise(part), got, "{n}");
                match &got {
                    Ok(d) => {
                        assert_eq!(SessionDescription::parse(&d.to_bytes().unwrap()), Ok(d.clone()));
                        assert!(d.media.len() <= whole.media.len());
                    }
                    Err(e) => assert!(
                        matches!(e, Error::Missing(_) | Error::Syntax { .. } | Error::Malformed { .. }),
                        "{n}: {e}"
                    ),
                }
            }
        }
    }

    /// A deterministic generator, so a failing case can be found again.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        fn pick<'a>(&mut self, xs: &[&'a str]) -> &'a str {
            xs[self.below(xs.len())]
        }
    }

    /// Checks the reader on `b`: it agrees with itself fed a byte at a
    /// time and in odd chunks, and what it reads, the writer writes and
    /// the reader reads back.
    fn check_bytes(b: &[u8], rng: &mut Lcg) {
        let got = SessionDescription::parse(b);
        assert_eq!(bytewise(b), got);
        let mut d = Decoder::new();
        let mut rest = b;
        while !rest.is_empty() {
            let n = (rng.below(7) + 1).min(rest.len());
            d.feed(&rest[..n]);
            rest = &rest[n..];
        }
        assert_eq!(d.finish(), got);
        if let Ok(desc) = got {
            let out = desc.to_bytes().unwrap();
            assert_eq!(SessionDescription::parse(&out), Ok(desc.clone()));
            for m in &desc.media {
                for a in &m.attributes {
                    if let Ok(r) = RtpMap::from_attribute(a) {
                        assert_eq!(RtpMap::from_attribute(&r.to_attribute().unwrap()), Ok(r));
                    }
                    if let Ok(f) = Fmtp::from_attribute(a) {
                        assert_eq!(Fmtp::from_attribute(&f.to_attribute().unwrap()), Ok(f));
                    }
                    if let Ok(c) = Candidate::from_attribute(a) {
                        assert_eq!(Candidate::from_attribute(&c.to_attribute().unwrap()), Ok(c));
                    }
                }
                let _ = desc.direction(m);
            }
        }
    }

    #[test]
    fn fuzz_reader() {
        let mut rng = Lcg(0x5d9);
        let lines: Vec<&[u8]> = EVERY_LINE.split_inclusive(|&b| b == b'\n').collect();
        let noise = b" =:/\r\n\0\xff0aZ-";
        for round in 0..4000 {
            let mut b: Vec<u8> = match round % 3 {
                // Random bytes.
                0 => (0..rng.below(200)).map(|_| rng.next() as u8).collect(),
                // Lines of the sample, shuffled, dropped and repeated.
                1 => {
                    let mut b = lines[..3].concat();
                    for _ in 0..rng.below(30) {
                        b.extend_from_slice(lines[rng.below(lines.len())]);
                    }
                    b
                }
                // The sample with bytes changed.
                _ => EVERY_LINE.to_vec(),
            };
            for _ in 0..rng.below(4) {
                if !b.is_empty() {
                    let i = rng.below(b.len());
                    b[i] = noise[rng.below(noise.len())];
                }
            }
            check_bytes(&b, &mut rng);
        }
    }

    #[test]
    fn fuzz_writer() {
        let mut rng = Lcg(42);
        let words =
            ["a", "IN", "IP4", "x y", "", "0", "rtp:map", "-", "\u{e9}", "a\r", "/", "RTP/AVP", "\0", "96 opus/48000"];
        let mut written = 0;
        for _ in 0..3000 {
            let mut d = sample();
            for _ in 0..rng.below(4) {
                let w = rng.pick(&words).to_string();
                let n = rng.next();
                match rng.below(16) {
                    0 => d.origin.username = w,
                    1 => d.origin.address = w,
                    2 => d.name = w,
                    3 => d.information = Some(w),
                    4 => d.attributes.push(Attribute { name: w, value: None }),
                    5 => d.attributes.push(Attribute::new("x", &w)),
                    6 => d.media[0].formats.push(w),
                    7 => d.media[0].proto = w,
                    8 => d.media[0].port_count = Some(n as u16 % 3),
                    9 => d.times[0].repeats.push(Repeat {
                        interval: n % 3,
                        duration: n,
                        offsets: vec![n; (n % 2) as usize],
                    }),
                    10 => d.times[0].zones.push(ZoneAdjustment { time: n, offset: n as i64 }),
                    11 => d.media[1].connections.push(Connection { net_type: w, ..Connection::default() }),
                    12 => d.bandwidths.push(Bandwidth { kind: w, value: n }),
                    13 => d.media.push(Media { kind: w, ..Media::default() }),
                    14 => d.connection = None,
                    _ => d.key = Some(w),
                }
            }
            if let Ok(bytes) = d.to_bytes() {
                written += 1;
                assert_eq!(SessionDescription::parse(&bytes), Ok(d.clone()));
                assert_eq!(bytewise(&bytes), Ok(d));
            }
        }
        assert!(written > 300, "{written}");
    }

    #[test]
    fn zone_needs_a_repeat() {
        // RFC 8866 section 9 and appendix: a z= line modifies the r= lines
        // just before it, and z= with no r= before it is a syntax error.
        assert_eq!(err(&with("t=0 0\r\nz=1 -1h\r\n")), Error::Order { line: 5, kind: 'z' });
        assert!(SessionDescription::parse(&with("t=0 0\r\nr=1 1 0\r\nz=1 -1h\r\n")).is_ok());
        let mut d = sample();
        d.times[1].zones = vec![ZoneAdjustment { time: 1, offset: 1 }];
        assert_eq!(d.to_bytes(), Err(Error::Syntax { line: 17, kind: 'z' }));
    }

    #[test]
    fn rtpmap_numbers_follow_the_grammar() {
        // clock-rate is an integer, which starts with a nonzero digit, and
        // payload-type is "0" or such an integer.
        for bad in ["96 opus/0", "96 opus/048000", "096 opus/48000", "00 PCMU/8000"] {
            assert_eq!(RtpMap::from_attribute(&Attribute::new("rtpmap", bad)), Err(AttributeError), "{bad}");
        }
        assert!(RtpMap::from_attribute(&Attribute::new("rtpmap", "0 PCMU/8000")).is_ok());
        let r = RtpMap { payload: 0, encoding: "PCMU".into(), clock_rate: 0, params: None };
        assert_eq!(r.to_attribute(), Err(AttributeError));
        // A format that is not a plain number names no payload type.
        let d = SessionDescription::parse(&with(
            "c=IN IP4 a\r\nt=0 0\r\nm=audio 1 RTP/AVP +96\r\na=rtpmap:96 opus/48000\r\n",
        ))
        .unwrap();
        assert_eq!(d.media[0].rtpmap("+96"), None);
        assert!(d.media[0].rtpmap("96").is_some());
    }

    #[test]
    fn candidate_type_round_trips() {
        // A world may build Other with a name the reader maps to a known
        // type. Written, it would read back as a different value.
        let host = Candidate::from_attribute(&Attribute::new("candidate", "1 1 UDP 1 a 1 typ host")).unwrap();
        for name in ["host", "srflx", "prflx", "relay", "HOST"] {
            let mut c = host.clone();
            c.kind = CandidateType::Other(name.into());
            assert_eq!(c.to_attribute(), Err(AttributeError), "{name}");
        }
        for kind in [CandidateType::Host, CandidateType::Relay, CandidateType::Other("x-new".into())] {
            assert_eq!(CandidateType::from_name(kind.as_str()), kind);
        }
    }

    #[test]
    fn candidate_keywords_ignore_case() {
        // RFC 8839 writes "typ", the type names, "raddr" and "rport" as ABNF
        // strings, which match in any case (RFC 5234, section 2.3).
        let a = Attribute::new("candidate", "1 1 UDP 1 a 1 TYP Srflx RADDR 10.0.0.1 RPort 9");
        let c = Candidate::from_attribute(&a).unwrap();
        assert_eq!(c.kind, CandidateType::ServerReflexive);
        assert_eq!((c.related_address.as_deref(), c.related_port), (Some("10.0.0.1"), Some(9)));
        assert!(c.extensions.is_empty());
        assert_eq!(Candidate::from_attribute(&c.to_attribute().unwrap()), Ok(c.clone()));
        // An extension named RADDR would read back as raddr.
        let mut c2 = c;
        c2.related_address = None;
        c2.extensions.push(("RADDR".into(), "x".into()));
        assert_eq!(c2.to_attribute(), Err(AttributeError));
        let bad = Attribute::new("candidate", "1 1 UDP 1 a 1 typ host raddr a RADDR b");
        assert_eq!(Candidate::from_attribute(&bad), Err(AttributeError));
    }

    #[test]
    fn fuzz_candidate_writer() {
        let mut rng = Lcg(7);
        let words = ["host", "HOST", "Relay", "x", "a b", "", "raddr", "RPORT", "typ", "1", "+/", "\u{e9}", "a\r"];
        let mut written = 0;
        for _ in 0..3000 {
            let mut c = Candidate {
                foundation: rng.pick(&words).into(),
                component: rng.below(300) as u16,
                transport: rng.pick(&words).into(),
                priority: rng.next() as u32,
                address: rng.pick(&words).into(),
                port: rng.next() as u16,
                kind: CandidateType::from_name(rng.pick(&words)),
                ..Candidate::default()
            };
            if rng.below(3) == 0 {
                c.kind = CandidateType::Other(rng.pick(&words).into());
            }
            if rng.below(2) == 0 {
                c.related_address = Some(rng.pick(&words).into());
            }
            if rng.below(2) == 0 {
                c.related_port = Some(rng.next() as u16);
            }
            for _ in 0..rng.below(3) {
                c.extensions.push((rng.pick(&words).into(), rng.pick(&words).into()));
            }
            if let Ok(a) = c.to_attribute() {
                written += 1;
                assert_eq!(Candidate::from_attribute(&a), Ok(c));
            }
        }
        assert!(written > 100, "{written}");
    }

    #[test]
    fn session_attributes_named() {
        let d = SessionDescription::parse(&with("t=0 0\r\na=x:1\r\na=y\r\na=x:2\r\n")).unwrap();
        let xs: Vec<_> = d.attributes_named("x").map(|a| a.value.as_deref()).collect();
        assert_eq!(xs, [Some("1"), Some("2")]);
        assert_eq!(d.attribute("y"), Some(&Attribute::flag("y")));
        // Candidates and their types have defaults, so worlds can build them.
        let c = Candidate { foundation: "1".into(), component: 1, transport: "UDP".into(), ..Candidate::default() };
        assert_eq!(c.kind, CandidateType::Host);
        assert!(Candidate::from_attribute(&Candidate { address: "a".into(), ..c }.to_attribute().unwrap()).is_ok());
    }

    #[test]
    fn decoder_stops_at_the_first_error() {
        let mut d = Decoder::new();
        d.feed(b"v=0\r\nq=1\r\n");
        assert_eq!(d.error(), Some(Error::UnknownType { line: 2, kind: 'q' }));
        d.feed(RFC_EXAMPLE);
        assert_eq!(d.finish(), Err(Error::UnknownType { line: 2, kind: 'q' }));
    }

    #[test]
    fn errors_display() {
        let all = [
            Error::TooLong,
            Error::TooManyLines,
            Error::LineTooLong { line: 1 },
            Error::Malformed { line: 1 },
            Error::UnknownType { line: 1, kind: 'x' },
            Error::Encoding { line: 1 },
            Error::Syntax { line: 1, kind: 'o' },
            Error::Order { line: 1, kind: 'a' },
            Error::Missing('t'),
        ];
        for e in all {
            assert!(!e.to_string().is_empty());
        }
        assert!(!AttributeError.to_string().is_empty());
    }
}
