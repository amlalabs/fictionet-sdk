//! The Git wire protocol: pkt-lines, requests, ref advertisements and
//! negotiation lines, read and written with no I/O.
//!
//! Git clients fetch and push over TCP port 9418 (`git://`), over SSH and
//! over smart HTTP. All three carry the same messages, split into
//! pkt-lines: a four-digit hex length, then the data. A flush packet
//! (`0000`) ends a message. Protocol version 2 adds a delimiter packet
//! (`0001`) and a response-end packet (`0002`). This module follows the
//! Git documentation pages gitprotocol-common, gitprotocol-pack and
//! gitprotocol-v2.
//!
//! A world that plays a Git server passes bytes from a
//! [`tcp`](crate::stdlib::tcp) connection to
//! [`Stream<Frames>`](super::codec::Stream), reads the client's [`ProtoRequest`],
//! and writes back an
//! [`Advertisement`] (version 0 or 1) or a [`CapabilityAdvertisement`]
//! (version 2). It then reads the client's [`V2Request`]s or
//! [`ClientLine`]s and answers with [`LsRef`]s, [`ServerLine`]s and pack
//! data split by [`band_packets`]. Which refs exist, which objects they
//! name, and the packfile's bytes are up to world code. This module keeps
//! packfiles as bytes and never looks inside them.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. Strings are UTF-8. Every name, path and value is at most
//! [`MAX_TEXT`] bytes, and every list has a named limit. Writers refuse
//! invalid fields and values beyond these limits.
//!
//! ```
//! use fictionet::stdlib::git_protocol::{
//!     Capability, CapabilityAdvertisement, LsRef, LsRefsArg, ObjectId, Packet, V2Request,
//! };
//! use fictionet::stdlib::codec::Wire;
//!
//! // What the server says first, in protocol version 2.
//! let ad = CapabilityAdvertisement {
//!     capabilities: vec![Capability::new("ls-refs"), Capability::with_value("fetch", "shallow")],
//! };
//! assert!(ad.to_bytes().unwrap().starts_with(b"000eversion 2\n000cls-refs\n"));
//!
//! // The client asks which refs there are.
//! let bytes = b"0014command=ls-refs\n0001000csymrefs\n0014ref-prefix HEAD\n0000";
//! let request = V2Request::parse(bytes).unwrap();
//! let V2Request::Command(command) = request else { panic!("an empty request") };
//! assert_eq!(command.name, "ls-refs");
//! let args = command.ls_refs_args().unwrap();
//! assert_eq!(args, [LsRefsArg::Symrefs, LsRefsArg::RefPrefix("HEAD".to_string())]);
//!
//! // The world's answer: HEAD, pointing at its one branch.
//! let tip = ObjectId::parse("e83c5163316f89bfbde7d9ab23ca2e25604af290").unwrap();
//! let head = LsRef {
//!     id: Some(tip),
//!     name: "HEAD".to_string(),
//!     symref_target: Some("refs/heads/main".to_string()),
//!     peeled: None,
//! };
//! let mut reply = head.to_packet().unwrap().to_bytes().unwrap();
//! reply.extend(Packet::Flush.to_bytes().unwrap());
//! assert_eq!(&reply[..4], b"0050");
//! assert!(reply.ends_with(b" HEAD symref-target:refs/heads/main\n0000"));
//! ```

use super::codec::{Decode, Step, Wire};

/// The TCP port `git://` servers listen on.
pub const PORT: u16 = 9418;
/// The length of a pkt-line's header: four hex digits.
pub const HEADER_LEN: usize = 4;
/// The longest pkt-line, header included.
pub const MAX_PACKET: usize = 65520;
/// The most data one pkt-line can carry.
pub const MAX_DATA: usize = MAX_PACKET - HEADER_LEN;
/// The longest text line, not counting the line feed that ends it.
pub const MAX_LINE: usize = MAX_DATA - 1;
/// The longest name, path or value this module reads or writes.
pub const MAX_TEXT: usize = 4096;
/// The most capabilities, or extra request parameters, in one list.
pub const MAX_CAPABILITIES: usize = 256;
/// The most refs, shallow lines or command arguments in one message.
pub const MAX_ITEMS: usize = 65536;
/// The most packets one message may have before its flush packet.
pub const MAX_MESSAGE_PACKETS: usize = 2 * MAX_ITEMS + MAX_CAPABILITIES + 4;
/// The length of a SHA-1 object id in hex.
pub const SHA1_HEX_LEN: usize = 40;
/// The length of a SHA-256 object id in hex.
pub const SHA256_HEX_LEN: usize = 64;
/// The longest packet, header included, with the `side-band` capability.
pub const SIDE_BAND_PACKET: usize = 1000;
/// The longest packet, header included, with `side-band-64k`.
pub const SIDE_BAND_64K_PACKET: usize = MAX_PACKET;

/// One pkt-line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    /// `0000`: the end of a message.
    Flush,
    /// `0001`: splits a version 2 request or response into sections.
    Delim,
    /// `0002`: the end of a version 2 response over a stateless transport.
    ResponseEnd,
    /// Data. Text lines usually end with a line feed.
    Data(Vec<u8>),
}

/// Why bytes are not a pkt-line. The stream holds no more packets a
/// reader can find, and a real server closes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketError {
    /// The length was not four hex digits.
    Header,
    /// The length was `0003`, which no packet uses.
    Reserved,
    /// The length was above [`MAX_PACKET`].
    TooLong(usize),
    /// The value cannot be written without changing it.
    Unwritable,
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketError::Unwritable => f.write_str("value cannot be written without changing it"),
            PacketError::Header => write!(f, "pkt-line length is not four hex digits"),
            PacketError::Reserved => write!(f, "pkt-line length 0003 is reserved"),
            PacketError::TooLong(n) => write!(f, "pkt-line length {n} is above {MAX_PACKET}"),
        }
    }
}

impl std::error::Error for PacketError {}

/// Why an exact [`Wire`] parse did not read one complete packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketParseError {
    /// The pkt-line header is invalid.
    Frame(PacketError),
    /// The input ended before a complete packet, including empty input.
    Truncated,
    /// Bytes follow the first complete packet.
    Trailing,
}

impl core::fmt::Display for PacketParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Frame(e) => e.fmt(f),
            Self::Truncated => f.write_str("input ended before a complete Git packet"),
            Self::Trailing => f.write_str("bytes follow the Git packet"),
        }
    }
}

impl core::error::Error for PacketParseError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Frame(e) => Some(e),
            Self::Truncated | Self::Trailing => None,
        }
    }
}

impl Packet {
    /// A data packet holding the complete line and a line feed.
    /// Writing refuses a line longer than [`MAX_LINE`].
    pub fn text(line: &str) -> Packet {
        let mut data = line.as_bytes().to_vec();
        data.push(b'\n');
        Packet::Data(data)
    }

    /// The data, if this is a data packet.
    pub fn data(&self) -> Option<&[u8]> {
        match self {
            Packet::Data(d) => Some(d),
            _ => None,
        }
    }
}

impl Wire for Packet {
    type ParseError = PacketParseError;
    type WriteError = PacketError;

    /// Reads exactly one pkt-line. Hex digits may be upper or lower case.
    /// Refuses invalid lengths, incomplete input, and trailing bytes.
    fn parse(b: &[u8]) -> Result<Self, PacketParseError> {
        match Pkt::parse(b).map_err(PacketParseError::Frame)? {
            Some((packet, used)) if used == b.len() => Ok(packet.to_packet()),
            Some(_) => Err(PacketParseError::Trailing),
            None => Err(PacketParseError::Truncated),
        }
    }

    /// Appends one pkt-line. Refuses data above [`MAX_DATA`]. Leaves `out`
    /// unchanged on error. Control packets keep their wire form.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), PacketError> {
        if let Self::Data(data) = self
            && data.len() > MAX_DATA
        {
            return Err(PacketError::Unwritable);
        }
        match self {
            Packet::Flush => out.extend_from_slice(b"0000"),
            Packet::Delim => out.extend_from_slice(b"0001"),
            Packet::ResponseEnd => out.extend_from_slice(b"0002"),
            Packet::Data(data) => {
                out.extend_from_slice(format!("{:04x}", data.len() + HEADER_LEN).as_bytes());
                out.extend_from_slice(data);
            }
        }
        Ok(())
    }
}

/// Reads Git pkt-lines without holding input bytes.
///
/// Use with [`codec::Stream`](super::codec::Stream) for a buffer limited
/// to [`MAX_PACKET`]. Oversized packets are refused from the header.
/// Partial packets return [`Step::Need`], including at EOF, so the stream
/// reports truncation. Flush, delimiter, response-end, and empty data
/// packets are separate items. Control packets do not end the stream.
///
/// After the flush that ends a receive-pack command list, raw PACK bytes
/// may follow. Before reading another item, the world must hand off with
/// [`Stream::into_parts`](super::codec::Stream::into_parts), or
/// [`Stream::swap`](super::codec::Stream::swap) to a pack decoder. Both
/// preserve unread bytes; [`Frames`] cannot parse raw PACK data.
#[derive(Clone, Copy, Debug, Default)]
pub struct Frames;

impl Frames {
    /// Creates a frame decoder with no retained state.
    pub fn new() -> Self {
        Self
    }
}

impl Decode for Frames {
    type Item = Packet;
    type Error = PacketError;
    const NAME: &'static str = "Git pkt-line";

    fn capacity(&self) -> usize {
        MAX_PACKET
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Packet>, PacketError> {
        Ok(match Pkt::parse(input)? {
            Some((packet, used)) => Step::Item(packet.to_packet(), used),
            None => Step::Need,
        })
    }
}

/// A packet borrowed from the bytes it was read from, so that a message
/// can be checked without copying its data.
#[derive(Clone, Copy, Debug)]
enum Pkt<'a> {
    Flush,
    Delim,
    ResponseEnd,
    Data(&'a [u8]),
}

impl<'a> Pkt<'a> {
    fn of(p: &'a Packet) -> Pkt<'a> {
        match p {
            Packet::Flush => Pkt::Flush,
            Packet::Delim => Pkt::Delim,
            Packet::ResponseEnd => Pkt::ResponseEnd,
            Packet::Data(d) => Pkt::Data(d),
        }
    }

    fn to_packet(self) -> Packet {
        match self {
            Pkt::Flush => Packet::Flush,
            Pkt::Delim => Packet::Delim,
            Pkt::ResponseEnd => Packet::ResponseEnd,
            Pkt::Data(d) => Packet::Data(d.to_vec()),
        }
    }

    fn parse(b: &'a [u8]) -> Result<Option<(Pkt<'a>, usize)>, PacketError> {
        let mut len = 0usize;
        // A bad digit is known before the rest of the header comes.
        for &c in b.iter().take(HEADER_LEN) {
            len = len * 16 + usize::from(hex_digit(c).ok_or(PacketError::Header)?);
        }
        if b.len() < HEADER_LEN {
            return Ok(None);
        }
        let packet = match len {
            0 => Pkt::Flush,
            1 => Pkt::Delim,
            2 => Pkt::ResponseEnd,
            3 => return Err(PacketError::Reserved),
            n if n > MAX_PACKET => return Err(PacketError::TooLong(n)),
            n => match b.get(HEADER_LEN..n) {
                Some(data) => Pkt::Data(data),
                None => return Ok(None),
            },
        };
        Ok(Some((packet, len.max(HEADER_LEN))))
    }
}

/// Why packets are not the message a reader expected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The unit is incomplete.
    Truncated,
    /// Bytes remain after the unit.
    Trailing,
    /// The value cannot be written without changing it.
    Unwritable,
    /// The bytes were not pkt-lines.
    Packet(PacketError),
    /// A line was not UTF-8, or held a NUL or line feed where none may be.
    Text,
    /// An object id was not 40 or 64 hex digits, or in an advertisement
    /// not as long as its `object-format` capability says.
    ObjectId,
    /// The packets did not follow the grammar. The text says what was
    /// expected.
    Syntax(&'static str),
    /// A name, path or value was longer than [`MAX_TEXT`], or a line
    /// longer than [`MAX_LINE`].
    TooLong,
    /// A list passed its limit.
    TooMany,
    /// The other side sent an `ERR` line. This holds its message.
    Remote(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Truncated => f.write_str("incomplete Git protocol unit"),
            ParseError::Trailing => f.write_str("bytes after Git protocol unit"),
            ParseError::Unwritable => f.write_str("value cannot be written without changing it"),
            ParseError::Packet(e) => write!(f, "{e}"),
            ParseError::Text => write!(f, "a line is not UTF-8 text on one line"),
            ParseError::ObjectId => write!(f, "an object id is not 40 or 64 hex digits"),
            ParseError::Syntax(what) => write!(f, "expected {what}"),
            ParseError::TooLong => write!(f, "a field or line is too long"),
            ParseError::TooMany => write!(f, "a list is too long"),
            ParseError::Remote(m) => write!(f, "the other side reported an error: {m}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<PacketError> for ParseError {
    fn from(e: PacketError) -> ParseError {
        ParseError::Packet(e)
    }
}

/// An object id: 40 hex digits for SHA-1 or 64 for SHA-256, kept in lower
/// case. A value of this type always holds a valid one.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId(String);

impl ObjectId {
    /// Reads an object id. It returns `None` unless `s` is 40 or 64 hex
    /// digits. The protocol says both sides send lower case but must
    /// accept either, so upper-case digits are read and stored in lower
    /// case.
    pub fn parse(s: &str) -> Option<ObjectId> {
        let ok = (s.len() == SHA1_HEX_LEN || s.len() == SHA256_HEX_LEN) && s.bytes().all(|c| c.is_ascii_hexdigit());
        ok.then(|| ObjectId(s.to_ascii_lowercase()))
    }

    /// The all-zero id, SHA-256 long if `sha256` is set and SHA-1 long
    /// otherwise.
    pub fn zero(sha256: bool) -> ObjectId {
        ObjectId("0".repeat(if sha256 { SHA256_HEX_LEN } else { SHA1_HEX_LEN }))
    }

    /// Whether every digit is zero.
    pub fn is_zero(&self) -> bool {
        self.0.bytes().all(|c| c == b'0')
    }

    /// The hex digits.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A line this module does not know, kept as it came. `T` is the type
/// whose reader made it, such as [`ClientLine`]. Only that reader makes
/// one, and only that type's writer takes it, so writing it back reads
/// back the same. A line one reader did not know may mean something to
/// another, so it cannot move between them.
pub struct Unknown<T> {
    line: String,
    kind: std::marker::PhantomData<fn() -> T>,
}

impl<T> Unknown<T> {
    fn new(line: &str) -> Unknown<T> {
        Unknown { line: line.to_string(), kind: std::marker::PhantomData }
    }

    /// The line, without its line feed.
    pub fn as_str(&self) -> &str {
        &self.line
    }
}

impl<T> Clone for Unknown<T> {
    fn clone(&self) -> Unknown<T> {
        Unknown::new(&self.line)
    }
}

impl<T> std::fmt::Debug for Unknown<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Unknown").field(&self.line).finish()
    }
}

impl<T> PartialEq for Unknown<T> {
    fn eq(&self, other: &Unknown<T>) -> bool {
        self.line == other.line
    }
}

impl<T> Eq for Unknown<T> {}

impl<T> std::hash::Hash for Unknown<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.line.hash(state);
    }
}

/// One capability: a name and, for some, a value after `=`, such as
/// `agent=git/2.45.0` or `symref=HEAD:refs/heads/main`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    /// The name, such as `ofs-delta`.
    pub name: String,
    /// The text after `=`, if there was one.
    pub value: Option<String>,
}

impl Capability {
    /// A capability with no value.
    pub fn new(name: &str) -> Capability {
        Capability { name: name.to_string(), value: None }
    }

    /// A capability with a value.
    pub fn with_value(name: &str, value: &str) -> Capability {
        Capability { name: name.to_string(), value: Some(value.to_string()) }
    }

    fn parse(s: &str) -> Result<Capability, ParseError> {
        let (name, value) = match s.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (s, None),
        };
        if !is_key(name) {
            return Err(ParseError::Syntax("a capability name"));
        }
        Ok(Capability { name: field(name)?, value: value.map(field).transpose()? })
    }

    fn token(&self, v0: bool) -> Result<String, ParseError> {
        let name = checked_key(&self.name)?;
        Ok(match &self.value {
            Some(value) => format!("{name}={}", checked_text(value, if v0 { &[' '] } else { &[] }, MAX_TEXT)?),
            None => name.to_string(),
        })
    }
}

/// The first capability in `list` named `name`.
pub fn find_capability<'a>(list: &'a [Capability], name: &str) -> Option<&'a Capability> {
    list.iter().find(|c| c.name == name)
}

/// The service a client asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    /// `git-upload-pack`: fetch and clone.
    UploadPack,
    /// `git-receive-pack`: push.
    ReceivePack,
    /// `git-upload-archive`: `git archive --remote`.
    UploadArchive,
}

impl Service {
    /// The service's name on the wire.
    pub fn name(self) -> &'static str {
        match self {
            Service::UploadPack => "git-upload-pack",
            Service::ReceivePack => "git-receive-pack",
            Service::UploadArchive => "git-upload-archive",
        }
    }

    /// The service with this name.
    pub fn from_name(name: &str) -> Option<Service> {
        match name {
            "git-upload-pack" => Some(Service::UploadPack),
            "git-receive-pack" => Some(Service::ReceivePack),
            "git-upload-archive" => Some(Service::UploadArchive),
            _ => None,
        }
    }
}

/// The first packet a `git://` client sends: which service, which
/// repository, and on which host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtoRequest {
    /// The service asked for.
    pub service: Service,
    /// The repository's path, such as `/project.git`.
    pub path: String,
    /// The host the client connected to, with `:port` if it gave one.
    pub host: Option<String>,
    /// Extra parameters, such as `version=2`.
    pub extra: Vec<String>,
}

impl ProtoRequest {
    fn parse_prefix(b: &[u8]) -> Result<Option<(ProtoRequest, usize)>, ParseError> {
        match Pkt::parse(b)? {
            None => Ok(None),
            Some((Pkt::Data(d), used)) => Ok(Some((ProtoRequest::from_data(d)?, used))),
            Some(_) => Err(ParseError::Syntax("a request line")),
        }
    }

    /// Reads a request from a packet's data.
    pub fn from_data(d: &[u8]) -> Result<ProtoRequest, ParseError> {
        if d.len() > MAX_DATA { return Err(ParseError::TooLong); }
        let sp = d.iter().position(|&c| c == b' ').ok_or(ParseError::Syntax("a request line"))?;
        let service = Service::from_name(text(&d[..sp])?).ok_or(ParseError::Syntax("a service name"))?;
        let rest = &d[sp + 1..];
        let (path, mut rest) = until_nul(rest)?;
        let mut req = ProtoRequest { service, path: field(utf8(path)?)?, host: None, extra: Vec::new() };
        if let Some(h) = rest.strip_prefix(b"host=") {
            let (host, after) = until_nul(h)?;
            req.host = Some(field(utf8(host)?)?);
            rest = after;
        }
        if let Some((&first, mut params)) = rest.split_first() {
            if first != 0 {
                return Err(ParseError::Syntax("a NUL before extra parameters"));
            }
            // After that NUL comes at least one parameter, and none is empty.
            if params.is_empty() {
                return Err(ParseError::Syntax("an extra parameter"));
            }
            while !params.is_empty() {
                let (p, after) = until_nul(params)?;
                if p.is_empty() {
                    return Err(ParseError::Syntax("an extra parameter"));
                }
                if req.extra.len() >= MAX_CAPABILITIES {
                    return Err(ParseError::TooMany);
                }
                req.extra.push(field(utf8(p)?)?);
                params = after;
            }
        }
        Ok(req)
    }

    /// The protocol version the client asks for with `version=N`, if any.
    /// As in Git's server, only `0`, `1` and `2` count, written just so,
    /// and if the client sent more than one of them the highest counts.
    pub fn version(&self) -> Option<u32> {
        let v = |p: &String| match p.strip_prefix("version=")? {
            "0" => Some(0),
            "1" => Some(1),
            "2" => Some(2),
            _ => None,
        };
        self.extra.iter().filter_map(v).max()
    }

    /// Builds the complete request packet. Refuses NULs, empty extra
    /// parameters, and fields or lists beyond their limits.
    pub fn to_packet(&self) -> Result<Packet, ParseError> {
        if self.extra.len() > MAX_CAPABILITIES { return Err(ParseError::Unwritable); }
        let mut text = format!("{} {}\0", self.service.name(), checked_nul(&self.path)?);
        if let Some(host) = &self.host {
            text.push_str("host=");
            text.push_str(checked_nul(host)?);
            text.push('\0');
        }
        if !self.extra.is_empty() { text.push('\0'); }
        for parameter in &self.extra {
            let parameter = checked_nul(parameter)?;
            if parameter.is_empty() || text.len().saturating_add(parameter.len()).saturating_add(1) > MAX_DATA {
                return Err(ParseError::Unwritable);
            }
            text.push_str(parameter);
            text.push('\0');
        }
        if text.len() > MAX_DATA { return Err(ParseError::Unwritable); }
        Ok(Packet::Data(text.into_bytes()))
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), ParseError> {
        self.to_packet()?.write(out).map_err(|_| ParseError::Unwritable)
    }
}

/// A smart HTTP service announcement followed by a flush packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceHeader(
    /// The service announced by the HTTP response.
    pub Service,
);

impl ServiceHeader {
    fn parse_prefix(bytes: &[u8]) -> Result<Option<(Self, usize)>, ParseError> {
        let Some((packets, used)) = until_flush(bytes, true)? else { return Ok(None) };
        let [packet] = packets.as_slice() else { return Err(ParseError::Syntax("one service line")) };
        let text = line(data_of(packet)?)?;
        let name = text.strip_prefix("# service=").ok_or(ParseError::Syntax("# service="))?;
        let service = Service::from_name(name).ok_or(ParseError::Syntax("a service name"))?;
        Ok(Some((Self(service), used)))
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), ParseError> {
        Packet::text(&format!("# service={}", self.0.name())).write(out)?;
        Packet::Flush.write(out)?;
        Ok(())
    }
}

/// One ref in a version 0 or 1 advertisement. A name ending in `^{}`
/// gives the object an annotated tag points at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvertisedRef {
    /// The object the ref points at.
    pub id: ObjectId,
    /// The ref's name, such as `refs/heads/main`.
    pub name: String,
}

/// What a version 0 or 1 server sends first: its refs, its capabilities,
/// and the commits where a shallow repository stops.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Advertisement {
    /// Whether it starts with `version 1`.
    pub version_1: bool,
    /// The refs, in order.
    pub refs: Vec<AdvertisedRef>,
    /// The capabilities, sent after the first ref.
    pub capabilities: Vec<Capability>,
    /// The `shallow` lines.
    pub shallow: Vec<ObjectId>,
}

impl Advertisement {
    fn parse_prefix(b: &[u8]) -> Result<Option<(Advertisement, usize)>, ParseError> {
        let Some((packets, used)) = until_flush(b, true)? else { return Ok(None) };
        Ok(Some((Advertisement::read(&packets)?, used)))
    }

    /// Reads an advertisement from its packets, not counting the flush.
    /// Every object id must be as long as the `object-format` capability
    /// says: 40 hex digits without one or with `sha1`, and 64 with
    /// `sha256`.
    pub fn from_packets(packets: &[Packet]) -> Result<Advertisement, ParseError> {
        if packets.len() > MAX_MESSAGE_PACKETS { return Err(ParseError::TooMany); }
        Advertisement::read(&packets.iter().map(Pkt::of).collect::<Vec<_>>())
    }

    fn read(packets: &[Pkt<'_>]) -> Result<Advertisement, ParseError> {
        any_remote(packets)?;
        let mut ad = Advertisement::default();
        let mut rest = packets;
        if let Some((p, more)) = rest.split_first()
            && strip_lf(data_of(p)?) == b"version 1"
        {
            ad.version_1 = true;
            rest = more;
        }
        let mut no_refs = false;
        if let Some((p, more)) = rest.split_first() {
            let d = strip_lf(data_of(p)?);
            // A writer adds a line feed, so the whole line must leave room.
            if d.len() > MAX_LINE {
                return Err(ParseError::TooLong);
            }
            let (head, caps) = match d.iter().position(|&c| c == 0) {
                Some(n) => (&d[..n], Some(&d[n + 1..])),
                None => (d, None),
            };
            let head = text(head)?;
            if let Some(c) = caps {
                ad.capabilities = parse_caps(text(c)?)?;
            }
            let r = ref_line(head)?;
            // Git takes this line to mean "no refs" only with a zero id.
            // With any other id it is an ordinary ref.
            if r.name == "capabilities^{}" && r.id.is_zero() {
                no_refs = true;
            } else {
                ad.refs.push(r);
            }
            rest = more;
        }
        for p in rest {
            let s = line(data_of(p)?)?;
            if let Some(id) = s.strip_prefix("shallow ") {
                if ad.shallow.len() >= MAX_ITEMS {
                    return Err(ParseError::TooMany);
                }
                ad.shallow.push(oid(id)?);
            } else if no_refs || !ad.shallow.is_empty() {
                return Err(ParseError::Syntax("a shallow line"));
            } else {
                if ad.refs.len() >= MAX_ITEMS {
                    return Err(ParseError::TooMany);
                }
                ad.refs.push(ref_line(s)?);
            }
        }
        if let Some(n) = id_len(&ad.capabilities)
            && ad.refs.iter().map(|r| &r.id).chain(&ad.shallow).any(|id| id.as_str().len() != n)
        {
            return Err(ParseError::ObjectId);
        }
        Ok(ad)
    }

    /// The first capability named `name`.
    pub fn capability(&self, name: &str) -> Option<&Capability> {
        find_capability(&self.capabilities, name)
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), ParseError> {
        if self.refs.len() > MAX_ITEMS || self.shallow.len() > MAX_ITEMS { return Err(ParseError::Unwritable); }
        let length = id_len(&self.capabilities);
        let fits = |id: &ObjectId| length.is_none_or(|n| id.as_str().len() == n);
        if self.refs.iter().any(|r| !fits(&r.id)) || self.shallow.iter().any(|id| !fits(id))
            || self.refs.first().is_some_and(|r| r.id.is_zero() && r.name == "capabilities^{}") {
            return Err(ParseError::Unwritable);
        }
        if self.version_1 { Packet::text("version 1").write(out)?; }
        let mut first = match self.refs.first() {
            Some(reference) => format!("{} {}\0", reference.id, checked_text(&reference.name, &[], MAX_TEXT)?),
            None => format!("{} capabilities^{{}}\0", ObjectId::zero(length == Some(SHA256_HEX_LEN))),
        };
        push_caps(&mut first, &self.capabilities, "")?;
        Packet::text(&first).write(out)?;
        for reference in self.refs.iter().skip(1) {
            Packet::text(&format!("{} {}", reference.id, checked_text(&reference.name, &[], MAX_TEXT)?)).write(out)?;
        }
        for id in &self.shallow { Packet::text(&format!("shallow {id}")).write(out)?; }
        Packet::Flush.write(out)?;
        Ok(())
    }
}

/// What a version 2 server sends first: `version 2` and one capability
/// per line, such as `ls-refs` or `fetch=shallow`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilityAdvertisement {
    /// The capabilities, in order.
    pub capabilities: Vec<Capability>,
}

impl CapabilityAdvertisement {
    fn parse_prefix(b: &[u8]) -> Result<Option<(CapabilityAdvertisement, usize)>, ParseError> {
        let Some((packets, used)) = until_flush(b, true)? else { return Ok(None) };
        Ok(Some((CapabilityAdvertisement::read(&packets)?, used)))
    }

    /// Reads an advertisement from its packets, not counting the flush.
    pub fn from_packets(packets: &[Packet]) -> Result<CapabilityAdvertisement, ParseError> {
        if packets.len() > MAX_MESSAGE_PACKETS { return Err(ParseError::TooMany); }
        CapabilityAdvertisement::read(&packets.iter().map(Pkt::of).collect::<Vec<_>>())
    }

    fn read(packets: &[Pkt<'_>]) -> Result<CapabilityAdvertisement, ParseError> {
        any_remote(packets)?;
        let Some((first, rest)) = packets.split_first() else { return Err(ParseError::Syntax("version 2")) };
        let s = line(data_of(first)?)?;
        if s != "version 2" {
            return Err(ParseError::Syntax("version 2"));
        }
        if rest.len() > MAX_CAPABILITIES {
            return Err(ParseError::TooMany);
        }
        let capabilities = rest.iter().map(|p| Capability::parse(line(data_of(p)?)?)).collect::<Result<_, _>>()?;
        Ok(CapabilityAdvertisement { capabilities })
    }

    /// The first capability named `name`.
    pub fn capability(&self, name: &str) -> Option<&Capability> {
        find_capability(&self.capabilities, name)
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), ParseError> {
        Packet::text("version 2").write(out)?;
        write_caps_v2(out, &self.capabilities)?;
        Packet::Flush.write(out)?;
        Ok(())
    }
}

/// A version 2 command: its name, the capabilities the client uses with
/// it, and its arguments, one per line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    /// The command, such as `ls-refs` or `fetch`.
    pub name: String,
    /// Capabilities sent with the command, such as `agent=git/2.45.0`.
    pub capabilities: Vec<Capability>,
    /// The arguments, each without its line feed.
    pub args: Vec<String>,
}

impl Command {
    /// The arguments read as `ls-refs` arguments. More than
    /// [`MAX_ITEMS`] is an error, as in a request read from bytes.
    pub fn ls_refs_args(&self) -> Result<Vec<LsRefsArg>, ParseError> {
        if self.args.len() > MAX_ITEMS {
            return Err(ParseError::TooMany);
        }
        self.args.iter().map(|a| LsRefsArg::parse_line(checked_line(a)?)).collect()
    }

    /// The arguments read as `fetch` arguments. More than [`MAX_ITEMS`]
    /// is an error, as in a request read from bytes. So is `deepen` with
    /// `deepen-since` or `deepen-not`, which gitprotocol-v2 says cannot be
    /// used together.
    pub fn fetch_args(&self) -> Result<Vec<ClientLine>, ParseError> {
        if self.args.len() > MAX_ITEMS {
            return Err(ParseError::TooMany);
        }
        let args = self.args.iter().map(|a| ClientLine::parse_line(checked_line(a)?)).collect::<Result<Vec<_>, _>>()?;
        let deepen = args.iter().any(|a| matches!(a, ClientLine::Deepen(_)));
        if deepen && args.iter().any(|a| matches!(a, ClientLine::DeepenSince(_) | ClientLine::DeepenNot(_))) {
            return Err(ParseError::Syntax("deepen without deepen-since or deepen-not"));
        }
        Ok(args)
    }
}

/// One version 2 request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum V2Request {
    /// A lone flush packet: the client is done.
    Empty,
    /// A command.
    Command(Command),
}

impl V2Request {
    fn parse_prefix(b: &[u8]) -> Result<Option<(V2Request, usize)>, ParseError> {
        let Some((packets, used)) = until_flush(b, false)? else { return Ok(None) };
        Ok(Some((V2Request::read(&packets)?, used)))
    }

    /// Reads a request from its packets, not counting the flush. The
    /// delimiter packet before the arguments may be left out when there
    /// are none.
    pub fn from_packets(packets: &[Packet]) -> Result<V2Request, ParseError> {
        if packets.len() > MAX_MESSAGE_PACKETS { return Err(ParseError::TooMany); }
        V2Request::read(&packets.iter().map(Pkt::of).collect::<Vec<_>>())
    }

    fn read(packets: &[Pkt<'_>]) -> Result<V2Request, ParseError> {
        let Some((first, rest)) = packets.split_first() else { return Ok(V2Request::Empty) };
        let s = line(data_of(first)?)?;
        let name = s.strip_prefix("command=").ok_or(ParseError::Syntax("command="))?;
        if !is_key(name) {
            return Err(ParseError::Syntax("a command name"));
        }
        let mut cmd = Command { name: field(name)?, capabilities: Vec::new(), args: Vec::new() };
        let mut in_args = false;
        for p in rest {
            match p {
                Pkt::Delim if !in_args => in_args = true,
                Pkt::Data(d) => {
                    let s = line(d)?;
                    if in_args {
                        if cmd.args.len() >= MAX_ITEMS {
                            return Err(ParseError::TooMany);
                        }
                        cmd.args.push(s.to_string());
                    } else {
                        if cmd.capabilities.len() >= MAX_CAPABILITIES {
                            return Err(ParseError::TooMany);
                        }
                        cmd.capabilities.push(Capability::parse(s)?);
                    }
                }
                _ => return Err(ParseError::Syntax("a data packet")),
            }
        }
        Ok(V2Request::Command(cmd))
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), ParseError> {
        if let Self::Command(command) = self {
            if command.args.len() > MAX_ITEMS { return Err(ParseError::Unwritable); }
            let name = checked_key(&command.name)?;
            Packet::text(&format!("command={name}")).write(out)?;
            write_caps_v2(out, &command.capabilities)?;
            Packet::Delim.write(out)?;
            for argument in &command.args {
                Packet::text(checked_text(argument, &[], MAX_LINE)?).write(out)?;
            }
        }
        Packet::Flush.write(out)?;
        Ok(())
    }
}

/// One `ls-refs` argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LsRefsArg {
    /// `symrefs`: say where symbolic refs point.
    Symrefs,
    /// `peel`: say what annotated tags point at.
    Peel,
    /// `ref-prefix <prefix>`: only refs whose names start with this.
    RefPrefix(String),
    /// `unborn`: list HEAD even when its branch has no commits.
    Unborn,
    /// Any other argument.
    Other(Unknown<LsRefsArg>),
}

impl LsRefsArg {
    fn read(data: &[u8]) -> Result<Self, ParseError> {
        Self::parse_line(line(data)?)
    }

    fn parse_line(s: &str) -> Result<LsRefsArg, ParseError> {
        Ok(match s {
            "symrefs" => LsRefsArg::Symrefs,
            "peel" => LsRefsArg::Peel,
            "unborn" => LsRefsArg::Unborn,
            _ => match s.strip_prefix("ref-prefix ") {
                Some(p) => LsRefsArg::RefPrefix(field(p)?),
                None => LsRefsArg::Other(Unknown::new(s)),
            },
        })
    }

    fn encode_line(&self) -> Result<String, ParseError> {
        Ok(match self {
            LsRefsArg::Symrefs => "symrefs".to_string(),
            LsRefsArg::Peel => "peel".to_string(),
            LsRefsArg::Unborn => "unborn".to_string(),
            LsRefsArg::RefPrefix(p) => format!("ref-prefix {}", checked_text(p, &[], MAX_TEXT)?),
            LsRefsArg::Other(u) => u.line.clone(),
        })
    }
}

/// One line of `ls-refs` output, or of a `wanted-refs` section:
/// `<id> <name>`, then optional attributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LsRef {
    /// The object the ref points at, or `None` for `unborn`: HEAD names a
    /// branch with no commits yet.
    pub id: Option<ObjectId>,
    /// The ref's name.
    pub name: String,
    /// Where a symbolic ref points, sent for `symrefs`.
    pub symref_target: Option<String>,
    /// What an annotated tag points at, sent for `peel`.
    pub peeled: Option<ObjectId>,
}

impl LsRef {
    fn read(data: &[u8]) -> Result<LsRef, ParseError> {
        let s = line(data)?;
        let mut parts = s.split(' ');
        let first = parts.next().unwrap_or("");
        let name = parts.next().ok_or(ParseError::Syntax("a ref line"))?;
        let id = if first == "unborn" { None } else { Some(oid(first)?) };
        let mut r = LsRef { id, name: field(name)?, symref_target: None, peeled: None };
        for a in parts {
            if let Some(t) = a.strip_prefix("symref-target:") {
                r.symref_target = Some(field(t)?);
            } else if let Some(p) = a.strip_prefix("peeled:") {
                r.peeled = Some(oid(p)?);
            }
        }
        Ok(r)
    }

    fn encode_line(&self) -> Result<String, ParseError> {
        let mut s = match &self.id {
            Some(id) => format!("{id} "),
            None => "unborn ".to_string(),
        };
        s.push_str(checked_text(&self.name, &[' '], MAX_TEXT)?);
        if let Some(t) = &self.symref_target {
            s.push_str(" symref-target:");
            s.push_str(checked_text(t, &[' '], MAX_TEXT)?);
        }
        if let Some(p) = &self.peeled {
            s.push_str(" peeled:");
            s.push_str(p.as_str());
        }
        Ok(s)
    }

}

/// One line a client sends while fetching: a version 0 upload request or
/// negotiation line, or a version 2 `fetch` argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientLine {
    /// `want <id>`. In version 0 the first one carries the capabilities
    /// the client chose.
    Want {
        /// The object wanted.
        id: ObjectId,
        /// The capabilities, empty after the first `want`.
        capabilities: Vec<Capability>,
    },
    /// `want-ref <ref>` (version 2).
    WantRef(String),
    /// `have <id>`: the client has this object.
    Have(ObjectId),
    /// `done`: the client is ready for the pack.
    Done,
    /// `shallow <id>`: the client's history stops at this commit.
    Shallow(ObjectId),
    /// `deepen <depth>`.
    Deepen(u32),
    /// `deepen-since <timestamp>`.
    DeepenSince(u64),
    /// `deepen-not <ref>`.
    DeepenNot(String),
    /// `deepen-relative` (version 2).
    DeepenRelative,
    /// `filter <filter-spec>`, such as `blob:none`.
    Filter(String),
    /// `thin-pack` (version 2).
    ThinPack,
    /// `no-progress` (version 2).
    NoProgress,
    /// `include-tag` (version 2).
    IncludeTag,
    /// `ofs-delta` (version 2).
    OfsDelta,
    /// `sideband-all` (version 2).
    SidebandAll,
    /// `wait-for-done` (version 2).
    WaitForDone,
    /// `packfile-uris <protocols>` (version 2).
    PackfileUris(String),
    /// Any other line.
    Other(Unknown<ClientLine>),
}

impl ClientLine {
    fn read(data: &[u8]) -> Result<ClientLine, ParseError> {
        ClientLine::parse_line(line(data)?)
    }

    fn parse_line(s: &str) -> Result<ClientLine, ParseError> {
        Ok(match s {
            "done" => ClientLine::Done,
            "deepen-relative" => ClientLine::DeepenRelative,
            "thin-pack" => ClientLine::ThinPack,
            "no-progress" => ClientLine::NoProgress,
            "include-tag" => ClientLine::IncludeTag,
            "ofs-delta" => ClientLine::OfsDelta,
            "sideband-all" => ClientLine::SidebandAll,
            "wait-for-done" => ClientLine::WaitForDone,
            _ => {
                if let Some(rest) = s.strip_prefix("want ") {
                    let (id, caps) = rest.split_once(' ').unwrap_or((rest, ""));
                    ClientLine::Want { id: oid(id)?, capabilities: parse_caps(caps)? }
                } else if let Some(r) = s.strip_prefix("want-ref ") {
                    ClientLine::WantRef(field(r)?)
                } else if let Some(id) = s.strip_prefix("have ") {
                    ClientLine::Have(oid(id)?)
                } else if let Some(id) = s.strip_prefix("shallow ") {
                    ClientLine::Shallow(oid(id)?)
                } else if let Some(n) = s.strip_prefix("deepen ") {
                    ClientLine::Deepen(number(n)?)
                } else if let Some(t) = s.strip_prefix("deepen-since ") {
                    ClientLine::DeepenSince(number(t)?)
                } else if let Some(r) = s.strip_prefix("deepen-not ") {
                    ClientLine::DeepenNot(field(r)?)
                } else if let Some(f) = s.strip_prefix("filter ") {
                    ClientLine::Filter(field(f)?)
                } else if let Some(p) = s.strip_prefix("packfile-uris ") {
                    ClientLine::PackfileUris(field(p)?)
                } else {
                    ClientLine::Other(Unknown::new(s))
                }
            }
        })
    }

    fn encode_line(&self) -> Result<String, ParseError> {
        Ok(match self {
            ClientLine::Want { id, capabilities } => {
                let mut s = format!("want {id}");
                push_caps(&mut s, capabilities, " ")?;
                s
            }
            ClientLine::WantRef(r) => format!("want-ref {}", checked_text(r, &[], MAX_TEXT)?),
            ClientLine::Have(id) => format!("have {id}"),
            ClientLine::Done => "done".to_string(),
            ClientLine::Shallow(id) => format!("shallow {id}"),
            ClientLine::Deepen(n) => format!("deepen {n}"),
            ClientLine::DeepenSince(t) => format!("deepen-since {t}"),
            ClientLine::DeepenNot(r) => format!("deepen-not {}", checked_text(r, &[], MAX_TEXT)?),
            ClientLine::DeepenRelative => "deepen-relative".to_string(),
            ClientLine::Filter(f) => format!("filter {}", checked_text(f, &[], MAX_TEXT)?),
            ClientLine::ThinPack => "thin-pack".to_string(),
            ClientLine::NoProgress => "no-progress".to_string(),
            ClientLine::IncludeTag => "include-tag".to_string(),
            ClientLine::OfsDelta => "ofs-delta".to_string(),
            ClientLine::SidebandAll => "sideband-all".to_string(),
            ClientLine::WaitForDone => "wait-for-done".to_string(),
            ClientLine::PackfileUris(p) => format!("packfile-uris {}", checked_text(p, &[], MAX_TEXT)?),
            ClientLine::Other(u) => u.line.clone(),
        })
    }

}

/// What an `ACK` adds after the object id in version 0 multi-ack modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckStatus {
    /// `continue` (`multi_ack`).
    Continue,
    /// `common` (`multi_ack_detailed`).
    Common,
    /// `ready` (`multi_ack_detailed`).
    Ready,
}

impl AckStatus {
    fn name(self) -> &'static str {
        match self {
            AckStatus::Continue => "continue",
            AckStatus::Common => "common",
            AckStatus::Ready => "ready",
        }
    }
}

/// A section header in a version 2 `fetch` response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    /// `acknowledgments`.
    Acknowledgments,
    /// `shallow-info`.
    ShallowInfo,
    /// `wanted-refs`.
    WantedRefs,
    /// `packfile-uris`.
    PackfileUris,
    /// `packfile`: side-band packets follow.
    Packfile,
}

impl Section {
    /// The header's text.
    pub fn name(self) -> &'static str {
        match self {
            Section::Acknowledgments => "acknowledgments",
            Section::ShallowInfo => "shallow-info",
            Section::WantedRefs => "wanted-refs",
            Section::PackfileUris => "packfile-uris",
            Section::Packfile => "packfile",
        }
    }

    fn from_name(s: &str) -> Option<Section> {
        [Section::Acknowledgments, Section::ShallowInfo, Section::WantedRefs, Section::PackfileUris, Section::Packfile]
            .into_iter()
            .find(|x| x.name() == s)
    }
}

/// One line a server sends while a client fetches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerLine {
    /// `NAK`: no object in common yet.
    Nak,
    /// `ACK <id>`, with a status in version 0 multi-ack modes.
    Ack {
        /// An object both sides have.
        id: ObjectId,
        /// The status, if any.
        status: Option<AckStatus>,
    },
    /// `ready` (version 2): the server can send a pack.
    Ready,
    /// `shallow <id>`: the client's history will stop at this commit.
    Shallow(ObjectId),
    /// `unshallow <id>`: this commit's parents will be sent.
    Unshallow(ObjectId),
    /// A version 2 section header.
    Section(Section),
    /// `ERR <message>`: the server gives up.
    Error(String),
    /// Any other line, such as a `wanted-refs` or `packfile-uris` entry.
    Other(Unknown<ServerLine>),
}

impl ServerLine {
    fn read(data: &[u8]) -> Result<ServerLine, ParseError> {
        let s = line(data)?;
        if let Some(section) = Section::from_name(s) {
            return Ok(ServerLine::Section(section));
        }
        Ok(match s {
            "NAK" => ServerLine::Nak,
            "ready" => ServerLine::Ready,
            _ => {
                if let Some(rest) = s.strip_prefix("ACK ") {
                    let (id, status) = match rest.split_once(' ') {
                        None => (rest, None),
                        Some((id, "continue")) => (id, Some(AckStatus::Continue)),
                        Some((id, "common")) => (id, Some(AckStatus::Common)),
                        Some((id, "ready")) => (id, Some(AckStatus::Ready)),
                        Some(_) => return Err(ParseError::Syntax("an ACK status")),
                    };
                    ServerLine::Ack { id: oid(id)?, status }
                } else if let Some(id) = s.strip_prefix("shallow ") {
                    ServerLine::Shallow(oid(id)?)
                } else if let Some(id) = s.strip_prefix("unshallow ") {
                    ServerLine::Unshallow(oid(id)?)
                } else if let Some(m) = s.strip_prefix("ERR ") {
                    ServerLine::Error(field(m)?)
                } else {
                    ServerLine::Other(Unknown::new(s))
                }
            }
        })
    }

    fn encode_line(&self) -> Result<String, ParseError> {
        Ok(match self {
            ServerLine::Nak => "NAK".to_string(),
            ServerLine::Ack { id, status: None } => format!("ACK {id}"),
            ServerLine::Ack { id, status: Some(s) } => format!("ACK {id} {}", s.name()),
            ServerLine::Ready => "ready".to_string(),
            ServerLine::Shallow(id) => format!("shallow {id}"),
            ServerLine::Unshallow(id) => format!("unshallow {id}"),
            ServerLine::Section(s) => s.name().to_string(),
            ServerLine::Error(m) => format!("ERR {}", checked_text(m, &[], MAX_TEXT)?),
            ServerLine::Other(u) => u.line.clone(),
        })
    }

}

/// A side-band stream: the first byte of each data packet says which.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Band {
    /// 1: packfile bytes.
    Pack,
    /// 2: progress text for the user's terminal.
    Progress,
    /// 3: an error message; the transfer has failed.
    Error,
}

impl Band {
    /// The band's number on the wire.
    pub fn code(self) -> u8 {
        match self {
            Band::Pack => 1,
            Band::Progress => 2,
            Band::Error => 3,
        }
    }

    /// The band with this number.
    pub fn from_code(c: u8) -> Option<Band> {
        match c {
            1 => Some(Band::Pack),
            2 => Some(Band::Progress),
            3 => Some(Band::Error),
            _ => None,
        }
    }
}

/// Splits a side-band data packet into its band and payload.
pub fn split_band(data: &[u8]) -> Result<(Band, &[u8]), ParseError> {
    let (&c, rest) = data.split_first().ok_or(ParseError::Syntax("a band byte"))?;
    Ok((Band::from_code(c).ok_or(ParseError::Syntax("band 1, 2 or 3"))?, rest))
}

/// `payload` as side-band packets on `band`, each at most `packet_max`
/// bytes long, header included: [`SIDE_BAND_PACKET`] for `side-band` and
/// [`SIDE_BAND_64K_PACKET`] for `side-band-64k`. A value out of that
/// range is brought into it, so the packets add at most one byte in 199
/// to the payload. An empty payload gives no packets.
pub fn band_packets(band: Band, payload: &[u8], packet_max: usize) -> impl Iterator<Item = Packet> + '_ {
    let chunk = packet_max.clamp(SIDE_BAND_PACKET, SIDE_BAND_64K_PACKET) - HEADER_LEN - 1;
    payload.chunks(chunk).map(move |piece| {
        let mut data = Vec::with_capacity(piece.len() + 1);
        data.push(band.code());
        data.extend_from_slice(piece);
        Packet::Data(data)
    })
}

/// A side-band payload or control packet returned by [`Bands`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Demuxed {
    /// A data packet's payload and its band.
    Data(Band, Vec<u8>),
    /// A flush packet: the end of the pack.
    Flush,
    /// A delimiter packet.
    Delim,
    /// A response-end packet.
    ResponseEnd,
}

/// Reads side-band packets without holding input bytes. Switch a packet
/// stream with `stream.swap(Bands)` after the packfile section begins.
#[derive(Clone, Copy, Debug, Default)]
pub struct Bands;

impl Decode for Bands {
    type Item = Demuxed;
    type Error = ParseError;
    const NAME: &'static str = "Git side-band";

    fn capacity(&self) -> usize { MAX_PACKET }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Demuxed>, ParseError> {
        let Some((packet, used)) = Pkt::parse(input)? else { return Ok(Step::Need) };
        let item = match packet {
            Pkt::Flush => Demuxed::Flush,
            Pkt::Delim => Demuxed::Delim,
            Pkt::ResponseEnd => Demuxed::ResponseEnd,
            Pkt::Data(data) => {
                let (band, payload) = split_band(data)?;
                Demuxed::Data(band, payload.to_vec())
            }
        };
        Ok(Step::Item(item, used))
    }
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// The packets before the first flush, borrowed from `b`, and how many
/// bytes up to and including it. In a message from a server, `errors`,
/// an `ERR` line ends the message at once, as gitprotocol-pack says.
fn until_flush(b: &[u8], errors: bool) -> Result<Option<(Vec<Pkt<'_>>, usize)>, ParseError> {
    let mut at = 0;
    let mut packets = Vec::new();
    loop {
        match Pkt::parse(&b[at..])? {
            None => return Ok(None),
            Some((Pkt::Flush, used)) => return Ok(Some((packets, at + used))),
            Some((p, used)) => {
                if let Pkt::Data(d) = p
                    && errors
                {
                    remote(d)?;
                }
                if packets.len() >= MAX_MESSAGE_PACKETS {
                    return Err(ParseError::TooMany);
                }
                packets.push(p);
                at += used;
            }
        }
    }
}

fn data_of<'a>(p: &Pkt<'a>) -> Result<&'a [u8], ParseError> {
    match *p {
        Pkt::Data(d) => Ok(d),
        _ => Err(ParseError::Syntax("a data packet")),
    }
}

/// The first `ERR` line among `packets`, as an error.
fn any_remote(packets: &[Pkt<'_>]) -> Result<(), ParseError> {
    packets.iter().try_for_each(|p| if let Pkt::Data(d) = p { remote(d) } else { Ok(()) })
}

/// How long an advertisement's ids are, by its `object-format`
/// capability, or `None` for a format this module does not know.
fn id_len(caps: &[Capability]) -> Option<usize> {
    match find_capability(caps, "object-format") {
        None => Some(SHA1_HEX_LEN),
        Some(c) => match c.value.as_deref() {
            Some("sha1") => Some(SHA1_HEX_LEN),
            Some("sha256") => Some(SHA256_HEX_LEN),
            _ => None,
        },
    }
}

fn strip_lf(b: &[u8]) -> &[u8] {
    b.strip_suffix(b"\n").unwrap_or(b)
}

fn text(b: &[u8]) -> Result<&str, ParseError> {
    checked_line(utf8(b)?)
}

fn utf8(b: &[u8]) -> Result<&str, ParseError> {
    std::str::from_utf8(b).map_err(|_| ParseError::Text)
}

/// `s`, if it can be one line.
fn checked_line(s: &str) -> Result<&str, ParseError> {
    if s.contains(['\0', '\n']) {
        return Err(ParseError::Text);
    }
    if s.len() > MAX_LINE {
        return Err(ParseError::TooLong);
    }
    Ok(s)
}

/// A packet's data as one line of text, with one line feed taken off the
/// end.
fn line(data: &[u8]) -> Result<&str, ParseError> {
    text(strip_lf(data))
}

fn field(s: &str) -> Result<String, ParseError> {
    if s.len() > MAX_TEXT {
        return Err(ParseError::TooLong);
    }
    Ok(s.to_string())
}

fn oid(s: &str) -> Result<ObjectId, ParseError> {
    ObjectId::parse(s).ok_or(ParseError::ObjectId)
}

fn number<T: std::str::FromStr>(s: &str) -> Result<T, ParseError> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return Err(ParseError::Syntax("a number"));
    }
    s.parse().map_err(|_| ParseError::Syntax("a number"))
}

/// A packet's data as an error, if it is an `ERR` line. The message
/// need not be UTF-8 text: the other side has given up either way.
fn remote(d: &[u8]) -> Result<(), ParseError> {
    match strip_lf(d).strip_prefix(b"ERR ") {
        Some(m) => Err(ParseError::Remote(clipped_text(&String::from_utf8_lossy(&m[..m.len().min(MAX_TEXT + 3)]), MAX_TEXT).to_string())),
        None => Ok(()),
    }
}

/// The bytes before the next NUL, and those after it.
fn until_nul(b: &[u8]) -> Result<(&[u8], &[u8]), ParseError> {
    let n = b.iter().position(|&c| c == 0).ok_or(ParseError::Syntax("a NUL"))?;
    Ok((&b[..n], &b[n + 1..]))
}

/// `<id> <name>`, as in a version 0 advertisement.
fn ref_line(s: &str) -> Result<AdvertisedRef, ParseError> {
    let (id, name) = s.split_once(' ').ok_or(ParseError::Syntax("a ref line"))?;
    Ok(AdvertisedRef { id: oid(id)?, name: field(name)? })
}

/// A version 0 capability list: names split at spaces.
fn parse_caps(s: &str) -> Result<Vec<Capability>, ParseError> {
    let mut caps = Vec::new();
    for t in s.split(' ').filter(|t| !t.is_empty()) {
        if caps.len() >= MAX_CAPABILITIES {
            return Err(ParseError::TooMany);
        }
        caps.push(Capability::parse(t)?);
    }
    Ok(caps)
}

fn push_caps(out: &mut String, caps: &[Capability], first_sep: &str) -> Result<(), ParseError> {
    if caps.len() > MAX_CAPABILITIES { return Err(ParseError::Unwritable); }
    for (index, capability) in caps.iter().enumerate() {
        let token = capability.token(true)?;
        let separator = if index == 0 { first_sep } else { " " };
        if out.len().saturating_add(separator.len()).saturating_add(token.len()) > MAX_LINE {
            return Err(ParseError::Unwritable);
        }
        out.push_str(separator);
        out.push_str(&token);
    }
    Ok(())
}

fn write_caps_v2(out: &mut Vec<u8>, caps: &[Capability]) -> Result<(), ParseError> {
    if caps.len() > MAX_CAPABILITIES { return Err(ParseError::Unwritable); }
    for capability in caps { Packet::text(&capability.token(false)?).write(out)?; }
    Ok(())
}

/// Whether `s` is a key: a capability or command name, made of one or
/// more ASCII letters, digits, `-` and `_`.
fn is_key(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(is_key_byte)
}

fn is_key_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
}

fn checked_key(text: &str) -> Result<&str, ParseError> {
    if text.len() > MAX_TEXT || !is_key(text) { return Err(ParseError::Unwritable); }
    Ok(text)
}

fn checked_nul(text: &str) -> Result<&str, ParseError> {
    if text.len() > MAX_TEXT || text.contains('\0') { return Err(ParseError::Unwritable); }
    Ok(text)
}

fn checked_text<'a>(text: &'a str, excluded: &[char], max: usize) -> Result<&'a str, ParseError> {
    if text.len() > max || text.chars().any(|c| c == '\0' || c == '\n' || excluded.contains(&c)) {
        return Err(ParseError::Unwritable);
    }
    Ok(text)
}

/// `s` cut to at most `max` bytes, at a character boundary.
fn clipped_text(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut i = max;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

macro_rules! message_wire {
    ($ty:ty, $parse_doc:literal, $write_doc:literal) => {
        impl Wire for $ty {
            type ParseError = ParseError;
            type WriteError = ParseError;

            #[doc = $parse_doc]
            /// Refuses incomplete or trailing packets and lists beyond their limits.
            fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
                match Self::parse_prefix(bytes)? {
                    Some((value, used)) if used == bytes.len() => Ok(value),
                    Some(_) => Err(ParseError::Trailing),
                    None => Err(ParseError::Truncated),
                }
            }

            #[doc = $write_doc]
            /// Leaves the destination unchanged on error.
            fn write(&self, out: &mut Vec<u8>) -> Result<(), ParseError> {
                let start = out.len();
                if self.encode(out).is_err() || Self::parse(&out[start..]).as_ref() != Ok(self) {
                    out.truncate(start);
                    return Err(ParseError::Unwritable);
                }
                Ok(())
            }
        }
    };
}
message_wire!(ProtoRequest,
    "Reads the initial git:// service request. Refuses non-data packets, unknown services, missing NUL separators, malformed host or extra parameters, and fields above MAX_TEXT. Line endings inside NUL-delimited fields are preserved.",
    "Appends the complete request packet. Refuses NULs, empty extra parameters, excessive fields or lists, and a request above MAX_DATA.");
message_wire!(ServiceHeader,
    "Reads one smart HTTP service line followed by a flush. Refuses unknown services and any other packet layout.",
    "Appends the service announcement and flush. Every service value is representable.");
message_wire!(Advertisement,
    "Reads a version 0 or 1 ref advertisement through its flush. Refuses malformed refs or capabilities, object IDs inconsistent with object-format, and refs after shallow lines. An ERR line returns ParseError::Remote immediately, even before a flush; its text is limited to MAX_TEXT. Each parse starts at the beginning. For incremental input, collect packets with [`Stream<Frames>`](super::codec::Stream) and use [`Advertisement::from_packets`].",
    "Appends refs, capabilities, shallow lines, and a flush. Refuses invalid fields, conflicting object formats, a first ref that would become the empty-ref marker, and values beyond the reader limits. SHA-1 is the default object format.");
message_wire!(CapabilityAdvertisement,
    "Reads version 2 and its capabilities through a flush. Refuses missing version 2 or malformed capabilities. An ERR line returns ParseError::Remote immediately, even before a flush; its text is limited to MAX_TEXT.",
    "Appends version 2, each capability, and a flush. Refuses malformed capability names or values and lists beyond MAX_CAPABILITIES.");
message_wire!(V2Request,
    "Reads one version 2 request through its flush. A lone flush means Empty. Refuses missing command=, malformed capabilities, repeated delimiters, or control packets in arguments. The delimiter may be omitted when there are no arguments.",
    "Appends the command, capabilities, delimiter, arguments, and flush, or a lone flush for Empty. Refuses invalid command names, capabilities, line endings, and excessive fields or lists.");

macro_rules! line_wire {
    ($($ty:ty),+ $(,)?) => {$ (
        impl $ty {
            /// Builds a pkt-line around this value. Refuses values that cannot
            /// be represented without changing their fields.
            pub fn to_packet(&self) -> Result<Packet, ParseError> {
                Ok(Packet::Data(Wire::to_bytes(self)?))
            }
        }
        impl Wire for $ty {
            type ParseError = ParseError;
            type WriteError = ParseError;

            /// Reads one text line. Refuses invalid UTF-8, embedded line endings,
            /// malformed fields, and fields or lists beyond their limits.
            fn parse(bytes: &[u8]) -> Result<Self, ParseError> { Self::read(bytes) }

            /// Appends the line and its line feed. Refuses invalid or oversized
            /// fields and any value that would read back differently.
            /// Leaves the destination unchanged on error.
            fn write(&self, out: &mut Vec<u8>) -> Result<(), ParseError> {
                let mut text = self.encode_line()?;
                if text.len() > MAX_LINE { return Err(ParseError::Unwritable); }
                text.push('\n');
                if Self::read(text.as_bytes()).as_ref() != Ok(self) { return Err(ParseError::Unwritable); }
                out.extend_from_slice(text.as_bytes());
                Ok(())
            }
        }
    )+};
}
line_wire!(LsRefsArg, LsRef, ClientLine, ServerLine);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::codec::{Stream, Fail, contract, test_support::{Lcg, mutate, decode_all}};

    const A: &str = "7217a7c7e582c46cec22a130adf4b9d7d950fba0";
    const B: &str = "1d3fcd5ced445d1abc402225c0b8a1299641f497";
    const C: &str = "ab52c4a3f2ab3c0e0d9d3cbb43e9bb6e4ef1b1e7c59a6bdf3b2a3f0c9e1d8a7b";

    fn id(s: &str) -> ObjectId {
        ObjectId::parse(s).unwrap()
    }

    fn pkt(lines: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for l in lines {
            match *l {
                "0000" => Packet::Flush.write(&mut out).unwrap(),
                "0001" => Packet::Delim.write(&mut out).unwrap(),
                "0002" => Packet::ResponseEnd.write(&mut out).unwrap(),
                l => Packet::Data(l.as_bytes().to_vec()).write(&mut out).unwrap(),
            }
        }
        out
    }

    // Examples from gitprotocol-common, "pkt-line Format".
    #[test]
    fn packet_examples() {
        for (bytes, data) in [(&b"0006a\n"[..], &b"a\n"[..]), (b"0005a", b"a"), (b"000bfoobar\n", b"foobar\n"), (b"0004", b"")] {
            let packet = Packet::parse(bytes).unwrap();
            assert_eq!(packet, Packet::Data(data.to_vec()));
            assert_eq!(packet.to_bytes().unwrap(), bytes);
        }
        assert_eq!(Packet::parse(b"0000rest"), Err(PacketParseError::Trailing));
        assert_eq!(Frames::new().decode(b"0000rest", false), Ok(Step::Item(Packet::Flush, 4)));
        assert_eq!(Packet::parse(b"0001"), Ok(Packet::Delim));
        assert_eq!(Packet::parse(b"0002"), Ok(Packet::ResponseEnd));
        assert_eq!(Packet::parse(b"000Bfoobar\n"), Ok(Packet::Data(b"foobar\n".to_vec())));
        assert_eq!(Packet::text("a"), Packet::Data(b"a\n".to_vec()));
        assert_eq!(Packet::Flush.data(), None);
    }

    #[test]
    fn packet_errors() {
        for (bytes, error) in [(&b"0003"[..], PacketError::Reserved), (b"fff1", PacketError::TooLong(0xfff1)),
            (b"ffff", PacketError::TooLong(0xffff)), (b"00g0", PacketError::Header),
            (b"x", PacketError::Header), (b"0 ", PacketError::Header)] {
            assert_eq!(Packet::parse(bytes), Err(PacketParseError::Frame(error)));
            assert!(!error.to_string().is_empty());
        }
        assert_eq!(Frames::new().decode(b"fff0", false), Ok(Step::Need));
        let bytes = b"000bfoobar\n";
        for n in 0..bytes.len() {
            assert_eq!(Packet::parse(&bytes[..n]), Err(PacketParseError::Truncated));
            assert_eq!(Frames::new().decode(&bytes[..n], false), Ok(Step::Need));
        }
    }

    #[test]
    fn packet_writers_refuse_oversized_values() {
        let packet = Packet::Data(vec![b'x'; MAX_DATA + 100]);
        assert!(packet.to_bytes().is_err());
        contract::check_wire_value(&packet);
        let long = "é".repeat(MAX_DATA);
        let packet = Packet::text(&long);
        assert_eq!(packet.data().unwrap().len(), long.len() + 1);
        assert!(packet.to_bytes().is_err());
        contract::check_wire_value(&packet);
        let packet = Packet::Data(vec![0; MAX_DATA]);
        let bytes = packet.to_bytes().unwrap();
        assert_eq!(bytes.len(), MAX_PACKET);
        assert_eq!(&bytes[..4], b"fff0");
        contract::check_wire::<Packet>(&bytes);
    }

    #[test]
    fn stream_splits_packets() {
        let bytes = pkt(&["want x\n", "0001", "0000", "done\n"]);
        contract::check_decode_with_alloc_limit(Frames::new, &bytes, 2 * MAX_PACKET);
        assert_eq!(decode_all(Frames::new, &bytes),
            (vec![Packet::text("want x"), Packet::Delim, Packet::Flush, Packet::text("done")], None));
        let mut stream = Stream::new(Frames::new());
        assert_eq!(stream.push(b"00"), 2);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.buffered(), 2);
        assert_eq!(stream.push(b"03"), 2);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(PacketError::Reserved))));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.failed(), Some(&Fail::Protocol(PacketError::Reserved)));
    }

    #[test]
    fn stream_takes_many_small_packets_in_linear_time() {
        let stream: Vec<u8> = b"0009done\n".iter().copied().cycle().take(9 * 200_000).collect();
        let started = std::time::Instant::now();
        let (packets, failed) = decode_all(Frames::new, &stream);
        assert_eq!(failed, None);
        assert_eq!(packets.len(), 200_000);
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    // gitprotocol-pack, "Git Transport".
    #[test]
    fn proto_request_example() {
        let bytes = b"0033git-upload-pack /project.git\0host=myserver.com\0";
        let req = ProtoRequest::parse(bytes).unwrap();
        assert_eq!(req.service, Service::UploadPack);
        assert_eq!(req.path, "/project.git");
        assert_eq!(req.host.as_deref(), Some("myserver.com"));
        assert_eq!(req.version(), None);
        assert_eq!(req.to_bytes().unwrap(), bytes);
        // Version 2 rides in an extra parameter.
        let v2 = b"git-receive-pack /r\0host=h:9418\0\0version=2\0";
        let req = ProtoRequest::from_data(v2).unwrap();
        assert_eq!(req.service, Service::ReceivePack);
        assert_eq!(req.extra, ["version=2"]);
        assert_eq!(req.version(), Some(2));
        assert_eq!(req.to_packet().unwrap(), Packet::Data(v2.to_vec()));
        // No host, and extra parameters.
        let req = ProtoRequest::from_data(b"git-upload-archive /a\0\0a\0b\0").unwrap();
        assert_eq!(req.host, None);
        assert_eq!(req.extra, ["a", "b"]);
        assert_eq!(ProtoRequest::from_data(req.to_packet().unwrap().data().unwrap()), Ok(req));
        // gitprotocol-pack, "Extra Parameters".
        let v1 = b"003egit-upload-pack /project.git\0host=myserver.com\0\0version=1\0";
        let req = ProtoRequest::parse(v1).unwrap();
        assert_eq!(req.version(), Some(1));
        assert_eq!(req.to_bytes().unwrap(), v1);
        for s in [Service::UploadPack, Service::ReceivePack, Service::UploadArchive] {
            assert_eq!(Service::from_name(s.name()), Some(s));
        }
    }

    #[test]
    fn proto_request_errors() {
        let syntax = |b: &[u8]| matches!(ProtoRequest::from_data(b), Err(ParseError::Syntax(_)));
        assert!(syntax(b"git-upload-pack"));
        assert!(syntax(b"git-upload-dog /x\0"));
        assert!(syntax(b"git-upload-pack /x"));
        assert!(syntax(b"git-upload-pack /x\0host=h"));
        assert!(syntax(b"git-upload-pack /x\0junk\0"));
        assert!(syntax(b"git-upload-pack /x\0\0version=2"));
        // Each extra parameter has at least one byte, and the NUL before
        // them is followed by at least one.
        assert_eq!(ProtoRequest::from_data(b"git-upload-pack /x\0\0a\0\0"), Err(ParseError::Syntax("an extra parameter")));
        assert_eq!(ProtoRequest::from_data(b"git-upload-pack /x\0\0\0"), Err(ParseError::Syntax("an extra parameter")));
        assert_eq!(ProtoRequest::from_data(b"git-upload-pack /x\0host=h\0\0"), Err(ParseError::Syntax("an extra parameter")));
        assert_eq!(ProtoRequest::from_data(b"git-upload-pack /\xff\0"), Err(ParseError::Text));
        let long = format!("git-upload-pack /{}\0", "x".repeat(MAX_TEXT));
        assert_eq!(ProtoRequest::from_data(long.as_bytes()), Err(ParseError::TooLong));
        let many = format!("git-upload-pack /x\0\0{}", "p\0".repeat(MAX_CAPABILITIES + 1));
        assert_eq!(ProtoRequest::from_data(many.as_bytes()), Err(ParseError::TooMany));
        assert_eq!(ProtoRequest::parse(b"0000"), Err(ParseError::Syntax("a request line")));
        assert_eq!(ProtoRequest::parse(b"0003"), Err(ParseError::Packet(PacketError::Reserved)));
        let bytes = ProtoRequest { service: Service::UploadPack, path: "/p".into(), host: None, extra: vec![] }.to_bytes().unwrap();
        for n in 0..bytes.len() {
            assert_eq!(ProtoRequest::parse(&bytes[..n]), Err(ParseError::Truncated));
        }
    }

    #[test]
    fn proto_request_writer_refuses_invalid_fields() {
        let base = ProtoRequest { service: Service::UploadPack, path: "/p".into(), host: None, extra: vec![] };
        for request in [
            ProtoRequest { path: "/a\0b\n".repeat(MAX_TEXT), ..base.clone() },
            ProtoRequest { host: Some("h\0".into()), ..base.clone() },
            ProtoRequest { extra: vec!["x".repeat(MAX_TEXT); MAX_CAPABILITIES + 1], ..base.clone() },
            ProtoRequest { extra: vec!["x".repeat(MAX_TEXT); MAX_CAPABILITIES], ..base.clone() },
            ProtoRequest { extra: vec![String::new(), "\0".into(), "version=2".into()], ..base.clone() },
        ] {
            assert_eq!(request.to_bytes(), Err(ParseError::Unwritable));
            contract::check_wire_value(&request);
        }
        let request = ProtoRequest { path: "/a\nb".into(), ..base };
        assert_eq!(ProtoRequest::parse(&request.to_bytes().unwrap()), Ok(request));
    }

    #[test]
    fn service_header_round_trip() {
        let bytes = ServiceHeader(Service::UploadPack).to_bytes().unwrap();
        assert_eq!(bytes, b"001e# service=git-upload-pack\n0000");
        assert_eq!(ServiceHeader::parse(&bytes), Ok(ServiceHeader(Service::UploadPack)));
        for n in 0..bytes.len() {
            assert_eq!(ServiceHeader::parse(&bytes[..n]), Err(ParseError::Truncated));
        }
        assert_eq!(ServiceHeader::parse(b"0000"), Err(ParseError::Syntax("one service line")));
        assert_eq!(ServiceHeader::parse(&pkt(&["# x\n", "0000"])), Err(ParseError::Syntax("# service=")));
        assert_eq!(ServiceHeader::parse(&pkt(&["# service=git-x\n", "0000"])), Err(ParseError::Syntax("a service name")));
        assert_eq!(ServiceHeader::parse(&pkt(&["0001", "0000"])), Err(ParseError::Syntax("a data packet")));
        assert_eq!(ServiceHeader::parse(&pkt(&["ERR no\n", "0000"])), Err(ParseError::Remote("no".into())));
    }

    // gitprotocol-pack, "Reference Discovery".
    #[test]
    fn advertisement_example() {
        let caps = "multi_ack thin-pack side-band side-band-64k ofs-delta shallow no-progress include-tag";
        let first = format!("{A} HEAD\0{caps}\n");
        let lines = [
            first.as_str(),
            "1d3fcd5ced445d1abc402225c0b8a1299641f497 refs/heads/integration\n",
            "7217a7c7e582c46cec22a130adf4b9d7d950fba0 refs/heads/master\n",
            "b88d2441cac0977faf98efc80305012112238d9d refs/tags/v0.9\n",
            "525128480b96c89e6418b1e40909bf6c5b2d580f refs/tags/v1.0\n",
            "e92df48743b7bc7d26bcaabfddde0a1e20cae47c refs/tags/v1.0^{}\n",
            "0000",
        ];
        let bytes = pkt(&lines);
        assert_eq!(&bytes[..4], b"0088");
        assert!(bytes[136..].starts_with(b"00441d3f"));
        let ad = Advertisement::parse(&bytes).unwrap();
        assert!(!ad.version_1);
        assert_eq!(ad.refs.len(), 6);
        assert_eq!(ad.refs[0], AdvertisedRef { id: id(A), name: "HEAD".into() });
        assert_eq!(ad.refs[5].name, "refs/tags/v1.0^{}");
        assert_eq!(ad.capabilities.len(), 8);
        assert!(ad.capability("ofs-delta").is_some());
        assert!(ad.capability("agent").is_none());
        assert_eq!(ad.to_bytes().unwrap(), bytes);
        for n in 0..bytes.len() {
            assert_eq!(Advertisement::parse(&bytes[..n]), Err(ParseError::Truncated), "{n} bytes");
        }
    }

    #[test]
    fn advertisement_without_refs_and_with_shallow() {
        let ad = Advertisement {
            version_1: true,
            refs: vec![],
            capabilities: vec![Capability::with_value("object-format", "sha256"), Capability::with_value("agent", "git/2")],
            shallow: vec![id(C)],
        };
        let bytes = ad.to_bytes().unwrap();
        let zero = "0".repeat(64);
        let expected = pkt(&[
            "version 1\n",
            &format!("{zero} capabilities^{{}}\0object-format=sha256 agent=git/2\n"),
            &format!("shallow {C}\n"),
            "0000",
        ]);
        assert_eq!(bytes, expected);
        assert_eq!(Advertisement::parse(&bytes).unwrap(), ad);
        // A bare flush is an empty advertisement.
        assert_eq!(Advertisement::parse(b"0000"), Ok(Advertisement::default()));
        // A first line with no capabilities.
        let ad = Advertisement::parse(&pkt(&[&format!("{A} HEAD\n"), "0000"])).unwrap();
        assert!(ad.capabilities.is_empty());
        assert_eq!(Advertisement::parse(&ad.to_bytes().unwrap()).unwrap(), ad);
        // A leading ref named capabilities^{} with a zero id is refused.
        let odd = Advertisement {
            refs: vec![
                AdvertisedRef { id: ObjectId::zero(false), name: "capabilities^{}".into() },
                AdvertisedRef { id: id(B), name: "x".into() },
            ],
            ..Advertisement::default()
        };
        assert_eq!(odd.to_bytes(), Err(ParseError::Unwritable));
        contract::check_wire_value(&odd);
    }

    // Git reads capabilities^{} as "no refs" only with a zero id
    // (process_dummy_ref in connect.c). Otherwise it is a ref.
    #[test]
    fn capabilities_line_needs_a_zero_id() {
        let bytes = pkt(&[&format!("{A} capabilities^{{}}\0ofs-delta\n"), &format!("{B} refs/heads/x\n"), "0000"]);
        let ad = Advertisement::parse(&bytes).unwrap();
        assert_eq!(ad.refs.len(), 2);
        assert_eq!(ad.refs[0], AdvertisedRef { id: id(A), name: "capabilities^{}".into() });
        assert_eq!(ad.to_bytes().unwrap(), bytes);
        // With a zero id, of either length, it is the no-refs line.
        for zero in [ObjectId::zero(false), ObjectId::zero(true)] {
            let bytes = pkt(&[&format!("{zero} capabilities^{{}}\0ofs-delta\n"), "0000"]);
            assert!(Advertisement::parse(&bytes).unwrap().refs.is_empty());
        }
    }

    // gitprotocol-pack: "both MUST treat obj-id as case-insensitive".
    #[test]
    fn object_ids_are_case_insensitive() {
        let upper = A.to_uppercase();
        assert_eq!(ObjectId::parse(&upper), Some(id(A)));
        assert_eq!(ClientLine::parse(format!("have {upper}\n").as_bytes()), Ok(ClientLine::Have(id(A))));
        assert_eq!(ServerLine::parse(format!("ACK {upper} common").as_bytes()).unwrap().to_bytes().unwrap(), format!("ACK {A} common\n").as_bytes());
        let ad = Advertisement::parse(&pkt(&[&format!("{upper} HEAD\0\n"), "0000"])).unwrap();
        assert_eq!(ad.refs[0].id.as_str(), A);
        let zero = Advertisement::parse(&pkt(&[&format!("{} capabilities^{{}}\0\n", "0".repeat(40)), "0000"]));
        assert!(zero.unwrap().refs.is_empty());
    }

    // Git's determine_protocol_version_server takes the greatest version
    // the client asked for that parse_protocol_version knows: "0", "1" or
    // "2", written just so.
    #[test]
    fn version_is_the_greatest_one_asked_for() {
        let req = |extra: &[u8]| ProtoRequest::from_data(&[&b"git-upload-pack /x\0\0"[..], extra].concat()).unwrap();
        assert_eq!(req(b"version=2\0version=1\0").version(), Some(2));
        assert_eq!(req(b"version=1\0version=2\0").version(), Some(2));
        assert_eq!(req(b"version=+2\0").version(), None);
        assert_eq!(req(b"version=\0version= 1\0").version(), None);
        assert_eq!(req(b"version=x\0version=1\0").version(), Some(1));
        assert_eq!(req(b"version=99999999999\0").version(), None);
        assert_eq!(req(b"version=1\0version=3\0").version(), Some(1));
        assert_eq!(req(b"version=02\0").version(), None);
        assert_eq!(req(b"version=0\0").version(), Some(0));
    }

    // A line one reader keeps as unknown can mean something to another,
    // so each Other variant holds its own reader's Unknown. Each writes
    // back the line it read.
    #[test]
    fn unknown_lines_keep_their_reader() {
        let ServerLine::Other(s) = ServerLine::parse(b"want zz\n").unwrap() else { panic!() };
        assert_eq!(s.as_str(), "want zz");
        assert_eq!(ServerLine::parse(ServerLine::Other(s.clone()).to_packet().unwrap().data().unwrap()), Ok(ServerLine::Other(s)));
        let long = format!("ref-prefix {}", "p".repeat(MAX_TEXT + 1));
        let ClientLine::Other(c) = ClientLine::parse(long.as_bytes()).unwrap() else { panic!() };
        assert_eq!(format!("{c:?}"), format!("Unknown({long:?})"));
        assert_eq!(ClientLine::parse(&ClientLine::Other(c.clone()).to_bytes().unwrap()), Ok(ClientLine::Other(c)));
        let ls = Command { name: "ls-refs".into(), capabilities: vec![], args: vec!["ACK x".into()] };
        let Ok([LsRefsArg::Other(a)]) = <[LsRefsArg; 1]>::try_from(ls.ls_refs_args().unwrap()) else { panic!() };
        assert_eq!(LsRefsArg::parse(&LsRefsArg::Other(a.clone()).to_bytes().unwrap()), Ok(LsRefsArg::Other(a)));
        let set: std::collections::HashSet<_> = [Unknown::<ServerLine>::new("a"), Unknown::new("a")].into();
        assert_eq!(set.len(), 1);
    }

    // gitprotocol-v2: key = 1*(ALPHA | DIGIT | "-_"); command = "command=" key.
    #[test]
    fn keys_are_checked() {
        let name = Err(ParseError::Syntax("a capability name"));
        assert_eq!(Advertisement::parse(&pkt(&[&format!("{A} HEAD\0ofs delta=x a.b\n"), "0000"])).map(|_| ()), name);
        assert_eq!(CapabilityAdvertisement::parse(&pkt(&["version 2\n", "ls refs\n", "0000"])).map(|_| ()), name);
        assert_eq!(CapabilityAdvertisement::parse(&pkt(&["version 2\n", "fetch/x=y\n", "0000"])).map(|_| ()), name);
        assert_eq!(ClientLine::parse(format!("want {A} th!n-pack").as_bytes()).map(|_| ()), name);
        let ok = CapabilityAdvertisement::parse(&pkt(&["version 2\n", "Ab-9_=v w\n", "0000"])).unwrap();
        assert_eq!(ok.capabilities, [Capability::with_value("Ab-9_", "v w")]);
        let command = Err(ParseError::Syntax("a command name"));
        assert_eq!(V2Request::parse(&pkt(&["command=\n", "0000"])).map(|_| ()), command);
        assert_eq!(V2Request::parse(&pkt(&["command=ls refs\n", "0000"])).map(|_| ()), command);
        assert_eq!(V2Request::parse(&pkt(&["command=a=b\n", "0000"])).map(|_| ()), command);
        // A command whose name has nothing a key may hold is refused.
        let empty = V2Request::Command(Command { name: "?!".into(), capabilities: vec![], args: vec!["x".into()] });
        assert_eq!(empty.to_bytes(), Err(ParseError::Unwritable));
        contract::check_wire_value(&empty);
        let cap = Capability::with_value("é x", "v");
        let ad = CapabilityAdvertisement { capabilities: vec![cap.clone(), Capability::new("~")] };
        assert_eq!(ad.to_bytes(), Err(ParseError::Unwritable));
        contract::check_wire_value(&ad);
    }

    #[test]
    fn advertisement_errors() {
        let first = format!("{A} HEAD\0ofs-delta\n");
        let parse = |lines: &[&str]| Advertisement::parse(&pkt(lines)).map(|_| ());
        let zero = format!("{} capabilities^{{}}\0\n", "0".repeat(40));
        assert_eq!(parse(&[&zero, &format!("{A} x\n"), "0000"]), Err(ParseError::Syntax("a shallow line")));
        assert_eq!(parse(&[&first, &format!("shallow {A}\n"), &format!("{A} x\n"), "0000"]), Err(ParseError::Syntax("a shallow line")));
        assert_eq!(parse(&["nothex HEAD\0\n", "0000"]), Err(ParseError::ObjectId));
        assert_eq!(parse(&[&first, "shallow zz\n", "0000"]), Err(ParseError::ObjectId));
        assert_eq!(parse(&["ERR access denied\n", "0000"]), Err(ParseError::Remote("access denied".into())));
        assert_eq!(parse(&[&first, "ERR later\n", "0000"]), Err(ParseError::Remote("later".into())));
        assert_eq!(parse(&[&first, "0001", "0000"]), Err(ParseError::Syntax("a data packet")));
        assert_eq!(parse(&["0002", "0000"]), Err(ParseError::Syntax("a data packet")));
        assert_eq!(parse(&[A, "0000"]), Err(ParseError::Syntax("a ref line")));
        assert_eq!(parse(&[&format!("{A} HEAD\0=x\n"), "0000"]), Err(ParseError::Syntax("a capability name")));
        assert_eq!(parse(&[&format!("{A} HEAD\0a\0b\n"), "0000"]), Err(ParseError::Text));
        assert_eq!(parse(&[&first, &format!("{A} a\0b\n"), "0000"]), Err(ParseError::Text));
        assert_eq!(parse(&[&format!("{A} HEAD\0\u{0}\n"), "0000"]), Err(ParseError::Text));
        let many = format!("{A} HEAD\0{}\n", "c ".repeat(MAX_CAPABILITIES + 1));
        assert_eq!(parse(&[&many, "0000"]), Err(ParseError::TooMany));
        let long = format!("{A} {}\n", "r".repeat(MAX_TEXT + 1));
        assert_eq!(parse(&[&long, "0000"]), Err(ParseError::TooLong));
        assert_eq!(Advertisement::parse(b"0003"), Err(ParseError::Packet(PacketError::Reserved)));
        // Too many refs.
        let mut lines = vec![first.clone()];
        lines.extend((0..MAX_ITEMS).map(|i| format!("{A} r{i}\n")));
        lines.push("0000".into());
        let refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        assert_eq!(parse(&refs), Err(ParseError::TooMany));
    }

    #[test]
    fn advertisement_writer_refuses_invalid_fields() {
        let ad = Advertisement {
            version_1: false,
            refs: vec![
                AdvertisedRef { id: id(A), name: "HE\0AD\n".into() },
                AdvertisedRef { id: id(B), name: "n".repeat(MAX_TEXT * 2) },
            ],
            capabilities: vec![Capability::with_value("a b=c", "x y"); MAX_CAPABILITIES + 5]
                .into_iter()
                .chain([Capability::new(""), Capability::with_value("big", &"v".repeat(MAX_TEXT))])
                .collect(),
            shallow: vec![],
        };
        assert_eq!(ad.to_bytes(), Err(ParseError::Unwritable));
        contract::check_wire_value(&ad);
        // Many long capabilities stop where the line is full.
        let full = Advertisement {
            capabilities: vec![Capability::with_value("k", &"v".repeat(MAX_TEXT - 10)); 40],
            ..Advertisement::default()
        };
        assert_eq!(full.to_bytes(), Err(ParseError::Unwritable));
        contract::check_wire_value(&full);
    }

    // gitprotocol-v2, "Capability Advertisement".
    #[test]
    fn capability_advertisement_example() {
        let bytes = pkt(&[
            "version 2\n",
            "agent=git/2.20.1\n",
            "ls-refs=unborn\n",
            "fetch=shallow wait-for-done\n",
            "server-option\n",
            "object-format=sha1\n",
            "0000",
        ]);
        let ad = CapabilityAdvertisement::parse(&bytes).unwrap();
        assert_eq!(ad.capabilities.len(), 5);
        assert_eq!(ad.capability("fetch"), Some(&Capability::with_value("fetch", "shallow wait-for-done")));
        assert_eq!(ad.capability("server-option"), Some(&Capability::new("server-option")));
        assert_eq!(ad.to_bytes().unwrap(), bytes);
        for n in 0..bytes.len() {
            assert_eq!(CapabilityAdvertisement::parse(&bytes[..n]), Err(ParseError::Truncated));
        }
        assert_eq!(CapabilityAdvertisement::parse(b"0000"), Err(ParseError::Syntax("version 2")));
        assert_eq!(CapabilityAdvertisement::parse(&pkt(&["version 1\n", "0000"])), Err(ParseError::Syntax("version 2")));
        assert_eq!(CapabilityAdvertisement::parse(&pkt(&["ERR x\n", "0000"])), Err(ParseError::Remote("x".into())));
        assert_eq!(
            CapabilityAdvertisement::parse(&pkt(&["version 2\n", "=v\n", "0000"])),
            Err(ParseError::Syntax("a capability name"))
        );
        assert_eq!(CapabilityAdvertisement::parse(&pkt(&["version 2\n", "0001", "0000"])), Err(ParseError::Syntax("a data packet")));
        let mut many = vec!["version 2\n"];
        many.extend(std::iter::repeat_n("c\n", MAX_CAPABILITIES + 1));
        many.push("0000");
        assert_eq!(CapabilityAdvertisement::parse(&pkt(&many)), Err(ParseError::TooMany));
        // A capability named like an error reads back as a capability.
        let odd = CapabilityAdvertisement { capabilities: vec![Capability::new("ERR x"), Capability::new("=")] };
        assert_eq!(odd.to_bytes(), Err(ParseError::Unwritable));
        contract::check_wire_value(&odd);
    }

    // gitprotocol-v2, "ls-refs" and "fetch".
    #[test]
    fn v2_requests() {
        let bytes = pkt(&["command=fetch\n", "agent=git/2.45\n", "object-format=sha1\n", "0001",
            "thin-pack\n", "ofs-delta\n", &format!("want {A}\n"), &format!("have {B}\n"), "done\n", "0000"]);
        let req = V2Request::parse(&bytes).unwrap();
        let V2Request::Command(cmd) = &req else { panic!() };
        assert_eq!(cmd.name, "fetch");
        assert_eq!(cmd.capabilities[0], Capability::with_value("agent", "git/2.45"));
        assert_eq!(
            cmd.fetch_args().unwrap(),
            [
                ClientLine::ThinPack,
                ClientLine::OfsDelta,
                ClientLine::Want { id: id(A), capabilities: vec![] },
                ClientLine::Have(id(B)),
                ClientLine::Done
            ]
        );
        assert_eq!(req.to_bytes().unwrap(), bytes);
        for n in 0..bytes.len() {
            assert_eq!(V2Request::parse(&bytes[..n]), Err(ParseError::Truncated));
        }
        assert_eq!(V2Request::parse(b"0000"), Ok(V2Request::Empty));
        assert_eq!(V2Request::Empty.to_bytes().unwrap(), b"0000");
        // No delimiter and no arguments.
        let req = V2Request::parse(&pkt(&["command=ls-refs\n", "0000"])).unwrap();
        assert_eq!(req, V2Request::Command(Command { name: "ls-refs".into(), capabilities: vec![], args: vec![] }));
        let ls = Command {
            name: "ls-refs".into(),
            capabilities: vec![],
            args: vec!["peel".into(), "unborn".into(), "ref-prefix refs/tags/".into(), "x-y".into()],
        };
        let args = ls.ls_refs_args().unwrap();
        assert_eq!(args[..3], [LsRefsArg::Peel, LsRefsArg::Unborn, LsRefsArg::RefPrefix("refs/tags/".into())]);
        assert_eq!(args[3].to_bytes().unwrap(), b"x-y\n");
        let LsRefsArg::Other(u) = &args[3] else { panic!() };
        assert_eq!(u.as_str(), "x-y");
        for a in &args {
            assert_eq!(LsRefsArg::parse(&a.to_bytes().unwrap()).as_ref(), Ok(a));
        }
    }

    #[test]
    fn v2_request_errors() {
        let parse = |lines: &[&str]| V2Request::parse(&pkt(lines)).map(|_| ());
        assert_eq!(parse(&["ls-refs\n", "0000"]), Err(ParseError::Syntax("command=")));
        assert_eq!(parse(&["0001", "0000"]), Err(ParseError::Syntax("a data packet")));
        assert_eq!(parse(&["command=x\n", "0001", "0001", "0000"]), Err(ParseError::Syntax("a data packet")));
        assert_eq!(parse(&["command=x\n", "0002", "0000"]), Err(ParseError::Syntax("a data packet")));
        assert_eq!(parse(&["command=x\n", "=y\n", "0000"]), Err(ParseError::Syntax("a capability name")));
        assert_eq!(parse(&["command=x\n", "0001", "a\nb\n", "0000"]), Err(ParseError::Text));
        assert_eq!(parse(&["command=\u{0}\n", "0000"]), Err(ParseError::Text));
        let mut many = vec!["command=x\n"];
        many.extend(std::iter::repeat_n("c\n", MAX_CAPABILITIES + 1));
        many.push("0000");
        assert_eq!(parse(&many), Err(ParseError::TooMany));
        let mut args = vec!["command=x\n", "0001"];
        args.extend(std::iter::repeat_n("a\n", MAX_ITEMS + 1));
        args.push("0000");
        assert_eq!(parse(&args), Err(ParseError::TooMany));
        let bad = Command { name: "fetch".into(), capabilities: vec![], args: vec!["want zz".into()] };
        assert_eq!(bad.fetch_args(), Err(ParseError::ObjectId));
        let bad = Command { name: "ls-refs".into(), capabilities: vec![], args: vec!["a\nb".into()] };
        assert_eq!(bad.ls_refs_args(), Err(ParseError::Text));
        let long = Command { name: "ls-refs".into(), capabilities: vec![], args: vec![format!("ref-prefix {}", "p".repeat(MAX_TEXT + 1))] };
        assert_eq!(long.ls_refs_args(), Err(ParseError::TooLong));
        // Writers refuse fields that would need changes.
        let req = V2Request::Command(Command {
            name: "a\nb".into(),
            capabilities: vec![Capability::with_value("k=k", "v\0v")],
            args: vec!["x\ny".into(), "z".repeat(MAX_DATA * 2)],
        });
        assert_eq!(req.to_bytes(), Err(ParseError::Unwritable));
        contract::check_wire_value(&req);
    }

    // gitprotocol-pack, "Packfile Negotiation".
    #[test]
    fn client_lines() {
        let want = format!("want {A} multi_ack_detailed side-band-64k thin-pack ofs-delta agent=git/2.45\n");
        let line = ClientLine::parse(want.as_bytes()).unwrap();
        let ClientLine::Want { id: w, capabilities } = &line else { panic!() };
        assert_eq!(w, &id(A));
        assert_eq!(capabilities.len(), 5);
        assert_eq!(find_capability(capabilities, "agent").unwrap().value.as_deref(), Some("git/2.45"));
        assert_eq!(line.to_packet().unwrap(), Packet::Data(want.into_bytes()));
        let all = [
            ClientLine::Want { id: id(B), capabilities: vec![] },
            ClientLine::WantRef("refs/heads/main".into()),
            ClientLine::Have(id(A)),
            ClientLine::Done,
            ClientLine::Shallow(id(A)),
            ClientLine::Deepen(3),
            ClientLine::DeepenSince(1_700_000_000),
            ClientLine::DeepenNot("refs/tags/v1".into()),
            ClientLine::DeepenRelative,
            ClientLine::Filter("blob:none".into()),
            ClientLine::ThinPack,
            ClientLine::NoProgress,
            ClientLine::IncludeTag,
            ClientLine::OfsDelta,
            ClientLine::SidebandAll,
            ClientLine::WaitForDone,
            ClientLine::PackfileUris("https".into()),
        ];
        for l in &all {
            assert_eq!(ClientLine::parse(l.to_packet().unwrap().data().unwrap()).as_ref(), Ok(l));
        }
        assert_eq!(ClientLine::parse(b"deepen 007"), Ok(ClientLine::Deepen(7)));
        let other = ClientLine::parse(b"want\n").unwrap();
        assert_eq!(other.to_bytes().unwrap(), b"want\n");
        // Errors.
        assert_eq!(ClientLine::parse(b"want 123\n"), Err(ParseError::ObjectId));
        assert_eq!(ClientLine::parse(format!("have {}\n", &A[1..]).as_bytes()), Err(ParseError::ObjectId));
        assert_eq!(ClientLine::parse(format!("want {A} =x").as_bytes()), Err(ParseError::Syntax("a capability name")));
        assert_eq!(ClientLine::parse(b"deepen -1"), Err(ParseError::Syntax("a number")));
        assert_eq!(ClientLine::parse(b"deepen "), Err(ParseError::Syntax("a number")));
        assert_eq!(ClientLine::parse(b"deepen 99999999999"), Err(ParseError::Syntax("a number")));
        assert_eq!(ClientLine::parse(b"deepen-since x"), Err(ParseError::Syntax("a number")));
        assert_eq!(ClientLine::parse(b"done\n\n"), Err(ParseError::Text));
        assert_eq!(ClientLine::parse(b"\xc3"), Err(ParseError::Text));
        assert_eq!(ClientLine::parse(format!("filter {}", "f".repeat(MAX_TEXT + 1)).as_bytes()), Err(ParseError::TooLong));
    }

    #[test]
    fn server_lines() {
        let all = [
            ServerLine::Nak,
            ServerLine::Ack { id: id(A), status: None },
            ServerLine::Ack { id: id(A), status: Some(AckStatus::Continue) },
            ServerLine::Ack { id: id(A), status: Some(AckStatus::Common) },
            ServerLine::Ack { id: id(A), status: Some(AckStatus::Ready) },
            ServerLine::Ready,
            ServerLine::Shallow(id(B)),
            ServerLine::Unshallow(id(B)),
            ServerLine::Section(Section::Acknowledgments),
            ServerLine::Section(Section::ShallowInfo),
            ServerLine::Section(Section::WantedRefs),
            ServerLine::Section(Section::PackfileUris),
            ServerLine::Section(Section::Packfile),
            ServerLine::Error("upload-pack: not our ref".into()),
        ];
        for l in &all {
            assert_eq!(ServerLine::parse(l.to_packet().unwrap().data().unwrap()).as_ref(), Ok(l));
        }
        assert_eq!(ServerLine::parse(b"0008NAK\n"), Ok(ServerLine::Other(Unknown::new("0008NAK"))));
        assert_eq!(ServerLine::parse(b"NAK\n"), Ok(ServerLine::Nak));
        assert_eq!(ServerLine::parse(format!("ACK {A} maybe").as_bytes()), Err(ParseError::Syntax("an ACK status")));
        assert_eq!(ServerLine::parse(b"ACK x"), Err(ParseError::ObjectId));
        assert_eq!(ServerLine::parse(b"unshallow x"), Err(ParseError::ObjectId));
        assert_eq!(ServerLine::parse(format!("ERR {}", "e".repeat(MAX_TEXT + 1)).as_bytes()), Err(ParseError::TooLong));
        assert_eq!(ServerLine::Error("a\nb".into()).to_bytes(), Err(ParseError::Unwritable));
        // A wanted-refs entry reads as an LsRef.
        let other = ServerLine::parse(format!("{A} refs/heads/main\n").as_bytes()).unwrap();
        let ServerLine::Other(u) = other else { panic!() };
        assert_eq!(LsRef::parse(u.as_str().as_bytes()).unwrap().name, "refs/heads/main");
    }

    #[test]
    fn ls_refs_lines() {
        let s = format!("{A} refs/tags/v1 peeled:{B}\n");
        let r = LsRef::parse(s.as_bytes()).unwrap();
        assert_eq!(r, LsRef { id: Some(id(A)), name: "refs/tags/v1".into(), symref_target: None, peeled: Some(id(B)) });
        assert_eq!(r.to_packet().unwrap(), Packet::Data(s.into_bytes()));
        let u = LsRef::parse(b"unborn HEAD symref-target:refs/heads/main x:y").unwrap();
        assert_eq!(u.id, None);
        assert_eq!(u.to_bytes().unwrap(), b"unborn HEAD symref-target:refs/heads/main\n");
        assert_eq!(LsRef::parse(A.as_bytes()), Err(ParseError::Syntax("a ref line")));
        assert_eq!(LsRef::parse(b"zz HEAD"), Err(ParseError::ObjectId));
        assert_eq!(LsRef::parse(format!("{A} H peeled:q").as_bytes()), Err(ParseError::ObjectId));
        assert_eq!(LsRef::parse(format!("{A} {}", "n".repeat(MAX_TEXT + 1)).as_bytes()), Err(ParseError::TooLong));
        let odd = LsRef { id: None, name: "a b\0".into(), symref_target: Some("c d".into()), peeled: None };
        assert_eq!(odd.to_bytes(), Err(ParseError::Unwritable));
        contract::check_wire_value(&odd);
        let empty = LsRef { id: Some(id(A)), name: String::new(), symref_target: None, peeled: None };
        assert_eq!(LsRef::parse(&empty.to_bytes().unwrap()), Ok(empty));
    }

    #[test]
    fn object_ids() {
        assert!(ObjectId::parse(A).is_some());
        assert!(ObjectId::parse(&"a".repeat(64)).is_some());
        assert!(ObjectId::parse(&"a".repeat(41)).is_none());
        assert!(ObjectId::parse(&"g".repeat(40)).is_none());
        assert!(ObjectId::zero(false).is_zero());
        assert_eq!(ObjectId::zero(true).as_str().len(), 64);
        assert!(!id(A).is_zero());
        assert_eq!(id(A).to_string(), A);
    }

    // gitprotocol-pack, "Packfile Data".
    #[test]
    fn side_band() {
        let pack = vec![7; 2500];
        let mut bytes = Vec::new();
        for packet in band_packets(Band::Pack, &pack, SIDE_BAND_PACKET)
            .chain(band_packets(Band::Progress, b"Counting objects: 3\r", SIDE_BAND_64K_PACKET))
            .chain([Packet::Flush]) { packet.write(&mut bytes).unwrap(); }
        contract::check_decode_with_alloc_limit(|| Bands, &bytes, 2 * MAX_PACKET);
        let (items, failure) = decode_all(|| Bands, &bytes);
        assert_eq!(failure, None);
        let mut got = Vec::new();
        let mut sizes = Vec::new();
        for item in items {
            match item {
                Demuxed::Data(Band::Pack, payload) => { sizes.push(payload.len()); got.extend(payload); }
                Demuxed::Data(Band::Progress, payload) => assert_eq!(payload, b"Counting objects: 3\r"),
                Demuxed::Flush => (),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(got, pack);
        assert_eq!(sizes, [995, 995, 510]);
        assert_eq!(band_packets(Band::Error, b"", 1000).count(), 0);
        assert_eq!(band_packets(Band::Error, b"ab", 0).next().unwrap().to_bytes().unwrap(), b"0007\x03ab");
        let small: usize = band_packets(Band::Pack, &[1; 99_500], 6).map(|p| p.to_bytes().unwrap().len()).sum();
        assert_eq!(small, 99_500 + 100 * 5);
        assert_eq!(&band_packets(Band::Pack, &vec![0; MAX_PACKET * 2], usize::MAX).next().unwrap().to_bytes().unwrap()[..4], b"fff0");
        for band in [Band::Pack, Band::Progress, Band::Error] { assert_eq!(Band::from_code(band.code()), Some(band)); }
        assert_eq!(split_band(b"\x02hi"), Ok((Band::Progress, &b"hi"[..])));
        assert_eq!(split_band(b""), Err(ParseError::Syntax("a band byte")));
        assert_eq!(split_band(b"\x04"), Err(ParseError::Syntax("band 1, 2 or 3")));
        assert_eq!(decode_all(|| Bands, b"00010002000509"), (vec![Demuxed::Delim, Demuxed::ResponseEnd],
            Some(Fail::Protocol(ParseError::Syntax("band 1, 2 or 3")))));
        assert_eq!(decode_all(|| Bands, b"zz").1, Some(Fail::Protocol(ParseError::Packet(PacketError::Header))));
        let mut stream = Stream::new(Frames::new());
        assert_eq!(stream.push(b"000dpackfile\n0006\x01P"), 19);
        assert_eq!(ServerLine::parse(stream.next().unwrap().unwrap().data().unwrap()), Ok(ServerLine::Section(Section::Packfile)));
        let mut stream = stream.swap(Bands);
        assert_eq!(stream.next(), Some(Ok(Demuxed::Data(Band::Pack, b"P".to_vec()))));
        assert_eq!(stream.next(), None);
    }

    #[test]
    fn errors_display() {
        for e in [
            ParseError::Packet(PacketError::Header),
            ParseError::Text,
            ParseError::ObjectId,
            ParseError::Syntax("x"),
            ParseError::TooLong,
            ParseError::TooMany,
            ParseError::Remote("r".into()),
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    // A stream pushed without being drained holds at most MAX_PACKET
    // bytes, and says how many it took.
    #[test]
    fn stream_buffer_is_bounded() {
        let bytes = b"0000".repeat(MAX_PACKET);
        let mut stream = Stream::new(Frames::new());
        assert_eq!(stream.push(&bytes), MAX_PACKET);
        assert_eq!(stream.push(b"0000"), 0);
        assert_eq!(stream.next(), Some(Ok(Packet::Flush)));
        assert_eq!(stream.push(b"0000"), 4);
        contract::check_decode_with_alloc_limit(Frames::new, &bytes[..1024], 2 * MAX_PACKET);
        let mut bands = Stream::new(Bands);
        assert_eq!(bands.push(&bytes), MAX_PACKET);
        assert_eq!(bands.buffered(), MAX_PACKET);
    }

    // gitprotocol-pack, "Packfile Data": without side-band the packfile
    // follows NAK as raw bytes.
    #[test]
    fn stream_hands_over_raw_bytes() {
        let bytes = b"0008NAK\nPACK\x00\x00\x00\x02";
        let mut stream = Stream::new(Frames::new());
        assert_eq!(stream.push(bytes), bytes.len());
        assert_eq!(ServerLine::parse(stream.next().unwrap().unwrap().data().unwrap()), Ok(ServerLine::Nak));
        assert_eq!(stream.into_parts().0.unread(), b"PACK\x00\x00\x00\x02");
        assert!(Stream::new(Frames::new()).into_parts().0.unread().is_empty());
    }

    #[test]
    fn command_args_are_bounded() {
        let many = Command { name: "fetch".into(), capabilities: vec![], args: vec!["done".into(); MAX_ITEMS + 1] };
        assert_eq!(many.fetch_args(), Err(ParseError::TooMany));
        assert_eq!(many.ls_refs_args(), Err(ParseError::TooMany));
    }

    // A first line of a whole packet with no line feed cannot be written
    // back with one, so it is too long; one byte less reads and writes back.
    #[test]
    fn full_first_line() {
        let names = |last: usize| {
            let mut v = vec!["a".repeat(MAX_TEXT); 15];
            v.push("a".repeat(last));
            v.join(" ")
        };
        let full = format!("{} HEAD\0{}", "a".repeat(40), names(4015));
        assert_eq!(full.len(), MAX_DATA);
        assert_eq!(Advertisement::parse(&pkt(&[&full, "0000"])), Err(ParseError::TooLong));
        let fits = format!("{} HEAD\0{}\n", "a".repeat(40), names(4014));
        assert_eq!(fits.len(), MAX_DATA);
        let ad = Advertisement::parse(&pkt(&[&fits, "0000"])).unwrap();
        assert_eq!(ad.capabilities.len(), 16);
        let bytes = ad.to_bytes().unwrap();
        assert_eq!(Advertisement::parse(&bytes), Ok(ad));
    }

    // gitprotocol-pack, "Git Transport": a pathname is any bytes but NUL.
    #[test]
    fn proto_request_fields_may_hold_line_feeds() {
        let req = ProtoRequest::from_data(b"git-upload-pack /a\nb\0host=h\0\0x\ny\0").unwrap();
        assert_eq!(req.path, "/a\nb");
        assert_eq!(req.extra, ["x\ny"]);
        assert_eq!(req.to_packet().unwrap(), Packet::Data(b"git-upload-pack /a\nb\0host=h\0\0x\ny\0".to_vec()));
    }

    // gitprotocol-pack, "pkt-line Format": an ERR packet ends the transfer,
    // so no flush follows it.
    #[test]
    fn err_lines_end_a_message() {
        let remote = |m: &str| Err::<(), _>(ParseError::Remote(m.into()));
        assert_eq!(Advertisement::parse(b"000bERR no\n").map(|_| ()), remote("no"));
        let first = format!("{A} HEAD\0ofs-delta\n");
        assert_eq!(Advertisement::parse(&pkt(&[&first, "ERR later\n"])).map(|_| ()), remote("later"));
        assert_eq!(CapabilityAdvertisement::parse(&pkt(&["version 2\n", "ERR x\n"])).map(|_| ()), remote("x"));
        assert_eq!(CapabilityAdvertisement::parse(&pkt(&["version 2\n", "ERR x\n", "0000"])).map(|_| ()), remote("x"));
        let packets = [Packet::text("version 2"), Packet::text("ERR y")];
        assert_eq!(CapabilityAdvertisement::from_packets(&packets).map(|_| ()), remote("y"));
        assert_eq!(ServiceHeader::parse(&pkt(&["ERR z\n"])).map(|_| ()), remote("z"));
        assert_eq!(Advertisement::parse(&pkt(&["ERR \u{0}\n"])).map(|_| ()), remote("\u{0}"));
        assert_eq!(Advertisement::parse(b"0009ERR \xff").map(|_| ()), remote("\u{fffd}"));
        // Keep enough source bytes to finish a character at the boundary.
        for room in 0..4 {
            let prefix = "a".repeat(MAX_TEXT - room);
            let text = format!("{prefix}😀tail");
            let packet = Packet::Data(format!("ERR {text}").into_bytes());
            assert_eq!(Advertisement::from_packets(&[packet]).map(|_| ()), remote(&prefix));
        }
    }

    // gitprotocol-capabilities, "object-format": ids are as long as the
    // format says, SHA-1 when none is given.
    #[test]
    fn ids_follow_the_object_format() {
        let sha256 = format!("{C} HEAD\0object-format=sha256\n");
        assert!(Advertisement::parse(&pkt(&[&sha256, "0000"])).is_ok());
        assert_eq!(Advertisement::parse(&pkt(&[&sha256, &format!("shallow {B}\n"), "0000"])), Err(ParseError::ObjectId));
        assert_eq!(Advertisement::parse(&pkt(&[&sha256, &format!("{A} refs/x\n"), "0000"])), Err(ParseError::ObjectId));
        assert_eq!(Advertisement::parse(&pkt(&[&format!("{C} HEAD\0ofs-delta\n"), "0000"])), Err(ParseError::ObjectId));
        let sha1 = format!("{C} HEAD\0object-format=sha1\n");
        assert_eq!(Advertisement::parse(&pkt(&[&sha1, "0000"])), Err(ParseError::ObjectId));
        // A format this module does not know is not checked.
        let odd = format!("{C} HEAD\0object-format=x\n");
        assert!(Advertisement::parse(&pkt(&[&odd, &format!("{A} refs/x\n"), "0000"])).is_ok());
        // Writers leave out ids of the wrong length.
        let ad = Advertisement {
            version_1: false,
            refs: vec![AdvertisedRef { id: id(A), name: "HEAD".into() }, AdvertisedRef { id: id(C), name: "refs/c".into() }],
            capabilities: vec![Capability::with_value("object-format", "sha256")],
            shallow: vec![id(B), id(C)],
        };
        assert_eq!(ad.to_bytes(), Err(ParseError::Unwritable));
        contract::check_wire_value(&ad);
        let mut caps = vec![Capability::with_value("k", &"v".repeat(MAX_TEXT - 10)); 40];
        caps.push(Capability::with_value("object-format", "sha256"));
        let full = Advertisement { capabilities: caps, ..ad };
        assert_eq!(full.to_bytes(), Err(ParseError::Unwritable));
        contract::check_wire_value(&full);
    }

    // gitprotocol-v2, "fetch": deepen-since and deepen-not cannot be used
    // with deepen.
    #[test]
    fn fetch_deepen_combinations() {
        let fetch = |args: &[&str]| {
            Command { name: "fetch".into(), capabilities: vec![], args: args.iter().map(|a| a.to_string()).collect() }
                .fetch_args()
                .map(|_| ())
        };
        let both = Err(ParseError::Syntax("deepen without deepen-since or deepen-not"));
        assert_eq!(fetch(&["deepen 1", "deepen-since 1"]), both);
        assert_eq!(fetch(&["deepen-not refs/x", "deepen 2"]), both);
        assert_eq!(fetch(&["deepen-since 1", "deepen-not refs/x"]), Ok(()));
        assert_eq!(fetch(&["deepen 1", "deepen-relative"]), Ok(()));
    }

    fn check(data: &[u8]) {
        contract::check_decode_with_alloc_limit(Frames::new, data, 2 * MAX_PACKET);
        contract::check_decode_with_alloc_limit(|| Bands, data, 2 * MAX_PACKET);
        contract::check_wire::<Packet>(data);
        contract::check_wire::<ProtoRequest>(data);
        contract::check_wire::<ServiceHeader>(data);
        contract::check_wire::<Advertisement>(data);
        contract::check_wire::<CapabilityAdvertisement>(data);
        contract::check_wire::<V2Request>(data);
        // Bytes still buffered are handed over without changes, even after a bad packet.
        let mut stream = Stream::new(Frames::new());
        let pushed = stream.push(data);
        let mut used = 0;
        while let Some(Ok(packet)) = stream.next() {
            used += packet.to_bytes().unwrap().len();
        }
        let (buffer, _) = stream.into_parts();
        assert_eq!(buffer.unread(), &data[used..pushed]);
        for packet in decode_all(Frames::new, data).0 {
            if let Some(bytes) = packet.data() {
                contract::check_wire::<ClientLine>(bytes);
                contract::check_wire::<ServerLine>(bytes);
                contract::check_wire::<LsRef>(bytes);
                contract::check_wire::<LsRefsArg>(bytes);
                if let Ok(request) = ProtoRequest::from_data(bytes) {
                    assert!(request.to_bytes().is_ok(), "{request:?}");
                    contract::check_wire_value(&request);
                }
            }
        }
        if let Ok(V2Request::Command(command)) = V2Request::parse(data) {
            if let Ok(args) = command.fetch_args() {
                for arg in args {
                    assert!(arg.to_bytes().is_ok(), "{arg:?}");
                    contract::check_wire_value(&arg);
                }
            }
            if let Ok(args) = command.ls_refs_args() {
                for arg in args {
                    assert!(arg.to_bytes().is_ok(), "{arg:?}");
                    contract::check_wire_value(&arg);
                }
            }
        }
        let max = data.first().map_or(0, |b| usize::from(*b) * 300);
        let mut bytes = Vec::new();
        for packet in band_packets(Band::Pack, data, max) {
            packet.write(&mut bytes).unwrap();
        }
        let (items, failure) = decode_all(|| Bands, &bytes);
        assert_eq!(failure, None);
        let mut back = Vec::new();
        for item in items {
            let Demuxed::Data(Band::Pack, payload) = item else { panic!("unexpected band") };
            back.extend(payload);
        }
        assert_eq!(back, data);
    }

    #[test]
    fn generated_inputs_obey_contracts() {
        let pieces: Vec<Vec<u8>> = vec![
            b"0000".to_vec(),
            b"0001".to_vec(),
            b"0002".to_vec(),
            b"0003".to_vec(),
            b"0004".to_vec(),
            Packet::text("version 1").to_bytes().unwrap(),
            Packet::text("version 2").to_bytes().unwrap(),
            Packet::text(&format!("{A} HEAD\0ofs-delta agent=git/2 =x")).to_bytes().unwrap(),
            Packet::text(&format!("{} capabilities^{{}}\0side-band", "0".repeat(40))).to_bytes().unwrap(),
            Packet::text(&format!("{A} capabilities^{{}}\0thin-pack")).to_bytes().unwrap(),
            Packet::text(&format!("{} refs/heads/up", B.to_uppercase())).to_bytes().unwrap(),
            Packet::Data(b"git-upload-pack /x\0\0\0".to_vec()).to_bytes().unwrap(),
            Packet::text("command=").to_bytes().unwrap(),
            Packet::text("x.y=z").to_bytes().unwrap(),
            Packet::text(&format!("{B} refs/heads/a b")).to_bytes().unwrap(),
            Packet::text(&format!("shallow {B}")).to_bytes().unwrap(),
            Packet::text("command=ls-refs").to_bytes().unwrap(),
            Packet::text("command=fetch").to_bytes().unwrap(),
            Packet::text("agent=x y").to_bytes().unwrap(),
            Packet::text("symrefs").to_bytes().unwrap(),
            Packet::text("ref-prefix refs/").to_bytes().unwrap(),
            Packet::text(&format!("want {A} thin-pack")).to_bytes().unwrap(),
            Packet::text(&format!("have {B}")).to_bytes().unwrap(),
            Packet::text("done").to_bytes().unwrap(),
            Packet::text("deepen 12").to_bytes().unwrap(),
            Packet::text("deepen-since 99").to_bytes().unwrap(),
            Packet::text("filter blob:none").to_bytes().unwrap(),
            Packet::text("NAK").to_bytes().unwrap(),
            Packet::text(&format!("ACK {A} common")).to_bytes().unwrap(),
            Packet::text("ERR nope").to_bytes().unwrap(),
            Packet::text("packfile").to_bytes().unwrap(),
            Packet::text(&format!("unborn HEAD symref-target:refs/heads/main peeled:{B}")).to_bytes().unwrap(),
            Packet::text("# service=git-upload-pack").to_bytes().unwrap(),
            Packet::Data(b"git-upload-pack /x\0host=h\0\0version=2\0".to_vec()).to_bytes().unwrap(),
            band_packets(Band::Pack, b"PACK", 1000).next().unwrap().to_bytes().unwrap(),
            band_packets(Band::Progress, b"50%\r", 1000).next().unwrap().to_bytes().unwrap(),
            b"0006\x07x".to_vec(),
            b"0005\xff".to_vec(),
        ];
        let mut rng = Lcg::new(0x2545_f491_4f6c_dd1d);
        for _ in 0..4000 {
            let mut bytes = Vec::new();
            for _ in 0..rng.index(8) {
                if rng.coin() { bytes.extend(rng.bytes(12)); }
                else if rng.coin() {
                    let alphabet = b" \0\n=^{}abc0123";
                    let data = rng.text(20).bytes().map(|b| alphabet[usize::from(b) % alphabet.len()]).collect();
                    Packet::Data(data).write(&mut bytes).unwrap();
                } else {
                    let mut piece = pieces[rng.index(pieces.len())].clone();
                    mutate(&mut rng, &mut piece);
                    bytes.extend(piece);
                }
            }
            mutate(&mut rng, &mut bytes);
            check(&bytes);
        }
        // The pieces alone and in pairs.
        for a in &pieces {
            check(a);
            for b in &pieces {
                check(&[a.as_slice(), b].concat());
            }
        }
    }
}
