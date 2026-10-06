//! DTLS: reading and writing Datagram TLS records and handshake messages,
//! with no I/O and no cryptography.
//!
//! DTLS is TLS for datagrams. It secures CoAP on UDP port 5684, WebRTC
//! data channels, and VPNs that run over UDP port 443. Each UDP datagram
//! holds one or more records. This module follows RFC 6347 (DTLS 1.2) and
//! RFC 9147 (DTLS 1.3), and reads the connection ID record of RFC 9146.
//!
//! Records come with one of two headers. The 13-byte header of DTLS 1.0
//! and 1.2 ([`PlainRecord`]) carries a content type, a version, a 16-bit
//! epoch and a 48-bit sequence number. DTLS 1.3 also uses it for records
//! that are not protected, such as the first ClientHello. DTLS 1.3
//! protects every other record behind the unified header
//! ([`UnifiedRecord`]): one byte of flags, then an optional connection ID,
//! an 8-bit or 16-bit sequence number and an optional length. The first
//! byte tells the two apart.
//!
//! Handshake messages travel in records of type handshake, each behind a
//! 12-byte header that adds a message sequence number and a fragment
//! offset and length to the TLS header. A message bigger than a datagram is
//! split into [`Fragment`]s, which can arrive out of order, twice, or
//! overlapping. A [`Reassembler`] puts them back together into whole
//! [`Handshake`] messages and gives them out in order. [`Body`] reads the
//! messages that start a connection: [`ClientHello`], [`ServerHello`] and
//! the DTLS 1.2 cookie exchange's [`HelloVerifyRequest`]. Extensions stay
//! as numbered bytes ([`Extension`]).
//!
//! Nothing here reads a socket or decrypts anything. A world that plays a
//! DTLS server takes each datagram it receives, reads it with
//! [`Datagram::parse`], passes handshake fragments to a [`Reassembler`] and
//! decides what to answer. Protected records keep their bytes as they
//! came; keys and ciphers are up to world code.
//!
//! Every reader checks lengths and ranges, because the agent can send any
//! bytes it likes. Writers refuse values that would change. The bytes they write
//! always read back.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::dtls::{
//!     Body, ClientHello, ContentType, Fragment, Handshake, HelloVerifyRequest, PlainRecord, Reassembler, Record,
//!     handshake_type, Datagram, Fragments, version,
//! };
//!
//! // A client's first ClientHello, with no cookie yet.
//! let hello = ClientHello {
//!     version: version::DTLS_1_2,
//!     random: [1; 32],
//!     session_id: vec![],
//!     cookie: vec![],
//!     cipher_suites: vec![0xc02b],
//!     compression_methods: vec![0],
//!     extensions: None,
//! };
//! let message = Handshake { msg_type: handshake_type::CLIENT_HELLO, message_seq: 0, body: hello.to_bytes().unwrap() };
//! let record = PlainRecord {
//!     content_type: ContentType::HANDSHAKE,
//!     version: version::DTLS_1_0,
//!     epoch: 0,
//!     sequence: 0,
//!     connection_id: vec![],
//!     fragment: message.to_bytes().unwrap(),
//! };
//! let datagram = Record::<0>::Plain(record).to_bytes().unwrap();
//! // A 13-byte record header, a 12-byte handshake header, a 42-byte body.
//! assert_eq!(datagram.len(), 13 + 12 + 42);
//!
//! // The server reads the datagram and puts the message back together.
//! let records = Datagram::<0>::parse(&datagram).unwrap().0;
//! let Record::Plain(record) = &records[0] else { panic!("a plain record") };
//! assert_eq!(record.content_type, ContentType::HANDSHAKE);
//! let mut reassembler = Reassembler::new();
//! for fragment in Fragments::parse(&record.fragment).unwrap().0 {
//!     reassembler.add(&fragment).unwrap();
//! }
//! let got = reassembler.next_message().unwrap();
//! let Ok(Body::ClientHello(read)) = got.parse_body() else { panic!("a ClientHello") };
//! assert_eq!(read, hello);
//!
//! // It has no cookie, so the server asks for one.
//! let ask = HelloVerifyRequest { version: version::DTLS_1_0, cookie: vec![0xaa; 16] };
//! let reply = Handshake { msg_type: handshake_type::HELLO_VERIFY_REQUEST, message_seq: 0, body: ask.to_bytes().unwrap() };
//! let Ok(Body::HelloVerifyRequest(back)) = reply.parse_body() else { panic!("a HelloVerifyRequest") };
//! assert_eq!(back.cookie, [0xaa; 16]);
//! ```

extern crate self as fictionet;
use fictionet::stdlib::codec::Wire;

/// The UDP port CoAP over DTLS listens on.
pub const COAPS_PORT: u16 = 5684;
/// The UDP port VPNs that run over DTLS often listen on, shared with HTTPS.
pub const VPN_PORT: u16 = 443;

/// The length of the DTLS 1.0 and 1.2 record header, without a connection
/// ID.
pub const RECORD_HEADER_LEN: usize = 13;
/// The length of a handshake message's header.
pub const HANDSHAKE_HEADER_LEN: usize = 12;
/// The most bytes a record with the 13-byte header may carry past epoch 0:
/// 2^14 plus 2048, the DTLS 1.2 limit for protected records.
pub const MAX_PLAIN_FRAGMENT: usize = 16384 + 2048;
/// The most bytes a record in epoch 0, which is not protected, may carry:
/// 2^14 (RFC 6347, section 4.1).
pub const MAX_PLAINTEXT: usize = 16384;
/// The most bytes a record with the unified header may carry: 2^14 plus
/// 256, the DTLS 1.3 limit.
pub const MAX_UNIFIED_PAYLOAD: usize = 16384 + 256;
/// The longest connection ID.
pub const MAX_CID_LEN: usize = 255;
/// The largest 48-bit sequence number a 13-byte header can carry.
pub const MAX_SEQUENCE: u64 = (1 << 48) - 1;
/// The most records [`Datagram::parse`] reads from one datagram.
pub const MAX_RECORDS_PER_DATAGRAM: usize = 256;
/// The most handshake fragments [`Fragments::parse`] reads from one
/// record.
pub const MAX_FRAGMENTS_PER_RECORD: usize = 2048;
/// The longest handshake message this module reads or writes. The header
/// allows up to 2^24 - 1 bytes, but a hello is far smaller, and this bounds
/// what a [`Reassembler`] holds.
pub const MAX_MESSAGE_LEN: usize = 1 << 18;
/// How far past the next expected message sequence number a
/// [`Reassembler`] keeps fragments.
pub const MAX_PENDING_MESSAGES: u16 = 8;
/// The most separate byte ranges a [`Reassembler`] holds for one message
/// before it is whole.
pub const MAX_FRAGMENT_RANGES: usize = 64;
/// The most bytes a [`Reassembler`] holds across all messages not yet given
/// out.
pub const MAX_REASSEMBLY_BYTES: usize = 1 << 20;
/// The length of a hello's random value.
pub const RANDOM_LEN: usize = 32;
/// The longest session ID.
pub const MAX_SESSION_ID: usize = 32;
/// The longest cookie.
pub const MAX_COOKIE: usize = 255;
/// The most cipher suites a ClientHello can list.
pub const MAX_CIPHER_SUITES: usize = 32767;
/// The most compression methods a ClientHello can list.
pub const MAX_COMPRESSION_METHODS: usize = 255;
/// The most bytes a hello's extension block may hold.
pub const MAX_EXTENSIONS_LEN: usize = 65535;

/// The random value of a DTLS 1.3 ServerHello that is a HelloRetryRequest:
/// the SHA-256 hash of "HelloRetryRequest" (RFC 8446, section 4.1.3).
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11,
    0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Protocol versions as they appear on the wire. DTLS counts down from
/// 0xfeff.
pub mod version {
    /// DTLS 1.0, also used in the record header of a first ClientHello.
    pub const DTLS_1_0: u16 = 0xfeff;
    /// DTLS 1.2, also the record version of every DTLS 1.3 record.
    pub const DTLS_1_2: u16 = 0xfefd;
    /// DTLS 1.3, found only in the supported_versions extension.
    pub const DTLS_1_3: u16 = 0xfefc;
}

/// Handshake message types.
pub mod handshake_type {
    /// Asks a DTLS 1.2 client to start a new handshake.
    pub const HELLO_REQUEST: u8 = 0;
    /// The client's first message, and its answer to a cookie request.
    pub const CLIENT_HELLO: u8 = 1;
    /// The server's answer to a ClientHello, or a DTLS 1.3 HelloRetryRequest.
    pub const SERVER_HELLO: u8 = 2;
    /// A DTLS 1.2 server's request for a cookie.
    pub const HELLO_VERIFY_REQUEST: u8 = 3;
    /// A ticket the client can use to resume the session.
    pub const NEW_SESSION_TICKET: u8 = 4;
    /// Ends a TLS 1.3 client's early data. DTLS 1.3 does not use it.
    pub const END_OF_EARLY_DATA: u8 = 5;
    /// The DTLS 1.3 server's protected extensions.
    pub const ENCRYPTED_EXTENSIONS: u8 = 8;
    /// Asks the peer for more connection IDs (DTLS 1.3).
    pub const REQUEST_CONNECTION_ID: u8 = 9;
    /// Gives the peer more connection IDs (DTLS 1.3).
    pub const NEW_CONNECTION_ID: u8 = 10;
    /// A certificate chain.
    pub const CERTIFICATE: u8 = 11;
    /// The DTLS 1.2 server's key exchange values.
    pub const SERVER_KEY_EXCHANGE: u8 = 12;
    /// Asks the client for a certificate.
    pub const CERTIFICATE_REQUEST: u8 = 13;
    /// Ends the DTLS 1.2 server's first flight.
    pub const SERVER_HELLO_DONE: u8 = 14;
    /// A signature over the handshake so far.
    pub const CERTIFICATE_VERIFY: u8 = 15;
    /// The DTLS 1.2 client's key exchange values.
    pub const CLIENT_KEY_EXCHANGE: u8 = 16;
    /// A MAC over the handshake, which ends it.
    pub const FINISHED: u8 = 20;
    /// Says the sender changed its keys (DTLS 1.3).
    pub const KEY_UPDATE: u8 = 24;
    /// Stands for a hashed ClientHello in the DTLS 1.3 transcript.
    pub const MESSAGE_HASH: u8 = 254;
}

/// Extension type numbers seen in DTLS hellos.
pub mod extension_type {
    /// The host name the client wants (server_name).
    pub const SERVER_NAME: u16 = 0;
    /// The key exchange groups the client supports.
    pub const SUPPORTED_GROUPS: u16 = 10;
    /// The elliptic curve point formats the client supports.
    pub const EC_POINT_FORMATS: u16 = 11;
    /// The signature algorithms the sender accepts.
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    /// SRTP keying for media, as WebRTC uses (RFC 5764).
    pub const USE_SRTP: u16 = 14;
    /// The application protocols offered or chosen (ALPN).
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: u16 = 16;
    /// Asks for encrypt-then-MAC in DTLS 1.2 (RFC 7366).
    pub const ENCRYPT_THEN_MAC: u16 = 22;
    /// Asks for the extended master secret (RFC 7627).
    pub const EXTENDED_MASTER_SECRET: u16 = 23;
    /// A DTLS 1.2 session ticket (RFC 5077).
    pub const SESSION_TICKET: u16 = 35;
    /// The pre-shared keys offered or chosen.
    pub const PRE_SHARED_KEY: u16 = 41;
    /// Says early data is sent or allowed.
    pub const EARLY_DATA: u16 = 42;
    /// The versions offered, or the one chosen.
    pub const SUPPORTED_VERSIONS: u16 = 43;
    /// A DTLS 1.3 HelloRetryRequest's cookie, echoed by the client.
    pub const COOKIE: u16 = 44;
    /// The ways the client can use a pre-shared key.
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 45;
    /// Key exchange values for DTLS 1.3.
    pub const KEY_SHARE: u16 = 51;
    /// The connection ID the sender wants to receive (RFC 9146).
    pub const CONNECTION_ID: u16 = 54;
    /// Binds a DTLS 1.2 renegotiation to the connection (RFC 5746).
    pub const RENEGOTIATION_INFO: u16 = 0xff01;
}

/// The bits of a unified header's first byte (RFC 9147, section 4).
pub mod unified_bits {
    /// The three top bits, which hold [`FIXED`] in every unified header.
    pub const FIXED_MASK: u8 = 0xe0;
    /// The value of the three top bits: 001.
    pub const FIXED: u8 = 0x20;
    /// Set when a connection ID follows the first byte.
    pub const CID: u8 = 0x10;
    /// Set when the sequence number is 16 bits, clear when it is 8.
    pub const SEQ16: u8 = 0x08;
    /// Set when a 16-bit length follows the sequence number.
    pub const LENGTH: u8 = 0x04;
    /// The low two bits of the epoch.
    pub const EPOCH_MASK: u8 = 0x03;
}

/// The content type of a record with the 13-byte header. It always lies in
/// 20 to 31, so every value can be written and read back. RFC 7983 gives
/// DTLS the first bytes 20 to 63, and RFC 9147 reserves 32 to 63 for the
/// unified header, which leaves 20 to 31 for content types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentType(u8);

impl ContentType {
    /// The lowest content type a 13-byte header may carry.
    pub const MIN: u8 = 20;
    /// The highest content type a 13-byte header may carry. Bytes from 32
    /// to 63 start a unified header instead.
    pub const MAX: u8 = 31;
    /// Says the next records use the keys just agreed (DTLS 1.2).
    pub const CHANGE_CIPHER_SPEC: ContentType = ContentType(20);
    /// An alert: a warning or a fatal error.
    pub const ALERT: ContentType = ContentType(21);
    /// Handshake fragments.
    pub const HANDSHAKE: ContentType = ContentType(22);
    /// Application data, protected.
    pub const APPLICATION_DATA: ContentType = ContentType(23);
    /// A heartbeat message (RFC 6520).
    pub const HEARTBEAT: ContentType = ContentType(24);
    /// A DTLS 1.2 record with a connection ID (RFC 9146).
    pub const TLS12_CID: ContentType = ContentType(25);
    /// A DTLS 1.3 acknowledgment.
    pub const ACK: ContentType = ContentType(26);

    /// The content type with number `n`, if it lies in 20 to 31.
    pub fn new(n: u8) -> Option<ContentType> {
        if (Self::MIN..=Self::MAX).contains(&n) { Some(ContentType(n)) } else { None }
    }

    /// The content type's number.
    pub fn get(self) -> u8 {
        self.0
    }
}

/// A record with the 13-byte header of DTLS 1.0 and 1.2, which DTLS 1.3
/// also uses for records that are not protected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlainRecord {
    /// What the record carries.
    pub content_type: ContentType,
    /// The record version, such as [`version::DTLS_1_2`]. Readers do not
    /// check it; that is up to world code.
    pub version: u16,
    /// Counts the times the keys have changed, starting at 0.
    pub epoch: u16,
    /// The record's sequence number within its epoch. Values above 48 bits are refused.
    pub sequence: u64,
    /// The connection ID. Only records of type [`ContentType::TLS12_CID`]
    /// carry one. Other types refuse a nonempty ID. Its length is not on
    /// the wire. The writer refuses a length different from `CID_LEN`,
    /// whose maximum is [`MAX_CID_LEN`].
    pub connection_id: Vec<u8>,
    /// The record's payload: plaintext in epoch 0, and protected bytes
    /// after that. The writer refuses more than [`MAX_PLAINTEXT`] bytes in
    /// epoch 0, or more than [`MAX_PLAIN_FRAGMENT`] after it.
    pub fragment: Vec<u8>,
}

/// A unified header's sequence number, which is 8 or 16 bits on the wire.
/// Both are the low bits of the full sequence number, which are encrypted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sequence {
    /// The low 8 bits.
    Short(u8),
    /// The low 16 bits.
    Long(u16),
}

impl Sequence {
    /// The bits on the wire, widened to 16 bits.
    pub fn value(self) -> u16 {
        match self {
            Sequence::Short(s) => u16::from(s),
            Sequence::Long(s) => s,
        }
    }
}

/// A DTLS 1.3 record behind the unified header. Its sequence number is
/// encrypted, and so is its payload. Both stay as bytes here. RFC 9147
/// has receivers drop a protected record whose payload is shorter than 16
/// bytes, since the sequence number mask needs 16; readers here take any
/// length, and world code that removes the mask checks it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnifiedRecord {
    /// The low two bits of the epoch. The writer refuses values above 3.
    pub epoch_bits: u8,
    /// The connection ID, if the header carries one. Its length is not on
    /// the wire. Readers use the `CID_LEN` const parameter. The writer
    /// refuses a length different from `CID_LEN` or above [`MAX_CID_LEN`].
    pub connection_id: Option<Vec<u8>>,
    /// The sequence number's low bits.
    pub sequence: Sequence,
    /// Whether the header has a length. A record without one runs to the
    /// end of the datagram.
    pub has_length: bool,
    /// The protected payload. The writer refuses more than
    /// [`MAX_UNIFIED_PAYLOAD`] bytes.
    pub payload: Vec<u8>,
}

/// One DTLS record, with either header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record<const CID_LEN: u8 = 0> {
    /// A record with the 13-byte header.
    Plain(PlainRecord),
    /// A DTLS 1.3 record with the unified header.
    Unified(UnifiedRecord),
}

/// Why bytes are not a DTLS record. A receiver drops the rest of the
/// datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// Bytes follow the complete record.
    Trailing,

    /// The value cannot be written without changing it.
    Unwritable,
    /// There were no bytes.
    Empty,
    /// The first byte starts neither header: it is not a content type from
    /// 20 to 31, and its top three bits are not 001.
    ContentType(u8),
    /// The bytes end inside the record.
    Truncated,
    /// The record's length is more than its header allows: more than
    /// [`MAX_PLAINTEXT`] in epoch 0, [`MAX_PLAIN_FRAGMENT`] in a later
    /// epoch, or [`MAX_UNIFIED_PAYLOAD`] behind the unified header.
    Length(usize),
    /// The datagram holds more than [`MAX_RECORDS_PER_DATAGRAM`] records.
    TooManyRecords,
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordError::Trailing => f.write_str("bytes after the record"),
            RecordError::Unwritable => f.write_str("value cannot be written without changing it"),
            RecordError::Empty => write!(f, "no bytes"),
            RecordError::ContentType(t) => write!(f, "first byte {t} starts no DTLS record"),
            RecordError::Truncated => write!(f, "the bytes end inside a record"),
            RecordError::Length(n) => write!(f, "record length {n} is over the limit"),
            RecordError::TooManyRecords => write!(f, "more than {MAX_RECORDS_PER_DATAGRAM} records in a datagram"),
        }
    }
}

impl std::error::Error for RecordError {}

impl<const CID_LEN: u8> Record<CID_LEN> {
    /// Reads the record at the start of `b` and says how many bytes it
    /// took. `CID_LEN` is the length of the connection IDs this end
    /// chose, 0 if it uses none. A unified header without a length takes
    /// every byte left.
    fn parse_prefix(b: &[u8]) -> Result<(Self, usize), RecordError> {
        let Some(&first) = b.first() else { return Err(RecordError::Empty) };
        let mut r = Reader::new(b);
        if first & unified_bits::FIXED_MASK == unified_bits::FIXED {
            r.u8()?;
            let connection_id =
                if first & unified_bits::CID != 0 { Some(r.take(usize::from(CID_LEN))?.to_vec()) } else { None };
            let sequence =
                if first & unified_bits::SEQ16 != 0 { Sequence::Long(r.u16()?) } else { Sequence::Short(r.u8()?) };
            let has_length = first & unified_bits::LENGTH != 0;
            let payload = if has_length {
                let len = usize::from(r.u16()?);
                if len > MAX_UNIFIED_PAYLOAD {
                    return Err(RecordError::Length(len));
                }
                r.take(len)?
            } else {
                let rest = r.rest();
                if rest.len() > MAX_UNIFIED_PAYLOAD {
                    return Err(RecordError::Length(rest.len()));
                }
                rest
            };
            let record = UnifiedRecord {
                epoch_bits: first & unified_bits::EPOCH_MASK,
                connection_id,
                sequence,
                has_length,
                payload: payload.to_vec(),
            };
            return Ok((Record::Unified(record), r.at));
        }
        let Some(content_type) = ContentType::new(first) else { return Err(RecordError::ContentType(first)) };
        r.u8()?;
        let version = r.u16()?;
        let epoch = r.u16()?;
        let sequence = r.u48()?;
        let connection_id =
            if content_type == ContentType::TLS12_CID { r.take(usize::from(CID_LEN))?.to_vec() } else { Vec::new() };
        let len = usize::from(r.u16()?);
        if len > plain_limit(epoch) {
            return Err(RecordError::Length(len));
        }
        let fragment = r.take(len)?.to_vec();
        let record = PlainRecord { content_type, version, epoch, sequence, connection_id, fragment };
        Ok((Record::Plain(record), r.at))
    }
}

/// Records carried by one datagram, with the session's connection ID length.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Datagram<const CID_LEN: u8 = 0>(
    /// Records in datagram order.
    pub Vec<Record<CID_LEN>>,
);

impl<const CID_LEN: u8> Wire for Datagram<CID_LEN> {
    type ParseError = RecordError;
    type WriteError = RecordError;

    /// Reads all records. Refuses malformed records and more than the named record limit.
    fn parse(b: &[u8]) -> Result<Self, RecordError> {
        let mut records = Vec::new();
        let mut at = 0;
        while at < b.len() {
            if records.len() == MAX_RECORDS_PER_DATAGRAM { return Err(RecordError::TooManyRecords); }
            let (record, used) = Record::<CID_LEN>::parse_prefix(&b[at..])?;
            records.push(record);
            at += used;
        }
        Ok(Self(records))
    }

    /// Appends every record. Refuses mismatched IDs, oversized fields and a record after an open unified record.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), RecordError> {
        if self.0.len() > MAX_RECORDS_PER_DATAGRAM { return Err(RecordError::Unwritable); }
        let mut out = Vec::new();
        for (i, record) in self.0.iter().enumerate() {
            if matches!(record, Record::Unified(u) if !u.has_length) && i + 1 != self.0.len() {
                return Err(RecordError::Unwritable);
            }
            record.write(&mut out)?;
        }
        commit_record(dst, &out)
    }
}

/// The most bytes a record with the 13-byte header carries in `epoch`.
fn plain_limit(epoch: u16) -> usize {
    if epoch == 0 { MAX_PLAINTEXT } else { MAX_PLAIN_FRAGMENT }
}

/// Why bytes are not a handshake fragment or the body of a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeError {
    /// The value cannot be written without changing it.
    Unwritable,
    /// The bytes end inside a field.
    Truncated,
    /// The message length is more than [`MAX_MESSAGE_LEN`].
    TooLong(u32),
    /// The fragment's offset plus its length is past the message's end.
    FragmentRange,
    /// A record holds more than [`MAX_FRAGMENTS_PER_RECORD`] fragments.
    TooManyFragments,
    /// Bytes are left over after the last field of a body.
    Trailing,
    /// The session ID is longer than [`MAX_SESSION_ID`] bytes.
    SessionId(usize),
    /// The cipher suite list is empty or has an odd number of bytes.
    CipherSuites,
    /// The compression method list is empty.
    CompressionMethods,
    /// An extension runs past the end of the extension block.
    Extensions,
    /// Two extensions in one hello have this type.
    DuplicateExtension(u16),
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Unwritable => f.write_str("value cannot be written without changing it"),
            HandshakeError::Truncated => write!(f, "the bytes end inside a field"),
            HandshakeError::TooLong(n) => write!(f, "message length {n} is over {MAX_MESSAGE_LEN}"),
            HandshakeError::FragmentRange => write!(f, "the fragment runs past the end of its message"),
            HandshakeError::TooManyFragments => write!(f, "more than {MAX_FRAGMENTS_PER_RECORD} fragments in a record"),
            HandshakeError::Trailing => write!(f, "bytes left after the body"),
            HandshakeError::SessionId(n) => write!(f, "session ID of {n} bytes, over {MAX_SESSION_ID}"),
            HandshakeError::CipherSuites => write!(f, "cipher suite list empty or of an odd length"),
            HandshakeError::CompressionMethods => write!(f, "compression method list empty"),
            HandshakeError::Extensions => write!(f, "an extension runs past the extension block"),
            HandshakeError::DuplicateExtension(t) => write!(f, "two extensions of type {t}"),
        }
    }
}

impl std::error::Error for HandshakeError {}

/// One fragment of a handshake message: the 12-byte header and the bytes
/// it carries. A message small enough for one record is sent as a single
/// fragment that covers all of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment {
    /// The message type, from [`handshake_type`].
    pub msg_type: u8,
    /// The length of the whole message. At most [`MAX_MESSAGE_LEN`] is
    /// written.
    pub length: u32,
    /// The message's place in the handshake, counting from 0 for each side.
    pub message_seq: u16,
    /// Where this fragment's bytes start in the message.
    pub offset: u32,
    /// The bytes. The writer refuses bytes past the declared message end.
    pub body: Vec<u8>,
}

impl Fragment {
    /// Reads the fragment at the start of `b` and says how many bytes it
    /// took.
    fn parse_prefix(b: &[u8]) -> Result<(Fragment, usize), HandshakeError> {
        let mut r = Reader::new(b);
        let msg_type = r.u8()?;
        let length = r.u24()?;
        let message_seq = r.u16()?;
        let offset = r.u24()?;
        let fragment_length = r.u24()?;
        if length as usize > MAX_MESSAGE_LEN {
            return Err(HandshakeError::TooLong(length));
        }
        if u64::from(offset) + u64::from(fragment_length) > u64::from(length) {
            return Err(HandshakeError::FragmentRange);
        }
        let body = r.take(fragment_length as usize)?.to_vec();
        Ok((Fragment { msg_type, length, message_seq, offset, body }, r.at))
    }

    /// Whether this fragment covers its whole message.
    pub fn is_whole(&self) -> bool {
        self.offset == 0 && self.body.len() == self.length as usize
    }
}

/// A whole handshake message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handshake {
    /// The message type, from [`handshake_type`].
    pub msg_type: u8,
    /// The message's place in the handshake.
    pub message_seq: u16,
    /// The message body. The writer refuses more than [`MAX_MESSAGE_LEN`] bytes.
    pub body: Vec<u8>,
}

impl Handshake {
    /// One fragment that covers the whole message.
    pub fn to_fragment(&self) -> Result<Fragment, HandshakeError> {
        if self.body.len() > MAX_MESSAGE_LEN { return Err(HandshakeError::Unwritable); }
        let body = &self.body;
        Ok(Fragment {
            msg_type: self.msg_type,
            length: body.len() as u32,
            message_seq: self.message_seq,
            offset: 0,
            body: body.to_vec(),
        })
    }

    /// The message split into fragments of at most `max_body` bytes each, in
    /// order. A `max_body` of 0 counts as 1. An empty message is one empty
    /// fragment.
    pub fn fragments(&self, max_body: usize) -> Result<Vec<Fragment>, HandshakeError> {
        if self.body.len() > MAX_MESSAGE_LEN { return Err(HandshakeError::Unwritable); }
        let body = &self.body;
        if body.is_empty() {
            return Ok(vec![self.to_fragment()?]);
        }
        let step = max_body.clamp(1, MAX_MESSAGE_LEN);
        Ok(body.chunks(step)
            .enumerate()
            .map(|(i, chunk)| Fragment {
                msg_type: self.msg_type,
                length: body.len() as u32,
                message_seq: self.message_seq,
                offset: (i * step) as u32,
                body: chunk.to_vec(),
            })
            .collect())
    }

    /// Reads the body, for the message types this module knows.
    pub fn parse_body(&self) -> Result<Body, HandshakeError> {
        match self.msg_type {
            handshake_type::CLIENT_HELLO => ClientHello::parse(&self.body).map(Body::ClientHello),
            handshake_type::SERVER_HELLO => ServerHello::parse(&self.body).map(Body::ServerHello),
            handshake_type::HELLO_VERIFY_REQUEST => HelloVerifyRequest::parse(&self.body).map(Body::HelloVerifyRequest),
            other => Ok(Body::Other(other)),
        }
    }
}

/// A handshake message's body, read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    /// A ClientHello.
    ClientHello(ClientHello),
    /// A ServerHello, or a DTLS 1.3 HelloRetryRequest.
    ServerHello(ServerHello),
    /// A DTLS 1.2 HelloVerifyRequest.
    HelloVerifyRequest(HelloVerifyRequest),
    /// A message of this type, which this module does not read. Its body
    /// stays in the [`Handshake`].
    Other(u8),
}

/// One hello extension, kept by its type number with its bytes unread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    /// The extension's type, from [`extension_type`].
    pub typ: u16,
    /// The extension's bytes.
    pub data: Vec<u8>,
}

/// A ClientHello body, in the DTLS 1.2 form. DTLS 1.3 keeps the same
/// layout and offers its own version in the supported_versions extension.
///
/// Readers insist on what the format does: at least one cipher suite and
/// one compression method, and no two extensions of one type. What
/// depends on the version the server picks is up to world code: RFC 5246
/// has the compression methods include 0, and a server that picks DTLS
/// 1.3 aborts on a cookie that is not empty (RFC 9147, section 5.3) or
/// compression methods other than exactly 0 (RFC 8446, section 4.1.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHello {
    /// The highest version the client offers, or [`version::DTLS_1_2`] in
    /// DTLS 1.3.
    pub version: u16,
    /// The client's random value.
    pub random: [u8; RANDOM_LEN],
    /// A session to resume. The writer refuses more than [`MAX_SESSION_ID`] bytes.
    pub session_id: Vec<u8>,
    /// The cookie from a HelloVerifyRequest, or empty. The writer refuses
    /// more than [`MAX_COOKIE`] bytes.
    pub cookie: Vec<u8>,
    /// The cipher suites offered, by number, in order of preference. The
    /// writer refuses an empty list or more than [`MAX_CIPHER_SUITES`].
    pub cipher_suites: Vec<u16>,
    /// The compression methods offered. 0 is none. The writer refuses an
    /// empty list or more than [`MAX_COMPRESSION_METHODS`].
    pub compression_methods: Vec<u8>,
    /// The extensions, or None if their length field is absent.
    /// Writers refuse duplicate types and blocks above [`MAX_EXTENSIONS_LEN`].
    pub extensions: Option<Vec<Extension>>,
}

impl ClientHello {
    /// The bytes of the first extension of type `typ`.
    pub fn extension(&self, typ: u16) -> Option<&[u8]> {
        find_extension(self.extensions.as_deref(), typ)
    }

    /// The versions listed in the supported_versions extension, or `None`
    /// if there is none or it is malformed. RFC 8446 requires one version
    /// at least, so an empty list is malformed.
    pub fn supported_versions(&self) -> Option<Vec<u16>> {
        let data = self.extension(extension_type::SUPPORTED_VERSIONS)?;
        let (&n, list) = data.split_first()?;
        if n < 2 || usize::from(n) != list.len() || !n.is_multiple_of(2) {
            return None;
        }
        Some(list.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect())
    }
}

/// A ServerHello body. In DTLS 1.3 a ServerHello whose random is
/// [`HELLO_RETRY_REQUEST_RANDOM`] is a HelloRetryRequest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerHello {
    /// The version chosen, or [`version::DTLS_1_2`] in DTLS 1.3.
    pub version: u16,
    /// The server's random value.
    pub random: [u8; RANDOM_LEN],
    /// The session ID. In DTLS 1.3 it is empty: unlike TLS 1.3, a DTLS 1.3
    /// server must not echo the client's (RFC 9147, section 5). The writer
    /// refuses more than [`MAX_SESSION_ID`] bytes.
    pub session_id: Vec<u8>,
    /// The cipher suite chosen.
    pub cipher_suite: u16,
    /// The compression method chosen.
    pub compression_method: u8,
    /// The extensions, or None if their length field is absent.
    /// Writers refuse duplicate types and blocks above [`MAX_EXTENSIONS_LEN`].
    pub extensions: Option<Vec<Extension>>,
}

impl ServerHello {
    /// The bytes of the first extension of type `typ`.
    pub fn extension(&self, typ: u16) -> Option<&[u8]> {
        find_extension(self.extensions.as_deref(), typ)
    }

    /// The version in the supported_versions extension, which a DTLS 1.3
    /// server uses to say it chose DTLS 1.3.
    pub fn selected_version(&self) -> Option<u16> {
        match self.extension(extension_type::SUPPORTED_VERSIONS)? {
            &[a, b] => Some(u16::from_be_bytes([a, b])),
            _ => None,
        }
    }

    /// Whether this is a DTLS 1.3 HelloRetryRequest.
    pub fn is_hello_retry_request(&self) -> bool {
        self.random == HELLO_RETRY_REQUEST_RANDOM
    }
}

/// A DTLS 1.2 HelloVerifyRequest body: the server's answer to a
/// ClientHello without the right cookie. The client sends its ClientHello
/// again with this cookie, which shows it can receive at its address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelloVerifyRequest {
    /// The server version. RFC 6347 has servers send
    /// [`version::DTLS_1_0`] here.
    pub version: u16,
    /// The cookie. The writer refuses more than [`MAX_COOKIE`] bytes.
    pub cookie: Vec<u8>,
}

/// Why a [`Reassembler`] did not take a fragment. None of these break it:
/// it holds what it held before, and later fragments are taken as usual.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReassemblyError {
    /// The fragment's own fields disagree: its length is over
    /// [`MAX_MESSAGE_LEN`], or its bytes run past that length.
    Invalid,
    /// Earlier fragments of the same message gave a different type or
    /// length.
    Conflict,
    /// The message sequence number is [`MAX_PENDING_MESSAGES`] or more past
    /// the next one expected.
    Window(u16),
    /// The message would be in more than [`MAX_FRAGMENT_RANGES`] separate
    /// pieces.
    TooManyRanges,
    /// Holding the message would take more than [`MAX_REASSEMBLY_BYTES`].
    /// The next message expected never gets this: messages after it are
    /// dropped to make room, and the peer sends them again when it
    /// retransmits its flight.
    Memory,
}

impl std::fmt::Display for ReassemblyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReassemblyError::Invalid => write!(f, "the fragment's fields disagree"),
            ReassemblyError::Conflict => write!(f, "the fragment disagrees with earlier ones of its message"),
            ReassemblyError::Window(s) => write!(f, "message sequence {s} is too far ahead"),
            ReassemblyError::TooManyRanges => write!(f, "more than {MAX_FRAGMENT_RANGES} pieces of one message"),
            ReassemblyError::Memory => write!(f, "more than {MAX_REASSEMBLY_BYTES} bytes held"),
        }
    }
}

impl std::error::Error for ReassemblyError {}

/// What a [`Reassembler`] did with a fragment it took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Added {
    /// The fragment brought bytes the reassembler did not hold.
    New,
    /// The reassembler already held all of it, or already gave out its
    /// message. A peer that sends this is retransmitting, which often means
    /// it missed the last flight sent to it.
    Repeat,
}

/// One message being put back together.
#[derive(Clone, Debug)]
struct Partial {
    msg_type: u8,
    message_seq: u16,
    data: Vec<u8>,
    /// The byte ranges held, sorted, not touching each other.
    ranges: Vec<(usize, usize)>,
}

impl Partial {
    fn is_whole(&self) -> bool {
        self.data.is_empty() || self.ranges == [(0, self.data.len())]
    }
}

/// Puts handshake fragments back together into whole messages, and gives
/// them out in message sequence order. Pass every handshake fragment
/// the peer sends, in any order and with repeats. It can be cloned, so world
/// code can try a fragment on a copy.
#[derive(Clone, Debug, Default)]
pub struct Reassembler {
    next_seq: u16,
    pending: Vec<Partial>,
    held: usize,
}

impl Reassembler {
    /// A reassembler that expects message 0 first.
    pub fn new() -> Reassembler {
        Reassembler::default()
    }

    /// A reassembler that expects message `seq` first. A DTLS 1.2 server
    /// that answered with a HelloVerifyRequest expects message 1 next.
    pub fn starting_at(seq: u16) -> Reassembler {
        Reassembler { next_seq: seq, ..Reassembler::default() }
    }

    /// The message sequence number of the next message to be given out.
    pub fn next_seq(&self) -> u16 {
        self.next_seq
    }

    /// How many bytes are held for messages not yet given out.
    pub fn buffered(&self) -> usize {
        self.held
    }

    /// Takes a fragment. Fragments of messages already given out are
    /// [`Added::Repeat`], as are bytes already held and empty fragments of a
    /// message that is not empty. Where a fragment
    /// overlaps bytes already held, the bytes held stay and the fragment's
    /// copy of them is dropped, so a repeat with other bytes changes
    /// nothing. Messages past the next one expected give way to it when
    /// the bytes held would go over [`MAX_REASSEMBLY_BYTES`].
    pub fn add(&mut self, f: &Fragment) -> Result<Added, ReassemblyError> {
        let length = f.length as usize;
        if length > MAX_MESSAGE_LEN {
            return Err(ReassemblyError::Invalid);
        }
        let start = f.offset as usize;
        let end = match start.checked_add(f.body.len()) {
            Some(end) if end <= length => end,
            _ => return Err(ReassemblyError::Invalid),
        };
        let ahead = f.message_seq.wrapping_sub(self.next_seq);
        if ahead >= 0x8000 {
            return Ok(Added::Repeat);
        }
        if ahead >= MAX_PENDING_MESSAGES {
            return Err(ReassemblyError::Window(f.message_seq));
        }
        let found = self.pending.iter().position(|p| p.message_seq == f.message_seq);
        let ranges = match found {
            Some(i) => {
                let p = &self.pending[i];
                if p.msg_type != f.msg_type || p.data.len() != length {
                    return Err(ReassemblyError::Conflict);
                }
                if start == end || p.ranges.iter().any(|&(a, b)| a <= start && end <= b) {
                    return Ok(Added::Repeat);
                }
                merged(&p.ranges, start, end)
            }
            // An empty piece of a message not yet seen brings nothing to hold.
            None if start == end && length > 0 => return Ok(Added::Repeat),
            None => {
                if self.held.saturating_add(length) > MAX_REASSEMBLY_BYTES {
                    if ahead != 0 {
                        return Err(ReassemblyError::Memory);
                    }
                    self.make_room(length);
                }
                if start == end { Vec::new() } else { vec![(start, end)] }
            }
        };
        if ranges.len() > MAX_FRAGMENT_RANGES {
            return Err(ReassemblyError::TooManyRanges);
        }
        let i = match found {
            Some(i) => i,
            None => {
                self.held += length;
                self.pending.push(Partial {
                    msg_type: f.msg_type,
                    message_seq: f.message_seq,
                    data: vec![0; length],
                    ranges: Vec::new(),
                });
                self.pending.len() - 1
            }
        };
        let p = &mut self.pending[i];
        // Copy only into the gaps, so bytes already held stay as they came.
        // The sentinel range at `end` fills the last gap.
        let mut at = start;
        for &(a, b) in p.ranges.iter().chain(std::iter::once(&(end, end))) {
            if at >= end {
                break;
            }
            if b <= at {
                continue;
            }
            let gap_end = a.min(end);
            if gap_end > at {
                p.data[at..gap_end].copy_from_slice(&f.body[at - start..gap_end - start]);
            }
            at = b;
        }
        p.ranges = ranges;
        Ok(Added::New)
    }

    /// Drops the messages furthest ahead until `length` more bytes fit.
    /// One message always fits once the others are gone, since
    /// [`MAX_MESSAGE_LEN`] is no more than [`MAX_REASSEMBLY_BYTES`].
    fn make_room(&mut self, length: usize) {
        while self.held.saturating_add(length) > MAX_REASSEMBLY_BYTES {
            let next = self.next_seq;
            let Some(i) = (0..self.pending.len()).max_by_key(|&i| self.pending[i].message_seq.wrapping_sub(next))
            else {
                return;
            };
            let p = self.pending.swap_remove(i);
            self.held -= p.data.len();
        }
    }

    /// The next message in sequence, if all of it has come.
    pub fn next_message(&mut self) -> Option<Handshake> {
        let i = self.pending.iter().position(|p| p.message_seq == self.next_seq && p.is_whole())?;
        let p = self.pending.swap_remove(i);
        self.held -= p.data.len();
        self.next_seq = self.next_seq.wrapping_add(1);
        Some(Handshake { msg_type: p.msg_type, message_seq: p.message_seq, body: p.data })
    }
}

/// `ranges` with `start..end` added, merging ranges that overlap or touch.
fn merged(ranges: &[(usize, usize)], start: usize, end: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::with_capacity(ranges.len() + 1);
    let (mut a, mut b) = (start, end);
    let mut placed = false;
    for &(x, y) in ranges {
        if y < a {
            out.push((x, y));
        } else if b < x {
            if !placed {
                out.push((a, b));
                placed = true;
            }
            out.push((x, y));
        } else {
            a = a.min(x);
            b = b.max(y);
        }
    }
    if !placed {
        out.push((a, b));
    }
    out
}

fn random(r: &mut Reader<'_>) -> Result<[u8; RANDOM_LEN], HandshakeError> {
    let mut out = [0; RANDOM_LEN];
    out.copy_from_slice(r.take(RANDOM_LEN)?);
    Ok(out)
}

fn session_id(r: &mut Reader<'_>) -> Result<Vec<u8>, HandshakeError> {
    let id = r.vec8()?;
    if id.len() > MAX_SESSION_ID {
        return Err(HandshakeError::SessionId(id.len()));
    }
    Ok(id.to_vec())
}

/// Reads the optional extension block that ends a hello.
fn extensions(r: &mut Reader<'_>) -> Result<Option<Vec<Extension>>, HandshakeError> {
    if r.remaining() == 0 {
        return Ok(None);
    }
    let block = r.vec16()?;
    if r.remaining() != 0 {
        return Err(HandshakeError::Trailing);
    }
    let mut e = Reader::new(block);
    let mut out = Vec::new();
    let mut seen = TypeSet::new();
    while e.remaining() > 0 {
        let typ = e.u16().map_err(|_| HandshakeError::Extensions)?;
        let data = e.vec16().map_err(|_| HandshakeError::Extensions)?;
        if !seen.insert(typ) {
            return Err(HandshakeError::DuplicateExtension(typ));
        }
        out.push(Extension { typ, data: data.to_vec() });
    }
    Ok(Some(out))
}

/// A set of extension types: one bit for each of the 65536.
struct TypeSet(Vec<u64>);

impl TypeSet {
    fn new() -> TypeSet {
        TypeSet(vec![0; 1024])
    }

    /// Adds `typ`, and says whether it was not there before.
    fn insert(&mut self, typ: u16) -> bool {
        let (word, bit) = (usize::from(typ >> 6), 1u64 << (typ & 63));
        let new = self.0[word] & bit == 0;
        self.0[word] |= bit;
        new
    }
}

fn put_extensions(out: &mut Vec<u8>, extensions: Option<&[Extension]>) -> Result<(), HandshakeError> {
    let Some(extensions) = extensions else { return Ok(()) };
    let mut block = Vec::new();
    let mut seen = TypeSet::new();
    for e in extensions {
        if e.data.len() > MAX_EXTENSIONS_LEN || block.len() + 4 + e.data.len() > MAX_EXTENSIONS_LEN || !seen.insert(e.typ) {
            return Err(HandshakeError::Unwritable);
        }
        block.extend_from_slice(&e.typ.to_be_bytes());
        block.extend_from_slice(&(e.data.len() as u16).to_be_bytes());
        block.extend_from_slice(&e.data);
    }
    out.extend_from_slice(&(block.len() as u16).to_be_bytes());
    out.extend_from_slice(&block);
    Ok(())
}

fn find_extension(extensions: Option<&[Extension]>, typ: u16) -> Option<&[u8]> {
    extensions?.iter().find(|e| e.typ == typ).map(|e| e.data.as_slice())
}

/// Writes `b`, at most 255 bytes, behind a one-byte length.
fn put_vec8(out: &mut Vec<u8>, b: &[u8]) -> Result<(), HandshakeError> {
    if b.len() > 255 { return Err(HandshakeError::Unwritable); }
    out.push(b.len() as u8);
    out.extend_from_slice(b);
    Ok(())
}

/// The bytes ran out.
struct Short;

impl From<Short> for RecordError {
    fn from(_: Short) -> RecordError {
        RecordError::Truncated
    }
}

impl From<Short> for HandshakeError {
    fn from(_: Short) -> HandshakeError {
        HandshakeError::Truncated
    }
}

/// Reads big-endian fields from a slice, checking every length.
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Short> {
        let end = self.at.checked_add(n).ok_or(Short)?;
        let s = self.b.get(self.at..end).ok_or(Short)?;
        self.at = end;
        Ok(s)
    }

    fn rest(&mut self) -> &'a [u8] {
        let s = self.b.get(self.at..).unwrap_or(&[]);
        self.at = self.b.len();
        s
    }

    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.at)
    }

    fn u8(&mut self) -> Result<u8, Short> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Short> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    fn u24(&mut self) -> Result<u32, Short> {
        let s = self.take(3)?;
        Ok(u32::from_be_bytes([0, s[0], s[1], s[2]]))
    }

    fn u48(&mut self) -> Result<u64, Short> {
        let s = self.take(6)?;
        Ok(u64::from_be_bytes([0, 0, s[0], s[1], s[2], s[3], s[4], s[5]]))
    }

    fn vec8(&mut self) -> Result<&'a [u8], Short> {
        let n = self.u8()?;
        self.take(usize::from(n))
    }

    fn vec16(&mut self) -> Result<&'a [u8], Short> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }
}

impl<const CID_LEN: u8> Wire for Record<CID_LEN> {
    type ParseError = RecordError;
    type WriteError = RecordError;

    /// Reads one complete record. `CID_LEN` is the connection ID length
    /// chosen by this endpoint, or zero when it uses no connection IDs.
    /// Refuses unknown content types, short or oversized payloads and trailing bytes.
    /// A unified record without a length consumes the whole input.
    fn parse(b: &[u8]) -> Result<Self, RecordError> {
        let (record, used) = Self::parse_prefix(b)?;
        if used != b.len() { return Err(RecordError::Trailing); }
        Ok(record)
    }

    /// Appends the record. Refuses sequence numbers wider than 48 bits, epoch bits
    /// above three, wrong connection ID lengths, IDs on non-CID plaintext records,
    /// and oversized payloads. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), RecordError> {
        let mut out = Vec::new();
        match self {
            Record::Plain(p) => {
                if p.sequence > MAX_SEQUENCE || p.fragment.len() > plain_limit(p.epoch)
                    || if p.content_type == ContentType::TLS12_CID { p.connection_id.len() != usize::from(CID_LEN) } else { !p.connection_id.is_empty() }
                { return Err(RecordError::Unwritable); }
                out.push(p.content_type.get());
                out.extend_from_slice(&p.version.to_be_bytes());
                out.extend_from_slice(&p.epoch.to_be_bytes());
                out.extend_from_slice(&(p.sequence & MAX_SEQUENCE).to_be_bytes()[2..]);
                if p.content_type == ContentType::TLS12_CID {
                    out.extend_from_slice(&p.connection_id);
                }
                let fragment = &p.fragment;
                out.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
                out.extend_from_slice(fragment);
            }
            Record::Unified(u) => {
                if u.epoch_bits > unified_bits::EPOCH_MASK || u.payload.len() > MAX_UNIFIED_PAYLOAD
                    || u.connection_id.as_ref().is_some_and(|id| id.len() != usize::from(CID_LEN))
                { return Err(RecordError::Unwritable); }
                let has_length = u.has_length;
                let mut first = unified_bits::FIXED | (u.epoch_bits & unified_bits::EPOCH_MASK);
                if u.connection_id.is_some() {
                    first |= unified_bits::CID;
                }
                if matches!(u.sequence, Sequence::Long(_)) {
                    first |= unified_bits::SEQ16;
                }
                if has_length {
                    first |= unified_bits::LENGTH;
                }
                out.push(first);
                if let Some(cid) = &u.connection_id {
                    out.extend_from_slice(cid);
                }
                match u.sequence {
                    Sequence::Short(s) => out.push(s),
                    Sequence::Long(s) => out.extend_from_slice(&s.to_be_bytes()),
                }
                let payload = &u.payload;
                if has_length {
                    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                }
                out.extend_from_slice(payload);
            }
        }
        commit_record(dst, &out)
    }
}

impl Wire for Fragment {
    type ParseError = HandshakeError;
    type WriteError = HandshakeError;

    /// Reads one fragment. Refuses malformed ranges, oversized messages and trailing bytes.
    fn parse(b: &[u8]) -> Result<Fragment, HandshakeError> {
        let (fragment, used) = Self::parse_prefix(b)?;
        if used != b.len() { return Err(HandshakeError::Trailing); }
        Ok(fragment)
    }

    /// Appends the complete fragment. Refuses messages above [`MAX_MESSAGE_LEN`] and
    /// fragment ranges outside their declared message. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), HandshakeError> {
        if self.length as usize > MAX_MESSAGE_LEN || self.offset > self.length || self.body.len() > (self.length - self.offset) as usize { return Err(HandshakeError::Unwritable); }
        let length = self.length;
        let offset = self.offset;
        let body = &self.body;
        let mut out = Vec::with_capacity(HANDSHAKE_HEADER_LEN + body.len());
        out.push(self.msg_type);
        out.extend_from_slice(&length.to_be_bytes()[1..]);
        out.extend_from_slice(&self.message_seq.to_be_bytes());
        out.extend_from_slice(&offset.to_be_bytes()[1..]);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        out.extend_from_slice(body);
        commit_handshake(dst, &out)
    }
}

impl Wire for Handshake {
    type ParseError = HandshakeError;
    type WriteError = HandshakeError;

    /// Reads one whole handshake. Refuses partial fragments and trailing bytes.
    fn parse(b: &[u8]) -> Result<Handshake, HandshakeError> {
        let fragment = Fragment::parse(b)?;
        if !fragment.is_whole() { return Err(HandshakeError::FragmentRange); }
        Ok(Self { msg_type: fragment.msg_type, message_seq: fragment.message_seq, body: fragment.body })
    }

    /// Appends one whole handshake fragment. Refuses bodies above [`MAX_MESSAGE_LEN`].
    /// Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), HandshakeError> {
        self.to_fragment()?.write(dst)
    }
}

impl Wire for ClientHello {
    type ParseError = HandshakeError;
    type WriteError = HandshakeError;

    /// Reads a ClientHello body.
    /// Refuses malformed or trailing input.
    fn parse(b: &[u8]) -> Result<ClientHello, HandshakeError> {
        let mut r = Reader::new(b);
        let version = r.u16()?;
        let random = random(&mut r)?;
        let session_id = session_id(&mut r)?;
        let cookie = r.vec8()?.to_vec();
        let suites = r.vec16()?;
        if suites.is_empty() || !suites.len().is_multiple_of(2) {
            return Err(HandshakeError::CipherSuites);
        }
        let cipher_suites = suites.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        let compression_methods = r.vec8()?.to_vec();
        if compression_methods.is_empty() {
            return Err(HandshakeError::CompressionMethods);
        }
        let extensions = extensions(&mut r)?;
        Ok(ClientHello { version, random, session_id, cookie, cipher_suites, compression_methods, extensions })
    }

    /// Appends the hello body. Refuses oversized session IDs or cookies, empty or oversized
    /// suite and compression lists, duplicate extensions and oversized extension blocks.
    /// Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), HandshakeError> {
        if self.session_id.len() > MAX_SESSION_ID { return Err(HandshakeError::Unwritable); }
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.random);
        put_vec8(&mut out, &self.session_id)?;
        put_vec8(&mut out, &self.cookie)?;
        if self.cipher_suites.is_empty() || self.cipher_suites.len() > MAX_CIPHER_SUITES
            || self.compression_methods.is_empty() || self.compression_methods.len() > MAX_COMPRESSION_METHODS {
            return Err(HandshakeError::Unwritable);
        }
        let suites = &self.cipher_suites;
        out.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
        for s in suites {
            out.extend_from_slice(&s.to_be_bytes());
        }
        let methods = &self.compression_methods;
        put_vec8(&mut out, methods)?;
        put_extensions(&mut out, self.extensions.as_deref())?;
        commit_handshake(dst, &out)
    }
}

impl Wire for ServerHello {
    type ParseError = HandshakeError;
    type WriteError = HandshakeError;

    /// Reads a ServerHello body.
    /// Refuses malformed or trailing input.
    fn parse(b: &[u8]) -> Result<ServerHello, HandshakeError> {
        let mut r = Reader::new(b);
        let version = r.u16()?;
        let random = random(&mut r)?;
        let session_id = session_id(&mut r)?;
        let cipher_suite = r.u16()?;
        let compression_method = r.u8()?;
        let extensions = extensions(&mut r)?;
        Ok(ServerHello { version, random, session_id, cipher_suite, compression_method, extensions })
    }

    /// Appends the hello body. Refuses oversized session IDs, duplicate extensions and
    /// oversized extension blocks. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), HandshakeError> {
        if self.session_id.len() > MAX_SESSION_ID { return Err(HandshakeError::Unwritable); }
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.random);
        put_vec8(&mut out, &self.session_id)?;
        out.extend_from_slice(&self.cipher_suite.to_be_bytes());
        out.push(self.compression_method);
        put_extensions(&mut out, self.extensions.as_deref())?;
        commit_handshake(dst, &out)
    }
}

impl Wire for HelloVerifyRequest {
    type ParseError = HandshakeError;
    type WriteError = HandshakeError;

    /// Reads a HelloVerifyRequest body.
    /// Refuses malformed or trailing input.
    fn parse(b: &[u8]) -> Result<HelloVerifyRequest, HandshakeError> {
        let mut r = Reader::new(b);
        let version = r.u16()?;
        let cookie = r.vec8()?.to_vec();
        if r.remaining() != 0 {
            return Err(HandshakeError::Trailing);
        }
        Ok(HelloVerifyRequest { version, cookie })
    }

    /// Appends the version and cookie. Refuses cookies above 255 bytes.
    /// Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), HandshakeError> {
        let mut out = self.version.to_be_bytes().to_vec();
        put_vec8(&mut out, &self.cookie)?;
        commit_handshake(dst, &out)
    }
}

/// The complete handshake fragments in one record payload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fragments(
    /// Fragments in record order.
    pub Vec<Fragment>,
);

impl Wire for Fragments {
    type ParseError = HandshakeError;
    type WriteError = HandshakeError;

    /// Reads every fragment. Refuses invalid fragments, incomplete input and excess fragment counts.
    fn parse(b: &[u8]) -> Result<Self, HandshakeError> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < b.len() {
            if out.len() == MAX_FRAGMENTS_PER_RECORD {
                return Err(HandshakeError::TooManyFragments);
            }
            let (f, used) = Fragment::parse_prefix(&b[at..])?;
            out.push(f);
            at += used;
        }
        Ok(Self(out))
    }

    /// Appends every fragment. Refuses invalid values and more than [`MAX_FRAGMENTS_PER_RECORD`].
    /// Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), HandshakeError> {
        if self.0.len() > MAX_FRAGMENTS_PER_RECORD { return Err(HandshakeError::Unwritable); }
        let mut out = Vec::new();
        for fragment in &self.0 { fragment.write(&mut out)?; }
        commit_handshake(dst, &out)
    }
}

/// Appends staged bytes after reserving space. Refuses allocation failure.
fn commit_handshake(dst: &mut Vec<u8>, out: &[u8]) -> Result<(), HandshakeError> {
    dst.try_reserve(out.len())
        .map_err(|_| HandshakeError::Unwritable)?;
    dst.extend_from_slice(out);
    Ok(())
}

/// Appends staged bytes after reserving space. Refuses allocation failure.
fn commit_record(dst: &mut Vec<u8>, out: &[u8]) -> Result<(), RecordError> {
    dst.try_reserve(out.len())
        .map_err(|_| RecordError::Unwritable)?;
    dst.extend_from_slice(out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use fictionet::stdlib::codec::{contract, test_support::{Lcg, mutate}};
    use super::*;

    /// A DTLS 1.2 handshake record, laid out field by field as in RFC 6347,
    /// section 4.1: type 22, version 0xfefd, epoch 1, sequence 5, length 3.
    const PLAIN: [u8; 16] = [22, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 5, 0, 3, 0xaa, 0xbb, 0xcc];

    /// A ClientHello body: version 0xfefd, a random of 7s, an empty session
    /// ID, a 2-byte cookie, two cipher suites, compression null, and one
    /// supported_versions extension offering DTLS 1.3 and 1.2.
    fn client_hello_bytes() -> Vec<u8> {
        let mut b = vec![0xfe, 0xfd];
        b.extend_from_slice(&[7; 32]);
        b.push(0);
        b.extend_from_slice(&[2, 0xc0, 0x0c]);
        b.extend_from_slice(&[0, 4, 0xc0, 0x2b, 0x13, 0x01]);
        b.extend_from_slice(&[1, 0]);
        b.extend_from_slice(&[0, 9, 0, 43, 0, 5, 4, 0xfe, 0xfc, 0xfe, 0xfd]);
        b
    }

    fn server_hello_bytes() -> Vec<u8> {
        let mut b = vec![0xfe, 0xfd];
        b.extend_from_slice(&HELLO_RETRY_REQUEST_RANDOM);
        b.push(0);
        b.extend_from_slice(&[0x13, 0x01, 0]);
        b.extend_from_slice(&[0, 6, 0, 43, 0, 2, 0xfe, 0xfc]);
        b
    }

    #[test]
    fn plain_record() {
        let r = Record::<0>::parse(&PLAIN).unwrap();
        assert_eq!(r.to_bytes().unwrap().len(), 16);
        let Record::Plain(p) = &r else { panic!() };
        assert_eq!(p.content_type, ContentType::HANDSHAKE);
        assert_eq!((p.version, p.epoch, p.sequence), (version::DTLS_1_2, 1, 5));
        assert_eq!(p.fragment, [0xaa, 0xbb, 0xcc]);
        assert!(p.connection_id.is_empty());
        assert_eq!(r.to_bytes().unwrap(), PLAIN);
        // Bytes after the record are left for the next one.
        let mut two = PLAIN.to_vec();
        two.extend_from_slice(&PLAIN);
        assert_eq!(Record::<0>::parse(&two), Err(RecordError::Trailing));
        // The full 48-bit sequence number.
        let mut b = PLAIN;
        b[5..11].copy_from_slice(&[0xff; 6]);
        let Record::Plain(p) = Record::<0>::parse(&b).unwrap() else { panic!() };
        assert_eq!(p.sequence, MAX_SEQUENCE);
    }

    #[test]
    fn tls12_cid_record() {
        // RFC 9146: the connection ID sits between the sequence number and
        // the length.
        let b = [25, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 9, 0x11, 0x22, 0, 1, 0x55];
        let r = Record::<2>::parse(&b).unwrap();
        assert_eq!(r.to_bytes().unwrap().len(), b.len());
        let Record::Plain(p) = &r else { panic!() };
        assert_eq!(p.content_type, ContentType::TLS12_CID);
        assert_eq!(p.connection_id, [0x11, 0x22]);
        assert_eq!(p.fragment, [0x55]);
        assert_eq!(r.to_bytes().unwrap(), b);
        // Other types carry no connection ID, whatever its length.
        assert_eq!(Record::<2>::parse(&PLAIN).unwrap().to_bytes().unwrap().len(), 16);
    }

    #[test]
    fn unified_records() {
        // 0x2c: fixed bits 001, no connection ID, 16-bit sequence, a
        // length, epoch bits 0 (RFC 9147, section 4).
        let b = [0x2c, 0x01, 0x02, 0x00, 0x02, 0xde, 0xad, 0xff];
        assert_eq!(Record::<0>::parse(&b), Err(RecordError::Trailing));
        let r = Record::<0>::parse(&b[..7]).unwrap();
        assert_eq!(r.to_bytes().unwrap().len(), 7);
        assert_eq!(
            r,
            Record::Unified(UnifiedRecord {
                epoch_bits: 0,
                connection_id: None,
                sequence: Sequence::Long(0x0102),
                has_length: true,
                payload: vec![0xde, 0xad],
            })
        );
        assert_eq!(r.to_bytes().unwrap(), b[..7]);
        // 0x33: a connection ID, an 8-bit sequence, no length, epoch bits 3.
        // The record runs to the end of the datagram.
        let b = [0x33, 0xa1, 0xa2, 0xa3, 0x07, 1, 2, 3, 4];
        let r = Record::<3>::parse(&b).unwrap();
        assert_eq!(r.to_bytes().unwrap().len(), b.len());
        let Record::Unified(u) = &r else { panic!() };
        assert_eq!(u.epoch_bits, 3);
        assert_eq!(u.connection_id.as_deref(), Some(&[0xa1, 0xa2, 0xa3][..]));
        assert_eq!(u.sequence, Sequence::Short(7));
        assert!(!u.has_length);
        assert_eq!(u.payload, [1, 2, 3, 4]);
        assert_eq!(r.to_bytes().unwrap(), b);
        // The top three bits decide: 0x3f is unified, 0x40 is neither.
        assert!(matches!(Record::<0>::parse(&[0x3f, 0, 0, 0, 0]), Ok(Record::Unified(_))));
        assert_eq!(Record::<0>::parse(&[0x40, 0, 0]), Err(RecordError::ContentType(0x40)));
    }

    #[test]
    fn record_errors() {
        assert_eq!(Record::<0>::parse(&[]), Err(RecordError::Empty));
        assert_eq!(Record::<0>::parse(&[19, 0xfe, 0xfd]), Err(RecordError::ContentType(19)));
        assert_eq!(Record::<0>::parse(&[0xff]), Err(RecordError::ContentType(0xff)));
        // Every prefix of a plain record ends inside it.
        for n in 1..PLAIN.len() {
            assert_eq!(Record::<0>::parse(&PLAIN[..n]), Err(RecordError::Truncated), "{n} bytes");
        }
        let cid = [25, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 9, 0x11, 0x22, 0, 1, 0x55];
        for n in 1..cid.len() {
            assert_eq!(Record::<2>::parse(&cid[..n]), Err(RecordError::Truncated), "{n} bytes");
        }
        // Every prefix of a unified record with a length.
        let u = [0x3c, 0xaa, 0x01, 0x02, 0x00, 0x02, 0xde, 0xad];
        for n in 1..u.len() {
            assert_eq!(Record::<1>::parse(&u[..n]), Err(RecordError::Truncated), "{n} bytes");
        }
        // Without a length, a prefix past the sequence number still reads.
        let u = [0x30, 0xaa, 0x01, 0xde, 0xad];
        assert_eq!(Record::<1>::parse(&u[..1]), Err(RecordError::Truncated));
        assert_eq!(Record::<1>::parse(&u[..2]), Err(RecordError::Truncated));
        assert!(Record::<1>::parse(&u[..3]).is_ok());
        // Lengths over the limits.
        let mut b = PLAIN;
        b[11..13].copy_from_slice(&((MAX_PLAIN_FRAGMENT + 1) as u16).to_be_bytes());
        assert_eq!(Record::<0>::parse(&b), Err(RecordError::Length(MAX_PLAIN_FRAGMENT + 1)));
        let b = [0x2c, 0, 0, 0xff, 0xff];
        assert_eq!(Record::<0>::parse(&b), Err(RecordError::Length(0xffff)));
        let mut b = vec![0x20, 0];
        b.extend(std::iter::repeat_n(0, MAX_UNIFIED_PAYLOAD + 1));
        assert_eq!(Record::<0>::parse(&b), Err(RecordError::Length(MAX_UNIFIED_PAYLOAD + 1)));
        b.pop();
        assert!(Record::<0>::parse(&b).is_ok());
    }

    #[test]
    fn datagrams() {
        let plain = Record::<0>::parse(&PLAIN).unwrap();
        let tail = Record::Unified(UnifiedRecord {
            epoch_bits: 2,
            connection_id: None,
            sequence: Sequence::Short(1),
            has_length: false,
            payload: vec![9; 5],
        });
        let Record::Unified(mut framed) = tail.clone() else { panic!() };
        framed.has_length = true;
        let framed = Record::Unified(framed);
        let records = vec![plain.clone(), framed.clone(), plain.clone(), tail.clone()];
        let bytes = Datagram::<0>(records.to_vec()).to_bytes().unwrap();
        let back = Datagram::<0>::parse(&bytes).map(|d| d.0).unwrap();
        assert_eq!(back, records);
        assert_eq!(Datagram::<0>(back.to_vec()).to_bytes().unwrap(), bytes);
        assert_eq!(Datagram::<0>::parse(&[]).map(|d| d.0), Ok(vec![]));
        // An error anywhere fails the datagram.
        let mut bad = PLAIN.to_vec();
        bad.push(0x99);
        assert_eq!(Datagram::<0>::parse(&bad).map(|d| d.0), Err(RecordError::ContentType(0x99)));
        bad.pop();
        bad.extend_from_slice(&PLAIN[..5]);
        assert_eq!(Datagram::<0>::parse(&bad).map(|d| d.0), Err(RecordError::Truncated));
        // Too many records.
        let empty = [0x2c, 0, 0, 0, 0];
        let many: Vec<u8> = empty.iter().copied().cycle().take(5 * (MAX_RECORDS_PER_DATAGRAM + 1)).collect();
        assert_eq!(Datagram::<0>::parse(&many).map(|d| d.0), Err(RecordError::TooManyRecords));
        assert_eq!(Datagram::<0>::parse(&many[5..]).map(|d| d.0).unwrap().len(), MAX_RECORDS_PER_DATAGRAM);
        let many = Datagram::<0>(vec![plain; MAX_RECORDS_PER_DATAGRAM + 5]);
        contract::check_wire_value(&many);
        assert_eq!(many.to_bytes(), Err(RecordError::Unwritable));
    }

    #[test]
    fn content_types() {
        for n in 0..=255u8 {
            assert_eq!(ContentType::new(n).is_some(), (20..=31).contains(&n));
            if let Some(t) = ContentType::new(n) {
                assert_eq!(t.get(), n);
            }
        }
    }

    #[test]
    fn fragments() {
        // RFC 6347, section 4.2.2: type, length, message_seq,
        // fragment_offset, fragment_length, then the bytes. Bytes 2 to 4
        // of a 6-byte ClientHello, message 3.
        let b = [1, 0, 0, 6, 0, 3, 0, 0, 2, 0, 0, 3, 7, 8, 9];
        let f = Fragment::parse(&b).unwrap();
        assert_eq!(f.to_bytes().unwrap().len(), b.len());
        assert_eq!(f, Fragment { msg_type: 1, length: 6, message_seq: 3, offset: 2, body: vec![7, 8, 9] });
        assert!(!f.is_whole());
        assert_eq!(f.to_bytes().unwrap(), b);
        for n in 0..b.len() {
            assert_eq!(Fragment::parse(&b[..n]), Err(HandshakeError::Truncated), "{n} bytes");
            if n > 0 {
                assert_eq!(Fragments::parse(&b[..n]).map(|fragments| fragments.0), Err(HandshakeError::Truncated));
            }
        }
        // Past the message's end.
        let b = [1, 0, 0, 6, 0, 3, 0, 0, 4, 0, 0, 3, 7, 8, 9];
        assert_eq!(Fragment::parse(&b), Err(HandshakeError::FragmentRange));
        // Too long a message.
        let n = (MAX_MESSAGE_LEN + 1) as u32;
        let mut b = vec![11];
        b.extend_from_slice(&n.to_be_bytes()[1..]);
        b.extend_from_slice(&[0; 8]);
        assert_eq!(Fragment::parse(&b), Err(HandshakeError::TooLong(n)));
        // Several fragments in one record, and too many.
        let empty = Handshake { msg_type: 14, message_seq: 1, body: vec![] }.to_bytes().unwrap();
        assert_eq!(empty, [14, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        let many: Vec<u8> = empty.iter().copied().cycle().take(12 * MAX_FRAGMENTS_PER_RECORD).collect();
        assert_eq!(
            Fragments::parse(&many).unwrap().0.len(),
            MAX_FRAGMENTS_PER_RECORD
        );
        let mut more = many.clone();
        more.extend_from_slice(&empty);
        assert_eq!(Fragments::parse(&more).map(|fragments| fragments.0), Err(HandshakeError::TooManyFragments));
    }

    #[test]
    fn splitting_messages() {
        let m = Handshake { msg_type: 11, message_seq: 2, body: (0..100).collect() };
        let parts = m.fragments(30).unwrap();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts.iter().map(|f| f.offset).collect::<Vec<_>>(), [0, 30, 60, 90]);
        assert!(parts.iter().all(|f| f.length == 100));
        assert!(m.to_fragment().unwrap().is_whole());
        assert_eq!(m.fragments(0).unwrap().len(), 100);
        assert_eq!(m.fragments(1000).unwrap(), [m.to_fragment().unwrap()]);
        let empty = Handshake { msg_type: 14, message_seq: 0, body: vec![] };
        assert_eq!(empty.fragments(10).unwrap(), [empty.to_fragment().unwrap()]);
    }

    #[test]
    fn client_hello() {
        let b = client_hello_bytes();
        let ch = ClientHello::parse(&b).unwrap();
        assert_eq!(ch.version, version::DTLS_1_2);
        assert_eq!(ch.random, [7; 32]);
        assert!(ch.session_id.is_empty());
        assert_eq!(ch.cookie, [0xc0, 0x0c]);
        assert_eq!(ch.cipher_suites, [0xc02b, 0x1301]);
        assert_eq!(ch.compression_methods, [0]);
        assert_eq!(ch.supported_versions(), Some(vec![version::DTLS_1_3, version::DTLS_1_2]));
        assert_eq!(ch.extension(extension_type::COOKIE), None);
        assert_eq!(ch.to_bytes().unwrap(), b);
        // Without the extension block, the hello ends after compression.
        let short = &b[..b.len() - 11];
        let plain = ClientHello::parse(short).unwrap();
        assert_eq!(plain.extensions, None);
        assert_eq!(plain.supported_versions(), None);
        assert_eq!(plain.to_bytes().unwrap(), short);
        // Every other prefix fails.
        for n in 0..b.len() {
            let r = ClientHello::parse(&b[..n]);
            if n == short.len() {
                assert!(r.is_ok());
            } else {
                assert!(r.is_err(), "{n} bytes");
            }
        }
        for n in 0..short.len() {
            assert_eq!(ClientHello::parse(&b[..n]), Err(HandshakeError::Truncated), "{n} bytes");
        }
        // An empty extension block reads as an empty list, not as `None`.
        let mut empty = short.to_vec();
        empty.extend_from_slice(&[0, 0]);
        assert_eq!(ClientHello::parse(&empty).unwrap().extensions, Some(vec![]));
    }

    #[test]
    fn client_hello_errors() {
        let b = client_hello_bytes();
        // A 33-byte session ID.
        let mut long = b[..34].to_vec();
        long.push(33);
        long.extend_from_slice(&[0; 33]);
        long.extend_from_slice(&b[35..]);
        assert_eq!(ClientHello::parse(&long), Err(HandshakeError::SessionId(33)));
        // An odd cipher suite list.
        let mut odd = b[..38].to_vec();
        odd.extend_from_slice(&[0, 3, 0xc0, 0x2b, 0x13]);
        odd.extend_from_slice(&b[44..]);
        assert_eq!(ClientHello::parse(&odd), Err(HandshakeError::CipherSuites));
        // Bytes after the extension block.
        let mut trailing = b.clone();
        trailing.push(0);
        assert_eq!(ClientHello::parse(&trailing), Err(HandshakeError::Trailing));
        // An extension that runs past its block: the block says 9 bytes,
        // the extension inside says 6.
        let mut bad = b.clone();
        let at = b.len() - 6;
        bad[at] = 6;
        assert_eq!(ClientHello::parse(&bad), Err(HandshakeError::Extensions));
        // A block with 3 bytes, too few for an extension header.
        let mut bad = b[..b.len() - 11].to_vec();
        bad.extend_from_slice(&[0, 3, 0, 43, 0]);
        assert_eq!(ClientHello::parse(&bad), Err(HandshakeError::Extensions));
        // A malformed supported_versions list.
        let mut ch = ClientHello::parse(&b).unwrap();
        ch.extensions = Some(vec![Extension { typ: extension_type::SUPPORTED_VERSIONS, data: vec![3, 0xfe, 0xfc, 0] }]);
        assert_eq!(ch.supported_versions(), None);
        // RFC 8446, section 4.2.1: versions<2..254>, so an empty list is
        // malformed.
        ch.extensions = Some(vec![Extension { typ: extension_type::SUPPORTED_VERSIONS, data: vec![0] }]);
        assert_eq!(ch.supported_versions(), None);
        ch.extensions = Some(vec![Extension { typ: extension_type::SUPPORTED_VERSIONS, data: vec![2, 0xfe, 0xfc] }]);
        assert_eq!(ch.supported_versions(), Some(vec![version::DTLS_1_3]));
    }

    #[test]
    fn overlapping_bytes_keep_the_first_copy() {
        // A repeat that covers held bytes changes nothing, whether it covers
        // them all or only some.
        let f = |offset: u32, body: Vec<u8>| Fragment { msg_type: 1, length: 6, message_seq: 0, offset, body };
        let mut r = Reassembler::new();
        assert_eq!(r.add(&f(0, vec![1, 2, 3, 4])), Ok(Added::New));
        assert_eq!(r.add(&f(1, vec![9, 9])), Ok(Added::Repeat));
        assert_eq!(r.add(&f(2, vec![9, 9, 5, 6])), Ok(Added::New));
        assert_eq!(r.next_message().unwrap().body, [1, 2, 3, 4, 5, 6]);
        // Gaps on both sides of a held range fill from one fragment.
        let mut r = Reassembler::new();
        assert_eq!(r.add(&f(2, vec![3, 4])), Ok(Added::New));
        assert_eq!(r.add(&f(0, vec![1, 2, 8, 8, 5, 6])), Ok(Added::New));
        assert_eq!(r.next_message().unwrap().body, [1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn empty_fragments_hold_nothing() {
        // An empty fragment of a message not yet seen brings no bytes, so the
        // reassembler sets nothing aside for it and does not pin its type.
        let mut r = Reassembler::new();
        let empty = Fragment { msg_type: 1, length: 1000, message_seq: 0, offset: 0, body: vec![] };
        assert_eq!(r.add(&empty), Ok(Added::Repeat));
        assert_eq!(r.buffered(), 0);
        let real = Handshake { msg_type: 2, message_seq: 0, body: vec![7; 3] };
        assert_eq!(r.add(&real.to_fragment().unwrap()), Ok(Added::New));
        assert_eq!(r.next_message(), Some(real));
        // An empty message is still given out.
        let none = Handshake { msg_type: 14, message_seq: 1, body: vec![] };
        assert_eq!(r.add(&none.to_fragment().unwrap()), Ok(Added::New));
        assert_eq!(r.next_message(), Some(none));
    }

    #[test]
    fn world_code_can_copy_state() {
        // A reassembler can be cloned, so a world can try a fragment on a
        // copy first.
        let mut r = Reassembler::new();
        let m = Handshake { msg_type: 1, message_seq: 0, body: vec![1, 2, 3, 4] };
        let parts = m.fragments(2).unwrap();
        r.add(&parts[0]).unwrap();
        let mut copy = r.clone();
        copy.add(&parts[1]).unwrap();
        assert_eq!(copy.next_message(), Some(m));
        assert_eq!(r.next_message(), None);
        // A sequence number's bits, whatever their width.
        assert_eq!(Sequence::Short(7).value(), 7);
        assert_eq!(Sequence::Long(0x0102).value(), 0x0102);
    }

    #[test]
    fn server_hello() {
        let b = server_hello_bytes();
        let sh = ServerHello::parse(&b).unwrap();
        assert!(sh.is_hello_retry_request());
        assert!(sh.session_id.is_empty());
        assert_eq!((sh.cipher_suite, sh.compression_method), (0x1301, 0));
        assert_eq!(sh.selected_version(), Some(version::DTLS_1_3));
        assert_eq!(sh.to_bytes().unwrap(), b);
        let short = &b[..b.len() - 8];
        for n in 0..b.len() {
            let r = ServerHello::parse(&b[..n]);
            assert_eq!(r.is_ok(), n == short.len(), "{n} bytes");
        }
        let mut long = b[..34].to_vec();
        long.push(40);
        long.extend_from_slice(&[0; 40]);
        assert_eq!(ServerHello::parse(&long), Err(HandshakeError::SessionId(40)));
        let mut trailing = b.clone();
        trailing.push(1);
        assert_eq!(ServerHello::parse(&trailing), Err(HandshakeError::Trailing));
        let mut plain = ServerHello::parse(short).unwrap();
        assert!(plain.is_hello_retry_request());
        assert_eq!(plain.selected_version(), None);
        plain.random = [0; 32];
        assert!(!plain.is_hello_retry_request());
    }

    #[test]
    fn hello_verify_request() {
        // RFC 6347, section 4.2.1: server_version, then the cookie.
        let b = [0xfe, 0xff, 3, 1, 2, 3];
        let h = HelloVerifyRequest::parse(&b).unwrap();
        assert_eq!(h, HelloVerifyRequest { version: version::DTLS_1_0, cookie: vec![1, 2, 3] });
        assert_eq!(h.to_bytes().unwrap(), b);
        for n in 0..b.len() {
            assert_eq!(HelloVerifyRequest::parse(&b[..n]), Err(HandshakeError::Truncated), "{n} bytes");
        }
        assert_eq!(HelloVerifyRequest::parse(&[0xfe, 0xff, 0, 0]), Err(HandshakeError::Trailing));
        let m = Handshake { msg_type: handshake_type::HELLO_VERIFY_REQUEST, message_seq: 0, body: b.to_vec() };
        assert_eq!(m.parse_body(), Ok(Body::HelloVerifyRequest(h)));
        let other = Handshake { msg_type: handshake_type::FINISHED, message_seq: 4, body: vec![1, 2] };
        assert_eq!(other.parse_body(), Ok(Body::Other(handshake_type::FINISHED)));
        let bad = Handshake { msg_type: handshake_type::SERVER_HELLO, message_seq: 1, body: vec![1] };
        assert_eq!(bad.parse_body(), Err(HandshakeError::Truncated));
    }

    #[test]
    fn writers_refuse_oversized_fields() {
        let ch = ClientHello {
            version: version::DTLS_1_2,
            random: [0; 32],
            session_id: vec![1; 100],
            cookie: vec![2; 300],
            cipher_suites: vec![0x1301; 40000],
            compression_methods: vec![0; 300],
            extensions: Some(vec![
                Extension { typ: 1, data: vec![0; 40000] },
                Extension { typ: 2, data: vec![0; 30000] },
                Extension { typ: 3, data: vec![0; 20000] },
            ]),
        };
        contract::check_wire_value(&ch);
        assert_eq!(ch.to_bytes(), Err(HandshakeError::Unwritable));
        let mut ch = ClientHello::parse(&client_hello_bytes()).unwrap();
        ch.extensions = Some(vec![Extension { typ: 1, data: vec![0; 20000] }]);
        // The body is too big for one record, but splits into fragments
        // that reassemble.
        let m = Handshake { msg_type: 1, message_seq: 0, body: ch.to_bytes().unwrap() };
        let mut r = Reassembler::new();
        for f in m.fragments(MAX_PLAINTEXT - HANDSHAKE_HEADER_LEN).unwrap() {
            let rec = Record::<0>::Plain(PlainRecord {
                content_type: ContentType::HANDSHAKE,
                version: version::DTLS_1_2,
                epoch: 0,
                sequence: 0,
                connection_id: vec![],
                fragment: f.to_bytes().unwrap(),
            });
            let Record::Plain(p) = Record::<0>::parse(&rec.to_bytes().unwrap()).unwrap() else { panic!() };
            for f in Fragments::parse(&p.fragment).unwrap().0 {
                assert_eq!(r.add(&f), Ok(Added::New));
            }
        }
        assert_eq!(r.next_message().unwrap(), m);

        let sh = ServerHello {
            version: 0,
            random: [0; 32],
            session_id: vec![0; 64],
            cipher_suite: 0,
            compression_method: 0,
            extensions: None,
        };
        contract::check_wire_value(&sh);
        assert_eq!(sh.to_bytes(), Err(HandshakeError::Unwritable));
        let h = HelloVerifyRequest { version: 0, cookie: vec![0; 1000] };
        contract::check_wire_value(&h);
        assert_eq!(h.to_bytes(), Err(HandshakeError::Unwritable));

        let p = Record::<0>::Plain(PlainRecord {
            content_type: ContentType::TLS12_CID,
            version: 0,
            epoch: 0,
            sequence: u64::MAX,
            connection_id: vec![1; 300],
            fragment: vec![0; 70000],
        });
        contract::check_wire_value(&p);
        assert_eq!(p.to_bytes(), Err(RecordError::Unwritable));
        let u = Record::<0>::Unified(UnifiedRecord {
            epoch_bits: 0xff,
            connection_id: Some(vec![1; 300]),
            sequence: Sequence::Long(9),
            has_length: false,
            payload: vec![0; 70000],
        });
        contract::check_wire_value(&u);
        assert_eq!(u.to_bytes(), Err(RecordError::Unwritable));

        let f = Fragment { msg_type: 1, length: u32::MAX, message_seq: 0, offset: u32::MAX, body: vec![1; 10] };
        contract::check_wire_value(&f);
        assert_eq!(f.to_bytes(), Err(HandshakeError::Unwritable));
        let f = Fragment { msg_type: 1, length: 4, message_seq: 0, offset: 2, body: vec![1; 10] };
        contract::check_wire_value(&f);
        assert_eq!(f.to_bytes(), Err(HandshakeError::Unwritable));
        let big = Handshake { msg_type: 1, message_seq: 0, body: vec![0; MAX_MESSAGE_LEN + 10] };
        assert_eq!(big.to_fragment(), Err(HandshakeError::Unwritable));
        assert_eq!(big.to_bytes(), Err(HandshakeError::Unwritable));
        contract::check_wire_value(&big);
    }

    #[test]
    fn reassembly_in_any_order() {
        let m = Handshake { msg_type: 11, message_seq: 0, body: (0..=255).collect() };
        let mut parts = m.fragments(40).unwrap();
        parts.reverse();
        let mut r = Reassembler::new();
        for f in &parts {
            assert_eq!(r.next_message(), None);
            assert_eq!(r.add(f), Ok(Added::New));
        }
        assert_eq!(r.buffered(), 256);
        assert_eq!(r.next_message(), Some(m.clone()));
        assert_eq!(r.next_message(), None);
        assert_eq!((r.next_seq(), r.buffered()), (1, 0));
        // A retransmission of a message already given out.
        assert_eq!(r.add(&parts[0]), Ok(Added::Repeat));

        // Overlapping pieces, and bytes already held.
        let m = Handshake { msg_type: 2, message_seq: 1, body: (0..50).collect() };
        let piece = |a: usize, b: usize| Fragment {
            msg_type: 2,
            length: 50,
            message_seq: 1,
            offset: a as u32,
            body: m.body[a..b].to_vec(),
        };
        assert_eq!(r.add(&piece(10, 30)), Ok(Added::New));
        assert_eq!(r.add(&piece(12, 20)), Ok(Added::Repeat));
        assert_eq!(r.add(&piece(25, 50)), Ok(Added::New));
        assert_eq!(r.add(&piece(0, 0)), Ok(Added::Repeat));
        assert_eq!(r.next_message(), None);
        assert_eq!(r.add(&piece(0, 11)), Ok(Added::New));
        assert_eq!(r.next_message(), Some(m));

        // A later message waits for an earlier one.
        let a = Handshake { msg_type: 14, message_seq: 2, body: vec![] };
        let b = Handshake { msg_type: 16, message_seq: 3, body: vec![5; 3] };
        assert_eq!(r.add(&b.to_fragment().unwrap()), Ok(Added::New));
        assert_eq!(r.next_message(), None);
        assert_eq!(r.add(&a.to_fragment().unwrap()), Ok(Added::New));
        assert_eq!(r.add(&a.to_fragment().unwrap()), Ok(Added::Repeat));
        assert_eq!(r.next_message(), Some(a));
        assert_eq!(r.next_message(), Some(b));
    }

    #[test]
    fn reassembly_one_byte_at_a_time() {
        let m = Handshake { msg_type: 1, message_seq: 0, body: client_hello_bytes() };
        let mut r = Reassembler::new();
        for f in m.fragments(1).unwrap() {
            let bytes = f.to_bytes().unwrap();
            let f = Fragment::parse(&bytes).unwrap();
            assert_eq!(r.add(&f), Ok(Added::New));
        }
        let got = r.next_message().unwrap();
        assert_eq!(got, m);
        assert!(matches!(got.parse_body(), Ok(Body::ClientHello(_))));
    }

    #[test]
    fn reassembly_errors() {
        let mut r = Reassembler::starting_at(65534);
        assert_eq!(r.next_seq(), 65534);
        let f = |seq: u16, length: u32, offset: u32, body: Vec<u8>| Fragment {
            msg_type: 1,
            length,
            message_seq: seq,
            offset,
            body,
        };
        assert_eq!(r.add(&f(65534, 4, 3, vec![1, 2])), Err(ReassemblyError::Invalid));
        assert_eq!(r.add(&f(65534, (MAX_MESSAGE_LEN + 1) as u32, 0, vec![])), Err(ReassemblyError::Invalid));
        assert_eq!(r.add(&f(65534, 4, u32::MAX, vec![1])), Err(ReassemblyError::Invalid));
        // The window wraps past 65535.
        assert_eq!(r.add(&f(5, 1, 0, vec![1])), Ok(Added::New));
        assert_eq!(r.add(&f(6, 1, 0, vec![1])), Err(ReassemblyError::Window(6)));
        assert_eq!(r.add(&f(65533, 1, 0, vec![1])), Ok(Added::Repeat));
        // A type or length that disagrees.
        assert_eq!(r.add(&f(65534, 4, 0, vec![1])), Ok(Added::New));
        assert_eq!(r.add(&f(65534, 5, 0, vec![1])), Err(ReassemblyError::Conflict));
        let mut other = f(65534, 4, 1, vec![1]);
        other.msg_type = 2;
        assert_eq!(r.add(&other), Err(ReassemblyError::Conflict));
        assert_eq!(r.add(&f(65534, 4, 1, vec![2, 3, 4])), Ok(Added::New));
        assert_eq!(r.next_message().unwrap().body, [1, 2, 3, 4]);
        assert_eq!(r.next_seq(), 65535);

        // Too many separate pieces: every other byte.
        let mut r = Reassembler::new();
        let n = 2 * MAX_FRAGMENT_RANGES + 2;
        for i in 0..MAX_FRAGMENT_RANGES {
            assert_eq!(r.add(&f(0, n as u32, (2 * i) as u32, vec![0])), Ok(Added::New));
        }
        let gap = (2 * MAX_FRAGMENT_RANGES) as u32;
        assert_eq!(r.add(&f(0, n as u32, gap, vec![0])), Err(ReassemblyError::TooManyRanges));
        // Filling a gap still works, and so does the rest.
        assert_eq!(r.add(&f(0, n as u32, 1, vec![0])), Ok(Added::New));
        assert_eq!(r.add(&f(0, n as u32, gap, vec![0])), Ok(Added::New));
        assert_eq!(r.buffered(), n);

        // Too many bytes held.
        let mut r = Reassembler::new();
        let big = MAX_MESSAGE_LEN as u32;
        let mut seq = 0;
        while r.buffered() + MAX_MESSAGE_LEN <= MAX_REASSEMBLY_BYTES {
            assert_eq!(r.add(&f(seq, big, 0, vec![0])), Ok(Added::New));
            seq += 1;
        }
        assert_eq!(r.add(&f(seq, big, 0, vec![0])), Err(ReassemblyError::Memory));
        assert_eq!(r.buffered(), MAX_REASSEMBLY_BYTES);
        const { assert!(MAX_MESSAGE_LEN <= MAX_REASSEMBLY_BYTES) };
    }

    fn unified(cid: Option<Vec<u8>>, has_length: bool, payload: Vec<u8>) -> Record {
        Record::Unified(UnifiedRecord {
            epoch_bits: 3,
            connection_id: cid,
            sequence: Sequence::Short(4),
            has_length,
            payload,
        })
    }

    fn cid_record(cid: Vec<u8>) -> Record {
        Record::Plain(PlainRecord {
            content_type: ContentType::TLS12_CID,
            version: version::DTLS_1_2,
            epoch: 1,
            sequence: 2,
            connection_id: cid,
            fragment: vec![0x55],
        })
    }

    #[test]
    fn datagrams_keep_protected_headers() {
        // RFC 9147, section 4: the unified header is the AEAD's additional
        // data, so a writer must not add a length to it. A record without
        // one ends the datagram, so later records make the value unwritable.
        let open = unified(None, false, vec![9; 20]);
        let plain = Record::<0>::parse(&PLAIN).unwrap();
        let invalid = Datagram::<0>(vec![plain.clone(), open.clone(), plain.clone()]);
        contract::check_wire_value(&invalid);
        assert_eq!(invalid.to_bytes(), Err(RecordError::Unwritable));
        let valid = Datagram::<0>(vec![plain, open]);
        contract::check_wire_value(&valid);
    }

    #[test]
    fn datagrams_keep_one_cid_length() {
        // RFC 9146, section 4: the receiver reads every connection ID with
        // the one length it chose, so a datagram holds only that length.
        let records = [
            cid_record(vec![0xaa]),
            cid_record(vec![0xbb, 0xcc]),
            unified(Some(vec![1, 2]), true, vec![0; 16]),
            unified(Some(vec![3]), true, vec![0; 16]),
            unified(None, true, vec![0; 16]),
        ];
        assert_eq!(Datagram::<0>(records.to_vec()).to_bytes(), Err(RecordError::Unwritable));
        for record in records { contract::check_wire_value(&record); }
    }

    #[test]
    fn plaintext_records_hold_two_to_the_fourteen() {
        // RFC 6347, section 4.1: an epoch-0 record is plaintext, at most
        // 2^14 bytes; protected records may carry 2048 more.
        let record = |epoch: u16, n: usize| {
            let mut b = vec![22, 0xfe, 0xfd];
            b.extend_from_slice(&epoch.to_be_bytes());
            b.extend_from_slice(&[0; 6]);
            b.extend_from_slice(&(n as u16).to_be_bytes());
            b.extend(std::iter::repeat_n(0, n));
            b
        };
        assert!(Record::<0>::parse(&record(0, MAX_PLAINTEXT)).is_ok());
        assert_eq!(Record::<0>::parse(&record(0, MAX_PLAINTEXT + 1)), Err(RecordError::Length(MAX_PLAINTEXT + 1)));
        assert!(Record::<0>::parse(&record(1, MAX_PLAIN_FRAGMENT)).is_ok());
        let Ok(Record::Plain(mut p)) = Record::<0>::parse(&record(1, MAX_PLAIN_FRAGMENT)) else { panic!() };
        p.epoch = 0;
        let value = Record::<0>::Plain(p);
        contract::check_wire_value(&value);
        assert_eq!(value.to_bytes(), Err(RecordError::Unwritable));
    }

    #[test]
    fn later_messages_do_not_starve_the_next() {
        // Messages 1 to 4 each claim a quarter of the budget with one byte.
        // Message 0 still goes in, and later messages make way for it.
        let mut r = Reassembler::new();
        let quarter = (MAX_REASSEMBLY_BYTES / 4) as u32;
        for seq in 1..=4 {
            let f = Fragment { msg_type: 1, length: quarter, message_seq: seq, offset: 0, body: vec![1] };
            assert_eq!(r.add(&f), Ok(Added::New));
        }
        let first = Handshake { msg_type: 1, message_seq: 0, body: vec![7] };
        assert_eq!(r.add(&first.to_fragment().unwrap()), Ok(Added::New));
        assert!(r.buffered() <= MAX_REASSEMBLY_BYTES);
        assert_eq!(r.next_message(), Some(first));
        // The furthest message made way; the nearer ones stay.
        assert_eq!(r.buffered(), 3 * quarter as usize);
        let second = Handshake { msg_type: 1, message_seq: 1, body: vec![1; quarter as usize] };
        assert_eq!(r.add(&second.to_fragment().unwrap()), Ok(Added::New));
        assert_eq!(r.next_message(), Some(second));
        // A message for the next place always fits, whatever is held.
        let mut r = Reassembler::new();
        for seq in 1..=4 {
            let f = Fragment { msg_type: 1, length: quarter, message_seq: seq, offset: 0, body: vec![1] };
            r.add(&f).unwrap();
        }
        let big = Handshake { msg_type: 1, message_seq: 0, body: vec![5; MAX_MESSAGE_LEN] };
        assert_eq!(r.add(&big.to_fragment().unwrap()), Ok(Added::New));
        assert!(r.buffered() <= MAX_REASSEMBLY_BYTES);
        assert_eq!(r.next_message(), Some(big));
    }

    #[test]
    fn client_hello_needs_suites_and_compression() {
        // RFC 6347, section 4.2.1 (as RFC 5246): cipher_suites<2..2^16-2>
        // and compression_methods<1..2^8-1>.
        let mut b = vec![0xfe, 0xfd];
        b.extend_from_slice(&[7; 32]);
        b.extend_from_slice(&[0, 0]);
        let mut empty_suites = b.clone();
        empty_suites.extend_from_slice(&[0, 0, 1, 0]);
        assert_eq!(ClientHello::parse(&empty_suites), Err(HandshakeError::CipherSuites));
        let mut empty_compression = b.clone();
        empty_compression.extend_from_slice(&[0, 2, 0xc0, 0x2b, 0]);
        assert_eq!(ClientHello::parse(&empty_compression), Err(HandshakeError::CompressionMethods));
        // Writers put in the least the format allows.
        let mut ch = ClientHello::parse(&client_hello_bytes()).unwrap();
        ch.cipher_suites.clear();
        ch.compression_methods.clear();
        contract::check_wire_value(&ch);
        assert_eq!(ch.to_bytes(), Err(HandshakeError::Unwritable));
    }

    #[test]
    fn extensions_are_unique() {
        // RFC 5246, section 7.4.1.4, and RFC 8446, section 4.2: one
        // extension of each type at most.
        let mut b = client_hello_bytes();
        let at = b.len() - 11;
        b.truncate(at);
        b.extend_from_slice(&[0, 14, 0, 43, 0, 3, 2, 0xfe, 0xfd, 0, 43, 0, 3, 2, 0xfe, 0xfc]);
        assert_eq!(ClientHello::parse(&b), Err(HandshakeError::DuplicateExtension(43)));
        let mut sh = ServerHello::parse(&server_hello_bytes()).unwrap();
        let mut bytes = sh.to_bytes().unwrap();
        let n = bytes.len();
        bytes[n - 7] = 12;
        bytes.extend_from_slice(&[0, 43, 0, 2, 0xfe, 0xfc]);
        assert_eq!(ServerHello::parse(&bytes), Err(HandshakeError::DuplicateExtension(43)));
        // Writers refuse duplicate types.
        let svs = |v: u8| Extension { typ: extension_type::SUPPORTED_VERSIONS, data: vec![0xfe, v] };
        sh.extensions = Some(vec![svs(0xfc), Extension { typ: 1, data: vec![] }, svs(0xfd)]);
        contract::check_wire_value(&sh);
        assert_eq!(sh.to_bytes(), Err(HandshakeError::Unwritable));
    }

    /// Checks every reader on `b`, and that what they read writes back to
    /// bytes that read the same.
    fn check<const CID_LEN: u8>(b: &[u8]) {
        contract::check_wire::<Record<CID_LEN>>(b);
        contract::check_wire::<Datagram<CID_LEN>>(b);
        if let Ok(record) = Record::<CID_LEN>::parse(b) {
            assert_eq!(record.to_bytes().unwrap(), b);
        }
        if let Ok(datagram) = Datagram::<CID_LEN>::parse(b) {
            assert_eq!(datagram.to_bytes().unwrap(), b);
        }
        contract::check_wire::<Fragment>(b);
        contract::check_wire::<Handshake>(b);
        contract::check_wire::<ClientHello>(b);
        contract::check_wire::<ServerHello>(b);
        contract::check_wire::<HelloVerifyRequest>(b);
        if let Ok(frags) = Fragments::parse(b).map(|fragments| fragments.0) {
            let bytes: Vec<u8> = frags.iter().flat_map(|f| f.to_bytes().unwrap()).collect();
            assert_eq!(bytes, b);
            let mut r = Reassembler::new();
            for f in &frags {
                let _ = r.add(f);
                assert!(r.buffered() <= MAX_REASSEMBLY_BYTES);
                while let Some(m) = r.next_message() {
                    let _ = m.parse_body();
                }
            }
            // The next message expected still goes in.
            let next = Handshake { msg_type: 1, message_seq: r.next_seq(), body: b.to_vec() };
            match r.add(&next.to_fragment().unwrap()) {
                Ok(_) => assert!(r.next_message().is_some()),
                Err(e) => assert_eq!(e, ReassemblyError::Conflict),
            }
        }
        if let Ok(ch) = ClientHello::parse(b) {
            assert_eq!(ch.to_bytes().unwrap(), b);
            assert!(!ch.cipher_suites.is_empty() && !ch.compression_methods.is_empty());
            let _ = ch.supported_versions();
        }
        if let Ok(sh) = ServerHello::parse(b) {
            assert_eq!(sh.to_bytes().unwrap(), b);
            let _ = (sh.selected_version(), sh.is_hello_retry_request());
        }
        if let Ok(h) = HelloVerifyRequest::parse(b) {
            assert_eq!(h.to_bytes().unwrap(), b);
        }
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg::new(0x4454_4c53);
        let samples = [PLAIN.to_vec(), client_hello_bytes(), server_hello_bytes(), vec![0xfe, 0xff, 3, 1, 2, 3]];
        let mut parsed = 0;
        for i in 0..6000 {
            let len = rng.index(160);
            let mut b = vec![0; len];
            rng.fill(&mut b);
            match i % 4 {
                // Random bytes.
                0 => {}
                // A sample with a few bytes changed, or cut short.
                1 => {
                    b = samples[rng.index(samples.len())].clone();
                    for _ in 0..1 + rng.index(3) { mutate(&mut rng, &mut b); }
                }
                // A record header that fits, over random bytes.
                2 => {
                    let n = b.len().saturating_sub(13) as u16;
                    if b.len() >= 13 {
                        b[0] = 20 + rng.index(12) as u8;
                        b[11..13].copy_from_slice(&n.to_be_bytes());
                    }
                }
                // A handshake fragment whose lengths fit.
                _ => {
                    if b.len() >= 12 {
                        let n = (b.len() - 12) as u32;
                        let extra = rng.index(4) as u32;
                        b[1..4].copy_from_slice(&(n + extra).to_be_bytes()[1..]);
                        b[6..9].copy_from_slice(&(extra.min(rng.index(2) as u32)).to_be_bytes()[1..]);
                        b[9..12].copy_from_slice(&n.to_be_bytes()[1..]);
                    }
                }
            }
            if Record::<0>::parse(&b).is_ok() || Fragment::parse(&b).is_ok() {
                parsed += 1;
            }
            { check::<0>(&b); check::<1>(&b); check::<8>(&b); };

            // Random messages, split into random fragments, passed in a random
            // order with repeats, and one byte at a time, come back whole.
            let m = Handshake { msg_type: rng.next() as u8, message_seq: 0, body: b.clone() };
            // Few enough pieces that the gaps stay under the range limit.
            let step = (1 + rng.index(16)).max(b.len().div_ceil(MAX_FRAGMENT_RANGES));
            let mut parts = m.fragments(step).unwrap();
            for k in (1..parts.len()).rev() {
                parts.swap(k, rng.index(k + 1));
            }
            if !parts.is_empty() && rng.coin() {
                let again = parts[rng.index(parts.len())].clone();
                parts.push(again);
            }
            let mut r = Reassembler::new();
            for f in &parts {
                let f = Fragment::parse(&f.to_bytes().unwrap()).unwrap();
                r.add(&f).unwrap();
            }
            assert_eq!(r.next_message().as_ref(), Some(&m));
            let mut r = Reassembler::new();
            for f in m.fragments(1).unwrap() {
                r.add(&f).unwrap();
            }
            assert_eq!(r.next_message(), Some(m));
            assert_eq!(r.buffered(), 0);
        }
        assert!(parsed > 500, "only {parsed} buffers read");
    }
}
