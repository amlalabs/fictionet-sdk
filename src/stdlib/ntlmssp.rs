//! NTLMSSP: reading and writing the NEGOTIATE, CHALLENGE and AUTHENTICATE
//! messages of NTLM authentication, with no I/O.
//!
//! A real client can answer a world's CHALLENGE with AUTHENTICATE, but this
//! module cannot verify that response or establish signing and sealing keys.
//!
//! The message and response types read and write complete values through
//! `Wire`. There is no stream decoder, authentication state machine, or
//! `Service`. Hashes, response verification, signing, and sealing belong to the
//! caller.
//!
//! NTLM is how Windows machines prove who a user is without a domain
//! controller in the path of every request. A client opens with a
//! NEGOTIATE message that lists what it supports. The server answers with
//! a CHALLENGE message that carries 8 random bytes and a list of names
//! (the target info). The client answers with an AUTHENTICATE message that
//! names the user and carries responses computed from the challenge and
//! the user's password. The three messages travel inside SMB, HTTP
//! (`Authorization: NTLM`), RPC, LDAP and others, often wrapped in a
//! [`spnego`](fictionet::stdlib::spnego) token. This module follows Microsoft's
//! \[MS-NLMP\] section 2.2.
//!
//! Nothing here reads a socket, decodes base64 or computes a hash. A world
//! that plays a file server takes the token its SMB or HTTP code hands it,
//! reads it with [`Message::parse`], and writes its answer with
//! [`Challenge::write`]. Names, responses and session keys are kept as
//! bytes. [`AvPairs::parse`], [`NtResponse::parse`] and
//! [`LmV2Response::parse`] read the parts that have a layout of their own.
//! Whether a response is correct, and whether to let the user in, is up to
//! world code.
//!
//! Every reader checks lengths and offsets, because the agent can send any
//! bytes it likes. A message is at most [`MAX_MESSAGE`] bytes, and a list
//! of AV pairs holds at most [`MAX_AV_PAIRS`] pairs. Writers return an
//! [`Error::Unwritable`] rather than write bytes a reader would refuse or read
//! back as something else.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::ntlmssp::{
//!     AvPair, Authenticate, Challenge, ClientChallenge, Message, Negotiate, NtResponse, NtlmV2Response,
//!     av_id, UnicodeName, AvPairs, flags,
//! };
//!
//! // What a client sends first.
//! let negotiate = Negotiate {
//!     flags: flags::NEGOTIATE_UNICODE | flags::NEGOTIATE_NTLM | flags::REQUEST_TARGET,
//!     domain: Vec::new(),
//!     workstation: Vec::new(),
//!     version: None,
//! };
//! let Ok(Message::Negotiate(n)) = Message::parse(&negotiate.to_bytes().unwrap()) else { panic!() };
//!
//! // The world, playing a server in domain CORP, answers with a challenge.
//! let names = [AvPair { id: av_id::NB_DOMAIN_NAME, value: UnicodeName("CORP".into()).to_bytes().unwrap() }];
//! let challenge = Challenge {
//!     flags: n.flags | flags::NEGOTIATE_TARGET_INFO | flags::TARGET_TYPE_DOMAIN,
//!     target_name: UnicodeName("CORP".into()).to_bytes().unwrap(),
//!     server_challenge: [1, 2, 3, 4, 5, 6, 7, 8],
//!     target_info: AvPairs(names.to_vec()).to_bytes().unwrap(),
//!     version: None,
//! };
//! let reply = challenge.to_bytes().unwrap();
//! assert_eq!(&reply[..12], b"NTLMSSP\0\x02\0\0\0");
//!
//! // The client's answer, built here to stand in for one the agent sends.
//! let nt = NtResponse::V2(NtlmV2Response {
//!     nt_proof: [0xaa; 16],
//!     client: ClientChallenge {
//!         resp_type: 1,
//!         hi_resp_type: 1,
//!         timestamp: 0,
//!         challenge: [9; 8],
//!         av_pairs: names.to_vec(),
//!         trailing: vec![0; 4],
//!     },
//! });
//! let auth = Authenticate {
//!     flags: n.flags,
//!     lm_response: vec![0; 24],
//!     nt_response: nt.to_bytes().unwrap(),
//!     domain: UnicodeName("CORP".into()).to_bytes().unwrap(),
//!     user: UnicodeName("alice".into()).to_bytes().unwrap(),
//!     workstation: Vec::new(),
//!     session_key: Vec::new(),
//!     version: None,
//!     mic: None,
//! };
//! let Ok(Message::Authenticate(a)) = Message::parse(&auth.to_bytes().unwrap()) else { panic!() };
//! assert_eq!(UnicodeName::parse(&a.user).unwrap().0, "alice");
//! let Ok(NtResponse::V2(v2)) = NtResponse::parse(&a.nt_response) else { panic!() };
//! assert_eq!(v2.client.challenge, [9; 8]);
//! ```

use fictionet::stdlib::codec::{Wire, le16, le32};

/// The 8 bytes every NTLMSSP message starts with.
pub const SIGNATURE: [u8; 8] = *b"NTLMSSP\0";
/// The longest message a reader accepts and a writer writes.
pub const MAX_MESSAGE: usize = 64 * 1024;
/// The longest payload field: its length is a 16-bit number.
pub const MAX_FIELD: usize = u16::MAX as usize;
/// The most AV pairs one list may hold, not counting the end marker.
pub const MAX_AV_PAIRS: usize = 1024;
/// The length of a [`Version`] on the wire.
pub const VERSION_LEN: usize = 8;
/// The length of the message integrity code in an AUTHENTICATE message.
pub const MIC_LEN: usize = 16;
/// Where the MIC of an AUTHENTICATE message ends: after the 64-byte fixed
/// part, the 8-byte version and the MIC itself.
pub const MIC_END: usize = AUTHENTICATE_HEADER_LEN + VERSION_LEN + MIC_LEN;
/// The fixed part of a NEGOTIATE message, before any version.
pub const NEGOTIATE_HEADER_LEN: usize = 32;
/// The fixed part of a CHALLENGE message, before any version.
pub const CHALLENGE_HEADER_LEN: usize = 48;
/// The fixed part of an AUTHENTICATE message, before any version and MIC.
pub const AUTHENTICATE_HEADER_LEN: usize = 64;
/// The length of an LMv1, LMv2 or NTLMv1 response.
pub const V1_RESPONSE_LEN: usize = 24;
/// The length of the NTProofStr at the start of an NTLMv2 response.
pub const NT_PROOF_LEN: usize = 16;
/// The fixed part of an NTLMv2 client challenge, before its AV pairs.
pub const CLIENT_CHALLENGE_HEADER_LEN: usize = 28;

/// The message type numbers, at bytes 8 to 11 of every message.
pub mod message_type {
    /// A NEGOTIATE message, sent by the client first.
    pub const NEGOTIATE: u32 = 1;
    /// A CHALLENGE message, the server's answer.
    pub const CHALLENGE: u32 = 2;
    /// An AUTHENTICATE message, the client's answer to the challenge.
    pub const AUTHENTICATE: u32 = 3;
}

/// The negotiate flags, from \[MS-NLMP\] section 2.2.2.5. Each names one
/// bit of the 32-bit flags field.
pub mod flags {
    /// Strings are UTF-16LE.
    pub const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
    /// Strings are in the OEM code page.
    pub const NEGOTIATE_OEM: u32 = 0x0000_0002;
    /// The server should send its name in the CHALLENGE message.
    pub const REQUEST_TARGET: u32 = 0x0000_0004;
    /// Messages after authentication are signed.
    pub const NEGOTIATE_SIGN: u32 = 0x0000_0010;
    /// Messages after authentication are sealed (encrypted).
    pub const NEGOTIATE_SEAL: u32 = 0x0000_0020;
    /// Connectionless (datagram) authentication.
    pub const NEGOTIATE_DATAGRAM: u32 = 0x0000_0040;
    /// LAN Manager session key computation.
    pub const NEGOTIATE_LM_KEY: u32 = 0x0000_0080;
    /// NTLM v1 session security.
    pub const NEGOTIATE_NTLM: u32 = 0x0000_0200;
    /// An anonymous connection.
    pub const ANONYMOUS: u32 = 0x0000_0800;
    /// The NEGOTIATE message's domain field is set.
    pub const NEGOTIATE_OEM_DOMAIN_SUPPLIED: u32 = 0x0000_1000;
    /// The NEGOTIATE message's workstation field is set.
    pub const NEGOTIATE_OEM_WORKSTATION_SUPPLIED: u32 = 0x0000_2000;
    /// A signature block on every message, even unsigned ones.
    pub const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
    /// The target name is a domain.
    pub const TARGET_TYPE_DOMAIN: u32 = 0x0001_0000;
    /// The target name is a server.
    pub const TARGET_TYPE_SERVER: u32 = 0x0002_0000;
    /// NTLM v2 session security (extended session security).
    pub const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
    /// An identify-level token.
    pub const NEGOTIATE_IDENTIFY: u32 = 0x0010_0000;
    /// A session key that does not come from the NT hash.
    pub const REQUEST_NON_NT_SESSION_KEY: u32 = 0x0040_0000;
    /// The CHALLENGE message's target info field is set.
    pub const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
    /// The message carries a [`Version`](super::Version).
    pub const NEGOTIATE_VERSION: u32 = 0x0200_0000;
    /// 128-bit session keys.
    pub const NEGOTIATE_128: u32 = 0x2000_0000;
    /// An encrypted session key is exchanged.
    pub const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
    /// 56-bit session keys.
    pub const NEGOTIATE_56: u32 = 0x8000_0000;
}

/// AV pair IDs, from \[MS-NLMP\] section 2.2.2.1.
pub mod av_id {
    /// The end of the list. Writers add it; it is never a pair of its own.
    pub const EOL: u16 = 0x0000;
    /// The server's NetBIOS computer name, UTF-16LE.
    pub const NB_COMPUTER_NAME: u16 = 0x0001;
    /// The server's NetBIOS domain name, UTF-16LE.
    pub const NB_DOMAIN_NAME: u16 = 0x0002;
    /// The server's DNS computer name, UTF-16LE.
    pub const DNS_COMPUTER_NAME: u16 = 0x0003;
    /// The server's DNS domain name, UTF-16LE.
    pub const DNS_DOMAIN_NAME: u16 = 0x0004;
    /// The DNS name of the forest, UTF-16LE.
    pub const DNS_TREE_NAME: u16 = 0x0005;
    /// A 32-bit little-endian flags value. Bit 0x2 says the AUTHENTICATE
    /// message carries a MIC.
    pub const FLAGS: u16 = 0x0006;
    /// The server's time as a 64-bit little-endian FILETIME.
    pub const TIMESTAMP: u16 = 0x0007;
    /// A Single_Host_Data structure.
    pub const SINGLE_HOST: u16 = 0x0008;
    /// The SPN of the target server, UTF-16LE.
    pub const TARGET_NAME: u16 = 0x0009;
    /// A 16-byte hash of the channel bindings.
    pub const CHANNEL_BINDINGS: u16 = 0x000a;
}

/// The revision number current versions of NTLMSSP send in a [`Version`].
pub const NTLMSSP_REVISION_W2K3: u8 = 0x0f;

/// The operating system version a message may carry, for debugging. Its
/// three reserved bytes are not kept and are written as zeros.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Version {
    /// The major version, such as 10 for Windows 10.
    pub major: u8,
    /// The minor version.
    pub minor: u8,
    /// The build number.
    pub build: u16,
    /// The NTLMSSP revision, usually [`NTLMSSP_REVISION_W2K3`].
    pub revision: u8,
}

impl Version {
    /// Reads a version from its 8 bytes.
    pub fn from_bytes(b: [u8; VERSION_LEN]) -> Version {
        Version {
            major: b[0],
            minor: b[1],
            build: u16::from_le_bytes([b[2], b[3]]),
            revision: b[7],
        }
    }
}

/// Why bytes are not the message, or the part of one, a reader expected,
/// or why a writer refused a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// A name is not valid UTF-16LE.
    Unicode,
    /// Bytes follow the last payload field.
    Trailing,
    /// A message of more than [`MAX_MESSAGE`] bytes, a message whose
    /// fields (which may overlap) would not fit in that when written
    /// back, or an NT response or AV pair list of more than [`MAX_FIELD`].
    TooLong,
    /// Fewer bytes than the fixed part of the message, or of the
    /// structure, needs.
    Truncated,
    /// The first 8 bytes are not [`SIGNATURE`].
    Signature,
    /// A message type other than the one expected, or not one of the three.
    MessageType(u32),
    /// A payload field, named here, runs past the end of the message or
    /// starts inside its fixed part.
    Field(&'static str),
    /// An AV pair's value runs past the end of the list, the list ends
    /// with no end marker, or bytes follow the end marker in a CHALLENGE
    /// message's target info.
    AvPairs,
    /// The end marker of an AV pair list has a length other than 0.
    AvEolLength(u16),
    /// More than [`MAX_AV_PAIRS`] pairs.
    TooManyAvPairs,
    /// A response with a length no layout has.
    ResponseLength(usize),
    /// An AV pair, by its ID, whose value has a length its ID does not
    /// allow: a flags value other than 4 bytes, a timestamp other than 8,
    /// channel bindings other than 16, or a name of odd length.
    AvValue(u16),
    /// A Unicode string field, named here, at an odd offset or of odd
    /// length. \[MS-NLMP\] 2.2.1.2 and 2.2.1.3 want both even.
    OddUnicode(&'static str),
    /// An NTLMv2 response whose two response version bytes, given here,
    /// are not both 1, as \[MS-NLMP\] 2.2.2.7 requires.
    ResponseVersion(u8, u8),
    /// A writer refused the value: its bytes would break the
    /// specification, or a reader would read them back as something else.
    Unwritable,
}

fictionet::error_display!(Error, f, {
    Error::Unicode => f.write_str("invalid UTF-16LE name"),
    Error::Trailing => f.write_str("bytes after the payload"),
    Error::TooLong => write!(
        f,
        "longer than {MAX_MESSAGE} bytes, or a response longer than {MAX_FIELD}"
    ),
    Error::Truncated => f.write_str("too short for its fixed fields"),
    Error::Signature => f.write_str("does not start with NTLMSSP\\0"),
    Error::MessageType(t) => write!(f, "message type {t} where another was expected"),
    Error::Field(name) => write!(f, "the {name} field lies outside the message payload"),
    Error::AvPairs => {
        f.write_str("an AV pair list that runs past its end or has no end marker")
    }
    Error::AvEolLength(n) => write!(f, "an AV pair end marker of length {n}, not 0"),
    Error::TooManyAvPairs => write!(f, "more than {MAX_AV_PAIRS} AV pairs"),
    Error::ResponseLength(n) => write!(f, "a response of {n} bytes, which no layout has"),
    Error::AvValue(id) => write!(
        f,
        "an AV pair with ID {id} whose value has the wrong length"
    ),
    Error::OddUnicode(name) => {
        write!(f, "the Unicode {name} field has an odd offset or length")
    }
    Error::ResponseVersion(a, b) => {
        write!(f, "an NTLMv2 response of versions {a} and {b}, not 1 and 1")
    }
    Error::Unwritable => f.write_str("value cannot be written without changing it"),
});

/// One attribute-value pair of a target info list.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AvPair {
    /// What the value is: one of the [`av_id`] numbers, or any other.
    pub id: u16,
    /// The value's bytes, at most 65535.
    pub value: Vec<u8>,
}

/// The bit of an [`av_id::FLAGS`] value that says the AUTHENTICATE message
/// carries a MIC.
const AV_FLAG_MIC: u32 = 0x0000_0002;

/// Whether `value` has a length the pair ID `id` allows, from \[MS-NLMP\]
/// 2.2.2.1. IDs the table does not define, and Single_Host_Data, are kept
/// as bytes of any length.
fn av_value_fits(id: u16, value: &[u8]) -> bool {
    match id {
        av_id::FLAGS => value.len() == 4,
        av_id::TIMESTAMP => value.len() == 8,
        av_id::CHANNEL_BINDINGS => value.len() == 16,
        av_id::NB_COMPUTER_NAME..=av_id::DNS_TREE_NAME | av_id::TARGET_NAME => {
            value.len().is_multiple_of(2)
        }
        _ => true,
    }
}

impl AvPair {
    /// The first pair in `pairs` with ID `id`.
    pub fn find(pairs: &[AvPair], id: u16) -> Option<&AvPair> {
        pairs.iter().find(|p| p.id == id)
    }
}

/// The NEGOTIATE message: what the client supports, and optionally its
/// domain and workstation names. The default has no flags, no names and
/// no version, and writes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Negotiate {
    /// The negotiate flags, from [`flags`].
    pub flags: u32,
    /// The client's domain name in the OEM code page. Usually empty.
    pub domain: Vec<u8>,
    /// The client's workstation name in the OEM code page. Usually empty.
    pub workstation: Vec<u8>,
    /// The client's version, present exactly when `flags` has
    /// [`flags::NEGOTIATE_VERSION`].
    pub version: Option<Version>,
}

/// The CHALLENGE message: the server's answer, with the random bytes the
/// client's responses are computed from. The default is all zeros and
/// empty fields, and writes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Challenge {
    /// The negotiate flags the server chose, from [`flags`].
    pub flags: u32,
    /// The server's name or domain, UTF-16LE or OEM as `flags` says.
    pub target_name: Vec<u8>,
    /// The 8 random bytes the client must answer.
    pub server_challenge: [u8; 8],
    /// The bytes of an AV pair list; read them with [`AvPairs::parse`]
    /// and write them with [`AvPairs::write`]. Kept as bytes, since
    /// the client copies them into its NTLMv2 response.
    pub target_info: Vec<u8>,
    /// The server's version, present exactly when `flags` has
    /// [`flags::NEGOTIATE_VERSION`].
    pub version: Option<Version>,
}

/// The AUTHENTICATE message: who the user is, and the responses that
/// prove it. The default is an empty message with no version or MIC, and
/// writes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Authenticate {
    /// The negotiate flags, from [`flags`].
    pub flags: u32,
    /// The LM response; see [`LmV2Response`]. Often 24 zeros or empty.
    pub lm_response: Vec<u8>,
    /// The NT response; read it with [`NtResponse::parse`].
    pub nt_response: Vec<u8>,
    /// The user's domain, UTF-16LE or OEM as `flags` says.
    pub domain: Vec<u8>,
    /// The user name, UTF-16LE or OEM as `flags` says.
    pub user: Vec<u8>,
    /// The client's workstation name, UTF-16LE or OEM as `flags` says.
    pub workstation: Vec<u8>,
    /// The encrypted random session key, when keys are exchanged.
    pub session_key: Vec<u8>,
    /// The client's version, present exactly when `flags` has
    /// [`flags::NEGOTIATE_VERSION`].
    pub version: Option<Version>,
    /// The 16 bytes of the MIC slot, at bytes 72 to 88. Readers fill it
    /// when the payload starts at byte 88 or later, so that the slot is
    /// not payload. Whether the client vouches for a MIC is a separate
    /// question, answered by [`Authenticate::claims_mic`]: a server that
    /// checks integrity must require a MIC whenever that is true, not
    /// only check one when this is `Some`.
    pub mic: Option<[u8; MIC_LEN]>,
}

/// Any of the three messages.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Message {
    /// Message type 1.
    Negotiate(Negotiate),
    /// Message type 2.
    Challenge(Challenge),
    /// Message type 3.
    Authenticate(Authenticate),
}

/// Checks the signature and the message type, and that `b` holds `fixed`
/// bytes. It returns the flags at `flags_at` and where the payload may
/// start, past the version if the flags say there is one.
fn header(
    b: &[u8],
    kind: u32,
    fixed: usize,
    flags_at: usize,
) -> Result<(u32, Option<Version>, usize), Error> {
    if b.len() > MAX_MESSAGE {
        return Err(Error::TooLong);
    }
    let n = b.len().min(SIGNATURE.len());
    if b[..n] != SIGNATURE[..n] {
        return Err(Error::Signature);
    }
    if b.len() < 12 {
        return Err(Error::Truncated);
    }
    let t = le32(b, 8).ok_or(Error::Truncated)?;
    if t != kind {
        return Err(Error::MessageType(t));
    }
    if b.len() < fixed {
        return Err(Error::Truncated);
    }
    let flags = le32(b, flags_at).ok_or(Error::Truncated)?;
    if flags & flags::NEGOTIATE_VERSION == 0 {
        return Ok((flags, None, fixed));
    }
    let end = fixed + VERSION_LEN;
    let Some(v) = b.get(fixed..end) else {
        return Err(Error::Truncated);
    };
    let mut bytes = [0u8; VERSION_LEN];
    bytes.copy_from_slice(v);
    Ok((flags, Some(Version::from_bytes(bytes)), end))
}

/// Where the payload field described at `at` starts, if it is not empty.
fn field_offset(b: &[u8], at: usize) -> Option<usize> {
    if le16(b, at)? != 0 {
        Some(le32(b, at + 4)? as usize)
    } else {
        None
    }
}

/// The payload field described at `at`: a length, a maximum length (not
/// read) and an offset. A field that is not empty must lie between `start`
/// and the end of `b`.
fn field(b: &[u8], at: usize, start: usize, name: &'static str) -> Result<Vec<u8>, Error> {
    let len = usize::from(le16(b, at).ok_or(Error::Truncated)?);
    if len == 0 {
        return Ok(Vec::new());
    }
    let offset = le32(b, at + 4).ok_or(Error::Truncated)? as usize;
    if offset < start {
        return Err(Error::Field(name));
    }
    let end = offset.checked_add(len).ok_or(Error::Field(name))?;
    b.get(offset..end)
        .map(<[u8]>::to_vec)
        .ok_or(Error::Field(name))
}

/// The payload field described at `at`, read as [`field`] reads it. When
/// `unicode` is true it is a UTF-16LE string, and a string that is not
/// empty must have an even offset and an even length.
fn text_field(
    b: &[u8],
    at: usize,
    start: usize,
    name: &'static str,
    unicode: bool,
) -> Result<Vec<u8>, Error> {
    let v = field(b, at, start, name)?;
    if unicode
        && !v.is_empty()
        && (!v.len().is_multiple_of(2)
            || !le32(b, at + 4).ok_or(Error::Truncated)?.is_multiple_of(2))
    {
        return Err(Error::OddUnicode(name));
    }
    Ok(v)
}

/// A field whose flag may be clear. \[MS-NLMP\] says the descriptor of a
/// field whose flag is clear must be ignored on receipt, so a bad one is
/// read as an empty field rather than an error. One that reads is kept as
/// bytes for world code to see, and is written back the same.
fn optional(present: bool, read: Result<Vec<u8>, Error>) -> Result<Vec<u8>, Error> {
    match read {
        Err(_) if !present => Ok(Vec::new()),
        r => r,
    }
}

/// Checks that a target info field that is not empty is exactly one AV
/// pair list, as \[MS-NLMP\] 2.2.1.2 wants: no bytes after the end marker.
fn check_target_info(t: &[u8]) -> Result<(), Error> {
    if t.is_empty() {
        return Ok(());
    }
    let (_, used) = AvPairs::parse_prefix(t)?;
    if used != t.len() {
        return Err(Error::AvPairs);
    }
    Ok(())
}

/// Checks that a Unicode string has an even length.
fn check_text(unicode: bool, data: &[u8]) -> Result<(), Error> {
    if unicode && !data.len().is_multiple_of(2) {
        return Err(Error::Unwritable);
    }
    Ok(())
}

/// Checks that the version matches the flags.
fn check_version(flags: u32, version: Option<Version>) -> Result<(), Error> {
    if version.is_some() != (flags & flags::NEGOTIATE_VERSION != 0) {
        return Err(Error::Unwritable);
    }
    Ok(())
}

/// How long a message is once written: `fixed` bytes, then each field
/// that is not empty, from an even offset. \[MS-NLMP\] wants Unicode
/// strings at even offsets, so writers pad one zero byte where needed.
/// Readers use this too, so that whatever they accept can be written back.
fn written_len(fixed: usize, lens: &[usize]) -> usize {
    let mut n = fixed;
    for &len in lens {
        if len != 0 {
            n = n.saturating_add(n % 2).saturating_add(len);
        }
    }
    n
}

/// Appends the payload fields to `out`, which holds the fixed part, and
/// fills in each field's length, maximum length and offset at its slot.
/// Each field that is not empty starts at an even offset.
fn put_fields(out: &mut Vec<u8>, fields: &[(usize, &[u8])]) -> Result<(), Error> {
    let mut lens = [0usize; 6];
    for (i, &(_, data)) in fields.iter().enumerate() {
        if data.len() > MAX_FIELD {
            return Err(Error::Unwritable);
        }
        if let Some(l) = lens.get_mut(i) {
            *l = data.len();
        }
    }
    let total = written_len(out.len(), &lens[..fields.len().min(lens.len())]);
    if total > MAX_MESSAGE {
        return Err(Error::Unwritable);
    }
    out.reserve(total - out.len());
    for &(slot, data) in fields {
        if !data.is_empty() && out.len() % 2 == 1 {
            out.push(0);
        }
        let len = (data.len() as u16).to_le_bytes();
        let offset = (out.len() as u32).to_le_bytes();
        out[slot..slot + 2].copy_from_slice(&len);
        out[slot + 2..slot + 4].copy_from_slice(&len);
        out[slot + 4..slot + 8].copy_from_slice(&offset);
        out.extend_from_slice(data);
    }
    Ok(())
}

/// Checks that fields read from a message, after a fixed part of `fixed`
/// bytes, would fit in [`MAX_MESSAGE`] when written back. Fields may
/// overlap in what an agent sends, so their total can exceed the message.
fn check_written(fixed: usize, fields: &[&[u8]]) -> Result<(), Error> {
    let mut lens = [0usize; 6];
    for (l, f) in lens.iter_mut().zip(fields) {
        *l = f.len();
    }
    if written_len(fixed, &lens[..fields.len().min(lens.len())]) > MAX_MESSAGE {
        return Err(Error::TooLong);
    }
    Ok(())
}

/// The first bytes of a message: signature and type, then zeros up to
/// `fixed`, the flags at `flags_at`, and the version if there is one.
fn start(
    kind: u32,
    fixed: usize,
    flags_at: usize,
    flags: u32,
    version: Option<Version>,
) -> Vec<u8> {
    let mut out = vec![0u8; fixed];
    out[..8].copy_from_slice(&SIGNATURE);
    out[8..12].copy_from_slice(&kind.to_le_bytes());
    out[flags_at..flags_at + 4].copy_from_slice(&flags.to_le_bytes());
    if let Some(v) = version {
        let [b0, b1] = v.build.to_le_bytes();
        out.extend_from_slice(&[v.major, v.minor, b0, b1, 0, 0, 0, v.revision]);
    }
    out
}

impl Challenge {
    /// The AV pairs of the target info, read with [`AvPairs::parse`].
    /// Bytes after the end marker are an error, [`Error::AvPairs`].
    pub fn target_info_pairs(&self) -> Result<Vec<AvPair>, Error> {
        let (pairs, used) = AvPairs::parse_prefix(&self.target_info)?;
        if used != self.target_info.len() {
            return Err(Error::AvPairs);
        }
        Ok(pairs)
    }
}

/// Where each AUTHENTICATE payload field is described, and its name.
const AUTH_FIELDS: [(usize, &str); 6] = [
    (12, "LM response"),
    (20, "NT response"),
    (28, "domain"),
    (36, "user"),
    (44, "workstation"),
    (52, "session key"),
];

impl Authenticate {
    /// The NT response, read with [`NtResponse::parse`].
    pub fn nt(&self) -> Result<NtResponse, Error> {
        NtResponse::parse(&self.nt_response)
    }

    /// Whether the client says the message carries a MIC: its NT response
    /// is NTLMv2, and the [`av_id::FLAGS`] pair there has bit 0x2 set
    /// (\[MS-NLMP\] 2.2.2.1 and 3.2.5.1.2). The NTProofStr covers that
    /// pair, so a peer cannot clear it without breaking the response. A
    /// message can say so and still leave no room for a MIC, with `mic`
    /// `None`; a server that checks integrity should then refuse it.
    pub fn claims_mic(&self) -> bool {
        let Ok(NtResponse::V2(v2)) = self.nt() else {
            return false;
        };
        AvPair::find(&v2.client.av_pairs, av_id::FLAGS)
            .and_then(|p| <[u8; 4]>::try_from(p.value.as_slice()).ok())
            .is_some_and(|v| u32::from_le_bytes(v) & AV_FLAG_MIC != 0)
    }

    /// A copy of the AUTHENTICATE message `b` with its MIC set to zeros,
    /// as the MIC is computed over it. `None` if `b` does not read as an
    /// AUTHENTICATE message with a MIC.
    pub fn mic_input(b: &[u8]) -> Option<MicInput> {
        Authenticate::parse(b).ok()?.mic?;
        let mut out = b.to_vec();
        out.get_mut(MIC_END - MIC_LEN..MIC_END)?.fill(0);
        Some(MicInput(out))
    }

    /// The six payload fields, in the order the message describes them.
    fn fields(&self) -> [&[u8]; 6] {
        [
            &self.lm_response,
            &self.nt_response,
            &self.domain,
            &self.user,
            &self.workstation,
            &self.session_key,
        ]
    }
}

impl Message {
    /// The message's type number, from [`message_type`].
    pub fn message_type(&self) -> u32 {
        match self {
            Message::Negotiate(_) => message_type::NEGOTIATE,
            Message::Challenge(_) => message_type::CHALLENGE,
            Message::Authenticate(_) => message_type::AUTHENTICATE,
        }
    }

    /// The message's flags.
    pub fn flags(&self) -> u32 {
        match self {
            Message::Negotiate(m) => m.flags,
            Message::Challenge(m) => m.flags,
            Message::Authenticate(m) => m.flags,
        }
    }
}

/// An LMv2 response: 16 bytes of HMAC, then the client's 8 random bytes.
/// An LMv1 response has the same length, so which one a message carries
/// is up to the flags and world code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LmV2Response {
    /// The HMAC-MD5 of the challenges.
    pub response: [u8; 16],
    /// The client's 8 random bytes.
    pub client_challenge: [u8; 8],
}

/// The client challenge blob of an NTLMv2 response (NTLMv2_CLIENT_CHALLENGE).
/// Its reserved fields are not kept and are written as zeros.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientChallenge {
    /// The response version, 1.
    pub resp_type: u8,
    /// The highest response version the client knows, 1.
    pub hi_resp_type: u8,
    /// The client's time, as a FILETIME: 100 ns units since 1601.
    pub timestamp: u64,
    /// The client's 8 random bytes.
    pub challenge: [u8; 8],
    /// The AV pairs, usually the server's target info with a few added.
    pub av_pairs: Vec<AvPair>,
    /// Bytes after the list's end marker. Windows sends the 4 zeros of
    /// \[MS-NLMP\] 3.3.2; a world building a response should too.
    pub trailing: Vec<u8>,
}

/// An NTLMv2 response: the NTProofStr, then the client challenge it was
/// computed over.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NtlmV2Response {
    /// The NTProofStr, an HMAC-MD5 of the challenges.
    pub nt_proof: [u8; NT_PROOF_LEN],
    /// The blob the proof covers.
    pub client: ClientChallenge,
}

/// The NT response of an AUTHENTICATE message, by its layout.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NtResponse {
    /// No response: an anonymous login.
    Empty,
    /// An NTLMv1 response: 24 bytes.
    V1([u8; V1_RESPONSE_LEN]),
    /// An NTLMv2 response.
    V2(NtlmV2Response),
}

/// A Unicode name encoded as UTF-16LE in an NTLM field.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UnicodeName(
    /// The decoded name.
    pub String,
);

impl Wire for UnicodeName {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads the whole name. Refuses invalid UTF-16 or more than [`MAX_FIELD`] bytes.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() > MAX_FIELD {
            return Err(Error::TooLong);
        }
        decode_utf16le(b).map(Self).ok_or(Error::Unicode)
    }

    /// Appends UTF-16LE. Refuses names above [`MAX_FIELD`] bytes.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let len = self
            .0
            .encode_utf16()
            .count()
            .checked_mul(2)
            .ok_or(Error::Unwritable)?;
        if len > MAX_FIELD {
            return Err(Error::Unwritable);
        }
        for unit in self.0.encode_utf16() {
            dst.extend_from_slice(&unit.to_le_bytes());
        }
        Ok(())
    }
}

/// The string UTF-16LE bytes spell, or None for odd length or invalid UTF-16.
fn decode_utf16le(b: &[u8]) -> Option<String> {
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let units = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]));
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .ok()
}

/// The original AUTHENTICATE layout with its MIC field set to zero.
/// Construct it with [`Authenticate::mic_input`] before computing the MIC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MicInput(Vec<u8>);

impl Wire for MicInput {
    type ParseError = Error;
    type WriteError = Error;

    /// Keeps the original layout. Refuses invalid tokens, absent MICs and nonzero MICs.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        if Authenticate::parse(b)?.mic != Some([0; MIC_LEN]) {
            return Err(Error::Field("MIC"));
        }
        Ok(Self(b.to_vec()))
    }

    /// Appends the stored token without changing field offsets. Refuses no values.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        dst.extend_from_slice(&self.0);
        Ok(())
    }
}

/// An AV pair list, including its end marker on the wire.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct AvPairs(
    /// AV pairs in wire order, excluding the final end marker.
    pub Vec<AvPair>,
);

impl AvPairs {
    /// Reads a list of pairs from the start of `b`, up to and including
    /// the end marker. It returns the pairs, without the marker, and how
    /// many bytes of `b` the list took. Bytes after the marker are left.
    ///
    /// A pair whose ID the specification defines must have a value of the
    /// length that ID allows (see [`Error::AvValue`]). Pairs with IDs
    /// it does not define are kept as they are, so that lists from newer
    /// peers still read. A list longer than [`MAX_FIELD`] bytes cannot sit
    /// in any message field and is refused with [`Error::TooLong`].
    fn parse_prefix(b: &[u8]) -> Result<(Vec<AvPair>, usize), Error> {
        let mut pairs = Vec::new();
        let mut at = 0usize;
        loop {
            let Some(head) = b.get(at..at.checked_add(4).ok_or(Error::AvPairs)?) else {
                return Err(Error::AvPairs);
            };
            if at + 4 > MAX_FIELD {
                return Err(Error::TooLong);
            }
            let id = u16::from_le_bytes([head[0], head[1]]);
            let len = u16::from_le_bytes([head[2], head[3]]);
            at += 4;
            if id == av_id::EOL {
                if len != 0 {
                    return Err(Error::AvEolLength(len));
                }
                return Ok((pairs, at));
            }
            let end = at.checked_add(usize::from(len)).ok_or(Error::AvPairs)?;
            let Some(value) = b.get(at..end) else {
                return Err(Error::AvPairs);
            };
            if end > MAX_FIELD {
                return Err(Error::TooLong);
            }
            if pairs.len() >= MAX_AV_PAIRS {
                return Err(Error::TooManyAvPairs);
            }
            if !av_value_fits(id, value) {
                return Err(Error::AvValue(id));
            }
            pairs.push(AvPair {
                id,
                value: value.to_vec(),
            });
            at = end;
        }
    }
}

/// Writes a complete AV list after checking all lengths.
fn write_pairs(pairs: &[AvPair], dst: &mut Vec<u8>) -> Result<(), Error> {
    if pairs.len() > MAX_AV_PAIRS {
        return Err(Error::Unwritable);
    }
    let mut total = 4usize;
    for p in pairs {
        if p.id == av_id::EOL {
            return Err(Error::Unwritable);
        }
        if p.value.len() > usize::from(u16::MAX) {
            return Err(Error::Unwritable);
        }
        if !av_value_fits(p.id, &p.value) {
            return Err(Error::Unwritable);
        }
        total = total.saturating_add(4 + p.value.len());
    }
    // Checked before anything is copied, so a long list costs nothing.
    if total > MAX_FIELD {
        return Err(Error::Unwritable);
    }
    let mut out = Vec::with_capacity(total);
    for p in pairs {
        out.extend_from_slice(&p.id.to_le_bytes());
        out.extend_from_slice(&(p.value.len() as u16).to_le_bytes());
        out.extend_from_slice(&p.value);
    }
    out.extend_from_slice(&[0, 0, 0, 0]);
    dst.extend_from_slice(&out);
    Ok(())
}

impl Wire for AvPairs {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a complete AV list and its end marker. Refuses a missing marker,
    /// invalid values for defined IDs, excess pair counts, lists above [`MAX_FIELD`]
    /// and trailing bytes. Unknown IDs keep their complete values.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        let (pairs, used) = Self::parse_prefix(b)?;
        if used != b.len() {
            return Err(Error::Trailing);
        }
        Ok(Self(pairs))
    }

    /// Appends a complete list. Refuses end-marker pairs, invalid lengths and oversized lists.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        write_pairs(&self.0, dst)
    }
}

impl Wire for Negotiate {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a NEGOTIATE message. Bytes past the payload are refused. A
    /// name whose flag ([`flags::NEGOTIATE_OEM_DOMAIN_SUPPLIED`] or
    /// [`flags::NEGOTIATE_OEM_WORKSTATION_SUPPLIED`]) is clear is read
    /// when its descriptor is good and is empty when it is not, since
    /// \[MS-NLMP\] 2.2.1.1 says to ignore that descriptor.
    /// Refuses malformed or trailing input.
    fn parse(b: &[u8]) -> Result<Negotiate, Error> {
        let (flags, version, start) = header(b, message_type::NEGOTIATE, NEGOTIATE_HEADER_LEN, 12)?;
        let n = Negotiate {
            flags,
            domain: optional(
                flags & flags::NEGOTIATE_OEM_DOMAIN_SUPPLIED != 0,
                field(b, 16, start, "domain"),
            )?,
            workstation: optional(
                flags & flags::NEGOTIATE_OEM_WORKSTATION_SUPPLIED != 0,
                field(b, 24, start, "workstation"),
            )?,
            version,
        };
        check_written(start, &[&n.domain, &n.workstation])?;
        check_end(b, start, &[16, 24])?;
        Ok(n)
    }

    /// Appends the token. Refuses oversized fields or messages and inconsistent
    /// flags and version. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        check_version(self.flags, self.version)?;
        let mut out = start(
            message_type::NEGOTIATE,
            NEGOTIATE_HEADER_LEN,
            12,
            self.flags,
            self.version,
        );
        put_fields(&mut out, &[(16, &self.domain), (24, &self.workstation)])?;
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for Challenge {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a CHALLENGE message. Bytes past the payload are refused.
    /// The 8 reserved bytes are ignored. A Unicode target name must have an
    /// even offset and length, and a target info must be exactly one AV
    /// pair list. A field whose flag ([`flags::REQUEST_TARGET`] or
    /// [`flags::NEGOTIATE_TARGET_INFO`]) is clear is read when it is good
    /// and is empty when it is not, since \[MS-NLMP\] 2.2.1.2 says to
    /// ignore its descriptor.
    /// Refuses malformed or trailing input.
    fn parse(b: &[u8]) -> Result<Challenge, Error> {
        let (flags, version, start) = header(b, message_type::CHALLENGE, CHALLENGE_HEADER_LEN, 20)?;
        let unicode = flags & flags::NEGOTIATE_UNICODE != 0;
        let mut server_challenge = [0u8; 8];
        server_challenge.copy_from_slice(&b[24..32]);
        let info =
            field(b, 40, start, "target info").and_then(|t| check_target_info(&t).map(|()| t));
        let c = Challenge {
            flags,
            target_name: optional(
                flags & flags::REQUEST_TARGET != 0,
                text_field(b, 12, start, "target name", unicode),
            )?,
            server_challenge,
            target_info: optional(flags & flags::NEGOTIATE_TARGET_INFO != 0, info)?,
            version,
        };
        check_written(start, &[&c.target_name, &c.target_info])?;
        check_end(b, start, &[12, 40])?;
        Ok(c)
    }

    /// Appends the token. Refuses oversized fields or messages, invalid target info,
    /// odd Unicode fields, and inconsistent flags and version.
    /// Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        check_version(self.flags, self.version)?;
        check_text(
            self.flags & flags::NEGOTIATE_UNICODE != 0,
            &self.target_name,
        )?;
        if self.target_info.len() <= MAX_FIELD && check_target_info(&self.target_info).is_err() {
            return Err(Error::Unwritable);
        }
        let mut out = start(
            message_type::CHALLENGE,
            CHALLENGE_HEADER_LEN,
            20,
            self.flags,
            self.version,
        );
        out[24..32].copy_from_slice(&self.server_challenge);
        put_fields(
            &mut out,
            &[(12, &self.target_name), (40, &self.target_info)],
        )?;
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for Authenticate {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads an AUTHENTICATE message. Bytes past the payload are refused.
    /// The MIC slot sits at bytes 72 to 88, after the version, whose 8
    /// bytes are there (as zeros) even when the flags say there is none.
    /// It is read when the payload (or, with every field empty, the
    /// message) starts at byte 88 or later; see [`Authenticate::mic`] and
    /// [`Authenticate::claims_mic`].
    ///
    /// The NT response must read with [`NtResponse::parse`], and Unicode
    /// names must have even offsets and lengths. Without
    /// [`flags::NEGOTIATE_KEY_EXCH`] the session key's descriptor is to be
    /// ignored (\[MS-NLMP\] 2.2.1.3): a good one is read, a bad one gives
    /// an empty key and does not move where the payload starts.
    /// Refuses malformed or trailing input.
    fn parse(b: &[u8]) -> Result<Authenticate, Error> {
        let (flags, version, mut start) =
            header(b, message_type::AUTHENTICATE, AUTHENTICATE_HEADER_LEN, 60)?;
        let unicode = flags & flags::NEGOTIATE_UNICODE != 0;
        let key_exch = flags & flags::NEGOTIATE_KEY_EXCH != 0;
        let [lm, nt, domain, user, workstation, key] = AUTH_FIELDS;
        let mut mic = None;
        let first = AUTH_FIELDS
            .iter()
            .filter(|&&(at, name)| at != key.0 || key_exch || field(b, at, start, name).is_ok())
            .filter_map(|&(at, _)| field_offset(b, at))
            .min()
            .unwrap_or(b.len());
        if first >= MIC_END && b.len() >= MIC_END {
            let mut m = [0u8; MIC_LEN];
            m.copy_from_slice(&b[MIC_END - MIC_LEN..MIC_END]);
            mic = Some(m);
            start = MIC_END;
        }
        let nt_response = field(b, nt.0, start, nt.1)?;
        NtResponse::parse(&nt_response)?;
        let a = Authenticate {
            flags,
            lm_response: field(b, lm.0, start, lm.1)?,
            nt_response,
            domain: text_field(b, domain.0, start, domain.1, unicode)?,
            user: text_field(b, user.0, start, user.1, unicode)?,
            workstation: text_field(b, workstation.0, start, workstation.1, unicode)?,
            session_key: optional(key_exch, field(b, key.0, start, key.1))?,
            version,
            mic,
        };
        check_written(start, &a.fields())?;
        check_end(b, start, &[12, 20, 28, 36, 44, 52])?;
        Ok(a)
    }

    /// Appends the token. Refuses oversized fields, odd Unicode fields, inconsistent
    /// flags and version, and MIC layouts that would change. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        check_version(self.flags, self.version)?;
        let unicode = self.flags & flags::NEGOTIATE_UNICODE != 0;
        check_text(unicode, &self.domain)?;
        check_text(unicode, &self.user)?;
        check_text(unicode, &self.workstation)?;
        if self.nt_response.len() <= MAX_FIELD && NtResponse::parse(&self.nt_response).is_err() {
            return Err(Error::Unwritable);
        }
        let mut out = start(
            message_type::AUTHENTICATE,
            AUTHENTICATE_HEADER_LEN,
            60,
            self.flags,
            self.version,
        );
        if let Some(m) = self.mic {
            out.resize(MIC_END - MIC_LEN, 0);
            out.extend_from_slice(&m);
        }
        let data = self.fields();
        let mut fields = [(0usize, &[][..]); 6];
        for (i, f) in fields.iter_mut().enumerate() {
            *f = (AUTH_FIELDS[i].0, data[i]);
        }
        put_fields(&mut out, &fields)?;
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a message of any of the three types.
    /// Refuses malformed or trailing input.
    fn parse(b: &[u8]) -> Result<Message, Error> {
        if b.len() > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        let n = b.len().min(SIGNATURE.len());
        if b[..n] != SIGNATURE[..n] {
            return Err(Error::Signature);
        }
        if b.len() < 12 {
            return Err(Error::Truncated);
        }
        match le32(b, 8).ok_or(Error::Truncated)? {
            message_type::NEGOTIATE => Negotiate::parse(b).map(Message::Negotiate),
            message_type::CHALLENGE => Challenge::parse(b).map(Message::Challenge),
            message_type::AUTHENTICATE => Authenticate::parse(b).map(Message::Authenticate),
            t => Err(Error::MessageType(t)),
        }
    }

    /// Appends the selected token. Refuses any value its token writer cannot preserve.
    /// Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Message::Negotiate(m) => m.write(dst),
            Message::Challenge(m) => m.write(dst),
            Message::Authenticate(m) => m.write(dst),
        }
    }
}

impl Wire for LmV2Response {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a 24-byte LMv2 response.
    /// Refuses malformed or trailing input.
    fn parse(b: &[u8]) -> Result<LmV2Response, Error> {
        if b.len() != V1_RESPONSE_LEN {
            return Err(Error::ResponseLength(b.len()));
        }
        let mut response = [0u8; 16];
        response.copy_from_slice(&b[..16]);
        let mut client_challenge = [0u8; 8];
        client_challenge.copy_from_slice(&b[16..]);
        Ok(LmV2Response {
            response,
            client_challenge,
        })
    }

    /// Appends the 16-byte response and 8-byte challenge. Refuses no values.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = [0u8; V1_RESPONSE_LEN];
        out[..16].copy_from_slice(&self.response);
        out[16..].copy_from_slice(&self.client_challenge);
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for NtResponse {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads an NT response: empty, 24 bytes for NTLMv1, or at least 48
    /// for NTLMv2 (the proof, the fixed part of the blob and an end
    /// marker). An NTLMv2 response's two version bytes must both be 1.
    /// Refuses malformed or trailing input.
    fn parse(b: &[u8]) -> Result<NtResponse, Error> {
        if b.is_empty() {
            return Ok(NtResponse::Empty);
        }
        if b.len() == V1_RESPONSE_LEN {
            let mut r = [0u8; V1_RESPONSE_LEN];
            r.copy_from_slice(b);
            return Ok(NtResponse::V1(r));
        }
        if b.len() > MAX_FIELD {
            return Err(Error::TooLong);
        }
        if b.len() < NT_PROOF_LEN + CLIENT_CHALLENGE_HEADER_LEN + 4 {
            return Err(Error::ResponseLength(b.len()));
        }
        NtlmV2Response::parse(b).map(Self::V2)
    }

    /// Appends the selected response. Refuses invalid NTLMv2 versions, AV pairs and
    /// lengths above [`MAX_FIELD`]. Leaves the destination unchanged on error.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Self::Empty => Ok(()),
            Self::V1(bytes) => {
                dst.extend_from_slice(bytes);
                Ok(())
            }
            Self::V2(value) => value.write(dst),
        }
    }
}

impl Wire for ClientChallenge {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads the complete blob and keeps bytes after its AV end marker.
    /// Refuses short headers, versions other than 1, invalid AV pairs and oversized blobs.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() > MAX_FIELD - NT_PROOF_LEN {
            return Err(Error::TooLong);
        }
        if b.len() < CLIENT_CHALLENGE_HEADER_LEN + 4 {
            return Err(Error::ResponseLength(b.len()));
        }
        if b[0] != 1 || b[1] != 1 {
            return Err(Error::ResponseVersion(b[0], b[1]));
        }
        let timestamp = u64::from_le_bytes(b[8..16].try_into().map_err(|_| Error::Truncated)?);
        let challenge = b[16..24].try_into().map_err(|_| Error::Truncated)?;
        let (av_pairs, used) = AvPairs::parse_prefix(&b[CLIENT_CHALLENGE_HEADER_LEN..])?;
        Ok(Self {
            resp_type: b[0],
            hi_resp_type: b[1],
            timestamp,
            challenge,
            av_pairs,
            trailing: b[CLIENT_CHALLENGE_HEADER_LEN + used..].to_vec(),
        })
    }

    /// Appends the complete blob with zero reserved fields. Refuses invalid versions,
    /// invalid AV pairs and lengths above the response limit.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        if self.resp_type != 1 || self.hi_resp_type != 1 || self.trailing.len() > MAX_FIELD {
            return Err(Error::Unwritable);
        }
        let mut pairs = Vec::new();
        write_pairs(&self.av_pairs, &mut pairs)?;
        let total = CLIENT_CHALLENGE_HEADER_LEN
            .checked_add(pairs.len())
            .and_then(|n| n.checked_add(self.trailing.len()))
            .ok_or(Error::Unwritable)?;
        if total > MAX_FIELD - NT_PROOF_LEN {
            return Err(Error::Unwritable);
        }
        dst.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0]);
        dst.extend_from_slice(&self.timestamp.to_le_bytes());
        dst.extend_from_slice(&self.challenge);
        dst.extend_from_slice(&[0; 4]);
        dst.extend_from_slice(&pairs);
        dst.extend_from_slice(&self.trailing);
        Ok(())
    }
}

impl Wire for NtlmV2Response {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads the proof and complete client blob. Refuses short or invalid blobs.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        let (proof, blob) = b
            .split_at_checked(NT_PROOF_LEN)
            .ok_or(Error::ResponseLength(b.len()))?;
        let nt_proof = proof.try_into().map_err(|_| Error::Truncated)?;
        Ok(Self {
            nt_proof,
            client: ClientChallenge::parse(blob)?,
        })
    }

    /// Appends the proof and client blob. Refuses invalid or oversized blobs.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.nt_proof);
        self.client.write(&mut out)?;
        dst.extend_from_slice(&out);
        Ok(())
    }
}

impl Wire for AvPair {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one pair, including an empty end marker. Refuses invalid lengths, values and trailing bytes.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() > MAX_FIELD {
            return Err(Error::TooLong);
        }
        if b.len() < 4 {
            return Err(Error::AvPairs);
        }
        let id = le16(b, 0).ok_or(Error::AvPairs)?;
        let len = le16(b, 2).ok_or(Error::AvPairs)?;
        if id == av_id::EOL && len != 0 {
            return Err(Error::AvEolLength(len));
        }
        if b.len() != 4 + usize::from(len) {
            return Err(Error::AvPairs);
        }
        if !av_value_fits(id, &b[4..]) {
            return Err(Error::AvValue(id));
        }
        Ok(Self {
            id,
            value: b[4..].to_vec(),
        })
    }

    /// Appends one pair. Refuses invalid values, lengths above [`MAX_FIELD`] and nonempty end markers.
    fn write(&self, dst: &mut Vec<u8>) -> Result<(), Error> {
        if self.value.len() > MAX_FIELD - 4
            || !av_value_fits(self.id, &self.value)
            || (self.id == av_id::EOL && !self.value.is_empty())
        {
            return Err(Error::Unwritable);
        }
        dst.extend_from_slice(&self.id.to_le_bytes());
        dst.extend_from_slice(&(self.value.len() as u16).to_le_bytes());
        dst.extend_from_slice(&self.value);
        Ok(())
    }
}

/// Checks the last in-bounds payload range. Empty or ignored descriptors add no bytes.
fn check_end(b: &[u8], fixed: usize, slots: &[usize]) -> Result<(), Error> {
    let mut end = fixed;
    for &slot in slots {
        let len = usize::from(le16(b, slot).ok_or(Error::Truncated)?);
        if len != 0 {
            let start = le32(b, slot + 4).ok_or(Error::Truncated)? as usize;
            if let Some(last) = start
                .checked_add(len)
                .filter(|last| start >= fixed && *last <= b.len())
            {
                end = end.max(last);
            }
        }
    }
    if end != b.len() {
        return Err(Error::Trailing);
    }
    Ok(())
}

impl Wire for Version {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly eight bytes. Refuses short or trailing input; reserved bytes are ignored.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        let bytes = b.try_into().map_err(|_| Error::Truncated)?;
        Ok(Self::from_bytes(bytes))
    }

    /// Appends eight bytes with zero reserved fields. Refuses no values.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let [b0, b1] = self.build.to_le_bytes();

        out.extend_from_slice(&[self.major, self.minor, b0, b1, 0, 0, 0, self.revision]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::Lcg;
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::mutate;

    /// The CHALLENGE message from \[MS-NLMP\] section 4.2.4.3.
    const SPEC_CHALLENGE: [u8; 104] = [
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0c,
        0x00, //
        0x38, 0x00, 0x00, 0x00, 0x33, 0x82, 0x8a, 0xe2, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x24, 0x00, 0x44, 0x00, 0x00,
        0x00, //
        0x06, 0x00, 0x70, 0x17, 0x00, 0x00, 0x00, 0x0f, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76,
        0x00, //
        0x65, 0x00, 0x72, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61,
        0x00, //
        0x69, 0x00, 0x6e, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76,
        0x00, //
        0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn spec_challenge() {
        let c = Challenge::parse(&SPEC_CHALLENGE).unwrap();
        assert_eq!(c.flags, 0xe28a_8233);
        assert_ne!(c.flags & flags::NEGOTIATE_VERSION, 0);
        assert_ne!(c.flags & flags::NEGOTIATE_TARGET_INFO, 0);
        assert_eq!(
            c.server_challenge,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        assert_eq!(
            c.version,
            Some(Version {
                major: 6,
                minor: 0,
                build: 6000,
                revision: NTLMSSP_REVISION_W2K3
            })
        );
        assert_eq!(
            UnicodeName::parse(&c.target_name)
                .ok()
                .map(|name| name.0)
                .as_deref(),
            Some("Server")
        );
        let AvPairs(pairs) = AvPairs::parse(&c.target_info).unwrap();
        assert_eq!(
            pairs,
            vec![
                AvPair {
                    id: av_id::NB_DOMAIN_NAME,
                    value: UnicodeName("Domain".into()).to_bytes().unwrap()
                },
                AvPair {
                    id: av_id::NB_COMPUTER_NAME,
                    value: UnicodeName("Server".into()).to_bytes().unwrap()
                },
            ]
        );
        assert_eq!(AvPairs(pairs.to_vec()).to_bytes().unwrap(), c.target_info);
        // Written back, it is the same bytes.
        assert_eq!(c.to_bytes().unwrap(), SPEC_CHALLENGE);
        assert_eq!(Message::parse(&SPEC_CHALLENGE), Ok(Message::Challenge(c)));
    }

    /// The AUTHENTICATE message from \[MS-NLMP\] section 4.2.4.3.
    const SPEC_AUTHENTICATE: [u8; 232] = [
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18,
        0x00, //
        0x6c, 0x00, 0x00, 0x00, 0x54, 0x00, 0x54, 0x00, 0x84, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0c,
        0x00, //
        0x48, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00, 0x54, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10,
        0x00, //
        0x5c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0xd8, 0x00, 0x00, 0x00, 0x35, 0x82, 0x88,
        0xe2, //
        0x05, 0x01, 0x28, 0x0a, 0x00, 0x00, 0x00, 0x0f, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61,
        0x00, //
        0x69, 0x00, 0x6e, 0x00, 0x55, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x43, 0x00, 0x4f,
        0x00, //
        0x4d, 0x00, 0x50, 0x00, 0x55, 0x00, 0x54, 0x00, 0x45, 0x00, 0x52, 0x00, 0x86, 0xc3, 0x50,
        0x97, //
        0xac, 0x9c, 0xec, 0x10, 0x25, 0x54, 0x76, 0x4a, 0x57, 0xcc, 0xcc, 0x19, 0xaa, 0xaa, 0xaa,
        0xaa, //
        0xaa, 0xaa, 0xaa, 0xaa, 0x68, 0xcd, 0x0a, 0xb8, 0x51, 0xe5, 0x1c, 0x96, 0xaa, 0xbc, 0x92,
        0x7b, //
        0xeb, 0xef, 0x6a, 0x1c, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, //
        0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00,
        0x00, //
        0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e,
        0x00, //
        0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72,
        0x00, //
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc5, 0xda, 0xd2, 0x54, 0x4f, 0xc9, 0x79,
        0x90, //
        0x94, 0xce, 0x1c, 0xe9, 0x0b, 0xc9, 0xd0, 0x3e, //
    ];

    #[test]
    fn spec_authenticate() {
        let a = Authenticate::parse(&SPEC_AUTHENTICATE).unwrap();
        assert_eq!(a.flags, 0xe288_8235);
        assert_eq!(
            a.version,
            Some(Version {
                major: 5,
                minor: 1,
                build: 2600,
                revision: NTLMSSP_REVISION_W2K3
            })
        );
        // The payload starts right after the version, so there is no MIC.
        assert_eq!(a.mic, None);
        fictionet::assert_cases!(|input| UnicodeName::parse(input).ok().map(|name| name.0).as_deref();
            domain: &a.domain => Some("Domain"),
            user: &a.user => Some("User"),
            workstation: &a.workstation => Some("COMPUTER"),
        );
        assert_eq!(a.session_key, SPEC_AUTHENTICATE[0xd8..].to_vec());
        let lm = LmV2Response::parse(&a.lm_response).unwrap();
        assert_eq!(lm.client_challenge, [0xaa; 8]);
        let NtResponse::V2(v2) = NtResponse::parse(&a.nt_response).unwrap() else {
            panic!()
        };
        assert_eq!(v2.nt_proof[..4], [0x68, 0xcd, 0x0a, 0xb8]);
        assert_eq!(
            (
                v2.client.resp_type,
                v2.client.hi_resp_type,
                v2.client.timestamp
            ),
            (1, 1, 0)
        );
        assert_eq!(v2.client.challenge, [0xaa; 8]);
        // The client copied the server's target info into its blob.
        let c = Challenge::parse(&SPEC_CHALLENGE).unwrap();
        assert_eq!(
            v2.client.av_pairs,
            AvPairs::parse(&c.target_info).unwrap().0
        );
        assert_eq!(v2.client.trailing, vec![0; 4]);
        assert_eq!(NtResponse::V2(v2).to_bytes().unwrap(), a.nt_response);
        // Written back, the fields are in another order, and read the same.
        let b = a.to_bytes().unwrap();
        assert_eq!(b.len(), SPEC_AUTHENTICATE.len());
        assert_eq!(Message::parse(&b), Ok(Message::Authenticate(a)));
    }

    #[test]
    fn spec_lmv2_response() {
        // The LMv2 response from \[MS-NLMP\] section 4.2.4.2.1.
        let b = [
            0x86, 0xc3, 0x50, 0x97, 0xac, 0x9c, 0xec, 0x10, 0x25, 0x54, 0x76, 0x4a, 0x57, 0xcc,
            0xcc, 0x19, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        ];
        let r = LmV2Response::parse(&b).unwrap();
        assert_eq!(r.client_challenge, [0xaa; 8]);
        assert_eq!(r.response[0], 0x86);
        assert_eq!(r.to_bytes().unwrap(), b);
        assert_eq!(
            LmV2Response::parse(&b[..23]),
            Err(Error::ResponseLength(23))
        );
    }

    #[test]
    fn negotiate_layout() {
        let n = Negotiate {
            flags: flags::NEGOTIATE_UNICODE
                | flags::NEGOTIATE_OEM_DOMAIN_SUPPLIED
                | flags::NEGOTIATE_VERSION,
            domain: b"CORP".to_vec(),
            workstation: Vec::new(),
            version: Some(Version {
                major: 10,
                minor: 0,
                build: 19041,
                revision: 15,
            }),
        };
        let b = n.to_bytes().unwrap();
        assert_eq!(&b[..12], b"NTLMSSP\0\x01\0\0\0");
        assert_eq!(le32(&b, 12).unwrap(), n.flags);
        // Domain: length 4, maximum 4, at 40, after the version.
        assert_eq!(&b[16..24], &[4, 0, 4, 0, 40, 0, 0, 0]);
        assert_eq!(&b[32..40], &[10, 0, 0x61, 0x4a, 0, 0, 0, 15]);
        assert_eq!(&b[40..], b"CORP");
        assert_eq!(Negotiate::parse(&b), Ok(n));
    }

    #[test]
    fn authenticate_layout_with_mic() {
        let a = Authenticate {
            flags: flags::NEGOTIATE_VERSION | flags::NEGOTIATE_UNICODE,
            lm_response: vec![0; 24],
            nt_response: vec![7; 24],
            domain: UnicodeName("D".into()).to_bytes().unwrap(),
            user: UnicodeName("u".into()).to_bytes().unwrap(),
            workstation: Vec::new(),
            session_key: vec![5; 16],
            version: Some(Version {
                major: 6,
                minor: 1,
                build: 7601,
                revision: 15,
            }),
            mic: Some([0x11; 16]),
        };
        let b = a.to_bytes().unwrap();
        assert_eq!(le32(&b, 8).unwrap(), message_type::AUTHENTICATE);
        assert_eq!(le32(&b, 60).unwrap(), a.flags);
        assert_eq!(&b[72..88], &[0x11; 16]);
        // The LM response is first, right after the MIC.
        assert_eq!(&b[12..20], &[24, 0, 24, 0, 88, 0, 0, 0]);
        assert_eq!(Authenticate::parse(&b), Ok(a.clone()));
        // With no MIC, the payload starts at 72 and none is read.
        let no_mic = Authenticate {
            mic: None,
            ..a.clone()
        };
        let b = no_mic.to_bytes().unwrap();
        assert_eq!(&b[12..20], &[24, 0, 24, 0, 72, 0, 0, 0]);
        assert_eq!(Authenticate::parse(&b), Ok(no_mic));
        // Every field empty: the message's length tells.
        let empty = Authenticate {
            lm_response: Vec::new(),
            nt_response: Vec::new(),
            domain: Vec::new(),
            user: Vec::new(),
            session_key: Vec::new(),
            ..a
        };
        assert_eq!(
            Authenticate::parse(&empty.to_bytes().unwrap()),
            Ok(empty.clone())
        );
        let empty = Authenticate { mic: None, ..empty };
        assert_eq!(Authenticate::parse(&empty.to_bytes().unwrap()), Ok(empty));
    }

    #[test]
    fn nt_responses() {
        assert_eq!(NtResponse::parse(&[]), Ok(NtResponse::Empty));
        assert_eq!(NtResponse::parse(&[3; 24]), Ok(NtResponse::V1([3; 24])));
        assert_eq!(NtResponse::parse(&[3; 25]), Err(Error::ResponseLength(25)));
        assert_eq!(NtResponse::parse(&[3; 47]), Err(Error::ResponseLength(47)));
        // The layout of \[MS-NLMP\] section 2.2.2.7, with Windows' 4 zeros
        // after the list.
        let mut b = vec![0xee; 16];
        b.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0]);
        b.extend_from_slice(&0x01d0_0000_0000_0000u64.to_le_bytes());
        b.extend_from_slice(&[0xaa; 8]);
        b.extend_from_slice(&[0, 0, 0, 0]);
        b.extend_from_slice(&[6, 0, 4, 0, 2, 0, 0, 0, 0, 0, 0, 0]);
        b.extend_from_slice(&[0, 0, 0, 0]);
        let NtResponse::V2(v2) = NtResponse::parse(&b).unwrap() else {
            panic!()
        };
        assert_eq!(v2.nt_proof, [0xee; 16]);
        assert_eq!((v2.client.resp_type, v2.client.hi_resp_type), (1, 1));
        assert_eq!(v2.client.timestamp, 0x01d0_0000_0000_0000);
        assert_eq!(v2.client.challenge, [0xaa; 8]);
        assert_eq!(
            v2.client.av_pairs,
            vec![AvPair {
                id: av_id::FLAGS,
                value: vec![2, 0, 0, 0]
            }]
        );
        assert_eq!(v2.client.trailing, vec![0, 0, 0, 0]);
        assert_eq!(NtResponse::V2(v2).to_bytes().unwrap(), b);
        // A list with no end marker.
        assert_eq!(NtResponse::parse(&b[..b.len() - 8]), Err(Error::AvPairs));
        assert_eq!(
            NtResponse::parse(&vec![0; MAX_FIELD + 1]),
            Err(Error::TooLong)
        );
    }

    #[test]
    fn av_pair_errors() {
        assert_eq!(AvPairs::parse(&[]), Err(Error::AvPairs));
        assert_eq!(AvPairs::parse(&[0, 0, 0]), Err(Error::AvPairs));
        assert_eq!(AvPairs::parse(&[0, 0, 1, 0, 9]), Err(Error::AvEolLength(1)));
        assert_eq!(AvPairs::parse(&[1, 0, 2, 0, 9]), Err(Error::AvPairs));
        assert_eq!(AvPairs::parse(&[0, 0, 0, 0, 7]), Err(Error::Trailing));
        // An ID the specification does not define keeps any value.
        assert_eq!(
            AvPairs::parse(&[0x40, 0, 1, 0, 9, 0, 0, 0, 0]),
            Ok(AvPairs(vec![AvPair {
                id: 0x40,
                value: vec![9]
            }]))
        );
        let many = vec![
            AvPair {
                id: 1,
                value: Vec::new()
            };
            MAX_AV_PAIRS + 1
        ];
        assert_eq!(AvPairs(many.to_vec()).to_bytes(), Err(Error::Unwritable));
        let mut b = Vec::new();
        for _ in 0..=MAX_AV_PAIRS {
            b.extend_from_slice(&[1, 0, 0, 0]);
        }
        b.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(AvPairs::parse(&b), Err(Error::TooManyAvPairs));
        assert_eq!(AvPairs::parse(&b[4..]).unwrap().0.len(), MAX_AV_PAIRS);
        assert_eq!(
            AvPairs(vec![AvPair {
                id: 0,
                value: Vec::new()
            }])
            .to_bytes(),
            Err(Error::Unwritable)
        );
        let big = AvPair {
            id: 1,
            value: vec![0; 65536],
        };
        assert_eq!(AvPairs([big].to_vec()).to_bytes(), Err(Error::Unwritable));
        let pairs = [
            AvPair {
                id: 9,
                value: vec![1],
            },
            AvPair {
                id: 9,
                value: vec![2],
            },
        ];
        assert_eq!(AvPair::find(&pairs, 9), Some(&pairs[0]));
        assert_eq!(AvPair::find(&pairs, 3), None);
    }

    #[test]
    fn parse_errors() {
        let n = Negotiate {
            flags: flags::NEGOTIATE_OEM_DOMAIN_SUPPLIED | flags::NEGOTIATE_OEM_WORKSTATION_SUPPLIED,
            domain: b"AB".to_vec(),
            ..Negotiate::default()
        };
        let good = n.to_bytes().unwrap();
        assert_eq!(
            Message::parse(&vec![0; MAX_MESSAGE + 1]),
            Err(Error::TooLong)
        );
        assert_eq!(
            Negotiate::parse(&vec![0; MAX_MESSAGE + 1]),
            Err(Error::TooLong)
        );
        assert_eq!(
            Message::parse(b"NTLMSSX\0\x01\0\0\0"),
            Err(Error::Signature)
        );
        assert_eq!(Message::parse(b"X"), Err(Error::Signature));
        assert_eq!(Message::parse(b"NTLM"), Err(Error::Truncated));
        assert_eq!(
            Message::parse(b"NTLMSSP\0\x04\0\0\0"),
            Err(Error::MessageType(4))
        );
        assert_eq!(Challenge::parse(&good), Err(Error::MessageType(1)));
        assert_eq!(Authenticate::parse(&good), Err(Error::MessageType(1)));
        assert_eq!(Negotiate::parse(&good[..31]), Err(Error::Truncated));
        // The version flag set with no room for the version.
        let mut b = good[..32].to_vec();
        b[12..16].copy_from_slice(&flags::NEGOTIATE_VERSION.to_le_bytes());
        b[16..24].fill(0);
        assert_eq!(Negotiate::parse(&b), Err(Error::Truncated));
        // A field past the end, and one inside the fixed part.
        assert_eq!(Negotiate::parse(&good[..33]), Err(Error::Field("domain")));
        let mut b = good.clone();
        b[20] = 8;
        assert_eq!(Negotiate::parse(&b), Err(Error::Field("domain")));
        // An offset so large the end overflows on 32-bit targets is still
        // only out of bounds.
        b[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(Negotiate::parse(&b), Err(Error::Field("domain")));
        // An empty field's offset is not read.
        let mut b = good.clone();
        b[24..32].copy_from_slice(&[0, 0, 9, 9, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(Negotiate::parse(&b), Ok(n));
        // A challenge whose target info is out of bounds.
        let mut b = SPEC_CHALLENGE.to_vec();
        b.pop();
        assert_eq!(Challenge::parse(&b), Err(Error::Field("target info")));
    }

    #[test]
    fn encode_errors() {
        let n = Negotiate {
            flags: flags::NEGOTIATE_VERSION,
            ..Negotiate::default()
        };
        assert_eq!(n.to_bytes(), Err(Error::Unwritable));
        let v = Version {
            major: 1,
            minor: 2,
            build: 3,
            revision: 4,
        };
        let n = Negotiate {
            flags: 0,
            version: Some(v),
            ..n
        };
        assert_eq!(n.to_bytes(), Err(Error::Unwritable));
        let n = Negotiate {
            domain: vec![0; MAX_FIELD + 1],
            ..Negotiate::default()
        };
        assert_eq!(n.to_bytes(), Err(Error::Unwritable));
        let a = Authenticate {
            mic: Some([0; 16]),
            ..Authenticate::default()
        };
        // A MIC with no version: 8 zero bytes stand in for the version.
        let b = a.to_bytes().unwrap();
        assert_eq!(b.len(), MIC_END);
        assert_eq!(Authenticate::parse(&b), Ok(a.clone()));
        // The padding byte that keeps a field at an even offset counts.
        let n = Negotiate {
            domain: vec![1],
            workstation: vec![2; MAX_MESSAGE - 33],
            ..Negotiate::default()
        };
        assert_eq!(n.to_bytes(), Err(Error::Unwritable));
        let n = Negotiate {
            workstation: vec![2; MAX_MESSAGE - 34],
            ..n
        };
        assert_eq!(n.to_bytes().unwrap().len(), MAX_MESSAGE);
        let a = Authenticate {
            mic: None,
            user: vec![0; MAX_FIELD],
            domain: vec![0; MAX_FIELD],
            ..a
        };
        assert_eq!(a.to_bytes(), Err(Error::Unwritable));
        let c = Challenge {
            target_info: vec![0; MAX_FIELD + 1],
            ..Challenge::default()
        };
        assert_eq!(c.to_bytes(), Err(Error::Unwritable));
        let big = NtResponse::V2(NtlmV2Response {
            nt_proof: [0; 16],
            client: ClientChallenge {
                resp_type: 1,
                hi_resp_type: 1,
                timestamp: 0,
                challenge: [0; 8],
                av_pairs: Vec::new(),
                trailing: vec![0; MAX_FIELD],
            },
        });
        assert_eq!(big.to_bytes(), Err(Error::Unwritable));
    }

    #[test]
    fn overlapping_fields_too_long_to_write() {
        // Two fields of 40000 bytes over the same payload: the message
        // fits, but written out the fields would not.
        let mut b = vec![0u8; NEGOTIATE_HEADER_LEN + 40000];
        b[..8].copy_from_slice(&SIGNATURE);
        b[8..12].copy_from_slice(&message_type::NEGOTIATE.to_le_bytes());
        for at in [16, 24] {
            b[at..at + 2].copy_from_slice(&40000u16.to_le_bytes());
            b[at + 4..at + 8].copy_from_slice(&32u32.to_le_bytes());
        }
        assert_eq!(Negotiate::parse(&b), Err(Error::TooLong));
        assert_eq!(Message::parse(&b), Err(Error::TooLong));
        // One of them alone reads and writes back.
        b[24..32].fill(0);
        let n = Negotiate::parse(&b).unwrap();
        assert_eq!(Negotiate::parse(&n.to_bytes().unwrap()), Ok(n));
    }

    #[test]
    fn mic_without_version_flag() {
        // \[MS-NLMP\] 2.2.1.3: the Version field is all zeros when the flag
        // is clear, and the MIC still follows it at byte 72.
        let mut b = vec![0u8; 88];
        b[..8].copy_from_slice(&SIGNATURE);
        b[8..12].copy_from_slice(&message_type::AUTHENTICATE.to_le_bytes());
        b[72..88].fill(0x5a);
        // A user name of 2 bytes at 88.
        b[36..38].copy_from_slice(&2u16.to_le_bytes());
        b[38..40].copy_from_slice(&2u16.to_le_bytes());
        b[40..44].copy_from_slice(&88u32.to_le_bytes());
        b.extend_from_slice(b"u\0");
        let a = Authenticate::parse(&b).unwrap();
        assert_eq!(a.version, None);
        assert_eq!(a.mic, Some([0x5a; 16]));
        assert_eq!(a.user, b"u\0");
        // Written back, the version is zeros, the MIC is in place and the
        // user name follows it.
        let w = a.to_bytes().unwrap();
        assert_eq!(w[64..88], b[64..88]);
        assert_eq!(w[88..], b[88..]);
        assert_eq!(Authenticate::parse(&w), Ok(a));
    }

    #[test]
    fn unicode_fields_start_at_even_offsets() {
        // \[MS-NLMP\] 3.2.5.1.2: an anonymous LM response is one zero byte.
        // Unicode names after it must still start at even offsets.
        let a = Authenticate {
            flags: flags::NEGOTIATE_UNICODE | flags::ANONYMOUS,
            lm_response: vec![0],
            domain: UnicodeName("D".into()).to_bytes().unwrap(),
            workstation: UnicodeName("W".into()).to_bytes().unwrap(),
            ..Authenticate::default()
        };
        let b = a.to_bytes().unwrap();
        for at in [28, 44] {
            assert_eq!(le32(&b, at + 4).unwrap() % 2, 0, "field at {at}");
        }
        assert_eq!(Authenticate::parse(&b), Ok(a));
    }

    #[test]
    fn defaults_and_accessors() {
        // Every default message writes, and reads back the same.
        for m in [
            Message::Negotiate(Negotiate::default()),
            Message::Challenge(Challenge::default()),
            Message::Authenticate(Authenticate::default()),
        ] {
            let b = m.to_bytes().unwrap();
            assert_eq!(le32(&b, 8).unwrap(), m.message_type());
            assert_eq!(Message::parse(&b), Ok(m));
        }
        let c = Challenge::parse(&SPEC_CHALLENGE).unwrap();
        assert_eq!(c.target_info_pairs().unwrap().len(), 2);
        assert_eq!(
            Challenge::default().target_info_pairs(),
            Err(Error::AvPairs)
        );
        let a = Authenticate::parse(&SPEC_AUTHENTICATE).unwrap();
        assert!(matches!(a.nt(), Ok(NtResponse::V2(_))));
        // The spec message has no MIC, so there is none to zero.
        assert_eq!(Authenticate::mic_input(&SPEC_AUTHENTICATE), None);
        assert_eq!(Authenticate::mic_input(&SPEC_CHALLENGE), None);
        let with = Authenticate {
            mic: Some([7; MIC_LEN]),
            ..Authenticate::default()
        };
        let b = with.to_bytes().unwrap();
        let z = Authenticate::mic_input(&b).unwrap().to_bytes().unwrap();
        assert_eq!(z[..MIC_END - MIC_LEN], b[..MIC_END - MIC_LEN]);
        assert_eq!(z[MIC_END - MIC_LEN..MIC_END], [0; MIC_LEN]);
        assert_eq!(Authenticate::parse(&z).unwrap().mic, Some([0; MIC_LEN]));
        // Errors print without panicking.
        assert!(!Error::TooLong.to_string().is_empty());
        assert!(!Error::Unwritable.to_string().is_empty());
    }

    #[test]
    fn utf16() {
        assert_eq!(
            UnicodeName("Ab".into()).to_bytes().unwrap(),
            [0x41, 0, 0x62, 0]
        );
        assert_eq!(
            UnicodeName::parse(&[0x41, 0, 0x62, 0])
                .ok()
                .map(|name| name.0)
                .as_deref(),
            Some("Ab")
        );
        assert_eq!(UnicodeName::parse(&[0x41]).ok().map(|name| name.0), None);
        assert_eq!(
            UnicodeName::parse(&[0x00, 0xd8]).ok().map(|name| name.0),
            None
        );
        assert_eq!(UnicodeName("\u{1f600}".into()).to_bytes().unwrap().len(), 4);
    }

    #[test]
    fn every_truncated_prefix_fails() {
        let msgs = [
            Message::Challenge(Challenge::parse(&SPEC_CHALLENGE).unwrap()),
            Message::Negotiate(Negotiate {
                flags: flags::NEGOTIATE_VERSION
                    | flags::NEGOTIATE_OEM_DOMAIN_SUPPLIED
                    | flags::NEGOTIATE_OEM_WORKSTATION_SUPPLIED,
                domain: b"D".to_vec(),
                workstation: b"W".to_vec(),
                version: Some(Version {
                    major: 1,
                    minor: 2,
                    build: 3,
                    revision: 15,
                }),
            }),
            Message::Authenticate(Authenticate {
                flags: flags::NEGOTIATE_VERSION | flags::NEGOTIATE_KEY_EXCH,
                lm_response: vec![1; 24],
                nt_response: vec![2; 24],
                domain: vec![3; 2],
                user: vec![4; 2],
                workstation: vec![5; 2],
                session_key: vec![6; 16],
                version: Some(Version {
                    major: 1,
                    minor: 2,
                    build: 3,
                    revision: 15,
                }),
                mic: Some([9; 16]),
            }),
        ];
        for m in msgs {
            let b = m.to_bytes().unwrap();
            assert_eq!(Message::parse(&b), Ok(m.clone()));
            for n in 0..b.len() {
                assert!(Message::parse(&b[..n]).is_err(), "prefix {n} of {m:?}");
            }
        }
        // An NTLMv2 response cut short.
        let v2 = NtResponse::V2(NtlmV2Response {
            nt_proof: [1; 16],
            client: ClientChallenge {
                resp_type: 1,
                hi_resp_type: 1,
                timestamp: 5,
                challenge: [2; 8],
                av_pairs: vec![AvPair {
                    id: 1,
                    value: vec![1, 2],
                }],
                trailing: Vec::new(),
            },
        });
        let b = v2.to_bytes().unwrap();
        for n in 1..b.len() {
            if n != V1_RESPONSE_LEN {
                assert!(NtResponse::parse(&b[..n]).is_err(), "prefix {n}");
            }
        }
        let list = AvPairs(
            [AvPair {
                id: 2,
                value: vec![1, 2, 3, 4],
            }]
            .to_vec(),
        )
        .to_bytes()
        .unwrap();
        for n in 0..list.len() {
            assert!(AvPairs::parse(&list[..n]).is_err());
        }
    }

    /// An NTLMv2 response whose AV pairs are `pairs`.
    fn v2_with(pairs: Vec<AvPair>) -> Vec<u8> {
        NtResponse::V2(NtlmV2Response {
            nt_proof: [1; 16],
            client: ClientChallenge {
                resp_type: 1,
                hi_resp_type: 1,
                timestamp: 0,
                challenge: [2; 8],
                av_pairs: pairs,
                trailing: vec![0; 4],
            },
        })
        .to_bytes()
        .unwrap()
    }

    #[test]
    fn mic_claimed_by_av_flags() {
        // \[MS-NLMP\] 2.2.2.1: MsvAvFlags bit 0x2 says a MIC is there.
        let flagged = v2_with(vec![AvPair {
            id: av_id::FLAGS,
            value: 2u32.to_le_bytes().to_vec(),
        }]);
        let with = Authenticate {
            flags: flags::NEGOTIATE_UNICODE,
            nt_response: flagged.clone(),
            user: UnicodeName("u".into()).to_bytes().unwrap(),
            mic: Some([3; MIC_LEN]),
            ..Authenticate::default()
        };
        let a = Authenticate::parse(&with.to_bytes().unwrap()).unwrap();
        assert!(a.claims_mic());
        assert_eq!(a.mic, Some([3; MIC_LEN]));
        // The MIC dropped, the payload moved up to byte 72: the message
        // still says it has one, which a server can see.
        let dropped = Authenticate {
            mic: None,
            ..with.clone()
        };
        let a = Authenticate::parse(&dropped.to_bytes().unwrap()).unwrap();
        assert_eq!(a.mic, None);
        assert!(a.claims_mic());
        assert_eq!(Authenticate::mic_input(&dropped.to_bytes().unwrap()), None);
        // No flag, or flags without the bit, or an NTLMv1 response: no claim.
        let plain = Authenticate {
            nt_response: v2_with(Vec::new()),
            ..with.clone()
        };
        assert!(!plain.claims_mic());
        let other = v2_with(vec![AvPair {
            id: av_id::FLAGS,
            value: 1u32.to_le_bytes().to_vec(),
        }]);
        assert!(
            !Authenticate {
                nt_response: other,
                ..with.clone()
            }
            .claims_mic()
        );
        assert!(
            !Authenticate {
                nt_response: vec![0; 24],
                ..with
            }
            .claims_mic()
        );
        assert!(
            !Authenticate::parse(&SPEC_AUTHENTICATE)
                .unwrap()
                .claims_mic()
        );
    }

    #[test]
    fn descriptors_whose_flag_is_clear_are_ignored() {
        // \[MS-NLMP\] 2.2.1.1: without NEGOTIATE_OEM_DOMAIN_SUPPLIED the
        // domain descriptor must be ignored on receipt.
        let mut b = Negotiate::default().to_bytes().unwrap();
        b[16..24].copy_from_slice(&[1, 0, 1, 0, 0xff, 0xff, 0xff, 0xff]);
        b[24..32].copy_from_slice(&[2, 0, 2, 0, 4, 0, 0, 0]);
        let n = Negotiate::parse(&b).unwrap();
        assert_eq!((n.domain.len(), n.workstation.len()), (0, 0));
        // With the flag set, the same descriptor is an error.
        b[12..16].copy_from_slice(&flags::NEGOTIATE_OEM_DOMAIN_SUPPLIED.to_le_bytes());
        assert_eq!(Negotiate::parse(&b), Err(Error::Field("domain")));
        // A good descriptor is still read with the flag clear, as the
        // spec's own CHALLENGE sends a target name without REQUEST_TARGET.
        let c = Challenge::parse(&SPEC_CHALLENGE).unwrap();
        assert_eq!(c.flags & flags::REQUEST_TARGET, 0);
        assert_eq!(
            UnicodeName::parse(&c.target_name)
                .ok()
                .map(|name| name.0)
                .as_deref(),
            Some("Server")
        );
        // \[MS-NLMP\] 2.2.1.2: target name and target info, flags clear.
        let mut b = Challenge::default().to_bytes().unwrap();
        b[12..20].copy_from_slice(&[4, 0, 4, 0, 0xff, 0xff, 0xff, 0xff]);
        b[40..48].copy_from_slice(&[4, 0, 4, 0, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(Challenge::parse(&b), Ok(Challenge::default()));
        b[20..24].copy_from_slice(&flags::NEGOTIATE_TARGET_INFO.to_le_bytes());
        assert_eq!(Challenge::parse(&b), Err(Error::Field("target info")));
        // \[MS-NLMP\] 2.2.1.3: the session key without KEY_EXCH. A bad
        // descriptor neither fails the message nor hides its MIC.
        let a = Authenticate {
            mic: Some([8; MIC_LEN]),
            user: b"u".to_vec(),
            ..Authenticate::default()
        };
        let mut b = a.to_bytes().unwrap();
        b[52..60].copy_from_slice(&[16, 0, 16, 0, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(Authenticate::parse(&b), Ok(a));
        b[60..64].copy_from_slice(&flags::NEGOTIATE_KEY_EXCH.to_le_bytes());
        assert_eq!(
            Authenticate::parse(&b).unwrap_err(),
            Error::Field("session key")
        );
    }

    #[test]
    fn nested_fields_read_with_their_own_readers() {
        // A target info that is not an AV pair list is not written.
        let c = Challenge {
            flags: flags::NEGOTIATE_TARGET_INFO,
            target_info: vec![1],
            ..Challenge::default()
        };
        assert_eq!(c.to_bytes(), Err(Error::Unwritable));
        // Nor is one with bytes after its end marker, and such bytes read
        // from a peer are an error.
        let mut junk = AvPairs(
            [AvPair {
                id: av_id::NB_DOMAIN_NAME,
                value: vec![b'D', 0],
            }]
            .to_vec(),
        )
        .to_bytes()
        .unwrap();
        junk.push(7);
        let c = Challenge {
            target_info: junk.clone(),
            ..c
        };
        assert_eq!(c.to_bytes(), Err(Error::Unwritable));
        assert_eq!(c.target_info_pairs(), Err(Error::AvPairs));
        let mut b = SPEC_CHALLENGE.to_vec();
        b[40] += 1;
        b.push(7);
        assert_eq!(Challenge::parse(&b), Err(Error::AvPairs));
        // An NT response no layout has is not written, nor read.
        let a = Authenticate {
            nt_response: vec![1],
            ..Authenticate::default()
        };
        assert_eq!(a.to_bytes(), Err(Error::Unwritable));
        let mut b = SPEC_AUTHENTICATE.to_vec();
        b[20] = 25;
        assert_eq!(Authenticate::parse(&b), Err(Error::ResponseLength(25)));
    }

    #[test]
    fn av_values_have_the_length_their_id_allows() {
        // \[MS-NLMP\] 2.2.2.1: MsvAvFlags is a 32-bit value.
        assert_eq!(
            AvPairs::parse(&[6, 0, 1, 0, 2, 0, 0, 0, 0]),
            Err(Error::AvValue(av_id::FLAGS))
        );
        for (id, len) in [
            (av_id::FLAGS, 4),
            (av_id::TIMESTAMP, 8),
            (av_id::CHANNEL_BINDINGS, 16),
        ] {
            for n in [0, 1, len - 1, len + 1] {
                let p = AvPair {
                    id,
                    value: vec![0; n],
                };
                assert_eq!(AvPairs([p].to_vec()).to_bytes(), Err(Error::Unwritable));
            }
            let p = AvPair {
                id,
                value: vec![0; len],
            };
            let list = AvPairs(vec![p.clone()]).to_bytes().unwrap();
            assert_eq!(AvPairs::parse(&list), Ok(AvPairs(vec![p])));
        }
        // Names are UTF-16LE, so of even length.
        for id in [1, 2, 3, 4, 5, 9] {
            assert_eq!(
                AvPairs(
                    [AvPair {
                        id,
                        value: vec![b'A']
                    }]
                    .to_vec()
                )
                .to_bytes(),
                Err(Error::Unwritable)
            );
            assert_eq!(
                AvPairs::parse(&[id as u8, 0, 1, 0, b'A', 0, 0, 0, 0]),
                Err(Error::AvValue(id))
            );
        }
    }

    #[test]
    fn unicode_names_have_even_offsets_and_lengths() {
        // \[MS-NLMP\] 2.2.1.3: a Unicode user name has an even length.
        let a = Authenticate {
            flags: flags::NEGOTIATE_UNICODE,
            user: vec![0x41],
            ..Authenticate::default()
        };
        assert_eq!(a.to_bytes(), Err(Error::Unwritable));
        // OEM names may be any length.
        let oem = Authenticate {
            flags: flags::NEGOTIATE_OEM,
            ..a
        };
        assert_eq!(Authenticate::parse(&oem.to_bytes().unwrap()), Ok(oem));
        let c = Challenge {
            flags: flags::NEGOTIATE_UNICODE,
            target_name: vec![1],
            ..Challenge::default()
        };
        assert_eq!(c.to_bytes(), Err(Error::Unwritable));
        // A two-byte user name at an odd offset, and one of odd length.
        let a = Authenticate {
            flags: flags::NEGOTIATE_UNICODE,
            user: UnicodeName("u".into()).to_bytes().unwrap(),
            ..Authenticate::default()
        };
        let mut b = a.to_bytes().unwrap();
        assert_eq!(Authenticate::parse(&b), Ok(a));
        assert_eq!(b[40], 64);
        b.insert(64, 0);
        b[40] = 65;
        assert_eq!(Authenticate::parse(&b), Err(Error::OddUnicode("user")));
        b[40] = 64;
        b[36] = 3;
        assert_eq!(Authenticate::parse(&b), Err(Error::OddUnicode("user")));
        // In the spec CHALLENGE, a target name moved to an odd offset.
        let mut b = SPEC_CHALLENGE.to_vec();
        b[12..14].copy_from_slice(&[0x0b, 0]);
        b[16] = 0x39;
        b[20..24].copy_from_slice(&(0xe28a_8233u32 | flags::REQUEST_TARGET).to_le_bytes());
        assert_eq!(Challenge::parse(&b), Err(Error::OddUnicode("target name")));
    }

    #[test]
    fn ntlmv2_versions_are_one() {
        // \[MS-NLMP\] 2.2.2.7: RespType and HiRespType MUST be 1.
        assert_eq!(
            NtResponse::parse(&[0; 48]),
            Err(Error::ResponseVersion(0, 0))
        );
        let mut b = v2_with(Vec::new());
        assert!(matches!(NtResponse::parse(&b), Ok(NtResponse::V2(_))));
        b[17] = 2;
        assert_eq!(NtResponse::parse(&b), Err(Error::ResponseVersion(1, 2)));
        b[17] = 1;
        let Ok(NtResponse::V2(mut v2)) = NtResponse::parse(&b) else {
            panic!()
        };
        v2.client.resp_type = 0;
        assert_eq!(NtResponse::V2(v2).to_bytes(), Err(Error::Unwritable));
    }

    #[test]
    fn av_lists_fit_in_a_field() {
        // Two pairs of 40000 bytes: too long for any field, refused before
        // anything is copied.
        let big = vec![
            AvPair {
                id: 0x40,
                value: vec![0; 40000]
            };
            2
        ];
        assert_eq!(AvPairs(big.to_vec()).to_bytes(), Err(Error::Unwritable));
        let one = AvPairs(big[..1].to_vec()).to_bytes().unwrap();
        assert_eq!(one.len(), 40008);
        // The longest list that fits is written and read.
        let fits = [AvPair {
            id: 0x40,
            value: vec![0; MAX_FIELD - 8],
        }];
        let list = AvPairs(fits.to_vec()).to_bytes().unwrap();
        assert_eq!(list.len(), MAX_FIELD);
        assert_eq!(AvPairs::parse(&list), Ok(AvPairs(fits.to_vec())));
        // A list read from a longer slice stops at that limit.
        let mut b = Vec::new();
        for _ in 0..2 {
            b.extend_from_slice(&[0x40, 0, 0x40, 0x9c]);
            b.extend_from_slice(&[0; 40000]);
        }
        b.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(AvPairs::parse(&b), Err(Error::TooLong));
        let mut over = list.clone();
        over[2..4].copy_from_slice(&((MAX_FIELD - 8) as u16 + 1).to_le_bytes());
        over.push(0);
        assert_eq!(AvPairs::parse(&over), Err(Error::TooLong));
    }

    trait Samples {
        fn name(&mut self, max: usize) -> Vec<u8>;
        fn pair(&mut self) -> AvPair;
        fn version(&mut self, flags: u32) -> Option<Version>;
        fn pairs(&mut self) -> Vec<AvPair>;
        fn message(&mut self) -> Message;
    }

    impl Samples for Lcg {
        /// Bytes of an even length, as a Unicode name has.
        fn name(&mut self, max: usize) -> Vec<u8> {
            let mut b = self.bytes(max);
            b.truncate(b.len() & !1);
            b
        }

        /// A value of the length the pair ID allows.
        fn pair(&mut self) -> AvPair {
            let id = 1 + self.index(12) as u16;
            let value = match id {
                av_id::FLAGS => (self.next() as u32).to_le_bytes().to_vec(),
                av_id::TIMESTAMP => vec![self.next() as u8; 8],
                av_id::CHANNEL_BINDINGS => vec![self.next() as u8; 16],
                av_id::SINGLE_HOST | 0x0b.. => self.bytes(20),
                _ => self.name(20),
            };
            AvPair { id, value }
        }

        fn version(&mut self, flags: u32) -> Option<Version> {
            (flags & flags::NEGOTIATE_VERSION != 0).then(|| Version {
                major: self.next() as u8,
                minor: self.next() as u8,
                build: self.next() as u16,
                revision: self.next() as u8,
            })
        }

        fn pairs(&mut self) -> Vec<AvPair> {
            (0..self.index(5)).map(|_| self.pair()).collect()
        }

        fn message(&mut self) -> Message {
            let flags = (self.next() as u32) | ((self.next() as u32) & flags::NEGOTIATE_VERSION);
            let version = self.version(flags);
            match self.index(3) {
                0 => Message::Negotiate(Negotiate {
                    flags,
                    domain: self.bytes(10),
                    workstation: self.bytes(10),
                    version,
                }),
                1 => Message::Challenge(Challenge {
                    flags,
                    target_name: self.name(20),
                    server_challenge: [self.next() as u8; 8],
                    target_info: AvPairs(self.pairs()).to_bytes().unwrap(),
                    version,
                }),
                _ => {
                    let nt = match self.index(3) {
                        0 => NtResponse::Empty,
                        1 => NtResponse::V1([self.next() as u8; 24]),
                        _ => NtResponse::V2(NtlmV2Response {
                            nt_proof: [self.next() as u8; 16],
                            client: ClientChallenge {
                                resp_type: 1,
                                hi_resp_type: 1,
                                timestamp: u64::from(self.next() as u32),
                                challenge: [self.next() as u8; 8],
                                av_pairs: self.pairs(),
                                trailing: self.bytes(4),
                            },
                        }),
                    };
                    let mic = self.coin().then(|| [self.next() as u8; 16]);
                    Message::Authenticate(Authenticate {
                        flags,
                        lm_response: self.bytes(24),
                        nt_response: nt.to_bytes().unwrap(),
                        domain: self.name(10),
                        user: self.name(10),
                        workstation: self.name(10),
                        session_key: self.bytes(16),
                        version,
                        mic,
                    })
                }
            }
        }
    }

    /// Whatever reads is written back and reads back the same.
    fn check(b: &[u8]) {
        contract::check_wire::<AvPair>(b);
        contract::check_wire::<AvPairs>(b);
        contract::check_wire::<Version>(b);
        contract::check_wire::<Message>(b);
        contract::check_wire::<Negotiate>(b);
        contract::check_wire::<Challenge>(b);
        contract::check_wire::<Authenticate>(b);
        contract::check_wire::<NtResponse>(b);
        contract::check_wire::<NtlmV2Response>(b);
        contract::check_wire::<ClientChallenge>(b);
        contract::check_wire::<LmV2Response>(b);
        contract::check_wire::<UnicodeName>(b);
        contract::check_wire::<MicInput>(b);

        if let Ok(m) = Message::parse(b) {
            let bytes = m.to_bytes().unwrap();
            assert_eq!(Message::parse(&bytes), Ok(m.clone()));
            assert_eq!(m.to_bytes(), Ok(bytes));
            // What a message holds reads with its own reader.
            if let Message::Challenge(c) = &m
                && !c.target_info.is_empty()
            {
                let pairs = c.target_info_pairs().unwrap();
                let list = AvPairs(pairs.to_vec()).to_bytes().unwrap();
                assert_eq!(AvPairs::parse(&list), Ok(AvPairs(pairs)));
            }
            if let Message::Authenticate(a) = &m {
                let nt = a.nt().unwrap();
                assert_eq!(NtResponse::parse(&nt.to_bytes().unwrap()), Ok(nt));
            }
        }
        if let Ok(nt) = NtResponse::parse(b) {
            assert_eq!(NtResponse::parse(&nt.to_bytes().unwrap()), Ok(nt));
        }
        if let Ok(AvPairs(pairs)) = AvPairs::parse(b) {
            let list = AvPairs(pairs.to_vec()).to_bytes().unwrap();
            assert_eq!(AvPairs::parse(&list), Ok(AvPairs(pairs)));
        }
        if let Ok(r) = LmV2Response::parse(b) {
            assert_eq!(r.to_bytes().unwrap(), b);
        }
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg::new(0x0e7c_1a55_0001);
        for _ in 0..4000 {
            // A value written and read back.
            let m = rng.message();
            let bytes = m.to_bytes().unwrap();
            assert_eq!(Message::parse(&bytes), Ok(m.clone()));
            if let Message::Authenticate(a) = &m {
                let nt = NtResponse::parse(&a.nt_response).unwrap();
                assert_eq!(nt.to_bytes().unwrap(), a.nt_response);
            }
            // Every prefix, read one byte longer at a time.
            for n in 0..bytes.len() {
                check(&bytes[..n]);
            }
            // Mutated bytes.
            let mut b = bytes.clone();
            for _ in 0..1 + rng.index(4) {
                mutate(&mut rng, &mut b);
            }
            check(&b);
            // Random bytes behind a valid signature and type.
            let mut r = SIGNATURE.to_vec();
            r.extend_from_slice(&(1 + rng.index(3) as u32).to_le_bytes());
            r.extend_from_slice(&rng.bytes(120));
            check(&r);
            // Random bytes on their own.
            check(&rng.bytes(64));
        }
        // Large messages whose field descriptors point anywhere, so that
        // fields overlap and run near the size limits.
        for _ in 0..200 {
            let mut b = vec![0u8; 1 + rng.index(MAX_MESSAGE + 64)];
            let kind = 1 + rng.index(3) as u32;
            let head = [12usize, 16, 20, 24, 28, 36, 40, 44, 52, 60];
            if b.len() >= 64 {
                b[..8].copy_from_slice(&SIGNATURE);
                b[8..12].copy_from_slice(&kind.to_le_bytes());
                for at in head {
                    if rng.coin() {
                        let len = rng.index(b.len()) as u16;
                        let off = rng.index(b.len()) as u32;
                        b[at..at + 2].copy_from_slice(&len.to_le_bytes());
                        b[at + 4..at + 8].copy_from_slice(&off.to_le_bytes());
                    }
                }
            }
            check(&b);
            if let Ok(m) = Message::parse(&b) {
                assert!(m.to_bytes().unwrap().len() <= MAX_MESSAGE);
            }
            if let Some(z) = Authenticate::mic_input(&b) {
                assert_eq!(z.to_bytes().unwrap().len(), b.len());
            }
        }
    }
}
