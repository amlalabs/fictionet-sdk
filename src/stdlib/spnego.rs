//! SPNEGO: reading and writing the GSS-API negotiation tokens that HTTP
//! Negotiate, SMB and LDAP carry, with no I/O.
//!
//! `NegotiationToken` implements `Wire`, and `codec::Frames<Frame>` decodes successive
//! tokens. There is no negotiation session or `Service`, mechanism
//! authentication, cryptography, or live transport. Inner tokens remain bytes.
//!
//! SPNEGO lets a client and a server agree on how to authenticate, usually
//! Kerberos or NTLM, and carries the chosen mechanism's own tokens while
//! they do. The client opens with a NegTokenInit that lists the mechanisms
//! it supports, often with a first token for the one it likes best. The
//! server answers with NegTokenResp messages until the exchange is done.
//! The first token travels inside the GSS-API initial context token
//! wrapper, which names the mechanism (SPNEGO) by its object identifier.
//! Only negTokenInit goes in this wrapper. Wrapped negTokenResp values
//! are refused on both read and write (RFC 4178 section 4.1).
//! Windows servers also send a NegTokenInit2 first, with hints, in the SMB
//! negotiate response. This module follows RFC 4178, the wrapper of
//! RFC 2743 section 3.1, and NegTokenInit2 from Microsoft's \[MS-SPNG\]
//! section 2.2.1.
//!
//! Nothing here reads a socket or decodes base64. A world that plays a web
//! server takes the bytes of an `Authorization: Negotiate` header, reads
//! them with [`NegotiationToken::parse`], looks at the mechanisms offered,
//! and writes its answer with [`NegotiationToken::write`]. The inner
//! mechanism tokens (a Kerberos AP-REQ, an NTLM message) are kept as bytes.
//! What they mean, and whether to accept them, is up to world code. HTTP,
//! SMB and LDAP each give a token's length, so most worlds never need the
//! [`Stream<Frames<Frame>>`](fictionet::stdlib::codec::Stream), which splits tokens sent back to back.
//!
//! Every reader checks lengths and nesting, because the agent can send any
//! bytes it likes. Tokens are read as BER and written as DER. A token is at
//! most [`MAX_TOKEN`] bytes and offers at most [`MAX_MECHS`] mechanisms.
//! [`Wire::parse`] refuses a received hintAddress with [`Error::HintAddress`].
//! A world playing an HTTP or SMB server cannot read such a negotiation token.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::spnego::{InitialContextToken, Mech, NegState, NegTokenInit, NegTokenResp, NegotiationToken};
//!
//! // What a client sends first: NTLM offered, with its NEGOTIATE message.
//! let negotiate = b"NTLMSSP\0\x01\0\0\0".to_vec();
//! let offer = NegotiationToken::Init(NegTokenInit {
//!     mech_types: vec![Mech::Ntlm],
//!     mech_token: Some(negotiate.clone()),
//!     ..NegTokenInit::default()
//! });
//! let wire = InitialContextToken::spnego(&offer).unwrap().to_bytes().unwrap();
//! assert_eq!(wire[0], 0x60);
//!
//! // The world's server reads it and picks NTLM.
//! let NegotiationToken::Init(init) = NegotiationToken::parse(&wire).unwrap() else { panic!() };
//! assert_eq!(init.mech_types, [Mech::Ntlm]);
//! assert_eq!(init.mech_token.as_deref(), Some(&negotiate[..]));
//!
//! let reply = NegotiationToken::Resp(NegTokenResp {
//!     neg_state: Some(NegState::AcceptIncomplete),
//!     supported_mech: Some(Mech::Ntlm),
//!     response_token: Some(b"NTLMSSP\0\x02\0\0\0".to_vec()),
//!     mech_list_mic: None,
//! });
//! let bytes = reply.to_bytes().unwrap();
//! assert_eq!(bytes[..9], [0xa1, 0x25, 0x30, 0x23, 0xa0, 0x03, 0x0a, 0x01, 0x01]);
//! assert_eq!(NegotiationToken::parse(&bytes).unwrap(), reply);
//! ```

use fictionet::stdlib::asn1::{
    self, Class, Element, Header, Length, Oid, Reader, Rules, StringKind, Tag, Writer,
};
#[cfg(test)]
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{Prefixed, Wire};
use std::fmt;

/// The longest token, wrapper included, a reader accepts and a writer
/// writes. Windows caps its own tokens at 65,535 bytes (MaxTokenSize).
pub const MAX_TOKEN: usize = 64 * 1024;
/// The most mechanisms one NegTokenInit may offer.
pub const MAX_MECHS: usize = 32;

/// The first byte of a GSS-API initial context token: `[APPLICATION 0]`,
/// constructed.
pub const GSS_TAG: u8 = 0x60;
/// The first byte of a negTokenInit (or NegTokenInit2): `[0]`,
/// constructed.
pub const INIT_TAG: u8 = 0xa0;
/// The first byte of a negTokenResp: `[1]`, constructed.
pub const RESP_TAG: u8 = 0xa1;

/// Why bytes are not a SPNEGO token, or why a writer could not write one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Encoding would change the value when parsed.
    Unwritable,
    /// The bytes are not well-formed ASN.1, or a field has the wrong type.
    Asn1(asn1::Error),
    /// The token, or a value a writer was given, is longer than
    /// [`MAX_TOKEN`].
    TooLong,
    /// A NegTokenInit offers more than [`MAX_MECHS`] mechanisms.
    TooManyMechs,
    /// The first element is not a GSS-API wrapper, a negTokenInit or a
    /// negTokenResp.
    NotToken,
    /// A GSS-API wrapper, or a token given to the [`Stream<Frames<Frame>>`](fictionet::stdlib::codec::Stream), has an
    /// indefinite length. RFC 2743 requires a definite one.
    Indefinite,
    /// A GSS-API wrapper names a mechanism other than SPNEGO.
    WrongMech,
    /// A field of a NegTokenInit or NegTokenResp is not context-specific,
    /// or comes out of order or twice.
    Field,
    /// A negTokenResp inside a GSS-API wrapper. RFC 4178 section 4.1 wraps
    /// only the first token, and a negTokenResp never comes first.
    WrappedResp,
    /// A NegTokenInit, not a NegTokenInit2, offers no mechanism: it has no
    /// mechTypes, or an empty list.
    MissingMechTypes,
    /// A negState outside the four RFC 4178 defines.
    NegState(i64),
    /// A received or written token has a hintAddress. \[MS-SPNG\] 2.2.1
    /// says a sender must leave it out, even an empty one.
    HintAddress,
}

fictionet::error_display!(Error, f, {
    Error::Unwritable => f.write_str("value cannot be written without changing it"),
    Error::Asn1(e) => write!(f, "ASN.1: {e}"),
    Error::TooLong => write!(f, "token longer than {MAX_TOKEN} bytes"),
    Error::TooManyMechs => write!(f, "more than {MAX_MECHS} mechanisms"),
    Error::NotToken => f.write_str("not a GSS-API or SPNEGO token"),
    Error::Indefinite => f.write_str("indefinite length on a token"),
    Error::WrongMech => f.write_str("GSS-API wrapper for a mechanism other than SPNEGO"),
    Error::Field => f.write_str("field out of order, repeated or not context-specific"),
    Error::WrappedResp => f.write_str("negTokenResp inside a GSS-API wrapper"),
    Error::MissingMechTypes => f.write_str("NegTokenInit without mechTypes"),
    Error::NegState(v) => write!(f, "negState {v}, outside 0..=3"),
    Error::HintAddress => f.write_str("hintAddress, which a sender must leave out"),
});

impl From<asn1::Error> for Error {
    fn from(e: asn1::Error) -> Error {
        Error::Asn1(e)
    }
}

/// A GSS-API mechanism, named when this module knows its object
/// identifier. Two mechanisms are equal, and hash the same, when their
/// object identifiers are, so `Mech::Other` holding NTLM's identifier
/// equals `Mech::Ntlm`.
#[derive(Clone, Debug)]
pub enum Mech {
    /// SPNEGO itself, 1.3.6.1.5.5.2.
    Spnego,
    /// Kerberos 5, 1.2.840.113554.1.2.2 (RFC 1964).
    Kerberos,
    /// Kerberos 5 under the identifier early Windows wrote by mistake,
    /// 1.2.840.48018.1.2.2. Windows still lists it first.
    MsKerberos,
    /// Kerberos 5 user-to-user, 1.2.840.113554.1.2.2.3.
    KerberosUser2User,
    /// IAKERB, Kerberos through the server, 1.3.6.1.5.2.5 (RFC 9762).
    Iakerb,
    /// NTLM, 1.3.6.1.4.1.311.2.2.10.
    Ntlm,
    /// NEGOEX, the extended negotiation of \[MS-NEGOEX\],
    /// 1.3.6.1.4.1.311.2.2.30.
    NegoEx,
    /// Any other mechanism. A reader never gives this for an identifier
    /// named above: `Other` holding one is written as given and read back
    /// as the named variant, which equals it.
    Other(Oid),
}

impl PartialEq for Mech {
    fn eq(&self, other: &Mech) -> bool {
        self.contents() == other.contents()
    }
}

impl Eq for Mech {}

impl std::hash::Hash for Mech {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.contents().hash(state);
    }
}

/// Each named mechanism, its object identifier's contents, and its dotted
/// form.
static NAMED: [(Mech, &[u8], &str); 7] = [
    (
        Mech::Spnego,
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02],
        "1.3.6.1.5.5.2",
    ),
    (
        Mech::Kerberos,
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02],
        "1.2.840.113554.1.2.2",
    ),
    (
        Mech::MsKerberos,
        &[0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02],
        "1.2.840.48018.1.2.2",
    ),
    (
        Mech::KerberosUser2User,
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x03],
        "1.2.840.113554.1.2.2.3",
    ),
    (
        Mech::Iakerb,
        &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x05],
        "1.3.6.1.5.2.5",
    ),
    (
        Mech::Ntlm,
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a],
        "1.3.6.1.4.1.311.2.2.10",
    ),
    (
        Mech::NegoEx,
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1e],
        "1.3.6.1.4.1.311.2.2.30",
    ),
];

impl Mech {
    /// Where a named mechanism is in [`NAMED`].
    fn named(&self) -> Option<usize> {
        Some(match self {
            Mech::Spnego => 0,
            Mech::Kerberos => 1,
            Mech::MsKerberos => 2,
            Mech::KerberosUser2User => 3,
            Mech::Iakerb => 4,
            Mech::Ntlm => 5,
            Mech::NegoEx => 6,
            Mech::Other(_) => return None,
        })
    }

    /// The mechanism an object identifier names.
    pub fn from_oid(oid: &Oid) -> Mech {
        match NAMED.iter().find(|(_, c, _)| *c == oid.as_bytes()) {
            Some((m, _, _)) => m.clone(),
            None => Mech::Other(oid.clone()),
        }
    }

    /// The mechanism whose object identifier has these contents bytes.
    pub fn from_contents(b: &[u8]) -> Result<Mech, Error> {
        Ok(Mech::from_oid(&Oid::from_contents(b)?))
    }

    /// The object identifier's contents bytes, as X.690 encodes them.
    pub fn contents(&self) -> &[u8] {
        match self {
            Mech::Other(oid) => oid.as_bytes(),
            named => named
                .named()
                .and_then(|i| NAMED.get(i))
                .map_or(&[][..], |(_, c, _)| *c),
        }
    }

    /// The whole OBJECT IDENTIFIER element: tag, length and contents.
    fn element(&self) -> Vec<u8> {
        let c = self.contents();
        let mut out = Vec::with_capacity(c.len() + 3);
        out.push(0x06);
        asn1::encode_length(c.len(), &mut out);
        out.extend_from_slice(c);
        out
    }
}

impl fmt::Display for Mech {
    /// Writes the dotted form, such as `1.3.6.1.4.1.311.2.2.10`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mech::Other(oid) => write!(f, "{oid}"),
            named => f.write_str(
                named
                    .named()
                    .and_then(|i| NAMED.get(i))
                    .map_or("", |(_, _, s)| *s),
            ),
        }
    }
}

/// The GSS-API initial context token of RFC 2743 section 3.1: a
/// mechanism's object identifier, then that mechanism's own token. For
/// SPNEGO the inner token is a [`NegotiationToken::Init`]; for Kerberos it
/// is a two-byte token ID and an AP-REQ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialContextToken {
    /// The mechanism the token is for.
    pub mech: Mech,
    /// The mechanism's token, as bytes.
    pub inner: Vec<u8>,
}

impl InitialContextToken {
    /// Wraps an initial SPNEGO token for GSS-API. RFC 4178 section 4.1
    /// permits only negTokenInit here; negTokenResp is [`Error::WrappedResp`].
    /// Refuses tokens the writer cannot represent within [`MAX_TOKEN`].
    pub fn spnego(token: &NegotiationToken) -> Result<Self, Error> {
        if matches!(token, NegotiationToken::Resp(_)) {
            return Err(Error::WrappedResp);
        }
        let wrapper = Self {
            mech: Mech::Spnego,
            inner: token.to_bytes()?,
        };
        wrapper.encode()?;
        Ok(wrapper)
    }

    fn decode(b: &[u8]) -> Result<InitialContextToken, Error> {
        if b.len() > MAX_TOKEN {
            return Err(Error::TooLong);
        }
        let h = Header::parse(b, Rules::Ber)?;
        if h.tag != Tag::application(0).as_constructed() {
            return Err(Error::NotToken);
        }
        let Length::Definite(n) = h.length else {
            return Err(Error::Indefinite);
        };
        let end = h.len.checked_add(n).ok_or(Error::TooLong)?;
        if end > b.len() {
            return Err(Error::Asn1(asn1::Error::Truncated));
        }
        if end < b.len() {
            return Err(Error::Asn1(asn1::Error::Trailing));
        }
        let mut r = Reader::new(&b[h.len..end], Rules::Ber);
        let oid = r.read_oid()?;
        Ok(InitialContextToken {
            mech: Mech::from_oid(&oid),
            inner: r.remaining().to_vec(),
        })
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        let oid = self.mech.element();
        let body = oid
            .len()
            .checked_add(self.inner.len())
            .ok_or(Error::TooLong)?;
        if body > MAX_TOKEN {
            return Err(Error::TooLong);
        }
        let mut out = Vec::with_capacity(body + 4);
        out.push(GSS_TAG);
        asn1::encode_length(body, &mut out);
        out.extend_from_slice(&oid);
        out.extend_from_slice(&self.inner);
        if out.len() > MAX_TOKEN {
            return Err(Error::TooLong);
        }
        if self.mech == Mech::Spnego && self.inner.first() == Some(&RESP_TAG) {
            return Err(Error::WrappedResp);
        }
        Ok(out)
    }
}

/// The ContextFlags bit string of a NegTokenInit: the services the client
/// asks for. It is held as the 32 bits RFC 4178 gives it, first bit
/// highest, so named bit 0 (delegFlag) is `0x8000_0000`. Bits past the
/// 32nd are dropped when read. It is written in DER, with its trailing
/// zero bits left out (X.690 11.2.2), so no flags at all is `03 01 00`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ContextFlags(
    /// Flags in the high bits, as ordered on the wire.
    pub u32,
);

impl ContextFlags {
    /// delegFlag: the server may act as the client.
    pub const DELEG: ContextFlags = ContextFlags(1 << 31);
    /// mutualFlag: the server proves who it is too.
    pub const MUTUAL: ContextFlags = ContextFlags(1 << 30);
    /// replayFlag: replayed messages are detected.
    pub const REPLAY: ContextFlags = ContextFlags(1 << 29);
    /// sequenceFlag: messages out of order are detected.
    pub const SEQUENCE: ContextFlags = ContextFlags(1 << 28);
    /// anonFlag: the client stays anonymous.
    pub const ANON: ContextFlags = ContextFlags(1 << 27);
    /// confFlag: messages can be encrypted.
    pub const CONF: ContextFlags = ContextFlags(1 << 26);
    /// integFlag: messages can be signed.
    pub const INTEG: ContextFlags = ContextFlags(1 << 25);

    /// Whether every flag set in `other` is set here.
    pub fn contains(self, other: ContextFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// The flags from a bit string's bytes and unused-bit count.
    fn from_bits(bytes: &[u8], unused: u8) -> ContextFlags {
        let mut b = [0u8; 4];
        let n = bytes.len().min(4);
        b[..n].copy_from_slice(&bytes[..n]);
        // BER lets unused bits hold anything; they are not flags.
        if (1..=4).contains(&bytes.len()) && unused <= 7 {
            b[bytes.len() - 1] &= 0xffu8 << unused;
        }
        ContextFlags(u32::from_be_bytes(b))
    }

    /// The bit string's bytes and unused-bit count in DER: up to the last
    /// set bit, and no bytes when no bit is set.
    fn der_bits(self) -> ([u8; 4], usize, u8) {
        let bits = 32 - self.0.trailing_zeros() as usize;
        let len = bits.div_ceil(8);
        (self.0.to_be_bytes(), len, (len * 8 - bits) as u8)
    }
}

impl std::ops::BitOr for ContextFlags {
    type Output = ContextFlags;

    fn bitor(self, rhs: ContextFlags) -> ContextFlags {
        ContextFlags(self.0 | rhs.0)
    }
}

/// The hints of a NegTokenInit2 (\[MS-SPNG\] 2.2.1). Windows sends the
/// name `not_defined_in_RFC4178@please_ignore` and no address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NegHints {
    /// hintName: a GeneralString, as bytes.
    pub hint_name: Option<Vec<u8>>,
    /// hintAddress, as bytes. \[MS-SPNG\] says a sender must leave it out.
    /// Received and written hint addresses are refused with [`Error::HintAddress`].
    pub hint_address: Option<Vec<u8>>,
}

/// A NegTokenInit (RFC 4178 4.2.1), or a NegTokenInit2 (\[MS-SPNG\]
/// 2.2.1) when `neg_hints` is set. The two share the `[0]` choice and
/// their first three fields. Field `[3]` is the mechListMIC in one and the
/// hints in the other, and the NegTokenInit2 mechListMIC is `[4]`.
///
/// A NegTokenInit must offer at least one mechanism. A NegTokenInit2 may
/// offer none, and then has no mechTypes field: an empty `mech_types` is
/// written as no field. A reader tells the two apart by field `[3]`'s type,
/// or by a mechListMIC at `[4]`. A NegTokenInit2 read with a mechListMIC
/// but no hints gets empty hints, so it is written back as a NegTokenInit2,
/// with an empty `[3]`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NegTokenInit {
    /// mechTypes: the mechanisms offered, most preferred first. At least
    /// one in a NegTokenInit.
    pub mech_types: Vec<Mech>,
    /// reqFlags. RFC 4178 says to send none and ignore any received.
    pub req_flags: Option<ContextFlags>,
    /// mechToken: the first token of the first mechanism offered.
    pub mech_token: Option<Vec<u8>>,
    /// negHints: present only in a NegTokenInit2.
    pub neg_hints: Option<NegHints>,
    /// mechListMIC: the first mechanism's MIC over the encoded mechTypes.
    pub mech_list_mic: Option<Vec<u8>>,
}

/// The state of the negotiation, as the server says in a NegTokenResp.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NegState {
    /// accept-completed: authentication is done and succeeded.
    AcceptCompleted = 0,
    /// accept-incomplete: more tokens are needed.
    AcceptIncomplete = 1,
    /// reject: authentication failed.
    Reject = 2,
    /// request-mic: the client must send a mechListMIC.
    RequestMic = 3,
}

impl NegState {
    /// The state with this ENUMERATED value.
    pub fn from_value(v: i64) -> Result<NegState, Error> {
        Ok(match v {
            0 => NegState::AcceptCompleted,
            1 => NegState::AcceptIncomplete,
            2 => NegState::Reject,
            3 => NegState::RequestMic,
            _ => return Err(Error::NegState(v)),
        })
    }
}

/// A NegTokenResp (RFC 4178 4.2.2). Every field is optional.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NegTokenResp {
    /// negState.
    pub neg_state: Option<NegState>,
    /// supportedMech: the mechanism the server chose, in its first reply.
    pub supported_mech: Option<Mech>,
    /// responseToken: the chosen mechanism's token.
    pub response_token: Option<Vec<u8>>,
    /// mechListMIC.
    pub mech_list_mic: Option<Vec<u8>>,
}

/// A SPNEGO token: the NegotiationToken choice of RFC 4178 4.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NegotiationToken {
    /// negTokenInit, `[0]`: what a client sends first, or the hints a
    /// Windows server sends before that.
    Init(NegTokenInit),
    /// negTokenResp, `[1]`: every later token.
    Resp(NegTokenResp),
}

impl NegotiationToken {
    fn decode(b: &[u8]) -> Result<NegotiationToken, Error> {
        if b.len() > MAX_TOKEN {
            return Err(Error::TooLong);
        }
        if b.first() == Some(&GSS_TAG) {
            let t = InitialContextToken::parse(b)?;
            if t.mech != Mech::Spnego {
                return Err(Error::WrongMech);
            }
            return match parse_bare(&t.inner)? {
                NegotiationToken::Resp(_) => Err(Error::WrappedResp),
                init => Ok(init),
            };
        }
        parse_bare(b)
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut total: usize = 0;
        let mut add = |v: &Option<Vec<u8>>| {
            total = total.saturating_add(v.as_ref().map_or(0, Vec::len));
        };
        match self {
            NegotiationToken::Init(t) => {
                if t.mech_types.len() > MAX_MECHS {
                    return Err(Error::TooManyMechs);
                }
                if t.mech_types.is_empty() && t.neg_hints.is_none() {
                    return Err(Error::MissingMechTypes);
                }
                if t.neg_hints
                    .as_ref()
                    .is_some_and(|h| h.hint_address.is_some())
                {
                    return Err(Error::HintAddress);
                }
                add(&t.mech_token);
                add(&t.mech_list_mic);
                if let Some(h) = &t.neg_hints {
                    add(&h.hint_name);
                }
            }
            NegotiationToken::Resp(t) => {
                add(&t.response_token);
                add(&t.mech_list_mic);
            }
        }
        if total > MAX_TOKEN {
            return Err(Error::TooLong);
        }
        let mut w = Writer::new();
        match self {
            NegotiationToken::Init(t) => w.explicit(0, |w| write_init(w, t)),
            NegotiationToken::Resp(t) => w.explicit(1, |w| write_resp(w, t)),
        }
        let out = w.finish()?;
        if out.len() > MAX_TOKEN {
            return Err(Error::TooLong);
        }
        Ok(out)
    }
}

/// Reads a NegotiationToken with no wrapper.
fn parse_bare(b: &[u8]) -> Result<NegotiationToken, Error> {
    if b.len() > MAX_TOKEN {
        return Err(Error::TooLong);
    }
    let mut r = Reader::new(b, Rules::Ber);
    let e = r.read()?;
    r.finish()?;
    let t = e.tag();
    if t.class != Class::ContextSpecific || t.number > 1 {
        return Err(Error::NotToken);
    }
    let mut outer = e.reader()?;
    let seq = outer.read_sequence()?;
    outer.finish()?;
    if t.number == 0 {
        Ok(NegotiationToken::Init(parse_init(seq)?))
    } else {
        Ok(NegotiationToken::Resp(parse_resp(seq)?))
    }
}

/// The one element inside an explicit tag.
fn explicit_one<'a, T>(
    e: &Element<'a>,
    f: impl FnOnce(&mut Reader<'a>) -> Result<T, asn1::Error>,
) -> Result<T, Error> {
    let mut r = e.reader()?;
    let v = f(&mut r)?;
    r.finish()?;
    Ok(v)
}

/// The fields of a sequence whose known fields have context-specific tags
/// `[0]` to `[last]`, in ascending order. Each known field is checked and
/// handed to `f`. Any other element is an addition after the extension
/// marker, which RFC 4178 4.2 says to ignore, whatever its tag; it comes
/// after every known field, so a known field after one is out of order.
fn fields<'a>(
    seq: Reader<'a>,
    last: u32,
    mut f: impl FnMut(u32, &Element<'a>) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut prev: Option<u32> = None;
    let mut extended = false;
    for e in seq {
        let e = e?;
        let t = e.tag();
        if t.class != Class::ContextSpecific || t.number > last {
            extended = true;
            continue;
        }
        if extended || prev.is_some_and(|p| t.number <= p) {
            return Err(Error::Field);
        }
        prev = Some(t.number);
        f(t.number, &e)?;
    }
    Ok(())
}

fn parse_init(seq: Reader<'_>) -> Result<NegTokenInit, Error> {
    let mut t = NegTokenInit::default();
    fields(seq, 4, |n, e| {
        match n {
            0 => {
                let mut list = explicit_one(e, |r| r.read_sequence())?;
                while !list.is_empty() {
                    if t.mech_types.len() >= MAX_MECHS {
                        return Err(Error::TooManyMechs);
                    }
                    t.mech_types.push(Mech::from_oid(&list.read_oid()?));
                }
            }
            1 => {
                let bits = explicit_one(e, |r| r.read_bit_string())?;
                t.req_flags = Some(ContextFlags::from_bits(bits.bytes(), bits.unused()));
            }
            2 => t.mech_token = Some(explicit_one(e, |r| r.read_octet_string())?.into_owned()),
            3 => {
                let mut r = e.reader()?;
                if r.peek()?.tag().same_type(Tag::SEQUENCE) {
                    t.neg_hints = Some(parse_hints(r.read_sequence()?)?);
                } else {
                    t.mech_list_mic = Some(r.read_octet_string()?.into_owned());
                }
                r.finish()?;
            }
            // After hints, [4] is the NegTokenInit2 mechListMIC. After a
            // mechListMIC at [3], it is an unknown field, and RFC 4178 4.2
            // says to ignore it. With no [3] it may be either, so it is the
            // mechListMIC only if it holds an OCTET STRING.
            4 if t.neg_hints.is_some() || (t.mech_list_mic.is_none() && holds_octet_string(e)) => {
                t.mech_list_mic = Some(explicit_one(e, |r| r.read_octet_string())?.into_owned());
                // A NegTokenInit2 without hints: given empty ones, so it
                // is written back as a NegTokenInit2, MIC at [4].
                t.neg_hints.get_or_insert_with(NegHints::default);
            }
            // A [4] that is not a mechListMIC is an addition, skipped.
            _ => {}
        }
        Ok(())
    })?;
    // RFC 4178 3.2 and 4.2.1: a NegTokenInit offers one or more
    // mechanisms. A NegTokenInit2 may leave the list out.
    if t.mech_types.is_empty() && t.neg_hints.is_none() {
        return Err(Error::MissingMechTypes);
    }
    Ok(t)
}

/// Whether an explicit tag holds an OCTET STRING, in either form, first.
fn holds_octet_string(e: &Element<'_>) -> bool {
    e.reader()
        .and_then(|r| r.peek())
        .is_ok_and(|x| x.tag().same_type(Tag::OCTET_STRING))
}

fn parse_hints(mut s: Reader<'_>) -> Result<NegHints, Error> {
    let mut h = NegHints::default();
    if let Some(e) = s.read_optional(Tag::context(0))? {
        h.hint_name =
            Some(explicit_one(&e, |r| r.read_string_bytes(StringKind::General))?.into_owned());
    }
    if let Some(e) = s.read_optional(Tag::context(1))? {
        h.hint_address = Some(explicit_one(&e, |r| r.read_octet_string())?.into_owned());
    }
    s.finish()?;
    Ok(h)
}

fn parse_resp(seq: Reader<'_>) -> Result<NegTokenResp, Error> {
    let mut t = NegTokenResp::default();
    fields(seq, 3, |n, e| {
        match n {
            0 => {
                let v = explicit_one(e, |r| r.read_enumerated())?;
                let v = v.to_i64().ok_or(Error::Asn1(asn1::Error::Integer))?;
                t.neg_state = Some(NegState::from_value(v)?);
            }
            1 => t.supported_mech = Some(Mech::from_oid(&explicit_one(e, |r| r.read_oid())?)),
            2 => t.response_token = Some(explicit_one(e, |r| r.read_octet_string())?.into_owned()),
            3 => t.mech_list_mic = Some(explicit_one(e, |r| r.read_octet_string())?.into_owned()),
            // `fields` hands over only [0] to [3].
            _ => {}
        }
        Ok(())
    })?;
    Ok(t)
}

fn write_init(w: &mut Writer, t: &NegTokenInit) {
    w.sequence(|w| {
        if !t.mech_types.is_empty() {
            w.explicit(0, |w| {
                w.sequence(|w| {
                    for m in &t.mech_types {
                        w.encoded(&m.element());
                    }
                })
            });
        }
        if let Some(f) = t.req_flags {
            let (bytes, len, unused) = f.der_bits();
            w.explicit(1, |w| w.bit_string(&bytes[..len], unused));
        }
        if let Some(tok) = &t.mech_token {
            w.explicit(2, |w| w.octet_string(tok));
        }
        match &t.neg_hints {
            Some(h) => {
                w.explicit(3, |w| {
                    w.sequence(|w| {
                        if let Some(name) = &h.hint_name {
                            w.explicit(0, |w| w.string_bytes(StringKind::General, name));
                        }
                    })
                });
                if let Some(mic) = &t.mech_list_mic {
                    w.explicit(4, |w| w.octet_string(mic));
                }
            }
            None => {
                if let Some(mic) = &t.mech_list_mic {
                    w.explicit(3, |w| w.octet_string(mic));
                }
            }
        }
    });
}

fn write_resp(w: &mut Writer, t: &NegTokenResp) {
    w.sequence(|w| {
        if let Some(s) = t.neg_state {
            w.explicit(0, |w| w.enumerated(s as i64));
        }
        if let Some(m) = &t.supported_mech {
            w.explicit(1, |w| w.encoded(&m.element()));
        }
        if let Some(tok) = &t.response_token {
            w.explicit(2, |w| w.octet_string(tok));
        }
        if let Some(mic) = &t.mech_list_mic {
            w.explicit(3, |w| w.octet_string(mic));
        }
    });
}

/// How long the token at the start of `b` is. It returns `Ok(None)` if `b`
/// holds only part of one. The token must start with a GSS-API wrapper, a
/// negTokenInit or a negTokenResp, with a definite length; only its outer
/// header is checked.
pub fn token_len(b: &[u8]) -> Result<Option<usize>, Error> {
    token_len_limited(b, MAX_TOKEN)
}

fn token_len_limited(b: &[u8], limit: usize) -> Result<Option<usize>, Error> {
    let Some(&first) = b.first() else {
        return Ok(None);
    };
    if !matches!(first, GSS_TAG | INIT_TAG | RESP_TAG) {
        return Err(Error::NotToken);
    }
    let h = match Header::parse(b, Rules::Ber) {
        Ok(h) => h,
        Err(asn1::Error::Truncated) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let Length::Definite(n) = h.length else {
        return Err(Error::Indefinite);
    };
    let total = h.len.checked_add(n).ok_or(Error::TooLong)?;
    if total > limit {
        return Err(Error::TooLong);
    }
    Ok(if b.len() >= total { Some(total) } else { None })
}

impl Wire for InitialContextToken {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a whole wrapper from `bytes`, which must hold nothing else.
    /// Reads BER. Refuses indefinite wrappers, wrapped negTokenResp, and
    /// input or DER output over [`MAX_TOKEN`].
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let value = Self::decode(bytes)?;
        value.encode()?;
        Ok(value)
    }

    /// Appends the wrapper as DER. It fails with [`Error::TooLong`] if
    /// the result would be longer than [`MAX_TOKEN`].
    /// Refuses a SPNEGO wrapper containing negTokenResp.
    /// Refuses values that change when encoded. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let bytes = self.encode()?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
    fn to_bytes(&self) -> Result<Vec<u8>, Self::WriteError> {
        self.encode()
    }
}

impl Wire for NegotiationToken {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a whole token from `bytes`, which must hold nothing else. A
    /// negTokenInit may be inside a GSS-API wrapper, as a first token is,
    /// or not. A negTokenResp must not be wrapped (RFC 4178 section 4.1),
    /// and gives [`Error::WrappedResp`] if it is. A wrapper must name
    /// SPNEGO.
    /// Reads BER. Refuses invalid fields, exceeded mechanism lists, hintAddress,
    /// and input or DER output over [`MAX_TOKEN`].
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let value = Self::decode(bytes)?;
        value.encode()?;
        Ok(value)
    }

    /// Appends the token as DER, without a GSS-API wrapper, as every token
    /// after the first is sent. It fails if the result would be longer than
    /// [`MAX_TOKEN`], if a NegTokenInit offers more than [`MAX_MECHS`]
    /// mechanisms or, without hints, none, if hints hold a hintAddress, or
    /// if a value cannot be written.
    /// Refuses values that change when encoded. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let bytes = self.encode()?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
    fn to_bytes(&self) -> Result<Vec<u8>, Self::WriteError> {
        self.encode()
    }
}

/// One bounded message's bytes, with only its framing checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame(pub Vec<u8>);

impl Wire for Frame {
    type ParseError = Error;
    type WriteError = Error;
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        match Self::parse_prefix(bytes, &Self::default_limit())? {
            Some((data, used)) if used == bytes.len() => Ok(Self(data)),
            Some(_) => Err(asn1::Error::Trailing.into()),
            None => Err(asn1::Error::Truncated.into()),
        }
    }
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        match token_len_limited(&self.0, MAX_TOKEN)? {
            Some(n) if n == self.0.len() => {}
            Some(_) => return Err(asn1::Error::Trailing.into()),
            None => return Err(asn1::Error::Truncated.into()),
        }
        out.extend_from_slice(&self.0);
        Ok(())
    }
}

fictionet::prefixed! {
    /// Frames one SPNEGO message and yields its uninterpreted bytes.
    /// Partial input needs more bytes, including at EOF. The stream reports truncation.
    Frame => (Vec<u8>, Error, usize);
    name = "SPNEGO";
    default { MAX_TOKEN }
    normalize(limit) { limit.min(MAX_TOKEN) }
    capacity(limit) { (*limit).max(asn1::HEADER_ROOM) }
    fn parse_prefix(
        input: &[u8],
        limit: &Self::Limit,
    ) -> Result<Option<(Self::Item, usize)>, Error> {
        Ok(token_len_limited(input, *limit)?.map(|n| (input[..n].to_vec(), n)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::assert_cases;
    use fictionet::stdlib::codec::{Fail, Lcg, Stream};
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::rounds;
    use fictionet::stdlib::test_support::{chunks, decode_all, mutate};

    fn initial_context_token(mech: Mech, inner: Vec<u8>) -> InitialContextToken {
        InitialContextToken { mech, inner }
    }

    fn neg_hints_fixture(hint_name: Option<Vec<u8>>, hint_address: Option<Vec<u8>>) -> NegHints {
        NegHints {
            hint_name,
            hint_address,
        }
    }

    /// The hint name Windows and Samba send in a NegTokenInit2.
    const HINT: &[u8] = b"not_defined_in_RFC4178@please_ignore";

    /// A NegTokenInit2 as Samba sends it in an SMB2 NEGOTIATE response:
    /// NTLM offered, with the hint name of \[MS-SPNG\] 3.2.5.2.
    fn samba_init2() -> Vec<u8> {
        let mut b = vec![
            0x60, 0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, // wrapper, SPNEGO
            0xa0, 0x3e, 0x30, 0x3c, // negTokenInit, SEQUENCE
            0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02,
            0x02, 0x0a, 0xa3, 0x2a, 0x30, 0x28, 0xa0, 0x26, 0x1b, 0x24, // negHints, hintName
        ];
        b.extend_from_slice(HINT);
        b
    }

    /// mechTypes offering one mechanism, 1.2.
    const MECH_1_2: &[u8] = &[0xa0, 0x05, 0x30, 0x03, 0x06, 0x01, 0x2a];

    /// A negTokenInit holding these fields, with short-form lengths.
    fn init_of(fields: &[&[u8]]) -> Vec<u8> {
        let body = fields.concat();
        let mut b = vec![0xa0, body.len() as u8 + 2, 0x30, body.len() as u8];
        b.extend_from_slice(&body);
        b
    }

    /// The last token of a successful exchange: accept-completed and
    /// nothing else.
    const ACCEPT_COMPLETED: [u8; 9] = [0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x00];

    fn sample_tokens() -> Vec<NegotiationToken> {
        vec![
            NegotiationToken::Init(NegTokenInit {
                mech_types: vec![Mech::MsKerberos, Mech::Kerberos, Mech::NegoEx, Mech::Ntlm],
                req_flags: Some(ContextFlags::MUTUAL | ContextFlags::INTEG),
                mech_token: Some(vec![0x60, 0x82, 1, 2, 3]),
                neg_hints: None,
                mech_list_mic: Some(vec![9; 16]),
            }),
            NegotiationToken::Init(NegTokenInit {
                mech_types: vec![
                    Mech::Ntlm,
                    Mech::Iakerb,
                    Mech::KerberosUser2User,
                    Mech::Spnego,
                ],
                req_flags: None,
                mech_token: None,
                neg_hints: Some(neg_hints_fixture(Some(HINT.to_vec()), None)),
                mech_list_mic: Some(vec![7; 3]),
            }),
            NegotiationToken::Init(NegTokenInit {
                neg_hints: Some(NegHints::default()),
                ..NegTokenInit::default()
            }),
            NegotiationToken::Init(NegTokenInit {
                mech_types: vec![Mech::Spnego],
                ..NegTokenInit::default()
            }),
            NegotiationToken::Resp(NegTokenResp::default()),
            NegotiationToken::Resp(NegTokenResp {
                neg_state: Some(NegState::RequestMic),
                supported_mech: Some(Mech::Other("1.2.3.4.5".parse().unwrap())),
                response_token: Some(vec![0; 300]),
                mech_list_mic: Some(Vec::new()),
            }),
        ]
    }

    #[test]
    fn review_encoders_validate_before_writing() {
        assert_eq!(
            NegotiationToken::Init(NegTokenInit::default()).to_bytes(),
            Err(Error::MissingMechTypes)
        );
        let wrapped = initial_context_token(Mech::Spnego, vec![RESP_TAG, 0]);
        assert_eq!(wrapped.to_bytes(), Err(Error::WrappedResp));
        let huge = initial_context_token(Mech::Ntlm, vec![0; MAX_TOKEN]);
        assert_eq!(huge.to_bytes(), Err(Error::TooLong));
        let named = Mech::Other("1.3.6.1.4.1.311.2.2.10".parse().unwrap());
        let token = NegotiationToken::Resp(NegTokenResp {
            supported_mech: Some(named),
            ..Default::default()
        });
        assert_eq!(
            NegotiationToken::parse(&token.to_bytes().unwrap()),
            Ok(token)
        );
    }

    #[test]
    fn samba_negtokeninit2() {
        let b = samba_init2();
        let NegotiationToken::Init(t) = NegotiationToken::parse(&b).unwrap() else {
            panic!()
        };
        assert_eq!(t.mech_types, [Mech::Ntlm]);
        assert_eq!(t.req_flags, None);
        assert_eq!(t.mech_token, None);
        assert_eq!(
            t.neg_hints,
            Some(neg_hints_fixture(Some(HINT.to_vec()), None))
        );
        assert_eq!(t.mech_list_mic, None);
        // Written back, byte for byte.
        assert_eq!(
            InitialContextToken::spnego(&NegotiationToken::Init(t))
                .and_then(|token| token.to_bytes())
                .unwrap(),
            b
        );
        // The wrapper on its own.
        let w = InitialContextToken::parse(&b).unwrap();
        assert_eq!(w.mech, Mech::Spnego);
        assert_eq!(w.inner, b[10..]);
        assert_eq!(w.to_bytes().unwrap(), b);
        assert_eq!(token_len(&b), Ok(Some(b.len())));
    }

    #[test]
    fn accept_completed() {
        let t = NegotiationToken::parse(&ACCEPT_COMPLETED).unwrap();
        let want = NegotiationToken::Resp(NegTokenResp {
            neg_state: Some(NegState::AcceptCompleted),
            ..NegTokenResp::default()
        });
        assert_eq!(t, want);
        assert_eq!(want.to_bytes().unwrap(), ACCEPT_COMPLETED);
    }

    #[test]
    fn rfc4178_init_with_mic_at_3() {
        // RFC 4178 NegTokenInit: mechListMIC is [3] and an OCTET STRING.
        let t = NegotiationToken::Init(NegTokenInit {
            mech_types: vec![Mech::Kerberos],
            mech_list_mic: Some(vec![0xaa, 0xbb]),
            ..NegTokenInit::default()
        });
        let b = t.to_bytes().unwrap();
        let tail = [0xa3, 0x04, 0x04, 0x02, 0xaa, 0xbb];
        assert_eq!(b[b.len() - tail.len()..], tail);
        assert_eq!(NegotiationToken::parse(&b).unwrap(), t);
    }

    #[test]
    fn init2_mic_at_4() {
        let t = NegotiationToken::Init(NegTokenInit {
            mech_types: vec![Mech::Kerberos],
            neg_hints: Some(NegHints::default()),
            mech_list_mic: Some(vec![0xaa]),
            ..NegTokenInit::default()
        });
        let b = t.to_bytes().unwrap();
        let tail = [0xa3, 0x02, 0x30, 0x00, 0xa4, 0x03, 0x04, 0x01, 0xaa];
        assert_eq!(b[b.len() - tail.len()..], tail);
        assert_eq!(NegotiationToken::parse(&b).unwrap(), t);
    }

    #[test]
    fn context_flags() {
        let t = NegotiationToken::Init(NegTokenInit {
            mech_types: vec![Mech::from_contents(&[0x2a]).unwrap()],
            req_flags: Some(ContextFlags::DELEG | ContextFlags::CONF),
            ..NegTokenInit::default()
        });
        let b = t.to_bytes().unwrap();
        // [0] { [0] { 1.2 } [1] { BIT STRING 2 unused, 84 } }
        assert_eq!(
            b,
            init_of(&[MECH_1_2, &[0xa1, 0x04, 0x03, 0x02, 0x02, 0x84]])
        );
        // A short bit string, with garbage in its unused bits, as BER allows.
        let short = init_of(&[MECH_1_2, &[0xa1, 0x04, 0x03, 0x02, 0x01, 0x63]]);
        let NegotiationToken::Init(i) = NegotiationToken::parse(&short).unwrap() else {
            panic!()
        };
        let f = i.req_flags.unwrap();
        assert_eq!(f, ContextFlags(0x6200_0000));
        assert!(f.contains(ContextFlags::MUTUAL | ContextFlags::REPLAY | ContextFlags::INTEG));
        assert!(!f.contains(ContextFlags::DELEG));
        // Bits past the 32nd are dropped.
        let l = init_of(&[MECH_1_2, &[0xa1, 0x08, 0x03, 0x06, 0x00, 1, 2, 3, 4, 5]]);
        let NegotiationToken::Init(i) = NegotiationToken::parse(&l).unwrap() else {
            panic!()
        };
        assert_eq!(i.req_flags, Some(ContextFlags(0x0102_0304)));
    }

    #[test]
    fn mechs_named() {
        for (m, c, s) in NAMED.iter() {
            let oid = Oid::from_contents(c).unwrap();
            assert_eq!(oid.to_string(), *s);
            assert_eq!(&Mech::from_oid(&oid), m);
            assert_eq!(m.contents(), *c);
            assert_eq!(m.to_string(), *s);
            assert_eq!(Mech::from_contents(c).unwrap(), *m);
        }
        let other: Oid = "1.2.3".parse().unwrap();
        assert_eq!(Mech::from_oid(&other), Mech::Other(other.clone()));
        assert_eq!(Mech::Other(other).to_string(), "1.2.3");
        assert!(Mech::from_contents(&[]).is_err());
        // A long identifier needs a long-form length.
        let long = Mech::Other(
            Oid::from_arcs(&[
                1,
                2,
                1 << 120,
                1 << 120,
                1 << 120,
                1 << 120,
                1 << 120,
                1 << 120,
                1 << 120,
                1 << 120,
            ])
            .unwrap(),
        );
        assert!(long.contents().len() >= 128);
        let t = NegotiationToken::Resp(NegTokenResp {
            supported_mech: Some(long),
            ..NegTokenResp::default()
        });
        assert_eq!(NegotiationToken::parse(&t.to_bytes().unwrap()).unwrap(), t);
    }

    #[test]
    fn round_trips() {
        for t in sample_tokens() {
            let bare = t.to_bytes().unwrap();
            assert_eq!(NegotiationToken::parse(&bare).unwrap(), t);
            assert_eq!(token_len(&bare), Ok(Some(bare.len())));
            if let NegotiationToken::Init(_) = t {
                let wrapped = InitialContextToken::spnego(&t)
                    .and_then(|token| token.to_bytes())
                    .unwrap();
                assert_eq!(NegotiationToken::parse(&wrapped).unwrap(), t);
                assert_eq!(token_len(&wrapped), Ok(Some(wrapped.len())));
            }
        }
        let k = initial_context_token(Mech::Kerberos, vec![1, 0, 0x6e, 0x00]);
        assert_eq!(
            InitialContextToken::parse(&k.to_bytes().unwrap()).unwrap(),
            k
        );
        let empty = initial_context_token(Mech::Ntlm, Vec::new());
        assert_eq!(
            InitialContextToken::parse(&empty.to_bytes().unwrap()).unwrap(),
            empty
        );
    }

    #[test]
    fn ber_forms_are_read() {
        // accept-completed with indefinite lengths and a long-form length.
        let b = [
            0xa1, 0x80, 0x30, 0x80, 0xa0, 0x81, 0x03, 0x0a, 0x01, 0x00, 0, 0, 0, 0,
        ];
        assert_eq!(
            NegotiationToken::parse(&b).unwrap(),
            NegotiationToken::parse(&ACCEPT_COMPLETED).unwrap()
        );
        // A responseToken split into two segments.
        let b = [
            0xa1, 0x0e, 0x30, 0x0c, 0xa2, 0x0a, 0x24, 0x08, 0x04, 0x02, 1, 2, 0x04, 0x02, 3, 4,
        ];
        let NegotiationToken::Resp(r) = NegotiationToken::parse(&b).unwrap() else {
            panic!()
        };
        assert_eq!(r.response_token, Some(vec![1, 2, 3, 4]));
        // A wrapper with a long-form length that is not minimal.
        let samba = samba_init2();
        let mut w = vec![0x60, 0x82, 0x00, 0x48];
        w.extend_from_slice(&samba[2..]);
        assert_eq!(
            NegotiationToken::parse(&w).unwrap(),
            NegotiationToken::parse(&samba).unwrap()
        );
    }

    #[test]
    fn ber_values_are_read_and_written_as_der() {
        // reqFlags as a constructed bit string, and as an empty one.
        let b = init_of(&[MECH_1_2, &[0xa1, 0x06, 0x23, 0x04, 0x03, 0x02, 0x00, 0xff]]);
        let NegotiationToken::Init(i) = NegotiationToken::parse(&b).unwrap() else {
            panic!()
        };
        assert_eq!(i.req_flags, Some(ContextFlags(0xff00_0000)));
        let b = init_of(&[MECH_1_2, &[0xa1, 0x03, 0x03, 0x01, 0x00]]);
        let t = NegotiationToken::parse(&b).unwrap();
        let NegotiationToken::Init(i) = &t else {
            panic!()
        };
        assert_eq!(i.req_flags, Some(ContextFlags(0)));
        assert_eq!(t.to_bytes().unwrap(), b);
        // Garbage in the unused bits is dropped when written.
        let b = init_of(&[MECH_1_2, &[0xa1, 0x04, 0x03, 0x02, 0x01, 0x63]]);
        let t = NegotiationToken::parse(&b).unwrap();
        assert_eq!(
            t.to_bytes().unwrap(),
            init_of(&[MECH_1_2, &[0xa1, 0x04, 0x03, 0x02, 0x01, 0x62]])
        );
        // A hint name in two OCTET STRING segments, as X.690 8.23.6 allows.
        let b = [
            0xa0, 0x14, 0x30, 0x12, 0xa0, 0x02, 0x30, 0x00, 0xa3, 0x0c, 0x30, 0x0a, 0xa0, 0x08,
            0x3b, 0x06, 0x04, 0x01, b'a', 0x04, 0x01, b'b',
        ];
        let t = NegotiationToken::parse(&b).unwrap();
        let NegotiationToken::Init(i) = &t else {
            panic!()
        };
        assert_eq!(
            i.neg_hints.as_ref().and_then(|h| h.hint_name.as_deref()),
            Some(&b"ab"[..])
        );
        assert_eq!(NegotiationToken::parse(&t.to_bytes().unwrap()).unwrap(), t);
        // An identifier with a padded arc is not read, so it is never
        // written back.
        let b = [
            0xa0, 0x0a, 0x30, 0x08, 0xa0, 0x06, 0x30, 0x04, 0x06, 0x02, 0x80, 0x01,
        ];
        assert_eq!(
            NegotiationToken::parse(&b),
            Err(Error::Asn1(asn1::Error::Oid))
        );
        assert_eq!(
            InitialContextToken::parse(&[0x60, 0x04, 0x06, 0x02, 0x80, 0x01]),
            Err(Error::Asn1(asn1::Error::Oid))
        );
    }

    #[test]
    fn wrapped_resp_is_rejected() {
        let response = NegotiationToken::Resp(NegTokenResp::default());
        assert_eq!(
            InitialContextToken::spnego(&response),
            Err(Error::WrappedResp)
        );
        // RFC 4178 4.1: tokens after the first are never wrapped, and a
        // negTokenResp is never a first token.
        for inner in [
            ACCEPT_COMPLETED.as_slice(),
            &[
                0xa1, 0x80, 0x30, 0x80, 0xa0, 0x03, 0x0a, 0x01, 0x00, 0, 0, 0, 0,
            ],
        ] {
            assert!(matches!(
                NegotiationToken::parse(inner),
                Ok(NegotiationToken::Resp(_))
            ));
            let wrapper = initial_context_token(Mech::Spnego, inner.to_vec());
            let mut out = vec![42];
            assert_eq!(wrapper.write(&mut out), Err(Error::WrappedResp));
            assert_eq!(out, [42]);
            contract::check_wire_value(&wrapper);

            // Received wrappers still need the same check.
            let mut bytes = vec![
                0x60,
                (8 + inner.len()) as u8,
                0x06,
                0x06,
                0x2b,
                0x06,
                0x01,
                0x05,
                0x05,
                0x02,
            ];
            bytes.extend_from_slice(inner);
            assert_eq!(InitialContextToken::parse(&bytes), Err(Error::WrappedResp));
            assert_eq!(NegotiationToken::parse(&bytes), Err(Error::WrappedResp));
            contract::check_wire::<InitialContextToken>(&bytes);

            // Other mechanisms retain their own inner-token syntax.
            contract::check_wire_value(&initial_context_token(Mech::Ntlm, inner.to_vec()));
        }
    }

    #[test]
    fn unknown_field_4_in_init_is_ignored() {
        // RFC 4178 4.2: unknown fields are ignored. With no [3], a [4]
        // that is not an OCTET STRING cannot be an Init2 mechListMIC.
        let b = init_of(&[MECH_1_2, &[0xa4, 0x03, 0x02, 0x01, 0x07]]);
        let NegotiationToken::Init(i) = NegotiationToken::parse(&b).unwrap() else {
            panic!()
        };
        assert_eq!(i.mech_list_mic, None);
        let b = init_of(&[MECH_1_2, &[0x84, 0x00]]);
        assert!(NegotiationToken::parse(&b).is_ok());
        // After hints, [4] is the Init2 mechListMIC and must be one.
        let b = [
            0xa0, 0x0f, 0x30, 0x0d, 0xa0, 0x02, 0x30, 0x00, 0xa3, 0x02, 0x30, 0x00, 0xa4, 0x03,
            0x02, 0x01, 0x07,
        ];
        assert!(matches!(
            NegotiationToken::parse(&b),
            Err(Error::Asn1(asn1::Error::Unexpected { .. }))
        ));
    }

    #[test]
    fn extensions_are_skipped() {
        // A NegTokenResp with a [5] field after the known ones.
        let b = [
            0xa1, 0x0c, 0x30, 0x0a, 0xa0, 0x03, 0x0a, 0x01, 0x02, 0xa5, 0x03, 0x02, 0x01, 0x07,
        ];
        let NegotiationToken::Resp(r) = NegotiationToken::parse(&b).unwrap() else {
            panic!()
        };
        assert_eq!(r.neg_state, Some(NegState::Reject));
        // A NegTokenInit with a mechListMIC at [3] and an extension at [4].
        let b = init_of(&[
            MECH_1_2,
            &[0xa3, 0x03, 0x04, 0x01, 0xaa, 0xa4, 0x03, 0x04, 0x01, 0xbb],
        ]);
        let NegotiationToken::Init(i) = NegotiationToken::parse(&b).unwrap() else {
            panic!()
        };
        assert_eq!(i.mech_list_mic, Some(vec![0xaa]));
    }

    #[test]
    fn error_paths() {
        use asn1::Error as A;
        let p = NegotiationToken::parse;
        assert_cases!(|input| p(input);
            empty: &[] => Err(Error::Asn1(A::Empty)),
            bare_sequence: &[0x30, 0x00] => Err(Error::NotToken),
            unknown_choice: &[0xa2, 0x02, 0x30, 0x00] => Err(Error::NotToken),
            primitive_choice: &[0x80, 0x00] => Err(Error::Asn1(A::Primitive)),
            empty_response: &[0xa1, 0x00] => Err(Error::Asn1(A::Empty)),
            truncated_response: &[0xa1, 0x03, 0x30, 0x00] => Err(Error::Asn1(A::Truncated)),
            trailing_token: &[0xa1, 0x02, 0x30, 0x00, 0x30, 0x00] => Err(Error::Asn1(A::Trailing)),
            trailing_sequence: &[0xa1, 0x04, 0x30, 0x00, 0x30, 0x00] => Err(Error::Asn1(A::Trailing)),
            // NegTokenInit without mechTypes.
            missing_mech_types: &[0xa0, 0x02, 0x30, 0x00] => Err(Error::MissingMechTypes),
            // Fields out of order or repeated. One of another class is an
            // extension, skipped.
            reordered_fields: &[
                0xa1, 0x0a, 0x30, 0x08, 0xa2, 0x02, 0x04, 0x00, 0xa0, 0x02, 0x04, 0x00,
            ] => Err(Error::Field),
            duplicate_fields: &[
                0xa1, 0x0a, 0x30, 0x08, 0xa2, 0x02, 0x04, 0x00, 0xa2, 0x02, 0x04, 0x00,
            ] => Err(Error::Field),
            unknown_field: &[0xa1, 0x04, 0x30, 0x02, 0x04, 0x00]
                => Ok(NegotiationToken::Resp(NegTokenResp::default())),
        );
        // A field holding the wrong type, or two values, or a primitive tag.
        assert!(matches!(
            p(&[0xa1, 0x06, 0x30, 0x04, 0xa2, 0x02, 0x02, 0x00]),
            Err(Error::Asn1(A::Unexpected { .. }))
        ));
        assert_cases!(|input| p(input);
            trailing_field_value: &[0xa1, 0x08, 0x30, 0x06, 0xa2, 0x04, 0x04, 0x00, 0x04, 0x00]
                => Err(Error::Asn1(A::Trailing)),
            primitive_field: &[0xa1, 0x04, 0x30, 0x02, 0x82, 0x00] => Err(Error::Asn1(A::Primitive)),
            primitive_response: &[0x81, 0x02, 0x30, 0x00] => Err(Error::Asn1(A::Primitive)),
            // A negState outside 0..=3.
            state_four: &[0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x04] => Err(Error::NegState(4)),
            negative_state: &[0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0xff]
                => Err(Error::NegState(-1)),
        );
        assert_eq!(NegState::from_value(9), Err(Error::NegState(9)));
        // A negState too large for an i64.
        let mut big = vec![0xa1, 0x10, 0x30, 0x0e, 0xa0, 0x0c, 0x0a, 0x0a, 0x01];
        big.extend_from_slice(&[0; 9]);
        assert_eq!(p(&big), Err(Error::Asn1(A::Integer)));
        // Hints with an unknown field.
        assert_eq!(
            p(&init_of(&[MECH_1_2, &[0xa3, 0x04, 0x30, 0x02, 0x85, 0x00]])),
            Err(Error::Asn1(A::Trailing))
        );
        // [3] holding neither an OCTET STRING nor a SEQUENCE.
        assert!(matches!(
            p(&init_of(&[MECH_1_2, &[0xa3, 0x03, 0x02, 0x01, 0x00]])),
            Err(Error::Asn1(A::Unexpected { .. }))
        ));
        // [3] empty.
        assert_eq!(
            p(&init_of(&[MECH_1_2, &[0xa3, 0x00]])),
            Err(Error::Asn1(A::Empty))
        );
        // Too many mechanisms, read and written.
        let mut list = Vec::new();
        for _ in 0..=MAX_MECHS {
            list.extend_from_slice(&[0x06, 0x01, 0x2a]);
        }
        let mut b = vec![
            0xa0, 0x82, 0, 0, 0x30, 0x82, 0, 0, 0xa0, 0x82, 0, 0, 0x30, 0x82, 0, 0,
        ];
        let n = list.len();
        b[14..16].copy_from_slice(&(n as u16).to_be_bytes());
        b[10..12].copy_from_slice(&(n as u16 + 4).to_be_bytes());
        b[6..8].copy_from_slice(&(n as u16 + 8).to_be_bytes());
        b[2..4].copy_from_slice(&(n as u16 + 12).to_be_bytes());
        b.extend_from_slice(&list);
        assert_eq!(p(&b), Err(Error::TooManyMechs));
        let too_many = NegTokenInit {
            mech_types: vec![Mech::Ntlm; MAX_MECHS + 1],
            ..NegTokenInit::default()
        };
        assert_eq!(
            NegotiationToken::Init(too_many).to_bytes(),
            Err(Error::TooManyMechs)
        );
        let most = NegTokenInit {
            mech_types: vec![Mech::Ntlm; MAX_MECHS],
            ..NegTokenInit::default()
        };
        let most = NegotiationToken::Init(most);
        assert_eq!(p(&most.to_bytes().unwrap()).unwrap(), most);
        // Too long, read and written.
        assert_eq!(p(&vec![0xa1; MAX_TOKEN + 1]), Err(Error::TooLong));
        assert_eq!(
            InitialContextToken::parse(&vec![0x60; MAX_TOKEN + 1]),
            Err(Error::TooLong)
        );
        let huge = NegTokenResp {
            response_token: Some(vec![0; MAX_TOKEN]),
            ..NegTokenResp::default()
        };
        assert_eq!(NegotiationToken::Resp(huge).to_bytes(), Err(Error::TooLong));
        let near = NegTokenResp {
            response_token: Some(vec![0; MAX_TOKEN - 20]),
            ..NegTokenResp::default()
        };
        let near = NegotiationToken::Resp(near);
        let bytes = near.to_bytes().unwrap();
        assert!(bytes.len() <= MAX_TOKEN);
        assert_eq!(p(&bytes).unwrap(), near);
        assert_eq!(
            initial_context_token(Mech::Spnego, bytes).to_bytes(),
            Err(Error::TooLong)
        );
        let near = NegTokenInit {
            mech_types: vec![Mech::Ntlm],
            mech_token: Some(vec![0; MAX_TOKEN - 40]),
            ..NegTokenInit::default()
        };
        let near = NegotiationToken::Init(near);
        assert_eq!(p(&near.to_bytes().unwrap()).unwrap(), near);
        assert_eq!(
            InitialContextToken::spnego(&near).and_then(|token| token.to_bytes()),
            Err(Error::TooLong)
        );
        let big = initial_context_token(Mech::Ntlm, vec![0; MAX_TOKEN]);
        assert_eq!(big.to_bytes(), Err(Error::TooLong));
        // Wrapper errors.
        let ic = InitialContextToken::parse;
        assert_cases!(|input| ic(input);
            wrong_application_tag: &[0x61, 0x00] => Err(Error::NotToken),
            primitive_application: &[0x40, 0x00] => Err(Error::NotToken),
            indefinite_length: &[0x60, 0x80, 0x06, 0x01, 0x2a, 0, 0] => Err(Error::Indefinite),
            truncated_oid: &[0x60, 0x03, 0x06, 0x01] => Err(Error::Asn1(A::Truncated)),
            trailing_context: &[0x60, 0x03, 0x06, 0x01, 0x2a, 0x00] => Err(Error::Asn1(A::Trailing)),
            empty_context: &[0x60, 0x00] => Err(Error::Asn1(A::Empty)),
            empty_oid: &[0x60, 0x02, 0x06, 0x00] => Err(Error::Asn1(A::Oid)),
            missing_length: &[0x60] => Err(Error::Asn1(A::Truncated)),
            invalid_length: &[0x60, 0xff] => Err(Error::Asn1(A::Length)),
        );
        // A wrapper for another mechanism.
        let k = initial_context_token(Mech::Kerberos, samba_init2()[10..].to_vec())
            .to_bytes()
            .unwrap();
        assert_eq!(p(&k), Err(Error::WrongMech));
        // A wrapper around nothing SPNEGO reads.
        let w = initial_context_token(Mech::Spnego, vec![0x30, 0x00])
            .to_bytes()
            .unwrap();
        assert_eq!(p(&w), Err(Error::NotToken));
        // A hint name the writer cannot write is impossible: GeneralString
        // bytes are not checked. Every error has a message.
        for e in [
            Error::Asn1(A::Empty),
            Error::TooLong,
            Error::TooManyMechs,
            Error::NotToken,
            Error::Indefinite,
            Error::WrongMech,
            Error::Field,
            Error::WrappedResp,
            Error::MissingMechTypes,
            Error::NegState(7),
            Error::HintAddress,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn token_len_errors() {
        assert_cases!(|input| token_len(input);
            empty_prefix: &[] => Ok(None),
            wrong_prefix: &[0x30] => Err(Error::NotToken),
            tag_only: &[0xa1] => Ok(None),
            indefinite_prefix: &[0xa1, 0x80] => Err(Error::Indefinite),
            invalid_prefix_length: &[0xa1, 0xff] => Err(Error::Asn1(asn1::Error::Length)),
            oversized_prefix: &[0xa1, 0x83, 0x01, 0x00, 0x00] => Err(Error::TooLong),
            partial_long_length: &[0xa1, 0x82, 0xff] => Ok(None),
            maximum_length: &[0xa1, 0x82, 0xff, 0xfc] => Ok(None),
            oversized_length: &[0xa1, 0x82, 0xff, 0xfd] => Err(Error::TooLong),
        );
    }

    #[test]
    fn truncated_prefixes() {
        let mut all = vec![samba_init2(), ACCEPT_COMPLETED.to_vec()];
        for t in sample_tokens() {
            all.push(t.to_bytes().unwrap());
            if let Ok(w) = InitialContextToken::spnego(&t).and_then(|token| token.to_bytes()) {
                all.push(w);
            }
        }
        for b in &all {
            for n in 0..b.len() {
                assert!(
                    NegotiationToken::parse(&b[..n]).is_err(),
                    "prefix {n} of {b:02x?}"
                );
                assert_eq!(token_len(&b[..n]), Ok(None));
                if b[0] == GSS_TAG {
                    assert!(InitialContextToken::parse(&b[..n]).is_err());
                }
            }
        }
    }

    #[test]
    fn decoder() {
        let a = samba_init2();
        let b = ACCEPT_COMPLETED.to_vec();
        let mut stream = a.clone();
        stream.extend_from_slice(&b);
        stream.extend_from_slice(&a);
        let mut d = Stream::new(Frames::<Frame>::new());
        for (i, byte) in chunks(&stream, &[1]).enumerate() {
            assert_eq!(d.push(byte), 1);
            match i + 1 {
                n if n == a.len() => assert_eq!(d.next(), Some(Ok(a.clone()))),
                n if n == a.len() + b.len() => assert_eq!(d.next(), Some(Ok(b.clone()))),
                n if n == stream.len() => assert_eq!(d.next(), Some(Ok(a.clone()))),
                _ => assert_eq!(d.next(), None),
            }
        }
        assert_eq!(d.buffered(), 0);
        assert_eq!(d.push(&[0x30, 0x00]), 2);
        assert_eq!(d.next(), Some(Err(Fail::Protocol(Error::NotToken))));
        assert_eq!(d.push(&b), b.len());
        assert_eq!(d.next(), None);
        assert_eq!(d.failed(), Some(&Fail::Protocol(Error::NotToken)));
    }

    #[test]
    fn decoder_holds_at_most_max_token() {
        // Pushed again and again without taking tokens out.
        let mut d = Stream::new(Frames::<Frame>::new());
        for _ in 0..rounds(40_000) {
            let _ = d.push(&ACCEPT_COMPLETED);
            assert!(d.buffered() <= MAX_TOKEN);
        }
        assert!(d.into_parts().0.allocated() <= 2 * MAX_TOKEN);
        // One push far longer than a token.
        let mut d = Stream::new(Frames::<Frame>::new());
        let _ = d.push(&vec![0xa1; 4 * MAX_TOKEN]);
        assert!(d.buffered() <= MAX_TOKEN);
        assert!(d.into_parts().0.allocated() <= 2 * MAX_TOKEN);
    }

    #[test]
    fn decoder_takes_what_fits() {
        let mut stream = Vec::new();
        while stream.len() < 3 * MAX_TOKEN {
            stream.extend_from_slice(&ACCEPT_COMPLETED);
        }
        let mut d = Stream::new(Frames::<Frame>::new());
        let mut rest = &stream[..];
        let mut got = 0;
        while !rest.is_empty() {
            let n = d.push(rest);
            assert!(d.buffered() <= MAX_TOKEN);
            rest = &rest[n..];
            while let Some(t) = d.next() {
                assert_eq!(t.unwrap(), ACCEPT_COMPLETED);
                got += 1;
            }
        }
        assert_eq!(got * ACCEPT_COMPLETED.len(), stream.len());
        assert!(d.buffered() <= MAX_TOKEN);
        // After an error every byte is taken and dropped.
        assert_eq!(d.push(&[0x30, 0x00]), 2);
        assert_eq!(d.next(), Some(Err(Fail::Protocol(Error::NotToken))));
        let held = d.buffered();
        assert_eq!(d.push(&stream), stream.len());
        assert_eq!(d.buffered(), held);
        assert_eq!(d.next(), None);
        assert!(d.into_parts().0.allocated() <= 2 * MAX_TOKEN);
    }

    #[test]
    fn context_flags_are_der() {
        // X.690 11.2.2: a named bit list drops its trailing zero bits.
        let write = |f: u32| {
            let t = NegotiationToken::Init(NegTokenInit {
                mech_types: vec![Mech::Ntlm],
                req_flags: Some(ContextFlags(f)),
                ..NegTokenInit::default()
            });
            let b = t.to_bytes().unwrap();
            assert_eq!(NegotiationToken::parse(&b).unwrap(), t);
            // Fields [0] (16 bytes) come before the flags.
            let start = 4 + 16;
            b[start + 2..].to_vec()
        };
        assert_eq!(write(ContextFlags::INTEG.0), [0x03, 0x02, 0x01, 0x02]);
        assert_eq!(write(0), [0x03, 0x01, 0x00]);
        assert_eq!(write(ContextFlags::DELEG.0), [0x03, 0x02, 0x07, 0x80]);
        assert_eq!(write(1), [0x03, 0x05, 0x00, 0, 0, 0, 1]);
        assert_eq!(write(0x0001_0000), [0x03, 0x03, 0x00, 0, 1]);
    }

    #[test]
    fn init2_mic_without_hints_stays_at_4() {
        // A NegTokenInit2 with mechTypes and a mechListMIC at [4], no [3].
        let b = [
            0xa0, 0x17, 0x30, 0x15, 0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
            0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa4, 0x03, 0x04, 0x01, 0xaa,
        ];
        let t = NegotiationToken::parse(&b).unwrap();
        let NegotiationToken::Init(i) = &t else {
            panic!()
        };
        assert_eq!(i.mech_list_mic, Some(vec![0xaa]));
        let out = t.to_bytes().unwrap();
        // Written back as a NegTokenInit2: the MIC is still at [4].
        assert_eq!(out[out.len() - 5..], [0xa4, 0x03, 0x04, 0x01, 0xaa]);
        assert_eq!(NegotiationToken::parse(&out).unwrap(), t);
    }

    #[test]
    fn init2_without_mech_types() {
        // [MS-SPNG] 2.2.1: mechTypes is optional in a NegTokenInit2.
        let b = [0xa0, 0x06, 0x30, 0x04, 0xa3, 0x02, 0x30, 0x00];
        let t = NegotiationToken::parse(&b).unwrap();
        let NegotiationToken::Init(i) = &t else {
            panic!()
        };
        assert!(i.mech_types.is_empty());
        assert_eq!(i.neg_hints, Some(NegHints::default()));
        assert_eq!(t.to_bytes().unwrap(), b);
        // With a mechListMIC at [4] and nothing else.
        let b = [0xa0, 0x07, 0x30, 0x05, 0xa4, 0x03, 0x04, 0x01, 0xaa];
        let t = NegotiationToken::parse(&b).unwrap();
        assert_eq!(NegotiationToken::parse(&t.to_bytes().unwrap()).unwrap(), t);
        // An empty list in a NegTokenInit2 is written as no list.
        let b = [
            0xa0, 0x0a, 0x30, 0x08, 0xa0, 0x02, 0x30, 0x00, 0xa3, 0x02, 0x30, 0x00,
        ];
        let t = NegotiationToken::parse(&b).unwrap();
        assert_eq!(
            t.to_bytes().unwrap(),
            [0xa0, 0x06, 0x30, 0x04, 0xa3, 0x02, 0x30, 0x00]
        );
    }

    #[test]
    fn rfc_init_needs_a_mechanism() {
        // RFC 4178 4.2.1: a NegTokenInit offers one or more mechanisms.
        let b = [0xa0, 0x06, 0x30, 0x04, 0xa0, 0x02, 0x30, 0x00];
        assert_eq!(NegotiationToken::parse(&b), Err(Error::MissingMechTypes));
        let b = [
            0xa0, 0x0b, 0x30, 0x09, 0xa0, 0x02, 0x30, 0x00, 0xa3, 0x03, 0x04, 0x01, 0xaa,
        ];
        assert_eq!(NegotiationToken::parse(&b), Err(Error::MissingMechTypes));
        assert_eq!(
            NegotiationToken::Init(NegTokenInit::default()).to_bytes(),
            Err(Error::MissingMechTypes)
        );
        let t = NegTokenInit {
            mech_list_mic: Some(vec![1]),
            ..NegTokenInit::default()
        };
        assert_eq!(
            InitialContextToken::spnego(&NegotiationToken::Init(t))
                .and_then(|token| token.to_bytes()),
            Err(Error::MissingMechTypes)
        );
    }

    #[test]
    fn unknown_extensions_of_any_class_are_skipped() {
        // accept-completed, then a NULL added after the extension marker.
        let b = [
            0xa1, 0x09, 0x30, 0x07, 0xa0, 0x03, 0x0a, 0x01, 0x00, 0x05, 0x00,
        ];
        assert_eq!(
            NegotiationToken::parse(&b).unwrap(),
            NegotiationToken::parse(&ACCEPT_COMPLETED).unwrap()
        );
        // An application-class and a private-class addition, in a
        // NegTokenInit.
        let b = [
            0xa0, 0x0d, 0x30, 0x0b, 0xa0, 0x05, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x41, 0x00, 0xc2,
            0x00,
        ];
        let NegotiationToken::Init(i) = NegotiationToken::parse(&b).unwrap() else {
            panic!()
        };
        assert_eq!(i.mech_types, [Mech::from_contents(&[0x2a]).unwrap()]);
        // A known field after an unknown one is out of order.
        let b = [
            0xa1, 0x09, 0x30, 0x07, 0x05, 0x00, 0xa0, 0x03, 0x0a, 0x01, 0x00,
        ];
        assert_eq!(NegotiationToken::parse(&b), Err(Error::Field));
    }

    #[test]
    fn hint_address_is_never_written() {
        // [MS-SPNG] 2.2.1: hintAddress MUST be omitted by the sender.
        for addr in [Vec::new(), vec![1, 2]] {
            let t = NegotiationToken::Init(NegTokenInit {
                mech_types: vec![Mech::Ntlm],
                neg_hints: Some(neg_hints_fixture(Some(HINT.to_vec()), Some(addr))),
                ..NegTokenInit::default()
            });
            assert_eq!(t.to_bytes(), Err(Error::HintAddress));
            assert_eq!(
                InitialContextToken::spnego(&t).and_then(|token| token.to_bytes()),
                Err(Error::HintAddress)
            );
        }
        // The Wire domain excludes received hint addresses too.
        let b = [
            0xa0, 0x0e, 0x30, 0x0c, 0xa0, 0x02, 0x30, 0x00, 0xa3, 0x06, 0x30, 0x04, 0xa1, 0x02,
            0x04, 0x00,
        ];
        assert_eq!(NegotiationToken::parse(&b), Err(Error::HintAddress));
        contract::check_decode_with_alloc_limit(Frames::<Frame>::new, &b, 2 * MAX_TOKEN);
    }

    #[test]
    fn other_holding_a_named_oid_equals_the_named_mech() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let hash = |m: &Mech| {
            let mut h = DefaultHasher::new();
            m.hash(&mut h);
            h.finish()
        };
        for (named, _, dotted) in NAMED.iter() {
            let other = Mech::Other(dotted.parse().unwrap());
            assert_eq!(&other, named);
            assert_eq!(hash(&other), hash(named));
            assert_eq!(other.to_string(), named.to_string());
            let t = NegotiationToken::Resp(NegTokenResp {
                supported_mech: Some(other),
                ..NegTokenResp::default()
            });
            assert_eq!(NegotiationToken::parse(&t.to_bytes().unwrap()).unwrap(), t);
        }
        assert_ne!(Mech::Ntlm, Mech::NegoEx);
        assert_ne!(Mech::Other("1.2.3".parse().unwrap()), Mech::Kerberos);
    }

    fn make_mech(rng: &mut Lcg) -> Mech {
        match rng.index(NAMED.len() + 1) {
            i if i < NAMED.len() => NAMED[i].0.clone(),
            // A named identifier held in `Other`, which equals the
            // named variant it is read back as.
            _ if rng.next().is_multiple_of(4) => {
                Mech::Other(NAMED[rng.index(NAMED.len())].2.parse().unwrap())
            }
            _ => Mech::Other(
                Oid::from_arcs(&[2, u128::from(rng.next()), u128::from(rng.next())]).unwrap(),
            ),
        }
    }

    fn make_token(rng: &mut Lcg) -> NegotiationToken {
        if !rng.coin() {
            // A NegTokenInit offers a mechanism; a NegTokenInit2 need not.
            let neg_hints = if !rng.coin() {
                None
            } else {
                Some(neg_hints_fixture(rng.coin().then(|| rng.bytes(20)), None))
            };
            let least = usize::from(neg_hints.is_none());
            NegotiationToken::Init(NegTokenInit {
                mech_types: (0..least + rng.index(5)).map(|_| make_mech(rng)).collect(),
                req_flags: if !rng.coin() {
                    None
                } else {
                    Some(ContextFlags(rng.next() as u32))
                },
                mech_token: rng.coin().then(|| rng.bytes(40)),
                neg_hints,
                mech_list_mic: rng.coin().then(|| rng.bytes(20)),
            })
        } else {
            NegotiationToken::Resp(NegTokenResp {
                neg_state: match rng.index(5) {
                    4 => None,
                    v => Some(NegState::from_value(v as i64).unwrap()),
                },
                supported_mech: if !rng.coin() {
                    None
                } else {
                    Some(make_mech(rng))
                },
                response_token: rng.coin().then(|| rng.bytes(40)),
                mech_list_mic: rng.coin().then(|| rng.bytes(20)),
            })
        }
    }

    /// Whatever a parse gives, writing it and reading it back gives the
    /// same value.
    fn check(b: &[u8]) {
        contract::check_wire::<NegotiationToken>(b);
        contract::check_wire::<InitialContextToken>(b);
        if let Ok(Some(n)) = token_len(b) {
            assert!(n <= b.len());
        }
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg::new(0x0005_eed5_ae90);
        for _ in 0..4000 {
            // A value written and read back.
            let t = make_token(&mut rng);
            let wrap = matches!(t, NegotiationToken::Init(_)) && !rng.coin();
            let bytes = if wrap {
                InitialContextToken::spnego(&t).and_then(|token| token.to_bytes())
            } else {
                t.to_bytes()
            }
            .unwrap();
            assert_eq!(NegotiationToken::parse(&bytes).as_ref(), Ok(&t));
            assert_eq!(token_len(&bytes), Ok(Some(bytes.len())));

            // The same bytes, damaged.
            let mut m = bytes.clone();
            for _ in 0..1 + rng.index(3) {
                mutate(&mut rng, &mut m);
            }
            check(&m);

            // Random bytes, often after a plausible first byte.
            let mut r = rng.bytes(64);
            if let Some(first) = r.first_mut() {
                *first = [GSS_TAG, INIT_TAG, RESP_TAG, *first][rng.index(4)];
            }
            check(&r);

            // A stream of tokens, with chunking checked by the contract.
            let mut stream = Vec::new();
            for _ in 0..rng.index(4) {
                stream.extend_from_slice(&make_token(&mut rng).to_bytes().unwrap());
            }
            if !rng.coin() {
                stream.extend_from_slice(&m);
            }
            contract::check_decode_with_alloc_limit(Frames::<Frame>::new, &stream, 2 * MAX_TOKEN);
            for token in decode_all(Frames::<Frame>::new, &stream).0 {
                check(&token);
            }
        }
    }

    #[test]
    fn codec_frames_bound_headers_and_report_once() {
        use fictionet::stdlib::codec::{Fail, Stream};
        use fictionet::stdlib::test_support::contract;
        assert_eq!(Frames::<Frame>::new().capacity(), MAX_TOKEN);
        let mut stream = Stream::new(Frames::<Frame>::new());
        let bytes = [GSS_TAG, 0x83, 1, 0, 0];
        contract::check_decode_with_alloc_limit(Frames::<Frame>::new, &bytes, 2 * MAX_TOKEN);
        assert_eq!(stream.push(&bytes), bytes.len());
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::TooLong))));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.buffered(), bytes.len());
    }

    #[test]
    fn codec_wire_domain_excludes_hint_addresses() {
        use fictionet::stdlib::codec::Wire;
        use fictionet::stdlib::test_support::contract;
        // A received hint address is outside the Wire domain.
        let bytes = [0xa0, 10, 0x30, 8, 0xa3, 6, 0x30, 4, 0xa1, 2, 4, 0];
        let token = NegotiationToken::Init(NegTokenInit {
            neg_hints: Some(neg_hints_fixture(None, Some(Vec::new()))),
            ..Default::default()
        });
        assert_eq!(token.to_bytes(), Err(Error::HintAddress));
        assert_eq!(
            <NegotiationToken as Wire>::parse(&bytes),
            Err(Error::HintAddress)
        );
        contract::check_wire::<NegotiationToken>(&bytes);
        contract::check_wire_value(&token);
        let mut out = vec![42];
        assert_eq!(token.write(&mut out), Err(Error::HintAddress));
        assert_eq!(out, [42]);
        let good = NegotiationToken::Resp(NegTokenResp::default());
        contract::check_wire_value(&good);
        let wrapper = initial_context_token(Mech::Kerberos, vec![1, 0, 5, 0]);
        contract::check_wire_value(&wrapper);
        let mut bytes = wrapper.to_bytes().unwrap();
        bytes.push(0);
        assert!(<InitialContextToken as Wire>::parse(&bytes).is_err());
    }
}
