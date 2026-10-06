//! Kerberos V5: reading and writing the messages a client, a KDC and a
//! service trade, with no I/O and no cryptography.
//!
//! Kerberos is how Active Directory and most Unix sites log users in. A
//! client asks the key distribution center (KDC) for a ticket-granting
//! ticket with an AS-REQ and gets an AS-REP. It trades that ticket for a
//! service ticket with a TGS-REQ and gets a TGS-REP. It shows the service
//! ticket to a server in an AP-REQ, and may get an AP-REP back. Anything
//! that goes wrong is a KRB-ERROR. Each message is ASN.1, written in DER.
//! KDCs listen on port 88, over UDP (one message per datagram) and TCP
//! (each message after a 4-byte length). This module follows RFC 4120,
//! sections 5 and 7.2.
//!
//! Nothing here reads a socket or touches a key. A world that plays a KDC
//! pushes the bytes it reads from a [`tcp`](crate::stdlib::tcp) connection
//! to a [`Stream<Frames>`](super::codec::Stream), or takes a UDP datagram as it is, and reads each
//! message with [`Message::parse`]. It writes the reply with
//! [`Wire::write`], with a [`Frame`] around its DER for TCP. The parts
//! that are encrypted (the ticket's secrets, the reply's session key, the
//! authenticator) stay [`EncryptedData`]: an encryption type, a key
//! version and opaque bytes. Which principals exist, which keys they have,
//! and how the world encrypts is up to world code.
//!
//! Every reader checks tags, lengths, integer ranges and list sizes,
//! because the agent can send any bytes it likes. A message is at most
//! [`MAX_MESSAGE`] bytes, and each list in it has its own limit, such as
//! [`MAX_PADATA`]. Writers check the same limits, so whatever they write,
//! [`Message::parse`] reads back.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire, pump, finish};
//! use fictionet::stdlib::kerberos::{
//!     error_code, msg_type, name_type, padata_type, Frame, Frames, KdcReq, KdcReqBody, KerberosTime, KrbError, Message,
//!     MethodData, PaData, PrincipalName,
//! };
//!
//! // A client asks for a ticket-granting ticket for alice, without
//! // pre-authentication.
//! let request = Message::AsReq(KdcReq {
//!     padata: None,
//!     body: KdcReqBody {
//!         kdc_options: 0x4000_0000, // forwardable
//!         cname: Some(PrincipalName::new(name_type::PRINCIPAL, &["alice"])),
//!         realm: "EXAMPLE.COM".to_string(),
//!         sname: Some(PrincipalName::new(name_type::SRV_INST, &["krbtgt", "EXAMPLE.COM"])),
//!         from: None,
//!         till: KerberosTime::new("20370913024805Z").unwrap(),
//!         rtime: None,
//!         nonce: 0x1234_5678,
//!         etypes: vec![18, 17],
//!         addresses: None,
//!         enc_authorization_data: None,
//!         additional_tickets: None,
//!     },
//! });
//! let wire = Frame(request.to_bytes().unwrap()).to_bytes().unwrap();
//!
//! // The KDC reads it from its TCP connection, a few bytes at a time.
//! let mut decoder = Stream::new(Frames::new());
//! let mut got = Vec::new();
//! for chunk in wire.chunks(5) {
//!     pump(&mut decoder, chunk, |m| got.push(m)).unwrap();
//! }
//! finish(&mut decoder, |m| got.push(m)).unwrap();
//! assert_eq!(got.len(), 1);
//! let Message::AsReq(req) = Message::parse(&got[0]).unwrap() else { panic!("not an AS-REQ") };
//! assert_eq!(req.body.cname.as_ref().unwrap().to_string(), "alice");
//!
//! // It asks for pre-authentication, as Active Directory does.
//! let reply = Message::KrbError(KrbError {
//!     ctime: None,
//!     cusec: None,
//!     stime: KerberosTime::new("20261005120000Z").unwrap(),
//!     susec: 0,
//!     error_code: error_code::KDC_ERR_PREAUTH_REQUIRED,
//!     crealm: None,
//!     cname: req.body.cname.clone(),
//!     realm: req.body.realm.clone(),
//!     sname: req.body.sname.clone().unwrap(),
//!     e_text: None,
//!     e_data: Some(
//!         // METHOD-DATA: the pre-authentication types the KDC accepts.
//!         MethodData(vec![PaData { padata_type: padata_type::ENC_TIMESTAMP, value: Vec::new() }]).to_bytes()
//!             .unwrap(),
//!     ),
//! });
//! let der = reply.to_bytes().unwrap();
//! assert_eq!(der[0], 0x7e); // [APPLICATION 30]
//! assert_eq!(Message::parse(&der).unwrap(), reply);
//! assert_eq!(reply.msg_type(), msg_type::KRB_ERROR);
//! ```

use super::asn1::{self, Reader, Rules, StringKind, Tag, Writer};
use super::codec::{Decode, Step, Wire};
use std::fmt;

/// The port KDCs listen on, over UDP and TCP.
pub const PORT: u16 = 88;
/// The protocol version every message carries (pvno and tkt-vno).
pub const PVNO: i64 = 5;
/// The longest message, in bytes, this module reads or writes. Tickets
/// that carry a Windows PAC run to tens of kilobytes, so this leaves room.
pub const MAX_MESSAGE: usize = 256 * 1024;
/// The length of the TCP length prefix.
pub const TCP_HEADER_LEN: usize = 4;
/// The most components a principal name may have.
pub const MAX_NAME_COMPONENTS: usize = 32;
/// The most PA-DATA entries in one message.
pub const MAX_PADATA: usize = 64;
/// The most encryption types a request may list.
pub const MAX_ETYPES: usize = 64;
/// The most host addresses a request may list.
pub const MAX_ADDRESSES: usize = 64;
/// The most additional tickets a request may carry.
pub const MAX_TICKETS: usize = 16;
/// The largest value of a Microseconds field.
pub const MAX_MICROSECONDS: u32 = 999_999;

/// The msg-type of each message this module reads (RFC 4120 section 7.5.7).
/// It is also the message's APPLICATION tag number.
pub mod msg_type {
    /// KRB_AS_REQ (10): the client requests initial authentication.
    pub const AS_REQ: i64 = 10;
    /// KRB_AS_REP (11): the authentication service answers an initial request.
    pub const AS_REP: i64 = 11;
    /// KRB_TGS_REQ (12): the client requests a ticket using a ticket-granting ticket.
    pub const TGS_REQ: i64 = 12;
    /// KRB_TGS_REP (13): the ticket-granting service answers a ticket request.
    pub const TGS_REP: i64 = 13;
    /// KRB_AP_REQ (14): the client presents a ticket and authenticator to a service.
    pub const AP_REQ: i64 = 14;
    /// KRB_AP_REP (15): the service answers a request for mutual authentication.
    pub const AP_REP: i64 = 15;
    /// KRB_ERROR (30): a response reports an error.
    pub const KRB_ERROR: i64 = 30;
}

/// The APPLICATION tag number of a Ticket.
pub const TICKET_TAG: u32 = 1;

/// Principal name types (RFC 4120 section 6.2).
pub mod name_type {
    /// KRB_NT_UNKNOWN (0): the principal's name type is not specified.
    pub const UNKNOWN: i32 = 0;
    /// KRB_NT_PRINCIPAL (1): a principal name, such as a user's name.
    pub const PRINCIPAL: i32 = 1;
    /// KRB_NT_SRV_INST (2): a service name followed by a unique instance.
    pub const SRV_INST: i32 = 2;
    /// KRB_NT_SRV_HST (3): a service name followed by a host name.
    pub const SRV_HST: i32 = 3;
    /// KRB_NT_SRV_XHST (4): a service name with the host in the remaining components.
    pub const SRV_XHST: i32 = 4;
    /// KRB_NT_UID (5): a unique identifier names the principal.
    pub const UID: i32 = 5;
    /// KRB_NT_X500_PRINCIPAL (6): an encoded X.509 distinguished name.
    pub const X500_PRINCIPAL: i32 = 6;
    /// KRB_NT_SMTP_NAME (7): a principal name in SMTP email address form.
    pub const SMTP_NAME: i32 = 7;
    /// KRB_NT_ENTERPRISE (10): an enterprise name that may map to a principal name.
    pub const ENTERPRISE: i32 = 10;
}

/// Pre-authentication data types (RFC 4120 section 7.5.2).
pub mod padata_type {
    /// PA-TGS-REQ (1): carries the AP-REQ that authenticates a ticket request.
    pub const TGS_REQ: i32 = 1;
    /// PA-ENC-TIMESTAMP (2): an encrypted timestamp proves knowledge of the client's key.
    pub const ENC_TIMESTAMP: i32 = 2;
    /// PA-PW-SALT (3): the salt used to derive the client's key from a password.
    pub const PW_SALT: i32 = 3;
    /// PA-ETYPE-INFO (11): encryption types and salts offered for pre-authentication.
    pub const ETYPE_INFO: i32 = 11;
    /// PA-ETYPE-INFO2 (19): encryption types, salts, and key derivation parameters.
    pub const ETYPE_INFO2: i32 = 19;
}

/// KDC option flags for [`KdcReqBody::kdc_options`]. Bit 0 of the BIT
/// STRING is the most significant bit of the `u32` (RFC 4120 section 5.4.1).
pub mod kdc_options {
    /// FORWARDABLE (bit 1): requests a ticket that permits forwarding credentials.
    pub const FORWARDABLE: u32 = 1 << 30;
    /// FORWARDED (bit 2): requests a ticket-granting ticket for a new network address.
    pub const FORWARDED: u32 = 1 << 29;
    /// PROXIABLE (bit 3): requests a ticket that permits proxy tickets.
    pub const PROXIABLE: u32 = 1 << 28;
    /// PROXY (bit 4): requests a proxy ticket for another network address.
    pub const PROXY: u32 = 1 << 27;
    /// ALLOW-POSTDATE (bit 5): requests permission to issue postdated tickets.
    pub const ALLOW_POSTDATE: u32 = 1 << 26;
    /// POSTDATED (bit 6): requests a ticket with a future start time.
    pub const POSTDATED: u32 = 1 << 25;
    /// RENEWABLE (bit 8): requests a ticket that can be renewed.
    pub const RENEWABLE: u32 = 1 << 23;
    /// OPT-HARDWARE-AUTH (bit 11): reserved for requesting hardware authentication.
    pub const OPT_HARDWARE_AUTH: u32 = 1 << 20;
    /// DISABLE-TRANSITED-CHECK (bit 26): asks the KDC to skip transited-realm checks.
    pub const DISABLE_TRANSITED_CHECK: u32 = 1 << 5;
    /// RENEWABLE-OK (bit 27): accepts a renewable ticket if the requested lifetime is too long.
    pub const RENEWABLE_OK: u32 = 1 << 4;
    /// ENC-TKT-IN-SKEY (bit 28): encrypts the ticket with the additional ticket's session key.
    pub const ENC_TKT_IN_SKEY: u32 = 1 << 3;
    /// RENEW (bit 30): requests renewal of the supplied renewable ticket.
    pub const RENEW: u32 = 1 << 1;
    /// VALIDATE (bit 31): requests validation of a postdated ticket.
    pub const VALIDATE: u32 = 1;
}

/// AP option flags for [`ApReq::ap_options`]. Bit 0 of the BIT STRING is
/// the most significant bit of the `u32`.
pub mod ap_options {
    /// USE-SESSION-KEY (bit 1): the ticket uses the recipient's session key.
    pub const USE_SESSION_KEY: u32 = 1 << 30;
    /// MUTUAL-REQUIRED (bit 2): requests an AP-REP to authenticate the service.
    pub const MUTUAL_REQUIRED: u32 = 1 << 29;
}

/// Error codes for [`KrbError::error_code`] (RFC 4120 section 7.5.9).
pub mod error_code {
    /// KDC_ERR_NONE (0): the KDC reports no error.
    pub const KDC_ERR_NONE: i32 = 0;
    /// KDC_ERR_NAME_EXP (1): the client's database entry has expired.
    pub const KDC_ERR_NAME_EXP: i32 = 1;
    /// KDC_ERR_SERVICE_EXP (2): the service's database entry has expired.
    pub const KDC_ERR_SERVICE_EXP: i32 = 2;
    /// KDC_ERR_BAD_PVNO (3): the KDC does not support the requested protocol version.
    pub const KDC_ERR_BAD_PVNO: i32 = 3;
    /// KDC_ERR_C_PRINCIPAL_UNKNOWN (6): the client is not in the database.
    pub const KDC_ERR_C_PRINCIPAL_UNKNOWN: i32 = 6;
    /// KDC_ERR_S_PRINCIPAL_UNKNOWN (7): the service is not in the database.
    pub const KDC_ERR_S_PRINCIPAL_UNKNOWN: i32 = 7;
    /// KDC_ERR_PRINCIPAL_NOT_UNIQUE (8): the database has multiple entries for the principal.
    pub const KDC_ERR_PRINCIPAL_NOT_UNIQUE: i32 = 8;
    /// KDC_ERR_NULL_KEY (9): the client or service has a null key.
    pub const KDC_ERR_NULL_KEY: i32 = 9;
    /// KDC_ERR_CANNOT_POSTDATE (10): this ticket does not permit postdating.
    pub const KDC_ERR_CANNOT_POSTDATE: i32 = 10;
    /// KDC_ERR_NEVER_VALID (11): the requested start time is after the end time.
    pub const KDC_ERR_NEVER_VALID: i32 = 11;
    /// KDC_ERR_POLICY (12): KDC policy refuses the request.
    pub const KDC_ERR_POLICY: i32 = 12;
    /// KDC_ERR_BADOPTION (13): the KDC cannot satisfy a requested option.
    pub const KDC_ERR_BADOPTION: i32 = 13;
    /// KDC_ERR_ETYPE_NOSUPP (14): the KDC does not support the encryption type.
    pub const KDC_ERR_ETYPE_NOSUPP: i32 = 14;
    /// KDC_ERR_SUMTYPE_NOSUPP (15): the KDC does not support the checksum type.
    pub const KDC_ERR_SUMTYPE_NOSUPP: i32 = 15;
    /// KDC_ERR_PADATA_TYPE_NOSUPP (16): the KDC does not support the pre-authentication type.
    pub const KDC_ERR_PADATA_TYPE_NOSUPP: i32 = 16;
    /// KDC_ERR_CLIENT_REVOKED (18): the client's credentials were revoked.
    pub const KDC_ERR_CLIENT_REVOKED: i32 = 18;
    /// KDC_ERR_SERVICE_REVOKED (19): the service's credentials were revoked.
    pub const KDC_ERR_SERVICE_REVOKED: i32 = 19;
    /// KDC_ERR_TGT_REVOKED (20): the ticket-granting ticket was revoked.
    pub const KDC_ERR_TGT_REVOKED: i32 = 20;
    /// KDC_ERR_CLIENT_NOTYET (21): the client's credentials are not yet valid.
    pub const KDC_ERR_CLIENT_NOTYET: i32 = 21;
    /// KDC_ERR_SERVICE_NOTYET (22): the service's credentials are not yet valid.
    pub const KDC_ERR_SERVICE_NOTYET: i32 = 22;
    /// KDC_ERR_KEY_EXPIRED (23): the password has expired and must be changed.
    pub const KDC_ERR_KEY_EXPIRED: i32 = 23;
    /// KDC_ERR_PREAUTH_FAILED (24): the pre-authentication data is invalid.
    pub const KDC_ERR_PREAUTH_FAILED: i32 = 24;
    /// KDC_ERR_PREAUTH_REQUIRED (25): the KDC needs more pre-authentication data.
    pub const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
    /// KDC_ERR_SERVER_NOMATCH (26): the requested service does not match the ticket.
    pub const KDC_ERR_SERVER_NOMATCH: i32 = 26;
    /// KDC_ERR_MUST_USE_USER2USER (27): the service requires user-to-user authentication.
    pub const KDC_ERR_MUST_USE_USER2USER: i32 = 27;
    /// KDC_ERR_SVC_UNAVAILABLE (29): the requested service is unavailable.
    pub const KDC_ERR_SVC_UNAVAILABLE: i32 = 29;
    /// KRB_AP_ERR_BAD_INTEGRITY (31): decrypted data failed its integrity check.
    pub const KRB_AP_ERR_BAD_INTEGRITY: i32 = 31;
    /// KRB_AP_ERR_TKT_EXPIRED (32): the ticket's validity period has ended.
    pub const KRB_AP_ERR_TKT_EXPIRED: i32 = 32;
    /// KRB_AP_ERR_TKT_NYV (33): the ticket's validity period has not begun.
    pub const KRB_AP_ERR_TKT_NYV: i32 = 33;
    /// KRB_AP_ERR_REPEAT (34): the authenticator repeats an earlier request.
    pub const KRB_AP_ERR_REPEAT: i32 = 34;
    /// KRB_AP_ERR_NOT_US (35): the ticket names a different service.
    pub const KRB_AP_ERR_NOT_US: i32 = 35;
    /// KRB_AP_ERR_BADMATCH (36): the ticket and authenticator name different clients.
    pub const KRB_AP_ERR_BADMATCH: i32 = 36;
    /// KRB_AP_ERR_SKEW (37): the difference between clocks exceeds the allowed limit.
    pub const KRB_AP_ERR_SKEW: i32 = 37;
    /// KRB_AP_ERR_BADADDR (38): the sender's address does not match the ticket.
    pub const KRB_AP_ERR_BADADDR: i32 = 38;
    /// KRB_AP_ERR_BADVERSION (39): the protocol version is unsupported.
    pub const KRB_AP_ERR_BADVERSION: i32 = 39;
    /// KRB_AP_ERR_MSG_TYPE (40): the message has an unexpected type.
    pub const KRB_AP_ERR_MSG_TYPE: i32 = 40;
    /// KRB_AP_ERR_MODIFIED (41): the message stream was modified.
    pub const KRB_AP_ERR_MODIFIED: i32 = 41;
    /// KRB_AP_ERR_BADKEYVER (44): the requested key version is unavailable.
    pub const KRB_AP_ERR_BADKEYVER: i32 = 44;
    /// KRB_AP_ERR_NOKEY (45): no service key is available.
    pub const KRB_AP_ERR_NOKEY: i32 = 45;
    /// KRB_AP_ERR_METHOD (48): an alternative authentication method is required.
    pub const KRB_AP_ERR_METHOD: i32 = 48;
    /// KRB_ERR_RESPONSE_TOO_BIG (52): the reply needs TCP because it is too large for UDP.
    pub const KRB_ERR_RESPONSE_TOO_BIG: i32 = 52;
    /// KRB_ERR_GENERIC (60): a generic error is described in the e-text field.
    pub const KRB_ERR_GENERIC: i32 = 60;
    /// KRB_ERR_FIELD_TOOLONG (61): a field exceeds the implementation's length limit.
    pub const KRB_ERR_FIELD_TOOLONG: i32 = 61;
}

/// Why bytes are not a Kerberos message, or why a value cannot be
/// written as one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Encoding would change the value when parsed.
    Unwritable,
    /// The ASN.1 is malformed, or not the structure RFC 4120 gives.
    Asn1(asn1::Error),
    /// The outer tag is not one of the messages this module reads. It
    /// holds the tag number of an APPLICATION tag, or `u32::MAX` for any
    /// other class.
    UnknownMessage(u32),
    /// A pvno or tkt-vno is not 5.
    Version(i64),
    /// A msg-type does not match the message's APPLICATION tag.
    MessageType {
        /// The type the tag calls for.
        expected: i64,
        /// The type the message says.
        found: i64,
    },
    /// An integer is outside its type's range: Int32, UInt32 or
    /// Microseconds.
    Range,
    /// A list is longer than its limit. It holds the field's name.
    TooMany(&'static str),
    /// A writer was given an empty optional list: padata in a request or
    /// reply, addresses, or additional-tickets. RFC 4120 section 5.1.3
    /// says senders should not send one. It holds the field's name. Leave
    /// the field out (`None`) instead. Readers take an empty one as
    /// absent.
    Empty(&'static str),
    /// A KerberosString is not UTF-8, or a realm holds a NUL, which RFC
    /// 4120 section 5.2.2 forbids.
    Text,
    /// A KerberosTime is not `YYYYMMDDhhmmssZ`.
    Time,
    /// A message is longer than [`MAX_MESSAGE`].
    TooLong,
    /// A HostAddress of a type RFC 4120 section 7.1 defines does not have
    /// that type's form: an IPv4 address (type 2) is not 4 bytes, or an
    /// IPv6 address (type 24) is not 16 bytes or is one the section
    /// forbids (unspecified, loopback, link-local, or IPv4-mapped, which
    /// must be type 2). Other types hold any bytes.
    Address,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::Asn1(e) => write!(f, "ASN.1: {e}"),
            Error::UnknownMessage(n) => write!(f, "not a Kerberos message (tag {n})"),
            Error::Version(v) => write!(f, "protocol version {v}, not 5"),
            Error::MessageType { expected, found } => {
                write!(f, "msg-type {found}, expected {expected}")
            }
            Error::Range => f.write_str("integer out of range"),
            Error::TooMany(what) => write!(f, "too many entries in {what}"),
            Error::Empty(what) => write!(f, "{what} is present but empty"),
            Error::Text => f.write_str("KerberosString not UTF-8, or a realm with a NUL"),
            Error::Time => f.write_str("KerberosTime not YYYYMMDDhhmmssZ"),
            Error::TooLong => write!(f, "message longer than {MAX_MESSAGE} bytes"),
            Error::Address => f.write_str("host address not of its type's form"),
        }
    }
}

impl std::error::Error for Error {}

impl From<asn1::Error> for Error {
    fn from(e: asn1::Error) -> Error {
        Error::Asn1(e)
    }
}

/// A KerberosTime: a GeneralizedTime in UTC with no fraction, such as
/// `20261005120000Z`. It is always well formed. Since every time has the
/// same fixed-width form, times compare in time order.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KerberosTime(String);

impl KerberosTime {
    /// The time `text` names, which must be `YYYYMMDDhhmmssZ` and a real
    /// date and time.
    pub fn new(text: &str) -> Result<KerberosTime, Error> {
        let b = text.as_bytes();
        if b.len() != 15 || asn1::check_generalized_time(b, Rules::Der).is_err() {
            return Err(Error::Time);
        }
        Ok(KerberosTime(text.to_string()))
    }

    /// The time from its parts. The year is 0 to 9999.
    pub fn from_parts(
        year: u32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    ) -> Result<KerberosTime, Error> {
        if year > 9999 {
            return Err(Error::Time);
        }
        KerberosTime::new(&format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z"))
    }

    /// The text, such as `20261005120000Z`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KerberosTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A PrincipalName: a type and the name's components, such as `krbtgt`
/// and `EXAMPLE.COM` for a realm's ticket-granting service.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrincipalName {
    /// One of [`name_type`].
    pub name_type: i32,
    /// The components, at most [`MAX_NAME_COMPONENTS`].
    pub components: Vec<String>,
}

impl PrincipalName {
    /// A name of type `name_type` with these components.
    pub fn new(name_type: i32, components: &[&str]) -> PrincipalName {
        PrincipalName { name_type, components: components.iter().map(|s| s.to_string()).collect() }
    }

    fn check(&self) -> Result<(), Error> {
        limit(self.components.len(), MAX_NAME_COMPONENTS, "name-string")
    }

    fn read(r: &mut Reader<'_>) -> Result<PrincipalName, Error> {
        let mut s = r.read_sequence()?;
        let name_type = field(&mut s, 0, int32)?;
        let components = field(&mut s, 1, |r| seq_of(r, MAX_NAME_COMPONENTS, "name-string", kstring))?;
        s.finish()?;
        Ok(PrincipalName { name_type, components })
    }

    fn write_fields(&self, w: &mut Writer) {
        w.sequence(|w| {
            w_int(w, 0, self.name_type.into());
            w.explicit(1, |w| {
                w.sequence(|w| {
                    for c in &self.components {
                        w.string_bytes(StringKind::General, c.as_bytes());
                    }
                })
            });
        });
    }
}

/// The components joined with `/`, as `krbtgt/EXAMPLE.COM`. The type and
/// realm are not shown.
impl fmt::Display for PrincipalName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, c) in self.components.iter().enumerate() {
            if i > 0 {
                f.write_str("/")?;
            }
            f.write_str(c)?;
        }
        Ok(())
    }
}

/// A HostAddress: an address type (2 for IPv4, 24 for IPv6, 20 for a
/// NetBIOS name) and its bytes. Readers and writers check IPv4 and IPv6
/// addresses as RFC 4120 section 7.1 gives them (see [`Error::Address`]),
/// and take the bytes of any other type as they are.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostAddress {
    /// The address type.
    pub addr_type: i32,
    /// The address, as bytes.
    pub address: Vec<u8>,
}

impl HostAddress {
    /// The type of an IPv4 address.
    pub const IPV4: i32 = 2;
    /// The type of an IPv6 address.
    pub const IPV6: i32 = 24;

    fn check(&self) -> Result<(), Error> {
        let ok = match self.addr_type {
            HostAddress::IPV4 => self.address.len() == 4,
            HostAddress::IPV6 => match <[u8; 16]>::try_from(self.address.as_slice()) {
                Ok(a) => {
                    let unspecified_or_loopback = a[..15].iter().all(|&b| b == 0) && a[15] <= 1;
                    let link_local = a[0] == 0xfe && a[1] & 0xc0 == 0x80;
                    let v4_mapped = a[..10].iter().all(|&b| b == 0) && a[10] == 0xff && a[11] == 0xff;
                    !(unspecified_or_loopback || link_local || v4_mapped)
                }
                Err(_) => false,
            },
            _ => true,
        };
        if ok { Ok(()) } else { Err(Error::Address) }
    }

    fn read(r: &mut Reader<'_>) -> Result<HostAddress, Error> {
        let mut s = r.read_sequence()?;
        let addr_type = field(&mut s, 0, int32)?;
        let address = field(&mut s, 1, octets)?;
        s.finish()?;
        let a = HostAddress { addr_type, address };
        a.check()?;
        Ok(a)
    }

    fn write_fields(&self, w: &mut Writer) {
        w.sequence(|w| {
            w_int(w, 0, self.addr_type.into());
            w.explicit(1, |w| w.octet_string(&self.address));
        });
    }
}

/// One PA-DATA entry: pre-authentication data, or hints about it. The
/// value's structure depends on the type and is kept as bytes. For
/// [`padata_type::ENC_TIMESTAMP`] it is an [`EncryptedData`], read with
/// [`EncryptedData::parse`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PaData {
    /// One of [`padata_type`].
    pub padata_type: i32,
    /// The DER the value holds, or any bytes.
    pub value: Vec<u8>,
}

impl PaData {
    fn read(r: &mut Reader<'_>) -> Result<PaData, Error> {
        let mut s = r.read_sequence()?;
        let padata_type = field(&mut s, 1, int32)?;
        let value = field(&mut s, 2, octets)?;
        s.finish()?;
        Ok(PaData { padata_type, value })
    }

    fn write_fields(&self, w: &mut Writer) {
        w.sequence(|w| {
            w_int(w, 1, self.padata_type.into());
            w.explicit(2, |w| w.octet_string(&self.value));
        });
    }
}

/// EncryptedData: an encryption type, the key's version, and ciphertext.
/// This module never looks inside the ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EncryptedData {
    /// The encryption type, such as 18 for aes256-cts-hmac-sha1-96 or 23
    /// for rc4-hmac.
    pub etype: i32,
    /// The key version number, if the key has one.
    pub kvno: Option<u32>,
    /// The ciphertext.
    pub cipher: Vec<u8>,
}

impl EncryptedData {
    fn decode(der: &[u8]) -> Result<EncryptedData, Error> {
        whole(der, Rules::Der, EncryptedData::read)
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        finish(|w| self.write_fields(w))
    }

    fn read(r: &mut Reader<'_>) -> Result<EncryptedData, Error> {
        let mut s = r.read_sequence()?;
        let etype = field(&mut s, 0, int32)?;
        let kvno = optional(&mut s, 1, uint32)?;
        let cipher = field(&mut s, 2, octets)?;
        s.finish()?;
        Ok(EncryptedData { etype, kvno, cipher })
    }

    fn write_fields(&self, w: &mut Writer) {
        w.sequence(|w| {
            w_int(w, 0, self.etype.into());
            if let Some(k) = self.kvno {
                w_int(w, 1, k.into());
            }
            w.explicit(2, |w| w.octet_string(&self.cipher));
        });
    }
}

/// A Ticket: the realm and name of the service it is for, and its
/// encrypted part, which only the service and the KDC can read. Its
/// tkt-vno is always 5.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ticket {
    /// The service's realm.
    pub realm: String,
    /// The service's name.
    pub sname: PrincipalName,
    /// The EncTicketPart, encrypted in the service's key.
    pub enc_part: EncryptedData,
}

impl Ticket {
    fn decode(der: &[u8]) -> Result<Ticket, Error> {
        whole(der, Rules::Der, Ticket::read)
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        self.check()?;
        finish(|w| self.write_fields(w))
    }

    fn check(&self) -> Result<(), Error> {
        check_realm(&self.realm)?;
        self.sname.check()
    }

    fn read(r: &mut Reader<'_>) -> Result<Ticket, Error> {
        let outer = r.read_expected(Tag::application(TICKET_TAG))?;
        let mut o = outer.reader()?;
        let mut s = o.read_sequence()?;
        o.finish()?;
        field(&mut s, 0, version)?;
        let realm = field(&mut s, 1, realm)?;
        let sname = field(&mut s, 2, PrincipalName::read)?;
        let enc_part = field(&mut s, 3, EncryptedData::read)?;
        s.finish()?;
        Ok(Ticket { realm, sname, enc_part })
    }

    fn write_fields(&self, w: &mut Writer) {
        w.constructed(Tag::application(TICKET_TAG), |w| {
            w.sequence(|w| {
                w_int(w, 0, PVNO);
                w_str(w, 1, &self.realm);
                w.explicit(2, |w| self.sname.write_fields(w));
                w.explicit(3, |w| self.enc_part.write_fields(w));
            })
        });
    }
}

/// The body of an AS-REQ or TGS-REQ: what the client asks for.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KdcReqBody {
    /// The flags in [`kdc_options`].
    pub kdc_options: u32,
    /// The client's name. An AS-REQ has one; a TGS-REQ usually does not.
    pub cname: Option<PrincipalName>,
    /// The realm of the server, and in an AS-REQ, of the client too.
    pub realm: String,
    /// The service's name. Left out only with ENC-TKT-IN-SKEY.
    pub sname: Option<PrincipalName>,
    /// When a postdated ticket should start.
    pub from: Option<KerberosTime>,
    /// When the ticket should end.
    pub till: KerberosTime,
    /// When a renewable ticket should stop being renewable.
    pub rtime: Option<KerberosTime>,
    /// A number the reply must repeat.
    pub nonce: u32,
    /// The encryption types the client takes, best first. At most
    /// [`MAX_ETYPES`].
    pub etypes: Vec<i32>,
    /// The addresses the ticket may be used from. At most
    /// [`MAX_ADDRESSES`], and when present, not empty.
    pub addresses: Option<Vec<HostAddress>>,
    /// Authorization data for the ticket, encrypted.
    pub enc_authorization_data: Option<EncryptedData>,
    /// Tickets for user-to-user and similar requests. At most
    /// [`MAX_TICKETS`], and when present, not empty.
    pub additional_tickets: Option<Vec<Ticket>>,
}

impl KdcReqBody {
    fn decode(der: &[u8]) -> Result<KdcReqBody, Error> {
        whole(der, Rules::Der, KdcReqBody::read)
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        self.check()?;
        finish(|w| self.write_fields(w))
    }

    fn check(&self) -> Result<(), Error> {
        check_realm(&self.realm)?;
        if let Some(n) = &self.cname {
            n.check()?;
        }
        if let Some(n) = &self.sname {
            n.check()?;
        }
        limit(self.etypes.len(), MAX_ETYPES, "etype")?;
        if let Some(a) = &self.addresses {
            limit(a.len(), MAX_ADDRESSES, "addresses")?;
            not_empty(a.len(), "addresses")?;
            a.iter().try_for_each(HostAddress::check)?;
        }
        if let Some(t) = &self.additional_tickets {
            limit(t.len(), MAX_TICKETS, "additional-tickets")?;
            not_empty(t.len(), "additional-tickets")?;
            t.iter().try_for_each(Ticket::check)?;
        }
        Ok(())
    }

    fn read(r: &mut Reader<'_>) -> Result<KdcReqBody, Error> {
        let mut s = r.read_sequence()?;
        let body = KdcReqBody {
            kdc_options: field(&mut s, 0, flags)?,
            cname: optional(&mut s, 1, PrincipalName::read)?,
            realm: field(&mut s, 2, realm)?,
            sname: optional(&mut s, 3, PrincipalName::read)?,
            from: optional(&mut s, 4, ktime)?,
            till: field(&mut s, 5, ktime)?,
            rtime: optional(&mut s, 6, ktime)?,
            nonce: field(&mut s, 7, uint32)?,
            etypes: field(&mut s, 8, |r| seq_of(r, MAX_ETYPES, "etype", int32))?,
            addresses: optional_list(&mut s, 9, MAX_ADDRESSES, "addresses", HostAddress::read)?,
            enc_authorization_data: optional(&mut s, 10, EncryptedData::read)?,
            additional_tickets: optional_list(&mut s, 11, MAX_TICKETS, "additional-tickets", Ticket::read)?,
        };
        s.finish()?;
        Ok(body)
    }

    fn write_fields(&self, w: &mut Writer) {
        w.sequence(|w| {
            w_flags(w, 0, self.kdc_options);
            if let Some(n) = &self.cname {
                w.explicit(1, |w| n.write_fields(w));
            }
            w_str(w, 2, &self.realm);
            if let Some(n) = &self.sname {
                w.explicit(3, |w| n.write_fields(w));
            }
            if let Some(t) = &self.from {
                w_time(w, 4, t);
            }
            w_time(w, 5, &self.till);
            if let Some(t) = &self.rtime {
                w_time(w, 6, t);
            }
            w_int(w, 7, self.nonce.into());
            w.explicit(8, |w| {
                w.sequence(|w| {
                    for &e in &self.etypes {
                        w.integer_i64(e.into());
                    }
                })
            });
            if let Some(a) = &self.addresses {
                w.explicit(9, |w| w.sequence(|w| a.iter().for_each(|h| h.write_fields(w))));
            }
            if let Some(e) = &self.enc_authorization_data {
                w.explicit(10, |w| e.write_fields(w));
            }
            if let Some(t) = &self.additional_tickets {
                w.explicit(11, |w| w.sequence(|w| t.iter().for_each(|t| t.write_fields(w))));
            }
        });
    }
}

/// An AS-REQ or TGS-REQ. Which one it is is the [`Message`] variant that
/// holds it.
///
/// Readers and writers check the structure RFC 4120 section 5.4.1 gives,
/// not the rules that tie one field to another: that a TGS-REQ carries a
/// [`padata_type::TGS_REQ`], that `enc_authorization_data` appears only in
/// a TGS-REQ, or that `sname` is left out only with
/// [`kdc_options::ENC_TKT_IN_SKEY`]. A world playing a KDC checks those
/// itself, so it can answer a request that breaks them with the KRB-ERROR
/// a real KDC sends, and a world playing a client can send such a request
/// on purpose.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KdcReq {
    /// Pre-authentication data, at most [`MAX_PADATA`] entries. When
    /// present it is not empty. A TGS-REQ carries its AP-REQ here, as
    /// [`padata_type::TGS_REQ`].
    pub padata: Option<Vec<PaData>>,
    /// What the client asks for.
    pub body: KdcReqBody,
}

impl KdcReq {
    fn check(&self) -> Result<(), Error> {
        if let Some(p) = &self.padata {
            limit(p.len(), MAX_PADATA, "padata")?;
            not_empty(p.len(), "padata")?;
        }
        self.body.check()
    }

    fn read(r: &mut Reader<'_>, msg_type: i64) -> Result<KdcReq, Error> {
        let mut s = r.read_sequence()?;
        field(&mut s, 1, version)?;
        field(&mut s, 2, |r| expect_type(r, msg_type))?;
        let padata = optional_list(&mut s, 3, MAX_PADATA, "padata", PaData::read)?;
        let body = field(&mut s, 4, KdcReqBody::read)?;
        s.finish()?;
        Ok(KdcReq { padata, body })
    }

    fn write_fields(&self, w: &mut Writer, msg_type: i64) {
        w.sequence(|w| {
            w_int(w, 1, PVNO);
            w_int(w, 2, msg_type);
            if let Some(p) = &self.padata {
                w.explicit(3, |w| w.sequence(|w| p.iter().for_each(|p| p.write_fields(w))));
            }
            w.explicit(4, |w| self.body.write_fields(w));
        });
    }
}

/// An AS-REP or TGS-REP. Which one it is is the [`Message`] variant that
/// holds it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KdcRep {
    /// Pre-authentication data, such as the salt the client's key was
    /// made with. At most [`MAX_PADATA`] entries, and when present, not
    /// empty.
    pub padata: Option<Vec<PaData>>,
    /// The client's realm.
    pub crealm: String,
    /// The client's name.
    pub cname: PrincipalName,
    /// The new ticket.
    pub ticket: Ticket,
    /// The EncKDCRepPart, with the session key, encrypted in the client's
    /// key (AS-REP) or the TGT's session key (TGS-REP).
    pub enc_part: EncryptedData,
}

impl KdcRep {
    fn check(&self) -> Result<(), Error> {
        if let Some(p) = &self.padata {
            limit(p.len(), MAX_PADATA, "padata")?;
            not_empty(p.len(), "padata")?;
        }
        check_realm(&self.crealm)?;
        self.cname.check()?;
        self.ticket.check()
    }

    fn read(r: &mut Reader<'_>, msg_type: i64) -> Result<KdcRep, Error> {
        let mut s = r.read_sequence()?;
        field(&mut s, 0, version)?;
        field(&mut s, 1, |r| expect_type(r, msg_type))?;
        let rep = KdcRep {
            padata: optional_list(&mut s, 2, MAX_PADATA, "padata", PaData::read)?,
            crealm: field(&mut s, 3, realm)?,
            cname: field(&mut s, 4, PrincipalName::read)?,
            ticket: field(&mut s, 5, Ticket::read)?,
            enc_part: field(&mut s, 6, EncryptedData::read)?,
        };
        s.finish()?;
        Ok(rep)
    }

    fn write_fields(&self, w: &mut Writer, msg_type: i64) {
        w.sequence(|w| {
            w_int(w, 0, PVNO);
            w_int(w, 1, msg_type);
            if let Some(p) = &self.padata {
                w.explicit(2, |w| w.sequence(|w| p.iter().for_each(|p| p.write_fields(w))));
            }
            w_str(w, 3, &self.crealm);
            w.explicit(4, |w| self.cname.write_fields(w));
            w.explicit(5, |w| self.ticket.write_fields(w));
            w.explicit(6, |w| self.enc_part.write_fields(w));
        });
    }
}

/// An AP-REQ: a ticket and an authenticator, shown to a service.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ApReq {
    /// The flags in [`ap_options`].
    pub ap_options: u32,
    /// The service ticket.
    pub ticket: Ticket,
    /// The Authenticator, encrypted in the ticket's session key.
    pub authenticator: EncryptedData,
}

impl ApReq {
    fn read(r: &mut Reader<'_>) -> Result<ApReq, Error> {
        let mut s = r.read_sequence()?;
        field(&mut s, 0, version)?;
        field(&mut s, 1, |r| expect_type(r, msg_type::AP_REQ))?;
        let req = ApReq {
            ap_options: field(&mut s, 2, flags)?,
            ticket: field(&mut s, 3, Ticket::read)?,
            authenticator: field(&mut s, 4, EncryptedData::read)?,
        };
        s.finish()?;
        Ok(req)
    }

    fn write_fields(&self, w: &mut Writer) {
        w.sequence(|w| {
            w_int(w, 0, PVNO);
            w_int(w, 1, msg_type::AP_REQ);
            w_flags(w, 2, self.ap_options);
            w.explicit(3, |w| self.ticket.write_fields(w));
            w.explicit(4, |w| self.authenticator.write_fields(w));
        });
    }
}

/// An AP-REP: a service's answer when the client asked for mutual
/// authentication.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ApRep {
    /// The EncAPRepPart, encrypted in the session key.
    pub enc_part: EncryptedData,
}

impl ApRep {
    fn read(r: &mut Reader<'_>) -> Result<ApRep, Error> {
        let mut s = r.read_sequence()?;
        field(&mut s, 0, version)?;
        field(&mut s, 1, |r| expect_type(r, msg_type::AP_REP))?;
        let enc_part = field(&mut s, 2, EncryptedData::read)?;
        s.finish()?;
        Ok(ApRep { enc_part })
    }

    fn write_fields(&self, w: &mut Writer) {
        w.sequence(|w| {
            w_int(w, 0, PVNO);
            w_int(w, 1, msg_type::AP_REP);
            w.explicit(2, |w| self.enc_part.write_fields(w));
        });
    }
}

/// A KRB-ERROR: why a KDC or service refused a request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KrbError {
    /// The client's time, copied from its request.
    pub ctime: Option<KerberosTime>,
    /// The microseconds of `ctime`, at most [`MAX_MICROSECONDS`].
    pub cusec: Option<u32>,
    /// The server's time.
    pub stime: KerberosTime,
    /// The microseconds of `stime`, at most [`MAX_MICROSECONDS`].
    pub susec: u32,
    /// One of [`error_code`].
    pub error_code: i32,
    /// The client's realm.
    pub crealm: Option<String>,
    /// The client's name.
    pub cname: Option<PrincipalName>,
    /// The service's realm.
    pub realm: String,
    /// The service's name.
    pub sname: PrincipalName,
    /// Text for a person to read.
    pub e_text: Option<String>,
    /// More data. With [`error_code::KDC_ERR_PREAUTH_REQUIRED`] it is a
    /// [`MethodData`].
    pub e_data: Option<Vec<u8>>,
}

impl KrbError {
    fn check(&self) -> Result<(), Error> {
        if self.cusec.is_some_and(|u| u > MAX_MICROSECONDS) || self.susec > MAX_MICROSECONDS {
            return Err(Error::Range);
        }
        if let Some(r) = &self.crealm {
            check_realm(r)?;
        }
        check_realm(&self.realm)?;
        if let Some(n) = &self.cname {
            n.check()?;
        }
        self.sname.check()
    }

    fn read(r: &mut Reader<'_>) -> Result<KrbError, Error> {
        let mut s = r.read_sequence()?;
        field(&mut s, 0, version)?;
        field(&mut s, 1, |r| expect_type(r, msg_type::KRB_ERROR))?;
        let e = KrbError {
            ctime: optional(&mut s, 2, ktime)?,
            cusec: optional(&mut s, 3, microseconds)?,
            stime: field(&mut s, 4, ktime)?,
            susec: field(&mut s, 5, microseconds)?,
            error_code: field(&mut s, 6, int32)?,
            crealm: optional(&mut s, 7, realm)?,
            cname: optional(&mut s, 8, PrincipalName::read)?,
            realm: field(&mut s, 9, realm)?,
            sname: field(&mut s, 10, PrincipalName::read)?,
            e_text: optional(&mut s, 11, kstring)?,
            e_data: optional(&mut s, 12, octets)?,
        };
        s.finish()?;
        Ok(e)
    }

    fn write_fields(&self, w: &mut Writer) {
        w.sequence(|w| {
            w_int(w, 0, PVNO);
            w_int(w, 1, msg_type::KRB_ERROR);
            if let Some(t) = &self.ctime {
                w_time(w, 2, t);
            }
            if let Some(u) = self.cusec {
                w_int(w, 3, u.into());
            }
            w_time(w, 4, &self.stime);
            w_int(w, 5, self.susec.into());
            w_int(w, 6, self.error_code.into());
            if let Some(r) = &self.crealm {
                w_str(w, 7, r);
            }
            if let Some(n) = &self.cname {
                w.explicit(8, |w| n.write_fields(w));
            }
            w_str(w, 9, &self.realm);
            w.explicit(10, |w| self.sname.write_fields(w));
            if let Some(t) = &self.e_text {
                w_str(w, 11, t);
            }
            if let Some(d) = &self.e_data {
                w.explicit(12, |w| w.octet_string(d));
            }
        });
    }
}

/// One Kerberos message: what a UDP datagram or a TCP record holds.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Message {
    /// A request for a ticket-granting ticket: `[APPLICATION 10]`.
    AsReq(KdcReq),
    /// The KDC's answer to an AS-REQ: `[APPLICATION 11]`.
    AsRep(KdcRep),
    /// A request for a service ticket: `[APPLICATION 12]`.
    TgsReq(KdcReq),
    /// The KDC's answer to a TGS-REQ: `[APPLICATION 13]`.
    TgsRep(KdcRep),
    /// A ticket shown to a service: `[APPLICATION 14]`.
    ApReq(ApReq),
    /// A service's answer to an AP-REQ: `[APPLICATION 15]`.
    ApRep(ApRep),
    /// An error: `[APPLICATION 30]`.
    KrbError(KrbError),
}

impl Message {
    fn decode(der: &[u8]) -> Result<Message, Error> {
        Message::parse_with(der, Rules::Der)
    }

    /// Reads one message under `rules`. [`Rules::Ber`] also takes the
    /// indefinite lengths and split strings some older implementations
    /// send.
    pub fn parse_with(b: &[u8], rules: Rules) -> Result<Message, Error> {
        whole(b, rules, |r| {
            let tag = r.peek()?.tag();
            let number = match tag.class {
                asn1::Class::Application if tag.constructed => tag.number,
                asn1::Class::Application => return Err(Error::Asn1(asn1::Error::Primitive)),
                _ => return Err(Error::UnknownMessage(u32::MAX)),
            };
            let outer = r.read()?;
            let mut o = outer.reader()?;
            let t = i64::from(number);
            let m = match t {
                msg_type::AS_REQ => Message::AsReq(KdcReq::read(&mut o, t)?),
                msg_type::AS_REP => Message::AsRep(KdcRep::read(&mut o, t)?),
                msg_type::TGS_REQ => Message::TgsReq(KdcReq::read(&mut o, t)?),
                msg_type::TGS_REP => Message::TgsRep(KdcRep::read(&mut o, t)?),
                msg_type::AP_REQ => Message::ApReq(ApReq::read(&mut o)?),
                msg_type::AP_REP => Message::ApRep(ApRep::read(&mut o)?),
                msg_type::KRB_ERROR => Message::KrbError(KrbError::read(&mut o)?),
                _ => return Err(Error::UnknownMessage(number)),
            };
            o.finish()?;
            Ok(m)
        })
    }

    /// The KDC-REQ-BODY of the AS-REQ or TGS-REQ in `b`, exactly as the
    /// client sent it. A checksum over the body, such as the one in a
    /// TGS-REQ's authenticator (RFC 4120 section 5.2.7.1), covers these
    /// bytes, which [`KdcReqBody::write`] does not always give back. The
    /// message is read as [`Message::parse_with`] reads it, and any of its
    /// errors is returned. Any other message is [`Error::UnknownMessage`]
    /// with its tag number.
    pub fn kdc_req_body(b: &[u8], rules: Rules) -> Result<&[u8], Error> {
        let m = Message::parse_with(b, rules)?;
        if !matches!(m, Message::AsReq(_) | Message::TgsReq(_)) {
            return Err(Error::UnknownMessage(u32::try_from(m.msg_type()).unwrap_or(u32::MAX)));
        }
        // The message read, so each step below finds what it looks for.
        let mut r = Reader::new(b, rules);
        let outer = r.read()?;
        let mut o = outer.reader()?;
        let mut s = o.read_sequence()?;
        s.read_explicit(1)?;
        s.read_explicit(2)?;
        if s.peek()?.tag().same_type(Tag::context(3)) {
            s.read_explicit(3)?;
        }
        let body = s.read_explicit(4)?;
        Ok(body.peek()?.raw())
    }

    /// The message's msg-type, one of [`msg_type`].
    pub fn msg_type(&self) -> i64 {
        match self {
            Message::AsReq(_) => msg_type::AS_REQ,
            Message::AsRep(_) => msg_type::AS_REP,
            Message::TgsReq(_) => msg_type::TGS_REQ,
            Message::TgsRep(_) => msg_type::TGS_REP,
            Message::ApReq(_) => msg_type::AP_REQ,
            Message::ApRep(_) => msg_type::AP_REP,
            Message::KrbError(_) => msg_type::KRB_ERROR,
        }
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        match self {
            Message::AsReq(m) | Message::TgsReq(m) => m.check()?,
            Message::AsRep(m) | Message::TgsRep(m) => m.check()?,
            Message::ApReq(m) => m.ticket.check()?,
            Message::ApRep(_) => {}
            Message::KrbError(m) => m.check()?,
        }
        let t = self.msg_type();
        let tag = Tag::application(u32::try_from(t).unwrap_or(u32::MAX));
        finish(|w| {
            w.constructed(tag, |w| match self {
                Message::AsReq(m) | Message::TgsReq(m) => m.write_fields(w, t),
                Message::AsRep(m) | Message::TgsRep(m) => m.write_fields(w, t),
                Message::ApReq(m) => m.write_fields(w),
                Message::ApRep(m) => m.write_fields(w),
                Message::KrbError(m) => m.write_fields(w),
            })
        })
    }
}

/// Why a TCP stream cannot be split into messages. Either way the stream
/// holds no more messages a reader can find. For a set reserved bit, RFC
/// 4120 section 7.2.2 says a KDC must answer with
/// [`error_code::KRB_ERR_FIELD_TOOLONG`] and close the connection. The
/// RFC sets no rule for a length over [`MAX_MESSAGE`]; the same answer
/// suits it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The length's high bit, reserved for extensions, is set.
    Reserved(u32),
    /// The length is above [`MAX_MESSAGE`].
    TooLong(u32),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Reserved(n) => write!(f, "length {n:#010x} has the reserved high bit set"),
            FrameError::TooLong(n) => write!(f, "length {n} is above {MAX_MESSAGE}"),
        }
    }
}

impl std::error::Error for FrameError {}

asn1::der_wire!(Message,
    /// Reads one complete DER message, as RFC 4120 requires.
    /// Refuses invalid tags, versions, fields, and lists, trailing bytes,
    /// and input or DER output over [`MAX_MESSAGE`]. Short flags and signed
    /// integer forms can expand when written.
    parse checks encode;
    /// Appends the message as DER, as a UDP datagram carries it. A list over its
    /// limit, a Microseconds field over [`MAX_MICROSECONDS`], or a message
    /// longer than [`MAX_MESSAGE`] is an error, and nothing is written. A
    /// message read with [`Message::parse_with`] near the limit may grow
    /// past it. DER can expand BER forms or short flags. [`Wire::parse`]
    /// checks that the resulting encoding fits.
    /// Refuses values that change when encoded. Leaves `out` unchanged on error.
    write;
);

/// One TCP record's payload, bounded by [`MAX_MESSAGE`].
///
/// [`super::codec::Wire`] reads exactly one length-prefixed record and
/// writes the prefix and payload. The payload is not interpreted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame(
    /// Message bytes without the four-byte TCP length.
    pub Vec<u8>,
);

/// Why bytes do not contain exactly one complete TCP record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameParseError {
    /// The record's length was refused.
    Frame(FrameError),
    /// The input ended inside the prefix or payload.
    Truncated,
    /// Bytes followed the complete record.
    Trailing,
}

impl core::fmt::Display for FrameParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Frame(e) => e.fmt(f),
            Self::Truncated => f.write_str("Kerberos TCP record ended early"),
            Self::Trailing => f.write_str("bytes after the Kerberos TCP record"),
        }
    }
}

impl core::error::Error for FrameParseError {}

impl Wire for Frame {
    type ParseError = FrameParseError;
    type WriteError = FrameError;

    /// Reads one TCP record. Refuses a reserved length bit, payloads over
    /// [`MAX_MESSAGE`], incomplete records, and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, FrameParseError> {
        match Frames::new().decode(bytes, true).map_err(FrameParseError::Frame)? {
            Step::Item(data, n) if n == bytes.len() => Ok(Self(data)),
            Step::Item(_, _) => Err(FrameParseError::Trailing),
            _ => Err(FrameParseError::Truncated),
        }
    }

    /// Appends the four-byte length and payload. Refuses payloads over
    /// [`MAX_MESSAGE`], leaving `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), FrameError> {
        let length = u32::try_from(self.0.len()).map_err(|_| FrameError::TooLong(u32::MAX))?;
        if self.0.len() > MAX_MESSAGE {
            return Err(FrameError::TooLong(length));
        }
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&self.0);
        Ok(())
    }
}

/// Reads Kerberos TCP records without holding input bytes.
///
/// Use with [`Stream<Frames>`](super::codec::Stream) for a buffer limited to
/// [`TCP_HEADER_LEN`] plus the configured message limit. The four-byte prefix
/// suffices to refuse reserved bits and oversized messages. Map each
/// payload through [`Message::parse`] to interpret it. Partial records
/// return [`super::codec::Step::Need`], including at EOF. The stream
/// reports truncation at EOF and framing errors once.
#[derive(Clone, Copy, Debug)]
pub struct Frames {
    limit: usize,
}

impl Frames {
    /// Creates a decoder accepting messages up to [`MAX_MESSAGE`] bytes.
    pub fn new() -> Self {
        Self::with_limit(MAX_MESSAGE)
    }

    /// Sets the message limit, excluding the TCP header, clamped to
    /// [`MAX_MESSAGE`]. Zero accepts only empty records.
    pub fn with_limit(limit: usize) -> Self {
        Self { limit: limit.min(MAX_MESSAGE) }
    }

    /// The maximum message size, excluding its TCP header.
    pub fn limit(&self) -> usize {
        self.limit
    }
}

impl Default for Frames {
    fn default() -> Self {
        Self::new()
    }
}

impl Decode for Frames {
    type Item = Vec<u8>;
    type Error = FrameError;
    const NAME: &'static str = "Kerberos TCP";

    fn capacity(&self) -> usize {
        TCP_HEADER_LEN.saturating_add(self.limit)
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Vec<u8>>, FrameError> {
        let Some(&[a, b, c, d]) = input.get(..TCP_HEADER_LEN) else {
            return Ok(Step::Need);
        };
        let length = u32::from_be_bytes([a, b, c, d]);
        let n = frame_len(length)?;
        if n > self.limit {
            return Err(FrameError::TooLong(length));
        }
        let total = TCP_HEADER_LEN.checked_add(n).ok_or(FrameError::TooLong(length))?;
        Ok(match input.get(TCP_HEADER_LEN..total) {
            Some(bytes) => Step::Item(bytes.to_vec(), total),
            None => Step::Need,
        })
    }
}

/// The body length a TCP length prefix gives, if it is allowed.
fn frame_len(len: u32) -> Result<usize, FrameError> {
    if len & 0x8000_0000 != 0 {
        return Err(FrameError::Reserved(len));
    }
    usize::try_from(len).ok().filter(|&n| n <= MAX_MESSAGE).ok_or(FrameError::TooLong(len))
}

// Reading helpers. Each reads one value from `r` and leaves the rest.

/// Reads all of `b` with `f`, which must use every byte.
fn whole<T>(b: &[u8], rules: Rules, f: impl FnOnce(&mut Reader<'_>) -> Result<T, Error>) -> Result<T, Error> {
    if b.len() > MAX_MESSAGE {
        return Err(Error::TooLong);
    }
    let mut r = Reader::new(b, rules);
    let v = f(&mut r)?;
    r.finish()?;
    Ok(v)
}

/// Reads the explicitly tagged field `[n]`, which must hold exactly what
/// `f` reads.
fn field<'a, T>(r: &mut Reader<'a>, n: u32, f: impl FnOnce(&mut Reader<'a>) -> Result<T, Error>) -> Result<T, Error> {
    let mut inner = r.read_explicit(n)?;
    let v = f(&mut inner)?;
    inner.finish()?;
    Ok(v)
}

/// Reads the OPTIONAL field `[n]`, if it comes next.
fn optional<'a, T>(
    r: &mut Reader<'a>,
    n: u32,
    f: impl FnOnce(&mut Reader<'a>) -> Result<T, Error>,
) -> Result<Option<T>, Error> {
    if r.is_empty() || !r.peek()?.tag().same_type(Tag::context(n)) {
        return Ok(None);
    }
    field(r, n, f).map(Some)
}

/// Reads a SEQUENCE OF with at most `max` entries.
fn seq_of<'a, T>(
    r: &mut Reader<'a>,
    max: usize,
    what: &'static str,
    mut f: impl FnMut(&mut Reader<'a>) -> Result<T, Error>,
) -> Result<Vec<T>, Error> {
    let mut s = r.read_sequence()?;
    let mut out = Vec::new();
    while !s.is_empty() {
        if out.len() >= max {
            return Err(Error::TooMany(what));
        }
        out.push(f(&mut s)?);
    }
    Ok(out)
}

/// Reads the OPTIONAL SEQUENCE OF `[n]`, if it comes next. An empty one
/// reads as absent, as RFC 4120 section 5.1.3 asks of receivers.
fn optional_list<'a, T>(
    r: &mut Reader<'a>,
    n: u32,
    max: usize,
    what: &'static str,
    f: impl FnMut(&mut Reader<'a>) -> Result<T, Error>,
) -> Result<Option<Vec<T>>, Error> {
    Ok(optional(r, n, |r| seq_of(r, max, what, f))?.filter(|v| !v.is_empty()))
}

fn limit(len: usize, max: usize, what: &'static str) -> Result<(), Error> {
    if len > max { Err(Error::TooMany(what)) } else { Ok(()) }
}

fn not_empty(len: usize, what: &'static str) -> Result<(), Error> {
    if len == 0 { Err(Error::Empty(what)) } else { Ok(()) }
}

/// A Realm may not hold a NUL (RFC 4120 section 5.2.2).
fn check_realm(s: &str) -> Result<(), Error> {
    if s.contains('\0') { Err(Error::Text) } else { Ok(()) }
}

fn int32(r: &mut Reader<'_>) -> Result<i32, Error> {
    let v = r.read_integer()?.to_i64().ok_or(Error::Range)?;
    i32::try_from(v).map_err(|_| Error::Range)
}

/// A UInt32. A negative value that fits 32 bits is read as its two's
/// complement, since some older implementations write nonces and key
/// versions as signed numbers.
fn uint32(r: &mut Reader<'_>) -> Result<u32, Error> {
    let v = r.read_integer()?.to_i64().ok_or(Error::Range)?;
    if let Ok(u) = u32::try_from(v) { Ok(u) } else { i32::try_from(v).map(|i| i as u32).map_err(|_| Error::Range) }
}

fn microseconds(r: &mut Reader<'_>) -> Result<u32, Error> {
    let v = r.read_integer()?.to_i64().ok_or(Error::Range)?;
    u32::try_from(v).ok().filter(|&u| u <= MAX_MICROSECONDS).ok_or(Error::Range)
}

fn version(r: &mut Reader<'_>) -> Result<(), Error> {
    let v = r.read_integer()?.to_i64().ok_or(Error::Range)?;
    if v == PVNO { Ok(()) } else { Err(Error::Version(v)) }
}

fn expect_type(r: &mut Reader<'_>, expected: i64) -> Result<(), Error> {
    let found = r.read_integer()?.to_i64().ok_or(Error::Range)?;
    if found == expected { Ok(()) } else { Err(Error::MessageType { expected, found }) }
}

/// A KerberosString: a GeneralString, read as UTF-8 as MIT and Windows
/// send it.
fn kstring(r: &mut Reader<'_>) -> Result<String, Error> {
    let b = r.read_string_bytes(StringKind::General)?;
    String::from_utf8(b.into_owned()).map_err(|_| Error::Text)
}

/// A Realm: a KerberosString with no NUL.
fn realm(r: &mut Reader<'_>) -> Result<String, Error> {
    let s = kstring(r)?;
    check_realm(&s)?;
    Ok(s)
}

fn ktime(r: &mut Reader<'_>) -> Result<KerberosTime, Error> {
    KerberosTime::new(&r.read_generalized_time()?)
}

fn octets(r: &mut Reader<'_>) -> Result<Vec<u8>, Error> {
    Ok(r.read_octet_string()?.into_owned())
}

/// KerberosFlags: a BIT STRING of 32 bits or more. Bits past 32 are
/// ignored, and missing bits are zero.
fn flags(r: &mut Reader<'_>) -> Result<u32, Error> {
    let b = r.read_bit_string()?;
    Ok((0..32).fold(0u32, |acc, i| if b.bit(i) == Some(true) { acc | (0x8000_0000 >> i) } else { acc }))
}

// Writing helpers.

/// Runs the writer `f`. Output past [`MAX_MESSAGE`] is [`Error::TooLong`],
/// including output the ASN.1 writer stopped at its own, larger limit.
fn finish(f: impl FnOnce(&mut Writer)) -> Result<Vec<u8>, Error> {
    let mut w = Writer::new();
    f(&mut w);
    let out = w.finish().map_err(|e| if e == asn1::Error::TooLong { Error::TooLong } else { Error::Asn1(e) })?;
    if out.len() > MAX_MESSAGE {
        return Err(Error::TooLong);
    }
    Ok(out)
}

fn w_int(w: &mut Writer, n: u32, v: i64) {
    w.explicit(n, |w| w.integer_i64(v));
}

fn w_str(w: &mut Writer, n: u32, s: &str) {
    w.explicit(n, |w| w.string_bytes(StringKind::General, s.as_bytes()));
}

fn w_time(w: &mut Writer, n: u32, t: &KerberosTime) {
    w.explicit(n, |w| w.generalized_time(t.as_str()));
}

fn w_flags(w: &mut Writer, n: u32, f: u32) {
    w.explicit(n, |w| w.bit_string(&f.to_be_bytes(), 0));
}

asn1::der_wire!(EncryptedData,
    /// Reads an EncryptedData standing alone in `bytes`, as a PA-DATA value
    /// holds one.
    /// Refuses malformed DER, trailing bytes, and input or DER output over
    /// [`MAX_MESSAGE`]. Signed kvno values are read as UInt32.
    parse checks encode;
    /// Appends this EncryptedData as DER. Refuses output over [`MAX_MESSAGE`].
    /// Signed kvno input can expand when written as UInt32. The parser checks
    /// that the resulting encoding still fits.
    /// Refuses values that change when encoded. Leaves `out` unchanged on error.
    write;
);

asn1::der_wire!(Ticket,
    /// Reads a Ticket standing alone in `bytes`, as a credential cache holds
    /// one.
    /// Refuses malformed DER, invalid realms or names, wrong versions, trailing
    /// bytes, and input or DER output over [`MAX_MESSAGE`].
    parse checks encode;
    /// Appends this Ticket as DER. Refuses invalid realms or names and
    /// output over [`MAX_MESSAGE`]. As with [`EncryptedData::write`], DER
    /// may expand a signed kvno; the parser checks that the result fits.
    /// Refuses values that change when encoded. Leaves `out` unchanged on error.
    write;
);

asn1::der_wire!(KdcReqBody,
    /// Reads a KDC-REQ-BODY standing alone in `bytes`, such as the bytes a
    /// checksum covers.
    /// Refuses malformed DER, invalid fields or lists, trailing bytes,
    /// and input or DER output over [`MAX_MESSAGE`].
    parse checks encode;
    /// Appends the body as DER. A body read and written again may
    /// not be the bytes it was read from: options shorter than 32 bits, a
    /// nonce or kvno written as a negative number, an empty optional list,
    /// or BER all come out differently. To check a checksum over a body
    /// that was received, take its bytes with [`Message::kdc_req_body`].
    /// Refuses invalid fields or lists and output over [`MAX_MESSAGE`].
    /// Refuses values that change when encoded. Leaves `out` unchanged on error.
    write;
);

/// METHOD-DATA: a DER SEQUENCE OF PA-DATA, bounded by [`MAX_PADATA`].
/// A KRB-ERROR with [`error_code::KDC_ERR_PREAUTH_REQUIRED`] carries it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct MethodData(
    /// The pre-authentication methods, in wire order. An empty list is allowed.
    pub Vec<PaData>,
);

impl Wire for MethodData {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one DER METHOD-DATA. Refuses malformed fields, trailing bytes,
    /// more than [`MAX_PADATA`] methods, and input over [`MAX_MESSAGE`].
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        whole(bytes, Rules::Der, |r| seq_of(r, MAX_PADATA, "padata", PaData::read)).map(Self)
    }

    /// Appends DER METHOD-DATA. Refuses more than [`MAX_PADATA`] methods
    /// and output over [`MAX_MESSAGE`], leaving `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        limit(self.0.len(), MAX_PADATA, "padata")?;
        let bytes = finish(|w| w.sequence(|w| self.0.iter().for_each(|p| p.write_fields(w))))?;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::codec::{
        Fail, Stream, contract, finish as finish_stream, pump,
        test_support::{Lcg, chunks, mutate},
    };
    use super::*;

    fn time(s: &str) -> KerberosTime {
        KerberosTime::new(s).unwrap()
    }

    fn enc(etype: i32, kvno: Option<u32>, cipher: &[u8]) -> EncryptedData {
        EncryptedData { etype, kvno, cipher: cipher.to_vec() }
    }

    fn tgt() -> Ticket {
        Ticket {
            realm: "EXAMPLE.COM".into(),
            sname: PrincipalName::new(name_type::SRV_INST, &["krbtgt", "EXAMPLE.COM"]),
            enc_part: enc(18, Some(2), &[0xaa; 40]),
        }
    }

    fn as_req() -> KdcReq {
        KdcReq {
            padata: Some(vec![PaData {
                padata_type: padata_type::ENC_TIMESTAMP,
                value: enc(18, None, &[1, 2, 3]).to_bytes().unwrap(),
            }]),
            body: KdcReqBody {
                kdc_options: kdc_options::FORWARDABLE | kdc_options::RENEWABLE | kdc_options::RENEWABLE_OK,
                cname: Some(PrincipalName::new(name_type::PRINCIPAL, &["alice"])),
                realm: "EXAMPLE.COM".into(),
                sname: Some(PrincipalName::new(name_type::SRV_INST, &["krbtgt", "EXAMPLE.COM"])),
                from: Some(time("20261005000000Z")),
                till: time("20261006000000Z"),
                rtime: Some(time("20261012000000Z")),
                nonce: 0xdead_beef,
                etypes: vec![18, 17, 23],
                addresses: Some(vec![HostAddress { addr_type: 2, address: vec![10, 0, 0, 5] }]),
                enc_authorization_data: Some(enc(18, None, b"ad")),
                additional_tickets: Some(vec![tgt()]),
            },
        }
    }

    fn krb_error() -> KrbError {
        KrbError {
            ctime: Some(time("20261005115959Z")),
            cusec: Some(999_999),
            stime: time("20261005120000Z"),
            susec: 12,
            error_code: error_code::KDC_ERR_PREAUTH_REQUIRED,
            crealm: Some("EXAMPLE.COM".into()),
            cname: Some(PrincipalName::new(name_type::PRINCIPAL, &["alice"])),
            realm: "EXAMPLE.COM".into(),
            sname: PrincipalName::new(name_type::SRV_INST, &["krbtgt", "EXAMPLE.COM"]),
            e_text: Some("pre-authentication required".into()),
            e_data: Some(vec![0x30, 0x00]),
        }
    }

    fn all_messages() -> Vec<Message> {
        let rep = KdcRep {
            padata: Some(vec![PaData { padata_type: padata_type::ETYPE_INFO2, value: vec![0x30, 0x00] }]),
            crealm: "EXAMPLE.COM".into(),
            cname: PrincipalName::new(name_type::PRINCIPAL, &["alice"]),
            ticket: tgt(),
            enc_part: enc(18, Some(5), &[0x55; 64]),
        };
        let mut tgs = as_req();
        tgs.body.cname = None;
        tgs.padata = None;
        vec![
            Message::AsReq(as_req()),
            Message::AsRep(rep.clone()),
            Message::TgsReq(tgs),
            Message::TgsRep(KdcRep { padata: None, ..rep }),
            Message::ApReq(ApReq {
                ap_options: ap_options::MUTUAL_REQUIRED,
                ticket: tgt(),
                authenticator: enc(23, None, &[9; 20]),
            }),
            Message::ApRep(ApRep { enc_part: enc(18, None, &[7; 30]) }),
            Message::KrbError(krb_error()),
        ]
    }

    // Hand-encoded DER for structures RFC 4120 section 5 defines.

    #[test]
    fn principal_name_by_hand() {
        let n = PrincipalName::new(name_type::SRV_INST, &["krbtgt", "A.B"]);
        let mut w = Writer::new();
        n.write_fields(&mut w);
        let der = w.finish().unwrap();
        #[rustfmt::skip]
        let expected = [
            0x30, 0x16,
            0xa0, 0x03, 0x02, 0x01, 0x02,
            0xa1, 0x0f, 0x30, 0x0d,
            0x1b, 0x06, b'k', b'r', b'b', b't', b'g', b't',
            0x1b, 0x03, b'A', b'.', b'B',
        ];
        assert_eq!(der, expected);
        assert_eq!(whole(&der, Rules::Der, PrincipalName::read).unwrap(), n);
        assert_eq!(n.to_string(), "krbtgt/A.B");
    }

    #[test]
    fn ap_rep_by_hand() {
        #[rustfmt::skip]
        let der = [
            0x6f, 0x19, 0x30, 0x17,
            0xa0, 0x03, 0x02, 0x01, 0x05,
            0xa1, 0x03, 0x02, 0x01, 0x0f,
            0xa2, 0x0b, 0x30, 0x09,
            0xa0, 0x03, 0x02, 0x01, 0x12,
            0xa2, 0x02, 0x04, 0x00,
        ];
        let m = Message::parse(&der).unwrap();
        assert_eq!(m, Message::ApRep(ApRep { enc_part: enc(18, None, &[]) }));
        assert_eq!(m.to_bytes().unwrap(), der);
    }

    #[test]
    fn encrypted_data_by_hand() {
        // kvno 128 needs a leading zero byte to stay positive.
        let der = [
            0x30, 0x10, 0xa0, 0x03, 0x02, 0x01, 0x17, 0xa1, 0x04, 0x02, 0x02, 0x00, 0x80, 0xa2, 0x03, 0x04, 0x01, 0xff,
        ];
        let e = EncryptedData::parse(&der).unwrap();
        assert_eq!(e, enc(23, Some(128), &[0xff]));
        assert_eq!(e.to_bytes().unwrap(), der);
        // A kvno written as a signed -1 reads as 0xFFFFFFFF.
        let signed = [0x30, 0x0e, 0xa0, 0x03, 0x02, 0x01, 0x17, 0xa1, 0x03, 0x02, 0x01, 0xff, 0xa2, 0x02, 0x04, 0x00];
        assert_eq!(EncryptedData::parse(&signed).unwrap().kvno, Some(u32::MAX));
    }

    #[test]
    fn flags_are_32_bits() {
        let m = Message::AsReq(as_req());
        let der = m.to_bytes().unwrap();
        // kdc-options [0] BIT STRING with no unused bits and 4 bytes.
        let want = [0xa0, 0x07, 0x03, 0x05, 0x00, 0x40, 0x80, 0x00, 0x10];
        assert!(der.windows(want.len()).any(|w| w == want));
        // A short bit string reads with the missing bits as zero.
        let mut r = Reader::new(&[0x03, 0x02, 0x00, 0x40], Rules::Der);
        assert_eq!(flags(&mut r).unwrap(), kdc_options::FORWARDABLE);
        // Bits past 32 are ignored.
        let mut r = Reader::new(&[0x03, 0x06, 0x00, 0, 0, 0, 1, 0xff], Rules::Der);
        assert_eq!(flags(&mut r).unwrap(), 1);
    }

    #[test]
    fn every_message_round_trips() {
        for m in all_messages() {
            let der = m.to_bytes().unwrap();
            assert_eq!(der[0], 0x60 | m.msg_type() as u8 & 0x1f, "{m:?}");
            assert_eq!(Message::parse(&der).unwrap(), m);
            assert_eq!(Message::parse_with(&der, Rules::Ber).unwrap(), m);
            let tcp = Frame(m.to_bytes().unwrap()).to_bytes().unwrap();
            assert_eq!(tcp[..4], (der.len() as u32).to_be_bytes());
        }
        let t = tgt();
        assert_eq!(Ticket::parse(&t.to_bytes().unwrap()).unwrap(), t);
        let body = as_req().body;
        let mut r = Reader::new(&[], Rules::Der);
        assert!(KdcReqBody::read(&mut r).is_err());
        let der = body.to_bytes().unwrap();
        assert_eq!(whole(&der, Rules::Der, KdcReqBody::read).unwrap(), body);
    }

    #[test]
    fn method_data() {
        let p = MethodData(vec![
            PaData { padata_type: padata_type::ENC_TIMESTAMP, value: vec![] },
            PaData { padata_type: padata_type::ETYPE_INFO2, value: vec![0x30, 0x00] },
        ]);
        let der = p.to_bytes().unwrap();
        assert_eq!(MethodData::parse(&der).unwrap(), p);
        let many = MethodData(vec![p.0[0].clone(); MAX_PADATA + 1]);
        assert_eq!(many.to_bytes(), Err(Error::TooMany("padata")));
    }

    #[test]
    fn times() {
        assert!(KerberosTime::new("20261005120000Z").is_ok());
        assert_eq!(KerberosTime::new("20261005120000.5Z"), Err(Error::Time));
        assert_eq!(KerberosTime::new("20261305120000Z"), Err(Error::Time));
        assert_eq!(KerberosTime::new("2026100512000Z"), Err(Error::Time));
        assert_eq!(KerberosTime::new("20261005120000"), Err(Error::Time));
        assert_eq!(KerberosTime::from_parts(2026, 2, 28, 23, 59, 59).unwrap().as_str(), "20260228235959Z");
        assert_eq!(KerberosTime::from_parts(2026, 2, 29, 0, 0, 0), Err(Error::Time));
        assert_eq!(KerberosTime::from_parts(10000, 1, 1, 0, 0, 0), Err(Error::Time));
        assert_eq!(time("20261005120000Z").to_string(), "20261005120000Z");
        assert!(time("20251231235959Z") < time("20260101000000Z"));
    }

    fn replace(der: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
        let i = der.windows(from.len()).position(|w| w == from).unwrap();
        let mut out = der[..i].to_vec();
        out.extend_from_slice(to);
        out.extend_from_slice(&der[i + from.len()..]);
        out
    }

    #[test]
    fn error_paths() {
        let ap_rep = Message::ApRep(ApRep { enc_part: enc(18, None, &[]) }).to_bytes().unwrap();
        // Wrong version.
        let v4 = replace(&ap_rep, &[0xa0, 0x03, 0x02, 0x01, 0x05], &[0xa0, 0x03, 0x02, 0x01, 0x04]);
        assert_eq!(Message::parse(&v4), Err(Error::Version(4)));
        // msg-type that does not match the tag.
        let t = replace(&ap_rep, &[0xa1, 0x03, 0x02, 0x01, 0x0f], &[0xa1, 0x03, 0x02, 0x01, 0x0e]);
        assert_eq!(Message::parse(&t), Err(Error::MessageType { expected: 15, found: 14 }));
        // Unknown application tag, and a universal one.
        let mut u = ap_rep.clone();
        u[0] = 0x75; // [APPLICATION 21], KRB-PRIV
        assert_eq!(Message::parse(&u), Err(Error::UnknownMessage(21)));
        assert_eq!(Message::parse(&ap_rep[2..]), Err(Error::UnknownMessage(u32::MAX)));
        let mut p = ap_rep.clone();
        p[0] = 0x4f;
        assert_eq!(Message::parse(&p), Err(Error::Asn1(asn1::Error::Primitive)));
        // Trailing bytes, and an empty input.
        let mut tr = ap_rep.clone();
        tr.push(0);
        assert_eq!(Message::parse(&tr), Err(Error::Asn1(asn1::Error::Trailing)));
        assert_eq!(Message::parse(&[]), Err(Error::Asn1(asn1::Error::Empty)));
        // Too long.
        assert_eq!(Message::parse(&vec![0; MAX_MESSAGE + 1]), Err(Error::TooLong));
        // Int32 out of range: etype 2^31.
        let big = [0x30, 0x11, 0xa0, 0x07, 0x02, 0x05, 0x00, 0x80, 0, 0, 0, 0xa2, 0x06, 0x04, 0x04, 0, 0, 0, 0];
        assert_eq!(EncryptedData::parse(&big), Err(Error::Range));
        // UInt32 below -2^31.
        let neg = [
            0x30, 0x12, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x07, 0x02, 0x05, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xa2, 0x02,
            0x04, 0x00,
        ];
        assert_eq!(EncryptedData::parse(&neg), Err(Error::Range));
        // Not UTF-8 in a KerberosString.
        let bad = [0x30, 0x0c, 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, 0x05, 0x30, 0x03, 0x1b, 0x01, 0xff];
        assert_eq!(whole(&bad, Rules::Der, PrincipalName::read), Err(Error::Text));
        // A missing required field.
        let missing = [0x30, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x01];
        assert_eq!(whole(&missing, Rules::Der, PrincipalName::read), Err(Error::Asn1(asn1::Error::Empty)));
        // Fields out of order.
        let swapped = [0x30, 0x09, 0xa1, 0x02, 0x30, 0x00, 0xa0, 0x03, 0x02, 0x01, 0x01];
        assert!(matches!(
            whole(&swapped, Rules::Der, PrincipalName::read),
            Err(Error::Asn1(asn1::Error::Unexpected { .. }))
        ));
        // Two elements inside one explicit tag.
        let two = [0x30, 0x0b, 0xa0, 0x05, 0x02, 0x01, 0x01, 0x05, 0x00, 0xa1, 0x02, 0x30, 0x00];
        assert_eq!(whole(&two, Rules::Der, PrincipalName::read), Err(Error::Asn1(asn1::Error::Trailing)));
        // A primitive explicit tag.
        let prim = [0x30, 0x07, 0x80, 0x01, 0x01, 0xa1, 0x02, 0x30, 0x00];
        assert_eq!(whole(&prim, Rules::Der, PrincipalName::read), Err(Error::Asn1(asn1::Error::Primitive)));
        // A KerberosTime with a fraction.
        let e = krb_error();
        let der = Message::KrbError(e).to_bytes().unwrap();
        let frac = replace(&der, b"\x18\x0f20261005120000Z", b"\x18\x1120261005120000.5Z");
        assert!(Message::parse(&frac).is_err());
        let mut r = Reader::new(b"\x18\x1120261005120000.5Z", Rules::Der);
        assert_eq!(ktime(&mut r), Err(Error::Time));
        // Microseconds out of range.
        let mut r = Reader::new(&[0x02, 0x03, 0x0f, 0x42, 0x40], Rules::Der);
        assert_eq!(microseconds(&mut r), Err(Error::Range));
        let mut r = Reader::new(&[0x02, 0x01, 0xff], Rules::Der);
        assert_eq!(microseconds(&mut r), Err(Error::Range));
        // An integer too big for i64.
        let mut r = Reader::new(&[0x02, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0], Rules::Der);
        assert_eq!(int32(&mut r), Err(Error::Range));
    }

    #[test]
    fn list_limits() {
        let mut n = PrincipalName::new(1, &[]);
        n.components = vec!["a".into(); MAX_NAME_COMPONENTS];
        let mut e = krb_error();
        e.sname = n.clone();
        assert!(Message::KrbError(e.clone()).to_bytes().is_ok());
        n.components.push("a".into());
        e.sname = n.clone();
        assert_eq!(Message::KrbError(e.clone()).to_bytes(), Err(Error::TooMany("name-string")));
        // The parser refuses the same list when it arrives.
        let mut w = Writer::new();
        n.write_fields(&mut w);
        let der = w.finish().unwrap();
        assert_eq!(whole(&der, Rules::Der, PrincipalName::read), Err(Error::TooMany("name-string")));

        let mut r = as_req();
        r.body.etypes = vec![1; MAX_ETYPES + 1];
        assert_eq!(Message::AsReq(r).to_bytes(), Err(Error::TooMany("etype")));
        let mut r = as_req();
        r.body.addresses = Some(vec![HostAddress { addr_type: 2, address: vec![10, 0, 0, 1] }; MAX_ADDRESSES + 1]);
        assert_eq!(Message::AsReq(r).to_bytes(), Err(Error::TooMany("addresses")));
        let mut r = as_req();
        r.body.additional_tickets = Some(vec![tgt(); MAX_TICKETS + 1]);
        assert_eq!(Message::TgsReq(r).to_bytes(), Err(Error::TooMany("additional-tickets")));
        let mut r = as_req();
        r.padata = Some(vec![PaData { padata_type: 2, value: vec![] }; MAX_PADATA + 1]);
        assert_eq!(Message::AsReq(r).to_bytes(), Err(Error::TooMany("padata")));
        let mut e = krb_error();
        e.susec = MAX_MICROSECONDS + 1;
        assert_eq!(Message::KrbError(e).to_bytes(), Err(Error::Range));
        let mut e = krb_error();
        e.cusec = Some(MAX_MICROSECONDS + 1);
        assert_eq!(Message::KrbError(e).to_bytes(), Err(Error::Range));
        // A message over the size limit.
        let big = Message::ApRep(ApRep { enc_part: enc(18, None, &vec![0; MAX_MESSAGE]) });
        assert_eq!(big.to_bytes(), Err(Error::TooLong));
        assert_eq!(Frame(vec![0; MAX_MESSAGE + 1]).to_bytes(), Err(FrameError::TooLong(MAX_MESSAGE as u32 + 1)));
        assert!(Frame(vec![0; MAX_MESSAGE]).to_bytes().is_ok());
    }

    #[test]
    fn values_past_the_asn1_limit_are_too_long() {
        // Past asn1::MAX_INPUT the writer itself stops. That is still a
        // message longer than MAX_MESSAGE, and says so.
        let huge = vec![0; asn1::MAX_INPUT + 1];
        let big = Message::ApRep(ApRep { enc_part: enc(18, None, &huge) });
        assert_eq!(big.to_bytes(), Err(Error::TooLong));
        assert_eq!(enc(18, None, &huge).to_bytes(), Err(Error::TooLong));
        let mut t = tgt();
        t.enc_part.cipher = huge.clone();
        assert_eq!(t.to_bytes(), Err(Error::TooLong));
        let p = PaData { padata_type: 2, value: huge.clone() };
        assert_eq!(MethodData(vec![p]).to_bytes(), Err(Error::TooLong));
        let mut body = as_req().body;
        body.enc_authorization_data = Some(enc(18, None, &huge));
        assert_eq!(body.to_bytes(), Err(Error::TooLong));
    }

    #[test]
    fn a_request_body_reads_on_its_own() {
        let body = as_req().body;
        let der = body.to_bytes().unwrap();
        assert_eq!(KdcReqBody::parse(&der), Ok(body));
        for n in 0..der.len() {
            assert!(KdcReqBody::parse(&der[..n]).is_err());
        }
        let mut tr = der.clone();
        tr.push(0);
        assert_eq!(KdcReqBody::parse(&tr), Err(Error::Asn1(asn1::Error::Trailing)));
        assert_eq!(KdcReqBody::parse(&vec![0; MAX_MESSAGE + 1]), Err(Error::TooLong));
    }

    #[test]
    fn writers_refuse_empty_lists_marked_not_empty() {
        // RFC 4120 section 5.4.1: padata and additional-tickets in a
        // KDC-REQ, and padata in a KDC-REP, are "not empty". Writers
        // refuse them.
        let mut r = as_req();
        r.padata = Some(Vec::new());
        assert_eq!(Message::AsReq(r.clone()).to_bytes(), Err(Error::Empty("padata")));

        let mut r = as_req();
        r.body.additional_tickets = Some(Vec::new());
        assert_eq!(Message::TgsReq(r.clone()).to_bytes(), Err(Error::Empty("additional-tickets")));

        let Message::AsRep(mut rep) = all_messages().swap_remove(1) else { panic!() };
        rep.padata = Some(Vec::new());
        assert_eq!(Message::AsRep(rep.clone()).to_bytes(), Err(Error::Empty("padata")));
        // A reader takes them as absent; see empty_optional_lists_read_as_absent.

        // METHOD-DATA has no such note, so an empty one is fine.
        assert_eq!(MethodData::parse(&MethodData::default().to_bytes().unwrap()), Ok(MethodData::default()));
    }

    #[test]
    fn realms_hold_no_nul() {
        // RFC 4120 section 5.2.2: realms shall not contain a NUL.
        let mut t = tgt();
        t.realm = "EXAMPLE\0COM".into();
        assert_eq!(t.to_bytes(), Err(Error::Text));
        let mut w = Writer::new();
        t.write_fields(&mut w);
        assert_eq!(Ticket::parse(&w.finish().unwrap()), Err(Error::Text));

        let mut e = krb_error();
        e.crealm = Some("A\0".into());
        assert_eq!(Message::KrbError(e.clone()).to_bytes(), Err(Error::Text));
        let mut w = Writer::new();
        w.constructed(Tag::application(30), |w| e.write_fields(w));
        assert_eq!(Message::parse(&w.finish().unwrap()), Err(Error::Text));

        let mut r = as_req();
        r.body.realm = "\0".into();
        assert_eq!(Message::AsReq(r).to_bytes(), Err(Error::Text));
        // A NUL in a name component is not a realm, and is kept.
        let mut e = krb_error();
        e.sname = PrincipalName::new(name_type::PRINCIPAL, &["a\0b"]);
        let m = Message::KrbError(e);
        assert_eq!(Message::parse(&m.to_bytes().unwrap()).unwrap(), m);
    }

    #[test]
    fn a_signed_kvno_near_the_limit_may_not_write_again() {
        // An EncryptedData of exactly MAX_MESSAGE bytes with kvno -1 reads,
        // but its kvno takes 4 more bytes written as a UInt32.
        let head = [0x30, 0x83, 0, 0, 0, 0xa0, 0x03, 0x02, 0x01, 0x12, 0xa1, 0x03, 0x02, 0x01, 0xff];
        let cipher_len = MAX_MESSAGE - head.len() - 2 * 5;
        let mut der = head.to_vec();
        let inner = 5 + cipher_len;
        der.push(0xa2);
        der.extend_from_slice(&[0x83, (inner >> 16) as u8, (inner >> 8) as u8, inner as u8]);
        der.push(0x04);
        der.extend_from_slice(&[0x83, (cipher_len >> 16) as u8, (cipher_len >> 8) as u8, cipher_len as u8]);
        der.resize(der.len() + cipher_len, 0);
        let body = der.len() - 5;
        der[2..5].copy_from_slice(&[(body >> 16) as u8, (body >> 8) as u8, body as u8]);
        assert_eq!(der.len(), MAX_MESSAGE);
        assert_eq!(EncryptedData::parse(&der), Err(Error::TooLong));
        assert_eq!(check_any(&der), 0);
    }

    #[test]
    fn every_truncated_prefix_fails() {
        for m in all_messages() {
            let der = m.to_bytes().unwrap();
            for n in 0..der.len() {
                assert!(Message::parse(&der[..n]).is_err(), "{n} of {}", der.len());
                assert!(Message::parse_with(&der[..n], Rules::Ber).is_err());
            }
            let tcp = Frame(m.to_bytes().unwrap()).to_bytes().unwrap();
            for n in 0..tcp.len() {
                let mut d = Stream::new(Frames::new());
                assert_eq!(d.push(&tcp[..n]), n);
                assert_eq!(d.next(), None);
                assert_eq!(d.buffered(), n);
            }
        }
    }

    #[test]
    fn ber_is_read_when_asked() {
        // The AP-REP from above with indefinite lengths on the outer two
        // elements.
        #[rustfmt::skip]
        let ber = [
            0x6f, 0x80, 0x30, 0x80,
            0xa0, 0x03, 0x02, 0x01, 0x05,
            0xa1, 0x03, 0x02, 0x01, 0x0f,
            0xa2, 0x0b, 0x30, 0x09,
            0xa0, 0x03, 0x02, 0x01, 0x12,
            0xa2, 0x02, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(Message::parse(&ber), Err(Error::Asn1(asn1::Error::Indefinite)));
        let m = Message::parse_with(&ber, Rules::Ber).unwrap();
        assert_eq!(Message::parse(&m.to_bytes().unwrap()).unwrap(), m);
    }

    #[test]
    fn decoder_splits_a_stream() {
        let msgs = all_messages();
        let stream: Vec<u8> = msgs.iter().flat_map(|m| Frame(m.to_bytes().unwrap()).to_bytes().unwrap()).collect();
        let mut d = Stream::new(Frames::new());
        let mut got = Vec::new();
        for b in chunks(&stream, &[1]) {
            assert_eq!(d.push(b), (b).len());
            while let Some(m) = d.next() {
                got.push(Message::parse(&m.unwrap()).unwrap());
            }
        }
        assert_eq!(got, msgs);
        assert_eq!(d.buffered(), 0);
        // A zero-length record is passed on, and fails to parse.
        assert_eq!(d.push(&[0, 0, 0, 0]), 4);
        assert_eq!(d.next(), Some(Ok(Vec::new())));
        // The reserved bit breaks the stream for good.
        assert_eq!(d.push(&[0x80, 0, 0, 1, 0]), 5);
        assert_eq!(d.next(), Some(Err(Fail::Protocol(FrameError::Reserved(0x8000_0001)))));
        assert_eq!(d.push(&stream), stream.len());
        assert_eq!(d.next(), None);
        assert_eq!(d.failed(), Some(&Fail::Protocol(FrameError::Reserved(0x8000_0001))));
        // So does a length over the limit, known before the body comes.
        let mut d = Stream::new(Frames::new());
        let over = (MAX_MESSAGE as u32 + 1).to_be_bytes();
        assert_eq!(d.push(&over), over.len());
        assert_eq!(d.next(), Some(Err(Fail::Protocol(FrameError::TooLong(MAX_MESSAGE as u32 + 1)))));
        assert!(!FrameError::TooLong(1).to_string().is_empty());
    }

    #[test]
    fn decoder_takes_many_small_messages_in_linear_time() {
        let one = Frame(Message::ApRep(ApRep { enc_part: enc(18, None, &[]) }).to_bytes().unwrap()).to_bytes().unwrap();
        let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * 100_000).collect();
        let mut d = Stream::new(Frames::new());
        let mut n = 0;
        pump(&mut d, &stream, |_| n += 1).unwrap();
        finish_stream(&mut d, |_| n += 1).unwrap();
        assert_eq!(n, 100_000);
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn stream_stops_after_a_bad_header() {
        let one = Frame(Message::ApRep(ApRep { enc_part: enc(18, None, &[]) }).to_bytes().unwrap()).to_bytes().unwrap();
        let mut bytes = one.repeat(2);
        bytes.extend_from_slice(&(MAX_MESSAGE as u32 + 1).to_be_bytes());
        bytes.extend_from_slice(&[0; 1000]);
        contract::check_decode_with_alloc_limit(Frames::new, &bytes, 2 * (TCP_HEADER_LEN + MAX_MESSAGE));
        let mut stream = Stream::new(Frames::new());
        let mut got = Vec::new();
        assert_eq!(
            pump(&mut stream, &bytes, |m| got.push(m)),
            Err(Fail::Protocol(FrameError::TooLong(MAX_MESSAGE as u32 + 1)))
        );
        assert_eq!(got, [one[4..].to_vec(), one[4..].to_vec()]);
        let held = stream.buffered();
        assert_eq!(stream.push(&one), one.len());
        assert_eq!(stream.buffered(), held);
        assert_eq!(stream.next(), None);
        let mut stream = Stream::new(Frames::new());
        assert_eq!(stream.push(&[0x80, 0]), 2);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.push(&[0, 5]), 2);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(FrameError::Reserved(0x8000_0005)))));
    }

    #[test]
    fn a_drained_decoder_lets_go_of_a_large_buffer() {
        let big =
            Frame(Message::ApRep(ApRep { enc_part: enc(18, None, &vec![0; MAX_MESSAGE - 100]) }).to_bytes().unwrap())
                .to_bytes()
                .unwrap();
        let mut d = Stream::new(Frames::new());
        let mut count = 0;
        pump(&mut d, &big, |_| count += 1).unwrap();
        pump(&mut d, &big, |_| count += 1).unwrap();
        finish_stream(&mut d, |_| count += 1).unwrap();
        assert_eq!(count, 2);
        assert_eq!(d.buffered(), 0);
        assert!(d.into_parts().0.allocated() <= MAX_MESSAGE + TCP_HEADER_LEN);
    }

    #[test]
    fn empty_optional_lists_read_as_absent() {
        // RFC 4120 section 5.1.3: an empty optional SEQUENCE OF means the
        // same as an absent one. Senders should not send one, and
        // receivers should take it as absent.
        let mut r = as_req();
        r.padata = Some(Vec::new());
        r.body.addresses = Some(Vec::new());
        r.body.additional_tickets = Some(Vec::new());
        let mut w = Writer::new();
        w.constructed(Tag::application(12), |w| r.write_fields(w, msg_type::TGS_REQ));
        let Message::TgsReq(got) = Message::parse(&w.finish().unwrap()).unwrap() else { panic!() };
        assert_eq!(got.padata, None);
        assert_eq!(got.body.addresses, None);
        assert_eq!(got.body.additional_tickets, None);

        let Message::AsRep(mut rep) = all_messages().swap_remove(1) else { panic!() };
        rep.padata = Some(Vec::new());
        let mut w = Writer::new();
        w.constructed(Tag::application(11), |w| rep.write_fields(w, msg_type::AS_REP));
        let Message::AsRep(got) = Message::parse(&w.finish().unwrap()).unwrap() else { panic!() };
        assert_eq!(got.padata, None);

        // Writers leave them out instead: an empty list is an error.
        let mut r = as_req();
        r.body.addresses = Some(Vec::new());
        assert_eq!(Message::AsReq(r.clone()).to_bytes(), Err(Error::Empty("addresses")));
        assert_eq!(r.body.to_bytes(), Err(Error::Empty("addresses")));
    }

    #[test]
    fn a_request_body_comes_back_as_sent() {
        // A checksum over a TGS-REQ's body covers the bytes the client
        // sent. Here a ticket in it holds a kvno written as a signed -1,
        // which DER writes back longer, so only the bytes as sent will do.
        let mut r = as_req();
        r.padata = Some(vec![PaData { padata_type: padata_type::TGS_REQ, value: vec![1, 2, 3] }]);
        let der = Message::TgsReq(r).to_bytes().unwrap();
        let sent = replace(&der, &[0xa1, 0x03, 0x02, 0x01, 0x02], &[0xa1, 0x03, 0x02, 0x01, 0xff]);
        let Message::TgsReq(got) = Message::parse(&sent).unwrap() else { panic!() };
        assert_eq!(got.body.additional_tickets.as_ref().unwrap()[0].enc_part.kvno, Some(u32::MAX));
        let body = Message::kdc_req_body(&sent, Rules::Der).unwrap();
        assert_ne!(body, got.body.to_bytes().unwrap());
        assert_eq!(KdcReqBody::parse(body), Ok(got.body.clone()));
        assert!(sent.windows(body.len()).any(|w| w == body));
        assert_eq!(body[0], 0x30);
        // The same under BER, with the body's indefinite length kept.
        let ber = [0x6a, 0x80, 0x30, 0x80, 0xa1, 0x03, 0x02, 0x01, 0x05, 0xa2, 0x03, 0x02, 0x01, 0x0a, 0xa4, 0x80];
        let mut ber = ber.to_vec();
        let plain = as_req().body.to_bytes().unwrap();
        let mut indef = vec![0x30, 0x80];
        // The body is long enough for a 2-byte length: 0x30 0x82 hi lo.
        assert_eq!(plain[1], 0x82);
        indef.extend_from_slice(&plain[4..]);
        indef.extend_from_slice(&[0, 0]);
        ber.extend_from_slice(&indef);
        ber.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        assert_eq!(Message::kdc_req_body(&ber, Rules::Ber), Ok(&indef[..]));
        // Other messages, and bytes that are not a message, have none.
        let rep = all_messages().swap_remove(1).to_bytes().unwrap();
        assert_eq!(Message::kdc_req_body(&rep, Rules::Der), Err(Error::UnknownMessage(11)));
        assert!(Message::kdc_req_body(&sent[..sent.len() - 1], Rules::Der).is_err());
    }

    #[test]
    fn host_addresses_have_their_types_form() {
        // RFC 4120 section 7.1.
        let with = |a: HostAddress| {
            let mut r = as_req();
            r.body.addresses = Some(vec![a]);
            r
        };
        let mut v6 = [0u8; 16];
        v6[0] = 0x20;
        v6[1] = 0x01;
        v6[15] = 7;
        let mut mapped = [0u8; 16];
        mapped[10..].copy_from_slice(&[0xff, 0xff, 10, 0, 0, 1]);
        let mut link_local = [0u8; 16];
        link_local[..2].copy_from_slice(&[0xfe, 0x80]);
        link_local[15] = 1;
        let mut loopback = [0u8; 16];
        loopback[15] = 1;
        let good = [
            HostAddress { addr_type: HostAddress::IPV4, address: vec![192, 0, 2, 1] },
            HostAddress { addr_type: HostAddress::IPV6, address: v6.to_vec() },
            // A NetBIOS name, and a local type, hold any bytes.
            HostAddress { addr_type: 20, address: b"HOST            ".to_vec() },
            HostAddress { addr_type: -1, address: vec![] },
        ];
        for a in good {
            let m = Message::AsReq(with(a));
            assert_eq!(Message::parse(&m.to_bytes().unwrap()), Ok(m));
        }
        let bad = [
            HostAddress { addr_type: HostAddress::IPV4, address: vec![1] },
            HostAddress { addr_type: HostAddress::IPV4, address: vec![1, 2, 3, 4, 5] },
            HostAddress { addr_type: HostAddress::IPV6, address: vec![0x20; 4] },
            HostAddress { addr_type: HostAddress::IPV6, address: vec![0; 16] },
            HostAddress { addr_type: HostAddress::IPV6, address: loopback.to_vec() },
            HostAddress { addr_type: HostAddress::IPV6, address: link_local.to_vec() },
            HostAddress { addr_type: HostAddress::IPV6, address: mapped.to_vec() },
        ];
        for a in bad {
            let r = with(a.clone());
            assert_eq!(Message::AsReq(r.clone()).to_bytes(), Err(Error::Address), "{a:?}");
            assert_eq!(r.body.to_bytes(), Err(Error::Address));
            // The reader refuses the same address when it arrives.
            let mut w = Writer::new();
            w.constructed(Tag::application(10), |w| r.write_fields(w, msg_type::AS_REQ));
            assert_eq!(Message::parse(&w.finish().unwrap()), Err(Error::Address), "{a:?}");
        }
    }

    #[test]
    fn errors_display() {
        for e in [
            Error::Asn1(asn1::Error::Truncated),
            Error::UnknownMessage(3),
            Error::Version(4),
            Error::MessageType { expected: 1, found: 2 },
            Error::Range,
            Error::TooMany("x"),
            Error::Empty("x"),
            Error::Text,
            Error::Time,
            Error::TooLong,
            Error::Address,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    /// Checks what can be read from `data` writes back, and returns how
    /// many messages it read.
    fn check_any(data: &[u8]) -> usize {
        let mut read = 0;
        for rules in [Rules::Der, Rules::Ber] {
            if let Ok(m) = Message::parse_with(data, rules) {
                read += 1;
                // Written again, a message near the limit may grow past it.
                match m.to_bytes() {
                    Ok(der) => assert_eq!(Message::parse(&der).unwrap(), m),
                    Err(e) => assert_eq!(e, Error::TooLong),
                }
            }
        }
        contract::check_wire::<Ticket>(data);
        contract::check_wire::<EncryptedData>(data);
        contract::check_wire::<KdcReqBody>(data);
        contract::check_wire::<MethodData>(data);
        contract::check_decode_with_alloc_limit(Frames::new, data, 2 * (TCP_HEADER_LEN + MAX_MESSAGE));
        contract::check_wire::<Message>(data);
        read
    }

    #[test]
    fn fuzz_loop() {
        let mut rng = Lcg::new(0x6b65_7262_6572_6f73);
        let mut seeds: Vec<Vec<u8>> = all_messages().iter().map(|m| m.to_bytes().unwrap()).collect();
        seeds.push(as_req().body.to_bytes().unwrap());
        seeds.push(tgt().to_bytes().unwrap());
        let mut read = 0;
        for i in 0..6000 {
            let data = if i % 3 == 0 {
                // Random bytes, sometimes behind a plausible header.
                let mut d = rng.bytes(199);
                if i % 2 == 0 && d.len() >= 2 {
                    d[0] = 0x60 | [10, 11, 12, 13, 14, 15, 30][rng.index(7)];
                }
                d
            } else {
                // A real message with a few bytes changed, cut or added.
                let mut d = seeds[rng.index(seeds.len())].clone();
                for _ in 0..1 + rng.index(4) {
                    mutate(&mut rng, &mut d);
                }
                d
            };
            read += check_any(&data);
            if let Ok(f) = Frame(data.clone()).to_bytes() {
                check_any(&f);
                let mut d = Stream::new(Frames::new());
                for part in chunks(&f, &[1]) {
                    assert_eq!(d.push(part), part.len());
                }
                assert_eq!(d.next(), Some(Ok(data.clone())));
            }
        }
        // Some changed messages still read, so the round trip is tested.
        assert!(read > 50, "only {read} read");
    }

    #[test]
    fn codec_frames_bound_input_and_keep_empty_records() {
        use super::super::codec::{Decode, Fail, Stream, Wire, contract};
        assert_eq!(Frames::new().capacity(), TCP_HEADER_LEN + MAX_MESSAGE);
        let frame = Frame(vec![9; MAX_MESSAGE]);
        let bytes = <Frame as Wire>::to_bytes(&frame).unwrap();
        let mut stream = Stream::new(Frames::new());
        assert_eq!(stream.push(&bytes), bytes.len());
        assert_eq!(stream.push(&[0]), 0);
        assert_eq!(stream.next(), Some(Ok(frame.0)));
        contract::check_decode_with_alloc_limit(Frames::new, &[0, 0, 0, 0, 0x80, 0, 0, 0], 2 * (TCP_HEADER_LEN + MAX_MESSAGE));
        assert_eq!(stream.push(&[0x80, 0, 0, 0]), 4);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(FrameError::Reserved(0x8000_0000)))));
        assert_eq!(stream.next(), None);
        contract::check_wire_value(&Frame(Vec::new()));
    }

    #[test]
    fn codec_writers_are_exact_and_transactional() {
        use super::super::codec::{Wire, contract};
        for message in all_messages() {
            contract::check_wire_value(&message);
            contract::check_wire::<Message>(&message.to_bytes().unwrap());
        }
        let mut out = vec![42];
        let oversized = Frame(vec![0; MAX_MESSAGE + 1]);
        assert!(oversized.write(&mut out).is_err());
        assert_eq!(out, [42]);
        assert_eq!(<Frame as Wire>::parse(&[0, 0, 0, 0, 0]), Err(FrameParseError::Trailing));
        assert_eq!(<Frame as Wire>::parse(&[0, 0, 0, 1]), Err(FrameParseError::Truncated));
        let mut request = as_req();
        request.padata = Some(Vec::new());
        // Optional empty lists are refused without changing the destination.
        let message = Message::AsReq(request);
        assert!(message.to_bytes().is_err());
        assert_eq!(message.write(&mut out), Err(Error::Empty("padata")));
        assert_eq!(out, [42]);
    }

    #[test]
    fn codec_wire_parse_refuses_reencoding_past_the_limit() {
        use super::super::codec::Wire;
        let build = |cipher_len| {
            let mut w = Writer::new();
            w.constructed(Tag::application(15), |w| {
                w.sequence(|w| {
                    w_int(w, 0, PVNO);
                    w_int(w, 1, msg_type::AP_REP);
                    w.explicit(2, |w| {
                        w.sequence(|w| {
                            w_int(w, 0, 18);
                            w_int(w, 1, -1); // Accepted as UInt32::MAX; DER expands it.
                            w.explicit(2, |w| w.octet_string(&vec![0; cipher_len]));
                        });
                    });
                });
            });
            w.finish().unwrap()
        };
        let payload_len = MAX_MESSAGE - 100;
        let overhead = build(payload_len).len() - payload_len;
        let bytes = build(MAX_MESSAGE - overhead);
        assert_eq!(bytes.len(), MAX_MESSAGE);
        assert_eq!(Message::parse(&bytes), Err(Error::TooLong));
        contract::check_wire::<Message>(&bytes);
    }
}
