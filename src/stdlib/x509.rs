//! X.509 certificates and CRLs: reading them into their parts and writing
//! them back, with PEM, and with no I/O.
//!
//! A certificate binds a public key to a name. An issuer signs a
//! TBSCertificate (the part "to be signed") that holds a serial number,
//! the issuer's and subject's names, a validity period, the subject's
//! public key and a list of extensions. A certificate revocation list
//! (CRL) is a signed list of the serial numbers an issuer has revoked.
//! Both are DER, and both usually travel as PEM text or inside TLS, LDAP
//! and S/MIME. This module follows RFC 5280, writes names as RFC 4514
//! text, and reads and writes PEM as RFC 7468 describes.
//!
//! Nothing here reads a socket, and nothing here checks a signature. A
//! world that plays a server builds a [`TbsCertificate`], signs its bytes
//! with its own code, and joins them with [`Certificate::assemble`]. A
//! world that reads certificates the agent sends parses them with
//! [`Certificate::parse`] or [`Certificate::from_pem`], and reads the
//! common extensions with [`TbsCertificate::get`]. Whether a certificate
//! is trusted, and what its signature proves, is up to world code. The
//! bytes the signature covers are kept as they came, in
//! [`Certificate::tbs_der`].
//!
//! Every reader holds input to DER through [`asn1`], and
//! checks lengths, counts and versions, because the agent can send any
//! bytes it likes. Every list has a named limit, such as
//! [`MAX_EXTENSIONS`]. Every writer reads its own output back before it
//! returns it, so it never returns bytes a reader here refuses.
//!
//! Readers relax a few rules that real certificates break. A field
//! written out at its default value (a critical flag or a cA flag of
//! FALSE, a certificate version of v1) is read, and left out when written
//! again. A key usage or reason bit string may end in zero bits. A time
//! may be a GeneralizedTime before 2050 or have a fraction of a second. A
//! CRL may hold an empty list of revoked certificates. Serial numbers may
//! be negative or longer than 20 bytes.
//!
//! ```
//! use fictionet::stdlib::asn1::{BitString, Oid, StringKind};
//! use fictionet::stdlib::x509::{
//!     AlgorithmIdentifier, BasicConstraints, Certificate, ExtensionValue, GeneralName, Name, PublicKeyInfo,
//!     SubjectAltName, TbsCertificate, Time, Validity, Value, Version, oid,
//! };
//!
//! let id = |b: &[u8]| Oid::from_contents(b).unwrap();
//! let ecdsa_sha256 = AlgorithmIdentifier { oid: id(oid::ECDSA_WITH_SHA256), parameters: None };
//! let mut name = Name::default();
//! name.push(id(oid::COUNTRY), Value::Text { kind: StringKind::Printable, text: "US".into() });
//! name.push(id(oid::COMMON_NAME), Value::Text { kind: StringKind::Utf8, text: "www.example.com".into() });
//! // An uncompressed P-256 point, with the named curve as the parameter.
//! let p256 = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
//! let mut point = vec![0x04];
//! point.extend_from_slice(&[0x11; 64]);
//! let tbs = TbsCertificate {
//!     version: Version::V3,
//!     serial: vec![0x12, 0x34],
//!     signature: ecdsa_sha256.clone(),
//!     issuer: name.clone(),
//!     // 2025-01-01 and 2035-01-01, midnight UTC.
//!     validity: Validity {
//!         not_before: Time::from_unix(1_735_689_600).unwrap(),
//!         not_after: Time::from_unix(2_051_222_400).unwrap(),
//!     },
//!     subject: name,
//!     public_key: PublicKeyInfo {
//!         algorithm: AlgorithmIdentifier { oid: id(oid::EC_PUBLIC_KEY), parameters: Some(p256) },
//!         key: BitString::new(point, 0).unwrap(),
//!     },
//!     issuer_unique_id: None,
//!     subject_unique_id: None,
//!     extensions: vec![
//!         BasicConstraints { ca: false, path_len: None }.to_extension(true).unwrap(),
//!         SubjectAltName(vec![GeneralName::Dns("www.example.com".into())]).to_extension(false).unwrap(),
//!     ],
//! };
//! let tbs_der = tbs.to_der().unwrap();
//! // The world signs `tbs_der` with its own key. These bytes stand in for
//! // the signature.
//! let signature = BitString::new(vec![0x30, 0x00], 0).unwrap();
//! let cert = Certificate::assemble(&tbs_der, ecdsa_sha256, signature).unwrap();
//! let pem = cert.to_pem().unwrap();
//! assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
//!
//! // What a client reads back.
//! let back = Certificate::from_pem(pem.as_bytes()).unwrap();
//! assert_eq!(back.tbs_der, tbs_der);
//! assert_eq!(back.tbs.subject.to_string(), "CN=www.example.com,C=US");
//! assert_eq!(back.tbs.validity.not_after.text(), "350101000000Z");
//! let san = back.tbs.get::<SubjectAltName>().unwrap().unwrap();
//! assert_eq!(san.0, [GeneralName::Dns("www.example.com".into())]);
//! ```

use super::asn1::{self, BitString, Class, Element, Oid, Reader, Rules, StringKind, Tag, Writer};
use std::fmt;
use std::fmt::Write as _;

/// The longest certificate, in DER bytes, a reader accepts.
pub const MAX_CERT: usize = 64 * 1024;
/// The longest CRL, in DER bytes, a reader accepts.
pub const MAX_CRL: usize = asn1::MAX_INPUT;
/// The most relative distinguished names (the parts between commas) one
/// name may have.
pub const MAX_RDNS: usize = 64;
/// The most attributes one relative distinguished name may have.
pub const MAX_RDN_ATTRIBUTES: usize = 16;
/// The most extensions one certificate, CRL or CRL entry may have.
pub const MAX_EXTENSIONS: usize = 64;
/// The most general names one list of them may have, as in a subject
/// alternative name extension.
pub const MAX_GENERAL_NAMES: usize = 1024;
/// The most key purposes an extended key usage extension may list.
pub const MAX_KEY_PURPOSES: usize = 64;
/// The most distribution points a CRL distribution points extension may
/// list.
pub const MAX_DISTRIBUTION_POINTS: usize = 32;
/// The most access descriptions an authority information access extension
/// may list.
pub const MAX_ACCESS_DESCRIPTIONS: usize = 32;
/// The most revoked certificates one CRL may list.
pub const MAX_REVOKED: usize = 65_536;
/// Values kept as raw DER ([`Value::Raw`], algorithm parameters, other
/// names) are checked as if nested this deep, so a writer can place them
/// anywhere a certificate or extension holds them.
pub const RAW_CHECK_DEPTH: usize = 8;
/// The most bytes one PEM block may decode to.
pub const MAX_PEM_DATA: usize = asn1::MAX_INPUT;
/// The longest line, in bytes, PEM text may have.
pub const MAX_PEM_LINE: usize = 64 * 1024;
/// The longest PEM label, such as `CERTIFICATE`.
pub const MAX_PEM_LABEL: usize = 64;
/// The most blocks [`pem_decode`] returns from one text.
pub const MAX_PEM_BLOCKS: usize = 256;
/// The PEM label of a certificate.
pub const PEM_CERTIFICATE: &str = "CERTIFICATE";
/// The PEM label of a CRL.
pub const PEM_CRL: &str = "X509 CRL";

/// Object identifiers this module and its callers use, as contents bytes.
/// Compare one with [`Oid::as_bytes`], and build an [`Oid`] from one with
/// [`Oid::from_contents`].
pub mod oid {
    /// 2.5.4.3, commonName (CN).
    pub const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
    /// 2.5.4.4, surname.
    pub const SURNAME: &[u8] = &[0x55, 0x04, 0x04];
    /// 2.5.4.5, serialNumber.
    pub const SERIAL_NUMBER: &[u8] = &[0x55, 0x04, 0x05];
    /// 2.5.4.6, countryName (C).
    pub const COUNTRY: &[u8] = &[0x55, 0x04, 0x06];
    /// 2.5.4.7, localityName (L).
    pub const LOCALITY: &[u8] = &[0x55, 0x04, 0x07];
    /// 2.5.4.8, stateOrProvinceName (ST).
    pub const STATE: &[u8] = &[0x55, 0x04, 0x08];
    /// 2.5.4.9, streetAddress (STREET).
    pub const STREET: &[u8] = &[0x55, 0x04, 0x09];
    /// 2.5.4.10, organizationName (O).
    pub const ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0a];
    /// 2.5.4.11, organizationalUnitName (OU).
    pub const ORGANIZATIONAL_UNIT: &[u8] = &[0x55, 0x04, 0x0b];
    /// 0.9.2342.19200300.100.1.25, domainComponent (DC).
    pub const DOMAIN_COMPONENT: &[u8] = &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19];
    /// 0.9.2342.19200300.100.1.1, userId (UID).
    pub const USER_ID: &[u8] = &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01];
    /// 1.2.840.113549.1.9.1, emailAddress.
    pub const EMAIL_ADDRESS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01];

    /// 2.5.29.14, the subject key identifier extension.
    pub const SUBJECT_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x0e];
    /// 2.5.29.15, the key usage extension.
    pub const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
    /// 2.5.29.17, the subject alternative name extension.
    pub const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
    /// 2.5.29.18, the issuer alternative name extension.
    pub const ISSUER_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x12];
    /// 2.5.29.19, the basic constraints extension.
    pub const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
    /// 2.5.29.20, the CRL number extension.
    pub const CRL_NUMBER: &[u8] = &[0x55, 0x1d, 0x14];
    /// 2.5.29.21, the CRL entry's reason code extension.
    pub const REASON_CODE: &[u8] = &[0x55, 0x1d, 0x15];
    /// 2.5.29.31, the CRL distribution points extension.
    pub const CRL_DISTRIBUTION_POINTS: &[u8] = &[0x55, 0x1d, 0x1f];
    /// 2.5.29.32, the certificate policies extension.
    pub const CERTIFICATE_POLICIES: &[u8] = &[0x55, 0x1d, 0x20];
    /// 2.5.29.35, the authority key identifier extension.
    pub const AUTHORITY_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x23];
    /// 2.5.29.37, the extended key usage extension.
    pub const EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
    /// 1.3.6.1.5.5.7.1.1, the authority information access extension.
    pub const AUTHORITY_INFO_ACCESS: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];

    /// 1.3.6.1.5.5.7.3.1, the key purpose of a TLS server.
    pub const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    /// 1.3.6.1.5.5.7.3.2, the key purpose of a TLS client.
    pub const CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
    /// 1.3.6.1.5.5.7.3.3, the key purpose of code signing.
    pub const CODE_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
    /// 1.3.6.1.5.5.7.3.4, the key purpose of signed or encrypted email.
    pub const EMAIL_PROTECTION: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04];
    /// 1.3.6.1.5.5.7.3.8, the key purpose of time stamping.
    pub const TIME_STAMPING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];
    /// 1.3.6.1.5.5.7.3.9, the key purpose of signing OCSP responses.
    pub const OCSP_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];

    /// 1.3.6.1.5.5.7.48.1, the access method of an OCSP responder.
    pub const OCSP: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
    /// 1.3.6.1.5.5.7.48.2, the access method of the issuer's certificate.
    pub const CA_ISSUERS: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02];

    /// 1.2.840.113549.1.1.1, an RSA public key.
    pub const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    /// 1.2.840.113549.1.1.11, an RSA signature over SHA-256.
    pub const SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    /// 1.2.840.10045.2.1, an elliptic curve public key.
    pub const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    /// 1.2.840.10045.3.1.7, the P-256 curve.
    pub const PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    /// 1.2.840.10045.4.3.2, an ECDSA signature over SHA-256.
    pub const ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    /// 1.3.101.112, an Ed25519 key or signature.
    pub const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
}

/// Why bytes are not the certificate, CRL, extension or PEM a reader
/// asked for, or why a writer could not write a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The DER is malformed, or does not have the shape RFC 5280 gives it.
    Asn1(asn1::Error),
    /// The input is longer than its limit: [`MAX_CERT`], [`MAX_CRL`],
    /// [`MAX_PEM_DATA`] or [`MAX_PEM_LINE`].
    TooLong,
    /// A list is longer than its limit, such as [`MAX_EXTENSIONS`].
    TooMany,
    /// An unknown version number, or a field the version does not allow:
    /// unique identifiers in a v1 certificate, extensions in a certificate
    /// before v3, or extensions in a v1 CRL.
    Version,
    /// The signature algorithm outside the TBS part differs from the one
    /// inside it.
    SignatureMismatch,
    /// Two extensions in one list have the same identifier.
    DuplicateExtension,
    /// A list RFC 5280 says holds at least one item holds none.
    Empty,
    /// A value outside what the field allows: an unknown general name
    /// tag, a named bit past the 16 this module keeps, a time outside the
    /// years 1950 to 9999.
    Value,
    /// PEM text is malformed: a bad base64 line, a block with no end, or
    /// an end line whose label does not match.
    Pem,
    /// The PEM text holds no block with the label asked for.
    NoBlock,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Asn1(e) => write!(f, "DER: {e}"),
            Error::TooLong => f.write_str("input longer than its limit"),
            Error::TooMany => f.write_str("list longer than its limit"),
            Error::Version => f.write_str("unknown version, or a field the version does not allow"),
            Error::SignatureMismatch => f.write_str("outer and inner signature algorithms differ"),
            Error::DuplicateExtension => f.write_str("extension appears twice"),
            Error::Empty => f.write_str("list that needs an item is empty"),
            Error::Value => f.write_str("value outside what the field allows"),
            Error::Pem => f.write_str("malformed PEM"),
            Error::NoBlock => f.write_str("no PEM block with that label"),
        }
    }
}

impl std::error::Error for Error {}

impl From<asn1::Error> for Error {
    fn from(e: asn1::Error) -> Error {
        Error::Asn1(e)
    }
}

/// Adds `item` to `list`, unless the list already holds `max` items.
fn push_limited<T>(list: &mut Vec<T>, item: T, max: usize) -> Result<(), Error> {
    if list.len() >= max {
        return Err(Error::TooMany);
    }
    list.push(item);
    Ok(())
}

/// The one element `der` holds, read under DER.
fn single(der: &[u8]) -> Result<Element<'_>, Error> {
    let mut r = Reader::new(der, Rules::Der);
    let e = r.read()?;
    r.finish()?;
    Ok(e)
}

/// A reader over the children of the one SEQUENCE `der` holds.
fn top_sequence(der: &[u8]) -> Result<Reader<'_>, Error> {
    let mut r = Reader::new(der, Rules::Der);
    let s = r.read_sequence()?;
    r.finish()?;
    Ok(s)
}

/// Runs `f` on a fresh writer and returns what it wrote.
fn build(f: impl FnOnce(&mut Writer)) -> Result<Vec<u8>, Error> {
    let mut w = Writer::new();
    f(&mut w);
    Ok(w.finish()?)
}

/// Checks `raw` is one DER element a writer could copy at
/// [`RAW_CHECK_DEPTH`].
fn check_raw(raw: &[u8]) -> Result<(), Error> {
    fn wrap(w: &mut Writer, n: usize, raw: &[u8]) {
        if n == 0 {
            w.encoded(raw);
        } else {
            w.sequence(|w| wrap(w, n - 1, raw));
        }
    }
    build(|w| wrap(w, RAW_CHECK_DEPTH, raw)).map(drop)
}

/// The version of a certificate or CRL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Version {
    /// Version 1 (number 0): no unique identifiers and no extensions.
    V1,
    /// Version 2 (number 1): unique identifiers in a certificate, and
    /// extensions in a CRL.
    V2,
    /// Version 3 (number 2): extensions in a certificate. CRLs have no v3.
    V3,
}

impl Version {
    /// The number written for the version: one less than its name.
    pub fn number(self) -> i64 {
        match self {
            Version::V1 => 0,
            Version::V2 => 1,
            Version::V3 => 2,
        }
    }

    /// The version a number stands for.
    pub fn from_number(n: i64) -> Result<Version, Error> {
        match n {
            0 => Ok(Version::V1),
            1 => Ok(Version::V2),
            2 => Ok(Version::V3),
            _ => Err(Error::Version),
        }
    }
}

/// An algorithm and its parameters, as a signature or a public key names
/// them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AlgorithmIdentifier {
    /// The algorithm, such as [`oid::ECDSA_WITH_SHA256`].
    pub oid: Oid,
    /// The parameters as one DER element, if any: `05 00` (NULL) for
    /// most RSA algorithms, a curve's identifier for an EC key.
    pub parameters: Option<Vec<u8>>,
}

fn read_alg(r: &mut Reader<'_>) -> Result<AlgorithmIdentifier, Error> {
    let mut s = r.read_sequence()?;
    let oid = s.read_oid()?;
    let parameters = if s.is_empty() {
        None
    } else {
        let e = s.read()?;
        check_raw(e.raw())?;
        Some(e.raw().to_vec())
    };
    s.finish()?;
    Ok(AlgorithmIdentifier { oid, parameters })
}

fn write_alg(w: &mut Writer, a: &AlgorithmIdentifier) {
    w.sequence(|w| {
        w.oid(&a.oid);
        if let Some(p) = &a.parameters {
            w.encoded(p);
        }
    });
}

/// One attribute value in a name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Value {
    /// A string of a type [`asn1`] decodes, such as a
    /// UTF8String or PrintableString, with the type it had.
    Text {
        /// The string type.
        kind: StringKind,
        /// The text.
        text: String,
    },
    /// Any other value, such as a TeletexString or an OCTET STRING, as
    /// one DER element.
    Raw(Vec<u8>),
}

impl Value {
    /// The text, for a [`Value::Text`].
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text { text, .. } => Some(text),
            Value::Raw(_) => None,
        }
    }

    /// The value as one DER element.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        build(|w| write_value(w, self))
    }
}

fn read_value(e: &Element<'_>) -> Result<Value, Error> {
    if let Some(kind) = StringKind::from_tag(e.tag()).filter(|k| k.is_decoded()) {
        return Ok(Value::Text { kind, text: e.text(kind)? });
    }
    check_raw(e.raw())?;
    Ok(Value::Raw(e.raw().to_vec()))
}

fn write_value(w: &mut Writer, v: &Value) {
    match v {
        Value::Text { kind, text } => w.text(*kind, text),
        Value::Raw(raw) => w.encoded(raw),
    }
}

/// One attribute of a name: a type, such as [`oid::COMMON_NAME`], and a
/// value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Attribute {
    /// The attribute type.
    pub oid: Oid,
    /// The value.
    pub value: Value,
}

/// A distinguished name: a sequence of relative distinguished names,
/// each a set of attributes, most general first (country before common
/// name). Its `Display` is the RFC 4514 text, which lists them the other
/// way round, such as `CN=www.example.com,O=Example Corp,C=US`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Name {
    /// The relative distinguished names, in the order they are encoded.
    /// A writer puts the attributes of each in DER order.
    pub rdns: Vec<Vec<Attribute>>,
}

impl Name {
    /// Adds a relative distinguished name of one attribute at the end
    /// (the most specific place).
    pub fn push(&mut self, oid: Oid, value: Value) {
        self.rdns.push(vec![Attribute { oid, value }]);
    }

    /// The first value of the attribute type `oid` (contents bytes, as in
    /// [`oid`]), in encoding order.
    pub fn find(&self, oid: &[u8]) -> Option<&Value> {
        self.rdns.iter().flatten().find(|a| a.oid.as_bytes() == oid).map(|a| &a.value)
    }

    /// The text of the last common name, the most specific one.
    pub fn common_name(&self) -> Option<&str> {
        self.rdns
            .iter()
            .flatten()
            .filter(|a| a.oid.as_bytes() == oid::COMMON_NAME)
            .filter_map(|a| a.value.as_text())
            .next_back()
    }

    /// Reads a name from its DER.
    pub fn from_der(der: &[u8]) -> Result<Name, Error> {
        let mut r = Reader::new(der, Rules::Der);
        let n = read_name(&mut r)?;
        r.finish()?;
        Ok(n)
    }

    /// The name's DER, as an issuer or subject field holds it.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let der = build(|w| write_name(w, self))?;
        Name::from_der(&der)?;
        Ok(der)
    }
}

fn read_name(r: &mut Reader<'_>) -> Result<Name, Error> {
    let mut seq = r.read_sequence()?;
    let mut rdns = Vec::new();
    while !seq.is_empty() {
        let set = seq.read_set_of()?;
        push_limited(&mut rdns, read_rdn(set)?, MAX_RDNS)?;
    }
    Ok(Name { rdns })
}

/// Reads the attributes of a relative distinguished name: a SET OF, with
/// at least one.
fn read_rdn(mut r: Reader<'_>) -> Result<Vec<Attribute>, Error> {
    let mut attrs = Vec::new();
    while !r.is_empty() {
        let mut s = r.read_sequence()?;
        let oid = s.read_oid()?;
        let value = read_value(&s.read()?)?;
        s.finish()?;
        push_limited(&mut attrs, Attribute { oid, value }, MAX_RDN_ATTRIBUTES)?;
    }
    if attrs.is_empty() {
        return Err(Error::Empty);
    }
    Ok(attrs)
}

fn write_rdn(w: &mut Writer, attrs: &[Attribute]) {
    w.set_of(|w| {
        for a in attrs {
            w.sequence(|w| {
                w.oid(&a.oid);
                write_value(w, &a.value);
            });
        }
    });
}

fn write_name(w: &mut Writer, n: &Name) {
    w.sequence(|w| {
        for rdn in &n.rdns {
            write_rdn(w, rdn);
        }
    });
}

/// The short name RFC 4514 section 3 gives an attribute type, if any.
fn short_name(oid: &[u8]) -> Option<&'static str> {
    Some(match oid {
        oid::COMMON_NAME => "CN",
        oid::LOCALITY => "L",
        oid::STATE => "ST",
        oid::ORGANIZATION => "O",
        oid::ORGANIZATIONAL_UNIT => "OU",
        oid::COUNTRY => "C",
        oid::STREET => "STREET",
        oid::DOMAIN_COMPONENT => "DC",
        oid::USER_ID => "UID",
        _ => return None,
    })
}

fn push_hex(out: &mut String, b: &[u8]) {
    for byte in b {
        let _ = write!(out, "{byte:02x}");
    }
}

/// Appends `s` as an RFC 4514 attribute value, with the characters
/// section 2.4 names escaped, and control characters as hex pairs.
fn escape_value(out: &mut String, s: &str) {
    for (i, c) in s.char_indices() {
        let first = i == 0;
        let last = i + c.len_utf8() == s.len();
        match c {
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            ' ' if first || last => out.push_str("\\ "),
            '#' if first => out.push_str("\\#"),
            c if c < ' ' || c == '\x7f' => {
                let _ = write!(out, "\\{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

fn write_attribute(out: &mut String, a: &Attribute) {
    match (short_name(a.oid.as_bytes()), &a.value) {
        (Some(short), Value::Text { text, .. }) => {
            out.push_str(short);
            out.push('=');
            escape_value(out, text);
        }
        (short, value) => {
            match short {
                Some(s) => out.push_str(s),
                None => {
                    let _ = write!(out, "{}", a.oid);
                }
            }
            out.push('=');
            match value.to_der() {
                Ok(der) => {
                    out.push('#');
                    push_hex(out, &der);
                }
                // A value no writer can encode is shown as text.
                Err(_) => escape_value(out, value.as_text().unwrap_or("")),
            }
        }
    }
}

impl fmt::Display for Name {
    /// The RFC 4514 text: relative distinguished names last first, joined
    /// by `,`, and the attributes of each joined by `+`. Types with a
    /// short name in section 3 use it, with their value as text. Other
    /// types are written in dotted decimal, with their value as `#` and
    /// the hex of its DER, as section 2.4 requires.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::new();
        for (i, rdn) in self.rdns.iter().rev().enumerate() {
            if i > 0 {
                out.push(',');
            }
            for (j, a) in rdn.iter().enumerate() {
                if j > 0 {
                    out.push('+');
                }
                write_attribute(&mut out, a);
            }
        }
        f.write_str(&out)
    }
}

/// A point in time, as a certificate writes it: a UTCTime for the years
/// 1950 to 2049, and a GeneralizedTime otherwise (RFC 5280 4.1.2.5).
/// [`Time::from_unix`] gives only those forms. Readers also take a
/// GeneralizedTime for an earlier year, and one with a fraction of a
/// second, which RFC 5280 forbids.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Time {
    /// A UTCTime, such as `"250101000000Z"`.
    Utc(String),
    /// A GeneralizedTime, such as `"20500101000000Z"`.
    Generalized(String),
}

/// The first and last seconds [`Time::from_unix`] takes: the start of
/// 1950 and the end of 9999.
const UNIX_RANGE: std::ops::RangeInclusive<i64> = -631_152_000..=253_402_300_799;

impl Time {
    /// The time `secs` seconds after 1970-01-01 00:00:00 UTC, in the form
    /// RFC 5280 asks for. Times before 1950 or after 9999 are
    /// [`Error::Value`].
    pub fn from_unix(secs: i64) -> Result<Time, Error> {
        if !UNIX_RANGE.contains(&secs) {
            return Err(Error::Value);
        }
        let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
        let rem = secs.rem_euclid(86_400);
        let (hh, mm, ss) = (rem / 3600, rem % 3600 / 60, rem % 60);
        Ok(if y < 2050 {
            Time::Utc(format!("{:02}{m:02}{d:02}{hh:02}{mm:02}{ss:02}Z", y % 100))
        } else {
            Time::Generalized(format!("{y:04}{m:02}{d:02}{hh:02}{mm:02}{ss:02}Z"))
        })
    }

    /// The text.
    pub fn text(&self) -> &str {
        match self {
            Time::Utc(s) | Time::Generalized(s) => s,
        }
    }

    /// Seconds since 1970-01-01 00:00:00 UTC, with any fraction dropped.
    /// A UTCTime's two-digit years 50 to 99 are 19xx, the rest 20xx. Text
    /// not in the form DER allows gives `None`.
    pub fn unix(&self) -> Option<i64> {
        let (year, rest) = match self {
            Time::Utc(s) => {
                let b = s.as_bytes();
                if b.len() != 13 || b[12] != b'Z' {
                    return None;
                }
                let yy = digits(b, 0, 2)?;
                (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &b[2..12])
            }
            Time::Generalized(s) => {
                let b = s.as_bytes();
                if b.len() < 15 || b.last() != Some(&b'Z') {
                    return None;
                }
                // Nothing but `Z`, or a fraction and `Z`, after the seconds.
                let tail = &b[14..b.len() - 1];
                if let Some((&dot, frac)) = tail.split_first()
                    && (dot != b'.' || frac.is_empty() || !frac.iter().all(u8::is_ascii_digit))
                {
                    return None;
                }
                (digits(b, 0, 4)?, &b[4..14])
            }
        };
        let (month, day) = (digits(rest, 0, 2)?, digits(rest, 2, 2)?);
        let (hour, minute, second) = (digits(rest, 4, 2)?, digits(rest, 6, 2)?, digits(rest, 8, 2)?);
        if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
            return None;
        }
        if hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
    }
}

/// The number written in `b[i..i + n]`, if all of them are digits.
fn digits(b: &[u8], i: usize, n: usize) -> Option<i64> {
    let s = b.get(i..i.checked_add(n)?)?;
    s.iter().try_fold(0i64, |v, &c| c.is_ascii_digit().then(|| v * 10 + i64::from(c - b'0')))
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a date in the proleptic Gregorian calendar.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date `z` days after 1970-01-01. `z` is within [`UNIX_RANGE`].
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn read_time(r: &mut Reader<'_>) -> Result<Time, Error> {
    let tag = r.peek()?.tag();
    if tag.same_type(Tag::UTC_TIME) {
        Ok(Time::Utc(r.read_utc_time()?))
    } else if tag.same_type(Tag::GENERALIZED_TIME) {
        Ok(Time::Generalized(r.read_generalized_time()?))
    } else {
        Err(asn1::Error::Unexpected { expected: Tag::UTC_TIME, found: tag }.into())
    }
}

fn is_time(r: &Reader<'_>) -> bool {
    r.peek().is_ok_and(|e| e.tag().same_type(Tag::UTC_TIME) || e.tag().same_type(Tag::GENERALIZED_TIME))
}

fn write_time(w: &mut Writer, t: &Time) {
    match t {
        Time::Utc(s) => w.utc_time(s),
        Time::Generalized(s) => w.generalized_time(s),
    }
}

/// When a certificate may be used: from `not_before` to `not_after`, both
/// included.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Validity {
    /// The first moment the certificate is valid.
    pub not_before: Time,
    /// The last moment the certificate is valid.
    pub not_after: Time,
}

impl Validity {
    /// Whether the time `secs` seconds after the Unix epoch falls in the
    /// period. A time whose text cannot be read gives `false`.
    pub fn contains(&self, secs: i64) -> bool {
        match (self.not_before.unix(), self.not_after.unix()) {
            (Some(a), Some(b)) => a <= secs && secs <= b,
            _ => false,
        }
    }
}

/// A subject's public key and the algorithm it is for.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicKeyInfo {
    /// The key's algorithm and parameters, such as
    /// [`oid::EC_PUBLIC_KEY`] with a curve.
    pub algorithm: AlgorithmIdentifier,
    /// The key, in the algorithm's own encoding.
    pub key: BitString<'static>,
}

impl PublicKeyInfo {
    /// The SubjectPublicKeyInfo's DER.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let der = build(|w| write_spki(w, self))?;
        PublicKeyInfo::from_der(&der)?;
        Ok(der)
    }

    /// Reads a SubjectPublicKeyInfo from its DER.
    pub fn from_der(der: &[u8]) -> Result<PublicKeyInfo, Error> {
        let mut r = Reader::new(der, Rules::Der);
        let k = read_spki(&mut r)?;
        r.finish()?;
        Ok(k)
    }
}

fn read_spki(r: &mut Reader<'_>) -> Result<PublicKeyInfo, Error> {
    let mut s = r.read_sequence()?;
    let algorithm = read_alg(&mut s)?;
    let key = s.read_bit_string()?.into_owned();
    s.finish()?;
    Ok(PublicKeyInfo { algorithm, key })
}

fn write_spki(w: &mut Writer, k: &PublicKeyInfo) {
    w.sequence(|w| {
        write_alg(w, &k.algorithm);
        w.bit_string_value(&k.key);
    });
}

/// One extension: its identifier, whether a reader that does not know it
/// must refuse the certificate, and its value's DER.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Extension {
    /// The extension's identifier, such as [`oid::SUBJECT_ALT_NAME`].
    pub oid: Oid,
    /// Whether the extension is critical. A reader takes an explicit
    /// FALSE, and a writer leaves FALSE out, as DER requires.
    pub critical: bool,
    /// The value's DER: the contents of the extnValue OCTET STRING. Read
    /// it with the matching [`ExtensionValue`] type.
    pub value: Vec<u8>,
}

/// Reads an Extensions list: at least one, at most [`MAX_EXTENSIONS`],
/// with no identifier twice.
fn read_extensions(r: &mut Reader<'_>) -> Result<Vec<Extension>, Error> {
    let mut seq = r.read_sequence()?;
    let mut list: Vec<Extension> = Vec::new();
    while !seq.is_empty() {
        let mut s = seq.read_sequence()?;
        let oid = s.read_oid()?;
        let critical = match s.read_optional(Tag::BOOLEAN)? {
            Some(e) => e.boolean()?,
            None => false,
        };
        let value = s.read_octet_string()?.into_owned();
        s.finish()?;
        if list.iter().any(|x| x.oid == oid) {
            return Err(Error::DuplicateExtension);
        }
        push_limited(&mut list, Extension { oid, critical, value }, MAX_EXTENSIONS)?;
    }
    // Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension.
    if list.is_empty() {
        return Err(Error::Empty);
    }
    Ok(list)
}

fn write_extensions(w: &mut Writer, list: &[Extension]) {
    w.sequence(|w| {
        for x in list {
            w.sequence(|w| {
                w.oid(&x.oid);
                if x.critical {
                    w.boolean(true);
                }
                w.octet_string(&x.value);
            });
        }
    });
}

/// The extension in `list` with the identifier `oid`.
fn find_extension<'a>(list: &'a [Extension], oid: &[u8]) -> Option<&'a Extension> {
    list.iter().find(|x| x.oid.as_bytes() == oid)
}

/// The typed value of the extension `T` in `list`, if it is there.
fn get_extension<T: ExtensionValue>(list: &[Extension]) -> Result<Option<T>, Error> {
    find_extension(list, T::OID).map(|x| T::from_der(&x.value)).transpose()
}

/// An extension's value, read and written with its own type.
pub trait ExtensionValue: Sized {
    /// The extension's identifier, as contents bytes.
    const OID: &'static [u8];

    /// Reads the value from an extension's [`Extension::value`].
    fn from_der(der: &[u8]) -> Result<Self, Error>;

    /// The value's DER. It reads back with [`ExtensionValue::from_der`].
    fn to_der(&self) -> Result<Vec<u8>, Error>;

    /// An extension holding this value.
    fn to_extension(&self, critical: bool) -> Result<Extension, Error> {
        Ok(Extension { oid: Oid::from_contents(Self::OID)?, critical, value: self.to_der()? })
    }
}

/// Checks `der` reads back as a `T`, and returns it.
fn verified<T: ExtensionValue>(der: Vec<u8>) -> Result<Vec<u8>, Error> {
    T::from_der(&der)?;
    Ok(der)
}

/// Reads named bits (X.680 22.7) into a `u16`: bit `i` of the string is
/// `1 << i`. A set bit past 15 is [`Error::Value`].
fn read_bits(b: &BitString<'_>) -> Result<u16, Error> {
    let mut v = 0u16;
    for i in 0..b.len() {
        if b.bit(i) == Some(true) {
            if i >= 16 {
                return Err(Error::Value);
            }
            v |= 1 << i;
        }
    }
    Ok(v)
}

/// Writes named bits, without trailing zero bits, as DER requires
/// (X.690 11.2.2).
fn write_bits(w: &mut Writer, v: u16) {
    let n = 16 - v.leading_zeros() as usize;
    let mut bytes = vec![0u8; n.div_ceil(8)];
    for i in 0..n {
        if v & (1 << i) != 0 {
            bytes[i / 8] |= 0x80 >> (i % 8);
        }
    }
    let unused = (bytes.len() * 8 - n) as u8;
    w.bit_string(&bytes, unused);
}

/// The basic constraints extension (RFC 5280 4.2.1.9): whether the
/// subject is a CA, and how many CAs may follow it in a chain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BasicConstraints {
    /// Whether the subject is a certificate authority.
    pub ca: bool,
    /// The most intermediate CA certificates that may follow this one.
    pub path_len: Option<u64>,
}

impl ExtensionValue for BasicConstraints {
    const OID: &'static [u8] = oid::BASIC_CONSTRAINTS;

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let mut s = top_sequence(der)?;
        let ca = match s.read_optional(Tag::BOOLEAN)? {
            Some(e) => e.boolean()?,
            None => false,
        };
        let path_len = if s.is_empty() { None } else { Some(s.read_u64()?) };
        s.finish()?;
        Ok(BasicConstraints { ca, path_len })
    }

    fn to_der(&self) -> Result<Vec<u8>, Error> {
        verified::<Self>(build(|w| {
            w.sequence(|w| {
                if self.ca {
                    w.boolean(true);
                }
                if let Some(n) = self.path_len {
                    w.integer_u64(n);
                }
            })
        })?)
    }
}

/// The key usage extension (RFC 5280 4.2.1.3): what the key may be used
/// for. Bit `i` of the named bit string is `1 << i` here. A reader takes
/// trailing zero bits, which DER leaves out (X.690 11.2.2), and a writer
/// leaves them out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct KeyUsage(pub u16);

impl KeyUsage {
    /// Signatures other than on certificates and CRLs.
    pub const DIGITAL_SIGNATURE: u16 = 1 << 0;
    /// Signatures that bind the signer to content (nonRepudiation).
    pub const CONTENT_COMMITMENT: u16 = 1 << 1;
    /// Encrypting keys, as RSA key transport does.
    pub const KEY_ENCIPHERMENT: u16 = 1 << 2;
    /// Encrypting data directly.
    pub const DATA_ENCIPHERMENT: u16 = 1 << 3;
    /// Key agreement, as ECDH does.
    pub const KEY_AGREEMENT: u16 = 1 << 4;
    /// Signing certificates.
    pub const KEY_CERT_SIGN: u16 = 1 << 5;
    /// Signing CRLs.
    pub const CRL_SIGN: u16 = 1 << 6;
    /// With key agreement, only encrypting.
    pub const ENCIPHER_ONLY: u16 = 1 << 7;
    /// With key agreement, only decrypting.
    pub const DECIPHER_ONLY: u16 = 1 << 8;

    /// Whether every bit in `bits` is set.
    pub fn contains(self, bits: u16) -> bool {
        self.0 & bits == bits
    }
}

impl ExtensionValue for KeyUsage {
    const OID: &'static [u8] = oid::KEY_USAGE;

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(der, Rules::Der);
        let b = r.read_bit_string()?;
        r.finish()?;
        Ok(KeyUsage(read_bits(&b)?))
    }

    fn to_der(&self) -> Result<Vec<u8>, Error> {
        verified::<Self>(build(|w| write_bits(w, self.0))?)
    }
}

/// The extended key usage extension (RFC 5280 4.2.1.12): the purposes
/// the key may be used for, such as [`oid::SERVER_AUTH`]. It lists at
/// least one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ExtendedKeyUsage(pub Vec<Oid>);

impl ExtendedKeyUsage {
    /// Whether the purpose `oid` (contents bytes) is listed.
    pub fn contains(&self, oid: &[u8]) -> bool {
        self.0.iter().any(|o| o.as_bytes() == oid)
    }
}

impl ExtensionValue for ExtendedKeyUsage {
    const OID: &'static [u8] = oid::EXTENDED_KEY_USAGE;

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let mut s = top_sequence(der)?;
        let mut list = Vec::new();
        while !s.is_empty() {
            push_limited(&mut list, s.read_oid()?, MAX_KEY_PURPOSES)?;
        }
        if list.is_empty() {
            return Err(Error::Empty);
        }
        Ok(ExtendedKeyUsage(list))
    }

    fn to_der(&self) -> Result<Vec<u8>, Error> {
        verified::<Self>(build(|w| {
            w.sequence(|w| {
                for o in &self.0 {
                    w.oid(o);
                }
            })
        })?)
    }
}

/// A general name (RFC 5280 4.2.1.6): one of the forms a subject or
/// issuer may be named by besides its distinguished name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum GeneralName {
    /// `[0]` otherName: a type and a value as one DER element.
    Other {
        /// The type of name.
        type_id: Oid,
        /// The value, as one DER element.
        value: Vec<u8>,
    },
    /// `[1]` rfc822Name: an email address.
    Email(String),
    /// `[2]` dNSName: a host name, such as `www.example.com` or
    /// `*.example.com`.
    Dns(String),
    /// `[4]` directoryName: a distinguished name.
    Directory(Name),
    /// `[6]` uniformResourceIdentifier: a URI.
    Uri(String),
    /// `[7]` iPAddress: 4 bytes for IPv4, 16 for IPv6. Name constraints
    /// use 8 and 32, an address and a mask, so any length is kept.
    Ip(Vec<u8>),
    /// `[8]` registeredID: an object identifier.
    RegisteredId(Oid),
    /// `[3]` x400Address or `[5]` ediPartyName, kept as one DER element.
    Unsupported(Vec<u8>),
}

impl GeneralName {
    /// The address of an [`GeneralName::Ip`] of 4 or 16 bytes.
    pub fn ip_addr(&self) -> Option<std::net::IpAddr> {
        let GeneralName::Ip(b) = self else { return None };
        if let Ok(a) = <[u8; 4]>::try_from(b.as_slice()) {
            return Some(a.into());
        }
        <[u8; 16]>::try_from(b.as_slice()).ok().map(Into::into)
    }
}

fn read_general_name(e: &Element<'_>) -> Result<GeneralName, Error> {
    let t = e.tag();
    if t.class != Class::ContextSpecific {
        return Err(Error::Value);
    }
    Ok(match t.number {
        0 => {
            let mut s = e.reader()?;
            let type_id = s.read_oid()?;
            let mut v = s.read_explicit(0)?;
            let value = v.read()?;
            v.finish()?;
            s.finish()?;
            check_raw(value.raw())?;
            GeneralName::Other { type_id, value: value.raw().to_vec() }
        }
        1 => GeneralName::Email(e.text(StringKind::Ia5)?),
        2 => GeneralName::Dns(e.text(StringKind::Ia5)?),
        3 | 5 => {
            if !t.constructed {
                return Err(asn1::Error::Primitive.into());
            }
            check_raw(e.raw())?;
            GeneralName::Unsupported(e.raw().to_vec())
        }
        4 => {
            let mut s = e.reader()?;
            let n = read_name(&mut s)?;
            s.finish()?;
            GeneralName::Directory(n)
        }
        6 => GeneralName::Uri(e.text(StringKind::Ia5)?),
        7 => GeneralName::Ip(e.octet_string()?.into_owned()),
        8 => GeneralName::RegisteredId(e.oid()?),
        _ => return Err(Error::Value),
    })
}

fn write_general_name(w: &mut Writer, g: &GeneralName) {
    match g {
        GeneralName::Other { type_id, value } => w.constructed(Tag::context(0), |w| {
            w.oid(type_id);
            w.explicit(0, |w| w.encoded(value));
        }),
        GeneralName::Email(s) => w.implicit(Tag::context(1), |w| w.text(StringKind::Ia5, s)),
        GeneralName::Dns(s) => w.implicit(Tag::context(2), |w| w.text(StringKind::Ia5, s)),
        GeneralName::Directory(n) => w.explicit(4, |w| write_name(w, n)),
        GeneralName::Uri(s) => w.implicit(Tag::context(6), |w| w.text(StringKind::Ia5, s)),
        GeneralName::Ip(b) => w.primitive(Tag::context(7), b),
        GeneralName::RegisteredId(o) => w.implicit(Tag::context(8), |w| w.oid(o)),
        GeneralName::Unsupported(raw) => w.encoded(raw),
    }
}

/// Reads GeneralNames: at least one, at most [`MAX_GENERAL_NAMES`].
fn read_general_names(mut r: Reader<'_>) -> Result<Vec<GeneralName>, Error> {
    let mut list = Vec::new();
    while !r.is_empty() {
        let e = r.read()?;
        push_limited(&mut list, read_general_name(&e)?, MAX_GENERAL_NAMES)?;
    }
    if list.is_empty() {
        return Err(Error::Empty);
    }
    Ok(list)
}

fn write_general_names(w: &mut Writer, list: &[GeneralName]) {
    for g in list {
        write_general_name(w, g);
    }
}

/// Reads one SEQUENCE OF GeneralName that fills `der`.
fn general_names_from_der(der: &[u8]) -> Result<Vec<GeneralName>, Error> {
    read_general_names(top_sequence(der)?)
}

/// The subject alternative name extension (RFC 5280 4.2.1.6): the host
/// names, addresses and other names the certificate is for. It lists at
/// least one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SubjectAltName(pub Vec<GeneralName>);

impl ExtensionValue for SubjectAltName {
    const OID: &'static [u8] = oid::SUBJECT_ALT_NAME;

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        general_names_from_der(der).map(SubjectAltName)
    }

    fn to_der(&self) -> Result<Vec<u8>, Error> {
        verified::<Self>(build(|w| w.sequence(|w| write_general_names(w, &self.0)))?)
    }
}

/// The subject key identifier extension (RFC 5280 4.2.1.2): bytes that
/// name the subject's key, often a hash of it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SubjectKeyIdentifier(pub Vec<u8>);

impl ExtensionValue for SubjectKeyIdentifier {
    const OID: &'static [u8] = oid::SUBJECT_KEY_IDENTIFIER;

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(der, Rules::Der);
        let id = r.read_octet_string()?.into_owned();
        r.finish()?;
        Ok(SubjectKeyIdentifier(id))
    }

    fn to_der(&self) -> Result<Vec<u8>, Error> {
        verified::<Self>(build(|w| w.octet_string(&self.0))?)
    }
}

/// The authority key identifier extension (RFC 5280 4.2.1.1): which key
/// of the issuer signed the certificate or CRL.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct AuthorityKeyIdentifier {
    /// `[0]` the issuer's subject key identifier.
    pub key_id: Option<Vec<u8>>,
    /// `[1]` the names of the issuer's issuer.
    pub issuer: Option<Vec<GeneralName>>,
    /// `[2]` the serial number of the issuer's certificate, as
    /// two's-complement bytes. A writer drops leading bytes that do not
    /// change the value.
    pub serial: Option<Vec<u8>>,
}

impl ExtensionValue for AuthorityKeyIdentifier {
    const OID: &'static [u8] = oid::AUTHORITY_KEY_IDENTIFIER;

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let mut s = top_sequence(der)?;
        let key_id = s.read_optional(Tag::context(0))?.map(|e| e.octet_string().map(|b| b.into_owned())).transpose()?;
        let issuer = s.read_optional(Tag::context(1))?.map(|e| read_general_names(e.reader()?)).transpose()?;
        let serial =
            s.read_optional(Tag::context(2))?.map(|e| e.integer().map(|i| i.as_bytes().to_vec())).transpose()?;
        s.finish()?;
        Ok(AuthorityKeyIdentifier { key_id, issuer, serial })
    }

    fn to_der(&self) -> Result<Vec<u8>, Error> {
        verified::<Self>(build(|w| {
            w.sequence(|w| {
                if let Some(id) = &self.key_id {
                    w.primitive(Tag::context(0), id);
                }
                if let Some(names) = &self.issuer {
                    w.constructed(Tag::context(1), |w| write_general_names(w, names));
                }
                if let Some(serial) = &self.serial {
                    w.implicit(Tag::context(2), |w| w.integer_bytes(serial));
                }
            })
        })?)
    }
}

/// Reasons a CRL may cover (RFC 5280 4.2.1.13). Bit `i` of the named bit
/// string is `1 << i` here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ReasonFlags(pub u16);

impl ReasonFlags {
    /// The key was compromised.
    pub const KEY_COMPROMISE: u16 = 1 << 1;
    /// The CA's key was compromised.
    pub const CA_COMPROMISE: u16 = 1 << 2;
    /// The subject's name or other details changed.
    pub const AFFILIATION_CHANGED: u16 = 1 << 3;
    /// The certificate was replaced.
    pub const SUPERSEDED: u16 = 1 << 4;
    /// The certificate is no longer needed.
    pub const CESSATION_OF_OPERATION: u16 = 1 << 5;
    /// The certificate is on hold.
    pub const CERTIFICATE_HOLD: u16 = 1 << 6;
    /// A privilege in the certificate was withdrawn.
    pub const PRIVILEGE_WITHDRAWN: u16 = 1 << 7;
    /// An attribute authority's key was compromised.
    pub const AA_COMPROMISE: u16 = 1 << 8;
}

/// Where a distribution point is: a list of names, or a name relative to
/// the CRL issuer's.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DistributionPointName {
    /// `[0]` fullName: general names, usually one URI.
    Full(Vec<GeneralName>),
    /// `[1]` nameRelativeToCRLIssuer: a relative distinguished name to add
    /// to the CRL issuer's name.
    RelativeToIssuer(Vec<Attribute>),
}

/// One CRL distribution point (RFC 5280 4.2.1.13).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DistributionPoint {
    /// Where the CRL is.
    pub name: Option<DistributionPointName>,
    /// The reasons the CRL covers, if not all of them.
    pub reasons: Option<ReasonFlags>,
    /// Who signs the CRL, if not the certificate's issuer.
    pub crl_issuer: Option<Vec<GeneralName>>,
}

fn read_distribution_point(mut s: Reader<'_>) -> Result<DistributionPoint, Error> {
    let name = match s.read_optional(Tag::context(0))? {
        Some(e) => {
            let mut inner = e.reader()?;
            let c = inner.read()?;
            inner.finish()?;
            let t = c.tag();
            Some(match (t.class, t.number) {
                (Class::ContextSpecific, 0) => DistributionPointName::Full(read_general_names(c.reader()?)?),
                (Class::ContextSpecific, 1) => DistributionPointName::RelativeToIssuer(read_rdn(c.set_of_reader()?)?),
                _ => return Err(Error::Value),
            })
        }
        None => None,
    };
    let reasons = s
        .read_optional(Tag::context(1))?
        .map(|e| e.bit_string().map_err(Error::from).and_then(|b| read_bits(&b)))
        .transpose()?
        .map(ReasonFlags);
    let crl_issuer = s.read_optional(Tag::context(2))?.map(|e| read_general_names(e.reader()?)).transpose()?;
    s.finish()?;
    Ok(DistributionPoint { name, reasons, crl_issuer })
}

fn write_distribution_point(w: &mut Writer, p: &DistributionPoint) {
    w.sequence(|w| {
        match &p.name {
            Some(DistributionPointName::Full(names)) => {
                w.explicit(0, |w| w.constructed(Tag::context(0), |w| write_general_names(w, names)));
            }
            Some(DistributionPointName::RelativeToIssuer(attrs)) => {
                w.explicit(0, |w| w.implicit(Tag::context(1), |w| write_rdn(w, attrs)));
            }
            None => {}
        }
        if let Some(r) = p.reasons {
            w.implicit(Tag::context(1), |w| write_bits(w, r.0));
        }
        if let Some(names) = &p.crl_issuer {
            w.constructed(Tag::context(2), |w| write_general_names(w, names));
        }
    });
}

/// The CRL distribution points extension (RFC 5280 4.2.1.13): where to
/// fetch the CRLs that cover the certificate. It lists at least one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CrlDistributionPoints(pub Vec<DistributionPoint>);

impl ExtensionValue for CrlDistributionPoints {
    const OID: &'static [u8] = oid::CRL_DISTRIBUTION_POINTS;

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let mut s = top_sequence(der)?;
        let mut list = Vec::new();
        while !s.is_empty() {
            push_limited(&mut list, read_distribution_point(s.read_sequence()?)?, MAX_DISTRIBUTION_POINTS)?;
        }
        if list.is_empty() {
            return Err(Error::Empty);
        }
        Ok(CrlDistributionPoints(list))
    }

    fn to_der(&self) -> Result<Vec<u8>, Error> {
        verified::<Self>(build(|w| {
            w.sequence(|w| {
                for p in &self.0 {
                    write_distribution_point(w, p);
                }
            })
        })?)
    }
}

/// One way to reach information about the issuer: a method, such as
/// [`oid::OCSP`] or [`oid::CA_ISSUERS`], and a location, usually a URI.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AccessDescription {
    /// What the location offers.
    pub method: Oid,
    /// Where it is.
    pub location: GeneralName,
}

/// The authority information access extension (RFC 5280 4.2.2.1): where
/// the issuer's OCSP responder and certificate are. It lists at least
/// one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct AuthorityInfoAccess(pub Vec<AccessDescription>);

impl ExtensionValue for AuthorityInfoAccess {
    const OID: &'static [u8] = oid::AUTHORITY_INFO_ACCESS;

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let mut s = top_sequence(der)?;
        let mut list = Vec::new();
        while !s.is_empty() {
            let mut d = s.read_sequence()?;
            let method = d.read_oid()?;
            let location = read_general_name(&d.read()?)?;
            d.finish()?;
            push_limited(&mut list, AccessDescription { method, location }, MAX_ACCESS_DESCRIPTIONS)?;
        }
        if list.is_empty() {
            return Err(Error::Empty);
        }
        Ok(AuthorityInfoAccess(list))
    }

    fn to_der(&self) -> Result<Vec<u8>, Error> {
        verified::<Self>(build(|w| {
            w.sequence(|w| {
                for d in &self.0 {
                    w.sequence(|w| {
                        w.oid(&d.method);
                        write_general_name(w, &d.location);
                    });
                }
            })
        })?)
    }
}

/// The issuer alternative name extension (RFC 5280 4.2.1.7): other names
/// for the issuer, in the same form as [`SubjectAltName`]. It lists at
/// least one. Certificates and CRLs may both carry it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct IssuerAltName(pub Vec<GeneralName>);

impl ExtensionValue for IssuerAltName {
    const OID: &'static [u8] = oid::ISSUER_ALT_NAME;

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        general_names_from_der(der).map(IssuerAltName)
    }

    fn to_der(&self) -> Result<Vec<u8>, Error> {
        verified::<Self>(build(|w| w.sequence(|w| write_general_names(w, &self.0)))?)
    }
}

/// The CRL number extension (RFC 5280 5.2.3): a number that grows with
/// each CRL an issuer makes. It is held as two's-complement bytes, most
/// significant first, since RFC 5280 allows up to 20 of them. It is never
/// negative.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CrlNumber(pub Vec<u8>);

impl CrlNumber {
    /// The CRL number `n`.
    pub fn from_u64(n: u64) -> CrlNumber {
        let mut b = vec![0];
        b.extend_from_slice(&n.to_be_bytes());
        CrlNumber(minimal_int(&b).to_vec())
    }

    /// The number, if it fits in a `u64`.
    pub fn to_u64(&self) -> Option<u64> {
        asn1::Integer::from_bytes(minimal_int(&self.0)).ok()?.to_u64()
    }
}

impl ExtensionValue for CrlNumber {
    const OID: &'static [u8] = oid::CRL_NUMBER;

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(der, Rules::Der);
        let n = r.read_integer()?;
        r.finish()?;
        if n.is_negative() {
            return Err(Error::Value);
        }
        Ok(CrlNumber(n.as_bytes().to_vec()))
    }

    fn to_der(&self) -> Result<Vec<u8>, Error> {
        verified::<Self>(build(|w| w.integer_bytes(&self.0))?)
    }
}

/// The reason code CRL entry extension (RFC 5280 5.3.1): why a
/// certificate was revoked. Read it with [`RevokedCertificate::get`]. The
/// values are those of the CRLReason ENUMERATED. Value 7 is not used, and
/// a reader or writer refuses it and any value past 10 with
/// [`Error::Value`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CrlReason(pub u8);

impl CrlReason {
    /// No reason given.
    pub const UNSPECIFIED: u8 = 0;
    /// The key was compromised.
    pub const KEY_COMPROMISE: u8 = 1;
    /// The CA's key was compromised.
    pub const CA_COMPROMISE: u8 = 2;
    /// The subject's name or other details changed.
    pub const AFFILIATION_CHANGED: u8 = 3;
    /// The certificate was replaced.
    pub const SUPERSEDED: u8 = 4;
    /// The certificate is no longer needed.
    pub const CESSATION_OF_OPERATION: u8 = 5;
    /// The certificate is on hold.
    pub const CERTIFICATE_HOLD: u8 = 6;
    /// A delta CRL takes the certificate off hold.
    pub const REMOVE_FROM_CRL: u8 = 8;
    /// A privilege in the certificate was withdrawn.
    pub const PRIVILEGE_WITHDRAWN: u8 = 9;
    /// An attribute authority's key was compromised.
    pub const AA_COMPROMISE: u8 = 10;
}

impl ExtensionValue for CrlReason {
    const OID: &'static [u8] = oid::REASON_CODE;

    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(der, Rules::Der);
        let n = r.read_enumerated()?;
        r.finish()?;
        match n.to_i64() {
            Some(v @ (0..=6 | 8..=10)) => Ok(CrlReason(v as u8)),
            _ => Err(Error::Value),
        }
    }

    fn to_der(&self) -> Result<Vec<u8>, Error> {
        verified::<Self>(build(|w| w.enumerated(i64::from(self.0)))?)
    }
}

/// `b`, a two's-complement integer, without the leading bytes that do
/// not change its value. An empty slice stays empty.
fn minimal_int(b: &[u8]) -> &[u8] {
    let mut b = b;
    while let [first, second, ..] = b {
        if (*first == 0 && second & 0x80 == 0) || (*first == 0xff && second & 0x80 != 0) {
            b = &b[1..];
        } else {
            break;
        }
    }
    b
}

/// The part of a certificate its issuer signs (RFC 5280 4.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TbsCertificate {
    /// The version. Extensions need [`Version::V3`]; unique identifiers
    /// need v2 or v3.
    pub version: Version,
    /// The serial number, as two's-complement bytes, most significant
    /// first. RFC 5280 asks for a positive number of at most 20 bytes.
    /// Readers here accept any. A writer drops leading bytes that do not
    /// change the value, so `00 05` reads back as `05`.
    pub serial: Vec<u8>,
    /// The signature algorithm. It must match
    /// [`Certificate::signature_algorithm`].
    pub signature: AlgorithmIdentifier,
    /// Who signed the certificate.
    pub issuer: Name,
    /// When the certificate may be used.
    pub validity: Validity,
    /// Who the certificate is for. It may be empty when a subject
    /// alternative name says who.
    pub subject: Name,
    /// The subject's public key.
    pub public_key: PublicKeyInfo,
    /// `[1]` the issuer's unique identifier, which RFC 5280 says not to
    /// write.
    pub issuer_unique_id: Option<BitString<'static>>,
    /// `[2]` the subject's unique identifier, which RFC 5280 says not to
    /// write.
    pub subject_unique_id: Option<BitString<'static>>,
    /// The extensions, in order. Read the common ones with
    /// [`TbsCertificate::get`].
    pub extensions: Vec<Extension>,
}

impl TbsCertificate {
    /// Reads a TBSCertificate from its DER.
    pub fn parse(der: &[u8]) -> Result<TbsCertificate, Error> {
        if der.len() > MAX_CERT {
            return Err(Error::TooLong);
        }
        read_tbs(single(der)?)
    }

    /// The TBSCertificate's DER: the bytes to sign. The issuer signs them
    /// with its own code and passes them to [`Certificate::assemble`].
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let der = build(|w| self.write(w))?;
        TbsCertificate::parse(&der)?;
        Ok(der)
    }

    fn write(&self, w: &mut Writer) {
        w.sequence(|w| {
            if self.version != Version::V1 {
                w.explicit(0, |w| w.integer_i64(self.version.number()));
            }
            w.integer_bytes(&self.serial);
            write_alg(w, &self.signature);
            write_name(w, &self.issuer);
            w.sequence(|w| {
                write_time(w, &self.validity.not_before);
                write_time(w, &self.validity.not_after);
            });
            write_name(w, &self.subject);
            write_spki(w, &self.public_key);
            if let Some(id) = &self.issuer_unique_id {
                w.implicit(Tag::context(1), |w| w.bit_string_value(id));
            }
            if let Some(id) = &self.subject_unique_id {
                w.implicit(Tag::context(2), |w| w.bit_string_value(id));
            }
            if !self.extensions.is_empty() {
                w.explicit(3, |w| write_extensions(w, &self.extensions));
            }
        });
    }

    /// The extension with the identifier `oid` (contents bytes, as in
    /// [`oid`]).
    pub fn extension(&self, oid: &[u8]) -> Option<&Extension> {
        find_extension(&self.extensions, oid)
    }

    /// The value of the extension `T`, such as
    /// `tbs.get::<SubjectAltName>()`. It is `Ok(None)` if the certificate
    /// does not have one, and an error if its value is malformed.
    pub fn get<T: ExtensionValue>(&self) -> Result<Option<T>, Error> {
        get_extension(&self.extensions)
    }
}

fn read_tbs(e: Element<'_>) -> Result<TbsCertificate, Error> {
    if !e.tag().same_type(Tag::SEQUENCE) {
        return Err(asn1::Error::Unexpected { expected: Tag::SEQUENCE, found: e.tag() }.into());
    }
    let mut s = e.reader()?;
    let version = match s.read_optional(Tag::context(0))? {
        Some(e) => {
            let mut v = e.reader()?;
            let n = v.read_i64()?;
            v.finish()?;
            Version::from_number(n)?
        }
        None => Version::V1,
    };
    let serial = s.read_integer()?.as_bytes().to_vec();
    let signature = read_alg(&mut s)?;
    let issuer = read_name(&mut s)?;
    let mut v = s.read_sequence()?;
    let validity = Validity { not_before: read_time(&mut v)?, not_after: read_time(&mut v)? };
    v.finish()?;
    let subject = read_name(&mut s)?;
    let public_key = read_spki(&mut s)?;
    let issuer_unique_id =
        s.read_optional(Tag::context(1))?.map(|e| e.bit_string().map(BitString::into_owned)).transpose()?;
    let subject_unique_id =
        s.read_optional(Tag::context(2))?.map(|e| e.bit_string().map(BitString::into_owned)).transpose()?;
    let extensions = match s.read_optional(Tag::context(3))? {
        Some(e) => {
            let mut x = e.reader()?;
            let list = read_extensions(&mut x)?;
            x.finish()?;
            list
        }
        None => Vec::new(),
    };
    s.finish()?;
    let has_ids = issuer_unique_id.is_some() || subject_unique_id.is_some();
    if (has_ids && version == Version::V1) || (!extensions.is_empty() && version != Version::V3) {
        return Err(Error::Version);
    }
    Ok(TbsCertificate {
        version,
        serial,
        signature,
        issuer,
        validity,
        subject,
        public_key,
        issuer_unique_id,
        subject_unique_id,
        extensions,
    })
}

/// A certificate: the signed part, read and as bytes, and the signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate {
    /// The signed part, read.
    pub tbs: TbsCertificate,
    /// The signed part's DER, exactly as it came: the bytes the signature
    /// covers. [`Certificate::to_der`] writes these, not `tbs`.
    pub tbs_der: Vec<u8>,
    /// The signature algorithm, the same as `tbs.signature`.
    pub signature_algorithm: AlgorithmIdentifier,
    /// The signature, in the algorithm's own encoding.
    pub signature: BitString<'static>,
}

impl Certificate {
    /// Reads a certificate from its DER. It must be exactly one
    /// certificate, at most [`MAX_CERT`] bytes.
    pub fn parse(der: &[u8]) -> Result<Certificate, Error> {
        if der.len() > MAX_CERT {
            return Err(Error::TooLong);
        }
        let mut s = top_sequence(der)?;
        let tbs_e = s.read()?;
        let tbs = read_tbs(tbs_e)?;
        let signature_algorithm = read_alg(&mut s)?;
        let signature = s.read_bit_string()?.into_owned();
        s.finish()?;
        if tbs.signature != signature_algorithm {
            return Err(Error::SignatureMismatch);
        }
        Ok(Certificate { tbs, tbs_der: tbs_e.raw().to_vec(), signature_algorithm, signature })
    }

    /// Joins signed TBSCertificate bytes, such as
    /// [`TbsCertificate::to_der`] gave, with their signature.
    pub fn assemble(
        tbs_der: &[u8],
        signature_algorithm: AlgorithmIdentifier,
        signature: BitString<'static>,
    ) -> Result<Certificate, Error> {
        let tbs = TbsCertificate::parse(tbs_der)?;
        if tbs.signature != signature_algorithm {
            return Err(Error::SignatureMismatch);
        }
        let cert = Certificate { tbs, tbs_der: tbs_der.to_vec(), signature_algorithm, signature };
        cert.to_der()?;
        Ok(cert)
    }

    /// The certificate's DER: [`Certificate::tbs_der`], the algorithm and
    /// the signature. A certificate read by [`Certificate::parse`] gives
    /// back the same bytes.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let der = build(|w| {
            w.sequence(|w| {
                w.encoded(&self.tbs_der);
                write_alg(w, &self.signature_algorithm);
                w.bit_string_value(&self.signature);
            })
        })?;
        Certificate::parse(&der)?;
        Ok(der)
    }

    /// Reads the first `CERTIFICATE` block of PEM text. Text after that
    /// block is not read.
    pub fn from_pem(text: &[u8]) -> Result<Certificate, Error> {
        Certificate::parse(&first_pem_block(text, PEM_CERTIFICATE)?)
    }

    /// The certificate as a PEM `CERTIFICATE` block.
    pub fn to_pem(&self) -> Result<String, Error> {
        Pem { label: PEM_CERTIFICATE.into(), data: self.to_der()? }.encode()
    }
}

/// One revoked certificate in a CRL.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RevokedCertificate {
    /// The certificate's serial number, as two's-complement bytes. A
    /// writer drops leading bytes that do not change the value.
    pub serial: Vec<u8>,
    /// When it was revoked.
    pub revocation_date: Time,
    /// The entry's extensions, such as a reason code. They need a v2 CRL.
    pub extensions: Vec<Extension>,
}

impl RevokedCertificate {
    /// The entry extension with the identifier `oid` (contents bytes).
    pub fn extension(&self, oid: &[u8]) -> Option<&Extension> {
        find_extension(&self.extensions, oid)
    }

    /// The value of the entry extension `T`, such as
    /// `entry.get::<CrlReason>()`. It is `Ok(None)` if the entry does not
    /// have one, and an error if its value is malformed.
    pub fn get<T: ExtensionValue>(&self) -> Result<Option<T>, Error> {
        get_extension(&self.extensions)
    }
}

/// The part of a CRL its issuer signs (RFC 5280 5.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TbsCertList {
    /// [`Version::V2`] when the CRL has extensions, and otherwise
    /// [`Version::V1`]. CRLs have no v3.
    pub version: Version,
    /// The signature algorithm. It must match
    /// [`Crl::signature_algorithm`].
    pub signature: AlgorithmIdentifier,
    /// Who signed the CRL.
    pub issuer: Name,
    /// When the CRL was issued.
    pub this_update: Time,
    /// When the next CRL will be issued.
    pub next_update: Option<Time>,
    /// The revoked certificates. An empty list is not written, as RFC
    /// 5280 asks. A reader takes an empty one too.
    pub revoked: Vec<RevokedCertificate>,
    /// The CRL's extensions, such as a CRL number.
    pub extensions: Vec<Extension>,
}

impl TbsCertList {
    /// Reads a TBSCertList from its DER.
    pub fn parse(der: &[u8]) -> Result<TbsCertList, Error> {
        if der.len() > MAX_CRL {
            return Err(Error::TooLong);
        }
        read_tbs_crl(single(der)?)
    }

    /// The TBSCertList's DER: the bytes to sign.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let der = build(|w| self.write(w))?;
        TbsCertList::parse(&der)?;
        Ok(der)
    }

    fn write(&self, w: &mut Writer) {
        w.sequence(|w| {
            if self.version != Version::V1 {
                w.integer_i64(self.version.number());
            }
            write_alg(w, &self.signature);
            write_name(w, &self.issuer);
            write_time(w, &self.this_update);
            if let Some(t) = &self.next_update {
                write_time(w, t);
            }
            if !self.revoked.is_empty() {
                w.sequence(|w| {
                    for r in &self.revoked {
                        w.sequence(|w| {
                            w.integer_bytes(&r.serial);
                            write_time(w, &r.revocation_date);
                            if !r.extensions.is_empty() {
                                write_extensions(w, &r.extensions);
                            }
                        });
                    }
                });
            }
            if !self.extensions.is_empty() {
                w.explicit(0, |w| write_extensions(w, &self.extensions));
            }
        });
    }

    /// The CRL extension with the identifier `oid` (contents bytes).
    pub fn extension(&self, oid: &[u8]) -> Option<&Extension> {
        find_extension(&self.extensions, oid)
    }

    /// The value of the CRL extension `T`, such as
    /// `tbs.get::<AuthorityKeyIdentifier>()`.
    pub fn get<T: ExtensionValue>(&self) -> Result<Option<T>, Error> {
        get_extension(&self.extensions)
    }
}

fn read_tbs_crl(e: Element<'_>) -> Result<TbsCertList, Error> {
    if !e.tag().same_type(Tag::SEQUENCE) {
        return Err(asn1::Error::Unexpected { expected: Tag::SEQUENCE, found: e.tag() }.into());
    }
    let mut s = e.reader()?;
    let version = match s.peek()?.tag().same_type(Tag::INTEGER) {
        // If present, the version must be v2 (RFC 5280 5.1.2.1).
        true => match Version::from_number(s.read_i64()?)? {
            Version::V2 => Version::V2,
            _ => return Err(Error::Version),
        },
        false => Version::V1,
    };
    let signature = read_alg(&mut s)?;
    let issuer = read_name(&mut s)?;
    let this_update = read_time(&mut s)?;
    let next_update = if is_time(&s) { Some(read_time(&mut s)?) } else { None };
    let mut revoked = Vec::new();
    if let Some(list) = s.read_optional(Tag::SEQUENCE)? {
        let mut list = list.reader()?;
        while !list.is_empty() {
            let mut r = list.read_sequence()?;
            let serial = r.read_integer()?.as_bytes().to_vec();
            let revocation_date = read_time(&mut r)?;
            let extensions = if r.is_empty() { Vec::new() } else { read_extensions(&mut r)? };
            r.finish()?;
            push_limited(&mut revoked, RevokedCertificate { serial, revocation_date, extensions }, MAX_REVOKED)?;
        }
    }
    let extensions = match s.read_optional(Tag::context(0))? {
        Some(e) => {
            let mut x = e.reader()?;
            let list = read_extensions(&mut x)?;
            x.finish()?;
            list
        }
        None => Vec::new(),
    };
    s.finish()?;
    let any_extensions = !extensions.is_empty() || revoked.iter().any(|r| !r.extensions.is_empty());
    if any_extensions && version != Version::V2 {
        return Err(Error::Version);
    }
    Ok(TbsCertList { version, signature, issuer, this_update, next_update, revoked, extensions })
}

/// A certificate revocation list: the signed part, read and as bytes, and
/// the signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Crl {
    /// The signed part, read.
    pub tbs: TbsCertList,
    /// The signed part's DER, exactly as it came. [`Crl::to_der`] writes
    /// these, not `tbs`.
    pub tbs_der: Vec<u8>,
    /// The signature algorithm, the same as `tbs.signature`.
    pub signature_algorithm: AlgorithmIdentifier,
    /// The signature.
    pub signature: BitString<'static>,
}

impl Crl {
    /// Reads a CRL from its DER. It must be exactly one CRL, at most
    /// [`MAX_CRL`] bytes.
    pub fn parse(der: &[u8]) -> Result<Crl, Error> {
        if der.len() > MAX_CRL {
            return Err(Error::TooLong);
        }
        let mut s = top_sequence(der)?;
        let tbs_e = s.read()?;
        let tbs = read_tbs_crl(tbs_e)?;
        let signature_algorithm = read_alg(&mut s)?;
        let signature = s.read_bit_string()?.into_owned();
        s.finish()?;
        if tbs.signature != signature_algorithm {
            return Err(Error::SignatureMismatch);
        }
        Ok(Crl { tbs, tbs_der: tbs_e.raw().to_vec(), signature_algorithm, signature })
    }

    /// Joins signed TBSCertList bytes with their signature.
    pub fn assemble(
        tbs_der: &[u8],
        signature_algorithm: AlgorithmIdentifier,
        signature: BitString<'static>,
    ) -> Result<Crl, Error> {
        let tbs = TbsCertList::parse(tbs_der)?;
        if tbs.signature != signature_algorithm {
            return Err(Error::SignatureMismatch);
        }
        let crl = Crl { tbs, tbs_der: tbs_der.to_vec(), signature_algorithm, signature };
        crl.to_der()?;
        Ok(crl)
    }

    /// The CRL's DER. A CRL read by [`Crl::parse`] gives back the same
    /// bytes.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let der = build(|w| {
            w.sequence(|w| {
                w.encoded(&self.tbs_der);
                write_alg(w, &self.signature_algorithm);
                w.bit_string_value(&self.signature);
            })
        })?;
        Crl::parse(&der)?;
        Ok(der)
    }

    /// Whether the CRL lists the serial number `serial` (two's-complement
    /// bytes, as [`TbsCertificate::serial`] holds them). Numbers compare
    /// by value, so `00 05` matches `05`.
    pub fn is_revoked(&self, serial: &[u8]) -> bool {
        let serial = minimal_int(serial);
        self.tbs.revoked.iter().any(|r| minimal_int(&r.serial) == serial)
    }

    /// Reads the first `X509 CRL` block of PEM text. Text after that block
    /// is not read.
    pub fn from_pem(text: &[u8]) -> Result<Crl, Error> {
        Crl::parse(&first_pem_block(text, PEM_CRL)?)
    }

    /// The CRL as a PEM `X509 CRL` block.
    pub fn to_pem(&self) -> Result<String, Error> {
        Pem { label: PEM_CRL.into(), data: self.to_der()? }.encode()
    }
}

// PEM (RFC 7468).

const PEM_BEGIN: &[u8] = b"-----BEGIN ";
const PEM_END: &[u8] = b"-----END ";
const PEM_DASHES: &[u8] = b"-----";
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// The most base64 characters one block may hold.
const MAX_PEM_CHARS: usize = MAX_PEM_DATA.div_ceil(3) * 4;

/// One PEM block: a label, such as `CERTIFICATE`, and the bytes its
/// base64 holds.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Pem {
    /// The label, from the `-----BEGIN` line.
    pub label: String,
    /// The decoded bytes.
    pub data: Vec<u8>,
}

impl Pem {
    /// The block as text: the `-----BEGIN` line, the base64 in lines of
    /// 64 characters, and the `-----END` line, each ending in `\n`. A
    /// label RFC 7468 does not allow is [`Error::Pem`], and data longer
    /// than [`MAX_PEM_DATA`] is [`Error::TooLong`].
    pub fn encode(&self) -> Result<String, Error> {
        if !valid_label(self.label.as_bytes()) {
            return Err(Error::Pem);
        }
        if self.data.len() > MAX_PEM_DATA {
            return Err(Error::TooLong);
        }
        let b64 = base64_encode(&self.data);
        let mut out = String::with_capacity(b64.len() + b64.len() / 64 + 2 * self.label.len() + 40);
        let _ = writeln!(out, "-----BEGIN {}-----", self.label);
        for line in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).unwrap_or_default());
            out.push('\n');
        }
        let _ = writeln!(out, "-----END {}-----", self.label);
        Ok(out)
    }
}

/// Whether `l` is a label RFC 7468 section 3 allows: printable ASCII but
/// `-`, with single spaces or hyphens between, at most [`MAX_PEM_LABEL`]
/// bytes. An empty label is allowed.
fn valid_label(l: &[u8]) -> bool {
    let labelchar = |c: u8| (0x21..=0x7e).contains(&c) && c != b'-';
    if l.len() > MAX_PEM_LABEL {
        return false;
    }
    if l.is_empty() {
        return true;
    }
    if !labelchar(l[0]) || !labelchar(l[l.len() - 1]) || !l.iter().all(|&c| labelchar(c) || c == b'-' || c == b' ') {
        return false;
    }
    l.windows(2).all(|p| labelchar(p[0]) || labelchar(p[1]))
}

/// The label of a `-----BEGIN label-----` line, which may end in spaces
/// or tabs.
fn begin_label(line: &[u8]) -> Option<String> {
    let end = line.iter().rposition(|&c| !matches!(c, b' ' | b'\t')).map_or(0, |i| i + 1);
    let label = line[..end].strip_prefix(PEM_BEGIN)?.strip_suffix(PEM_DASHES)?;
    valid_label(label).then(|| String::from_utf8_lossy(label).into_owned())
}

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(BASE64[(n >> (18 - 6 * i) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn base64_value(c: u8) -> Option<u32> {
    Some(u32::from(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    }))
}

/// Decodes base64 with its padding, whitespace already removed. Bits
/// left over after the last byte are ignored.
fn base64_decode(s: &[u8]) -> Result<Vec<u8>, Error> {
    if !s.len().is_multiple_of(4) {
        return Err(Error::Pem);
    }
    let pad = s.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return Err(Error::Pem);
    }
    let body = &s[..s.len() - pad];
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in body.chunks(4) {
        let mut n = 0u32;
        for &c in chunk {
            n = n << 6 | base64_value(c).ok_or(Error::Pem)?;
        }
        n <<= 6 * (4 - chunk.len() as u32);
        let bytes = n.to_be_bytes();
        let keep = match chunk.len() {
            4 => 3,
            3 => 2,
            2 => 1,
            _ => return Err(Error::Pem),
        };
        out.extend_from_slice(&bytes[1..1 + keep]);
    }
    Ok(out)
}

/// A block whose `-----BEGIN` line has been read.
#[derive(Debug)]
struct OpenBlock {
    label: String,
    /// The `-----END label-----` marker that closes it.
    marker: Vec<u8>,
    /// The base64 characters so far, without whitespace.
    chars: Vec<u8>,
}

/// What [`Scanner::step`] did.
enum Step {
    /// The text holds no complete line to read.
    Need,
    /// A line of this many bytes, newline included, was read.
    Line(usize),
    /// A block closed after this many bytes.
    Block(Pem, usize),
}

/// Reads PEM text a line at a time. Lines end in `\n` or `\r`, so a
/// `\r\n` ends a line and leaves an empty one (RFC 7468 section 3 allows
/// all three). Spaces, tabs, vertical tabs and form feeds are ignored in
/// base64 lines, and lines outside blocks are text and skipped.
#[derive(Debug, Default)]
struct Scanner {
    open: Option<OpenBlock>,
}

impl Scanner {
    /// Reads the next line of `b`, whose first `searched` bytes are known
    /// to hold no line end.
    fn step(&mut self, b: &[u8], searched: usize) -> Result<Step, Error> {
        let nl = b
            .get(searched..)
            .and_then(|rest| rest.iter().position(|&c| matches!(c, b'\n' | b'\r')))
            .map(|i| i + searched);
        let Some(open) = &mut self.open else {
            let Some(n) = nl else {
                return if b.len() > MAX_PEM_LINE { Err(Error::TooLong) } else { Ok(Step::Need) };
            };
            if n > MAX_PEM_LINE {
                return Err(Error::TooLong);
            }
            if let Some(label) = begin_label(&b[..n]) {
                let marker = [PEM_END, label.as_bytes(), PEM_DASHES].concat();
                self.open = Some(OpenBlock { label, marker, chars: Vec::new() });
            }
            return Ok(Step::Line(n + 1));
        };
        // The end marker closes the block as soon as it is all there.
        // Anything after it on its line is text outside the block.
        if b.starts_with(&open.marker) {
            let used = open.marker.len();
            let data = base64_decode(&open.chars)?;
            // The last group of four characters may hold up to two bytes
            // past the limit, which `Pem::encode` would refuse.
            if data.len() > MAX_PEM_DATA {
                return Err(Error::TooLong);
            }
            let label = std::mem::take(&mut open.label);
            self.open = None;
            return Ok(Step::Block(Pem { label, data }, used));
        }
        let Some(n) = nl else {
            if !open.marker.starts_with(b) && b.len() > MAX_PEM_LINE {
                return Err(Error::TooLong);
            }
            return Ok(Step::Need);
        };
        if n > MAX_PEM_LINE {
            return Err(Error::TooLong);
        }
        for &c in &b[..n] {
            match c {
                b' ' | b'\t' | 0x0b | 0x0c => {}
                c if c == b'=' || base64_value(c).is_some() => {
                    if open.chars.len() >= MAX_PEM_CHARS {
                        return Err(Error::TooLong);
                    }
                    open.chars.push(c);
                }
                _ => return Err(Error::Pem),
            }
        }
        Ok(Step::Line(n + 1))
    }
}

/// Every PEM block in `text`, in order, with the text around them
/// skipped. A block with no end line is [`Error::Pem`], and more than
/// [`MAX_PEM_BLOCKS`] blocks is [`Error::TooMany`].
pub fn pem_decode(text: &[u8]) -> Result<Vec<Pem>, Error> {
    let mut scanner = Scanner::default();
    let mut pos = 0;
    let mut blocks = Vec::new();
    loop {
        match scanner.step(&text[pos..], 0)? {
            Step::Need => break,
            Step::Line(n) => pos += n,
            Step::Block(p, n) => {
                push_limited(&mut blocks, p, MAX_PEM_BLOCKS)?;
                pos += n;
            }
        }
    }
    if scanner.open.is_some() {
        return Err(Error::Pem);
    }
    Ok(blocks)
}

/// The data of the first block labeled `label` in `text`. Text after it
/// is not read, and blocks before it are not kept.
fn first_pem_block(text: &[u8], label: &str) -> Result<Vec<u8>, Error> {
    let mut scanner = Scanner::default();
    let mut pos = 0;
    loop {
        match scanner.step(text.get(pos..).unwrap_or_default(), 0)? {
            Step::Need if scanner.open.is_some() => return Err(Error::Pem),
            Step::Need => return Err(Error::NoBlock),
            Step::Line(n) => pos += n,
            Step::Block(p, _) if p.label == label => return Ok(p.data),
            Step::Block(_, n) => pos += n,
        }
    }
}

/// Splits a stream of PEM text into blocks, such as a bundle of
/// certificates a world reads from a connection. Feed it the bytes in
/// order, and take blocks out until it has none.
#[derive(Debug, Default)]
pub struct PemDecoder {
    buf: Vec<u8>,
    /// Where the bytes not yet read start.
    start: usize,
    /// How many bytes after `start` are known to hold no newline.
    searched: usize,
    scanner: Scanner,
    failed: Option<Error>,
}

impl PemDecoder {
    /// A decoder holding no text.
    pub fn new() -> PemDecoder {
        PemDecoder::default()
    }

    /// Adds text read from the stream. After an error the stream cannot
    /// be read any further, and it is dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_none() {
            if self.start > 0 && self.start >= self.buf.len() / 2 {
                self.buf.drain(..self.start);
                self.start = 0;
            }
            self.buf.extend_from_slice(bytes);
        }
    }

    /// The next whole block, if one has come. It returns `None` when it
    /// needs more text, and keeps returning the same error once the
    /// stream has broken. It holds at most one block's base64 and one
    /// line beyond what has been read, plus what one `feed` added.
    pub fn next_block(&mut self) -> Option<Result<Pem, Error>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        loop {
            match self.scanner.step(&self.buf[self.start..], self.searched) {
                Ok(Step::Need) => {
                    self.searched = self.buf.len() - self.start;
                    return None;
                }
                Ok(Step::Line(n)) => {
                    self.start += n;
                    self.searched = 0;
                }
                Ok(Step::Block(p, n)) => {
                    self.start += n;
                    self.searched = 0;
                    return Some(Ok(p));
                }
                Err(e) => {
                    self.failed = Some(e);
                    self.buf = Vec::new();
                    self.start = 0;
                    self.searched = 0;
                    return Some(Err(e));
                }
            }
        }
    }

    /// Whether a block has begun and not yet ended. At the end of a
    /// stream, this means the last block was cut short.
    pub fn in_block(&self) -> bool {
        self.scanner.open.is_some()
    }

    /// How many bytes are held, not yet read as lines.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed P-256 certificate made with OpenSSL, with every
    /// extension this module reads.
    const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIC8DCCApegAwIBAgIEEjSrzTAKBggqhkjOPQQDAjA+MQswCQYDVQQGEwJVUzEV
MBMGA1UECgwMRXhhbXBsZSBDb3JwMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20w
HhcNMjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjA+MQswCQYDVQQGEwJVUzEV
MBMGA1UECgwMRXhhbXBsZSBDb3JwMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20w
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARBIutJCEAtRbgYT0v8yyBS7clwbHBp
Odiv6Q3QAixkkh/VK06GjqbnFgq3tCkTu+gqR6fROZP+3KYeOtY6xw57o4IBgTCC
AX0wEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYw
FAYIKwYBBQUHAwEGCCsGAQUFBwMCMGgGA1UdEQRhMF+CD3d3dy5leGFtcGxlLmNv
bYILZXhhbXBsZS5jb22HBMAAAgGHECABDbgAAAAAAAAAAAAAAAGBEWFkbWluQGV4
YW1wbGUuY29thhRodHRwczovL2V4YW1wbGUuY29tLzAdBgNVHQ4EFgQUJI8VUtWZ
ZWkVjiK7ioxKE4wALrowHwYDVR0jBBgwFoAUJI8VUtWZZWkVjiK7ioxKE4wALrow
LgYDVR0fBCcwJTAjoCGgH4YdaHR0cDovL2NybC5leGFtcGxlLmNvbS9jYS5jcmww
XgYIKwYBBQUHAQEEUjBQMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5leGFtcGxl
LmNvbS8wKAYIKwYBBQUHMAKGHGh0dHA6Ly9jYS5leGFtcGxlLmNvbS9jYS5jcnQw
CgYIKoZIzj0EAwIDRwAwRAIgFvMEMo5s94IKd7E5pn9qlK+O8wtGt8mjXgeq8r2e
kaUCIFm77EWcOU60wVpx5FKjZhAMS5AMAhqs7tK9keVeEMeH
-----END CERTIFICATE-----
";

    /// A v2 CRL from the same issuer, made with OpenSSL: two entries, one
    /// with a reason code, and an authority key identifier and CRL number.
    const CRL_PEM: &str = "-----BEGIN X509 CRL-----
MIIBNDCB2gIBATAKBggqhkjOPQQDAjA+MQswCQYDVQQGEwJVUzEVMBMGA1UECgwM
RXhhbXBsZSBDb3JwMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20XDTI1MDcwMTAw
MDAwMFoXDTI1MDgwMTAwMDAwMFowOTASAgEFFw0yNTA2MDIwMDAwMDBaMCMCBBI0
q84XDTI1MDYwMTAwMDAwMFowDDAKBgNVHRUEAwoBAaAwMC4wHwYDVR0jBBgwFoAU
JI8VUtWZZWkVjiK7ioxKE4wALrowCwYDVR0UBAQCAhAAMAoGCCqGSM49BAMCA0kA
MEYCIQCmAkVAI1dJW72/Um54KQJqVYUOybGrFRSv63Ue9UGkJwIhAJzOcKgHYbg5
DsrW/cKuXzHiZH3HJwCIjEBL56j3WttF
-----END X509 CRL-----
";

    const SKI: [u8; 20] = [
        0x24, 0x8f, 0x15, 0x52, 0xd5, 0x99, 0x65, 0x69, 0x15, 0x8e, 0x22, 0xbb, 0x8a, 0x8c, 0x4a, 0x13, 0x8c, 0x00,
        0x2e, 0xba,
    ];

    fn oid(b: &[u8]) -> Oid {
        Oid::from_contents(b).unwrap()
    }

    fn cert_der() -> Vec<u8> {
        pem_decode(CERT_PEM.as_bytes()).unwrap().remove(0).data
    }

    fn crl_der() -> Vec<u8> {
        pem_decode(CRL_PEM.as_bytes()).unwrap().remove(0).data
    }

    fn text(kind: StringKind, s: &str) -> Value {
        Value::Text { kind, text: s.into() }
    }

    fn uri(s: &str) -> GeneralName {
        GeneralName::Uri(s.into())
    }

    /// A small v3 TBSCertificate for writer tests.
    fn sample_tbs() -> TbsCertificate {
        let alg = AlgorithmIdentifier { oid: oid(oid::ED25519), parameters: None };
        let mut name = Name::default();
        name.push(oid(oid::COMMON_NAME), text(StringKind::Utf8, "test"));
        TbsCertificate {
            version: Version::V3,
            serial: vec![1],
            signature: alg.clone(),
            issuer: name.clone(),
            validity: Validity { not_before: Time::from_unix(0).unwrap(), not_after: Time::from_unix(86_400).unwrap() },
            subject: name,
            public_key: PublicKeyInfo { algorithm: alg, key: BitString::new(vec![7; 32], 0).unwrap() },
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Vec::new(),
        }
    }

    #[test]
    fn oid_constants_are_the_identifiers_they_name() {
        let cases: [(&[u8], &str); 34] = [
            (oid::COMMON_NAME, "2.5.4.3"),
            (oid::SURNAME, "2.5.4.4"),
            (oid::SERIAL_NUMBER, "2.5.4.5"),
            (oid::COUNTRY, "2.5.4.6"),
            (oid::LOCALITY, "2.5.4.7"),
            (oid::STATE, "2.5.4.8"),
            (oid::STREET, "2.5.4.9"),
            (oid::ORGANIZATION, "2.5.4.10"),
            (oid::ORGANIZATIONAL_UNIT, "2.5.4.11"),
            (oid::DOMAIN_COMPONENT, "0.9.2342.19200300.100.1.25"),
            (oid::USER_ID, "0.9.2342.19200300.100.1.1"),
            (oid::EMAIL_ADDRESS, "1.2.840.113549.1.9.1"),
            (oid::SUBJECT_KEY_IDENTIFIER, "2.5.29.14"),
            (oid::KEY_USAGE, "2.5.29.15"),
            (oid::SUBJECT_ALT_NAME, "2.5.29.17"),
            (oid::ISSUER_ALT_NAME, "2.5.29.18"),
            (oid::BASIC_CONSTRAINTS, "2.5.29.19"),
            (oid::CRL_NUMBER, "2.5.29.20"),
            (oid::REASON_CODE, "2.5.29.21"),
            (oid::CRL_DISTRIBUTION_POINTS, "2.5.29.31"),
            (oid::CERTIFICATE_POLICIES, "2.5.29.32"),
            (oid::AUTHORITY_KEY_IDENTIFIER, "2.5.29.35"),
            (oid::EXTENDED_KEY_USAGE, "2.5.29.37"),
            (oid::AUTHORITY_INFO_ACCESS, "1.3.6.1.5.5.7.1.1"),
            (oid::SERVER_AUTH, "1.3.6.1.5.5.7.3.1"),
            (oid::CLIENT_AUTH, "1.3.6.1.5.5.7.3.2"),
            (oid::CODE_SIGNING, "1.3.6.1.5.5.7.3.3"),
            (oid::EMAIL_PROTECTION, "1.3.6.1.5.5.7.3.4"),
            (oid::TIME_STAMPING, "1.3.6.1.5.5.7.3.8"),
            (oid::OCSP_SIGNING, "1.3.6.1.5.5.7.3.9"),
            (oid::OCSP, "1.3.6.1.5.5.7.48.1"),
            (oid::CA_ISSUERS, "1.3.6.1.5.5.7.48.2"),
            (oid::EC_PUBLIC_KEY, "1.2.840.10045.2.1"),
            (oid::ED25519, "1.3.101.112"),
        ];
        for (bytes, dotted) in cases {
            assert_eq!(oid(bytes).to_string(), dotted);
        }
        for (bytes, dotted) in [
            (oid::RSA_ENCRYPTION, "1.2.840.113549.1.1.1"),
            (oid::SHA256_WITH_RSA, "1.2.840.113549.1.1.11"),
            (oid::PRIME256V1, "1.2.840.10045.3.1.7"),
            (oid::ECDSA_WITH_SHA256, "1.2.840.10045.4.3.2"),
        ] {
            assert_eq!(oid(bytes).to_string(), dotted);
        }
    }

    #[test]
    fn reads_an_openssl_certificate() {
        let der = cert_der();
        assert_eq!(der.len(), 756);
        let cert = Certificate::parse(&der).unwrap();
        let tbs = &cert.tbs;
        assert_eq!(tbs.version, Version::V3);
        assert_eq!(tbs.serial, [0x12, 0x34, 0xab, 0xcd]);
        assert_eq!(tbs.signature, AlgorithmIdentifier { oid: oid(oid::ECDSA_WITH_SHA256), parameters: None });
        assert_eq!(cert.signature_algorithm, tbs.signature);
        assert_eq!(tbs.issuer.to_string(), "CN=www.example.com,O=Example Corp,C=US");
        assert_eq!(tbs.subject, tbs.issuer);
        assert_eq!(tbs.subject.common_name(), Some("www.example.com"));
        assert_eq!(tbs.subject.find(oid::COUNTRY), Some(&text(StringKind::Printable, "US")));
        assert_eq!(tbs.validity.not_before, Time::Utc("250101000000Z".into()));
        assert_eq!(tbs.validity.not_after, Time::Utc("350101000000Z".into()));
        assert!(tbs.validity.contains(1_735_689_600));
        assert!(!tbs.validity.contains(1_735_689_599));
        assert!(tbs.validity.contains(2_051_222_400));
        assert!(!tbs.validity.contains(2_051_222_401));
        let key = &tbs.public_key;
        assert_eq!(key.algorithm.oid.as_bytes(), oid::EC_PUBLIC_KEY);
        assert_eq!(
            key.algorithm.parameters.as_deref(),
            Some(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07][..])
        );
        assert_eq!(key.key.bytes().len(), 65);
        assert_eq!(key.key.bytes()[..3], [0x04, 0x41, 0x22]);
        assert_eq!(cert.signature.bytes()[..4], [0x30, 0x44, 0x02, 0x20]);
        assert_eq!(cert.tbs_der[..4], [0x30, 0x82, 0x02, 0x97]);
        assert_eq!(tbs.extensions.len(), 8);

        let bc = tbs.get::<BasicConstraints>().unwrap().unwrap();
        assert_eq!(bc, BasicConstraints { ca: true, path_len: Some(0) });
        assert!(tbs.extension(oid::BASIC_CONSTRAINTS).unwrap().critical);
        let ku = tbs.get::<KeyUsage>().unwrap().unwrap();
        assert_eq!(ku.0, KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN);
        assert!(ku.contains(KeyUsage::KEY_CERT_SIGN) && !ku.contains(KeyUsage::KEY_ENCIPHERMENT));
        let eku = tbs.get::<ExtendedKeyUsage>().unwrap().unwrap();
        assert_eq!(eku.0, [oid(oid::SERVER_AUTH), oid(oid::CLIENT_AUTH)]);
        assert!(eku.contains(oid::SERVER_AUTH) && !eku.contains(oid::CODE_SIGNING));
        assert!(!tbs.extension(oid::EXTENDED_KEY_USAGE).unwrap().critical);
        let san = tbs.get::<SubjectAltName>().unwrap().unwrap();
        assert_eq!(
            san.0,
            [
                GeneralName::Dns("www.example.com".into()),
                GeneralName::Dns("example.com".into()),
                GeneralName::Ip(vec![192, 0, 2, 1]),
                GeneralName::Ip(vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                GeneralName::Email("admin@example.com".into()),
                uri("https://example.com/"),
            ]
        );
        assert_eq!(san.0[2].ip_addr(), Some("192.0.2.1".parse().unwrap()));
        assert_eq!(san.0[3].ip_addr(), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(san.0[0].ip_addr(), None);
        assert_eq!(tbs.get::<SubjectKeyIdentifier>().unwrap().unwrap().0, SKI);
        let aki = tbs.get::<AuthorityKeyIdentifier>().unwrap().unwrap();
        assert_eq!(aki, AuthorityKeyIdentifier { key_id: Some(SKI.to_vec()), issuer: None, serial: None });
        let dp = tbs.get::<CrlDistributionPoints>().unwrap().unwrap();
        assert_eq!(
            dp.0,
            [DistributionPoint {
                name: Some(DistributionPointName::Full(vec![uri("http://crl.example.com/ca.crl")])),
                reasons: None,
                crl_issuer: None,
            }]
        );
        let aia = tbs.get::<AuthorityInfoAccess>().unwrap().unwrap();
        assert_eq!(
            aia.0,
            [
                AccessDescription { method: oid(oid::OCSP), location: uri("http://ocsp.example.com/") },
                AccessDescription { method: oid(oid::CA_ISSUERS), location: uri("http://ca.example.com/ca.crt") },
            ]
        );
        assert_eq!(tbs.extension(oid::CERTIFICATE_POLICIES), None);
        assert_eq!(tbs.get::<SubjectKeyIdentifier>().unwrap().map(|k| k.0.len()), Some(20));
    }

    #[test]
    fn a_read_certificate_writes_back_the_same_bytes() {
        let der = cert_der();
        let cert = Certificate::parse(&der).unwrap();
        assert_eq!(cert.to_der().unwrap(), der);
        assert_eq!(cert.tbs.to_der().unwrap(), cert.tbs_der);
        assert_eq!(cert.to_pem().unwrap(), CERT_PEM);
        assert_eq!(Certificate::from_pem(CERT_PEM.as_bytes()).unwrap(), cert);
        // Each typed extension writes the bytes OpenSSL wrote.
        let tbs = &cert.tbs;
        let same = |o: &[u8], der: Vec<u8>| assert_eq!(tbs.extension(o).unwrap().value, der, "{o:02x?}");
        same(oid::BASIC_CONSTRAINTS, tbs.get::<BasicConstraints>().unwrap().unwrap().to_der().unwrap());
        same(oid::KEY_USAGE, tbs.get::<KeyUsage>().unwrap().unwrap().to_der().unwrap());
        same(oid::EXTENDED_KEY_USAGE, tbs.get::<ExtendedKeyUsage>().unwrap().unwrap().to_der().unwrap());
        same(oid::SUBJECT_ALT_NAME, tbs.get::<SubjectAltName>().unwrap().unwrap().to_der().unwrap());
        same(oid::SUBJECT_KEY_IDENTIFIER, tbs.get::<SubjectKeyIdentifier>().unwrap().unwrap().to_der().unwrap());
        same(oid::AUTHORITY_KEY_IDENTIFIER, tbs.get::<AuthorityKeyIdentifier>().unwrap().unwrap().to_der().unwrap());
        same(oid::CRL_DISTRIBUTION_POINTS, tbs.get::<CrlDistributionPoints>().unwrap().unwrap().to_der().unwrap());
        same(oid::AUTHORITY_INFO_ACCESS, tbs.get::<AuthorityInfoAccess>().unwrap().unwrap().to_der().unwrap());
        let ext = tbs.get::<KeyUsage>().unwrap().unwrap().to_extension(true).unwrap();
        assert_eq!(&ext, tbs.extension(oid::KEY_USAGE).unwrap());
        assert_eq!(
            tbs.issuer.to_der().unwrap(),
            Name::from_der(&tbs.issuer.to_der().unwrap()).unwrap().to_der().unwrap()
        );
        assert_eq!(PublicKeyInfo::from_der(&tbs.public_key.to_der().unwrap()).unwrap(), tbs.public_key);
    }

    #[test]
    fn reads_an_openssl_crl() {
        let der = crl_der();
        let crl = Crl::parse(&der).unwrap();
        let tbs = &crl.tbs;
        assert_eq!(tbs.version, Version::V2);
        assert_eq!(tbs.issuer.to_string(), "CN=www.example.com,O=Example Corp,C=US");
        assert_eq!(tbs.this_update, Time::Utc("250701000000Z".into()));
        assert_eq!(tbs.next_update, Some(Time::Utc("250801000000Z".into())));
        assert_eq!(tbs.revoked.len(), 2);
        assert_eq!(tbs.revoked[0].serial, [5]);
        assert_eq!(tbs.revoked[0].revocation_date, Time::Utc("250602000000Z".into()));
        assert!(tbs.revoked[0].extensions.is_empty());
        assert_eq!(tbs.revoked[1].serial, [0x12, 0x34, 0xab, 0xce]);
        // keyCompromise (1), as an ENUMERATED.
        assert_eq!(tbs.revoked[1].extension(oid::REASON_CODE).unwrap().value, [0x0a, 0x01, 0x01]);
        assert!(crl.is_revoked(&[0x12, 0x34, 0xab, 0xce]));
        assert!(!crl.is_revoked(&[0x12, 0x34, 0xab, 0xcd]));
        assert_eq!(tbs.get::<AuthorityKeyIdentifier>().unwrap().unwrap().key_id.as_deref(), Some(&SKI[..]));
        // CRL number 4096.
        assert_eq!(tbs.extension(oid::CRL_NUMBER).unwrap().value, [0x02, 0x02, 0x10, 0x00]);
        assert_eq!(crl.to_der().unwrap(), der);
        assert_eq!(crl.tbs.to_der().unwrap(), crl.tbs_der);
        assert_eq!(crl.to_pem().unwrap(), CRL_PEM);
        assert_eq!(Crl::from_pem(CRL_PEM.as_bytes()).unwrap(), crl);
        // The issuer's certificate is not a CRL, and the other way round.
        assert_eq!(Crl::from_pem(CERT_PEM.as_bytes()), Err(Error::NoBlock));
        assert_eq!(Certificate::from_pem(CRL_PEM.as_bytes()), Err(Error::NoBlock));
        assert!(Crl::parse(&cert_der()).is_err());
        assert!(Certificate::parse(&der).is_err());
    }

    #[test]
    fn writes_and_reads_a_v1_crl() {
        let alg = AlgorithmIdentifier { oid: oid(oid::ED25519), parameters: None };
        let tbs = TbsCertList {
            version: Version::V1,
            signature: alg.clone(),
            issuer: Name::default(),
            this_update: Time::from_unix(0).unwrap(),
            next_update: None,
            revoked: vec![RevokedCertificate {
                serial: vec![0x00, 0x80],
                revocation_date: Time::from_unix(1).unwrap(),
                extensions: vec![],
            }],
            extensions: vec![],
        };
        let der = tbs.to_der().unwrap();
        assert_eq!(TbsCertList::parse(&der).unwrap(), tbs);
        let crl = Crl::assemble(&der, alg.clone(), BitString::new(vec![1; 64], 0).unwrap()).unwrap();
        assert_eq!(Crl::parse(&crl.to_der().unwrap()).unwrap(), crl);
        assert_eq!(crl.tbs.issuer.to_string(), "");
        // An empty revoked list is left out, and reads back empty.
        let empty = TbsCertList { revoked: vec![], ..tbs.clone() };
        assert_eq!(TbsCertList::parse(&empty.to_der().unwrap()).unwrap(), empty);
        // A v1 CRL may not have extensions.
        let mut bad = tbs.clone();
        bad.extensions.push(SubjectKeyIdentifier(vec![1]).to_extension(false).unwrap());
        assert_eq!(bad.to_der(), Err(Error::Version));
        bad.version = Version::V2;
        assert!(bad.to_der().is_ok());
        let mut bad = tbs.clone();
        bad.revoked[0].extensions.push(SubjectKeyIdentifier(vec![1]).to_extension(false).unwrap());
        assert_eq!(bad.to_der(), Err(Error::Version));
        // CRLs have no v3, and an explicit v1 is refused.
        assert_eq!(TbsCertList { version: Version::V3, ..tbs.clone() }.to_der(), Err(Error::Version));
        let mut explicit_v1 = vec![0x02, 0x01, 0x00];
        explicit_v1.extend_from_slice(&der[2..]);
        let mut seq = vec![0x30, explicit_v1.len() as u8];
        seq.extend_from_slice(&explicit_v1);
        assert_eq!(TbsCertList::parse(&seq), Err(Error::Version));
        // Mismatched algorithms.
        let other = AlgorithmIdentifier { oid: oid(oid::ECDSA_WITH_SHA256), parameters: None };
        assert_eq!(Crl::assemble(&der, other, BitString::new(vec![1], 0).unwrap()), Err(Error::SignatureMismatch));
    }

    #[test]
    fn the_doc_example_works() {
        let ecdsa_sha256 = AlgorithmIdentifier { oid: oid(oid::ECDSA_WITH_SHA256), parameters: None };
        let mut name = Name::default();
        name.push(oid(oid::COUNTRY), text(StringKind::Printable, "US"));
        name.push(oid(oid::COMMON_NAME), text(StringKind::Utf8, "www.example.com"));
        let p256 = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        let mut point = vec![0x04];
        point.extend_from_slice(&[0x11; 64]);
        let tbs = TbsCertificate {
            version: Version::V3,
            serial: vec![0x12, 0x34],
            signature: ecdsa_sha256.clone(),
            issuer: name.clone(),
            validity: Validity {
                not_before: Time::from_unix(1_735_689_600).unwrap(),
                not_after: Time::from_unix(2_051_222_400).unwrap(),
            },
            subject: name,
            public_key: PublicKeyInfo {
                algorithm: AlgorithmIdentifier { oid: oid(oid::EC_PUBLIC_KEY), parameters: Some(p256) },
                key: BitString::new(point, 0).unwrap(),
            },
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: vec![
                BasicConstraints { ca: false, path_len: None }.to_extension(true).unwrap(),
                SubjectAltName(vec![GeneralName::Dns("www.example.com".into())]).to_extension(false).unwrap(),
            ],
        };
        let tbs_der = tbs.to_der().unwrap();
        let signature = BitString::new(vec![0x30, 0x00], 0).unwrap();
        let cert = Certificate::assemble(&tbs_der, ecdsa_sha256, signature).unwrap();
        let pem = cert.to_pem().unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        let back = Certificate::from_pem(pem.as_bytes()).unwrap();
        assert_eq!(back.tbs_der, tbs_der);
        assert_eq!(back.tbs, tbs);
        assert_eq!(back.tbs.subject.to_string(), "CN=www.example.com,C=US");
        assert_eq!(back.tbs.validity.not_after.text(), "350101000000Z");
        let san = back.tbs.get::<SubjectAltName>().unwrap().unwrap();
        assert_eq!(san.0, [GeneralName::Dns("www.example.com".into())]);
        // BasicConstraints with cA FALSE is an empty sequence.
        assert_eq!(back.tbs.extensions[0].value, [0x30, 0x00]);
    }

    #[test]
    fn rfc4514_examples() {
        let dc = |s: &str| vec![Attribute { oid: oid(oid::DOMAIN_COMPONENT), value: text(StringKind::Ia5, s) }];
        let one = |o: &[u8], s: &str| vec![Attribute { oid: oid(o), value: text(StringKind::Utf8, s) }];
        // Section 4's examples. RDNs are listed most general first.
        let n = Name { rdns: vec![dc("net"), dc("example"), one(oid::USER_ID, "jsmith")] };
        assert_eq!(n.to_string(), "UID=jsmith,DC=example,DC=net");
        let multi = vec![
            Attribute { oid: oid(oid::ORGANIZATIONAL_UNIT), value: text(StringKind::Utf8, "Sales") },
            Attribute { oid: oid(oid::COMMON_NAME), value: text(StringKind::Utf8, "J.  Smith") },
        ];
        let n = Name { rdns: vec![dc("net"), dc("example"), multi] };
        assert_eq!(n.to_string(), "OU=Sales+CN=J.  Smith,DC=example,DC=net");
        // DER puts OU first in the set, since its encoding is shorter.
        assert_eq!(Name::from_der(&n.to_der().unwrap()).unwrap(), n);
        let n = Name { rdns: vec![dc("net"), dc("example"), one(oid::COMMON_NAME, "James \"Jim\" Smith, III")] };
        assert_eq!(n.to_string(), "CN=James \\\"Jim\\\" Smith\\, III,DC=example,DC=net");
        let n = Name { rdns: vec![dc("net"), dc("example"), one(oid::COMMON_NAME, "Before\rAfter")] };
        assert_eq!(n.to_string(), "CN=Before\\0dAfter,DC=example,DC=net");
        let n = Name {
            rdns: vec![
                dc("com"),
                dc("example"),
                vec![Attribute {
                    oid: "1.3.6.1.4.1.1466.0".parse().unwrap(),
                    value: Value::Raw(vec![0x04, 0x02, 0x48, 0x69]),
                }],
            ],
        };
        assert_eq!(n.to_string(), "1.3.6.1.4.1.1466.0=#04024869,DC=example,DC=com");
        assert_eq!(Name::from_der(&n.to_der().unwrap()).unwrap(), n);
        let n = Name { rdns: vec![one(oid::COMMON_NAME, "Lu\u{10d}i\u{107}")] };
        assert_eq!(n.to_string(), "CN=Lu\u{10d}i\u{107}");
        // Leading and trailing spaces, a leading #, and the other specials.
        let n = Name { rdns: vec![one(oid::COMMON_NAME, " #a+b;c<d>e\\f #")] };
        assert_eq!(n.to_string(), r"CN=\ #a\+b\;c\<d\>e\\f #");
        let n = Name { rdns: vec![one(oid::COMMON_NAME, "a ")] };
        assert_eq!(n.to_string(), "CN=a\\ ");
        let n = Name { rdns: vec![one(oid::COMMON_NAME, "\0")] };
        assert_eq!(n.to_string(), "CN=\\00");
        // A type with no short name has its value in hex.
        let n =
            Name { rdns: vec![vec![Attribute { oid: oid(oid::EMAIL_ADDRESS), value: text(StringKind::Ia5, "a@b") }]] };
        assert_eq!(n.to_string(), "1.2.840.113549.1.9.1=#1603614062");
        // A short-named type with a raw value.
        let n = Name {
            rdns: vec![vec![Attribute { oid: oid(oid::COMMON_NAME), value: Value::Raw(vec![0x14, 0x01, 0x41]) }]],
        };
        assert_eq!(n.to_string(), "CN=#140141");
        assert_eq!(Name::from_der(&n.to_der().unwrap()).unwrap(), n);
        assert_eq!(Name::default().to_string(), "");
    }

    #[test]
    fn times() {
        assert_eq!(Time::from_unix(0).unwrap(), Time::Utc("700101000000Z".into()));
        assert_eq!(Time::from_unix(-631_152_000).unwrap(), Time::Utc("500101000000Z".into()));
        assert_eq!(Time::from_unix(-631_152_001), Err(Error::Value));
        // The last second of 2049 is a UTCTime, and the next a
        // GeneralizedTime (RFC 5280 4.1.2.5).
        assert_eq!(Time::from_unix(2_524_607_999).unwrap(), Time::Utc("491231235959Z".into()));
        assert_eq!(Time::from_unix(2_524_608_000).unwrap(), Time::Generalized("20500101000000Z".into()));
        assert_eq!(Time::from_unix(253_402_300_799).unwrap(), Time::Generalized("99991231235959Z".into()));
        assert_eq!(Time::from_unix(253_402_300_800), Err(Error::Value));
        assert_eq!(Time::from_unix(i64::MIN), Err(Error::Value));
        assert_eq!(Time::from_unix(i64::MAX), Err(Error::Value));
        // A leap day.
        assert_eq!(Time::from_unix(951_782_400).unwrap(), Time::Utc("000229000000Z".into()));
        for secs in [-631_152_000, -1, 0, 1, 951_782_400, 2_524_607_999, 2_524_608_000, 4_102_444_800, 253_402_300_799]
        {
            assert_eq!(Time::from_unix(secs).unwrap().unix(), Some(secs));
        }
        let mut x = 12345u64;
        for _ in 0..2000 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let secs = -631_152_000 + (x >> 20) as i64 % 254_033_452_800;
            let t = Time::from_unix(secs).unwrap();
            assert_eq!(t.unix(), Some(secs));
            // What the writer takes, DER reads.
            let mut w = Writer::new();
            write_time(&mut w, &t);
            let der = w.finish().unwrap();
            assert_eq!(read_time(&mut Reader::new(&der, Rules::Der)).unwrap(), t);
        }
        assert_eq!(Time::Generalized("20500101000000.5Z".into()).unix(), Some(2_524_608_000));
        for bad in [
            "",
            "20500101000000",
            "2050010100000Z",
            "20501301000000Z",
            "20500230000000Z",
            "20500101240000Z",
            "20500101000000.Z",
            "20500101000000xZ",
        ] {
            assert_eq!(Time::Generalized(bad.into()).unix(), None, "{bad}");
        }
        for bad in ["", "500101000000", "5001010000Z", "501301000000Z", "50010100000aZ"] {
            assert_eq!(Time::Utc(bad.into()).unix(), None, "{bad}");
        }
        let v = Validity { not_before: Time::Utc("bad".into()), not_after: Time::from_unix(0).unwrap() };
        assert!(!v.contains(0));
        // A time the writer cannot write is an error, not bad output.
        let mut tbs = sample_tbs();
        tbs.validity.not_after = Time::Utc("20500101000000Z".into());
        assert!(matches!(tbs.to_der(), Err(Error::Asn1(asn1::Error::Time))));
    }

    #[test]
    fn version_rules() {
        let tbs = sample_tbs();
        let der = tbs.to_der().unwrap();
        // v3 is written as [0] { INTEGER 2 } after the SEQUENCE header.
        assert_eq!(der[2..7], [0xa0, 0x03, 0x02, 0x01, 0x02]);
        let v1 = TbsCertificate { version: Version::V1, ..tbs.clone() };
        let v1_der = v1.to_der().unwrap();
        assert_eq!(v1_der[2], 0x02);
        assert_eq!(TbsCertificate::parse(&v1_der).unwrap(), v1);
        // Extensions need v3.
        let mut e = tbs.clone();
        e.extensions.push(BasicConstraints::default().to_extension(false).unwrap());
        assert!(e.to_der().is_ok());
        e.version = Version::V2;
        assert_eq!(e.to_der(), Err(Error::Version));
        // Unique identifiers need v2 or v3.
        let mut u = TbsCertificate { version: Version::V2, ..tbs.clone() };
        u.issuer_unique_id = Some(BitString::new(vec![0xaa], 0).unwrap());
        u.subject_unique_id = Some(BitString::new(vec![0xf0], 4).unwrap());
        let u_der = u.to_der().unwrap();
        assert_eq!(TbsCertificate::parse(&u_der).unwrap(), u);
        u.version = Version::V1;
        assert_eq!(u.to_der(), Err(Error::Version));
        // An unknown version number.
        let mut bad = der.clone();
        bad[6] = 3;
        assert_eq!(TbsCertificate::parse(&bad), Err(Error::Version));
        assert_eq!(Version::from_number(-1), Err(Error::Version));
        // An explicit v1 is read, and left out when written.
        let mut explicit = vec![0xa0, 0x03, 0x02, 0x01, 0x00];
        explicit.extend_from_slice(&v1_der[2..]);
        let mut seq = vec![0x30, explicit.len() as u8];
        seq.extend_from_slice(&explicit);
        assert_eq!(TbsCertificate::parse(&seq).unwrap(), v1);
    }

    #[test]
    fn certificate_errors() {
        let der = cert_der();
        let tbs = TbsCertificate::parse(&Certificate::parse(&der).unwrap().tbs_der).unwrap();
        // Outer and inner algorithms must match.
        let rsa = AlgorithmIdentifier { oid: oid(oid::SHA256_WITH_RSA), parameters: Some(vec![0x05, 0x00]) };
        let sig = BitString::new(vec![1, 2, 3], 0).unwrap();
        let tbs_der = tbs.to_der().unwrap();
        assert_eq!(Certificate::assemble(&tbs_der, rsa.clone(), sig.clone()), Err(Error::SignatureMismatch));
        let mut cert = Certificate::parse(&der).unwrap();
        cert.signature_algorithm = rsa;
        assert_eq!(cert.to_der(), Err(Error::SignatureMismatch));
        // Bytes that are not a TBSCertificate cannot be assembled.
        let ed = AlgorithmIdentifier { oid: oid(oid::ED25519), parameters: None };
        assert!(Certificate::assemble(&[0x30, 0x00], ed.clone(), sig.clone()).is_err());
        let mut cert = Certificate::parse(&der).unwrap();
        cert.tbs_der = vec![0x05, 0x00];
        assert!(cert.to_der().is_err());
        // Too long.
        let mut long = der.clone();
        long.resize(MAX_CERT + 1, 0);
        assert_eq!(Certificate::parse(&long), Err(Error::TooLong));
        assert_eq!(TbsCertificate::parse(&long), Err(Error::TooLong));
        assert_eq!(Crl::parse(&vec![0; MAX_CRL + 1]), Err(Error::TooLong));
        assert_eq!(TbsCertList::parse(&vec![0; MAX_CRL + 1]), Err(Error::TooLong));
        // Trailing bytes.
        let mut trailing = der.clone();
        trailing.push(0);
        assert_eq!(Certificate::parse(&trailing), Err(Error::Asn1(asn1::Error::Trailing)));
        // Not a sequence.
        assert!(matches!(Certificate::parse(&[0x31, 0x00]), Err(Error::Asn1(asn1::Error::Unexpected { .. }))));
        assert!(matches!(TbsCertificate::parse(&[0x31, 0x00]), Err(Error::Asn1(asn1::Error::Unexpected { .. }))));
        assert!(matches!(TbsCertList::parse(&[0x31, 0x00]), Err(Error::Asn1(asn1::Error::Unexpected { .. }))));
        assert_eq!(Certificate::parse(&[]), Err(Error::Asn1(asn1::Error::Empty)));
        // Two extensions with one identifier.
        let mut dup = tbs.clone();
        dup.extensions.push(dup.extensions[0].clone());
        assert_eq!(dup.to_der(), Err(Error::DuplicateExtension));
        // Too many extensions.
        let mut many = sample_tbs();
        for i in 0..=MAX_EXTENSIONS as u128 {
            many.extensions.push(Extension {
                oid: Oid::from_arcs(&[1, 2, i]).unwrap(),
                critical: false,
                value: vec![],
            });
        }
        assert_eq!(many.to_der(), Err(Error::TooMany));
        many.extensions.pop();
        assert!(many.to_der().is_ok());
        // A malformed extension value reads as an error from `get`.
        let mut broken = sample_tbs();
        broken.extensions.push(Extension { oid: oid(oid::KEY_USAGE), critical: true, value: vec![0x05, 0x00] });
        let broken = TbsCertificate::parse(&broken.to_der().unwrap()).unwrap();
        assert!(broken.get::<KeyUsage>().is_err());
        assert_eq!(broken.get::<BasicConstraints>(), Ok(None));
        // An explicit critical FALSE is read, and left out when written.
        let ext = [0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0x00, 0x04, 0x02, 0x30, 0x00];
        let mut list = vec![0x30, ext.len() as u8];
        list.extend_from_slice(&ext);
        let read = read_extensions(&mut Reader::new(&list, Rules::Der)).unwrap();
        assert!(!read[0].critical);
        assert_eq!(build(|w| write_extensions(w, &read)).unwrap().len(), list.len() - 3);
        // A string value with characters its type does not allow.
        let mut bad = sample_tbs();
        bad.subject.push(oid(oid::COUNTRY), text(StringKind::Printable, "a@b"));
        assert_eq!(bad.to_der(), Err(Error::Asn1(asn1::Error::Charset)));
        // A name with too many parts, and an RDN with too many attributes.
        let mut big = sample_tbs();
        big.subject.rdns =
            vec![vec![Attribute { oid: oid(oid::COMMON_NAME), value: text(StringKind::Utf8, "x") }]; MAX_RDNS + 1];
        assert_eq!(big.to_der(), Err(Error::TooMany));
        let attrs: Vec<Attribute> = (0..=MAX_RDN_ATTRIBUTES)
            .map(|i| Attribute { oid: oid(oid::COMMON_NAME), value: text(StringKind::Utf8, &i.to_string()) })
            .collect();
        big.subject.rdns = vec![attrs];
        assert_eq!(big.to_der(), Err(Error::TooMany));
        // An empty RDN.
        big.subject.rdns = vec![vec![]];
        assert_eq!(big.to_der(), Err(Error::Empty));
        // A raw value that is not one DER element.
        big.subject.rdns =
            vec![vec![Attribute { oid: oid(oid::COMMON_NAME), value: Value::Raw(vec![0x02, 0x02, 0x00, 0x01]) }]];
        assert_eq!(big.to_der(), Err(Error::Asn1(asn1::Error::Integer)));
        big.subject.rdns = vec![vec![Attribute { oid: oid(oid::COMMON_NAME), value: Value::Raw(vec![]) }]];
        assert!(big.to_der().is_err());
        // Bad algorithm parameters.
        let mut alg = sample_tbs();
        alg.public_key.algorithm.parameters = Some(vec![0x05, 0x01, 0x00]);
        assert_eq!(alg.to_der(), Err(Error::Asn1(asn1::Error::Null)));
    }

    #[test]
    fn raw_values_nest_only_so_deep() {
        // A raw value nested as deep as the check allows writes; one level
        // deeper does not read.
        let deep = |levels: usize| {
            let mut v = vec![0x05, 0x00];
            for _ in 0..levels {
                let mut s = vec![0x30, v.len() as u8];
                s.extend_from_slice(&v);
                v = s;
            }
            v
        };
        let ok = asn1::MAX_DEPTH - RAW_CHECK_DEPTH;
        assert!(check_raw(&deep(ok)).is_ok());
        assert_eq!(check_raw(&deep(ok + 1)), Err(Error::Asn1(asn1::Error::TooDeep)));
        let mut tbs = sample_tbs();
        tbs.subject.rdns = vec![vec![Attribute { oid: oid(oid::COMMON_NAME), value: Value::Raw(deep(ok)) }]];
        let der = tbs.to_der().unwrap();
        let cert = Certificate::assemble(&der, tbs.signature.clone(), BitString::new(vec![1], 0).unwrap()).unwrap();
        assert_eq!(Certificate::parse(&cert.to_der().unwrap()).unwrap().tbs, tbs);
        tbs.subject.rdns[0][0].value = Value::Raw(deep(ok + 1));
        assert!(tbs.to_der().is_err());
    }

    #[test]
    fn extension_values_round_trip() {
        let dir = {
            let mut n = Name::default();
            n.push(oid(oid::COMMON_NAME), text(StringKind::Utf8, "dir"));
            n
        };
        let names = vec![
            GeneralName::Other { type_id: oid(oid::EMAIL_ADDRESS), value: vec![0x0c, 0x01, 0x61] },
            GeneralName::Email("a@b".into()),
            GeneralName::Dns("*.example.com".into()),
            GeneralName::Unsupported(vec![0xa3, 0x02, 0x05, 0x00]),
            GeneralName::Directory(dir.clone()),
            GeneralName::Unsupported(vec![0xa5, 0x00]),
            uri("urn:x"),
            GeneralName::Ip(vec![10, 0, 0, 0, 255, 0, 0, 0]),
            GeneralName::RegisteredId(oid(oid::OCSP)),
        ];
        let san = SubjectAltName(names.clone());
        assert_eq!(SubjectAltName::from_der(&san.to_der().unwrap()).unwrap(), san);
        let aki = AuthorityKeyIdentifier {
            key_id: Some(vec![1, 2]),
            issuer: Some(names.clone()),
            serial: Some(vec![0x00, 0xff]),
        };
        assert_eq!(AuthorityKeyIdentifier::from_der(&aki.to_der().unwrap()).unwrap(), aki);
        assert_eq!(AuthorityKeyIdentifier::from_der(&[0x30, 0x00]).unwrap(), AuthorityKeyIdentifier::default());
        let dps = CrlDistributionPoints(vec![
            DistributionPoint {
                name: Some(DistributionPointName::RelativeToIssuer(dir.rdns[0].clone())),
                reasons: Some(ReasonFlags(ReasonFlags::KEY_COMPROMISE | ReasonFlags::AA_COMPROMISE)),
                crl_issuer: Some(vec![GeneralName::Directory(dir.clone())]),
            },
            DistributionPoint::default(),
            DistributionPoint {
                name: Some(DistributionPointName::Full(names.clone())),
                reasons: Some(ReasonFlags(0)),
                crl_issuer: None,
            },
        ]);
        assert_eq!(CrlDistributionPoints::from_der(&dps.to_der().unwrap()).unwrap(), dps);
        let aia = AuthorityInfoAccess(vec![AccessDescription {
            method: oid(oid::CA_ISSUERS),
            location: GeneralName::Directory(dir),
        }]);
        assert_eq!(AuthorityInfoAccess::from_der(&aia.to_der().unwrap()).unwrap(), aia);
        for bits in [0u16, 1, 0x80, 0x100, 0x1ff, 0x8000, 0xffff] {
            let ku = KeyUsage(bits);
            let der = ku.to_der().unwrap();
            assert_eq!(KeyUsage::from_der(&der).unwrap(), ku);
            // No trailing zero bits (X.690 11.2.2).
            if bits != 0 {
                let unused = der[2];
                assert_ne!(der[der.len() - 1] & (1 << unused), 0, "{bits:#x}");
            }
        }
        assert_eq!(KeyUsage(0).to_der().unwrap(), [0x03, 0x01, 0x00]);
        assert_eq!(KeyUsage(KeyUsage::DIGITAL_SIGNATURE).to_der().unwrap(), [0x03, 0x02, 0x07, 0x80]);
        assert_eq!(KeyUsage(KeyUsage::DECIPHER_ONLY).to_der().unwrap(), [0x03, 0x03, 0x07, 0x00, 0x80]);
        // Trailing zero bits are read.
        assert_eq!(KeyUsage::from_der(&[0x03, 0x02, 0x00, 0x80]).unwrap(), KeyUsage(1));
        let bc = BasicConstraints { ca: true, path_len: Some(u64::MAX) };
        assert_eq!(BasicConstraints::from_der(&bc.to_der().unwrap()).unwrap(), bc);
        // An explicit cA FALSE is read.
        assert_eq!(BasicConstraints::from_der(&[0x30, 0x03, 0x01, 0x01, 0x00]).unwrap(), BasicConstraints::default());
        let eku = ExtendedKeyUsage(vec![oid(oid::TIME_STAMPING)]);
        assert_eq!(ExtendedKeyUsage::from_der(&eku.to_der().unwrap()).unwrap(), eku);
        let ski = SubjectKeyIdentifier(vec![]);
        assert_eq!(SubjectKeyIdentifier::from_der(&ski.to_der().unwrap()).unwrap(), ski);
    }

    #[test]
    fn extension_value_errors() {
        // Lists that must hold at least one item.
        assert_eq!(SubjectAltName(vec![]).to_der(), Err(Error::Empty));
        assert_eq!(SubjectAltName::from_der(&[0x30, 0x00]), Err(Error::Empty));
        assert_eq!(ExtendedKeyUsage::from_der(&[0x30, 0x00]), Err(Error::Empty));
        assert_eq!(ExtendedKeyUsage(vec![]).to_der(), Err(Error::Empty));
        assert_eq!(CrlDistributionPoints::from_der(&[0x30, 0x00]), Err(Error::Empty));
        assert_eq!(AuthorityInfoAccess::from_der(&[0x30, 0x00]), Err(Error::Empty));
        let full_empty = DistributionPoint { name: Some(DistributionPointName::Full(vec![])), ..Default::default() };
        assert_eq!(CrlDistributionPoints(vec![full_empty]).to_der(), Err(Error::Empty));
        let rel_empty =
            DistributionPoint { name: Some(DistributionPointName::RelativeToIssuer(vec![])), ..Default::default() };
        assert_eq!(CrlDistributionPoints(vec![rel_empty]).to_der(), Err(Error::Empty));
        // Lists past their limits.
        assert_eq!(
            SubjectAltName(vec![GeneralName::Dns("a".into()); MAX_GENERAL_NAMES + 1]).to_der(),
            Err(Error::TooMany)
        );
        assert!(SubjectAltName(vec![GeneralName::Dns("a".into()); MAX_GENERAL_NAMES]).to_der().is_ok());
        assert_eq!(ExtendedKeyUsage(vec![oid(oid::SERVER_AUTH); MAX_KEY_PURPOSES + 1]).to_der(), Err(Error::TooMany));
        assert_eq!(
            CrlDistributionPoints(vec![DistributionPoint::default(); MAX_DISTRIBUTION_POINTS + 1]).to_der(),
            Err(Error::TooMany)
        );
        let ad = AccessDescription { method: oid(oid::OCSP), location: uri("x") };
        assert_eq!(AuthorityInfoAccess(vec![ad; MAX_ACCESS_DESCRIPTIONS + 1]).to_der(), Err(Error::TooMany));
        // Named bits past 15.
        assert_eq!(KeyUsage::from_der(&[0x03, 0x04, 0x07, 0x00, 0x00, 0x80]), Err(Error::Value));
        // General names: unknown tags, universal tags, wrong forms.
        assert_eq!(SubjectAltName::from_der(&[0x30, 0x02, 0x89, 0x00]), Err(Error::Value));
        assert_eq!(SubjectAltName::from_der(&[0x30, 0x02, 0x04, 0x00]), Err(Error::Value));
        assert_eq!(SubjectAltName::from_der(&[0x30, 0x02, 0x83, 0x00]), Err(Error::Asn1(asn1::Error::Primitive)));
        assert_eq!(SubjectAltName::from_der(&[0x30, 0x02, 0xa2, 0x00]), Err(Error::Asn1(asn1::Error::Constructed)));
        assert_eq!(SubjectAltName::from_der(&[0x30, 0x03, 0x82, 0x01, 0x80]), Err(Error::Asn1(asn1::Error::Charset)));
        assert_eq!(
            SubjectAltName(vec![GeneralName::Dns("\u{e9}".into())]).to_der(),
            Err(Error::Asn1(asn1::Error::Charset))
        );
        assert!(SubjectAltName(vec![GeneralName::Unsupported(vec![0xa4, 0x00])]).to_der().is_err());
        assert!(SubjectAltName(vec![GeneralName::Unsupported(vec![0x04, 0x00])]).to_der().is_err());
        assert!(
            SubjectAltName(vec![GeneralName::Other { type_id: oid(oid::OCSP), value: vec![0x02, 0x00] }])
                .to_der()
                .is_err()
        );
        // A distribution point name that is neither [0] nor [1].
        assert_eq!(
            CrlDistributionPoints::from_der(&[0x30, 0x06, 0x30, 0x04, 0xa0, 0x02, 0xa2, 0x00]),
            Err(Error::Value)
        );
        // A negative path length, and trailing fields.
        assert_eq!(BasicConstraints::from_der(&[0x30, 0x03, 0x02, 0x01, 0xff]), Err(Error::Asn1(asn1::Error::Integer)));
        assert_eq!(
            BasicConstraints::from_der(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]),
            Err(Error::Asn1(asn1::Error::Trailing))
        );
        // Fields out of order.
        assert_eq!(
            AuthorityKeyIdentifier::from_der(&[0x30, 0x06, 0x82, 0x01, 0x01, 0x80, 0x01, 0x01]),
            Err(Error::Asn1(asn1::Error::Trailing))
        );
    }

    #[test]
    fn every_truncated_prefix_is_refused() {
        let cert = cert_der();
        for n in 0..cert.len() {
            assert!(Certificate::parse(&cert[..n]).is_err(), "{n}");
        }
        let tbs = Certificate::parse(&cert).unwrap().tbs_der;
        for n in 0..tbs.len() {
            assert!(TbsCertificate::parse(&tbs[..n]).is_err(), "{n}");
        }
        let crl = crl_der();
        for n in 0..crl.len() {
            assert!(Crl::parse(&crl[..n]).is_err(), "{n}");
        }
        let c = Certificate::parse(&cert).unwrap();
        for x in &c.tbs.extensions {
            for n in 0..x.value.len() {
                let v = &x.value[..n];
                assert!(BasicConstraints::from_der(v).is_err());
                assert!(KeyUsage::from_der(v).is_err());
                assert!(ExtendedKeyUsage::from_der(v).is_err());
                assert!(SubjectAltName::from_der(v).is_err());
                assert!(SubjectKeyIdentifier::from_der(v).is_err());
                assert!(AuthorityKeyIdentifier::from_der(v).is_err());
                assert!(CrlDistributionPoints::from_der(v).is_err());
                assert!(AuthorityInfoAccess::from_der(v).is_err());
            }
        }
        // PEM text cut short: nothing before the BEGIN line is complete, a
        // block cut before its end marker is an error, and once the marker
        // is all there the block is whole.
        let text = CERT_PEM.as_bytes();
        let begin_end = text.iter().position(|&c| c == b'\n').unwrap() + 1;
        let marker_end = text.len() - 1;
        for n in 0..text.len() {
            let r = pem_decode(&text[..n]);
            if n < begin_end {
                assert_eq!(r, Ok(vec![]), "{n}");
            } else if n < marker_end {
                assert_eq!(r, Err(Error::Pem), "{n}");
            } else {
                assert_eq!(r.unwrap().len(), 1, "{n}");
            }
        }
    }

    #[test]
    fn pem() {
        let blocks = pem_decode(format!("text before\n{CERT_PEM}between\r\n{CRL_PEM}after").as_bytes()).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].label, "CERTIFICATE");
        assert_eq!(blocks[1].label, "X509 CRL");
        assert_eq!(blocks[1].data, crl_der());
        // CRLF line endings, spaces and short lines are read.
        let crlf = CERT_PEM.replace('\n', " \r\n").replace("MIIC8DCC", "MIIC\n8DCC");
        assert_eq!(pem_decode(crlf.as_bytes()).unwrap()[0].data, cert_der());
        // RFC 4648 test vectors, through PEM.
        for (data, b64) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(data.as_bytes()), b64);
            assert_eq!(base64_decode(b64.as_bytes()).unwrap(), data.as_bytes());
            let p = Pem { label: "X".into(), data: data.as_bytes().to_vec() };
            let text = p.encode().unwrap();
            assert_eq!(
                text,
                if b64.is_empty() {
                    "-----BEGIN X-----\n-----END X-----\n".to_string()
                } else {
                    format!("-----BEGIN X-----\n{b64}\n-----END X-----\n")
                }
            );
            assert_eq!(pem_decode(text.as_bytes()).unwrap(), [p]);
        }
        // Bad base64.
        for bad in ["Zg=", "Z===", "Zg=a", "Z", "Zm9v=", "Zm=v", "Zm9*"] {
            let text = format!("-----BEGIN X-----\n{bad}\n-----END X-----\n");
            assert_eq!(pem_decode(text.as_bytes()), Err(Error::Pem), "{bad}");
        }
        // A mismatched or missing end line.
        assert_eq!(pem_decode(b"-----BEGIN X-----\nZg==\n-----END Y-----\n"), Err(Error::Pem));
        assert_eq!(pem_decode(b"-----BEGIN X-----\nZg==\n"), Err(Error::Pem));
        // Malformed BEGIN lines are text.
        for line in [
            "-----BEGIN X----",
            "-----BEGIN -X-----",
            "-----BEGIN X  Y-----",
            "-----BEGIN X-----Z",
            " -----BEGIN X-----",
        ] {
            assert_eq!(pem_decode(format!("{line}\nZg==\n").as_bytes()), Ok(vec![]), "{line}");
        }
        // An empty label, and trailing whitespace after BEGIN.
        assert_eq!(pem_decode(b"-----BEGIN -----\t \n-----END -----").unwrap()[0].label, "");
        // Labels the encoder refuses.
        for label in ["-X", "X-", "a\nb", "a  b", &"L".repeat(MAX_PEM_LABEL + 1)] {
            assert_eq!(Pem { label: label.into(), data: vec![] }.encode(), Err(Error::Pem), "{label}");
        }
        assert_eq!(Pem { label: "X".into(), data: vec![0; MAX_PEM_DATA + 1] }.encode(), Err(Error::TooLong));
        // A big block encodes and decodes.
        let big = Pem { label: "X".into(), data: (0..MAX_PEM_DATA).map(|i| i as u8).collect() };
        assert_eq!(pem_decode(big.encode().unwrap().as_bytes()).unwrap(), [big]);
        // Too much data, too long a line, too many blocks.
        let mut text = b"-----BEGIN X-----\n".to_vec();
        let line = [b'A'; 64];
        for _ in 0..MAX_PEM_CHARS / 64 + 1 {
            text.extend_from_slice(&line);
            text.push(b'\n');
        }
        assert_eq!(pem_decode(&text), Err(Error::TooLong));
        let long = vec![b'a'; MAX_PEM_LINE + 1];
        assert_eq!(pem_decode(&long), Err(Error::TooLong));
        let mut long_line = b"-----BEGIN X-----\n".to_vec();
        long_line.extend_from_slice(&[b'A'; MAX_PEM_LINE + 1]);
        assert_eq!(pem_decode(&long_line), Err(Error::TooLong));
        long_line.push(b'\n');
        assert_eq!(pem_decode(&long_line), Err(Error::TooLong));
        let many = "-----BEGIN X-----\n-----END X-----\n".repeat(MAX_PEM_BLOCKS + 1);
        assert_eq!(pem_decode(many.as_bytes()), Err(Error::TooMany));
        // Text after an end marker on its line is outside the block.
        assert_eq!(pem_decode(b"-----BEGIN X-----\nZg==\n-----END X-----junk\n").unwrap().len(), 1);
        assert_eq!(
            Certificate::from_pem(b"-----BEGIN CERTIFICATE-----\nZg==\n-----END CERTIFICATE-----\n").map(drop),
            Err(Error::Asn1(asn1::Error::Truncated))
        );
    }

    /// Every block the decoder gives, and whether it failed.
    fn decode_stream(text: &[u8], chunk: usize) -> (Vec<Pem>, bool) {
        let mut d = PemDecoder::new();
        let mut out = Vec::new();
        for c in text.chunks(chunk.max(1)) {
            d.feed(c);
            while let Some(r) = d.next_block() {
                match r {
                    Ok(p) => out.push(p),
                    Err(_) => return (out, true),
                }
            }
        }
        (out, false)
    }

    #[test]
    fn pem_decoder_splits_a_stream() {
        let text = format!("junk\n{CERT_PEM}{CRL_PEM}{CERT_PEM}");
        let whole = decode_stream(text.as_bytes(), text.len());
        assert_eq!(whole.0.len(), 3);
        assert!(!whole.1);
        for chunk in [1, 2, 3, 7, 64, 65] {
            assert_eq!(decode_stream(text.as_bytes(), chunk), whole, "{chunk}");
        }
        let mut d = PemDecoder::new();
        for b in text.as_bytes() {
            d.feed(std::slice::from_ref(b));
            while let Some(r) = d.next_block() {
                r.unwrap();
            }
        }
        assert!(!d.in_block());
        assert_eq!(d.buffered(), 0);
        // A block cut short.
        let mut d = PemDecoder::new();
        d.feed(&CERT_PEM.as_bytes()[..100]);
        assert!(d.next_block().is_none());
        assert!(d.in_block());
        // A broken stream stays broken.
        d.feed(b"!!!\n");
        assert_eq!(d.next_block(), Some(Err(Error::Pem)));
        d.feed(CERT_PEM.as_bytes());
        assert_eq!(d.next_block(), Some(Err(Error::Pem)));
        assert_eq!(d.buffered(), 0);
        // A long line fed a byte at a time is refused once it is too long.
        let mut d = PemDecoder::new();
        for _ in 0..MAX_PEM_LINE {
            d.feed(b"a");
            assert_eq!(d.next_block(), None);
        }
        d.feed(b"a");
        assert_eq!(d.next_block(), Some(Err(Error::TooLong)));
    }

    #[test]
    fn pem_decoder_takes_a_big_block_a_byte_at_a_time_in_linear_time() {
        let big = Pem { label: "X".into(), data: vec![0x5a; MAX_PEM_DATA] }.encode().unwrap();
        let started = std::time::Instant::now();
        let mut d = PemDecoder::new();
        let mut n = 0;
        for b in big.as_bytes() {
            d.feed(std::slice::from_ref(b));
            while let Some(r) = d.next_block() {
                assert_eq!(r.unwrap().data.len(), MAX_PEM_DATA);
                n += 1;
            }
        }
        assert_eq!(n, 1);
        assert!(started.elapsed().as_secs() < 10, "took {:?}", started.elapsed());
    }

    /// The checks the fuzz target makes, on one input.
    fn check(data: &[u8]) {
        if let Ok(c) = Certificate::parse(data) {
            assert_eq!(c.to_der().unwrap(), data);
            let tbs = c.tbs.to_der().unwrap();
            assert_eq!(TbsCertificate::parse(&tbs).unwrap(), c.tbs);
            let _ = (c.tbs.subject.to_string(), c.tbs.issuer.to_string(), c.tbs.validity.contains(0));
            let pem = c.to_pem().unwrap();
            assert_eq!(Certificate::from_pem(pem.as_bytes()).unwrap(), c);
            for x in &c.tbs.extensions {
                check_extension_value(&x.value);
            }
        }
        if let Ok(c) = Crl::parse(data) {
            assert_eq!(c.to_der().unwrap(), data);
            let tbs = c.tbs.to_der().unwrap();
            assert_eq!(TbsCertList::parse(&tbs).unwrap(), c.tbs);
            let _ = c.tbs.issuer.to_string();
            for x in c.tbs.extensions.iter().chain(c.tbs.revoked.iter().flat_map(|r| &r.extensions)) {
                check_extension_value(&x.value);
            }
            if let Some(r) = c.tbs.revoked.first() {
                assert!(c.is_revoked(&r.serial));
            }
            let pem = c.to_pem().unwrap();
            assert_eq!(Crl::from_pem(pem.as_bytes()).unwrap(), c);
        }
        if let Ok(n) = Name::from_der(data) {
            assert_eq!(Name::from_der(&n.to_der().unwrap()).unwrap(), n);
            let _ = n.to_string();
        }
        check_extension_value(data);
    }

    fn round_trip<T: ExtensionValue + PartialEq + std::fmt::Debug>(data: &[u8]) {
        if let Ok(v) = T::from_der(data) {
            let der = v.to_der().unwrap();
            assert_eq!(T::from_der(&der).unwrap(), v);
            assert_eq!(v.to_extension(true).unwrap().value, der);
        }
    }

    fn check_extension_value(data: &[u8]) {
        round_trip::<BasicConstraints>(data);
        round_trip::<KeyUsage>(data);
        round_trip::<ExtendedKeyUsage>(data);
        round_trip::<SubjectAltName>(data);
        round_trip::<SubjectKeyIdentifier>(data);
        round_trip::<AuthorityKeyIdentifier>(data);
        round_trip::<CrlDistributionPoints>(data);
        round_trip::<AuthorityInfoAccess>(data);
        round_trip::<IssuerAltName>(data);
        round_trip::<CrlNumber>(data);
        round_trip::<CrlReason>(data);
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n.max(1) as u64) as usize
        }
    }

    #[test]
    fn fuzz_der_does_not_panic_and_round_trips() {
        let mut rng = Lcg(0x5eed);
        let seeds = [cert_der(), crl_der()];
        let exts: Vec<Vec<u8>> =
            Certificate::parse(&seeds[0]).unwrap().tbs.extensions.iter().map(|x| x.value.clone()).collect();
        let mut parsed = 0;
        for i in 0..6000 {
            let mut data = match i % 4 {
                0 => seeds[0].clone(),
                1 => seeds[1].clone(),
                2 => exts[rng.below(exts.len())].clone(),
                _ => (0..rng.below(200)).map(|_| rng.next() as u8).collect(),
            };
            // Change a few bytes, and sometimes cut or grow the buffer.
            for _ in 0..1 + rng.below(3) {
                if !data.is_empty() {
                    let at = rng.below(data.len());
                    data[at] = match rng.below(4) {
                        0 => rng.next() as u8,
                        1 => data[at] ^ (1 << rng.below(8)),
                        2 => data[at].wrapping_add(1),
                        _ => data[at].wrapping_sub(1),
                    };
                }
            }
            match rng.below(6) {
                0 => data.truncate(rng.below(data.len() + 1)),
                1 => {
                    let at = rng.below(data.len() + 1);
                    data.insert(at, rng.next() as u8);
                }
                _ => {}
            }
            check(&data);
            if Certificate::parse(&data).is_ok() || Crl::parse(&data).is_ok() {
                parsed += 1;
            }
        }
        // Some mutations keep a valid certificate or CRL, so the round
        // trips above ran.
        assert!(parsed > 50, "{parsed}");
    }

    #[test]
    fn fuzz_pem_whole_and_bytewise_agree() {
        let mut rng = Lcg(0xfeed);
        let pieces: [&[u8]; 12] = [
            b"-----BEGIN X-----\n",
            b"-----END X-----\n",
            b"-----BEGIN CERTIFICATE-----\n",
            b"-----END CERTIFICATE-----",
            b"Zm9v\n",
            b"Zg==\r\n",
            b"AAAA",
            b" \t",
            b"\n",
            b"junk -----\n",
            b"-----END Y-----\n",
            b"=",
        ];
        for _ in 0..4000 {
            let mut text = Vec::new();
            for _ in 0..rng.below(12) {
                if rng.below(8) == 0 {
                    text.push(rng.next() as u8);
                } else {
                    text.extend_from_slice(pieces[rng.below(pieces.len())]);
                }
            }
            if rng.below(10) == 0 {
                text.extend_from_slice(CERT_PEM.as_bytes());
            }
            let whole = decode_stream(&text, text.len());
            assert_eq!(decode_stream(&text, 1), whole);
            assert_eq!(decode_stream(&text, 1 + rng.below(9)), whole);
            match pem_decode(&text) {
                Ok(blocks) => {
                    assert!(!whole.1);
                    assert_eq!(blocks, whole.0);
                    for b in &blocks {
                        if let Ok(t) = b.encode() {
                            assert_eq!(pem_decode(t.as_bytes()).unwrap(), std::slice::from_ref(b));
                        }
                        check(&b.data);
                    }
                }
                // A block with no end is an error for the whole text, and
                // leaves a decoder waiting inside it.
                Err(Error::Pem) if !whole.1 => {
                    let mut d = PemDecoder::new();
                    d.feed(&text);
                    while d.next_block().is_some() {}
                    assert!(d.in_block());
                }
                Err(e) => assert!(whole.1, "{e}"),
            }
        }
    }

    /// `seq` (one SEQUENCE) with `child` added after its last child.
    fn append_child(seq: &[u8], child: &[u8]) -> Vec<u8> {
        let contents = single(seq).unwrap().contents();
        build(|w| {
            w.sequence(|w| {
                for c in Reader::new(contents, Rules::Der) {
                    w.encoded(c.unwrap().raw());
                }
                w.encoded(child);
            })
        })
        .unwrap()
    }

    #[test]
    fn an_empty_extension_list_is_refused() {
        // Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension (RFC 5280
        // 4.1 and 5.1), so an empty one is not DER for the type, and a v1
        // certificate or CRL that has one has an extensions field.
        let empty_cert_exts = [0xa3, 0x02, 0x30, 0x00];
        let v3 = sample_tbs().to_der().unwrap();
        assert_eq!(TbsCertificate::parse(&append_child(&v3, &empty_cert_exts)), Err(Error::Empty));
        let v1 = TbsCertificate { version: Version::V1, ..sample_tbs() }.to_der().unwrap();
        assert!(TbsCertificate::parse(&append_child(&v1, &empty_cert_exts)).is_err());

        let alg = AlgorithmIdentifier { oid: oid(oid::ED25519), parameters: None };
        let crl = TbsCertList {
            version: Version::V2,
            signature: alg,
            issuer: Name::default(),
            this_update: Time::from_unix(0).unwrap(),
            next_update: None,
            revoked: vec![],
            extensions: vec![],
        };
        let empty_crl_exts = [0xa0, 0x02, 0x30, 0x00];
        let v2 = crl.to_der().unwrap();
        assert_eq!(TbsCertList::parse(&append_child(&v2, &empty_crl_exts)), Err(Error::Empty));
        let v1 = TbsCertList { version: Version::V1, ..crl.clone() }.to_der().unwrap();
        assert!(TbsCertList::parse(&append_child(&v1, &empty_crl_exts)).is_err());

        // An entry's crlEntryExtensions has the same type.
        let entry = build(|w| {
            w.sequence(|w| {
                w.sequence(|w| {
                    w.integer_i64(1);
                    write_time(w, &Time::from_unix(0).unwrap());
                    w.sequence(|_| {});
                })
            })
        })
        .unwrap();
        assert_eq!(TbsCertList::parse(&append_child(&v2, &entry)), Err(Error::Empty));
        // The same entry with one extension is read.
        let entry = build(|w| {
            w.sequence(|w| {
                w.sequence(|w| {
                    w.integer_i64(1);
                    write_time(w, &Time::from_unix(0).unwrap());
                    write_extensions(w, &[SubjectKeyIdentifier(vec![1]).to_extension(false).unwrap()]);
                })
            })
        })
        .unwrap();
        assert_eq!(TbsCertList::parse(&append_child(&v2, &entry)).unwrap().revoked[0].extensions.len(), 1);
    }

    #[test]
    fn pem_lines_may_end_in_a_lone_cr() {
        // RFC 7468 section 3: eol = CRLF / CR / LF.
        for eol in ["\r", "\r\n", "\n", "\n\r"] {
            let text = format!("text before{eol}{}", CERT_PEM.replace('\n', eol));
            let blocks = pem_decode(text.as_bytes()).unwrap();
            assert_eq!(blocks.len(), 1, "{eol:?}");
            assert_eq!(blocks[0].data, cert_der());
            let whole = decode_stream(text.as_bytes(), text.len());
            assert_eq!(whole, (blocks.clone(), false));
            assert_eq!(decode_stream(text.as_bytes(), 1), whole);
            assert_eq!(decode_stream(text.as_bytes(), 7), whole);
        }
        // Vertical tabs and form feeds are whitespace in base64 text (W in
        // section 3).
        let text = "-----BEGIN X-----\n\x0bZm9v\x0cYg==\n-----END X-----\n";
        assert_eq!(pem_decode(text.as_bytes()).unwrap()[0].data, b"foob");
    }

    #[test]
    fn pem_data_past_its_limit_is_refused() {
        // MAX_PEM_DATA is not a multiple of 3, so the last base64 group
        // can hold a byte or two more than the limit. A reader refuses
        // them, so every block it returns encodes again.
        for extra in [1, 2] {
            let b64 = base64_encode(&vec![0x5a; MAX_PEM_DATA + extra]);
            let mut text = b"-----BEGIN X-----\n".to_vec();
            for line in b64.as_bytes().chunks(64) {
                text.extend_from_slice(line);
                text.push(b'\n');
            }
            text.extend_from_slice(b"-----END X-----\n");
            assert_eq!(pem_decode(&text), Err(Error::TooLong), "{extra}");
            assert_eq!(decode_stream(&text, 4096), (vec![], true), "{extra}");
        }
    }

    #[test]
    fn serials_compare_by_value() {
        let alg = AlgorithmIdentifier { oid: oid(oid::ED25519), parameters: None };
        let tbs = TbsCertList {
            version: Version::V1,
            signature: alg.clone(),
            issuer: Name::default(),
            this_update: Time::from_unix(0).unwrap(),
            next_update: None,
            revoked: vec![RevokedCertificate {
                serial: vec![0x00, 0x05],
                revocation_date: Time::from_unix(1).unwrap(),
                extensions: vec![],
            }],
            extensions: vec![],
        };
        // The writer writes the shortest form.
        let der = tbs.to_der().unwrap();
        let crl = Crl::assemble(&der, alg, BitString::new(vec![1], 0).unwrap()).unwrap();
        assert_eq!(crl.tbs.revoked[0].serial, [0x05]);
        for same in [&[0x05][..], &[0x00, 0x05], &[0x00, 0x00, 0x05]] {
            assert!(crl.is_revoked(same), "{same:02x?}");
        }
        for other in [&[0x06][..], &[0xff, 0x05], &[], &[0x05, 0x00]] {
            assert!(!crl.is_revoked(other), "{other:02x?}");
        }
        // Negative numbers keep their sign: ff 85 is -123, the same as 85.
        let mut neg = tbs.clone();
        neg.revoked[0].serial = vec![0xff, 0x85];
        let crl = Crl { tbs: neg, ..crl };
        assert!(crl.is_revoked(&[0x85]));
        assert!(!crl.is_revoked(&[0x00, 0x85]));
    }

    #[test]
    fn from_pem_reads_the_first_block_with_its_label() {
        // Text after the first certificate is not read, even when it is
        // broken or holds many blocks.
        let broken_after = format!("{CERT_PEM}-----BEGIN X-----\n!!!\n-----END X-----\n");
        assert_eq!(Certificate::from_pem(broken_after.as_bytes()).unwrap().to_pem().unwrap(), CERT_PEM);
        let unterminated = format!("{CRL_PEM}-----BEGIN X-----\nZg==\n");
        assert!(Crl::from_pem(unterminated.as_bytes()).is_ok());
        let many = format!("{CERT_PEM}{}", "-----BEGIN X-----\n-----END X-----\n".repeat(MAX_PEM_BLOCKS + 1));
        assert!(Certificate::from_pem(many.as_bytes()).is_ok());
        // Blocks with other labels before it are skipped.
        let after_others = format!("{}{CERT_PEM}", "-----BEGIN X-----\n-----END X-----\n".repeat(MAX_PEM_BLOCKS + 1));
        assert!(Certificate::from_pem(after_others.as_bytes()).is_ok());
        // Text before it must still read.
        let broken_before = format!("-----BEGIN X-----\n!!!\n-----END X-----\n{CERT_PEM}");
        assert_eq!(Certificate::from_pem(broken_before.as_bytes()), Err(Error::Pem));
        assert_eq!(Certificate::from_pem(b"-----BEGIN CERTIFICATE-----\nMA==\n"), Err(Error::Pem));
        assert_eq!(Certificate::from_pem(b""), Err(Error::NoBlock));
    }

    #[test]
    fn crl_entry_and_crl_extensions_have_types() {
        let crl = Crl::parse(&crl_der()).unwrap();
        assert_eq!(crl.tbs.get::<CrlNumber>().unwrap(), Some(CrlNumber(vec![0x10, 0x00])));
        assert_eq!(crl.tbs.get::<CrlNumber>().unwrap().unwrap().to_u64(), Some(4096));
        assert_eq!(crl.tbs.revoked[0].get::<CrlReason>().unwrap(), None);
        assert_eq!(crl.tbs.revoked[1].get::<CrlReason>().unwrap(), Some(CrlReason(CrlReason::KEY_COMPROMISE)));
        // Each writes the bytes OpenSSL wrote.
        let ext = |x: &[Extension], o: &[u8]| find_extension(x, o).unwrap().value.clone();
        assert_eq!(CrlNumber::from_u64(4096).to_der().unwrap(), ext(&crl.tbs.extensions, oid::CRL_NUMBER));
        assert_eq!(
            CrlReason(CrlReason::KEY_COMPROMISE).to_der().unwrap(),
            ext(&crl.tbs.revoked[1].extensions, oid::REASON_CODE)
        );
        // Every reason RFC 5280 5.3.1 lists, and no others.
        for n in 0..=255u8 {
            let r = CrlReason(n);
            if n <= 10 && n != 7 {
                assert_eq!(CrlReason::from_der(&r.to_der().unwrap()).unwrap(), r);
            } else {
                assert_eq!(r.to_der(), Err(Error::Value), "{n}");
            }
        }
        assert_eq!(CrlReason::from_der(&[0x0a, 0x01, 0x07]), Err(Error::Value));
        assert_eq!(CrlReason::from_der(&[0x0a, 0x01, 0xff]), Err(Error::Value));
        assert_eq!(CrlReason::from_der(&[0x0a, 0x02, 0x01, 0x00]), Err(Error::Value));
        assert!(CrlReason::from_der(&[0x02, 0x01, 0x01]).is_err());
        // CRL numbers are not negative.
        for n in [0, 1, 127, 128, u64::MAX] {
            let c = CrlNumber::from_u64(n);
            assert_eq!(CrlNumber::from_der(&c.to_der().unwrap()).unwrap().to_u64(), Some(n));
        }
        assert_eq!(CrlNumber::from_der(&[0x02, 0x01, 0xff]), Err(Error::Value));
        assert_eq!(CrlNumber(vec![0x80]).to_der(), Err(Error::Value));
        assert_eq!(CrlNumber(vec![0x01; 21]).to_u64(), None);
        // The issuer alternative name has the shape of the subject's.
        let ian = IssuerAltName(vec![uri("http://ca.example.com/")]);
        let x = ian.to_extension(false).unwrap();
        assert_eq!(x.oid.as_bytes(), oid::ISSUER_ALT_NAME);
        assert_eq!(IssuerAltName::from_der(&x.value).unwrap(), ian);
        assert_eq!(IssuerAltName(vec![]).to_der(), Err(Error::Empty));
        // Truncated values are refused.
        for v in [CrlNumber::from_u64(4096).to_der().unwrap(), CrlReason(1).to_der().unwrap(), x.value] {
            for n in 0..v.len() {
                assert!(CrlNumber::from_der(&v[..n]).is_err());
                assert!(CrlReason::from_der(&v[..n]).is_err());
                assert!(IssuerAltName::from_der(&v[..n]).is_err());
            }
        }
    }
}
