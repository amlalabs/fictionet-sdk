//! OCSP: reading and writing certificate status requests and responses,
//! with no I/O.
//!
//! The Online Certificate Status Protocol is how a client asks a
//! certificate authority whether a certificate is still good. The client
//! names each certificate by a [`CertId`]: hashes of its issuer's name and
//! key, and its serial number. The responder answers each one as good,
//! revoked or unknown, and signs the answer. Requests and responses are
//! DER, carried over HTTP, usually on TCP port 80: a request is the body
//! of a POST, or is base64 in the path of a GET. This module follows
//! RFC 6960, with the nonce extension as RFC 9654 describes it.
//!
//! Nothing here reads a socket. A world that plays a responder reads each
//! HTTP request's body (or the path of a GET, with
//! [`OcspRequest::from_get_path`]) as an [`OcspRequest`], decides each
//! certificate's status, and writes an [`OcspResponse`] back as the body
//! of the reply. Which certificates exist and whether they are revoked is
//! up to world code. So is the signature: this module keeps signatures as
//! bytes and never checks or makes one. A world that signs its answers
//! signs the bytes [`ResponseData::to_der`] gives, and a client that signs
//! its request signs the bytes [`OcspRequest::tbs_der`] gives.
//!
//! Every reader checks lengths, tags and the DER rules, because the agent
//! can send any bytes it likes. Messages are at most [`MAX_MESSAGE`]
//! bytes, and each list in them has a limit of its own. Parts this module
//! does not look inside (names, certificates, algorithm parameters) are
//! kept as the DER bytes of one element, checked as DER.
//!
//! ```
//! use fictionet::stdlib::ocsp::{
//!     AlgorithmIdentifier, BasicResponse, CertId, CertStatus, Extension, OcspRequest, OcspResponse, Request,
//!     ResponderId, ResponseData, SingleResponse,
//! };
//!
//! // The client's side: ask about serial number 0x1234 with SHA-1 hashes.
//! let id = CertId {
//!     hash_algorithm: AlgorithmIdentifier::sha1(),
//!     issuer_name_hash: vec![0x11; 20],
//!     issuer_key_hash: vec![0x22; 20],
//!     serial_number: vec![0x12, 0x34],
//! };
//! let mut request = OcspRequest::new(vec![Request { cert_id: id, extensions: vec![] }]);
//! request.extensions.push(Extension::nonce(b"0123456789abcdef").unwrap());
//! let body = request.to_der().unwrap();
//!
//! // The responder's side: read the request and say every certificate is good.
//! let request = OcspRequest::parse(&body).unwrap();
//! let data = ResponseData {
//!     version: 0,
//!     responder_id: ResponderId::ByKey(vec![0x22; 20]),
//!     produced_at: "20261005120000Z".to_string(),
//!     responses: request
//!         .requests
//!         .iter()
//!         .map(|r| SingleResponse {
//!             cert_id: r.cert_id.clone(),
//!             status: CertStatus::Good,
//!             this_update: "20261005120000Z".to_string(),
//!             next_update: None,
//!             extensions: vec![],
//!         })
//!         .collect(),
//!     extensions: request.nonce().and_then(|n| Extension::nonce(n).ok()).into_iter().collect(),
//! };
//! // A real responder signs `data.to_der()`; these bytes stand in for it.
//! let basic = BasicResponse {
//!     data,
//!     signature_algorithm: AlgorithmIdentifier::sha1(),
//!     signature: vec![0; 64],
//!     certs: vec![],
//! };
//! let reply = OcspResponse::basic(basic).to_der().unwrap();
//!
//! // The client reads the answer, with the nonce it sent.
//! let response = OcspResponse::parse(&reply).unwrap();
//! let basic = response.basic_response().unwrap();
//! assert_eq!(basic.data.nonce(), Some(&b"0123456789abcdef"[..]));
//! assert_eq!(basic.data.responses[0].status, CertStatus::Good);
//! assert_eq!(basic.data.responses[0].cert_id.serial_number, [0x12, 0x34]);
//! ```

use super::asn1::{self, Class, Element, Header, Length, Oid, Reader, Rules, Tag, Writer};

/// The TCP port OCSP responders usually listen on, since OCSP runs over
/// plain HTTP.
pub const PORT: u16 = 80;
/// The HTTP media type of a request body.
pub const REQUEST_MEDIA_TYPE: &str = "application/ocsp-request";
/// The HTTP media type of a response body.
pub const RESPONSE_MEDIA_TYPE: &str = "application/ocsp-response";
/// The longest request or response, in bytes, a reader accepts and a
/// writer writes. Real ones are a few kilobytes at most.
pub const MAX_MESSAGE: usize = 1 << 16;
/// The longest GET path segment [`decode_get_path`] accepts: the
/// percent-encoded base64 of a [`MAX_MESSAGE`]-byte request, with every
/// character escaped.
pub const MAX_GET_PATH: usize = MAX_MESSAGE.div_ceil(3) * 4 * 3;
/// The most certificates one request may ask about.
pub const MAX_REQUESTS: usize = 256;
/// The most single responses one response may hold.
pub const MAX_RESPONSES: usize = 256;
/// The most extensions in one list of extensions.
pub const MAX_EXTENSIONS: usize = 32;
/// The most certificates a signature or response may carry.
pub const MAX_CERTS: usize = 16;

/// The contents of object identifiers OCSP uses.
pub mod oid {
    /// id-pkix-ocsp-basic, 1.3.6.1.5.5.7.48.1.1: a [`BasicResponse`](super::BasicResponse).
    pub const BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
    /// id-pkix-ocsp-nonce, 1.3.6.1.5.5.7.48.1.2: the nonce extension.
    pub const NONCE: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];
    /// id-sha1, 1.3.14.3.2.26: the hash most clients use in a CertID.
    pub const SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
    /// id-sha256, 2.16.840.1.101.3.4.2.1.
    pub const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    /// id-sha384, 2.16.840.1.101.3.4.2.2.
    pub const SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
    /// id-sha512, 2.16.840.1.101.3.4.2.3.
    pub const SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
}

/// Why bytes are not the OCSP message a reader asked for, or why a writer
/// could not write one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes are not the DER the structure needs: a wrong tag, a
    /// missing field, a bad length, bytes left over, and so on.
    Asn1(asn1::Error),
    /// The message is longer than [`MAX_MESSAGE`].
    TooLong,
    /// A list holds more items than its limit allows.
    TooMany,
    /// A field whose value is its DEFAULT was written out. DER leaves such
    /// fields out: version v1, or an extension's critical flag set to
    /// FALSE.
    ExplicitDefault,
    /// A list of extensions is present but empty. RFC 5280 needs at least
    /// one.
    EmptyExtensions,
    /// A signature's BIT STRING does not end on a whole byte.
    UnusedBits,
    /// A certificate status is not good `[0]`, revoked `[1]` or unknown
    /// `[2]`.
    CertStatus,
    /// A responder ID is not a name `[1]` or a key hash `[2]`, or a name
    /// is not a SEQUENCE.
    ResponderId,
    /// A certificate is not a SEQUENCE.
    Certificate,
    /// A GET path segment is not percent-encoded base64.
    GetPath,
    /// A response's status and its responseBytes disagree: a successful
    /// response must carry them, and any other status must not.
    ResponseBytes,
    /// A signed request does not name its requestor, or a requestor name
    /// is not a GeneralName (RFC 5280 4.2.1.6).
    RequestorName,
    /// A nonce is not 1 to 128 bytes long (RFC 9654 2.1).
    Nonce,
    /// A hash is not as long as its algorithm makes it: a CertID's hashes
    /// under SHA-1, SHA-256, SHA-384 or SHA-512, or a responder's key
    /// hash, which is SHA-1.
    HashLength,
    /// A request asks about no certificates. RFC 6960 4.1.2 needs at least
    /// one.
    NoRequests,
    /// A response status or revocation reason is not one of the values
    /// its ENUMERATED type lists.
    Enumerated,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Asn1(e) => write!(f, "OCSP DER: {e}"),
            Error::TooLong => write!(f, "OCSP message longer than {MAX_MESSAGE} bytes"),
            Error::TooMany => f.write_str("OCSP list longer than its limit"),
            Error::ExplicitDefault => f.write_str("DEFAULT value written out (DER)"),
            Error::EmptyExtensions => f.write_str("empty list of extensions"),
            Error::UnusedBits => f.write_str("signature does not end on a whole byte"),
            Error::CertStatus => f.write_str("certificate status not good, revoked or unknown"),
            Error::ResponderId => f.write_str("responder ID not a name or key hash"),
            Error::Certificate => f.write_str("certificate not a SEQUENCE"),
            Error::GetPath => f.write_str("GET path not percent-encoded base64"),
            Error::ResponseBytes => f.write_str("responseBytes do not match the status"),
            Error::RequestorName => f.write_str("requestor name missing from a signed request, or not a GeneralName"),
            Error::Nonce => f.write_str("nonce not 1 to 128 bytes long"),
            Error::HashLength => f.write_str("hash not as long as its algorithm makes it"),
            Error::NoRequests => f.write_str("request asks about no certificates"),
            Error::Enumerated => f.write_str("ENUMERATED value not in its type"),
        }
    }
}

impl std::error::Error for Error {}

impl From<asn1::Error> for Error {
    fn from(e: asn1::Error) -> Error {
        Error::Asn1(e)
    }
}

/// An algorithm and its parameters, such as the hash a [`CertId`] uses or
/// the algorithm of a signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlgorithmIdentifier {
    /// Which algorithm.
    pub algorithm: Oid,
    /// The parameters, as the DER of one element, if there are any. Hashes
    /// usually have a NULL here: `[0x05, 0x00]`.
    pub parameters: Option<Vec<u8>>,
}

impl AlgorithmIdentifier {
    /// SHA-1 with NULL parameters, as most clients name their CertID hash.
    pub fn sha1() -> AlgorithmIdentifier {
        AlgorithmIdentifier { algorithm: known_oid(oid::SHA1), parameters: Some(vec![0x05, 0x00]) }
    }

    /// SHA-256 with NULL parameters.
    pub fn sha256() -> AlgorithmIdentifier {
        AlgorithmIdentifier { algorithm: known_oid(oid::SHA256), parameters: Some(vec![0x05, 0x00]) }
    }
}

/// Which certificate a request or response is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertId {
    /// The hash used for the two hashes below.
    pub hash_algorithm: AlgorithmIdentifier,
    /// The hash of the issuer's distinguished name, as DER.
    pub issuer_name_hash: Vec<u8>,
    /// The hash of the issuer's public key: the BIT STRING's bytes, without
    /// its tag, length or unused-bit count.
    pub issuer_key_hash: Vec<u8>,
    /// The certificate's serial number, as the INTEGER's two's-complement
    /// bytes in their shortest form: at least one byte, and no leading
    /// byte that only repeats the sign. A writer refuses any other form
    /// with an [`asn1::Error::Integer`], since it would read back
    /// different.
    pub serial_number: Vec<u8>,
}

/// One extension: an identifier, whether a reader that does not know it
/// must refuse the message, and its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    /// Which extension.
    pub id: Oid,
    /// Whether a reader that does not know the extension must refuse the
    /// message.
    pub critical: bool,
    /// The value: the contents of the extnValue OCTET STRING, which is
    /// usually DER itself.
    pub value: Vec<u8>,
}

impl Extension {
    /// A nonce extension holding `nonce`: its value is the DER of an OCTET
    /// STRING, as RFC 6960 and RFC 9654 say. RFC 9654 allows 1 to
    /// [`MAX_NONCE`] bytes, and asks clients for at least 32. Any other
    /// length is [`Error::Nonce`].
    pub fn nonce(nonce: &[u8]) -> Result<Extension, Error> {
        if !(1..=MAX_NONCE).contains(&nonce.len()) {
            return Err(Error::Nonce);
        }
        let mut w = Writer::new();
        w.octet_string(nonce);
        Ok(Extension { id: known_oid(oid::NONCE), critical: false, value: w.finish()? })
    }
}

/// The longest nonce RFC 9654 allows, in bytes.
pub const MAX_NONCE: usize = 128;

/// The nonce in a list of extensions, if there is one that is 1 to
/// [`MAX_NONCE`] bytes long. Its value should be the DER of an OCTET
/// STRING, and then this is that string's contents. Some old clients put
/// the bare bytes there, and then this is the whole value. RFC 9654 2.1
/// has a responder answer `malformedRequest` to a request whose nonce
/// extension is present but gives `None` here.
pub fn find_nonce(extensions: &[Extension]) -> Option<&[u8]> {
    let ext = extensions.iter().find(|e| e.id.as_bytes() == oid::NONCE)?;
    let mut r = Reader::new(&ext.value, Rules::Der);
    let nonce = match r.read_expected(Tag::OCTET_STRING) {
        Ok(e) if r.is_empty() && !e.tag().constructed => e.contents(),
        _ => &ext.value,
    };
    (1..=MAX_NONCE).contains(&nonce.len()).then_some(nonce)
}

/// One certificate a request asks about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The certificate.
    pub cert_id: CertId,
    /// Extensions for this certificate alone. Usually none.
    pub extensions: Vec<Extension>,
}

/// A request's signature. Most requests are not signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// The signature algorithm.
    pub algorithm: AlgorithmIdentifier,
    /// The signature's bytes.
    pub signature: Vec<u8>,
    /// Certificates that help check the signature, each as DER.
    pub certs: Vec<Vec<u8>>,
}

/// An OCSPRequest: which certificates a client asks about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OcspRequest {
    /// The version: 0 for v1, the only one RFC 6960 defines.
    pub version: i64,
    /// Who sent the request, as the DER of a GeneralName. Usually absent,
    /// and needed only when the request is signed.
    pub requestor_name: Option<Vec<u8>>,
    /// The certificates asked about, at most [`MAX_REQUESTS`].
    pub requests: Vec<Request>,
    /// Extensions for the whole request, such as the nonce.
    pub extensions: Vec<Extension>,
    /// The signature, if the request is signed. A signed request must
    /// have a `requestor_name` (RFC 6960 4.1.2).
    pub signature: Option<Signature>,
}

impl OcspRequest {
    /// A v1 request about `requests`, unsigned, with no extensions.
    pub fn new(requests: Vec<Request>) -> OcspRequest {
        OcspRequest { version: 0, requestor_name: None, requests, extensions: vec![], signature: None }
    }

    /// Reads a request from its DER, such as a POST body.
    pub fn parse(b: &[u8]) -> Result<OcspRequest, Error> {
        let mut top = outer(b)?;
        let mut req = top.read_sequence()?;
        top.finish()?;
        let mut tbs = req.read_sequence()?;
        let version = read_version(&mut tbs)?;
        let requestor_name = match explicit(&mut tbs, 1)? {
            Some(mut inner) => {
                let name = checked_raw(&inner.read()?)?;
                inner.finish()?;
                check_general_name(&name)?;
                Some(name)
            }
            None => None,
        };
        let mut list = tbs.read_sequence()?;
        let mut requests = Vec::new();
        while !list.is_empty() {
            if requests.len() >= MAX_REQUESTS {
                return Err(Error::TooMany);
            }
            let mut one = list.read_sequence()?;
            let cert_id = read_cert_id(&mut one)?;
            let extensions = read_extensions(&mut one, 0)?;
            one.finish()?;
            requests.push(Request { cert_id, extensions });
        }
        if requests.is_empty() {
            return Err(Error::NoRequests);
        }
        let extensions = read_extensions(&mut tbs, 2)?;
        tbs.finish()?;
        let signature = match explicit(&mut req, 0)? {
            Some(mut inner) => {
                let mut s = inner.read_sequence()?;
                inner.finish()?;
                let algorithm = read_algorithm(&mut s)?;
                let signature = read_signature_bits(&mut s)?;
                let certs = read_certs(&mut s)?;
                s.finish()?;
                Some(Signature { algorithm, signature, certs })
            }
            None => None,
        };
        req.finish()?;
        if signature.is_some() && requestor_name.is_none() {
            return Err(Error::RequestorName);
        }
        Ok(OcspRequest { version, requestor_name, requests, extensions, signature })
    }

    /// The request's DER, for a world that plays a client. It fails if a
    /// list is empty or over its limit, a hash has the wrong length, a raw
    /// DER part is not one well-formed element, the requestor name is not
    /// a GeneralName, the request is signed but names no requestor, or the
    /// whole is over [`MAX_MESSAGE`].
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.check_tbs()?;
        if let Some(s) = &self.signature {
            if self.requestor_name.is_none() {
                return Err(Error::RequestorName);
            }
            check_certs(&s.certs)?;
        }
        let mut w = Writer::new();
        w.sequence(|w| {
            self.write_tbs(w);
            if let Some(s) = &self.signature {
                w.explicit(0, |w| {
                    w.sequence(|w| {
                        write_algorithm(w, &s.algorithm);
                        w.bit_string(&s.signature, 0);
                        write_certs(w, &s.certs);
                    })
                });
            }
        });
        finish(w)
    }

    /// The DER of the request's TBSRequest: the bytes a client signs, and a
    /// responder checks the signature over, as they appear inside the
    /// whole request. It fails where [`OcspRequest::to_der`] does, except
    /// that `signature` is not looked at.
    pub fn tbs_der(&self) -> Result<Vec<u8>, Error> {
        self.check_tbs()?;
        let mut w = Writer::new();
        self.write_tbs(&mut w);
        finish(w)
    }

    /// The nonce the request carries, if any. See [`find_nonce`].
    pub fn nonce(&self) -> Option<&[u8]> {
        find_nonce(&self.extensions)
    }

    /// Checks what a writer cannot check while writing the TBSRequest.
    fn check_tbs(&self) -> Result<(), Error> {
        if self.requests.is_empty() {
            return Err(Error::NoRequests);
        }
        limit(&self.requests, MAX_REQUESTS)?;
        limit(&self.extensions, MAX_EXTENSIONS)?;
        for r in &self.requests {
            limit(&r.extensions, MAX_EXTENSIONS)?;
            check_cert_id(&r.cert_id)?;
        }
        if let Some(name) = &self.requestor_name {
            check_general_name(name)?;
        }
        Ok(())
    }

    fn write_tbs(&self, w: &mut Writer) {
        w.sequence(|w| {
            write_version(w, self.version);
            if let Some(name) = &self.requestor_name {
                w.explicit(1, |w| w.encoded(name));
            }
            w.sequence(|w| {
                for r in &self.requests {
                    w.sequence(|w| {
                        write_cert_id(w, &r.cert_id);
                        write_extensions(w, 0, &r.extensions);
                    });
                }
            });
            write_extensions(w, 2, &self.extensions);
        });
    }

    /// Reads a request sent with HTTP GET, from the path segment after the
    /// responder's URL and its slash. See [`decode_get_path`].
    pub fn from_get_path(segment: &str) -> Result<OcspRequest, Error> {
        OcspRequest::parse(&decode_get_path(segment)?)
    }

    /// The path segment that sends this request with HTTP GET, to put
    /// after the responder's URL and a slash. See [`encode_get_path`].
    pub fn to_get_path(&self) -> Result<String, Error> {
        encode_get_path(&self.to_der()?)
    }
}

/// Whether the responder could answer, the first field of every response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseStatus {
    /// The response holds an answer.
    Successful,
    /// The request was not well formed.
    MalformedRequest,
    /// The responder failed.
    InternalError,
    /// The responder cannot answer now; try later.
    TryLater,
    /// The responder needs requests to be signed.
    SigRequired,
    /// The client may not ask this responder.
    Unauthorized,
}

impl ResponseStatus {
    /// The ENUMERATED value.
    pub fn code(self) -> i64 {
        match self {
            ResponseStatus::Successful => 0,
            ResponseStatus::MalformedRequest => 1,
            ResponseStatus::InternalError => 2,
            ResponseStatus::TryLater => 3,
            ResponseStatus::SigRequired => 5,
            ResponseStatus::Unauthorized => 6,
        }
    }

    /// The status for value `c`, or `None` for a value RFC 6960 4.2.1 does
    /// not list, such as 4. A reader refuses those with
    /// [`Error::Enumerated`].
    pub fn from_code(c: i64) -> Option<ResponseStatus> {
        Some(match c {
            0 => ResponseStatus::Successful,
            1 => ResponseStatus::MalformedRequest,
            2 => ResponseStatus::InternalError,
            3 => ResponseStatus::TryLater,
            5 => ResponseStatus::SigRequired,
            6 => ResponseStatus::Unauthorized,
            _ => return None,
        })
    }
}

/// What a successful response carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseBytes {
    /// The basic response type, id-pkix-ocsp-basic, which every responder
    /// sends.
    Basic(BasicResponse),
    /// Any other type, with its bytes unread. A reader never makes this
    /// with the basic type's identifier, and a writer refuses it with
    /// [`Error::ResponseBytes`]: use [`ResponseBytes::Basic`].
    Other {
        /// The response type.
        response_type: Oid,
        /// The response's bytes.
        response: Vec<u8>,
    },
}

/// An OCSPResponse: the status, and the answer if there is one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OcspResponse {
    /// Whether the responder could answer.
    pub status: ResponseStatus,
    /// The answer: present with [`ResponseStatus::Successful`], and
    /// absent with any other status (RFC 6960 4.2.1). Readers and writers
    /// both insist.
    pub bytes: Option<ResponseBytes>,
}

impl OcspResponse {
    /// A response that says only that the request failed with `status`.
    pub fn error(status: ResponseStatus) -> OcspResponse {
        OcspResponse { status, bytes: None }
    }

    /// A successful response carrying `basic`.
    pub fn basic(basic: BasicResponse) -> OcspResponse {
        OcspResponse { status: ResponseStatus::Successful, bytes: Some(ResponseBytes::Basic(basic)) }
    }

    /// The basic response it carries, if any.
    pub fn basic_response(&self) -> Option<&BasicResponse> {
        match &self.bytes {
            Some(ResponseBytes::Basic(b)) => Some(b),
            _ => None,
        }
    }

    /// Reads a response from its DER, such as an HTTP reply's body. A basic
    /// response inside is read too, and an error in it is an error here.
    pub fn parse(b: &[u8]) -> Result<OcspResponse, Error> {
        let mut top = outer(b)?;
        let mut resp = top.read_sequence()?;
        top.finish()?;
        let status = ResponseStatus::from_code(read_enum(&mut resp)?).ok_or(Error::Enumerated)?;
        let bytes = match explicit(&mut resp, 0)? {
            Some(mut inner) => {
                let mut rb = inner.read_sequence()?;
                inner.finish()?;
                let response_type = rb.read_oid()?;
                let response = rb.read_octet_string()?;
                rb.finish()?;
                Some(if response_type.as_bytes() == oid::BASIC {
                    ResponseBytes::Basic(BasicResponse::parse(&response)?)
                } else {
                    ResponseBytes::Other { response_type, response: response.into_owned() }
                })
            }
            None => None,
        };
        resp.finish()?;
        check_status(status, &bytes)?;
        Ok(OcspResponse { status, bytes })
    }

    /// The response's DER, for a world that plays a responder. It fails
    /// where [`BasicResponse::to_der`] does, if the status and the bytes
    /// disagree or [`ResponseBytes::Other`] has the basic type's
    /// identifier ([`Error::ResponseBytes`]), or if the whole is over
    /// [`MAX_MESSAGE`].
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        check_status(self.status, &self.bytes)?;
        let basic;
        let (response_type, response): (Option<&Oid>, &[u8]) = match &self.bytes {
            None => (None, &[]),
            Some(ResponseBytes::Basic(b)) => {
                basic = (known_oid(oid::BASIC), b.to_der()?);
                (Some(&basic.0), &basic.1)
            }
            Some(ResponseBytes::Other { response_type, response }) => {
                if response_type.as_bytes() == oid::BASIC {
                    return Err(Error::ResponseBytes);
                }
                if response.len() > MAX_MESSAGE {
                    return Err(Error::TooLong);
                }
                (Some(response_type), response)
            }
        };
        let mut w = Writer::new();
        w.sequence(|w| {
            w.enumerated(self.status.code());
            if let Some(t) = response_type {
                w.explicit(0, |w| {
                    w.sequence(|w| {
                        w.oid(t);
                        w.octet_string(response);
                    })
                });
            }
        });
        finish(w)
    }
}

/// A BasicOCSPResponse: the answers, and the responder's signature over
/// them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasicResponse {
    /// The answers, which the signature covers.
    pub data: ResponseData,
    /// The signature algorithm.
    pub signature_algorithm: AlgorithmIdentifier,
    /// The signature's bytes, over the DER of `data`. Never checked here.
    pub signature: Vec<u8>,
    /// Certificates that help check the signature, each as DER, such as a
    /// delegated responder's certificate.
    pub certs: Vec<Vec<u8>>,
}

impl BasicResponse {
    /// Reads a basic response from its DER: the contents of a response's
    /// OCTET STRING.
    pub fn parse(b: &[u8]) -> Result<BasicResponse, Error> {
        let mut top = outer(b)?;
        let mut s = top.read_sequence()?;
        top.finish()?;
        let data = read_response_data(&mut s)?;
        let signature_algorithm = read_algorithm(&mut s)?;
        let signature = read_signature_bits(&mut s)?;
        let certs = read_certs(&mut s)?;
        s.finish()?;
        Ok(BasicResponse { data, signature_algorithm, signature, certs })
    }

    /// The basic response's DER. It fails if a list is over its limit, a
    /// time is not in the form RFC 5280 allows, a raw DER part is not one
    /// well-formed element, or the whole is over [`MAX_MESSAGE`].
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.data.check()?;
        check_certs(&self.certs)?;
        let mut w = Writer::new();
        w.sequence(|w| {
            write_response_data(w, &self.data);
            write_algorithm(w, &self.signature_algorithm);
            w.bit_string(&self.signature, 0);
            write_certs(w, &self.certs);
        });
        finish(w)
    }
}

/// Who signed a response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponderId {
    /// `[1]`: the responder's distinguished name, as the DER of a Name (a
    /// SEQUENCE).
    ByName(Vec<u8>),
    /// `[2]`: the SHA-1 hash of the responder's public key, 20 bytes.
    /// Any other length is [`Error::HashLength`].
    ByKey(Vec<u8>),
}

/// ResponseData: the part of a basic response the signature covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseData {
    /// The version: 0 for v1, the only one RFC 6960 defines.
    pub version: i64,
    /// Who signed the response.
    pub responder_id: ResponderId,
    /// When the response was signed, as GeneralizedTime text in the form
    /// RFC 5280 allows: `YYYYMMDDHHMMSSZ`, such as `"20261005120000Z"`,
    /// with no fractional seconds.
    pub produced_at: String,
    /// One answer per certificate, at most [`MAX_RESPONSES`].
    pub responses: Vec<SingleResponse>,
    /// Extensions for the whole response, such as the nonce.
    pub extensions: Vec<Extension>,
}

impl ResponseData {
    /// The DER the responder signs, as it appears inside a
    /// [`BasicResponse`].
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        self.check()?;
        let mut w = Writer::new();
        write_response_data(&mut w, self);
        finish(w)
    }

    /// The nonce the response carries, if any. See [`find_nonce`].
    pub fn nonce(&self) -> Option<&[u8]> {
        find_nonce(&self.extensions)
    }

    /// Checks what a writer cannot check while writing: the lists' limits,
    /// the responder ID, the hashes' lengths, and that no time has
    /// fractional seconds.
    fn check(&self) -> Result<(), Error> {
        limit(&self.responses, MAX_RESPONSES)?;
        limit(&self.extensions, MAX_EXTENSIONS)?;
        check_time(&self.produced_at)?;
        for r in &self.responses {
            limit(&r.extensions, MAX_EXTENSIONS)?;
            check_time(&r.this_update)?;
            if let Some(t) = &r.next_update {
                check_time(t)?;
            }
            if let CertStatus::Revoked { time, .. } = &r.status {
                check_time(time)?;
            }
        }
        match &self.responder_id {
            ResponderId::ByName(name) if name.first() != Some(&0x30) => return Err(Error::ResponderId),
            ResponderId::ByKey(hash) if hash.len() != 20 => return Err(Error::HashLength),
            _ => {}
        }
        for r in &self.responses {
            check_cert_id(&r.cert_id)?;
        }
        Ok(())
    }
}

/// Why a certificate was revoked: the CRLReason codes of RFC 5280.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // each variant is the reason it names
pub enum CrlReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
}

impl CrlReason {
    /// The ENUMERATED value.
    pub fn code(self) -> i64 {
        match self {
            CrlReason::Unspecified => 0,
            CrlReason::KeyCompromise => 1,
            CrlReason::CaCompromise => 2,
            CrlReason::AffiliationChanged => 3,
            CrlReason::Superseded => 4,
            CrlReason::CessationOfOperation => 5,
            CrlReason::CertificateHold => 6,
            CrlReason::RemoveFromCrl => 8,
            CrlReason::PrivilegeWithdrawn => 9,
            CrlReason::AaCompromise => 10,
        }
    }

    /// The reason for value `c`, or `None` for a value RFC 5280 5.3.1 does
    /// not list, such as 7. A reader refuses those with
    /// [`Error::Enumerated`].
    pub fn from_code(c: i64) -> Option<CrlReason> {
        Some(match c {
            0 => CrlReason::Unspecified,
            1 => CrlReason::KeyCompromise,
            2 => CrlReason::CaCompromise,
            3 => CrlReason::AffiliationChanged,
            4 => CrlReason::Superseded,
            5 => CrlReason::CessationOfOperation,
            6 => CrlReason::CertificateHold,
            8 => CrlReason::RemoveFromCrl,
            9 => CrlReason::PrivilegeWithdrawn,
            10 => CrlReason::AaCompromise,
            _ => return None,
        })
    }
}

/// A certificate's status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertStatus {
    /// `[0]`: not revoked, as far as the responder knows.
    Good,
    /// `[1]`: revoked.
    Revoked {
        /// When, as GeneralizedTime text: `YYYYMMDDHHMMSSZ`.
        time: String,
        /// Why, if the responder says.
        reason: Option<CrlReason>,
    },
    /// `[2]`: the responder does not know the certificate.
    Unknown,
}

/// The answer about one certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleResponse {
    /// The certificate, as the request named it.
    pub cert_id: CertId,
    /// Its status.
    pub status: CertStatus,
    /// When the status was known to be right, as GeneralizedTime text:
    /// `YYYYMMDDHHMMSSZ`.
    pub this_update: String,
    /// When newer information will be ready, if the responder says, in the
    /// same form.
    pub next_update: Option<String>,
    /// Extensions for this answer alone.
    pub extensions: Vec<Extension>,
}

/// The path segment that sends a request's DER with HTTP GET: its base64,
/// with `+`, `/` and `=` percent-encoded (RFC 6960 appendix A.1). Requests
/// over [`MAX_MESSAGE`] bytes are refused.
pub fn encode_get_path(der: &[u8]) -> Result<String, Error> {
    if der.len() > MAX_MESSAGE {
        return Err(Error::TooLong);
    }
    let mut out = String::with_capacity(der.len().div_ceil(3) * 4 * 3);
    for chunk in der.chunks(3) {
        let b = [chunk[0], chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                let c = BASE64[(n >> (18 - 6 * i) & 0x3f) as usize];
                match c {
                    b'+' => out.push_str("%2B"),
                    b'/' => out.push_str("%2F"),
                    c => out.push(char::from(c)),
                }
            } else {
                out.push_str("%3D");
            }
        }
    }
    Ok(out)
}

/// Reads a GET path segment back into a request's DER. Percent escapes
/// are decoded first, in either case, and then the base64, whose padding
/// may be left off. Clients that do not escape `+`, `/` or `=` are read
/// too.
pub fn decode_get_path(segment: &str) -> Result<Vec<u8>, Error> {
    let s = segment.as_bytes();
    if s.len() > MAX_GET_PATH {
        return Err(Error::TooLong);
    }
    let mut text = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            let hex = s.get(i + 1..i + 3).ok_or(Error::GetPath)?;
            let (hi, lo) = (hex_digit(hex[0])?, hex_digit(hex[1])?);
            text.push(hi << 4 | lo);
            i += 3;
        } else {
            text.push(s[i]);
            i += 1;
        }
    }
    let pad = text.iter().rev().take_while(|&&c| c == b'=').count();
    let body = &text[..text.len() - pad];
    if pad > 2 || (pad > 0 && text.len() % 4 != 0) || body.len() % 4 == 1 {
        return Err(Error::GetPath);
    }
    let mut out = Vec::with_capacity(body.len() / 4 * 3 + 2);
    for chunk in body.chunks(4) {
        let mut n: u32 = 0;
        for (j, &c) in chunk.iter().enumerate() {
            n |= u32::from(base64_value(c)?) << (18 - 6 * j);
        }
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..chunk.len()]);
    }
    if out.len() > MAX_MESSAGE {
        return Err(Error::TooLong);
    }
    Ok(out)
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_value(c: u8) -> Result<u8, Error> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(Error::GetPath),
    }
}

fn hex_digit(c: u8) -> Result<u8, Error> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::GetPath),
    }
}

/// Splits a byte stream into whole DER messages, such as an HTTP body that
/// comes in pieces. Feed it the bytes in order, and take messages out until
/// it has none. Read each one with [`OcspRequest::parse`] or
/// [`OcspResponse::parse`]. It holds at most [`MAX_MESSAGE`] bytes not yet
/// taken out.
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are dropped
    /// in `feed` once they are half the buffer.
    start: usize,
    failed: Option<Error>,
}

impl Decoder {
    /// A decoder holding no bytes.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Adds bytes from the start of `bytes`, and returns how many it took.
    /// It holds at most [`MAX_MESSAGE`] bytes not yet taken out, so it may
    /// take only part of `bytes`: take messages out with
    /// [`Decoder::next_message`], then feed it the rest. Once it holds
    /// [`MAX_MESSAGE`] bytes, `next_message` always gives a message or an
    /// error, so a loop of the two never stalls. After an error the stream
    /// cannot be read any further, and every byte is taken and dropped.
    #[must_use = "the bytes past the count it returns were not taken"]
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.failed.is_some() {
            return bytes.len();
        }
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let n = bytes.len().min(MAX_MESSAGE - self.buffered().min(MAX_MESSAGE));
        self.buf.extend_from_slice(&bytes[..n]);
        n
    }

    /// The next whole message's bytes, if one has come. It returns `None`
    /// when it needs more bytes, and keeps returning the same error once
    /// the stream has broken. A header that is not DER, or that announces
    /// more than [`MAX_MESSAGE`] bytes, breaks it at once.
    pub fn next_message(&mut self) -> Option<Result<Vec<u8>, Error>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        let held = &self.buf[self.start..];
        if held.is_empty() {
            return None;
        }
        let total = match Header::parse(held, Rules::Der) {
            Err(asn1::Error::Truncated) => return None,
            Err(e) => return Some(Err(self.fail(Error::Asn1(e)))),
            Ok(Header { length: Length::Indefinite, .. }) => {
                return Some(Err(self.fail(Error::Asn1(asn1::Error::Indefinite))));
            }
            Ok(Header { length: Length::Definite(n), len, .. }) => len.checked_add(n),
        };
        let total = match total {
            Some(t) if t <= MAX_MESSAGE => t,
            _ => return Some(Err(self.fail(Error::TooLong))),
        };
        if held.len() < total {
            return None;
        }
        let message = held[..total].to_vec();
        self.start += total;
        Some(Ok(message))
    }

    /// How many bytes are held, waiting for the rest of a message.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }

    fn fail(&mut self, e: Error) -> Error {
        self.failed = Some(e);
        self.buf = Vec::new();
        self.start = 0;
        e
    }
}

/// An object identifier from contents known to be well formed.
fn known_oid(contents: &[u8]) -> Oid {
    Oid::from_contents(contents).expect("the constants in `oid` are well formed")
}

/// A reader over a whole message, after checking its size.
fn outer(b: &[u8]) -> Result<Reader<'_>, Error> {
    if b.len() > MAX_MESSAGE {
        return Err(Error::TooLong);
    }
    Ok(Reader::new(b, Rules::Der))
}

/// A writer's bytes, or its error, or [`Error::TooLong`].
fn finish(w: Writer) -> Result<Vec<u8>, Error> {
    let b = w.finish()?;
    if b.len() > MAX_MESSAGE { Err(Error::TooLong) } else { Ok(b) }
}

/// Refuses a status and responseBytes that disagree (RFC 6960 4.2.1).
fn check_status(status: ResponseStatus, bytes: &Option<ResponseBytes>) -> Result<(), Error> {
    let successful = status == ResponseStatus::Successful;
    if successful == bytes.is_some() { Ok(()) } else { Err(Error::ResponseBytes) }
}

/// Refuses a time with fractional seconds, which RFC 6960 4.2.2.1 rules
/// out by taking RFC 5280's form, `YYYYMMDDHHMMSSZ`. The rest of the form
/// is checked as DER by the asn1 reader and writer.
fn check_time(t: &str) -> Result<(), Error> {
    if t.contains(['.', ',']) { Err(Error::Asn1(asn1::Error::Time)) } else { Ok(()) }
}

/// A GeneralizedTime in the form RFC 5280 allows.
fn read_time(r: &mut Reader<'_>) -> Result<String, Error> {
    let t = r.read_generalized_time()?;
    check_time(&t)?;
    Ok(t)
}

fn limit<T>(items: &[T], max: usize) -> Result<(), Error> {
    if items.len() > max { Err(Error::TooMany) } else { Ok(()) }
}

fn check_certs(certs: &[Vec<u8>]) -> Result<(), Error> {
    limit(certs, MAX_CERTS)?;
    if certs.iter().any(|c| c.first() != Some(&0x30)) {
        return Err(Error::Certificate);
    }
    Ok(())
}

/// One element's DER, checked as [`Writer::encoded`] checks it at the same
/// depth, so a writer can always write back what a reader kept. The
/// recursion is as deep as the element, at most [`asn1::MAX_DEPTH`].
fn checked_raw(e: &Element<'_>) -> Result<Vec<u8>, Error> {
    fn nest(w: &mut Writer, levels: usize, raw: &[u8]) {
        if levels == 0 {
            w.encoded(raw);
        } else {
            w.explicit(0, |w| nest(w, levels - 1, raw));
        }
    }
    let mut w = Writer::new();
    nest(&mut w, e.depth().min(asn1::MAX_DEPTH), e.raw());
    w.finish()?;
    Ok(e.raw().to_vec())
}

/// The reader inside an explicitly tagged `[n]` field, if it is next.
fn explicit<'a>(r: &mut Reader<'a>, n: u32) -> Result<Option<Reader<'a>>, Error> {
    match r.read_optional(Tag::context(n))? {
        Some(e) => Ok(Some(e.reader()?)),
        None => Ok(None),
    }
}

fn read_enum(r: &mut Reader<'_>) -> Result<i64, Error> {
    Ok(r.read_enumerated()?.to_i64().ok_or(asn1::Error::Integer)?)
}

/// `[0] EXPLICIT Version DEFAULT v1`.
fn read_version(r: &mut Reader<'_>) -> Result<i64, Error> {
    match explicit(r, 0)? {
        Some(mut inner) => {
            let v = inner.read_i64()?;
            inner.finish()?;
            if v == 0 { Err(Error::ExplicitDefault) } else { Ok(v) }
        }
        None => Ok(0),
    }
}

fn write_version(w: &mut Writer, v: i64) {
    if v != 0 {
        w.explicit(0, |w| w.integer_i64(v));
    }
}

fn read_algorithm(r: &mut Reader<'_>) -> Result<AlgorithmIdentifier, Error> {
    let mut s = r.read_sequence()?;
    let algorithm = s.read_oid()?;
    let parameters = if s.is_empty() { None } else { Some(checked_raw(&s.read()?)?) };
    s.finish()?;
    Ok(AlgorithmIdentifier { algorithm, parameters })
}

fn write_algorithm(w: &mut Writer, a: &AlgorithmIdentifier) {
    w.sequence(|w| {
        w.oid(&a.algorithm);
        if let Some(p) = &a.parameters {
            w.encoded(p);
        }
    });
}

fn read_cert_id(r: &mut Reader<'_>) -> Result<CertId, Error> {
    let mut s = r.read_sequence()?;
    let hash_algorithm = read_algorithm(&mut s)?;
    let issuer_name_hash = s.read_octet_string()?.into_owned();
    let issuer_key_hash = s.read_octet_string()?.into_owned();
    let serial_number = s.read_integer()?.as_bytes().to_vec();
    s.finish()?;
    let id = CertId { hash_algorithm, issuer_name_hash, issuer_key_hash, serial_number };
    check_cert_id(&id)?;
    Ok(id)
}

/// The length of a hash, for the hashes this module knows.
fn hash_len(algorithm: &Oid) -> Option<usize> {
    match algorithm.as_bytes() {
        oid::SHA1 => Some(20),
        oid::SHA256 => Some(32),
        oid::SHA384 => Some(48),
        oid::SHA512 => Some(64),
        _ => None,
    }
}

/// Refuses a CertID whose hashes are not as long as its known hash
/// algorithm makes them (RFC 6960 4.1.1), or whose serial number is not in
/// its shortest form. Other algorithms' hashes must not be empty.
fn check_cert_id(c: &CertId) -> Result<(), Error> {
    asn1::Integer::from_bytes(&c.serial_number)?;
    let ok = |h: &[u8]| match hash_len(&c.hash_algorithm.algorithm) {
        Some(n) => h.len() == n,
        None => !h.is_empty(),
    };
    if ok(&c.issuer_name_hash) && ok(&c.issuer_key_hash) { Ok(()) } else { Err(Error::HashLength) }
}

/// Refuses DER that is not one GeneralName (RFC 5280 4.2.1.6): a context
/// tag from `[0]` to `[8]`, in the form its alternative takes, with the
/// contents the alternative needs where this module can tell. The DER
/// rules themselves are checked elsewhere, by the reader and the writer.
fn check_general_name(der: &[u8]) -> Result<(), Error> {
    let bad = Error::RequestorName;
    let mut r = Reader::new(der, Rules::Der);
    let e = r.read().map_err(|_| bad)?;
    r.finish().map_err(|_| bad)?;
    let t = e.tag();
    if t.class != Class::ContextSpecific {
        return Err(bad);
    }
    let ascii = |b: &[u8]| b.is_ascii();
    let ok = match (t.number, t.constructed) {
        // otherName [0] IMPLICIT SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
        (0, true) => {
            let mut inner = e.reader().map_err(|_| bad)?;
            inner.read_oid().is_ok()
                && inner.read().is_ok_and(|v| v.tag() == Tag::context(0).as_constructed())
                && inner.is_empty()
        }
        // rfc822Name [1], dNSName [2], uniformResourceIdentifier [6]: IA5String
        (1 | 2 | 6, false) => ascii(e.contents()),
        // x400Address [3] and ediPartyName [5]: SEQUENCEs, IMPLICIT
        (3 | 5, true) => true,
        // directoryName [4]: a Name, a CHOICE, so EXPLICIT: one SEQUENCE
        (4, true) => {
            let mut inner = e.reader().map_err(|_| bad)?;
            inner.read().is_ok_and(|n| n.tag() == Tag::SEQUENCE) && inner.is_empty()
        }
        // iPAddress [7]: an IPv4 or IPv6 address
        (7, false) => matches!(e.contents().len(), 4 | 16),
        // registeredID [8]: an OBJECT IDENTIFIER's contents
        (8, false) => Oid::from_contents(e.contents()).is_ok(),
        _ => false,
    };
    if ok { Ok(()) } else { Err(bad) }
}

fn write_cert_id(w: &mut Writer, c: &CertId) {
    w.sequence(|w| {
        write_algorithm(w, &c.hash_algorithm);
        w.octet_string(&c.issuer_name_hash);
        w.octet_string(&c.issuer_key_hash);
        w.integer_bytes(&c.serial_number);
    });
}

/// `[n] EXPLICIT Extensions OPTIONAL`, read as an empty list when absent.
fn read_extensions(r: &mut Reader<'_>, n: u32) -> Result<Vec<Extension>, Error> {
    let Some(mut inner) = explicit(r, n)? else { return Ok(Vec::new()) };
    let mut list = inner.read_sequence()?;
    inner.finish()?;
    let mut out = Vec::new();
    while !list.is_empty() {
        if out.len() >= MAX_EXTENSIONS {
            return Err(Error::TooMany);
        }
        let mut s = list.read_sequence()?;
        let id = s.read_oid()?;
        let critical = match s.read_optional(Tag::BOOLEAN)? {
            Some(e) if e.boolean()? => true,
            Some(_) => return Err(Error::ExplicitDefault),
            None => false,
        };
        let value = s.read_octet_string()?.into_owned();
        s.finish()?;
        out.push(Extension { id, critical, value });
    }
    if out.is_empty() {
        return Err(Error::EmptyExtensions);
    }
    Ok(out)
}

/// Writes `[n] EXPLICIT Extensions`, or nothing for an empty list.
fn write_extensions(w: &mut Writer, n: u32, exts: &[Extension]) {
    if exts.is_empty() {
        return;
    }
    w.explicit(n, |w| {
        w.sequence(|w| {
            for e in exts {
                w.sequence(|w| {
                    w.oid(&e.id);
                    if e.critical {
                        w.boolean(true);
                    }
                    w.octet_string(&e.value);
                });
            }
        })
    });
}

fn read_signature_bits(r: &mut Reader<'_>) -> Result<Vec<u8>, Error> {
    let bits = r.read_bit_string()?;
    if bits.unused() != 0 {
        return Err(Error::UnusedBits);
    }
    Ok(bits.bytes().to_vec())
}

/// `[0] EXPLICIT SEQUENCE OF Certificate OPTIONAL`, read as an empty list
/// when absent.
fn read_certs(r: &mut Reader<'_>) -> Result<Vec<Vec<u8>>, Error> {
    let Some(mut inner) = explicit(r, 0)? else { return Ok(Vec::new()) };
    let list = inner.read_sequence()?;
    inner.finish()?;
    let mut out = Vec::new();
    for e in list {
        let e = e?;
        if out.len() >= MAX_CERTS {
            return Err(Error::TooMany);
        }
        if e.tag() != Tag::SEQUENCE {
            return Err(Error::Certificate);
        }
        out.push(checked_raw(&e)?);
    }
    Ok(out)
}

/// Writes `[0] EXPLICIT SEQUENCE OF Certificate`, or nothing for none.
fn write_certs(w: &mut Writer, certs: &[Vec<u8>]) {
    if certs.is_empty() {
        return;
    }
    w.explicit(0, |w| {
        w.sequence(|w| {
            for c in certs {
                w.encoded(c);
            }
        })
    });
}

fn read_response_data(r: &mut Reader<'_>) -> Result<ResponseData, Error> {
    let mut s = r.read_sequence()?;
    let version = read_version(&mut s)?;
    let id = s.read()?;
    let t = id.tag();
    let responder_id = match (t.class, t.number) {
        (Class::ContextSpecific, 1) => {
            let mut inner = id.reader()?;
            let name = inner.read()?;
            inner.finish()?;
            if name.tag() != Tag::SEQUENCE {
                return Err(Error::ResponderId);
            }
            ResponderId::ByName(checked_raw(&name)?)
        }
        (Class::ContextSpecific, 2) => {
            let mut inner = id.reader()?;
            let hash = inner.read_octet_string()?.into_owned();
            inner.finish()?;
            if hash.len() != 20 {
                return Err(Error::HashLength);
            }
            ResponderId::ByKey(hash)
        }
        _ => return Err(Error::ResponderId),
    };
    let produced_at = read_time(&mut s)?;
    let mut list = s.read_sequence()?;
    let mut responses = Vec::new();
    while !list.is_empty() {
        if responses.len() >= MAX_RESPONSES {
            return Err(Error::TooMany);
        }
        responses.push(read_single_response(&mut list)?);
    }
    let extensions = read_extensions(&mut s, 1)?;
    s.finish()?;
    Ok(ResponseData { version, responder_id, produced_at, responses, extensions })
}

fn write_response_data(w: &mut Writer, d: &ResponseData) {
    w.sequence(|w| {
        write_version(w, d.version);
        match &d.responder_id {
            ResponderId::ByName(name) => w.explicit(1, |w| w.encoded(name)),
            ResponderId::ByKey(hash) => w.explicit(2, |w| w.octet_string(hash)),
        }
        w.generalized_time(&d.produced_at);
        w.sequence(|w| {
            for r in &d.responses {
                write_single_response(w, r);
            }
        });
        write_extensions(w, 1, &d.extensions);
    });
}

fn read_single_response(r: &mut Reader<'_>) -> Result<SingleResponse, Error> {
    let mut s = r.read_sequence()?;
    let cert_id = read_cert_id(&mut s)?;
    let e = s.read()?;
    let t = e.tag();
    let status = match (t.class, t.number) {
        // good [0] IMPLICIT NULL
        (Class::ContextSpecific, 0) => {
            e.null()?;
            CertStatus::Good
        }
        // revoked [1] IMPLICIT RevokedInfo
        (Class::ContextSpecific, 1) => {
            let mut info = e.reader()?;
            let time = read_time(&mut info)?;
            let reason = match explicit(&mut info, 0)? {
                Some(mut inner) => {
                    let v = read_enum(&mut inner)?;
                    inner.finish()?;
                    Some(CrlReason::from_code(v).ok_or(Error::Enumerated)?)
                }
                None => None,
            };
            info.finish()?;
            CertStatus::Revoked { time, reason }
        }
        // unknown [2] IMPLICIT UnknownInfo, a NULL
        (Class::ContextSpecific, 2) => {
            e.null()?;
            CertStatus::Unknown
        }
        _ => return Err(Error::CertStatus),
    };
    let this_update = read_time(&mut s)?;
    let next_update = match explicit(&mut s, 0)? {
        Some(mut inner) => {
            let t = read_time(&mut inner)?;
            inner.finish()?;
            Some(t)
        }
        None => None,
    };
    let extensions = read_extensions(&mut s, 1)?;
    s.finish()?;
    Ok(SingleResponse { cert_id, status, this_update, next_update, extensions })
}

fn write_single_response(w: &mut Writer, r: &SingleResponse) {
    w.sequence(|w| {
        write_cert_id(w, &r.cert_id);
        match &r.status {
            CertStatus::Good => w.primitive(Tag::context(0), &[]),
            CertStatus::Revoked { time, reason } => w.constructed(Tag::context(1), |w| {
                w.generalized_time(time);
                if let Some(reason) = reason {
                    w.explicit(0, |w| w.enumerated(reason.code()));
                }
            }),
            CertStatus::Unknown => w.primitive(Tag::context(2), &[]),
        }
        w.generalized_time(&r.this_update);
        if let Some(next) = &r.next_update {
            w.explicit(0, |w| w.generalized_time(next));
        }
        write_extensions(w, 1, &r.extensions);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_id(serial: &[u8]) -> CertId {
        CertId {
            hash_algorithm: AlgorithmIdentifier::sha1(),
            issuer_name_hash: vec![0x11; 20],
            issuer_key_hash: vec![0x22; 20],
            serial_number: serial.to_vec(),
        }
    }

    /// The smallest request: one SHA-1 CertID for serial 1, unsigned, with
    /// no extensions, as RFC 6960 4.1.1 lays it out.
    fn minimal_request_der() -> Vec<u8> {
        let mut b = vec![0x30, 0x42, 0x30, 0x40, 0x30, 0x3e, 0x30, 0x3c, 0x30, 0x3a];
        b.extend_from_slice(&[0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00]);
        b.extend_from_slice(&[0x04, 0x14]);
        b.extend_from_slice(&[0x11; 20]);
        b.extend_from_slice(&[0x04, 0x14]);
        b.extend_from_slice(&[0x22; 20]);
        b.extend_from_slice(&[0x02, 0x01, 0x01]);
        b
    }

    fn full_request() -> OcspRequest {
        let mut req = OcspRequest::new(vec![
            Request { cert_id: cert_id(&[0x01]), extensions: vec![] },
            Request {
                cert_id: CertId {
                    hash_algorithm: AlgorithmIdentifier::sha256(),
                    issuer_name_hash: vec![0x33; 32],
                    issuer_key_hash: vec![0x44; 32],
                    ..cert_id(&[0x00, 0x80, 0x01])
                },
                extensions: vec![Extension { id: "1.2.3.4".parse().unwrap(), critical: true, value: vec![5, 0] }],
            },
        ]);
        req.version = 0;
        // A GeneralName: directoryName [4] holding an empty Name.
        req.requestor_name = Some(vec![0xa4, 0x02, 0x30, 0x00]);
        req.extensions.push(Extension::nonce(&[0xab; 16]).unwrap());
        req.signature = Some(Signature {
            algorithm: AlgorithmIdentifier { algorithm: "1.2.840.113549.1.1.11".parse().unwrap(), parameters: None },
            signature: vec![0x5a; 32],
            certs: vec![vec![0x30, 0x03, 0x02, 0x01, 0x07]],
        });
        req
    }

    fn full_response() -> OcspResponse {
        let single = |status, serial: &[u8]| SingleResponse {
            cert_id: cert_id(serial),
            status,
            this_update: "20261005000000Z".to_string(),
            next_update: Some("20261012000000Z".to_string()),
            extensions: vec![],
        };
        let mut unknown = single(CertStatus::Unknown, &[3]);
        unknown.next_update = None;
        unknown.extensions.push(Extension { id: "1.2.3".parse().unwrap(), critical: false, value: vec![] });
        OcspResponse::basic(BasicResponse {
            data: ResponseData {
                version: 0,
                responder_id: ResponderId::ByName(vec![0x30, 0x00]),
                produced_at: "20261005120000Z".to_string(),
                responses: vec![
                    single(CertStatus::Good, &[1]),
                    single(
                        CertStatus::Revoked {
                            time: "20260101000000Z".to_string(),
                            reason: Some(CrlReason::KeyCompromise),
                        },
                        &[2],
                    ),
                    single(CertStatus::Revoked { time: "20260102000000Z".to_string(), reason: None }, &[4]),
                    unknown,
                ],
                extensions: vec![Extension::nonce(&[0xab; 16]).unwrap()],
            },
            signature_algorithm: AlgorithmIdentifier {
                algorithm: "1.2.840.10045.4.3.2".parse().unwrap(),
                parameters: None,
            },
            signature: vec![0x77; 70],
            certs: vec![vec![0x30, 0x00], vec![0x30, 0x03, 0x01, 0x01, 0xff]],
        })
    }

    #[test]
    fn minimal_request_reads_and_writes() {
        let der = minimal_request_der();
        assert_eq!(der.len(), 68);
        let req = OcspRequest::parse(&der).unwrap();
        assert_eq!(req, OcspRequest::new(vec![Request { cert_id: cert_id(&[1]), extensions: vec![] }]));
        assert_eq!(req.nonce(), None);
        assert_eq!(req.to_der().unwrap(), der);
    }

    #[test]
    fn error_responses_are_five_bytes() {
        // RFC 6960 4.2.1: an error status carries no responseBytes.
        let cases = [
            (ResponseStatus::MalformedRequest, 1),
            (ResponseStatus::InternalError, 2),
            (ResponseStatus::TryLater, 3),
            (ResponseStatus::SigRequired, 5),
            (ResponseStatus::Unauthorized, 6),
        ];
        for (status, code) in cases {
            let der = OcspResponse::error(status).to_der().unwrap();
            assert_eq!(der, [0x30, 0x03, 0x0a, 0x01, code]);
            assert_eq!(OcspResponse::parse(&der).unwrap(), OcspResponse::error(status));
        }
        for c in -300..300 {
            assert_eq!(
                ResponseStatus::from_code(c).map(ResponseStatus::code),
                [0, 1, 2, 3, 5, 6].contains(&c).then_some(c)
            );
            assert_eq!(
                CrlReason::from_code(c).map(CrlReason::code),
                (0..=10).contains(&c).then_some(c).filter(|&c| c != 7)
            );
        }
    }

    #[test]
    fn nonce_is_an_octet_string_inside_the_value() {
        let ext = Extension::nonce(b"abc").unwrap();
        assert_eq!(ext.id.to_string(), "1.3.6.1.5.5.7.48.1.2");
        assert_eq!(ext.value, [0x04, 0x03, b'a', b'b', b'c']);
        assert_eq!(find_nonce(std::slice::from_ref(&ext)), Some(&b"abc"[..]));
        // Old clients put the bare bytes in the value.
        let bare = Extension { value: b"xyz".to_vec(), ..ext };
        assert_eq!(find_nonce(&[bare]), Some(&b"xyz"[..]));
        assert_eq!(find_nonce(&[]), None);
    }

    #[test]
    fn oids_are_the_ones_named() {
        assert_eq!(known_oid(oid::BASIC).to_string(), "1.3.6.1.5.5.7.48.1.1");
        assert_eq!(known_oid(oid::SHA1).to_string(), "1.3.14.3.2.26");
        assert_eq!(known_oid(oid::SHA256).to_string(), "2.16.840.1.101.3.4.2.1");
    }

    #[test]
    fn full_request_round_trips() {
        let req = full_request();
        let der = req.to_der().unwrap();
        let back = OcspRequest::parse(&der).unwrap();
        assert_eq!(back, req);
        assert_eq!(back.to_der().unwrap(), der);
        assert_eq!(back.nonce(), Some(&[0xab; 16][..]));
        // A version other than v1 is written out and read back.
        let mut v2 = req.clone();
        v2.version = 1;
        assert_eq!(OcspRequest::parse(&v2.to_der().unwrap()).unwrap(), v2);
    }

    #[test]
    fn full_response_round_trips() {
        let resp = full_response();
        let der = resp.to_der().unwrap();
        let back = OcspResponse::parse(&der).unwrap();
        assert_eq!(back, resp);
        assert_eq!(back.to_der().unwrap(), der);
        let basic = back.basic_response().unwrap();
        assert_eq!(basic.data.nonce(), Some(&[0xab; 16][..]));
        // The signed bytes appear as they are inside the response.
        let tbs = basic.data.to_der().unwrap();
        assert!(der.windows(tbs.len()).any(|w| w == tbs));
        // The statuses' encodings: [0] and [2] IMPLICIT NULL, [1] constructed.
        assert!(tbs.windows(2).any(|w| w == [0x80, 0x00]));
        assert!(tbs.windows(2).any(|w| w == [0x82, 0x00]));
        assert!(tbs.windows(2).any(|w| w == [0xa1, 0x16]));
        // By key, with no certificates and no extensions.
        let mut b = basic.clone();
        b.data.responder_id = ResponderId::ByKey(vec![9; 20]);
        b.certs.clear();
        b.data.extensions.clear();
        let r = OcspResponse::basic(b);
        assert_eq!(OcspResponse::parse(&r.to_der().unwrap()).unwrap(), r);
    }

    #[test]
    fn other_response_types_are_kept() {
        let r = OcspResponse {
            status: ResponseStatus::Successful,
            bytes: Some(ResponseBytes::Other { response_type: "1.2.3.4".parse().unwrap(), response: vec![1, 2, 3] }),
        };
        assert_eq!(OcspResponse::parse(&r.to_der().unwrap()).unwrap(), r);
        // With the basic type's identifier the bytes must be a basic response.
        let bad = OcspResponse {
            status: ResponseStatus::Successful,
            bytes: Some(ResponseBytes::Other { response_type: known_oid(oid::BASIC), response: vec![1, 2, 3] }),
        };
        assert_eq!(bad.to_der(), Err(Error::ResponseBytes));
        // Even when they are one: it would read back as Basic, not as it was.
        let basic = full_response().basic_response().unwrap().to_der().unwrap();
        let as_other = OcspResponse {
            status: ResponseStatus::Successful,
            bytes: Some(ResponseBytes::Other { response_type: known_oid(oid::BASIC), response: basic }),
        };
        assert_eq!(as_other.to_der(), Err(Error::ResponseBytes));
        // Bytes over a message are refused before they are copied.
        let huge = OcspResponse {
            status: ResponseStatus::Successful,
            bytes: Some(ResponseBytes::Other {
                response_type: "1.2.3.4".parse().unwrap(),
                response: vec![0; MAX_MESSAGE + 1],
            }),
        };
        assert_eq!(huge.to_der(), Err(Error::TooLong));
    }

    #[test]
    fn get_path() {
        let der = minimal_request_der();
        let path = encode_get_path(&der).unwrap();
        // 30 42 30 40 30 3e ... is "MEIwQDA+..." in base64, with + escaped.
        assert!(path.starts_with("MEIwQDA%2BMDwwOjAJ"), "{path}");
        assert_eq!(decode_get_path(&path).unwrap(), der);
        assert_eq!(OcspRequest::from_get_path(&path).unwrap().to_der().unwrap(), der);
        // Unescaped, lowercase escapes and no padding all read.
        let plain = path.replace("%2B", "+").replace("%2F", "/").replace("%3D", "=");
        assert_eq!(decode_get_path(&plain).unwrap(), der);
        assert_eq!(decode_get_path(&path.replace("%2B", "%2b")).unwrap(), der);
        assert_eq!(decode_get_path(plain.trim_end_matches('=')).unwrap(), der);
        // Every length, through padding.
        for n in 0..10 {
            let b: Vec<u8> = (0..n).map(|i| (i * 37 + 250) as u8).collect();
            assert_eq!(decode_get_path(&encode_get_path(&b).unwrap()).unwrap(), b);
        }
        assert_eq!(encode_get_path(b"\xfb\xff").unwrap(), "%2B%2F8%3D");
        let full = full_request();
        assert_eq!(OcspRequest::from_get_path(&full.to_get_path().unwrap()).unwrap(), full);
    }

    #[test]
    fn get_path_errors() {
        for bad in ["A", "AB=C", "ABC==", "AB===", "AB%", "AB%4", "AB%G0", "AB-_", "AB C", "ABCDE"] {
            assert_eq!(decode_get_path(bad), Err(Error::GetPath), "{bad}");
        }
        assert_eq!(decode_get_path(&"A".repeat(MAX_GET_PATH + 1)), Err(Error::TooLong));
        // Under the path limit, but decoding to more than a message.
        assert_eq!(decode_get_path(&"A".repeat((MAX_MESSAGE / 3 + 1) * 4)), Err(Error::TooLong));
        assert_eq!(encode_get_path(&vec![0; MAX_MESSAGE + 1]), Err(Error::TooLong));
        assert!(encode_get_path(&vec![0xff; MAX_MESSAGE]).unwrap().len() <= MAX_GET_PATH);
        assert!(decode_get_path(&encode_get_path(&vec![0xff; MAX_MESSAGE]).unwrap()).is_ok());
    }

    /// One DER element with a one-byte tag.
    fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
        let n = contents.len();
        let mut out = vec![tag];
        if n < 0x80 {
            out.push(n as u8);
        } else if n < 0x100 {
            out.extend_from_slice(&[0x81, n as u8]);
        } else {
            out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
        }
        out.extend_from_slice(contents);
        out
    }

    /// The minimal request with `front` before the TBSRequest's list and
    /// `back` after it, lengths fixed up.
    fn request_with(front: &[u8], back: &[u8]) -> Vec<u8> {
        let list = &minimal_request_der()[4..];
        tlv(0x30, &tlv(0x30, &[front, list, back].concat()))
    }

    #[test]
    fn request_errors() {
        // Not a SEQUENCE, trailing bytes, a short read.
        assert!(matches!(OcspRequest::parse(&[0x31, 0x00]), Err(Error::Asn1(asn1::Error::Unexpected { .. }))));
        let mut trailing = minimal_request_der();
        trailing.push(0);
        assert_eq!(OcspRequest::parse(&trailing), Err(Error::Asn1(asn1::Error::Trailing)));
        assert_eq!(OcspRequest::parse(&[]), Err(Error::Asn1(asn1::Error::Empty)));
        assert_eq!(OcspRequest::parse(&vec![0x30; MAX_MESSAGE + 1]), Err(Error::TooLong));
        // Version v1 written out: [0] { INTEGER 0 }.
        assert_eq!(
            OcspRequest::parse(&request_with(&[0xa0, 0x03, 0x02, 0x01, 0x00], &[])),
            Err(Error::ExplicitDefault)
        );
        let v2 = OcspRequest::parse(&request_with(&[0xa0, 0x03, 0x02, 0x01, 0x01], &[])).unwrap();
        assert_eq!(v2.version, 1);
        // An empty list of extensions: [2] { SEQUENCE {} }.
        assert_eq!(OcspRequest::parse(&request_with(&[], &[0xa2, 0x02, 0x30, 0x00])), Err(Error::EmptyExtensions));
        // critical FALSE written out.
        let ext = [0xa2, 0x0c, 0x30, 0x0a, 0x30, 0x08, 0x06, 0x01, 0x2a, 0x01, 0x01, 0x00, 0x04, 0x00];
        assert_eq!(OcspRequest::parse(&request_with(&[], &ext)), Err(Error::ExplicitDefault));
        let mut ext_true = ext;
        ext_true[11] = 0xff;
        assert!(OcspRequest::parse(&request_with(&[], &ext_true)).unwrap().extensions[0].critical);
        // A requestor name that is not DER: a BOOLEAN of 0x01.
        assert_eq!(
            OcspRequest::parse(&request_with(&[0xa1, 0x03, 0x01, 0x01, 0x01], &[])),
            Err(Error::Asn1(asn1::Error::Boolean))
        );
        // Too many extensions, and too many certificates asked about.
        let one = [0x30, 0x05, 0x06, 0x01, 0x2a, 0x04, 0x00];
        let mut w = Writer::new();
        w.explicit(2, |w| {
            w.sequence(|w| {
                for _ in 0..=MAX_EXTENSIONS {
                    w.encoded(&one);
                }
            })
        });
        assert_eq!(OcspRequest::parse(&request_with(&[], &w.finish().unwrap())), Err(Error::TooMany));
        let mut w = Writer::new();
        w.sequence(|w| {
            w.sequence(|w| {
                w.sequence(|w| {
                    for _ in 0..=MAX_REQUESTS {
                        w.sequence(|w| write_cert_id(w, &cert_id(&[1])));
                    }
                })
            })
        });
        assert_eq!(OcspRequest::parse(&w.finish().unwrap()), Err(Error::TooMany));
    }

    #[test]
    fn signature_errors() {
        let req = full_request();
        let der = req.to_der().unwrap();
        // The signature BIT STRING is 03 21 00 5a...; give it 1 unused bit.
        let at = der.windows(3).position(|w| w == [0x03, 0x21, 0x00]).unwrap();
        let mut odd = der.clone();
        odd[at + 2] = 1;
        odd[at + 34] = 0x5a & 0xfe;
        assert_eq!(OcspRequest::parse(&odd), Err(Error::UnusedBits));
        // A certificate that is not a SEQUENCE.
        let mut not_seq = der.clone();
        let at = not_seq.windows(5).position(|w| w == [0x30, 0x03, 0x02, 0x01, 0x07]).unwrap();
        not_seq[at] = 0x31;
        assert_eq!(OcspRequest::parse(&not_seq), Err(Error::Certificate));
        // Too many certificates, either way.
        let mut many = req.clone();
        many.signature.as_mut().unwrap().certs = vec![vec![0x30, 0x00]; MAX_CERTS + 1];
        assert_eq!(many.to_der(), Err(Error::TooMany));
        let mut sig = Writer::new();
        sig.explicit(0, |w| {
            w.sequence(|w| {
                write_algorithm(w, &AlgorithmIdentifier::sha1());
                w.bit_string(&[1], 0);
                write_certs(w, &vec![vec![0x30, 0x00]; MAX_CERTS + 1]);
            })
        });
        let sig = sig.finish().unwrap();
        let tbs = &minimal_request_der()[2..];
        let mut w = Writer::new();
        w.sequence(|w| {
            w.encoded(tbs);
            w.encoded(&sig);
        });
        assert_eq!(OcspRequest::parse(&w.finish().unwrap()), Err(Error::TooMany));
    }

    #[test]
    fn writer_errors() {
        let mut r = full_request();
        r.requests = vec![Request { cert_id: cert_id(&[1]), extensions: vec![] }; MAX_REQUESTS + 1];
        assert_eq!(r.to_der(), Err(Error::TooMany));
        let mut r = full_request();
        r.extensions = vec![Extension::nonce(b"x").unwrap(); MAX_EXTENSIONS + 1];
        assert_eq!(r.to_der(), Err(Error::TooMany));
        let mut r = full_request();
        r.requestor_name = Some(vec![0x01, 0x01, 0x01]);
        assert_eq!(r.to_der(), Err(Error::RequestorName));
        r.requestor_name = Some(vec![0xa4, 0x05, 0x30, 0x03, 0x01, 0x01, 0x01]);
        assert_eq!(r.to_der(), Err(Error::Asn1(asn1::Error::Boolean)));
        let mut r = full_request();
        r.signature.as_mut().unwrap().certs = vec![vec![0x02, 0x01, 0x00]];
        assert_eq!(r.to_der(), Err(Error::Certificate));
        let mut r = full_request();
        r.extensions = vec![Extension { id: known_oid(oid::NONCE), critical: false, value: vec![0; MAX_MESSAGE] }];
        assert_eq!(r.to_der(), Err(Error::TooLong));

        let mut resp = full_response();
        let Some(ResponseBytes::Basic(b)) = &mut resp.bytes else { panic!() };
        b.data.produced_at = "2026-10-05".to_string();
        assert_eq!(resp.to_der(), Err(Error::Asn1(asn1::Error::Time)));
        let mut resp = full_response();
        let Some(ResponseBytes::Basic(b)) = &mut resp.bytes else { panic!() };
        b.data.responder_id = ResponderId::ByName(vec![0x04, 0x00]);
        assert_eq!(resp.to_der(), Err(Error::ResponderId));
        let mut resp = full_response();
        let Some(ResponseBytes::Basic(b)) = &mut resp.bytes else { panic!() };
        b.data.responses = vec![b.data.responses[0].clone(); MAX_RESPONSES + 1];
        assert_eq!(resp.to_der(), Err(Error::TooMany));
        let mut resp = full_response();
        let Some(ResponseBytes::Basic(b)) = &mut resp.bytes else { panic!() };
        b.signature_algorithm.parameters = Some(vec![0x05, 0x00, 0x05, 0x00]);
        assert_eq!(resp.to_der(), Err(Error::Asn1(asn1::Error::Trailing)));
    }

    #[test]
    fn response_errors() {
        let der = full_response().to_der().unwrap();
        let basic = full_response().basic_response().unwrap().to_der().unwrap();
        let wrap = |basic: &[u8]| {
            let mut w = Writer::new();
            w.sequence(|w| {
                w.enumerated(0);
                w.explicit(0, |w| {
                    w.sequence(|w| {
                        w.oid(&known_oid(oid::BASIC));
                        w.octet_string(basic);
                    })
                });
            });
            w.finish().unwrap()
        };
        assert_eq!(wrap(&basic), der);
        // A status tag of [3].
        let mut bad = basic.clone();
        let at = bad.windows(2).position(|w| w == [0x80, 0x00]).unwrap();
        bad[at] = 0x83;
        assert_eq!(OcspResponse::parse(&wrap(&bad)), Err(Error::CertStatus));
        // good with contents: [0] { 00 } in place of [0] {} needs a length change, so use a constructed [0].
        bad[at] = 0xa0;
        assert_eq!(OcspResponse::parse(&wrap(&bad)), Err(Error::Asn1(asn1::Error::Constructed)));
        // A responder ID of [3], and a name that is not a SEQUENCE.
        let mut bad = basic.clone();
        let at = bad.windows(4).position(|w| w == [0xa1, 0x02, 0x30, 0x00]).unwrap();
        bad[at] = 0xa3;
        assert_eq!(BasicResponse::parse(&bad), Err(Error::ResponderId));
        bad[at] = 0xa1;
        bad[at + 2] = 0x31;
        assert_eq!(BasicResponse::parse(&bad), Err(Error::ResponderId));
        // A bad time.
        let mut bad = basic.clone();
        let at = bad.windows(4).position(|w| w == *b"2026").unwrap();
        bad[at + 4] = b'9';
        assert_eq!(BasicResponse::parse(&bad), Err(Error::Asn1(asn1::Error::Time)));
        // A non-DER boolean in a certificate kept as raw DER.
        let mut bad = basic.clone();
        let at = bad.windows(5).position(|w| w == [0x30, 0x03, 0x01, 0x01, 0xff]).unwrap();
        bad[at + 4] = 0x01;
        assert_eq!(BasicResponse::parse(&bad), Err(Error::Asn1(asn1::Error::Boolean)));
        // The error inside reaches the outer parse.
        assert_eq!(OcspResponse::parse(&wrap(&bad)), Err(Error::Asn1(asn1::Error::Boolean)));
        // An ENUMERATED too large for i64.
        let big = [0x30, 0x0b, 0x0a, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(OcspResponse::parse(&big), Err(Error::Asn1(asn1::Error::Integer)));
        assert_eq!(OcspResponse::parse(&[0x30, 0x03, 0x0a, 0x01, 0x04]), Err(Error::Enumerated));
    }

    #[test]
    fn every_truncated_prefix_fails() {
        for der in [minimal_request_der(), full_request().to_der().unwrap()] {
            for n in 0..der.len() {
                assert!(OcspRequest::parse(&der[..n]).is_err(), "{n}");
                let mut d = Decoder::new();
                let fed = &der[..n];
                assert_eq!(d.feed(fed), fed.len());
                assert_eq!(d.next_message(), None, "{n}");
                assert_eq!(d.buffered(), n);
            }
        }
        let der = full_response().to_der().unwrap();
        for n in 0..der.len() {
            assert!(OcspResponse::parse(&der[..n]).is_err(), "{n}");
        }
        let basic = full_response().basic_response().unwrap().to_der().unwrap();
        for n in 0..basic.len() {
            assert!(BasicResponse::parse(&basic[..n]).is_err(), "{n}");
        }
    }

    #[test]
    fn decoder_splits_messages() {
        let a = minimal_request_der();
        let b = full_response().to_der().unwrap();
        let stream: Vec<u8> = a.iter().chain(&b).copied().collect();
        let mut d = Decoder::new();
        let mut got = Vec::new();
        for byte in &stream {
            let fed = std::slice::from_ref(byte);
            assert_eq!(d.feed(fed), fed.len());
            while let Some(m) = d.next_message() {
                got.push(m.unwrap());
            }
        }
        assert_eq!(got, [a.clone(), b]);
        assert_eq!(d.buffered(), 0);
        // A header announcing too much breaks the stream at once.
        let fed = &[0x30, 0x83, 0x01, 0x00, 0x01];
        assert_eq!(d.feed(fed), fed.len());
        assert_eq!(d.next_message(), Some(Err(Error::TooLong)));
        let fed = &a;
        assert_eq!(d.feed(fed), fed.len());
        assert_eq!(d.next_message(), Some(Err(Error::TooLong)));
        assert_eq!(d.buffered(), 0);
        // Indefinite lengths are not DER.
        let mut d = Decoder::new();
        let fed = &[0x30, 0x80];
        assert_eq!(d.feed(fed), fed.len());
        assert!(matches!(d.next_message(), Some(Err(Error::Asn1(_)))));
        // A message just at the limit is fine.
        let mut d = Decoder::new();
        let fed = &[0x04, 0x82, 0xff, 0xfc];
        assert_eq!(d.feed(fed), fed.len());
        let fed = &vec![0; MAX_MESSAGE - 4];
        assert_eq!(d.feed(fed), fed.len());
        assert_eq!(d.next_message().unwrap().unwrap().len(), MAX_MESSAGE);
    }

    #[test]
    fn fractional_seconds_are_refused() {
        // RFC 6960 4.2.2.1 takes the time format of RFC 5280 4.1.2.5.2:
        // YYYYMMDDHHMMSSZ, with no fractional seconds.
        let mut resp = full_response();
        let Some(ResponseBytes::Basic(b)) = &mut resp.bytes else { panic!() };
        b.data.responses[0].this_update = "20261005000000.5Z".to_string();
        assert_eq!(resp.to_der(), Err(Error::Asn1(asn1::Error::Time)));
        for set in [
            |d: &mut ResponseData| d.produced_at = "20261005120000.25Z".to_string(),
            |d: &mut ResponseData| d.responses[0].next_update = Some("20261012000000.1Z".to_string()),
            |d: &mut ResponseData| {
                d.responses[0].status = CertStatus::Revoked { time: "20260101000000.9Z".to_string(), reason: None }
            },
        ] {
            let mut d = full_response().basic_response().unwrap().data.clone();
            set(&mut d);
            assert_eq!(d.to_der(), Err(Error::Asn1(asn1::Error::Time)));
        }
        // The reader refuses the same bytes. The internal writer skips the
        // check, so it can make them.
        let mut d = full_response().basic_response().unwrap().data.clone();
        d.produced_at = "20261005120000.5Z".to_string();
        let mut w = Writer::new();
        w.sequence(|w| {
            write_response_data(w, &d);
            write_algorithm(w, &AlgorithmIdentifier::sha1());
            w.bit_string(&[1], 0);
        });
        let inner = w.finish().unwrap();
        assert_eq!(BasicResponse::parse(&inner), Err(Error::Asn1(asn1::Error::Time)));
    }

    #[test]
    fn response_bytes_follow_the_status() {
        // RFC 6960 4.2.1: an error status carries no responseBytes, and a
        // successful one answers.
        let mut bad = full_response();
        bad.status = ResponseStatus::TryLater;
        assert_eq!(bad.to_der(), Err(Error::ResponseBytes));
        let empty = OcspResponse::error(ResponseStatus::Successful);
        assert_eq!(empty.to_der(), Err(Error::ResponseBytes));
        assert_eq!(OcspResponse::parse(&[0x30, 0x03, 0x0a, 0x01, 0x00]), Err(Error::ResponseBytes));
        let mut der = full_response().to_der().unwrap();
        let at = der.windows(3).position(|w| w == [0x0a, 0x01, 0x00]).unwrap();
        der[at + 2] = 3;
        assert_eq!(OcspResponse::parse(&der), Err(Error::ResponseBytes));
    }

    #[test]
    fn signed_requests_name_their_requestor() {
        // RFC 6960 4.1.2: a signed request SHALL name its requestor.
        let mut req = full_request();
        req.requestor_name = None;
        assert_eq!(req.to_der(), Err(Error::RequestorName));
        let mut w = Writer::new();
        w.sequence(|w| {
            w.encoded(&minimal_request_der()[2..]);
            w.explicit(0, |w| {
                w.sequence(|w| {
                    write_algorithm(w, &AlgorithmIdentifier::sha1());
                    w.bit_string(&[1], 0);
                })
            });
        });
        assert_eq!(OcspRequest::parse(&w.finish().unwrap()), Err(Error::RequestorName));
        // Unsigned with a name is fine.
        let mut req = full_request();
        req.signature = None;
        assert_eq!(OcspRequest::parse(&req.to_der().unwrap()).unwrap(), req);
    }

    #[test]
    fn enumerations_are_closed() {
        // RFC 6960 4.2.1 and RFC 5280 5.3.1 list every value, with no
        // extension marker: 4 is not a status, and 7 not a reason.
        assert_eq!(ResponseStatus::from_code(4), None);
        assert_eq!(CrlReason::from_code(7), None);
        assert_eq!(OcspResponse::parse(&[0x30, 0x03, 0x0a, 0x01, 0x07]), Err(Error::Enumerated));
        assert_eq!(OcspResponse::parse(&[0x30, 0x03, 0x0a, 0x01, 0xff]), Err(Error::Enumerated));
        let basic = full_response().basic_response().unwrap().to_der().unwrap();
        // The KeyCompromise reason is [0] { ENUMERATED 1 }; make it 7.
        let at = basic.windows(5).position(|w| w == [0xa0, 0x03, 0x0a, 0x01, 0x01]).unwrap();
        let mut bad = basic.clone();
        bad[at + 4] = 7;
        assert_eq!(BasicResponse::parse(&bad), Err(Error::Enumerated));
        bad[at + 4] = 10;
        assert!(BasicResponse::parse(&bad).is_ok());
    }

    #[test]
    fn decoder_holds_at_most_a_message() {
        // One large feed takes only what fits, and the rest waits.
        let mut big = vec![0; 1 << 20];
        big[..5].copy_from_slice(&[0x04, 0x83, 0x0f, 0xff, 0xfb]);
        let mut d = Decoder::new();
        assert_eq!(d.feed(&big), MAX_MESSAGE);
        assert_eq!(d.buffered(), MAX_MESSAGE);
        assert_eq!(d.feed(&big), 0);
        // Full, it always answers: here the header announces too much.
        assert_eq!(d.next_message(), Some(Err(Error::TooLong)));
        // A stream of many messages goes through in pieces of any size.
        let a = minimal_request_der();
        let stream: Vec<u8> = (0..3000).flat_map(|_| a.iter().copied()).collect();
        let mut d = Decoder::new();
        let (mut rest, mut got) = (&stream[..], 0);
        while !rest.is_empty() {
            let n = d.feed(rest);
            rest = &rest[n..];
            assert!(d.buffered() <= MAX_MESSAGE);
            while let Some(m) = d.next_message() {
                assert_eq!(m.unwrap(), a);
                got += 1;
            }
        }
        assert_eq!(got, 3000);
    }

    #[test]
    fn requestor_name_is_a_general_name() {
        // RFC 6960 4.1.1: requestorName [1] EXPLICIT GeneralName.
        let mut r = full_request();
        for good in [
            vec![0xa4, 0x02, 0x30, 0x00],
            tlv(0x81, b"a@example.com"),
            tlv(0x82, b"example.com"),
            tlv(0x86, b"http://example.com/"),
            vec![0x87, 0x04, 10, 0, 0, 1],
            vec![0x88, 0x03, 0x2a, 0x03, 0x04],
            vec![0xa0, 0x07, 0x06, 0x01, 0x2a, 0xa0, 0x02, 0x05, 0x00],
            vec![0xa3, 0x00],
            vec![0xa5, 0x00],
        ] {
            r.requestor_name = Some(good.clone());
            let der = r.to_der().unwrap();
            assert_eq!(OcspRequest::parse(&der).unwrap(), r, "{good:02x?}");
        }
        for bad in [
            vec![0x05, 0x00],
            vec![0x30, 0x00],
            vec![0x84, 0x00],
            vec![0xa4, 0x02, 0x31, 0x00],
            vec![0xa4, 0x04, 0x30, 0x00, 0x30, 0x00],
            vec![0xa1, 0x00],
            vec![0x82, 0x01, 0xff],
            vec![0x87, 0x03, 10, 0, 0],
            vec![0x88, 0x01, 0x80],
            vec![0xa0, 0x03, 0x06, 0x01, 0x2a],
            vec![0x89, 0x00],
        ] {
            r.requestor_name = Some(bad.clone());
            assert_eq!(r.to_der(), Err(Error::RequestorName), "{bad:02x?}");
            let der = request_with(&tlv(0xa1, &bad), &[]);
            assert_eq!(OcspRequest::parse(&der), Err(Error::RequestorName), "{bad:02x?}");
        }
    }

    #[test]
    fn nonces_are_1_to_128_bytes() {
        // RFC 9654 2.1: Nonce ::= OCTET STRING(SIZE(1..128)).
        assert_eq!(Extension::nonce(&[]), Err(Error::Nonce));
        assert_eq!(Extension::nonce(&[0; MAX_NONCE + 1]), Err(Error::Nonce));
        assert!(Extension::nonce(&[0; MAX_NONCE]).is_ok());
        let ext = |value: Vec<u8>| Extension { id: known_oid(oid::NONCE), critical: false, value };
        assert_eq!(find_nonce(&[ext(vec![0x04, 0x00])]), None);
        assert_eq!(find_nonce(&[ext(vec![])]), None);
        assert_eq!(find_nonce(&[ext(tlv(0x04, &[1; MAX_NONCE + 1]))]), None);
        assert_eq!(find_nonce(&[ext(vec![7; MAX_NONCE + 1])]), None);
        assert_eq!(find_nonce(&[ext(tlv(0x04, &[1; MAX_NONCE]))]), Some(&[1; MAX_NONCE][..]));
        // A request with an empty nonce reads, but carries no nonce.
        let mut r = OcspRequest::new(vec![Request { cert_id: cert_id(&[1]), extensions: vec![] }]);
        r.extensions.push(ext(vec![0x04, 0x00]));
        assert_eq!(OcspRequest::parse(&r.to_der().unwrap()).unwrap().nonce(), None);
    }

    #[test]
    fn hashes_have_their_lengths() {
        // RFC 6960 4.1.1: the CertID hashes are hashAlgorithm's; 4.2.1:
        // KeyHash is a SHA-1 hash.
        let one = |c: CertId| OcspRequest::new(vec![Request { cert_id: c, extensions: vec![] }]);
        let mut c = cert_id(&[1]);
        c.issuer_name_hash.clear();
        assert_eq!(one(c).to_der(), Err(Error::HashLength));
        let mut c = cert_id(&[1]);
        c.hash_algorithm = AlgorithmIdentifier::sha256();
        assert_eq!(one(c.clone()).to_der(), Err(Error::HashLength));
        c.issuer_name_hash = vec![1; 32];
        c.issuer_key_hash = vec![2; 32];
        assert!(one(c).to_der().is_ok());
        // An unknown algorithm's hashes only need to be there.
        let mut c = cert_id(&[1]);
        c.hash_algorithm.algorithm = "1.2.3.4".parse().unwrap();
        c.issuer_key_hash = vec![1];
        assert!(one(c.clone()).to_der().is_ok());
        c.issuer_key_hash.clear();
        assert_eq!(one(c).to_der(), Err(Error::HashLength));
        // The reader refuses a 19-byte SHA-1 hash.
        let mut der = minimal_request_der();
        let at = der.windows(2).position(|w| w == [0x04, 0x14]).unwrap();
        der[at + 1] = 0x13;
        der.remove(at + 2);
        for i in [1, 3, 5, 7, 9] {
            der[i] -= 1;
        }
        assert_eq!(OcspRequest::parse(&der), Err(Error::HashLength));
        // A responder key hash of other than 20 bytes, either way.
        let mut resp = full_response();
        let Some(ResponseBytes::Basic(b)) = &mut resp.bytes else { panic!() };
        b.data.responder_id = ResponderId::ByKey(vec![]);
        assert_eq!(resp.to_der(), Err(Error::HashLength));
        let mut w = Writer::new();
        w.sequence(|w| {
            w.sequence(|w| {
                w.explicit(2, |w| w.octet_string(&[9; 19]));
                w.generalized_time("20261005120000Z");
                w.sequence(|_| {});
            });
            write_algorithm(w, &AlgorithmIdentifier::sha1());
            w.bit_string(&[1], 0);
        });
        assert_eq!(BasicResponse::parse(&w.finish().unwrap()), Err(Error::HashLength));
    }

    #[test]
    fn serial_numbers_write_as_they_read() {
        // A serial number in a longer form than DER's would read back
        // shorter, so a writer refuses it.
        let one = |serial: &[u8]| OcspRequest::new(vec![Request { cert_id: cert_id(serial), extensions: vec![] }]);
        for bad in [&[][..], &[0x00, 0x01], &[0xff, 0x80]] {
            assert_eq!(one(bad).to_der(), Err(Error::Asn1(asn1::Error::Integer)), "{bad:02x?}");
        }
        for good in [&[0x00][..], &[0x00, 0x80], &[0x7f], &[0x01, 0x00]] {
            let r = one(good);
            assert_eq!(OcspRequest::parse(&r.to_der().unwrap()).unwrap(), r, "{good:02x?}");
        }
        let mut resp = full_response();
        let Some(ResponseBytes::Basic(b)) = &mut resp.bytes else { panic!() };
        b.data.responses[0].cert_id.serial_number = vec![0, 1];
        assert_eq!(resp.to_der(), Err(Error::Asn1(asn1::Error::Integer)));
    }

    #[test]
    fn requests_ask_about_at_least_one_certificate() {
        // RFC 6960 4.1.2: requestList contains one or more requests.
        assert_eq!(OcspRequest::new(vec![]).to_der(), Err(Error::NoRequests));
        assert_eq!(OcspRequest::new(vec![]).tbs_der(), Err(Error::NoRequests));
        assert_eq!(OcspRequest::parse(&[0x30, 0x04, 0x30, 0x02, 0x30, 0x00]), Err(Error::NoRequests));
    }

    #[test]
    fn tbs_der_is_the_signed_part() {
        // RFC 6960 4.1.2: the signature covers tbsRequest.
        let req = full_request();
        let der = req.to_der().unwrap();
        let tbs = req.tbs_der().unwrap();
        let mut outer = Reader::new(&der, Rules::Der);
        let mut inner = outer.read_sequence().unwrap();
        assert_eq!(inner.read().unwrap().raw(), &tbs[..]);
        let mut unsigned = req.clone();
        unsigned.signature = None;
        assert_eq!(unsigned.tbs_der().unwrap(), tbs);
        assert_eq!(unsigned.to_der().unwrap(), tlv(0x30, &tbs));
    }

    /// `levels` explicit [0] tags around an empty SEQUENCE.
    fn nested_name(levels: usize) -> Vec<u8> {
        let mut b = vec![0x30, 0x00];
        for _ in 0..levels {
            b = tlv(0xa0, &b);
        }
        b
    }

    #[test]
    fn raw_parts_write_where_they_read() {
        // Raw DER parts at every depth: a writer takes exactly what a
        // reader takes, in each place one can go.
        let (mut wrote, mut refused) = (0, 0);
        for levels in 0..asn1::MAX_DEPTH + 4 {
            let name = nested_name(levels);
            let mut req = full_request();
            req.requestor_name = Some(tlv(0xa4, &tlv(0x30, &name)));
            req.signature.as_mut().unwrap().certs = vec![tlv(0x30, &name)];
            req.requests[0].cert_id.hash_algorithm.parameters = Some(name.clone());
            match req.to_der() {
                Ok(der) => {
                    assert_eq!(OcspRequest::parse(&der).unwrap(), req, "{levels}");
                    wrote += 1;
                }
                Err(_) => refused += 1,
            }
            let mut resp = full_response();
            let Some(ResponseBytes::Basic(b)) = &mut resp.bytes else { panic!() };
            b.data.responder_id = ResponderId::ByName(tlv(0x30, &name));
            b.data.responses[0].cert_id.hash_algorithm.parameters = Some(name.clone());
            b.certs = vec![tlv(0x30, &name)];
            b.signature_algorithm.parameters = Some(name.clone());
            if let Ok(der) = resp.to_der() {
                assert_eq!(OcspResponse::parse(&der).unwrap(), resp, "{levels}");
            }
        }
        assert!(wrote > 0 && refused > 0, "{wrote} {refused}");
        // And each place on its own, read from bytes made by hand: what
        // reads also writes.
        for levels in 0..asn1::MAX_DEPTH + 4 {
            let name = nested_name(levels);
            let der = request_with(&tlv(0xa1, &tlv(0xa4, &tlv(0x30, &name))), &[]);
            if let Ok(r) = OcspRequest::parse(&der) {
                assert_eq!(r.to_der().unwrap(), der, "{levels}");
            }
        }
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn below(&mut self, n: usize) -> usize {
            self.next() as usize % n.max(1)
        }
    }

    /// Reads `b` every way this module can, and checks what reads also
    /// writes and reads back the same.
    fn exercise(b: &[u8]) -> usize {
        let mut ok = 0;
        if let Ok(r) = OcspRequest::parse(b) {
            let der = r.to_der().unwrap();
            assert_eq!(OcspRequest::parse(&der).unwrap(), r);
            assert_eq!(OcspRequest::from_get_path(&r.to_get_path().unwrap()).unwrap(), r);
            ok += 1;
        }
        if let Ok(r) = OcspResponse::parse(b) {
            let der = r.to_der().unwrap();
            assert_eq!(OcspResponse::parse(&der).unwrap(), r);
            ok += 1;
        }
        if let Ok(r) = BasicResponse::parse(b) {
            let der = r.to_der().unwrap();
            assert_eq!(BasicResponse::parse(&der).unwrap(), r);
            ok += 1;
        }
        let _ = decode_get_path(&String::from_utf8_lossy(b));
        // Whole and byte by byte, the decoder finds the same messages.
        let mut whole = Decoder::new();
        let fed = b;
        assert_eq!(whole.feed(fed), fed.len());
        let mut all = Vec::new();
        while let Some(Ok(m)) = whole.next_message() {
            all.push(m);
        }
        let mut bytewise = Decoder::new();
        let mut again = Vec::new();
        for byte in b {
            let fed = std::slice::from_ref(byte);
            assert_eq!(bytewise.feed(fed), fed.len());
            while let Some(Ok(m)) = bytewise.next_message() {
                again.push(m);
            }
        }
        assert_eq!(all, again);
        ok
    }

    #[test]
    fn lcg_fuzz() {
        let seeds = [
            minimal_request_der(),
            full_request().to_der().unwrap(),
            full_response().to_der().unwrap(),
            full_response().basic_response().unwrap().to_der().unwrap(),
            OcspResponse::error(ResponseStatus::TryLater).to_der().unwrap(),
        ];
        let mut rng = Lcg(0x6f63_7370);
        let mut parsed = 0;
        for round in 0..6000 {
            let seed = &seeds[round % seeds.len()];
            let mut b = seed.clone();
            match rng.below(4) {
                0 => {
                    for _ in 0..1 + rng.below(4) {
                        let i = rng.below(b.len());
                        b[i] = rng.next() as u8;
                    }
                }
                1 => {
                    let i = rng.below(b.len());
                    b[i] ^= 1 << rng.below(8);
                }
                2 => {
                    let n = rng.below(b.len());
                    b.truncate(n);
                    b.extend((0..rng.below(8)).map(|_| rng.next() as u8));
                }
                _ => b = (0..rng.below(200)).map(|_| rng.next() as u8).collect(),
            }
            parsed += exercise(&b);
        }
        for s in &seeds {
            assert!(exercise(s) > 0);
        }
        assert!(parsed > 100, "only {parsed} mutated inputs parsed");
    }

    #[test]
    fn module_example() {
        let id = cert_id(&[0x12, 0x34]);
        let mut request = OcspRequest::new(vec![Request { cert_id: id, extensions: vec![] }]);
        request.extensions.push(Extension::nonce(b"0123456789abcdef").unwrap());
        let body = request.to_der().unwrap();
        let request = OcspRequest::parse(&body).unwrap();
        let data = ResponseData {
            version: 0,
            responder_id: ResponderId::ByKey(vec![0x22; 20]),
            produced_at: "20261005120000Z".to_string(),
            responses: request
                .requests
                .iter()
                .map(|r| SingleResponse {
                    cert_id: r.cert_id.clone(),
                    status: CertStatus::Good,
                    this_update: "20261005120000Z".to_string(),
                    next_update: None,
                    extensions: vec![],
                })
                .collect(),
            extensions: request.nonce().and_then(|n| Extension::nonce(n).ok()).into_iter().collect(),
        };
        let basic = BasicResponse {
            data,
            signature_algorithm: AlgorithmIdentifier::sha1(),
            signature: vec![0; 64],
            certs: vec![],
        };
        let reply = OcspResponse::basic(basic).to_der().unwrap();
        let response = OcspResponse::parse(&reply).unwrap();
        let basic = response.basic_response().unwrap();
        assert_eq!(basic.data.nonce(), Some(&b"0123456789abcdef"[..]));
        assert_eq!(basic.data.responses[0].status, CertStatus::Good);
        assert_eq!(basic.data.responses[0].cert_id.serial_number, [0x12, 0x34]);
    }
}
