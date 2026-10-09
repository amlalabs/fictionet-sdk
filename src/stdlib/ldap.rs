//! LDAP: reading and writing messages, search filters and distinguished
//! names, with no I/O.
//!
//! `Message` implements `Wire` and supports `codec::Frames<Message>` stream
//! decoding. These are wire messages only, with no bind session, directory
//! `Service`, authentication, or TLS transport.
//!
//! LDAP is how most directories are read and changed: Active Directory,
//! OpenLDAP and the address books behind mail servers. A client binds (logs
//! in), then searches, adds, modifies, renames and deletes entries, each
//! named by a distinguished name (DN) such as `uid=jdoe,dc=example,dc=com`.
//! Every message is one BER-encoded `LDAPMessage` over TCP, usually on port
//! 389 (636 inside TLS). Connectionless LDAP (CLDAP), as Active Directory
//! uses it, sends the same messages in UDP datagrams on port 389. This
//! module follows RFC 4511 (the protocol), RFC 4515 (search filters as
//! text) and RFC 4514 (DNs as text).
//!
//! Nothing here reads a socket. A world that plays a directory server pushes
//! the bytes it reads from a [`tcp`](fictionet::stdlib::tcp) connection to a
//! [`Stream<codec::Frames<Message>>`](fictionet::stdlib::codec::Stream), gets [`Message`]s back, matches on each one's [`Op`], and
//! writes the reply's bytes with [`Message::write`]. A CLDAP server reads
//! each datagram with [`Message::parse`], and a client reads a reply that
//! may hold several messages with [`Message::parse_datagram`]. Which entries
//! exist, and whether a password is right, is up to world code.
//!
//! Every reader checks lengths, tags, ranges and nesting, because the agent
//! can send any bytes it likes. A message is at most [`MAX_MESSAGE`] bytes,
//! filters nest at most [`MAX_FILTER_DEPTH`] deep, and filter and DN text is
//! at most [`MAX_TEXT`] bytes. LDAP forbids indefinite lengths and
//! constructed strings, so they are refused. Unknown fields at the end of a
//! SEQUENCE are skipped, as RFC 4511 section 4 asks. RFC 4511 says a server that
//! cannot read a message sends a notice of disconnection and closes the
//! connection, so a [`Stream<codec::Frames<Message>>`](fictionet::stdlib::codec::Stream) stops at the first [`Error`]. The writers
//! check what they are given and return an error instead of bytes a reader
//! would refuse.
//!
//! ```
//! use fictionet::stdlib::codec::Frames;
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::ldap::{Authentication, BindResponse, Dn, Filter, LdapResult, Op, ResultCode};
//!
//! let mut decoder = Stream::new(Frames::<fictionet::stdlib::ldap::Message>::new());
//! // An anonymous simple bind: message 1, LDAP version 3, no name, no password.
//! let bind = [0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00];
//! assert_eq!(decoder.push(&bind), bind.len());
//! let request = decoder.next().unwrap().unwrap();
//! let Op::BindRequest(bind) = &request.op else { panic!("not a bind") };
//! assert_eq!((bind.version, bind.name.as_str()), (3, ""));
//! assert_eq!(bind.auth, Authentication::Simple(Vec::new()));
//!
//! let ok = BindResponse { result: LdapResult::new(ResultCode::SUCCESS), server_sasl_creds: None };
//! let reply = request.reply(Op::BindResponse(ok));
//! assert_eq!(
//!     reply.to_bytes().unwrap(),
//!     [0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00]
//! );
//!
//! // Search filters and DNs, read from and written as text.
//! let filter = Filter::parse_text("(&(objectClass=person)(cn=J*n))").unwrap();
//! assert_eq!(filter.to_text().unwrap(), "(&(objectClass=person)(cn=J*n))");
//! let dn = Dn::parse("uid=jdoe,dc=example,dc=com").unwrap();
//! assert_eq!(dn.0.len(), 3);
//! assert_eq!(dn.to_text().unwrap(), "uid=jdoe,dc=example,dc=com");
//! ```

use fictionet::stdlib::asn1::{self, Class, Element, Length, Reader, Rules, Tag};
#[cfg(test)]
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::codec::ascii::{hex_lower, hex_value as hex_digit};
use std::fmt;

/// The port LDAP servers listen on, over TCP, and CLDAP over UDP.
pub const PORT: u16 = 389;
/// The port for LDAP inside TLS from the first byte (LDAPS).
pub const TLS_PORT: u16 = 636;
/// The largest message ID, size limit and time limit: `maxInt` in RFC 4511.
pub const MAX_INT: u32 = 2_147_483_647;
/// The longest message, in bytes, a reader accepts and a writer writes.
/// [`codec::Frames<Message>::with_limit`](fictionet::stdlib::codec::Frames::with_limit) can set a lower limit.
pub const MAX_MESSAGE: usize = asn1::MAX_INPUT;
/// How deep filters may nest. A filter with no `&`, `|` or `!` has depth 1.
pub const MAX_FILTER_DEPTH: usize = 16;
/// The longest filter or DN text, in bytes, a reader accepts and a writer
/// writes.
pub const MAX_TEXT: usize = 65_536;
/// The name of the unsolicited notice a server sends before it closes a
/// connection it cannot go on with (RFC 4511 section 4.4.1).
pub const NOTICE_OF_DISCONNECTION: &str = "1.3.6.1.4.1.1466.20036";
/// The name of the extended operation that starts TLS on the connection
/// (RFC 4511 section 4.14).
pub const START_TLS: &str = "1.3.6.1.4.1.1466.20037";

/// Why bytes or text are not LDAP, or why a value cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes are not BER, or not the BER LDAP allows: a wrong tag, a
    /// missing or extra field, an indefinite length or a constructed
    /// string.
    Ber(asn1::Error),
    /// A message is longer than the limit. It holds the length the message
    /// has, or for a writer, the length it reached.
    TooLarge(usize),
    /// The protocol operation's tag names no LDAP operation.
    Operation(Tag),
    /// A number is outside its range. It names the field.
    Range(&'static str),
    /// A string LDAP holds as UTF-8 is not UTF-8.
    Utf8,
    /// A filter breaks a rule of RFC 4511: it nests deeper than
    /// [`MAX_FILTER_DEPTH`], a substring filter has no parts or has them
    /// out of order, or an extensible match has neither a type nor a rule.
    Filter(&'static str),
    /// Filter or DN text is malformed at this byte offset.
    Syntax(usize),
    /// Filter or DN text is longer than [`MAX_TEXT`].
    TextTooLong,
    /// A value has no form a reader would accept, such as an attribute
    /// name with spaces in filter text. The reason says what is wrong.
    Unwritable(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Ber(_) => f.write_str("malformed BER"),
            Error::TooLarge(n) => write!(f, "message of {n} bytes is over the limit"),
            Error::Operation(t) => write!(f, "{t} is not an LDAP operation"),
            Error::Range(what) => write!(f, "{what} out of range"),
            Error::Utf8 => f.write_str("string is not UTF-8"),
            Error::Filter(why) => write!(f, "bad filter: {why}"),
            Error::Syntax(at) => write!(f, "malformed text at byte {at}"),
            Error::TextTooLong => write!(f, "text longer than {MAX_TEXT} bytes"),
            Error::Unwritable(why) => write!(f, "cannot write: {why}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Ber(e) => Some(e),
            _ => None,
        }
    }
}

impl From<asn1::Error> for Error {
    fn from(e: asn1::Error) -> Error {
        Error::Ber(e)
    }
}

/// An `LDAPMessage`: one request or response, with the ID that pairs them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Chosen by the client, at most [`MAX_INT`], and copied into every
    /// response to the request. Unsolicited notices use 0.
    pub id: u32,
    /// What the message asks or answers.
    pub op: Op,
    /// Controls that change how the operation is done. None is the usual
    /// case.
    pub controls: Vec<Control>,
}

/// A protocol operation: the body of a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// Log in, or change who the connection acts as.
    BindRequest(BindRequest),
    /// The answer to a bind.
    BindResponse(BindResponse),
    /// The client is closing the connection. It has no answer.
    UnbindRequest,
    /// Find entries.
    SearchRequest(SearchRequest),
    /// One entry a search found. A search has any number of these.
    SearchResultEntry(SearchResultEntry),
    /// The end of a search's results.
    SearchResultDone(LdapResult),
    /// URIs of other servers that may hold more results. There must be at
    /// least one.
    SearchResultReference(Vec<String>),
    /// Change an entry's attributes.
    ModifyRequest(ModifyRequest),
    /// The answer to a modify.
    ModifyResponse(LdapResult),
    /// Add an entry.
    AddRequest(AddRequest),
    /// The answer to an add.
    AddResponse(LdapResult),
    /// Delete the entry with this DN.
    DelRequest(String),
    /// The answer to a delete.
    DelResponse(LdapResult),
    /// Rename or move an entry.
    ModifyDnRequest(ModifyDnRequest),
    /// The answer to a rename.
    ModifyDnResponse(LdapResult),
    /// Ask whether an entry's attribute holds a value.
    CompareRequest(CompareRequest),
    /// The answer to a compare: [`ResultCode::COMPARE_TRUE`] or
    /// [`ResultCode::COMPARE_FALSE`] on success.
    CompareResponse(LdapResult),
    /// Stop working on the request with this message ID. It has no answer.
    AbandonRequest(u32),
    /// An operation named by an OID, such as [`START_TLS`].
    ExtendedRequest(ExtendedRequest),
    /// The answer to an extended operation, or an unsolicited notice.
    ExtendedResponse(ExtendedResponse),
    /// A response that comes before an operation's last one.
    IntermediateResponse(IntermediateResponse),
}

/// A control: an OID, whether the server must act on it, and a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Control {
    /// The control's OID, such as `1.2.840.113556.1.4.319` for paged
    /// results.
    pub oid: String,
    /// Whether a server that does not know the control must refuse the
    /// operation, with [`ResultCode::UNAVAILABLE_CRITICAL_EXTENSION`].
    pub critical: bool,
    /// The control's value, whose form the control's specification sets.
    pub value: Option<Vec<u8>>,
}

/// The result most responses carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LdapResult {
    /// Whether the operation worked, and if not, why.
    pub code: ResultCode,
    /// For some failures, the closest entry above the name that does exist.
    /// Usually empty.
    pub matched_dn: String,
    /// Text for a person to read. Usually empty on success.
    pub message: String,
    /// With [`ResultCode::REFERRAL`], URIs of servers to try instead. Empty
    /// means none.
    pub referral: Vec<String>,
}

impl LdapResult {
    /// A result with `code`, no matched DN, no message and no referral.
    pub fn new(code: ResultCode) -> LdapResult {
        LdapResult {
            code,
            matched_dn: String::new(),
            message: String::new(),
            referral: Vec::new(),
        }
    }
}

/// A result code (RFC 4511 appendix A). Any `u32` can be held. The
/// constants are the codes RFC 4511 names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResultCode(
    /// The numeric LDAP result code.
    pub u32,
);
impl ResultCode {
    /// success (0): the operation completed successfully.
    pub const SUCCESS: ResultCode = ResultCode(0);
    /// operationsError (1): the operation is out of sequence with other operations.
    pub const OPERATIONS_ERROR: ResultCode = ResultCode(1);
    /// protocolError (2): the request violates the protocol or asks for an unsupported operation.
    pub const PROTOCOL_ERROR: ResultCode = ResultCode(2);
    /// timeLimitExceeded (3): the operation exceeded the client's time limit.
    pub const TIME_LIMIT_EXCEEDED: ResultCode = ResultCode(3);
    /// sizeLimitExceeded (4): the operation exceeded the client's result size limit.
    pub const SIZE_LIMIT_EXCEEDED: ResultCode = ResultCode(4);
    /// compareFalse (5): the comparison completed with a false or undefined assertion.
    pub const COMPARE_FALSE: ResultCode = ResultCode(5);
    /// compareTrue (6): the comparison completed with a true assertion.
    pub const COMPARE_TRUE: ResultCode = ResultCode(6);
    /// authMethodNotSupported (7): the server does not support the authentication method.
    pub const AUTH_METHOD_NOT_SUPPORTED: ResultCode = ResultCode(7);
    /// strongerAuthRequired (8): the operation requires stronger authentication.
    pub const STRONGER_AUTH_REQUIRED: ResultCode = ResultCode(8);
    /// referral (10): the client must follow a referral to complete the operation.
    pub const REFERRAL: ResultCode = ResultCode(10);
    /// adminLimitExceeded (11): the operation exceeded a limit set by the administrator.
    pub const ADMIN_LIMIT_EXCEEDED: ResultCode = ResultCode(11);
    /// unavailableCriticalExtension (12): the server cannot perform a critical control.
    pub const UNAVAILABLE_CRITICAL_EXTENSION: ResultCode = ResultCode(12);
    /// confidentialityRequired (13): the operation needs protection against disclosure.
    pub const CONFIDENTIALITY_REQUIRED: ResultCode = ResultCode(13);
    /// saslBindInProgress (14): the SASL bind needs another exchange.
    pub const SASL_BIND_IN_PROGRESS: ResultCode = ResultCode(14);
    /// noSuchAttribute (16): the named entry lacks the requested attribute or value.
    pub const NO_SUCH_ATTRIBUTE: ResultCode = ResultCode(16);
    /// undefinedAttributeType (17): the server does not recognize the attribute type.
    pub const UNDEFINED_ATTRIBUTE_TYPE: ResultCode = ResultCode(17);
    /// inappropriateMatching (18): the matching rule does not apply to the attribute.
    pub const INAPPROPRIATE_MATCHING: ResultCode = ResultCode(18);
    /// constraintViolation (19): an attribute value violates a data model constraint.
    pub const CONSTRAINT_VIOLATION: ResultCode = ResultCode(19);
    /// attributeOrValueExists (20): the attribute or value being added already exists.
    pub const ATTRIBUTE_OR_VALUE_EXISTS: ResultCode = ResultCode(20);
    /// invalidAttributeSyntax (21): a value does not follow its attribute's syntax.
    pub const INVALID_ATTRIBUTE_SYNTAX: ResultCode = ResultCode(21);
    /// noSuchObject (32): the named object is absent from the directory.
    pub const NO_SUCH_OBJECT: ResultCode = ResultCode(32);
    /// aliasProblem (33): an alias is invalid, such as one naming a missing object.
    pub const ALIAS_PROBLEM: ResultCode = ResultCode(33);
    /// invalidDNSyntax (34): a distinguished name or relative name has invalid syntax.
    pub const INVALID_DN_SYNTAX: ResultCode = ResultCode(34);
    /// aliasDereferencingProblem (36): the server cannot follow an alias.
    pub const ALIAS_DEREFERENCING_PROBLEM: ResultCode = ResultCode(36);
    /// inappropriateAuthentication (48): the bind requires credentials.
    pub const INAPPROPRIATE_AUTHENTICATION: ResultCode = ResultCode(48);
    /// invalidCredentials (49): the supplied authentication credentials are invalid.
    pub const INVALID_CREDENTIALS: ResultCode = ResultCode(49);
    /// insufficientAccessRights (50): the client lacks permission for the operation.
    pub const INSUFFICIENT_ACCESS_RIGHTS: ResultCode = ResultCode(50);
    /// busy (51): the server is too busy to handle the operation.
    pub const BUSY: ResultCode = ResultCode(51);
    /// unavailable (52): the server is stopping or a required subsystem is offline.
    pub const UNAVAILABLE: ResultCode = ResultCode(52);
    /// unwillingToPerform (53): the server refuses to perform the operation.
    pub const UNWILLING_TO_PERFORM: ResultCode = ResultCode(53);
    /// loopDetect (54): the server found an internal loop while processing the operation.
    pub const LOOP_DETECT: ResultCode = ResultCode(54);
    /// namingViolation (64): the entry's name violates naming rules.
    pub const NAMING_VIOLATION: ResultCode = ResultCode(64);
    /// objectClassViolation (65): the entry violates its object class rules.
    pub const OBJECT_CLASS_VIOLATION: ResultCode = ResultCode(65);
    /// notAllowedOnNonLeaf (66): the operation is not allowed on an entry with children.
    pub const NOT_ALLOWED_ON_NON_LEAF: ResultCode = ResultCode(66);
    /// notAllowedOnRDN (67): the operation would remove a value used in the entry's relative name.
    pub const NOT_ALLOWED_ON_RDN: ResultCode = ResultCode(67);
    /// entryAlreadyExists (68): an entry already occupies the target name.
    pub const ENTRY_ALREADY_EXISTS: ResultCode = ResultCode(68);
    /// objectClassModsProhibited (69): the requested object class change is forbidden.
    pub const OBJECT_CLASS_MODS_PROHIBITED: ResultCode = ResultCode(69);
    /// affectsMultipleDSAs (71): the operation would require changes on multiple servers.
    pub const AFFECTS_MULTIPLE_DSAS: ResultCode = ResultCode(71);
    /// other (80): the server encountered an internal error.
    pub const OTHER: ResultCode = ResultCode(80);
}

impl ResultCode {
    /// The name RFC 4511 gives the code, such as `noSuchObject`, or `None`
    /// for a code it does not name.
    pub fn name(self) -> Option<&'static str> {
        Some(match self.0 {
            0 => "success",
            1 => "operationsError",
            2 => "protocolError",
            3 => "timeLimitExceeded",
            4 => "sizeLimitExceeded",
            5 => "compareFalse",
            6 => "compareTrue",
            7 => "authMethodNotSupported",
            8 => "strongerAuthRequired",
            10 => "referral",
            11 => "adminLimitExceeded",
            12 => "unavailableCriticalExtension",
            13 => "confidentialityRequired",
            14 => "saslBindInProgress",
            16 => "noSuchAttribute",
            17 => "undefinedAttributeType",
            18 => "inappropriateMatching",
            19 => "constraintViolation",
            20 => "attributeOrValueExists",
            21 => "invalidAttributeSyntax",
            32 => "noSuchObject",
            33 => "aliasProblem",
            34 => "invalidDNSyntax",
            36 => "aliasDereferencingProblem",
            48 => "inappropriateAuthentication",
            49 => "invalidCredentials",
            50 => "insufficientAccessRights",
            51 => "busy",
            52 => "unavailable",
            53 => "unwillingToPerform",
            54 => "loopDetect",
            64 => "namingViolation",
            65 => "objectClassViolation",
            66 => "notAllowedOnNonLeaf",
            67 => "notAllowedOnRDN",
            68 => "entryAlreadyExists",
            69 => "objectClassModsProhibited",
            71 => "affectsMultipleDSAs",
            80 => "other",
            _ => return None,
        })
    }
}

impl fmt::Display for ResultCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(n) => f.write_str(n),
            None => write!(f, "result code {}", self.0),
        }
    }
}

/// A bind request: who the client says it is, and how it proves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindRequest {
    /// The protocol version, 1 to 127. Clients today send 3.
    pub version: u8,
    /// The DN to bind as. Empty for an anonymous bind, and often empty for
    /// SASL.
    pub name: String,
    /// The proof.
    pub auth: Authentication,
}

/// How a bind proves who the client is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authentication {
    /// A password, sent as it is. Empty means an anonymous or
    /// unauthenticated bind.
    Simple(Vec<u8>),
    /// A SASL mechanism, such as `EXTERNAL` or `GSSAPI`, and its data.
    Sasl {
        /// The mechanism's name.
        mechanism: String,
        /// The mechanism's data, if this step has any.
        credentials: Option<Vec<u8>>,
    },
    /// Another choice, by its context tag number (not 0 or 3), with its
    /// contents unread. A server answers it with
    /// [`ResultCode::AUTH_METHOD_NOT_SUPPORTED`]. It is written in the form
    /// it came in.
    Other {
        /// The context tag number.
        number: u32,
        /// Whether the tag is in constructed form.
        constructed: bool,
        /// The contents, as they came.
        contents: Vec<u8>,
    },
}

/// The answer to a bind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindResponse {
    /// Whether the bind worked.
    pub result: LdapResult,
    /// SASL data for the client's next step, if the mechanism has any.
    pub server_sasl_creds: Option<Vec<u8>>,
}

/// Where a search looks below its base.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    /// Only the base entry.
    Base,
    /// The base entry's children, not the base itself.
    OneLevel,
    /// The base entry and everything below it.
    Subtree,
    /// Another value, from an extension. 0 to 2 are the named values, so
    /// `Other` with one of them is not written.
    Other(u32),
}

impl Scope {
    /// The scope's number on the wire.
    pub fn code(self) -> u32 {
        match self {
            Scope::Base => 0,
            Scope::OneLevel => 1,
            Scope::Subtree => 2,
            Scope::Other(n) => n,
        }
    }

    /// The scope for number `n`.
    pub fn from_code(n: u32) -> Scope {
        match n {
            0 => Scope::Base,
            1 => Scope::OneLevel,
            2 => Scope::Subtree,
            n => Scope::Other(n),
        }
    }
}

/// When a search follows alias entries to what they name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DerefAliases {
    /// Never.
    Never,
    /// Below the base, not at it.
    InSearching,
    /// At the base, not below it.
    FindingBase,
    /// Always.
    Always,
}

impl DerefAliases {
    /// The value's number on the wire.
    pub fn code(self) -> u32 {
        match self {
            DerefAliases::Never => 0,
            DerefAliases::InSearching => 1,
            DerefAliases::FindingBase => 2,
            DerefAliases::Always => 3,
        }
    }

    /// The value for number `n`, which must be 0 to 3.
    pub fn from_code(n: u32) -> Option<DerefAliases> {
        Some(match n {
            0 => DerefAliases::Never,
            1 => DerefAliases::InSearching,
            2 => DerefAliases::FindingBase,
            3 => DerefAliases::Always,
            _ => return None,
        })
    }
}

/// A search request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchRequest {
    /// The DN the search starts from.
    pub base: String,
    /// Where it looks below the base.
    pub scope: Scope,
    /// When it follows aliases.
    pub deref: DerefAliases,
    /// The most entries to return, at most [`MAX_INT`]. 0 means no limit.
    pub size_limit: u32,
    /// The most seconds to spend, at most [`MAX_INT`]. 0 means no limit.
    pub time_limit: u32,
    /// Whether to return attribute names without their values.
    pub types_only: bool,
    /// Which entries match.
    pub filter: Filter,
    /// Which attributes to return. Empty means all user attributes; `*`
    /// and `1.1` have the meanings RFC 4511 gives them.
    pub attributes: Vec<String>,
}

/// An attribute: a description such as `cn` or `userCertificate;binary`
/// and its values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribute {
    /// The attribute description.
    pub name: String,
    /// The values, in the order they came.
    pub values: Vec<Vec<u8>>,
}

/// One entry a search found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchResultEntry {
    /// The entry's DN.
    pub dn: String,
    /// The attributes asked for.
    pub attributes: Vec<Attribute>,
}

/// What a modify does to one attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ModifyOperation {
    /// Add the values, creating the attribute if needed.
    Add,
    /// Delete the values, or the whole attribute if none are given.
    Delete,
    /// Replace every value with these, or delete the attribute if none are
    /// given.
    Replace,
    /// Another value, from an extension, such as 3 for increment (RFC
    /// 4525). 0 to 2 are the named values, so `Other` with one of them is
    /// not written.
    Other(u32),
}

impl ModifyOperation {
    /// The operation's number on the wire.
    pub fn code(self) -> u32 {
        match self {
            ModifyOperation::Add => 0,
            ModifyOperation::Delete => 1,
            ModifyOperation::Replace => 2,
            ModifyOperation::Other(n) => n,
        }
    }

    /// The operation for number `n`.
    pub fn from_code(n: u32) -> ModifyOperation {
        match n {
            0 => ModifyOperation::Add,
            1 => ModifyOperation::Delete,
            2 => ModifyOperation::Replace,
            n => ModifyOperation::Other(n),
        }
    }
}

/// One change in a modify request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// What to do.
    pub op: ModifyOperation,
    /// The attribute and values it is done with.
    pub attribute: Attribute,
}

/// A modify request: changes to one entry, done in order, all or none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModifyRequest {
    /// The entry's DN.
    pub dn: String,
    /// The changes.
    pub changes: Vec<Change>,
}

/// An add request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddRequest {
    /// The new entry's DN.
    pub dn: String,
    /// Its attributes. Each must have at least one value.
    pub attributes: Vec<Attribute>,
}

/// A request to rename an entry, or move it under another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModifyDnRequest {
    /// The entry's DN.
    pub dn: String,
    /// Its new relative DN, such as `cn=New Name`.
    pub new_rdn: String,
    /// Whether to delete the old RDN's values from the entry.
    pub delete_old_rdn: bool,
    /// The DN of its new parent, if it moves.
    pub new_superior: Option<String>,
}

/// A compare request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompareRequest {
    /// The entry's DN.
    pub dn: String,
    /// The attribute description.
    pub attribute: String,
    /// The value to look for.
    pub value: Vec<u8>,
}

/// An extended request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtendedRequest {
    /// The operation's OID.
    pub name: String,
    /// Its value, whose form the operation sets.
    pub value: Option<Vec<u8>>,
}

/// An extended response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtendedResponse {
    /// Whether the operation worked.
    pub result: LdapResult,
    /// The response's OID, if it has one.
    pub name: Option<String>,
    /// Its value, if it has one.
    pub value: Option<Vec<u8>>,
}

/// An intermediate response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntermediateResponse {
    /// The response's OID, if it has one.
    pub name: Option<String>,
    /// Its value, if it has one.
    pub value: Option<Vec<u8>>,
}

/// A search filter (RFC 4511 section 4.5.1.7). Values are bytes; names are
/// attribute descriptions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Filter {
    /// Every filter matches. Empty is true (RFC 4526).
    And(Vec<Filter>),
    /// Some filter matches. Empty is false (RFC 4526).
    Or(Vec<Filter>),
    /// The filter does not match.
    Not(Box<Filter>),
    /// `(attribute=value)`.
    Equal {
        /// The attribute description.
        attribute: String,
        /// The value.
        value: Vec<u8>,
    },
    /// `(attribute=initial*any*any*last)`. At least one part must be there.
    Substrings {
        /// The attribute description.
        attribute: String,
        /// What the value starts with.
        initial: Option<Vec<u8>>,
        /// What it holds, in order, between the start and the end.
        any: Vec<Vec<u8>>,
        /// What it ends with: the `final` part in RFC 4511.
        last: Option<Vec<u8>>,
    },
    /// `(attribute>=value)`.
    GreaterOrEqual {
        /// The attribute description.
        attribute: String,
        /// The value.
        value: Vec<u8>,
    },
    /// `(attribute<=value)`.
    LessOrEqual {
        /// The attribute description.
        attribute: String,
        /// The value.
        value: Vec<u8>,
    },
    /// `(attribute=*)`: the entry has the attribute.
    Present(String),
    /// `(attribute~=value)`.
    Approx {
        /// The attribute description.
        attribute: String,
        /// The value.
        value: Vec<u8>,
    },
    /// `(attribute:dn:rule:=value)`. A type, a rule, or both must be there.
    Extensible {
        /// The matching rule's name or OID.
        rule: Option<String>,
        /// The attribute description.
        attribute: Option<String>,
        /// The value.
        value: Vec<u8>,
        /// Whether the attributes of the entry's DN count too.
        dn_attributes: bool,
    },
    /// A choice from an extension, by its context tag number (above 9),
    /// with its contents unread. A server takes it as Undefined. It is
    /// written in the form it came in, and has no text form.
    Other {
        /// The context tag number.
        number: u32,
        /// Whether the tag is in constructed form.
        constructed: bool,
        /// The contents, as they came.
        contents: Vec<u8>,
    },
}

/// A distinguished name: its RDNs, the entry's own first, as RFC 4514 text
/// writes them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dn(
    /// Relative distinguished names, in text order.
    pub Vec<Rdn>,
);

/// A relative distinguished name: one or more attribute values, joined by
/// `+` in text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rdn(
    /// The attribute values in this relative name.
    pub Vec<Ava>,
);

/// One attribute type and value in an RDN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ava {
    /// The attribute type: a name such as `cn` or a numeric OID.
    pub attribute: String,
    /// The value.
    pub value: AttributeValue,
}

/// An RDN value, as RFC 4514 text holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttributeValue {
    /// A string value, with escapes undone.
    Text(String),
    /// The BER encoding of the value, written `#` and hex digits. It is
    /// not read further.
    Ber(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Reading BER.

/// The next element, which must have a definite length.
fn next<'a>(r: &mut Reader<'a>) -> Result<Element<'a>, Error> {
    let e = r.read()?;
    if e.is_indefinite() {
        return Err(Error::Ber(asn1::Error::Indefinite));
    }
    Ok(e)
}

/// The next element, which must have exactly `tag`.
fn expect<'a>(r: &mut Reader<'a>, tag: Tag) -> Result<Element<'a>, Error> {
    let e = next(r)?;
    if e.tag() != tag {
        return Err(Error::Ber(asn1::Error::Unexpected {
            expected: tag,
            found: e.tag(),
        }));
    }
    Ok(e)
}

/// Ends a SEQUENCE. RFC 4511 section 4 has readers ignore trailing
/// components whose tags they do not recognize, so each element left in
/// `r` is skipped, unless `known` says its tag is one of the sequence's
/// own fields.
fn end(r: &mut Reader<'_>, known: impl Fn(Tag) -> bool) -> Result<(), Error> {
    while !r.is_empty() {
        if known(next(r)?.tag()) {
            return Err(Error::Ber(asn1::Error::Trailing));
        }
    }
    Ok(())
}

/// Whether `t` has one of `tags`' class and number.
fn one_of(tags: &[Tag]) -> impl Fn(Tag) -> bool + '_ {
    move |t| tags.iter().any(|k| k.same_type(t))
}

/// The tags an LDAPResult's fields have.
const RESULT_TAGS: &[Tag] = &[Tag::ENUMERATED, Tag::OCTET_STRING, Tag::context(3)];

/// The next element if it has exactly `tag`, for an OPTIONAL field.
fn optional<'a>(r: &mut Reader<'a>, tag: Tag) -> Result<Option<Element<'a>>, Error> {
    if r.is_empty() || r.peek()?.tag() != tag {
        return Ok(None);
    }
    expect(r, tag).map(Some)
}

/// A primitive element's contents.
fn octets(e: &Element<'_>) -> Result<Vec<u8>, Error> {
    if e.tag().constructed {
        return Err(Error::Ber(asn1::Error::Constructed));
    }
    Ok(e.contents().to_vec())
}

/// A primitive element's contents as UTF-8.
fn text(e: &Element<'_>) -> Result<String, Error> {
    String::from_utf8(octets(e)?).map_err(|_| Error::Utf8)
}

/// An INTEGER or ENUMERATED in `min..=max`.
fn number(e: &Element<'_>, what: &'static str, min: u32, max: u32) -> Result<u32, Error> {
    let v = e.integer()?.to_i64().ok_or(Error::Range(what))?;
    if v < i64::from(min) || v > i64::from(max) {
        return Err(Error::Range(what));
    }
    Ok(v as u32)
}

fn read_string(r: &mut Reader<'_>) -> Result<String, Error> {
    text(&expect(r, Tag::OCTET_STRING)?)
}

fn read_octets(r: &mut Reader<'_>) -> Result<Vec<u8>, Error> {
    octets(&expect(r, Tag::OCTET_STRING)?)
}

/// A `SEQUENCE SIZE (1..MAX) OF URI`: a referral or a search reference.
fn read_uris(r: Reader<'_>) -> Result<Vec<String>, Error> {
    if r.is_empty() {
        return Err(Error::Ber(asn1::Error::Empty));
    }
    read_strings(r)
}

fn read_bool(r: &mut Reader<'_>) -> Result<bool, Error> {
    Ok(expect(r, Tag::BOOLEAN)?.boolean()?)
}

/// Every element left in `r`, each an OCTET STRING of UTF-8.
fn read_strings(mut r: Reader<'_>) -> Result<Vec<String>, Error> {
    let mut out = Vec::new();
    while !r.is_empty() {
        out.push(read_string(&mut r)?);
    }
    Ok(out)
}

/// An optional primitive `[number]` as bytes.
fn optional_octets(r: &mut Reader<'_>, number: u32) -> Result<Option<Vec<u8>>, Error> {
    optional(r, Tag::context(number))?
        .map(|e| octets(&e))
        .transpose()
}

/// An optional primitive `[number]` as UTF-8.
fn optional_text(r: &mut Reader<'_>, number: u32) -> Result<Option<String>, Error> {
    optional(r, Tag::context(number))?
        .map(|e| text(&e))
        .transpose()
}

fn read_result(r: &mut Reader<'_>) -> Result<LdapResult, Error> {
    let code = ResultCode(number(
        &expect(r, Tag::ENUMERATED)?,
        "resultCode",
        0,
        u32::MAX,
    )?);
    let matched_dn = read_string(r)?;
    let message = read_string(r)?;
    let referral = match optional(r, Tag::context(3).as_constructed())? {
        Some(e) => read_uris(e.reader()?)?,
        None => Vec::new(),
    };
    Ok(LdapResult {
        code,
        matched_dn,
        message,
        referral,
    })
}

/// A whole LDAPResult in a constructed element.
fn result_only(e: &Element<'_>) -> Result<LdapResult, Error> {
    let mut r = e.reader()?;
    let result = read_result(&mut r)?;
    end(&mut r, one_of(RESULT_TAGS))?;
    Ok(result)
}

/// A PartialAttribute, or with `nonempty` an Attribute, which must have a
/// value.
fn read_attribute(e: &Element<'_>, nonempty: bool) -> Result<Attribute, Error> {
    let mut r = e.reader()?;
    let name = read_string(&mut r)?;
    let mut set = expect(&mut r, Tag::SET)?.reader()?;
    end(&mut r, one_of(&[Tag::OCTET_STRING, Tag::SET]))?;
    if nonempty && set.is_empty() {
        return Err(Error::Ber(asn1::Error::Empty));
    }
    let mut values = Vec::new();
    while !set.is_empty() {
        values.push(read_octets(&mut set)?);
    }
    Ok(Attribute { name, values })
}

/// A SEQUENCE OF attributes, each with a value if `nonempty`.
fn read_attributes(r: &mut Reader<'_>, nonempty: bool) -> Result<Vec<Attribute>, Error> {
    let mut list = expect(r, Tag::SEQUENCE)?.reader()?;
    let mut out = Vec::new();
    while !list.is_empty() {
        out.push(read_attribute(
            &expect(&mut list, Tag::SEQUENCE)?,
            nonempty,
        )?);
    }
    Ok(out)
}

fn read_control(e: &Element<'_>) -> Result<Control, Error> {
    let mut r = e.reader()?;
    let oid = read_string(&mut r)?;
    let critical = match optional(&mut r, Tag::BOOLEAN)? {
        Some(b) => b.boolean()?,
        None => false,
    };
    let value = optional(&mut r, Tag::OCTET_STRING)?
        .map(|v| octets(&v))
        .transpose()?;
    end(&mut r, one_of(&[Tag::OCTET_STRING, Tag::BOOLEAN]))?;
    Ok(Control {
        oid,
        critical,
        value,
    })
}

fn unexpected(expected: Tag, found: Tag) -> Error {
    Error::Ber(asn1::Error::Unexpected { expected, found })
}

impl Message {
    fn decode(b: &[u8]) -> Result<Message, Error> {
        if b.len() > MAX_MESSAGE {
            return Err(Error::TooLarge(b.len()));
        }
        let mut top = Reader::new(b, Rules::Ber);
        let msg = expect(&mut top, Tag::SEQUENCE)?;
        top.finish()?;
        Message::read(&msg)
    }

    /// Reads a CLDAP datagram: one or more whole messages, back to back.
    /// A server answering a CLDAP search may send the entries and the
    /// search's end in one datagram, as Active Directory does. RFC 1798's
    /// older CLDAP messages, with their own envelope, are not read.
    pub fn parse_datagram(b: &[u8]) -> Result<Vec<Message>, Error> {
        if b.len() > MAX_MESSAGE {
            return Err(Error::TooLarge(b.len()));
        }
        let mut top = Reader::new(b, Rules::Ber);
        let mut out = Vec::new();
        loop {
            out.push(Message::read(&expect(&mut top, Tag::SEQUENCE)?)?);
            if top.is_empty() {
                return Ok(out);
            }
        }
    }

    /// Reads the message in a SEQUENCE element.
    fn read(msg: &Element<'_>) -> Result<Message, Error> {
        let mut r = msg.reader()?;
        let id = number(&expect(&mut r, Tag::INTEGER)?, "messageID", 0, MAX_INT)?;
        let op = Op::read(&next(&mut r)?)?;
        let mut controls = Vec::new();
        if let Some(c) = optional(&mut r, Tag::context(0).as_constructed())? {
            let mut list = c.reader()?;
            while !list.is_empty() {
                controls.push(read_control(&expect(&mut list, Tag::SEQUENCE)?)?);
            }
        }
        // A second operation is not an extension.
        end(&mut r, |t| {
            t.class == Class::Application || one_of(&[Tag::INTEGER, Tag::context(0)])(t)
        })?;
        Ok(Message { id, op, controls })
    }

    /// A message with this one's ID, carrying `op` and no controls: the
    /// reply to this request.
    pub fn reply(&self, op: Op) -> Message {
        Message {
            id: self.id,
            op,
            controls: Vec::new(),
        }
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.id > MAX_INT {
            return Err(Error::Range("messageID"));
        }
        let mut w = W::default();
        w.nest(Tag::SEQUENCE, |w| {
            w.uint(Tag::INTEGER, self.id)?;
            self.op.write(w)?;
            if !self.controls.is_empty() {
                w.nest(Tag::context(0), |w| {
                    for c in &self.controls {
                        w.nest(Tag::SEQUENCE, |w| {
                            w.octets(c.oid.as_bytes())?;
                            if c.critical {
                                w.boolean(Tag::BOOLEAN, true)?;
                            }
                            if let Some(v) = &c.value {
                                w.octets(v)?;
                            }
                            Ok(())
                        })?;
                    }
                    Ok(())
                })?;
            }
            Ok(())
        })?;
        Ok(w.out)
    }
}

impl Op {
    fn read(e: &Element<'_>) -> Result<Op, Error> {
        let t = e.tag();
        if t.class != Class::Application {
            return Err(Error::Operation(t));
        }
        Ok(match (t.number, t.constructed) {
            (0, true) => {
                let mut r = e.reader()?;
                let version = number(&expect(&mut r, Tag::INTEGER)?, "version", 1, 127)? as u8;
                let name = read_string(&mut r)?;
                let a = next(&mut r)?;
                // Context tags 0 to 3 are authentication choices RFC 4511
                // names or reserves.
                end(&mut r, |t| {
                    (t.class == Class::ContextSpecific && t.number <= 3)
                        || one_of(&[Tag::INTEGER, Tag::OCTET_STRING])(t)
                })?;
                let at = a.tag();
                let auth = match (at.class, at.number, at.constructed) {
                    (Class::ContextSpecific, 0, false) => Authentication::Simple(octets(&a)?),
                    (Class::ContextSpecific, 3, true) => {
                        let mut s = a.reader()?;
                        let mechanism = read_string(&mut s)?;
                        let credentials = optional(&mut s, Tag::OCTET_STRING)?
                            .map(|c| octets(&c))
                            .transpose()?;
                        end(&mut s, one_of(&[Tag::OCTET_STRING]))?;
                        Authentication::Sasl {
                            mechanism,
                            credentials,
                        }
                    }
                    (Class::ContextSpecific, n, constructed) if n != 0 && n != 3 => {
                        Authentication::Other {
                            number: n,
                            constructed,
                            contents: a.contents().to_vec(),
                        }
                    }
                    _ => return Err(unexpected(Tag::context(0), at)),
                };
                Op::BindRequest(BindRequest {
                    version,
                    name,
                    auth,
                })
            }
            (1, true) => {
                let mut r = e.reader()?;
                let result = read_result(&mut r)?;
                let server_sasl_creds = optional_octets(&mut r, 7)?;
                end(&mut r, |t| {
                    one_of(RESULT_TAGS)(t) || t.same_type(Tag::context(7))
                })?;
                Op::BindResponse(BindResponse {
                    result,
                    server_sasl_creds,
                })
            }
            (2, false) => {
                if !e.contents().is_empty() {
                    return Err(Error::Ber(asn1::Error::Null));
                }
                Op::UnbindRequest
            }
            (3, true) => {
                let mut r = e.reader()?;
                let base = read_string(&mut r)?;
                let scope = Scope::from_code(number(
                    &expect(&mut r, Tag::ENUMERATED)?,
                    "scope",
                    0,
                    u32::MAX,
                )?);
                let deref = number(&expect(&mut r, Tag::ENUMERATED)?, "derefAliases", 0, 3)?;
                let deref = DerefAliases::from_code(deref).ok_or(Error::Range("derefAliases"))?;
                let size_limit = number(&expect(&mut r, Tag::INTEGER)?, "sizeLimit", 0, MAX_INT)?;
                let time_limit = number(&expect(&mut r, Tag::INTEGER)?, "timeLimit", 0, MAX_INT)?;
                let types_only = read_bool(&mut r)?;
                let filter = Filter::read(&next(&mut r)?, 1)?;
                let attributes = read_strings(expect(&mut r, Tag::SEQUENCE)?.reader()?)?;
                // Context tags 0 to 9 are filter choices.
                end(&mut r, |t| {
                    (t.class == Class::ContextSpecific && t.number <= 9)
                        || one_of(&[
                            Tag::OCTET_STRING,
                            Tag::ENUMERATED,
                            Tag::INTEGER,
                            Tag::BOOLEAN,
                            Tag::SEQUENCE,
                        ])(t)
                })?;
                Op::SearchRequest(SearchRequest {
                    base,
                    scope,
                    deref,
                    size_limit,
                    time_limit,
                    types_only,
                    filter,
                    attributes,
                })
            }
            (4, true) => {
                let mut r = e.reader()?;
                let dn = read_string(&mut r)?;
                let attributes = read_attributes(&mut r, false)?;
                end(&mut r, one_of(&[Tag::OCTET_STRING, Tag::SEQUENCE]))?;
                Op::SearchResultEntry(SearchResultEntry { dn, attributes })
            }
            (5, true) => Op::SearchResultDone(result_only(e)?),
            (6, true) => {
                let mut r = e.reader()?;
                let dn = read_string(&mut r)?;
                let mut list = expect(&mut r, Tag::SEQUENCE)?.reader()?;
                end(&mut r, one_of(&[Tag::OCTET_STRING, Tag::SEQUENCE]))?;
                let mut changes = Vec::new();
                while !list.is_empty() {
                    let mut c = expect(&mut list, Tag::SEQUENCE)?.reader()?;
                    let op = number(&expect(&mut c, Tag::ENUMERATED)?, "operation", 0, u32::MAX)?;
                    let attribute = read_attribute(&expect(&mut c, Tag::SEQUENCE)?, false)?;
                    end(&mut c, one_of(&[Tag::ENUMERATED, Tag::SEQUENCE]))?;
                    changes.push(Change {
                        op: ModifyOperation::from_code(op),
                        attribute,
                    });
                }
                Op::ModifyRequest(ModifyRequest { dn, changes })
            }
            (7, true) => Op::ModifyResponse(result_only(e)?),
            (8, true) => {
                let mut r = e.reader()?;
                let dn = read_string(&mut r)?;
                let attributes = read_attributes(&mut r, true)?;
                end(&mut r, one_of(&[Tag::OCTET_STRING, Tag::SEQUENCE]))?;
                Op::AddRequest(AddRequest { dn, attributes })
            }
            (9, true) => Op::AddResponse(result_only(e)?),
            (10, false) => Op::DelRequest(text(e)?),
            (11, true) => Op::DelResponse(result_only(e)?),
            (12, true) => {
                let mut r = e.reader()?;
                let dn = read_string(&mut r)?;
                let new_rdn = read_string(&mut r)?;
                let delete_old_rdn = read_bool(&mut r)?;
                let new_superior = optional_text(&mut r, 0)?;
                end(
                    &mut r,
                    one_of(&[Tag::OCTET_STRING, Tag::BOOLEAN, Tag::context(0)]),
                )?;
                Op::ModifyDnRequest(ModifyDnRequest {
                    dn,
                    new_rdn,
                    delete_old_rdn,
                    new_superior,
                })
            }
            (13, true) => Op::ModifyDnResponse(result_only(e)?),
            (14, true) => {
                let mut r = e.reader()?;
                let dn = read_string(&mut r)?;
                let mut ava = expect(&mut r, Tag::SEQUENCE)?.reader()?;
                end(&mut r, one_of(&[Tag::OCTET_STRING, Tag::SEQUENCE]))?;
                let attribute = read_string(&mut ava)?;
                let value = read_octets(&mut ava)?;
                end(&mut ava, one_of(&[Tag::OCTET_STRING]))?;
                Op::CompareRequest(CompareRequest {
                    dn,
                    attribute,
                    value,
                })
            }
            (15, true) => Op::CompareResponse(result_only(e)?),
            (16, false) => Op::AbandonRequest(number(e, "messageID", 0, MAX_INT)?),
            (19, true) => Op::SearchResultReference(read_uris(e.reader()?)?),
            (23, true) => {
                let mut r = e.reader()?;
                let name = text(&expect(&mut r, Tag::context(0))?)?;
                let value = optional_octets(&mut r, 1)?;
                end(&mut r, one_of(&[Tag::context(0), Tag::context(1)]))?;
                Op::ExtendedRequest(ExtendedRequest { name, value })
            }
            (24, true) => {
                let mut r = e.reader()?;
                let result = read_result(&mut r)?;
                let name = optional_text(&mut r, 10)?;
                let value = optional_octets(&mut r, 11)?;
                end(&mut r, |t| {
                    one_of(RESULT_TAGS)(t)
                        || t.same_type(Tag::context(10))
                        || t.same_type(Tag::context(11))
                })?;
                Op::ExtendedResponse(ExtendedResponse {
                    result,
                    name,
                    value,
                })
            }
            (25, true) => {
                let mut r = e.reader()?;
                let name = optional_text(&mut r, 0)?;
                let value = optional_octets(&mut r, 1)?;
                end(&mut r, one_of(&[Tag::context(0), Tag::context(1)]))?;
                Op::IntermediateResponse(IntermediateResponse { name, value })
            }
            _ => return Err(Error::Operation(t)),
        })
    }

    fn write(&self, w: &mut W) -> Result<(), Error> {
        let app = Tag::application;
        match self {
            Op::BindRequest(b) => {
                if !(1..=127).contains(&b.version) {
                    return Err(Error::Range("version"));
                }
                w.nest(app(0), |w| {
                    w.uint(Tag::INTEGER, u32::from(b.version))?;
                    w.octets(b.name.as_bytes())?;
                    match &b.auth {
                        Authentication::Simple(p) => w.put(Tag::context(0), p),
                        Authentication::Sasl {
                            mechanism,
                            credentials,
                        } => w.nest(Tag::context(3), |w| {
                            w.octets(mechanism.as_bytes())?;
                            match credentials {
                                Some(c) => w.octets(c),
                                None => Ok(()),
                            }
                        }),
                        Authentication::Other {
                            number,
                            constructed,
                            contents,
                        } => {
                            if *number == 0 || *number == 3 {
                                return Err(Error::Unwritable(
                                    "authentication choice 0 or 3 is simple or SASL",
                                ));
                            }
                            w.put(context(*number, *constructed), contents)
                        }
                    }
                })
            }
            Op::BindResponse(b) => w.nest(app(1), |w| {
                write_result(w, &b.result)?;
                match &b.server_sasl_creds {
                    Some(c) => w.put(Tag::context(7), c),
                    None => Ok(()),
                }
            }),
            Op::UnbindRequest => w.put(app(2), &[]),
            Op::SearchRequest(s) => {
                if s.size_limit > MAX_INT {
                    return Err(Error::Range("sizeLimit"));
                }
                if s.time_limit > MAX_INT {
                    return Err(Error::Range("timeLimit"));
                }
                if matches!(s.scope, Scope::Other(0..=2)) {
                    return Err(Error::Unwritable(
                        "Scope::Other with a named scope's number",
                    ));
                }
                w.nest(app(3), |w| {
                    w.octets(s.base.as_bytes())?;
                    w.uint(Tag::ENUMERATED, s.scope.code())?;
                    w.uint(Tag::ENUMERATED, s.deref.code())?;
                    w.uint(Tag::INTEGER, s.size_limit)?;
                    w.uint(Tag::INTEGER, s.time_limit)?;
                    w.boolean(Tag::BOOLEAN, s.types_only)?;
                    s.filter.write(w, 1)?;
                    w.nest(Tag::SEQUENCE, |w| {
                        for a in &s.attributes {
                            w.octets(a.as_bytes())?;
                        }
                        Ok(())
                    })
                })
            }
            Op::SearchResultEntry(s) => w.nest(app(4), |w| {
                w.octets(s.dn.as_bytes())?;
                write_attributes(w, &s.attributes)
            }),
            Op::SearchResultDone(r) => w.nest(app(5), |w| write_result(w, r)),
            Op::ModifyRequest(m) => w.nest(app(6), |w| {
                w.octets(m.dn.as_bytes())?;
                w.nest(Tag::SEQUENCE, |w| {
                    for c in &m.changes {
                        if matches!(c.op, ModifyOperation::Other(0..=2)) {
                            return Err(Error::Unwritable(
                                "ModifyOperation::Other with a named operation's number",
                            ));
                        }
                        w.nest(Tag::SEQUENCE, |w| {
                            w.uint(Tag::ENUMERATED, c.op.code())?;
                            write_attribute(w, &c.attribute)
                        })?;
                    }
                    Ok(())
                })
            }),
            Op::ModifyResponse(r) => w.nest(app(7), |w| write_result(w, r)),
            Op::AddRequest(a) => {
                if a.attributes.iter().any(|a| a.values.is_empty()) {
                    return Err(Error::Unwritable("an added attribute with no values"));
                }
                w.nest(app(8), |w| {
                    w.octets(a.dn.as_bytes())?;
                    write_attributes(w, &a.attributes)
                })
            }
            Op::AddResponse(r) => w.nest(app(9), |w| write_result(w, r)),
            Op::DelRequest(dn) => w.put(app(10), dn.as_bytes()),
            Op::DelResponse(r) => w.nest(app(11), |w| write_result(w, r)),
            Op::ModifyDnRequest(m) => w.nest(app(12), |w| {
                w.octets(m.dn.as_bytes())?;
                w.octets(m.new_rdn.as_bytes())?;
                w.boolean(Tag::BOOLEAN, m.delete_old_rdn)?;
                match &m.new_superior {
                    Some(s) => w.put(Tag::context(0), s.as_bytes()),
                    None => Ok(()),
                }
            }),
            Op::ModifyDnResponse(r) => w.nest(app(13), |w| write_result(w, r)),
            Op::CompareRequest(c) => w.nest(app(14), |w| {
                w.octets(c.dn.as_bytes())?;
                w.nest(Tag::SEQUENCE, |w| {
                    w.octets(c.attribute.as_bytes())?;
                    w.octets(&c.value)
                })
            }),
            Op::CompareResponse(r) => w.nest(app(15), |w| write_result(w, r)),
            Op::AbandonRequest(id) => {
                if *id > MAX_INT {
                    return Err(Error::Range("messageID"));
                }
                w.uint(app(16), *id)
            }
            Op::SearchResultReference(uris) if uris.is_empty() => {
                Err(Error::Unwritable("a search reference with no URIs"))
            }
            Op::SearchResultReference(uris) => w.nest(app(19), |w| {
                for u in uris {
                    w.octets(u.as_bytes())?;
                }
                Ok(())
            }),
            Op::ExtendedRequest(x) => w.nest(app(23), |w| {
                w.put(Tag::context(0), x.name.as_bytes())?;
                match &x.value {
                    Some(v) => w.put(Tag::context(1), v),
                    None => Ok(()),
                }
            }),
            Op::ExtendedResponse(x) => w.nest(app(24), |w| {
                write_result(w, &x.result)?;
                if let Some(n) = &x.name {
                    w.put(Tag::context(10), n.as_bytes())?;
                }
                match &x.value {
                    Some(v) => w.put(Tag::context(11), v),
                    None => Ok(()),
                }
            }),
            Op::IntermediateResponse(x) => w.nest(app(25), |w| {
                if let Some(n) = &x.name {
                    w.put(Tag::context(0), n.as_bytes())?;
                }
                match &x.value {
                    Some(v) => w.put(Tag::context(1), v),
                    None => Ok(()),
                }
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Writing BER.

/// A BER writer that writes definite lengths in their shortest form, and
/// refuses to grow past [`MAX_MESSAGE`].
#[derive(Default)]
struct W {
    out: Vec<u8>,
}

impl W {
    fn put(&mut self, tag: Tag, contents: &[u8]) -> Result<(), Error> {
        let mut head = Vec::with_capacity(16);
        tag.encode(&mut head);
        asn1::encode_length(contents.len(), &mut head);
        let total = self
            .out
            .len()
            .saturating_add(head.len())
            .saturating_add(contents.len());
        if total > MAX_MESSAGE {
            return Err(Error::TooLarge(total));
        }
        self.out.extend_from_slice(&head);
        self.out.extend_from_slice(contents);
        Ok(())
    }

    /// Writes a constructed `tag` around what `f` writes.
    fn nest(&mut self, tag: Tag, f: impl FnOnce(&mut W) -> Result<(), Error>) -> Result<(), Error> {
        let start = self.out.len();
        f(self)?;
        let contents = self.out.split_off(start);
        self.put(tag.as_constructed(), &contents)
    }

    fn octets(&mut self, b: &[u8]) -> Result<(), Error> {
        self.put(Tag::OCTET_STRING, b)
    }

    fn uint(&mut self, tag: Tag, v: u32) -> Result<(), Error> {
        let b = u64::from(v).to_be_bytes();
        // Keep one zero byte before a high bit, so the value stays positive.
        let mut i = 0;
        while i < 7 && b[i] == 0 && b[i + 1] & 0x80 == 0 {
            i += 1;
        }
        self.put(tag, &b[i..])
    }

    fn boolean(&mut self, tag: Tag, v: bool) -> Result<(), Error> {
        self.put(tag, &[if v { 0xff } else { 0x00 }])
    }
}

/// The context tag `number`, in constructed form if `constructed`.
fn context(number: u32, constructed: bool) -> Tag {
    let t = Tag::context(number);
    if constructed { t.as_constructed() } else { t }
}

fn write_result(w: &mut W, r: &LdapResult) -> Result<(), Error> {
    w.uint(Tag::ENUMERATED, r.code.0)?;
    w.octets(r.matched_dn.as_bytes())?;
    w.octets(r.message.as_bytes())?;
    if !r.referral.is_empty() {
        w.nest(Tag::context(3), |w| {
            for u in &r.referral {
                w.octets(u.as_bytes())?;
            }
            Ok(())
        })?;
    }
    Ok(())
}

fn write_attribute(w: &mut W, a: &Attribute) -> Result<(), Error> {
    w.nest(Tag::SEQUENCE, |w| {
        w.octets(a.name.as_bytes())?;
        w.nest(Tag::SET, |w| {
            for v in &a.values {
                w.octets(v)?;
            }
            Ok(())
        })
    })
}

fn write_attributes(w: &mut W, list: &[Attribute]) -> Result<(), Error> {
    w.nest(Tag::SEQUENCE, |w| {
        for a in list {
            write_attribute(w, a)?;
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Filters.

impl Filter {
    /// Reads a filter from its BER element, at nesting depth `depth`.
    fn read(e: &Element<'_>, depth: usize) -> Result<Filter, Error> {
        if depth > MAX_FILTER_DEPTH {
            return Err(Error::Filter("nested too deep"));
        }
        let t = e.tag();
        if t.class != Class::ContextSpecific {
            return Err(unexpected(Tag::context(0), t));
        }
        let ava = |e: &Element<'_>| -> Result<(String, Vec<u8>), Error> {
            let mut r = e.reader()?;
            let attribute = read_string(&mut r)?;
            let value = read_octets(&mut r)?;
            end(&mut r, one_of(&[Tag::OCTET_STRING]))?;
            Ok((attribute, value))
        };
        Ok(match (t.number, t.constructed) {
            (0 | 1, true) => {
                let mut r = e.reader()?;
                let mut list = Vec::new();
                while !r.is_empty() {
                    list.push(Filter::read(&next(&mut r)?, depth + 1)?);
                }
                if t.number == 0 {
                    Filter::And(list)
                } else {
                    Filter::Or(list)
                }
            }
            (2, true) => {
                let mut r = e.reader()?;
                let inner = Filter::read(&next(&mut r)?, depth + 1)?;
                r.finish()?;
                Filter::Not(Box::new(inner))
            }
            (3, true) => {
                let (attribute, value) = ava(e)?;
                Filter::Equal { attribute, value }
            }
            (4, true) => {
                let mut r = e.reader()?;
                let attribute = read_string(&mut r)?;
                let mut parts = expect(&mut r, Tag::SEQUENCE)?.reader()?;
                end(&mut r, one_of(&[Tag::OCTET_STRING, Tag::SEQUENCE]))?;
                let (mut initial, mut any, mut last) = (None, Vec::new(), None);
                let mut first = true;
                while !parts.is_empty() {
                    let p = next(&mut parts)?;
                    let pt = p.tag();
                    if pt.class != Class::ContextSpecific || pt.constructed || pt.number > 2 {
                        return Err(unexpected(Tag::context(1), pt));
                    }
                    if last.is_some() {
                        return Err(Error::Filter("substring after the final part"));
                    }
                    let v = octets(&p)?;
                    match pt.number {
                        0 if first => initial = Some(v),
                        0 => return Err(Error::Filter("initial substring not first")),
                        1 => any.push(v),
                        _ => last = Some(v),
                    }
                    first = false;
                }
                if first {
                    return Err(Error::Filter("substring filter with no parts"));
                }
                Filter::Substrings {
                    attribute,
                    initial,
                    any,
                    last,
                }
            }
            (5, true) => {
                let (attribute, value) = ava(e)?;
                Filter::GreaterOrEqual { attribute, value }
            }
            (6, true) => {
                let (attribute, value) = ava(e)?;
                Filter::LessOrEqual { attribute, value }
            }
            (7, false) => Filter::Present(text(e)?),
            (8, true) => {
                let (attribute, value) = ava(e)?;
                Filter::Approx { attribute, value }
            }
            (9, true) => {
                let mut r = e.reader()?;
                let rule = optional_text(&mut r, 1)?;
                let attribute = optional_text(&mut r, 2)?;
                let value = octets(&expect(&mut r, Tag::context(3))?)?;
                let dn_attributes = match optional(&mut r, Tag::context(4))? {
                    Some(b) => b.boolean()?,
                    None => false,
                };
                end(&mut r, |t| {
                    t.class == Class::ContextSpecific && (1..=4).contains(&t.number)
                })?;
                if rule.is_none() && attribute.is_none() {
                    return Err(Error::Filter("extensible match with neither type nor rule"));
                }
                Filter::Extensible {
                    rule,
                    attribute,
                    value,
                    dn_attributes,
                }
            }
            (n, constructed) if n > 9 => Filter::Other {
                number: n,
                constructed,
                contents: e.contents().to_vec(),
            },
            (n, c) => {
                let want = if c {
                    Tag::context(n)
                } else {
                    Tag::context(n).as_constructed()
                };
                return Err(unexpected(want, t));
            }
        })
    }

    fn write(&self, w: &mut W, depth: usize) -> Result<(), Error> {
        if depth > MAX_FILTER_DEPTH {
            return Err(Error::Filter("nested too deep"));
        }
        let ava = |w: &mut W, n: u32, attribute: &str, value: &[u8]| {
            w.nest(Tag::context(n), |w| {
                w.octets(attribute.as_bytes())?;
                w.octets(value)
            })
        };
        match self {
            Filter::And(list) | Filter::Or(list) => {
                let n = if matches!(self, Filter::And(_)) { 0 } else { 1 };
                w.nest(Tag::context(n), |w| {
                    for f in list {
                        f.write(w, depth + 1)?;
                    }
                    Ok(())
                })
            }
            Filter::Not(f) => w.nest(Tag::context(2), |w| f.write(w, depth + 1)),
            Filter::Equal { attribute, value } => ava(w, 3, attribute, value),
            Filter::Substrings {
                attribute,
                initial,
                any,
                last,
            } => {
                if initial.is_none() && any.is_empty() && last.is_none() {
                    return Err(Error::Filter("substring filter with no parts"));
                }
                w.nest(Tag::context(4), |w| {
                    w.octets(attribute.as_bytes())?;
                    w.nest(Tag::SEQUENCE, |w| {
                        if let Some(v) = initial {
                            w.put(Tag::context(0), v)?;
                        }
                        for v in any {
                            w.put(Tag::context(1), v)?;
                        }
                        match last {
                            Some(v) => w.put(Tag::context(2), v),
                            None => Ok(()),
                        }
                    })
                })
            }
            Filter::GreaterOrEqual { attribute, value } => ava(w, 5, attribute, value),
            Filter::LessOrEqual { attribute, value } => ava(w, 6, attribute, value),
            Filter::Present(attribute) => w.put(Tag::context(7), attribute.as_bytes()),
            Filter::Approx { attribute, value } => ava(w, 8, attribute, value),
            Filter::Extensible {
                rule,
                attribute,
                value,
                dn_attributes,
            } => {
                if rule.is_none() && attribute.is_none() {
                    return Err(Error::Filter("extensible match with neither type nor rule"));
                }
                w.nest(Tag::context(9), |w| {
                    if let Some(r) = rule {
                        w.put(Tag::context(1), r.as_bytes())?;
                    }
                    if let Some(a) = attribute {
                        w.put(Tag::context(2), a.as_bytes())?;
                    }
                    w.put(Tag::context(3), value)?;
                    if *dn_attributes {
                        w.boolean(Tag::context(4), true)?;
                    }
                    Ok(())
                })
            }
            Filter::Other {
                number,
                constructed,
                contents,
            } => {
                if *number <= 9 {
                    return Err(Error::Unwritable(
                        "filter choices 0 to 9 have their own variants",
                    ));
                }
                w.put(context(*number, *constructed), contents)
            }
        }
    }

    /// Reads a filter from RFC 4515 text, such as `(&(cn=Babs*)(!(ou=x)))`.
    /// The outer parentheses are required, and no spaces are allowed
    /// around the parts. `(&)` and `(|)` are true and false (RFC 4526). In
    /// values, `\` and two hex digits stand for a byte.
    pub fn parse_text(text: &str) -> Result<Filter, Error> {
        if text.len() > MAX_TEXT {
            return Err(Error::TextTooLong);
        }
        let mut p = FilterText {
            s: text.as_bytes(),
            i: 0,
        };
        let f = p.filter(1)?;
        if p.i != p.s.len() {
            return Err(Error::Syntax(p.i));
        }
        Ok(f)
    }

    /// The filter as RFC 4515 text. Bytes that are not UTF-8, NUL, `(`,
    /// `)`, `*` and `\` are written as `\` and two hex digits. It refuses a
    /// filter whose attribute or rule is not a name or numeric OID, a
    /// substring filter with an empty initial or final part (the text would
    /// read back without it), a [`Filter::Other`], a filter
    /// [`Message::parse`] would refuse, or text longer than [`MAX_TEXT`].
    pub fn to_text(&self) -> Result<String, Error> {
        let mut out = String::new();
        self.write_text(&mut out, 1)?;
        Ok(out)
    }

    /// Appends the filter's text to `out`, which never grows past
    /// [`MAX_TEXT`].
    fn write_text(&self, out: &mut String, depth: usize) -> Result<(), Error> {
        if depth > MAX_FILTER_DEPTH {
            return Err(Error::Filter("nested too deep"));
        }
        let name = |out: &mut String, a: &str| {
            if !is_attribute(a) {
                return Err(Error::Unwritable(
                    "attribute description is not a name or numeric OID",
                ));
            }
            push_text(out, a)
        };
        push_text(out, "(")?;
        match self {
            Filter::And(list) | Filter::Or(list) => {
                push_text(
                    out,
                    if matches!(self, Filter::And(_)) {
                        "&"
                    } else {
                        "|"
                    },
                )?;
                for f in list {
                    f.write_text(out, depth + 1)?;
                }
            }
            Filter::Not(f) => {
                push_text(out, "!")?;
                f.write_text(out, depth + 1)?;
            }
            Filter::Equal { attribute, value } => {
                name(out, attribute)?;
                push_text(out, "=")?;
                escape_value(out, value)?;
            }
            Filter::Substrings {
                attribute,
                initial,
                any,
                last,
            } => {
                if initial.is_none() && any.is_empty() && last.is_none() {
                    return Err(Error::Filter("substring filter with no parts"));
                }
                // Text cannot tell an empty initial or final part from none.
                if initial.as_ref().is_some_and(Vec::is_empty)
                    || last.as_ref().is_some_and(Vec::is_empty)
                {
                    return Err(Error::Unwritable(
                        "an empty initial or final substring has no text form",
                    ));
                }
                name(out, attribute)?;
                push_text(out, "=")?;
                if let Some(v) = initial {
                    escape_value(out, v)?;
                }
                push_text(out, "*")?;
                for v in any {
                    escape_value(out, v)?;
                    push_text(out, "*")?;
                }
                if let Some(v) = last {
                    escape_value(out, v)?;
                }
            }
            Filter::GreaterOrEqual { attribute, value } => {
                name(out, attribute)?;
                push_text(out, ">=")?;
                escape_value(out, value)?;
            }
            Filter::LessOrEqual { attribute, value } => {
                name(out, attribute)?;
                push_text(out, "<=")?;
                escape_value(out, value)?;
            }
            Filter::Present(attribute) => {
                name(out, attribute)?;
                push_text(out, "=*")?;
            }
            Filter::Approx { attribute, value } => {
                name(out, attribute)?;
                push_text(out, "~=")?;
                escape_value(out, value)?;
            }
            Filter::Extensible {
                rule,
                attribute,
                value,
                dn_attributes,
            } => {
                if rule.is_none() && attribute.is_none() {
                    return Err(Error::Filter("extensible match with neither type nor rule"));
                }
                if let Some(a) = attribute {
                    name(out, a)?;
                }
                if *dn_attributes {
                    push_text(out, ":dn")?;
                }
                if let Some(r) = rule {
                    if !is_oid(r) {
                        return Err(Error::Unwritable(
                            "matching rule is not a name or numeric OID",
                        ));
                    }
                    // After a type, text reads a lone `:dn` as the
                    // dnAttributes flag. With no type it can only be a rule.
                    if r.eq_ignore_ascii_case("dn") && !dn_attributes && attribute.is_some() {
                        return Err(Error::Unwritable(
                            "a matching rule named dn after a type reads back as the dn flag",
                        ));
                    }
                    push_text(out, ":")?;
                    push_text(out, r)?;
                }
                push_text(out, ":=")?;
                escape_value(out, value)?;
            }
            Filter::Other { .. } => {
                return Err(Error::Unwritable("filter choice with no text form"));
            }
        }
        push_text(out, ")")
    }
}

impl std::str::FromStr for Filter {
    type Err = Error;

    fn from_str(s: &str) -> Result<Filter, Error> {
        Filter::parse_text(s)
    }
}

/// Appends `s` to filter or DN text, unless the text would then be longer
/// than [`MAX_TEXT`]. Text writers append only through it, so what they
/// hold stays bounded whatever they are given.
fn push_text(out: &mut String, s: &str) -> Result<(), Error> {
    if out.len().saturating_add(s.len()) > MAX_TEXT {
        return Err(Error::TextTooLong);
    }
    out.push_str(s);
    Ok(())
}

/// Appends one character with [`push_text`].
fn push_char(out: &mut String, c: char) -> Result<(), Error> {
    push_text(out, c.encode_utf8(&mut [0; 4]))
}

/// Appends `v` as an RFC 4515 assertion value.
fn escape_value(out: &mut String, v: &[u8]) -> Result<(), Error> {
    for chunk in v.utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '\0' | '(' | ')' | '*' | '\\' => push_hex_escape(out, c as u8)?,
                c => push_char(out, c)?,
            }
        }
        for &b in chunk.invalid() {
            push_hex_escape(out, b)?;
        }
    }
    Ok(())
}

/// The two lowercase hex digits of `b`.
fn hex(b: u8) -> [u8; 2] {
    [hex_lower(b >> 4), hex_lower(b)]
}

/// Appends `\` and the two hex digits of `b`.
fn push_hex_escape(out: &mut String, b: u8) -> Result<(), Error> {
    let [h, l] = hex(b);
    push_text(out, "\\")?;
    push_char(out, char::from(h))?;
    push_char(out, char::from(l))
}

/// Two hex digits as a byte.
fn hex_pair(b: &[u8]) -> Option<u8> {
    match b {
        [h, l] => Some(hex_digit(*h)? << 4 | hex_digit(*l)?),
        _ => None,
    }
}

/// A `descr` (RFC 4512): a letter, then letters, digits and hyphens.
fn is_descr(s: &str) -> bool {
    let b = s.as_bytes();
    b.first().is_some_and(u8::is_ascii_alphabetic)
        && b.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-')
}

/// A `numericoid` (RFC 4512): two or more numbers with no leading zeros,
/// joined by dots.
fn is_numericoid(s: &str) -> bool {
    let mut n = 0;
    for part in s.split('.') {
        let b = part.as_bytes();
        if b.is_empty() || !b.iter().all(u8::is_ascii_digit) || (b.len() > 1 && b[0] == b'0') {
            return false;
        }
        n += 1;
    }
    n >= 2
}

/// An `oid` (RFC 4512): a `descr` or a `numericoid`.
fn is_oid(s: &str) -> bool {
    is_descr(s) || is_numericoid(s)
}

/// An `attributedescription` (RFC 4512): an `oid`, then options after
/// semicolons.
fn is_attribute(s: &str) -> bool {
    let mut parts = s.split(';');
    parts.next().is_some_and(is_oid)
        && parts.all(|o| !o.is_empty() && o.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
}

/// A recursive-descent reader of RFC 4515 text. Recursion is bounded by
/// [`MAX_FILTER_DEPTH`].
struct FilterText<'a> {
    s: &'a [u8],
    i: usize,
}

impl FilterText<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn eat(&mut self, c: u8) -> Result<(), Error> {
        if self.peek() != Some(c) {
            return Err(Error::Syntax(self.i));
        }
        self.i += 1;
        Ok(())
    }

    fn filter(&mut self, depth: usize) -> Result<Filter, Error> {
        if depth > MAX_FILTER_DEPTH {
            return Err(Error::Filter("nested too deep"));
        }
        self.eat(b'(')?;
        let f = match self.peek() {
            Some(b'&') => {
                self.i += 1;
                Filter::And(self.list(depth)?)
            }
            Some(b'|') => {
                self.i += 1;
                Filter::Or(self.list(depth)?)
            }
            Some(b'!') => {
                self.i += 1;
                Filter::Not(Box::new(self.filter(depth + 1)?))
            }
            _ => self.item()?,
        };
        self.eat(b')')?;
        Ok(f)
    }

    fn list(&mut self, depth: usize) -> Result<Vec<Filter>, Error> {
        let mut out = Vec::new();
        while self.peek() == Some(b'(') {
            out.push(self.filter(depth + 1)?);
        }
        Ok(out)
    }

    /// The text of a `str` slice cut at ASCII bytes, so always UTF-8.
    fn str_at(&self, start: usize, end: usize) -> Result<&str, Error> {
        std::str::from_utf8(&self.s[start..end]).map_err(|_| Error::Syntax(start))
    }

    fn attribute(&self, start: usize, end: usize) -> Result<String, Error> {
        let a = self.str_at(start, end)?;
        if !is_attribute(a) {
            return Err(Error::Syntax(start));
        }
        Ok(a.to_string())
    }

    /// A simple, present, substring or extensible item, up to its `)`.
    fn item(&mut self) -> Result<Filter, Error> {
        let start = self.i;
        let end = start
            + self.s[start..]
                .iter()
                .position(|&c| c == b')')
                .ok_or(Error::Syntax(self.s.len()))?;
        let eq = start
            + self.s[start..end]
                .iter()
                .position(|&c| c == b'=')
                .ok_or(Error::Syntax(end))?;
        let (vstart, value) = (eq + 1, &self.s[eq + 1..end]);
        let simple = |n: usize| self.attribute(start, eq - n);
        let f = match self.s[start..eq].last() {
            Some(b'~') => Filter::Approx {
                attribute: simple(1)?,
                value: unescape(value, vstart)?,
            },
            Some(b'>') => Filter::GreaterOrEqual {
                attribute: simple(1)?,
                value: unescape(value, vstart)?,
            },
            Some(b'<') => Filter::LessOrEqual {
                attribute: simple(1)?,
                value: unescape(value, vstart)?,
            },
            Some(b':') => self.extensible(start, eq - 1, value, vstart)?,
            _ => {
                let attribute = simple(0)?;
                if value == b"*" {
                    Filter::Present(attribute)
                } else if value.contains(&b'*') {
                    let mut parts = Vec::new();
                    let mut at = vstart;
                    for p in value.split(|&c| c == b'*') {
                        parts.push(unescape(p, at)?);
                        at += p.len() + 1;
                    }
                    // Split on at least one star, so there are two or more.
                    let last = parts.pop().filter(|v| !v.is_empty());
                    let mut rest = parts.into_iter();
                    let initial = rest.next().filter(|v| !v.is_empty());
                    Filter::Substrings {
                        attribute,
                        initial,
                        any: rest.collect(),
                        last,
                    }
                } else {
                    Filter::Equal {
                        attribute,
                        value: unescape(value, vstart)?,
                    }
                }
            }
        };
        self.i = end;
        Ok(f)
    }

    /// `[attr][:dn][:rule]:=value`, with `self.s[start..end]` the part
    /// before `:=`.
    fn extensible(
        &self,
        start: usize,
        end: usize,
        value: &[u8],
        vstart: usize,
    ) -> Result<Filter, Error> {
        let left = self.str_at(start, end)?;
        let mut parts = left.split(':');
        let attribute = match parts.next() {
            Some("") | None => None,
            Some(_) => Some(self.attribute(start, start + left.find(':').unwrap_or(left.len()))?),
        };
        let rest: Vec<&str> = parts.collect();
        let (dn_attributes, rule) = match rest.as_slice() {
            [] => (false, None),
            // With no type, `:dn:=` is a rule named dn (RFC 4515 section 3).
            [x] if x.eq_ignore_ascii_case("dn") && attribute.is_some() => (true, None),
            [x] => (false, Some(*x)),
            [d, x] if d.eq_ignore_ascii_case("dn") => (true, Some(*x)),
            _ => return Err(Error::Syntax(start)),
        };
        if let Some(r) = rule
            && !is_oid(r)
        {
            return Err(Error::Syntax(start));
        }
        if attribute.is_none() && rule.is_none() {
            return Err(Error::Syntax(start));
        }
        Ok(Filter::Extensible {
            rule: rule.map(str::to_string),
            attribute,
            value: unescape(value, vstart)?,
            dn_attributes,
        })
    }
}

/// An RFC 4515 assertion value's bytes, with escapes undone. `at` is where
/// it starts in the text, for errors.
fn unescape(v: &[u8], at: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(v.len());
    let mut k = 0;
    while k < v.len() {
        match v[k] {
            b'\\' => {
                let b = v
                    .get(k + 1..k + 3)
                    .and_then(hex_pair)
                    .ok_or(Error::Syntax(at + k))?;
                out.push(b);
                k += 3;
            }
            0 | b'(' | b')' | b'*' => return Err(Error::Syntax(at + k)),
            c => {
                out.push(c);
                k += 1;
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Distinguished names.

impl Dn {
    /// Reads a DN from RFC 4514 text, such as `cn=J. Smith+ou=Sales,dc=com`.
    /// The empty string is the empty DN. Attribute types must be names or
    /// numeric OIDs, and no spaces are allowed around `,`, `+` or `=`.
    /// Escapes are undone; the result must be UTF-8.
    pub fn parse(text: &str) -> Result<Dn, Error> {
        if text.len() > MAX_TEXT {
            return Err(Error::TextTooLong);
        }
        let s = text.as_bytes();
        let mut rdns = Vec::new();
        if s.is_empty() {
            return Ok(Dn(rdns));
        }
        let mut i = 0;
        loop {
            let mut avas = Vec::new();
            loop {
                let (ava, next) = parse_ava(s, i)?;
                avas.push(ava);
                i = next;
                if s.get(i) != Some(&b'+') {
                    break;
                }
                i += 1;
            }
            rdns.push(Rdn(avas));
            match s.get(i) {
                None => break,
                Some(b',') => i += 1,
                Some(_) => return Err(Error::Syntax(i)),
            }
        }
        Ok(Dn(rdns))
    }

    /// The DN as RFC 4514 text. It escapes `"`, `+`, `,`, `;`, `<`, `>`
    /// and `\`, a leading space or `#`, a trailing space, and NUL. It
    /// refuses an RDN with no values, an attribute type that is not a name
    /// or numeric OID, an empty [`AttributeValue::Ber`], or text longer
    /// than [`MAX_TEXT`].
    pub fn to_text(&self) -> Result<String, Error> {
        let mut out = String::new();
        self.write_text(&mut out)?;
        Ok(out)
    }

    /// Appends the DN's text to `out`, which never grows past [`MAX_TEXT`].
    fn write_text(&self, out: &mut String) -> Result<(), Error> {
        for (k, rdn) in self.0.iter().enumerate() {
            if k > 0 {
                push_text(out, ",")?;
            }
            if rdn.0.is_empty() {
                return Err(Error::Unwritable("an RDN with no values"));
            }
            for (j, ava) in rdn.0.iter().enumerate() {
                if j > 0 {
                    push_text(out, "+")?;
                }
                if !is_oid(&ava.attribute) {
                    return Err(Error::Unwritable(
                        "attribute type is not a name or numeric OID",
                    ));
                }
                push_text(out, &ava.attribute)?;
                push_text(out, "=")?;
                match &ava.value {
                    AttributeValue::Text(v) => escape_dn_value(out, v)?,
                    AttributeValue::Ber(b) => {
                        if b.is_empty() {
                            return Err(Error::Unwritable("an empty BER value"));
                        }
                        push_text(out, "#")?;
                        for &x in b {
                            let [h, l] = hex(x);
                            push_char(out, char::from(h))?;
                            push_char(out, char::from(l))?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl std::str::FromStr for Dn {
    type Err = Error;

    fn from_str(s: &str) -> Result<Dn, Error> {
        Dn::parse(s)
    }
}

fn escape_dn_value(out: &mut String, v: &str) -> Result<(), Error> {
    let n = v.chars().count();
    for (k, c) in v.chars().enumerate() {
        match c {
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' => {
                push_text(out, "\\")?;
                push_char(out, c)?;
            }
            '\0' => push_text(out, "\\00")?,
            ' ' if k == 0 || k + 1 == n => push_text(out, "\\ ")?,
            '#' if k == 0 => push_text(out, "\\#")?,
            c => push_char(out, c)?,
        }
    }
    Ok(())
}

/// The attribute type and value at `s[start..]`, and where it ends.
fn parse_ava(s: &[u8], start: usize) -> Result<(Ava, usize), Error> {
    let eq = start
        + s[start..]
            .iter()
            .position(|&c| c == b'=' || c == b',' || c == b'+')
            .ok_or(Error::Syntax(s.len()))?;
    let attribute = std::str::from_utf8(&s[start..eq]).map_err(|_| Error::Syntax(start))?;
    if s[eq] != b'=' || !is_oid(attribute) {
        return Err(Error::Syntax(start));
    }
    let attribute = attribute.to_string();
    let mut i = eq + 1;
    if s.get(i) == Some(&b'#') {
        i += 1;
        let mut bytes = Vec::new();
        while let Some(&c) = s.get(i) {
            if c == b',' || c == b'+' {
                break;
            }
            bytes.push(s.get(i..i + 2).and_then(hex_pair).ok_or(Error::Syntax(i))?);
            i += 2;
        }
        if bytes.is_empty() {
            return Err(Error::Syntax(i));
        }
        return Ok((
            Ava {
                attribute,
                value: AttributeValue::Ber(bytes),
            },
            i,
        ));
    }
    let vstart = i;
    let mut bytes = Vec::new();
    let mut trailing_space = false;
    while let Some(&c) = s.get(i) {
        match c {
            b',' | b'+' => break,
            b'\\' => {
                let n = *s.get(i + 1).ok_or(Error::Syntax(i))?;
                if b"\"+,;<>\\ #=".contains(&n) {
                    bytes.push(n);
                    i += 2;
                } else {
                    bytes.push(
                        s.get(i + 1..i + 3)
                            .and_then(hex_pair)
                            .ok_or(Error::Syntax(i))?,
                    );
                    i += 3;
                }
                trailing_space = false;
            }
            0 | b'"' | b';' | b'<' | b'>' => return Err(Error::Syntax(i)),
            b' ' if i == vstart => return Err(Error::Syntax(i)),
            c => {
                trailing_space = c == b' ';
                bytes.push(c);
                i += 1;
            }
        }
    }
    if trailing_space {
        return Err(Error::Syntax(i - 1));
    }
    let value = String::from_utf8(bytes).map_err(|_| Error::Utf8)?;
    Ok((
        Ava {
            attribute,
            value: AttributeValue::Text(value),
        },
        i,
    ))
}

// ---------------------------------------------------------------------------
// The stream.

impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one whole message: a TCP message the caller has framed, or a
    /// CLDAP datagram that holds one message. Bytes after it are an error.
    /// Reads BER. Refuses malformed fields and messages over [`MAX_MESSAGE`].
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode(bytes)
    }

    /// Appends DER. Refuses values that
    /// [`Message::parse`] would refuse or read back as another value: an ID
    /// or limit over [`MAX_INT`], a version outside 1 to 127, a filter
    /// [`Message::parse`] would not take, an [`Authentication::Other`],
    /// [`Filter::Other`], [`Scope::Other`] or [`ModifyOperation::Other`]
    /// with a number a named choice uses, an added attribute with no
    /// values, a search reference with no URIs, or more than
    /// [`MAX_MESSAGE`] bytes. A false criticality or `dnAttributes`, and an
    /// empty list of controls, are left out, as their defaults. An empty
    /// referral is left out, as no referral.
    /// Refuses values that change when encoded. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        asn1::write_checked(
            self,
            Self::encode,
            Self::decode,
            Error::Unwritable("message changes when parsed"),
            out,
        )
    }
}

fictionet::prefixed! {
    /// Reads LDAP messages without holding input bytes.
    ///
    /// Use with [`Stream<codec::Frames<Message>>`](fictionet::stdlib::codec::Stream) for bounded input. Partial messages
    /// return [`fictionet::stdlib::codec::Step::Need`], including at EOF. The stream reports
    /// truncation at EOF and errors once. A malformed message ends the stream.
    /// This includes a well-framed message that [`Message::parse`] rejects:
    /// [RFC 4511 section 4.1.1](https://www.rfc-editor.org/rfc/rfc4511.html#section-4.1.1)
    /// requires termination for malformed envelopes and encodings. For parsing
    /// failures as individual items, use
    /// `asn1::Elements::new(Rules::Ber).map(|bytes| Message::parse(&bytes))`.
    Message => (Message, Error, usize);
    name = "LDAP";
    default { MAX_MESSAGE }
    normalize(limit) { limit.min(MAX_MESSAGE) }
    capacity(limit) { let limit = *limit;
        limit.max(asn1::HEADER_ROOM) }

    #[inline]
    fn parse_prefix(
        input: &[u8],
        limit: &Self::Limit,
    ) -> Result<Option<(Self::Item, usize)>, Self::Error> {
        let limit = *limit;
        let header = match asn1::Header::parse(input, Rules::Ber) {
            Ok(header) => header,
            Err(asn1::Error::Truncated) => return Ok(None),
            Err(asn1::Error::TooLong) => return Err(Error::TooLarge(declared_total(input))),
            Err(e) => return Err(Error::Ber(e)),
        };
        if header.tag != Tag::SEQUENCE {
            return Err(unexpected(Tag::SEQUENCE, header.tag));
        }
        let Length::Definite(n) = header.length else {
            return Err(Error::Ber(asn1::Error::Indefinite));
        };
        let total = header.len.saturating_add(n);
        if total > limit {
            return Err(Error::TooLarge(total));
        }
        Ok(match input.get(..total) {
            Some(bytes) => Some((Message::parse(bytes)?, total)),
            None => None,
        })
    }
}

/// The whole length a header at the start of `b` declares: the header and
/// the contents. It is for a header [`asn1::Header::parse`] found too long,
/// so its length octets are all in `b`.
fn declared_total(b: &[u8]) -> usize {
    let Ok((_, i)) = Tag::parse(b) else {
        return usize::MAX;
    };
    let n = usize::from(b.get(i).map_or(0, |c| c & 0x7f));
    let Some(octets) = b.get(i + 1..i + 1 + n) else {
        return usize::MAX;
    };
    let v = octets.iter().fold(0u64, |v, &c| {
        v.saturating_mul(256).saturating_add(u64::from(c))
    });
    usize::try_from(v)
        .unwrap_or(usize::MAX)
        .saturating_add(i + 1 + n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Fail, Lcg, Stream};
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::{assert_linear, rounds};
    use fictionet::stdlib::test_support::{chunks, decode_all, mutate};

    fn msg(id: u32, op: Op) -> Message {
        Message {
            id,
            op,
            controls: Vec::new(),
        }
    }

    /// Pushes bytes that fit.
    fn put(d: &mut Stream<Frames<Message>>, b: &[u8]) {
        assert_eq!(d.push(b), b.len());
    }

    fn eq(attribute: &str, value: &str) -> Filter {
        Filter::Equal {
            attribute: attribute.into(),
            value: value.into(),
        }
    }

    #[test]
    fn search_request_bytes() {
        // Message 2: search dc=x, whole subtree, (objectClass=*), all
        // attributes, encoded by hand from RFC 4511 section 4.5.1.
        let mut bytes = vec![0x30, 0x29, 0x02, 0x01, 0x02, 0x63, 0x24];
        bytes.extend_from_slice(&[0x04, 0x04, b'd', b'c', b'=', b'x']);
        bytes.extend_from_slice(&[
            0x0a, 0x01, 0x02, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
        ]);
        bytes.extend_from_slice(&[0x01, 0x01, 0x00, 0x87, 0x0b]);
        bytes.extend_from_slice(b"objectClass");
        bytes.extend_from_slice(&[0x30, 0x00]);
        let m = Message::parse(&bytes).unwrap();
        let want = msg(
            2,
            Op::SearchRequest(SearchRequest {
                base: "dc=x".into(),
                scope: Scope::Subtree,
                deref: DerefAliases::Never,
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter: Filter::Present("objectClass".into()),
                attributes: vec![],
            }),
        );
        assert_eq!(m, want);
        assert_eq!(m.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn bind_unbind_abandon_bytes() {
        let bind = [
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
        ];
        let m = Message::parse(&bind).unwrap();
        assert_eq!(
            m,
            msg(
                1,
                Op::BindRequest(BindRequest {
                    version: 3,
                    name: String::new(),
                    auth: Authentication::Simple(vec![])
                })
            )
        );
        assert_eq!(m.to_bytes().unwrap(), bind);
        // Unbind is [APPLICATION 2] NULL; abandon is [APPLICATION 16] INTEGER.
        let unbind = [0x30, 0x05, 0x02, 0x01, 0x03, 0x42, 0x00];
        assert_eq!(Message::parse(&unbind), Ok(msg(3, Op::UnbindRequest)));
        assert_eq!(msg(3, Op::UnbindRequest).to_bytes().unwrap(), unbind);
        let abandon = [0x30, 0x06, 0x02, 0x01, 0x04, 0x50, 0x01, 0x02];
        assert_eq!(Message::parse(&abandon), Ok(msg(4, Op::AbandonRequest(2))));
        // A message ID of 128 needs a leading zero byte.
        assert_eq!(
            msg(128, Op::UnbindRequest).to_bytes().unwrap(),
            [0x30, 0x06, 0x02, 0x02, 0x00, 0x80, 0x42, 0x00]
        );
        // Controls: [0] holding a SEQUENCE; criticality TRUE.
        let mut m = msg(5, Op::DelRequest("cn=x".into()));
        m.controls.push(Control {
            oid: "1.2.3".into(),
            critical: true,
            value: Some(vec![1, 2]),
        });
        let b = m.to_bytes().unwrap();
        assert_eq!(&b[..2], [0x30, 0x1b]);
        assert_eq!(&b[5..11], [0x4a, 0x04, b'c', b'n', b'=', b'x']);
        assert_eq!(
            &b[11..],
            [
                0xa0, 0x10, 0x30, 0x0e, 0x04, 0x05, b'1', b'.', b'2', b'.', b'3', 0x01, 0x01, 0xff,
                0x04, 0x02, 1, 2
            ]
        );
        contract::check_written(&m);
    }

    #[test]
    fn every_operation_round_trips() {
        let result = LdapResult {
            code: ResultCode::REFERRAL,
            matched_dn: "dc=example".into(),
            message: "try elsewhere".into(),
            referral: vec!["ldap://other/".into()],
        };
        let attr = Attribute {
            name: "cn".into(),
            values: vec![b"b".to_vec(), b"a".to_vec()],
        };
        let ops = vec![
            Op::BindRequest(BindRequest {
                version: 3,
                name: "cn=admin".into(),
                auth: Authentication::Sasl {
                    mechanism: "PLAIN".into(),
                    credentials: Some(b"\0u\0p".to_vec()),
                },
            }),
            Op::BindRequest(BindRequest {
                version: 2,
                name: String::new(),
                auth: Authentication::Sasl {
                    mechanism: "EXTERNAL".into(),
                    credentials: None,
                },
            }),
            Op::BindRequest(BindRequest {
                version: 127,
                name: String::new(),
                auth: Authentication::Other {
                    number: 9,
                    constructed: false,
                    contents: vec![1, 2, 3],
                },
            }),
            Op::BindResponse(BindResponse {
                result: result.clone(),
                server_sasl_creds: Some(vec![9]),
            }),
            Op::UnbindRequest,
            Op::SearchRequest(SearchRequest {
                base: String::new(),
                scope: Scope::Other(3),
                deref: DerefAliases::Always,
                size_limit: MAX_INT,
                time_limit: 30,
                types_only: true,
                filter: Filter::parse_text(
                    "(&(|(a=1)(b>=2)(c<=3))(!(d~=4))(e=x*y*z)(:1.2:=v)(f:dn:=w)(g=*))",
                )
                .unwrap(),
                attributes: vec!["cn".into(), "*".into()],
            }),
            Op::SearchResultEntry(SearchResultEntry {
                dn: "cn=x".into(),
                attributes: vec![attr.clone()],
            }),
            Op::SearchResultDone(LdapResult::new(ResultCode::SUCCESS)),
            Op::SearchResultReference(vec!["ldap://a/".into(), "ldap://b/".into()]),
            Op::ModifyRequest(ModifyRequest {
                dn: "cn=x".into(),
                changes: vec![
                    Change {
                        op: ModifyOperation::Add,
                        attribute: attr.clone(),
                    },
                    Change {
                        op: ModifyOperation::Other(3),
                        attribute: Attribute {
                            name: "n".into(),
                            values: vec![],
                        },
                    },
                ],
            }),
            Op::ModifyResponse(result.clone()),
            Op::AddRequest(AddRequest {
                dn: "cn=x".into(),
                attributes: vec![attr],
            }),
            Op::AddResponse(LdapResult::new(ResultCode::ENTRY_ALREADY_EXISTS)),
            Op::DelRequest("cn=x".into()),
            Op::DelResponse(LdapResult::new(ResultCode::NO_SUCH_OBJECT)),
            Op::ModifyDnRequest(ModifyDnRequest {
                dn: "cn=x,dc=a".into(),
                new_rdn: "cn=y".into(),
                delete_old_rdn: true,
                new_superior: Some("dc=b".into()),
            }),
            Op::ModifyDnRequest(ModifyDnRequest {
                dn: "cn=x".into(),
                new_rdn: "cn=y".into(),
                delete_old_rdn: false,
                new_superior: None,
            }),
            Op::ModifyDnResponse(LdapResult::new(ResultCode::SUCCESS)),
            Op::CompareRequest(CompareRequest {
                dn: "cn=x".into(),
                attribute: "sn".into(),
                value: b"y".to_vec(),
            }),
            Op::CompareResponse(LdapResult::new(ResultCode::COMPARE_TRUE)),
            Op::AbandonRequest(MAX_INT),
            Op::ExtendedRequest(ExtendedRequest {
                name: START_TLS.into(),
                value: None,
            }),
            Op::ExtendedRequest(ExtendedRequest {
                name: "1.2.3".into(),
                value: Some(vec![]),
            }),
            Op::ExtendedResponse(ExtendedResponse {
                result: LdapResult::new(ResultCode::UNAVAILABLE),
                name: Some(NOTICE_OF_DISCONNECTION.into()),
                value: Some(vec![1]),
            }),
            Op::ExtendedResponse(ExtendedResponse {
                result: LdapResult::new(ResultCode(4000)),
                name: None,
                value: None,
            }),
            Op::IntermediateResponse(IntermediateResponse {
                name: Some("1.2".into()),
                value: Some(vec![7]),
            }),
            Op::IntermediateResponse(IntermediateResponse {
                name: None,
                value: None,
            }),
        ];
        for (i, op) in ops.into_iter().enumerate() {
            contract::check_written(&msg(i as u32, op));
        }
    }

    #[test]
    fn rfc4515_examples() {
        let cases = [
            "(cn=Babs Jensen)",
            "(!(cn=Tim Howes))",
            "(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))",
            "(o=univ*of*mich*)",
            "(seeAlso=)",
            "(cn:caseExactMatch:=Fred Flintstone)",
            "(cn:=Betty Rubble)",
            "(sn:dn:2.4.6.8.10:=Barney Rubble)",
            "(o:dn:=Ace Industry)",
            "(:1.2.3:=Wilma Flintstone)",
            "(:DN:2.4.6.8.10:=Dino)",
            r"(o=Parens R Us \28for all your parenthetical needs\29)",
            r"(cn=*\2A*)",
            r"(filename=C:\5cMyFile)",
            r"(bin=\00\00\00\04)",
            r"(sn=Lu\c4\8di\c4\87)",
            r"(1.3.6.1.4.1.1466.0=\04\02\48\69)",
        ];
        for text in cases {
            let f = Filter::parse_text(text).unwrap_or_else(|e| panic!("{text}: {e}"));
            let again = f.to_text().unwrap();
            assert_eq!(
                Filter::parse_text(&again),
                Ok(f.clone()),
                "{text} -> {again}"
            );
            let m = msg(1, Op::SearchRequest(search(f)));
            contract::check_written(&m);
        }
        assert_eq!(
            Filter::parse_text("(cn=Babs Jensen)"),
            Ok(eq("cn", "Babs Jensen"))
        );
        assert_eq!(
            Filter::parse_text("(o=univ*of*mich*)"),
            Ok(Filter::Substrings {
                attribute: "o".into(),
                initial: Some(b"univ".to_vec()),
                any: vec![b"of".to_vec(), b"mich".to_vec()],
                last: None,
            })
        );
        assert_eq!(
            Filter::parse_text("(:DN:2.4.6.8.10:=Dino)"),
            Ok(Filter::Extensible {
                rule: Some("2.4.6.8.10".into()),
                attribute: None,
                value: b"Dino".to_vec(),
                dn_attributes: true,
            })
        );
        assert_eq!(
            Filter::parse_text(r"(bin=\00\00\00\04)"),
            Ok(Filter::Equal {
                attribute: "bin".into(),
                value: vec![0, 0, 0, 4]
            })
        );
        assert_eq!(
            Filter::parse_text(r"(sn=Lu\c4\8di\c4\87)")
                .unwrap()
                .to_text()
                .unwrap(),
            "(sn=Lučić)"
        );
        assert_eq!(
            Filter::parse_text(r"(cn=*\2A*)")
                .unwrap()
                .to_text()
                .unwrap(),
            r"(cn=*\2a*)"
        );
        assert_eq!(Filter::parse_text("(&)"), Ok(Filter::And(vec![])));
        assert_eq!(Filter::parse_text("(|)"), Ok(Filter::Or(vec![])));
        assert_eq!(
            Filter::parse_text("(cn=**)"),
            Ok(Filter::Substrings {
                attribute: "cn".into(),
                initial: None,
                any: vec![vec![]],
                last: None
            })
        );
        assert_eq!(
            Filter::parse_text("(cn;lang-en>=b)")
                .unwrap()
                .to_text()
                .unwrap(),
            "(cn;lang-en>=b)"
        );
    }

    fn search(filter: Filter) -> SearchRequest {
        SearchRequest {
            base: String::new(),
            scope: Scope::Base,
            deref: DerefAliases::Never,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter,
            attributes: vec![],
        }
    }

    #[test]
    fn filter_text_errors() {
        let bad = [
            ("", 0),
            ("cn=x", 0),
            ("(cn=x", 5),
            ("(cn=x))", 6),
            ("(cn)", 3),
            ("(=x)", 1),
            ("( cn=x)", 1),
            ("(1cn=x)", 1),
            ("(01.2=x)", 1),
            ("(cn;=x)", 1),
            ("(cn=a(b)", 5),
            (r"(cn=\4)", 4),
            (r"(cn=\zz)", 4),
            ("(cn>=a*)", 6),
            ("(cn~=*)", 5),
            ("(:=x)", 1),
            ("(cn:x:y:=v)", 1),
            ("(cn:1.:=v)", 1),
            ("(cn:dn=v)", 1),
            ("(&(a=1)x)", 7),
            ("(!)", 2),
            ("(!(a=1)(b=2))", 7),
        ];
        for (text, at) in bad {
            assert_eq!(Filter::parse_text(text), Err(Error::Syntax(at)), "{text:?}");
        }
        assert_eq!(Filter::parse_text("(cn=\0)"), Err(Error::Syntax(4)));
        let deep = "(!".repeat(MAX_FILTER_DEPTH - 1) + "(a=1)" + &")".repeat(MAX_FILTER_DEPTH - 1);
        assert!(Filter::parse_text(&deep).is_ok());
        let deeper = "(!".repeat(MAX_FILTER_DEPTH) + "(a=1)" + &")".repeat(MAX_FILTER_DEPTH);
        assert_eq!(
            Filter::parse_text(&deeper),
            Err(Error::Filter("nested too deep"))
        );
        let long = format!("(cn={})", "x".repeat(MAX_TEXT));
        assert_eq!(Filter::parse_text(&long), Err(Error::TextTooLong));
    }

    #[test]
    fn filter_writers_refuse() {
        let no_parts = Filter::Substrings {
            attribute: "cn".into(),
            initial: None,
            any: vec![],
            last: None,
        };
        assert_eq!(
            no_parts.to_text(),
            Err(Error::Filter("substring filter with no parts"))
        );
        assert_eq!(
            msg(1, Op::SearchRequest(search(no_parts))).to_bytes(),
            Err(Error::Filter("substring filter with no parts"))
        );
        let neither = Filter::Extensible {
            rule: None,
            attribute: None,
            value: vec![],
            dn_attributes: true,
        };
        assert!(matches!(neither.to_text(), Err(Error::Filter(_))));
        assert!(matches!(
            msg(1, Op::SearchRequest(search(neither))).to_bytes(),
            Err(Error::Filter(_))
        ));
        assert!(matches!(
            eq("c n", "x").to_text(),
            Err(Error::Unwritable(_))
        ));
        assert!(matches!(eq("", "x").to_text(), Err(Error::Unwritable(_))));
        let bad_rule = Filter::Extensible {
            rule: Some("1..2".into()),
            attribute: Some("cn".into()),
            value: vec![],
            dn_attributes: false,
        };
        assert!(matches!(bad_rule.to_text(), Err(Error::Unwritable(_))));
        let dn_rule = Filter::Extensible {
            rule: Some("dn".into()),
            attribute: Some("cn".into()),
            value: vec![],
            dn_attributes: false,
        };
        assert!(matches!(dn_rule.to_text(), Err(Error::Unwritable(_))));
        let other = Filter::Other {
            number: 12,
            constructed: false,
            contents: vec![1],
        };
        assert!(matches!(other.to_text(), Err(Error::Unwritable(_))));
        contract::check_written(&msg(1, Op::SearchRequest(search(other))));
        let other_low = Filter::Other {
            number: 7,
            constructed: false,
            contents: vec![],
        };
        assert!(matches!(
            msg(1, Op::SearchRequest(search(other_low))).to_bytes(),
            Err(Error::Unwritable(_))
        ));
        let mut deep = eq("a", "1");
        for _ in 0..MAX_FILTER_DEPTH {
            deep = Filter::Not(Box::new(deep));
        }
        assert_eq!(deep.to_text(), Err(Error::Filter("nested too deep")));
        assert_eq!(
            msg(1, Op::SearchRequest(search(deep))).to_bytes(),
            Err(Error::Filter("nested too deep"))
        );
        // Values with every byte are escaped so they read back.
        let all: Vec<u8> = (0..=255).collect();
        let f = Filter::Equal {
            attribute: "x".into(),
            value: all,
        };
        assert_eq!(Filter::parse_text(&f.to_text().unwrap()), Ok(f));
        let long = eq("cn", &"x".repeat(MAX_TEXT));
        assert_eq!(long.to_text(), Err(Error::TextTooLong));
    }

    #[test]
    fn empty_initial_or_final_has_no_text_form() {
        // `(cn=*)` reads back as a presence filter, and `(cn=*x*)` with no
        // initial part, so an empty initial or final part cannot be text.
        for (initial, any, last) in [
            (Some(vec![]), vec![], None),
            (None, vec![], Some(vec![])),
            (Some(vec![]), vec![b"x".to_vec()], None),
            (None, vec![b"x".to_vec()], Some(vec![])),
        ] {
            let f = Filter::Substrings {
                attribute: "cn".into(),
                initial,
                any,
                last,
            };
            assert!(matches!(f.to_text(), Err(Error::Unwritable(_))), "{f:?}");
            // The BER form still holds it.
            contract::check_written(&msg(1, Op::SearchRequest(search(f))));
        }
    }

    #[test]
    fn deepest_filters_fit_the_ber_nesting_limit() {
        // A filter MAX_FILTER_DEPTH deep, with the most deeply nested leaf
        // kinds at the bottom, in a message with controls, stays under
        // asn1::MAX_DEPTH, so the writer never writes what the reader
        // refuses.
        let leaves = [
            Filter::Substrings {
                attribute: "cn".into(),
                initial: Some(b"a".to_vec()),
                any: vec![b"b".to_vec()],
                last: Some(b"c".to_vec()),
            },
            Filter::Extensible {
                rule: Some("1.2".into()),
                attribute: Some("cn".into()),
                value: b"v".to_vec(),
                dn_attributes: true,
            },
            Filter::And(vec![]),
            Filter::Other {
                number: 40,
                constructed: true,
                contents: vec![],
            },
        ];
        for leaf in leaves {
            let mut f = leaf;
            for _ in 1..MAX_FILTER_DEPTH {
                f = Filter::Or(vec![f]);
            }
            let mut m = msg(1, Op::SearchRequest(search(f.clone())));
            m.controls.push(Control {
                oid: "1.2.3".into(),
                critical: true,
                value: Some(vec![1]),
            });
            contract::check_written(&m);
            let mut d = Stream::new(Frames::<Message>::new());
            put(&mut d, &m.to_bytes().unwrap());
            assert_eq!(d.next(), Some(Ok(m)));
            if let Ok(t) = f.to_text() {
                assert_eq!(t.parse::<Filter>(), Ok(f));
            }
        }
    }

    #[test]
    fn decoder_names_lengths_over_the_maximum_too_large() {
        let mut d = Stream::new(Frames::<Message>::new());
        put(&mut d, &[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff]);
        assert_eq!(
            d.next(),
            Some(Err(Fail::Protocol(Error::TooLarge(0x7fff_ffff + 6))))
        );
        let mut d = Stream::new(Frames::<Message>::new());
        put(&mut d, &[0x30, 0x83, 0x10, 0x00, 0x01]);
        assert_eq!(
            d.next(),
            Some(Err(Fail::Protocol(Error::TooLarge(0x10_0001 + 5))))
        );
    }

    #[test]
    fn rfc4514_examples() {
        let cases = [
            "UID=jsmith,DC=example,DC=net",
            "OU=Sales+CN=J.  Smith,DC=example,DC=net",
            r#"CN=James \"Jim\" Smith\, III,DC=example,DC=net"#,
            r"CN=Before\0dAfter,DC=example,DC=net",
            "1.3.6.1.4.1.1466.0=#04024869,DC=example,DC=com",
            r"CN=Lu\C4\8Di\C4\87",
            "",
        ];
        for text in cases {
            let dn = Dn::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"));
            let again = dn.to_text().unwrap();
            assert_eq!(Dn::parse(&again), Ok(dn), "{text} -> {again}");
        }
        let dn = Dn::parse("OU=Sales+CN=J.  Smith,DC=example,DC=net").unwrap();
        assert_eq!(dn.0.len(), 3);
        assert_eq!(dn.0[0].0.len(), 2);
        assert_eq!(dn.0[0].0[1].value, AttributeValue::Text("J.  Smith".into()));
        let dn = Dn::parse(r#"CN=James \"Jim\" Smith\, III,DC=example,DC=net"#).unwrap();
        assert_eq!(
            dn.0[0].0[0].value,
            AttributeValue::Text(r#"James "Jim" Smith, III"#.into())
        );
        assert_eq!(
            dn.to_text().unwrap(),
            r#"CN=James \"Jim\" Smith\, III,DC=example,DC=net"#
        );
        let dn = Dn::parse("1.3.6.1.4.1.1466.0=#04024869").unwrap();
        assert_eq!(
            dn.0[0].0[0].value,
            AttributeValue::Ber(vec![0x04, 0x02, 0x48, 0x69])
        );
        assert_eq!(dn.to_text().unwrap(), "1.3.6.1.4.1.1466.0=#04024869");
        let dn: Dn = r"CN=Lu\C4\8Di\C4\87".parse().unwrap();
        assert_eq!(dn.0[0].0[0].value, AttributeValue::Text("Lučić".into()));
        assert_eq!(
            Dn::parse(r"cn=\ a\ ").unwrap().0[0].0[0].value,
            AttributeValue::Text(" a ".into())
        );
        assert_eq!(
            Dn::parse("cn=").unwrap().0[0].0[0].value,
            AttributeValue::Text(String::new())
        );
        assert_eq!(
            Dn::parse("cn=a=b#c").unwrap().0[0].0[0].value,
            AttributeValue::Text("a=b#c".into())
        );
    }

    #[test]
    fn dn_writer_escapes() {
        let ava = |v: &str| {
            Dn(vec![Rdn(vec![Ava {
                attribute: "cn".into(),
                value: AttributeValue::Text(v.into()),
            }])])
        };
        assert_eq!(ava(" #a, b+c ").to_text().unwrap(), r"cn=\ #a\, b\+c\ ");
        assert_eq!(ava("#x").to_text().unwrap(), r"cn=\#x");
        assert_eq!(ava(" ").to_text().unwrap(), r"cn=\ ");
        assert_eq!(
            ava("a\0b;<>\\\"").to_text().unwrap(),
            r#"cn=a\00b\;\<\>\\\""#
        );
        for v in [" #a, b+c ", "#x", " ", "a\0b;<>\\\"", "", "é ", "  "] {
            let dn = ava(v);
            assert_eq!(Dn::parse(&dn.to_text().unwrap()), Ok(dn));
        }
        assert!(matches!(
            Dn(vec![Rdn(vec![])]).to_text(),
            Err(Error::Unwritable(_))
        ));
        let bad_type = Dn(vec![Rdn(vec![Ava {
            attribute: "c n".into(),
            value: AttributeValue::Text("x".into()),
        }])]);
        assert!(matches!(bad_type.to_text(), Err(Error::Unwritable(_))));
        let empty_ber = Dn(vec![Rdn(vec![Ava {
            attribute: "cn".into(),
            value: AttributeValue::Ber(vec![]),
        }])]);
        assert!(matches!(empty_ber.to_text(), Err(Error::Unwritable(_))));
        assert_eq!(
            ava(&"x".repeat(MAX_TEXT)).to_text(),
            Err(Error::TextTooLong)
        );
    }

    #[test]
    fn dn_text_errors() {
        let bad = [
            ("cn", 2),
            ("=x", 0),
            ("cn=x,", 5),
            (",cn=x", 0),
            ("cn=x+", 5),
            ("c n=x", 0),
            ("cn =x", 0),
            ("cn= x", 3),
            ("cn=x ", 4),
            ("cn=a;b", 4),
            ("cn=a\"b", 4),
            ("cn=<", 3),
            ("cn=a>", 4),
            (r"cn=\", 3),
            (r"cn=\q", 3),
            (r"cn=\4", 3),
            ("cn=#", 4),
            ("cn=#0", 4),
            ("cn=#zz", 4),
            ("cn=x,o", 6),
        ];
        for (text, at) in bad {
            assert_eq!(Dn::parse(text), Err(Error::Syntax(at)), "{text:?}");
        }
        assert_eq!(Dn::parse("cn=a\0"), Err(Error::Syntax(4)));
        assert_eq!(Dn::parse(r"cn=\ff"), Err(Error::Utf8));
        assert_eq!(
            Dn::parse(&format!("cn={}", "x".repeat(MAX_TEXT))),
            Err(Error::TextTooLong)
        );
    }

    #[test]
    fn message_errors() {
        let ok = msg(7, Op::DelRequest("cn=x".into())).to_bytes().unwrap();
        // Not a SEQUENCE; bytes after it; an indefinite length.
        assert!(matches!(
            Message::parse(&[0x31, 0x00]),
            Err(Error::Ber(asn1::Error::Unexpected { .. }))
        ));
        let mut trailing = ok.clone();
        trailing.push(0);
        assert_eq!(
            Message::parse(&trailing),
            Err(Error::Ber(asn1::Error::Trailing))
        );
        let mut indefinite = vec![0x30, 0x80];
        indefinite.extend_from_slice(&ok[2..]);
        indefinite.extend_from_slice(&[0, 0]);
        assert_eq!(
            Message::parse(&indefinite),
            Err(Error::Ber(asn1::Error::Indefinite))
        );
        // A message ID over maxInt, or negative.
        assert_eq!(
            Message::parse(&[0x30, 0x08, 0x02, 0x04, 0x80, 0, 0, 0, 0x42, 0x00]),
            Err(Error::Range("messageID"))
        );
        assert_eq!(
            Message::parse(&[0x30, 0x05, 0x02, 0x01, 0xff, 0x42, 0x00]),
            Err(Error::Range("messageID"))
        );
        assert_eq!(
            Message::parse(&[0x30, 0x09, 0x02, 0x05, 0x00, 0x80, 0, 0, 0, 0x42, 0x00]),
            Err(Error::Range("messageID"))
        );
        // An unknown operation, and a known one in the wrong form.
        assert_eq!(
            Message::parse(&[0x30, 0x05, 0x02, 0x01, 0x01, 0x5e, 0x00]),
            Err(Error::Operation(Tag::application(30)))
        );
        assert_eq!(
            Message::parse(&[0x30, 0x05, 0x02, 0x01, 0x01, 0x62, 0x00]),
            Err(Error::Operation(Tag::application(2).as_constructed()))
        );
        assert_eq!(
            Message::parse(&[0x30, 0x05, 0x02, 0x01, 0x01, 0x04, 0x00]),
            Err(Error::Operation(Tag::OCTET_STRING))
        );
        // An unbind with contents.
        assert_eq!(
            Message::parse(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x42, 0x01, 0x00]),
            Err(Error::Ber(asn1::Error::Null))
        );
        // A DN that is not UTF-8.
        assert_eq!(
            Message::parse(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x4a, 0x01, 0xff]),
            Err(Error::Utf8)
        );
        // A constructed string, as a delete's DN and as a bind's name.
        assert_eq!(
            Message::parse(&[
                0x30, 0x09, 0x02, 0x01, 0x01, 0x6a, 0x04, 0x04, 0x02, b'c', b'n'
            ]),
            Err(Error::Operation(Tag::application(10).as_constructed()))
        );
        assert!(matches!(
            Message::parse(&[
                0x30, 0x0e, 0x02, 0x01, 0x01, 0x60, 0x09, 0x02, 0x01, 0x03, 0x24, 0x02, 0x04, 0x00,
                0x80, 0x00
            ]),
            Err(Error::Ber(asn1::Error::Unexpected { .. }))
        ));
        // Bind version 0 and 128.
        assert_eq!(
            Message::parse(&[
                0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x00, 0x04, 0x00, 0x80, 0x00
            ]),
            Err(Error::Range("version"))
        );
        assert_eq!(
            Message::parse(&[
                0x30, 0x0d, 0x02, 0x01, 0x01, 0x60, 0x08, 0x02, 0x02, 0x00, 0x80, 0x04, 0x00, 0x80,
                0x00
            ]),
            Err(Error::Range("version"))
        );
        // A simple bind in constructed form, and SASL in primitive form.
        assert!(matches!(
            Message::parse(&[
                0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0xa0, 0x00
            ]),
            Err(Error::Ber(asn1::Error::Unexpected { .. }))
        ));
        assert!(matches!(
            Message::parse(&[
                0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x83, 0x00
            ]),
            Err(Error::Ber(asn1::Error::Unexpected { .. }))
        ));
        // derefAliases 4, and a size limit of -1.
        let s = msg(1, Op::SearchRequest(search(Filter::Present("a".into()))))
            .to_bytes()
            .unwrap();
        // The search's fields start at byte 7: base (2 bytes), scope (3), deref (3), size (3), time (3), typesOnly (3).
        let mut bad = s.clone();
        assert_eq!(bad[14], 0x00);
        bad[14] = 4;
        assert_eq!(Message::parse(&bad), Err(Error::Range("derefAliases")));
        let mut bad = s.clone();
        bad[17] = 0xff;
        assert_eq!(Message::parse(&bad), Err(Error::Range("sizeLimit")));
        // A filter of the wrong class.
        let mut bad = s.clone();
        assert_eq!(bad[24], 0x87);
        bad[24] = 0x04;
        assert!(matches!(
            Message::parse(&bad),
            Err(Error::Ber(asn1::Error::Unexpected { .. }))
        ));
        // Present in constructed form.
        let mut bad = s.clone();
        bad[24] = 0xa7;
        assert!(matches!(Message::parse(&bad), Err(Error::Ber(_))));
        // Too large.
        assert!(matches!(
            Message::parse(&vec![0; MAX_MESSAGE + 1]),
            Err(Error::TooLarge(_))
        ));
    }

    /// A search request message with this filter's BER as its filter.
    fn search_with_filter_bytes(filter: &[u8]) -> Vec<u8> {
        let mut op = vec![
            0x04, 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            0x01, 0x01, 0x00,
        ];
        op.extend_from_slice(filter);
        op.extend_from_slice(&[0x30, 0x00]);
        let mut body = vec![0x02, 0x01, 0x01];
        let mut w = W::default();
        w.put(Tag::application(3).as_constructed(), &op).unwrap();
        body.extend_from_slice(&w.out);
        let mut w = W::default();
        w.put(Tag::SEQUENCE, &body).unwrap();
        w.out
    }

    #[test]
    fn filter_ber_errors() {
        let parse = |f: &[u8]| match Message::parse(&search_with_filter_bytes(f))? {
            Message {
                op: Op::SearchRequest(s),
                ..
            } => Ok(s.filter),
            _ => unreachable!(),
        };
        // Substrings: none, initial after any, any after final, two finals.
        let subs = |parts: &[u8]| {
            let mut v = vec![
                0xa4,
                (parts.len() + 5) as u8,
                0x04,
                0x01,
                b'c',
                0x30,
                parts.len() as u8,
            ];
            v.extend_from_slice(parts);
            v
        };
        assert_eq!(
            parse(&subs(&[])),
            Err(Error::Filter("substring filter with no parts"))
        );
        assert_eq!(
            parse(&subs(&[0x81, 0x00, 0x80, 0x00])),
            Err(Error::Filter("initial substring not first"))
        );
        assert_eq!(
            parse(&subs(&[0x82, 0x00, 0x81, 0x00])),
            Err(Error::Filter("substring after the final part"))
        );
        assert_eq!(
            parse(&subs(&[0x82, 0x00, 0x82, 0x00])),
            Err(Error::Filter("substring after the final part"))
        );
        assert!(matches!(parse(&subs(&[0x83, 0x00])), Err(Error::Ber(_))));
        assert_eq!(
            parse(&subs(&[0x80, 0x01, b'a', 0x81, 0x00, 0x82, 0x01, b'z'])),
            Ok(Filter::Substrings {
                attribute: "c".into(),
                initial: Some(b"a".to_vec()),
                any: vec![vec![]],
                last: Some(b"z".to_vec())
            })
        );
        // Extensible with neither rule nor type; with both and dnAttributes.
        assert_eq!(
            parse(&[0xa9, 0x02, 0x83, 0x00]),
            Err(Error::Filter("extensible match with neither type nor rule"))
        );
        assert_eq!(
            parse(&[
                0xa9, 0x0b, 0x81, 0x01, b'r', 0x82, 0x01, b't', 0x83, 0x00, 0x84, 0x01, 0xff
            ]),
            Ok(Filter::Extensible {
                rule: Some("r".into()),
                attribute: Some("t".into()),
                value: vec![],
                dn_attributes: true
            })
        );
        // An explicit FALSE for dnAttributes reads, and is left out on writing.
        assert_eq!(
            parse(&[0xa9, 0x07, 0x82, 0x00, 0x83, 0x00, 0x84, 0x01, 0x00]),
            Ok(Filter::Extensible {
                rule: None,
                attribute: Some(String::new()),
                value: vec![],
                dn_attributes: false
            })
        );
        // Not with two filters, and with none.
        assert_eq!(
            parse(&[0xa2, 0x04, 0x87, 0x00, 0x87, 0x00]),
            Err(Error::Ber(asn1::Error::Trailing))
        );
        assert_eq!(parse(&[0xa2, 0x00]), Err(Error::Ber(asn1::Error::Empty)));
        // An extension choice, kept as it is, and written in the same form.
        for form in [0x8a, 0xaa] {
            let b = search_with_filter_bytes(&[form, 0x02, 0x05, 0x00]);
            let m = Message::parse(&b).unwrap();
            let Op::SearchRequest(s) = &m.op else {
                unreachable!()
            };
            assert_eq!(
                s.filter,
                Filter::Other {
                    number: 10,
                    constructed: form == 0xaa,
                    contents: vec![0x05, 0x00]
                }
            );
            assert_eq!(m.to_bytes().unwrap(), b);
        }
        // Too deep.
        let mut f = vec![0x87, 0x00];
        for _ in 0..MAX_FILTER_DEPTH {
            let mut g = vec![0xa2, f.len() as u8];
            g.extend_from_slice(&f);
            f = g;
        }
        assert_eq!(parse(&f), Err(Error::Filter("nested too deep")));
        assert!(parse(&f[2..]).is_ok());
    }

    #[test]
    fn writers_refuse_out_of_range() {
        assert_eq!(
            msg(MAX_INT + 1, Op::UnbindRequest).to_bytes(),
            Err(Error::Range("messageID"))
        );
        assert_eq!(
            msg(1, Op::AbandonRequest(MAX_INT + 1)).to_bytes(),
            Err(Error::Range("messageID"))
        );
        let bind = |version| {
            Op::BindRequest(BindRequest {
                version,
                name: String::new(),
                auth: Authentication::Simple(vec![]),
            })
        };
        assert_eq!(msg(1, bind(0)).to_bytes(), Err(Error::Range("version")));
        assert_eq!(msg(1, bind(128)).to_bytes(), Err(Error::Range("version")));
        let mut s = search(Filter::Present("a".into()));
        s.size_limit = MAX_INT + 1;
        assert_eq!(
            msg(1, Op::SearchRequest(s.clone())).to_bytes(),
            Err(Error::Range("sizeLimit"))
        );
        s.size_limit = 0;
        s.time_limit = u32::MAX;
        assert_eq!(
            msg(1, Op::SearchRequest(s)).to_bytes(),
            Err(Error::Range("timeLimit"))
        );
        let other = |number| {
            Op::BindRequest(BindRequest {
                version: 3,
                name: String::new(),
                auth: Authentication::Other {
                    number,
                    constructed: false,
                    contents: vec![],
                },
            })
        };
        assert!(matches!(
            msg(1, other(0)).to_bytes(),
            Err(Error::Unwritable(_))
        ));
        assert!(matches!(
            msg(1, other(3)).to_bytes(),
            Err(Error::Unwritable(_))
        ));
        contract::check_written(&msg(1, other(u32::MAX)));
        // Too large: the writer stops at MAX_MESSAGE.
        let big = msg(1, Op::DelRequest("x".repeat(MAX_MESSAGE)));
        assert!(matches!(big.to_bytes(), Err(Error::TooLarge(_))));
        // The largest that fits is written and read back.
        let fits = msg(1, Op::DelRequest("x".repeat(MAX_MESSAGE - 13)));
        let b = fits.to_bytes().unwrap();
        assert_eq!(b.len(), MAX_MESSAGE);
        assert_eq!(Message::parse(&b), Ok(fits));
    }

    #[test]
    fn result_codes() {
        assert_eq!(ResultCode::NO_SUCH_OBJECT.to_string(), "noSuchObject");
        assert_eq!(ResultCode(9).to_string(), "result code 9");
        assert_eq!(ResultCode::OTHER.name(), Some("other"));
        for c in [0u32, 1, 80, 4000, u32::MAX] {
            contract::check_written(&msg(1, Op::DelResponse(LdapResult::new(ResultCode(c)))));
        }
        for n in 0..4 {
            assert_eq!(DerefAliases::from_code(n).map(DerefAliases::code), Some(n));
        }
        assert_eq!(DerefAliases::from_code(4), None);
        for n in 0..10 {
            assert_eq!(Scope::from_code(n).code(), n);
            assert_eq!(ModifyOperation::from_code(n).code(), n);
        }
    }

    fn samples() -> Vec<Vec<u8>> {
        let mut g = Lcg::new(7);
        let mut out = vec![
            msg(
                1,
                Op::SearchRequest(search(Filter::parse_text("(&(cn=a*b)(!(x~=1)))").unwrap())),
            )
            .to_bytes()
            .unwrap(),
        ];
        for _ in 0..40 {
            out.push(make_message(&mut g).to_bytes().unwrap());
        }
        out
    }

    #[test]
    fn every_truncated_prefix() {
        for bytes in samples() {
            for n in 0..bytes.len() {
                assert!(
                    Message::parse(&bytes[..n]).is_err(),
                    "{n} of {}",
                    bytes.len()
                );
                let mut d = Stream::new(Frames::<Message>::new());
                put(&mut d, &bytes[..n]);
                assert_eq!(d.next(), None, "{n} of {}", bytes.len());
                assert_eq!(d.buffered(), n);
            }
        }
        for text in [
            "(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))",
            "(sn:dn:2.4.6.8.10:=Barney Rubble)",
        ] {
            for n in 0..text.len() {
                assert!(Filter::parse_text(&text[..n]).is_err(), "{:?}", &text[..n]);
            }
        }
        // A DN cut anywhere is a DN or an error; it never panics.
        let dn = r#"CN=James \"Jim\" Smith\, III,1.2.3=#0401ff,O=x"#;
        for n in 0..dn.len() {
            let _ = Dn::parse(&dn[..n]);
        }
    }

    #[test]
    fn decoder_splits_a_stream() {
        let a = msg(1, Op::DelRequest("cn=a".into())).to_bytes().unwrap();
        let b = msg(2, Op::UnbindRequest).to_bytes().unwrap();
        let stream: Vec<u8> = a.iter().chain(&b).copied().collect();
        let mut d = Stream::new(Frames::<Message>::new());
        let mut got = Vec::new();
        for byte in chunks(&stream, &[1]) {
            put(&mut d, byte);
            while let Some(m) = d.next() {
                got.push(m.unwrap().id);
            }
        }
        assert_eq!(got, [1, 2]);
        assert_eq!(d.buffered(), 0);
        // A broken stream stays broken.
        put(&mut d, &[0x31, 0x00]);
        let e = d.next();
        assert!(matches!(
            e,
            Some(Err(Fail::Protocol(Error::Ber(
                asn1::Error::Unexpected { .. }
            ))))
        ));
        put(&mut d, &a);
        assert_eq!(d.next(), None);
        assert_eq!(d.failed(), e.as_ref().and_then(|r| r.as_ref().err()));
        // A bad message inside a good frame breaks it too.
        let mut d = Stream::new(Frames::<Message>::new());
        put(&mut d, &[0x30, 0x03, 0x02, 0x01, 0x01]);
        put(&mut d, &a);
        assert_eq!(
            d.next(),
            Some(Err(Fail::Protocol(Error::Ber(asn1::Error::Empty))))
        );
        assert_eq!(d.next(), None);
        // Indefinite lengths, and lengths over the limit, are known from the header.
        let mut d = Stream::new(Frames::<Message>::new());
        put(&mut d, &[0x30, 0x80]);
        assert_eq!(
            d.next(),
            Some(Err(Fail::Protocol(Error::Ber(asn1::Error::Indefinite))))
        );
        let mut d = Stream::new(Frames::<Message>::with_limit(100));
        assert_eq!(d.decoder().limit(), 100);
        put(&mut d, &[0x30, 0x81, 0x80]);
        assert_eq!(d.next(), Some(Err(Fail::Protocol(Error::TooLarge(131)))));
        let mut d = Stream::new(Frames::<Message>::with_limit(usize::MAX));
        assert_eq!(d.decoder().limit(), MAX_MESSAGE);
        put(&mut d, &[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff]);
        assert_eq!(
            d.next(),
            Some(Err(Fail::Protocol(Error::TooLarge(0x7fff_ffff + 6))))
        );
    }

    #[test]
    fn decoder_takes_many_small_messages_in_linear_time() {
        assert_linear(
            "decoder_takes_many_small_messages_in_linear_time",
            rounds(50_000),
            |size| {
                let one = msg(1, Op::UnbindRequest).to_bytes().unwrap();
                let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * size).collect();
                let mut d = Stream::new(Frames::<Message>::new());
                let mut rest = &stream[..];
                let mut n = 0;
                while !rest.is_empty() {
                    rest = &rest[d.push(rest)..];
                    while let Some(m) = d.next() {
                        m.unwrap();
                        n += 1;
                    }
                }
                assert_eq!(n, size);
                assert_eq!(d.buffered(), 0);
            },
        );
    }

    #[test]
    fn decoder_holds_at_most_its_limit() {
        // Noise is taken only up to the limit, and fails at its header.
        let mut d = Stream::new(Frames::<Message>::with_limit(100));
        assert_eq!(d.push(&vec![0; rounds(100_000)]), 100);
        assert!(d.buffered() <= 100);
        assert!(matches!(d.next(), Some(Err(_))));
        let held = d.buffered();
        assert_eq!(d.push(&[0; 10]), 10);
        assert_eq!(d.buffered(), held);
        // Many whole messages: it takes what fits, and more once they are
        // taken out.
        let one = msg(1, Op::UnbindRequest).to_bytes().unwrap();
        let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * 50).collect();
        let mut d = Stream::new(Frames::<Message>::with_limit(20));
        let (mut rest, mut n) = (&stream[..], 0);
        while !rest.is_empty() {
            let took = d.push(rest);
            assert!(d.buffered() <= 20);
            rest = &rest[took..];
            while let Some(m) = d.next() {
                assert_eq!(m, Ok(msg(1, Op::UnbindRequest)));
                n += 1;
            }
        }
        assert_eq!(n, 50);
        // A tiny limit still sees a header, and refuses the message.
        let mut d = Stream::new(Frames::<Message>::with_limit(0));
        assert_eq!(d.push(&one), one.len());
        assert_eq!(
            d.next(),
            Some(Err(Fail::Protocol(Error::TooLarge(one.len()))))
        );
    }

    #[test]
    fn datagram_with_several_messages() {
        let entry = msg(
            3,
            Op::SearchResultEntry(SearchResultEntry {
                dn: String::new(),
                attributes: vec![Attribute {
                    name: "netlogon".into(),
                    values: vec![vec![0x17, 0x00]],
                }],
            }),
        );
        let done = msg(
            3,
            Op::SearchResultDone(LdapResult::new(ResultCode::SUCCESS)),
        );
        let mut b = entry.to_bytes().unwrap();
        b.extend_from_slice(&done.to_bytes().unwrap());
        assert_eq!(Message::parse_datagram(&b), Ok(vec![entry.clone(), done]));
        assert_eq!(Message::parse(&b), Err(Error::Ber(asn1::Error::Trailing)));
        let one = entry.to_bytes().unwrap();
        assert_eq!(Message::parse_datagram(&one), Ok(vec![entry]));
        assert!(Message::parse_datagram(&[]).is_err());
        b.push(0);
        assert!(Message::parse_datagram(&b).is_err());
    }

    #[test]
    fn unknown_trailing_components_are_ignored() {
        // RFC 4511 section 4: a BindResponse with an unknown [9] after its
        // fields reads, and is written without it.
        let b = [
            0x30, 0x0e, 0x02, 0x01, 0x01, 0x61, 0x09, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
            0x89, 0x00,
        ];
        let want = msg(
            1,
            Op::BindResponse(BindResponse {
                result: LdapResult::new(ResultCode::SUCCESS),
                server_sasl_creds: None,
            }),
        );
        assert_eq!(Message::parse(&b), Ok(want));
        // In the envelope, a control, a search and a filter's AVA too.
        let mut m = msg(2, Op::SearchRequest(search(eq("cn", "x"))));
        m.controls.push(Control {
            oid: "1.2.3".into(),
            critical: false,
            value: None,
        });
        let plain = m.to_bytes().unwrap();
        // Inserts `9f 64 00` ([100], empty) at the end of each element
        // whose header starts at an offset in `add`, and fixes the lengths
        // of every element in `fix`, which holds those and the ones around
        // them. Every length here is one byte.
        let grown = |add: &[usize], fix: &[usize]| {
            let end = |o: usize| o + 2 + usize::from(plain[o + 1]);
            let mut b = plain.clone();
            let mut at: Vec<usize> = add.iter().map(|&o| end(o)).collect();
            at.sort_unstable_by(|x, y| y.cmp(x));
            for &p in &at {
                b.splice(p..p, [0x9f, 0x64, 0x00]);
            }
            for &o in fix {
                let inside = at.iter().filter(|&&p| p > o && p <= end(o)).count();
                // Elements before `o` that grew move it along.
                let shift = 3 * at.iter().filter(|&&p| p <= o).count();
                b[o + shift + 1] += 3 * inside as u8;
            }
            b
        };
        // Offsets: 0 the envelope, 5 the search, 24 the AVA, 35 the
        // controls and 37 the control.
        assert_eq!(plain[24], 0xa3);
        assert_eq!(plain[37], 0x30);
        for (add, fix) in [
            (&[0][..], &[0][..]),
            (&[0, 5], &[0, 5]),
            (&[0, 5, 24], &[0, 5, 24]),
            (&[37], &[0, 35, 37]),
        ] {
            let b = grown(add, fix);
            assert_eq!(Message::parse(&b).as_ref(), Ok(&m), "{add:?} {b:02x?}");
        }
        // In a list of controls it is not an extension.
        assert!(Message::parse(&grown(&[35], &[0, 35])).is_err());
        // A known tag after the last field is still an error.
        let mut dup = plain.clone();
        dup.extend_from_slice(&[0x02, 0x01, 0x01]);
        dup[1] += 3;
        assert_eq!(Message::parse(&dup), Err(Error::Ber(asn1::Error::Trailing)));
    }

    #[test]
    fn size_one_or_more() {
        // An added attribute needs a value; a reference and a referral need
        // a URI (RFC 4511 sections 4.1.10, 4.5.3 and 4.7).
        let add = msg(
            1,
            Op::AddRequest(AddRequest {
                dn: "cn=x".into(),
                attributes: vec![Attribute {
                    name: "cn".into(),
                    values: vec![],
                }],
            }),
        );
        assert!(matches!(add.to_bytes(), Err(Error::Unwritable(_))));
        // 30 0e 02 01 01 68 09 04 01 x 30 04 30 02 04 00 ... built by hand.
        let add_bytes = [
            0x30, 0x13, 0x02, 0x01, 0x01, 0x68, 0x0e, 0x04, 0x04, b'c', b'n', b'=', b'x', 0x30,
            0x06, 0x30, 0x04, 0x04, 0x00, 0x31, 0x00,
        ];
        assert!(Message::parse(&add_bytes).is_err());
        let empty_ref = [0x30, 0x05, 0x02, 0x01, 0x01, 0x73, 0x00];
        assert!(Message::parse(&empty_ref).is_err());
        assert!(matches!(
            msg(1, Op::SearchResultReference(vec![])).to_bytes(),
            Err(Error::Unwritable(_))
        ));
        let empty_referral = [
            0x30, 0x0e, 0x02, 0x01, 0x01, 0x65, 0x09, 0x0a, 0x01, 0x0a, 0x04, 0x00, 0x04, 0x00,
            0xa3, 0x00,
        ];
        assert!(Message::parse(&empty_referral).is_err());
        // A search result entry's attribute may have none.
        contract::check_written(&msg(
            1,
            Op::SearchResultEntry(SearchResultEntry {
                dn: "cn=x".into(),
                attributes: vec![Attribute {
                    name: "cn".into(),
                    values: vec![],
                }],
            }),
        ));
    }

    #[test]
    fn other_codes_of_named_values_are_refused() {
        let mut s = search(Filter::Present("a".into()));
        for n in 0..=2 {
            s.scope = Scope::Other(n);
            assert!(matches!(
                msg(1, Op::SearchRequest(s.clone())).to_bytes(),
                Err(Error::Unwritable(_))
            ));
            let m = msg(
                1,
                Op::ModifyRequest(ModifyRequest {
                    dn: String::new(),
                    changes: vec![Change {
                        op: ModifyOperation::Other(n),
                        attribute: Attribute {
                            name: "a".into(),
                            values: vec![],
                        },
                    }],
                }),
            );
            assert!(matches!(m.to_bytes(), Err(Error::Unwritable(_))));
        }
        s.scope = Scope::Other(3);
        contract::check_written(&msg(1, Op::SearchRequest(s)));
    }

    #[test]
    fn a_rule_named_dn_with_no_type() {
        // RFC 4515: with no type, `:dn` before `:=` can only be the rule.
        let f = Filter::Extensible {
            rule: Some("dn".into()),
            attribute: None,
            value: b"x".to_vec(),
            dn_attributes: false,
        };
        assert_eq!(Filter::parse_text("(:dn:=x)"), Ok(f.clone()));
        assert_eq!(f.to_text().unwrap(), "(:dn:=x)");
        // With a type, `(cn:dn:=x)` is the flag, so that form is refused.
        let typed = Filter::Extensible {
            rule: Some("dn".into()),
            attribute: Some("cn".into()),
            value: b"x".to_vec(),
            dn_attributes: false,
        };
        assert!(matches!(typed.to_text(), Err(Error::Unwritable(_))));
    }

    #[test]
    fn text_writers_stop_at_the_limit() {
        // Each value is longer than MAX_TEXT once escaped; the writer stops
        // before its text passes MAX_TEXT, not after.
        let nul = vec![0u8; MAX_TEXT];
        for f in [
            Filter::Equal {
                attribute: "cn".into(),
                value: nul.clone(),
            },
            Filter::Substrings {
                attribute: "cn".into(),
                initial: None,
                any: vec![nul[..MAX_TEXT / 4].to_vec(); 8],
                last: None,
            },
        ] {
            let mut out = String::new();
            assert_eq!(f.write_text(&mut out, 1), Err(Error::TextTooLong));
            assert!(out.len() <= MAX_TEXT, "{}", out.len());
        }
        let dn = |value| {
            Dn(vec![Rdn(vec![Ava {
                attribute: "cn".into(),
                value,
            }])])
        };
        for d in [
            dn(AttributeValue::Text(",".repeat(MAX_TEXT))),
            dn(AttributeValue::Ber(nul)),
        ] {
            let mut out = String::new();
            assert_eq!(d.write_text(&mut out), Err(Error::TextTooLong));
            assert!(out.len() <= MAX_TEXT, "{}", out.len());
        }
    }

    fn nonempty_bytes(g: &mut Lcg, max: usize) -> Vec<u8> {
        let mut bytes = g.bytes(max);
        bytes.push(g.next() as u8);
        bytes
    }

    fn attribute_name(g: &mut Lcg) -> String {
        const NAMES: &[&str] = &[
            "cn",
            "objectClass",
            "o",
            "1.2.840.113549.1.9.1",
            "cn;lang-en",
            "x-y",
        ];
        NAMES[g.index(NAMES.len())].to_string()
    }

    fn value_text(g: &mut Lcg, max: usize) -> String {
        let mut text = g.text(max);
        // Keep UTF-8 and NUL in the filter and DN value tests.
        if g.coin() {
            text.push(if g.coin() { 'é' } else { '\0' });
        }
        text
    }

    /// Mixes LDAP text with arbitrary bytes to cover escaping and binary values.
    fn filter_value(g: &mut Lcg, max: usize) -> Vec<u8> {
        if g.coin() {
            value_text(g, max).into_bytes()
        } else {
            g.bytes(max)
        }
    }

    #[test]
    fn generated_text_covers_ldap_escape_characters() {
        let mut g = Lcg::new(0x1da9);
        let mut dn_chars = String::new();
        let mut filter_chars = String::new();
        for _ in 0..1024 {
            let text = value_text(&mut g, 6);
            dn_chars.push_str(&text);
            let dn = Dn(vec![Rdn(vec![Ava {
                attribute: "cn".into(),
                value: AttributeValue::Text(text),
            }])]);
            assert_eq!(Dn::parse(&dn.to_text().unwrap()), Ok(dn));

            let value = filter_value(&mut g, 6);
            if let Ok(text) = std::str::from_utf8(&value) {
                filter_chars.push_str(text);
            }
            let filter = Filter::Equal {
                attribute: "cn".into(),
                value,
            };
            assert_eq!(Filter::parse_text(&filter.to_text().unwrap()), Ok(filter));
        }
        for ch in [
            '\\', '\0', 'é', '*', '(', ')', '"', ',', '+', '<', '>', ';', '=', '#',
        ] {
            assert!(dn_chars.contains(ch), "DN generator missed {ch:?}");
            assert!(filter_chars.contains(ch), "filter generator missed {ch:?}");
        }
    }

    /// A filter text can write: names that are names, no empty initial or
    /// final parts, no extension choices.
    fn make_filter(g: &mut Lcg, depth: usize) -> Filter {
        let leaf = depth >= 5 || g.below(3) == 0;
        let k = if leaf { 3 + g.below(7) } else { g.below(3) };
        match k {
            0 => Filter::And((0..g.below(4)).map(|_| make_filter(g, depth + 1)).collect()),
            1 => Filter::Or((0..g.below(4)).map(|_| make_filter(g, depth + 1)).collect()),
            2 => Filter::Not(Box::new(make_filter(g, depth + 1))),
            3 => Filter::Equal {
                attribute: attribute_name(g),
                value: filter_value(g, 6),
            },
            4 => {
                let initial = if g.coin() {
                    Some(nonempty_bytes(g, 4))
                } else {
                    None
                };
                let last = if g.coin() {
                    Some(nonempty_bytes(g, 4))
                } else {
                    None
                };
                let n = if initial.is_none() && last.is_none() {
                    1 + g.below(3)
                } else {
                    g.below(3)
                };
                Filter::Substrings {
                    attribute: attribute_name(g),
                    initial,
                    any: (0..n).map(|_| filter_value(g, 3)).collect(),
                    last,
                }
            }
            5 => Filter::GreaterOrEqual {
                attribute: attribute_name(g),
                value: filter_value(g, 6),
            },
            6 => Filter::LessOrEqual {
                attribute: attribute_name(g),
                value: filter_value(g, 6),
            },
            7 => Filter::Present(attribute_name(g)),
            8 => Filter::Approx {
                attribute: attribute_name(g),
                value: filter_value(g, 6),
            },
            _ => {
                let rule = if g.coin() {
                    Some(["2.5.13.2", "caseExactMatch"][g.index(2)].to_string())
                } else {
                    None
                };
                let attribute = if rule.is_none() || g.coin() {
                    Some(attribute_name(g))
                } else {
                    None
                };
                Filter::Extensible {
                    rule,
                    attribute,
                    value: filter_value(g, 6),
                    dn_attributes: g.coin(),
                }
            }
        }
    }

    fn make_attribute(g: &mut Lcg) -> Attribute {
        Attribute {
            name: value_text(g, 5),
            values: (0..g.below(3)).map(|_| g.bytes(5)).collect(),
        }
    }

    fn make_result(g: &mut Lcg) -> LdapResult {
        LdapResult {
            code: ResultCode(g.next() as u32 % 100),
            matched_dn: value_text(g, 5),
            message: value_text(g, 8),
            referral: (0..g.below(3)).map(|_| value_text(g, 5)).collect(),
        }
    }

    fn make_message(g: &mut Lcg) -> Message {
        let op = match g.below(21) {
            0 => Op::BindRequest(BindRequest {
                version: 1 + g.below(127) as u8,
                name: value_text(g, 6),
                auth: match g.below(3) {
                    0 => Authentication::Simple(g.bytes(6)),
                    1 => Authentication::Sasl {
                        mechanism: value_text(g, 5),
                        credentials: g.coin().then(|| g.bytes(6)),
                    },
                    _ => Authentication::Other {
                        number: [1, 2, 4, 9, 40, 1000][g.index(6)],
                        constructed: g.coin(),
                        contents: g.bytes(4),
                    },
                },
            }),
            1 => Op::BindResponse(BindResponse {
                result: make_result(g),
                server_sasl_creds: g.coin().then(|| g.bytes(6)),
            }),
            2 => Op::UnbindRequest,
            3 => Op::SearchRequest(SearchRequest {
                base: value_text(g, 6),
                scope: Scope::from_code(g.below(5) as u32),
                deref: DerefAliases::from_code(g.below(4) as u32).unwrap(),
                size_limit: g.next() as u32 % (MAX_INT + 1),
                time_limit: g.below(1000) as u32,
                types_only: g.coin(),
                filter: if g.below(8) == 0 {
                    Filter::Other {
                        number: 10 + g.below(50) as u32,
                        constructed: g.coin(),
                        contents: g.bytes(3),
                    }
                } else {
                    make_filter(g, 1)
                },
                attributes: (0..g.below(3)).map(|_| attribute_name(g)).collect(),
            }),
            4 => Op::SearchResultEntry(SearchResultEntry {
                dn: value_text(g, 6),
                attributes: (0..g.below(3)).map(|_| make_attribute(g)).collect(),
            }),
            5 => Op::SearchResultDone(make_result(g)),
            6 => Op::SearchResultReference((0..1 + g.below(3)).map(|_| value_text(g, 6)).collect()),
            7 => Op::ModifyRequest(ModifyRequest {
                dn: value_text(g, 6),
                changes: (0..g.below(3))
                    .map(|_| Change {
                        op: ModifyOperation::from_code(g.below(5) as u32),
                        attribute: make_attribute(g),
                    })
                    .collect(),
            }),
            8 => Op::ModifyResponse(make_result(g)),
            9 => Op::AddRequest(AddRequest {
                dn: value_text(g, 6),
                attributes: (0..g.below(3))
                    .map(|_| {
                        let mut a = make_attribute(g);
                        a.values.push(g.bytes(5));
                        a
                    })
                    .collect(),
            }),
            10 => Op::AddResponse(make_result(g)),
            11 => Op::DelRequest(value_text(g, 8)),
            12 => Op::DelResponse(make_result(g)),
            13 => Op::ModifyDnRequest(ModifyDnRequest {
                dn: value_text(g, 6),
                new_rdn: value_text(g, 4),
                delete_old_rdn: g.coin(),
                new_superior: g.coin().then(|| value_text(g, 6)),
            }),
            14 => Op::ModifyDnResponse(make_result(g)),
            15 => Op::CompareRequest(CompareRequest {
                dn: value_text(g, 6),
                attribute: value_text(g, 3),
                value: g.bytes(4),
            }),
            16 => Op::CompareResponse(make_result(g)),
            17 => Op::AbandonRequest(g.next() as u32 % (MAX_INT + 1)),
            18 => Op::ExtendedRequest(ExtendedRequest {
                name: value_text(g, 6),
                value: g.coin().then(|| g.bytes(6)),
            }),
            19 => Op::ExtendedResponse(ExtendedResponse {
                result: make_result(g),
                name: g.coin().then(|| value_text(g, 6)),
                value: g.coin().then(|| g.bytes(6)),
            }),
            _ => Op::IntermediateResponse(IntermediateResponse {
                name: g.coin().then(|| value_text(g, 6)),
                value: g.coin().then(|| g.bytes(6)),
            }),
        };
        let controls = (0..g.below(3))
            .map(|_| Control {
                oid: value_text(g, 5),
                critical: g.coin(),
                value: g.coin().then(|| g.bytes(6)),
            })
            .collect();
        Message {
            id: g.next() as u32 % (MAX_INT + 1),
            op,
            controls,
        }
    }

    fn make_dn(g: &mut Lcg) -> Dn {
        Dn((0..g.below(4))
            .map(|_| {
                Rdn((0..1 + g.below(2))
                    .map(|_| {
                        let attribute = ["cn", "O", "2.5.4.3", "x-1"][g.index(4)].to_string();
                        let value = if g.below(4) == 0 {
                            AttributeValue::Ber(nonempty_bytes(g, 4))
                        } else {
                            AttributeValue::Text(value_text(g, 6))
                        };
                        Ava { attribute, value }
                    })
                    .collect())
            })
            .collect())
    }

    fn check_bytes(data: &[u8]) {
        if let Ok(m) = Message::parse(data) {
            let b = m.to_bytes().unwrap();
            assert!(b.len() <= data.len());
            assert_eq!(Message::parse(&b), Ok(m.clone()));
            if let Op::SearchRequest(s) = &m.op
                && let Ok(t) = s.filter.to_text()
            {
                assert_eq!(Filter::parse_text(&t).as_ref(), Ok(&s.filter), "{t}");
            }
        }
        let whole = decode_all(Frames::<Message>::new, data);
        contract::check_decode_with_alloc_limit(Frames::<Message>::new, data, 2 * MAX_MESSAGE);
        contract::check_wire::<Message>(data);
        for m in &whole.0 {
            assert_eq!(Message::parse(&m.to_bytes().unwrap()).as_ref(), Ok(m));
        }
    }

    fn check_text(text: &str) {
        if let Ok(f) = Filter::parse_text(text) {
            let t = f.to_text().unwrap();
            assert!(t.len() <= text.len());
            assert_eq!(Filter::parse_text(&t), Ok(f.clone()), "{text:?} -> {t:?}");
            let m = msg(1, Op::SearchRequest(search(f)));
            contract::check_written(&m);
        }
        if let Ok(dn) = Dn::parse(text) {
            let t = dn.to_text().unwrap();
            assert!(t.len() <= text.len());
            assert_eq!(Dn::parse(&t), Ok(dn), "{text:?} -> {t:?}");
        }
    }

    #[test]
    fn lcg_fuzz() {
        const ROUNDS: usize = 10_000;
        let mut g = Lcg::new(0x1da9);
        let mut stream = Vec::new();
        for _ in 0..ROUNDS {
            // A generated message reads back as itself.
            let m = make_message(&mut g);
            let b = m.to_bytes().unwrap();
            assert_eq!(Message::parse(&b).as_ref(), Ok(&m));
            stream.extend_from_slice(&b);
            // A generated filter and DN read back from text.
            let f = make_filter(&mut g, 1);
            let t = f.to_text().unwrap();
            assert_eq!(Filter::parse_text(&t).as_ref(), Ok(&f), "{t}");
            let dn = make_dn(&mut g);
            let t = dn.to_text().unwrap();
            assert_eq!(Dn::parse(&t).as_ref(), Ok(&dn), "{t}");
            // The same bytes, broken: changed, cut, grown, or noise.
            let mut bad = b.clone();
            if g.below(4) == 0 {
                bad = g.bytes(40);
            } else {
                for _ in 0..1 + g.index(3) {
                    mutate(&mut g, &mut bad);
                }
            }
            check_bytes(&bad);
            check_bytes(&b);
            // Text made of the characters filters and DNs use.
            const T: &[u8] = b"()&|!=*~<>:\\0123456789abcdefABCDEFdnDN.;-, +#\"cnou";
            let n = g.index(30);
            let text: String = (0..n).map(|_| char::from(T[g.index(T.len())])).collect();
            check_text(&text);
            let mut tf = f.to_text().unwrap().into_bytes();
            if !tf.is_empty() {
                let i = g.index(tf.len());
                tf[i] = T[g.index(T.len())];
            }
            check_text(&String::from_utf8_lossy(&tf));
            mutate(&mut g, &mut tf);
            check_text(&String::from_utf8_lossy(&tf));
        }
        // Check the generated stream across chunk boundaries and at EOF.
        contract::check_decode_with_alloc_limit(Frames::<Message>::new, &stream, 2 * MAX_MESSAGE);
        let (all, err) = decode_all(Frames::<Message>::new, &stream);
        assert_eq!(all.len(), ROUNDS);
        assert_eq!(err, None);
    }

    #[test]
    fn codec_frames_obey_small_limits_and_report_once() {
        use fictionet::stdlib::codec::{Fail, Stream};
        use fictionet::stdlib::test_support::contract;
        let bytes = Message {
            id: 1,
            op: Op::UnbindRequest,
            controls: Vec::new(),
        }
        .to_bytes()
        .unwrap();
        for limit in 0..=16 {
            assert_eq!(Frames::<Message>::with_limit(limit).capacity(), 16);
            contract::check_decode_with_alloc_limit(
                || Frames::<Message>::with_limit(limit),
                &bytes,
                2 * Frames::<Message>::with_limit(limit).capacity(),
            );
        }
        assert_eq!(
            Frames::<Message>::with_limit(usize::MAX).limit(),
            MAX_MESSAGE
        );
        let mut stream = Stream::new(Frames::<Message>::new());
        assert_eq!(stream.push(&[0x30, 0x80]), 2);
        assert_eq!(
            stream.next(),
            Some(Err(Fail::Protocol(Error::Ber(asn1::Error::Indefinite))))
        );
        assert_eq!(stream.next(), None);
        assert_eq!(stream.buffered(), 2);
    }

    #[test]
    fn codec_message_writer_rolls_back() {
        use fictionet::stdlib::codec::Wire;
        use fictionet::stdlib::test_support::contract;
        let mut message = Message {
            id: 1,
            op: Op::UnbindRequest,
            controls: Vec::new(),
        };
        contract::check_wire_value(&message);
        contract::check_wire::<Message>(&message.to_bytes().unwrap());
        message.id = MAX_INT + 1;
        let mut out = vec![42];
        assert!(message.write(&mut out).is_err());
        assert_eq!(out, [42]);
        contract::check_wire_value(&message);
    }
}
