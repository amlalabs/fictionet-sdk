//! DCE/RPC over connections: reading and writing PDUs, with no I/O.
//!
//! DCE/RPC is the remote procedure call protocol under most of Windows
//! administration: the endpoint mapper on TCP port 135, services on the
//! dynamic ports it hands out, and the named pipes of SMB (`\pipe\samr`,
//! `\pipe\lsarpc`, `\pipe\svcctl` and others). A client binds to an
//! interface, named by a UUID and a version, and agrees on a transfer
//! syntax, usually NDR. It then sends requests, each naming an operation
//! by number (the opnum), and the server sends back responses or faults.
//! Every PDU starts with a 16-byte header: the version, the packet type,
//! flags, the data representation (the byte order of the integers that
//! follow), the fragment length, the length of the authentication
//! verifier, and a call ID that ties a response to its request. This
//! module follows The Open Group's DCE 1.1 RPC specification (C706),
//! chapter 12, and Microsoft's extensions in MS-RPCE, section 2.2.2.
//!
//! Nothing here reads a socket. A world that plays an RPC server feeds the
//! bytes it reads from a connection or a pipe to a [`Decoder`], gets
//! [`Pdu`]s back, and writes the bytes of its answers. A large call comes
//! in several fragments, which a [`Reassembler`] joins, and
//! [`Pdu::fragments`] splits an answer the same way. Which interfaces
//! exist, and what each operation does, is up to world code. Stub data,
//! the NDR-encoded arguments and results, stays as bytes.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. A header that cannot be read breaks the stream, since the next
//! PDU cannot be found. A body that cannot be read is an [`Error`] for
//! that PDU alone, and the stream goes on. Writers return an
//! [`EncodeError`] rather than write bytes a reader would refuse or read
//! back as something else.
//!
//! ```
//! use fictionet::stdlib::dcerpc::{
//!     Bind, BindAck, Body, Context, ContextResult, Decoder, EPMAPPER, NDR, Pdu, reason,
//! };
//!
//! /// An endpoint mapper that accepts NDR for its own interface only.
//! fn answer(pdu: &Pdu) -> Option<Pdu> {
//!     let Body::Bind(bind) = &pdu.body else { return None };
//!     let results = bind
//!         .contexts
//!         .iter()
//!         .map(|c| {
//!             if c.abstract_syntax != EPMAPPER {
//!                 ContextResult::reject(reason::ABSTRACT_SYNTAX_NOT_SUPPORTED)
//!             } else if c.transfer_syntaxes.contains(&NDR) {
//!                 ContextResult::accept(NDR)
//!             } else {
//!                 ContextResult::reject(reason::PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED)
//!             }
//!         })
//!         .collect();
//!     let ack = BindAck {
//!         max_xmit_frag: 4280,
//!         max_recv_frag: 4280,
//!         assoc_group: 0x1234,
//!         secondary_address: b"135\0".to_vec(),
//!         results,
//!     };
//!     Some(pdu.reply(Body::BindAck(ack)))
//! }
//!
//! let bind = Pdu::new(
//!     1,
//!     Body::Bind(Bind {
//!         max_xmit_frag: 5840,
//!         max_recv_frag: 5840,
//!         assoc_group: 0,
//!         contexts: vec![Context { id: 0, abstract_syntax: EPMAPPER, transfer_syntaxes: vec![NDR] }],
//!     }),
//! );
//! let bytes = bind.to_bytes().unwrap();
//! // The header, 12 bytes of bind fields, and one context of 44 bytes.
//! assert_eq!(bytes.len(), 72);
//! assert_eq!(bytes[..4], [5, 0, 11, 3]);
//!
//! let mut decoder = Decoder::new();
//! // The bind arrives in two pieces.
//! assert_eq!(decoder.feed(&bytes[..30]), 30);
//! assert!(decoder.next_pdu().is_none());
//! assert_eq!(decoder.feed(&bytes[30..]), 42);
//! let pdu = decoder.next_pdu().unwrap().unwrap();
//! assert_eq!(pdu, bind);
//!
//! let reply = answer(&pdu).unwrap().to_bytes().unwrap();
//! // Type 12 is bind_ack. The header, 8 bytes of fields, the address
//! // "135" with its length, 2 bytes of padding, and one result.
//! assert_eq!(reply[2], 12);
//! assert_eq!(reply.len(), 16 + 8 + 2 + 4 + 2 + 4 + 24);
//! ```

use super::codec::{Decode, Step, Wire};

/// The TCP port of the endpoint mapper.
pub const PORT: u16 = 135;
/// The major version of the connection-oriented protocol.
pub const VERSION: u8 = 5;
/// The length of the common header, before the body.
pub const HEADER_LEN: usize = 16;
/// The length of the authentication trailer before the verifier's value:
/// type, level, padding length, a reserved byte and the context ID.
pub const SEC_TRAILER_LEN: usize = 8;
/// The longest fragment: the fragment length is 16 bits.
pub const MAX_FRAG: usize = 65535;
/// The most bytes a [`Decoder`] holds that have not been taken out: one
/// longest fragment.
pub const MAX_BUFFERED: usize = MAX_FRAG;
/// The most stub data a [`Reassembler`] joins for one call.
pub const MAX_STUB: usize = 4 << 20;
/// The most fragments [`Pdu::fragments`] makes of one PDU. The peer picks
/// the fragment size it takes, so this keeps a tiny one from making a
/// world build millions of fragments.
pub const MAX_FRAGMENTS: usize = 1 << 16;
/// What the writer pads the stub data of a request, response or fault to,
/// before an authentication trailer, as MS-RPCE asks. Other PDUs pad the
/// trailer to 4 bytes from the start of the PDU, as C706 asks.
pub const AUTH_PAD_ALIGN: usize = 16;

/// Packet types. Types 1 and 4 to 10 belong to the connectionless
/// protocol, which this module does not read.
pub mod ptype {
    /// A call: an operation's input arguments.
    pub const REQUEST: u8 = 0;
    /// A call's output arguments.
    pub const RESPONSE: u8 = 2;
    /// A call that failed.
    pub const FAULT: u8 = 3;
    /// Opens an association and offers presentation contexts.
    pub const BIND: u8 = 11;
    /// Accepts an association and answers each context.
    pub const BIND_ACK: u8 = 12;
    /// Refuses an association.
    pub const BIND_NAK: u8 = 13;
    /// Offers more presentation contexts on an open association.
    pub const ALTER_CONTEXT: u8 = 14;
    /// Answers an alter_context.
    pub const ALTER_CONTEXT_RESP: u8 = 15;
    /// The third leg of a three-way authentication (MS-RPCE).
    pub const AUTH3: u8 = 16;
    /// Asks the client to close the connection.
    pub const SHUTDOWN: u8 = 17;
    /// Asks the server to cancel a call in progress.
    pub const CO_CANCEL: u8 = 18;
    /// Tells the server the client has abandoned a call.
    pub const ORPHANED: u8 = 19;
}

/// Bits of the header's flags byte.
pub mod flags {
    /// The first fragment of a call.
    pub const FIRST_FRAG: u8 = 0x01;
    /// The last fragment of a call.
    pub const LAST_FRAG: u8 = 0x02;
    /// A cancel was pending at the sender (C706).
    pub const PENDING_CANCEL: u8 = 0x04;
    /// In a bind or alter_context, the client can sign headers (MS-RPCE).
    /// The same bit as [`PENDING_CANCEL`].
    pub const SUPPORT_HEADER_SIGN: u8 = 0x04;
    /// Reserved.
    pub const RESERVED_1: u8 = 0x08;
    /// The sender multiplexes calls on the connection.
    pub const CONC_MPX: u8 = 0x10;
    /// In a fault, the call was not run.
    pub const DID_NOT_EXECUTE: u8 = 0x20;
    /// The call has "maybe" semantics: no response is wanted.
    pub const MAYBE: u8 = 0x40;
    /// A request carries an object UUID.
    pub const OBJECT_UUID: u8 = 0x80;
}

/// Bits of a fault's flags byte, the byte after its cancel count, which
/// C706 reserves and MS-RPCE 2.2.2.8 gives a meaning.
pub mod fault_flags {
    /// The stub data is RPC extended error information (MS-EERR).
    pub const EXTENDED_ERROR: u8 = 0x01;
}

/// Answers to one presentation context in a bind_ack.
pub mod result {
    /// The context is accepted.
    pub const ACCEPTANCE: u16 = 0;
    /// The server's application refused the context.
    pub const USER_REJECTION: u16 = 1;
    /// The RPC runtime refused the context.
    pub const PROVIDER_REJECTION: u16 = 2;
    /// An answer to a bind-time feature negotiation (MS-RPCE).
    pub const NEGOTIATE_ACK: u16 = 3;
}

/// Why a presentation context was refused.
pub mod reason {
    /// No reason given.
    pub const NOT_SPECIFIED: u16 = 0;
    /// The server does not have the interface.
    pub const ABSTRACT_SYNTAX_NOT_SUPPORTED: u16 = 1;
    /// The server reads none of the transfer syntaxes offered.
    pub const PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED: u16 = 2;
    /// The server has too many contexts.
    pub const LOCAL_LIMIT_EXCEEDED: u16 = 3;
}

/// Why a bind_nak refused an association.
pub mod reject {
    /// No reason given.
    pub const REASON_NOT_SPECIFIED: u16 = 0;
    /// The server is too busy.
    pub const TEMPORARY_CONGESTION: u16 = 1;
    /// The server has too many associations.
    pub const LOCAL_LIMIT_EXCEEDED: u16 = 2;
    /// The address called is unknown.
    pub const CALLED_PADDR_UNKNOWN: u16 = 3;
    /// The server does not speak this protocol version.
    pub const PROTOCOL_VERSION_NOT_SUPPORTED: u16 = 4;
    /// The default context is not supported.
    pub const DEFAULT_CONTEXT_NOT_SUPPORTED: u16 = 5;
    /// The server could not read the PDU.
    pub const USER_DATA_NOT_READABLE: u16 = 6;
    /// No presentation service access point is free.
    pub const NO_PSAP_AVAILABLE: u16 = 7;
    /// The authentication type is unknown (MS-RPCE).
    pub const AUTHENTICATION_TYPE_NOT_RECOGNIZED: u16 = 8;
    /// The authentication value did not check (MS-RPCE).
    pub const INVALID_CHECKSUM: u16 = 9;
}

/// Status codes a fault carries (C706 appendix E, MS-RPCE 2.2.2.11).
pub mod status {
    /// The call was refused for lack of rights.
    pub const ACCESS_DENIED: u32 = 0x0000_0005;
    /// The stub data could not be read (`nca_s_fault_ndr`).
    pub const FAULT_NDR: u32 = 0x0000_06f7;
    /// The interface has no operation with this opnum.
    pub const OP_RNG_ERROR: u32 = 0x1c01_0002;
    /// The server does not have the interface.
    pub const UNK_IF: u32 = 0x1c01_0003;
    /// The PDU broke the protocol.
    pub const PROTO_ERROR: u32 = 0x1c01_000b;
    /// The output arguments are too large.
    pub const OUT_ARGS_TOO_BIG: u32 = 0x1c01_0013;
    /// The server is too busy.
    pub const SERVER_TOO_BUSY: u32 = 0x1c01_0014;
    /// The server does not support a type in the call.
    pub const UNSUPPORTED_TYPE: u32 = 0x1c01_0017;
    /// The call divided an integer by zero.
    pub const FAULT_INT_DIV_BY_ZERO: u32 = 0x1c00_0001;
    /// The call touched a bad address.
    pub const FAULT_ADDR_ERROR: u32 = 0x1c00_0002;
    /// A union's tag was not one of its arms.
    pub const FAULT_INVALID_TAG: u32 = 0x1c00_0006;
    /// An array's bound was out of range.
    pub const FAULT_INVALID_BOUND: u32 = 0x1c00_0007;
    /// The call was cancelled.
    pub const FAULT_CANCEL: u32 = 0x1c00_000d;
    /// An unspecified fault.
    pub const FAULT_UNSPEC: u32 = 0x1c00_0012;
    /// The server ran out of memory.
    pub const FAULT_REMOTE_NO_MEMORY: u32 = 0x1c00_001b;
    /// A context handle did not match.
    pub const FAULT_CONTEXT_MISMATCH: u32 = 0x1c00_001a;
}

/// Authentication types, from MS-RPCE 2.2.1.1.7.
pub mod auth_type {
    /// No authentication.
    pub const NONE: u8 = 0x00;
    /// SPNEGO, which picks Kerberos or NTLM.
    pub const GSS_NEGOTIATE: u8 = 0x09;
    /// NTLM.
    pub const WINNT: u8 = 0x0a;
    /// Schannel (TLS).
    pub const GSS_SCHANNEL: u8 = 0x0e;
    /// Kerberos.
    pub const GSS_KERBEROS: u8 = 0x10;
    /// The Netlogon secure channel.
    pub const NETLOGON: u8 = 0x44;
    /// The default type.
    pub const DEFAULT: u8 = 0xff;
}

/// Authentication levels, from MS-RPCE 2.2.1.1.8.
pub mod auth_level {
    /// The default level.
    pub const DEFAULT: u8 = 0;
    /// No protection.
    pub const NONE: u8 = 1;
    /// Authenticated when the association opens.
    pub const CONNECT: u8 = 2;
    /// Authenticated at the start of each call.
    pub const CALL: u8 = 3;
    /// Each PDU is authenticated.
    pub const PKT: u8 = 4;
    /// Each PDU is signed.
    pub const PKT_INTEGRITY: u8 = 5;
    /// Each PDU is signed and its stub data encrypted.
    pub const PKT_PRIVACY: u8 = 6;
}

/// A UUID, kept in the byte order its string form reads in. On the wire
/// its first three fields follow the data representation's byte order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Uuid(pub [u8; 16]);

impl Uuid {
    /// The UUID of all zeros.
    pub const NIL: Uuid = Uuid([0; 16]);

    /// The UUID with these fields: `time_low`, `time_mid`,
    /// `time_hi_and_version`, then the last 8 bytes as written.
    pub const fn from_fields(a: u32, b: u16, c: u16, d: [u8; 8]) -> Uuid {
        let a = a.to_be_bytes();
        let b = b.to_be_bytes();
        let c = c.to_be_bytes();
        Uuid([a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
    }

    /// Reads the usual string form, such as
    /// `8a885d04-1ceb-11c9-9fe8-08002b104860`, in either case. Anything
    /// else gives `None`.
    pub fn parse(s: &str) -> Option<Uuid> {
        let s = s.as_bytes();
        if s.len() != 36 {
            return None;
        }
        let mut out = [0u8; 16];
        let mut n = 0;
        let mut i = 0;
        while i < 36 {
            if matches!(i, 8 | 13 | 18 | 23) {
                if s[i] != b'-' {
                    return None;
                }
                i += 1;
                continue;
            }
            let hi = hex(s[i])?;
            let lo = hex(*s.get(i + 1)?)?;
            out[n] = hi << 4 | lo;
            n += 1;
            i += 2;
        }
        Some(Uuid(out))
    }
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl std::fmt::Display for Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// An interface or transfer syntax: a UUID and a version. On the wire the
/// version is one 32-bit number in the data representation's byte order,
/// with the major version in the low 16 bits (C706 12.6.3.1). With
/// little-endian integers that is the major then the minor as two 16-bit
/// numbers, as MS-RPCE writes it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SyntaxId {
    /// The interface's or syntax's UUID.
    pub uuid: Uuid,
    /// The major version.
    pub major: u16,
    /// The minor version.
    pub minor: u16,
}

impl SyntaxId {
    /// The empty syntax a refused context is answered with.
    pub const NIL: SyntaxId = SyntaxId { uuid: Uuid::NIL, major: 0, minor: 0 };
}

/// The NDR transfer syntax, version 2.0.
pub const NDR: SyntaxId = SyntaxId {
    uuid: Uuid::from_fields(0x8a88_5d04, 0x1ceb, 0x11c9, [0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60]),
    major: 2,
    minor: 0,
};

/// The NDR64 transfer syntax, version 1.0 (MS-RPCE).
pub const NDR64: SyntaxId = SyntaxId {
    uuid: Uuid::from_fields(0x7171_0533, 0xbeba, 0x4937, [0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36]),
    major: 1,
    minor: 0,
};

/// The endpoint mapper's interface, version 3.0.
pub const EPMAPPER: SyntaxId = SyntaxId {
    uuid: Uuid::from_fields(0xe1af_8308, 0x5d1f, 0x11c9, [0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa]),
    major: 3,
    minor: 0,
};

/// The data representation: the byte order of integers, the character set
/// and the float format, kept as its four bytes so it reads back the
/// same. Only the integer byte order changes how this module reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataRep(pub [u8; 4]);

impl DataRep {
    /// Little-endian integers, ASCII and IEEE floats, as Windows sends.
    pub const LITTLE_ENDIAN: DataRep = DataRep([0x10, 0, 0, 0]);
    /// Big-endian integers, ASCII and IEEE floats.
    pub const BIG_ENDIAN: DataRep = DataRep([0x00, 0, 0, 0]);

    /// Whether integers are little-endian: `None` for an integer format
    /// other than 0 (big-endian) or 1 (little-endian).
    pub fn little_endian(self) -> Option<bool> {
        match self.0[0] >> 4 {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    /// The character set: 0 for ASCII, 1 for EBCDIC.
    pub fn character(self) -> u8 {
        self.0[0] & 0x0f
    }

    /// The float format: 0 IEEE, 1 VAX, 2 Cray, 3 IBM.
    pub fn float(self) -> u8 {
        self.0[1]
    }
}

impl Default for DataRep {
    fn default() -> DataRep {
        DataRep::LITTLE_ENDIAN
    }
}

/// An authentication verifier: the trailer at the end of a PDU and the
/// security provider's token. The padding before it and the reserved
/// byte are not kept; the writer works the padding out, as zeros.
/// [`Decoder::next_frame`] gives a PDU's bytes as they came, padding
/// included, for a world that checks or decrypts a verifier. To sign one
/// it writes, a world writes the PDU with a token of the right length,
/// then fills the token in over the last bytes (and, for privacy,
/// encrypts the stub data and padding in place).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Auth {
    /// The authentication type, one of [`auth_type`].
    pub kind: u8,
    /// The authentication level, one of [`auth_level`].
    pub level: u8,
    /// Which security context on the connection this PDU uses.
    pub context_id: u32,
    /// The token: 1 to 65535 bytes, since an empty one is no verifier.
    pub value: Vec<u8>,
}

/// One presentation context a bind or alter_context offers: an interface
/// and the transfer syntaxes the client can use for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    /// The context's ID, which requests name.
    pub id: u16,
    /// The interface.
    pub abstract_syntax: SyntaxId,
    /// The transfer syntaxes, at most 255.
    pub transfer_syntaxes: Vec<SyntaxId>,
}

/// The body of a bind or alter_context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bind {
    /// The largest fragment the client sends.
    pub max_xmit_frag: u16,
    /// The largest fragment the client takes.
    pub max_recv_frag: u16,
    /// The association group to join, or 0 for a new one.
    pub assoc_group: u32,
    /// The contexts offered, at most 255.
    pub contexts: Vec<Context>,
}

/// The answer to one presentation context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextResult {
    /// One of [`result`].
    pub result: u16,
    /// One of [`reason`], when the context was refused.
    pub reason: u16,
    /// The transfer syntax accepted, or [`SyntaxId::NIL`].
    pub transfer_syntax: SyntaxId,
}

impl ContextResult {
    /// A context accepted with `syntax`.
    pub fn accept(syntax: SyntaxId) -> ContextResult {
        ContextResult { result: result::ACCEPTANCE, reason: reason::NOT_SPECIFIED, transfer_syntax: syntax }
    }

    /// A context the runtime refused, for `reason`.
    pub fn reject(reason: u16) -> ContextResult {
        ContextResult { result: result::PROVIDER_REJECTION, reason, transfer_syntax: SyntaxId::NIL }
    }
}

/// The body of a bind_ack or alter_context_resp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindAck {
    /// The largest fragment the server sends.
    pub max_xmit_frag: u16,
    /// The largest fragment the server takes.
    pub max_recv_frag: u16,
    /// The association group the connection is in.
    pub assoc_group: u32,
    /// The secondary address: the server's port or pipe name as bytes,
    /// with its terminating zero, such as `b"135\0"` or
    /// `b"\\PIPE\\samr\0"`. Often empty in an alter_context_resp.
    pub secondary_address: Vec<u8>,
    /// One answer per context offered, at most 255.
    pub results: Vec<ContextResult>,
}

/// The body of a bind_nak.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindNak {
    /// One of [`reject`].
    pub reason: u16,
    /// The protocol versions the server speaks, major and minor, at most
    /// 255. A bind_nak that stops after its reason reads as none.
    pub versions: Vec<(u8, u8)>,
}

/// What a PDU carries, by packet type.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // each variant's doc names its fields
pub enum Body {
    /// Type 0: a call of operation `opnum` on context `context_id`, with
    /// an object UUID if the [`flags::OBJECT_UUID`] flag is set.
    /// `alloc_hint` is the stub size the sender expects in all, or 0.
    Request { alloc_hint: u32, context_id: u16, opnum: u16, object: Option<Uuid>, stub: Vec<u8> },
    /// Type 2: a call's results.
    Response { alloc_hint: u32, context_id: u16, cancel_count: u8, stub: Vec<u8> },
    /// Type 3: a call failed with `status`, one of [`status`].
    /// `fault_flags` holds bits of [`fault_flags`]: with
    /// [`fault_flags::EXTENDED_ERROR`] set the stub data is extended error
    /// information (MS-RPCE 2.2.2.8), and otherwise it is C706's fault
    /// stub data, which MS-RPCE peers ignore.
    Fault { alloc_hint: u32, context_id: u16, cancel_count: u8, fault_flags: u8, status: u32, stub: Vec<u8> },
    /// Type 11.
    Bind(Bind),
    /// Type 12.
    BindAck(BindAck),
    /// Type 13. It never has an auth verifier.
    BindNak(BindNak),
    /// Type 14.
    AlterContext(Bind),
    /// Type 15.
    AlterContextResp(BindAck),
    /// Type 16. Its body is 4 bytes of padding, which are not kept, and
    /// it always has an auth verifier.
    Auth3,
    /// Type 17. It never has an auth verifier.
    Shutdown,
    /// Type 18.
    Cancel,
    /// Type 19.
    Orphaned,
}

impl Body {
    /// The packet type, one of [`ptype`].
    pub fn ptype(&self) -> u8 {
        match self {
            Body::Request { .. } => ptype::REQUEST,
            Body::Response { .. } => ptype::RESPONSE,
            Body::Fault { .. } => ptype::FAULT,
            Body::Bind(_) => ptype::BIND,
            Body::BindAck(_) => ptype::BIND_ACK,
            Body::BindNak(_) => ptype::BIND_NAK,
            Body::AlterContext(_) => ptype::ALTER_CONTEXT,
            Body::AlterContextResp(_) => ptype::ALTER_CONTEXT_RESP,
            Body::Auth3 => ptype::AUTH3,
            Body::Shutdown => ptype::SHUTDOWN,
            Body::Cancel => ptype::CO_CANCEL,
            Body::Orphaned => ptype::ORPHANED,
        }
    }

    /// The stub data of a request, response or fault.
    pub fn stub(&self) -> Option<&[u8]> {
        match self {
            Body::Request { stub, .. } | Body::Response { stub, .. } | Body::Fault { stub, .. } => Some(stub),
            _ => None,
        }
    }

    /// A copy with any stub data left out.
    fn clone_without_stub(&self) -> Body {
        match self {
            Body::Request { alloc_hint, context_id, opnum, object, .. } => Body::Request {
                alloc_hint: *alloc_hint,
                context_id: *context_id,
                opnum: *opnum,
                object: *object,
                stub: Vec::new(),
            },
            Body::Response { alloc_hint, context_id, cancel_count, .. } => Body::Response {
                alloc_hint: *alloc_hint,
                context_id: *context_id,
                cancel_count: *cancel_count,
                stub: Vec::new(),
            },
            Body::Fault { alloc_hint, context_id, cancel_count, fault_flags, status, .. } => Body::Fault {
                alloc_hint: *alloc_hint,
                context_id: *context_id,
                cancel_count: *cancel_count,
                fault_flags: *fault_flags,
                status: *status,
                stub: Vec::new(),
            },
            other => other.clone(),
        }
    }

    fn stub_mut(&mut self) -> Option<&mut Vec<u8>> {
        match self {
            Body::Request { stub, .. } | Body::Response { stub, .. } | Body::Fault { stub, .. } => Some(stub),
            _ => None,
        }
    }
}

/// One connection-oriented PDU: the header's fields, the body and the
/// authentication verifier. The header's fragment and auth lengths are
/// worked out from the rest, so neither is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pdu {
    /// The minor version: 0 or 1.
    pub version_minor: u8,
    /// Bits from [`flags`]. In a request, [`flags::OBJECT_UUID`] must
    /// agree with whether the body has an object UUID.
    pub flags: u8,
    /// The data representation, which sets the byte order of every
    /// integer in the PDU.
    pub drep: DataRep,
    /// Ties a response to its request, and the fragments of a call.
    pub call_id: u32,
    /// What the PDU carries.
    pub body: Body,
    /// The authentication verifier, if any.
    pub auth: Option<Auth>,
}

/// Why bytes are not a PDU this module reads. The first three break the
/// stream, since the end of the PDU cannot be found; see
/// [`Error::breaks_stream`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The version was not 5.0 or 5.1.
    Version {
        /// The major version read.
        major: u8,
        /// The minor version read.
        minor: u8,
    },
    /// The data representation's integer format was not 0 or 1, so the
    /// lengths cannot be read.
    IntegerRep(u8),
    /// The fragment length was shorter than the header.
    FragLength(u16),
    /// A packet type this module does not read: connectionless or unknown.
    Type(u8),
    /// The auth length leaves no room for the trailer before it, or the
    /// packet type cannot have it: an auth3 needs a verifier (MS-RPCE
    /// 2.2.2.10), and a bind_nak or shutdown has none (C706 12.6.4).
    AuthLength(u16),
    /// The padding before the trailer runs back into the header, or the
    /// trailer does not start on a 4-byte boundary (C706 13.2.6.1).
    AuthPad(u8),
    /// The body is shorter than its fields, or its counts run past it.
    Truncated,
    /// A bind_ack's secondary address does not end with its terminating
    /// zero (C706 12.6.3.1).
    Address,
}

impl Error {
    /// Whether the stream cannot be read past this error.
    pub fn breaks_stream(self) -> bool {
        matches!(self, Error::Version { .. } | Error::IntegerRep(_) | Error::FragLength(_))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Version { major, minor } => write!(f, "DCE/RPC version {major}.{minor}, not 5.0 or 5.1"),
            Error::IntegerRep(r) => write!(f, "integer representation {r}, not 0 or 1"),
            Error::FragLength(n) => write!(f, "fragment length {n}, shorter than the header"),
            Error::Type(t) => write!(f, "packet type {t} is not a connection-oriented PDU"),
            Error::AuthLength(n) => write!(f, "auth length {n} does not fit in the fragment or the packet type"),
            Error::AuthPad(n) => write!(f, "auth padding of {n} bytes runs into the header or misaligns the trailer"),
            Error::Truncated => f.write_str("the PDU body is shorter than its fields"),
            Error::Address => f.write_str("the secondary address does not end with a zero byte"),
        }
    }
}

impl std::error::Error for Error {}

/// Why a writer refused a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// A minor version other than 0 or 1.
    Version(u8),
    /// A data representation whose integer format is not 0 or 1.
    IntegerRep(u8),
    /// A request whose [`flags::OBJECT_UUID`] flag disagrees with its
    /// object UUID.
    ObjectFlag,
    /// An auth verifier with an empty value, which reads as none.
    EmptyAuth,
    /// More than 255 contexts, transfer syntaxes, results or versions.
    Count,
    /// A PDU longer than [`MAX_FRAG`], or a field longer than its length
    /// can say.
    TooLong,
    /// Fragments too small for the request or response header.
    FragSize,
    /// Splitting a PDU that has an auth verifier, which each fragment
    /// needs its own of.
    FragmentAuth,
    /// An auth3 with no auth verifier, or a bind_nak or shutdown with one.
    Auth,
    /// A nonempty secondary address without its terminating zero.
    Address,
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::Version(m) => write!(f, "minor version {m}, not 0 or 1"),
            EncodeError::IntegerRep(r) => write!(f, "integer representation {r}, not 0 or 1"),
            EncodeError::ObjectFlag => f.write_str("the object UUID flag disagrees with the object UUID"),
            EncodeError::EmptyAuth => f.write_str("an auth verifier needs a value"),
            EncodeError::Count => f.write_str("more than 255 items in a list"),
            EncodeError::TooLong => f.write_str("longer than one fragment may be"),
            EncodeError::FragSize => f.write_str("fragments too small for the header or too many"),
            EncodeError::FragmentAuth => f.write_str("a PDU with an auth verifier cannot be split"),
            EncodeError::Auth => f.write_str("this packet type cannot have, or must have, an auth verifier"),
            EncodeError::Address => f.write_str("the secondary address does not end with a zero byte"),
        }
    }
}

impl std::error::Error for EncodeError {}

impl Pdu {
    /// A whole PDU (first and last fragment) with little-endian integers,
    /// version 5.0 and no auth verifier. A request with an object UUID
    /// gets the [`flags::OBJECT_UUID`] flag.
    pub fn new(call_id: u32, body: Body) -> Pdu {
        let mut flags = flags::FIRST_FRAG | flags::LAST_FRAG;
        if let Body::Request { object: Some(_), .. } = body {
            flags |= self::flags::OBJECT_UUID;
        }
        Pdu { version_minor: 0, flags, drep: DataRep::LITTLE_ENDIAN, call_id, body, auth: None }
    }

    /// A whole PDU that answers this one with `body`, with the same call
    /// ID, version and data representation.
    pub fn reply(&self, body: Body) -> Pdu {
        Pdu { version_minor: self.version_minor, drep: self.drep, ..Pdu::new(self.call_id, body) }
    }

    /// How long the PDU at the start of `b` is, from its header. It
    /// returns `Ok(None)` until the fragment length has come, and an
    /// error as soon as the bytes so far break the header, from the second
    /// byte on.
    pub fn frame_length(b: &[u8]) -> Result<Option<usize>, Error> {
        if b.len() >= 2 && (b[0] != VERSION || b[1] > 1) {
            return Err(Error::Version { major: b[0], minor: b[1] });
        }
        if b.len() < 5 {
            return Ok(None);
        }
        let le = DataRep([b[4], 0, 0, 0]).little_endian().ok_or(Error::IntegerRep(b[4] >> 4))?;
        if b.len() < 10 {
            return Ok(None);
        }
        let n = rd16(le, b, 8);
        if usize::from(n) < HEADER_LEN {
            return Err(Error::FragLength(n));
        }
        Ok(Some(usize::from(n)))
    }

    /// Reads the PDU at the start of `b`. It returns `Ok(None)` if `b`
    /// holds only part of one, and otherwise the PDU and how many bytes of
    /// `b` it took.
    pub fn parse(b: &[u8]) -> Result<Option<(Pdu, usize)>, Error> {
        let Some(n) = Pdu::frame_length(b)? else { return Ok(None) };
        if b.len() < n {
            return Ok(None);
        }
        Ok(Some((parse_fragment(&b[..n])?, n)))
    }

    /// The PDU's bytes. A value [`Pdu::parse`] would refuse or read back
    /// as something else is an error; see [`EncodeError`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        if self.version_minor > 1 {
            return Err(EncodeError::Version(self.version_minor));
        }
        let le = self.drep.little_endian().ok_or(EncodeError::IntegerRep(self.drep.0[0] >> 4))?;
        if let Body::Request { object, .. } = &self.body
            && object.is_some() != (self.flags & flags::OBJECT_UUID != 0)
        {
            return Err(EncodeError::ObjectFlag);
        }
        match (&self.body, &self.auth) {
            (Body::Auth3, None) | (Body::BindNak(_) | Body::Shutdown, Some(_)) => return Err(EncodeError::Auth),
            _ => {}
        }
        let mut w = W { out: Vec::with_capacity(64), le };
        w.out.extend_from_slice(&[VERSION, self.version_minor, self.body.ptype(), self.flags]);
        w.out.extend_from_slice(&self.drep.0);
        // The fragment and auth lengths, filled in at the end.
        w.out.extend_from_slice(&[0; 4]);
        w.u32(self.call_id);
        let mut stub_start = None;
        match &self.body {
            Body::Request { alloc_hint, context_id, opnum, object, stub } => {
                w.u32(*alloc_hint);
                w.u16(*context_id);
                w.u16(*opnum);
                if let Some(u) = object {
                    w.uuid(*u);
                }
                stub_start = Some(w.out.len());
                w.bytes(stub)?;
            }
            Body::Response { alloc_hint, context_id, cancel_count, stub } => {
                w.u32(*alloc_hint);
                w.u16(*context_id);
                w.out.extend_from_slice(&[*cancel_count, 0]);
                stub_start = Some(w.out.len());
                w.bytes(stub)?;
            }
            Body::Fault { alloc_hint, context_id, cancel_count, fault_flags, status, stub } => {
                w.u32(*alloc_hint);
                w.u16(*context_id);
                w.out.extend_from_slice(&[*cancel_count, *fault_flags]);
                w.u32(*status);
                w.u32(0);
                stub_start = Some(w.out.len());
                w.bytes(stub)?;
            }
            Body::Bind(b) | Body::AlterContext(b) => {
                w.u16(b.max_xmit_frag);
                w.u16(b.max_recv_frag);
                w.u32(b.assoc_group);
                w.out.extend_from_slice(&[count(b.contexts.len())?, 0, 0, 0]);
                for c in &b.contexts {
                    w.u16(c.id);
                    w.out.extend_from_slice(&[count(c.transfer_syntaxes.len())?, 0]);
                    w.syntax(c.abstract_syntax);
                    for s in &c.transfer_syntaxes {
                        w.syntax(*s);
                    }
                    w.check()?;
                }
            }
            Body::BindAck(a) | Body::AlterContextResp(a) => {
                w.u16(a.max_xmit_frag);
                w.u16(a.max_recv_frag);
                w.u32(a.assoc_group);
                if a.secondary_address.last().is_some_and(|&b| b != 0) {
                    return Err(EncodeError::Address);
                }
                let n = u16::try_from(a.secondary_address.len()).map_err(|_| EncodeError::TooLong)?;
                w.u16(n);
                w.bytes(&a.secondary_address)?;
                w.align(4);
                w.out.extend_from_slice(&[count(a.results.len())?, 0, 0, 0]);
                for r in &a.results {
                    w.u16(r.result);
                    w.u16(r.reason);
                    w.syntax(r.transfer_syntax);
                }
            }
            Body::BindNak(n) => {
                w.u16(n.reason);
                w.out.push(count(n.versions.len())?);
                for &(major, minor) in &n.versions {
                    w.out.extend_from_slice(&[major, minor]);
                }
            }
            Body::Auth3 => w.out.extend_from_slice(&[0; 4]),
            Body::Shutdown | Body::Cancel | Body::Orphaned => {}
        }
        let mut auth_len = 0u16;
        if let Some(a) = &self.auth {
            if a.value.is_empty() {
                return Err(EncodeError::EmptyAuth);
            }
            auth_len = u16::try_from(a.value.len()).map_err(|_| EncodeError::TooLong)?;
            // Padding before the trailer: the stub data of a call to a
            // multiple of 16 bytes, anything else to 4 from the PDU's start.
            let before = w.out.len();
            match stub_start {
                Some(s) => {
                    let n = before - s;
                    w.out.resize(before + (AUTH_PAD_ALIGN - n % AUTH_PAD_ALIGN) % AUTH_PAD_ALIGN, 0);
                }
                None => w.align(4),
            }
            let pad = w.out.len() - before;
            w.out.extend_from_slice(&[a.kind, a.level, pad as u8, 0]);
            w.u32(a.context_id);
            w.bytes(&a.value)?;
        }
        let frag = u16::try_from(w.out.len()).map_err(|_| EncodeError::TooLong)?;
        let (f, l) = if le {
            (frag.to_le_bytes(), auth_len.to_le_bytes())
        } else {
            (frag.to_be_bytes(), auth_len.to_be_bytes())
        };
        w.out[8..10].copy_from_slice(&f);
        w.out[10..12].copy_from_slice(&l);
        Ok(w.out)
    }

    /// Splits a request or response into fragments of at most `max_frag`
    /// bytes each, such as the `max_recv_frag` the peer bound with. The
    /// first has [`flags::FIRST_FRAG`], the last [`flags::LAST_FRAG`],
    /// and each keeps the PDU's other flags and fields, except that a
    /// nonzero `alloc_hint` counts down by the stub data already sent, as
    /// MS-RPCE 2.2.2.6 asks. Any other PDU comes back whole if it writes
    /// in at most `max_frag` bytes, and is [`EncodeError::FragSize`] if
    /// it is longer. A PDU with an auth verifier is an error, since each
    /// fragment's verifier is the security provider's to make, and so is
    /// a split into more than [`MAX_FRAGMENTS`] fragments. Every other
    /// error [`Pdu::to_bytes`] gives is checked before anything is copied.
    pub fn fragments(&self, max_frag: u16) -> Result<Vec<Pdu>, EncodeError> {
        if self.auth.is_some() {
            return Err(EncodeError::FragmentAuth);
        }
        let header = match &self.body {
            Body::Request { object: Some(_), .. } => HEADER_LEN + 24,
            Body::Request { .. } | Body::Response { .. } => HEADER_LEN + 8,
            _ => {
                // The writer stops at MAX_FRAG bytes, so this copies at
                // most one fragment's worth.
                if self.to_bytes()?.len() > usize::from(max_frag) {
                    return Err(EncodeError::FragSize);
                }
                return Ok(vec![self.clone()]);
            }
        };
        // The body without its stub, cloned once per fragment, so the
        // stub is copied once in all rather than once per fragment.
        let template = self.body.clone_without_stub();
        // The header the fragments share, written once to check it.
        Pdu { auth: None, body: template.clone(), ..*self }.to_bytes()?;
        let room = usize::from(max_frag).checked_sub(header).filter(|&r| r > 0).ok_or(EncodeError::FragSize)?;
        let stub = self.body.stub().unwrap_or(&[]);
        let n = stub.len().div_ceil(room).max(1);
        if n > MAX_FRAGMENTS {
            return Err(EncodeError::FragSize);
        }
        let base = self.flags & !(flags::FIRST_FRAG | flags::LAST_FRAG);
        let pieces: Vec<&[u8]> = if stub.is_empty() { vec![&[]] } else { stub.chunks(room).collect() };
        let last = n - 1;
        let mut out = Vec::with_capacity(n);
        for (i, piece) in pieces.into_iter().enumerate() {
            let mut f = base;
            if i == 0 {
                f |= flags::FIRST_FRAG;
            }
            if i == last {
                f |= flags::LAST_FRAG;
            }
            let mut body = template.clone();
            let sent = u32::try_from(i * room).unwrap_or(u32::MAX);
            if let Body::Request { alloc_hint, .. } | Body::Response { alloc_hint, .. } = &mut body
                && *alloc_hint != 0
            {
                *alloc_hint = alloc_hint.saturating_sub(sent);
            }
            if let Some(s) = body.stub_mut() {
                *s = piece.to_vec();
            }
            out.push(Pdu {
                version_minor: self.version_minor,
                flags: f,
                drep: self.drep,
                call_id: self.call_id,
                body,
                auth: None,
            });
        }
        Ok(out)
    }
}

/// Why a fragment stream cannot continue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// A version, integer representation, or fragment length broke framing.
    Header(Error),
    /// The declared fragment length exceeded the configured limit.
    TooLong {
        /// Declared length, including the common header.
        length: usize,
        /// Largest accepted fragment.
        limit: usize,
    },
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Header(e) => e.fmt(f),
            Self::TooLong { length, limit } => write!(f, "DCE/RPC fragment of {length} bytes exceeds {limit}"),
        }
    }
}

impl core::error::Error for FrameError {}

/// Why an exact [`Wire`] parse did not contain one writable PDU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The PDU header or body was invalid.
    Pdu(Error),
    /// The input ended before a complete fragment.
    Incomplete,
    /// Bytes followed the complete fragment.
    Trailing {
        /// Number of bytes after the fragment.
        remaining: usize,
    },
    /// The writer's padding or reserved fields would exceed [`MAX_FRAG`].
    Unrepresentable(EncodeError),
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Pdu(e) => e.fmt(f),
            Self::Incomplete => f.write_str("incomplete DCE/RPC fragment"),
            Self::Trailing { remaining } => write!(f, "{remaining} bytes after DCE/RPC fragment"),
            Self::Unrepresentable(e) => write!(f, "DCE/RPC PDU cannot be re-encoded: {e}"),
        }
    }
}

impl core::error::Error for ParseError {}

impl Wire for Pdu {
    type ParseError = ParseError;
    type WriteError = EncodeError;

    /// Reads exactly one PDU whose re-encoding fits [`MAX_FRAG`].
    ///
    /// The writer adds padding and reserved fields some peers omit. A PDU
    /// that would then exceed the fragment limit is refused. [`Pdu::parse`]
    /// and [`Frames`] retain their broader receive behavior.
    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let (pdu, used) = Pdu::parse(bytes).map_err(ParseError::Pdu)?.ok_or(ParseError::Incomplete)?;
        if used != bytes.len() {
            return Err(ParseError::Trailing { remaining: bytes.len().saturating_sub(used) });
        }
        pdu.wire_len().map_err(ParseError::Unrepresentable)?;
        Ok(pdu)
    }

    /// Appends one PDU with at most [`MAX_FRAG`] bytes of temporary storage.
    /// Leaves `out` unchanged on error. Padding follows [`Pdu::to_bytes`].
    fn write(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.wire_len()?;
        out.extend_from_slice(&self.to_bytes()?);
        Ok(())
    }
}

impl Pdu {
    // Check the canonical length before the legacy writer allocates its body.
    fn wire_len(&self) -> Result<usize, EncodeError> {
        let add = |a: usize, b: usize| a.checked_add(b).filter(|&n| n <= MAX_FRAG).ok_or(EncodeError::TooLong);
        let mut length = HEADER_LEN;
        match &self.body {
            Body::Request { object, stub, .. } => {
                length = add(length, if object.is_some() { 24 } else { 8 })?;
                length = add(length, stub.len())?;
            }
            Body::Response { stub, .. } | Body::Fault { stub, .. } => {
                length = add(length, if matches!(self.body, Body::Fault { .. }) { 16 } else { 8 })?;
                length = add(length, stub.len())?;
            }
            Body::Bind(bind) | Body::AlterContext(bind) => {
                count(bind.contexts.len())?;
                length = add(length, 12)?;
                for context in &bind.contexts {
                    let syntaxes = usize::from(count(context.transfer_syntaxes.len())?);
                    length = add(length, 24)?;
                    length = add(length, syntaxes.checked_mul(20).ok_or(EncodeError::TooLong)?)?;
                }
            }
            Body::BindAck(ack) | Body::AlterContextResp(ack) => {
                let results = usize::from(count(ack.results.len())?);
                length = add(length, 10)?;
                length = add(length, ack.secondary_address.len())?;
                length = add(length, (4 - length % 4) % 4)?;
                length = add(length, 4)?;
                length = add(length, results.checked_mul(24).ok_or(EncodeError::TooLong)?)?;
            }
            Body::BindNak(nak) => {
                let versions = usize::from(count(nak.versions.len())?);
                length = add(length, 3)?;
                length = add(length, versions.checked_mul(2).ok_or(EncodeError::TooLong)?)?;
            }
            Body::Auth3 => length = add(length, 4)?,
            Body::Shutdown | Body::Cancel | Body::Orphaned => {}
        }
        if let Some(auth) = &self.auth {
            let padding = match self.body.stub() {
                Some(stub) => (AUTH_PAD_ALIGN - stub.len() % AUTH_PAD_ALIGN) % AUTH_PAD_ALIGN,
                None => (4 - length % 4) % 4,
            };
            length = add(length, padding)?;
            length = add(length, SEC_TRAILER_LEN)?;
            length = add(length, auth.value.len())?;
        }
        Ok(length)
    }
}

/// Reads DCE/RPC fragments without retaining input.
///
/// Each item is a PDU or a recoverable body error. Only header errors and
/// fragments above [`limit`](Self::limit) end the stream. Lengths are checked
/// as soon as their first ten header bytes arrive, before any body is needed.
/// Partial fragments return [`Step::Need`], including at EOF, so
/// [`super::codec::Stream`] reports truncation. Its `with_next` method gives
/// the original fragment bytes for authentication, including discarded padding.
/// The legacy [`Decoder`] remains separate to preserve borrowed frames,
/// repeated framing errors, and buffer clearing on failure.
///
/// ```
/// use fictionet::stdlib::{codec::{Stream, Wire}, dcerpc::{Body, Frames, Pdu}};
/// let pdu = Pdu::new(7, Body::Shutdown);
/// let bytes = Wire::to_bytes(&pdu)?;
/// let mut stream = Stream::new(Frames::new());
/// assert_eq!(stream.push(&bytes), bytes.len());
/// assert_eq!(stream.next(), Some(Ok(Ok(pdu))));
/// # Ok::<(), fictionet::stdlib::dcerpc::EncodeError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frames {
    limit: usize,
}

impl Frames {
    /// Creates a decoder accepting fragments up to [`MAX_FRAG`] bytes.
    pub fn new() -> Self {
        Self::with_limit(MAX_FRAG)
    }

    /// Sets the whole-fragment limit, clamped to [`HEADER_LEN`] through [`MAX_FRAG`].
    pub fn with_limit(limit: usize) -> Self {
        Self { limit: limit.clamp(HEADER_LEN, MAX_FRAG) }
    }

    /// The largest accepted fragment, including its common header.
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
    type Item = Result<Pdu, Error>;
    type Error = FrameError;
    const NAME: &'static str = "DCE/RPC";

    fn capacity(&self) -> usize {
        self.limit
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Self::Item>, FrameError> {
        let Some(used) = Pdu::frame_length(input).map_err(FrameError::Header)? else { return Ok(Step::Need) };
        if used > self.limit {
            return Err(FrameError::TooLong { length: used, limit: self.limit });
        }
        let Some(bytes) = input.get(..used) else { return Ok(Step::Need) };
        Ok(Step::Item(parse_fragment(bytes), used))
    }
}

/// How many items a list holds, as its 8-bit count.
fn count(n: usize) -> Result<u8, EncodeError> {
    u8::try_from(n).map_err(|_| EncodeError::Count)
}

/// Reads one whole fragment, whose length the header has been checked to
/// be.
fn parse_fragment(f: &[u8]) -> Result<Pdu, Error> {
    let drep = DataRep([f[4], f[5], f[6], f[7]]);
    let le = drep.little_endian().ok_or(Error::IntegerRep(f[4] >> 4))?;
    let (version_minor, kind, pdu_flags) = (f[1], f[2], f[3]);
    let auth_len = rd16(le, f, 10);
    let call_id = rd32(le, f, 12);
    if !matches!(kind, 0 | 2 | 3 | 11..=19) {
        return Err(Error::Type(kind));
    }
    match kind {
        ptype::AUTH3 if auth_len == 0 => return Err(Error::AuthLength(0)),
        ptype::BIND_NAK | ptype::SHUTDOWN if auth_len > 0 => return Err(Error::AuthLength(auth_len)),
        _ => {}
    }
    let mut end = f.len();
    let mut auth = None;
    if auth_len > 0 {
        let t = f
            .len()
            .checked_sub(usize::from(auth_len) + SEC_TRAILER_LEN)
            .filter(|&t| t >= HEADER_LEN)
            .ok_or(Error::AuthLength(auth_len))?;
        let pad = f[t + 2];
        end = t.checked_sub(usize::from(pad)).filter(|&e| e >= HEADER_LEN && t % 4 == 0).ok_or(Error::AuthPad(pad))?;
        auth = Some(Auth {
            kind: f[t],
            level: f[t + 1],
            context_id: rd32(le, f, t + 4),
            value: f[t + SEC_TRAILER_LEN..].to_vec(),
        });
    }
    let mut r = R { b: &f[..end], pos: HEADER_LEN, le };
    let body = match kind {
        ptype::REQUEST => {
            let (alloc_hint, context_id, opnum) = (r.u32()?, r.u16()?, r.u16()?);
            let object = if pdu_flags & flags::OBJECT_UUID != 0 { Some(r.uuid()?) } else { None };
            Body::Request { alloc_hint, context_id, opnum, object, stub: r.rest() }
        }
        ptype::RESPONSE => {
            let (alloc_hint, context_id, cancel_count) = (r.u32()?, r.u16()?, r.u8()?);
            r.take(1)?;
            Body::Response { alloc_hint, context_id, cancel_count, stub: r.rest() }
        }
        ptype::FAULT => {
            let (alloc_hint, context_id, cancel_count, fault_flags) = (r.u32()?, r.u16()?, r.u8()?, r.u8()?);
            let status = r.u32()?;
            // The reserved word after the status; some senders leave it
            // out of a fault with no stub data.
            let stub = if r.take(4).is_ok() { r.rest() } else { Vec::new() };
            Body::Fault { alloc_hint, context_id, cancel_count, fault_flags, status, stub }
        }
        ptype::BIND | ptype::ALTER_CONTEXT => {
            let b = read_bind(&mut r)?;
            if kind == ptype::BIND { Body::Bind(b) } else { Body::AlterContext(b) }
        }
        ptype::BIND_ACK | ptype::ALTER_CONTEXT_RESP => {
            let a = read_bind_ack(&mut r)?;
            if kind == ptype::BIND_ACK { Body::BindAck(a) } else { Body::AlterContextResp(a) }
        }
        ptype::BIND_NAK => {
            let reason = r.u16()?;
            let mut versions = Vec::new();
            if r.pos < r.b.len() {
                let n = r.u8()?;
                for _ in 0..n {
                    let v = r.take(2)?;
                    versions.push((v[0], v[1]));
                }
            }
            Body::BindNak(BindNak { reason, versions })
        }
        ptype::AUTH3 => {
            r.take(4)?;
            Body::Auth3
        }
        ptype::SHUTDOWN => Body::Shutdown,
        ptype::CO_CANCEL => Body::Cancel,
        _ => Body::Orphaned,
    };
    Ok(Pdu { version_minor, flags: pdu_flags, drep, call_id, body, auth })
}

fn read_bind(r: &mut R) -> Result<Bind, Error> {
    let (max_xmit_frag, max_recv_frag, assoc_group) = (r.u16()?, r.u16()?, r.u32()?);
    let n = r.u8()?;
    r.take(3)?;
    let mut contexts = Vec::new();
    for _ in 0..n {
        let id = r.u16()?;
        let k = r.u8()?;
        r.take(1)?;
        let abstract_syntax = r.syntax()?;
        let mut transfer_syntaxes = Vec::new();
        for _ in 0..k {
            transfer_syntaxes.push(r.syntax()?);
        }
        contexts.push(Context { id, abstract_syntax, transfer_syntaxes });
    }
    Ok(Bind { max_xmit_frag, max_recv_frag, assoc_group, contexts })
}

fn read_bind_ack(r: &mut R) -> Result<BindAck, Error> {
    let (max_xmit_frag, max_recv_frag, assoc_group) = (r.u16()?, r.u16()?, r.u32()?);
    let n = r.u16()?;
    let secondary_address = r.take(usize::from(n))?.to_vec();
    if secondary_address.last().is_some_and(|&b| b != 0) {
        return Err(Error::Address);
    }
    r.take((4 - r.pos % 4) % 4)?;
    let k = r.u8()?;
    r.take(3)?;
    let mut results = Vec::new();
    for _ in 0..k {
        let (result, reason) = (r.u16()?, r.u16()?);
        results.push(ContextResult { result, reason, transfer_syntax: r.syntax()? });
    }
    Ok(BindAck { max_xmit_frag, max_recv_frag, assoc_group, secondary_address, results })
}

/// Reads fields from a fragment, counting `pos` from the PDU's start so
/// alignment works.
struct R<'a> {
    b: &'a [u8],
    pos: usize,
    le: bool,
}

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.b.len()).ok_or(Error::Truncated)?;
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        let s = self.take(2)?;
        Ok(rd16(self.le, s, 0))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        let s = self.take(4)?;
        Ok(rd32(self.le, s, 0))
    }

    fn uuid(&mut self) -> Result<Uuid, Error> {
        let (a, b, c) = (self.u32()?, self.u16()?, self.u16()?);
        let d = self.take(8)?;
        let mut rest = [0u8; 8];
        rest.copy_from_slice(d);
        Ok(Uuid::from_fields(a, b, c, rest))
    }

    fn syntax(&mut self) -> Result<SyntaxId, Error> {
        let uuid = self.uuid()?;
        let v = self.u32()?;
        Ok(SyntaxId { uuid, major: v as u16, minor: (v >> 16) as u16 })
    }

    fn rest(&mut self) -> Vec<u8> {
        let s = self.b[self.pos..].to_vec();
        self.pos = self.b.len();
        s
    }
}

/// Writes fields in the data representation's byte order.
struct W {
    out: Vec<u8>,
    le: bool,
}

impl W {
    fn u16(&mut self, v: u16) {
        self.out.extend_from_slice(&if self.le { v.to_le_bytes() } else { v.to_be_bytes() });
    }

    fn u32(&mut self, v: u32) {
        self.out.extend_from_slice(&if self.le { v.to_le_bytes() } else { v.to_be_bytes() });
    }

    fn uuid(&mut self, u: Uuid) {
        let b = u.0;
        self.u32(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
        self.u16(u16::from_be_bytes([b[4], b[5]]));
        self.u16(u16::from_be_bytes([b[6], b[7]]));
        self.out.extend_from_slice(&b[8..]);
    }

    fn syntax(&mut self, s: SyntaxId) {
        self.uuid(s.uuid);
        self.u32(u32::from(s.minor) << 16 | u32::from(s.major));
    }

    /// Appends bytes, refusing once the PDU is past what one fragment
    /// holds, so a huge value is never copied whole.
    fn bytes(&mut self, b: &[u8]) -> Result<(), EncodeError> {
        if self.out.len().saturating_add(b.len()) > MAX_FRAG {
            return Err(EncodeError::TooLong);
        }
        self.out.extend_from_slice(b);
        Ok(())
    }

    fn check(&self) -> Result<(), EncodeError> {
        if self.out.len() > MAX_FRAG { Err(EncodeError::TooLong) } else { Ok(()) }
    }

    /// Pads with zeros to a multiple of `n` from the PDU's start.
    fn align(&mut self, n: usize) {
        let pad = (n - self.out.len() % n) % n;
        self.out.resize(self.out.len() + pad, 0);
    }
}

/// The auth type, level and context ID of a PDU's verifier, if it has one.
fn security(p: &Pdu) -> Option<(u8, u8, u32)> {
    p.auth.as_ref().map(|a| (a.kind, a.level, a.context_id))
}

fn rd16(le: bool, b: &[u8], i: usize) -> u16 {
    let v = [b[i], b[i + 1]];
    if le { u16::from_le_bytes(v) } else { u16::from_be_bytes(v) }
}

fn rd32(le: bool, b: &[u8], i: usize) -> u32 {
    let v = [b[i], b[i + 1], b[i + 2], b[i + 3]];
    if le { u32::from_le_bytes(v) } else { u32::from_be_bytes(v) }
}

/// Splits a DCE/RPC byte stream into PDUs. Feed it the bytes a connection
/// or pipe reads, in order, and take PDUs out until it has none.
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped in `feed` once they are half the buffer.
    start: usize,
    failed: Option<Error>,
}

impl Decoder {
    /// A decoder holding no bytes.
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// Takes bytes read from the connection, from the start of `bytes`,
    /// and returns how many it took. It takes them all unless that would
    /// make it hold more than [`MAX_BUFFERED`] bytes. Then take PDUs out
    /// with [`Decoder::next_pdu`] and feed it the rest. Once it is full,
    /// `next_pdu` always gives a PDU or an error, so a loop of feeding and
    /// taking out always ends. After an error that breaks the stream,
    /// every byte is taken and dropped.
    #[must_use = "bytes past the count returned were not taken"]
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.failed.is_some() {
            return bytes.len();
        }
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let n = bytes.len().min(MAX_BUFFERED.saturating_sub(self.buffered()));
        self.buf.extend_from_slice(&bytes[..n]);
        n
    }

    /// The next whole PDU, if one has come. It returns `None` when it
    /// needs more bytes. A PDU whose body cannot be read gives its error
    /// once, and the stream goes on after it. An error that breaks the
    /// stream ([`Error::breaks_stream`]) comes back on every call.
    pub fn next_pdu(&mut self) -> Option<Result<Pdu, Error>> {
        self.next_frame().map(|(r, _)| r)
    }

    /// Like [`Decoder::next_pdu`], with the PDU's bytes as they came. A
    /// world that checks or decrypts auth verifiers needs them: the
    /// security provider covers the header, the stub data and the padding
    /// before the trailer, and at [`auth_level::PKT_PRIVACY`] that padding
    /// is ciphertext, which a [`Pdu`] does not keep. After an error that
    /// breaks the stream the bytes are empty.
    pub fn next_frame(&mut self) -> Option<(Result<Pdu, Error>, &[u8])> {
        if let Some(e) = self.failed {
            return Some((Err(e), &[]));
        }
        let b = &self.buf[self.start..];
        match Pdu::frame_length(b) {
            Ok(Some(n)) if b.len() >= n => {
                let r = parse_fragment(&b[..n]);
                let at = self.start;
                self.start += n;
                Some((r, &self.buf[at..at + n]))
            }
            Ok(_) => None,
            Err(e) => {
                self.failed = Some(e);
                self.buf = Vec::new();
                self.start = 0;
                Some((Err(e), &[]))
            }
        }
    }

    /// How many bytes are held, waiting for the rest of a PDU.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.start
    }
}

/// Why a [`Reassembler`] dropped a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReassemblyError {
    /// A first fragment came while another call was still being joined.
    /// Both are dropped, since this module does not multiplex calls.
    Interleaved {
        /// The call ID of the new first fragment.
        call_id: u32,
    },
    /// A later fragment came with no call being joined, or for another
    /// call ID, type, context or operation, or with another auth type,
    /// level or context ID than the first fragment, or with a verifier
    /// when the first had none or the other way round (MS-RPCE 2.2.2.11).
    Unexpected {
        /// The fragment's call ID.
        call_id: u32,
    },
    /// The call's stub data grew past the reassembler's limit.
    TooLong {
        /// The call's ID.
        call_id: u32,
    },
}

impl std::fmt::Display for ReassemblyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReassemblyError::Interleaved { call_id } => write!(f, "call {call_id} started inside another call"),
            ReassemblyError::Unexpected { call_id } => write!(f, "a fragment of call {call_id} came out of order"),
            ReassemblyError::TooLong { call_id } => write!(f, "call {call_id} has more stub data than allowed"),
        }
    }
}

impl std::error::Error for ReassemblyError {}

/// Joins the fragments of requests and responses into whole calls. Push
/// each PDU a [`Decoder`] gives; a whole call comes back once its last
/// fragment has come. Other PDUs come back as they are. A fault or
/// orphaned PDU for the call being joined drops it.
///
/// A joined call keeps the first fragment's fields and flags, with
/// [`flags::LAST_FRAG`] added. A cancel that came on any fragment stays:
/// [`flags::PENDING_CANCEL`] is set if any fragment had it, and a
/// response's `cancel_count` is the highest any fragment gave. The joined
/// call has no auth verifier: each fragment's verifier is checked, if the
/// world checks it, before the fragment is pushed. Every fragment must
/// use the first one's auth type, level and context ID.
#[derive(Debug)]
pub struct Reassembler {
    limit: usize,
    partial: Option<Pdu>,
    /// The first fragment's auth type, level and context ID, if it had a
    /// verifier.
    security: Option<(u8, u8, u32)>,
}

impl Default for Reassembler {
    fn default() -> Reassembler {
        Reassembler::new(MAX_STUB)
    }
}

impl Reassembler {
    /// A reassembler that joins calls of up to `limit` bytes of stub data,
    /// or [`MAX_STUB`] if that is less.
    pub fn new(limit: usize) -> Reassembler {
        Reassembler { limit: limit.min(MAX_STUB), partial: None, security: None }
    }

    /// How many bytes of stub data are held for the call being joined.
    pub fn pending(&self) -> usize {
        self.partial.as_ref().and_then(|p| p.body.stub()).map_or(0, <[u8]>::len)
    }

    /// Takes one PDU. It returns a whole call or another PDU when one is
    /// ready, `None` while a call still needs fragments, and an error when
    /// fragments break the rules, after which the call is dropped.
    pub fn push(&mut self, pdu: Pdu) -> Result<Option<Pdu>, ReassemblyError> {
        let call_id = pdu.call_id;
        match &pdu.body {
            Body::Request { .. } | Body::Response { .. } => {}
            Body::Fault { .. } | Body::Orphaned => {
                if self.partial.as_ref().is_some_and(|p| p.call_id == call_id) {
                    self.partial = None;
                }
                return Ok(Some(pdu));
            }
            _ => return Ok(Some(pdu)),
        }
        let len = pdu.body.stub().map_or(0, <[u8]>::len);
        let first = pdu.flags & flags::FIRST_FRAG != 0;
        let last = pdu.flags & flags::LAST_FRAG != 0;
        if first {
            if self.partial.take().is_some() {
                return Err(ReassemblyError::Interleaved { call_id });
            }
            if len > self.limit {
                return Err(ReassemblyError::TooLong { call_id });
            }
            if last {
                return Ok(Some(pdu));
            }
            self.security = security(&pdu);
            self.partial = Some(Pdu { auth: None, ..pdu });
            return Ok(None);
        }
        let Some(mut p) = self.partial.take() else { return Err(ReassemblyError::Unexpected { call_id }) };
        let same = p.call_id == call_id
            && self.security == security(&pdu)
            && match (&p.body, &pdu.body) {
                (
                    Body::Request { context_id: a, opnum: b, object: c, .. },
                    Body::Request { context_id: x, opnum: y, object: z, .. },
                ) => a == x && b == y && c == z,
                (Body::Response { context_id: a, .. }, Body::Response { context_id: x, .. }) => a == x,
                _ => false,
            };
        if !same {
            return Err(ReassemblyError::Unexpected { call_id });
        }
        let Some(stub) = p.body.stub_mut() else { return Err(ReassemblyError::Unexpected { call_id }) };
        if stub.len().saturating_add(len) > self.limit {
            return Err(ReassemblyError::TooLong { call_id });
        }
        stub.extend_from_slice(pdu.body.stub().unwrap_or(&[]));
        p.flags |= pdu.flags & flags::PENDING_CANCEL;
        if let (Body::Response { cancel_count: a, .. }, Body::Response { cancel_count: b, .. }) =
            (&mut p.body, &pdu.body)
        {
            *a = (*a).max(*b);
        }
        if last {
            p.flags |= flags::LAST_FRAG;
            Ok(Some(p))
        } else {
            self.partial = Some(p);
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An endpoint mapper bind as Windows sends it: one context, the
    /// endpoint mapper over NDR.
    const BIND: [u8; 72] = [
        0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, //
        0xd0, 0x16, 0xd0, 0x16, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, //
        0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa, //
        0x03, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, //
        0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
    ];

    fn bind() -> Pdu {
        Pdu::new(
            1,
            Body::Bind(Bind {
                max_xmit_frag: 5840,
                max_recv_frag: 5840,
                assoc_group: 0,
                contexts: vec![Context { id: 0, abstract_syntax: EPMAPPER, transfer_syntaxes: vec![NDR] }],
            }),
        )
    }

    fn request(stub: Vec<u8>) -> Pdu {
        Pdu::new(7, Body::Request { alloc_hint: stub.len() as u32, context_id: 0, opnum: 3, object: None, stub })
    }

    fn round_trip(p: &Pdu) -> Vec<u8> {
        let bytes = p.to_bytes().unwrap();
        assert_eq!(Pdu::parse(&bytes), Ok(Some((p.clone(), bytes.len()))), "{p:?}");
        bytes
    }

    fn all_bodies() -> Vec<Pdu> {
        let ack = BindAck {
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group: 0x53f0,
            secondary_address: b"\\PIPE\\samr\0".to_vec(),
            results: vec![ContextResult::accept(NDR), ContextResult::reject(reason::ABSTRACT_SYNTAX_NOT_SUPPORTED)],
        };
        let b = match bind().body {
            Body::Bind(b) => b,
            _ => unreachable!(),
        };
        let object = Uuid::parse("12345678-1234-abcd-ef00-0123456789ab").unwrap();
        vec![
            request(vec![1, 2, 3]),
            Pdu::new(
                8,
                Body::Request { alloc_hint: 0, context_id: 2, opnum: 9, object: Some(object), stub: vec![9; 5] },
            ),
            Pdu::new(9, Body::Response { alloc_hint: 4, context_id: 1, cancel_count: 0, stub: vec![0, 0, 0, 0] }),
            Pdu::new(
                10,
                Body::Fault {
                    alloc_hint: 0,
                    context_id: 0,
                    cancel_count: 1,
                    fault_flags: 0,
                    status: status::OP_RNG_ERROR,
                    stub: vec![],
                },
            ),
            bind(),
            Pdu::new(1, Body::BindAck(ack.clone())),
            Pdu::new(1, Body::AlterContext(b)),
            Pdu::new(1, Body::AlterContextResp(BindAck { secondary_address: vec![], ..ack })),
            Pdu::new(
                1,
                Body::BindNak(BindNak { reason: reject::PROTOCOL_VERSION_NOT_SUPPORTED, versions: vec![(5, 0)] }),
            ),
            Pdu::new(1, Body::BindNak(BindNak { reason: 0, versions: vec![] })),
            Pdu {
                auth: Some(Auth {
                    kind: auth_type::WINNT,
                    level: auth_level::CONNECT,
                    context_id: 0,
                    value: vec![1; 9],
                }),
                ..Pdu::new(1, Body::Auth3)
            },
            Pdu::new(1, Body::Shutdown),
            Pdu::new(1, Body::Cancel),
            Pdu::new(1, Body::Orphaned),
        ]
    }

    #[test]
    fn windows_bind_example() {
        let (pdu, used) = Pdu::parse(&BIND).unwrap().unwrap();
        assert_eq!(used, 72);
        assert_eq!(pdu, bind());
        assert_eq!(bind().to_bytes().unwrap(), BIND);
        // Every prefix is part of a PDU.
        for n in 0..BIND.len() {
            assert_eq!(Pdu::parse(&BIND[..n]), Ok(None), "{n} bytes");
        }
        // Bytes past the fragment are left.
        let mut more = BIND.to_vec();
        more.extend_from_slice(&[5, 0]);
        assert_eq!(Pdu::parse(&more).unwrap().unwrap().1, 72);
    }

    #[test]
    fn uuids() {
        assert_eq!(NDR.uuid.to_string(), "8a885d04-1ceb-11c9-9fe8-08002b104860");
        assert_eq!(Uuid::parse("8A885D04-1CEB-11C9-9FE8-08002B104860"), Some(NDR.uuid));
        assert_eq!(EPMAPPER.uuid.to_string(), "e1af8308-5d1f-11c9-91a4-08002b14a0fa");
        assert_eq!(NDR64.uuid.to_string(), "71710533-beba-4937-8319-b5dbef9ccc36");
        assert_eq!(Uuid::parse("8a885d04-1ceb-11c9-9fe8-08002b10486"), None);
        assert_eq!(Uuid::parse("8a885d04x1ceb-11c9-9fe8-08002b104860"), None);
        assert_eq!(Uuid::parse("8a885d04-1ceb-11c9-9fe8-08002b10486g"), None);
        assert_eq!(Uuid::parse("8a885d04-1ceb-11c9-9fe8-08002b1048é"), None);
        assert_eq!(Uuid::parse(&Uuid::NIL.to_string()), Some(Uuid::NIL));
    }

    #[test]
    fn codec_writes_each_body_in_both_byte_orders() {
        use crate::stdlib::codec::contract;

        for mut pdu in all_bodies() {
            for drep in [DataRep::LITTLE_ENDIAN, DataRep::BIG_ENDIAN] {
                pdu.drep = drep;
                let bytes = Wire::to_bytes(&pdu).unwrap();
                assert_eq!(pdu.wire_len(), Ok(bytes.len()));
                assert_eq!(bytes, pdu.to_bytes().unwrap());
                contract::check_wire::<Pdu>(&bytes);
                contract::check_wire_value(&pdu);
                if matches!(pdu.body, Body::BindNak(_) | Body::Shutdown) {
                    continue;
                }
                let mut authenticated = pdu.clone();
                authenticated.auth = Some(Auth {
                    kind: auth_type::WINNT,
                    level: auth_level::PKT_PRIVACY,
                    context_id: 3,
                    value: vec![0xaa; 16],
                });
                let bytes = Wire::to_bytes(&authenticated).unwrap();
                assert_eq!(authenticated.wire_len(), Ok(bytes.len()));
                contract::check_wire::<Pdu>(&bytes);
                contract::check_wire_value(&authenticated);
            }
        }
    }

    #[test]
    fn every_body_round_trips_in_both_byte_orders() {
        for mut p in all_bodies() {
            round_trip(&p);
            p.drep = DataRep::BIG_ENDIAN;
            p.version_minor = 1;
            let bytes = round_trip(&p);
            for n in 0..bytes.len() {
                assert_eq!(Pdu::parse(&bytes[..n]), Ok(None));
            }
            if matches!(p.body, Body::BindNak(_) | Body::Shutdown) {
                continue;
            }
            p.auth = Some(Auth {
                kind: auth_type::WINNT,
                level: auth_level::PKT_PRIVACY,
                context_id: 3,
                value: vec![0xaa; 16],
            });
            let bytes = round_trip(&p);
            for n in 0..bytes.len() {
                assert_eq!(Pdu::parse(&bytes[..n]), Ok(None));
            }
        }
    }

    #[test]
    fn syntax_version_is_one_u32_in_the_data_representation() {
        // C706 12.6.3.1: if_version is a u32, the major version in the low
        // 16 bits. Little-endian, that is major then minor as two u16s.
        let v = SyntaxId { uuid: Uuid::NIL, major: 3, minor: 1 };
        let ctx = |s| Context { id: 0, abstract_syntax: s, transfer_syntaxes: vec![] };
        let mut p = Pdu::new(
            1,
            Body::Bind(Bind { max_xmit_frag: 0, max_recv_frag: 0, assoc_group: 0, contexts: vec![ctx(v)] }),
        );
        let b = round_trip(&p);
        assert_eq!(b[48..52], [3, 0, 1, 0]);
        // Big-endian, the u32 0x0001_0003 puts the minor version first.
        p.drep = DataRep::BIG_ENDIAN;
        let b = round_trip(&p);
        assert_eq!(b[48..52], [0, 1, 0, 3]);
        let mut be = b.clone();
        be[48..52].copy_from_slice(&[0, 0, 0, 2]);
        let Body::Bind(got) = Pdu::parse(&be).unwrap().unwrap().0.body else { panic!() };
        assert_eq!((got.contexts[0].abstract_syntax.major, got.contexts[0].abstract_syntax.minor), (2, 0));
    }

    #[test]
    fn status_codes_match_c706_appendix_e() {
        assert_eq!(status::FAULT_CONTEXT_MISMATCH, 0x1c00_001a);
        assert_eq!(status::FAULT_REMOTE_NO_MEMORY, 0x1c00_001b);
    }

    #[test]
    fn bind_ack_layout() {
        let p = Pdu::new(
            1,
            Body::BindAck(BindAck {
                max_xmit_frag: 4280,
                max_recv_frag: 4280,
                assoc_group: 0x1234,
                secondary_address: b"135\0".to_vec(),
                results: vec![ContextResult::accept(NDR)],
            }),
        );
        let b = round_trip(&p);
        assert_eq!(b.len(), 60);
        assert_eq!(b[24..30], [4, 0, b'1', b'3', b'5', 0]);
        // Two bytes of padding to a multiple of 4, then one result.
        assert_eq!(b[30..36], [0, 0, 1, 0, 0, 0]);
        assert_eq!(b[36..40], [0, 0, 0, 0]);
        assert_eq!(b[40..44], [0x04, 0x5d, 0x88, 0x8a]);
    }

    #[test]
    fn request_and_response_layout() {
        let b = round_trip(&request(vec![0xde, 0xad]));
        assert_eq!(b, [5, 0, 0, 3, 0x10, 0, 0, 0, 26, 0, 0, 0, 7, 0, 0, 0, 2, 0, 0, 0, 0, 0, 3, 0, 0xde, 0xad]);
        // The object UUID follows the opnum, in the data representation's
        // byte order.
        let object = Uuid::from_fields(0x0102_0304, 0x0506, 0x0708, [9, 10, 11, 12, 13, 14, 15, 16]);
        let p =
            Pdu::new(1, Body::Request { alloc_hint: 0, context_id: 0, opnum: 0, object: Some(object), stub: vec![] });
        assert_eq!(p.flags & flags::OBJECT_UUID, flags::OBJECT_UUID);
        let b = round_trip(&p);
        assert_eq!(b[24..40], [4, 3, 2, 1, 6, 5, 8, 7, 9, 10, 11, 12, 13, 14, 15, 16]);
        let fault = Pdu::new(
            7,
            Body::Fault {
                alloc_hint: 0,
                context_id: 0,
                cancel_count: 0,
                fault_flags: 0,
                status: status::UNK_IF,
                stub: vec![],
            },
        );
        let b = round_trip(&fault);
        assert_eq!(b.len(), 32);
        assert_eq!(b[24..28], [3, 0, 1, 0x1c]);
        // A fault without the reserved word still reads.
        let mut short = b[..28].to_vec();
        short[8] = 28;
        assert_eq!(Pdu::parse(&short).unwrap().unwrap().0, fault);
    }

    #[test]
    fn auth_trailer_and_padding() {
        let mut p = request(vec![1, 2, 3]);
        p.auth = Some(Auth {
            kind: auth_type::GSS_NEGOTIATE,
            level: auth_level::PKT_INTEGRITY,
            context_id: 0,
            value: vec![7; 16],
        });
        let b = round_trip(&p);
        // Stub of 3 padded to 16, then the trailer and the 16-byte token.
        assert_eq!(b.len(), 24 + 16 + 8 + 16);
        assert_eq!(b[10..12], [16, 0]);
        assert_eq!(b[40..44], [9, 5, 13, 0]);
        // A bind's trailer is aligned to 4 from the PDU's start.
        let mut p = bind();
        p.auth = Some(Auth { kind: auth_type::WINNT, level: auth_level::CONNECT, context_id: 0, value: vec![1; 40] });
        let b = round_trip(&p);
        assert_eq!(b.len(), 72 + 8 + 40);
        assert_eq!(b[74], 0);
        // Auth3 carries 4 bytes of padding before the trailer.
        let mut p = Pdu::new(3, Body::Auth3);
        p.auth = Some(Auth { kind: 0x0a, level: 2, context_id: 0, value: vec![1, 2] });
        let b = round_trip(&p);
        assert_eq!(b.len(), 20 + 8 + 2);
    }

    #[test]
    fn header_errors_break_the_stream() {
        assert_eq!(Pdu::parse(&[4, 0]), Err(Error::Version { major: 4, minor: 0 }));
        assert_eq!(Pdu::parse(&[5, 2]), Err(Error::Version { major: 5, minor: 2 }));
        assert_eq!(Pdu::parse(&[5]), Ok(None));
        assert_eq!(Pdu::parse(&[5, 0, 0, 3, 0x20]), Err(Error::IntegerRep(2)));
        assert_eq!(Pdu::parse(&[5, 0, 0, 3, 0x10, 0, 0, 0, 15, 0]), Err(Error::FragLength(15)));
        assert_eq!(Pdu::parse(&[5, 0, 0, 3, 0x00, 0, 0, 0, 0, 15]), Err(Error::FragLength(15)));
        for e in [Error::Version { major: 4, minor: 0 }, Error::IntegerRep(2), Error::FragLength(0)] {
            assert!(e.breaks_stream());
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn body_errors() {
        let header = |kind: u8, len: u8, auth: u8| {
            let mut b = vec![5, 0, kind, 3, 0x10, 0, 0, 0, len, 0, auth, 0, 1, 0, 0, 0];
            b.resize(usize::from(len), 0);
            b
        };
        // Connectionless and unknown types.
        for t in [1u8, 4, 5, 6, 7, 8, 9, 10, 20, 255] {
            assert_eq!(Pdu::parse(&header(t, 16, 0)), Err(Error::Type(t)));
        }
        // An auth length the fragment cannot hold.
        assert_eq!(Pdu::parse(&header(18, 24, 1)), Err(Error::AuthLength(1)));
        assert_eq!(Pdu::parse(&header(18, 25, 1)).unwrap().unwrap().0.auth.unwrap().value, [0]);
        // Padding that runs into the header.
        let mut b = header(18, 25, 1);
        b[18] = 1;
        assert_eq!(Pdu::parse(&b), Err(Error::AuthPad(1)));
        // Bodies shorter than their fields.
        assert_eq!(Pdu::parse(&header(0, 23, 0)), Err(Error::Truncated));
        assert_eq!(Pdu::parse(&header(2, 23, 0)), Err(Error::Truncated));
        assert_eq!(Pdu::parse(&header(3, 27, 0)), Err(Error::Truncated));
        assert_eq!(Pdu::parse(&header(11, 27, 0)), Err(Error::Truncated));
        assert_eq!(Pdu::parse(&header(12, 25, 0)), Err(Error::Truncated));
        assert_eq!(Pdu::parse(&header(13, 17, 0)), Err(Error::Truncated));
        // A request flagged with an object UUID too short to hold one.
        let mut b = header(0, 30, 0);
        b[3] |= flags::OBJECT_UUID;
        assert_eq!(Pdu::parse(&b), Err(Error::Truncated));
        // A context count past the body.
        let mut b = BIND;
        b[24] = 2;
        assert_eq!(Pdu::parse(&b), Err(Error::Truncated));
        // A transfer syntax count past the body.
        let mut b = BIND;
        b[30] = 2;
        assert_eq!(Pdu::parse(&b), Err(Error::Truncated));
        // A secondary address longer than the body.
        let mut b = header(12, 40, 0);
        b[24] = 30;
        assert_eq!(Pdu::parse(&b), Err(Error::Truncated));
        // A bind_nak with more versions than bytes.
        let mut b = header(13, 19, 0);
        b[18] = 2;
        assert_eq!(Pdu::parse(&b), Err(Error::Truncated));
        // A bind_nak that stops after its reason.
        assert_eq!(
            Pdu::parse(&header(13, 18, 0)).unwrap().unwrap().0.body,
            Body::BindNak(BindNak { reason: 0, versions: vec![] })
        );
        for e in [Error::Type(1), Error::AuthLength(1), Error::AuthPad(1), Error::Truncated, Error::Address] {
            assert!(!e.breaks_stream());
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn writers_refuse_what_would_not_read_back() {
        let mut p = request(vec![]);
        p.version_minor = 2;
        assert_eq!(p.to_bytes(), Err(EncodeError::Version(2)));
        let mut p = request(vec![]);
        p.drep = DataRep([0x20, 0, 0, 0]);
        assert_eq!(p.to_bytes(), Err(EncodeError::IntegerRep(2)));
        let mut p = request(vec![]);
        p.flags |= flags::OBJECT_UUID;
        assert_eq!(p.to_bytes(), Err(EncodeError::ObjectFlag));
        let mut p = request(vec![]);
        p.auth = Some(Auth { kind: 9, level: 6, context_id: 0, value: vec![] });
        assert_eq!(p.to_bytes(), Err(EncodeError::EmptyAuth));
        let mut p = request(vec![]);
        p.auth = Some(Auth { kind: 9, level: 6, context_id: 0, value: vec![0; 65536] });
        assert_eq!(p.to_bytes(), Err(EncodeError::TooLong));
        assert_eq!(request(vec![0; MAX_FRAG]).to_bytes(), Err(EncodeError::TooLong));
        // The longest request fits exactly.
        round_trip(&request(vec![0; MAX_FRAG - 24]));
        assert_eq!(request(vec![0; MAX_FRAG - 23]).to_bytes(), Err(EncodeError::TooLong));
        let mut b = match bind().body {
            Body::Bind(b) => b,
            _ => unreachable!(),
        };
        b.contexts[0].transfer_syntaxes = vec![NDR; 256];
        assert_eq!(Pdu::new(1, Body::Bind(b.clone())).to_bytes(), Err(EncodeError::Count));
        b.contexts = vec![Context { id: 0, abstract_syntax: NDR, transfer_syntaxes: vec![] }; 256];
        assert_eq!(Pdu::new(1, Body::Bind(b.clone())).to_bytes(), Err(EncodeError::Count));
        b.contexts = vec![Context { id: 0, abstract_syntax: NDR, transfer_syntaxes: vec![NDR; 255] }; 255];
        assert_eq!(Pdu::new(1, Body::Bind(b)).to_bytes(), Err(EncodeError::TooLong));
        let nak = BindNak { reason: 0, versions: vec![(5, 0); 256] };
        assert_eq!(Pdu::new(1, Body::BindNak(nak)).to_bytes(), Err(EncodeError::Count));
        let ack = BindAck {
            max_xmit_frag: 0,
            max_recv_frag: 0,
            assoc_group: 0,
            secondary_address: vec![0; 70000],
            results: vec![],
        };
        assert_eq!(Pdu::new(1, Body::BindAck(ack.clone())).to_bytes(), Err(EncodeError::TooLong));
        let ack = BindAck { secondary_address: vec![], results: vec![ContextResult::accept(NDR); 256], ..ack };
        assert_eq!(Pdu::new(1, Body::BindAck(ack)).to_bytes(), Err(EncodeError::Count));
        for e in [
            EncodeError::Version(2),
            EncodeError::IntegerRep(2),
            EncodeError::ObjectFlag,
            EncodeError::EmptyAuth,
            EncodeError::Count,
            EncodeError::TooLong,
            EncodeError::FragSize,
            EncodeError::FragmentAuth,
            EncodeError::Auth,
            EncodeError::Address,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn fragments_and_reassembly() {
        let stub: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let whole = request(stub.clone());
        let parts = whole.fragments(124).unwrap();
        assert_eq!(parts.len(), 10);
        assert_eq!(parts[0].flags, flags::FIRST_FRAG);
        assert_eq!(parts[9].flags, flags::LAST_FRAG);
        let mut r = Reassembler::default();
        for (i, p) in parts.iter().enumerate() {
            let bytes = round_trip(p);
            assert!(bytes.len() <= 124);
            let got = r.push(p.clone()).unwrap();
            if i < 9 {
                assert_eq!(got, None);
                assert_eq!(r.pending(), 100 * (i + 1));
            } else {
                assert_eq!(got, Some(whole.clone()));
            }
        }
        assert_eq!(r.pending(), 0);
        // An empty stub is one fragment; other PDUs come back whole.
        assert_eq!(request(vec![]).fragments(25).unwrap(), [request(vec![])]);
        assert_eq!(bind().fragments(72).unwrap(), [bind()]);
        // Too small for the header, and a PDU with a verifier.
        assert_eq!(request(vec![1]).fragments(24), Err(EncodeError::FragSize));
        let mut p = request(vec![1]);
        p.auth = Some(Auth { kind: 9, level: 6, context_id: 0, value: vec![1] });
        assert_eq!(p.fragments(1000), Err(EncodeError::FragmentAuth));
        // Responses with an object-less header split too.
        let resp = Pdu::new(4, Body::Response { alloc_hint: 9, context_id: 1, cancel_count: 0, stub: vec![5; 9] });
        let parts = resp.fragments(28).unwrap();
        assert_eq!(parts.len(), 3);
        let mut r = Reassembler::new(100);
        let mut out = None;
        for p in parts {
            out = r.push(p).unwrap();
        }
        assert_eq!(out, Some(resp));
    }

    #[test]
    fn fragments_are_bounded_and_linear() {
        // A peer that binds with a tiny max_recv_frag must not make a
        // world build millions of fragments, or copy the stub once per
        // fragment.
        assert_eq!(request(vec![0; MAX_STUB]).fragments(25), Err(EncodeError::FragSize));
        let n = MAX_FRAGMENTS;
        assert_eq!(request(vec![0; n]).fragments(25).map(|v| v.len()), Ok(n));
        assert_eq!(request(vec![0; n + 1]).fragments(25), Err(EncodeError::FragSize));
        let started = std::time::Instant::now();
        let parts = request(vec![1; 60_000]).fragments(25).unwrap();
        assert_eq!(parts.len(), 60_000);
        assert!(parts.iter().all(|p| p.body.stub() == Some(&[1][..])));
        assert!(started.elapsed().as_secs() < 2, "took {:?}", started.elapsed());
    }

    #[test]
    fn reassembly_errors() {
        let parts = request(vec![1; 30]).fragments(34).unwrap();
        assert_eq!(parts.len(), 3);
        // A middle fragment with nothing started.
        let mut r = Reassembler::default();
        assert_eq!(r.push(parts[1].clone()), Err(ReassemblyError::Unexpected { call_id: 7 }));
        // Two first fragments.
        assert_eq!(r.push(parts[0].clone()), Ok(None));
        assert_eq!(r.push(parts[0].clone()), Err(ReassemblyError::Interleaved { call_id: 7 }));
        assert_eq!(r.pending(), 0);
        // A fragment of another call.
        assert_eq!(r.push(parts[0].clone()), Ok(None));
        let mut other = parts[1].clone();
        other.call_id = 8;
        assert_eq!(r.push(other), Err(ReassemblyError::Unexpected { call_id: 8 }));
        // A fragment for another operation.
        assert_eq!(r.push(parts[0].clone()), Ok(None));
        let mut other = parts[1].clone();
        if let Body::Request { opnum, .. } = &mut other.body {
            *opnum = 4;
        }
        assert_eq!(r.push(other), Err(ReassemblyError::Unexpected { call_id: 7 }));
        // A response fragment inside a request.
        assert_eq!(r.push(parts[0].clone()), Ok(None));
        let resp = Pdu {
            flags: 0,
            ..Pdu::new(7, Body::Response { alloc_hint: 0, context_id: 0, cancel_count: 0, stub: vec![] })
        };
        assert_eq!(r.push(resp), Err(ReassemblyError::Unexpected { call_id: 7 }));
        // Over the limit, at the first fragment and later.
        let mut r = Reassembler::new(15);
        assert_eq!(r.push(parts[0].clone()), Ok(None));
        assert_eq!(r.push(parts[1].clone()), Err(ReassemblyError::TooLong { call_id: 7 }));
        let mut r = Reassembler::new(5);
        assert_eq!(r.push(parts[0].clone()), Err(ReassemblyError::TooLong { call_id: 7 }));
        // A fault or orphaned PDU ends the call; other PDUs pass by.
        let mut r = Reassembler::default();
        assert_eq!(r.push(parts[0].clone()), Ok(None));
        assert_eq!(r.push(Pdu::new(7, Body::Cancel)), Ok(Some(Pdu::new(7, Body::Cancel))));
        assert_eq!(r.pending(), 10);
        assert_eq!(r.push(Pdu::new(9, Body::Orphaned)), Ok(Some(Pdu::new(9, Body::Orphaned))));
        assert_eq!(r.pending(), 10);
        assert_eq!(r.push(Pdu::new(7, Body::Orphaned)), Ok(Some(Pdu::new(7, Body::Orphaned))));
        assert_eq!(r.pending(), 0);
        for e in [
            ReassemblyError::Interleaved { call_id: 1 },
            ReassemblyError::Unexpected { call_id: 1 },
            ReassemblyError::TooLong { call_id: 1 },
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    fn auth(context_id: u32) -> Auth {
        Auth { kind: auth_type::WINNT, level: auth_level::PKT_INTEGRITY, context_id, value: vec![7; 16] }
    }

    #[test]
    fn fragments_of_other_pdus_are_checked_first() {
        // A bind_ack too long to write is refused, not copied.
        let ack = BindAck {
            max_xmit_frag: 0,
            max_recv_frag: 0,
            assoc_group: 0,
            secondary_address: vec![0; 1 << 20],
            results: vec![],
        };
        assert_eq!(Pdu::new(1, Body::BindAck(ack)).fragments(4096), Err(EncodeError::TooLong));
        let fault = Body::Fault {
            alloc_hint: 0,
            context_id: 0,
            cancel_count: 0,
            fault_flags: 0,
            status: 0,
            stub: vec![0; 1 << 20],
        };
        assert_eq!(Pdu::new(1, fault).fragments(4096), Err(EncodeError::TooLong));
        // A PDU that writes but is longer than the fragments asked for.
        assert_eq!(bind().fragments(71), Err(EncodeError::FragSize));
        assert_eq!(bind().fragments(72).unwrap(), [bind()]);
        // A request the writer would refuse is refused before it is split.
        let mut p = request(vec![1; 300]);
        p.flags |= flags::OBJECT_UUID;
        assert_eq!(p.fragments(100), Err(EncodeError::ObjectFlag));
        let mut p = request(vec![1; 300]);
        p.version_minor = 2;
        assert_eq!(p.fragments(100), Err(EncodeError::Version(2)));
    }

    #[test]
    fn fragments_count_alloc_hint_down() {
        // MS-RPCE 2.2.2.6: each fragment's hint is the stub data left.
        let parts = request(vec![0; 1000]).fragments(124).unwrap();
        let hints: Vec<u32> = parts
            .iter()
            .map(|p| match p.body {
                Body::Request { alloc_hint, .. } => alloc_hint,
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(hints, [1000, 900, 800, 700, 600, 500, 400, 300, 200, 100]);
        // A zero hint stays zero.
        let mut p = request(vec![0; 300]);
        if let Body::Request { alloc_hint, .. } = &mut p.body {
            *alloc_hint = 0;
        }
        for f in p.fragments(124).unwrap() {
            assert!(matches!(f.body, Body::Request { alloc_hint: 0, .. }));
        }
    }

    #[test]
    fn reassembly_keeps_one_security_context() {
        // MS-RPCE 2.2.2.11: every fragment of a call has the same auth
        // type, level and context ID.
        let parts = request(vec![1; 30]).fragments(34).unwrap();
        let with = |i: usize, a: Option<Auth>| Pdu { auth: a, ..parts[i].clone() };
        let mut r = Reassembler::default();
        assert_eq!(r.push(with(0, Some(auth(1)))), Ok(None));
        assert_eq!(r.push(with(1, Some(auth(2)))), Err(ReassemblyError::Unexpected { call_id: 7 }));
        assert_eq!(r.push(with(0, Some(auth(1)))), Ok(None));
        let other = Auth { level: auth_level::PKT_PRIVACY, ..auth(1) };
        assert_eq!(r.push(with(1, Some(other))), Err(ReassemblyError::Unexpected { call_id: 7 }));
        assert_eq!(r.push(with(0, Some(auth(1)))), Ok(None));
        assert_eq!(r.push(with(1, None)), Err(ReassemblyError::Unexpected { call_id: 7 }));
        assert_eq!(r.push(with(0, None)), Ok(None));
        assert_eq!(r.push(with(1, Some(auth(1)))), Err(ReassemblyError::Unexpected { call_id: 7 }));
        // The same context throughout joins, with a different token each.
        assert_eq!(r.push(with(0, Some(auth(1)))), Ok(None));
        assert_eq!(r.push(with(1, Some(Auth { value: vec![9; 16], ..auth(1) }))), Ok(None));
        let got = r.push(with(2, Some(auth(1)))).unwrap().unwrap();
        assert_eq!(got.body.stub(), Some(&[1; 30][..]));
        assert_eq!(got.auth, None);
    }

    #[test]
    fn reassembly_keeps_a_later_cancel() {
        let resp = Pdu::new(4, Body::Response { alloc_hint: 0, context_id: 1, cancel_count: 0, stub: vec![5; 9] });
        let mut parts = resp.fragments(28).unwrap();
        assert_eq!(parts.len(), 3);
        parts[2].flags |= flags::PENDING_CANCEL;
        if let Body::Response { cancel_count, .. } = &mut parts[2].body {
            *cancel_count = 1;
        }
        let mut r = Reassembler::default();
        let mut got = None;
        for p in parts {
            got = r.push(p).unwrap();
        }
        let got = got.unwrap();
        assert_eq!(got.flags & flags::PENDING_CANCEL, flags::PENDING_CANCEL);
        assert!(matches!(got.body, Body::Response { cancel_count: 1, .. }));
        // A cancel pending on a middle fragment of a request stays too.
        let mut parts = request(vec![1; 30]).fragments(34).unwrap();
        parts[1].flags |= flags::PENDING_CANCEL;
        let mut r = Reassembler::default();
        let mut got = None;
        for p in parts {
            got = r.push(p).unwrap();
        }
        assert_eq!(got.unwrap().flags & flags::PENDING_CANCEL, flags::PENDING_CANCEL);
    }

    #[test]
    fn auth_rules_by_packet_type() {
        // MS-RPCE 2.2.2.10: an auth3 has a verifier and 4 bytes of pad.
        assert_eq!(Pdu::new(1, Body::Auth3).to_bytes(), Err(EncodeError::Auth));
        let bare = [5, 0, 16, 3, 0x10, 0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0];
        assert_eq!(Pdu::parse(&bare), Err(Error::AuthLength(0)));
        // A trailer straight after the header, with no pad.
        let mut b = bare.to_vec();
        b.extend_from_slice(&[0x0a, 2, 0, 0, 0, 0, 0, 0, 1]);
        b[8] = b.len() as u8;
        b[10] = 1;
        assert_eq!(Pdu::parse(&b), Err(Error::Truncated));
        // C706 12.6.4.5 and 12.6.4.11: a bind_nak or shutdown has none.
        for body in [Body::Shutdown, Body::BindNak(BindNak { reason: 0, versions: vec![] })] {
            let mut p = Pdu::new(1, body);
            let plain = p.to_bytes().unwrap();
            p.auth = Some(auth(0));
            assert_eq!(p.to_bytes(), Err(EncodeError::Auth));
            let mut b = plain.clone();
            b.resize(b.len().next_multiple_of(4), 0);
            b.extend_from_slice(&[0x0a, 5, (b.len() - plain.len()) as u8, 0, 0, 0, 0, 0]);
            b.extend_from_slice(&[7; 16]);
            b[8] = b.len() as u8;
            b[10] = 16;
            assert_eq!(Pdu::parse(&b), Err(Error::AuthLength(16)));
        }
    }

    #[test]
    fn auth_trailer_is_aligned() {
        // C706 13.2.6.1: the trailer starts on a 4-byte boundary. A request
        // with one byte of stub and no padding puts it at 25.
        let mut b = request(vec![9]).to_bytes().unwrap();
        b.extend_from_slice(&[0x0a, 5, 0, 0, 0, 0, 0, 0]);
        b.extend_from_slice(&[7; 16]);
        b[8] = b.len() as u8;
        b[10] = 16;
        assert_eq!(b.len(), 49);
        assert_eq!(Pdu::parse(&b), Err(Error::AuthPad(0)));
        // With 3 bytes of padding it reads.
        let mut b = request(vec![9]).to_bytes().unwrap();
        b.extend_from_slice(&[0, 0, 0, 0x0a, 5, 3, 0, 0, 0, 0, 0]);
        b.extend_from_slice(&[7; 16]);
        b[8] = b.len() as u8;
        b[10] = 16;
        let p = Pdu::parse(&b).unwrap().unwrap().0;
        assert_eq!(p.body.stub(), Some(&[9][..]));
    }

    #[test]
    fn secondary_address_ends_with_zero() {
        // C706 12.6.3.1: port_any_t's length counts its terminating zero.
        let ack = |a: &[u8]| {
            Pdu::new(
                1,
                Body::BindAck(BindAck {
                    max_xmit_frag: 0,
                    max_recv_frag: 0,
                    assoc_group: 0,
                    secondary_address: a.to_vec(),
                    results: vec![],
                }),
            )
        };
        assert_eq!(ack(b"135").to_bytes(), Err(EncodeError::Address));
        round_trip(&ack(b"135\0"));
        round_trip(&ack(b""));
        let mut b = ack(b"135\0").to_bytes().unwrap();
        b[29] = b'6';
        assert_eq!(Pdu::parse(&b), Err(Error::Address));
    }

    #[test]
    fn fault_flags_round_trip() {
        // MS-RPCE 2.2.2.8: the low bit of the byte after cancel_count says
        // extended error information follows.
        let p = Pdu::new(
            3,
            Body::Fault {
                alloc_hint: 0x24,
                context_id: 0,
                cancel_count: 0,
                fault_flags: fault_flags::EXTENDED_ERROR,
                status: status::ACCESS_DENIED,
                stub: vec![1, 2, 3, 4],
            },
        );
        let b = round_trip(&p);
        assert_eq!(b[23], 1);
    }

    #[test]
    fn decoder_gives_each_frame_as_it_came() {
        // A privacy-protected request: 3 bytes of stub and 13 bytes of
        // padding that are ciphertext too, so not zeros.
        let mut b = request(vec![1, 2, 3]).to_bytes().unwrap();
        b.extend_from_slice(&[0xee; 13]);
        b.extend_from_slice(&[0x0a, 6, 13, 0, 1, 0, 0, 0]);
        b.extend_from_slice(&[7; 16]);
        b[8] = b.len() as u8;
        b[10] = 16;
        let mut stream = b.clone();
        stream.extend(BIND);
        let mut d = Decoder::new();
        assert_eq!(d.feed(&stream), stream.len());
        let (p, frame) = d.next_frame().unwrap();
        assert_eq!(frame, &b[..]);
        let p = p.unwrap();
        assert_eq!(p.body.stub(), Some(&[1, 2, 3][..]));
        assert_eq!(p.auth.unwrap().context_id, 1);
        let (p, frame) = d.next_frame().unwrap();
        assert_eq!((p, frame), (Ok(bind()), &BIND[..]));
        assert!(d.next_frame().is_none());
        // A body that cannot be read still gives its bytes.
        let bad = [5, 0, 9, 3, 0x10, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(d.feed(&bad), 16);
        assert_eq!(d.next_frame(), Some((Err(Error::Type(9)), &bad[..])));
    }

    /// Feeds `data` in chunks of `chunk` bytes, taking PDUs out after each
    /// feed. Every result, ending with the error that broke the stream, if
    /// one did.
    fn split(data: &[u8], chunk: usize) -> Vec<Result<Pdu, Error>> {
        let mut d = Decoder::new();
        let mut out = Vec::new();
        for piece in data.chunks(chunk) {
            let mut rest = piece;
            while !rest.is_empty() {
                let took = d.feed(rest);
                assert!(d.buffered() <= MAX_BUFFERED);
                rest = &rest[took..];
                let mut progress = took > 0;
                while let Some(r) = d.next_pdu() {
                    let fatal = matches!(r, Err(e) if e.breaks_stream());
                    out.push(r);
                    if fatal {
                        return out;
                    }
                    progress = true;
                }
                assert!(progress, "a full decoder gave nothing");
            }
        }
        out
    }

    #[test]
    fn decoder_splits_a_stream() {
        let mut stream = Vec::new();
        for p in all_bodies() {
            stream.extend(p.to_bytes().unwrap());
        }
        // A PDU with a bad body, then a good one: the stream goes on.
        stream.extend_from_slice(&[5, 0, 9, 3, 0x10, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0]);
        stream.extend(BIND);
        let whole = split(&stream, stream.len());
        assert_eq!(whole.len(), all_bodies().len() + 2);
        assert_eq!(whole[whole.len() - 2], Err(Error::Type(9)));
        assert_eq!(whole[whole.len() - 1], Ok(bind()));
        for chunk in [1, 2, 7, 16, 100] {
            assert_eq!(split(&stream, chunk), whole);
        }
        // A broken header stays broken, and later bytes are dropped.
        let mut d = Decoder::new();
        assert_eq!(d.feed(&[6, 0, 0, 0]), 4);
        assert_eq!(d.next_pdu(), Some(Err(Error::Version { major: 6, minor: 0 })));
        assert_eq!(d.feed(&BIND), 72);
        assert_eq!(d.next_pdu(), Some(Err(Error::Version { major: 6, minor: 0 })));
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn decoder_holds_at_most_max_buffered() {
        let p = request(vec![3; MAX_FRAG - 24]);
        let one = p.to_bytes().unwrap();
        let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * 3).collect();
        let mut d = Decoder::new();
        assert_eq!(d.feed(&stream), MAX_BUFFERED);
        assert_eq!(d.feed(&stream[MAX_BUFFERED..]), 0);
        assert_eq!(d.next_pdu(), Some(Ok(p.clone())));
        assert_eq!(d.feed(&stream[MAX_BUFFERED..]), MAX_FRAG);
        let got = split(&stream, 5000);
        assert_eq!(got.len(), 3);
        assert!(got.iter().all(|r| r.as_ref() == Ok(&p)));
    }

    #[test]
    fn decoder_takes_many_small_pdus_in_linear_time() {
        let one = Pdu::new(1, Body::Shutdown).to_bytes().unwrap();
        let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * 200_000).collect();
        let started = std::time::Instant::now();
        let mut d = Decoder::new();
        let mut rest = &stream[..];
        let mut n = 0;
        while !rest.is_empty() {
            rest = &rest[d.feed(rest)..];
            while let Some(p) = d.next_pdu() {
                p.unwrap();
                n += 1;
            }
        }
        assert_eq!(n, 200_000);
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    /// A small deterministic generator, so the fuzz loop needs no crates.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u8 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u8
        }
    }

    /// Random bytes, often a real PDU or two with a few bytes changed, so
    /// the loop reaches the bodies.
    fn buffer(rng: &mut Lcg, samples: &[Vec<u8>]) -> Vec<u8> {
        let len = usize::from(rng.next()) % 120;
        let mut b: Vec<u8> = (0..len).map(|_| rng.next()).collect();
        if rng.next().is_multiple_of(2) && b.len() >= 16 {
            b[0] = 5;
            b[1] = rng.next() % 2;
            b[2] = rng.next() % 20;
            b[4] = 0x10 * (rng.next() % 2);
            if b[4] == 0 {
                b[8..10].copy_from_slice(&(len as u16).to_be_bytes());
            } else {
                b[8..10].copy_from_slice(&(len as u16).to_le_bytes());
            }
            b[10] = if rng.next().is_multiple_of(2) { 0 } else { rng.next() % 32 };
            b[11] = 0;
        }
        if rng.next().is_multiple_of(2) {
            b = samples[usize::from(rng.next()) % samples.len()].clone();
            if rng.next().is_multiple_of(2) {
                b.extend_from_slice(&samples[usize::from(rng.next()) % samples.len()]);
            }
            for _ in 0..usize::from(rng.next() % 4) {
                let i = usize::from(rng.next()) % b.len();
                b[i] = rng.next();
            }
        }
        b
    }

    #[test]
    fn fuzz_loop() {
        let mut samples = Vec::new();
        for mut p in all_bodies() {
            samples.push(p.to_bytes().unwrap());
            if matches!(p.body, Body::BindNak(_) | Body::Shutdown) {
                continue;
            }
            p.auth = Some(Auth { kind: 9, level: 6, context_id: 1, value: vec![1, 2, 3] });
            samples.push(p.to_bytes().unwrap());
            p.drep = DataRep::BIG_ENDIAN;
            samples.push(p.to_bytes().unwrap());
        }
        let mut rng = Lcg(0xdce);
        for _ in 0..20_000 {
            let data = buffer(&mut rng, &samples);
            let whole = split(&data, data.len().max(1));
            assert_eq!(split(&data, 1), whole);
            let mut r = Reassembler::new(64);
            for p in whole.into_iter().flatten() {
                // Whatever reads writes back and reads the same, unless the
                // writer's padding or reserved fields make it too long.
                match p.to_bytes() {
                    Ok(bytes) => assert_eq!(Pdu::parse(&bytes), Ok(Some((p.clone(), bytes.len())))),
                    Err(e) => assert_eq!(e, EncodeError::TooLong),
                }
                if p.auth.is_none()
                    && let Ok(parts) = p.fragments(40 + u16::from(rng.next()))
                {
                    let mut joined = Reassembler::default();
                    let mut got = None;
                    for f in parts {
                        assert!(f.to_bytes().is_ok());
                        got = joined.push(f).unwrap();
                    }
                    let mut want = p.clone();
                    if matches!(want.body, Body::Request { .. } | Body::Response { .. }) {
                        want.flags |= flags::FIRST_FRAG | flags::LAST_FRAG;
                    }
                    assert_eq!(got, Some(want));
                }
                let _ = r.push(p);
                assert!(r.pending() <= 64);
            }
            let _ = Pdu::parse(&data);
            let _ = Uuid::parse(&String::from_utf8_lossy(&data));
        }
    }
}
