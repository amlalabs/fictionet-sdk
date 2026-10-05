//! Portmapper and rpcbind: reading and writing every request and result of
//! the portmapper (version 2) and rpcbind (versions 3 and 4), and universal
//! addresses, with no I/O.
//!
//! An ONC RPC server listens on whatever port it likes. A client finds the
//! port by asking the portmapper, program 100000, on TCP or UDP port 111.
//! Version 2 maps a program, version and protocol to a port. Versions 3
//! and 4, called rpcbind, map a program and version on a network (a
//! "netid" such as "tcp6") to a universal address, a string such as
//! "10.0.0.5.8.1" for 10.0.0.5 port 2049. Both can also forward a call to
//! another program on the same host (CALLIT), list what is registered
//! (DUMP), and register and remove programs (SET and UNSET). This module
//! follows RFC 1833 for the procedures and RFC 5665 for universal
//! addresses.
//!
//! Nothing here reads a socket, and nothing here frames a message. The
//! [`onc_rpc`](crate::stdlib::onc_rpc) module reads and writes calls,
//! replies and TCP records. A world that plays a portmapper reads each
//! [`Call`] there, reads its [`Request`] here with
//! [`Request::from_call`], works out the answer, and writes it with
//! [`PmapResult::to_bytes`] or [`RpcbResult::to_bytes`] as the results of
//! a successful reply. What is registered, and what a forwarded call does,
//! is up to world code. A portmapper sends no reply at all when CALLIT
//! fails; [`silent_on_failure`](crate::stdlib::onc_rpc::silent_on_failure)
//! says which calls those are.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. Strings, opaque data and lists have limits, given below as
//! constants. Lists are read in a loop, never by recursion. Writers return
//! an [`EncodeError`] rather than write bytes a reader would refuse.
//!
//! ```
//! use fictionet::stdlib::onc_rpc::{Accept, Body, Call, Message, Reply, silent_on_failure};
//! use fictionet::stdlib::portmap::{
//!     format_uaddr, parse_uaddr, procedure, PmapRequest, PmapResult, Request, Rpcb, RpcbRequest,
//!     RpcbResult, IPPROTO_TCP,
//! };
//! use std::net::SocketAddr;
//!
//! /// A host at 10.0.0.5 with one program: NFS version 3 on TCP port 2049.
//! /// `None` means no reply at all.
//! fn answer(call: &Call) -> Option<Reply> {
//!     let nfs = |program: u32, version: u32| program == 100_003 && version == 3;
//!     let results = match Request::from_call(call) {
//!         Ok(Request::Pmap(PmapRequest::GetPort(m))) => {
//!             let found = nfs(m.program, m.version) && m.protocol == IPPROTO_TCP;
//!             PmapResult::Port(if found { 2049 } else { 0 }).to_bytes()
//!         }
//!         Ok(Request::Rpcb { request: RpcbRequest::GetAddr(b), .. }) => {
//!             // The netid is ignored: the call came in over TCP.
//!             let found = nfs(b.program, b.version);
//!             let addr = SocketAddr::from(([10, 0, 0, 5], 2049));
//!             RpcbResult::Addr(if found { format_uaddr(addr) } else { String::new() }).to_bytes()
//!         }
//!         Ok(Request::Pmap(PmapRequest::Null) | Request::Rpcb { request: RpcbRequest::Null, .. }) => {
//!             Ok(Vec::new())
//!         }
//!         // Forward nothing: a CALLIT that fails gets no reply.
//!         _ if silent_on_failure(call) => return None,
//!         // Register nothing and list nothing.
//!         Ok(_) => return Some(Reply::accepted(Accept::ProcUnavail)),
//!         Err(e) => return Some(Reply::accepted(e.status())),
//!     };
//!     // A GETPORT result and a short address always fit.
//!     Some(Reply::success(results.unwrap()))
//! }
//!
//! // A client asks rpcbind version 4 where NFS version 3 is on TCP. Call 9.
//! let ask = Rpcb {
//!     program: 100_003,
//!     version: 3,
//!     netid: "tcp".to_string(),
//!     addr: String::new(),
//!     owner: String::new(),
//! };
//! let request = Request::Rpcb { version: 4, request: RpcbRequest::GetAddr(ask) };
//! let message = Message::parse(&request.call(9).unwrap().to_bytes()).unwrap();
//! let Body::Call(call) = &message.body else { panic!("not a call") };
//! let reply = message.reply(answer(call).unwrap());
//!
//! // The client reads the reply.
//! let Body::Reply(Reply::Accepted { status, .. }) = reply.body else { panic!("refused") };
//! let Accept::Success(results) = status else { panic!("failed") };
//! let RpcbResult::Addr(uaddr) = RpcbResult::parse(procedure::GETADDR, &results).unwrap() else {
//!     panic!("not an address")
//! };
//! assert_eq!(uaddr, "10.0.0.5.8.1");
//! assert_eq!(parse_uaddr(&uaddr), Some(SocketAddr::from(([10, 0, 0, 5], 2049))));
//!
//! // A forwarded call gets no reply, since this host forwards nothing.
//! let forward = Request::Pmap(PmapRequest::CallIt(Default::default()));
//! assert!(answer(&forward.to_call().unwrap()).is_none());
//! ```

use std::net::{IpAddr, SocketAddr};

use super::onc_rpc::{
    Accept, Body, Call, MAX_RPCB_STRING, Message, PMAP_PROGRAM, PMAP_VERSION, RPCB_VERSION_HIGH,
    RPCB_VERSION_LOW, Reader, Writer, XdrError,
};
pub use super::onc_rpc::{IPPROTO_TCP, IPPROTO_UDP, Mapping, PORT, Rpcb};

/// The longest string this module reads or writes: a network ID, a
/// universal address, an owner, a protocol family or a protocol name.
pub const MAX_STRING: usize = MAX_RPCB_STRING;
/// The longest universal address [`parse_uaddr`] reads.
pub const MAX_UADDR: usize = MAX_STRING;
/// The most bytes of arguments or results a forwarded call (CALLIT or
/// INDIRECT) carries.
pub const MAX_CALL_DATA: usize = 65_536;
/// The most bytes of a transport address in a [`Netbuf`].
pub const MAX_NETBUF: usize = 255;
/// The most entries in any list this module reads or writes: a DUMP, an
/// address list, or the address and call lists of one [`RpcbStat`].
pub const MAX_LIST: usize = 1024;
/// How many procedure counters one [`RpcbStat`] holds: the procedures of
/// rpcbind version 4, plus one (RPCBSTAT_HIGHPROC).
pub const STAT_PROCEDURES: usize = 13;
/// How many [`RpcbStat`]s GETSTAT returns: one for each of versions 2, 3
/// and 4, in that order (RPCBVERS_STAT).
pub const STAT_VERSIONS: usize = 3;

/// Procedure numbers of the portmapper (version 2) and rpcbind (versions
/// 3 and 4). Some numbers have two names: GETPORT is GETADDR, and in
/// version 4 CALLIT is also called BCAST.
pub mod procedure {
    /// Does nothing, in every version.
    pub const NULL: u32 = 0;
    /// Registers a mapping or an address.
    pub const SET: u32 = 1;
    /// Removes the mappings or addresses of a program and version.
    pub const UNSET: u32 = 2;
    /// Version 2: the port of a program, version and protocol.
    pub const GETPORT: u32 = 3;
    /// Versions 3 and 4: the address of a program and version.
    pub const GETADDR: u32 = 3;
    /// Lists every mapping or registration.
    pub const DUMP: u32 = 4;
    /// Forwards a call to a program on the same host.
    pub const CALLIT: u32 = 5;
    /// Version 4's name for CALLIT.
    pub const BCAST: u32 = 5;
    /// Versions 3 and 4: the server's time.
    pub const GETTIME: u32 = 6;
    /// Versions 3 and 4: a universal address in binary form.
    pub const UADDR2TADDR: u32 = 7;
    /// Versions 3 and 4: a binary address as a universal address.
    pub const TADDR2UADDR: u32 = 8;
    /// Version 4: the address of exactly one version of a program.
    pub const GETVERSADDR: u32 = 9;
    /// Version 4: like CALLIT, but it replies when the call fails.
    pub const INDIRECT: u32 = 10;
    /// Version 4: every address of a program and version.
    pub const GETADDRLIST: u32 = 11;
    /// Version 4: what rpcbind counted.
    pub const GETSTAT: u32 = 12;
}

/// Common network IDs (RFC 5665, section 3).
pub mod netid {
    /// TCP over IPv4.
    pub const TCP: &str = "tcp";
    /// UDP over IPv4.
    pub const UDP: &str = "udp";
    /// TCP over IPv6.
    pub const TCP6: &str = "tcp6";
    /// UDP over IPv6.
    pub const UDP6: &str = "udp6";
}

/// Transport semantics in an [`RpcbEntry`] (the netconfig nc_semantics).
pub mod semantics {
    /// Connectionless, such as UDP.
    pub const CLTS: u32 = 1;
    /// Connection-oriented.
    pub const COTS: u32 = 2;
    /// Connection-oriented with orderly release, such as TCP.
    pub const COTS_ORD: u32 = 3;
    /// Raw.
    pub const RAW: u32 = 4;
}

/// Why a writer refused a value: a reader would refuse its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// A string, opaque data or a transport address over its limit.
    TooLong,
    /// A list of more than [`MAX_LIST`] entries.
    TooMany,
    /// An rpcbind request for a version that does not have it: a version
    /// other than 3 or 4, or a version 4 procedure for version 3.
    Version(u32),
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::TooLong => f.write_str("a string or opaque value over its limit"),
            EncodeError::TooMany => write!(f, "a list of more than {MAX_LIST} entries"),
            EncodeError::Version(v) => {
                write!(f, "rpcbind version {v} does not have this procedure")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

/// Why a call is not a request this module reads, or results are not what
/// the procedure returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The call is for another program than 100000.
    Program(u32),
    /// The call is for a version other than 2, 3 or 4.
    Version(u32),
    /// The version has no procedure with this number.
    Procedure(u32),
    /// The arguments or results do not read.
    Xdr(XdrError),
}

impl ParseError {
    /// The status a portmapper replies with when a call fails this way.
    pub fn status(&self) -> Accept {
        match self {
            ParseError::Program(_) => Accept::ProgUnavail,
            ParseError::Version(_) => Accept::ProgMismatch {
                low: PMAP_VERSION,
                high: RPCB_VERSION_HIGH,
            },
            ParseError::Procedure(_) => Accept::ProcUnavail,
            ParseError::Xdr(_) => Accept::GarbageArgs,
        }
    }
}

impl From<XdrError> for ParseError {
    fn from(e: XdrError) -> ParseError {
        ParseError::Xdr(e)
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Program(p) => write!(f, "program {p}, not the portmapper (100000)"),
            ParseError::Version(v) => write!(f, "portmapper version {v}, not 2, 3 or 4"),
            ParseError::Procedure(p) => write!(f, "no portmapper procedure {p} in this version"),
            ParseError::Xdr(e) => write!(f, "portmapper arguments or results: {e}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// The arguments of a forwarded call: the portmapper's CALLIT (call_args)
/// and rpcbind's CALLIT, BCAST and INDIRECT (rpcb_rmtcallargs) have the
/// same XDR.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CallArgs {
    /// The program to call.
    pub program: u32,
    /// The program's version.
    pub version: u32,
    /// The procedure to call.
    pub procedure: u32,
    /// The procedure's arguments, in XDR, at most [`MAX_CALL_DATA`] bytes.
    pub args: Vec<u8>,
}

impl CallArgs {
    fn read(r: &mut Reader<'_>) -> Result<CallArgs, XdrError> {
        Ok(CallArgs {
            program: r.uint()?,
            version: r.uint()?,
            procedure: r.uint()?,
            args: r.opaque(MAX_CALL_DATA)?.to_vec(),
        })
    }

    fn write(&self, w: &mut Writer) -> Result<(), EncodeError> {
        w.uint(self.program).uint(self.version).uint(self.procedure);
        opaque(w, &self.args, MAX_CALL_DATA)
    }
}

/// The results of the portmapper's CALLIT (call_result): the port of the
/// program it called, and that call's results.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CallResult {
    /// The port the called program listens on.
    pub port: u32,
    /// The called procedure's results, in XDR, at most [`MAX_CALL_DATA`]
    /// bytes.
    pub results: Vec<u8>,
}

/// The results of rpcbind's CALLIT, BCAST and INDIRECT (rpcb_rmtcallres):
/// the universal address of the program it called, and that call's
/// results.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct RmtCallResult {
    /// The called program's universal address, at most [`MAX_STRING`]
    /// bytes.
    pub addr: String,
    /// The called procedure's results, in XDR, at most [`MAX_CALL_DATA`]
    /// bytes.
    pub results: Vec<u8>,
}

/// A transport address in its binary form, such as a sockaddr (netbuf).
/// UADDR2TADDR returns one, and TADDR2UADDR takes one. Its bytes are as
/// the host lays them out, which this module does not read. As in TI-RPC,
/// a netbuf with more bytes than `maxlen` is refused when read and when
/// written.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Netbuf {
    /// The size of the buffer the bytes came from. It must be at least
    /// their length.
    pub maxlen: u32,
    /// The address, at most [`MAX_NETBUF`] bytes.
    pub buf: Vec<u8>,
}

impl Netbuf {
    fn read(r: &mut Reader<'_>) -> Result<Netbuf, XdrError> {
        let maxlen = r.uint()?;
        let max = usize::try_from(maxlen)
            .unwrap_or(usize::MAX)
            .min(MAX_NETBUF);
        Ok(Netbuf {
            maxlen,
            buf: r.opaque(max)?.to_vec(),
        })
    }

    fn write(&self, w: &mut Writer) -> Result<(), EncodeError> {
        if !u32::try_from(self.buf.len()).is_ok_and(|n| n <= self.maxlen) {
            return Err(EncodeError::TooLong);
        }
        w.uint(self.maxlen);
        opaque(w, &self.buf, MAX_NETBUF)
    }
}

/// One address of a program, as GETADDRLIST returns it (rpcb_entry): the
/// address and the transport it is on. Every string is at most
/// [`MAX_STRING`] bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct RpcbEntry {
    /// The universal address.
    pub maddr: String,
    /// The network ID, such as "tcp".
    pub netid: String,
    /// The transport's semantics, one of [`semantics`].
    pub semantics: u32,
    /// The protocol family, such as "inet" or "inet6".
    pub protofmly: String,
    /// The protocol, such as "tcp", "udp", or "-" for none.
    pub proto: String,
}

impl RpcbEntry {
    fn read(r: &mut Reader<'_>) -> Result<RpcbEntry, XdrError> {
        Ok(RpcbEntry {
            maddr: r.string(MAX_STRING)?.to_string(),
            netid: r.string(MAX_STRING)?.to_string(),
            semantics: r.uint()?,
            protofmly: r.string(MAX_STRING)?.to_string(),
            proto: r.string(MAX_STRING)?.to_string(),
        })
    }

    fn write(&self, w: &mut Writer) -> Result<(), EncodeError> {
        string(w, &self.maddr)?;
        string(w, &self.netid)?;
        w.uint(self.semantics);
        string(w, &self.protofmly)?;
        string(w, &self.proto)
    }
}

/// How often lookups of one program and version on one network went
/// (rpcbs_addrlist).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct AddrStat {
    /// The program number.
    pub program: u32,
    /// The program's version.
    pub version: u32,
    /// Lookups that found an address.
    pub success: i32,
    /// Lookups that did not.
    pub failure: i32,
    /// The network ID, at most [`MAX_STRING`] bytes.
    pub netid: String,
}

/// How often forwarded calls to one procedure went (rpcbs_rmtcalllist).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct RmtCallStat {
    /// The program number.
    pub program: u32,
    /// The program's version.
    pub version: u32,
    /// The procedure number.
    pub procedure: u32,
    /// Calls that succeeded.
    pub success: i32,
    /// Calls that failed.
    pub failure: i32,
    /// Calls made through INDIRECT.
    pub indirect: i32,
    /// The network ID, at most [`MAX_STRING`] bytes.
    pub netid: String,
}

/// What rpcbind counted for one version of its protocol (rpcb_stat).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct RpcbStat {
    /// Calls of each procedure, by number.
    pub info: [i32; STAT_PROCEDURES],
    /// SET calls that registered something.
    pub setinfo: i32,
    /// UNSET calls that removed something.
    pub unsetinfo: i32,
    /// Lookups, at most [`MAX_LIST`].
    pub addrinfo: Vec<AddrStat>,
    /// Forwarded calls, at most [`MAX_LIST`].
    pub rmtinfo: Vec<RmtCallStat>,
}

impl RpcbStat {
    fn read(r: &mut Reader<'_>) -> Result<RpcbStat, XdrError> {
        let mut info = [0; STAT_PROCEDURES];
        for n in &mut info {
            *n = r.int()?;
        }
        let setinfo = r.int()?;
        let unsetinfo = r.int()?;
        let addrinfo = read_list(r, |r| {
            Ok(AddrStat {
                program: r.uint()?,
                version: r.uint()?,
                success: r.int()?,
                failure: r.int()?,
                netid: r.string(MAX_STRING)?.to_string(),
            })
        })?;
        let rmtinfo = read_list(r, |r| {
            Ok(RmtCallStat {
                program: r.uint()?,
                version: r.uint()?,
                procedure: r.uint()?,
                success: r.int()?,
                failure: r.int()?,
                indirect: r.int()?,
                netid: r.string(MAX_STRING)?.to_string(),
            })
        })?;
        Ok(RpcbStat {
            info,
            setinfo,
            unsetinfo,
            addrinfo,
            rmtinfo,
        })
    }

    fn write(&self, w: &mut Writer) -> Result<(), EncodeError> {
        for n in self.info {
            w.int(n);
        }
        w.int(self.setinfo).int(self.unsetinfo);
        write_list(w, &self.addrinfo, |w, a| {
            w.uint(a.program)
                .uint(a.version)
                .int(a.success)
                .int(a.failure);
            string(w, &a.netid)
        })?;
        write_list(w, &self.rmtinfo, |w, c| {
            w.uint(c.program)
                .uint(c.version)
                .uint(c.procedure)
                .int(c.success)
                .int(c.failure)
                .int(c.indirect);
            string(w, &c.netid)
        })
    }
}

/// A call to the portmapper, version 2.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PmapRequest {
    /// Procedure 0: does nothing. Returns [`PmapResult::Null`].
    Null,
    /// Procedure 1: register a mapping. Returns [`PmapResult::Bool`].
    Set(Mapping),
    /// Procedure 2: remove the mappings of a program and version. The
    /// protocol and port are ignored. Returns [`PmapResult::Bool`].
    Unset(Mapping),
    /// Procedure 3: the port of a program, version and protocol. The port
    /// is ignored. Returns [`PmapResult::Port`], 0 if there is none.
    GetPort(Mapping),
    /// Procedure 4: every mapping. Returns [`PmapResult::Dump`].
    Dump,
    /// Procedure 5: call a procedure of a program on this host. The
    /// portmapper makes that call over UDP. Returns [`PmapResult::CallIt`],
    /// and no reply at all if the call fails.
    CallIt(CallArgs),
}

impl PmapRequest {
    /// Reads the request for `procedure` from a call's arguments, which
    /// must end where the request does.
    pub fn parse(procedure: u32, args: &[u8]) -> Result<PmapRequest, ParseError> {
        let mut r = Reader::new(args);
        let request = match procedure {
            procedure::NULL => PmapRequest::Null,
            procedure::SET => PmapRequest::Set(Mapping::read(&mut r)?),
            procedure::UNSET => PmapRequest::Unset(Mapping::read(&mut r)?),
            procedure::GETPORT => PmapRequest::GetPort(Mapping::read(&mut r)?),
            procedure::DUMP => PmapRequest::Dump,
            procedure::CALLIT => PmapRequest::CallIt(CallArgs::read(&mut r)?),
            p => return Err(ParseError::Procedure(p)),
        };
        r.finish()?;
        Ok(request)
    }

    /// The procedure number.
    pub fn procedure(&self) -> u32 {
        match self {
            PmapRequest::Null => procedure::NULL,
            PmapRequest::Set(_) => procedure::SET,
            PmapRequest::Unset(_) => procedure::UNSET,
            PmapRequest::GetPort(_) => procedure::GETPORT,
            PmapRequest::Dump => procedure::DUMP,
            PmapRequest::CallIt(_) => procedure::CALLIT,
        }
    }

    /// The call's arguments.
    pub fn to_args(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        match self {
            PmapRequest::Null | PmapRequest::Dump => {}
            PmapRequest::Set(m) | PmapRequest::Unset(m) | PmapRequest::GetPort(m) => {
                m.write(&mut w)
            }
            PmapRequest::CallIt(c) => c.write(&mut w)?,
        }
        Ok(w.finish())
    }
}

/// The results of a portmapper procedure.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PmapResult {
    /// NULL returns nothing.
    Null,
    /// SET and UNSET: whether anything changed.
    Bool(bool),
    /// GETPORT: the port, or 0 for none.
    Port(u32),
    /// DUMP: every mapping, at most [`MAX_LIST`].
    Dump(Vec<Mapping>),
    /// CALLIT: the called program's port and its results.
    CallIt(CallResult),
}

impl PmapResult {
    /// Reads the results of `procedure`, which must be the whole of
    /// `results`.
    pub fn parse(procedure: u32, results: &[u8]) -> Result<PmapResult, ParseError> {
        let mut r = Reader::new(results);
        let result = match procedure {
            procedure::NULL => PmapResult::Null,
            procedure::SET | procedure::UNSET => PmapResult::Bool(r.bool()?),
            procedure::GETPORT => PmapResult::Port(r.uint()?),
            procedure::DUMP => PmapResult::Dump(read_list(&mut r, Mapping::read)?),
            procedure::CALLIT => PmapResult::CallIt(CallResult {
                port: r.uint()?,
                results: r.opaque(MAX_CALL_DATA)?.to_vec(),
            }),
            p => return Err(ParseError::Procedure(p)),
        };
        r.finish()?;
        Ok(result)
    }

    /// A procedure that returns results of this kind: SET for
    /// [`PmapResult::Bool`].
    pub fn procedure(&self) -> u32 {
        match self {
            PmapResult::Null => procedure::NULL,
            PmapResult::Bool(_) => procedure::SET,
            PmapResult::Port(_) => procedure::GETPORT,
            PmapResult::Dump(_) => procedure::DUMP,
            PmapResult::CallIt(_) => procedure::CALLIT,
        }
    }

    /// The results' bytes, for [`Reply::success`](crate::stdlib::onc_rpc::Reply::success).
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        match self {
            PmapResult::Null => {}
            PmapResult::Bool(b) => {
                w.bool(*b);
            }
            PmapResult::Port(p) => {
                w.uint(*p);
            }
            PmapResult::Dump(list) => write_list(&mut w, list, |w, m| {
                m.write(w);
                Ok(())
            })?,
            PmapResult::CallIt(c) => {
                w.uint(c.port);
                opaque(&mut w, &c.results, MAX_CALL_DATA)?;
            }
        }
        Ok(w.finish())
    }
}

/// A call to rpcbind, version 3 or 4. Procedures 9 to 12 are in version 4
/// only.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RpcbRequest {
    /// Procedure 0: does nothing. Returns [`RpcbResult::Null`].
    Null,
    /// Procedure 1: register an address. Returns [`RpcbResult::Bool`].
    Set(Rpcb),
    /// Procedure 2: remove the registrations of a program and version, on
    /// one network or, with an empty netid, on all. Returns
    /// [`RpcbResult::Bool`].
    Unset(Rpcb),
    /// Procedure 3: the address of a program and version. The netid in
    /// the request is ignored: the network is the one the call came in
    /// on. Returns [`RpcbResult::Addr`], empty if there is none.
    GetAddr(Rpcb),
    /// Procedure 4: every registration. Returns [`RpcbResult::Dump`].
    Dump,
    /// Procedure 5, CALLIT, called BCAST in version 4: call a procedure
    /// of a program on this host. Returns [`RpcbResult::CallIt`], and no
    /// reply at all if the call fails.
    CallIt(CallArgs),
    /// Procedure 6: the server's time, in seconds since 1970. Returns
    /// [`RpcbResult::Time`].
    GetTime,
    /// Procedure 7: a universal address in binary form. Returns
    /// [`RpcbResult::Netbuf`].
    Uaddr2Taddr(String),
    /// Procedure 8: a binary address as a universal address. Returns
    /// [`RpcbResult::Addr`].
    Taddr2Uaddr(Netbuf),
    /// Procedure 9: like GETADDR, but only for that exact version.
    /// Returns [`RpcbResult::Addr`].
    GetVersAddr(Rpcb),
    /// Procedure 10: like CALLIT, but it replies when the call fails.
    /// Returns [`RpcbResult::CallIt`].
    Indirect(CallArgs),
    /// Procedure 11: every address of a program and version, on any
    /// network. Returns [`RpcbResult::AddrList`].
    GetAddrList(Rpcb),
    /// Procedure 12: what rpcbind counted. Returns [`RpcbResult::Stat`].
    GetStat,
}

impl RpcbRequest {
    /// Reads the request for `procedure` of rpcbind `version` from a call's
    /// arguments, which must end where the request does.
    pub fn parse(version: u32, procedure: u32, args: &[u8]) -> Result<RpcbRequest, ParseError> {
        if !(RPCB_VERSION_LOW..=RPCB_VERSION_HIGH).contains(&version) {
            return Err(ParseError::Version(version));
        }
        if version == RPCB_VERSION_LOW && procedure > procedure::TADDR2UADDR {
            return Err(ParseError::Procedure(procedure));
        }
        let mut r = Reader::new(args);
        let request = match procedure {
            procedure::NULL => RpcbRequest::Null,
            procedure::SET => RpcbRequest::Set(Rpcb::read(&mut r)?),
            procedure::UNSET => RpcbRequest::Unset(Rpcb::read(&mut r)?),
            procedure::GETADDR => RpcbRequest::GetAddr(Rpcb::read(&mut r)?),
            procedure::DUMP => RpcbRequest::Dump,
            procedure::CALLIT => RpcbRequest::CallIt(CallArgs::read(&mut r)?),
            procedure::GETTIME => RpcbRequest::GetTime,
            procedure::UADDR2TADDR => RpcbRequest::Uaddr2Taddr(r.string(MAX_STRING)?.to_string()),
            procedure::TADDR2UADDR => RpcbRequest::Taddr2Uaddr(Netbuf::read(&mut r)?),
            procedure::GETVERSADDR => RpcbRequest::GetVersAddr(Rpcb::read(&mut r)?),
            procedure::INDIRECT => RpcbRequest::Indirect(CallArgs::read(&mut r)?),
            procedure::GETADDRLIST => RpcbRequest::GetAddrList(Rpcb::read(&mut r)?),
            procedure::GETSTAT => RpcbRequest::GetStat,
            p => return Err(ParseError::Procedure(p)),
        };
        r.finish()?;
        Ok(request)
    }

    /// The procedure number.
    pub fn procedure(&self) -> u32 {
        match self {
            RpcbRequest::Null => procedure::NULL,
            RpcbRequest::Set(_) => procedure::SET,
            RpcbRequest::Unset(_) => procedure::UNSET,
            RpcbRequest::GetAddr(_) => procedure::GETADDR,
            RpcbRequest::Dump => procedure::DUMP,
            RpcbRequest::CallIt(_) => procedure::CALLIT,
            RpcbRequest::GetTime => procedure::GETTIME,
            RpcbRequest::Uaddr2Taddr(_) => procedure::UADDR2TADDR,
            RpcbRequest::Taddr2Uaddr(_) => procedure::TADDR2UADDR,
            RpcbRequest::GetVersAddr(_) => procedure::GETVERSADDR,
            RpcbRequest::Indirect(_) => procedure::INDIRECT,
            RpcbRequest::GetAddrList(_) => procedure::GETADDRLIST,
            RpcbRequest::GetStat => procedure::GETSTAT,
        }
    }

    /// The lowest rpcbind version that has this procedure: 3 or 4.
    pub fn min_version(&self) -> u32 {
        if self.procedure() > procedure::TADDR2UADDR {
            RPCB_VERSION_HIGH
        } else {
            RPCB_VERSION_LOW
        }
    }

    /// The call's arguments.
    pub fn to_args(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        match self {
            RpcbRequest::Null | RpcbRequest::Dump | RpcbRequest::GetTime | RpcbRequest::GetStat => {
            }
            RpcbRequest::Set(b)
            | RpcbRequest::Unset(b)
            | RpcbRequest::GetAddr(b)
            | RpcbRequest::GetVersAddr(b)
            | RpcbRequest::GetAddrList(b) => write_rpcb(&mut w, b)?,
            RpcbRequest::CallIt(c) | RpcbRequest::Indirect(c) => c.write(&mut w)?,
            RpcbRequest::Uaddr2Taddr(s) => string(&mut w, s)?,
            RpcbRequest::Taddr2Uaddr(n) => n.write(&mut w)?,
        }
        Ok(w.finish())
    }
}

/// The results of an rpcbind procedure.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RpcbResult {
    /// NULL returns nothing.
    Null,
    /// SET and UNSET: whether anything changed.
    Bool(bool),
    /// GETADDR, GETVERSADDR and TADDR2UADDR: a universal address, empty
    /// for none. At most [`MAX_STRING`] bytes.
    Addr(String),
    /// DUMP: every registration, at most [`MAX_LIST`].
    Dump(Vec<Rpcb>),
    /// CALLIT, BCAST and INDIRECT: the called program's address and its
    /// results.
    CallIt(RmtCallResult),
    /// GETTIME: seconds since 1970.
    Time(u32),
    /// UADDR2TADDR: the address in binary form.
    Netbuf(Netbuf),
    /// GETADDRLIST: every address, at most [`MAX_LIST`].
    AddrList(Vec<RpcbEntry>),
    /// GETSTAT: the counts for versions 2, 3 and 4, in that order.
    Stat(Box<[RpcbStat; STAT_VERSIONS]>),
}

impl RpcbResult {
    /// Reads the results of `procedure`, which must be the whole of
    /// `results`. The procedures of version 4 are read whatever the
    /// version.
    pub fn parse(procedure: u32, results: &[u8]) -> Result<RpcbResult, ParseError> {
        let mut r = Reader::new(results);
        let result = match procedure {
            procedure::NULL => RpcbResult::Null,
            procedure::SET | procedure::UNSET => RpcbResult::Bool(r.bool()?),
            procedure::GETADDR | procedure::TADDR2UADDR | procedure::GETVERSADDR => {
                RpcbResult::Addr(r.string(MAX_STRING)?.to_string())
            }
            procedure::DUMP => RpcbResult::Dump(read_list(&mut r, Rpcb::read)?),
            procedure::CALLIT | procedure::INDIRECT => RpcbResult::CallIt(RmtCallResult {
                addr: r.string(MAX_STRING)?.to_string(),
                results: r.opaque(MAX_CALL_DATA)?.to_vec(),
            }),
            procedure::GETTIME => RpcbResult::Time(r.uint()?),
            procedure::UADDR2TADDR => RpcbResult::Netbuf(Netbuf::read(&mut r)?),
            procedure::GETADDRLIST => RpcbResult::AddrList(read_list(&mut r, RpcbEntry::read)?),
            procedure::GETSTAT => RpcbResult::Stat(Box::new([
                RpcbStat::read(&mut r)?,
                RpcbStat::read(&mut r)?,
                RpcbStat::read(&mut r)?,
            ])),
            p => return Err(ParseError::Procedure(p)),
        };
        r.finish()?;
        Ok(result)
    }

    /// A procedure that returns results of this kind: SET for
    /// [`RpcbResult::Bool`], GETADDR for [`RpcbResult::Addr`] and CALLIT
    /// for [`RpcbResult::CallIt`].
    pub fn procedure(&self) -> u32 {
        match self {
            RpcbResult::Null => procedure::NULL,
            RpcbResult::Bool(_) => procedure::SET,
            RpcbResult::Addr(_) => procedure::GETADDR,
            RpcbResult::Dump(_) => procedure::DUMP,
            RpcbResult::CallIt(_) => procedure::CALLIT,
            RpcbResult::Time(_) => procedure::GETTIME,
            RpcbResult::Netbuf(_) => procedure::UADDR2TADDR,
            RpcbResult::AddrList(_) => procedure::GETADDRLIST,
            RpcbResult::Stat(_) => procedure::GETSTAT,
        }
    }

    /// The results' bytes, for [`Reply::success`](crate::stdlib::onc_rpc::Reply::success).
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        match self {
            RpcbResult::Null => {}
            RpcbResult::Bool(b) => {
                w.bool(*b);
            }
            RpcbResult::Addr(s) => string(&mut w, s)?,
            RpcbResult::Dump(list) => write_list(&mut w, list, write_rpcb)?,
            RpcbResult::CallIt(c) => {
                string(&mut w, &c.addr)?;
                opaque(&mut w, &c.results, MAX_CALL_DATA)?;
            }
            RpcbResult::Time(t) => {
                w.uint(*t);
            }
            RpcbResult::Netbuf(n) => n.write(&mut w)?,
            RpcbResult::AddrList(list) => write_list(&mut w, list, |w, e| e.write(w))?,
            RpcbResult::Stat(stats) => {
                for s in stats.iter() {
                    s.write(&mut w)?;
                }
            }
        }
        Ok(w.finish())
    }
}

/// A call to program 100000, the portmapper or rpcbind, by version.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Request {
    /// A call to version 2, the portmapper.
    Pmap(PmapRequest),
    /// A call to version 3 or 4, rpcbind.
    Rpcb {
        /// 3 or 4.
        version: u32,
        /// What the call asks.
        request: RpcbRequest,
    },
}

impl Request {
    /// Reads the request a call makes. When the call is not one, the
    /// error's [`ParseError::status`] is what a portmapper replies with,
    /// unless [`silent_on_failure`](crate::stdlib::onc_rpc::silent_on_failure)
    /// says it sends no reply. The credentials are not checked.
    pub fn from_call(call: &Call) -> Result<Request, ParseError> {
        if call.program != PMAP_PROGRAM {
            return Err(ParseError::Program(call.program));
        }
        if call.version == PMAP_VERSION {
            return Ok(Request::Pmap(PmapRequest::parse(
                call.procedure,
                &call.args,
            )?));
        }
        let request = RpcbRequest::parse(call.version, call.procedure, &call.args)?;
        Ok(Request::Rpcb {
            version: call.version,
            request,
        })
    }

    /// The version the request is for.
    pub fn version(&self) -> u32 {
        match self {
            Request::Pmap(_) => PMAP_VERSION,
            Request::Rpcb { version, .. } => *version,
        }
    }

    /// The procedure number.
    pub fn procedure(&self) -> u32 {
        match self {
            Request::Pmap(p) => p.procedure(),
            Request::Rpcb { request, .. } => request.procedure(),
        }
    }

    /// The call that makes this request, with AUTH_NONE. An rpcbind
    /// version that does not have the procedure is refused.
    pub fn to_call(&self) -> Result<Call, EncodeError> {
        let args = match self {
            Request::Pmap(p) => p.to_args()?,
            Request::Rpcb { version, request } => {
                if !(request.min_version()..=RPCB_VERSION_HIGH).contains(version) {
                    return Err(EncodeError::Version(*version));
                }
                request.to_args()?
            }
        };
        Ok(Call::new(
            PMAP_PROGRAM,
            self.version(),
            self.procedure(),
            args,
        ))
    }

    /// A call message that makes this request, with AUTH_NONE.
    pub fn call(&self, xid: u32) -> Result<Message, EncodeError> {
        Ok(Message {
            xid,
            body: Body::Call(self.to_call()?),
        })
    }
}

/// The universal address of an IP address and port (RFC 5665, sections
/// 5.2.3.3 and 5.2.3.4): the address as text, then the port's high and
/// low bytes in decimal, all joined by dots. 10.0.0.5 port 2049 is
/// "10.0.0.5.8.1". An IPv6 flow label and scope ID have no place in it
/// and are left out. [`parse_uaddr`] always reads it back.
pub fn format_uaddr(addr: SocketAddr) -> String {
    let [hi, lo] = addr.port().to_be_bytes();
    format!("{}.{hi}.{lo}", addr.ip())
}

/// Reads a universal address of an IPv4 or IPv6 address and a port. It
/// returns `None` for anything else, including the paths of local
/// transports, a port byte over 255 or with a leading zero, and strings
/// over [`MAX_UADDR`] bytes.
pub fn parse_uaddr(s: &str) -> Option<SocketAddr> {
    if s.len() > MAX_UADDR {
        return None;
    }
    let mut parts = s.rsplitn(3, '.');
    let lo = port_byte(parts.next()?)?;
    let hi = port_byte(parts.next()?)?;
    let ip: IpAddr = parts.next()?.parse().ok()?;
    Some(SocketAddr::new(ip, u16::from_be_bytes([hi, lo])))
}

/// A byte in decimal: 1 to 3 digits, with no leading zero but in "0".
fn port_byte(s: &str) -> Option<u8> {
    let b = s.as_bytes();
    if b.is_empty()
        || b.len() > 3
        || !b.iter().all(u8::is_ascii_digit)
        || (b.len() > 1 && b[0] == b'0')
    {
        return None;
    }
    s.parse().ok()
}

/// Writes a string of at most [`MAX_STRING`] bytes.
fn string(w: &mut Writer, s: &str) -> Result<(), EncodeError> {
    if s.len() > MAX_STRING {
        return Err(EncodeError::TooLong);
    }
    w.string(s);
    Ok(())
}

/// Writes opaque data of at most `max` bytes.
fn opaque(w: &mut Writer, data: &[u8], max: usize) -> Result<(), EncodeError> {
    if data.len() > max {
        return Err(EncodeError::TooLong);
    }
    w.opaque(data);
    Ok(())
}

/// Writes a registration whose strings are each at most [`MAX_STRING`]
/// bytes, as [`Rpcb::read`] reads them.
fn write_rpcb(w: &mut Writer, b: &Rpcb) -> Result<(), EncodeError> {
    w.uint(b.program).uint(b.version);
    string(w, &b.netid)?;
    string(w, &b.addr)?;
    string(w, &b.owner)
}

/// Reads an XDR linked list: each entry behind a 1, ended by a 0. A list
/// longer than [`MAX_LIST`] is refused. It reads in a loop, so a long
/// list never deepens the stack.
fn read_list<'a, T>(
    r: &mut Reader<'a>,
    mut item: impl FnMut(&mut Reader<'a>) -> Result<T, XdrError>,
) -> Result<Vec<T>, XdrError> {
    let mut out = Vec::new();
    while r.bool()? {
        if out.len() >= MAX_LIST {
            return Err(XdrError::TooLong(
                u32::try_from(MAX_LIST)
                    .unwrap_or(u32::MAX)
                    .saturating_add(1),
            ));
        }
        out.push(item(r)?);
    }
    Ok(out)
}

/// Writes an XDR linked list of at most [`MAX_LIST`] entries.
fn write_list<T>(
    w: &mut Writer,
    items: &[T],
    mut item: impl FnMut(&mut Writer, &T) -> Result<(), EncodeError>,
) -> Result<(), EncodeError> {
    if items.len() > MAX_LIST {
        return Err(EncodeError::TooMany);
    }
    for i in items {
        w.bool(true);
        item(w, i)?;
    }
    w.bool(false);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::onc_rpc::{Decoder, Reply, encode_record};
    use super::*;

    /// A small deterministic generator for the fuzz loop.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn below(&mut self, n: u32) -> u32 {
            self.next() % n
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
        fn text(&mut self, max: u32) -> String {
            let n = self.below(max + 1);
            (0..n)
                .map(|_| char::from(b'a' + self.below(26) as u8))
                .collect()
        }
        fn rpcb(&mut self) -> Rpcb {
            Rpcb {
                program: self.next(),
                version: self.next(),
                netid: self.text(6),
                addr: self.text(20),
                owner: self.text(5),
            }
        }
        fn call_args(&mut self) -> CallArgs {
            let n = self.below(40) as usize;
            CallArgs {
                program: self.next(),
                version: self.next(),
                procedure: self.next(),
                args: self.bytes(n),
            }
        }
        fn mapping(&mut self) -> Mapping {
            Mapping {
                program: self.next(),
                version: self.next(),
                protocol: self.next(),
                port: self.next(),
            }
        }
        fn stat(&mut self) -> RpcbStat {
            let mut s = RpcbStat {
                setinfo: self.next() as i32,
                unsetinfo: self.next() as i32,
                ..RpcbStat::default()
            };
            for n in &mut s.info {
                *n = self.next() as i32;
            }
            for _ in 0..self.below(3) {
                s.addrinfo.push(AddrStat {
                    program: self.next(),
                    version: self.next(),
                    success: self.next() as i32,
                    failure: self.next() as i32,
                    netid: self.text(4),
                });
            }
            for _ in 0..self.below(3) {
                s.rmtinfo.push(RmtCallStat {
                    program: self.next(),
                    version: self.next(),
                    procedure: self.next(),
                    success: self.next() as i32,
                    failure: self.next() as i32,
                    indirect: self.next() as i32,
                    netid: self.text(4),
                });
            }
            s
        }
        fn request(&mut self) -> Request {
            if self.below(3) == 0 {
                return Request::Pmap(match self.below(6) {
                    0 => PmapRequest::Null,
                    1 => PmapRequest::Set(self.mapping()),
                    2 => PmapRequest::Unset(self.mapping()),
                    3 => PmapRequest::GetPort(self.mapping()),
                    4 => PmapRequest::Dump,
                    _ => PmapRequest::CallIt(self.call_args()),
                });
            }
            let request = match self.below(13) {
                0 => RpcbRequest::Null,
                1 => RpcbRequest::Set(self.rpcb()),
                2 => RpcbRequest::Unset(self.rpcb()),
                3 => RpcbRequest::GetAddr(self.rpcb()),
                4 => RpcbRequest::Dump,
                5 => RpcbRequest::CallIt(self.call_args()),
                6 => RpcbRequest::GetTime,
                7 => RpcbRequest::Uaddr2Taddr(self.text(30)),
                8 => {
                    let n = self.below(20) as usize;
                    RpcbRequest::Taddr2Uaddr(Netbuf {
                        maxlen: n as u32 + self.below(100),
                        buf: self.bytes(n),
                    })
                }
                9 => RpcbRequest::GetVersAddr(self.rpcb()),
                10 => RpcbRequest::Indirect(self.call_args()),
                11 => RpcbRequest::GetAddrList(self.rpcb()),
                _ => RpcbRequest::GetStat,
            };
            let version = if request.min_version() == 4 {
                4
            } else {
                3 + self.below(2)
            };
            Request::Rpcb { version, request }
        }
        fn pmap_result(&mut self) -> PmapResult {
            match self.below(5) {
                0 => PmapResult::Null,
                1 => PmapResult::Bool(self.below(2) == 1),
                2 => PmapResult::Port(self.next()),
                3 => PmapResult::Dump((0..self.below(4)).map(|_| self.mapping()).collect()),
                _ => {
                    let n = self.below(30) as usize;
                    PmapResult::CallIt(CallResult {
                        port: self.next(),
                        results: self.bytes(n),
                    })
                }
            }
        }
        fn rpcb_result(&mut self) -> RpcbResult {
            match self.below(9) {
                0 => RpcbResult::Null,
                1 => RpcbResult::Bool(self.below(2) == 1),
                2 => RpcbResult::Addr(self.text(30)),
                3 => RpcbResult::Dump((0..self.below(4)).map(|_| self.rpcb()).collect()),
                4 => {
                    let n = self.below(30) as usize;
                    RpcbResult::CallIt(RmtCallResult {
                        addr: self.text(20),
                        results: self.bytes(n),
                    })
                }
                5 => RpcbResult::Time(self.next()),
                6 => {
                    let n = self.below(20) as usize;
                    RpcbResult::Netbuf(Netbuf {
                        maxlen: n as u32 + self.below(100),
                        buf: self.bytes(n),
                    })
                }
                7 => RpcbResult::AddrList(
                    (0..self.below(4))
                        .map(|_| RpcbEntry {
                            maddr: self.text(20),
                            netid: self.text(5),
                            semantics: self.next(),
                            protofmly: self.text(5),
                            proto: self.text(3),
                        })
                        .collect(),
                ),
                _ => RpcbResult::Stat(Box::new([self.stat(), self.stat(), self.stat()])),
            }
        }
    }

    fn nfs_rpcb() -> Rpcb {
        Rpcb {
            program: 100_003,
            version: 3,
            netid: "tcp".to_string(),
            addr: "10.0.0.5.8.1".to_string(),
            owner: "superuser".to_string(),
        }
    }

    /// Bytes of a request after the RPC header, checked by hand against
    /// RFC 1833's XDR.
    #[test]
    fn pmap_getport_bytes() {
        let m = Mapping {
            program: 100_003,
            version: 3,
            protocol: IPPROTO_UDP,
            port: 0,
        };
        let args = PmapRequest::GetPort(m).to_args().unwrap();
        assert_eq!(
            args,
            [0, 1, 0x86, 0xa3, 0, 0, 0, 3, 0, 0, 0, 17, 0, 0, 0, 0]
        );
        assert_eq!(
            PmapRequest::parse(procedure::GETPORT, &args),
            Ok(PmapRequest::GetPort(m))
        );
        assert_eq!(PmapResult::Port(2049).to_bytes().unwrap(), [0, 0, 8, 1]);
    }

    #[test]
    fn pmap_dump_bytes() {
        let a = Mapping {
            program: 100_000,
            version: 2,
            protocol: IPPROTO_TCP,
            port: 111,
        };
        let bytes = PmapResult::Dump(vec![a]).to_bytes().unwrap();
        assert_eq!(
            bytes,
            [
                0, 0, 0, 1, 0, 1, 0x86, 0xa0, 0, 0, 0, 2, 0, 0, 0, 6, 0, 0, 0, 111, 0, 0, 0, 0
            ]
        );
        assert_eq!(
            PmapResult::parse(procedure::DUMP, &bytes),
            Ok(PmapResult::Dump(vec![a]))
        );
        assert_eq!(PmapResult::Dump(vec![]).to_bytes().unwrap(), [0, 0, 0, 0]);
    }

    #[test]
    fn pmap_callit_bytes() {
        let c = CallArgs {
            program: 100_005,
            version: 1,
            procedure: 0,
            args: vec![1, 2, 3],
        };
        let args = PmapRequest::CallIt(c.clone()).to_args().unwrap();
        assert_eq!(
            args,
            [
                0, 1, 0x86, 0xa5, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 1, 2, 3, 0
            ]
        );
        assert_eq!(
            PmapRequest::parse(procedure::CALLIT, &args),
            Ok(PmapRequest::CallIt(c))
        );
        let r = PmapResult::CallIt(CallResult {
            port: 635,
            results: vec![],
        });
        assert_eq!(r.to_bytes().unwrap(), [0, 0, 2, 0x7b, 0, 0, 0, 0]);
    }

    #[test]
    fn rpcb_getaddr_bytes() {
        let args = RpcbRequest::GetAddr(nfs_rpcb()).to_args().unwrap();
        let mut want = vec![
            0, 1, 0x86, 0xa3, 0, 0, 0, 3, 0, 0, 0, 3, b't', b'c', b'p', 0,
        ];
        want.extend_from_slice(&[0, 0, 0, 12]);
        want.extend_from_slice(b"10.0.0.5.8.1");
        want.extend_from_slice(&[0, 0, 0, 9]);
        want.extend_from_slice(b"superuser\0\0\0");
        assert_eq!(args, want);
        assert_eq!(
            RpcbRequest::parse(3, procedure::GETADDR, &args),
            Ok(RpcbRequest::GetAddr(nfs_rpcb()))
        );
        let r = RpcbResult::Addr("10.0.0.5.8.1".into()).to_bytes().unwrap();
        assert_eq!(r[..4], [0, 0, 0, 12]);
        assert_eq!(
            RpcbResult::parse(procedure::GETVERSADDR, &r),
            Ok(RpcbResult::Addr("10.0.0.5.8.1".into()))
        );
    }

    #[test]
    fn rpcb_getstat_bytes() {
        let stats = Box::new([
            RpcbStat::default(),
            RpcbStat::default(),
            RpcbStat::default(),
        ]);
        let bytes = RpcbResult::Stat(stats.clone()).to_bytes().unwrap();
        // 13 counters, setinfo, unsetinfo, and two empty lists, three times.
        assert_eq!(bytes.len(), 3 * 17 * 4);
        assert!(bytes.iter().all(|&b| b == 0));
        assert_eq!(
            RpcbResult::parse(procedure::GETSTAT, &bytes),
            Ok(RpcbResult::Stat(stats))
        );
    }

    #[test]
    fn rpcb_entry_bytes() {
        let e = RpcbEntry {
            maddr: "0.0.0.0.0.111".into(),
            netid: "udp".into(),
            semantics: semantics::CLTS,
            protofmly: "inet".into(),
            proto: "udp".into(),
        };
        let bytes = RpcbResult::AddrList(vec![e.clone()]).to_bytes().unwrap();
        assert_eq!(bytes[..8], [0, 0, 0, 1, 0, 0, 0, 13]);
        assert_eq!(bytes[bytes.len() - 4..], [0, 0, 0, 0]);
        assert_eq!(
            RpcbResult::parse(procedure::GETADDRLIST, &bytes),
            Ok(RpcbResult::AddrList(vec![e]))
        );
    }

    #[test]
    fn uaddr_examples() {
        let v4 = SocketAddr::from(([10, 0, 0, 5], 2049));
        assert_eq!(format_uaddr(v4), "10.0.0.5.8.1");
        assert_eq!(parse_uaddr("10.0.0.5.8.1"), Some(v4));
        assert_eq!(
            parse_uaddr("0.0.0.0.0.111"),
            Some(SocketAddr::from(([0, 0, 0, 0], 111)))
        );
        let v6: SocketAddr = "[::1]:111".parse().unwrap();
        assert_eq!(format_uaddr(v6), "::1.0.111");
        assert_eq!(parse_uaddr("::1.0.111"), Some(v6));
        let mapped: SocketAddr = "[::ffff:1.2.3.4]:2049".parse().unwrap();
        assert_eq!(parse_uaddr(&format_uaddr(mapped)), Some(mapped));
        for bad in [
            "",
            "10.0.0.5",
            "10.0.0.5.8",
            "10.0.0.5.8.256",
            "10.0.0.5.08.1",
            "10.0.0.5.8.-1",
            "10.0.0.5.8.1 ",
            "10.0.0.5..1",
            "/var/run/rpcbind.sock",
            "300.0.0.5.8.1",
            "fe80::1%eth0.0.111",
        ] {
            assert_eq!(parse_uaddr(bad), None, "{bad:?}");
        }
        let long = format!("{}.0.1", "1".repeat(MAX_UADDR));
        assert_eq!(parse_uaddr(&long), None);
    }

    #[test]
    fn from_call_errors() {
        let call = Call::new(100_003, 2, 0, vec![]);
        assert_eq!(Request::from_call(&call), Err(ParseError::Program(100_003)));
        assert_eq!(ParseError::Program(1).status(), Accept::ProgUnavail);
        let call = Call::new(PMAP_PROGRAM, 5, 0, vec![]);
        assert_eq!(Request::from_call(&call), Err(ParseError::Version(5)));
        assert_eq!(
            ParseError::Version(5).status(),
            Accept::ProgMismatch { low: 2, high: 4 }
        );
        let call = Call::new(PMAP_PROGRAM, 1, 0, vec![]);
        assert_eq!(Request::from_call(&call), Err(ParseError::Version(1)));
        let call = Call::new(PMAP_PROGRAM, 2, 6, vec![]);
        assert_eq!(Request::from_call(&call), Err(ParseError::Procedure(6)));
        assert_eq!(ParseError::Procedure(6).status(), Accept::ProcUnavail);
        // Version 3 has no procedure 9; version 4 does.
        let call = Call::new(
            PMAP_PROGRAM,
            3,
            9,
            RpcbRequest::GetVersAddr(nfs_rpcb()).to_args().unwrap(),
        );
        assert_eq!(Request::from_call(&call), Err(ParseError::Procedure(9)));
        let call = Call { version: 4, ..call };
        assert!(Request::from_call(&call).is_ok());
        let call = Call::new(PMAP_PROGRAM, 4, 13, vec![]);
        assert_eq!(Request::from_call(&call), Err(ParseError::Procedure(13)));
        // Trailing bytes and short arguments.
        let call = Call::new(PMAP_PROGRAM, 2, 0, vec![0, 0, 0, 0]);
        assert_eq!(
            Request::from_call(&call),
            Err(ParseError::Xdr(XdrError::Trailing(4)))
        );
        assert_eq!(
            ParseError::Xdr(XdrError::Short).status(),
            Accept::GarbageArgs
        );
        let call = Call::new(PMAP_PROGRAM, 2, 3, vec![0, 0, 0]);
        assert_eq!(
            Request::from_call(&call),
            Err(ParseError::Xdr(XdrError::Short))
        );
        assert_eq!(RpcbRequest::parse(2, 0, &[]), Err(ParseError::Version(2)));
    }

    #[test]
    fn parse_errors() {
        assert_eq!(PmapResult::parse(6, &[]), Err(ParseError::Procedure(6)));
        assert_eq!(RpcbResult::parse(13, &[]), Err(ParseError::Procedure(13)));
        assert_eq!(
            PmapResult::parse(1, &[0, 0, 0, 2]),
            Err(ParseError::Xdr(XdrError::Bool(2)))
        );
        // A string over the limit.
        let mut b = vec![0, 0, 1, 0];
        b.extend_from_slice(&[b'a'; 256]);
        assert_eq!(
            RpcbResult::parse(3, &b),
            Err(ParseError::Xdr(XdrError::TooLong(256)))
        );
        // Not UTF-8.
        assert_eq!(
            RpcbResult::parse(3, &[0, 0, 0, 1, 0xff, 0, 0, 0]),
            Err(ParseError::Xdr(XdrError::Utf8))
        );
        // Nonzero padding.
        assert_eq!(
            RpcbResult::parse(3, &[0, 0, 0, 1, b'a', 1, 0, 0]),
            Err(ParseError::Xdr(XdrError::Padding))
        );
        // Call data over the limit.
        let mut b = vec![0, 0, 0, 0];
        b.extend_from_slice(&(MAX_CALL_DATA as u32 + 1).to_be_bytes());
        assert!(matches!(
            PmapResult::parse(5, &b),
            Err(ParseError::Xdr(XdrError::TooLong(_)))
        ));
        // A list one entry too long.
        let list = vec![
            Mapping {
                program: 1,
                version: 1,
                protocol: 6,
                port: 1
            };
            MAX_LIST
        ];
        let mut b = PmapResult::Dump(list).to_bytes().unwrap();
        b.truncate(b.len() - 4);
        b.extend_from_slice(&[
            0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0, 1, 0, 0, 0, 0,
        ]);
        assert_eq!(
            PmapResult::parse(4, &b),
            Err(ParseError::Xdr(XdrError::TooLong(MAX_LIST as u32 + 1)))
        );
        // A list bool that is not 0 or 1.
        assert_eq!(
            RpcbResult::parse(4, &[0, 0, 0, 7]),
            Err(ParseError::Xdr(XdrError::Bool(7)))
        );
        assert_eq!(
            RpcbResult::parse(0, &[0]),
            Err(ParseError::Xdr(XdrError::Trailing(1)))
        );
        for e in [
            ParseError::Program(1),
            ParseError::Version(1),
            ParseError::Procedure(1),
            ParseError::Xdr(XdrError::Short),
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn encode_errors() {
        let long = "x".repeat(MAX_STRING + 1);
        assert_eq!(
            RpcbResult::Addr(long.clone()).to_bytes(),
            Err(EncodeError::TooLong)
        );
        assert_eq!(
            RpcbResult::Addr("x".repeat(MAX_STRING))
                .to_bytes()
                .map(|b| b.len()),
            Ok(4 + 256)
        );
        let b = Rpcb {
            owner: long.clone(),
            ..nfs_rpcb()
        };
        assert_eq!(RpcbRequest::Set(b).to_args(), Err(EncodeError::TooLong));
        assert_eq!(
            RpcbRequest::Uaddr2Taddr(long).to_args(),
            Err(EncodeError::TooLong)
        );
        let c = CallArgs {
            program: 1,
            version: 1,
            procedure: 1,
            args: vec![0; MAX_CALL_DATA + 1],
        };
        assert_eq!(PmapRequest::CallIt(c).to_args(), Err(EncodeError::TooLong));
        let n = Netbuf {
            maxlen: u32::MAX,
            buf: vec![0; MAX_NETBUF + 1],
        };
        assert_eq!(
            RpcbRequest::Taddr2Uaddr(n.clone()).to_args(),
            Err(EncodeError::TooLong)
        );
        assert_eq!(RpcbResult::Netbuf(n).to_bytes(), Err(EncodeError::TooLong));
        let r = RmtCallResult {
            addr: String::new(),
            results: vec![0; MAX_CALL_DATA + 1],
        };
        assert_eq!(RpcbResult::CallIt(r).to_bytes(), Err(EncodeError::TooLong));
        let r = CallResult {
            port: 0,
            results: vec![0; MAX_CALL_DATA + 1],
        };
        assert_eq!(PmapResult::CallIt(r).to_bytes(), Err(EncodeError::TooLong));
        let list = vec![
            Mapping {
                program: 0,
                version: 0,
                protocol: 0,
                port: 0
            };
            MAX_LIST + 1
        ];
        assert_eq!(PmapResult::Dump(list).to_bytes(), Err(EncodeError::TooMany));
        assert_eq!(
            RpcbResult::AddrList(vec![RpcbEntry::default(); MAX_LIST + 1]).to_bytes(),
            Err(EncodeError::TooMany)
        );
        let s = RpcbStat { rmtinfo: vec![RmtCallStat::default(); MAX_LIST + 1], ..Default::default() };
        let stats = Box::new([RpcbStat::default(), RpcbStat::default(), s]);
        assert_eq!(
            RpcbResult::Stat(stats).to_bytes(),
            Err(EncodeError::TooMany)
        );
        let r = Request::Rpcb {
            version: 3,
            request: RpcbRequest::GetStat,
        };
        assert_eq!(r.call(1), Err(EncodeError::Version(3)));
        let r = Request::Rpcb {
            version: 2,
            request: RpcbRequest::Null,
        };
        assert_eq!(r.to_call(), Err(EncodeError::Version(2)));
        let r = Request::Rpcb {
            version: 5,
            request: RpcbRequest::Null,
        };
        assert_eq!(r.to_call(), Err(EncodeError::Version(5)));
        for e in [
            EncodeError::TooLong,
            EncodeError::TooMany,
            EncodeError::Version(3),
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    /// A netbuf holds at most `maxlen` bytes, as TI-RPC's xdr_netbuf
    /// reads it: more bytes than the buffer's size are refused, by the
    /// reader and the writer alike.
    #[test]
    fn netbuf_len_within_maxlen() {
        let fits = Netbuf {
            maxlen: 4,
            buf: vec![1, 2, 3, 4],
        };
        let bytes = RpcbResult::Netbuf(fits.clone()).to_bytes().unwrap();
        assert_eq!(bytes, [0, 0, 0, 4, 0, 0, 0, 4, 1, 2, 3, 4]);
        assert_eq!(
            RpcbResult::parse(procedure::UADDR2TADDR, &bytes),
            Ok(RpcbResult::Netbuf(fits))
        );
        let over = [0, 0, 0, 3, 0, 0, 0, 4, 1, 2, 3, 4];
        assert_eq!(
            RpcbResult::parse(procedure::UADDR2TADDR, &over),
            Err(ParseError::Xdr(XdrError::TooLong(4)))
        );
        assert_eq!(
            RpcbRequest::parse(3, procedure::TADDR2UADDR, &over),
            Err(ParseError::Xdr(XdrError::TooLong(4)))
        );
        let n = Netbuf {
            maxlen: 3,
            buf: vec![1, 2, 3, 4],
        };
        assert_eq!(
            RpcbRequest::Taddr2Uaddr(n.clone()).to_args(),
            Err(EncodeError::TooLong)
        );
        assert_eq!(RpcbResult::Netbuf(n).to_bytes(), Err(EncodeError::TooLong));
    }

    /// CALLIT and BCAST, in every version, are the calls that get no reply
    /// when they fail. INDIRECT and the rest are not.
    #[test]
    fn silent_calls() {
        use super::super::onc_rpc::silent_on_failure;
        let c = CallArgs::default();
        let silent = [
            Request::Pmap(PmapRequest::CallIt(c.clone())),
            Request::Rpcb {
                version: 3,
                request: RpcbRequest::CallIt(c.clone()),
            },
            Request::Rpcb {
                version: 4,
                request: RpcbRequest::CallIt(c.clone()),
            },
        ];
        for r in &silent {
            assert!(silent_on_failure(&r.to_call().unwrap()), "{r:?}");
        }
        let loud = [
            Request::Pmap(PmapRequest::Dump),
            Request::Rpcb {
                version: 4,
                request: RpcbRequest::Indirect(c),
            },
            Request::Rpcb {
                version: 3,
                request: RpcbRequest::GetTime,
            },
        ];
        for r in &loud {
            assert!(!silent_on_failure(&r.to_call().unwrap()), "{r:?}");
        }
    }

    /// Values built from defaults write, and read back the same.
    #[test]
    fn defaults_round_trip() {
        check_request(&Request::Pmap(PmapRequest::CallIt(CallArgs::default())));
        check_request(&Request::Rpcb {
            version: 3,
            request: RpcbRequest::Taddr2Uaddr(Netbuf::default()),
        });
        check_pmap_result(&PmapResult::CallIt(CallResult::default()));
        check_rpcb_result(&RpcbResult::CallIt(RmtCallResult::default()));
        check_rpcb_result(&RpcbResult::AddrList(vec![RpcbEntry::default()]));
        check_rpcb_result(&RpcbResult::Stat(Box::default()));
    }

    /// Checks a request: its call reads back the same, and every shorter
    /// prefix of its arguments is refused.
    fn check_request(req: &Request) {
        let call = req.to_call().unwrap();
        assert_eq!(Request::from_call(&call).as_ref(), Ok(req));
        let msg = req.call(42).unwrap();
        let Body::Call(back) = Message::parse(&msg.to_bytes()).unwrap().body else {
            panic!()
        };
        assert_eq!(Request::from_call(&back).as_ref(), Ok(req));
        for n in 0..call.args.len() {
            let short = Call {
                args: call.args[..n].to_vec(),
                ..call.clone()
            };
            assert!(Request::from_call(&short).is_err(), "{req:?} prefix {n}");
        }
    }

    fn check_pmap_result(res: &PmapResult) {
        let bytes = res.to_bytes().unwrap();
        assert_eq!(PmapResult::parse(res.procedure(), &bytes).as_ref(), Ok(res));
        for n in 0..bytes.len() {
            assert!(PmapResult::parse(res.procedure(), &bytes[..n]).is_err());
        }
    }

    fn check_rpcb_result(res: &RpcbResult) {
        let bytes = res.to_bytes().unwrap();
        assert_eq!(RpcbResult::parse(res.procedure(), &bytes).as_ref(), Ok(res));
        for n in 0..bytes.len() {
            assert!(RpcbResult::parse(res.procedure(), &bytes[..n]).is_err());
        }
    }

    #[test]
    fn round_trips_and_prefixes() {
        let mut g = Lcg(1);
        for _ in 0..600 {
            let req = g.request();
            check_request(&req);
            check_pmap_result(&g.pmap_result());
            check_rpcb_result(&g.rpcb_result());
        }
    }

    #[test]
    fn every_kind_round_trips() {
        let mut g = Lcg(2);
        // Enough draws to hit every variant many times.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2000 {
            let req = g.request();
            seen.insert((req.version().min(3), req.procedure()));
            check_request(&req);
        }
        // Version 2 has 6 procedures; versions 3 and 4 together have 13.
        assert_eq!(seen.len(), 6 + 13);
    }

    #[test]
    fn uaddr_round_trips() {
        let mut g = Lcg(3);
        for _ in 0..5000 {
            let port = g.next() as u16;
            let ip = if g.below(2) == 0 {
                IpAddr::from(g.next().to_be_bytes())
            } else {
                let mut b = [0u8; 16];
                for x in &mut b {
                    // Plenty of zeros, so "::" shows up.
                    *x = if g.below(2) == 0 { 0 } else { g.next() as u8 };
                }
                IpAddr::from(b)
            };
            let a = SocketAddr::new(ip, port);
            let s = format_uaddr(a);
            assert!(s.len() <= MAX_UADDR);
            assert_eq!(parse_uaddr(&s), Some(a), "{s}");
            assert_eq!(
                RpcbResult::parse(3, &RpcbResult::Addr(s.clone()).to_bytes().unwrap()),
                Ok(RpcbResult::Addr(s))
            );
        }
    }

    /// Whatever reads is written back, and reads back the same.
    fn reread(data: &[u8]) {
        for p in 0..14 {
            if let Ok(r) = PmapResult::parse(p, data) {
                let b = r.to_bytes().unwrap();
                assert_eq!(b, data);
                assert_eq!(PmapResult::parse(p, &b), Ok(r));
            }
            if let Ok(r) = RpcbResult::parse(p, data) {
                let b = r.to_bytes().unwrap();
                assert_eq!(b, data);
                assert_eq!(RpcbResult::parse(p, &b), Ok(r));
            }
            for v in 2..=5 {
                let call = Call::new(PMAP_PROGRAM, v, p, data.to_vec());
                if let Ok(req) = Request::from_call(&call) {
                    assert_eq!(req.to_call().unwrap(), call);
                }
            }
        }
        if let Ok(s) = std::str::from_utf8(data)
            && let Some(a) = parse_uaddr(s) {
                assert_eq!(parse_uaddr(&format_uaddr(a)), Some(a));
            }
    }

    #[test]
    fn lcg_fuzz() {
        let mut g = Lcg(0x5eed);
        for i in 0..6000 {
            let data = match i % 3 {
                // Random bytes, mostly small values so bools and lengths
                // sometimes read.
                0 => {
                    let n = g.below(80) as usize;
                    (0..n)
                        .map(|_| if g.below(3) == 0 { g.next() as u8 } else { 0 })
                        .collect::<Vec<u8>>()
                }
                // A valid encoding with a byte changed.
                1 => {
                    let mut b = if g.below(2) == 0 {
                        g.rpcb_result().to_bytes().unwrap()
                    } else {
                        g.request().to_call().unwrap().args
                    };
                    if !b.is_empty() {
                        let at = g.below(b.len() as u32) as usize;
                        b[at] = g.next() as u8;
                    }
                    b
                }
                // Text that looks like a universal address.
                _ => {
                    let alphabet = b"0123456789.:abcdef";
                    let n = g.below(30) as usize;
                    (0..n)
                        .map(|_| alphabet[g.below(alphabet.len() as u32) as usize])
                        .collect()
                }
            };
            reread(&data);
        }
    }

    /// Calls in TCP records, fed to a record decoder a byte at a time and
    /// all at once, read the same.
    #[test]
    fn lcg_fuzz_stream() {
        let mut g = Lcg(77);
        for _ in 0..300 {
            let mut stream = Vec::new();
            let mut want = Vec::new();
            for xid in 0..g.below(4) {
                let req = g.request();
                let mut bytes = req.call(xid).unwrap().to_bytes();
                if g.below(4) == 0 && bytes.len() > 40 {
                    let at = 40 + g.below((bytes.len() - 40) as u32) as usize;
                    bytes[at] ^= 1 + g.below(255) as u8;
                }
                stream.extend_from_slice(&encode_record(&bytes));
                want.push(bytes);
            }
            for bytewise in [false, true] {
                let mut d = Decoder::new();
                let mut got = Vec::new();
                let chunks: Vec<&[u8]> = if bytewise {
                    stream.chunks(1).collect()
                } else {
                    vec![&stream[..]]
                };
                for c in chunks {
                    d.feed(c);
                    while let Some(rec) = d.next_record() {
                        got.push(rec.unwrap());
                    }
                }
                assert_eq!(got, want);
                for rec in &got {
                    let Ok(msg) = Message::parse(rec) else {
                        continue;
                    };
                    let Body::Call(call) = &msg.body else {
                        panic!()
                    };
                    match Request::from_call(call) {
                        Ok(req) => assert_eq!(&req.to_call().unwrap(), call),
                        Err(e) => {
                            let _ = msg.reply(Reply::accepted(e.status())).to_bytes();
                        }
                    }
                }
            }
        }
    }
}
