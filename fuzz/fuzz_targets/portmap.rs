//! Portmapper and rpcbind requests and results, as a world playing a
//! portmapper reads them, and values a world builds, as it writes them.
#![no_main]

use arbitrary::{Result, Unstructured};
use fictionet::stdlib::onc_rpc::{Body, Call, Message, PMAP_PROGRAM};
use fictionet::stdlib::portmap::{
    AddrStat, CallArgs, CallResult, MAX_UADDR, Mapping, Netbuf, ParseError, PmapRequest, PmapResult, Request,
    RmtCallResult, RmtCallStat, Rpcb, RpcbEntry, RpcbRequest, RpcbResult, RpcbStat, format_uaddr,
    parse_uaddr,
};
use fictionet::stdlib::{
    codec::{Decode, Wire, contract},
    onc_rpc,
};
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, SocketAddr};

/// Any bytes as the arguments of every procedure of every version, and as
/// the results of every procedure. Whatever reads is written back to the
/// same bytes, and reads back the same.
fn read(data: &[u8]) {
    for procedure in 0..14 {
        if let Ok(r) = PmapResult::parse(procedure, data) {
            let bytes = r.to_bytes().unwrap();
            assert_eq!(bytes, data);
            assert_eq!(PmapResult::parse(procedure, &bytes), Ok(r));
        }
        if let Ok(r) = RpcbResult::parse(procedure, data) {
            let bytes = r.to_bytes().unwrap();
            assert_eq!(bytes, data);
            assert_eq!(RpcbResult::parse(procedure, &bytes), Ok(r));
        }
        for version in 1..=5 {
            let call = Call::new(PMAP_PROGRAM, version, procedure, data.to_vec());
            assert_eq!(Request::read(version, procedure, data), Request::from_call(&call));
            if let Ok(req) = Request::from_call(&call) {
                assert_eq!(req.to_call().unwrap(), call);
            }
        }
    }
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(a) = parse_uaddr(s) {
            assert_eq!(parse_uaddr(&format_uaddr(a)), Some(a));
        }
    }
}

/// A string of up to 300 bytes, so some are over the limit.
fn text(u: &mut Unstructured) -> Result<String> {
    let n = u.int_in_range(0..=300usize)?;
    Ok((0..n).map(|_| u.int_in_range(b'a'..=b'z').map(char::from)).collect::<Result<_>>()?)
}

fn bytes(u: &mut Unstructured, max: usize) -> Result<Vec<u8>> {
    let n = u.int_in_range(0..=max)?;
    Ok(u.bytes(n)?.to_vec())
}

fn mapping(u: &mut Unstructured) -> Result<Mapping> {
    Ok(Mapping {
        program: u.arbitrary()?,
        version: u.arbitrary()?,
        protocol: u.arbitrary()?,
        port: u.arbitrary()?,
    })
}

fn rpcb(u: &mut Unstructured) -> Result<Rpcb> {
    Ok(Rpcb {
        program: u.arbitrary()?,
        version: u.arbitrary()?,
        netid: text(u)?,
        addr: text(u)?,
        owner: text(u)?,
    })
}

fn call_args(u: &mut Unstructured) -> Result<CallArgs> {
    Ok(CallArgs {
        program: u.arbitrary()?,
        version: u.arbitrary()?,
        procedure: u.arbitrary()?,
        args: bytes(u, 70_000)?,
    })
}

/// A netbuf, usually with `maxlen` at least its length and at most 9000,
/// sometimes not.
fn netbuf(u: &mut Unstructured) -> Result<Netbuf> {
    let buf = bytes(u, 300)?;
    let maxlen =
        if u.arbitrary()? { u.arbitrary()? } else { buf.len() as u32 + u32::from(u.arbitrary::<u8>()?) };
    Ok(Netbuf { maxlen, buf })
}

fn stat(u: &mut Unstructured) -> Result<RpcbStat> {
    let mut s = RpcbStat { setinfo: u.arbitrary()?, unsetinfo: u.arbitrary()?, ..RpcbStat::default() };
    s.info = u.arbitrary()?;
    for _ in 0..u.int_in_range(0..=1100)? {
        s.addrinfo.push(AddrStat {
            program: u.arbitrary()?,
            version: u.arbitrary()?,
            success: u.arbitrary()?,
            failure: u.arbitrary()?,
            netid: text(u)?,
        });
    }
    for _ in 0..u.int_in_range(0..=1100)? {
        s.rmtinfo.push(RmtCallStat {
            program: u.arbitrary()?,
            version: u.arbitrary()?,
            procedure: u.arbitrary()?,
            success: u.arbitrary()?,
            failure: u.arbitrary()?,
            indirect: u.arbitrary()?,
            netid: text(u)?,
        });
    }
    Ok(s)
}

/// A request built from fuzz bytes, for any version, valid or not.
fn request(u: &mut Unstructured) -> Result<Request> {
    if u.arbitrary()? {
        return Ok(Request::Pmap(match u.int_in_range(0..=5u8)? {
            0 => PmapRequest::Null,
            1 => PmapRequest::Set(mapping(u)?),
            2 => PmapRequest::Unset(mapping(u)?),
            3 => PmapRequest::GetPort(mapping(u)?),
            4 => PmapRequest::Dump,
            _ => PmapRequest::CallIt(call_args(u)?),
        }));
    }
    let request = match u.int_in_range(0..=12u8)? {
        0 => RpcbRequest::Null,
        1 => RpcbRequest::Set(rpcb(u)?),
        2 => RpcbRequest::Unset(rpcb(u)?),
        3 => RpcbRequest::GetAddr(rpcb(u)?),
        4 => RpcbRequest::Dump,
        5 => RpcbRequest::CallIt(call_args(u)?),
        6 => RpcbRequest::GetTime,
        7 => RpcbRequest::Uaddr2Taddr(text(u)?),
        8 => RpcbRequest::Taddr2Uaddr(netbuf(u)?),
        9 => RpcbRequest::GetVersAddr(rpcb(u)?),
        10 => RpcbRequest::Indirect(call_args(u)?),
        11 => RpcbRequest::GetAddrList(rpcb(u)?),
        _ => RpcbRequest::GetStat,
    };
    Ok(Request::Rpcb { version: u.int_in_range(1..=6)?, request })
}

fn pmap_result(u: &mut Unstructured) -> Result<PmapResult> {
    Ok(match u.int_in_range(0..=4u8)? {
        0 => PmapResult::Null,
        1 => PmapResult::Bool(u.arbitrary()?),
        2 => PmapResult::Port(u.arbitrary()?),
        3 => {
            let n = u.int_in_range(0..=1100usize)?;
            PmapResult::Dump((0..n).map(|_| mapping(u)).collect::<Result<_>>()?)
        }
        _ => PmapResult::CallIt(CallResult { port: u.arbitrary()?, results: bytes(u, 70_000)? }),
    })
}

fn rpcb_result(u: &mut Unstructured) -> Result<RpcbResult> {
    Ok(match u.int_in_range(0..=8u8)? {
        0 => RpcbResult::Null,
        1 => RpcbResult::Bool(u.arbitrary()?),
        2 => RpcbResult::Addr(text(u)?),
        3 => {
            let n = u.int_in_range(0..=1100usize)?;
            RpcbResult::Dump((0..n).map(|_| rpcb(u)).collect::<Result<_>>()?)
        }
        4 => RpcbResult::CallIt(RmtCallResult { addr: text(u)?, results: bytes(u, 70_000)? }),
        5 => RpcbResult::Time(u.arbitrary()?),
        6 => RpcbResult::Netbuf(netbuf(u)?),
        7 => {
            let n = u.int_in_range(0..=1100usize)?;
            let entry = |u: &mut Unstructured| -> Result<RpcbEntry> {
                Ok(RpcbEntry {
                    maddr: text(u)?,
                    netid: text(u)?,
                    semantics: u.arbitrary()?,
                    protofmly: text(u)?,
                    proto: text(u)?,
                })
            };
            RpcbResult::AddrList((0..n).map(|_| entry(u)).collect::<Result<_>>()?)
        }
        _ => RpcbResult::Stat(Box::new([stat(u)?, stat(u)?, stat(u)?])),
    })
}

/// Values a world builds: whatever a writer accepts reads back the same.
fn built(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let req = request(&mut u)?;
    if let Ok(msg) = req.call(u.arbitrary()?) {
        let back = <Message as Wire>::parse(&msg.to_bytes().unwrap()).unwrap();
        let Body::Call(call) = &back.body else { panic!("not a call") };
        assert_eq!(Request::from_call(call), Ok(req));
    }
    let res = pmap_result(&mut u)?;
    if let Ok(bytes) = res.to_bytes() {
        assert_eq!(PmapResult::parse(res.procedure(), &bytes), Ok(res));
    }
    let res = rpcb_result(&mut u)?;
    if let Ok(bytes) = res.to_bytes() {
        assert_eq!(RpcbResult::parse(res.procedure(), &bytes), Ok(res));
    }
    let ip = if u.arbitrary()? {
        IpAddr::from(u.arbitrary::<[u8; 4]>()?)
    } else {
        IpAddr::from(u.arbitrary::<[u8; 16]>()?)
    };
    let addr = SocketAddr::new(ip, u.arbitrary()?);
    let s = format_uaddr(addr);
    assert!(s.len() <= MAX_UADDR);
    assert_eq!(parse_uaddr(&s), Some(addr));
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    const RECORD_LIMIT: usize = 1 << 16;
    contract::check_decode(|| onc_rpc::Fragments::with_limit(RECORD_LIMIT), data);
    contract::check_decode(|| onc_rpc::records(RECORD_LIMIT), data);
    contract::check_decode(
        || {
            onc_rpc::messages(RECORD_LIMIT).map(|message| {
                message.map(|message| match message.body {
                    Body::Call(call) => Some((message.xid, Request::from_call(&call))),
                    Body::Reply(_) => None,
                })
            })
        },
        data,
    );
    // Portmap arguments need version and procedure; Wire is the envelope.
    contract::check_wire::<Message>(data);
    contract::check_wire::<onc_rpc::Record>(data);
    // Any bytes as a whole message: a call a portmapper reads.
    if let Ok(msg) = <Message as Wire>::parse(data) {
        if let Body::Call(call) = &msg.body {
            match Request::from_call(call) {
                Ok(req) => {
                    let mut back = req.to_call().unwrap();
                    back.cred = call.cred.clone();
                    back.verf = call.verf.clone();
                    assert_eq!(&back, call);
                }
                Err(e) => {
                    // Only RPC version 2 is read; any other is refused.
                    if call.rpc_version != 2 {
                        assert_eq!(e, ParseError::RpcVersion(call.rpc_version));
                    }
                    let _ = msg.reply(e.reply()).to_bytes();
                }
            }
        }
    }
    read(data);
    let _ = built(data);
});
