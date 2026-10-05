//! NFS version 3 and MOUNT version 3 calls and results, as a world
//! playing a file server, or a client, reads them.
#![no_main]

use fictionet::stdlib::nfs::{
    DirOp, FileHandle, MAX_FH, MAX_NAME, MountRequest, MountResponse, NfsError, Request, Response, procedure,
};
use fictionet::stdlib::onc_rpc::{Body, Decoder, Message};
use libfuzzer_sys::fuzz_target;

/// Reads `bytes` as the arguments and the results of procedure `p`. Any
/// that read must write back as the same bytes, and READ and WRITE must
/// count the data they carry.
fn check(p: u32, bytes: &[u8]) {
    if let Ok(req) = Request::read(p, bytes) {
        assert_eq!(req.to_args(), bytes);
        if let Request::Write { count, data, .. } = &req {
            assert_eq!(*count as usize, data.len());
        }
    }
    if let Ok(resp) = Response::parse(p, bytes) {
        assert_eq!(resp.to_results(), bytes);
        if let Response::Read(Ok(ok)) = &resp {
            assert_eq!(ok.count as usize, ok.data.len());
        }
    }
    if let Ok(req) = MountRequest::read(p, bytes) {
        assert_eq!(req.to_args(), bytes);
    }
    if let Ok(resp) = MountResponse::parse(p, bytes) {
        assert_eq!(resp.to_results(), bytes);
    }
}

fuzz_target!(|data: &[u8]| {
    // The first byte picks a procedure. The rest is its arguments or
    // results.
    if let Some((&p, rest)) = data.split_first() {
        check(u32::from(p % 24), rest);
    }

    // A handle and a name made from the bytes, of any length and any
    // bytes, write back as themselves or, past their limits, as nothing:
    // never as another handle or name.
    let split = data.first().map_or(0, |&n| usize::from(n) % (MAX_FH + 8)).min(data.len());
    let (handle, name) = data.split_at(split);
    let op = DirOp { dir: FileHandle(handle.to_vec()), name: name.to_vec() };
    let Ok(Request::Remove(back)) = Request::read(procedure::REMOVE, &Request::Remove(op.clone()).to_args()) else {
        panic!("a REMOVE that does not read back")
    };
    assert!(back.dir == op.dir || (back.dir.0.is_empty() && op.dir.0.len() > MAX_FH));
    assert!(back.name == op.name || (back.name.is_empty() && op.name.len() > MAX_NAME));

    // The bytes as a TCP stream of calls, split two ways: all at once,
    // and a byte at a time.
    let limit = 1 << 16;
    let mut whole = Decoder::with_limit(limit);
    whole.feed(data);
    let mut records = Vec::new();
    while let Some(Ok(r)) = whole.next_record() {
        records.push(r);
    }
    let mut bytewise = Decoder::with_limit(limit);
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(Ok(r)) = bytewise.next_record() {
            again.push(r);
        }
    }
    assert_eq!(records, again);

    // Each record, and the bytes on their own as a UDP datagram.
    for bytes in records.iter().map(Vec::as_slice).chain([data]) {
        let Ok(Message { xid, body: Body::Call(call) }) = Message::parse(bytes) else { continue };
        // A request read makes the same call again.
        if let Ok(req) = Request::parse(&call) {
            assert_eq!(req.to_args(), call.args);
            let Body::Call(c) = req.call(xid).body else { unreachable!() };
            assert_eq!(Request::parse(&c), Ok(req.clone()));
            // A failure for it reads back.
            let failed = Response::failed(&req, NfsError::Io);
            assert_eq!(Response::parse(req.procedure(), &failed.to_results()), Ok(failed));
        }
        if let Ok(req) = MountRequest::parse(&call) {
            assert_eq!(req.to_args(), call.args);
            let Body::Call(c) = req.call(xid).body else { unreachable!() };
            assert_eq!(MountRequest::parse(&c), Ok(req));
        }
    }
});
