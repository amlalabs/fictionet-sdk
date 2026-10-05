//! NFS version 3 and MOUNT version 3 calls and results, as a world
//! playing a file server, or a client, reads them.
#![no_main]

use fictionet::stdlib::nfs::{MountRequest, MountResponse, NfsError, Request, Response};
use fictionet::stdlib::onc_rpc::{Body, Decoder, Message};
use libfuzzer_sys::fuzz_target;

/// Reads `bytes` as the arguments and the results of procedure `p`. Any
/// that read must write back as the same bytes.
fn check(p: u32, bytes: &[u8]) {
    if let Ok(req) = Request::read(p, bytes) {
        assert_eq!(req.to_args(), bytes);
    }
    if let Ok(resp) = Response::parse(p, bytes) {
        assert_eq!(resp.to_results(), bytes);
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
