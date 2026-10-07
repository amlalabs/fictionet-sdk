//! NFS version 3 and MOUNT version 3 calls and results, as a world
//! playing a file server, or a client, reads them.
#![no_main]

use fictionet::stdlib::nfs::{
    DirOp, FileHandle, MAX_FH, MAX_NAME, MountRequest, MountResponse, Status, Request, Response,
    procedure,
};
use fictionet::stdlib::onc_rpc::{Body, Message};
use fictionet::stdlib::{
    codec::{Assembled, Decode, Wire, contract, test_support::decode_all},
    onc_rpc,
};
use libfuzzer_sys::fuzz_target;

/// Reads `bytes` as the arguments and the results of procedure `p`. Any
/// that read must write back as the same bytes, and READ and WRITE must
/// count the data they carry.
fn check(p: u32, bytes: &[u8]) {
    if let Ok(req) = Request::read(p, bytes) {
        assert_eq!(req.to_args().unwrap(), bytes);
        if let Request::Write { count, data, .. } = &req {
            assert_eq!(*count as usize, data.len());
        }
    }
    if let Ok(resp) = Response::parse(p, bytes) {
        assert_eq!(resp.to_results().unwrap(), bytes);
        if let Response::Read(Ok(ok)) = &resp {
            assert_eq!(ok.count as usize, ok.data.len());
        }
    }
    if let Ok(req) = MountRequest::read(p, bytes) {
        assert_eq!(req.to_args().unwrap(), bytes);
    }
    if let Ok(resp) = MountResponse::parse(p, bytes) {
        assert_eq!(resp.to_results().unwrap(), bytes);
    }
}

fuzz_target!(|data: &[u8]| {
    // The first byte picks a procedure. The rest is its arguments or
    // results.
    if let Some((&p, rest)) = data.split_first() {
        check(u32::from(p % 24), rest);
    }

    // Handles and names must fit their protocol limits.
    let split = data
        .first()
        .map_or(0, |&n| usize::from(n) % (MAX_FH + 8))
        .min(data.len());
    let (handle, name) = data.split_at(split);
    let request = Request::Remove(DirOp {
        dir: FileHandle(handle.to_vec()),
        name: name.to_vec(),
    });
    match request.to_args() {
        Ok(bytes) => assert_eq!(Request::read(procedure::REMOVE, &bytes), Ok(request)),
        Err(_) => assert!(handle.len() > MAX_FH || name.len() > MAX_NAME),
    }

    // The bytes as a TCP stream of calls, across the contract partitions.
    let limit = 1 << 16;
    contract::check_decode(|| onc_rpc::Fragments::with_limit(limit), data);
    contract::check_decode(|| onc_rpc::records(limit), data);
    contract::check_decode(
        || {
            onc_rpc::messages(limit).map(|message| {
                message.map(|message| match message.body {
                    Body::Call(call) => Some((message.xid, Request::parse(&call))),
                    Body::Reply(_) => None,
                })
            })
        },
        data,
    );
    // NFS arguments need a procedure; Wire belongs to the RPC envelope.
    contract::check_wire::<Message>(data);
    contract::check_wire::<onc_rpc::Record>(data);
    let (records, _) = decode_all(|| onc_rpc::records(limit), data);

    // Each record, and the bytes on their own as a UDP datagram.
    for bytes in records
        .iter()
        .map(|record| match record {
            Assembled::Message(bytes) => bytes.as_slice(),
            Assembled::Whole(never) => match *never {},
        })
        .chain([data])
    {
        contract::check_wire::<Message>(bytes);
        let Ok(Message {
            xid,
            body: Body::Call(call),
        }) = <Message as Wire>::parse(bytes)
        else {
            continue;
        };
        // A request read makes the same call again.
        if let Ok(req) = Request::parse(&call) {
            assert_eq!(req.to_args().unwrap(), call.args);
            let Body::Call(c) = req.call(xid).unwrap().body else {
                unreachable!()
            };
            assert_eq!(Request::parse(&c), Ok(req.clone()));
            // A failure for it reads back.
            let failed = Response::failed(&req, Status::Io);
            assert_eq!(
                Response::parse(req.procedure(), &failed.to_results().unwrap()),
                Ok(failed)
            );
        }
        if let Ok(req) = MountRequest::parse(&call) {
            assert_eq!(req.to_args().unwrap(), call.args);
            let Body::Call(c) = req.call(xid).unwrap().body else {
                unreachable!()
            };
            assert_eq!(MountRequest::parse(&c), Ok(req));
        }
    }
});
