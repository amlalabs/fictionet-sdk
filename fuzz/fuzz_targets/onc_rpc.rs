//! ONC RPC records, calls and replies, and portmap and rpcbind requests,
//! as a world playing an RPC server reads them.
#![no_main]

use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::protocols::onc_rpc::{
    AuthSys, Body, MAX_ARRAY_RESERVE, Message, Reader, encode_fragments,
};
use fictionet::stdlib::protocols::portmap::{PmapResult, Request, procedure};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};
use fictionet::stdlib::{
    codec::{Assembled, Wire},
    protocols::onc_rpc,
    test_support::decode_all,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fictionet::stdlib::protocols::portmap::harness::check(data);
    // The stream, split two ways: all at once, and a byte at a time.
    let limit = 4096;
    assert_eq!(
        decode_chunks(
            &mut Stream::new(onc_rpc::Fragments::with_limit(limit)),
            chunks(data, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(|| onc_rpc::Fragments::with_limit(limit), data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(onc_rpc::records(limit)),
            chunks(data, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(|| onc_rpc::records(limit), data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(onc_rpc::messages(limit)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.held() <= limit);
            }
        ),
        decode_all(|| onc_rpc::messages(limit), data),
    );
    if let Ok(value) = <onc_rpc::Record as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <onc_rpc::Fragment as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <AuthSys as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Message as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
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
        if let Ok(value) = <Message as Wire>::parse(bytes) {
            let _ = assert_write(&value);
        }
        // A record written in fragments reads back the same.
        if let Ok(encoded) = encode_fragments(bytes, 7) {
            assert_eq!(
                onc_rpc::Record::parse(&encoded),
                Ok(onc_rpc::Record(bytes.to_vec()))
            );
        }
        let Ok(m) = <Message as Wire>::parse(bytes) else {
            continue;
        };
        let _ = assert_write(&m);
        // A message read writes back as the same bytes.
        assert_eq!(m.to_bytes().unwrap(), bytes);
        if let Body::Call(call) = &m.body {
            if let Ok(req) = Request::from_call(call) {
                assert_eq!(Request::from_call(&req.to_call().unwrap()), Ok(req));
            }
        }
    }
    // Any bytes as other XDR.
    let _ = <AuthSys as Wire>::parse(data);
    let _ = PmapResult::parse(procedure::DUMP, data);
    let mut r = Reader::new(data);
    let _ = r.array(64, |r| r.optional(|r| r.opaque(256).map(<[u8]>::to_vec)));
    // Items of no bytes: a count over MAX_ARRAY_RESERVE still needs 4 bytes
    // an item.
    if let Ok(v) = Reader::new(data).array(usize::MAX, |r| r.opaque_fixed(0)) {
        assert!(v.len() <= MAX_ARRAY_RESERVE.max(data.len() / 4));
    }
});
