//! ONC RPC records, calls and replies, and portmap and rpcbind requests,
//! as a world playing an RPC server reads them.
#![no_main]

use fictionet::stdlib::onc_rpc::{
    AuthSys, Body, Decoder, MAX_ARRAY_RESERVE, Message, PortmapRequest, Reader, RpcbRequest, encode_fragments,
    parse_dump,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let limit = 4096;
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
    // A drained decoder holds at most one record's worth, and both agree
    // on whether the stream stopped inside a record.
    assert!(whole.buffered() <= limit + 4);
    assert!(bytewise.buffered() <= limit + 4);
    assert_eq!(whole.mid_record(), bytewise.mid_record());
    assert_eq!(whole.next_record(), bytewise.next_record());

    // Each record, and the bytes on their own as a UDP datagram.
    for bytes in records.iter().map(Vec::as_slice).chain([data]) {
        // A record written in fragments reads back the same.
        let mut d = if bytes.len() <= limit { Decoder::with_limit(limit) } else { Decoder::new() };
        d.feed(&encode_fragments(bytes, 7));
        assert_eq!(d.next_record(), Some(Ok(bytes.to_vec())));
        assert!(!d.mid_record());
        let Ok(m) = Message::parse(bytes) else { continue };
        // A message read writes back as the same bytes.
        assert_eq!(m.to_bytes(), bytes);
        if let Body::Call(call) = &m.body {
            if let Ok(req) = PortmapRequest::parse(call) {
                let Body::Call(c) = req.call(m.xid).body else { unreachable!() };
                assert_eq!(PortmapRequest::parse(&c), Ok(req));
            }
            if let Ok(req) = RpcbRequest::parse(call) {
                let Body::Call(c) = req.call(m.xid, call.version).body else { unreachable!() };
                assert_eq!(RpcbRequest::parse(&c), Ok(req));
            }
        }
    }
    // Any bytes as other XDR.
    let _ = AuthSys::parse(data);
    let _ = parse_dump(data);
    let mut r = Reader::new(data);
    let _ = r.array(64, |r| r.optional(|r| r.opaque(256).map(<[u8]>::to_vec)));
    // Items of no bytes: a count over MAX_ARRAY_RESERVE still needs 4 bytes
    // an item.
    if let Ok(v) = Reader::new(data).array(usize::MAX, |r| r.opaque_fixed(0)) {
        assert!(v.len() <= MAX_ARRAY_RESERVE.max(data.len() / 4));
    }
});
