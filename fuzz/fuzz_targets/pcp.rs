//! PCP and NAT-PMP requests, reply construction and version negotiation.
#![no_main]

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::pcp::*;
use fictionet::stdlib::test_support::assert_write;
use libfuzzer_sys::fuzz_target;
use std::net::Ipv4Addr;

fuzz_target!(|data: &[u8]| {
    let source = Ipv4Addr::new(192, 168, 1, 20).into();
    // Fixed prefix work keeps the cost linear in the input length.
    for n in (0..=data.len().min(128)).chain((data.len() > 128).then_some(data.len())) {
        let b = &data[..n];
        if let Ok(value) = <Request as Wire>::parse(b) {
            let _ = assert_write(&value);
        }
        if let Ok(value) = <Response as Wire>::parse(b) {
            let _ = assert_write(&value);
        }
        if let Ok(value) = <NatPmpRequest as Wire>::parse(b) {
            let _ = assert_write(&value);
        }
        if let Ok(value) = <NatPmpResponse as Wire>::parse(b) {
            let _ = assert_write(&value);
        }
        if let Ok(value) = <Reply as Wire>::parse(b) {
            let _ = assert_write(&value);
        }
        if let Ok(request) = Request::parse(b) {
            let _ = request.check(source);
            let reply = request.reply(ResultCode::NoResources, 30, 1);
            let _ = assert_write(&reply);
            assert!(reply.to_bytes().is_ok());
        }
        if let Ok(request) = NatPmpRequest::parse(b) {
            let reply = request.refuse(NatPmpResult::NotAuthorized, 4);
            let _ = assert_write(&reply);
            assert!(reply.to_bytes().is_ok());
        }
        let reply = error_reply(b, ResultCode::MalformedRequest, 30, 1);
        let _ = assert_write(&reply);
        let bytes = reply.to_bytes().unwrap();
        let body = b
            .get(HEADER_LEN..b.len().min(MAX_MESSAGE))
            .unwrap_or_default();
        assert_eq!(&bytes[HEADER_LEN..HEADER_LEN + body.len()], body);
        assert!(
            bytes[HEADER_LEN + body.len()..]
                .iter()
                .all(|&byte| byte == 0)
        );
        for speaks in [Speaks::Pcp, Speaks::NatPmp, Speaks::Both] {
            if let Incoming::Reply(reply) = receive(b, speaks, source, 11) {
                let _ = assert_write(&reply);
                let bytes = reply.to_bytes().unwrap();
                assert!(bytes.len() <= MAX_MESSAGE);
                assert_eq!(receive(&bytes, speaks, source, 11), Incoming::Ignore);
            }
        }
        if let Some(version) = unsupported_version(b) {
            let _ = version.next_step(VERSION);
            let _ = version.next_step(NAT_PMP_VERSION);
        }
    }
});
