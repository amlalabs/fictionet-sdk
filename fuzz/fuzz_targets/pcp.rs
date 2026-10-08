//! PCP and NAT-PMP requests, reply construction and version negotiation.
#![no_main]

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::contract;
use fictionet::stdlib::pcp::*;
use libfuzzer_sys::fuzz_target;
use std::net::Ipv4Addr;

fuzz_target!(|data: &[u8]| {
    let source = Ipv4Addr::new(192, 168, 1, 20).into();
    // Fixed prefix work keeps the cost linear in the input length.
    for n in (0..=data.len().min(128)).chain((data.len() > 128).then_some(data.len())) {
        let b = &data[..n];
        contract::check_wire::<Request>(b);
        contract::check_wire::<Response>(b);
        contract::check_wire::<NatPmpRequest>(b);
        contract::check_wire::<NatPmpResponse>(b);
        contract::check_wire::<Reply>(b);
        if let Ok(request) = Request::parse(b) {
            let _ = request.check(source);
            let reply = request.reply(ResultCode::NoResources, 30, 1);
            contract::check_wire_value(&reply);
            assert!(reply.to_bytes().is_ok());
        }
        if let Ok(request) = NatPmpRequest::parse(b) {
            let reply = request.refuse(NatPmpResult::NotAuthorized, 4);
            contract::check_wire_value(&reply);
            assert!(reply.to_bytes().is_ok());
        }
        let reply = error_reply(b, ResultCode::MalformedRequest, 30, 1);
        contract::check_wire_value(&reply);
        let bytes = reply.to_bytes().unwrap();
        let body = b.get(HEADER_LEN..b.len().min(MAX_MESSAGE)).unwrap_or_default();
        assert_eq!(&bytes[HEADER_LEN..HEADER_LEN + body.len()], body);
        assert!(bytes[HEADER_LEN + body.len()..].iter().all(|&byte| byte == 0));
        for speaks in [Speaks::Pcp, Speaks::NatPmp, Speaks::Both] {
            if let Incoming::Reply(reply) = receive(b, speaks, source, 11) {
                contract::check_wire_value(&reply);
                let bytes = reply.to_bytes().unwrap();
                assert!(bytes.len() <= MAX_MESSAGE);
                // RFC 6886 section 3.5 writes the unsupported-version reply
                // with opcode 0, so a NAT-PMP server reads it back as an
                // external address request. Every other reply is ignored.
                if !matches!(reply, Reply::NatPmp(NatPmpResponse::UnsupportedVersion { .. })) {
                    assert_eq!(receive(&bytes, speaks, source, 11), Incoming::Ignore);
                }
            }
        }
        if let Some(version) = unsupported_version(b) {
            let _ = version.next_step(VERSION);
            let _ = version.next_step(NAT_PMP_VERSION);
        }
    }
});
