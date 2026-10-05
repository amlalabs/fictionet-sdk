//! PCP and NAT-PMP datagrams, as a world playing a gateway reads them from
//! the agent, and as a world playing a client reads the gateway's replies.
#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use fictionet::stdlib::pcp::{
    Incoming, MAX_MESSAGE, NAT_PMP_VERSION, NatPmpRequest, NatPmpResponse, NatPmpResult, Request, Response, ResultCode,
    Speaks, VERSION, receive, unsupported_version,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let source = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
    // The whole datagram, and each short prefix, as if it had been cut
    // short on the way. Prefixes stop at PREFIXES bytes, past every fixed
    // field, so a long input costs linear work, not quadratic.
    const PREFIXES: usize = 128;
    let whole = data.len();
    for n in (0..=whole.min(PREFIXES)).chain((whole > PREFIXES).then_some(whole)) {
        let b = &data[..n];
        if let Ok(r) = Request::parse(b) {
            // A request read can be written, and reads back the same.
            let bytes = r.to_bytes();
            assert!(bytes.len() <= MAX_MESSAGE);
            assert_eq!(Request::parse(&bytes), Ok(r.clone()));
            let _ = r.check(source);
            let resp = r.reply(ResultCode::NoResources, 30, 1);
            assert_eq!(Response::parse(&resp.to_bytes()), Ok(resp));
        }
        if let Ok(r) = Response::parse(b) {
            let bytes = r.to_bytes();
            assert!(bytes.len() <= MAX_MESSAGE);
            assert_eq!(Response::parse(&bytes), Ok(r));
        }
        if let Ok(r) = NatPmpRequest::parse(b) {
            assert_eq!(NatPmpRequest::parse(&r.to_bytes()), Ok(r.clone()));
            assert!(NatPmpResponse::parse(&r.refuse(NatPmpResult::NotAuthorized, 4).to_bytes()).is_ok());
        }
        if let Ok(r) = NatPmpResponse::parse(b) {
            assert_eq!(NatPmpResponse::parse(&r.to_bytes()), Ok(r));
        }
        // Whatever a server sends back reads as a reply, and is never
        // itself answered.
        for speaks in [Speaks::Pcp, Speaks::NatPmp, Speaks::Both] {
            if let Incoming::Reply(reply) = receive(b, speaks, source, 11) {
                assert!(reply.len() <= MAX_MESSAGE);
                if reply[0] == NAT_PMP_VERSION {
                    assert!(NatPmpResponse::parse(&reply).is_ok());
                } else {
                    assert!(Response::parse(&reply).is_ok());
                    assert_eq!(receive(&reply, speaks, source, 11), Incoming::Ignore);
                }
            }
        }
        if let Some(u) = unsupported_version(b) {
            let _ = u.next_step(VERSION);
            let _ = u.next_step(NAT_PMP_VERSION);
        }
    }
});
