//! IKEv2 messages, as a world playing a VPN gateway reads them on port 500
//! and port 4500.
#![no_main]

use fictionet::stdlib::ike::{Error, Header, Message, NatT, parse_payloads, payloads_to_bytes};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A message read can be written, and reads back the same.
    if let Ok(m) = Message::parse(data) {
        let bytes = m.to_bytes();
        assert!(bytes.len() <= data.len());
        assert_eq!(Message::parse(&bytes).as_ref(), Ok(&m));
        // Every prefix of a written message is short.
        for n in 0..bytes.len().min(200) {
            assert_eq!(Message::parse(&bytes[..n]), Err(Error::Short));
        }
        // Its payloads on their own, as inside an SK payload.
        let (first, chain) = payloads_to_bytes(&m.payloads);
        assert_eq!(parse_payloads(first, &chain).as_ref(), Ok(&m.payloads));
    }
    // The same bytes on port 4500.
    if let Ok(NatT::Ike(m)) = NatT::parse(data) {
        assert_eq!(NatT::parse(&m.to_nat_t_bytes()), Ok(NatT::Ike(m)));
    }
    let _ = Header::parse(data);
    // Any bytes as a payload chain, the first byte naming the first type.
    if let Some((&first, rest)) = data.split_first()
        && let Ok(p) = parse_payloads(first, rest)
    {
        let (f, chain) = payloads_to_bytes(&p);
        assert_eq!(parse_payloads(f, &chain), Ok(p));
    }
    // Every prefix, as a datagram that came in cut.
    for n in 0..data.len().min(200) {
        let _ = Message::parse(&data[..n]);
        let _ = NatT::parse(&data[..n]);
    }
});
