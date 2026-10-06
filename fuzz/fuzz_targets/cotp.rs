//! TPKT packets and class 0 COTP TPDUs, as a world playing an ISO
//! transport server reads them.
#![no_main]

use fictionet::stdlib::codec::contract::{
    check_decode, check_decode_with_held_limit, check_wire, check_wire_value,
};
use fictionet::stdlib::codec::{Wire, test_support::decode_all};
use fictionet::stdlib::cotp::{ErrorTpdu, MAX_MESSAGE, ParseError, Reassembler, Tpdu, segment};
use fictionet::stdlib::{cotp, tpkt};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    const MESSAGE_LIMIT: usize = 4096;
    check_decode(|| cotp::tpdus(tpkt::MAX_PACKET), data);
    check_decode_with_held_limit(|| cotp::messages(tpkt::MAX_PACKET, MESSAGE_LIMIT), data, MESSAGE_LIMIT);
    check_wire::<Tpdu>(data);
    let (packets, _) = decode_all(tpkt::Packets::new, data);

    let mut messages = Reassembler::with_limit(MESSAGE_LIMIT);
    // Each packet's TPDU, and any bytes as a TPDU on their own.
    for tpdu in packets.iter().map(|packet| packet.payload.as_slice()).chain([data]) {
        check_wire::<Tpdu>(tpdu);
        check_wire_value(&tpkt::Packet::new(tpdu.to_vec()));
        match <Tpdu as Wire>::parse(tpdu) {
            Ok(t) => {
                check_wire_value(&t);
                if let Ok(bytes) = t.to_bytes() {
                    assert_eq!(<Tpdu as Wire>::parse(&bytes), Ok(t.clone()));
                }
                match &t {
                    Tpdu::Data(d) => {
                        let _ = messages.push(d);
                        assert!(messages.pending() <= MESSAGE_LIMIT);
                    }
                    Tpdu::ConnectionRequest(c) => match c.confirm(1) {
                        Some(cc) => {
                            assert!(c.allows_class0());
                            assert_eq!(cc.class, 0);
                            let cc = Tpdu::ConnectionConfirm(cc);
                            assert_eq!(<Tpdu as Wire>::parse(&cc.to_bytes().unwrap()), Ok(cc));
                        }
                        None => assert!(!c.allows_class0()),
                    },
                    _ => {}
                }
            }
            Err(ParseError::Tpdu(e)) => {
                let er = Tpdu::Error(ErrorTpdu::rejecting(0, tpdu, &e));
                assert_eq!(<Tpdu as Wire>::parse(&er.to_bytes().unwrap()), Ok(er));
            }
            Err(ParseError::TooLong { .. }) => {}
        }
    }
    // Any bytes cut into segments read back as the same data TPDUs, and
    // put back together, they are the bytes again.
    if data.len() <= MAX_MESSAGE {
        let size = data.first().map_or(128, |&b| usize::from(b) * 3);
        let mut whole = Reassembler::new();
        let mut got = None;
        for s in segment(data, size) {
            let Ok(Tpdu::Data(back)) = <Tpdu as Wire>::parse(&Tpdu::Data(s.clone()).to_bytes().unwrap())
            else {
                panic!()
            };
            assert_eq!(back, s);
            assert!(got.is_none());
            got = whole.push(&back).unwrap();
        }
        assert_eq!(got.as_deref(), Some(data));
    }
});
