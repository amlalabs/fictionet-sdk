//! TPKT packets and class 0 COTP TPDUs, as a world playing an ISO
//! transport server reads them.
#![no_main]

use fictionet::stdlib::cotp::{Decoder, ErrorTpdu, Reassembler, Tpdu, parse_packet, segment, write_packet};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    whole.feed(data);
    let mut packets = Vec::new();
    while let Some(Ok(p)) = whole.next_packet() {
        packets.push(p);
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(Ok(p)) = bytewise.next_packet() {
            again.push(p);
        }
    }
    assert_eq!(packets, again);

    let mut messages = Reassembler::with_limit(4096);
    // Each packet's TPDU, and any bytes as a TPDU on their own.
    for tpdu in packets.iter().map(Vec::as_slice).chain([data]) {
        // A packet written reads back whole.
        let packet = write_packet(tpdu);
        let (_, used) = parse_packet(&packet).unwrap().unwrap();
        assert_eq!(used, packet.len());
        match Tpdu::parse(tpdu) {
            Ok(t) => {
                // A TPDU read can be written, and reads back the same once
                // the writer has cut what does not fit.
                let back = Tpdu::parse(&t.to_bytes()).unwrap();
                assert_eq!(Tpdu::parse(&back.to_bytes()), Ok(back.clone()));
                if tpdu.len() <= fictionet::stdlib::cotp::MAX_TPDU {
                    assert_eq!(back, t);
                }
                match &t {
                    Tpdu::Data(d) => {
                        let _ = messages.push(d);
                        assert!(messages.pending() <= 4096);
                    }
                    Tpdu::ConnectionRequest(c) => {
                        let cc = Tpdu::ConnectionConfirm(c.confirm(1));
                        assert_eq!(Tpdu::parse(&cc.to_bytes()), Ok(cc));
                    }
                    _ => {}
                }
            }
            Err(e) => {
                let er = Tpdu::Error(ErrorTpdu::rejecting(0, tpdu, &e));
                assert_eq!(Tpdu::parse(&er.to_bytes()), Ok(er));
            }
        }
    }
    // Any bytes cut into segments read back as data TPDUs.
    let size = data.first().map_or(128, |&b| usize::from(b));
    for s in segment(data, size) {
        assert!(matches!(Tpdu::parse(&Tpdu::Data(s).to_bytes()), Ok(Tpdu::Data(_))));
    }
});
