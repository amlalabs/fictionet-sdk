//! TPKT packets and class 0 COTP TPDUs, as a world playing an ISO
//! transport server reads them.
#![no_main]

use fictionet::stdlib::cotp::{Decoder, ErrorTpdu, MAX_MESSAGE, Reassembler, Tpdu, TpktError, parse_packet, segment, write_packet};
use libfuzzer_sys::fuzz_target;

/// Every packet a decoder gives for `data` fed in pieces of `step` bytes,
/// the error that ended the stream, if any, and how many bytes are left.
fn decode(data: &[u8], step: usize) -> (Vec<Vec<u8>>, Option<TpktError>, usize) {
    let mut d = Decoder::new();
    let mut packets = Vec::new();
    for piece in data.chunks(step.max(1)) {
        d.feed(piece);
        while let Some(r) = d.next_packet() {
            match r {
                Ok(p) => packets.push(p),
                Err(e) => return (packets, Some(e), d.buffered()),
            }
        }
    }
    (packets, None, d.buffered())
}

fuzz_target!(|data: &[u8]| {
    // The stream, split several ways, gives the same packets, the same
    // error and the same bytes left over.
    let (packets, error, left) = decode(data, data.len());
    for step in [1, 3, 64] {
        assert_eq!(decode(data, step), (packets.clone(), error, left));
    }

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
                    Tpdu::ConnectionRequest(c) => match c.confirm(1) {
                        Some(cc) => {
                            assert!(c.allows_class0());
                            assert_eq!(cc.class, 0);
                            let cc = Tpdu::ConnectionConfirm(cc);
                            assert_eq!(Tpdu::parse(&cc.to_bytes()), Ok(cc));
                        }
                        None => assert!(!c.allows_class0()),
                    },
                    _ => {}
                }
            }
            Err(e) => {
                let er = Tpdu::Error(ErrorTpdu::rejecting(0, tpdu, &e));
                assert_eq!(Tpdu::parse(&er.to_bytes()), Ok(er));
            }
        }
    }
    // Any bytes cut into segments read back as the same data TPDUs, and
    // put back together, they are the bytes again.
    if data.len() <= MAX_MESSAGE {
        let size = data.first().map_or(128, |&b| usize::from(b) * 3);
        let mut whole = Reassembler::new();
        let mut got = None;
        for s in segment(data, size) {
            let Ok(Tpdu::Data(back)) = Tpdu::parse(&Tpdu::Data(s.clone()).to_bytes()) else { panic!() };
            assert_eq!(back, s);
            assert!(got.is_none());
            got = whole.push(&back).unwrap();
        }
        assert_eq!(got.as_deref(), Some(data));
    }
});
