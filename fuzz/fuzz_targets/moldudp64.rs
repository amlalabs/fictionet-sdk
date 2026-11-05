//! MoldUDP64 datagrams as a listener and a re-request server read them,
//! and the receiver's gap recovery driven by whatever parses.
#![no_main]

use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::moldudp64::{
    Blocks, Downstream, Event, HEADER_LENGTH, Receiver, ReceiverConfig, Request, Retransmitter,
    Session, StoreConfig,
};
use fictionet::stdlib::protocols::session::Action;
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT: usize = 4096;
const DATAGRAM: usize = 64;

fuzz_target!(|input: &[u8]| {
    let data = input
        .get(..input.len().min(MAX_FUZZ_INPUT))
        .unwrap_or_default();
    if let Ok(value) = <Downstream as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Request as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    assert_eq!(
        decode_chunks(&mut Stream::new(Blocks), chunks(data, &[1, 7, 64]), |_| {}),
        decode_all(|| Blocks, data),
    );
    let _ = decode_all(|| Blocks, data);

    // Every 64-byte slice is a datagram for one receiver; requests it
    // emits are answered from a store holding the same messages.
    let session = Session::left_padded("FUZZ").unwrap();
    let mut store = Retransmitter::new(
        session,
        1,
        StoreConfig {
            packet_size: 200,
            max_messages: 32,
            max_bytes: 1024,
        },
    )
    .unwrap();
    let mut receiver = Receiver::new(ReceiverConfig {
        retry_ms: 10,
        attempts: 2,
        request_count: 8,
        ..ReceiverConfig::default()
    })
    .unwrap();
    let mut now = 0u64;
    for datagram in data.chunks(DATAGRAM) {
        now += u64::from(datagram.first().copied().unwrap_or(0));
        let _ = store.push(datagram);
        let mut packets = Vec::new();
        if let Ok(packet) = Downstream::parse(datagram) {
            let _ = assert_write(&packet);
            packets.push(packet);
        }
        // A header over the fuzz session, so sequence numbers vary.
        if datagram.len() >= HEADER_LENGTH {
            let mut forged = session.as_bytes().to_vec();
            forged.extend_from_slice(&datagram[10..]);
            if let Ok(packet) = Downstream::parse(&forged) {
                packets.push(packet);
            }
        }
        for packet in packets {
            let before = receiver.expected();
            let actions = receiver.receive(&packet, now).unwrap();
            for action in &actions {
                match action {
                    Action::Send(request) => {
                        assert!(request.count >= 1 && request.count <= 8);
                        let _ = assert_write(request);
                        if let Some(answer) = store.answer(request) {
                            let _ = assert_write(&answer);
                            assert!(answer.wire_len() <= 200);
                        }
                    }
                    Action::Event(Event::Deliver { skip, count, .. }) => {
                        assert!(skip + count <= packet.messages().len());
                    }
                    Action::Event(_) => {}
                }
            }
            if let (Some(a), Some(b)) = (before, receiver.expected()) {
                assert!(b >= a);
            }
        }
        for action in receiver.tick(now).unwrap() {
            if let Action::Send(request) = action {
                let _ = assert_write(&request);
            }
        }
    }
    assert!(store.held() <= 1024);
});
