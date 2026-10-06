use fictionet::stdlib::codec::{Decode, Step, Stream, finish, pump};
use fictionet::stdlib::tcp_stream::{FlowKey, Limits, Reassembler, Segment, TcpEvent};
use std::convert::Infallible;

struct UserDecoder;

impl Decode for UserDecoder {
    type Item = [u8; 2];
    type Error = Infallible;
    const NAME: &'static str = "user pairs";

    fn capacity(&self) -> usize {
        2
    }

    fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<Self::Item>, Self::Error> {
        Ok(match input.get(..2) {
            Some(pair) => Step::Item([pair[0], pair[1]], 2),
            None => Step::Need,
        })
    }
}

fn key() -> FlowKey {
    (
        "192.0.2.1".parse().unwrap(),
        40000,
        "192.0.2.2".parse().unwrap(),
        80,
    )
}

#[test]
fn public_events_drive_a_user_decoder_with_gap_and_end_hooks() {
    let mut tcp = Reassembler::new(Limits {
        max_buffered: 2,
        ..Limits::default()
    });
    let mut decoder = Stream::new(UserDecoder);
    let mut pairs = Vec::new();
    let mut gaps = 0;
    let mut ends = 0;
    for (seq, flags, payload) in [
        (100, 2, &b""[..]),
        (101, 0x18, &b"a"[..]),
        (104, 0x18, &b"de"[..]),
        (110, 0x18, &b"dropped"[..]),
        (106, 0x18, &b"fg"[..]),
        (108, 0x11, &b""[..]),
    ] {
        let result = tcp.push(Segment {
            key: key(),
            seq,
            ack: 0,
            flags,
            payload,
        });
        for event in result.events {
            match event {
                TcpEvent::Bytes { dir, bytes, .. } => {
                    assert_eq!(dir, key());
                    pump(&mut decoder, &bytes, |pair| pairs.push(pair)).unwrap();
                }
                TcpEvent::Gap { resumed: true, .. } => {
                    gaps += 1;
                    decoder = Stream::new(UserDecoder);
                }
                TcpEvent::Gap { resumed: false, .. } => panic!("expected a resumed gap"),
                TcpEvent::End { reset, .. } => {
                    assert!(!reset);
                    ends += 1;
                    finish(&mut decoder, |pair| pairs.push(pair)).unwrap();
                }
            }
        }
        assert!(tcp.buffered() <= tcp.limits().max_buffered);
    }
    assert_eq!(pairs, [*b"de", *b"fg"]);
    assert_eq!((gaps, ends), (1, 1));
    assert!(decoder.is_done());
}

#[test]
fn copied_module_compiles_and_runs_in_a_consumer_crate() {
    use fictionet_copy_modules::tcp_stream as copied;

    let mut tcp = copied::Reassembler::default();
    let key = key();
    let initial = copied::Segment {
        key,
        seq: u32::MAX,
        ack: 0,
        flags: 2,
        payload: b"",
    };
    tcp.push(initial);
    assert!(
        tcp.push(copied::Segment {
            seq: 2,
            flags: 0x18,
            payload: b"cd",
            ..initial
        })
        .events
        .is_empty()
    );
    let result = tcp.push(copied::Segment {
        seq: 0,
        flags: 0x18,
        payload: b"ab",
        ..initial
    });
    let mut decoder = Stream::new(UserDecoder);
    let mut pairs = Vec::new();
    for event in result.events {
        if let copied::TcpEvent::Bytes { bytes, .. } = event {
            pump(&mut decoder, &bytes, |pair| pairs.push(pair)).unwrap();
        }
    }
    assert_eq!(pairs, [*b"ab", *b"cd"]);
    assert_eq!(tcp.buffered(), 0);
}
