//! Telnet sessions and WebSocket frames, assembly, and handoff.

use fictionet::stdlib::codec::{
    AssembleError, Decode, Fail, Lcg, Step, Stream, Wire, finish, pump,
};
use fictionet::stdlib::test_support::contract;

use fictionet::stdlib::test_support::{chunks, decode_all};
use fictionet::stdlib::{telnet as tn, websocket as ws};

fn bounded<D: Decode>(make: impl Fn() -> D, bytes: &[u8])
where
    D::Item: PartialEq + core::fmt::Debug,
    D::Error: Clone + PartialEq + core::fmt::Debug,
{
    let limit = make().capacity().checked_mul(2).unwrap();
    contract::check_decode_with_alloc_limit(make, bytes, limit);
}

fn telnet_units() -> Vec<tn::Event> {
    vec![
        tn::Event::Data(b"hello\xff\r\0\r\n".to_vec()),
        tn::Event::Command(tn::Command::Nop),
        tn::Event::Subnegotiation { option: 42, data: vec![1, tn::IAC, 2] },
        tn::Event::Negotiation { verb: tn::Verb::Will, option: tn::option::ECHO },
        tn::Event::Data(b"last\r".to_vec()),
    ]
}

#[test]
fn telnet_default_delivers_login_without_waiting_for_more_input() {
    for decoder in [tn::Events::new(), tn::Events::default()] {
        let mut stream = Stream::new(decoder);
        assert_eq!(stream.push(b"root\r\n"), 6);
        for &byte in b"root\r\n" {
            assert_eq!(stream.next(), Some(Ok(tn::Event::Data(vec![byte]))));
        }
        assert_eq!(stream.next(), None);
        assert!(!stream.is_done());
        assert_eq!(stream.buffered(), 0);
        assert_eq!(stream.decoder().limit(), 1);
    }
    bounded(tn::Events::new, b"root\r\n");
    bounded(tn::Events::default, b"root\r\n");
}

#[test]
fn telnet_chunked_wire_round_trip() {
    let events = telnet_units();
    let mut bytes = Vec::new();
    for event in &events {
        event.write(&mut bytes).unwrap();
        contract::check_wire_value(event);
        contract::check_wire::<tn::Event>(&Wire::to_bytes(event).unwrap());
    }
    bounded(tn::Events::new, &bytes);
    contract::check_decode_with_held_limit(tn::Events::new, &bytes, 0);
    assert_eq!(
        decode_all(|| tn::Events::with_limit(tn::MAX_DATA), &bytes),
        (events.clone(), None)
    );
    let typed = [
        tn::Subnegotiation::TerminalTypeSend,
        tn::Subnegotiation::TerminalTypeIs("VT100".into()),
        tn::Subnegotiation::WindowSize { width: 255, height: 65535 },
        tn::Subnegotiation::Other { option: 42, data: vec![255, 13, 0] },
    ];
    for value in typed {
        contract::check_wire_value(&value);
        let bytes = Wire::to_bytes(&value).unwrap();
        contract::check_wire::<tn::Subnegotiation>(&bytes);
        assert_eq!(<tn::Subnegotiation as Wire>::parse(&bytes), Ok(value));
    }
}

// Test session: the item boundary is where a negotiated mode takes effect.
struct Negotiated {
    decoder: tn::Events,
    options: tn::Negotiation,
}

impl Negotiated {
    fn new() -> Self {
        let mut options = tn::Negotiation::new();
        options.allow_remote(tn::option::BINARY, true);
        Self {
            decoder: tn::Events::with_limit(tn::MAX_DATA),
            options,
        }
    }

    fn receive(&mut self, event: &tn::Event) {
        if let tn::Event::Negotiation { verb, option } = event
            && let Some(change) = self.options.receive(*verb, *option).change
            && change.side == tn::Side::Remote
            && change.option == tn::option::BINARY
        {
            self.decoder.set_binary(change.enabled);
        }
    }
}

impl Decode for Negotiated {
    type Item = tn::Event;
    type Error = tn::Error;
    const NAME: &'static str = "test Telnet session";

    fn capacity(&self) -> usize {
        self.decoder.capacity()
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, Self::Error> {
        let step = self.decoder.decode(input, eof)?;
        if let Step::Item(event, _) = &step {
            self.receive(event);
        }
        Ok(step)
    }
}

#[test]
fn telnet_binary_changes_between_items_in_one_buffer() {
    let events = vec![
        tn::Event::Data(b"NVT\r".to_vec()),
        tn::Event::Negotiation { verb: tn::Verb::Will, option: tn::option::BINARY },
        tn::Event::Data(b"\r\0\xff".to_vec()),
        tn::Event::Subnegotiation { option: 42, data: vec![255, 1] },
        tn::Event::Negotiation { verb: tn::Verb::Wont, option: tn::option::BINARY },
        tn::Event::Data(b"NVT again\r\0".to_vec()),
    ];
    let mut bytes = Vec::new();
    let mut binary = false;
    for event in &events {
        if binary {
            tn::BinaryEvent(event.clone()).write(&mut bytes).unwrap();
        } else {
            event.write(&mut bytes).unwrap();
        }
        if let tn::Event::Negotiation { verb, .. } = event {
            binary = *verb == tn::Verb::Will;
        }
    }
    bounded(Negotiated::new, &bytes);
    for pattern in [&[][..], &[1], &[2, 1, 13]] {
        // Here the world changes the decoder through Stream::decoder.
        let mut stream = Stream::new(tn::Events::with_limit(tn::MAX_DATA));
        let mut session = Negotiated::new();
        let mut got = Vec::new();
        for part in chunks(&bytes, pattern) {
            assert_eq!(stream.push(part), part.len());
            while let Some(event) = stream.next() {
                let event = event.unwrap();
                session.receive(&event);
                stream.decoder().set_binary(session.decoder.binary());
                got.push(event);
            }
        }
        finish(&mut stream, |event| got.push(event)).unwrap();
        assert_eq!(got, events);
    }
    // A bare NVT CR still owns a NUL separated from it by a negotiation.
    let bytes = b"\r\xff\xfb\0\0X";
    bounded(Negotiated::new, bytes);
    assert_eq!(
        decode_all(Negotiated::new, bytes).0,
        vec![
            tn::Event::Data(vec![13]),
            tn::Event::Negotiation { verb: tn::Verb::Will, option: 0 },
            tn::Event::Data(vec![b'X']),
        ]
    );
}

#[test]
fn telnet_data_runs_are_bounded_and_chunk_invariant() {
    let mut stream = Stream::new(tn::Events::with_limit(tn::MAX_DATA));
    assert_eq!(stream.push(b"root\r\n"), 6);
    assert_eq!(stream.next(), None);
    assert!(!stream.is_done());
    stream.end();
    assert_eq!(
        stream.next(),
        Some(Ok(tn::Event::Data(b"root\r\n".to_vec())))
    );

    let event = tn::Event::Data(vec![tn::IAC; tn::MAX_DATA]);
    let mut bytes = Wire::to_bytes(&event).unwrap();
    bytes.extend_from_slice(b"xyz");
    bounded(tn::Events::new, &bytes);
    bounded(|| tn::Events::with_limit(tn::MAX_DATA), &bytes);
    assert_eq!(
        decode_all(|| tn::Events::with_limit(tn::MAX_DATA), &bytes).0,
        [event, tn::Event::Data(b"xyz".to_vec())]
    );
    bounded(|| tn::Events::with_limit(1), b"\r\0\xff\xffx");
    assert_eq!(
        decode_all(|| tn::Events::with_limit(1), b"\r\0\xff\xffx").0,
        [tn::Event::Data(vec![13]), tn::Event::Data(vec![255]), tn::Event::Data(vec![b'x'])]
    );
    assert_eq!(tn::Events::with_limit(0).limit(), 1);
    assert_eq!(
        tn::Events::with_limit(usize::MAX).limit(),
        tn::MAX_DATA
    );
}

#[test]
fn telnet_recovers_from_bad_units_and_discards_oversized_subnegotiations() {
    let mut bytes = vec![tn::IAC, tn::cmd::SB, 42];
    bytes.extend([tn::IAC, tn::IAC].repeat(tn::MAX_SUBNEGOTIATION + 5));
    bytes.extend_from_slice(&[tn::IAC, tn::cmd::SE, tn::IAC, 1, tn::IAC, tn::cmd::SE]);
    bytes.extend_from_slice(&[tn::IAC, tn::cmd::SB, 43, 7, tn::IAC, tn::cmd::NOP]);
    let want = vec![
        tn::Event::Error(tn::Error::SubnegotiationTooLong { option: 42 }),
        tn::Event::Error(tn::Error::UnknownCommand(1)),
        tn::Event::Error(tn::Error::StraySubnegotiationEnd),
        tn::Event::Error(tn::Error::SubnegotiationInterrupted { option: 43 }),
        tn::Event::Command(tn::Command::Nop),
    ];
    contract::check_decode_with_held_limit(tn::Events::new, &bytes, 0);
    assert_eq!(decode_all(tn::Events::new, &bytes), (want.clone(), None));
    // Overflow followed by another command reports interruption.
    let mut interrupted = vec![255, 250, 42];
    interrupted.extend(vec![1; tn::MAX_SUBNEGOTIATION + 1]);
    interrupted.extend_from_slice(&[255, 251, 0]);
    bounded(tn::Events::new, &interrupted);
    assert_eq!(
        decode_all(tn::Events::new, &interrupted).0,
        [
            tn::Event::Error(tn::Error::SubnegotiationInterrupted { option: 42 }),
            tn::Event::Negotiation { verb: tn::Verb::Will, option: 0 },
        ]
    );
}

#[test]
fn telnet_eof_reports_partial_units_once() {
    for bytes in [&[255][..], &[255, 251], &[255, 250], &[255, 250, 42, 1, 255]] {
        bounded(tn::Events::new, bytes);
        assert_eq!(
            decode_all(tn::Events::new, bytes),
            (
                vec![],
                Some(Fail::Truncated {
                    unread: bytes.len()
                })
            )
        );
    }
    assert_eq!(
        decode_all(tn::Events::new, b"ok\xff"),
        (
            vec![tn::Event::Data(vec![b'o']), tn::Event::Data(vec![b'k'])],
            Some(Fail::Truncated { unread: 1 }),
        )
    );
    let mut bytes = vec![255, 250, 42];
    bytes.extend(vec![0; tn::MAX_SUBNEGOTIATION + 2]);
    for suffix in [&[][..], &[255]] {
        let mut input = bytes.clone();
        input.extend_from_slice(suffix);
        bounded(tn::Events::new, &input);
        assert_eq!(
            decode_all(tn::Events::new, &input).1,
            Some(Fail::Protocol(tn::Error::Truncated))
        );
    }
}

#[test]
fn telnet_wire_is_exact_strict_and_transactional() {
    for event in [
        tn::Event::Data(vec![]),
        tn::Event::Data(vec![1; tn::MAX_DATA + 1]),
        tn::Event::Subnegotiation { option: 42, data: vec![1; tn::MAX_SUBNEGOTIATION + 1] },
        tn::Event::Error(tn::Error::UnknownCommand(0)),
    ] {
        contract::check_wire_value(&event);
        let mut out = vec![7, 8];
        assert!(event.write(&mut out).is_err());
        assert_eq!(out, [7, 8]);
    }
    for sub in [
        tn::Subnegotiation::TerminalTypeIs(String::new()),
        tn::Subnegotiation::TerminalTypeIs("bad\0name".into()),
        tn::Subnegotiation::TerminalTypeIs("a".repeat(tn::MAX_TERMINAL_TYPE + 1)),
        tn::Subnegotiation::Other {
            option: tn::option::TERMINAL_TYPE,
            data: vec![1],
        },
        tn::Subnegotiation::Other {
            option: tn::option::NAWS,
            data: vec![0; 4],
        },
        tn::Subnegotiation::Other {
            option: 42,
            data: vec![0; tn::MAX_SUBNEGOTIATION + 1],
        },
    ] {
        contract::check_wire_value(&sub);
        let mut out = vec![7];
        assert!(sub.write(&mut out).is_err());
        assert_eq!(out, [7]);
    }
    assert_eq!(
        <tn::Event as Wire>::parse(&[255, 241, 1]),
        Err(tn::Error::Trailing)
    );
    assert!(<tn::Event as Wire>::parse(&[255, 1]).is_err());
    let data = tn::Event::Data((0..=255).collect());
    for binary in [false, true] {
        let mut out = vec![];
        if binary {
            tn::BinaryEvent(data.clone()).write(&mut out).unwrap();
        } else {
            data.write(&mut out).unwrap();
        }
        let parsed = if binary {
            tn::BinaryEvent::parse(&out).map(|event| event.0)
        } else {
            tn::Event::parse(&out)
        };
        assert_eq!(parsed, Ok(data.clone()));
        let mut decoder = tn::Events::with_limit(tn::MAX_DATA);
        decoder.set_binary(binary);
        assert_eq!(decode_all(|| decoder, &out).0, core::slice::from_ref(&data));
    }
}

fn frame(fin: bool, opcode: ws::Opcode, payload: &[u8], mask: Option<[u8; 4]>) -> ws::Frame {
    ws::Frame { fin, opcode, mask, payload: payload.to_vec() }
}

fn frame_bytes(frames: &[ws::Frame]) -> Vec<u8> {
    let mut bytes = vec![];
    for frame in frames {
        frame.write(&mut bytes).unwrap();
    }
    bytes
}

#[test]
fn websocket_masked_fragmented_text_with_interleaved_controls() {
    for (role, mask) in [(ws::Role::Server, Some([7, 8, 9, 10])), (ws::Role::Client, None)] {
        let frames = vec![
            frame(false, ws::Opcode::Text, b"He\xc3", mask),
            frame(true, ws::Opcode::Ping, b"?", mask),
            frame(true, ws::Opcode::Continuation, b"\xa9llo", mask),
            frame(true, ws::Opcode::Binary, &[3; 130], mask),
            frame(true, ws::Opcode::Pong, b"!", mask),
        ];
        let bytes = frame_bytes(&frames);
        for frame in &frames {
            contract::check_wire_value(frame);
            contract::check_wire::<ws::Frame>(&Wire::to_bytes(frame).unwrap());
        }
        bounded(|| ws::Frames::new(role), &bytes);
        bounded(|| ws::Messages::new(role), &bytes);
        contract::check_decode_with_held_limit(|| ws::Messages::new(role).with_limit(256), &bytes, 256);
        assert_eq!(decode_all(|| ws::Frames::new(role), &bytes), (frames.clone(), None));
        assert_eq!(
            decode_all(|| ws::Messages::new(role), &bytes),
            (
                vec![
                    ws::Message::Ping(b"?".to_vec()),
                    ws::Message::Text("Heéllo".into()),
                    ws::Message::Binary(vec![3; 130]),
                    ws::Message::Pong(b"!".to_vec()),
                ],
                None
            )
        );
    }
}

#[test]
fn websocket_message_limit_has_one_error_and_close_code() {
    let single = frame_bytes(&[frame(true, ws::Opcode::Binary, &[0; 126], None)]);
    let fragmented = frame_bytes(&[
        frame(false, ws::Opcode::Binary, &[0; 100], None),
        frame(true, ws::Opcode::Continuation, &[0; 26], None),
    ]);
    for bytes in [single, fragmented] {
        let make = || ws::Messages::new(ws::Role::Client).with_limit(125);
        bounded(make, &bytes);
        let (items, failure) = decode_all(make, &bytes);
        assert!(items.is_empty());
        assert_eq!(failure, Some(Fail::Protocol(AssembleError::Inner(ws::Error::TooBig))));
        let Some(Fail::Protocol(AssembleError::Inner(error))) = failure else {
            panic!()
        };
        assert_eq!(error.close_code(), ws::close_code::MESSAGE_TOO_BIG);
    }
    let mut header = vec![0x82, 127];
    header.extend_from_slice(&u64::try_from(ws::MAX_PAYLOAD + 1).unwrap().to_be_bytes());
    let make = || ws::Messages::new(ws::Role::Client);
    bounded(make, &header);
    assert_eq!(
        decode_all(make, &header),
        (
            vec![],
            Some(Fail::Protocol(AssembleError::Inner(ws::Error::TooBig)))
        )
    );
}

#[test]
fn websocket_wire_refuses_invalid_close_payloads_transactionally() {
    for payload in [&[0x03][..], &[0x03, 0xed], &[0x03, 0xe8, 0xff]] {
        let error = ws::Close::parse(payload).unwrap_err();
        for mask in [None, Some([1, 2, 3, 4])] {
            let frame = frame(true, ws::Opcode::Close, payload, mask);
            let mut out = vec![7, 8];
            assert_eq!(frame.write(&mut out), Err(ws::Error::Unwritable));
            assert_eq!(out, [7, 8]);
            contract::check_wire_value(&frame);
            // A malformed fixture must bypass the strict writer.
            let mut bytes = vec![0x88, payload.len() as u8 | if mask.is_some() { 0x80 } else { 0 }];
            if let Some(key) = mask {
                bytes.extend_from_slice(&key);
            }
            let start = bytes.len();
            bytes.extend_from_slice(payload);
            if let Some(key) = mask {
                ws::apply_mask(&mut bytes[start..], key, 0);
            }
            assert_eq!(
                <ws::Frame as Wire>::parse(&bytes),
                Err(error)
            );
            contract::check_wire::<ws::Frame>(&bytes);
        }
    }
    for payload in [&[][..], &[0x03, 0xe8], b"\x03\xe8bye"] {
        for (role, mask) in [
            (ws::Role::Client, None),
            (ws::Role::Server, Some([1, 2, 3, 4])),
        ] {
            let frame = frame(true, ws::Opcode::Close, payload, mask);
            contract::check_wire_value(&frame);
            let bytes = Wire::to_bytes(&frame).unwrap();
            assert_eq!(
                decode_all(|| ws::Frames::new(role), &bytes),
                (vec![frame], None)
            );
            assert_eq!(
                decode_all(|| ws::Messages::new(role), &bytes),
                (
                    vec![ws::Message::Close(if payload.is_empty() {
                        None
                    } else {
                        Some(ws::Close::parse(payload).unwrap())
                    })],
                    None
                )
            );
        }
    }
}

#[test]
fn websocket_refuses_frame_and_assembly_limits_from_headers() {
    let bytes = frame_bytes(&[frame(true, ws::Opcode::Binary, &[0; 130], Some([1; 4]))]);
    let h = ws::Header::parse(&bytes).unwrap().unwrap();
    let header = bytes.get(..h.header_len).unwrap();
    let mut stream = Stream::new(ws::Frames::new(ws::Role::Server).with_limit(3));
    assert_eq!(stream.push(header), header.len());
    assert_eq!(stream.next(), Some(Err(Fail::Protocol(ws::Error::TooBig))));
    assert_eq!(stream.next(), None);
    assert_eq!(stream.unread(), header);
    bounded(|| ws::Frames::new(ws::Role::Server).with_limit(3), &bytes);

    let first = frame_bytes(&[frame(false, ws::Opcode::Text, b"abc", None)]);
    let last = frame_bytes(&[frame(true, ws::Opcode::Continuation, b"def", None)]);
    let make = || ws::Messages::from_frames(ws::Frames::new(ws::Role::Client).with_limit(8), 5);
    let mut stream = Stream::new(make());
    assert_eq!(stream.push(&first), first.len());
    assert_eq!(stream.next(), None);
    assert_eq!(stream.held(), 3);
    assert_eq!(stream.push(last.get(..2).unwrap()), 2);
    assert_eq!(
        stream.next(),
        Some(Err(Fail::Protocol(AssembleError::Inner(ws::Error::TooBig))))
    );
    assert_eq!(stream.next(), None);
    let bytes = [first, last].concat();
    bounded(make, &bytes);
    assert_eq!(
        decode_all(make, &bytes).1,
        Some(Fail::Protocol(AssembleError::Inner(ws::Error::TooBig)))
    );
    assert_eq!(
        ws::Frames::new(ws::Role::Client).with_limit(usize::MAX).limit(),
        ws::MAX_PAYLOAD
    );
    assert_eq!(
        ws::Messages::new(ws::Role::Client).with_limit(usize::MAX).limit(),
        ws::MAX_MESSAGE
    );
}

#[test]
fn websocket_close_preserves_trailing_bytes_for_parts_and_swap() {
    let close = frame(true, ws::Opcode::Close, &[3, 232], None);
    let close_bytes = Wire::to_bytes(&close).unwrap();
    let tail = b"after\r\0close";
    let mut bytes = close_bytes.clone();
    bytes.extend_from_slice(tail);
    bounded(|| ws::Frames::new(ws::Role::Client), &bytes);
    bounded(|| ws::Messages::new(ws::Role::Client), &bytes);
    for eof in [false, true] {
        let mut stream = Stream::new(ws::Frames::new(ws::Role::Client));
        assert_eq!(stream.push(&bytes), bytes.len());
        if eof {
            stream.end();
        }
        assert_eq!(stream.next(), Some(Ok(close.clone())));
        assert_eq!(stream.next(), None);
        assert!(stream.is_done());
        assert_eq!(stream.offset(), u64::try_from(close_bytes.len()).unwrap());
        let (buffer, _) = stream.into_parts();
        assert_eq!(buffer.unread(), tail);
    }
    let mut stream = Stream::new(ws::Messages::new(ws::Role::Client));
    assert_eq!(stream.push(&bytes), bytes.len());
    assert_eq!(stream.next(), Some(Ok(ws::Message::Close(Some(ws::Close::new(1000))))));
    assert_eq!(stream.next(), None);
    let mut stream = stream.swap(tn::Events::with_limit(tn::MAX_DATA));
    assert_eq!(stream.offset(), u64::try_from(close_bytes.len()).unwrap());
    stream.end();
    assert_eq!(stream.next(), Some(Ok(tn::Event::Data(b"after\rclose".to_vec()))));
    assert_eq!(stream.next(), None);
}

#[test]
fn websocket_close_interrupts_assembly_and_pump_accounts_for_unaccepted_tail() {
    let mut bytes =
        frame_bytes(&[frame(false, ws::Opcode::Text, b"unfinished", None), frame(true, ws::Opcode::Close, &[], None)]);
    let end = bytes.len();
    bytes.extend(vec![42; 512]);
    let mut stream = Stream::new(ws::Messages::new(ws::Role::Client).with_limit(16));
    let mut items = vec![];
    let accepted = pump(&mut stream, &bytes, |item| items.push(item)).unwrap();
    assert_eq!(items, [ws::Message::Close(None)]);
    assert!(stream.is_done());
    assert_eq!(stream.held(), 0);
    let (buffer, _) = stream.into_parts();
    let tail = [buffer.unread(), bytes.get(accepted..).unwrap()].concat();
    assert_eq!(tail, bytes.get(end..).unwrap());
    bounded(|| ws::Messages::new(ws::Role::Client).with_limit(16), &bytes);
}

#[test]
fn websocket_framing_errors_end_the_stream_once() {
    let cases = [
        (vec![0x83], ws::Error::ReservedOpcode(3)),
        (vec![0xc2], ws::Error::ReservedBits(4)),
        (vec![0x09], ws::Error::FragmentedControl),
        (vec![0x89, 126], ws::Error::ControlTooLong),
        (vec![0x82, 126, 0, 1], ws::Error::NonMinimalLength),
        (vec![0x80, 0], ws::Error::UnexpectedContinuation),
        (vec![0x01, 0, 0x81, 0], ws::Error::ExpectedContinuation),
        (vec![0x81, 1, 0xff], ws::Error::InvalidUtf8),
        (vec![0x01, 1, 0xc3, 0x80, 1, b'x'], ws::Error::InvalidUtf8),
        (vec![0x88, 1, 0], ws::Error::CloseShort),
        (vec![0x88, 2, 0x03, 0xee], ws::Error::CloseCode(1006)),
        (vec![0x82, 0x80, 0, 0, 0, 0], ws::Error::Masked),
    ];
    for (mut bytes, error) in cases {
        bytes.extend_from_slice(&[0x82, 0]); // No item may follow the error.
        bounded(|| ws::Messages::new(ws::Role::Client), &bytes);
        assert_eq!(
            decode_all(|| ws::Messages::new(ws::Role::Client), &bytes),
            (vec![], Some(Fail::Protocol(AssembleError::Inner(error))))
        );
    }
    let mut stream = Stream::new(ws::Frames::new(ws::Role::Server));
    assert_eq!(stream.push(&[0x82, 0]), 2);
    let failure = Fail::Protocol(ws::Error::Unmasked);
    assert_eq!(stream.next(), Some(Err(failure.clone())));
    assert_eq!(stream.failed(), Some(&failure));
    assert!(stream.is_done());
    assert_eq!(stream.next(), None);
    assert_eq!(stream.unread(), [0x82, 0]);
}

#[test]
fn websocket_eof_distinguishes_frames_from_incomplete_messages() {
    for input in [&[0x82][..], &[0x82, 2, 1], &[0x82, 126, 0]] {
        assert_eq!(
            decode_all(|| ws::Messages::new(ws::Role::Client), input).1,
            Some(Fail::Truncated { unread: input.len() })
        );
        bounded(|| ws::Messages::new(ws::Role::Client), input);
    }
    for payload in [&[][..], b"partial"] {
        let bytes = frame_bytes(&[frame(false, ws::Opcode::Binary, payload, None)]);
        bounded(|| ws::Messages::new(ws::Role::Client), &bytes);
        assert_eq!(
            decode_all(|| ws::Messages::new(ws::Role::Client), &bytes).1,
            Some(Fail::Protocol(AssembleError::Incomplete { held: payload.len() }))
        );
    }
    // Zero-sized data messages and full-sized controls still work at limit zero.
    let bytes = frame_bytes(&[
        frame(false, ws::Opcode::Binary, &[], None),
        frame(true, ws::Opcode::Ping, &[42; 125], None),
        frame(true, ws::Opcode::Continuation, &[], None),
    ]);
    bounded(|| ws::Messages::new(ws::Role::Client).with_limit(0), &bytes);
    assert_eq!(
        decode_all(|| ws::Messages::new(ws::Role::Client).with_limit(0), &bytes),
        (vec![ws::Message::Ping(vec![42; 125]), ws::Message::Binary(vec![])], None)
    );
}

#[test]
fn websocket_wire_refuses_loss_and_requires_exact_input() {
    for frame in [
        frame(false, ws::Opcode::Ping, &[], None),
        frame(true, ws::Opcode::Pong, &[0; 126], None),
        ws::Frame::new(ws::Opcode::Binary, vec![0; ws::MAX_PAYLOAD + 1]),
    ] {
        contract::check_wire_value(&frame);
        let mut out = vec![1, 2];
        assert!(frame.write(&mut out).is_err());
        assert_eq!(out, [1, 2]);
    }
    assert_eq!(<ws::Frame as Wire>::parse(&[0x82]), Err(ws::Error::Truncated));
    assert_eq!(<ws::Frame as Wire>::parse(&[0x82, 0, 0]), Err(ws::Error::Trailing));
    for length in [0, 1, 125, 126, 65535, 65536] {
        contract::check_wire_value(&frame(true, ws::Opcode::Binary, &vec![7; length], Some([1, 2, 3, 4])));
    }
}

#[test]
fn interactive_contracts_on_generated_inputs() {
    let mut rng = Lcg::new(0x1a7e_6ac7);
    for round in 0..160 {
        let bytes = rng.bytes(96);
        bounded(tn::Events::new, &bytes);
        bounded(|| tn::Events::with_limit(7), &bytes);
        contract::check_wire::<tn::Event>(&bytes);
        contract::check_wire::<tn::Subnegotiation>(&bytes);
        contract::check_wire::<ws::Frame>(&bytes);
        let role = if round % 2 == 0 { ws::Role::Server } else { ws::Role::Client };
        bounded(|| ws::Frames::new(role).with_limit(64), &bytes);
        bounded(|| ws::Messages::new(role).with_limit(64), &bytes);
    }
}
