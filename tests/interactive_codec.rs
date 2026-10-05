//! Telnet sessions and WebSocket frames, assembly, and handoff.

use fictionet::stdlib::codec::{
    AssembleError, Decode, Fail, Step, Stream, Wire, contract, finish, pump,
    test_support::{Lcg, chunks},
};
use fictionet::stdlib::{telnet as tn, websocket as ws};

fn read<D>(decoder: D, bytes: &[u8], pattern: &[usize]) -> (Vec<D::Item>, Option<Fail<D::Error>>)
where
    D: Decode,
    D::Error: Clone,
{
    let mut stream = Stream::new(decoder);
    let mut items = Vec::new();
    for part in chunks(bytes, pattern) {
        match pump(&mut stream, part, |item| items.push(item)) {
            Ok(_) if stream.is_done() => break,
            Ok(n) => assert_eq!(n, part.len()),
            Err(error) => return (items, Some(error)),
        }
    }
    let failure = finish(&mut stream, |item| items.push(item)).err();
    assert!(stream.is_done());
    assert!(stream.next().is_none());
    (items, failure)
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
fn telnet_chunked_wire_round_trip() {
    let events = telnet_units();
    let mut bytes = Vec::new();
    for event in &events {
        event.write(&mut bytes).unwrap();
        contract::check_wire_value(event);
        contract::check_wire::<tn::Event>(&Wire::to_bytes(event).unwrap());
    }
    contract::check_decode(tn::Decode::new, &bytes);
    contract::check_decode_with_held_limit(tn::Decode::new, &bytes, 0);
    for pattern in [&[][..], &[1], &[3, 1, 2, 19]] {
        assert_eq!(read(tn::Decode::new(), &bytes, pattern), (events.clone(), None));
    }
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
    decoder: tn::Decode,
    options: tn::Negotiation,
}

impl Negotiated {
    fn new() -> Self {
        let mut options = tn::Negotiation::new();
        options.allow_remote(tn::option::BINARY, true);
        Self { decoder: tn::Decode::new(), options }
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
    type Error = tn::DecodeError;
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
        event.write_with(&mut bytes, binary).unwrap();
        if let tn::Event::Negotiation { verb, .. } = event {
            binary = *verb == tn::Verb::Will;
        }
    }
    contract::check_stack(Negotiated::new, &bytes);
    for pattern in [&[][..], &[1], &[2, 1, 13]] {
        // Here the world changes the decoder through Stream::decoder.
        let mut stream = Stream::new(tn::Decode::new());
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
    contract::check_stack(Negotiated::new, bytes);
    assert_eq!(
        read(Negotiated::new(), bytes, &[1]).0,
        vec![
            tn::Event::Data(vec![13]),
            tn::Event::Negotiation { verb: tn::Verb::Will, option: 0 },
            tn::Event::Data(vec![b'X']),
        ]
    );
}

#[test]
fn telnet_data_runs_are_bounded_and_chunk_invariant() {
    let event = tn::Event::Data(vec![tn::IAC; tn::MAX_DATA]);
    let mut bytes = Wire::to_bytes(&event).unwrap();
    bytes.extend_from_slice(b"xyz");
    contract::check_decode(tn::Decode::new, &bytes);
    assert_eq!(read(tn::Decode::new(), &bytes, &[1]).0, [event, tn::Event::Data(b"xyz".to_vec())]);
    contract::check_decode(|| tn::Decode::with_data_limit(1), b"\r\0\xff\xffx");
    assert_eq!(
        read(tn::Decode::with_data_limit(1), b"\r\0\xff\xffx", &[1]).0,
        [tn::Event::Data(vec![13]), tn::Event::Data(vec![255]), tn::Event::Data(vec![b'x'])]
    );
    assert_eq!(tn::Decode::with_data_limit(0).data_limit(), 1);
    assert_eq!(tn::Decode::with_data_limit(usize::MAX).data_limit(), tn::MAX_DATA);
}

#[test]
fn telnet_recovers_from_bad_units_and_discards_oversized_subnegotiations() {
    let mut bytes = vec![tn::IAC, tn::cmd::SB, 42];
    bytes.extend([tn::IAC, tn::IAC].repeat(tn::MAX_SUBNEGOTIATION + 5));
    bytes.extend_from_slice(&[tn::IAC, tn::cmd::SE, tn::IAC, 1, tn::IAC, tn::cmd::SE]);
    bytes.extend_from_slice(&[tn::IAC, tn::cmd::SB, 43, 7, tn::IAC, tn::cmd::NOP]);
    let want = vec![
        tn::Event::Error(tn::DecodeError::SubnegotiationTooLong { option: 42 }),
        tn::Event::Error(tn::DecodeError::UnknownCommand(1)),
        tn::Event::Error(tn::DecodeError::StraySubnegotiationEnd),
        tn::Event::Error(tn::DecodeError::SubnegotiationInterrupted { option: 43 }),
        tn::Event::Command(tn::Command::Nop),
    ];
    contract::check_decode_with_held_limit(tn::Decode::new, &bytes, 0);
    for pattern in [&[][..], &[1], &[7, 1, 19]] {
        assert_eq!(read(tn::Decode::new(), &bytes, pattern), (want.clone(), None));
    }
    // Overflow followed by another command reports interruption, as before.
    let mut interrupted = vec![255, 250, 42];
    interrupted.extend(vec![1; tn::MAX_SUBNEGOTIATION + 1]);
    interrupted.extend_from_slice(&[255, 251, 0]);
    contract::check_decode(tn::Decode::new, &interrupted);
    assert_eq!(
        read(tn::Decode::new(), &interrupted, &[1]).0,
        [
            tn::Event::Error(tn::DecodeError::SubnegotiationInterrupted { option: 42 }),
            tn::Event::Negotiation { verb: tn::Verb::Will, option: 0 },
        ]
    );
}

#[test]
fn telnet_eof_reports_partial_units_once() {
    for bytes in [&[255][..], &[255, 251], &[255, 250], &[255, 250, 42, 1, 255]] {
        contract::check_decode(tn::Decode::new, bytes);
        assert_eq!(read(tn::Decode::new(), bytes, &[1]), (vec![], Some(Fail::Truncated { unread: bytes.len() })));
    }
    assert_eq!(
        read(tn::Decode::new(), b"ok\xff", &[1]),
        (vec![tn::Event::Data(b"ok".to_vec())], Some(Fail::Truncated { unread: 1 }),)
    );
    let mut bytes = vec![255, 250, 42];
    bytes.extend(vec![0; tn::MAX_SUBNEGOTIATION + 2]);
    for suffix in [&[][..], &[255]] {
        let mut input = bytes.clone();
        input.extend_from_slice(suffix);
        contract::check_decode(tn::Decode::new, &input);
        assert_eq!(read(tn::Decode::new(), &input, &[1]).1, Some(Fail::Protocol(tn::DecodeError::Truncated)));
    }
}

#[test]
fn telnet_wire_is_exact_strict_and_transactional() {
    for event in [
        tn::Event::Data(vec![]),
        tn::Event::Data(vec![1; tn::MAX_DATA + 1]),
        tn::Event::Subnegotiation { option: 42, data: vec![1; tn::MAX_SUBNEGOTIATION + 1] },
        tn::Event::Error(tn::DecodeError::UnknownCommand(0)),
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
        tn::Subnegotiation::Other { option: tn::option::NAWS, data: vec![0; 4] },
        tn::Subnegotiation::Other { option: 42, data: vec![0; tn::MAX_SUBNEGOTIATION + 1] },
    ] {
        contract::check_wire_value(&sub);
        let mut out = vec![7];
        assert!(sub.write(&mut out).is_err());
        assert_eq!(out, [7]);
    }
    assert_eq!(<tn::Event as Wire>::parse(&[255, 241, 1]), Err(tn::WireError::Trailing));
    assert!(<tn::Event as Wire>::parse(&[255, 1]).is_err());
    let data = tn::Event::Data((0..=255).collect());
    for binary in [false, true] {
        let mut out = vec![];
        data.write_with(&mut out, binary).unwrap();
        assert_eq!(tn::Event::parse_with(&out, binary), Ok(data.clone()));
        let mut decoder = tn::Decode::new();
        decoder.set_binary(binary);
        assert_eq!(read(decoder, &out, &[1]).0, core::slice::from_ref(&data));
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
        contract::check_decode(|| ws::Frames::new(role), &bytes);
        contract::check_stack(|| ws::Assemble::new(role), &bytes);
        contract::check_decode_with_held_limit(|| ws::Assemble::with_limit(role, 256), &bytes, 256);
        for pattern in [&[][..], &[1], &[1, 3, 2, 64]] {
            assert_eq!(read(ws::Frames::new(role), &bytes, pattern), (frames.clone(), None));
            assert_eq!(
                read(ws::Assemble::new(role), &bytes, pattern),
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
}

#[test]
fn websocket_refuses_frame_and_assembly_limits_from_headers() {
    let bytes = frame_bytes(&[frame(true, ws::Opcode::Binary, &[0; 130], Some([1; 4]))]);
    let h = ws::Header::parse(&bytes).unwrap().unwrap();
    let header = bytes.get(..h.header_len).unwrap();
    let mut stream = Stream::new(ws::Frames::with_limit(ws::Role::Server, 3));
    assert_eq!(stream.push(header), header.len());
    assert_eq!(stream.next(), Some(Err(Fail::Protocol(ws::Error::TooBig))));
    assert_eq!(stream.next(), None);
    assert_eq!(stream.unread(), header);
    contract::check_decode(|| ws::Frames::with_limit(ws::Role::Server, 3), &bytes);

    let first = frame_bytes(&[frame(false, ws::Opcode::Text, b"abc", None)]);
    let last = frame_bytes(&[frame(true, ws::Opcode::Continuation, b"def", None)]);
    let make = || ws::Assemble::from_frames(ws::Frames::with_limit(ws::Role::Client, 8), 5);
    let mut stream = Stream::new(make());
    assert_eq!(stream.push(&first), first.len());
    assert_eq!(stream.next(), None);
    assert_eq!(stream.held(), 3);
    assert_eq!(stream.push(last.get(..2).unwrap()), 2);
    assert_eq!(stream.next(), Some(Err(Fail::Protocol(AssembleError::TooLong { limit: 5 }))));
    assert_eq!(stream.next(), None);
    let bytes = [first, last].concat();
    contract::check_stack(make, &bytes);
    assert_eq!(read(make(), &bytes, &[1]).1, Some(Fail::Protocol(AssembleError::TooLong { limit: 5 })));
    assert_eq!(ws::Frames::with_limit(ws::Role::Client, usize::MAX).limit(), ws::MAX_PAYLOAD);
    assert_eq!(ws::Assemble::with_limit(ws::Role::Client, usize::MAX).limit(), ws::MAX_MESSAGE);
}

#[test]
fn websocket_close_preserves_trailing_bytes_for_parts_and_swap() {
    let close = frame(true, ws::Opcode::Close, &[3, 232], None);
    let close_bytes = Wire::to_bytes(&close).unwrap();
    let tail = b"after\r\0close";
    let mut bytes = close_bytes.clone();
    bytes.extend_from_slice(tail);
    contract::check_decode(|| ws::Frames::new(ws::Role::Client), &bytes);
    contract::check_stack(|| ws::Assemble::new(ws::Role::Client), &bytes);
    for eof in [false, true] {
        let mut stream = Stream::new(ws::Frames::new(ws::Role::Client));
        assert_eq!(stream.push(&bytes), bytes.len());
        if eof {
            stream.end();
        }
        assert_eq!(stream.next(), Some(Ok(close.clone())));
        assert_eq!(stream.next(), None);
        assert!(stream.is_done());
        assert_eq!(stream.offset(), close_bytes.len() as u64);
        let (buffer, _) = stream.into_parts();
        assert_eq!(buffer.unread(), tail);
    }
    let mut stream = Stream::new(ws::Assemble::new(ws::Role::Client));
    assert_eq!(stream.push(&bytes), bytes.len());
    assert_eq!(stream.next(), Some(Ok(ws::Message::Close(Some(ws::Close::new(1000))))));
    assert_eq!(stream.next(), None);
    let mut stream = stream.swap(tn::Decode::new());
    assert_eq!(stream.offset(), close_bytes.len() as u64);
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
    let mut stream = Stream::new(ws::Assemble::with_limit(ws::Role::Client, 16));
    let mut items = vec![];
    let accepted = pump(&mut stream, &bytes, |item| items.push(item)).unwrap();
    assert_eq!(items, [ws::Message::Close(None)]);
    assert!(stream.is_done());
    assert_eq!(stream.held(), 0);
    let (buffer, _) = stream.into_parts();
    let tail = [buffer.unread(), bytes.get(accepted..).unwrap()].concat();
    assert_eq!(tail, bytes.get(end..).unwrap());
    contract::check_stack(|| ws::Assemble::with_limit(ws::Role::Client, 16), &bytes);
}

#[test]
fn websocket_framing_errors_end_the_stream_once() {
    let cases = [
        (vec![0x83], ws::Error::Frame(ws::FrameError::ReservedOpcode(3))),
        (vec![0xc2], ws::Error::Frame(ws::FrameError::ReservedBits(4))),
        (vec![0x09], ws::Error::Frame(ws::FrameError::FragmentedControl)),
        (vec![0x89, 126], ws::Error::Frame(ws::FrameError::ControlTooLong)),
        (vec![0x82, 126, 0, 1], ws::Error::Frame(ws::FrameError::NonMinimalLength)),
        (vec![0x80, 0], ws::Error::UnexpectedContinuation),
        (vec![0x01, 0, 0x81, 0], ws::Error::ExpectedContinuation),
        (vec![0x81, 1, 0xff], ws::Error::InvalidUtf8),
        (vec![0x01, 1, 0xc3, 0x80, 1, b'x'], ws::Error::InvalidUtf8),
        (vec![0x88, 1, 0], ws::Error::Close(ws::CloseError::Short)),
        (vec![0x88, 2, 0x03, 0xee], ws::Error::Close(ws::CloseError::Code(1006))),
        (vec![0x82, 0x80, 0, 0, 0, 0], ws::Error::Masked),
    ];
    for (mut bytes, error) in cases {
        bytes.extend_from_slice(&[0x82, 0]); // No item may follow the error.
        contract::check_stack(|| ws::Assemble::new(ws::Role::Client), &bytes);
        for pattern in [&[][..], &[1]] {
            assert_eq!(
                read(ws::Assemble::new(ws::Role::Client), &bytes, pattern),
                (vec![], Some(Fail::Protocol(AssembleError::Inner(error))))
            );
        }
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
            read(ws::Assemble::new(ws::Role::Client), input, &[1]).1,
            Some(Fail::Truncated { unread: input.len() })
        );
        contract::check_stack(|| ws::Assemble::new(ws::Role::Client), input);
    }
    for payload in [&[][..], b"partial"] {
        let bytes = frame_bytes(&[frame(false, ws::Opcode::Binary, payload, None)]);
        contract::check_stack(|| ws::Assemble::new(ws::Role::Client), &bytes);
        assert_eq!(
            read(ws::Assemble::new(ws::Role::Client), &bytes, &[1]).1,
            Some(Fail::Protocol(AssembleError::Incomplete { held: payload.len() }))
        );
    }
    // Zero-sized data messages and full-sized controls still work at limit zero.
    let bytes = frame_bytes(&[
        frame(false, ws::Opcode::Binary, &[], None),
        frame(true, ws::Opcode::Ping, &[42; 125], None),
        frame(true, ws::Opcode::Continuation, &[], None),
    ]);
    contract::check_stack(|| ws::Assemble::with_limit(ws::Role::Client, 0), &bytes);
    assert_eq!(
        read(ws::Assemble::with_limit(ws::Role::Client, 0), &bytes, &[1]),
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
    assert_eq!(<ws::Frame as Wire>::parse(&[0x82]), Err(ws::FrameParseError::Truncated));
    assert_eq!(<ws::Frame as Wire>::parse(&[0x82, 0, 0]), Err(ws::FrameParseError::Trailing));
    for length in [0, 1, 125, 126, 65535, 65536] {
        contract::check_wire_value(&frame(true, ws::Opcode::Binary, &vec![7; length], Some([1, 2, 3, 4])));
    }
}

#[test]
fn interactive_contracts_on_generated_inputs() {
    let mut rng = Lcg::new(0x1a7e_6ac7);
    for round in 0..160 {
        let length = rng.below(96);
        let bytes: Vec<_> = (0..length).map(|_| rng.next() as u8).collect();
        contract::check_decode(|| tn::Decode::with_data_limit(7), &bytes);
        contract::check_wire::<tn::Event>(&bytes);
        contract::check_wire::<tn::Subnegotiation>(&bytes);
        contract::check_wire::<ws::Frame>(&bytes);
        let role = if round % 2 == 0 { ws::Role::Server } else { ws::Role::Client };
        contract::check_decode(|| ws::Frames::with_limit(role, 64), &bytes);
        contract::check_stack(|| ws::Assemble::with_limit(role, 64), &bytes);
    }
}
