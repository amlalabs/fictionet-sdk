//! HTTP/3 streams, field sections, and Priority dictionaries.
#![no_main]

use fictionet::stdlib::{
    codec::{Decode, Wire, contract, test_support::decode_all},
    http3::{
        self, Connection, Endpoint, Frame, Frames, HeaderKind, HeaderList, MessageSide, Priority, RequestResult,
        RequestState, Settings, StreamDecoder, StreamHeader, StreamHeaders, StreamItem,
    },
    qpack::{self, SectionResult, Table},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let bytes = &input[..input.len().min(16 << 10)];
    contract::check_wire::<Frame>(bytes);
    contract::check_wire::<Settings>(bytes);
    contract::check_wire::<Priority>(bytes);
    contract::check_wire::<StreamHeader>(bytes);
    contract::check_decode_with_alloc_limit(Frames::new, bytes, 2 * http3::MAX_FRAME);
    contract::check_decode_with_alloc_limit(StreamHeaders::new, bytes, 2 * http3::MAX_STREAM_HEADER);
    for sender in [Endpoint::Client, Endpoint::Server] {
        contract::check_decode_with_alloc_limit(|| http3::ControlFrames::new(sender), bytes, 2 * http3::MAX_FRAME);
        for header in
            [StreamHeader::Control, StreamHeader::QpackEncoder, StreamHeader::QpackDecoder, StreamHeader::Unknown(64)]
        {
            let make = || StreamDecoder::after_header(header, sender);
            contract::check_decode_with_alloc_limit(make, bytes, 2 * make().capacity());
        }
    }
    let table = Table::new(0);
    let (items, _) = decode_all(Frames::new, bytes);
    for side in [MessageSide::Request, MessageSide::Response, MessageSide::HeadResponse, MessageSide::ConnectResponse] {
        let mut state = RequestState::new(0, side, false).unwrap();
        for frame in &items {
            let Ok(frame) = frame else { break };
            match state.step(frame, &table) {
                Ok(RequestResult::Event { event: Ok(_), ack }) => {
                    if let Some(ack) = ack {
                        contract::check_wire_value(&ack);
                    }
                }
                _ => break,
            }
        }
        let _ = state.finish();
    }
    if let Ok(SectionResult::Fields { fields, .. }) = qpack::decode_section(&table, 0, bytes) {
        for kind in [
            HeaderKind::Request { extended_connect: false },
            HeaderKind::Response,
            HeaderKind::Trailers,
            HeaderKind::Promise,
        ] {
            if let Ok(headers) = HeaderList::from_fields(fields.clone(), kind) {
                if headers.validate(kind).is_ok() {
                    let section =
                        headers.section(&mut qpack::Encoder::new(0, http3::MAX_FIELD_SECTION_SIZE), 0, kind).unwrap();
                    contract::check_wire_value(&section);
                }
                if let Ok(priority) = headers.priority() {
                    contract::check_wire_value(&priority);
                }
            }
        }
    }
    // Exercise routing and pause/resume while other streams have input.
    let mut connection = Connection::new(Endpoint::Client, 4, http3::MAX_FRAME * 2);
    let mut table = Table::new(4096);
    let mut state = RequestState::new(0, MessageSide::Request, false).unwrap();
    let mut held = qpack::BlockedSections::new(1);
    let split = bytes.len() / 2;
    let _ = connection.push(0, &bytes[..split]);
    let _ = connection.push(2, &bytes[split..]);
    connection.end(0);
    connection.end(2);
    while let Some((stream, Ok(Ok(item)))) = connection.next() {
        match item {
            StreamItem::EncoderInstruction(instruction) => {
                if table.apply(instruction).is_err() {
                    break;
                }
                if let Some((id, result)) = held.next_ready(&table) {
                    if state.resume(id, result).is_ok() {
                        connection.unpause(id);
                    }
                }
            }
            StreamItem::Frame(frame) if stream == 0 => {
                if let Ok(RequestResult::Blocked(section)) = state.step(&frame, &table) {
                    held.push(section).unwrap();
                    connection.pause(stream);
                }
            }
            _ => {}
        }
        assert!(connection.buffered() <= http3::MAX_FRAME * 2);
    }
    let _ = held.cancel(&table, 0);
    let _ = connection.remove(0);
    // Structured values reach writers even when arbitrary input fails framing.
    contract::check_wire_value(&Frame::Data(bytes.to_vec()));
    contract::check_wire_value(&Frame::Headers(bytes.to_vec()));
    let _ = Priority { urgency: input.first().copied(), incremental: Some(true) }.to_bytes();
});
