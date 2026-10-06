//! HTTP/3 streams, field sections, and Priority dictionaries.
#![no_main]

use fictionet::stdlib::{
    codec::{Decode, Wire, contract, test_support::decode_all},
    http3::{
        self, Connection, Endpoint, Event, Frame, Frames, HeaderKind, HeaderList, MessageSide, Priority,
        PriorityElement, RequestResult, RequestState, Settings, StreamDecoder, StreamHeader, StreamHeaders, StreamItem,
    },
    qpack::{self, SectionResult, Table},
};
use libfuzzer_sys::fuzz_target;

/// Checks an event and its acknowledgment, or pauses/cancels its request stream.
fn request_result(
    result: Result<RequestResult, http3::Error>,
    id: u64,
    side: MessageSide,
    connection: &mut Connection,
    table: &Table,
    held: &mut qpack::BlockedSections,
) -> bool {
    match result {
        Ok(RequestResult::Blocked(section)) => {
            held.push(section).unwrap();
            connection.pause(id);
            return true;
        }
        Ok(RequestResult::Event { event, ack }) => {
            if let Some(ack) = ack {
                contract::check_wire_value(&ack);
            }
            if let Ok(event) = event {
                match event {
                    Event::Headers(headers) if side == MessageSide::Request => {
                        assert_eq!(headers.validate(HeaderKind::Request { extended_connect: true }), Ok(()));
                    }
                    Event::Headers(headers) | Event::Informational(headers) => {
                        assert_eq!(headers.validate(HeaderKind::Response), Ok(()));
                    }
                    Event::Trailers(headers) => assert_eq!(headers.validate(HeaderKind::Trailers), Ok(())),
                    Event::PushPromise { headers, .. } => assert_eq!(headers.validate(HeaderKind::Promise), Ok(())),
                    Event::Unknown(frame) => contract::check_wire_value(&frame),
                    Event::Data(data) => assert!(data.len() <= http3::MAX_FRAME),
                }
                return true;
            }
        }
        Err(_) => {}
    }
    if let Some(cancel) = held.cancel(table, id) {
        contract::check_wire_value(&cancel);
    }
    let _ = connection.remove(id);
    false
}

/// Two request streams share a table while encoder instructions arrive in chunks.
fn shared_qpack(bytes: &[u8], side: MessageSide) {
    let [split, chunk, rest @ ..] = bytes else { return };
    let chunk = usize::from(*chunk).max(1);
    let (encoder, requests) = rest.split_at(rest.len() * usize::from(*split) / 256);
    let (first, second) = requests.split_at(requests.len() / 2);
    let (sender, encoder_id) = if side == MessageSide::Request { (Endpoint::Client, 2) } else { (Endpoint::Server, 3) };
    let mut connection = Connection::new(sender, 3, http3::MAX_FRAME * 2);
    assert_eq!(connection.push(encoder_id, &StreamHeader::QpackEncoder.to_bytes().unwrap()), 1);
    let mut table = Table::new(4096);
    let mut states = [RequestState::new(0, side, true).unwrap(), RequestState::new(4, side, true).unwrap()];
    let mut held = qpack::BlockedSections::new(2);
    let mut inputs = [first, second, encoder];
    let mut active = [true; 2];
    'drive: loop {
        let mut progress = false;
        for (k, id) in [0, 4, encoder_id].into_iter().enumerate() {
            if k < 2 && !active[k] {
                continue;
            }
            let used = connection.push(id, &inputs[k][..inputs[k].len().min(chunk)]);
            inputs[k] = &inputs[k][used..];
            progress |= used > 0;
            if k < 2 && inputs[k].is_empty() {
                connection.end(id);
            }
        }
        while let Some((stream, item)) = connection.next() {
            progress = true;
            match item {
                Ok(Ok(StreamItem::EncoderInstruction(instruction))) => {
                    if table.apply(instruction).is_err() {
                        break 'drive;
                    }
                    while let Some((id, result)) = held.next_ready(&table) {
                        let k = states.iter().position(|state| state.stream_id() == id).expect("unknown stream");
                        let state = &mut states[k];
                        assert!(state.is_blocked());
                        let result = state.resume(id, result);
                        active[k] = request_result(result, id, side, &mut connection, &table, &mut held);
                        if active[k] {
                            assert!(!state.is_blocked());
                            connection.unpause(id);
                        }
                    }
                }
                Ok(Ok(StreamItem::Frame(frame))) => {
                    let k = states.iter().position(|state| state.stream_id() == stream).expect("unknown stream");
                    let result = states[k].step(&frame, &table);
                    active[k] = request_result(result, stream, side, &mut connection, &table, &mut held);
                }
                Ok(Ok(_)) => {}
                _ if stream == encoder_id => break 'drive,
                _ => {
                    let k = states.iter().position(|state| state.stream_id() == stream).expect("unknown stream");
                    active[k] =
                        request_result(Err(http3::Error::State), stream, side, &mut connection, &table, &mut held);
                }
            }
            assert!(connection.buffered() <= http3::MAX_FRAME * 2);
            assert!(held.buffered() <= qpack::MAX_BLOCKED_BYTES);
        }
        if !progress {
            break;
        }
    }
    for state in &mut states {
        let _ = state.finish();
        contract::check_wire_value(&held.cancel(&table, state.stream_id()).unwrap());
        let _ = connection.remove(state.stream_id());
    }
}

fuzz_target!(|input: &[u8]| {
    let bytes = &input[..input.len().min(16 << 10)];
    contract::check_wire::<Frame>(bytes);
    contract::check_wire::<Settings>(bytes);
    contract::check_wire::<Priority>(bytes);
    contract::check_wire::<StreamHeader>(bytes);
    contract::check_decode_with_alloc_limit(Frames::new, bytes, 2 * http3::MAX_FRAME);
    contract::check_decode_with_alloc_limit(StreamHeaders::new, bytes, 2 * http3::MAX_STREAM_HEADER);
    contract::check_decode_with_alloc_limit(StreamDecoder::request, bytes, 2 * StreamDecoder::request().capacity());
    contract::check_decode_with_alloc_limit(
        StreamDecoder::unidirectional,
        bytes,
        2 * StreamDecoder::unidirectional().capacity(),
    );
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
    shared_qpack(bytes, MessageSide::Request);
    shared_qpack(bytes, MessageSide::Response);
    // Structured values reach writers even when arbitrary input fails framing.
    let id = bytes.iter().take(8).fold(0u64, |n, b| (n << 8) | u64::from(*b));
    for frame in [
        Frame::Data(bytes.to_vec()),
        Frame::Headers(bytes.to_vec()),
        Frame::Unknown { frame_type: id, payload: bytes.to_vec() },
        Frame::PushPromise { push_id: id, field_section: bytes.to_vec() },
        Frame::Goaway(id),
        Frame::CancelPush(id),
        Frame::MaxPushId(id),
        Frame::PriorityUpdate { element: PriorityElement::Request(id), value: bytes.to_vec() },
        Frame::PriorityUpdate { element: PriorityElement::Push(id), value: bytes.to_vec() },
    ] {
        contract::check_wire_value(&frame);
    }
    contract::check_wire_value(&Priority { urgency: input.first().copied(), incremental: Some(true) });
    let headers = HeaderList {
        fields: vec![
            qpack::Field::new(":method", "GET"),
            qpack::Field::new(":scheme", "https"),
            qpack::Field::new(":authority", "example.net"),
            qpack::Field::new(":path", "/"),
            qpack::Field { name: b"x-fuzz".to_vec(), value: bytes.to_vec(), never_index: id & 1 != 0 },
        ],
    };
    let kind = HeaderKind::Request { extended_connect: false };
    let result = headers.section(&mut qpack::Encoder::new(0, http3::MAX_FIELD_SECTION_SIZE), 0, kind);
    if headers.validate(kind).is_ok() {
        let section = result.unwrap();
        contract::check_wire_value(&section);
        let SectionResult::Fields { fields, ack } =
            qpack::decode_section(&Table::new(0), 0, &section.to_bytes().unwrap()).unwrap()
        else {
            panic!("a literal section blocked");
        };
        assert_eq!(ack, None);
        assert_eq!(HeaderList::from_fields(fields, kind), Ok(headers));
    } else {
        assert!(result.is_err());
    }
});
