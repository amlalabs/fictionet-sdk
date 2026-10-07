//! HTTP/3 streams, field sections, and Priority dictionaries.
#![no_main]

use fictionet::stdlib::{
    codec::{Decode, Wire, contract, test_support::decode_all},
    http3::{
        self, Endpoint, Event, Frame, Frames, HeaderKind, HeaderList, MessageSide, Priority,
        PriorityElement, RequestResult, RequestState, Session, Settings, StreamHeader, StreamHeaders, StreamItem, StreamItems,
    },
    qpack::{self, SectionResult, Table},
};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT: usize = 16 << 10;

/// A valid header list writes, reads back equal, and its Priority does too.
fn check_headers(headers: &HeaderList, kind: HeaderKind) {
    if headers.validate(kind).is_err() {
        return;
    }
    let section = headers.section(&mut qpack::Encoder::new(0, http3::MAX_FIELD_SECTION_SIZE), 0, kind).unwrap();
    contract::check_wire_value(&section);
    let SectionResult::Fields { fields, ack } =
        qpack::decode_section(&Table::new(0), 0, &section.to_bytes().unwrap()).unwrap()
    else {
        panic!("a literal section blocked");
    };
    assert_eq!(ack, None);
    assert_eq!(HeaderList::from_fields(fields, kind).as_ref(), Ok(headers));
    if let Ok(priority) = headers.priority() {
        assert_eq!(Priority::parse(&priority.to_bytes().unwrap()), Ok(priority));
    }
}

/// Checks a received event. `request` is the header kind of a request stream's headers;
/// other streams carry responses.
fn check_event(event: &Event, request: Option<HeaderKind>) {
    let (headers, kind) = match event {
        Event::Headers(headers) => (headers, request.unwrap_or(HeaderKind::Response)),
        Event::Informational(headers) => (headers, HeaderKind::Response),
        Event::Trailers(headers) => (headers, HeaderKind::Trailers),
        Event::PushPromise { headers, .. } => (headers, HeaderKind::Promise),
        Event::Unknown(frame) => return contract::check_wire_value(frame),
        Event::Data(data) => return assert!(data.len() <= http3::MAX_FRAME),
    };
    assert_eq!(headers.validate(kind), Ok(()));
    check_headers(headers, kind);
}

/// Checks an event and its acknowledgment, or pauses/cancels its request stream.
fn request_result(
    result: Result<RequestResult, http3::Error>,
    id: u64,
    side: MessageSide,
    session: &mut Session,
    table: &Table,
    held: &mut qpack::BlockedSections,
) -> bool {
    match result {
        Ok(RequestResult::Blocked(section)) => {
            held.push(section).unwrap();
            session.pause(id);
            return true;
        }
        Ok(RequestResult::Event { event, ack }) => {
            if let Some(ack) = ack {
                contract::check_wire_value(&ack);
            }
            if let Ok(event) = event {
                let request = (side == MessageSide::Request).then_some(HeaderKind::Request { extended_connect: true });
                check_event(&event, request);
                return true;
            }
        }
        Err(_) => {}
    }
    if let Some(cancel) = held.cancel(table, id) {
        contract::check_wire_value(&cancel);
    }
    let _ = session.remove(id);
    false
}

/// Two request streams share a table while encoder instructions arrive in chunks.
fn shared_qpack(bytes: &[u8], side: MessageSide) {
    let [split, chunk, rest @ ..] = bytes else { return };
    let chunk = usize::from(*chunk).max(1);
    let (encoder, requests) = rest.split_at(rest.len() * usize::from(*split) / 256);
    let (first, second) = requests.split_at(requests.len() / 2);
    let (sender, encoder_id) = if side == MessageSide::Request { (Endpoint::Client, 2) } else { (Endpoint::Server, 3) };
    let mut session = Session::new(sender, 3, http3::MAX_FRAME * 2);
    assert_eq!(session.push(encoder_id, &StreamHeader::QpackEncoder.to_bytes().unwrap()), 1);
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
            let used = session.push(id, &inputs[k][..inputs[k].len().min(chunk)]);
            inputs[k] = &inputs[k][used..];
            progress |= used > 0;
            if k < 2 && inputs[k].is_empty() {
                session.end(id);
            }
        }
        while let Some((stream, item)) = session.next() {
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
                        active[k] = request_result(result, id, side, &mut session, &table, &mut held);
                        if active[k] {
                            assert!(!state.is_blocked());
                            session.unpause(id);
                        }
                    }
                }
                Ok(Ok(StreamItem::Frame(frame))) => {
                    let k = states.iter().position(|state| state.stream_id() == stream).expect("unknown stream");
                    let result = states[k].step(&frame, &table);
                    active[k] = request_result(result, stream, side, &mut session, &table, &mut held);
                }
                Ok(Ok(_)) => {}
                _ if stream == encoder_id => break 'drive,
                _ => {
                    let k = states.iter().position(|state| state.stream_id() == stream).expect("unknown stream");
                    active[k] =
                        request_result(Err(http3::Error::State), stream, side, &mut session, &table, &mut held);
                }
            }
            assert!(session.buffered() <= http3::MAX_FRAME * 2);
            assert!(held.buffered() <= qpack::MAX_BLOCKED_BYTES);
        }
        if !progress {
            break;
        }
    }
    for state in &mut states {
        let _ = state.finish();
        contract::check_wire_value(&held.cancel(&table, state.stream_id()).unwrap());
        let _ = session.remove(state.stream_id());
    }
}

fuzz_target!(|input: &[u8]| {
    let bytes = &input[..input.len().min(MAX_FUZZ_INPUT)];
    contract::check_wire::<Frame>(bytes);
    contract::check_wire::<Settings>(bytes);
    contract::check_wire::<Priority>(bytes);
    contract::check_wire::<StreamHeader>(bytes);
    contract::check_decode_with_alloc_limit(Frames::new, bytes, 2 * http3::MAX_FRAME);
    contract::check_decode_with_alloc_limit(StreamHeaders::new, bytes, 2 * http3::MAX_STREAM_HEADER);
    contract::check_decode_with_alloc_limit(StreamItems::request, bytes, 2 * StreamItems::request().capacity());
    contract::check_decode_with_alloc_limit(
        StreamItems::unidirectional,
        bytes,
        2 * StreamItems::unidirectional().capacity(),
    );
    for sender in [Endpoint::Client, Endpoint::Server] {
        contract::check_decode_with_alloc_limit(|| http3::ControlFrames::new(sender), bytes, 2 * http3::MAX_FRAME);
        for header in
            [StreamHeader::Control, StreamHeader::QpackEncoder, StreamHeader::QpackDecoder, StreamHeader::Unknown(64)]
        {
            let make = || StreamItems::after_header(header, sender);
            contract::check_decode_with_alloc_limit(make, bytes, 2 * make().capacity());
        }
    }
    let budget = http3::MAX_FRAME + MAX_FUZZ_INPUT;
    let mut session = Session::new(Endpoint::Client, 5, budget);
    for (index, chunk) in bytes.chunks(17).enumerate() {
        let _ = session.push([0, 2, 4, 6, 10][index % 5], chunk);
        while session.next().is_some() {}
        assert!(session.buffered() <= budget);
    }
    for id in [0, 2, 4, 6, 10] {
        session.end(id);
    }
    while session.next().is_some() {}
    assert!(session.buffered() <= budget);
    let table = Table::new(0);
    let (items, _) = decode_all(Frames::new, bytes);
    for frame in items.iter().flatten() {
        contract::check_wire_value(frame);
    }
    for extended_connect in [false, true] {
        let request = Some(HeaderKind::Request { extended_connect });
        for (mut state, request) in [
            (RequestState::new(0, MessageSide::Request, extended_connect).unwrap(), request),
            (RequestState::new(0, MessageSide::Response, extended_connect).unwrap(), None),
            (RequestState::new(0, MessageSide::HeadResponse, extended_connect).unwrap(), None),
            (RequestState::new(0, MessageSide::ConnectResponse, extended_connect).unwrap(), None),
            (RequestState::push(3).unwrap(), None),
        ] {
            for frame in &items {
                let Ok(frame) = frame else { break };
                match state.step(frame, &table) {
                    Ok(RequestResult::Event { event: Ok(event), ack }) => {
                        check_event(&event, request);
                        if let Some(ack) = ack {
                            contract::check_wire_value(&ack);
                        }
                    }
                    _ => break,
                }
            }
            let _ = state.finish();
        }
    }
    if let Ok(SectionResult::Fields { fields, .. }) = qpack::decode_section(&table, 0, bytes) {
        for kind in [
            HeaderKind::Request { extended_connect: false },
            HeaderKind::Request { extended_connect: true },
            HeaderKind::Response,
            HeaderKind::Trailers,
            HeaderKind::Promise,
        ] {
            if let Ok(headers) = HeaderList::from_fields(fields.clone(), kind) {
                check_headers(&headers, kind);
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
