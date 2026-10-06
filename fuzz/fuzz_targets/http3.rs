//! HTTP/3 stream bytes, field sections and Priority dictionaries.
#![no_main]

use fictionet::stdlib::{codec::contract, http3};
use fictionet::stdlib::{
    http3::{
        ControlDecoder, Decoder, Endpoint, Error, Event, Frame, HeaderKind, HeaderList, MAX_BUFFERED,
        MAX_FIELD_SECTION_SIZE, MAX_FRAME, MAX_PRIORITY_BYTES, MAX_SECTION_BYTES, MAX_STREAM_BUFFERED,
        MAX_STREAM_HEADER, MessageSide, Priority, PriorityElement, RequestDecoder, Settings, StreamHeader,
        StreamHeaderDecoder,
    },
    qpack,
};
use libfuzzer_sys::fuzz_target;

/// Bounds work and collected events in the chunking comparisons.
pub const MAX_FUZZ_INPUT: usize = 16 << 10;
/// A two-byte frame is the smallest event; this also bounds Vec capacity growth.
pub const MAX_FUZZ_EVENTS: usize = MAX_FUZZ_INPUT;

fn check_frame(frame: &Frame) {
    let bytes = frame.to_bytes().unwrap();
    assert!(bytes.len() <= MAX_FRAME);
    assert_eq!(Frame::parse(&bytes), Ok(Some((frame.clone(), bytes.len()))));
}

fn check_headers(headers: &HeaderList, kind: HeaderKind) {
    if headers.validate(kind).is_err() {
        return;
    }
    let mut encoder = qpack::Encoder::new(0, MAX_FIELD_SECTION_SIZE);
    let mut decoder = qpack::Decoder::new(0, 0, MAX_FIELD_SECTION_SIZE);
    let bytes = headers.encode(&mut encoder, 0, kind).unwrap();
    assert!(bytes.len() <= MAX_SECTION_BYTES);
    assert_eq!(HeaderList::decode(&mut decoder, 0, &bytes, kind), Ok(Some(headers.clone())));
    if let Ok(priority) = headers.priority() {
        assert_eq!(Priority::parse(&priority.to_bytes().unwrap()), Ok(priority));
    }
}

fn raw(bytes: &[u8], chunk: usize) -> (Vec<Frame>, Option<Error>) {
    let mut decoder = Decoder::new();
    let mut frames = Vec::new();
    for part in bytes.chunks(chunk.max(1)) {
        let mut pos = 0;
        while pos < part.len() {
            let used = decoder.feed(part.get(pos..).unwrap());
            pos += used;
            let mut progress = used > 0;
            while let Some(result) = decoder.next_frame() {
                match result {
                    Ok(frame) => {
                        check_frame(&frame);
                        frames.push(frame);
                        progress = true;
                    }
                    Err(e) => return (frames, Some(e)),
                }
            }
            assert!(progress);
            assert!(frames.capacity() <= MAX_FUZZ_EVENTS);
            assert!(decoder.buffered() <= MAX_BUFFERED);
            assert!(decoder.capacity() <= MAX_BUFFERED);
        }
    }
    (frames, decoder.finish().err())
}

fn control(bytes: &[u8], chunk: usize, sender: Endpoint) -> (Vec<Frame>, Option<Error>) {
    let mut decoder = ControlDecoder::new(sender);
    let mut frames = Vec::new();
    for part in bytes.chunks(chunk.max(1)) {
        assert_eq!(decoder.feed(part), part.len());
        while let Some(result) = decoder.next_frame() {
            match result {
                Ok(frame) => {
                    check_frame(&frame);
                    frames.push(frame);
                }
                Err(e) => return (frames, Some(e)),
            }
        }
        assert!(frames.capacity() <= MAX_FUZZ_EVENTS);
        assert!(decoder.buffered() <= MAX_BUFFERED);
        assert!(decoder.capacity() <= MAX_BUFFERED);
    }
    (frames, decoder.finish().err())
}

fn message(bytes: &[u8], chunk: usize, side: MessageSide, push: bool) -> (Vec<Event>, Option<Error>) {
    let mut decoder = if push { RequestDecoder::push(3).unwrap() } else { RequestDecoder::new(0, side, true).unwrap() };
    let mut qpack = qpack::Decoder::new(0, 0, MAX_FIELD_SECTION_SIZE);
    let mut events = Vec::new();
    for part in bytes.chunks(chunk.max(1)) {
        assert_eq!(decoder.feed(part), part.len());
        while let Some(result) = decoder.next_event(&mut qpack) {
            let event = match result {
                Ok(event) => event,
                Err(e) => return (events, Some(e)),
            };
            match &event {
                Event::Headers(h) => check_headers(
                    h,
                    if side == MessageSide::Request {
                        HeaderKind::Request { extended_connect: true }
                    } else {
                        HeaderKind::Response
                    },
                ),
                Event::Informational(h) => check_headers(h, HeaderKind::Response),
                Event::Trailers(h) => check_headers(h, HeaderKind::Trailers),
                Event::PushPromise { headers, .. } => check_headers(headers, HeaderKind::Promise),
                Event::Unknown(f) => check_frame(f),
                Event::Data(b) => assert!(b.len() <= MAX_FRAME),
                Event::Blocked => panic!("zero-capacity QPACK cannot block"),
            }
            events.push(event);
        }
        assert!(events.capacity() <= MAX_FUZZ_EVENTS);
        assert!(decoder.buffered() <= MAX_STREAM_BUFFERED);
        assert!(decoder.capacity() <= MAX_STREAM_BUFFERED);
    }
    (events, decoder.finish().err())
}

/// Checks one event from a stream that shares a dynamic QPACK table.
/// Every released field list passes the writer's validation.
fn check_event(event: &Event, side: MessageSide) {
    match event {
        Event::Headers(h) if side == MessageSide::Request => {
            assert_eq!(h.validate(HeaderKind::Request { extended_connect: true }), Ok(()))
        }
        Event::Headers(h) | Event::Informational(h) => assert_eq!(h.validate(HeaderKind::Response), Ok(())),
        Event::Trailers(h) => assert_eq!(h.validate(HeaderKind::Trailers), Ok(())),
        Event::PushPromise { headers, .. } => assert_eq!(headers.validate(HeaderKind::Promise), Ok(())),
        Event::Unknown(f) => check_frame(f),
        Event::Data(b) => assert!(b.len() <= MAX_FRAME),
        Event::Blocked => {}
    }
}

/// Two request streams share a QPACK decoder with a dynamic table, so
/// sections block, resume out of order, fail while blocked and are
/// cancelled. The first byte splits the rest into encoder-stream bytes and
/// stream bytes; the second sets the chunk size. Encoder-stream chunks are
/// interleaved with stream chunks, and decoder-stream output is drained only
/// every other round, so QPACK backlog retries run too.
fn shared_qpack(data: &[u8], side: MessageSide) {
    let [split, chunk, rest @ ..] = data else { return };
    let chunk = usize::from(*chunk).max(1);
    let (encoder, streams) = rest.split_at(rest.len() * usize::from(*split) / 256);
    let (first, second) = streams.split_at(streams.len() / 2);
    let mut qpack = qpack::Decoder::new(4096, 2, MAX_FIELD_SECTION_SIZE);
    let mut decoders = [RequestDecoder::new(0, side, true).unwrap(), RequestDecoder::new(4, side, true).unwrap()];
    let mut inputs = [first, second];
    let mut encoder = encoder.chunks(chunk);
    let mut events = 0usize;
    let mut connection_failed = false;
    for round in 0..(MAX_FUZZ_INPUT * 4) {
        let mut progress = false;
        for (decoder, input) in decoders.iter_mut().zip(inputs.iter_mut()) {
            let used = decoder.feed(input.get(..input.len().min(chunk)).unwrap());
            *input = input.get(used..).unwrap();
            progress |= used > 0;
            while let Some(result) = decoder.next_event(&mut qpack) {
                progress = true;
                match result {
                    Ok(event) => {
                        check_event(&event, side);
                        events += 1;
                    }
                    Err(Error::Qpack(qpack::Error::Backlog)) => break,
                    Err(_) => {
                        let _ = qpack.cancel_stream(decoder.stream_id());
                        break;
                    }
                }
            }
            assert!(decoder.buffered() <= MAX_STREAM_BUFFERED);
            assert!(decoder.capacity() <= MAX_STREAM_BUFFERED);
        }
        if let Some(part) = encoder.next() {
            progress = true;
            if qpack.feed_encoder_stream(part).is_err() {
                connection_failed = true;
                break;
            }
        }
        while let Some((stream, fields)) = qpack.next_unblocked() {
            progress = true;
            let Some(decoder) = decoders.iter_mut().find(|d| d.stream_id() == stream) else {
                panic!("QPACK released a section for an unknown stream");
            };
            let blocked = decoder.is_blocked();
            match decoder.resume(stream, fields) {
                Ok(event) => {
                    assert!(blocked);
                    check_event(&event, side);
                    events += 1;
                }
                Err(Error::State) => assert!(!blocked),
                Err(_) => {
                    let _ = qpack.cancel_stream(stream);
                }
            }
        }
        if round % 2 == 1 {
            assert!(qpack.take_decoder_stream().len() <= MAX_FUZZ_INPUT * 4);
        }
        assert!(events <= MAX_FUZZ_EVENTS * 2);
        if !progress {
            if round % 2 == 0 {
                continue;
            }
            break;
        }
    }
    if !connection_failed {
        for decoder in &mut decoders {
            let _ = decoder.finish();
        }
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(http3::Frames::new, data);
    contract::check_decode(http3::StreamHeaders::new, data);
    contract::check_decode(http3::StreamDecoder::request, data);
    contract::check_decode(http3::StreamDecoder::unidirectional, data);
    for sender in [Endpoint::Client, Endpoint::Server] {
        contract::check_decode(|| http3::ControlFrames::new(sender), data);
    }
    for header in [StreamHeader::QpackEncoder, StreamHeader::QpackDecoder, StreamHeader::Unknown(64)] {
        contract::check_decode(|| http3::StreamDecoder::after_header(header, Endpoint::Client), data);
    }
    contract::check_wire::<Frame>(data);
    contract::check_wire::<Settings>(data);
    contract::check_wire::<StreamHeader>(data);

    if let Ok(Some((frame, _))) = Frame::parse(data) {
        check_frame(&frame);
    }
    if let Ok(settings) = Settings::parse(data) {
        assert_eq!(Settings::parse(&settings.to_bytes().unwrap()), Ok(settings));
    }
    if let Ok(priority) = Priority::parse(data) {
        let bytes = priority.to_bytes().unwrap();
        assert!(bytes.len() <= MAX_PRIORITY_BYTES);
        assert_eq!(Priority::parse(&bytes), Ok(priority));
    }
    if let Ok(Some((header, consumed))) = StreamHeader::parse(data) {
        let bytes = header.to_bytes().unwrap();
        assert!(bytes.len() <= MAX_STREAM_HEADER);
        assert_eq!(StreamHeader::parse(&bytes), Ok(Some((header, bytes.len()))));
        let mut prefix = StreamHeaderDecoder::new();
        assert_eq!(prefix.feed(data), consumed);
        assert!(prefix.buffered() <= MAX_STREAM_HEADER);
        assert_eq!(prefix.next_header(), Some(header));
        let mut prefix = StreamHeaderDecoder::new();
        for b in data.iter().take(consumed) {
            assert_eq!(prefix.feed(std::slice::from_ref(b)), 1);
        }
        assert_eq!(prefix.next_header(), Some(header));
        assert_eq!(prefix.finish(), Ok(()));
    }
    let bytes = data.get(..data.len().min(MAX_FUZZ_INPUT)).unwrap();
    let mut connection = http3::Connection::new(Endpoint::Client, 5, http3::MAX_FRAME + MAX_FUZZ_INPUT);
    for (index, chunk) in bytes.chunks(17).enumerate() {
        let id = [0, 2, 4, 6, 10][index % 5];
        let _ = connection.push(id, chunk);
        while connection.next().is_some() {}
        assert!(connection.buffered() <= MAX_FUZZ_INPUT);
    }
    for id in [0, 2, 4, 6, 10] {
        connection.end(id);
    }
    while connection.next().is_some() {}

    assert_eq!(raw(bytes, bytes.len()), raw(bytes, 1));
    for sender in [Endpoint::Client, Endpoint::Server] {
        assert_eq!(control(bytes, bytes.len(), sender), control(bytes, 1, sender));
    }
    for side in [MessageSide::Request, MessageSide::Response, MessageSide::HeadResponse, MessageSide::ConnectResponse] {
        assert_eq!(message(bytes, bytes.len(), side, false), message(bytes, 1, side, false));
    }
    assert_eq!(
        message(bytes, bytes.len(), MessageSide::Response, true),
        message(bytes, 1, MessageSide::Response, true)
    );
    shared_qpack(bytes, MessageSide::Request);
    shared_qpack(bytes, MessageSide::Response);

    for kind in [
        HeaderKind::Request { extended_connect: false },
        HeaderKind::Request { extended_connect: true },
        HeaderKind::Promise,
        HeaderKind::Response,
        HeaderKind::Trailers,
    ] {
        let mut decoder = qpack::Decoder::new(0, 0, MAX_FIELD_SECTION_SIZE);
        if let Ok(Some(headers)) = HeaderList::decode(&mut decoder, 0, data, kind) {
            check_headers(&headers, kind);
        }
    }
    // Construct values as well as parsing bytes, so writer refusal paths run.
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
        if frame.to_bytes().is_ok() {
            check_frame(&frame);
        }
    }
    let headers = HeaderList {
        fields: vec![
            qpack::Field::new(":method", "GET"),
            qpack::Field::new(":scheme", "https"),
            qpack::Field::new(":authority", "example.net"),
            qpack::Field::new(":path", "/"),
            qpack::Field { name: b"x-fuzz".to_vec(), value: bytes.to_vec(), never_index: id & 1 != 0 },
        ],
    };
    check_headers(&headers, HeaderKind::Request { extended_connect: false });
});
