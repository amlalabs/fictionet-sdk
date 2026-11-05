//! AMQP 0-9-1 frames, methods, content headers and field tables, as a
//! world playing a broker reads them.
#![no_main]

use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::{Decode, Wire};
use fictionet::stdlib::protocols::amqp::{
    BasicProperties, ContentHeader, Frame, FrameKind, Frames, MAX_PAYLOAD, Method, Table,
    content_frames, frame_limit, plain_credentials,
};
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};
use libfuzzer_sys::fuzz_target;

/// Writes a message with `content_frames` and reads it back through a
/// decoder of the same frame-max.
fn message(method: &Method, properties: &BasicProperties, body: &[u8], frame_max: u32) {
    let Ok(frames) = content_frames(1, method, properties, body, frame_max) else {
        return;
    };
    let room = (frame_limit(frame_max) - 8) as usize;
    let mut stream = Vec::new();
    for f in &frames {
        let bytes = f.to_bytes().unwrap();
        assert!(bytes.len() <= frame_limit(frame_max) as usize);
        stream.extend(bytes);
    }
    let (back, err) = decode_all(|| Frames::with_limit(frame_max), &stream);
    assert_eq!(err, None);
    assert_eq!(back, frames);
    assert_eq!(Method::parse(&back[0].payload).as_ref(), Ok(method));
    let header = ContentHeader::parse(&back[1].payload).unwrap();
    assert_eq!(header.body_size, body.len() as u64);
    assert_eq!(&header.properties, properties);
    let joined: Vec<u8> = back[2..]
        .iter()
        .flat_map(|f| f.payload.iter().copied())
        .collect();
    assert_eq!(joined, body);
    assert!(
        back[2..]
            .iter()
            .all(|f| f.kind == FrameKind::Body && f.payload.len() <= room)
    );
}

/// A payload read as each kind of thing it might be. Whatever reads can be
/// written, and what is written reads back to the same bytes.
fn payload(p: &[u8], frame_max: u32) {
    if let Ok(value) = <Method as Wire>::parse(p) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <ContentHeader as Wire>::parse(p) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Table as Wire>::parse(p) {
        let _ = assert_write(&value);
    }
    if let Ok(m) = Method::parse(p) {
        let bytes = m.to_bytes().unwrap();
        assert_eq!(Method::parse(&bytes).unwrap().to_bytes().unwrap(), bytes);
        if m.has_content() {
            message(&m, &BasicProperties::default(), p, frame_max);
        } else {
            assert!(content_frames(1, &m, &BasicProperties::default(), p, frame_max).is_err());
        }
    }
    if let Ok(h) = ContentHeader::parse(p) {
        let bytes = h.to_bytes().unwrap();
        assert_eq!(
            ContentHeader::parse(&bytes).unwrap().to_bytes().unwrap(),
            bytes
        );
        let publish = Method::BasicPublish {
            exchange: String::new(),
            routing_key: "q".into(),
            mandatory: false,
            immediate: false,
        };
        message(&publish, &h.properties, p, frame_max);
    }
    if let Ok(t) = Table::parse(p) {
        let bytes = t.to_bytes().unwrap();
        assert_eq!(Table::parse(&bytes).unwrap().to_bytes().unwrap(), bytes);
    }
}

fuzz_target!(|data: &[u8]| {
    let frame_max = data.first().map_or(0, |&b| u32::from(b) << 9);
    if let Ok(value) = <Frame as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    for make in [Frames::new as fn() -> Frames, Frames::server] {
        let bound = 2 * make().capacity();
        assert_eq!(
            decode_chunks(&mut Stream::new(make()), chunks(data, &[1, 7, 64]), |s| {
                assert!(s.allocated() <= bound);
            }),
            decode_all(make, data),
        );
        for frame in decode_all(make, data).0 {
            let _ = assert_write(&frame);
            payload(&frame.payload, frame_max);
        }
    }
    let make = || Frames::with_limit(frame_max);
    let bound = 2 * make().capacity();
    assert_eq!(
        decode_chunks(&mut Stream::new(make()), chunks(data, &[1, 7, 64]), |s| {
            assert!(s.allocated() <= bound);
        }),
        decode_all(make, data),
    );
    // A frame built from any bytes: whatever its writer writes, its reader
    // reads back as the same frame.
    if let [kind, c0, c1, rest @ ..] = data {
        let kinds = [
            FrameKind::Method,
            FrameKind::Header,
            FrameKind::Body,
            FrameKind::Heartbeat,
        ];
        let f = Frame {
            kind: kinds[usize::from(kind % 4)],
            channel: u16::from_be_bytes([*c0, *c1]),
            payload: rest.to_vec(),
        };
        let _ = assert_write(&f);
        if let Ok(bytes) = f.to_bytes() {
            assert!(f.payload.len() <= MAX_PAYLOAD);
            assert_eq!(Frame::parse(&bytes), Ok(f));
        }
    }
    // Any bytes as a payload on their own, and as a SASL PLAIN response.
    payload(data, frame_max);
    if let Some((user, password)) = plain_credentials(data) {
        assert!(!user.is_empty() && !password.is_empty());
        assert!(user.len() + password.len() + 2 <= data.len());
    }
});
