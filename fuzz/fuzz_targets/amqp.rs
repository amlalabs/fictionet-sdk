//! AMQP 0-9-1 frames, methods, content headers and field tables, as a
//! world playing a broker reads them.
#![no_main]

use fictionet::stdlib::amqp::{
    BasicProperties, ContentHeader, Decoder, Frame, FrameError, FrameKind, MAX_PAYLOAD, Method, Table, content_frames,
    frame_limit, plain_credentials,
};
use libfuzzer_sys::fuzz_target;

/// Feeds `data` in chunks, taking frames out after each feed, as a world
/// does. Every frame, then the error that broke the stream, if one did.
fn split(mut decoder: Decoder, data: &[u8], bytewise: bool) -> (Vec<Frame>, Option<FrameError>) {
    let mut frames = Vec::new();
    let chunks: Vec<&[u8]> = if bytewise { data.chunks(1).collect() } else { vec![data] };
    for chunk in chunks {
        let mut rest = chunk;
        while !rest.is_empty() {
            let took = decoder.feed(rest);
            assert!(decoder.buffered() <= decoder.capacity());
            rest = &rest[took..];
            let mut progress = took > 0;
            while let Some(r) = decoder.next_frame() {
                match r {
                    Ok(f) => frames.push(f),
                    Err(e) => return (frames, Some(e)),
                }
                progress = true;
            }
            // A full decoder always gives a frame or an error.
            assert!(progress);
        }
    }
    (frames, None)
}

/// Writes a message with `content_frames` and reads it back through a
/// decoder of the same frame-max.
fn message(method: &Method, properties: &BasicProperties, body: &[u8], frame_max: u32) {
    let Ok(frames) = content_frames(1, method, properties, body, frame_max) else { return };
    let room = (frame_limit(frame_max) - 8) as usize;
    let mut decoder = Decoder::new();
    decoder.set_frame_max(frame_max);
    let mut stream = Vec::new();
    for f in &frames {
        let bytes = f.to_bytes().unwrap();
        assert!(bytes.len() <= frame_limit(frame_max) as usize);
        stream.extend(bytes);
    }
    let (back, err) = split(decoder, &stream, false);
    assert_eq!(err, None);
    assert_eq!(back, frames);
    assert_eq!(Method::parse(&back[0].payload).as_ref(), Ok(method));
    let header = ContentHeader::parse(&back[1].payload).unwrap();
    assert_eq!(header.body_size, body.len() as u64);
    assert_eq!(props_bytes(&header.properties), props_bytes(properties));
    let joined: Vec<u8> = back[2..].iter().flat_map(|f| f.payload.iter().copied()).collect();
    assert_eq!(joined, body);
    assert!(back[2..].iter().all(|f| f.kind == FrameKind::Body && f.payload.len() <= room));
}

/// The bytes properties are written as, to compare them where a float
/// that is NaN keeps `PartialEq` from holding.
fn props_bytes(properties: &BasicProperties) -> Vec<u8> {
    ContentHeader { body_size: 0, properties: properties.clone() }.to_bytes().unwrap()
}

/// A payload read as each kind of thing it might be. Whatever reads can be
/// written, and what is written reads back to the same bytes.
fn payload(p: &[u8], frame_max: u32) {
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
        assert_eq!(ContentHeader::parse(&bytes).unwrap().to_bytes().unwrap(), bytes);
        let publish = Method::BasicPublish {
            exchange: String::new(),
            routing_key: "q".into(),
            mandatory: false,
            immediate: false,
        };
        message(&publish, &h.properties, p, frame_max);
    }
    if let Ok(t) = Table::decode(p) {
        let bytes = t.to_bytes().unwrap();
        assert_eq!(Table::decode(&bytes).unwrap().to_bytes().unwrap(), bytes);
    }
}

fuzz_target!(|data: &[u8]| {
    let frame_max = data.first().map_or(0, |&b| u32::from(b) << 9);
    // The stream, split two ways: all at once, and a byte at a time, as a
    // client's frames and as a broker's input with the protocol header.
    for server in [false, true] {
        let make = || if server { Decoder::server() } else { Decoder::new() };
        let whole = split(make(), data, false);
        assert_eq!(whole, split(make(), data, true));
        for f in &whole.0 {
            // A frame read can be written, and reads back the same.
            let bytes = f.to_bytes().unwrap();
            let (back, used) = Frame::parse(&bytes, 0).unwrap().unwrap();
            assert_eq!(&back, f);
            assert_eq!(used, bytes.len());
            payload(&f.payload, frame_max);
        }
    }
    // A frame built from any bytes: whatever its writer writes, its reader
    // reads back as the same frame.
    if let [kind, c0, c1, rest @ ..] = data {
        let kinds = [FrameKind::Method, FrameKind::Header, FrameKind::Body, FrameKind::Heartbeat];
        let f = Frame {
            kind: kinds[usize::from(kind % 4)],
            channel: u16::from_be_bytes([*c0, *c1]),
            payload: rest.to_vec(),
        };
        if let Ok(bytes) = f.to_bytes() {
            assert!(f.payload.len() <= MAX_PAYLOAD);
            assert_eq!(Frame::parse(&bytes, 0), Ok(Some((f, bytes.len()))));
        }
    }
    // Any bytes as a payload on their own, and as a SASL PLAIN response.
    payload(data, frame_max);
    if let Some((user, password)) = plain_credentials(data) {
        assert!(!user.is_empty() && !password.is_empty());
        assert!(user.len() + password.len() + 2 <= data.len());
    }
});
