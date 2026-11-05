//! RTSP messages, interleaved frames, and header values through codec contracts.
#![no_main]

use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::protocols::rtsp::harness::{round_trip, text_value};
use fictionet::stdlib::protocols::rtsp::{
    Frame, Frames, Interleaved, MAX_BODY, MAX_HEAD, MAX_INTERLEAVED, MAX_MESSAGE, Message, Range,
    Session, Transport, Transports, Version,
};
use fictionet::stdlib::test_support::decode_all;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_MESSAGE);
                assert_eq!(s.held(), 0);
            }
        ),
        decode_all(Frames::new, data),
    );
    if let Ok(value) = <Message as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Frame as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Interleaved as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Session as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Range as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Transport as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Transports as Wire>::parse(data) {
        let _ = assert_write(&value);
    }

    let frame = Interleaved {
        channel: data.first().copied().unwrap_or(0),
        data: data.get(..MAX_INTERLEAVED + 1).unwrap_or(data).to_vec(),
    };
    let _ = assert_write(&frame);
    let mut message = Message::response(Version::Rtsp20, 200, "OK");
    message.body = data.get(..MAX_BODY + 1).unwrap_or(data).to_vec();
    message.push_header("Content-Length", &message.body.len().to_string());
    let _ = assert_write(&message);
    if let Ok(bytes) = message.to_bytes() {
        if let Ok(value) = <Message as Wire>::parse(&bytes) {
            let _ = assert_write(&value);
        }
        assert_eq!(
            decode_chunks(
                &mut Stream::new(Frames::new()),
                chunks(&bytes, &[1, 7, 64]),
                |s| {
                    assert!(s.allocated() <= 2 * MAX_MESSAGE);
                }
            ),
            decode_all(Frames::new, &bytes),
        );
    }
    message.push_header("X", " leading");
    let _ = assert_write(&message);

    let (items, _) = decode_all(Frames::new, data);
    for item in items.iter().flatten() {
        round_trip(item);
    }
    if data.len() <= MAX_HEAD + 1
        && let Ok(text) = core::str::from_utf8(data)
    {
        // Accessors call the text readers without first invoking the writers.
        let mut message = Message::request(Version::Rtsp20, "SETUP", "rtsp://h/s");
        for name in ["Session", "Range", "Transport"] {
            message.push_header(name, text);
        }
        text_value(message.session());
        text_value(message.range());
        text_value(message.transports().map(|values| Transports { values }));
    }
    writers(data);
});

// Exercise message fields that parsed input has already normalized.
fn writers(data: &[u8]) {
    let bounded = data.get(..MAX_HEAD + 1).unwrap_or(data);
    let parts: Vec<String> = bounded
        .split(|&b| b == 0xff)
        .take(12)
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect();
    let part = |i: usize| parts.get(i).cloned().unwrap_or_default();
    let version = if data.first().is_some_and(|b| b & 1 == 1) {
        Version::Rtsp10
    } else {
        Version::Rtsp20
    };
    let mut message = if data.first().is_some_and(|b| b & 2 == 2) {
        Message::request(version, &part(0), &part(1))
    } else {
        Message::response(
            version,
            u16::from(data.first().copied().unwrap_or(0)) * 3,
            &part(1),
        )
    };
    for i in (2..parts.len()).step_by(2) {
        message.push_header(&part(i), &part(i + 1));
    }
    message.body = parts
        .last()
        .map(|p| p.as_bytes().to_vec())
        .unwrap_or_default();
    let _ = assert_write(&message);
    message.set_header("Content-Length", &message.body.len().to_string());
    let _ = assert_write(&message);
}
