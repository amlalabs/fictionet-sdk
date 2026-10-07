//! RTSP messages, interleaved frames, and header values through codec contracts.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract, test_support::decode_all};
use fictionet::stdlib::rtsp::{
    Error, Frames, Interleaved, Frame, MAX_BODY, MAX_HEAD, MAX_INTERLEAVED, MAX_MESSAGE, Message, Range, Session, Transport,
    Transports, Version,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Frames::new, data, 2 * MAX_MESSAGE);
    contract::check_decode_with_held_limit(Frames::new, data, 0);
    contract::check_wire::<Message>(data);
    contract::check_wire::<Frame>(data);
    contract::check_wire::<Interleaved>(data);
    contract::check_wire::<Session>(data);
    contract::check_wire::<Range>(data);
    contract::check_wire::<Transport>(data);
    contract::check_wire::<Transports>(data);

    let frame = Interleaved {
        channel: data.first().copied().unwrap_or(0),
        data: data.get(..MAX_INTERLEAVED + 1).unwrap_or(data).to_vec(),
    };
    contract::check_wire_value(&frame);
    let mut message = Message::response(Version::Rtsp20, 200, "OK");
    message.body = data.get(..MAX_BODY + 1).unwrap_or(data).to_vec();
    message.push_header("Content-Length", &message.body.len().to_string());
    contract::check_wire_value(&message);
    if let Ok(bytes) = message.to_bytes() {
        contract::check_wire::<Message>(&bytes);
        contract::check_decode_with_alloc_limit(Frames::new, &bytes, 2 * MAX_MESSAGE);
    }
    message.push_header("X", " leading");
    contract::check_wire_value(&message);

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

fn round_trip(item: &Frame) {
    contract::check_wire_value(item);
    if let Frame::Interleaved(frame) = item {
        frame.to_bytes().unwrap();
        return;
    }
    if let Err(error) = item.to_bytes() {
        assert!(matches!(error, Error::TooLong | Error::TooMany), "{error:?} for {item:?}");
        return;
    }
    if let Frame::Message(message) = item {
        if let Ok(value) = message.session() {
            contract::check_wire_value(&value);
            value.to_bytes().unwrap();
        }
        if let Ok(value) = message.range() {
            contract::check_wire_value(&value);
            value.to_bytes().unwrap();
        }
        if let Ok(values) = message.transports()
            && !values.is_empty()
        {
            let value = Transports { values };
            contract::check_wire_value(&value);
            value.to_bytes().unwrap();
        }
        if message.method().is_some() {
            let reply = message.reply(100, "Continue");
            contract::check_wire_value(&reply);
            assert!(matches!(reply.to_bytes(), Ok(_) | Err(Error::TooLong | Error::TooMany)));
        }
    }
}

fn text_value<T: Wire<ParseError = Error, WriteError = Error> + PartialEq + core::fmt::Debug>(value: Result<T, Error>) {
    if let Ok(value) = value {
        contract::check_wire_value(&value);
        assert!(matches!(value.to_bytes(), Ok(_) | Err(Error::TooLong)), "{value:?}");
    }
}

// Exercise message fields that parsed input has already normalized.
fn writers(data: &[u8]) {
    let bounded = data.get(..MAX_HEAD + 1).unwrap_or(data);
    let parts: Vec<String> =
        bounded.split(|&b| b == 0xff).take(12).map(|p| String::from_utf8_lossy(p).into_owned()).collect();
    let part = |i: usize| parts.get(i).cloned().unwrap_or_default();
    let version = if data.first().is_some_and(|b| b & 1 == 1) { Version::Rtsp10 } else { Version::Rtsp20 };
    let mut message = if data.first().is_some_and(|b| b & 2 == 2) {
        Message::request(version, &part(0), &part(1))
    } else {
        Message::response(version, u16::from(data.first().copied().unwrap_or(0)) * 3, &part(1))
    };
    for i in (2..parts.len()).step_by(2) {
        message.push_header(&part(i), &part(i + 1));
    }
    message.body = parts.last().map(|p| p.as_bytes().to_vec()).unwrap_or_default();
    contract::check_wire_value(&message);
    message.set_header("Content-Length", &message.body.len().to_string());
    contract::check_wire_value(&message);
}
