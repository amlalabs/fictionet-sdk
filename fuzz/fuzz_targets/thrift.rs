//! Thrift frames, messages and values in the binary and compact protocols,
//! as a world playing a Thrift server reads them.
#![no_main]
#![allow(deprecated)] // Also exercise the compatibility decoder.

use fictionet::stdlib::codec::{Decode, contract};
use fictionet::stdlib::thrift::{
    Decoder, Error, Frame, Frames, MAX_FRAME, Message, Messages, Protocol, StreamDecoder, Type,
    Value,
};
use libfuzzer_sys::fuzz_target;

const TYPES: [Type; 12] = [
    Type::Bool,
    Type::Byte,
    Type::I16,
    Type::I32,
    Type::I64,
    Type::Double,
    Type::Binary,
    Type::Uuid,
    Type::Struct,
    Type::List,
    Type::Set,
    Type::Map,
];

/// A message read can be written, and reads back to the same bytes.
fn rewrites(m: &Message, protocol: Protocol) {
    let bytes = m.to_bytes(protocol).unwrap();
    let (back, again, used) = Message::parse(&bytes).unwrap();
    assert_eq!((again, used), (protocol, bytes.len()));
    assert_eq!(back.to_bytes(protocol).unwrap(), bytes);
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Messages::new, data);
    contract::check_decode(Frames::new, data);
    contract::check_decode(
        || Frames::with_limit(usize::from(data.first().copied().unwrap_or(0))),
        data,
    );
    contract::check_wire::<Frame>(data);
    contract::check_decode(|| Frames::new().map(|frame| Message::parse(&frame.0)), data);
    contract::check_wire_value(&Frame(data.iter().take(MAX_FRAME + 1).copied().collect()));

    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    whole.feed(data);
    let mut frames = Vec::new();
    while let Some(Ok(f)) = whole.next_frame() {
        frames.push(f);
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(Ok(f)) = bytewise.next_frame() {
            again.push(f);
        }
    }
    assert_eq!(frames, again);
    for f in &frames {
        if let Ok((m, protocol, used)) = Message::parse(f) {
            assert!(used <= f.len());
            rewrites(&m, protocol);
        }
    }

    // The stream without frames, read whole and a byte at a time, gives the
    // messages that reading from the start again and again gives.
    let mut want = Vec::new();
    let mut rest = data;
    let end = loop {
        match Message::parse(rest) {
            Ok((m, protocol, used)) => {
                want.push((m, protocol));
                rest = &rest[used..];
            }
            Err(e) => break e,
        }
    };
    for whole in [true, false] {
        let mut d = StreamDecoder::new();
        let mut got = Vec::new();
        let mut failed = None;
        let pieces: Vec<&[u8]> = if whole {
            vec![data]
        } else {
            data.chunks(1).collect()
        };
        'feed: for piece in pieces {
            d.feed(piece);
            while let Some(r) = d.next_message() {
                match r {
                    Ok(m) => got.push(m),
                    Err(e) => {
                        failed = Some(e);
                        break 'feed;
                    }
                }
            }
        }
        assert_eq!(got, want);
        // A whole read can stop early on a count bigger than the bytes held,
        // where the stream decoder already sees an error further on.
        if end != Error::Truncated {
            assert_eq!(failed, Some(end));
        }
    }

    // Any bytes as a message on its own, and as a value of each type.
    if let Ok((m, protocol, used)) = Message::parse(data) {
        assert!(used <= data.len());
        rewrites(&m, protocol);
    }
    for protocol in [Protocol::Binary, Protocol::Compact] {
        for ty in TYPES {
            if let Ok((v, used)) = Value::parse(protocol, ty, data) {
                assert!(used <= data.len());
                let bytes = v.to_bytes(protocol).unwrap();
                let (back, n) = Value::parse(protocol, ty, &bytes).unwrap();
                assert_eq!(n, bytes.len());
                assert_eq!(back.to_bytes(protocol).unwrap(), bytes);
            }
        }
    }
});
