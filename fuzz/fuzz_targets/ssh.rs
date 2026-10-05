//! The SSH transport layer before encryption: version lines, packets and
//! messages, as a world playing an SSH server reads them.
#![no_main]

use fictionet::stdlib::ssh::{
    DECODER_CAPACITY, Decoder, Event, Line, Message, Packet, Reader, StreamError, parse_line,
};
use libfuzzer_sys::fuzz_target;

/// Every event up to and including the first error.
fn drain(d: &mut Decoder, out: &mut Vec<Result<Event, StreamError>>) {
    while let Some(e) = d.next_event() {
        let stop = e.is_err();
        out.push(e);
        if stop {
            break;
        }
    }
}

/// Every event of `data`, fed in pieces as large as the decoder takes,
/// which it never holds more than its capacity of.
fn whole(mut d: Decoder, mut data: &[u8]) -> Vec<Result<Event, StreamError>> {
    let mut out = Vec::new();
    loop {
        let n = d.feed(data);
        assert!(d.buffered() <= DECODER_CAPACITY);
        data = &data[n..];
        drain(&mut d, &mut out);
        if data.is_empty() || out.last().is_some_and(Result::is_err) {
            return out;
        }
    }
}

/// Every event of `data`, fed a byte at a time.
fn bytewise(mut d: Decoder, data: &[u8]) -> Vec<Result<Event, StreamError>> {
    let mut out = Vec::new();
    for b in data {
        if out.last().is_some_and(Result::is_err) {
            break;
        }
        assert_eq!(d.feed(std::slice::from_ref(b)), 1);
        drain(&mut d, &mut out);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let events = whole(Decoder::new(), data);
    assert_eq!(events, bytewise(Decoder::new(), data));

    for e in events.iter().flatten() {
        match e {
            Event::Banner(_) => {}
            // A version line read can be written, and reads back the same.
            Event::Version(id) => {
                let bytes = id.to_bytes();
                assert_eq!(
                    parse_line(&bytes),
                    Ok(Some((Line::Version(id.clone()), bytes.len())))
                );
            }
            // So can a packet, and the message it carries.
            Event::Packet { packet, .. } => {
                let bytes = packet.to_bytes();
                assert_eq!(
                    Packet::parse(&bytes),
                    Ok(Some((packet.clone(), bytes.len())))
                );
                if let Ok(m) = Message::parse(&packet.payload) {
                    assert_eq!(Message::parse(&m.to_payload()), Ok(m));
                }
            }
        }
    }

    // The same bytes as a stream already past the version line, as a
    // payload, and through the data type reader.
    let packets = whole(Decoder::after_version(), data);
    assert_eq!(packets, bytewise(Decoder::after_version(), data));
    if let Ok(m) = Message::parse(data) {
        assert_eq!(Message::parse(&m.to_payload()), Ok(m));
    }
    let mut r = Reader::new(data);
    let _ = (
        r.mpint(),
        r.name_list(usize::MAX),
        r.text(usize::MAX),
        r.uint64(),
        r.boolean(),
    );
});
