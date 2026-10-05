//! The SSH transport layer before encryption: version lines, packets and
//! messages, as a world playing an SSH server reads them.
#![no_main]

use fictionet::stdlib::ssh::{
    Decoder, Event, Line, Message, Packet, Reader, StreamError, parse_line,
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

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    whole.feed(data);
    let mut events = Vec::new();
    drain(&mut whole, &mut events);
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        if again
            .last()
            .is_some_and(|e: &Result<Event, StreamError>| e.is_err())
        {
            break;
        }
        bytewise.feed(std::slice::from_ref(b));
        drain(&mut bytewise, &mut again);
    }
    assert_eq!(events, again);

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
    let mut packets = Decoder::after_version();
    packets.feed(data);
    let mut rest = Vec::new();
    drain(&mut packets, &mut rest);
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
