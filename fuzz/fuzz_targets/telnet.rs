//! Telnet streams, negotiations and subnegotiations, as a world playing a
//! Telnet server reads them.
#![no_main]

use fictionet::stdlib::telnet::{Decoder, Event, Negotiation, Subnegotiation};
use libfuzzer_sys::fuzz_target;

/// Adjacent data events joined, so streams split in different places
/// compare equal.
fn merged(events: Vec<Event>) -> Vec<Event> {
    let mut out: Vec<Event> = Vec::new();
    for e in events {
        if let (Event::Data(d), Some(Event::Data(last))) = (&e, out.last_mut()) {
            last.extend_from_slice(d);
            continue;
        }
        out.push(e);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    // The first byte picks binary mode; the rest is the stream.
    let Some((&mode, stream)) = data.split_first() else { return };
    let binary = mode & 1 == 1;

    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    whole.set_binary(binary);
    let mut events = whole.feed(stream);
    events.extend(whole.finish());
    let events = merged(events);
    let mut bytewise = Decoder::new();
    bytewise.set_binary(binary);
    let mut again = Vec::new();
    for b in stream {
        again.extend(bytewise.feed(std::slice::from_ref(b)));
    }
    again.extend(bytewise.finish());
    assert_eq!(events, merged(again));

    // Events written back read back the same, less the errors.
    let written: Vec<u8> = events.iter().flat_map(|e| e.to_bytes(binary)).collect();
    let mut d = Decoder::new();
    d.set_binary(binary);
    let mut back = d.feed(&written);
    back.extend(d.finish());
    let expected: Vec<Event> = events.iter().filter(|e| !matches!(e, Event::Error(_))).cloned().collect();
    assert_eq!(merged(back), merged(expected));

    // Every negotiation is answered with a negotiation, and every typed
    // subnegotiation writes back what it read.
    let mut options = Negotiation::new();
    for o in 0..=255u8 {
        options.allow_local(o, o % 2 == 0);
        options.allow_remote(o, o % 3 == 0);
    }
    for e in &events {
        match e {
            Event::Negotiation { verb, option } => {
                if let Some(reply) = options.receive(*verb, *option).send {
                    let mut d = Decoder::new();
                    assert!(matches!(&d.feed(&reply)[..], [Event::Negotiation { .. }]));
                }
            }
            Event::Subnegotiation { option, data } => {
                if let Ok(sub) = Subnegotiation::parse(*option, data) {
                    assert_eq!(&sub.data(), data);
                }
            }
            _ => {}
        }
    }
    // Any bytes as subnegotiation data. Whatever a world builds, the
    // writer's bytes parse.
    for option in 0..=255u8 {
        let _ = Subnegotiation::parse(option, stream);
        let other = Subnegotiation::Other { option, data: stream.to_vec() };
        assert!(Subnegotiation::parse(option, &other.data()).is_ok());
    }
    let name = Subnegotiation::TerminalTypeIs(String::from_utf8_lossy(stream).into_owned());
    assert!(Subnegotiation::parse(name.option(), &name.data()).is_ok());
});
