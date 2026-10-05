//! Telnet streams, negotiations and subnegotiations, as a world playing a
//! Telnet server reads them.
#![no_main]
#![allow(deprecated)] // Keep exercising the legacy decoder beside the codec API.

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::telnet::{self, Decode, Decoder, Event, Negotiation, Side, Subnegotiation, option};
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

/// Reads `bytes` a negotiation at a time, answering each and switching
/// binary mode on the peer's BINARY changes before reading on.
fn negotiated(n: &mut Negotiation, d: &mut Decoder, mut bytes: &[u8]) -> Vec<Event> {
    let mut events = Vec::new();
    while !bytes.is_empty() {
        let (got, used) = d.feed_next(bytes);
        assert!(used >= 1 && used <= bytes.len());
        bytes = &bytes[used..];
        for e in &got {
            if let Event::Negotiation { verb, option } = e
                && let Some(c) = n.receive(*verb, *option).change
                && c.side == Side::Remote
                && c.option == option::BINARY
            {
                d.set_binary(c.enabled);
            }
        }
        events.extend(got);
    }
    events
}

/// A server that may ask for binary mode, reading the stream in two parts.
fn read_split(stream: &[u8], cut: usize, ask: bool, allow: bool) -> Vec<Event> {
    let mut n = Negotiation::new();
    n.allow_remote(option::BINARY, allow);
    if ask {
        n.enable_remote(option::BINARY);
    }
    let mut d = Decoder::new();
    let mut events = negotiated(&mut n, &mut d, &stream[..cut]);
    events.extend(negotiated(&mut n, &mut d, &stream[cut..]));
    events.extend(d.finish());
    merged(events)
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Decode::new, data);
    contract::check_decode_with_held_limit(|| Decode::with_data_limit(1), data, 0);
    contract::check_wire::<Event>(data);
    contract::check_wire::<Subnegotiation>(data);
    for binary in [false, true] {
        contract::check_decode(|| {
            let mut decoder = Decode::new();
            decoder.set_binary(binary);
            decoder
        }, data);
        let event = Event::Data(data.iter().take(telnet::MAX_DATA + 1).copied().collect());
        contract::check_wire_value(&event);
        let mut out = vec![1, 2, 3];
        match event.write_with(&mut out, binary) {
            Ok(()) => assert_eq!(Event::parse_with(&out[3..], binary), Ok(event)),
            Err(_) => assert_eq!(out, [1, 2, 3]),
        }
    }
    let payload: Vec<_> = data.iter().take(telnet::MAX_SUBNEGOTIATION + 1).copied().collect();
    let option = data.first().copied().unwrap_or(42);
    contract::check_wire_value(&Event::Subnegotiation { option, data: payload.clone() });
    contract::check_wire_value(&Subnegotiation::Other { option, data: payload });
    if let Ok(value) = <Subnegotiation as Wire>::parse(data) {
        contract::check_wire_value(&value);
    }

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

    // Read a negotiation at a time with no mode changes: the same events.
    let mut stepwise = Decoder::new();
    stepwise.set_binary(binary);
    let mut steps = Vec::new();
    let mut rest = stream;
    while !rest.is_empty() {
        let (got, used) = stepwise.feed_next(rest);
        rest = &rest[used..];
        steps.extend(got);
    }
    steps.extend(stepwise.finish());
    assert_eq!(events, merged(steps));

    // With binary mode switched by the peer's WILL and WONT BINARY, where
    // the stream is split does not change what is read.
    let ask = mode & 2 == 2;
    let allow = mode & 4 == 4;
    let whole_read = read_split(stream, 0, ask, allow);
    let cut = usize::from(mode >> 3).min(stream.len());
    assert_eq!(read_split(stream, cut, ask, allow), whole_read);
    assert_eq!(read_split(stream, stream.len() - cut, ask, allow), whole_read);

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
        // Whatever parses writes back exactly.
        if let Ok(sub) = Subnegotiation::parse(option, stream) {
            assert_eq!(sub.data(), stream);
        }
        let other = Subnegotiation::Other { option, data: stream.to_vec() };
        assert!(Subnegotiation::parse(option, &other.data()).is_ok());
    }
    let name = Subnegotiation::TerminalTypeIs(String::from_utf8_lossy(stream).into_owned());
    let written = Subnegotiation::parse(name.option(), &name.data());
    assert!(written.is_ok());
    // A valid name, spaces included, is written unchanged.
    if (1..=40).contains(&stream.len()) && stream.iter().all(|b| (0x20..=0x7e).contains(b)) {
        assert_eq!(written, Ok(name));
    }
});
