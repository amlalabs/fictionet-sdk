//! memcached text commands and replies, binary packets and UDP frames, as
//! a world playing a cache server reads them.
#![no_main]

use fictionet::stdlib::memcache::{
    BinaryDecoder, Command, CommandDecoder, CounterExtras, Error, Packet, Response, ResponseDecoder, StoreExtras,
    UdpFrame,
};
use libfuzzer_sys::fuzz_target;

/// Everything `next` gives, up to and including the first fatal error.
fn drain<T>(mut next: impl FnMut() -> Option<Result<T, Error>>) -> Vec<Result<T, Error>> {
    let mut out = Vec::new();
    while let Some(r) = next() {
        let fatal = matches!(r, Err(e) if e.is_fatal());
        out.push(r);
        if fatal {
            break;
        }
    }
    out
}

fn commands(data: &[u8], bytewise: bool) -> Vec<Result<Command, Error>> {
    let mut d = CommandDecoder::new();
    if !bytewise {
        d.feed(data);
        return drain(|| d.next_command());
    }
    let mut out = Vec::new();
    for b in data {
        d.feed(std::slice::from_ref(b));
        out.extend(drain(|| d.next_command()));
        if matches!(out.last(), Some(Err(e)) if e.is_fatal()) {
            break;
        }
    }
    out
}

fn responses(data: &[u8], bytewise: bool) -> Vec<Result<Response, Error>> {
    let mut d = ResponseDecoder::new();
    if !bytewise {
        d.feed(data);
        return drain(|| d.next_response());
    }
    let mut out = Vec::new();
    for b in data {
        d.feed(std::slice::from_ref(b));
        out.extend(drain(|| d.next_response()));
        if matches!(out.last(), Some(Err(e)) if e.is_fatal()) {
            break;
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let whole = commands(data, false);
    assert_eq!(whole, commands(data, true));
    for c in whole.iter().flatten() {
        // A command read can be written, and reads back the same.
        let bytes = c.to_bytes().unwrap();
        assert_eq!(commands(&bytes, false), [Ok(c.clone())]);
    }
    let whole = responses(data, false);
    assert_eq!(whole, responses(data, true));
    for r in whole.iter().flatten() {
        let bytes = r.to_bytes().unwrap();
        assert_eq!(responses(&bytes, false), [Ok(r.clone())]);
    }

    // The binary protocol, the same two ways.
    let mut whole = BinaryDecoder::new();
    whole.feed(data);
    let mut packets = Vec::new();
    while let Some(Ok(p)) = whole.next_packet() {
        packets.push(p);
    }
    let mut bytewise = BinaryDecoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(Ok(p)) = bytewise.next_packet() {
            again.push(p);
        }
    }
    assert_eq!(packets, again);
    for p in &packets {
        let bytes = p.to_bytes().unwrap();
        assert_eq!(Packet::parse(&bytes), Ok(Some((p.clone(), bytes.len()))));
        if let Some(e) = StoreExtras::parse(&p.extras) {
            assert_eq!(e.to_bytes()[..], p.extras[..]);
        }
        if let Some(e) = CounterExtras::parse(&p.extras) {
            assert_eq!(e.to_bytes()[..], p.extras[..]);
        }
    }

    // Any bytes as one UDP datagram.
    if let Ok(f) = UdpFrame::parse(data) {
        assert_eq!(f.to_bytes().unwrap(), data);
    }
});
