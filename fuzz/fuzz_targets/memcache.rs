//! memcached text commands and replies, binary packets and UDP frames, as
//! a world playing a cache server reads them.
#![no_main]

use fictionet::stdlib::codec::contract;
use fictionet::stdlib::memcache::{Commands, Responses, Frames};

use fictionet::stdlib::memcache::{
    BinaryDecoder, BinaryError, Command, CommandDecoder, CounterExtras, Error, MAX_BINARY_BUFFERED, MAX_BUFFERED,
    MetaFlag, MetaStatus, Packet, Response, ResponseDecoder, Status, StoreExtras, UDP_MAX_DATAGRAM, UdpFrame,
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

/// Feeds `data` in pieces of at most `step` bytes, taking messages out
/// after each, and checks the decoder never holds more than its bound.
fn commands(data: &[u8], step: usize) -> Vec<Result<Command, Error>> {
    let mut d = CommandDecoder::new();
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let n = d.feed(&rest[..rest.len().min(step)]);
        assert!(d.buffered() <= MAX_BUFFERED);
        rest = &rest[n..];
        out.extend(drain(|| d.next_command()));
        if matches!(out.last(), Some(Err(e)) if e.is_fatal()) {
            break;
        }
    }
    out
}

fn responses(data: &[u8], step: usize) -> Vec<Result<Response, Error>> {
    let mut d = ResponseDecoder::new();
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let n = d.feed(&rest[..rest.len().min(step)]);
        assert!(d.buffered() <= MAX_BUFFERED);
        rest = &rest[n..];
        out.extend(drain(|| d.next_response()));
        if matches!(out.last(), Some(Err(e)) if e.is_fatal()) {
            break;
        }
    }
    out
}

/// Every packet up to and including the first error.
fn packets(data: &[u8], step: usize) -> Vec<Result<Packet, BinaryError>> {
    let mut d = BinaryDecoder::new();
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let n = d.feed(&rest[..rest.len().min(step)]);
        assert!(d.buffered() <= MAX_BINARY_BUFFERED);
        rest = &rest[n..];
        while let Some(p) = d.next_packet() {
            let failed = p.is_err();
            out.push(p);
            if failed {
                return out;
            }
        }
    }
    out
}

/// A value a caller built, not one a reader made: if a writer takes it,
/// a reader must read back the same.
fn check_command(c: Command) {
    contract::check_wire_value(&c);
    if let Ok(bytes) = c.to_bytes() {
        assert_eq!(commands(&bytes, usize::MAX), [Ok(c)]);
    }
}

fn check_response(r: Response) {
    contract::check_wire_value(&r);
    if let Ok(bytes) = r.to_bytes() {
        assert_eq!(responses(&bytes, usize::MAX), [Ok(r)]);
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Commands::new, data);
    contract::check_decode(Responses::new, data);
    contract::check_decode(Frames::new, data);
    contract::check_decode(|| Commands::with_limit(17), data);
    contract::check_decode(|| Responses::with_limit(17), data);
    contract::check_decode(|| Frames::with_limit(17), data);
    contract::check_wire::<Command>(data);
    contract::check_wire::<Response>(data);
    contract::check_wire::<Packet>(data);

    // The stream, split two ways: all at once, and a byte at a time.
    let whole = commands(data, usize::MAX);
    assert_eq!(whole, commands(data, 1));
    for c in whole.iter().flatten() {
        // A command read can be written, and reads back the same.
        let bytes = c.to_bytes().unwrap();
        assert_eq!(commands(&bytes, usize::MAX), [Ok(c.clone())]);
    }
    let whole = responses(data, usize::MAX);
    assert_eq!(whole, responses(data, 1));
    for r in whole.iter().flatten() {
        let bytes = r.to_bytes().unwrap();
        assert_eq!(responses(&bytes, usize::MAX), [Ok(r.clone())]);
    }

    // Writers given values built from the input, not read from it.
    let words: Vec<Vec<u8>> = data.split(|&b| b == b' ').map(<[u8]>::to_vec).collect();
    let flags: Vec<MetaFlag> = words.iter().skip(1).filter_map(|w| Some(MetaFlag::new(*w.first()?, &w[1..]))).collect();
    let first = words.first().cloned().unwrap_or_default();
    check_command(Command::Get { keys: words.clone(), cas: data.len() % 2 == 0 });
    check_command(Command::Stats { args: words.clone() });
    check_command(Command::MetaGet { key: first.clone(), flags: flags.clone() });
    check_command(Command::MetaArithmetic { key: first.clone(), flags: flags.clone() });
    check_command(Command::MetaSet { key: first.clone(), flags: flags.clone(), data: data.to_vec() });
    check_response(Response::ServerError(data.to_vec()));
    check_response(Response::Stat { name: first.clone(), value: data.to_vec() });
    check_response(Response::Meta { status: MetaStatus::Header, flags });

    // The binary protocol, the same two ways, errors included.
    let whole = packets(data, usize::MAX);
    assert_eq!(whole, packets(data, 1));
    for p in whole.iter().flatten() {
        contract::check_wire_value(p);
        let bytes = p.to_bytes().unwrap();
        assert_eq!(Packet::parse(&bytes), Ok(Some((p.clone(), bytes.len()))));
        assert_eq!(Status::from_code(p.status).code(), p.status);
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
    // Any bytes as a reply, split into datagrams and put back together.
    let frames = UdpFrame::split(7, data).unwrap();
    let mut back = Vec::new();
    for (i, f) in frames.iter().enumerate() {
        let bytes = f.to_bytes().unwrap();
        assert!(bytes.len() <= UDP_MAX_DATAGRAM);
        let again = UdpFrame::parse(&bytes).unwrap();
        assert_eq!((again.request_id, usize::from(again.sequence), usize::from(again.total)), (7, i, frames.len()));
        back.extend(again.payload);
    }
    assert_eq!(back, data);
});
