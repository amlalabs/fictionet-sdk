//! gRPC message framing, request headers, trailers and header values, as
//! a world playing a gRPC server reads them, and the writers that answer.
#![no_main]

use fictionet::stdlib::codec::contract;
use fictionet::stdlib::grpc::{
    decode_message, encode_message, Code, ContentType, Decoder, FrameError, Message, Messages, MethodPath, Rejection, Request, Status,
    Timeout, MAX_MESSAGE,
};
use libfuzzer_sys::fuzz_target;

/// Everything a decoder with this limit gives for `data`, fed `chunk`
/// bytes at a time, then what `finish` says at the end.
fn decode(data: &[u8], chunk: usize, limit: usize) -> (Vec<Result<Message, FrameError>>, Result<(), FrameError>) {
    let mut d = Decoder::with_limit(limit);
    let mut out = Vec::new();
    for piece in data.chunks(chunk.max(1)) {
        let mut rest = piece;
        loop {
            let used = d.feed(rest);
            rest = &rest[used..];
            match d.next_message() {
                Some(Ok(m)) => out.push(Ok(m)),
                Some(Err(e)) => {
                    out.push(Err(e));
                    return (out, d.finish());
                }
                None => break,
            }
        }
        assert!(rest.is_empty());
    }
    (out, d.finish())
}

fn strings(h: &[(String, String)]) -> Vec<(&str, &str)> {
    h.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect()
}

/// The request headers with the fields that make a call: POST, a path
/// and a gRPC content-type, then whatever the input holds, so the checks
/// past the first three run.
fn with_call<'a>(headers: &[(&'a [u8], &'a [u8])]) -> Vec<(&'a [u8], &'a [u8])> {
    let mut h: Vec<(&[u8], &[u8])> =
        vec![(&b":method"[..], &b"POST"[..]), (b":path", b"/s.S/M"), (b"content-type", b"application/grpc")];
    h.extend(headers.iter().copied().filter(|(n, _)| ![&b":method"[..], b":path", b"content-type"].contains(n)));
    h
}

fn check_request(headers: &[(&[u8], &[u8])]) {
    match Request::parse(headers.iter().copied()) {
        Ok(r) => {
            // What the writer accepts reads back as the same request; what
            // it refuses, it refuses with an error rather than by leaving
            // fields out.
            if let Ok(h) = r.to_headers() {
                assert_eq!(Request::parse(strings(&h)), Ok(Request { te_trailers: true, ..r }));
            }
        }
        Err(Rejection::Status(s)) => {
            let back = Status::parse_trailers(strings(&Rejection::Status(s.clone()).to_headers()));
            assert_eq!(back, Ok(s));
        }
        Err(r @ Rejection::Http(_)) => {
            let h = r.to_headers();
            assert_eq!(h.len(), 1);
            let code: u16 = h[0].1.parse().unwrap();
            assert!((400..=599).contains(&code));
        }
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(|| Messages::with_limit(MAX_MESSAGE), data);
    contract::check_wire::<Message>(data);

    // The stream, split two ways: all at once, and a byte at a time. Both
    // agree with reading it message by message, and with each other at
    // the end of the stream.
    let (whole, end) = decode(data, data.len(), MAX_MESSAGE);
    assert_eq!(decode(data, 1, MAX_MESSAGE), (whole.clone(), end));
    let mut at = 0;
    let mut parsed = Vec::new();
    loop {
        match Message::parse(&data[at..]) {
            Ok(Some((m, used))) => {
                parsed.push(Ok(m));
                at += used;
            }
            Ok(None) => break,
            Err(e) => {
                parsed.push(Err(e));
                break;
            }
        }
    }
    assert_eq!(parsed, whole);
    // The stream ends cleanly exactly when every byte made a message.
    if !matches!(whole.last(), Some(Err(_))) {
        assert_eq!(end.is_ok(), at == data.len());
    }
    for m in whole.iter().flatten() {
        // A message read can be written, and reads back the same.
        let bytes = m.to_bytes().unwrap();
        assert_eq!(Message::parse(&bytes), Ok(Some((m.clone(), bytes.len()))));
    }

    // A smaller limit, from the first byte: messages within it come out
    // as before, and the first one over it is refused.
    if let Some(&l) = data.first() {
        let limit = usize::from(l);
        contract::check_decode(|| Messages::with_limit(limit), data);
        let (small, _) = decode(data, 3, limit);
        for (a, b) in small.iter().zip(whole.iter()) {
            match a {
                Ok(m) => assert_eq!(Ok(m), b.as_ref()),
                Err(FrameError::TooLarge { length, limit: got }) => {
                    assert_eq!(*got, limit);
                    assert!(*length as usize > limit);
                }
                Err(e) => assert_eq!(Err(e), b.as_ref()),
            }
        }
    }

    // A message built from the input, not read from it, writes and reads
    // back the same.
    let built = Message {
        compressed: data.first().is_some_and(|b| b & 1 == 1),
        data: data.get(..MAX_MESSAGE).unwrap_or(data).to_vec(),
    };
    contract::check_wire_value(&built);
    let bytes = built.to_bytes().unwrap();
    contract::check_wire::<Message>(&bytes);
    contract::check_decode(|| Messages::with_limit(MAX_MESSAGE), &bytes);
    assert_eq!(Message::parse(&bytes), Ok(Some((built, bytes.len()))));

    // Header values on their own.
    if let Ok(t) = Timeout::parse(data) {
        assert_eq!(Timeout::parse(t.to_header().as_bytes()), Ok(t));
    }
    if let Some(ct) = ContentType::parse(data) {
        assert_eq!(ContentType::parse(ct.to_header().as_bytes()), Some(ct));
    }
    if let Some(p) = MethodPath::parse(data) {
        assert_eq!(MethodPath::parse(p.to_path().as_bytes()), Some(p));
    }
    let text = decode_message(data);
    assert_eq!(decode_message(encode_message(&text).as_bytes()), text);
    // A status built from the input reads back from its trailers.
    if let Ok(t) = std::str::from_utf8(data) {
        let s = Status::new(Code::Internal, t);
        assert_eq!(Status::parse_trailers(strings(&s.to_trailers())), Ok(s.clone()));
        assert_eq!(Status::parse_trailers(strings(&s.trailers_only(&ContentType::plain()))), Ok(s));
    }

    // The bytes as a header block: names and values split at zero bytes.
    let mut parts = data.split(|&b| b == 0);
    let mut headers: Vec<(&[u8], &[u8])> = Vec::new();
    while let (Some(n), Some(v)) = (parts.next(), parts.next()) {
        headers.push((n, v));
    }
    let synthesized = Status::from_trailers(headers.iter().copied());
    if let Ok(s) = Status::parse_trailers(headers.iter().copied()) {
        // A client uses a status it can read as it is.
        assert_eq!(synthesized, s);
        assert_eq!(Status::parse_trailers(strings(&s.to_trailers())), Ok(s));
    }
    check_request(&headers);
    check_request(&with_call(&headers));
});
