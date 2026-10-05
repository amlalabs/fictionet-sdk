//! gRPC message framing, request headers, trailers and header values, as
//! a world playing a gRPC server reads them.
#![no_main]

use fictionet::stdlib::grpc::{
    decode_message, encode_message, ContentType, Decoder, FrameError, Message, MethodPath, Rejection, Request, Status,
    Timeout, MAX_MESSAGE,
};
use libfuzzer_sys::fuzz_target;

/// Everything a decoder gives for `data`, fed `chunk` bytes at a time.
fn decode(data: &[u8], chunk: usize) -> Vec<Result<Message, FrameError>> {
    let mut d = Decoder::with_limit(MAX_MESSAGE);
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
                    return out;
                }
                None => break,
            }
        }
        assert!(rest.is_empty());
    }
    out
}

fn strings(h: &[(String, String)]) -> Vec<(&str, &str)> {
    h.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect()
}

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time. Both
    // agree with reading it message by message.
    let whole = decode(data, data.len());
    assert_eq!(decode(data, 1), whole);
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
    for m in whole.iter().flatten() {
        // A message read can be written, and reads back the same.
        let bytes = m.to_bytes();
        assert_eq!(Message::parse(&bytes), Ok(Some((m.clone(), bytes.len()))));
    }

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

    // The bytes as a header block: names and values split at zero bytes.
    let mut parts = data.split(|&b| b == 0);
    let mut headers = Vec::new();
    while let (Some(n), Some(v)) = (parts.next(), parts.next()) {
        headers.push((n, v));
    }
    let synthesized = Status::from_trailers(headers.iter().copied());
    if let Ok(s) = Status::parse_trailers(headers.iter().copied()) {
        // A client uses a status it can read as it is.
        assert_eq!(synthesized, s);
        assert_eq!(Status::parse_trailers(strings(&s.to_trailers())), Ok(s));
    }
    match Request::parse(headers.iter().copied()) {
        Ok(r) => {
            assert!(Request::parse(strings(&r.to_headers())).is_ok());
        }
        Err(Rejection::Status(s)) => {
            let back = Status::parse_trailers(strings(&Rejection::Status(s.clone()).to_headers()));
            assert_eq!(back, Ok(s));
        }
        Err(Rejection::Http(_)) => {}
    }
});
