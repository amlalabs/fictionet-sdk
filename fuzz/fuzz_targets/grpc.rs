//! gRPC message framing, request headers, trailers and header values, as
//! a world playing a gRPC server reads them, and the writers that answer.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract};
use fictionet::stdlib::grpc::{
    Code, ContentType, MAX_MESSAGE, Message, Messages, MethodPath, Rejection, Request, Status, Timeout,
    decode_message, encode_message,
};
use libfuzzer_sys::fuzz_target;

fn strings(h: &[(String, String)]) -> Vec<(&str, &str)> {
    h.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect()
}

/// The request headers with the fields that make a call: POST, a path
/// and a gRPC content-type, then whatever the input holds, so the checks
/// past the first three run.
fn with_call<'a>(headers: &[(&'a [u8], &'a [u8])]) -> Vec<(&'a [u8], &'a [u8])> {
    let mut h: Vec<(&[u8], &[u8])> =
        vec![(&b":method"[..], &b"POST"[..]), (b":path", b"/s.S/M"), (b"content-type", b"application/grpc")];
    h.extend(
        headers.iter().copied().filter(|(n, _)| ![&b":method"[..], b":path", b"content-type"].contains(n)),
    );
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
            let back = Status::parse_trailers(strings(&Rejection::Status(s.clone()).to_headers().unwrap()));
            assert_eq!(back, Ok(s));
        }
        Err(r @ Rejection::Http(_)) => {
            let h = r.to_headers().unwrap();
            assert_eq!(h.len(), 1);
            let code: u16 = h[0].1.parse().unwrap();
            assert!((400..=599).contains(&code));
        }
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(|| Messages::with_limit(MAX_MESSAGE), data);
    contract::check_wire::<Message>(data);

    if let Some(&limit) = data.first() {
        contract::check_decode(|| Messages::with_limit(usize::from(limit)), data);
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
    assert_eq!(<Message as Wire>::parse(&bytes), Ok(built));

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
    assert_eq!(decode_message(encode_message(&text).unwrap().as_bytes()), text);
    // A status built from the input reads back from its trailers.
    if let Ok(t) = std::str::from_utf8(data) {
        let s = Status::new(Code::Internal, t);
        assert_eq!(Status::parse_trailers(strings(&s.to_trailers().unwrap())), Ok(s.clone()));
        assert_eq!(Status::parse_trailers(strings(&s.trailers_only(&ContentType::plain()).unwrap())), Ok(s));
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
        assert_eq!(Status::parse_trailers(strings(&s.to_trailers().unwrap())), Ok(s));
    }
    check_request(&headers);
    check_request(&with_call(&headers));
});
