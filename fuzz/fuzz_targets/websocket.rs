//! WebSocket frames, messages, close payloads and handshake fields, as a
//! world playing a WebSocket server or client reads them.
#![no_main]

use fictionet::stdlib::websocket::{
    Close, Decoder, Error, Frame, Header, Message, Role, check_request, check_response,
};
use libfuzzer_sys::fuzz_target;

/// The messages a decoder gives for `data`, fed in pieces whose sizes cycle
/// through `sizes`, and the error it stopped on, if any.
fn messages(role: Role, mut data: &[u8], sizes: &[usize]) -> (Vec<Message>, Option<Error>) {
    let mut d = Decoder::new(role);
    let mut out = Vec::new();
    let mut sizes = sizes.iter().cycle();
    while !data.is_empty() {
        let n = sizes.next().copied().unwrap_or(1).clamp(1, data.len());
        let (piece, rest) = data.split_at(n);
        data = rest;
        d.feed(piece);
        while let Some(m) = d.next_message() {
            match m {
                Ok(m) => out.push(m),
                Err(e) => {
                    assert_eq!(d.error(), Some(e));
                    assert_eq!(d.buffered(), 0);
                    return (out, Some(e));
                }
            }
        }
    }
    (out, None)
}

fuzz_target!(|data: &[u8]| {
    // Uneven piece sizes, taken from the input itself.
    let sizes: Vec<usize> = data.iter().take(4).map(|&b| usize::from(b % 17) + 1).collect();
    for role in [Role::Server, Role::Client] {
        // The stream, split three ways: all at once, a byte at a time, and
        // in uneven pieces. Each gives the same messages and error.
        let whole = messages(role, data, &[data.len()]);
        assert_eq!(whole, messages(role, data, &[1]));
        assert_eq!(whole, messages(role, data, &sizes));
        // A message read can be written, and reads back the same.
        let mask = if role == Role::Server { Some([1, 2, 3, 4]) } else { None };
        for m in &whole.0 {
            assert_eq!(messages(role, &m.to_bytes(mask), &[usize::MAX]), (vec![m.clone()], None));
        }
        // A clone made partway carries on as the original does.
        let (head, tail) = data.split_at(data.len() / 2);
        let mut d = Decoder::new(role);
        d.feed(head);
        while let Some(Ok(_)) = d.next_message() {}
        let mut copy = d.clone();
        d.feed(tail);
        copy.feed(tail);
        loop {
            let (a, b) = (d.next_message(), copy.next_message());
            assert_eq!(a, b);
            if !matches!(a, Some(Ok(_))) {
                break;
            }
        }
    }

    // Frames on their own are written back byte for byte.
    let mut rest = data;
    while let Ok(Some((f, used))) = Frame::parse(rest) {
        let bytes = f.to_bytes();
        assert_eq!(bytes, rest[..used]);
        assert_eq!(Frame::parse(&bytes), Ok(Some((f, used))));
        rest = &rest[used..];
    }
    if let Ok(Some(h)) = Header::parse(data) {
        assert!(h.header_len <= h.frame_len());
    }
    if let Ok(Some(c)) = Close::parse(data) {
        assert_eq!(c.to_payload(), data);
    }

    // The bytes as header fields, one "name: value" per line.
    if let Ok(text) = std::str::from_utf8(data) {
        let headers: Vec<(&str, &str)> = text.lines().filter_map(|l| l.split_once(':')).collect();
        match check_request(&headers) {
            Ok(u) => {
                let offered: Vec<&str> = u.protocols.iter().map(String::as_str).collect();
                let pick = offered.first().copied();
                assert_eq!(check_response(&u.response_headers(pick), &u.key, &offered), Ok(pick.map(str::to_string)));
            }
            Err(e) => assert!(matches!(e.status_code(), 400 | 426)),
        }
        let _ = check_response(&headers, "dGhlIHNhbXBsZSBub25jZQ==", &["chat"]);
    }
});
