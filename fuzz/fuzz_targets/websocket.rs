//! WebSocket frames, messages, close payloads and handshake fields, as a
//! world playing a WebSocket server or client reads them.
#![no_main]

use fictionet::stdlib::websocket::{
    Close, Decoder, Error, Frame, Header, Message, Role, check_request, check_response, request_headers,
};
use libfuzzer_sys::fuzz_target;

/// The messages a decoder with `max_message` gives for `data`, fed in
/// pieces whose sizes cycle through `sizes`, and the error it stopped on,
/// if any. With `lazy`, it feeds a second piece before taking messages out
/// whenever it can.
fn messages(role: Role, max_message: usize, mut data: &[u8], sizes: &[usize], lazy: bool) -> (Vec<Message>, Option<Error>) {
    let mut d = Decoder::with_max_message(role, max_message);
    let mut out = Vec::new();
    let mut sizes = sizes.iter().cycle();
    let mut turn = 0usize;
    while !data.is_empty() {
        let n = sizes.next().copied().unwrap_or(1).clamp(1, data.len());
        let took = d.feed(&data[..n]);
        assert!(took <= n);
        // The decoder never holds more than one frame's worth.
        assert!(d.buffered() <= d.capacity());
        data = &data[took..];
        turn += 1;
        if lazy && took == n && turn % 2 == 1 {
            continue;
        }
        let mut any = false;
        while let Some(m) = d.next_message() {
            any = true;
            match m {
                Ok(m) => out.push(m),
                Err(e) => {
                    assert_eq!(d.error(), Some(e));
                    assert_eq!(d.buffered(), 0);
                    return (out, Some(e));
                }
            }
        }
        // A decoder too full to take bytes always reads something.
        assert!(took > 0 || any || d.buffered() < d.capacity());
    }
    while let Some(m) = d.next_message() {
        match m {
            Ok(m) => out.push(m),
            Err(e) => return (out, Some(e)),
        }
    }
    (out, None)
}

fuzz_target!(|data: &[u8]| {
    // Uneven piece sizes and a message limit, taken from the input itself.
    let sizes: Vec<usize> = data.iter().take(4).map(|&b| usize::from(b % 17) + 1).collect();
    let limit = data.first().map_or(usize::MAX, |&b| if b & 1 == 0 { usize::MAX } else { usize::from(b) });
    for role in [Role::Server, Role::Client] {
        // The stream, split several ways: all at once, a byte at a time,
        // in uneven pieces, and with feeds that do not wait for messages
        // to be taken out. Each gives the same messages and error.
        let whole = messages(role, limit, data, &[data.len()], false);
        assert_eq!(whole, messages(role, limit, data, &[1], false));
        assert_eq!(whole, messages(role, limit, data, &sizes, false));
        assert_eq!(whole, messages(role, limit, data, &sizes, true));
        // A message read can be written, in one frame or split with a
        // key per frame, and reads back the same.
        let mask = if role == Role::Server { Some([1, 2, 3, 4]) } else { None };
        for m in &whole.0 {
            assert_eq!(messages(role, limit, &m.to_bytes(mask), &[usize::MAX], false), (vec![m.clone()], None));
            let size = sizes.first().copied().unwrap_or(1);
            let frames = match role {
                Role::Server => {
                    let mut k = 0u8;
                    m.to_masked_frames(size, || {
                        k = k.wrapping_add(1);
                        [k; 4]
                    })
                }
                Role::Client => m.to_frames(size, None),
            };
            let bytes: Vec<u8> = frames.iter().flat_map(Frame::to_bytes).collect();
            assert_eq!(messages(role, limit, &bytes, &sizes, false), (vec![m.clone()], None));
        }
        // A clone made partway carries on as the original does.
        let (head, tail) = data.split_at(data.len() / 2);
        let mut d = Decoder::new(role);
        let _ = d.feed(head);
        while let Some(Ok(_)) = d.next_message() {}
        let mut copy = d.clone();
        assert_eq!(d.feed(tail), copy.feed(tail));
        loop {
            let (a, b) = (d.next_message(), copy.next_message());
            assert_eq!(a, b);
            if !matches!(a, Some(Ok(_))) {
                break;
            }
        }
    }

    // Messages built straight from the input, not from a reader: whatever
    // the writer clamps, the reader takes what it writes.
    let (first, rest) = data.split_at(data.len().min(2));
    let code = u16::from_be_bytes([first.first().copied().unwrap_or(0), first.get(1).copied().unwrap_or(0)]);
    let reason = String::from_utf8_lossy(rest).repeat(4);
    for m in [
        Message::Ping(data.repeat(3)),
        Message::Pong(data.to_vec()),
        Message::Binary(data.to_vec()),
        Message::Text(reason.clone()),
        Message::Close(Some(Close { code, reason })),
    ] {
        let (got, err) = messages(Role::Server, usize::MAX, &m.to_bytes(Some([7, 7, 7, 7])), &[usize::MAX], false);
        assert_eq!((got.len(), err), (1, None));
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
            Ok(mut u) => {
                let offered: Vec<&str> = u.protocols.iter().map(String::as_str).collect();
                let pick = offered.first().copied();
                assert_eq!(check_response(&u.response_headers(pick), &u.key, &offered), Ok(pick.map(str::to_string)));
                // Changing the public fields cannot make the reply invalid.
                u.accept.clear();
                u.protocols.push(text.to_string());
                let offered: Vec<&str> = u.protocols.iter().map(String::as_str).collect();
                assert!(check_response(&u.response_headers(Some(text)), &u.key, &offered).is_ok());
            }
            Err(e) => assert!(matches!(e.status_code(), 400 | 426 | 431)),
        }
        let _ = check_response(&headers, "dGhlIHNhbXBsZSBub25jZQ==", &["chat"]);
        // A request the writer makes is one the reader accepts.
        let protocols: Vec<&str> = text.split(',').collect();
        let mut nonce = [0u8; 16];
        for (n, b) in nonce.iter_mut().zip(data) {
            *n = *b;
        }
        for host in [text, text.lines().next().unwrap_or("")] {
            if let Ok(h) = request_headers(host, nonce, &protocols) {
                let u = check_request(&h).expect("the reader accepts what the writer makes");
                assert_eq!(h[0].1, host);
                assert!(u.protocols.iter().all(|p| protocols.contains(&p.as_str())));
            }
        }
    }
});
