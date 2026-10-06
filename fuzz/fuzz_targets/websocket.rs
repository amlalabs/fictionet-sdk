//! WebSocket frames, messages, close payloads, and handshake fields.
#![no_main]

use fictionet::stdlib::codec::{Decode, Step, Wire, contract, test_support::decode_all};
use fictionet::stdlib::websocket::{
    Close, Frame, Frames, Header, MAX_HEADERS, MAX_MESSAGE, Message, Messages, Opcode, Role, WriteError, check_request,
    check_response, request_headers,
};
use libfuzzer_sys::fuzz_target;

fn bounded<D: Decode>(make: impl Fn() -> D, bytes: &[u8])
where
    D::Item: PartialEq + core::fmt::Debug,
    D::Error: Clone + PartialEq + core::fmt::Debug,
{
    let limit = make().capacity().checked_mul(2).unwrap();
    contract::check_decode_with_alloc_limit(make, bytes, limit);
}

fn check_clone(mut decoder: Messages, data: &[u8]) {
    let middle = data.len() / 2;
    let mut at = 0;
    loop {
        match decoder.decode(&data[at..middle], false) {
            Ok(Step::Item(_, used) | Step::Skip(used)) => at += used,
            Ok(Step::Need | Step::End) => break,
            Err(_) => return,
        }
    }
    let mut cloned = decoder.clone();
    loop {
        let step = decoder.decode(&data[at..], true);
        assert_eq!(cloned.decode(&data[at..], true), step);
        assert_eq!(cloned.held(), decoder.held());
        match step {
            Ok(Step::Item(_, used) | Step::Skip(used)) => at += used,
            _ => break,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Frame>(data);
    contract::check_wire::<Close>(data);
    if let Ok(close) = Close::parse(data) {
        assert_eq!(close.to_bytes().unwrap(), data);
    }
    let limit = data
        .first()
        .map_or(MAX_MESSAGE, |&b| if b & 1 == 0 { MAX_MESSAGE } else { usize::from(b) });
    for role in [Role::Server, Role::Client] {
        let frames = || Frames::with_limit(role, limit);
        let messages = || Messages::with_limit(role, limit);
        bounded(frames, data);
        bounded(messages, data);
        contract::check_decode_with_held_limit(messages, data, limit);
        check_clone(messages(), data);
        let mask = if role == Role::Server { Some([1, 2, 3, 4]) } else { None };
        for message in decode_all(messages, data).0 {
            let frame = message.to_frame(mask).unwrap();
            contract::check_wire_value(&frame);
            assert_eq!(
                decode_all(messages, &frame.to_bytes().unwrap()),
                (vec![message.clone()], None)
            );
            let size = data.first().map_or(1, |&b| usize::from(b).max(1));
            let frames = match role {
                Role::Server => {
                    let mut key = 0u8;
                    message.to_masked_frames(size, || {
                        key = key.wrapping_add(1);
                        [key; 4]
                    })
                }
                Role::Client => message.to_frames(size, None),
            }
            .unwrap();
            let mut bytes = Vec::new();
            for frame in frames {
                frame.write(&mut bytes).unwrap();
            }
            assert_eq!(decode_all(messages, &bytes), (vec![message], None));
        }
        let mut written = Vec::new();
        for frame in decode_all(|| Frames::new(role), data).0 {
            contract::check_wire_value(&frame);
            frame.write(&mut written).unwrap();
        }
        assert!(data.starts_with(&written));
    }
    let payload: Vec<_> = data.iter().take(4096).copied().collect();
    for opcode in [Opcode::Text, Opcode::Binary, Opcode::Continuation, Opcode::Close, Opcode::Ping, Opcode::Pong] {
        contract::check_wire_value(&Frame {
            fin: data.first().is_some_and(|b| b & 1 != 0),
            opcode,
            mask: data.first().is_some_and(|b| b & 2 != 0).then_some([1, 2, 3, 4]),
            payload: payload.clone(),
        });
    }
    let code = u16::from_be_bytes([data.first().copied().unwrap_or(0), data.get(1).copied().unwrap_or(0)]);
    let reason = String::from_utf8_lossy(&payload).into_owned();
    let close = Close {
        code,
        reason: reason.clone(),
    };
    contract::check_wire_value(&close);
    for message in [
        Message::Ping(payload.clone()),
        Message::Pong(payload.clone()),
        Message::Binary(payload),
        Message::Text(reason),
        Message::Close(Some(close)),
        Message::Close(None),
    ] {
        if let Ok(frame) = message.to_frame(Some([7; 4])) {
            contract::check_wire_value(&frame);
            assert_eq!(
                decode_all(|| Messages::new(Role::Server), &frame.to_bytes().unwrap()),
                (vec![message], None)
            );
        }
    }
    if let Ok(Some(header)) = Header::parse(data) {
        assert!(header.header_len <= header.frame_len());
    }

    // The bytes as header fields, one "name: value" per line.
    if let Ok(text) = std::str::from_utf8(data) {
        let headers: Vec<(&str, &str)> = text
            .lines()
            .filter_map(|l| l.split_once(':'))
            .take(MAX_HEADERS + 1)
            .collect();
        match check_request(&headers) {
            Ok(mut u) => {
                let offered: Vec<&str> = u.protocols.iter().map(String::as_str).collect();
                let pick = offered.first().copied();
                assert_eq!(
                    check_response(&u.response_headers(pick).unwrap(), &u.key, &offered),
                    Ok(pick.map(str::to_string))
                );
                // Changed public fields must be checked before making a reply.
                u.accept.clear();
                u.protocols.push(text.to_string());
                assert_eq!(u.response_headers(Some(text)), Err(WriteError::Unwritable));
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
