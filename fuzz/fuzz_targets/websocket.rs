//! WebSocket frames, messages, close payloads, and handshake fields.
#![no_main]

use fictionet::stdlib::websocket::{
    Error, MAX_HEADERS, MAX_MESSAGE, check_request, check_response, harness, request_headers,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limit = data.first().map_or(MAX_MESSAGE, |&b| {
        if b & 1 == 0 {
            MAX_MESSAGE
        } else {
            usize::from(b)
        }
    });
    let fragment = data.first().map_or(1, |&b| usize::from(b).max(1));
    harness::check_buffer(data, limit, fragment);

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
                assert_eq!(u.response_headers(Some(text)), Err(Error::Unwritable));
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
