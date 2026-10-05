//! WireGuard messages, as a world playing a peer reads them, and the replay
//! window it keeps for transport data counters.
#![no_main]

use fictionet::stdlib::wireguard::{
    CookieReply, Data, Initiation, MAX_ENCRYPTED, Message, REJECT_AFTER_MESSAGES, ReplayWindow, Response, TAG_LEN, pad,
    padding,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A message read can be written, and gives back the same bytes.
    if let Ok(m) = Message::parse(data) {
        let bytes = m.to_bytes();
        assert_eq!(bytes, data);
        assert_eq!(Message::parse(&bytes), Ok(m));
    }
    // Each reader on its own, and every prefix.
    let _ = Initiation::parse(data);
    let _ = Response::parse(data);
    let _ = CookieReply::parse(data);
    let _ = Data::parse(data);
    for n in 0..data.len().min(200) {
        let _ = Message::parse(&data[..n]);
    }

    // The bytes as counters, one at a time, into a replay window.
    let mut window = ReplayWindow::new();
    for chunk in data.chunks_exact(8) {
        let c = u64::from_le_bytes(chunk.try_into().unwrap());
        let before = window.clone();
        if window.accept(c) {
            assert!(c < REJECT_AFTER_MESSAGES);
            assert!(!window.accept(c));
        } else {
            assert_eq!(window, before);
        }
    }

    // Padding stays in range, and a padded plaintext fits in a message.
    if data.len() >= 4 {
        let mtu = usize::from(u16::from_le_bytes([data[0], data[1]]));
        let len = usize::from(u16::from_le_bytes([data[2], data[3]]));
        let n = padding(len, mtu);
        assert!(n < 16);
        let padded = pad(&data[4..], mtu);
        assert!(padded.len() + TAG_LEN <= MAX_ENCRYPTED);
    }
});
