//! WireGuard messages, as a world playing a peer reads them, and the replay
//! window it keeps for transport data counters.
#![no_main]

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::contract;
use fictionet::stdlib::wireguard::{
    CookieReply, Data, Error, Initiation, MAX_ENCRYPTED, MAX_PLAINTEXT, Message, Plaintext,
    REJECT_AFTER_MESSAGES, ReplayWindow, Response, TAG_LEN, padding,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_wire::<Message>(data);
    contract::check_wire::<Initiation>(data);
    contract::check_wire::<Response>(data);
    contract::check_wire::<CookieReply>(data);
    contract::check_wire::<Data>(data);
    contract::check_wire::<Plaintext>(data);

    // A message read can be written, and gives back the same bytes.
    if let Ok(m) = Message::parse(data) {
        let bytes = m.to_bytes().unwrap();
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

    // A transport data message built from the bytes, not read from them:
    // written unchanged when its length is one a peer takes, refused
    // otherwise, and never anything the reader rejects.
    if data.len() >= 12 {
        let receiver = u32::from_le_bytes(data[..4].try_into().unwrap());
        let counter = u64::from_le_bytes(data[4..12].try_into().unwrap());
        let d = Data { receiver, counter, encrypted: data[12..].to_vec() };
        contract::check_wire_value(&d);
        let n = d.encrypted.len();
        match d.to_bytes() {
            Ok(b) => {
                assert!((TAG_LEN..=MAX_ENCRYPTED).contains(&n));
                assert_eq!(Data::parse(&b), Ok(d));
            }
            Err(e) => {
                assert!(!(TAG_LEN..=MAX_ENCRYPTED).contains(&n));
                assert_eq!(e, Error::Unwritable);
            }
        }
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

    // Padding stays in range. A padded plaintext keeps every byte, adds
    // only zeros and fits in a message, or is refused for being too long.
    if data.len() >= 4 {
        let mtu = usize::from(u16::from_le_bytes([data[0], data[1]]));
        let len = usize::from(u16::from_le_bytes([data[2], data[3]]));
        let n = padding(len, mtu);
        assert!(n < 16);
        let plaintext = &data[4..];
        let n = padding(plaintext.len(), mtu);
        match Plaintext::padded(plaintext, mtu) {
            Ok(padded) => {
                contract::check_wire_value(&padded);
                let padded = padded.to_bytes().unwrap();
                assert_eq!(padded.len(), plaintext.len() + n);
                assert_eq!(&padded[..plaintext.len()], plaintext);
                assert!(padded[plaintext.len()..].iter().all(|&x| x == 0));
                assert!(padded.len() + TAG_LEN <= MAX_ENCRYPTED);
            }
            Err(_) => assert!(plaintext.len() + n > MAX_PLAINTEXT),
        }
    }
});
