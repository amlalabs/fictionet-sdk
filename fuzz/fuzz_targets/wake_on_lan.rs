//! Wake-on-LAN payloads, as a world playing a sleeping host or a tool reads
//! them, and magic packets a world builds, as it writes them.
#![no_main]

use arbitrary::{Result, Unstructured};
use fictionet::stdlib::wake_on_lan::{
    MAX_PACKET_LEN, MAX_PAYLOAD, Mac, MagicPacket, PACKET_LEN, ParseError, Password, Scanner,
    wakes,
};
use libfuzzer_sys::fuzz_target;

/// Feeds `data` to a scanner whole, or a byte at a time.
fn scan(data: &[u8], bytewise: bool) -> std::result::Result<(usize, MagicPacket), ParseError> {
    let mut s = Scanner::new();
    if bytewise {
        for b in data {
            s.feed(&[*b]);
            assert!(s.seen() <= MAX_PAYLOAD + 1);
        }
    } else {
        s.feed(data);
    }
    s.finish()
}

/// Whether `payload` wakes the card, checked the slow way: some offset
/// holds six 0xFF bytes, sixteen copies of `mac` and then, if the card has
/// one, every byte of `password`.
fn wakes_slowly(payload: &[u8], mac: Mac, password: Option<&Password>) -> bool {
    if payload.len() > MAX_PAYLOAD {
        return false;
    }
    let pw: &[u8] = password.map_or(&[][..], |p| p.as_bytes());
    (0..payload.len()).any(|i| {
        let Some(rest) = payload.get(i..) else { return false };
        rest.len() >= PACKET_LEN + pw.len()
            && rest[..6].iter().all(|&b| b == 0xff)
            && (0..16).all(|k| rest[6 + 6 * k..12 + 6 * k] == mac)
            && rest[PACKET_LEN..PACKET_LEN + pw.len()] == *pw
    })
}

/// A card with credentials taken from fuzz bytes, set independently of the
/// payload: `wakes` agrees with the slow check.
fn receiver(data: &[u8], payload: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let mac: Mac = u.arbitrary()?;
    let password = match u.int_in_range(0..=2u8)? {
        0 => None,
        1 => Some(Password::Four(u.arbitrary()?)),
        _ => Some(Password::Six(u.arbitrary()?)),
    };
    assert_eq!(
        wakes(payload, mac, password.as_ref()),
        wakes_slowly(payload, mac, password.as_ref())
    );
    Ok(())
}

/// A packet built from fuzz bytes: whatever is written reads back the same,
/// and wakes the card it names.
fn built(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let mac = u.arbitrary()?;
    let password = match u.int_in_range(0..=2u8)? {
        0 => None,
        1 => Some(Password::Four(u.arbitrary()?)),
        _ => Some(Password::Six(u.arbitrary()?)),
    };
    let packet = MagicPacket { mac, password };
    let bytes = packet.to_bytes();
    assert_eq!(bytes.len(), packet.len());
    assert!(bytes.len() <= MAX_PACKET_LEN);
    assert_eq!(MagicPacket::find(&bytes), Ok((0, packet)));
    assert!(wakes(&bytes, mac, password.as_ref()));
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // The payload read three ways: whole, and by a scanner fed all at once
    // and a byte at a time. All give the same answer.
    let found = MagicPacket::find(data);
    assert_eq!(scan(data, false), found);
    assert_eq!(scan(data, true), found);
    assert_eq!(MagicPacket::parse(data), found.map(|(_, p)| p));

    match found {
        Ok((offset, p)) => {
            assert!(offset + PACKET_LEN <= data.len());
            // What a reader found wakes the card it names.
            assert!(wakes(data, p.mac, None));
            assert!(wakes(data, p.mac, p.password.as_ref()));
            // A card that differs from it in any one password byte stays
            // asleep, unless a later packet in the payload wakes it.
            if let Some(pw) = p.password {
                for i in 0..pw.as_bytes().len() {
                    let mut wrong = pw.as_bytes().to_vec();
                    wrong[i] ^= 0x01;
                    let wrong = Password::from_bytes(&wrong);
                    assert_eq!(
                        wakes(data, p.mac, wrong.as_ref()),
                        wakes_slowly(data, p.mac, wrong.as_ref())
                    );
                }
            }
            // Written alone, it reads back the same.
            assert_eq!(MagicPacket::find(&p.to_bytes()), Ok((0, p)));
        }
        Err(ParseError::TooLong) => assert!(data.len() > MAX_PAYLOAD),
        Err(ParseError::NotFound) => {}
    }
    let _ = built(data);
    // A card set from the first bytes, reading the whole payload.
    let _ = receiver(data, data);
    // A card for the packet found, with a password set from the input.
    if let Ok((_, p)) = found {
        for n in [4, 6] {
            let pw = data.get(..n).and_then(Password::from_bytes);
            assert_eq!(
                wakes(data, p.mac, pw.as_ref()),
                wakes_slowly(data, p.mac, pw.as_ref())
            );
        }
    }
});
