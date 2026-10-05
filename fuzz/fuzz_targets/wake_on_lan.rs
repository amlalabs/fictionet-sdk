//! Wake-on-LAN payloads, as a world playing a sleeping host or a tool reads
//! them, and magic packets a world builds, as it writes them.
#![no_main]

use arbitrary::{Result, Unstructured};
use fictionet::stdlib::wake_on_lan::{
    MAX_PACKET_LEN, MAX_PAYLOAD, MagicPacket, PACKET_LEN, ParseError, Password, Scanner, wakes,
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
            // Written alone, it reads back the same.
            assert_eq!(MagicPacket::find(&p.to_bytes()), Ok((0, p)));
        }
        Err(ParseError::TooLong) => assert!(data.len() > MAX_PAYLOAD),
        Err(ParseError::NotFound) => {}
    }
    let _ = built(data);
});
