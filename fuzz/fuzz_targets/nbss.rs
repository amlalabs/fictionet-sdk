//! NetBIOS session packets, as a world playing a file server on port 139
//! reads them.
#![no_main]

use fictionet::stdlib::codec::contract;
use fictionet::stdlib::nbss::{
    Decoder, EncodeError, Error, Frames, HEADER_LEN, MAX_LABEL, MAX_LENGTH, MAX_NAME_LEN, NAME_LEN, Name, NegativeCode,
    Packet, decode_first_level,
};
use libfuzzer_sys::fuzz_target;

/// Feeds `data` to `d` in pieces of `step` bytes, taking packets out after
/// each, and returns the packets and the error that ended the stream, if
/// any. The decoder never holds more than it says it may.
fn read(d: &mut Decoder, data: &[u8], step: usize) -> (Vec<Packet>, Option<Error>) {
    let mut packets = Vec::new();
    for piece in data.chunks(step.max(1)) {
        let mut rest = piece;
        loop {
            rest = &rest[d.feed(rest)..];
            assert!(d.buffered() <= d.max_buffered());
            let mut took = false;
            while let Some(p) = d.next_packet() {
                match p {
                    Ok(p) => packets.push(p),
                    Err(e) => return (packets, Some(e)),
                }
                took = true;
            }
            if rest.is_empty() {
                break;
            }
            // A full decoder always gives a packet or an error.
            assert!(took);
        }
    }
    (packets, None)
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::new, data);
    contract::check_wire::<Packet>(data);
    contract::check_decode(|| Frames::with_limit(0), data);
    contract::check_decode(|| Frames::with_limit(64), data);

    // The stream, split three ways: all at once, a byte at a time, and in
    // pieces whose size the first byte picks.
    let (packets, end) = read(&mut Decoder::new(), data, data.len());
    assert_eq!(read(&mut Decoder::new(), data, 1), (packets.clone(), end));
    let step = usize::from(data.first().copied().unwrap_or(1)) + 1;
    assert_eq!(read(&mut Decoder::new(), data, step), (packets.clone(), end));

    // A small limit reads the same packets, up to the first one too long,
    // and stops there with Error::TooLong.
    let (limited, small_end) = read(&mut Decoder::with_limit(64), data, data.len());
    let fit = packets.iter().take_while(|p| p.to_bytes().unwrap().len() - HEADER_LEN <= 64).count();
    assert_eq!(&limited[..], &packets[..fit]);
    if fit < packets.len() {
        assert!(matches!(small_end, Some(Error::TooLong(n)) if n > 64));
    }

    for p in &packets {
        // A packet read can be written, and reads back the same.
        let bytes = p.to_bytes().unwrap();
        assert_eq!(Packet::parse(&bytes), Ok(Some((p.clone(), bytes.len()))));
    }
    // Any bytes as a name on their own.
    if let Some((name, used)) = Name::parse(data) {
        assert_eq!(name.to_bytes().unwrap(), data[..used]);
    }
    let _ = decode_first_level(data);

    // Values built from the bytes, not read: each either writes bytes
    // that read back as the same value, or is refused.
    if let Some((&first, rest)) = data.split_first() {
        let width = usize::from(first % 80);
        let scope: Vec<Vec<u8>> =
            if width == 0 { vec![Vec::new()] } else { rest.chunks(width).map(<[u8]>::to_vec).collect() };
        let name = Name { bytes: [first; NAME_LEN], scope };
        let fits = name.scope.iter().all(|l| (1..=MAX_LABEL).contains(&l.len()))
            && 2 + 2 * NAME_LEN + name.scope.iter().map(|l| 1 + l.len()).sum::<usize>() <= MAX_NAME_LEN;
        let req = Packet::Request { called: name.clone(), calling: name };
        contract::check_wire_value(&req);
        match req.to_bytes() {
            Ok(bytes) => {
                assert!(fits);
                assert_eq!(Packet::parse(&bytes), Ok(Some((req, bytes.len()))));
            }
            Err(e) => {
                assert!(!fits);
                assert_eq!(e, EncodeError::Name);
            }
        }
        let code = NegativeCode::Other(first);
        let neg = Packet::Negative(code);
        contract::check_wire_value(&neg);
        match neg.to_bytes() {
            Ok(bytes) => assert_eq!(Packet::parse(&bytes), Ok(Some((neg, bytes.len())))),
            Err(e) => {
                assert_eq!(e, EncodeError::Code(first));
                assert_ne!(NegativeCode::from_code(first), code);
            }
        }
        // A message past the limit is refused, not cut.
        if first == 0xff {
            let long = Packet::Message(vec![0; MAX_LENGTH + 1]);
            contract::check_wire_value(&long);
            assert_eq!(long.to_bytes(), Err(EncodeError::TooLong(MAX_LENGTH + 1)));
        }
    }
});
