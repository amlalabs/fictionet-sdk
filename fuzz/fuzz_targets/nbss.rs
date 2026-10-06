//! NetBIOS session packets, as a world playing a file server on port 139
//! reads them.
#![no_main]

use fictionet::stdlib::codec::{Decode, Fail, Wire, contract, test_support::decode_all};
use fictionet::stdlib::nbss::{
    Error, Frames, HEADER_LEN, MAX_LABEL, MAX_LENGTH, MAX_NAME_LEN, NAME_LEN, Name, NegativeCode,
    Packet, decode_first_level,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Frames::new, data, 2 * Frames::new().capacity());
    contract::check_wire::<Packet>(data);
    contract::check_decode_with_alloc_limit(|| Frames::with_limit(0), data, 2 * Frames::with_limit(0).capacity());
    contract::check_decode_with_alloc_limit(|| Frames::with_limit(64), data, 2 * Frames::with_limit(64).capacity());

    let (packets, _) = decode_all(Frames::new, data);

    // A small limit reads the same packets, up to the first one too long,
    // and stops there with Error::TooLong.
    let (limited, small_end) = decode_all(|| Frames::with_limit(64), data);
    let fit = packets.iter().take_while(|p| p.to_bytes().unwrap().len() - HEADER_LEN <= 64).count();
    assert_eq!(&limited[..], &packets[..fit]);
    if fit < packets.len() {
        assert!(matches!(small_end, Some(Fail::Protocol(Error::TooLong(n))) if n > 64));
    }

    for p in &packets {
        // A packet read can be written, and reads back the same.
        let bytes = p.to_bytes().unwrap();
        assert_eq!(Packet::parse(&bytes), Ok(p.clone()));
    }
    contract::check_wire::<Name>(data);
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
                assert_eq!(Packet::parse(&bytes), Ok(req));
            }
            Err(e) => {
                assert!(!fits);
                assert_eq!(e, Error::Unwritable);
            }
        }
        let code = NegativeCode::Other(first);
        let neg = Packet::Negative(code);
        contract::check_wire_value(&neg);
        match neg.to_bytes() {
            Ok(bytes) => assert_eq!(Packet::parse(&bytes), Ok(neg)),
            Err(e) => {
                assert_eq!(e, Error::Unwritable);
                assert_ne!(NegativeCode::from_code(first), code);
            }
        }
        // A message past the limit is refused, not cut.
        if first == 0xff {
            let long = Packet::Message(vec![0; MAX_LENGTH + 1]);
            contract::check_wire_value(&long);
            assert_eq!(long.to_bytes(), Err(Error::Unwritable));
        }
    }
});
