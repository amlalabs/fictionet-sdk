//! First-level NetBIOS encoding and uncompressed name limits.
#![no_main]

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::nbns::Name;
use fictionet::stdlib::netbios::{
    ENCODED_LEN, Error, MAX_LABEL, MAX_NAME_LEN, NAME_LEN, decode_first_level, encode_first_level,
    write_name,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let decoded = decode_first_level(data);
    assert_eq!(
        decoded.is_some(),
        data.len() == ENCODED_LEN && data.iter().all(|b| (b'A'..=b'P').contains(b))
    );
    if let Some(name) = decoded {
        assert_eq!(encode_first_level(&name), data);
    }

    if let Some((bytes, mut rest)) = data.split_at_checked(NAME_LEN) {
        let bytes: [u8; NAME_LEN] = bytes.try_into().unwrap();
        assert_eq!(decode_first_level(&encode_first_level(&bytes)), Some(bytes));

        let mut scope = Vec::new();
        while let Some((&len, labels)) = rest.split_first() {
            let (label, remaining) = labels.split_at(usize::from(len).min(labels.len()));
            scope.push(label.to_vec());
            rest = remaining;
        }
        let name = Name { bytes, scope };
        let length = ENCODED_LEN + 2 + name.scope.iter().map(|l| l.len() + 1).sum::<usize>();
        let fits = length <= MAX_NAME_LEN
            && name
                .scope
                .iter()
                .all(|l| (1..=MAX_LABEL).contains(&l.len()));
        let mut out = data.to_vec();
        match write_name(&mut out, &name.bytes, &name.scope) {
            Ok(()) => {
                assert!(fits);
                assert_eq!(&out[..data.len()], data);
                let wire = &out[data.len()..];
                assert_eq!(wire.len(), length);
                assert!(wire.len() <= MAX_NAME_LEN);
                assert_eq!(Name::parse(wire), Ok(name));
            }
            Err(error) => {
                assert!(!fits);
                assert_eq!(error, Error::Unwritable);
                assert_eq!(out, data);
            }
        }
    }
});
