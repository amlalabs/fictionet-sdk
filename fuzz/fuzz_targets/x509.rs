//! X.509 certificates, CRLs, their extensions and PEM text, as a world
//! reads them from what the agent sends, and writes them back.
#![no_main]

use fictionet::stdlib::codec::{Stream, Wire, finish, pump};
use fictionet::stdlib::protocols::asn1::{Oid, StringKind};
use fictionet::stdlib::protocols::x509::harness::check;
use fictionet::stdlib::protocols::x509::{
    BasicConstraints, ExtensionValue, GeneralName, KeyUsage, MAX_PEM_DATA, MAX_PEM_FRAME, Name,
    PemBlock, PemBlocks, SubjectAltName, Value, pem_decode,
};
use fictionet::stdlib::test_support::contract;
use libfuzzer_sys::fuzz_target;

/// A value built from the input, not read from it: its writer either
/// refuses it or writes bytes that read back as the same value.
fn built(data: &[u8]) {
    fn same<T: ExtensionValue + PartialEq + std::fmt::Debug>(v: T) {
        contract::check_wire_value(&v);
        if let Ok(der) = v.to_bytes() {
            assert_eq!(T::parse(&der).unwrap(), v);
        }
    }
    let text = String::from_utf8_lossy(data).into_owned();
    for g in [
        GeneralName::Unsupported(data.to_vec()),
        GeneralName::Ip(data.to_vec()),
        GeneralName::Dns(text.clone()),
        GeneralName::Uri(text.clone()),
        GeneralName::Email(text.clone()),
    ] {
        same(SubjectAltName(vec![g]));
    }
    if let Ok(oid) = Oid::from_contents(&[0x55, 0x04, 0x03]) {
        for value in [
            Value::Raw(data.to_vec()),
            Value::Text {
                kind: StringKind::Utf8,
                text,
            },
        ] {
            let mut n = Name::default();
            n.push(oid.clone(), value);
            if let Ok(der) = n.to_bytes() {
                assert_eq!(Name::parse(&der).unwrap(), n);
            }
        }
    }
    if let [a, b, ..] = *data {
        same(KeyUsage(u16::from_be_bytes([a, b])));
        same(BasicConstraints {
            ca: a & 1 != 0,
            path_len: (b & 1 != 0).then_some(u64::from(a)),
        });
    }
}

fuzz_target!(|data: &[u8]| {
    fictionet::stdlib::protocols::asn1::harness::check(data);
    if data.len() <= MAX_PEM_FRAME
        && let Ok(list) = pem_decode(data)
    {
        let mut stream = Stream::new(PemBlocks::new());
        let mut blocks = Vec::new();
        pump(&mut stream, data, |block| blocks.push(block)).unwrap();
        finish(&mut stream, |block| blocks.push(block)).unwrap();
        assert_eq!(list, blocks);
        for block in &list {
            if let Ok(text) = block.to_bytes() {
                assert_eq!(pem_decode(&text).unwrap(), std::slice::from_ref(block));
            }
        }
    }
    contract::check_decode(PemBlocks::new, data);
    contract::check_decode(|| PemBlocks::with_limit(128), data);
    contract::check_wire::<PemBlock>(data);
    let block = PemBlock {
        label: "CERTIFICATE".into(),
        data: data.get(..MAX_PEM_DATA + 1).unwrap_or(data).to_vec(),
    };
    contract::check_wire_value(&block);
    if let Ok(text) = block.to_bytes() {
        contract::check_decode(PemBlocks::new, &text);
        contract::check_wire::<PemBlock>(&text);
    }

    check(data);
    built(data);

    let mut stream = Stream::new(PemBlocks::new());
    let mut inspect = |block: PemBlock| {
        contract::check_wire_value(&block);
        check(&block.data);
    };
    let _ = pump(&mut stream, data, &mut inspect);
    let _ = finish(&mut stream, &mut inspect);
});
