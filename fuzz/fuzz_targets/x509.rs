//! X.509 certificates, CRLs, their extensions and PEM text, as a world
//! reads them from what the agent sends, and writes them back.
#![no_main]

use fictionet::stdlib::asn1::{Oid, StringKind};
use fictionet::stdlib::codec::{Stream, Wire, finish, pump};
use fictionet::stdlib::test_support::contract;
use fictionet::stdlib::x509::harness::check_extension_value;
use fictionet::stdlib::x509::{
    BasicConstraints, Certificate, Crl, ExtensionValue, GeneralName, KeyUsage, MAX_PEM_DATA,
    MAX_PEM_FRAME, Name, PemBlock, PemBlocks, RevokedCertificate, SubjectAltName, TbsCertList,
    TbsCertificate, Value, pem_decode,
};
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

/// The DER checks: what reads writes back.
fn der(data: &[u8]) {
    contract::check_wire::<Certificate>(data);
    contract::check_wire::<Crl>(data);
    contract::check_wire::<TbsCertificate>(data);
    contract::check_wire::<TbsCertList>(data);
    contract::check_wire::<Name>(data);
    if let Ok(c) = Certificate::parse(data) {
        // A certificate read gives back the same bytes.
        assert_eq!(c.to_bytes().unwrap(), data);
        let tbs = c.tbs.to_bytes().unwrap();
        assert_eq!(TbsCertificate::parse(&tbs).unwrap(), c.tbs);
        let _ = (
            c.tbs.subject.to_string(),
            c.tbs.issuer.to_string(),
            c.tbs.validity.contains(0),
        );
        let pem = PemBlock {
            label: "CERTIFICATE".into(),
            data: c.to_bytes().unwrap(),
        }
        .to_bytes()
        .unwrap();
        assert_eq!(Certificate::from_pem(&pem).unwrap(), c);
        for x in &c.tbs.extensions {
            check_extension_value(&x.value);
        }
        // A tbs changed after reading no longer matches the bytes.
        let mut changed = c.clone();
        changed.tbs.serial.push(0);
        assert!(changed.to_bytes().is_err());
    }
    if let Ok(c) = Crl::parse(data) {
        assert_eq!(c.to_bytes().unwrap(), data);
        let tbs = c.tbs.to_bytes().unwrap();
        assert_eq!(TbsCertList::parse(&tbs).unwrap(), c.tbs);
        let _ = c.tbs.issuer.to_string();
        for x in c
            .tbs
            .extensions
            .iter()
            .chain(c.tbs.revoked.iter().flat_map(|r| &r.extensions))
        {
            check_extension_value(&x.value);
        }
        if let Some(r) = c.tbs.revoked.first() {
            assert!(c.is_revoked(&r.serial));
        }
        let pem = PemBlock {
            label: "X509 CRL".into(),
            data: c.to_bytes().unwrap(),
        }
        .to_bytes()
        .unwrap();
        assert_eq!(Crl::from_pem(&pem).unwrap(), c);
        let mut changed = c.clone();
        let date = changed.tbs.this_update.clone();
        changed.tbs.revoked.push(RevokedCertificate {
            serial: vec![1],
            revocation_date: date,
            extensions: Vec::new(),
        });
        assert!(changed.to_bytes().is_err());
    }
    if let Ok(n) = Name::parse(data) {
        assert_eq!(Name::parse(&n.to_bytes().unwrap()).unwrap(), n);
        let _ = n.to_string();
    }
    check_extension_value(data);
}

fuzz_target!(|data: &[u8]| {
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

    der(data);
    built(data);

    let mut stream = Stream::new(PemBlocks::new());
    let mut inspect = |block: PemBlock| {
        contract::check_wire_value(&block);
        der(&block.data);
    };
    let _ = pump(&mut stream, data, &mut inspect);
    let _ = finish(&mut stream, &mut inspect);
});
