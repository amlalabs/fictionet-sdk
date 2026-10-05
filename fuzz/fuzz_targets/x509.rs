//! X.509 certificates, CRLs, their extensions and PEM text, as a world
//! reads them from what the agent sends, and writes them back.
#![no_main]

use fictionet::stdlib::asn1::{Oid, StringKind};
use fictionet::stdlib::codec::{Stream, contract, finish, pump};
use fictionet::stdlib::x509::{
    AuthorityInfoAccess, AuthorityKeyIdentifier, BasicConstraints, Certificate, Crl,
    CrlDistributionPoints, CrlNumber, CrlReason, ExtendedKeyUsage, ExtensionValue, GeneralName,
    IssuerAltName, KeyUsage, MAX_PEM_BUFFER, MAX_PEM_DATA, Name, Pem, PemBlocks, PemDecoder,
    RevokedCertificate, SubjectAltName, SubjectKeyIdentifier, TbsCertList, TbsCertificate, Value,
    pem_decode,
};
use libfuzzer_sys::fuzz_target;

/// A typed extension value that reads writes again, and reads back the
/// same.
fn round_trip<T: ExtensionValue + PartialEq + std::fmt::Debug>(data: &[u8]) {
    if let Ok(v) = T::from_der(data) {
        let der = v.to_der().unwrap();
        assert_eq!(T::from_der(&der).unwrap(), v);
    }
}

fn extension_value(data: &[u8]) {
    round_trip::<BasicConstraints>(data);
    round_trip::<KeyUsage>(data);
    round_trip::<ExtendedKeyUsage>(data);
    round_trip::<SubjectAltName>(data);
    round_trip::<SubjectKeyIdentifier>(data);
    round_trip::<AuthorityKeyIdentifier>(data);
    round_trip::<CrlDistributionPoints>(data);
    round_trip::<AuthorityInfoAccess>(data);
    round_trip::<IssuerAltName>(data);
    round_trip::<CrlNumber>(data);
    round_trip::<CrlReason>(data);
}

/// Every block a decoder gives, fed `data` in pieces of `chunk` bytes,
/// and whether the stream broke. With `lazy`, it feeds until the decoder
/// takes no more before it takes blocks out.
fn blocks(data: &[u8], chunk: usize, lazy: bool) -> (Vec<Pem>, bool) {
    let mut d = PemDecoder::new();
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let n = d.feed(&rest[..chunk.max(1).min(rest.len())]);
        rest = &rest[n..];
        assert!(d.buffered() <= MAX_PEM_BUFFER);
        if lazy && n > 0 && !rest.is_empty() {
            continue;
        }
        let before = d.buffered();
        let mut took = false;
        while let Some(r) = d.next_block() {
            took = true;
            match r {
                Ok(p) => out.push(p),
                Err(_) => return (out, true),
            }
        }
        // A decoder that took nothing reads at least a line.
        assert!(n > 0 || took || d.buffered() < before);
    }
    while let Some(r) = d.next_block() {
        match r {
            Ok(p) => out.push(p),
            Err(_) => return (out, true),
        }
    }
    (out, false)
}

/// A value built from the input, not read from it: its writer either
/// refuses it or writes bytes that read back as the same value.
fn built(data: &[u8]) {
    fn same<T: ExtensionValue + PartialEq + std::fmt::Debug>(v: T) {
        if let Ok(der) = v.to_der() {
            assert_eq!(T::from_der(&der).unwrap(), v);
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
        for value in [Value::Raw(data.to_vec()), Value::Text { kind: StringKind::Utf8, text }] {
            let mut n = Name::default();
            n.push(oid.clone(), value);
            if let Ok(der) = n.to_der() {
                assert_eq!(Name::from_der(&der).unwrap(), n);
            }
        }
    }
    if let [a, b, ..] = *data {
        same(KeyUsage(u16::from_be_bytes([a, b])));
        same(BasicConstraints { ca: a & 1 != 0, path_len: (b & 1 != 0).then_some(u64::from(a)) });
    }
}

/// The DER checks: what reads writes back.
fn der(data: &[u8]) {
    if let Ok(c) = Certificate::parse(data) {
        // A certificate read gives back the same bytes.
        assert_eq!(c.to_der().unwrap(), data);
        let tbs = c.tbs.to_der().unwrap();
        assert_eq!(TbsCertificate::parse(&tbs).unwrap(), c.tbs);
        let _ = (c.tbs.subject.to_string(), c.tbs.issuer.to_string(), c.tbs.validity.contains(0));
        let pem = c.to_pem().unwrap();
        assert_eq!(Certificate::from_pem(pem.as_bytes()).unwrap(), c);
        for x in &c.tbs.extensions {
            extension_value(&x.value);
        }
        // A tbs changed after reading no longer matches the bytes.
        let mut changed = c.clone();
        changed.tbs.serial.push(0);
        assert!(changed.to_der().is_err());
    }
    if let Ok(c) = Crl::parse(data) {
        assert_eq!(c.to_der().unwrap(), data);
        let tbs = c.tbs.to_der().unwrap();
        assert_eq!(TbsCertList::parse(&tbs).unwrap(), c.tbs);
        let _ = c.tbs.issuer.to_string();
        for x in c.tbs.extensions.iter().chain(c.tbs.revoked.iter().flat_map(|r| &r.extensions)) {
            extension_value(&x.value);
        }
        if let Some(r) = c.tbs.revoked.first() {
            assert!(c.is_revoked(&r.serial));
        }
        let pem = c.to_pem().unwrap();
        assert_eq!(Crl::from_pem(pem.as_bytes()).unwrap(), c);
        let mut changed = c.clone();
        let date = changed.tbs.this_update.clone();
        changed.tbs.revoked.push(RevokedCertificate { serial: vec![1], revocation_date: date, extensions: Vec::new() });
        assert!(changed.to_der().is_err());
    }
    if let Ok(n) = Name::from_der(data) {
        assert_eq!(Name::from_der(&n.to_der().unwrap()).unwrap(), n);
        let _ = n.to_string();
    }
    extension_value(data);
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(PemBlocks::new, data);
    contract::check_decode(|| PemBlocks::with_limit(128), data);
    // Accepted whole inputs fit below the stream's whole-block bound.
    if data.len() <= MAX_PEM_BUFFER
        && let Ok(expected) = pem_decode(data)
    {
        let mut stream = Stream::new(PemBlocks::new());
        let mut actual = Vec::new();
        pump(&mut stream, data, |block| actual.push(block)).unwrap();
        finish(&mut stream, |block| actual.push(block)).unwrap();
        assert_eq!(actual, expected);
    }
    contract::check_wire::<Pem>(data);
    let block = Pem { label: "CERTIFICATE".into(), data: data.get(..MAX_PEM_DATA + 1).unwrap_or(data).to_vec() };
    contract::check_wire_value(&block);
    if let Ok(text) = block.encode() {
        contract::check_decode(PemBlocks::new, text.as_bytes());
        contract::check_wire::<Pem>(text.as_bytes());
    }

    der(data);
    built(data);

    // The bytes as PEM text, split four ways: all at once, a byte at a
    // time, in pieces of a size the input picks, and those pieces fed
    // until the decoder is full before any block is taken out.
    let whole = blocks(data, data.len(), false);
    assert_eq!(blocks(data, 1, false), whole);
    let chunk = data.first().map_or(1, |&b| usize::from(b % 16) + 1);
    assert_eq!(blocks(data, chunk, false), whole);
    assert_eq!(blocks(data, chunk, true), whole);
    if let Ok(list) = pem_decode(data) {
        assert!(!whole.1);
        assert_eq!(list, whole.0);
        for p in &list {
            // A block encodes to text that decodes to the same block.
            if let Ok(text) = p.encode() {
                assert_eq!(pem_decode(text.as_bytes()).unwrap(), std::slice::from_ref(p));
            }
            der(&p.data);
        }
    }
});
