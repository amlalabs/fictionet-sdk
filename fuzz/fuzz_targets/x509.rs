//! X.509 certificates, CRLs, their extensions and PEM text, as a world
//! reads them from what the agent sends, and writes them back.
#![no_main]

use fictionet::stdlib::x509::{
    AuthorityInfoAccess, AuthorityKeyIdentifier, BasicConstraints, Certificate, Crl, CrlDistributionPoints, CrlNumber,
    CrlReason, ExtendedKeyUsage, ExtensionValue, IssuerAltName, KeyUsage, Name, Pem, PemDecoder, SubjectAltName,
    SubjectKeyIdentifier, TbsCertList, TbsCertificate, pem_decode,
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
/// and whether the stream broke.
fn blocks(data: &[u8], chunk: usize) -> (Vec<Pem>, bool) {
    let mut d = PemDecoder::new();
    let mut out = Vec::new();
    for c in data.chunks(chunk.max(1)) {
        d.feed(c);
        while let Some(r) = d.next_block() {
            match r {
                Ok(p) => out.push(p),
                Err(_) => return (out, true),
            }
        }
    }
    (out, false)
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
    }
    if let Ok(n) = Name::from_der(data) {
        assert_eq!(Name::from_der(&n.to_der().unwrap()).unwrap(), n);
        let _ = n.to_string();
    }
    extension_value(data);
}

fuzz_target!(|data: &[u8]| {
    der(data);

    // The bytes as PEM text, split three ways: all at once, a byte at a
    // time, and in pieces of a size the input picks.
    let whole = blocks(data, data.len());
    assert_eq!(blocks(data, 1), whole);
    let chunk = data.first().map_or(1, |&b| usize::from(b % 16) + 1);
    assert_eq!(blocks(data, chunk), whole);
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
