//! ASN.1 framing and its LDAP, OCSP, SPNEGO, PEM, and Kerberos consumers.

use core::fmt::Debug;
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{Decode, Fail, Stream, Wire, finish, pump};
use fictionet::stdlib::test_support::contract;
use fictionet::stdlib::{asn1, kerberos, ldap, ocsp, spnego, x509};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct CountingAllocator;

thread_local! {
    static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
}

fn count_allocation() {
    ALLOCATIONS.with(|count| count.set(count.get().map(|n| n + 1)));
}

// SAFETY: Every operation delegates to System with the original pointer and layout.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count_allocation();
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn allocations<T>(f: impl FnOnce() -> T) -> (T, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ALLOCATIONS.set(None);
        }
    }
    assert_eq!(ALLOCATIONS.replace(Some(0)), None);
    let _reset = Reset;
    let value = f();
    (value, ALLOCATIONS.get().unwrap())
}

#[test]
fn x509_raw_validation_only_allocates_the_kept_bytes() {
    let raw = [0x30, 3, 6, 1, 42];
    let (parsed, count) = allocations(|| x509::Value::parse(&raw));
    assert_eq!(parsed.unwrap(), x509::Value::Raw(raw.to_vec()));
    assert_eq!(count, 1);
}

#[test]
fn ocsp_raw_validation_only_allocates_the_kept_bytes() {
    let mut request = ocsp::Request::new(vec![ocsp::SingleRequest {
        cert_id: ocsp::CertId {
            hash_algorithm: ocsp::AlgorithmIdentifier::sha256(),
            issuer_name_hash: vec![1; 32],
            issuer_key_hash: vec![2; 32],
            serial_number: vec![3],
        },
        extensions: vec![],
    }]);
    request.requests[0].cert_id.hash_algorithm.parameters = None;
    let der = request.to_bytes().unwrap();
    let (parsed, without_raw) = allocations(|| ocsp::Request::parse(&der));
    assert_eq!(parsed.unwrap(), request);
    request.requests[0].cert_id.hash_algorithm.parameters = Some(vec![0x30, 3, 6, 1, 42]);
    let der = request.to_bytes().unwrap();
    let (parsed, with_raw) = allocations(|| ocsp::Request::parse(&der));
    assert_eq!(parsed.unwrap(), request);
    assert_eq!(with_raw, without_raw + 1);
}

fn wrapped_writer(raw: &[u8], wrappers: usize, explicit: bool) -> Result<(), asn1::Error> {
    fn nest(w: &mut asn1::Writer, raw: &[u8], wrappers: usize, explicit: bool) {
        if wrappers == 0 {
            w.encoded(raw);
        } else if explicit {
            w.explicit(0, |w| nest(w, raw, wrappers - 1, explicit));
        } else {
            w.sequence(|w| nest(w, raw, wrappers - 1, explicit));
        }
    }
    let mut w = asn1::Writer::new();
    nest(&mut w, raw, wrappers, explicit);
    w.finish().map(drop)
}

#[test]
fn der_validation_preserves_errors_without_allocating() {
    use asn1::Error;
    let cases: &[(&[u8], Result<(), Error>)] = &[
        (&[5, 0], Ok(())),
        (&[6, 1, 42], Ok(())),
        (b"\x17\x0d250101000000Z", Ok(())),
        (b"\x18\x1220250101000000.25Z", Ok(())),
        (&[0x31, 6, 2, 1, 1, 2, 1, 2], Ok(())),
        (&[0x80, 1, 0xff], Ok(())),
        (&[], Err(Error::Empty)),
        (&[0x30], Err(Error::Truncated)),
        (&[0x30, 0x80, 0, 0], Err(Error::Indefinite)),
        (&[5, 0x81, 0], Err(Error::NonMinimalLength)),
        (&[5, 0, 5, 0], Err(Error::Trailing)),
        (&[1, 1, 1, 5, 0], Err(Error::Trailing)),
        (&[0, 0], Err(Error::Eoc)),
        (&[0x30, 3, 1, 1, 1], Err(Error::Boolean)),
        (&[2, 2, 0, 1], Err(Error::Integer)),
        (&[3, 2, 1, 1], Err(Error::BitString)),
        (&[5, 1, 0], Err(Error::Null)),
        (&[6, 1, 0x80], Err(Error::Oid)),
        (&[6, 2, 0x80, 0], Err(Error::Oid)),
        (&[0x26, 0], Err(Error::Constructed)),
        (&[0x17, 1, 0xff], Err(Error::Charset)),
        (&[0x17, 1, b'X'], Err(Error::Time)),
        (&[0x18, 1, b'X'], Err(Error::Time)),
        (&[0x37, 0], Err(Error::Constructed)),
        (&[0x13, 1, b'@'], Err(Error::Charset)),
        (&[0x10, 0], Err(Error::Primitive)),
        (&[0x31, 6, 2, 1, 2, 2, 1, 1], Err(Error::SetOrder)),
    ];
    for &(raw, expected) in cases {
        for depth in [0, 8, asn1::MAX_DEPTH - 1] {
            let (result, count) = allocations(|| asn1::validate_der_wrapped(raw, depth));
            assert_eq!(result, expected, "{raw:02x?} at {depth}");
            assert_eq!(count, 0, "{raw:02x?} at {depth}");
            for explicit in [false, true] {
                assert_eq!(wrapped_writer(raw, depth, explicit), expected);
            }
        }
        // Invalid DER wins over the caller's exhausted byte budget.
        assert_eq!(
            asn1::validate_der(raw, 0, 0),
            expected.and(Err(Error::TooLong))
        );
    }
}

#[test]
fn der_validation_preserves_depth_boundaries() {
    for depth in 0..=asn1::MAX_DEPTH + 1 {
        let mut raw = vec![5, 0];
        for levels in 0..=asn1::MAX_DEPTH + 1 {
            let expected = if depth + levels <= asn1::MAX_DEPTH {
                Ok(())
            } else {
                Err(asn1::Error::TooDeep)
            };
            assert_eq!(asn1::validate_der_wrapped(&raw, depth), expected);
            assert_eq!(wrapped_writer(&raw, depth, false), expected);
            let mut outer = vec![0x30, raw.len() as u8];
            outer.extend_from_slice(&raw);
            raw = outer;
        }
    }
    assert_eq!(
        asn1::validate_der_wrapped(&[], usize::MAX),
        Err(asn1::Error::TooDeep)
    );
}

#[test]
fn der_validation_preserves_virtual_wrapper_sizes() {
    for len in [
        0, 125, 126, 127, 128, 253, 254, 255, 256, 65530, 65535, 65536,
    ]
    .into_iter()
    .chain(asn1::MAX_INPUT - 170..=asn1::MAX_INPUT)
    {
        let mut raw = vec![4];
        asn1::encode_length(len, &mut raw);
        raw.resize(raw.len() + len, 0);
        for depth in [0, 1, 8, asn1::MAX_DEPTH] {
            let (result, count) = allocations(|| asn1::validate_der_wrapped(&raw, depth));
            assert_eq!(count, 0);
            for explicit in [false, true] {
                assert_eq!(
                    result,
                    wrapped_writer(&raw, depth, explicit),
                    "{len}, {depth}"
                );
            }
            if len >= asn1::MAX_INPUT - 170 {
                let expected = if raw.len() + 5 * depth <= asn1::MAX_INPUT {
                    Ok(())
                } else {
                    Err(asn1::Error::TooLong)
                };
                assert_eq!(result, expected, "{len}, {depth}");
            }
        }
    }
    assert_eq!(asn1::validate_der(&[5, 0], 0, usize::MAX), Ok(()));
    assert_eq!(asn1::validate_der(&[5, 0], 0, 2), Ok(()));
    assert_eq!(asn1::validate_der(&[5, 0], 0, 1), Err(asn1::Error::TooLong));
}

#[test]
fn checked_writer_imports_are_compatible() {
    use fictionet::stdlib::codec::write_checked;

    for write in [write_checked, asn1::write_checked] {
        let mut out = vec![42];
        assert_eq!(
            write(
                &7u16,
                |v: &u16| Ok(vec![*v as u8]),
                |b: &[u8]| Ok(u16::from(b[0])),
                asn1::Error::Integer,
                &mut out,
            ),
            Ok(())
        );
        assert_eq!(out, [42, 7]);
    }
}

fn round_trip<D: Decode>(make: impl Fn() -> D, bytes: &[u8], expected: &[D::Item])
where
    D::Item: Debug + PartialEq,
    D::Error: Clone + Debug + PartialEq,
{
    let (items, failure) = contract::check_decode_with_held_limit(&make, bytes, 0);
    assert_eq!(items, expected);
    assert_eq!(failure, None);
    let mut stream = Stream::new(make());
    assert_eq!(pump(&mut stream, bytes, |_| {}), Ok(bytes.len()));
    assert_eq!(finish(&mut stream, |_| {}), Ok(()));
    assert_eq!(stream.buffered(), 0);
    assert_eq!(stream.held(), 0);
}

#[test]
fn asn1_elements_round_trip() -> Result<(), Box<dyn core::error::Error>> {
    let mut writer = asn1::Writer::new();
    writer.sequence(|w| {
        w.integer_i64(42);
        w.octet_string(b"payload");
    });
    let der = writer.finish()?;
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(der.get(2..).unwrap());
    ber.extend_from_slice(&[0, 0]);
    let mut bytes = Vec::new();
    for frame in [der.clone(), ber.clone(), der.clone()] {
        asn1::Frame(frame).write(&mut bytes)?;
    }
    round_trip(
        || asn1::Elements::new(asn1::Rules::Ber),
        &bytes,
        &[der.clone(), ber.clone(), der.clone()],
    );
    round_trip(
        || asn1::Elements::new(asn1::Rules::Der),
        &der,
        core::slice::from_ref(&der),
    );
    contract::check_truncated(|| asn1::Elements::new(asn1::Rules::Ber), &ber);
    assert_eq!(
        contract::check_decode(
            || asn1::Elements::new(asn1::Rules::Der),
            &[0x04, 0x83, 0x10, 0, 0]
        ),
        (vec![], Some(Fail::Protocol(asn1::Error::TooLong)))
    );
    Ok(())
}

#[test]
fn ldap_messages_round_trip() -> Result<(), Box<dyn core::error::Error>> {
    let request = ldap::Message {
        id: 7,
        op: ldap::Op::BindRequest(ldap::BindRequest {
            version: 3,
            name: "cn=reader".into(),
            auth: ldap::Authentication::Simple(b"secret".to_vec()),
        }),
        controls: Vec::new(),
    };
    let bytes = request.to_bytes()?;
    let mut both = bytes.clone();
    request.write(&mut both)?;
    round_trip(
        Frames::<ldap::Message>::new,
        &both,
        &[request.clone(), request.clone()],
    );
    // ASN.1 framing followed by LDAP interpretation agrees with LDAP framing.
    round_trip(
        || asn1::Elements::new(asn1::Rules::Ber).map(|b| ldap::Message::parse(&b)),
        &both,
        &[Ok(request.clone()), Ok(request)],
    );
    contract::check_truncated(Frames::<ldap::Message>::new, &bytes);
    assert_eq!(
        contract::check_decode(|| Frames::<ldap::Message>::with_limit(8), &[0x30, 9]),
        (vec![], Some(Fail::Protocol(ldap::Error::TooLarge(11))))
    );
    Ok(())
}

#[test]
fn ocsp_requests_and_responses_round_trip() -> Result<(), Box<dyn core::error::Error>> {
    let request = ocsp::Request::new(vec![ocsp::SingleRequest {
        cert_id: ocsp::CertId {
            hash_algorithm: ocsp::AlgorithmIdentifier::sha256(),
            issuer_name_hash: vec![1; 32],
            issuer_key_hash: vec![2; 32],
            serial_number: vec![3],
        },
        extensions: vec![ocsp::Extension::nonce(b"nonce")?],
    }]);
    let bytes = request.to_bytes()?;
    round_trip(
        || {
            fictionet::stdlib::codec::Frames::<ocsp::Frame>::new()
                .map(|b| <ocsp::Request as Wire>::parse(&b))
        },
        &bytes,
        &[Ok(request)],
    );
    let response = ocsp::Response::error(ocsp::ResponseStatus::TryLater);
    let reply = response.to_bytes()?;
    let mut both = reply.clone();
    response.write(&mut both)?;
    round_trip(
        || {
            fictionet::stdlib::codec::Frames::<ocsp::Frame>::new()
                .map(|b| <ocsp::Response as Wire>::parse(&b))
        },
        &both,
        &[Ok(response.clone()), Ok(response)],
    );
    contract::check_truncated(fictionet::stdlib::codec::Frames::<ocsp::Frame>::new, &bytes);
    assert_eq!(
        contract::check_decode(
            fictionet::stdlib::codec::Frames::<ocsp::Frame>::new,
            &[0x30, 0x83, 1, 0, 0]
        ),
        (vec![], Some(Fail::Protocol(ocsp::Error::TooLong)))
    );
    Ok(())
}

#[test]
fn spnego_tokens_round_trip() -> Result<(), Box<dyn core::error::Error>> {
    let init = spnego::NegotiationToken::Init(spnego::NegTokenInit {
        mech_types: vec![spnego::Mech::Kerberos, spnego::Mech::Ntlm],
        mech_token: Some(vec![1, 2, 3]),
        ..Default::default()
    });
    let wrapper = spnego::InitialContextToken {
        mech: spnego::Mech::Spnego,
        inner: init.to_bytes()?,
    };
    let mut bytes = wrapper.to_bytes()?;
    let first_len = bytes.len();
    let response = spnego::NegotiationToken::Resp(spnego::NegTokenResp {
        neg_state: Some(spnego::NegState::AcceptIncomplete),
        supported_mech: Some(spnego::Mech::Kerberos),
        response_token: Some(vec![4, 5]),
        ..Default::default()
    });
    response.write(&mut bytes)?;
    round_trip(
        || {
            fictionet::stdlib::codec::Frames::<spnego::Frame>::new()
                .map(|b| <spnego::NegotiationToken as Wire>::parse(&b))
        },
        &bytes,
        &[Ok(init), Ok(response)],
    );
    contract::check_truncated(
        fictionet::stdlib::codec::Frames::<spnego::Frame>::new,
        &bytes[..first_len],
    );
    assert_eq!(
        contract::check_decode(
            fictionet::stdlib::codec::Frames::<spnego::Frame>::new,
            &[0x60, 0x83, 1, 0, 0]
        ),
        (vec![], Some(Fail::Protocol(spnego::Error::TooLong)))
    );
    Ok(())
}

#[test]
fn x509_writers_preserve_errors_and_destinations() -> Result<(), Box<dyn core::error::Error>> {
    use x509::Error;

    assert_eq!(
        contract::check_refused(&x509::BasicConstraints {
            ca: false,
            path_len: Some(1),
        }),
        Error::Value
    );
    assert_eq!(contract::check_refused(&x509::KeyUsage(0)), Error::Value);
    assert_eq!(contract::check_refused(&x509::CrlReason(7)), Error::Value);
    assert_eq!(
        contract::check_refused(&x509::ExtendedKeyUsage(vec![])),
        Error::Empty
    );
    assert_eq!(
        contract::check_refused(&x509::SubjectAltName(vec![
            x509::GeneralName::Dns(
                "a".into()
            );
            x509::MAX_GENERAL_NAMES + 1
        ])),
        Error::TooMany
    );
    assert_eq!(
        contract::check_refused(&x509::CrlNumber(vec![0, 1])),
        Error::Unwritable
    );
    assert_eq!(
        contract::check_refused(&x509::Value::Raw(vec![0x0c, 1, b'a'])),
        Error::Value
    );
    assert_eq!(
        contract::check_refused(&x509::Value::Text {
            kind: asn1::StringKind::Printable,
            text: "@".into(),
        }),
        Error::Asn1(asn1::Error::Charset)
    );

    // Value maps a final decoding failure to Unwritable. Names preserve it.
    let mut raw = vec![0x05, 0];
    for _ in 0..=asn1::MAX_DEPTH - x509::RAW_CHECK_DEPTH {
        let mut nested = vec![0x30, u8::try_from(raw.len())?];
        nested.extend_from_slice(&raw);
        raw = nested;
    }
    assert_eq!(
        x509::Value::parse(&raw),
        Err(Error::Asn1(asn1::Error::TooDeep))
    );
    let value = x509::Value::Raw(raw);
    assert_eq!(contract::check_refused(&value), Error::Unwritable);
    let mut name = x509::Name::default();
    name.push(asn1::Oid::from_contents(x509::oid::COMMON_NAME)?, value);
    assert_eq!(
        contract::check_refused(&name),
        Error::Asn1(asn1::Error::TooDeep)
    );

    let cert = x509::Certificate::parse(include_bytes!("fixtures/tls/ed25519.cert.der"))?;
    let mut key = cert.tbs.public_key.clone();
    key.algorithm.parameters = Some(vec![0x05, 0]);
    assert_eq!(contract::check_refused(&key), Error::Value);
    let mut tbs = cert.tbs.clone();
    tbs.version = x509::Version::V1;
    tbs.extensions = vec![x509::Extension {
        oid: asn1::Oid::from_contents(x509::oid::KEY_USAGE)?,
        critical: false,
        value: vec![0x03, 2, 7, 0x80],
    }];
    assert_eq!(contract::check_refused(&tbs), Error::Version);
    tbs.version = x509::Version::V3;
    tbs.extensions.push(tbs.extensions[0].clone());
    assert_eq!(contract::check_refused(&tbs), Error::DuplicateExtension);
    tbs.extensions.truncate(1);
    tbs.extensions[0].value = vec![0; x509::MAX_CERT];
    assert_eq!(contract::check_refused(&tbs), Error::TooLong);
    Ok(())
}

#[test]
fn x509_signed_writes_check_fields_and_preserve_bytes() -> Result<(), Box<dyn core::error::Error>> {
    use x509::Error;

    let der = include_bytes!("fixtures/tls/ed25519.cert.der");
    let cert = x509::Certificate::parse(der)?;
    let mut out = vec![42];
    cert.write(&mut out)?;
    assert_eq!(out[0], 42);
    assert_eq!(&out[1..], der);

    let mut changed = cert.clone();
    changed.tbs.serial.push(0);
    assert_eq!(contract::check_refused(&changed), Error::Unwritable);
    // Decode errors still take precedence over the changed signed fields.
    changed.signature_algorithm.oid = asn1::Oid::from_contents(x509::oid::ECDSA_WITH_SHA256)?;
    assert_eq!(contract::check_refused(&changed), Error::SignatureMismatch);
    changed.signature_algorithm.parameters = Some(vec![0x05, 0]);
    assert_eq!(contract::check_refused(&changed), Error::Value);

    let tbs = x509::TbsCertList {
        version: x509::Version::V2,
        signature: cert.signature_algorithm.clone(),
        issuer: cert.tbs.issuer.clone(),
        this_update: cert.tbs.validity.not_before.clone(),
        next_update: None,
        revoked: Vec::new(),
        extensions: Vec::new(),
    };
    let crl = x509::Crl::assemble(&tbs.to_bytes()?, cert.signature_algorithm, cert.signature)?;
    contract::check_wire_value(&crl);
    let mut changed = crl.clone();
    changed.tbs.issuer.rdns.clear();
    assert_eq!(contract::check_refused(&changed), Error::Unwritable);
    changed.signature_algorithm.oid = asn1::Oid::from_contents(x509::oid::ECDSA_WITH_SHA256)?;
    assert_eq!(contract::check_refused(&changed), Error::SignatureMismatch);
    changed.signature_algorithm.parameters = Some(vec![0x05, 0]);
    assert_eq!(contract::check_refused(&changed), Error::Value);
    assert_eq!(contract::check_refused(&changed.tbs), Error::Empty);

    let unexpected = Error::Asn1(asn1::Error::Unexpected {
        expected: asn1::Tag::SEQUENCE,
        found: asn1::Tag::NULL,
    });
    changed = crl;
    changed.tbs_der = vec![0x05, 0];
    assert_eq!(contract::check_refused(&changed), unexpected);
    let mut changed = x509::Certificate::parse(der)?;
    changed.tbs_der = vec![0x05, 0];
    assert_eq!(contract::check_refused(&changed), unexpected);
    Ok(())
}

#[test]
fn x509_pem_blocks_round_trip() -> Result<(), Box<dyn core::error::Error>> {
    let algorithm = x509::AlgorithmIdentifier {
        oid: asn1::Oid::from_contents(x509::oid::ED25519)?,
        parameters: None,
    };
    let mut name = x509::Name::default();
    name.push(
        asn1::Oid::from_contents(x509::oid::COMMON_NAME)?,
        x509::Value::Text {
            kind: asn1::StringKind::Utf8,
            text: "test".into(),
        },
    );
    let tbs = x509::TbsCertificate {
        version: x509::Version::V3,
        serial: vec![1],
        signature: algorithm.clone(),
        issuer: name.clone(),
        validity: x509::Validity {
            not_before: x509::Time::from_unix(0)?,
            not_after: x509::Time::from_unix(86400)?,
        },
        subject: name,
        public_key: x509::PublicKeyInfo {
            algorithm: algorithm.clone(),
            key: asn1::BitString::new(vec![7; 32], 0)?,
        },
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Vec::new(),
    };
    let certificate = x509::Certificate::assemble(
        &tbs.to_bytes()?,
        algorithm,
        asn1::BitString::new(vec![8; 64], 0)?,
    )?;
    let block = x509::PemBlock {
        label: x509::PEM_CERTIFICATE.into(),
        data: certificate.to_bytes()?,
    };
    let bytes = block.to_bytes()?;
    let mut both = bytes.clone();
    block.write(&mut both)?;
    round_trip(x509::PemBlocks::new, &both, &[block.clone(), block]);
    round_trip(
        || x509::PemBlocks::new().map(|p| x509::Certificate::parse(&p.data)),
        &both,
        &[Ok(certificate.clone()), Ok(certificate)],
    );
    // End after a complete base64 line, while the block is still open.
    let cut = bytes
        .windows(b"-----END".len())
        .position(|w| w == b"-----END")
        .unwrap();
    let (items, failure) = contract::check_decode(x509::PemBlocks::new, bytes.get(..cut).unwrap());
    assert!(items.is_empty());
    assert!(matches!(failure, Some(Fail::Truncated { .. })));
    assert_eq!(
        contract::check_decode(|| x509::PemBlocks::with_limit(32), &bytes),
        (vec![], Some(Fail::Protocol(x509::Error::TooLong)))
    );
    Ok(())
}

#[test]
fn x509_pem_trailing_text_at_eof() -> Result<(), Box<dyn core::error::Error>> {
    let text = x509::PemBlock {
        label: "TEST".into(),
        data: vec![1, 2, 3],
    }
    .to_bytes()?;
    let text = String::from_utf8(text)?;
    for input in [
        format!("{text}# trailing comment"),
        format!("{}  ", text.trim_end_matches('\n')),
        format!("{}\t", text.trim_end_matches('\n')),
        "just text".into(),
    ] {
        let expected = x509::pem_decode(input.as_bytes())?;
        round_trip(x509::PemBlocks::new, input.as_bytes(), &expected);
    }
    let (items, failure) =
        contract::check_decode(x509::PemBlocks::new, b"-----BEGIN TEST-----\nAQID");
    assert!(items.is_empty());
    assert!(matches!(failure, Some(Fail::Truncated { .. })));
    Ok(())
}

#[test]
fn x509_pem_text_lines_have_their_own_limit() -> Result<(), Box<dyn core::error::Error>> {
    let text = x509::PemBlock {
        label: "TEST".into(),
        data: vec![1, 2, 3],
    }
    .to_bytes()?;
    let text = String::from_utf8(text)?;
    let limit = text.len() - 1;
    let comment = "#".repeat(128);
    let input = format!("{comment}\n{text}{comment}\n{text}{comment}");
    round_trip(
        || x509::PemBlocks::with_limit(limit),
        input.as_bytes(),
        &x509::pem_decode(input.as_bytes())?,
    );
    assert_eq!(
        contract::check_decode(|| x509::PemBlocks::with_limit(limit - 1), text.as_bytes()),
        (vec![], Some(Fail::Protocol(x509::Error::TooLong)))
    );

    let mut line = vec![b'#'; x509::MAX_PEM_LINE];
    round_trip(|| x509::PemBlocks::with_limit(0), &line, &[]);
    line.push(b'\n');
    round_trip(|| x509::PemBlocks::with_limit(0), &line, &[]);
    *line.last_mut().unwrap() = b'#';
    assert_eq!(
        contract::check_decode(|| x509::PemBlocks::with_limit(0), &line),
        (vec![], Some(Fail::Protocol(x509::Error::TooLong)))
    );
    line.push(b'\n');
    assert_eq!(
        contract::check_decode(|| x509::PemBlocks::with_limit(0), &line),
        (vec![], Some(Fail::Protocol(x509::Error::TooLong)))
    );
    Ok(())
}

#[test]
fn frame_limits_refuse_lengths_before_bodies() {
    for limit in [0, 1, 2, 15, 16, 32] {
        assert_eq!(
            contract::check_decode(
                || fictionet::stdlib::codec::Frames::<ocsp::Frame>::with_limit(limit),
                &[0x30, 0x81, 0x80]
            ),
            (vec![], Some(Fail::Protocol(ocsp::Error::TooLong)))
        );
        assert_eq!(
            contract::check_decode(
                || fictionet::stdlib::codec::Frames::<spnego::Frame>::with_limit(limit),
                &[0xa1, 0x81, 0x80]
            ),
            (vec![], Some(Fail::Protocol(spnego::Error::TooLong)))
        );
        assert_eq!(
            contract::check_decode(
                || fictionet::stdlib::codec::Frames::<kerberos::Frame>::with_limit(limit),
                &[0, 0, 0, 128]
            ),
            (
                vec![],
                Some(Fail::Protocol(kerberos::Error::LengthTooLong(128)))
            )
        );
        assert_eq!(
            fictionet::stdlib::codec::Frames::<ocsp::Frame>::with_limit(limit).capacity(),
            limit.max(16)
        );
        assert_eq!(
            fictionet::stdlib::codec::Frames::<spnego::Frame>::with_limit(limit).capacity(),
            limit.max(16)
        );
        assert_eq!(
            fictionet::stdlib::codec::Frames::<kerberos::Frame>::with_limit(limit).capacity(),
            limit + 4
        );
    }
    assert_eq!(
        contract::check_decode(
            || fictionet::stdlib::codec::Frames::<ocsp::Frame>::with_limit(0),
            &[0x30, 0]
        ),
        (vec![], Some(Fail::Protocol(ocsp::Error::TooLong)))
    );
    assert_eq!(
        contract::check_decode(
            || fictionet::stdlib::codec::Frames::<spnego::Frame>::with_limit(0),
            &[0xa1, 0]
        ),
        (vec![], Some(Fail::Protocol(spnego::Error::TooLong)))
    );
    round_trip(
        || fictionet::stdlib::codec::Frames::<ocsp::Frame>::with_limit(2),
        &[0x30, 0],
        &[vec![0x30, 0]],
    );
    round_trip(
        || fictionet::stdlib::codec::Frames::<spnego::Frame>::with_limit(2),
        &[0xa1, 0],
        &[vec![0xa1, 0]],
    );
    round_trip(
        || fictionet::stdlib::codec::Frames::<kerberos::Frame>::with_limit(0),
        &[0, 0, 0, 0],
        &[vec![]],
    );
    round_trip(
        || fictionet::stdlib::codec::Frames::<kerberos::Frame>::with_limit(1),
        &[0, 0, 0, 1, 42],
        &[vec![42]],
    );
    assert_eq!(
        fictionet::stdlib::codec::Frames::<ocsp::Frame>::with_limit(usize::MAX).limit(),
        ocsp::MAX_MESSAGE
    );
    assert_eq!(
        fictionet::stdlib::codec::Frames::<spnego::Frame>::with_limit(usize::MAX).limit(),
        spnego::MAX_TOKEN
    );
    assert_eq!(
        fictionet::stdlib::codec::Frames::<kerberos::Frame>::with_limit(usize::MAX).limit(),
        kerberos::MAX_MESSAGE
    );
    assert_eq!(
        fictionet::stdlib::codec::Frames::<ocsp::Frame>::default().limit(),
        ocsp::MAX_MESSAGE
    );
    assert_eq!(
        fictionet::stdlib::codec::Frames::<spnego::Frame>::default().limit(),
        spnego::MAX_TOKEN
    );
    assert_eq!(
        fictionet::stdlib::codec::Frames::<kerberos::Frame>::default().limit(),
        kerberos::MAX_MESSAGE
    );
}

#[test]
fn kerberos_tcp_messages_round_trip() -> Result<(), Box<dyn core::error::Error>> {
    let message = kerberos::Message::ApRep(kerberos::ApRep {
        enc_part: kerberos::EncryptedData {
            etype: 18,
            kvno: Some(2),
            cipher: vec![9; 133],
        },
    });
    let der = message.to_bytes()?;
    let frame = kerberos::Frame(der);
    let bytes = frame.to_bytes()?;
    let mut both = bytes.clone();
    frame.write(&mut both)?;
    round_trip(
        || {
            fictionet::stdlib::codec::Frames::<kerberos::Frame>::new()
                .map(|b| <kerberos::Message as Wire>::parse(&b))
        },
        &both,
        &[Ok(message.clone()), Ok(message)],
    );
    contract::check_truncated(
        fictionet::stdlib::codec::Frames::<kerberos::Frame>::new,
        &bytes,
    );
    let length = kerberos::MAX_MESSAGE as u32 + 1;
    assert_eq!(
        contract::check_decode(
            fictionet::stdlib::codec::Frames::<kerberos::Frame>::new,
            &length.to_be_bytes()
        ),
        (
            vec![],
            Some(Fail::Protocol(kerberos::Error::LengthTooLong(length)))
        )
    );
    Ok(())
}
