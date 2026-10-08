//! ASN.1 framing and its LDAP, OCSP, SPNEGO, PEM, and Kerberos consumers.

use fictionet::stdlib::codec::Frames;
use core::fmt::Debug;
use fictionet::stdlib::codec::{
    Decode, Fail, Stream, Wire, contract, finish, pump, test_support::chunks,
};
use fictionet::stdlib::{asn1, kerberos, ldap, ocsp, spnego, x509};

fn round_trip<D: Decode>(make: impl Fn() -> D, bytes: &[u8], expected: &[D::Item])
where
    D::Item: Debug + PartialEq,
    D::Error: Clone + Debug + PartialEq,
{
    contract::check_decode(&make, bytes);
    for pattern in [&[1][..], &[1, 2, 5, 3, 127], &[7, 1, 64], &[]] {
        let mut stream = Stream::new(make());
        let mut got = Vec::new();
        for part in chunks(bytes, pattern) {
            assert_eq!(
                pump(&mut stream, part, |item| got.push(item)),
                Ok(part.len())
            );
        }
        assert_eq!(finish(&mut stream, |item| got.push(item)), Ok(()));
        assert_eq!(got, expected);
        assert_eq!(stream.buffered(), 0);
        assert_eq!(stream.held(), 0);
        assert!(stream.failed().is_none());
    }
}

fn truncated<D: Decode>(make: impl Fn() -> D, bytes: &[u8])
where
    D::Item: Debug + PartialEq,
    D::Error: Clone + Debug + PartialEq,
{
    contract::check_decode(&make, bytes);
    let mut stream = Stream::new(make());
    for part in chunks(bytes, &[1]) {
        assert_eq!(
            pump(&mut stream, part, |_| panic!(
                "partial unit produced an item"
            )),
            Ok(part.len())
        );
    }
    assert!(matches!(
        finish(&mut stream, |_| panic!("partial unit produced an item")),
        Err(Fail::Truncated { .. })
    ));
    assert_eq!(stream.next(), None);
}

fn refused<D: Decode>(make: impl Fn() -> D, bytes: &[u8], error: D::Error)
where
    D::Item: Debug + PartialEq,
    D::Error: Clone + Debug + PartialEq,
{
    contract::check_decode(&make, bytes);
    for pattern in [&[1][..], &[]] {
        let mut stream = Stream::new(make());
        let mut result = Ok(0);
        for part in chunks(bytes, pattern) {
            result = pump(&mut stream, part, |_| {
                panic!("oversized unit produced an item")
            });
            if result.is_err() {
                break;
            }
        }
        assert_eq!(result, Err(Fail::Protocol(error.clone())));
        assert_eq!(stream.next(), None);
        assert_eq!(stream.failed(), Some(&Fail::Protocol(error.clone())));
    }
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
    truncated(
        || asn1::Elements::new(asn1::Rules::Ber),
        ber.get(..ber.len() - 1).unwrap(),
    );
    refused(
        || asn1::Elements::new(asn1::Rules::Der),
        &[0x04, 0x83, 0x10, 0, 0],
        asn1::Error::TooLong,
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
    truncated(Frames::<ldap::Message>::new, bytes.get(..bytes.len() - 1).unwrap());
    refused(
        || Frames::<ldap::Message>::with_limit(8),
        &[0x30, 9],
        ldap::Error::TooLarge(11),
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
        || ocsp::Frames::new().map(|b| <ocsp::Request as Wire>::parse(&b)),
        &bytes,
        &[Ok(request)],
    );
    let response = ocsp::Response::error(ocsp::ResponseStatus::TryLater);
    let reply = response.to_bytes()?;
    let mut both = reply.clone();
    response.write(&mut both)?;
    round_trip(
        || ocsp::Frames::new().map(|b| <ocsp::Response as Wire>::parse(&b)),
        &both,
        &[Ok(response.clone()), Ok(response)],
    );
    truncated(ocsp::Frames::new, bytes.get(..bytes.len() - 1).unwrap());
    refused(
        ocsp::Frames::new,
        &[0x30, 0x83, 1, 0, 0],
        ocsp::Error::TooLong,
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
        || spnego::Frames::new().map(|b| <spnego::NegotiationToken as Wire>::parse(&b)),
        &bytes,
        &[Ok(init), Ok(response)],
    );
    truncated(spnego::Frames::new, bytes.get(..first_len - 1).unwrap());
    refused(
        spnego::Frames::new,
        &[0x60, 0x83, 1, 0, 0],
        spnego::Error::TooLong,
    );
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
    truncated(x509::PemBlocks::new, bytes.get(..cut).unwrap());
    refused(
        || x509::PemBlocks::with_limit(32),
        &bytes,
        x509::Error::TooLong,
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
    truncated(x509::PemBlocks::new, b"-----BEGIN TEST-----\nAQID");
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
    refused(
        || x509::PemBlocks::with_limit(limit - 1),
        text.as_bytes(),
        x509::Error::TooLong,
    );

    let mut line = vec![b'#'; x509::MAX_PEM_LINE];
    round_trip(|| x509::PemBlocks::with_limit(0), &line, &[]);
    line.push(b'\n');
    round_trip(|| x509::PemBlocks::with_limit(0), &line, &[]);
    *line.last_mut().unwrap() = b'#';
    refused(
        || x509::PemBlocks::with_limit(0),
        &line,
        x509::Error::TooLong,
    );
    line.push(b'\n');
    refused(
        || x509::PemBlocks::with_limit(0),
        &line,
        x509::Error::TooLong,
    );
    Ok(())
}

#[test]
fn frame_limits_refuse_lengths_before_bodies() {
    for limit in [0, 1, 2, 15, 16, 32] {
        refused(
            || ocsp::Frames::with_limit(limit),
            &[0x30, 0x81, 0x80],
            ocsp::Error::TooLong,
        );
        refused(
            || spnego::Frames::with_limit(limit),
            &[0xa1, 0x81, 0x80],
            spnego::Error::TooLong,
        );
        refused(
            || kerberos::Frames::with_limit(limit),
            &[0, 0, 0, 128],
            kerberos::Error::LengthTooLong(128),
        );
        assert_eq!(ocsp::Frames::with_limit(limit).capacity(), limit.max(16));
        assert_eq!(spnego::Frames::with_limit(limit).capacity(), limit.max(16));
        assert_eq!(kerberos::Frames::with_limit(limit).capacity(), limit + 4);
    }
    refused(
        || ocsp::Frames::with_limit(0),
        &[0x30, 0],
        ocsp::Error::TooLong,
    );
    refused(
        || spnego::Frames::with_limit(0),
        &[0xa1, 0],
        spnego::Error::TooLong,
    );
    round_trip(|| ocsp::Frames::with_limit(2), &[0x30, 0], &[vec![0x30, 0]]);
    round_trip(
        || spnego::Frames::with_limit(2),
        &[0xa1, 0],
        &[vec![0xa1, 0]],
    );
    round_trip(|| kerberos::Frames::with_limit(0), &[0, 0, 0, 0], &[vec![]]);
    round_trip(
        || kerberos::Frames::with_limit(1),
        &[0, 0, 0, 1, 42],
        &[vec![42]],
    );
    assert_eq!(
        ocsp::Frames::with_limit(usize::MAX).limit(),
        ocsp::MAX_MESSAGE
    );
    assert_eq!(
        spnego::Frames::with_limit(usize::MAX).limit(),
        spnego::MAX_TOKEN
    );
    assert_eq!(
        kerberos::Frames::with_limit(usize::MAX).limit(),
        kerberos::MAX_MESSAGE
    );
    assert_eq!(ocsp::Frames::default().limit(), ocsp::MAX_MESSAGE);
    assert_eq!(spnego::Frames::default().limit(), spnego::MAX_TOKEN);
    assert_eq!(kerberos::Frames::default().limit(), kerberos::MAX_MESSAGE);
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
        || kerberos::Frames::new().map(|b| <kerberos::Message as Wire>::parse(&b)),
        &both,
        &[Ok(message.clone()), Ok(message)],
    );
    truncated(kerberos::Frames::new, bytes.get(..bytes.len() - 1).unwrap());
    let length = kerberos::MAX_MESSAGE as u32 + 1;
    refused(
        kerberos::Frames::new,
        &length.to_be_bytes(),
        kerberos::Error::LengthTooLong(length),
    );
    Ok(())
}
