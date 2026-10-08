//! ASN.1 framing and its LDAP, OCSP, SPNEGO, PEM, and Kerberos consumers.

use fictionet::stdlib::codec::Frames;
use core::fmt::Debug;
use fictionet::stdlib::codec::{
    Decode, Fail, Stream, Wire, finish, pump,
};
use fictionet::stdlib::test_support::contract;
use fictionet::stdlib::{asn1, kerberos, ldap, ocsp, spnego, x509};

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
        contract::check_decode(|| asn1::Elements::new(asn1::Rules::Der), &[0x04, 0x83, 0x10, 0, 0]),
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
    contract::check_truncated(ocsp::Frames::new, &bytes);
    assert_eq!(
        contract::check_decode(ocsp::Frames::new, &[0x30, 0x83, 1, 0, 0]),
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
        || spnego::Frames::new().map(|b| <spnego::NegotiationToken as Wire>::parse(&b)),
        &bytes,
        &[Ok(init), Ok(response)],
    );
    contract::check_truncated(spnego::Frames::new, &bytes[..first_len]);
    assert_eq!(
        contract::check_decode(spnego::Frames::new, &[0x60, 0x83, 1, 0, 0]),
        (vec![], Some(Fail::Protocol(spnego::Error::TooLong)))
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
    let (items, failure) = contract::check_decode(x509::PemBlocks::new, b"-----BEGIN TEST-----\nAQID");
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
            contract::check_decode(|| ocsp::Frames::with_limit(limit), &[0x30, 0x81, 0x80]),
            (vec![], Some(Fail::Protocol(ocsp::Error::TooLong)))
        );
        assert_eq!(
            contract::check_decode(|| spnego::Frames::with_limit(limit), &[0xa1, 0x81, 0x80]),
            (vec![], Some(Fail::Protocol(spnego::Error::TooLong)))
        );
        assert_eq!(
            contract::check_decode(|| kerberos::Frames::with_limit(limit), &[0, 0, 0, 128]),
            (vec![], Some(Fail::Protocol(kerberos::Error::LengthTooLong(128))))
        );
        assert_eq!(ocsp::Frames::with_limit(limit).capacity(), limit.max(16));
        assert_eq!(spnego::Frames::with_limit(limit).capacity(), limit.max(16));
        assert_eq!(kerberos::Frames::with_limit(limit).capacity(), limit + 4);
    }
    assert_eq!(
        contract::check_decode(|| ocsp::Frames::with_limit(0), &[0x30, 0]),
        (vec![], Some(Fail::Protocol(ocsp::Error::TooLong)))
    );
    assert_eq!(
        contract::check_decode(|| spnego::Frames::with_limit(0), &[0xa1, 0]),
        (vec![], Some(Fail::Protocol(spnego::Error::TooLong)))
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
    contract::check_truncated(kerberos::Frames::new, &bytes);
    let length = kerberos::MAX_MESSAGE as u32 + 1;
    assert_eq!(
        contract::check_decode(kerberos::Frames::new, &length.to_be_bytes()),
        (vec![], Some(Fail::Protocol(kerberos::Error::LengthTooLong(length))))
    );
    Ok(())
}
