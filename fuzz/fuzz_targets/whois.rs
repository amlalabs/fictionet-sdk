//! WHOIS queries, as a world playing a server reads them, responses and
//! their fields, as a world playing a client reads them, and values a
//! world builds, as it writes them.
#![no_main]

use arbitrary::{Result, Unstructured};
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::whois::{
    CollectedResponses, Field, MAX_QUERY, MAX_RESPONSE, Queries, Query, RESPONSE_WINDOW, Referral,
    ReferralKind, Response, find_referral, parse_fields,
};
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};
use libfuzzer_sys::fuzz_target;

/// Values a world builds: whatever a writer accepts reads back the same.
fn built(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let text: String = u.arbitrary()?;
    if let Ok(q) = Query::new(&text) {
        assert_eq!(decode_all(Queries::new, &q.to_bytes().unwrap()).0, [Ok(q)]);
    }
    let n = u.int_in_range(0..=8usize)?;
    let mut fields = Vec::new();
    let mut block = 0usize;
    for i in 0..n {
        if i > 0 && u.arbitrary()? {
            block += 1;
        }
        fields.push(Field {
            block,
            key: u.arbitrary()?,
            value: u.arbitrary()?,
        });
    }
    if let Ok(response) = Response::from_fields(&fields) {
        let _ = assert_write(&response);
        assert!(response.as_bytes().len() <= MAX_RESPONSE);
        assert_eq!(response.fields().unwrap(), fields);
    }
    let kind = *u.choose(&[
        ReferralKind::Refer,
        ReferralKind::RegistrarWhoisServer,
        ReferralKind::ReferralServer,
    ])?;
    let referral = Referral {
        kind,
        host: u.arbitrary()?,
        port: u.arbitrary()?,
    };
    if let Ok(f) = referral.to_field(0) {
        assert_eq!(Referral::from_field(&f), Some(referral));
    }
    // An IPv6 address, written in brackets, reads back the same.
    let ip: std::net::Ipv6Addr = u.arbitrary()?;
    let referral = Referral {
        kind,
        host: ip.to_string(),
        port: u.arbitrary()?,
    };
    if let Ok(f) = referral.to_field(0) {
        assert_eq!(Referral::from_field(&f), Some(referral));
    } else {
        assert_eq!(referral.port, 0);
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let bound = 2 * (MAX_QUERY + 2);
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Queries::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= bound);
            }
        ),
        decode_all(Queries::new, data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(CollectedResponses::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * RESPONSE_WINDOW);
                assert!(s.held() <= MAX_RESPONSE);
            }
        ),
        decode_all(CollectedResponses::new, data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(CollectedResponses::with_limit(17)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * RESPONSE_WINDOW);
                assert!(s.held() <= 17);
            }
        ),
        decode_all(|| CollectedResponses::with_limit(17), data),
    );
    if let Ok(value) = <Query as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Response as Wire>::parse(data) {
        let _ = assert_write(&value);
    }

    for query in decode_all(Queries::new, data).0.iter().flatten() {
        let _ = assert_write(query);
        assert_eq!(Query::parse(&query.to_bytes().unwrap()).as_ref(), Ok(query));
    }

    let (responses, failure) = decode_all(CollectedResponses::new, data);
    assert_eq!(failure, None);
    assert_eq!(responses.len(), 1);
    let collected = &responses[0];
    let response = &collected.response;
    let _ = assert_write(response);
    assert_eq!(response.as_bytes(), &data[..data.len().min(MAX_RESPONSE)]);
    assert_eq!(collected.truncated, data.len() > MAX_RESPONSE);
    if let Ok(fields) = response.fields() {
        if let Ok(built) = Response::from_fields(&fields) {
            let _ = assert_write(&built);
            assert_eq!(built.fields().unwrap(), fields);
        }
        for field in &fields {
            if let Some(referral) = Referral::from_field(field) {
                assert_eq!(
                    Referral::from_field(&referral.to_field(field.block).unwrap()),
                    Some(referral)
                );
            }
        }
        assert_eq!(response.referral(), find_referral(&fields));
    }
    if let Ok(text) = std::str::from_utf8(data)
        && !collected.truncated
    {
        assert_eq!(parse_fields(text), response.fields());
    }
    let _ = built(data);
});
