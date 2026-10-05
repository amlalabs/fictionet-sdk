//! WHOIS queries, as a world playing a server reads them, responses and
//! their fields, as a world playing a client reads them, and values a
//! world builds, as it writes them.
#![no_main]

use arbitrary::{Result, Unstructured};
use fictionet::stdlib::whois::{
    Field, MAX_BUFFERED, MAX_RESPONSE, Query, QueryDecoder, QueryError, Referral, ReferralKind,
    Response, ResponseDecoder, find_referral, parse_fields, write_fields,
};
use libfuzzer_sys::fuzz_target;

/// Feeds `data` in chunks of `size` bytes, taking queries out after each
/// feed, as a server does. Every query line, read or refused.
fn split(data: &[u8], size: usize) -> Vec<std::result::Result<Query, QueryError>> {
    let mut decoder = QueryDecoder::new();
    let mut out = Vec::new();
    for chunk in data.chunks(size.max(1)) {
        let mut rest = chunk;
        while !rest.is_empty() {
            let took = decoder.feed(rest);
            assert!(decoder.buffered() <= MAX_BUFFERED);
            rest = &rest[took..];
            let mut progress = took > 0;
            while let Some(q) = decoder.next_query() {
                out.push(q);
                progress = true;
            }
            // A full decoder always gives a query or an error.
            assert!(progress);
        }
    }
    out
}

/// A response read all at once or a byte at a time.
fn response(data: &[u8], bytewise: bool) -> (Response, bool) {
    let mut decoder = ResponseDecoder::new();
    if bytewise {
        for b in data.chunks(1) {
            decoder.feed(b);
        }
    } else {
        decoder.feed(data);
    }
    assert!(decoder.buffered() <= MAX_RESPONSE);
    let truncated = decoder.truncated();
    (decoder.finish(), truncated)
}

/// Values a world builds: whatever a writer accepts reads back the same.
fn built(data: &[u8]) -> Result<()> {
    let mut u = Unstructured::new(data);
    let text: String = u.arbitrary()?;
    if let Ok(q) = Query::new(&text) {
        assert_eq!(split(&q.to_bytes(), usize::MAX), [Ok(q)]);
    }
    let flags: Vec<&str> = u.arbitrary()?;
    let terms: &str = u.arbitrary()?;
    if let Ok(q) = Query::build(&flags, terms) {
        // The flags and terms read back as given.
        let words: Vec<&str> =
            q.flags().iter().flat_map(|f| std::iter::once(f.name).chain(f.argument)).collect();
        assert_eq!(words, flags);
        assert_eq!(q.terms(), terms.trim_matches([' ', '\t']));
        assert_eq!(split(&q.to_bytes(), usize::MAX), [Ok(q)]);
    }
    let n = u.int_in_range(0..=8usize)?;
    let mut fields = Vec::new();
    let mut block = 0usize;
    for i in 0..n {
        if i > 0 && u.arbitrary()? {
            block += 1;
        }
        fields.push(Field { block, key: u.arbitrary()?, value: u.arbitrary()? });
    }
    if let Ok(text) = write_fields(&fields) {
        assert_eq!(parse_fields(&text).unwrap(), fields);
        let resp = Response::from_fields(&fields).unwrap();
        assert_eq!(resp.fields().unwrap(), fields);
    }
    let kind = *u.choose(&[
        ReferralKind::Refer,
        ReferralKind::RegistrarWhoisServer,
        ReferralKind::ReferralServer,
    ])?;
    let referral = Referral { kind, host: u.arbitrary()?, port: u.arbitrary()? };
    if let Ok(f) = referral.to_field(0) {
        assert_eq!(Referral::from_field(&f), Some(referral));
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Queries, split three ways: all at once, a byte at a time, and in
    // chunks of a size the input picks. All give the same queries and the
    // same errors.
    let queries = split(data, usize::MAX);
    assert_eq!(split(data, 1), queries);
    let size = 1 + usize::from(data.first().copied().unwrap_or(0)) * 7;
    assert_eq!(split(data, size), queries);
    for q in queries.iter().flatten() {
        // A query read can be written, and reads back the same.
        let bytes = q.to_bytes();
        assert_eq!(Query::parse_line(&bytes[..bytes.len() - 2]).as_ref(), Ok(q));
        let _ = (q.flags(), q.terms());
    }

    // The response, read both ways, is the same.
    let (resp, truncated) = response(data, false);
    assert_eq!(response(data, true), (resp.clone(), truncated));
    if let Ok(fields) = resp.fields() {
        // Fields read can be written back if the writer takes them, and
        // read back the same.
        if let Ok(text) = write_fields(&fields) {
            assert_eq!(parse_fields(&text).unwrap(), fields);
        }
        for f in &fields {
            if let Some(r) = Referral::from_field(f) {
                assert_eq!(Referral::from_field(&r.to_field(f.block).unwrap()), Some(r));
            }
        }
        assert_eq!(resp.referral(), find_referral(&fields));
    }
    let _ = built(data);
});
