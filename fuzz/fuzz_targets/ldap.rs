//! LDAP messages, search filters and distinguished names, as a world
//! playing a directory server reads them.
#![no_main]

use fictionet::stdlib::ldap::{
    Decoder, DerefAliases, Dn, Error, Filter, MAX_TEXT, Message, Op, Scope, SearchRequest,
};
use libfuzzer_sys::fuzz_target;

/// Every message a decoder with `limit` gives, and the error it stops at.
/// Each chunk is fed until the decoder has taken all of it.
fn decode(chunks: &mut dyn Iterator<Item = &[u8]>, limit: usize) -> (Vec<Message>, Option<Error>) {
    let mut d = Decoder::with_limit(limit);
    let mut out = Vec::new();
    for mut c in chunks {
        loop {
            let n = d.feed(c);
            c = &c[n..];
            // It never holds more than its limit, or 16 bytes for a header.
            assert!(d.buffered() <= d.limit().max(16));
            while let Some(r) = d.next_message() {
                match r {
                    Ok(m) => out.push(m),
                    Err(e) => return (out, Some(e)),
                }
            }
            if c.is_empty() {
                break;
            }
            // It takes nothing only while it holds a message to take out.
            assert!(n > 0 || d.buffered() == 0);
        }
    }
    (out, None)
}

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let whole = decode(&mut std::iter::once(data), usize::MAX);
    let bytewise = decode(&mut data.chunks(1), usize::MAX);
    assert_eq!(whole, bytewise);
    // A low limit gives the same messages up to the first too long.
    let low = decode(&mut std::iter::once(data), 64);
    assert!(whole.0.starts_with(&low.0));

    // A message read can be written, reads back the same, and is written
    // the same again.
    for m in &whole.0 {
        let bytes = m.to_bytes().unwrap();
        assert_eq!(Message::parse(&bytes).as_ref(), Ok(m));
        assert_eq!(Message::parse(&bytes).unwrap().to_bytes().unwrap(), bytes);
    }
    // Any bytes as a CLDAP datagram.
    if let Ok(m) = Message::parse(data) {
        let bytes = m.to_bytes().unwrap();
        assert!(bytes.len() <= data.len());
        assert_eq!(Message::parse(&bytes).as_ref(), Ok(&m));
        // A search filter with a text form reads back from it.
        if let Op::SearchRequest(s) = &m.op {
            if let Ok(t) = s.filter.to_text() {
                assert_eq!(Filter::parse_text(&t).as_ref(), Ok(&s.filter));
            }
        }
    }
    if let Ok(list) = Message::parse_datagram(data) {
        assert!(!list.is_empty());
        let mut bytes = Vec::new();
        for m in &list {
            bytes.extend_from_slice(&m.to_bytes().unwrap());
        }
        assert!(bytes.len() <= data.len());
        assert_eq!(Message::parse_datagram(&bytes), Ok(list));
    }
    // Any text as a filter and as a DN.
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(f) = Filter::parse_text(text) {
            let t = f.to_text().unwrap();
            assert_eq!(Filter::parse_text(&t), Ok(f));
        }
        if let Ok(dn) = Dn::parse(text) {
            let t = dn.to_text().unwrap();
            assert_eq!(Dn::parse(&t), Ok(dn));
        }
    }
    // Values made from the bytes, not read: written and read back as
    // themselves, or refused.
    let code = data.first().map_or(0, |&b| u32::from(b % 6));
    let value = data.get(1..).unwrap_or_default().to_vec();
    let search = Message {
        id: 1,
        op: Op::SearchRequest(SearchRequest {
            base: String::new(),
            scope: Scope::Other(code),
            deref: DerefAliases::Never,
            size_limit: 0,
            time_limit: 0,
            types_only: false,
            filter: Filter::Equal {
                attribute: "cn".into(),
                value,
            },
            attributes: Vec::new(),
        }),
        controls: Vec::new(),
    };
    if let Ok(bytes) = search.to_bytes() {
        assert_eq!(Message::parse(&bytes).as_ref(), Ok(&search));
    }
    if let Op::SearchRequest(s) = &search.op {
        match s.filter.to_text() {
            Ok(t) => {
                assert!(t.len() <= MAX_TEXT);
                assert_eq!(Filter::parse_text(&t).as_ref(), Ok(&s.filter));
            }
            Err(e) => assert_eq!(e, Error::TextTooLong),
        }
    }
});
