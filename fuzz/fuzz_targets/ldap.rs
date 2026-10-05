//! LDAP messages, search filters and distinguished names, as a world
//! playing a directory server reads them.
#![no_main]

use fictionet::stdlib::ldap::{Decoder, Dn, Error, Filter, Message, Op};
use libfuzzer_sys::fuzz_target;

/// Every message a decoder gives, and the error it stops at.
fn decode(chunks: &mut dyn Iterator<Item = &[u8]>) -> (Vec<Message>, Option<Error>) {
    let mut d = Decoder::new();
    let mut out = Vec::new();
    for c in chunks {
        d.feed(c);
        while let Some(r) = d.next_message() {
            match r {
                Ok(m) => out.push(m),
                Err(e) => return (out, Some(e)),
            }
        }
    }
    (out, None)
}

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let whole = decode(&mut std::iter::once(data));
    let bytewise = decode(&mut data.chunks(1));
    assert_eq!(whole, bytewise);

    // A message read can be written, and reads back the same.
    for m in &whole.0 {
        let bytes = m.to_bytes().unwrap();
        assert_eq!(Message::parse(&bytes).as_ref(), Ok(m));
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
});
