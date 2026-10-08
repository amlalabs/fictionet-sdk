//! LDAP messages, search filters and distinguished names, as a world
//! playing a directory server reads them.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{Stream, Wire, finish, pump};
use fictionet::stdlib::ldap::{
    DerefAliases, Dn, Error, Filter, MAX_TEXT, Message, Op, Scope, SearchRequest,
};
use fictionet::stdlib::test_support::contract;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode(Frames::<Message>::new, data);
    contract::check_decode(|| Frames::<Message>::with_limit(64), data);
    contract::check_wire::<Message>(data);

    let mut stream = Stream::new(Frames::<Message>::new());
    let mut messages = Vec::new();
    let _ = pump(&mut stream, data, |m| messages.push(m));
    let _ = finish(&mut stream, |m| messages.push(m));
    let mut low = Stream::new(Frames::<Message>::with_limit(64));
    let mut smaller = Vec::new();
    let _ = pump(&mut low, data, |m| smaller.push(m));
    let _ = finish(&mut low, |m| smaller.push(m));
    assert!(messages.starts_with(&smaller));

    // A message read can be written, reads back the same, and is written
    // the same again.
    for m in &messages {
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
    contract::check_wire_value(&search);
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
