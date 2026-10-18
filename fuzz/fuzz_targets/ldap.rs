//! LDAP messages, search filters and distinguished names, as a world
//! playing a directory server reads them.
#![no_main]

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::ldap::{
    DerefAliases, Error, Filter, MAX_TEXT, Message, Op, Scope, SearchRequest, harness,
};
use fictionet::stdlib::test_support::contract;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    harness::check_bytes(data);
    if let Ok(text) = std::str::from_utf8(data) {
        harness::check_text(text);
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
