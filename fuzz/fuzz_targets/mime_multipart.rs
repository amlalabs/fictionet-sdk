//! MIME multipart bodies, as a world playing a web server reads uploaded
//! forms.
#![no_main]
#![allow(deprecated)] // This target also checks the compatibility API.

use fictionet::stdlib::codec::contract;
use fictionet::stdlib::mime_multipart::{Headers, Multipart, ParamValue, Parser, Part, boundary, valid_boundary};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first byte picks how many of the next bytes are the boundary.
    // If they are not a valid one, the boundary is "a".
    let (bnd, data) = match data.split_first() {
        Some((&n, rest)) => {
            let len = usize::from(n % 8);
            match rest.get(..len).and_then(|b| std::str::from_utf8(b).ok()) {
                Some(b) if valid_boundary(b) => (b.to_string(), &rest[len..]),
                _ => ("a".to_string(), rest),
            }
        }
        None => ("a".to_string(), data),
    };

    contract::check_decode(
        || fictionet::stdlib::mime_multipart::Parts::new(&bnd).unwrap(),
        data,
    );
    contract::check_wire::<Part>(data);
    // The body, read all at once and a byte at a time.
    let whole = Multipart::parse(data, &bnd);
    let mut bytewise = Multipart::default();
    let mut parser = Parser::new(&bnd).unwrap();
    let mut failed = None;
    'feed: for b in data {
        parser.feed(std::slice::from_ref(b));
        while let Some(e) = parser.next_event() {
            match e {
                Ok(e) => bytewise.push_event(e),
                Err(e) => {
                    failed = Some(e);
                    break 'feed;
                }
            }
        }
    }
    if failed.is_none() {
        parser.finish();
        while let Some(e) = parser.next_event() {
            match e {
                Ok(e) => bytewise.push_event(e),
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
    }
    match failed {
        Some(e) => assert_eq!(whole, Err(e)),
        None => assert_eq!(whole.as_ref(), Ok(&bytewise)),
    }

    if let Ok(m) = &whole {
        // A body read can always be written, with a boundary that is
        // free, and reads back the same.
        let (b, bytes) = m.write(&bnd).expect("a parsed body writes again");
        assert_eq!(Multipart::parse(&bytes, &b).as_ref(), Ok(m));
        for p in &m.parts {
            contract::check_wire_value(p);
            let _ = (p.name(), p.filename(), p.headers.content_type(), p.headers.get_one("x"));
            let _ = p.headers.get_all("content-type").count();
        }
    }

    // Any text as a header field: split at the first colon into name and
    // value. A writer either refuses the field or writes a body that
    // reads back the same, whatever the boundary.
    let text = String::from_utf8_lossy(data);
    if let Some((name, value)) = text.split_once(':') {
        let m = Multipart {
            parts: vec![Part { headers: Headers { fields: vec![(name.into(), value.into())] }, body: Vec::new() }],
            ..Multipart::default()
        };
        for p in &m.parts {
            contract::check_wire_value(p);
        }
        if let Ok((b, bytes)) = m.write(&bnd) {
            assert_eq!(Multipart::parse(&bytes, &b).as_ref(), Ok(&m));
        }
    }

    // Any text as a header value with parameters.
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(v) = ParamValue::parse(s) {
            if let Some(h) = v.to_header() {
                assert_eq!(ParamValue::parse(&h), Some(v));
            }
        }
        if let Some(b) = boundary(s) {
            assert!(valid_boundary(&b));
        }
    }
});
