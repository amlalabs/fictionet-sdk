//! MIME multipart bodies, as a world playing a web server reads uploaded
//! forms.
#![no_main]

use fictionet::stdlib::mime_multipart::{Multipart, ParamValue, Parser, boundary};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The body, read all at once and a byte at a time.
    let whole = Multipart::parse(data, "a");
    let mut bytewise = Multipart::default();
    let mut parser = Parser::new("a").unwrap();
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
        // A body read can be written, with a boundary that is free, and
        // reads back the same.
        if let Ok((b, bytes)) = m.write("a") {
            assert_eq!(Multipart::parse(&bytes, &b).as_ref(), Ok(m));
        }
        for p in &m.parts {
            let _ = (p.name(), p.filename(), p.headers.content_type(), p.headers.get_one("x"));
            let _ = p.headers.get_all("content-type").count();
        }
    }
    // Any text as a header value with parameters.
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(v) = ParamValue::parse(s) {
            if let Some(h) = v.to_header() {
                assert_eq!(ParamValue::parse(&h), Some(v));
            }
        }
        let _ = boundary(s);
    }
});
