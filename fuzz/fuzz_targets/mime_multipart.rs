//! Multipart body framing, MIME entities, parts, and parameterized headers.
#![no_main]

use fictionet::stdlib::codec::{Decode, Fail, Wire};
use fictionet::stdlib::test_support::contract;

use fictionet::stdlib::protocols::mime_multipart::{
    Body, Entity, Error, Headers, MAX_BOUNDARY, MAX_ENTITY, MAX_HEADER_BYTES, Multipart,
    ParamValue, Part, Parts, boundary, valid_boundary,
};
use fictionet::stdlib::test_support::decode_all;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let (&n, rest) = input.split_first().unwrap_or((&0, input));
    // Keep every existing corpus selector's meaning, and also try all valid lengths.
    check(rest, usize::from(n % 8));
    check(rest, usize::from(n) % MAX_BOUNDARY + 1);
});

fn check(input: &[u8], len: usize) {
    let (bnd, data) = match input.get(..len).and_then(|b| std::str::from_utf8(b).ok()) {
        Some(b) if valid_boundary(b) => (b.to_string(), &input[len..]),
        _ => ("a".to_string(), input),
    };
    let make = || Parts::new(&bnd).unwrap();
    contract::check_decode_with_alloc_limit(make, data, 2 * make().capacity());
    contract::check_wire::<Part>(data);
    contract::check_wire::<Entity>(data);
    contract::check_wire::<Body>(data);
    contract::check_wire::<ParamValue>(data);
    let (parts, error) = decode_all(make, data);
    for part in &parts {
        contract::check_wire_value(part);
        let _ = (
            part.name(),
            part.filename(),
            part.headers.content_type(),
            part.headers.get_one("x"),
        );
        let _ = part.headers.get_all("content-type").count();
    }
    match Multipart::parse(data, &bnd) {
        Ok(multipart) => {
            assert_eq!(error, None);
            assert_eq!(parts, multipart.parts);
            // Leave room for a longer free boundary, header spaces, and the MIME header.
            if data.len() < MAX_ENTITY / 2 {
                let entity = multipart
                    .with_free_boundary(&bnd)
                    .expect("a parsed body picks a boundary");
                let bytes = entity.to_bytes().expect("a parsed body writes again");
                assert_eq!(Entity::parse(&bytes).as_ref(), Ok(&entity));
                contract::check_wire_value(&entity);
                contract::check_wire_value(&Body {
                    boundary: entity.boundary,
                    multipart: entity.multipart,
                });
            }
        }
        // Parts has no aggregate body cap.
        Err(Error::EntityTooLong) if data.len() > MAX_ENTITY => {}
        Err(expected) if !data.is_empty() => match error {
            Some(Fail::Protocol(error)) => assert_eq!(error, expected),
            Some(Fail::Truncated { .. }) => assert_eq!(expected, Error::Truncated),
            other => panic!("{other:?}"),
        },
        Err(_) => assert!(data.is_empty()),
    }
    let text = String::from_utf8_lossy(data);
    if let Some((name, value)) = text.split_once(':') {
        let multipart = Multipart {
            parts: vec![Part {
                headers: Headers {
                    fields: vec![(name.into(), value.into())],
                },
                body: Vec::new(),
            }],
            ..Multipart::default()
        };
        contract::check_wire_value(&multipart.parts[0]);
        if let Ok(entity) = multipart.with_free_boundary(&bnd) {
            contract::check_wire_value(&entity);
        }
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let headers = Headers {
            fields: vec![
                ("Content-Type".into(), text.into()),
                ("Content-Disposition".into(), text.into()),
            ],
        };
        let disposition = headers.content_disposition();
        if text.contains(['\r', '\n']) || text.len() > MAX_HEADER_BYTES {
            assert_eq!(headers.content_type(), None);
            assert_eq!(disposition, None);
        }
        if let Some(bnd) = boundary(text) {
            assert!(valid_boundary(&bnd));
            assert!(headers.content_type().is_some());
        }
        if data.len() <= MAX_HEADER_BYTES {
            let comment = text
                .replace('\\', "\\\\")
                .replace('(', "\\(")
                .replace(')', "\\)");
            let value = format!("multipart/mixed; boundary=b ({comment})");
            let headers = Headers {
                fields: vec![("Content-Type".into(), value.clone())],
            };
            let expect_ok = !text.contains(['\r', '\n']) && value.len() <= MAX_HEADER_BYTES;
            if expect_ok {
                assert_eq!(boundary(&value).as_deref(), Some("b"));
                let ct = headers.content_type().expect("a valid MIME comment");
                assert_eq!(ct.value, "multipart/mixed");
                assert_eq!(ct.params.len(), 1);
                assert_eq!(ct.get("boundary"), Some("b"));
            } else {
                assert_eq!(boundary(&value), None);
                assert_eq!(headers.content_type(), None);
            }
            let input = format!("Content-Type: {value}\r\n\r\n--b--");
            if text.contains(['\r', '\n']) {
                // The entity parser can accept CRLF followed by folding whitespace.
                contract::check_wire::<Entity>(input.as_bytes());
            } else if value.len() + 18 <= MAX_HEADER_BYTES {
                // The field name, separator and empty line also count toward the cap.
                assert_eq!(
                    Entity::parse(input.as_bytes()),
                    Ok(Multipart::default().with_boundary("b"))
                );
            } else {
                assert_eq!(Entity::parse(input.as_bytes()), Err(Error::HeaderTooLong));
            }
        }
    }
}
