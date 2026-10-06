//! IPP heads, documents, and attribute values.
#![no_main]

use fictionet::stdlib::codec::{
    Decode, Fail, Step, Stream, Wire, contract, test_support::decode_all,
};
use fictionet::stdlib::ipp::{
    Attribute, Error, Head, HeadError, Header, MAX_DOCUMENT, MAX_FIELD, MAX_HEAD, Message,
    ParseError, Value, tag,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Head::new, data, 2 * MAX_HEAD);
    contract::check_decode_with_alloc_limit(|| Head::with_limit(64), data, 128);
    contract::check_wire::<Header>(data);
    contract::check_wire::<Message>(data);
    let (items, failure) = decode_all(Head::new, data);
    match Message::parse(data) {
        Ok(message) => {
            assert_eq!((items, failure), (vec![Ok(Header::from(message))], None));
        }
        Err(ParseError::DocumentTooLong) => {
            let Ok(Step::Item(Ok(header), used)) = Head::new().decode(data, false) else {
                panic!("document limit without a complete head");
            };
            assert!(data.len() - used > MAX_DOCUMENT);
            assert_eq!((items, failure), (vec![Ok(header)], None));
        }
        Err(ParseError::Truncated) => {
            assert!(items.is_empty());
            assert_eq!(
                failure,
                (!data.is_empty()).then_some(Fail::Truncated { unread: data.len() })
            );
        }
        Err(ParseError::Head(error @ (Error::Length(_) | Error::TooLong))) => {
            assert!(items.is_empty());
            assert_eq!(failure, Some(Fail::Protocol(error)));
        }
        Err(ParseError::Head(error)) => {
            let fixed = data.first_chunk::<8>().unwrap();
            let request_id = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
            assert_eq!(
                (items, failure),
                (vec![Err(HeadError { request_id, error })], None)
            );
        }
        Err(ParseError::Trailing) => panic!("a message includes its document"),
    }
    let mut stream = Stream::new(Head::new());
    let _ = stream.push(data);
    stream.end();
    let item = stream.next();
    if let Some(fixed) = data.first_chunk::<8>() {
        let expected = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let request_id = match item {
            Some(Ok(Ok(header))) => {
                let b = header.to_bytes().unwrap();
                assert_eq!(Header::parse(&b), Ok(header.clone()));
                contract::check_wire::<Header>(&b);
                header.request_id
            }
            Some(Ok(Err(error))) => error.request_id,
            _ => {
                let fixed = stream.unread().first_chunk::<8>().unwrap();
                u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]])
            }
        };
        assert_eq!(request_id, expected);
    }
    let mut message = Message::request(2, 7);
    message.add(
        tag::JOB_ATTRIBUTES,
        Attribute::new(
            "document",
            Value::OctetString(data.get(..MAX_FIELD + 1).unwrap_or(data).to_vec()),
        ),
    );
    contract::check_wire_value(&message);
    let built = Header::from(message);
    contract::check_wire_value(&built);
    let mut body = Header {
        version: (1, 1),
        code: 2,
        request_id: 7,
        groups: vec![],
    }
    .to_bytes()
    .unwrap();
    body.extend_from_slice(data.get(..4096).unwrap_or(data));
    contract::check_decode_with_alloc_limit(|| Head::with_limit(64), &body, 128);
});
