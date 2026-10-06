//! IPP heads, documents, and attribute values.
#![no_main]

use fictionet::stdlib::codec::{Decode, Step, Wire, contract};
use fictionet::stdlib::ipp::{
    Attribute, Error, Head, Header, MAX_DOCUMENT, MAX_FIELD, MAX_HEAD, Message, Value, tag,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Head::new, data, 2 * MAX_HEAD);
    contract::check_decode_with_alloc_limit(|| Head::with_limit(64), data, 128);
    contract::check_wire::<Header>(data);
    contract::check_wire::<Message>(data);
    let mut decoder = Head::new();
    let result = decoder.decode(data, false);
    let id = data
        .first_chunk::<8>()
        .map(|h| u32::from_be_bytes([h[4], h[5], h[6], h[7]]));
    if let Ok(Step::Item(ref head, _)) = result {
        let request_id = match head {
            Ok(header) => header.request_id,
            Err(error) => error.request_id,
        };
        assert_eq!(Some(request_id), id);
    }
    if let Ok(Step::Item(Ok(header), used)) = result {
        contract::check_wire_value(&header);
        if data.len() - used <= MAX_DOCUMENT {
            let message = header.with_document(data[used..].to_vec());
            contract::check_wire_value(&message);
            assert_eq!(Message::parse(data), Ok(message));
        } else {
            assert_eq!(Message::parse(data), Err(Error::DocumentTooLong));
        }
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
