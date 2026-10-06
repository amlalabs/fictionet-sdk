//! Internet Message Format headers and structured field values.
#![no_main]

use fictionet::stdlib::codec::{Wire, contract, test_support::decode_all};
use fictionet::stdlib::imf::{
    Address, AddressList, DateTime, ENCODED_LINE_LEN, EncodedText, Error, Head, Header,
    MAX_HEADER_BYTES, Mailbox, MessageId, MessageIds, decode_text, parse_address_list,
    parse_message_ids, split_message,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Head::new, data, 2 * MAX_HEADER_BYTES);
    contract::check_decode_with_alloc_limit(|| Head::with_limit(64), data, 128);
    contract::check_wire::<Header>(data);
    let (items, failure) = decode_all(Head::new, data);
    if !data.is_empty() && failure.is_none() {
        assert_eq!(items, vec![split_message(data).map(|(header, _)| header)]);
    }
    let mut values = vec![String::from_utf8_lossy(data).into_owned()];
    if let Ok((header, _)) = split_message(data) {
        contract::check_wire_value(&header);
        values.extend(header.fields.into_iter().map(|field| field.value));
    }
    for text in values {
        contract::check_wire::<Mailbox>(text.as_bytes());
        contract::check_wire::<Address>(text.as_bytes());
        contract::check_wire::<AddressList>(text.as_bytes());
        contract::check_wire::<DateTime>(text.as_bytes());
        contract::check_wire::<MessageId>(text.as_bytes());
        contract::check_wire::<MessageIds>(text.as_bytes());
        contract::check_wire::<EncodedText>(text.as_bytes());
        let value = EncodedText(text.clone());
        contract::check_wire_value(&value);
        match value.to_bytes() {
            Ok(bytes) => {
                let encoded = String::from_utf8(bytes).unwrap();
                assert_eq!(decode_text(&encoded), text);
                let mut header = Header::default();
                header.push("Subject", &encoded);
                contract::check_wire_value(&header);
                if let Ok(bytes) = header.to_bytes() {
                    assert!(
                        bytes
                            .split(|&c| c == b'\n')
                            .all(|line| line.len() <= ENCODED_LINE_LEN + 1)
                    );
                }
            }
            Err(error) => assert_eq!(error, Error::Unwritable),
        }
        if let Ok(list) = parse_address_list(&text) {
            contract::check_wire_value(&AddressList(list));
        }
        if let Ok(ids) = parse_message_ids(&text) {
            contract::check_wire_value(&MessageIds(ids));
        }
        let mut header = Header::default();
        header.push("Subject", &text);
        contract::check_wire_value(&header);
    }
    let mut body = Header::default().to_bytes().unwrap();
    body.extend_from_slice(data.get(..4096).unwrap_or(data));
    contract::check_decode_with_alloc_limit(|| Head::with_limit(64), &body, 128);
});
