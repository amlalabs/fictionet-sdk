//! Shared HPACK/QPACK Huffman contracts and byte round trips.
#![no_main]
use fictionet::stdlib::{
    codec::{Wire, contract},
    huffman::{self, HuffmanString},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let bytes = &bytes[..bytes.len().min(huffman::MAX_ENCODED + 1)];
    contract::check_wire::<HuffmanString>(bytes);
    let value = HuffmanString(bytes[..bytes.len().min(huffman::MAX_STRING + 1)].to_vec());
    contract::check_wire_value(&value);
    if let Ok(encoded) = value.to_bytes() {
        assert_eq!(HuffmanString::parse(&encoded).unwrap(), value);
        assert_eq!(huffman::encoded_len(&value.0).unwrap(), encoded.len());
    }
});
