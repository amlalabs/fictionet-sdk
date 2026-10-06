//! Kafka frames, requests, and responses as a broker or client reads them.
#![no_main]

use fictionet::stdlib::codec::{Decode, Wire, contract, test_support::decode_all};
use fictionet::stdlib::kafka::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Frames::new, data, 2 * Frames::new().capacity());
    let limit = usize::from(data.first().copied().unwrap_or(0));
    contract::check_decode_with_alloc_limit(|| Frames::with_limit(limit), data, 2 * Frames::with_limit(limit).capacity());
    contract::check_wire::<Frame>(data);
    contract::check_wire::<Request>(data);
    contract::check_wire::<RequestHeader>(data);
    contract::check_wire::<ResponseHead<0>>(data);
    contract::check_wire::<ResponseHead<1>>(data);
    contract::check_decode_with_alloc_limit(|| Frames::new().map(|frame| Request::parse(&frame.0)), data, 2 * Frames::new().capacity());
    contract::check_wire_value(&Frame(data.iter().take(MAX_FRAME + 1).copied().collect()));

    let frames = decode_all(Frames::new, data).0;
    for payload in frames.iter().map(|frame| frame.0.as_slice()).chain(core::iter::once(data)) {
        if let Ok(request) = Request::parse(payload) {
            contract::check_wire_value(&request);
            let frame = request.to_frame().unwrap();
            assert_eq!(decode_all(Frames::new, &frame.to_bytes().unwrap()), (vec![frame], None));
        }
        for key in [api_key::API_VERSIONS, api_key::METADATA] {
            for version in 0..=13 {
                if let Ok(response) = Response::parse(payload, key, version) {
                    let frame = response.to_frame(key, version).unwrap();
                    contract::check_wire_value(&frame);
                    assert_eq!(Response::parse(&frame.0, key, version), Ok(response));
                }
            }
        }
        let mut reader = Reader::new(payload);
        let _ = reader.tagged_fields();
        let _ = reader.varlong();
        let _ = reader.compact_nullable_string();
        let _ = reader.compact_array_len();
        let _ = reader.nullable_bytes();
    }
    macro_rules! fields {
        ($($ty:ty),*) => { $(contract::check_wire::<$ty>(data);)* };
    }
    fields!(Boolean, Int8, Uint8, Int16, Uint16, Int32, Uint32, Int64,
        Float64, Uuid, UnsignedVarint, Varint, Varlong, String16,
        NullableString, CompactString, CompactNullableString, BytesValue,
        NullableBytes, CompactBytes, CompactNullableBytes, ArrayLength,
        CompactArrayLength, TaggedFields);
    contract::check_wire_value(&TaggedFields(vec![TaggedField {
        tag: data.first().copied().map(u32::from).unwrap_or(0), data: data.to_vec(),
    }]));
});
