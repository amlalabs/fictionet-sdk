//! Kafka frames, requests, and responses as a broker or client reads them.
#![no_main]

use fictionet::stdlib::codec::Frames;

use fictionet::stdlib::codec::{Decode, Reader, Wire, contract, leb128, test_support::decode_all};
use fictionet::stdlib::kafka::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Frames::<Frame>::new, data, 2 * Frames::<Frame>::new().capacity());
    let limit = usize::from(data.first().copied().unwrap_or(0));
    contract::check_decode_with_alloc_limit(|| Frames::<Frame>::with_limit(limit), data, 2 * Frames::<Frame>::with_limit(limit).capacity());
    contract::check_wire::<Frame>(data);
    contract::check_wire::<Request>(data);
    contract::check_wire::<RequestHeader>(data);
    contract::check_decode_with_alloc_limit(|| Frames::<Frame>::new().map(|frame| Request::parse(&frame.0)), data, 2 * Frames::<Frame>::new().capacity());
    contract::check_wire_value(&Frame(data.iter().take(MAX_FRAME + 1).copied().collect()));

    let frames = decode_all(Frames::<Frame>::new, data).0;
    for payload in frames.iter().map(|frame| frame.0.as_slice()).chain(core::iter::once(data)) {
        if let Ok(request) = Request::parse(payload) {
            contract::check_wire_value(&request);
            let frame = request.to_frame().unwrap();
            assert_eq!(decode_all(Frames::<Frame>::new, &frame.to_bytes().unwrap()), (vec![frame], None));
        }
        for key in [api_key::API_VERSIONS, api_key::METADATA, api_key::PRODUCE] {
            for version in 0..=13 {
                if let Ok(response) = Response::parse(payload, key, version) {
                    let frame = response.to_frame(key, version).unwrap();
                    contract::check_wire_value(&frame);
                    assert_eq!(Response::parse(&frame.0, key, version), Ok(response));
                }
            }
        }
        // Parse bodies directly so arbitrary bytes reach fields without a header gate.
        for version in 0..=13 {
            for (key, body) in [
                (api_key::API_VERSIONS, ApiVersionsRequest::parse(payload, version).map(RequestBody::ApiVersions)),
                (api_key::METADATA, MetadataRequest::parse(payload, version).map(RequestBody::Metadata)),
            ] {
                if let Ok(body) = body {
                    contract::check_wire_value(&Request {
                        header: RequestHeader { api_key: key, api_version: version, ..Default::default() }, body,
                    });
                }
            }
            for (key, body) in [
                (api_key::API_VERSIONS, ApiVersionsResponse::parse(payload, version).map(ResponseBody::ApiVersions)),
                (api_key::METADATA, MetadataResponse::parse(payload, version).map(ResponseBody::Metadata)),
            ] {
                if let Ok(body) = body {
                    let response = Response { header: ResponseHeader::default(), body };
                    let frame = response.to_frame(key, version).unwrap();
                    contract::check_wire_value(&frame);
                    assert_eq!(Response::parse(&frame.0, key, version), Ok(response));
                }
            }
        }
        // Produce v9 has a version-1 response header. Supply the correlation
        // ID to exercise arbitrary tagged fields in that header directly.
        let mut response = vec![0; 4];
        response.extend_from_slice(payload);
        if let Ok(value) = Response::parse(&response, api_key::PRODUCE, 9) {
            let frame = value.to_frame(api_key::PRODUCE, 9).unwrap();
            assert_eq!(Response::parse(&frame.0, api_key::PRODUCE, 9), Ok(value));
        }
    }
    // Keep exercising the shared varint reader with both Kafka widths.
    for (width, max) in [(5, u64::from(u32::MAX)), (10, u64::MAX)] {
        let mut reader = Reader::new(data);
        if let Ok(value) = leb128::decode_with(|| reader.u8().map_err(|_| ()), width, max, ()) {
            let mut bytes = Vec::new();
            leb128::encode_with(value, |byte| bytes.push(byte));
            let mut reader = Reader::new(&bytes);
            assert_eq!(leb128::decode_with(|| reader.u8().map_err(|_| ()), width, max, ()), Ok(value));
            assert!(reader.is_empty());
        }
    }
    contract::check_wire_value(&RequestHeader {
        api_key: api_key::METADATA, api_version: 9,
        tagged_fields: vec![TaggedField {
            tag: data.first().copied().map(u32::from).unwrap_or(0), data: data.to_vec(),
        }],
        ..Default::default()
    });
});
