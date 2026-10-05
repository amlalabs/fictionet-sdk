//! OPC UA chunks, messages, built-in types and services, as a world
//! playing a server reads them.
#![no_main]

use fictionet::stdlib::opcua::{
    DataValue, Decoder, DiagnosticInfo, ExpandedNodeId, ExtensionObject, Limits, LocalizedText, Message, NodeId,
    ResponseHeader, Service, Variant, decode, encode,
};
use libfuzzer_sys::fuzz_target;

/// Reads a value, and if it reads and writes, checks that the bytes
/// written read back and write the same.
fn round_trip<T: fictionet::stdlib::opcua::Binary>(data: &[u8]) {
    if let Ok(v) = decode::<T>(data) {
        if let Ok(out) = encode(&v) {
            let back: T = decode(&out).unwrap();
            assert_eq!(encode(&back).unwrap(), out);
        }
    }
}

fn messages(d: &mut Decoder, out: &mut Vec<Result<Message, String>>) -> bool {
    while let Some(m) = d.next_message() {
        let failed = m.is_err();
        out.push(m.map_err(|e| e.to_string()));
        if failed {
            return true;
        }
    }
    false
}

fuzz_target!(|data: &[u8]| {
    // The first byte picks the limits, so small chunk and message limits
    // are reached too.
    let Some((&pick, data)) = data.split_first() else {
        return;
    };
    let limits = match pick % 3 {
        0 => Limits::default(),
        1 => Limits { receive_buffer_size: 8192, max_message_size: 1 << 14, max_chunk_count: 4 },
        _ => Limits { receive_buffer_size: 1 << 16, max_message_size: 0, max_chunk_count: 0 },
    };

    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::with_limits(limits);
    whole.feed(data);
    let mut first = Vec::new();
    messages(&mut whole, &mut first);
    let mut bytewise = Decoder::with_limits(limits);
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        if messages(&mut bytewise, &mut again) {
            break;
        }
    }
    assert_eq!(first, again);

    for m in first.iter().flatten() {
        // A message read can be written, and reads back the same.
        let bytes = m.to_bytes(&limits).unwrap();
        let mut d = Decoder::with_limits(limits);
        d.feed(&bytes);
        assert_eq!(d.next_message(), Some(Ok(m.clone())));
        if let Message::Secure(s) = m {
            if let Ok(service) = Service::parse(&s.body) {
                let body = service.to_bytes().unwrap();
                assert_eq!(Service::parse(&body), Ok(service));
            }
        }
    }

    // Any bytes as values on their own.
    round_trip::<Variant>(data);
    round_trip::<DataValue>(data);
    round_trip::<DiagnosticInfo>(data);
    round_trip::<ExpandedNodeId>(data);
    round_trip::<NodeId>(data);
    round_trip::<LocalizedText>(data);
    round_trip::<ExtensionObject>(data);
    round_trip::<ResponseHeader>(data);
    if let Ok(s) = Service::parse(data) {
        if let Ok(out) = s.to_bytes() {
            assert_eq!(Service::parse(&out), Ok(s));
        }
    }
});
