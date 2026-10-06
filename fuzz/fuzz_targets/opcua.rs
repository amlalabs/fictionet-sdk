//! OPC UA chunks, messages, built-in types and services, as a world
//! playing a server reads them.
#![no_main]

use fictionet::stdlib::codec::contract::{check_decode, check_wire, check_wire_value};
use fictionet::stdlib::codec::{Stream, Wire, pump};
use fictionet::stdlib::opcua::{
    Chunk, ChunkType, DataValue, DiagnosticInfo, ExpandedNodeId, ExtensionObject, Limits,
    LocalizedText, Message, MessageType, NodeId, QualifiedName, ResponseHeader, Service, Variant,
};
use fictionet::stdlib::opcua::{Frames, Messages};
use libfuzzer_sys::fuzz_target;

/// Checks the shared contract for an exact binary value.
fn round_trip<T: Wire + PartialEq + core::fmt::Debug>(data: &[u8]) {
    check_wire::<T>(data);
}

fuzz_target!(|data: &[u8]| {
    // The first byte picks the limits, so small chunk and message limits
    // are reached too.
    let (pick, data) = data
        .split_first()
        .map_or((0, &[][..]), |(&pick, data)| (pick, data));
    let limits = match pick % 3 {
        0 => Limits::default(),
        1 => Limits {
            receive_buffer_size: 8192,
            max_message_size: 1 << 14,
            max_chunk_count: 4,
        },
        _ => Limits {
            receive_buffer_size: 1 << 16,
            max_message_size: 0,
            max_chunk_count: 0,
        },
    };

    check_decode(|| Frames::with_limits(limits), data);
    check_wire::<Chunk>(data);
    let chunk = Chunk {
        message_type: match pick % 4 {
            0 => MessageType::Hello,
            1 => MessageType::Open,
            2 => MessageType::Close,
            _ => MessageType::Message,
        },
        chunk_type: match pick % 3 {
            0 => ChunkType::Final,
            1 => ChunkType::Intermediate,
            _ => ChunkType::Abort,
        },
        body: data
            .get(
                ..data
                    .len()
                    .min(fictionet::stdlib::opcua::MAX_BUFFER_SIZE as usize),
            )
            .unwrap_or_default()
            .to_vec(),
    };
    check_wire_value(&chunk);

    fictionet::stdlib::codec::contract::check_decode_with_held_limit(
        || Messages::with_limits(limits),
        data,
        limits.message_limit() as usize,
    );
    let mut stream = Stream::new(Messages::with_limits(limits));
    let _ = pump(&mut stream, data, |message| {
        if let Message::Secure(s) = message {
            check_wire::<Service>(&s.body);
        }
    });

    // Any bytes as values on their own.
    round_trip::<Variant>(data);
    round_trip::<DataValue>(data);
    round_trip::<DiagnosticInfo>(data);
    round_trip::<ExpandedNodeId>(data);
    round_trip::<NodeId>(data);
    round_trip::<QualifiedName>(data);
    round_trip::<LocalizedText>(data);
    round_trip::<ExtensionObject>(data);
    round_trip::<ResponseHeader>(data);
    if let Ok(s) = <Service as Wire>::parse(data) {
        let out = s.to_bytes().unwrap();
        assert_eq!(<Service as Wire>::parse(&out), Ok(s));
    }
});
