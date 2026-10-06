//! OPC UA chunks, messages, built-in types and services, as a world
//! playing a server reads them.
#![no_main]

use fictionet::stdlib::codec::contract::{check_decode, check_wire, check_wire_value};
use fictionet::stdlib::codec::{Stream, Wire, pump};
use fictionet::stdlib::opcua::{
    Binary, Chunk, ChunkType, DataValue, DiagnosticInfo, EncodeError, ExpandedNodeId,
    ExtensionObject, Limits, LocalizedText, Message, MessageType, NodeId, QualifiedName, Reader,
    ResponseHeader, Service, Variant,
};
use fictionet::stdlib::opcua::{Frames, Messages};
use libfuzzer_sys::fuzz_target;

/// Checks permissive reads, including reserved Variant types that cannot be written.
fn check_reader<T: Binary + Wire<WriteError = EncodeError> + PartialEq + core::fmt::Debug>(
    data: &[u8],
) {
    let mut reader = Reader::new(data);
    if let Ok(value) = reader.read::<T>()
        && reader.finish().is_ok()
    {
        match value.to_bytes() {
            Ok(bytes) => assert_eq!(<T as Wire>::parse(&bytes).unwrap(), value),
            Err(EncodeError::VariantType) => {}
            Err(error) => panic!("{error}"),
        }
    }
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
        let mut bytes = Vec::new();
        for chunk in message.chunks(&limits).unwrap() {
            chunk.write(&mut bytes).unwrap();
        }
        let mut again = Stream::new(Messages::with_limits(limits));
        let mut back = Vec::new();
        pump(&mut again, &bytes, |m| back.push(m)).unwrap();
        assert_eq!(back, [message.clone()]);
        if let Message::Secure(s) = message {
            check_wire::<Service>(&s.body);
        }
    });

    // Any bytes as values on their own.
    check_wire::<Variant>(data);
    check_wire::<DataValue>(data);
    check_wire::<DiagnosticInfo>(data);
    check_reader::<Variant>(data);
    check_reader::<DataValue>(data);
    check_reader::<DiagnosticInfo>(data);
    check_wire::<ExpandedNodeId>(data);
    check_wire::<NodeId>(data);
    check_wire::<QualifiedName>(data);
    check_wire::<LocalizedText>(data);
    check_wire::<ExtensionObject>(data);
    check_wire::<ResponseHeader>(data);
    check_wire::<Service>(data);
});
