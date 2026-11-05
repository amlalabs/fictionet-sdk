//! OPC UA chunks, messages, built-in types and services, as a world
//! playing a server reads them.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::opcua::Messages;
use fictionet::stdlib::protocols::opcua::harness::check_reader;
use fictionet::stdlib::protocols::opcua::{
    Chunk, ChunkType, DataValue, DiagnosticInfo, ExpandedNodeId, ExtensionObject, Limits,
    LocalizedText, Message, MessageType, NodeId, QualifiedName, ResponseHeader, Service, Variant,
};
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};
use libfuzzer_sys::fuzz_target;

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

    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Chunk>::with_limit(limits)),
            chunks(data, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(|| Frames::<Chunk>::with_limit(limits), data),
    );
    if let Ok(value) = <Chunk as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
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
                    .min(fictionet::stdlib::protocols::opcua::MAX_BUFFER_SIZE as usize),
            )
            .unwrap_or_default()
            .to_vec(),
    };
    let _ = assert_write(&chunk);

    let held = limits.message_limit() as usize;
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Messages::with_limits(limits)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.held() <= held);
            }
        ),
        decode_all(|| Messages::with_limits(limits), data),
    );
    let (messages, _) = decode_all(|| Messages::with_limits(limits), data);
    for message in messages {
        let mut bytes = Vec::new();
        for chunk in message.chunks(&limits).unwrap() {
            chunk.write(&mut bytes).unwrap();
        }
        let (back, failure) = decode_all(|| Messages::with_limits(limits), &bytes);
        assert!(failure.is_none());
        assert_eq!(back, [message.clone()]);
        if let Message::Secure(s) = message {
            if let Ok(value) = <Service as Wire>::parse(&s.body) {
                let _ = assert_write(&value);
            }
        }
    }

    // Any bytes as values on their own.
    if let Ok(value) = <Variant as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <DataValue as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <DiagnosticInfo as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    check_reader::<Variant>(data);
    check_reader::<DataValue>(data);
    check_reader::<DiagnosticInfo>(data);
    if let Ok(value) = <ExpandedNodeId as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <NodeId as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <QualifiedName as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <LocalizedText as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <ExtensionObject as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <ResponseHeader as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Service as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
});
