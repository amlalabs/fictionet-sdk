//! Bounded SBE XML schemas, dynamic messages, and codec contracts.
#![no_main]

use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::sbe::harness::{CAR_BYTES, Car};
use fictionet::stdlib::protocols::sbe::{
    MAX_MESSAGE_BYTES, MessageWire, Messages, Scalar, Schema, SchemaSource, Value,
};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_all, decode_chunks};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_BYTES: usize = 8192;
fuzz_target!(|input: &[u8]| {
    let data = input
        .get(..input.len().min(MAX_FUZZ_BYTES))
        .unwrap_or_default();
    // Exercise arbitrary schemas both as a whole and with a binary suffix.
    if let Ok(xml) = std::str::from_utf8(data) {
        let _ = Schema::parse(xml);
    }
    if let Some(at) = data.iter().position(|b| *b == 0) {
        if let (Some(xml), Some(bytes)) = (data.get(..at), data.get(at + 1..)) {
            if let Ok(xml) = std::str::from_utf8(xml) {
                if let Ok(schema) = Schema::parse(xml) {
                    assert_eq!(
                        decode_chunks(
                            &mut Stream::new(Messages::new(&schema)),
                            chunks(bytes, &[1, 7, 64]),
                            |s| {
                                assert!(s.allocated() <= 2 * MAX_MESSAGE_BYTES);
                            }
                        ),
                        decode_all(|| Messages::new(&schema), bytes),
                    );
                    if let Ok(message) = schema.decode(bytes) {
                        let mut out = vec![0xaa];
                        schema.write(&message, &mut out).unwrap();
                        assert_eq!(schema.decode(&out[1..]), Ok(message));
                    }
                }
            }
        }
    }
    let schema = Car::schema().unwrap();
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Messages::new(schema)),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_MESSAGE_BYTES);
            }
        ),
        decode_all(|| Messages::new(schema), data),
    );
    if let Ok(value) = <MessageWire<Car> as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    // Mutate valid framing so fuzzing reaches values and nested groups.
    let mut bytes = CAR_BYTES.to_vec();
    for pair in data.chunks_exact(2) {
        if let [at, byte] = pair {
            let len = bytes.len();
            if let Some(slot) = bytes.get_mut(usize::from(*at) % len) {
                *slot = *byte;
            }
        }
    }
    if let Ok(value) = <MessageWire<Car> as Wire>::parse(&bytes) {
        let _ = assert_write(&value);
    }
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Messages::new(schema)),
            chunks(&bytes, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_MESSAGE_BYTES);
            }
        ),
        decode_all(|| Messages::new(schema), &bytes),
    );
    let mut value = MessageWire::<Car>::parse(CAR_BYTES).unwrap();
    if let Some(first) = data.first() {
        value.message.header.version = u64::from(*first);
        if let Some(field) = value.message.fields.get_mut(0) {
            field.value = match first % 4 {
                0 => Value::Null,
                1 => Value::Scalar(Scalar::Uint(u64::from(*first))),
                2 => Value::Bytes(data.to_vec()),
                _ => Value::Absent,
            };
        }
    }
    let _ = assert_write(&value);
});
