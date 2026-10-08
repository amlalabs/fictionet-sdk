//! Bounded SBE XML schemas, dynamic messages, and codec contracts.
#![no_main]

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::sbe::harness::{CAR_BYTES, Car};
use fictionet::stdlib::sbe::{
    MAX_MESSAGE_BYTES, MessageWire, Messages, Scalar, Schema, SchemaSource, Value,
};
use fictionet::stdlib::test_support::contract;
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
                    contract::check_decode_with_alloc_limit(
                        || Messages::new(&schema),
                        bytes,
                        2 * MAX_MESSAGE_BYTES,
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
    contract::check_decode_with_alloc_limit(|| Messages::new(schema), data, 2 * MAX_MESSAGE_BYTES);
    contract::check_wire::<MessageWire<Car>>(data);
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
    contract::check_wire::<MessageWire<Car>>(&bytes);
    contract::check_decode_with_alloc_limit(
        || Messages::new(schema),
        &bytes,
        2 * MAX_MESSAGE_BYTES,
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
    contract::check_wire_value(&value);
});
