//! QPACK wire units, instruction streams, and caller-owned session state.
#![no_main]

use fictionet::stdlib::{
    codec::{Wire, contract, test_support::decode_all},
    qpack::{
        self, DecoderInstruction, DecoderInstructions, EncoderInstruction, EncoderInstructions, FieldSection,
        HuffmanString, Integer, Representation, SectionResult, Table,
    },
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let bytes = &input[..input.len().min(16 << 10)];
    contract::check_wire::<Integer<5>>(bytes);
    contract::check_wire::<Integer<8>>(bytes);
    contract::check_wire::<HuffmanString>(bytes);
    contract::check_wire::<EncoderInstruction>(bytes);
    contract::check_wire::<DecoderInstruction>(bytes);
    contract::check_wire::<Representation>(bytes);
    contract::check_wire::<FieldSection>(bytes);
    contract::check_decode_with_alloc_limit(EncoderInstructions::new, bytes, 2 * qpack::MAX_INSTRUCTION);
    contract::check_decode_with_alloc_limit(DecoderInstructions::new, bytes, 2 * qpack::MAX_INTEGER_BYTES);

    let mut table = Table::new(4096);
    let (instructions, _) = decode_all(EncoderInstructions::new, bytes);
    for instruction in instructions {
        if instruction.and_then(|instruction| table.apply(instruction)).is_err() {
            break;
        }
    }
    assert!(table.size() <= table.capacity());
    assert!(table.capacity() <= table.max_capacity());
    let mut held = qpack::BlockedSections::new(4);
    if let Ok(section) = qpack::decode_section(&table, 0, bytes) {
        match section {
            SectionResult::Fields { fields, ack } => {
                if let Some(ack) = ack {
                    contract::check_wire_value(&ack);
                }
                let mut encoder = qpack::Encoder::new(0, qpack::MAX_FIELD_SECTION_SIZE);
                let value = encoder.section(0, &fields).unwrap();
                contract::check_wire_value(&value);
                assert_eq!(
                    qpack::decode_section(&Table::new(0), 0, &value.to_bytes().unwrap()),
                    Ok(SectionResult::Fields { fields, ack: None })
                );
            }
            SectionResult::Blocked(section) => {
                held.push(section).unwrap();
                table.set_capacity(4096).unwrap();
                for n in 0..64u8 {
                    table.insert(vec![b'x', n], vec![n]).unwrap();
                    if let Some((_, Ok(SectionResult::Fields { ack: Some(ack), .. }))) = held.next_ready(&table) {
                        contract::check_wire_value(&ack);
                    }
                }
            }
        }
    }
    if let Some(ack) = held.cancel(&table, 0) {
        contract::check_wire_value(&ack);
    }
    if let Some(ack) = table.take_increment() {
        contract::check_wire_value(&ack);
    }

    let mut encoder = qpack::Encoder::new(4096, qpack::MAX_FIELD_SECTION_SIZE);
    let mut receiving = Table::new(4096);
    receiving.apply(encoder.set_capacity(4096).unwrap()).unwrap();
    let value = &bytes[..bytes.len().min(256)];
    let (_, instruction) = encoder.insert(b"x-fuzz", value).unwrap();
    contract::check_wire_value(&instruction);
    receiving.apply(instruction).unwrap();
    encoder.apply_instruction(receiving.take_increment().unwrap()).unwrap();
    let section = encoder.section(4, &[qpack::Field::new("x-fuzz", value)]).unwrap();
    contract::check_wire_value(&section);
    let (acks, _) = decode_all(DecoderInstructions::new, bytes);
    for ack in acks {
        if ack.and_then(|ack| encoder.apply_instruction(ack)).is_err() {
            break;
        }
    }
});
