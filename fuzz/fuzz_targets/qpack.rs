//! QPACK wire units, instruction streams, and caller-owned session state.
#![no_main]

use fictionet::stdlib::{
    codec::{Stream, Wire, contract, test_support::decode_all, try_pump},
    huffman::HuffmanString,
    prefix_int::Integer,
    qpack::{
        self, DecoderInstruction, DecoderInstructions, EncoderInstruction, EncoderInstructions,
        FieldSection, Representation, SectionResult, Table,
    },
};
use libfuzzer_sys::fuzz_target;

/// Retains sections from two streams across a partial encoder instruction.
fn blocked_sections(bytes: &[u8]) {
    // This caller does not order sections, so no per-stream ordering is checked.
    let Some((&split, rest)) = bytes.split_first() else { return };
    let (instructions, sections) = rest.split_at(usize::from(split) * rest.len() / 255);
    let (early, late) = instructions.split_at(instructions.len() / 2);
    let mut table = Table::new(4096);
    let mut input = Stream::new(EncoderInstructions::new());
    let mut held = qpack::BlockedSections::new(2);
    let mut sent = [Vec::new(), Vec::new()];
    if try_pump(&mut input, early, |instruction| table.apply(instruction?)).is_ok() {
        for (i, piece) in sections.chunks(sections.len().div_ceil(4).max(1)).enumerate() {
            let k = i % 2;
            match qpack::decode_section(&table, k as u64 * 4, piece) {
                Ok(SectionResult::Blocked(section)) => {
                    sent[k].push(section.clone());
                    held.push(section).unwrap();
                }
                Ok(SectionResult::Fields { ack, .. }) => {
                    if let Some(ack) = ack {
                        contract::check_wire_value(&ack);
                    }
                }
                Err(_) => break,
            }
            assert_eq!(held.len(), sent.iter().map(Vec::len).sum::<usize>());
            assert!(held.buffered() <= qpack::MAX_BLOCKED_BYTES);
        }
        let mut taken = [0; 2];
        if try_pump(&mut input, late, |instruction| table.apply(instruction?)).is_ok() {
            while let Some((id, result)) = held.next_ready(&table) {
                let k = match id {
                    0 => 0,
                    4 => 1,
                    _ => panic!("released an unknown stream"),
                };
                assert!(taken[k] < sent[k].len());
                assert_eq!(result, sent[k][taken[k]].clone().retry(&table));
                assert!(!matches!(result, Ok(SectionResult::Blocked(_))));
                if let Ok(SectionResult::Fields { ack: Some(ack), .. }) = result {
                    contract::check_wire_value(&ack);
                }
                taken[k] += 1;
                assert!(held.buffered() <= qpack::MAX_BLOCKED_BYTES);
            }
        }
        let pending = [sent[0].len() - taken[0], sent[1].len() - taken[1]];
        assert_eq!(held.len(), pending.iter().sum::<usize>());
        for (k, id) in [0, 4].into_iter().enumerate() {
            let before = held.len();
            contract::check_wire_value(&held.cancel(&table, id).unwrap());
            assert_eq!(held.len(), before - pending[k]);
            assert!(held.buffered() <= qpack::MAX_BLOCKED_BYTES);
        }
        assert!(held.is_empty());
        assert_eq!(held.buffered(), 0);
    }
}

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

    let integer = input.iter().take(8).fold(0u64, |n, b| (n << 8) | u64::from(*b));
    let value = input[..input.len().min(qpack::MAX_STRING + 1)].to_vec();
    for instruction in [
        EncoderInstruction::SetCapacity(integer),
        EncoderInstruction::Duplicate(integer),
        EncoderInstruction::InsertWithNameRef { static_table: true, index: integer, value: value.clone() },
        EncoderInstruction::InsertWithLiteralName { name: b"x-fuzz".to_vec(), value: value.clone() },
    ] {
        contract::check_wire_value(&instruction);
    }
    for instruction in [
        DecoderInstruction::SectionAck(integer),
        DecoderInstruction::StreamCancel(integer),
        DecoderInstruction::InsertCountIncrement(integer),
    ] {
        contract::check_wire_value(&instruction);
    }
    contract::check_wire_value(&HuffmanString(value.clone()));
    contract::check_wire_value(&Representation::LiteralName {
        never_index: integer & 1 != 0,
        name: b"x-fuzz".to_vec(),
        value,
    });
    blocked_sections(bytes);

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
    let (_, instruction) = encoder.insert(b"x-other", b"2").unwrap();
    receiving.apply(instruction).unwrap();
    encoder.apply_instruction(receiving.take_increment().unwrap()).unwrap();
    for stream in [0, 4, 4] {
        let section =
            encoder.section(stream, &[qpack::Field::new("x-fuzz", value), qpack::Field::new("x-other", "2")]).unwrap();
        contract::check_wire_value(&section);
    }
    let (acks, _) = decode_all(DecoderInstructions::new, bytes);
    for ack in acks {
        if ack.and_then(|ack| encoder.apply_instruction(ack)).is_err() {
            break;
        }
    }
});
