//! HPACK wire contracts, complete blocks, table recovery, and round trips.
#![no_main]
use fictionet::stdlib::{
    codec::Collect,
    hpack::{self, Encoder, Field, StringLiteral, Table},
    prefix_int::Integer,
    test_support::contract,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let bytes = &input[..input.len().min(hpack::MAX_BLOCK + 1)];
    contract::check_wire::<Integer<1>>(bytes);
    contract::check_wire::<Integer<5>>(bytes);
    contract::check_wire::<Integer<8>>(bytes);
    contract::check_wire::<StringLiteral>(bytes);
    contract::check_wire::<Field>(bytes);
    let short = &bytes[..bytes.len().min(512)];
    contract::check_decode(|| Collect::<Field>::new(hpack::MAX_BLOCK), short);
    for mut decoder in [Table::default(), Table::new(0), Table::for_observation()] {
        let _ = decoder.decode_block(bytes, hpack::MAX_DECODED);
        assert!(decoder.table_size() <= hpack::MAX_TABLE);
        for (i, piece) in short.chunks(32).enumerate() {
            if i % 3 == 0 {
                decoder.forget();
            }
            if i % 5 == 0 {
                decoder.set_settings_limit(usize::from(piece[0]));
            }
            let _ = decoder.decode_block(piece, i);
            assert!(decoder.table_size() <= hpack::MAX_TABLE);
            assert!(decoder.table_len() <= hpack::MAX_TABLE / hpack::ENTRY_OVERHEAD);
        }
    }
    let integer = short
        .iter()
        .take(8)
        .fold(0u64, |v, b| (v << 8) | u64::from(*b));
    contract::check_wire_value(&Integer::<5> {
        flags: 0x20,
        value: integer,
    });
    let value = &bytes[..bytes.len().min(hpack::MAX_STRING + 1)];
    contract::check_wire_value(&StringLiteral(value.to_vec()));
    contract::check_wire_value(&Field::new(b"x-fuzz", value));
    let mut encoder = Encoder::default();
    let mut decoder = Table::default();
    for (i, piece) in short.chunks(64).enumerate() {
        let size = usize::from(piece[0]);
        encoder.set_settings_limit(size);
        decoder.set_settings_limit(size);
        encoder.set_capacity(size).unwrap();
        encoder.set_huffman(i % 2 == 0);
        let mut field = Field::new(b"x-fuzz", piece);
        field.never_index = i % 3 == 0;
        let mut out = Vec::new();
        encoder.encode_block(&[field.clone()], &mut out).unwrap();
        let block = decoder.decode_block(&out, hpack::MAX_DECODED).unwrap();
        assert_eq!(block.more, 0);
        assert_eq!(block.headers.len(), 1);
        assert_eq!(
            block.headers[0].name.as_deref(),
            Some(field.name.as_slice())
        );
        assert_eq!(
            block.headers[0].value.as_deref(),
            Some(field.value.as_slice())
        );
        assert_eq!(block.headers[0].never_index, field.never_index);
        assert_eq!(encoder.table_size(), decoder.table_size());
    }
});
