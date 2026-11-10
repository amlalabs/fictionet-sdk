//! Differential checks of HPACK against the Lean model in
//! `verification/hpack-grpc/lean`. Each case holds what the model computed;
//! this test runs the Rust code on the same input and compares.
//! Run through `cargo xtask hpack-verify diff`, which sets `HPACK_VECTORS`.

use fictionet::stdlib::protocols::hpack::{Encoder, Error, Field, MAX_DECODED, Table};
use fictionet::stdlib::protocols::{huffman, prefix_int};
use serde_json::Value;

fn cases(kind: &str, mut check: impl FnMut(&Value)) {
    let dir = std::env::var_os("HPACK_VECTORS").expect("run cargo xtask hpack-verify diff");
    let path = std::path::Path::new(&dir).join(format!("{kind}.json"));
    let data: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let cases = data.as_array().unwrap();
    assert!(!cases.is_empty(), "empty {kind} vectors");
    for case in cases {
        check(case);
    }
    println!("{kind}: {} cases, 0 disagree", cases.len());
}

fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap().as_bytes();
    text.chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn n(value: &Value) -> u64 {
    value.as_u64().unwrap()
}

fn size(value: &Value) -> usize {
    usize::try_from(n(value)).unwrap()
}

/// The model's name for each error `Table::decode_block` returns.
fn error_name(error: Error) -> &'static str {
    match error {
        Error::Truncated => "truncated",
        Error::IntegerOverflow => "integer_overflow",
        Error::StringTooLong => "string_too_long",
        Error::Huffman => "huffman",
        Error::Index => "index",
        Error::TableSize => "table_size",
        Error::SizeUpdateOrder => "size_update_order",
        Error::MissingSizeUpdate => "missing_size_update",
        Error::BlockTooLong => "block_too_long",
        Error::Trailing | Error::ContextRequired | Error::Unwritable => {
            panic!("decode_block returned {error:?}")
        }
    }
}

fn fields(value: &Value) -> Vec<Field> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|f| Field {
            name: hex(&f[0]),
            value: hex(&f[1]),
            never_index: f[2].as_bool().unwrap(),
        })
        .collect()
}

/// The dynamic table's entries, newest first, read through the public API:
/// a copy of the table decodes a block that names each dynamic index.
fn entries(table: &Table) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut block = Vec::new();
    for index in 62..62 + table.table_len() as u64 {
        prefix_int::write(&mut block, 7, 0x80, index).unwrap();
    }
    let read = table.clone().decode_block(&block, MAX_DECODED).unwrap();
    assert_eq!(read.more, 0);
    read.headers
        .into_iter()
        .map(|f| (f.name, f.value))
        .collect()
}

#[test]
fn int_decode() {
    cases("int_decode", |case| {
        let prefix = u8::try_from(n(&case["prefix"])).unwrap();
        let got = prefix_int::read(&hex(&case["input"]), prefix);
        match case.get("error") {
            Some(error) => {
                let name = match got {
                    Err(prefix_int::Error::Truncated) => "truncated",
                    Err(prefix_int::Error::Overflow) => "overflow",
                    other => panic!("{case}: {other:?}"),
                };
                assert_eq!(name, error.as_str().unwrap(), "{case}");
            }
            None => assert_eq!(got, Ok((n(&case["value"]), size(&case["used"]))), "{case}"),
        }
    });
}

#[test]
fn int_encode() {
    cases("int_encode", |case| {
        let mut out = Vec::new();
        prefix_int::write(
            &mut out,
            u8::try_from(n(&case["prefix"])).unwrap(),
            u8::try_from(n(&case["flags"])).unwrap(),
            n(&case["value"]),
        )
        .unwrap();
        assert_eq!(out, hex(&case["output"]), "{case}");
    });
}

#[test]
fn huffman_encode() {
    cases("huffman_encode", |case| {
        let input = hex(&case["input"]);
        let mut out = Vec::new();
        huffman::encode(&input, &mut out).unwrap();
        assert_eq!(out, hex(&case["output"]), "{case}");
        assert_eq!(huffman::encoded_len(&input), Ok(out.len()), "{case}");
    });
}

#[test]
fn huffman_decode() {
    cases("huffman_decode", |case| {
        let got = huffman::decode_limited(&hex(&case["input"]), size(&case["limit"]));
        match case.get("error") {
            Some(error) => {
                let name = match got {
                    Err(huffman::Error::InvalidCode) => "invalid",
                    Err(huffman::Error::TooLong) => "too_long",
                    other => panic!("{case}: {other:?}"),
                };
                assert_eq!(name, error.as_str().unwrap(), "{case}");
            }
            None => assert_eq!(got, Ok(hex(&case["output"])), "{case}"),
        }
    });
}

#[test]
fn blocks() {
    cases("blocks", |case| {
        let mut table = Table::new(size(&case["settings"]));
        for step in case["steps"].as_array().unwrap() {
            if let Some(limit) = step.get("ack") {
                table.set_settings_limit(size(limit));
                continue;
            }
            let got = table.decode_block(&hex(&step["block"]), MAX_DECODED);
            if let Some(error) = step.get("error") {
                let Err(got) = got else {
                    panic!("{case}: {step}: accepted")
                };
                assert_eq!(error_name(got), error.as_str().unwrap(), "{step}");
                // A decoding error ends the connection; the session stops.
                break;
            }
            let block = got.unwrap_or_else(|e| panic!("{step}: {e:?}"));
            assert_eq!(block.more, size(&step["more"]), "{step}");
            assert_eq!(block.headers, fields(&step["fields"]), "{step}");
            let want: Vec<(Vec<u8>, Vec<u8>)> = step["table"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| (hex(&e[0]), hex(&e[1])))
                .collect();
            assert_eq!(entries(&table), want, "{step}");
            assert_eq!(table.table_size(), size(&step["size"]), "{step}");
            assert_eq!(table.table_capacity(), size(&step["max"]), "{step}");
        }
    });
}

#[test]
fn encoder() {
    cases("encoder", |case| {
        let settings = size(&case["settings"]);
        let mut encoder = Encoder::new(settings);
        let mut table = Table::new(settings);
        for step in case["steps"].as_array().unwrap() {
            if let Some(limit) = step.get("settings") {
                // The SETTINGS acknowledgment goes out before the next block,
                // so the decoder applies the limit before reading it.
                encoder.set_settings_limit(size(limit));
                table.set_settings_limit(size(limit));
            } else if let Some(capacity) = step.get("capacity") {
                let got = encoder.set_capacity(size(capacity));
                assert_eq!(got.is_ok(), step["ok"].as_bool().unwrap(), "{step}");
            } else if let Some(huffman) = step.get("huffman") {
                encoder.set_huffman(huffman.as_bool().unwrap());
            } else {
                let given = fields(&step["fields"]);
                let mut out = Vec::new();
                let got = encoder.encode_block(&given, &mut out);
                if step.get("error").is_some() {
                    assert_eq!(got, Err(Error::Unwritable), "{step}");
                    assert!(out.is_empty(), "{step}");
                    continue;
                }
                got.unwrap();
                assert_eq!(out, hex(&step["output"]), "{step}");
                assert_eq!(encoder.table_size(), size(&step["size"]), "{step}");
                let block = table.decode_block(&out, MAX_DECODED).unwrap();
                assert_eq!(block.headers, fields(&step["decoded"]), "{step}");
                assert_eq!(block.more, size(&step["more"]), "{step}");
                assert_eq!(table.table_size(), encoder.table_size(), "{step}");
            }
        }
    });
}
