//! Differential checks of HPACK against the Lean model in
//! `verification/hpack-grpc/lean`. Each case holds what the model computed;
//! this test runs the Rust code on the same input and compares.
//! Run through `cargo xtask hpack-verify diff`, which sets `HPACK_VECTORS`.
//!
//! Every block a session decodes or encodes is also a costed step
//! (verification/resources/cost.rs): the table holds no more than
//! `most_held()` at any moment, and the step asks the allocator for at
//! most a linear bound of its input, stated in [`decoding`] and
//! [`encoding`].

#[path = "../verification/resources/alloc.rs"]
mod alloc;
#[path = "../verification/resources/cost.rs"]
mod cost;

use cost::{Charged, Costs, Linear};
use fictionet::stdlib::protocols::fields::Fields;
use fictionet::stdlib::protocols::hpack::{
    DynamicTable, Encoder, Error, Field, MAX_DECODED, STATIC_TABLE, Table,
};
use fictionet::stdlib::protocols::{huffman, prefix_int};
use fictionet::{Budget, Chunk};
use serde_json::Value;

/// What a name copied into a table entry takes beyond its octets: the
/// shared allocation's header, two `usize` counts, padded to their
/// alignment.
const NAME_HEADER: usize = 2 * size_of::<usize>() + align_of::<usize>() - 1;

/// The entry slots' share of `DynamicTable::most_held(capacity)`. A step
/// that inserts may double the slots, and the doublings within one block
/// come to at most twice the last.
fn slots(capacity: usize) -> usize {
    DynamicTable::most_held(capacity) - capacity
}

/// The decoder's linear bound on a block of encoded bytes. Its literals
/// decode to at most 8 octets for every 5 bits, the shortest Huffman code:
/// 8/5 a byte, the most a value or a literal name copied into the table
/// takes. Each insertion takes at least 2 bytes of the block (its flags
/// with a name index, and a value length), and copies at most a name's
/// header and the longest static name besides: half of that a byte. The
/// slots may double, at most twice their share of `most_held` over the
/// block, at the larger of the settings limit and the capacity.
fn decoding(table: &Table) -> Linear {
    let longest_static = STATIC_TABLE.iter().map(|(n, _)| n.len()).max().unwrap();
    Linear {
        num: 8 * 2 + 5 * (NAME_HEADER + longest_static),
        den: 5 * 2,
        fixed: 2 * slots(table.settings_limit().max(table.table_capacity())),
    }
}

/// The encoder's linear bound on a block's fields, counting each field's
/// name and value octets and one for the field: a field it indexes copies
/// its value and its name, with the name's header, so at most
/// `NAME_HEADER` a unit. The slots' doublings come to at most twice their
/// share of `Encoder::most_held`, which the encoder gives in full.
fn encoding(encoder: &Encoder) -> Linear {
    Linear {
        num: NAME_HEADER,
        den: 1,
        fixed: 2 * encoder.most_held(),
    }
}

/// A change of the encoder's settings limit or capacity evicts and never
/// allocates. It is a step all the same, so the session's count of live
/// bytes sees what it frees.
const NOTHING: Linear = Linear {
    num: 0,
    den: 1,
    fixed: 0,
};

/// A block decoded: the fields kept, with their never-indexed flags, and
/// how many were left out.
struct Decoded {
    headers: Vec<Field>,
    more: usize,
}

/// Decodes `block` into a head block as large as `most_block` says it can
/// need, as the server does.
fn decode(table: &mut Table, block: &[u8]) -> Result<Decoded, Error> {
    let bound = table.most_block(block.len(), MAX_DECODED).bytes();
    let mut out = Fields::in_block(Chunk::block(&Budget::unlimited(), 0, bound.max(1)).unwrap());
    table.decode_block(block, &mut out, &Budget::unlimited(), MAX_DECODED)?;
    Ok(read(&out))
}

fn read(out: &Fields) -> Decoded {
    Decoded {
        headers: out
            .iter_marked()
            .map(|(name, value, never_index)| Field {
                name: name.to_vec(),
                value: value.to_vec(),
                never_index,
            })
            .collect(),
        more: out.left_out(),
    }
}

/// [`decode`] as a costed step. The table's charge is `most_held()` as it
/// is before the step, a bound even once the limit has fallen, since it
/// counts the entry slots the table grew before. The server holds less
/// tightly: it charges `most_held()` when the connection opens and never
/// gives it back. The head block, made before the step, is the budget's;
/// growing it would be the step's own charge.
fn decode_costed(table: &mut Table, block: &[u8], costs: &mut Costs) -> Result<Decoded, Error> {
    // The budget is the connection's, made before its blocks.
    let budget = Budget::unlimited();
    let bound = table.most_block(block.len(), MAX_DECODED).bytes();
    let mut out = Fields::in_block(Chunk::block(&budget, 0, bound.max(1)).unwrap());
    let (charge, linear, before) = (table.most_held(), decoding(table), out.charged());
    let result = costs.step(block.len(), charge, linear, || {
        let value = table.decode_block(block, &mut out, &budget, MAX_DECODED);
        Charged {
            value,
            charged: out.charged().saturating_sub(before),
            moved: 0,
        }
    });
    result.map(|()| read(&out))
}

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
    let read = decode(&mut table.clone(), &block).unwrap();
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
    let mut total = Costs::new("blocks");
    let mut session = 0;
    cases("blocks", |case| {
        session += 1;
        let mut costs = Costs::new(format!("blocks session {session}"));
        let mut table = Table::new(size(&case["settings"]));
        for step in case["steps"].as_array().unwrap() {
            if let Some(limit) = step.get("ack") {
                table.set_settings_limit(size(limit));
                continue;
            }
            let got = decode_costed(&mut table, &hex(&step["block"]), &mut costs);
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
        total.absorb(&costs);
    });
    total.print();
}

#[test]
fn encoder() {
    let mut total = Costs::new("encoder");
    let mut session = 0;
    cases("encoder", |case| {
        session += 1;
        let mut costs = Costs::new(format!("encoder session {session}"));
        let mut decoder_costs = Costs::new(format!("encoder session {session}, decoder"));
        let settings = size(&case["settings"]);
        let mut encoder = Encoder::new(settings);
        let mut table = Table::new(settings);
        for step in case["steps"].as_array().unwrap() {
            if let Some(limit) = step.get("settings") {
                // The SETTINGS acknowledgment goes out before the next block,
                // so the decoder applies the limit before reading it.
                let charge = encoder.most_held();
                costs.step(0, charge, NOTHING, || Charged {
                    value: encoder.set_settings_limit(size(limit)),
                    charged: 0,
                    moved: 0,
                });
                table.set_settings_limit(size(limit));
            } else if let Some(capacity) = step.get("capacity") {
                let charge = encoder.most_held();
                let got = costs.step(0, charge, NOTHING, || Charged {
                    value: encoder.set_capacity(size(capacity)),
                    charged: 0,
                    moved: 0,
                });
                assert_eq!(got.is_ok(), step["ok"].as_bool().unwrap(), "{step}");
            } else if let Some(huffman) = step.get("huffman") {
                encoder.set_huffman(huffman.as_bool().unwrap());
            } else {
                let given = fields(&step["fields"]);
                // Room for the block is made before the step, as a caller
                // that writes into a charged block does.
                let mut out = Vec::with_capacity(encoder.block_bound(&given).unwrap_or(0));
                let input = given.iter().map(|f| f.name.len() + f.value.len() + 1).sum();
                let (charge, linear) = (encoder.most_held(), encoding(&encoder));
                let got = costs.step(input, charge, linear, || Charged {
                    value: encoder.encode_block(&given, &mut out),
                    charged: 0,
                    moved: 0,
                });
                if step.get("error").is_some() {
                    assert_eq!(got, Err(Error::Unwritable), "{step}");
                    assert!(out.is_empty(), "{step}");
                    continue;
                }
                got.unwrap();
                assert_eq!(out, hex(&step["output"]), "{step}");
                assert_eq!(encoder.table_size(), size(&step["size"]), "{step}");
                let block = decode_costed(&mut table, &out, &mut decoder_costs).unwrap();
                assert_eq!(block.headers, fields(&step["decoded"]), "{step}");
                assert_eq!(block.more, size(&step["more"]), "{step}");
                assert_eq!(table.table_size(), encoder.table_size(), "{step}");
            }
        }
        total.absorb(&costs);
        total.absorb(&decoder_costs);
    });
    total.print();
}
