//! Generated files compile as consumer-owned modules and run their own tests.
#![allow(dead_code)]
#[path = "../codegen/tests/golden/groups.rs"]
mod groups;
#[path = "../codegen/tests/golden/primitives.rs"]
mod primitives;
#[path = "../codegen/tests/golden/recursive.rs"]
mod recursive;
#[path = "../codegen/tests/golden/xdr.rs"]
mod xdr;

#[path = "../codegen/tests/golden/budgets.rs"]
mod budgets;
#[path = "../codegen/tests/golden/edges.rs"]
mod edges;

use fictionet::stdlib::{
    codec::{Decode, Lcg, Step, Wire, contract},
    onc_rpc::{Reader, Writer, XdrError},
};

fn dynamic_read(bytes: &[u8]) -> Result<xdr::Record, XdrError> {
    let mut r = Reader::new(bytes);
    let unsigned = r.uint()?;
    let signed = r.int()?;
    let wide = r.uhyper()?;
    let negative = r.hyper()?;
    let choice = match r.enumeration()? {
        -1 => xdr::Choice::Negative,
        0 => xdr::Choice::Zero,
        1 => xdr::Choice::Positive,
        n => return Err(XdrError::Discriminant(n as u32)),
    };
    let opaque = r.opaque_fixed(4)?.to_vec();
    let entries = r.array(8, Reader::uint)?;
    let maybe = r.optional(Reader::uhyper)?;
    r.finish()?;
    Ok(xdr::Record {
        unsigned,
        signed,
        wide,
        negative,
        choice,
        opaque,
        entries,
        maybe,
    })
}
fn dynamic_write(value: &xdr::Record) -> Vec<u8> {
    let mut w = Writer::new();
    w.uint(value.unsigned)
        .int(value.signed)
        .uhyper(value.wide)
        .hyper(value.negative);
    w.enumeration(match value.choice {
        xdr::Choice::Negative => -1,
        xdr::Choice::Zero => 0,
        xdr::Choice::Positive => 1,
    });
    w.opaque_fixed(&value.opaque);
    w.uint(value.entries.len() as u32);
    for n in &value.entries {
        w.uint(*n);
    }
    w.bool(value.maybe.is_some());
    if let Some(n) = value.maybe {
        w.uhyper(n);
    }
    w.finish().unwrap()
}
#[test]
fn xdr_differential_examples_generated_values_and_mutated_inputs() {
    let mut rng = Lcg::new(0x1234);
    for _ in 0..512 {
        let wide = (rng.next() << 33) | rng.next();
        let value = xdr::Record {
            unsigned: rng.next() as u32,
            signed: rng.next() as i32,
            wide,
            negative: !(wide as i64),
            choice: match rng.below(3) {
                0 => xdr::Choice::Negative,
                1 => xdr::Choice::Zero,
                _ => xdr::Choice::Positive,
            },
            opaque: vec![rng.next() as u8; 4],
            entries: (0..rng.below(9)).map(|_| rng.next() as u32).collect(),
            maybe: rng.coin().then_some(wide),
        };
        let bytes = value.to_bytes().unwrap();
        assert_eq!(bytes, dynamic_write(&value));
        assert_eq!(dynamic_read(&bytes).unwrap(), value);
        assert_eq!(xdr::Record::parse(&bytes).unwrap(), value);
        for end in 0..bytes.len() {
            let prefix = bytes.get(..end).unwrap();
            assert_eq!(xdr::Record::parse(prefix).ok(), dynamic_read(prefix).ok());
        }
        let mut mutated = bytes;
        for _ in 0..4 {
            fictionet::stdlib::codec::test_support::mutate(&mut rng, &mut mutated);
            assert_eq!(
                xdr::Record::parse(&mutated).ok(),
                dynamic_read(&mutated).ok()
            );
        }
    }
    for _ in 0..256 {
        let bytes = rng.bytes(96);
        assert_eq!(xdr::Record::parse(&bytes).ok(), dynamic_read(&bytes).ok());
    }
}
#[test]
fn recursive_depth_and_transactional_errors() {
    use recursive::{Error, Node, Nodes};
    let mut value = Node {
        value: 1,
        children: Vec::new(),
        next: None,
    };
    for _ in 0..5 {
        value = Node {
            value: 2,
            children: vec![value],
            next: None,
        };
    }
    contract::check_wire_value(&value);
    let mut framed = Vec::new();
    Nodes::write(&value, &mut framed).unwrap();
    let mut decoder = Nodes;
    assert_eq!(
        decoder.decode(&framed, false).unwrap(),
        Step::Item(value.clone(), framed.len())
    );
    for end in 0..framed.len() {
        assert_eq!(decoder.decode(&framed[..end], false).unwrap(), Step::Need);
    }
    assert_eq!(
        decoder.decode(&[70, 78, 255, 255, 255, 255], false),
        Err(Error::Limit)
    );
    assert_eq!(
        decoder.decode(&[0, 0, 0, 0, 0, 0], false),
        Err(Error::Header)
    );
    for _ in 0..recursive::MAX_DEPTH {
        value = Node {
            value: 3,
            children: Vec::new(),
            next: Some(Box::new(value)),
        };
    }
    let mut out = vec![0xaa, 0xbb];
    assert_eq!(value.write(&mut out), Err(Error::Depth));
    assert_eq!(out, [0xaa, 0xbb]);
    assert_eq!(Nodes::write(&value, &mut out), Err(Error::Depth));
    assert_eq!(out, [0xaa, 0xbb]);
    // A chain encoded directly must fail at the same depth.
    let mut bytes = Vec::new();
    for _ in 0..recursive::MAX_DEPTH {
        bytes.extend_from_slice(&[0, 0, 0, 1, 0, 1]);
    }
    bytes.extend_from_slice(&[0, 0, 0, 1, 0, 0]);
    assert_eq!(Node::parse(&bytes), Err(Error::Depth));
    contract::check_decode_with_alloc_limit(
        || Nodes,
        &bytes,
        2 * (recursive::MAX_MESSAGE + 6),
    );
}
#[test]
fn strict_data_null_float_and_set_writes() {
    use primitives::PrimitiveMessage;
    let mut value = PrimitiveMessage {
        value_u8: 255,
        value_u16: 65535,
        value_u32: 0x12345678,
        value_u64: u64::MAX,
        value_i8: i8::MIN,
        value_i16: i16::MIN,
        value_i32: i32::MIN,
        value_i64: i64::MIN,
        value_f32: -0.0,
        value_f64: 1.25,
        null_u8: None,
        null_u16: None,
        null_u32: None,
        null_u64: None,
        null_i8: None,
        null_i16: None,
        null_i32: None,
        null_i64: None,
        null_f32: None,
        null_f64: None,
        type_: vec![1, 2, 3, 4],
        fixed_text: "abc".into(),
        data: vec![5, 6],
        text: "é".into(),
        maybe: Some(7),
    };
    let bytes = value.to_bytes().unwrap();
    assert_eq!(PrimitiveMessage::parse(&bytes).unwrap(), value);
    assert_eq!(
        bytes.get(1..7),
        Some(&[255, 255, 0x12, 0x34, 0x56, 0x78][..])
    );
    let mut extra = bytes.clone();
    extra.push(0);
    assert_eq!(
        PrimitiveMessage::parse(&extra),
        Err(primitives::Error::Trailing)
    );
    value.null_u8 = Some(255);
    contract::check_wire_value(&value);
    let mut out = vec![1, 2];
    assert_eq!(value.write(&mut out), Err(primitives::Error::Value));
    assert_eq!(out, [1, 2]);
    value.null_u8 = Some(254);
    value.value_f64 = f64::NAN;
    assert_eq!(value.write(&mut out), Err(primitives::Error::Value));
    assert_eq!(out, [1, 2]);
    value.value_f64 = 0.0;
    value.type_.push(5);
    assert_eq!(value.write(&mut out), Err(primitives::Error::Limit));
    assert_eq!(out, [1, 2]);
    assert_eq!(groups::Flags(2).write(&mut out), Err(groups::Error::Value));
    assert_eq!(out, [1, 2]);
    assert_eq!(groups::Status::parse(&[0, 0]), Err(groups::Error::Value));
}
#[test]
fn arbitrary_input_contracts() {
    let mut rng = Lcg::new(13);
    for _ in 0..128 {
        let bytes = rng.bytes(128);
        contract::check_wire::<primitives::PrimitiveMessage>(&bytes);
        contract::check_wire::<groups::Batch>(&bytes);
        contract::check_wire::<recursive::Node>(&bytes);
        contract::check_decode_with_alloc_limit(
            || recursive::Nodes,
            &bytes,
            2 * (recursive::MAX_MESSAGE + 6),
        );
    }
}

#[test]
fn differential_fixture_matches_programmatic_ir() {
    use fictionet_codegen::{emit, ir::*, validate};
    let fields = [
        ("unsigned", Type::Scalar(Primitive::U32)),
        ("signed", Type::Scalar(Primitive::I32)),
        ("wide", Type::Scalar(Primitive::U64)),
        ("negative", Type::Scalar(Primitive::I64)),
        ("choice", Type::Ref("Choice".into())),
        ("opaque", Type::Bytes(Length::Fixed(4))),
        (
            "entries",
            Type::Group {
                item: Box::new(Type::Scalar(Primitive::U32)),
                count: Width::U32,
                limit: Some(8),
            },
        ),
        (
            "maybe",
            Type::Optional {
                item: Box::new(Type::Scalar(Primitive::U64)),
                presence: Presence::Flag(Width::U32),
            },
        ),
    ]
    .into_iter()
    .map(|(name, ty)| Field {
        name: name.into(),
        doc: String::new(),
        ty,
        byte_order: None,
        fixed_size: None,
        offset: None,
    })
    .collect();
    let schema = Schema {
        types: vec![
            NamedType {
                name: "Choice".into(),
                doc: String::new(),
                definition: Definition::Enum {
                    repr: Primitive::I32,
                    variants: [("negative", -1), ("zero", 0), ("positive", 1)]
                        .into_iter()
                        .map(|(name, value)| Variant {
                            name: name.into(),
                            doc: String::new(),
                            value,
                        })
                        .collect(),
                },
            },
            NamedType {
                name: "Record".into(),
                doc: String::new(),
                definition: Definition::Struct(fields),
            },
        ],
        ..Schema::default()
    };
    let source = emit(
        &validate(schema, Limits::default()).unwrap(),
        &["xdr.json".into()],
    )
    .unwrap();
    assert_eq!(source, include_str!("../codegen/tests/golden/xdr.rs"));
}

#[test]
fn generator_handles_mutated_and_arbitrary_json() {
    use fictionet_codegen::{Input, Limits, generate};
    let seed = include_bytes!("../codegen/tests/schemas/recursive.json");
    let mut rng = Lcg::new(917);
    for _ in 0..512 {
        let mut bytes = seed.to_vec();
        for _ in 0..4 {
            fictionet::stdlib::codec::test_support::mutate(&mut rng, &mut bytes);
        }
        let _ = generate(
            "ir",
            &[Input {
                name: "mutated.json".into(),
                bytes,
            }],
            Limits::default(),
        );
        let bytes = rng.bytes(512);
        let _ = generate(
            "ir",
            &[Input {
                name: "arbitrary.json".into(),
                bytes,
            }],
            Limits::default(),
        );
    }
}

#[test]
fn total_allocation_and_node_budgets_cover_empty_groups() {
    use budgets::{Bag, Empty, Error};
    // Three zero-sized entries: seven structural visits and no heap bytes.
    assert!(Bag::parse(&[3, 0]).is_ok());
    // Four entries fit the allocation budget but exceed eight structural visits.
    assert_eq!(Bag::parse(&[4, 0]), Err(Error::Limit));
    // Five entries also exceed the structural visit budget.
    assert_eq!(Bag::parse(&[5, 0]), Err(Error::Limit));
    let mut out = vec![1, 2, 3];
    let value = Bag {
        items: (0..4).map(|_| Empty {}).collect(),
        data: Vec::new(),
    };
    assert_eq!(value.write(&mut out), Err(Error::Limit));
    assert_eq!(out, [1, 2, 3]);
    let mut bytes = vec![0, 33];
    bytes.extend_from_slice(&[0; 33]);
    assert_eq!(Bag::parse(&bytes), Err(Error::Limit));
    let mut bytes = vec![0; 129];
    bytes[0] = 0;
    assert_eq!(Bag::parse(&bytes), Err(Error::Limit));
}

#[test]
fn group_counts_must_fit_the_remaining_input() {
    use fictionet::stdlib::codec::Wire;
    // A count must fit the remaining bytes before it consumes allocation budget.
    assert_eq!(groups::Batch::parse(&[255]), Err(groups::Error::Limit));
    assert_eq!(groups::Batch::parse(&[3]), Err(groups::Error::Truncated));
    assert_eq!(
        groups::TextBatch::parse(&[0, 16, 0, 0, 0]),
        Err(groups::Error::Truncated)
    );
}
