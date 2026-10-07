//! Schemas for the layout checks. `codegen/tests/layout.rs` checks them,
//! and the build script of `codegen/tests/layouts` generates the random
//! ones into a crate that compiles them against the SDK and runs their
//! tests.
use fictionet_codegen::*;

/// The random schemas are generated from the seeds `0..SEEDS`.
pub const SEEDS: u64 = 64;

fn field(name: String, ty: Type) -> Field {
    Field {
        name,
        ty,
        doc: String::new(),
        byte_order: None,
        fixed_size: None,
        offset: None,
    }
}
fn named(name: String, definition: Definition) -> NamedType {
    NamedType {
        name,
        definition,
        doc: String::new(),
    }
}
pub fn layout_schema(n: usize) -> Schema {
    let s = "s".repeat(n);
    let e = "e".repeat(n);
    let b = "b".repeat(n);
    Schema {
        types: vec![
            named(
                s.clone(),
                Definition::Struct(vec![field("f".repeat(n), Type::Scalar(Primitive::U8))]),
            ),
            named(
                e.clone(),
                Definition::Enum {
                    repr: Primitive::I64,
                    variants: vec![
                        Variant {
                            name: "v".repeat(n),
                            doc: String::new(),
                            value: i64::MIN.into(),
                        },
                        Variant {
                            name: "w".repeat(n),
                            doc: String::new(),
                            value: i64::MAX.into(),
                        },
                    ],
                },
            ),
            named(
                b,
                Definition::Set {
                    repr: Width::U64,
                    bits: vec![Bit {
                        name: "a".repeat(n),
                        doc: String::new(),
                        bit: 63,
                    }],
                },
            ),
            named(
                "Refs".into(),
                Definition::Struct(vec![field("r".repeat(n), Type::Ref(e))]),
            ),
            named("Empty".into(), Definition::Struct(vec![])),
        ],
        streams: vec![Stream {
            name: "d".repeat(n),
            item: s,
            prefix: Width::U32,
            byte_order: ByteOrder::Big,
            magic: vec![],
        }],
        ..Schema::default()
    }
}

/// A valid schema with random fields, the same for the same seed.
pub fn random_schema(seed: u64) -> ValidatedSchema {
    let mut rng = Random(seed);
    let mut schema = layout_schema(1 + rng.below(MAX_NAME));
    let reference = schema.types[1].name.clone();
    let fields = (0..rng.below(8))
        .map(|i| {
            let mut f = field(
                format!("f{i}{}", "x".repeat(rng.below(MAX_NAME - 3))),
                rng.ty(4, &reference),
            );
            f.byte_order = [None, Some(ByteOrder::Big), Some(ByteOrder::Little)][rng.below(3)];
            f
        })
        .collect();
    schema.types[0].definition = Definition::Struct(fields);
    validate(schema, Limits::default()).unwrap()
}

struct Random(u64);
impl Random {
    fn below(&mut self, n: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 32) as usize) % n
    }
    fn ty(&mut self, depth: usize, reference: &str) -> Type {
        let scalar = [
            Primitive::U8,
            Primitive::U64,
            Primitive::I64,
            Primitive::F32,
            Primitive::F64,
        ][self.below(5)];
        match self.below(if depth == 0 { 5 } else { 8 }) {
            0 => Type::Scalar(scalar),
            1 => Type::Ref(reference.into()),
            2 => Type::Bytes(Length::Fixed(self.below(8))),
            3 => Type::String(Length::Variable {
                prefix: Width::U16,
                limit: Some(self.below(16)),
            }),
            4 => Type::Optional {
                item: Box::new(Type::Scalar(scalar)),
                presence: Presence::Null(Number::Integer(0)),
            },
            5 => Type::Optional {
                item: Box::new(self.ty(depth - 1, reference)),
                presence: Presence::Flag(Width::U8),
            },
            _ => Type::Group {
                item: Box::new(self.ty(depth - 1, reference)),
                count: Width::U32,
                limit: Some(self.below(8)),
            },
        }
    }
}
