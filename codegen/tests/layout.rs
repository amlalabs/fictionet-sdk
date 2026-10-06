//! Layout checks over schema shapes and the full identifier range.
use fictionet_codegen::*;
mod support;
use support::{Scratch, check_rustfmt, compile_and_run, rustfmt_available};

fn field(name: String, ty: Type) -> Field {
    Field {
        name,
        ty,
        doc: String::new(),
        byte_order: None,
        fixed_size: None,
    }
}
fn named(name: String, definition: Definition) -> NamedType {
    NamedType {
        name,
        definition,
        doc: String::new(),
    }
}
fn layout_schema(n: usize) -> Schema {
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
#[test]
fn all_name_lengths_are_rustfmt_clean() {
    if !rustfmt_available() {
        return;
    }
    let scratch = Scratch::new();
    let mut files = Vec::new();
    for n in 1..=MAX_NAME {
        let checked = validate(layout_schema(n), Limits::default()).unwrap();
        let path = scratch.0.join(format!("length_{n}.rs"));
        std::fs::write(&path, emit(&checked, &[]).unwrap()).unwrap();
        files.push(path);
        let path = scratch.0.join(format!("fuzz_{n}.rs"));
        std::fs::write(
            &path,
            emit_fuzz(&checked, &format!("length_{n}.rs"), &[]).unwrap(),
        )
        .unwrap();
        files.push(path);
    }
    check_rustfmt(&files);
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
#[test]
fn random_valid_schemas_are_deterministic_and_rustfmt_clean() {
    let scratch = Scratch::new();
    let mut files = Vec::new();
    for seed in 0..64 {
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
        let checked = validate(schema, Limits::default()).unwrap();
        let source = emit(&checked, &[]).unwrap();
        assert_eq!(source, emit(&checked, &[]).unwrap(), "seed {seed}");
        let path = scratch.0.join(format!("seed_{seed}.rs"));
        std::fs::write(&path, source).unwrap();
        files.push(path);
    }
    if rustfmt_available() {
        check_rustfmt(&files);
    }
    compile_and_run(&files, &scratch);
}
