//! Code generator integration checks.
use fictionet_codegen::*;
fn schema(json: &str) -> Result<Schema, Error> {
    IrFrontEnd.parse(
        &[Input {
            name: "test.json".into(),
            bytes: json.as_bytes().to_vec(),
        }],
        Limits::default(),
    )
}
fn checked(json: &str) -> Result<ValidatedSchema, Error> {
    validate(schema(json)?, Limits::default())
}
fn fail(json: &str, kind: ErrorKind) {
    let e = checked(json).unwrap_err();
    assert_eq!(e.kind, kind, "{e}");
    assert!(!e.location.is_empty());
    assert!(!e.message.is_empty());
}
fn one(ty: Type) -> Schema {
    Schema {
        types: vec![NamedType {
            name: "Value".into(),
            doc: String::new(),
            definition: Definition::Struct(vec![Field {
                name: "field".into(),
                doc: String::new(),
                ty,
                byte_order: None,
                fixed_size: None,
                offset: None,
            }]),
        }],
        ..Schema::default()
    }
}
#[test]
fn scope_names_and_mapping() {
    assert_eq!(
        rust_identifier("HTTPMessage-ID", IdentifierCase::Field).unwrap(),
        "http_message_id"
    );
    assert_eq!(
        rust_identifier("9 price", IdentifierCase::Type).unwrap(),
        "N9Price"
    );
    assert_eq!(
        rust_identifier("type", IdentifierCase::Field).unwrap(),
        "type_"
    );
    assert_eq!(
        rust_identifier("Self", IdentifierCase::Type).unwrap(),
        "Self_"
    );
    for n in ["", "---", "日本語"] {
        assert_eq!(
            rust_identifier(n, IdentifierCase::Field).unwrap_err().kind,
            ErrorKind::InvalidName
        );
    }
    assert_eq!(
        rust_identifier(&"a".repeat(MAX_NAME + 1), IdentifierCase::Type)
            .unwrap_err()
            .kind,
        ErrorKind::InvalidName
    );
    fail(
        r#"{"types":[{"name":"A","kind":"struct","fields":[]},{"name":"A","kind":"struct","fields":[]}]}"#,
        ErrorKind::DuplicateName,
    );
    fail(
        r#"{"types":[{"name":"Error","kind":"struct","fields":[]}]}"#,
        ErrorKind::RustCollision,
    );
    fail(
        r#"{"types":[{"name":"A","kind":"struct","fields":[{"name":"a-b","type":"u8"},{"name":"a_b","type":"u8"}]}]}"#,
        ErrorKind::RustCollision,
    );
    fail(
        r#"{"types":[{"name":"A","kind":"struct","fields":[{"name":"x","type":"u8"},{"name":"x","type":"u16"}]}]}"#,
        ErrorKind::DuplicateName,
    );
    fail(
        r#"{"types":[{"name":"A","kind":"enum","repr":"u8","variants":[{"name":"a-b","value":1},{"name":"a_b","value":2}]}]}"#,
        ErrorKind::RustCollision,
    );
    fail(
        r#"{"types":[{"name":"---","kind":"struct","fields":[]}]}"#,
        ErrorKind::InvalidName,
    );
}
#[test]
fn scalar_widths_nulls_enums_and_sets() {
    for (repr, value) in [
        ("u8", "256"),
        ("u64", "18446744073709551616"),
        ("i8", "-129"),
        ("i64", "9223372036854775808"),
        ("f32", "1"),
    ] {
        fail(
            &format!(
                r#"{{"types":[{{"name":"A","kind":"enum","repr":"{repr}","variants":[{{"name":"v","value":{value}}}]}}]}}"#
            ),
            ErrorKind::InvalidValue,
        );
    }
    fail(
        r#"{"types":[{"name":"A","kind":"enum","repr":"u8","variants":[]}]}"#,
        ErrorKind::InvalidValue,
    );
    fail(
        r#"{"types":[{"name":"A","kind":"enum","repr":"u8","variants":[{"name":"a","value":1},{"name":"b","value":1}]}]}"#,
        ErrorKind::InvalidValue,
    );
    fail(
        r#"{"types":[{"name":"A","kind":"set","repr":"u8","bits":[{"name":"a","bit":8}]}]}"#,
        ErrorKind::InvalidValue,
    );
    fail(
        r#"{"types":[{"name":"A","kind":"set","repr":"u64","bits":[{"name":"a","bit":63},{"name":"b","bit":63}]}]}"#,
        ErrorKind::InvalidValue,
    );
    for (p, n) in [
        (Primitive::U8, Number::Integer(256)),
        (Primitive::I8, Number::Integer(-129)),
        (Primitive::F32, Number::Float(0.1)),
        (Primitive::F64, Number::Float(f64::INFINITY)),
        (Primitive::F64, Number::Float(f64::NAN)),
    ] {
        let s = one(Type::Optional {
            item: Box::new(Type::Scalar(p)),
            presence: Presence::Null(n),
        });
        assert_eq!(
            validate(s, Limits::default()).unwrap_err().kind,
            ErrorKind::InvalidValue
        );
    }
    for (repr, min, max, null, valid) in [
        ("i64", "1", "3", "1", false),
        ("i64", "1", "3", "3", false),
        ("i64", "1", "3", "2", false),
        ("i64", "1", "3", "0", true),
        ("f64", "1.0", "3.0", "1", false),
        ("f64", "1", "3", "3.0", false),
        ("f64", "1", "3.0", "1.5", false),
        ("f64", "1.0", "3", "0.5", true),
        ("u64", "9007199254740993", "9007199254740995", "9007199254740992", true),
        ("i64", "-9007199254740995", "-9007199254740993", "-9007199254740992", true),
        ("f64", "9007199254740992", "9007199254740994.0", "9007199254740994", false),
        ("f64", "9007199254740992.0", "9007199254740994", "9007199254740996", true),
        ("f64", "1", "3", "170141183460469231731687303715884105727", false),
    ] {
        let json = format!(
            r#"{{"types":[{{"name":"A","kind":"struct","fields":[{{"name":"x","type":{{"kind":"optional","null":{null},"item":{{"kind":"range","item":"{repr}","min":{min},"max":{max}}}}}}}]}}]}}"#
        );
        if valid {
            checked(&json).unwrap();
        } else {
            fail(&json, ErrorKind::InvalidValue);
        }
    }
    fail(
        r#"{"types":[{"name":"A","kind":"struct","fields":[{"name":"x","type":{"kind":"optional","item":{"kind":"bytes","size":1},"null":0}}]}]}"#,
        ErrorKind::InvalidValue,
    );
    fail(
        r#"{"types":[{"name":"A","kind":"struct","fields":[{"name":"x","type":"u16","fixed_size":1}]}]}"#,
        ErrorKind::InvalidSize,
    );
}
#[test]
fn limits_and_references() {
    let checked = validate(
        one(Type::Bytes(Length::Variable {
            prefix: Width::U8,
            limit: None,
        })),
        Limits::default(),
    )
    .unwrap();
    let Definition::Struct(fs) = &checked.schema().types[0].definition else {
        panic!()
    };
    assert_eq!(
        fs[0].ty,
        Type::Bytes(Length::Variable {
            prefix: Width::U8,
            limit: Some(255)
        })
    );
    assert_eq!(
        validate(
            one(Type::Bytes(Length::Variable {
                prefix: Width::U8,
                limit: Some(256)
            })),
            Limits::default()
        )
        .unwrap_err()
        .kind,
        ErrorKind::InvalidLimit
    );
    assert_eq!(
        validate(
            one(Type::Bytes(Length::Fixed(DEFAULT_MAX_MESSAGE + 1))),
            Limits::default()
        )
        .unwrap_err()
        .kind,
        ErrorKind::InvalidSize
    );
    assert_eq!(
        validate(
            Schema::default(),
            Limits {
                max_depth: 65,
                ..Limits::default()
            }
        )
        .unwrap_err()
        .kind,
        ErrorKind::InvalidLimit
    );
    assert_eq!(
        validate(one(Type::Ref("missing".into())), Limits::default())
            .unwrap_err()
            .kind,
        ErrorKind::UnknownReference
    );
    assert_eq!(
        validate(one(Type::Ref("Value".into())), Limits::default())
            .unwrap_err()
            .kind,
        ErrorKind::UninhabitedType
    );
    fail(
        r#"{"types":[],"streams":[{"name":"Frames","item":"missing","prefix":"u16"}]}"#,
        ErrorKind::UnknownReference,
    );
    let mut ty = Type::Scalar(Primitive::U8);
    for _ in 0..MAX_NESTING {
        ty = Type::Optional {
            item: Box::new(ty),
            presence: Presence::Flag(Width::U8),
        };
    }
    assert_eq!(
        validate(one(ty), Limits::default()).unwrap_err().kind,
        ErrorKind::IrLimit
    );
    let mut s = Schema::default();
    for i in 0..=MAX_TYPES {
        s.types.push(NamedType {
            name: format!("T{i}"),
            doc: String::new(),
            definition: Definition::Struct(Vec::new()),
        });
    }
    assert_eq!(
        validate(s, Limits::default()).unwrap_err().kind,
        ErrorKind::IrLimit
    );
    let mut s = one(Type::Scalar(Primitive::U8));
    s.doc = "x".repeat(MAX_DOC + 1);
    assert_eq!(
        validate(s, Limits::default()).unwrap_err().kind,
        ErrorKind::IrLimit
    );
}
#[test]
fn mutual_cycles_and_fixed_reference_sizes() {
    let v = checked(r#"{"types":[{"name":"A","kind":"struct","fields":[{"name":"b","type":{"kind":"ref","name":"B"}}]},{"name":"B","kind":"struct","fields":[{"name":"a","type":{"kind":"optional","flag":"u8","item":{"kind":"ref","name":"A"}}}]}]}"#).unwrap();
    assert_eq!(v.recursive_types().collect::<Vec<_>>(), ["A", "B"]);
    checked(r#"{"types":[{"name":"A","kind":"struct","fields":[{"name":"b","fixed_size":4,"type":{"kind":"ref","name":"B"}}]},{"name":"B","kind":"struct","fields":[{"name":"x","type":"u32"}]}]}"#).unwrap();
}
#[test]
fn bounded_strict_json() {
    for bad in [
        "",
        "[]{}",
        "{\"types\":[],\"types\":[]}",
        "{\"types\":[],,}",
        "{\"types\":[] /*x*/}",
        "{\"doc\":\"\\uD800\",\"types\":[]}",
        "{\"doc\":\"\\uDC00\",\"types\":[]}",
        "{\"doc\":\"\\q\",\"types\":[]}",
        "01",
        "1.",
        "1e",
        "[1,]",
        "\"a\nb\"",
    ] {
        assert_eq!(
            schema(bad).unwrap_err().kind,
            ErrorKind::JsonSyntax,
            "{bad}"
        );
    }
    for bad in [
        "[]",
        "null",
        "false",
        "1",
        "{}",
        r#"{"types":[],"typo":1}"#,
        r#"{"types":[],"byte_order":"native"}"#,
        r#"{"types":[{"name":"A","kind":"struct","fields":[{"name":"x","type":"uint"}]}]}"#,
    ] {
        assert_eq!(schema(bad).unwrap_err().kind, ErrorKind::JsonShape, "{bad}");
    }
    checked(r#"{"doc":"\uD83D\uDE00 and café","types":[]}"#).unwrap();
    assert_eq!(
        schema(&" ".repeat(MAX_INPUT + 1)).unwrap_err().kind,
        ErrorKind::InputLimit
    );
    assert_eq!(
        schema(&format!(
            "{}0{}",
            "[".repeat(MAX_JSON_DEPTH),
            "]".repeat(MAX_JSON_DEPTH)
        ))
        .unwrap_err()
        .kind,
        ErrorKind::InputLimit
    );
    assert_eq!(
        schema(&format!("[{}0]", "0,".repeat(MAX_JSON_ELEMENTS)))
            .unwrap_err()
            .kind,
        ErrorKind::InputLimit
    );
    let error = IrFrontEnd
        .parse(
            &[Input {
                name: "bad".into(),
                bytes: vec![b'"', 0xff, b'"'],
            }],
            Limits::default(),
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::JsonSyntax);
    assert_eq!(
        generate("unknown", &[], Limits::default())
            .unwrap_err()
            .kind,
        ErrorKind::UnknownFormat
    );
}

#[test]
fn rejected_deep_ir_is_disposed_without_recursive_drop() {
    let mut ty = Type::Scalar(Primitive::U8);
    for _ in 0..20_000 {
        ty = Type::Group {
            item: Box::new(ty),
            count: Width::U8,
            limit: Some(0),
        };
    }
    assert_eq!(
        validate(one(ty), Limits::default()).unwrap_err().kind,
        ErrorKind::IrLimit
    );
}

#[test]
fn integer_float_nulls_must_be_exact_even_at_i128_edges() {
    for (p, n, accepted) in [
        (Primitive::F64, i128::MAX, false),
        (Primitive::F64, i128::MIN, true),
        (Primitive::F64, (1i128 << 53) + 1, false),
        (Primitive::F32, (1i128 << 24) + 1, false),
        (Primitive::F32, 1i128 << 24, true),
    ] {
        let ty = Type::Optional {
            item: Box::new(Type::Scalar(p)),
            presence: Presence::Null(Number::Integer(n)),
        };
        assert_eq!(validate(one(ty), Limits::default()).is_ok(), accepted);
    }
}

#[test]
fn diagnostic_locations_do_not_copy_unbounded_names() {
    let mut schema = one(Type::Scalar(Primitive::U8));
    schema.types[0].name = "x".repeat(MAX_INPUT);
    let error = validate(schema, Limits::default()).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidName);
    assert!(error.location.len() < MAX_NAME);
    let error = IrFrontEnd
        .parse(
            &[Input {
                name: "x".repeat(MAX_INPUT + 1),
                bytes: Vec::new(),
            }],
            Limits::default(),
        )
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::InputLimit);
    assert!(error.location.len() < MAX_NAME);
}

#[test]
fn minimum_depth_and_message_size_must_fit() {
    let mut chain = Schema::default();
    for i in 0..=40 {
        let mut named = one(if i == 40 {
            Type::Scalar(Primitive::U8)
        } else {
            Type::Ref(format!("C{}", i + 1))
        })
        .types
        .remove(0);
        named.name = format!("C{i}");
        chain.types.push(named);
    }
    assert_eq!(
        validate(chain.clone(), Limits::default()).unwrap_err().kind,
        ErrorKind::IrLimit
    );
    validate(
        chain,
        Limits {
            max_depth: 41,
            ..Limits::default()
        },
    )
    .unwrap();

    let pair = schema(r#"{"types":[{"name":"A","kind":"struct","fields":[{"name":"b","type":{"kind":"ref","name":"B"}}]},{"name":"B","kind":"enum","repr":"u8","variants":[{"name":"v","value":1}]}]}"#).unwrap();
    assert_eq!(
        validate(
            pair.clone(),
            Limits {
                max_depth: 1,
                ..Limits::default()
            }
        )
        .unwrap_err()
        .kind,
        ErrorKind::IrLimit
    );
    validate(
        pair,
        Limits {
            max_depth: 2,
            max_message: 1,
            ..Limits::default()
        },
    )
    .unwrap();

    let mut s = one(Type::Bytes(Length::Fixed(DEFAULT_MAX_MESSAGE)));
    let Definition::Struct(fs) = &mut s.types[0].definition else {
        unreachable!()
    };
    let mut second = fs[0].clone();
    second.name = "second".into();
    fs.push(second);
    assert_eq!(
        validate(s, Limits::default()).unwrap_err().kind,
        ErrorKind::IrLimit
    );
    for ty in [
        Type::Optional {
            item: Box::new(Type::Ref("Value".into())),
            presence: Presence::Flag(Width::U8),
        },
        Type::Group {
            item: Box::new(Type::Ref("Value".into())),
            count: Width::U8,
            limit: Some(1),
        },
    ] {
        validate(
            one(ty),
            Limits {
                max_depth: 1,
                max_message: 1,
                ..Limits::default()
            },
        )
        .unwrap();
    }
}

#[test]
fn public_fields_show_types_and_only_inline_cycles_need_boxes() {
    let groups = emit(&checked(include_str!("schemas/groups.json")).unwrap(), &[]).unwrap();
    for declaration in [
        "pub status: Status,",
        "pub flags: Flags,",
        "pub values: Vec<Vec<i32>>,",
        "pub entries: Vec<Entry>,",
        "pub label: Option<String>,",
    ] {
        assert!(groups.contains(declaration), "missing {declaration}");
    }
    let recursive = emit(
        &checked(include_str!("schemas/recursive.json")).unwrap(),
        &[],
    )
    .unwrap();
    assert!(recursive.contains("pub children: Vec<Node>,"));
    assert!(recursive.contains("pub next: Option<Box<Node>>,"));
    let mutual = checked(r#"{"types":[{"name":"A","kind":"struct","fields":[{"name":"b","type":{"kind":"ref","name":"B"}}]},{"name":"B","kind":"struct","fields":[{"name":"a","type":{"kind":"optional","flag":"u8","item":{"kind":"ref","name":"A"}}}]},{"name":"C","kind":"struct","fields":[{"name":"a","type":{"kind":"ref","name":"A"}},{"name":"c","type":{"kind":"optional","flag":"u8","item":{"kind":"ref","name":"C"}}}]}]}"#).unwrap();
    let source = emit(&mutual, &[]).unwrap();
    assert!(source.contains("pub b: Box<B>,"));
    assert!(source.contains("pub a: Option<Box<A>>,"));
    assert!(source.contains("pub a: A,"));
    let vector_cycle = checked(r#"{"types":[{"name":"A","kind":"struct","fields":[{"name":"b","type":{"kind":"ref","name":"B"}}]},{"name":"B","kind":"struct","fields":[{"name":"a","type":{"kind":"group","count":"u8","item":{"kind":"ref","name":"A"}}}]}]}"#).unwrap();
    assert_eq!(
        vector_cycle.recursive_types().collect::<Vec<_>>(),
        ["A", "B"]
    );
    let source = emit(&vector_cycle, &[]).unwrap();
    assert!(source.contains("pub b: B,"));
    assert!(source.contains("pub a: Vec<A>,"));
}

#[test]
fn float_null_decimals_round_trip_at_their_width() {
    for (repr, literal, accepted) in [
        ("f32", "1e-400", false),
        ("f64", "1e-400", false),
        ("f32", "-1e-400", false),
        ("f64", "-1e-400", false),
        ("f32", "1.00000001", false),
        ("f64", "0.10000000000000001", false),
        ("f32", "0.1", true),
        ("f64", "0.1", true),
        ("f32", "1.2500e0", true),
        ("f64", "125e-2", true),
        ("f32", "3.4028235e38", true),
        ("f64", "1.7976931348623157e308", true),
        ("f32", "1e-45", true),
        ("f64", "5e-324", true),
        ("f32", "-0.0", true),
        ("f64", "0.00e123", true),
        ("f32", "1e39", false),
        ("f64", "1e309", false),
    ] {
        let input = format!(
            r#"{{"types":[{{"name":"A","kind":"struct","fields":[{{"name":"n","type":{{"kind":"optional","item":"{repr}","null":{literal}}}}}]}}]}}"#
        );
        assert_eq!(checked(&input).is_ok(), accepted, "{repr}: {literal}");
    }
    let s = one(Type::Optional {
        item: Box::new(Type::Scalar(Primitive::F32)),
        presence: Presence::Null(Number::Float(f64::from(f32::MAX))),
    });
    let source = emit(&validate(s, Limits::default()).unwrap(), &[]).unwrap();
    assert!(source.contains("3.4028235e38f32"));
    assert!(!source.contains("3.4028234663852886"));
}

#[test]
fn wire_docs_name_only_applicable_value_refusals() {
    let source = emit(
        &checked(include_str!("schemas/short_names.json")).unwrap(),
        &[],
    )
    .unwrap();
    let wire = source
        .split("impl fictionet::stdlib::codec::Wire for A {")
        .nth(1)
        .unwrap()
        .split("/// Frames of")
        .next()
        .unwrap();
    assert!(wire.contains("unknown enum values"));
    for irrelevant in [
        "non-finite",
        "nulls",
        "UTF-8",
        "fixed data",
        "set bits",
        "flags other",
    ] {
        assert!(!wire.contains(irrelevant), "{irrelevant}");
    }
    let source = emit(&checked(include_str!("schemas/groups.json")).unwrap(), &[]).unwrap();
    let entry = source
        .split("impl fictionet::stdlib::codec::Wire for Entry {")
        .nth(1)
        .unwrap()
        .split("#[doc =")
        .next()
        .unwrap();
    assert!(entry.contains("unknown enum values"));
    assert!(entry.contains("undeclared set bits"));
    assert!(!entry.contains("UTF-8"));
}

const HEADER: &str = r#"{"size":4,"fields":[{"name":"len","offset":0,"width":"u16","role":"length"},{"name":"n","offset":2,"width":"u8","role":"count"}]}"#;
fn with_entry(field: &str) -> String {
    format!(
        r#"{{"types":[{{"name":"E","kind":"enum","repr":"u8","variants":[{{"name":"a","value":1}}]}},{{"name":"B","kind":"block","length":2,"fields":[{{"name":"x","type":"u16"}}]}},{{"name":"S","kind":"struct","fields":[{field}]}}]}}"#
    )
}
fn union(header: &str, cases: &str) -> String {
    format!(
        r#"{{"types":[{{"name":"B","kind":"block","length":2,"fields":[{{"name":"x","type":"u16"}}]}},{{"name":"T","kind":"struct","fields":[]}},{{"name":"U","kind":"union","header":{header},"cases":[{cases}]}}]}}"#
    )
}
const UNION_HEADER: &str = r#"{"size":4,"fields":[{"name":"len","offset":0,"width":"u16","role":"length"},{"name":"tag","offset":2,"width":"u16","role":"tag","max":100}]}"#;

#[test]
fn ranges_constants_and_null_enums() {
    checked(&with_entry(
        r#"{"name":"r","type":{"kind":"range","item":"i8","min":-5,"max":5}},
           {"name":"c","type":{"kind":"constant","item":"u8","value":7}},
           {"name":"k","type":{"kind":"constant","enum":"E","variant":"a"}},
           {"name":"b","type":{"kind":"constant","bytes":[1,2]}},
           {"name":"o","type":{"kind":"optional","item":{"kind":"ref","name":"E"},"null":0}},
           {"name":"p","type":{"kind":"optional","item":{"kind":"range","item":"u8","min":1,"max":9},"null":0}}"#,
    ))
    .unwrap();
    for field in [
        r#"{"name":"r","type":{"kind":"range","item":"i8","min":5,"max":-5}}"#,
        r#"{"name":"r","type":{"kind":"range","item":"u8","min":0,"max":256}}"#,
        r#"{"name":"c","type":{"kind":"constant","item":"u8","value":-1}}"#,
        r#"{"name":"c","type":{"kind":"constant","enum":"E","variant":"zzz"}}"#,
        r#"{"name":"c","type":{"kind":"constant","enum":"B","variant":"x"}}"#,
        r#"{"name":"g","type":{"kind":"optional","flag":"u8","item":{"kind":"constant","item":"u8","value":1}}}"#,
        r#"{"name":"o","type":{"kind":"optional","item":{"kind":"ref","name":"E"},"null":1}}"#,
        r#"{"name":"o","type":{"kind":"optional","item":{"kind":"ref","name":"E"},"null":256}}"#,
        r#"{"name":"o","type":{"kind":"optional","item":{"kind":"ref","name":"B"},"null":0}}"#,
        r#"{"name":"g","type":{"kind":"block_group","item":"E","header":HEADER}}"#,
        r#"{"name":"g","type":{"kind":"block_group","item":"S","header":HEADER}}"#,
    ] {
        fail(
            &with_entry(&field.replace("HEADER", HEADER)),
            ErrorKind::InvalidValue,
        );
    }
    fail(
        &with_entry(r#"{"name":"c","type":{"kind":"constant","enum":"Q","variant":"a"}}"#),
        ErrorKind::UnknownReference,
    );
    fail(
        &with_entry(r#"{"name":"c","type":{"kind":"constant","item":"u8","value":1},"offset":0}"#),
        ErrorKind::InvalidSize,
    );
    let mut s = one(Type::Constant(Constant::Bytes(vec![0; MAX_CONSTANT + 1])));
    assert_eq!(
        validate(s.clone(), Limits::default()).unwrap_err().kind,
        ErrorKind::InvalidValue
    );
    s.types[0].definition = Definition::Struct(vec![]);
    validate(s, Limits::default()).unwrap();
}

#[test]
fn offsets_and_block_layouts() {
    let ok = checked(
        r#"{"types":[{"name":"S","kind":"struct","fields":[{"name":"a","type":"u8"},{"name":"b","type":"u16","offset":4}]},
            {"name":"T","kind":"struct","fields":[{"name":"s","type":{"kind":"ref","name":"S"},"fixed_size":6}]}]}"#,
    );
    ok.unwrap();
    for json in [
        r#"{"types":[{"name":"S","kind":"struct","fields":[{"name":"a","type":"u16"},{"name":"b","type":"u8","offset":1}]}]}"#,
        r#"{"types":[{"name":"S","kind":"struct","fields":[{"name":"a","type":{"kind":"bytes","prefix":"u8"}},{"name":"b","type":"u8","offset":9}]}]}"#,
        r#"{"types":[{"name":"B","kind":"block","length":1,"fields":[{"name":"a","type":"u16"}]}]}"#,
        r#"{"types":[{"name":"B","kind":"block","length":4,"fields":[{"name":"a","type":{"kind":"bytes","prefix":"u8"}},{"name":"b","type":"u8"}]}]}"#,
        r#"{"types":[{"name":"B","kind":"block","length":2000000,"fields":[]}]}"#,
    ] {
        fail(json, ErrorKind::InvalidSize);
    }
    for offset in [0, 4, 8] {
        let fields = format!(
            r#"[{{"name":"data","type":{{"kind":"bytes","prefix":"u8"}},"offset":{offset}}}]"#
        );
        let json = format!(
            r#"{{"types":[{{"name":"B","kind":"block","length":4,"fields":{fields}}}]}}"#
        );
        fail(&json, ErrorKind::InvalidSize);
        assert_eq!(checked(&json).unwrap_err().location, "types.B.data");
        checked(&format!(
            r#"{{"types":[{{"name":"S","kind":"struct","fields":{fields}}}]}}"#
        )).unwrap();
    }
    let blocks = checked(
        r#"{"types":[{"name":"B","kind":"block","length":8,"fields":[{"name":"a","type":"u16"}]},
            {"name":"S","kind":"struct","fields":[{"name":"b","type":{"kind":"ref","name":"B"},"fixed_size":8}]}]}"#,
    );
    blocks.unwrap();
}

#[test]
fn headers_unions_and_block_groups() {
    checked(&union(
        UNION_HEADER,
        r#"{"name":"b","tag":1,"item":"B"},{"name":"c","tag":2,"item":"B"}"#,
    ))
    .unwrap();
    checked(&union(
        r#"{"size":1,"fields":[{"name":"tag","offset":0,"width":"u8","role":"tag"}]}"#,
        r#"{"name":"t","tag":1,"item":"T"}"#,
    ))
    .unwrap();
    for (header, cases) in [
        (
            UNION_HEADER,
            r#"{"name":"b","tag":1,"item":"B"},{"name":"c","tag":1,"item":"B"}"#,
        ),
        (UNION_HEADER, r#"{"name":"b","tag":101,"item":"B"}"#),
        (UNION_HEADER, r#"{"name":"t","tag":1,"item":"T"}"#),
        (UNION_HEADER, ""),
        (
            r#"{"size":2,"fields":[{"name":"len","offset":0,"width":"u16","role":"length"}]}"#,
            r#"{"name":"b","tag":1,"item":"B"}"#,
        ),
        (
            r#"{"size":2,"fields":[{"name":"t","offset":0,"width":"u8","role":"tag"},{"name":"n","offset":1,"width":"u8","role":"count"}]}"#,
            r#"{"name":"t","tag":1,"item":"T"}"#,
        ),
        (
            r#"{"size":2,"fields":[{"name":"t","offset":0,"width":"u8","role":"tag","max":300}]}"#,
            r#"{"name":"t","tag":1,"item":"T"}"#,
        ),
        (
            r#"{"size":2,"fields":[{"name":"t","offset":0,"width":"u8","role":"tag"},{"name":"c","offset":1,"width":"u8","role":"constant","value":9,"max":8}]}"#,
            r#"{"name":"t","tag":1,"item":"T"}"#,
        ),
        (
            r#"{"size":2,"fields":[{"name":"t","offset":0,"width":"u8","role":"tag"},{"name":"v","offset":1,"width":"u8","role":"version","current":1,"minimum":2}]}"#,
            r#"{"name":"t","tag":1,"item":"T"}"#,
        ),
    ] {
        fail(&union(header, cases), ErrorKind::InvalidValue);
    }
    for header in [
        r#"{"size":2,"fields":[{"name":"t","offset":0,"width":"u16","role":"tag"},{"name":"c","offset":1,"width":"u8","role":"constant","value":1}]}"#,
        r#"{"size":1,"fields":[{"name":"t","offset":0,"width":"u16","role":"tag"}]}"#,
    ] {
        fail(
            &union(header, r#"{"name":"t","tag":1,"item":"T"}"#),
            ErrorKind::InvalidSize,
        );
    }
    fail(
        &union(
            r#"{"size":300,"fields":[{"name":"t","offset":0,"width":"u8","role":"tag"}]}"#,
            r#"{"name":"t","tag":1,"item":"T"}"#,
        ),
        ErrorKind::IrLimit,
    );
    fail(
        &union(UNION_HEADER, r#"{"name":"b","tag":1,"item":"Q"}"#),
        ErrorKind::UnknownReference,
    );
    fail(
        &union(
            UNION_HEADER,
            r#"{"name":"b","tag":1,"item":"B"},{"name":"b","tag":2,"item":"B"}"#,
        ),
        ErrorKind::DuplicateName,
    );
    // A union inside its own case is refused, even through a group.
    fail(
        r#"{"types":[{"name":"S","kind":"struct","fields":[{"name":"u","type":{"kind":"group","count":"u8","item":{"kind":"ref","name":"U"}}}]},
            {"name":"U","kind":"union","header":{"size":1,"fields":[{"name":"t","offset":0,"width":"u8","role":"tag"}]},"cases":[{"name":"s","tag":1,"item":"S"}]}]}"#,
        ErrorKind::IrLimit,
    );
    let group = |limit: &str, max: &str| {
        with_entry(&format!(
            r#"{{"name":"g","type":{{"kind":"block_group","item":"B",{limit}"header":{{"size":3,"fields":[{{"name":"len","offset":0,"width":"u16","role":"length"{max}}},{{"name":"n","offset":2,"width":"u8","role":"count","max":10}}]}}}}}}"#
        ))
    };
    let checked_group = checked(&group("", "")).unwrap();
    let Definition::Struct(fields) = &checked_group.schema().types[2].definition else {
        panic!()
    };
    assert!(matches!(
        fields[0].ty,
        Type::BlockGroup {
            limit: Some(10),
            ..
        }
    ));
    fail(&group(r#""limit":11,"#, ""), ErrorKind::InvalidLimit);
    fail(&group("", r#","max":1"#), ErrorKind::InvalidValue);
}
