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
