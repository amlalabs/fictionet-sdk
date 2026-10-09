//! Document entries, schema/instance pairs, formats, dependencies, and examples.
#![no_main]

use fictionet::stdlib::json::{self, Value};
use fictionet::stdlib::json_schema::{
    CompileKind, Dialect, ErrorMode, FormatPolicy, GenerationLimits, Limits, Options,
    PatternPolicy, Schema,
};
use fictionet::stdlib::test_support::contract;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let Some((&flags, rest)) = input.split_first() else {
        return;
    };
    let Some((&split, data)) = rest.split_first() else {
        return;
    };
    let at = usize::from(split).saturating_mul(data.len()) / 255;
    let (schema_bytes, instance_bytes) = data.split_at(at);
    let parse_limits = json::Limits {
        depth: 16,
        size: 8192,
        elements: 512,
    };
    let (Ok(source), Ok(instance)) = (
        json::parse_with(schema_bytes, &parse_limits),
        json::parse_with(instance_bytes, &parse_limits),
    ) else {
        return;
    };
    let options = Options {
        dialect: if flags & 1 == 0 {
            Dialect::Draft202012
        } else {
            Dialect::OpenApi30
        },
        patterns: if flags & 2 == 0 {
            PatternPolicy::Reject
        } else {
            PatternPolicy::Annotate
        },
        formats: if flags & 4 == 0 {
            FormatPolicy::Annotate
        } else {
            FormatPolicy::Assert
        },
        limits: Limits {
            schema_nodes: 512,
            instance_nodes: 512,
            bytes: 8192,
            depth: 16,
            validation_depth: 24,
            work: 50_000,
            errors: 8,
            ..Limits::default()
        },
    };
    let check = |schema: Schema| {
        let first = schema.validate(&instance);
        let all = schema.validate_with(&instance, ErrorMode::All);
        assert_eq!(first.is_valid(), all.is_valid());
        assert!(all.errors.len() <= 8);
        let bounds = GenerationLimits {
            depth: 5,
            items: 8,
            string_length: 64,
            total_nodes: 64,
            attempts: 64,
            work: 50_000,
        };
        let seed = u64::from(flags) * 256 + u64::from(split);
        let result = schema.generate(seed, bounds);
        assert_eq!(result, schema.generate(seed, bounds));
        if let Ok(example) = result {
            assert!(schema.validate(&example).is_valid());
            contract::check_wire_value(&example);
        }
    };
    if let Ok(schema) = Schema::compile_with(&source, options) {
        check(schema);
    }
    let document = Value::Object(vec![
        (
            "components".into(),
            Value::Object(vec![("schema".into(), source)]),
        ),
        (
            "body".into(),
            Value::Object(vec![("$ref".into(), Value::from("#/components/schema"))]),
        ),
        ("unrelated".into(), instance.clone()),
    ]);
    for pointer in ["/body", "/components/schema"] {
        if let Ok(schema) = Schema::compile_at(&document, pointer, options) {
            check(schema);
        }
    }
    if let Some(pointer) = instance.as_str() {
        let _ = Schema::compile_at(&document, pointer, options);
    }
    let formats = [
        "date-time",
        "date",
        "time",
        "email",
        "uuid",
        "uri",
        "ipv4",
        "ipv6",
        "hostname",
    ];
    let formatted = Value::Object(vec![
        ("type".into(), Value::from("string")),
        (
            "format".into(),
            Value::from(formats[usize::from(flags) % formats.len()]),
        ),
        ("minLength".into(), Value::from(i64::from(split % 48))),
        ("maxLength".into(), Value::from(i64::from(split % 48 + 16))),
    ]);
    if let Ok(schema) = Schema::compile_with(&formatted, options) {
        check(schema);
    }
    let dependent = Value::Object(vec![(
        "dependentSchemas".into(),
        Value::Object(vec![("trigger".into(), formatted)]),
    )]);
    if let Ok(schema) = Schema::compile_with(&dependent, options) {
        check(schema);
    }
    for keyword in [
        "unevaluatedProperties",
        "unevaluatedItems",
        "$dynamicRef",
        "$dynamicAnchor",
        "$recursiveRef",
        "contentSchema",
    ] {
        let source = Value::Object(vec![(keyword.into(), instance.clone())]);
        if let Err(error) = Schema::compile_with(&source, options) {
            assert!(matches!(
                error.kind,
                CompileKind::UnsupportedKeyword(_)
                    | CompileKind::Limit(_)
                    | CompileKind::DuplicateKey
            ));
        } else {
            panic!("unsupported keyword compiled: {keyword}");
        }
    }
});
