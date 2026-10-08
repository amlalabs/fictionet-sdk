//! Schema validation and mock values using only the public API.
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::contract;
use fictionet::stdlib::test_support;
use fictionet::stdlib::json::{self, Value};
use fictionet::stdlib::json_schema::{
    Dialect, ErrorMode, GenerationLimits, Options, Schema, ValidationKind,
};

fn parse(bytes: &[u8]) -> Value {
    json::parse_with(bytes, &json::Limits::default()).unwrap()
}

#[test]
fn mcp_tool_input_schema_and_mock_arguments() {
    let tool = parse(
        br#"{
        "name":"lookup_customer",
        "inputSchema":{
            "type":"object",
            "properties":{
                "customer/id":{"type":"integer","minimum":1},
                "include_notes":{"type":"boolean"},
                "limit":{"type":"integer","minimum":1,"maximum":10}
            },
            "required":["customer/id"],
            "additionalProperties":false
        }
    }"#,
    );
    let schema = Schema::compile(tool.get("inputSchema").unwrap()).unwrap();
    let args = parse(br#"{"customer/id":42,"include_notes":true}"#);
    assert!(schema.validate(&args).is_valid());
    let report = schema.validate_with(
        &parse(br#"{"customer/id":0,"limit":"ten"}"#),
        ErrorMode::All,
    );
    assert_eq!(report.errors.len(), 2);
    assert_eq!(report.errors[0].instance_path, "/customer~1id");
    assert_eq!(
        report.errors[0].schema_path,
        "/properties/customer~1id/minimum"
    );
    assert_eq!(report.errors[0].kind, ValidationKind::Assertion("minimum"));
    assert_eq!(report.errors[1].instance_path, "/limit");
    for seed in 0..100 {
        let example = schema.generate(seed, GenerationLimits::default()).unwrap();
        assert!(schema.validate(&example).is_valid());
        assert_eq!(
            example,
            schema.generate(seed, GenerationLimits::default()).unwrap()
        );
        contract::check_wire_value(&example);
        let bytes = example.to_bytes().unwrap();
        let (streamed, failure) = test_support::decode_all(json::Values::default, &bytes);
        assert!(failure.is_none());
        assert_eq!(streamed, [example]);
    }
}

#[test]
fn openapi30_nullable_request_body_and_examples() {
    let request_body = parse(
        br#"{
        "required":true,
        "content":{"application/json":{"schema":{
            "type":"object",
            "properties":{
                "name":{"type":"string","minLength":1,"example":"Ada"},
                "note":{"type":"string","nullable":true},
                "amount":{"type":"number","minimum":0,"exclusiveMinimum":true}
            },
            "required":["name","note","amount"],
            "additionalProperties":false
        }}}
    }"#,
    );
    let source = request_body
        .get("content")
        .unwrap()
        .get("application/json")
        .unwrap()
        .get("schema")
        .unwrap();
    let schema = Schema::compile_with(
        source,
        Options {
            dialect: Dialect::OpenApi30,
            ..Options::default()
        },
    )
    .unwrap();
    assert!(
        schema
            .validate(&parse(br#"{"name":"Ada","note":null,"amount":0.01}"#))
            .is_valid()
    );
    let report = schema.validate(&parse(br#"{"name":"Ada","note":null,"amount":0}"#));
    assert_eq!(report.errors[0].instance_path, "/amount");
    assert_eq!(
        report.errors[0].schema_path,
        "/properties/amount/exclusiveMinimum"
    );
    for seed in 0..100 {
        let example = schema.generate(seed, GenerationLimits::default()).unwrap();
        assert!(schema.validate(&example).is_valid());
    }
    assert_eq!(
        Schema::compile(source).unwrap_err().schema_path,
        "/properties/amount/exclusiveMinimum"
    );
}

#[test]
fn copied_schema_module_composes_with_sdk_json() {
    let source = parse(br#"{"type":"integer","minimum":4}"#);
    let schema = fictionet_copy_modules::json_schema::Schema::compile(&source).unwrap();
    assert!(schema.validate(&Value::from(5)).is_valid());
    let example = schema.generate(12, Default::default()).unwrap();
    assert!(schema.validate(&example).is_valid());
}

#[test]
fn openapi_document_entries_only_compile_reachable_schemas() {
    let mut paths: Vec<_> = (0..5000)
        .map(|i| {
            (
                format!("/p{i}"),
                parse(br#"{"get":{"description":"unused","responses":{}}}"#),
            )
        })
        .collect();
    paths.push(("/pets".into(), parse(br##"{"post":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Pet"}}}}}}"##)));
    let document = Value::Object(vec![
        ("openapi".into(), Value::from("3.0.3")),
        ("paths".into(), Value::Object(paths)),
        ("components".into(), parse(br#"{"schemas":{"Pet":{"type":"object","required":["id"],"properties":{"id":{"type":"integer","minimum":1}},"additionalProperties":false},"Unused":{"unevaluatedProperties":false}}}"#)),
        ("ignored".into(), Value::from("x".repeat(2 << 20))),
    ]);
    let options = Options {
        dialect: Dialect::OpenApi30,
        ..Options::default()
    };
    for entry in [
        "/components/schemas/Pet",
        "/paths/~1pets/post/requestBody/content/application~1json/schema",
    ] {
        let schema = Schema::compile_at(&document, entry, options).unwrap();
        assert!(schema.validate(&parse(br#"{"id":1}"#)).is_valid());
        let report = schema.validate(&parse(br#"{"id":0}"#));
        assert_eq!(
            report.errors[0].schema_path,
            "/components/schemas/Pet/properties/id/minimum"
        );
        let example = schema.generate(17, GenerationLimits::default()).unwrap();
        assert!(schema.validate(&example).is_valid());
        contract::check_wire_value(&example);
    }
}

// Peak resident memory in KiB, from the kernel's high-water mark.
#[cfg(target_os = "linux")]
fn peak_kib() -> usize {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with("VmHWM:")).unwrap();
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[cfg(target_os = "linux")]
#[test]
fn instance_paths_are_not_copied_per_child() {
    let key = "a".repeat(4000);
    let zeros = vec![Value::from(0); 99_000];
    let members = (0..99_000)
        .map(|i| (i.to_string(), Value::Null))
        .collect::<Vec<_>>();
    let cases = [
        (
            Value::Object(vec![(
                "properties".into(),
                Value::Object(vec![(
                    key.clone(),
                    parse(br#"{"items":{"type":"integer"}}"#),
                )]),
            )]),
            Value::Object(vec![(key.clone(), Value::Array(zeros))]),
        ),
        (
            Value::Object(vec![(
                "properties".into(),
                Value::Object(vec![(
                    key.clone(),
                    parse(br#"{"additionalProperties":true}"#),
                )]),
            )]),
            Value::Object(vec![(key.clone(), Value::Object(members))]),
        ),
    ];
    for (source, instance) in cases {
        let schema = Schema::compile(&source).unwrap();
        let before = peak_kib();
        let report = schema.validate(&instance);
        assert!(report.is_valid(), "{:?}", report.errors);
        let grown = peak_kib().saturating_sub(before);
        assert!(
            grown < 64 * 1024,
            "validation raised peak memory by {grown} KiB"
        );
    }
}
