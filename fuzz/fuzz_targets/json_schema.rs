//! Arbitrary schema/instance pairs, dialects, bounded validation, and examples.
#![no_main]

use fictionet::stdlib::codec::contract;
use fictionet::stdlib::json;
use fictionet::stdlib::json_schema::{
    Dialect, ErrorMode, GenerationLimits, Limits, Options, PatternPolicy, Schema,
};
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
        limits: Limits {
            max_schema_nodes: 512,
            max_instance_nodes: 512,
            max_bytes: 8192,
            max_depth: 16,
            max_validation_depth: 24,
            max_work: 50_000,
            max_errors: 8,
            ..Limits::default()
        },
    };
    if let Ok(schema) = Schema::compile_with(&source, options) {
        let first = schema.validate(&instance);
        let all = schema.validate_with(&instance, ErrorMode::All);
        assert_eq!(first.is_valid(), all.is_valid());
        assert!(all.errors.len() <= 8);
        let bounds = GenerationLimits {
            depth: 5,
            items: 8,
            string_length: 32,
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
    }
});
