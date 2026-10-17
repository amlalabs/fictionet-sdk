//! Code generator integration checks.
use fictionet_codegen::{FrontEnd, Input, IrFrontEnd, Limits, emit, emit_fuzz, generate, validate};
use std::path::Path;
#[path = "support/rustfmt.rs"]
mod rustfmt;
use rustfmt::check_rustfmt;

const EXAMPLES: &[&str] = &[
    "primitives",
    "groups",
    "recursive",
    "xdr",
    "budgets",
    "edges",
    "one_field",
    "short_names",
    "long_names",
    "float_nulls",
    "blocks",
];
/// SBE XML schemas with goldens, read by the `sbe` front end.
const SBE_EXAMPLES: &[&str] = &["sbe_sample"];
fn examples() -> impl Iterator<Item = (&'static str, &'static str, &'static str)> {
    EXAMPLES
        .iter()
        .map(|n| (*n, "ir", "json"))
        .chain(SBE_EXAMPLES.iter().map(|n| (*n, "sbe", "xml")))
}
#[test]
fn goldens_and_determinism() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    for (name, format, extension) in examples() {
        let limits = if name == "budgets" {
            Limits {
                max_message: 128,
                max_collection: 8,
                max_depth: 4,
                max_allocation: 32,
                max_nodes: 8,
            }
        } else {
            Limits::default()
        };
        let input = Input {
            name: format!("/ignored/path/{name}.{extension}"),
            bytes: std::fs::read(root.join(format!("schemas/{name}.{extension}"))).unwrap(),
        };
        let source = generate(format, std::slice::from_ref(&input), limits)
            .unwrap()
            .source;
        assert_eq!(
            source,
            generate(format, std::slice::from_ref(&input), limits)
                .unwrap()
                .source
        );
        let path = root.join(format!("golden/{name}.rs"));
        if std::env::var_os("BLESS_CODEGEN").is_some() {
            std::fs::write(&path, &source).unwrap();
        }
        assert_eq!(
            source,
            std::fs::read_to_string(&path).unwrap(),
            "golden {name}; set BLESS_CODEGEN=1 to update"
        );
        let mut renamed = input.clone();
        renamed.name = format!("C:\\other\\{name}.{extension}");
        assert_eq!(source, generate(format, &[renamed], limits).unwrap().source);
        if name == "recursive" {
            assert_eq!(source.matches("fn __read").count(), 9);
            let checked = validate(IrFrontEnd.parse(&[input], limits).unwrap(), limits).unwrap();
            assert_eq!(checked.recursive_types().collect::<Vec<_>>(), ["Node"]);
            let target = emit_fuzz(
                "ir",
                &checked,
                "../../codegen/tests/golden/recursive.rs",
                &["recursive.json".into()],
            )
            .unwrap();
            let target_path = root.join("../../fuzz/fuzz_targets/codegen_ir.rs");
            if std::env::var_os("BLESS_CODEGEN").is_some() {
                std::fs::write(&target_path, &target).unwrap();
            }
            assert_eq!(target, std::fs::read_to_string(target_path).unwrap());
        }
    }
}
#[test]
fn goldens_are_rustfmt_clean() {
    let files: Vec<_> = examples()
        .map(|(name, _, _)| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/golden/{name}.rs"))
        })
        .collect();
    check_rustfmt(&files);
}
#[test]
fn header_quotes_untrusted_filenames() {
    let checked = validate(Default::default(), Limits::default()).unwrap();
    let source = emit("ir", &checked, &["file\n#[bad].json".into()]).unwrap();
    assert!(source.contains(r#"// Schema: "file\n#[bad].json""#));
}

#[test]
fn headers_record_only_nondefault_limits_in_order() {
    for (limits, options) in [
        (Limits::default(), ""),
        (
            Limits {
                max_collection: 0,
                ..Limits::default()
            },
            " --max-collection 0",
        ),
        (
            Limits {
                max_message: 128,
                max_collection: 8,
                max_depth: 4,
                max_allocation: 32,
                max_nodes: 8,
            },
            " --max-message 128 --max-collection 8 --max-depth 4 --max-allocation 32 --max-nodes 8",
        ),
    ] {
        let checked = validate(Default::default(), limits).unwrap();
        let inputs = ["schema.json".into()];
        for (source, outputs) in [
            (emit("ir", &checked, &inputs).unwrap(), "-o <this file>"),
            (
                emit_fuzz("ir", &checked, "module.rs", &inputs).unwrap(),
                "-o \"module.rs\" --fuzz <this file>",
            ),
        ] {
            assert_eq!(
                source.lines().nth(2).unwrap(),
                format!(
                    "// Regenerate with: fictionet-codegen ir \"schema.json\"{options} {outputs}"
                )
            );
        }
    }
}

#[test]
fn output_limit_counts_emitted_bytes() {
    let checked = validate(Default::default(), Limits::default()).unwrap();
    let base = emit("x", &checked, &[]).unwrap();
    // The format appears twice in the generated header.
    let extra = fictionet_codegen::MAX_OUTPUT - base.len();
    let mut format = "x".repeat(1 + extra / 2);
    let source = emit(&format, &checked, &[]).unwrap();
    assert_eq!(source.len(), fictionet_codegen::MAX_OUTPUT - extra % 2);
    format.push('x');
    let error = emit(&format, &checked, &[]).unwrap_err();
    assert_eq!(error.kind, fictionet_codegen::ErrorKind::InputLimit);
    assert_eq!(error.location, "output");
    assert_eq!(error.message, "MAX_OUTPUT exceeded");
}
