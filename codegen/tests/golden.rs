//! Code generator integration checks.
use fictionet_codegen::{FrontEnd, Input, IrFrontEnd, Limits, emit, emit_fuzz, generate, validate};
use std::{path::Path, process::Command};

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
            let checked = validate(IrFrontEnd.parse(&[input], limits).unwrap(), limits).unwrap();
            assert_eq!(checked.recursive_types().collect::<Vec<_>>(), ["Node"]);
            let target = emit_fuzz(
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
fn goldens_are_rustfmt_clean_when_available() {
    if Command::new("rustfmt").arg("--version").output().is_err() {
        eprintln!("rustfmt is not on PATH; skipping golden formatting check");
        return;
    }
    let mut command = Command::new("rustfmt");
    command.args(["--edition", "2024", "--check"]);
    for (name, _, _) in examples() {
        command.arg(Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/golden/{name}.rs")));
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn header_quotes_untrusted_filenames() {
    let checked = validate(Default::default(), Limits::default()).unwrap();
    let source = emit(&checked, &["file\n#[bad].json".into()]).unwrap();
    assert!(source.contains(r#"// Input: "file\n#[bad].json""#));
}
