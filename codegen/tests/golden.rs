//! Code generator integration checks.
use fictionet_codegen::{Limits, emit, emit_fuzz, validate};

#[test]
fn header_quotes_untrusted_filenames() {
    let checked = validate(Default::default(), Limits::default()).unwrap();
    let source = emit("ir", &checked, &["file\n#[bad].json".into()]).unwrap();
    assert!(source.contains(r#"// Schema: "file\n#[bad].json""#));
    // The fuzz target's module path is written as code.
    for module in ["", "a::", "::a", "a::b;\nfn evil() {}", "1a", "_", "a-b"] {
        let error = emit_fuzz("ir", &checked, module, &[]).unwrap_err();
        assert_eq!(
            error.kind,
            fictionet_codegen::ErrorKind::InvalidName,
            "{module:?}"
        );
    }
    assert!(emit_fuzz("ir", &checked, "crate_a::_b::C1", &[]).is_ok());
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
