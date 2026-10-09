//! Layout checks over schema shapes and the full identifier range. The
//! crate in `codegen/tests/layouts` compiles the random schemas against
//! the SDK and runs their generated tests.
use fictionet_codegen::*;
mod support;
use support::schemas::{SEEDS, layout_schema, random_schema};
use support::{Scratch, check_rustfmt, rustfmt_available};

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
        std::fs::write(&path, emit("ir", &checked, &[]).unwrap()).unwrap();
        files.push(path);
        let path = scratch.0.join(format!("fuzz_{n}.rs"));
        std::fs::write(
            &path,
            emit_fuzz("ir", &checked, &format!("length_{n}.rs"), &[]).unwrap(),
        )
        .unwrap();
        files.push(path);
    }
    check_rustfmt(&files);
}
#[test]
fn random_valid_schemas_are_deterministic_and_rustfmt_clean() {
    let scratch = Scratch::new();
    let mut files = Vec::new();
    for seed in 0..SEEDS {
        let checked = random_schema(seed);
        let source = emit("ir", &checked, &[]).unwrap();
        assert_eq!(
            source,
            emit("ir", &random_schema(seed), &[]).unwrap(),
            "seed {seed}"
        );
        let path = scratch.0.join(format!("seed_{seed}.rs"));
        std::fs::write(&path, source).unwrap();
        files.push(path);
    }
    if rustfmt_available() {
        check_rustfmt(&files);
    }
}
