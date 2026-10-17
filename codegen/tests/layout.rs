//! Layout checks over schema shapes and the full identifier range. The
//! crate in `codegen/tests/layouts` compiles the random schemas against
//! the SDK and runs their generated tests.
//! Missing rustfmt skips formatting checks with a note locally and fails
//! when `CI` is set, even to an empty value. A nonzero rustfmt exit always fails.
use fictionet_codegen::*;
#[path = "../../tests/it/common/requirements.rs"]
mod requirements;
#[path = "support/rustfmt.rs"]
mod rustfmt;
mod support;
use rustfmt::check_rustfmt;
use support::Scratch;
use support::schemas::{SEEDS, layout_schema, random_schema};

#[test]
fn all_name_lengths_are_rustfmt_clean() {
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
    check_rustfmt(&files);
}

#[test]
fn missing_rustfmt_for_name_lengths_fails_in_ci() {
    requirements::fails_in_ci(
        "all_name_lengths_are_rustfmt_clean",
        "rustfmt is not on PATH",
    );
}

#[test]
fn missing_rustfmt_for_random_schemas_fails_in_ci() {
    requirements::fails_in_ci(
        "random_valid_schemas_are_deterministic_and_rustfmt_clean",
        "rustfmt is not on PATH",
    );
}

#[cfg(unix)]
#[test]
fn rustfmt_exits_nonzero() {
    use std::{os::unix::fs::PermissionsExt, process::Command};

    let scratch = Scratch::new();
    let rustfmt = scratch.0.join("rustfmt");
    std::fs::write(
        &rustfmt,
        "#!/bin/sh\necho 'rustfmt stdout'\necho 'rustfmt stderr' >&2\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(&rustfmt, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut paths = vec![scratch.0.clone()];
    if let Some(path) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&path));
    }
    let path = std::env::join_paths(paths).unwrap();
    for test in [
        "all_name_lengths_are_rustfmt_clean",
        "random_valid_schemas_are_deterministic_and_rustfmt_clean",
    ] {
        for ci in [None, Some(""), Some("1")] {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", test, "--nocapture"])
                .env("PATH", &path)
                .env_remove("CI");
            if let Some(value) = ci {
                command.env("CI", value);
            }
            let output = command.output().unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("running 1 test"), "{output:?}");
            assert!(!output.status.success(), "{output:?}");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("rustfmt stdout"), "{output:?}");
            assert!(stderr.contains("rustfmt stderr"), "{output:?}");
            assert!(!stderr.contains("skipped:"), "{output:?}");
        }
    }
}
