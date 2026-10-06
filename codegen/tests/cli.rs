//! Code generator integration checks.
use std::{
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let cache = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".cache")
            });
        let p = cache.join(format!(
            "fictionet-codegen-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fictionet-codegen"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn list_help_and_argument_errors() {
    let list = cli(&["--list"]);
    assert!(list.status.success());
    assert_eq!(list.stdout, b"ir\n");
    assert!(cli(&["--help"]).status.success());
    for (args, kind) in [
        (vec!["not-a-format"], "UnknownFormat"),
        (vec!["ir", "schema.json"], "Cli"),
        (vec!["ir", "-o", "out.rs"], "Cli"),
        (vec!["--format"], "Cli"),
        (vec!["ir", "--wat"], "Cli"),
        (vec!["ir", "--max-depth", "no"], "Cli"),
        (vec!["ir", "--max-depth", "-1"], "Cli"),
    ] {
        let output = cli(&args);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(kind));
    }
}
#[test]
fn generate_limits_fuzz_and_bad_files() {
    let scratch = Scratch::new();
    let input = scratch.0.join("schema.json");
    let output = scratch.0.join("module.rs");
    let fuzz = scratch.0.join("fuzz.rs");
    let i = input.to_str().unwrap();
    let o = output.to_str().unwrap();
    let f = fuzz.to_str().unwrap();
    let io = cli(&["ir", i, "-o", o]);
    assert!(String::from_utf8_lossy(&io.stderr).contains("Io"));
    std::fs::write(&input, "{bad").unwrap();
    let bad = cli(&["ir", i, "-o", o]);
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("JsonSyntax"));
    assert!(!output.exists());
    std::fs::write(&input, include_str!("schemas/recursive.json")).unwrap();
    let good = cli(&[
        "--format",
        "ir",
        i,
        "-o",
        o,
        "--fuzz",
        f,
        "--max-message",
        "512",
        "--max-depth",
        "8",
        "--max-collection",
        "2",
        "--max-allocation",
        "2048",
        "--max-nodes",
        "100",
    ]);
    assert!(
        good.status.success(),
        "{}",
        String::from_utf8_lossy(&good.stderr)
    );
    let source = std::fs::read_to_string(&output).unwrap();
    assert!(source.contains("MAX_MESSAGE: usize = 512"));
    assert!(source.contains("MAX_DEPTH: usize = 8"));
    assert!(
        std::fs::read_to_string(&fuzz)
            .unwrap()
            .contains("#[path = \"module.rs\"]")
    );
    let invalid = cli(&["ir", i, "-o", o, "--max-depth", "65"]);
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("InvalidLimit"));
    assert_eq!(std::fs::read_to_string(&output).unwrap(), source);
    assert!(!cli(&["ir", i, "-o", i]).status.success());
    assert!(!cli(&["ir", i, "-o", o, "--fuzz", o]).status.success());
}

#[test]
fn outputs_cannot_alias_inputs_or_each_other() {
    let scratch = Scratch::new();
    let schema = include_str!("schemas/recursive.json");
    for args in [
        vec!["ir", "input.json", "-o", "out.rs", "--fuzz", "./input.json"],
        vec!["ir", "input.json", "-o", "./input.json"],
        vec!["ir", "input.json", "-o", "out.rs", "--fuzz", "./out.rs"],
    ] {
        std::fs::write(scratch.0.join("input.json"), schema).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_fictionet-codegen"))
            .current_dir(&scratch.0)
            .args(&args)
            .output()
            .unwrap();
        assert!(!result.status.success(), "accepted {args:?}");
        assert!(String::from_utf8_lossy(&result.stderr).contains("Cli"));
        assert_eq!(
            std::fs::read_to_string(scratch.0.join("input.json")).unwrap(),
            schema
        );
        assert!(!scratch.0.join("out.rs").exists());
    }
}

#[cfg(unix)]
#[test]
fn outputs_cannot_alias_inputs_through_links() {
    let scratch = Scratch::new();
    let schema = include_str!("schemas/recursive.json");
    std::fs::write(scratch.0.join("input.json"), schema).unwrap();
    std::os::unix::fs::symlink("input.json", scratch.0.join("link.json")).unwrap();
    std::fs::hard_link(scratch.0.join("input.json"), scratch.0.join("hard.json")).unwrap();
    for args in [
        vec!["ir", "link.json", "-o", "input.json"],
        vec!["ir", "input.json", "-o", "link.json"],
        vec!["ir", "input.json", "-o", "out.rs", "--fuzz", "link.json"],
        vec!["ir", "hard.json", "-o", "input.json"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_fictionet-codegen"))
            .current_dir(&scratch.0)
            .args(&args)
            .output()
            .unwrap();
        assert!(!result.status.success(), "accepted {args:?}");
        assert_eq!(
            std::fs::read_to_string(scratch.0.join("input.json")).unwrap(),
            schema
        );
        assert!(!scratch.0.join("out.rs").exists());
    }
}

#[test]
fn failed_fuzz_staging_keeps_existing_module() {
    let scratch = Scratch::new();
    std::fs::write(
        scratch.0.join("input.json"),
        include_str!("schemas/recursive.json"),
    )
    .unwrap();
    std::fs::write(scratch.0.join("out.rs"), "original").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_fictionet-codegen"))
        .current_dir(&scratch.0)
        .args([
            "ir",
            "input.json",
            "-o",
            "out.rs",
            "--fuzz",
            "missing/fuzz.rs",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(
        std::fs::read_to_string(scratch.0.join("out.rs")).unwrap(),
        "original"
    );
    assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 2);
}

#[test]
fn checks_all_paths_before_opening_inputs() {
    let scratch = Scratch::new();
    std::fs::write(scratch.0.join("input.json"), "unread").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_fictionet-codegen"))
        .current_dir(&scratch.0)
        .args([
            "ir",
            "missing.json",
            "input.json",
            "-o",
            "out.rs",
            "--fuzz",
            "./input.json",
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("Cli"));
    assert_eq!(
        std::fs::read_to_string(scratch.0.join("input.json")).unwrap(),
        "unread"
    );
}

#[test]
fn refuses_an_impossible_depth_from_cli() {
    let scratch = Scratch::new();
    let schema = r#"{"types":[{"name":"A","kind":"struct","fields":[{"name":"b","type":{"kind":"ref","name":"B"}}]},{"name":"B","kind":"struct","fields":[]}]}"#;
    std::fs::write(scratch.0.join("input.json"), schema).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_fictionet-codegen"))
        .current_dir(&scratch.0)
        .args(["ir", "input.json", "-o", "out.rs", "--max-depth", "1"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("IrLimit"));
    assert!(!scratch.0.join("out.rs").exists());
}
