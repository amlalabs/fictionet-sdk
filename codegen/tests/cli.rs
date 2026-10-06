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
