//! The steps every area's resource properties share (verification/README.md,
//! "Resource properties"): Kani harnesses that count what the code
//! allocates, and TLC on the configs of a model that threads its storage
//! through `verification/resources/tla/Resources.tla`. An area's verify
//! command names its harnesses and configs; the cost bounds of its replays
//! run with the replays themselves.
//!
//! TLC runs as `$JAVA -Xmx4g -cp $TLA2TOOLS tlc2.TLC -workers 2`.
//! `TLA2TOOLS` names `tla2tools.jar`, and `JAVA` a Java 11 or later (`java`
//! when unset).

use std::path::Path;

use crate::Result;
use crate::lean_vectors::{Report, logged, scoped};

/// The Kani harnesses `harnesses` of `package`'s library, with the
/// allocation functions stubbed by their counting ones (`-Z stubbing`) and
/// `malloc` under them (`-Z c-ffi`), which tell a live allocation from a dangling pointer (`-Z mem-predicates`), and Kani's
/// `flags` besides, such as `-Z restrict-vtable` for harnesses that drop
/// what a budget charged. Each harness must report
/// `VERIFICATION:- SUCCESSFUL`. What Kani prints goes to
/// `kani-<package>.out`.
pub fn kani(
    root: &Path,
    out: &Path,
    package: &str,
    flags: &[&str],
    harnesses: &[&str],
) -> Result<Report> {
    let mut report = Report::new("kani");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = scoped(cargo, "14G");
    command.args([
        "kani",
        "-p",
        package,
        "--lib",
        "-Z",
        "stubbing",
        "-Z",
        "c-ffi",
        "-Z",
        "mem-predicates",
    ]);
    command.args(flags).arg("--exact");
    for harness in harnesses {
        command.arg("--harness").arg(harness);
    }
    let (text, ran) = logged(
        command.env("CARGO_BUILD_JOBS", "8").current_dir(root),
        &out.join(format!("kani-{package}.out")),
    )?;
    // Kani prints each harness's name, then its verdict.
    let mut current = None;
    let mut verdicts = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Checking harness ") {
            current = Some(rest.trim_end_matches("...").to_string());
        } else if let Some(verdict) = line.strip_prefix("VERIFICATION:- ")
            && let Some(harness) = current.take()
        {
            verdicts.push((harness, verdict == "SUCCESSFUL"));
        }
    }
    for harness in harnesses {
        match verdicts.iter().find(|(name, _)| name == harness) {
            Some((_, true)) => report.pass(format!("{harness}: successful")),
            Some((_, false)) => report.fail(format!("{harness}: failed; see kani-{package}.out")),
            None => report.fail(format!("{harness}: no verdict; see kani-{package}.out")),
        }
    }
    if !ran && verdicts.iter().all(|(_, ok)| *ok) {
        report.fail(format!("cargo kani failed; see kani-{package}.out"));
    }
    Ok(report)
}

/// TLC on `module` in `dir` with each of `configs`, which must do what the
/// first line of each says: `\* Must pass`, or `\* Must violate <name>`.
/// Modules find `Resources.tla` through `TLA-Library`.
pub fn tlc(root: &Path, out: &Path, dir: &Path, module: &str, configs: &[&str]) -> Result<Report> {
    let mut report = Report::new("tlc");
    let jar = std::env::var_os("TLA2TOOLS").ok_or("TLA2TOOLS must name tla2tools.jar")?;
    let java = std::env::var_os("JAVA").unwrap_or_else(|| "java".into());
    let library = root.join("verification").join("resources").join("tla");
    for config in configs {
        let first = std::fs::read_to_string(dir.join(config))?
            .lines()
            .next()
            .unwrap_or_default()
            .to_string();
        let name = config.trim_end_matches(".cfg");
        let states = out.join("states").join(name);
        let (text, _) = logged(
            scoped(&java, "6G")
                .arg(format!("-Djava.io.tmpdir={}", states.display()))
                .arg(format!("-DTLA-Library={}", library.display()))
                .args(["-XX:+UseParallelGC", "-Xmx4g", "-cp"])
                .arg(&jar)
                .args(["tlc2.TLC", "-workers", "2", "-metadir"])
                .arg(&states)
                .args(["-config", config, &format!("{module}.tla")])
                .current_dir(dir),
            &out.join(format!("{name}.out")),
        )?;
        let passed = text.contains("Model checking completed. No error has been found.");
        if first.starts_with("\\* Must pass") {
            if passed {
                report.pass(format!("{name}: passes"));
            } else {
                report.fail(format!("{name}: must pass; see {name}.out"));
            }
        } else if let Some(rest) = first.strip_prefix("\\* Must violate ") {
            let invariant = rest.split([':', ' ']).next().unwrap_or_default();
            if text.contains(&format!("Invariant {invariant} is violated.")) {
                report.pass(format!("{name}: violates {invariant}, as it must"));
            } else {
                report.fail(format!("{name}: must violate {invariant}; see {name}.out"));
            }
        } else {
            report.fail(format!(
                "{name}: its first line says neither what must pass nor fail"
            ));
        }
    }
    Ok(report)
}
