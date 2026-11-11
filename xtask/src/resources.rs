//! The steps every area's resource properties share (verification/README.md,
//! "Resource properties"): Kani harnesses that count what the code
//! allocates, TLC on the configs of a model that threads its storage
//! through `verification/resources/tla/Resources.tla`, and replays whose
//! steps are held to cost bounds (`verification/resources/cost.rs`). An
//! area's verify command names its harnesses, configs and replays.
//!
//! TLC runs as `$JAVA -Xmx4g -cp $TLA2TOOLS tlc2.TLC -workers 2`.
//! `TLA2TOOLS` names `tla2tools.jar`, and `JAVA` a Java 11 or later (`java`
//! when unset).

use std::path::Path;

use crate::Result;
use crate::lean_vectors::{Report, logged, scoped};

#[path = "../../verification/resources/line.rs"]
mod line;
use line::CostLine;

/// The Kani harnesses `harnesses` of `package`'s library, with the
/// allocation functions stubbed by their counting ones (`-Z stubbing`) and
/// `malloc` under them (`-Z c-ffi`), which tell a live allocation from a dangling pointer (`-Z mem-predicates`). A trait object's call
/// may reach only the implementations whose vtables it can hold
/// (`-Z restrict-vtable`), which proves no less: without it, a harness
/// that charges a `Budget` runs CBMC out of 14 GiB on the wake path of
/// its release. Each harness must report `VERIFICATION:- SUCCESSFUL`.
/// Kani runs in a scope of `memory` (a systemd `MemoryMax`, such as
/// `10G`). What Kani prints goes to `kani-<package>.out`.
pub fn kani(
    root: &Path,
    out: &Path,
    package: &str,
    harnesses: &[&str],
    memory: &str,
) -> Result<Report> {
    let mut report = Report::new("kani");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = scoped(cargo, memory);
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
        "-Z",
        "restrict-vtable",
        "--exact",
        // One harness at a time: Kani runs several at once otherwise, and
        // together they pass the scope's memory.
        "-j",
        "1",
    ]);
    for harness in harnesses {
        command.arg("--harness").arg(harness);
    }
    let _slot = crate::kani_slot::take(root, memory)?;
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

/// A test target of a package.
#[derive(Clone, Copy)]
pub enum Target<'a> {
    /// The library's unit tests (`--lib`).
    Lib,
    /// An integration test binary (`--test <name>`).
    Test(&'a str),
}

/// Costed replays: the tests matching `filters` in `targets` of
/// `package`, each of which prints a [`CostLine`] for every session it
/// costs and fails when a step breaks a bound.
pub struct Replay<'a> {
    /// Names the replay in the report and its log, `<name>.out`.
    pub name: &'a str,
    pub package: &'a str,
    pub features: &'a [&'a str],
    pub targets: &'a [Target<'a>],
    pub filters: &'a [&'a str],
}

/// Runs `replay`'s tests, which must pass and cost at least one session.
/// Each session's line is reported.
pub fn replay(root: &Path, out: &Path, replay: &Replay) -> Result<Report> {
    let mut report = Report::new("replay");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = scoped(cargo, "14G");
    command.args(["test", "-p", replay.package]);
    if !replay.features.is_empty() {
        command.arg("--features").arg(replay.features.join(","));
    }
    for target in replay.targets {
        match target {
            Target::Lib => command.arg("--lib"),
            Target::Test(name) => command.args(["--test", name]),
        };
    }
    command.args(["--", "--nocapture"]).args(replay.filters);
    let log = format!("{}.out", replay.name);
    let (text, passed) = logged(
        command.env("CARGO_BUILD_JOBS", "8").current_dir(root),
        &out.join(&log),
    )?;
    let costed = costs(&mut report, replay.name, &text);
    if !passed {
        report.fail(format!("{}: failed; see {log}", replay.name));
    } else if costed == 0 {
        report.fail(format!("{}: no session was costed; see {log}", replay.name));
    }
    Ok(report)
}

/// Reports, under `context`, each [`CostLine`] in `text`, what a run of
/// costed tests printed, and fails a line that starts like one but is not
/// one. Gives the number of sessions costed.
pub fn costs(report: &mut Report, context: &str, text: &str) -> usize {
    let mut costed = 0;
    for found in text.lines().filter_map(CostLine::find) {
        match found {
            Ok(line) => {
                costed += 1;
                report.pass(format!("{context}: {line}"));
            }
            Err(line::Malformed(text)) => {
                report.fail(format!("{context}: not a cost line: {text}"));
            }
        }
    }
    costed
}

#[cfg(test)]
mod tests {
    use super::line::{Closest, CostLine};

    /// A line reads back as the session that printed it, wherever it
    /// starts on the line, and a line changed in any part does not.
    #[test]
    fn a_cost_line_reads_back_as_printed() {
        let printed = CostLine {
            session: "pieces, 3: 4 at a time".into(),
            steps: 12,
            charge: Closest {
                used: 300,
                allowed: 4096,
            },
            linear: Closest {
                used: 7,
                allowed: 9,
            },
        };
        let text = printed.to_string();
        assert_eq!(CostLine::find(&text), Some(Ok(printed.clone())));
        let after = format!("test a::b ... {text}");
        assert_eq!(CostLine::find(&after), Some(Ok(printed)));
        assert_eq!(CostLine::find("test a::b ... ok"), None);
        let extra = format!("{text} and more");
        assert!(matches!(CostLine::find(&extra), Some(Err(_))));
        let fewer = text.replacen("12 steps", "steps", 1);
        assert!(matches!(CostLine::find(&fewer), Some(Err(_))));
    }
}
