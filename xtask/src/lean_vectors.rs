//! The steps every Lean model with a differential test shares: build the
//! model and audit its axioms, write its vectors from a seed, and replay them
//! on the Rust code with a named integration test. A [`Project`] names the
//! directories, the axiom file, the test and the variable that points the
//! test at the vectors.
//!
//! Each command runs in its own systemd scope in `fictionet-work.slice`, with
//! a memory cap and no swap, so a runaway proof or generator stops there.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Result;

/// The axioms a headline theorem may rest on: Lean's own, and no `sorryAx`.
const STANDARD_AXIOMS: [&str; 3] = ["propext", "Quot.sound", "Classical.choice"];

/// One Lean model and its differential test.
pub struct Project {
    /// The repository.
    pub root: PathBuf,
    /// The Lake project.
    pub lean: PathBuf,
    /// The file of `#print axioms` lines, relative to `lean`.
    pub axioms: &'static str,
    /// The integration test that replays the vectors.
    pub test: &'static str,
    /// The variable that names the vectors' directory for the test.
    pub vectors_var: &'static str,
    /// This run's directory under Cargo's target directory.
    pub out: PathBuf,
}

impl Project {
    /// `verification/<dir>/lean` in the repository, and a fresh run directory
    /// named `command` in Cargo's target directory.
    pub fn new(
        command: &'static str,
        dir: &str,
        axioms: &'static str,
        test: &'static str,
        vectors_var: &'static str,
    ) -> Result<Project> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or("xtask lives in the repository")?
            .to_path_buf();
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .map(|dir| {
                if dir.is_relative() {
                    root.join(dir)
                } else {
                    dir
                }
            })
            .unwrap_or_else(|| root.join("target"));
        Ok(Project {
            lean: root.join("verification").join(dir).join("lean"),
            out: crate::verification_run(&target.join(command))?,
            root,
            axioms,
            test,
            vectors_var,
        })
    }

    fn vectors_dir(&self, seed: u64) -> PathBuf {
        self.out.join("vectors").join(seed.to_string())
    }
}

/// What one step found: a line per check, and whether every check passed.
pub struct Report {
    step: &'static str,
    lines: Vec<String>,
    failures: usize,
}

impl Report {
    pub fn new(step: &'static str) -> Report {
        Report {
            step,
            lines: Vec::new(),
            failures: 0,
        }
    }

    fn pass(&mut self, line: String) {
        self.lines.push(line);
    }

    fn fail(&mut self, line: String) {
        self.lines.push(format!("FAILED: {line}"));
        self.failures += 1;
    }

    /// Takes in the lines and failures of another run of the same step.
    pub fn absorb(&mut self, other: Report) {
        self.lines.extend(other.lines);
        self.failures += other.failures;
    }

    pub fn print(&self) {
        for line in &self.lines {
            println!("{line}");
        }
        if self.failures == 0 {
            println!("{}: passed", self.step);
        } else {
            println!("{}: {} failed", self.step, self.failures);
        }
    }

    pub fn result(&self, command: &str) -> Result {
        if self.failures == 0 {
            Ok(())
        } else {
            Err(format!("{command} {}: {} failed", self.step, self.failures).into())
        }
    }
}

/// Runs `command`, writing what it prints to `log` as it prints it, and gives
/// that text and whether it exited successfully.
fn logged(command: &mut Command, log: &Path) -> Result<(String, bool)> {
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let file = std::fs::File::create(log)?;
    let status = command
        .stdout(file.try_clone()?)
        .stderr(file)
        .status()
        .map_err(|e| format!("{:?}: {e}", command.get_program()))?;
    Ok((std::fs::read_to_string(log)?, status.success()))
}

/// `program` in its own scope of `fictionet-work.slice`, at most `memory`.
fn scoped(program: impl AsRef<std::ffi::OsStr>, memory: &str) -> Command {
    let mut command = Command::new("systemd-run");
    command.args([
        "--user",
        "--scope",
        "-q",
        "--slice=fictionet-work.slice",
        "-p",
        &format!("MemoryMax={memory}"),
        "-p",
        "MemorySwapMax=0",
        "--setenv=PATH",
    ]);
    command.arg(program);
    command
}

/// Lake is `$LAKE`, or `lake`.
fn lake() -> Command {
    scoped(
        std::env::var_os("LAKE").unwrap_or_else(|| "lake".into()),
        "6G",
    )
}

/// `lake build`, then the axiom file, whose `#print axioms` lines must name
/// only Lean's standard axioms.
pub fn lean(project: &Project) -> Result<Report> {
    let out = project.out.join("lean");
    let mut report = Report::new("lean");
    let (log, built) = logged(
        lake().arg("build").current_dir(&project.lean),
        &out.join("build.out"),
    )?;
    if !built {
        report.fail("lake build; see lean/build.out".to_string());
        return Ok(report);
    }
    // Lean accepts a proof left as `sorry` with a warning, which Lake
    // prints again for a module it does not rebuild.
    let sorry: Vec<&str> = log
        .lines()
        .filter(|line| line.contains("declaration uses") && line.contains("sorry"))
        .collect();
    if !sorry.is_empty() {
        report.fail(format!("a proof is left as sorry: {}", sorry.join("; ")));
        return Ok(report);
    }
    report.pass("lake build: every proof checks, none left as sorry".to_string());
    let (text, checked) = logged(
        lake()
            .args(["env", "lean", project.axioms])
            .current_dir(&project.lean),
        &out.join("axioms.out"),
    )?;
    if !checked {
        report.fail(format!(
            "{} does not check; see lean/axioms.out",
            project.axioms
        ));
        return Ok(report);
    }
    let mut theorems = 0;
    for line in text.lines() {
        let Some((theorem, rest)) = line.split_once(" depends on axioms: [") else {
            if line.contains("does not depend on any axioms") {
                theorems += 1;
            }
            continue;
        };
        theorems += 1;
        let theorem = theorem.rsplit(' ').next().unwrap_or(theorem);
        let others: Vec<&str> = rest
            .trim_end_matches(']')
            .split(',')
            .map(str::trim)
            .filter(|axiom| !STANDARD_AXIOMS.contains(axiom))
            .collect();
        if !others.is_empty() {
            report.fail(format!("{theorem} rests on {}", others.join(", ")));
        }
    }
    if theorems == 0 {
        report.fail(format!(
            "{} printed no axioms; see lean/axioms.out",
            project.axioms
        ));
    } else {
        report.pass(format!(
            "axioms: {theorems} headline theorems rest on {} at most",
            STANDARD_AXIOMS.join(", ")
        ));
    }
    Ok(report)
}

/// Builds and runs `gen` into `vectors/<seed>/`, emptied first so no file of
/// an older run is left.
pub fn vectors(project: &Project, seed: u64) -> Result<Report> {
    let dir = project.vectors_dir(seed);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let mut report = Report::new("vectors");
    let build_log = format!("build-gen-{seed}.out");
    let (_, built) = logged(
        lake().args(["build", "gen"]).current_dir(&project.lean),
        &project.out.join("lean").join(&build_log),
    )?;
    if !built {
        report.fail(format!(
            "seed {seed}: generator build failed; see lean/{build_log}"
        ));
        return Ok(report);
    }
    let log = format!("gen-{seed}.out");
    let (text, made) = logged(
        lake()
            .args(["env", ".lake/build/bin/gen"])
            .arg(&dir)
            .arg(seed.to_string())
            .current_dir(&project.lean),
        &project.out.join("lean").join(&log),
    )?;
    if made {
        let files: Vec<&str> = text.lines().filter(|l| l.contains(".json")).collect();
        report.pass(format!("seed {seed}: {}", files.join(", ")));
    } else {
        report.fail(format!("seed {seed}: generator execution; see lean/{log}"));
    }
    Ok(report)
}

/// For each of `seeds`, the vectors, then the project's test with its
/// variable naming them. Each kind's line of the test's output goes in the
/// report, after its seed.
pub fn diff(project: &Project, seeds: &[u64]) -> Result<Report> {
    let mut report = Report::new("diff");
    for &seed in seeds {
        let made = vectors(project, seed)?;
        for line in made.lines {
            report.lines.push(format!("vectors: {line}"));
        }
        if made.failures > 0 {
            report.failures += made.failures;
            continue;
        }
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let log = format!("diff-{seed}.out");
        let (text, passed) = logged(
            scoped(cargo, "8G")
                .args(["test", "-p", "fictionet", "--test", project.test])
                .args(["--", "--nocapture", "--test-threads=1"])
                .env(project.vectors_var, project.vectors_dir(seed))
                .env("CARGO_BUILD_JOBS", "4")
                .current_dir(&project.root),
            &project.out.join(&log),
        )?;
        let kinds: Vec<&str> = text
            .lines()
            .filter(|line| line.contains(" cases, ") && line.contains(" disagree"))
            .collect();
        for line in &kinds {
            if line.contains(", 0 disagree") {
                report.pass(format!("seed {seed}: {line}"));
            } else {
                report.fail(format!("seed {seed}: {line}"));
            }
        }
        if !passed {
            report.fail(format!(
                "seed {seed}: cargo test --test {}; see {log}",
                project.test
            ));
        } else if kinds.is_empty() {
            report.fail(format!(
                "seed {seed}: the differential test ran no kind; see {log}"
            ));
        }
    }
    Ok(report)
}
