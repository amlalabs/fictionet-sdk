//! `cargo xtask tcp-rfc-verify`: the Lean 4 model of RFC 9293 segment
//! arrival in `verification/tcp-rfc/lean/`, and the differential test that
//! holds smoltcp's TCP socket to it.
//!
//! | Command | Does |
//! | --- | --- |
//! | `tcp-rfc-verify lean` | `lake build`, then the axioms of every headline theorem |
//! | `tcp-rfc-verify vectors [seed]` | the model's vectors, from `seed`, or from each of seeds 1 to 8 when left out |
//! | `tcp-rfc-verify diff [seed]` | the vectors, then `rfc9293_arrival_vectors` in smoltcp against them, for each seed |
//!
//! Everything is written under a fresh run directory in `tcp-rfc-verify/`
//! in Cargo's target directory (`CARGO_TARGET_DIR`, or `target/`): Lean's
//! output in `lean/`, the vectors of each seed in `vectors/<seed>/`, and
//! the differential test's output in `diff-<seed>.out`. The vectors are made
//! again on every run and never committed. Lake is `$LAKE`, or `lake`.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Result;

/// The axioms a headline theorem may rest on: Lean's own, and no `sorryAx`.
const STANDARD_AXIOMS: [&str; 3] = ["propext", "Quot.sound", "Classical.choice"];

/// The seeds of the vectors when none is given. Each seed draws other
/// random cases after the same boundary cases.
const SEEDS: std::ops::RangeInclusive<u64> = 1..=8;

/// Runs `tcp-rfc-verify` with the arguments after it.
pub fn run(args: &[String]) -> Result {
    let paths = Paths::new()?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let report = match args.as_slice() {
        ["lean"] => lean(&paths)?,
        ["vectors", seed @ ..] if seed.len() <= 1 => {
            let mut report = Report::new("vectors");
            for seed in seeds_of(seed)? {
                report.absorb(vectors(&paths, seed)?);
            }
            report
        }
        ["diff", seed @ ..] if seed.len() <= 1 => diff(&paths, &seeds_of(seed)?)?,
        _ => return Err("expected tcp-rfc-verify lean, vectors [seed] or diff [seed]".into()),
    };
    report.print();
    report.result()
}

/// The seed given, or [`SEEDS`].
fn seeds_of(args: &[&str]) -> Result<Vec<u64>> {
    match args.first() {
        Some(seed) => {
            Ok(vec![seed.parse().map_err(|_| {
                format!("the seed must be a number, not {seed}")
            })?])
        }
        None => Ok(SEEDS.collect()),
    }
}

/// Where the sources are and where the results go.
struct Paths {
    /// The repository.
    root: PathBuf,
    /// `verification/tcp-rfc/lean`.
    lean: PathBuf,
    /// The run directory in `tcp-rfc-verify/` in Cargo's target directory.
    out: PathBuf,
}

impl Paths {
    fn new() -> Result<Paths> {
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
        Ok(Paths {
            lean: root.join("verification").join("tcp-rfc").join("lean"),
            out: crate::verification_run(&target.join("tcp-rfc-verify"))?,
            root,
        })
    }
}

/// What one step found: a line per check, and whether every check passed.
struct Report {
    step: &'static str,
    lines: Vec<String>,
    failures: usize,
}

impl Report {
    fn new(step: &'static str) -> Report {
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

    fn print(&self) {
        for line in &self.lines {
            println!("{line}");
        }
        if self.failures == 0 {
            println!("{}: passed", self.step);
        } else {
            println!("{}: {} failed", self.step, self.failures);
        }
    }

    /// Takes in the lines and failures of `other`, another run of the
    /// same step.
    fn absorb(&mut self, other: Report) {
        self.lines.extend(other.lines);
        self.failures += other.failures;
    }

    fn result(&self) -> Result {
        if self.failures == 0 {
            Ok(())
        } else {
            Err(format!("tcp-rfc-verify {}: {} failed", self.step, self.failures).into())
        }
    }
}

/// Runs `command`, writes what it printed to `log`, and gives that text and
/// whether it exited successfully.
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

/// `program` in its own memory-capped scope of the work slice.
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

fn lake() -> Command {
    scoped(
        std::env::var_os("LAKE").unwrap_or_else(|| "lake".into()),
        "6G",
    )
}

/// `lake build`, then `TcpRfc/Axioms.lean`, which prints the axioms of
/// every headline theorem; any axiom but Lean's own fails the step.
fn lean(paths: &Paths) -> Result<Report> {
    let out = paths.out.join("lean");
    let mut report = Report::new("lean");
    let (_, built) = logged(
        lake().arg("build").current_dir(&paths.lean),
        &out.join("build.out"),
    )?;
    if !built {
        report.fail("lake build; see lean/build.out".to_string());
        return Ok(report);
    }
    report.pass("lake build: every proof checks".to_string());
    let (text, checked) = logged(
        lake()
            .args(["env", "lean", "TcpRfc/Axioms.lean"])
            .current_dir(&paths.lean),
        &out.join("axioms.out"),
    )?;
    if !checked {
        report.fail("TcpRfc/Axioms.lean does not check; see lean/axioms.out".to_string());
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
        report.fail("TcpRfc/Axioms.lean printed no axioms; see lean/axioms.out".to_string());
    } else {
        report.pass(format!(
            "axioms: {theorems} headline theorems rest on {} at most",
            STANDARD_AXIOMS.join(", ")
        ));
    }
    Ok(report)
}

fn vectors_dir(paths: &Paths, seed: u64) -> PathBuf {
    paths.out.join("vectors").join(seed.to_string())
}

/// Builds and runs `gen` into `vectors/<seed>/`.
fn vectors(paths: &Paths, seed: u64) -> Result<Report> {
    let dir = vectors_dir(paths, seed);
    std::fs::create_dir_all(&dir)?;
    let mut report = Report::new("vectors");
    let (_, built) = logged(
        lake().args(["build", "gen"]).current_dir(&paths.lean),
        &paths.out.join("lean").join(format!("build-gen-{seed}.out")),
    )?;
    if !built {
        report.fail(format!(
            "seed {seed}: generator build failed; see lean/build-gen-{seed}.out"
        ));
        return Ok(report);
    }
    let log = format!("gen-{seed}.out");
    let (text, made) = logged(
        lake()
            .args(["env", ".lake/build/bin/gen"])
            .arg(&dir)
            .arg(seed.to_string())
            .current_dir(&paths.lean),
        &paths.out.join("lean").join(&log),
    )?;
    if made {
        report.pass(format!("seed {seed}: {}", text.trim()));
    } else {
        report.fail(format!("seed {seed}: generator failed; see lean/{log}"));
    }
    Ok(report)
}

/// For each of `seeds`, the vectors, then smoltcp's ignored test
/// `rfc9293_arrival_vectors` with `TCP_RFC_VECTORS` naming them.
fn diff(paths: &Paths, seeds: &[u64]) -> Result<Report> {
    let mut report = Report::new("diff");
    for &seed in seeds {
        let made = vectors(paths, seed)?;
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
                .args([
                    "test",
                    "-p",
                    "smoltcp",
                    "--lib",
                    "--",
                    "--ignored",
                    "--exact",
                    "socket::tcp::test::rfc9293_arrival_vectors",
                    "--nocapture",
                ])
                .env("TCP_RFC_VECTORS", vectors_dir(paths, seed))
                .current_dir(&paths.root),
            &paths.out.join(&log),
        )?;
        let counts: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("arrive: ") && line.contains(" cases, "))
            .collect();
        for line in &counts {
            if line.ends_with(", 0 disagree") {
                report.pass(format!("seed {seed}: {line}"));
            } else {
                report.fail(format!("seed {seed}: {line}; see {log}"));
            }
        }
        if counts.is_empty() {
            report.fail(format!(
                "seed {seed}: the test printed no counts; see {log}"
            ));
        } else if !passed && counts.iter().all(|line| line.ends_with(", 0 disagree")) {
            report.fail(format!("seed {seed}: cargo test failed; see {log}"));
        }
    }
    Ok(report)
}
