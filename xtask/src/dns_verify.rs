//! `cargo xtask dns-verify`: the TLA+ and Lean 4 verification of Fictionet's
//! DNS in `verification/dns/`, and the differential test that holds the Rust
//! code to the Lean model.
//!
//! | Command | Does |
//! | --- | --- |
//! | `dns-verify tlc [spec] [config]` | TLC once per property of each config, checking that each ablation fails with exactly the violation its config expects |
//! | `dns-verify lean` | `lake build`, then the axioms of every headline theorem |
//! | `dns-verify vectors [seed]` | the Lean model's test vectors, from `seed`, or from each of seeds 1 to 8 when left out |
//! | `dns-verify diff [seed]` | the vectors, then `tests/dns_vectors.rs` against them, for each seed |
//! | `dns-verify all` | all four, with a summary in `SUMMARY.txt` |
//!
//! Everything is written under `dns-verify/` in Cargo's target directory
//! (`CARGO_TARGET_DIR`, or `target/`): TLC's output in `tlc/`, Lean's in
//! `lean/`, the vectors of each seed in `vectors/<seed>/`, and the
//! differential test's output in `diff-<seed>.out`. The vectors are made
//! again on every run and never committed.
//!
//! TLC runs as `$JAVA -Xmx6g -cp $TLA2TOOLS tlc2.TLC`. `TLA2TOOLS` names
//! `tla2tools.jar`, and `JAVA` a Java 11 or later (`java` when unset). Lake
//! is `$LAKE`, or `lake`.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::Result;

/// The axioms a headline theorem may rest on: Lean's own, and no `sorryAx`.
const STANDARD_AXIOMS: [&str; 3] = ["propext", "Quot.sound", "Classical.choice"];

/// The seeds of the vectors when none is given. The generator draws other
/// zones, messages, and caches from each seed, so several seeds reach
/// cases one seed misses.
const SEEDS: std::ops::RangeInclusive<u64> = 1..=8;

/// Runs `dns-verify` with the arguments after it.
pub fn run(args: &[String]) -> Result {
    let paths = Paths::new()?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["tlc", filter @ ..] if filter.len() <= 2 => {
            let report = tlc(&paths, filter.first().copied(), filter.get(1).copied())?;
            report.print();
            report.result()
        }
        ["lean"] => {
            let report = lean(&paths)?;
            report.print();
            report.result()
        }
        ["vectors", seed @ ..] if seed.len() <= 1 => {
            let mut report = Report::new("vectors");
            for seed in seeds_of(seed)? {
                report.absorb(vectors(&paths, seed)?);
            }
            report.print();
            report.result()
        }
        ["diff", seed @ ..] if seed.len() <= 1 => {
            let report = diff(&paths, &seeds_of(seed)?)?;
            report.print();
            report.result()
        }
        ["all"] => all(&paths),
        _ => Err(
            "expected dns-verify tlc [spec] [config], lean, vectors [seed], diff [seed], or all"
                .into(),
        ),
    }
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
    /// `verification/dns/tla`.
    tla: PathBuf,
    /// `verification/dns/lean`.
    lean: PathBuf,
    /// `dns-verify/` in Cargo's target directory.
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
        let verification = root.join("verification").join("dns");
        Ok(Paths {
            tla: verification.join("tla"),
            lean: verification.join("lean"),
            out: target.join("dns-verify"),
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

    fn heading(&self) -> String {
        if self.failures == 0 {
            format!("{}: passed", self.step)
        } else {
            format!("{}: {} failed", self.step, self.failures)
        }
    }

    fn print(&self) {
        for line in &self.lines {
            println!("{line}");
        }
        println!("{}", self.heading());
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
            Err(format!("dns-verify {}: {} failed", self.step, self.failures).into())
        }
    }
}

/// Runs `command`, writes what it printed to `log`, and gives that text and
/// whether it exited successfully.
fn logged(command: &mut Command, log: &Path) -> Result<(String, bool)> {
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let output = command
        .output()
        .map_err(|e| format!("{:?}: {e}", command.get_program()))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    std::fs::write(log, &text)?;
    Ok((text, output.status.success()))
}

fn lake() -> Command {
    Command::new(std::env::var_os("LAKE").unwrap_or_else(|| "lake".into()))
}

// ---------------------------------------------------------------------
// TLC
// ---------------------------------------------------------------------

/// The keywords that start a section of a TLC config file.
const SECTIONS: [&str; 18] = [
    "CONSTANT",
    "CONSTANTS",
    "INIT",
    "NEXT",
    "SPECIFICATION",
    "INVARIANT",
    "INVARIANTS",
    "PROPERTY",
    "PROPERTIES",
    "SYMMETRY",
    "CONSTRAINT",
    "CONSTRAINTS",
    "ACTION_CONSTRAINT",
    "ACTION_CONSTRAINTS",
    "VIEW",
    "CHECK_DEADLOCK",
    "POSTCONDITION",
    "ALIAS",
];

/// What a property is to TLC's config: an invariant of states, or a
/// property of behaviours.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Checked {
    Invariant,
    Property,
}

/// One TLC config file.
struct Config {
    /// The config's file name without `.cfg`, such as `Resolution_base`.
    name: String,
    /// The spec it checks: the part of the name before the first `_`.
    spec: String,
    /// The config's text.
    text: String,
    /// Its invariants and properties, in the order it lists them.
    checks: Vec<(String, Checked)>,
    /// The properties its `\* expect violation: <Property>` lines name.
    expected: BTreeSet<String>,
}

impl Config {
    fn read(path: &Path) -> Result<Config> {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or("a config file name is UTF-8")?
            .to_string();
        let spec = name.split('_').next().unwrap_or(&name).to_string();
        let text = std::fs::read_to_string(path)?;
        let mut checks = Vec::new();
        let mut expected = BTreeSet::new();
        let mut section: Option<Checked> = None;
        for line in text.lines() {
            if let Some(comment) = line.trim_start().strip_prefix("\\*") {
                if let Some(property) = comment.trim().strip_prefix("expect violation:") {
                    expected.insert(property.trim().to_string());
                }
                continue;
            }
            for token in line.split_whitespace() {
                if SECTIONS.contains(&token) {
                    section = match token {
                        "INVARIANT" | "INVARIANTS" => Some(Checked::Invariant),
                        "PROPERTY" | "PROPERTIES" => Some(Checked::Property),
                        _ => None,
                    };
                } else if let Some(kind) = section {
                    checks.push((token.to_string(), kind));
                }
            }
        }
        Ok(Config {
            name,
            spec,
            text,
            checks,
            expected,
        })
    }

    /// The config with `property` as the only thing it checks.
    fn checking_only(&self, property: &str, kind: Checked) -> String {
        let mut out = String::new();
        let mut skipping = false;
        for line in self.text.lines() {
            let first = line.split_whitespace().next();
            if let Some(token) = first
                && SECTIONS.contains(&token)
            {
                skipping = matches!(
                    token,
                    "INVARIANT" | "INVARIANTS" | "PROPERTY" | "PROPERTIES"
                );
            }
            if !skipping {
                out.push_str(line);
                out.push('\n');
            }
        }
        let keyword = match kind {
            Checked::Invariant => "INVARIANT",
            Checked::Property => "PROPERTY",
        };
        let _ = writeln!(out, "{keyword}\n    {property}");
        out
    }
}

/// How one TLC run ended.
enum Outcome {
    /// TLC found no error.
    Pass,
    /// TLC reported a violation of the property it checked.
    Violated,
    /// TLC stopped for another reason: a parse error, a deadlock, a crash.
    Error(String),
}

/// Reads how a TLC run of `property` ended from its output.
fn outcome(text: &str, property: &str) -> Outcome {
    if text.contains("Model checking completed. No error has been found.") {
        return Outcome::Pass;
    }
    let invariant = format!("Error: Invariant {property} is violated");
    let action = format!("Error: Action property {property} is violated");
    if text.contains(&invariant)
        || text.contains(&action)
        || text.contains("Error: Temporal properties were violated.")
    {
        return Outcome::Violated;
    }
    let error = text
        .lines()
        .find(|line| line.starts_with("Error:"))
        .unwrap_or("TLC did not finish")
        .to_string();
    Outcome::Error(error)
}

/// The distinct states and the depth a TLC run reports, when it does.
fn statistics(text: &str) -> String {
    let states = text.lines().rev().find_map(|line| {
        let words: Vec<&str> = line.split_whitespace().collect();
        let at = words.iter().position(|w| *w == "distinct")?;
        words.get(at.checked_sub(1)?).map(|n| n.to_string())
    });
    let depth = text.lines().rev().find_map(|line| {
        line.strip_prefix("The depth of the complete state graph search is ")
            .map(|d| d.trim_end_matches('.').to_string())
    });
    match (states, depth) {
        (Some(states), Some(depth)) => format!("{states} distinct states, depth {depth}"),
        (Some(states), None) => format!("{states} distinct states"),
        _ => "no statistics".to_string(),
    }
}

/// Every config of `verification/dns/tla`, or those of `spec`, or the one
/// config `config` names (as `Resolution_base` or as `base`).
fn configs(paths: &Paths, spec: Option<&str>, config: Option<&str>) -> Result<Vec<Config>> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(&paths.tla)?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().is_some_and(|e| e == "cfg"))
        .collect();
    files.sort();
    let mut chosen = Vec::new();
    for file in files {
        let config_file = Config::read(&file)?;
        let spec_matches = spec.is_none_or(|s| config_file.spec == s);
        let config_matches = config.is_none_or(|c| {
            config_file.name == c || config_file.name == format!("{}_{c}", config_file.spec)
        });
        if spec_matches && config_matches {
            chosen.push(config_file);
        }
    }
    if chosen.is_empty() {
        return Err(format!("no TLC config matches {spec:?} {config:?}").into());
    }
    Ok(chosen)
}

/// TLC on each config, once per property. A config that expects
/// violations must list exactly the properties it expects to fail, and
/// each must fail; every other config must pass every property.
fn tlc(paths: &Paths, spec: Option<&str>, config: Option<&str>) -> Result<Report> {
    let jar = std::env::var_os("TLA2TOOLS").ok_or("TLA2TOOLS must name tla2tools.jar")?;
    let java = std::env::var_os("JAVA").unwrap_or_else(|| "java".into());
    let out = paths.out.join("tlc");
    // TLC looks for a config in the directory of its spec, so the specs
    // are copied next to the one-property configs made from them.
    let specs = out.join("specs");
    std::fs::create_dir_all(&specs)?;
    for entry in std::fs::read_dir(&paths.tla)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "tla") {
            std::fs::copy(&path, specs.join(path.file_name().ok_or("a file name")?))?;
        }
    }
    let mut report = Report::new("tlc");
    for config in configs(paths, spec, config)? {
        let listed: BTreeSet<String> = config.checks.iter().map(|(p, _)| p.clone()).collect();
        if !config.expected.is_empty() && config.expected != listed {
            report.fail(format!(
                "{}: expects violations of {:?} but checks {:?}",
                config.name, config.expected, listed
            ));
            continue;
        }
        let spec_file = format!("{}.tla", config.spec);
        for (property, kind) in &config.checks {
            let expect_violation = config.expected.contains(property);
            let run = format!("{}-{property}", config.name);
            let cfg = specs.join(format!("{run}.cfg"));
            std::fs::write(&cfg, config.checking_only(property, *kind))?;
            let states = out.join("states").join(&run);
            // One worker for an ablation, so its counterexample is a
            // shortest one.
            let workers = if expect_violation { "1" } else { "auto" };
            let mut command = Command::new(&java);
            command
                .arg("-XX:+UseParallelGC")
                .arg("-Xmx6g")
                .arg("-cp")
                .arg(&jar)
                .arg("tlc2.TLC")
                .arg("-workers")
                .arg(workers)
                .arg("-metadir")
                .arg(&states)
                .arg("-config")
                .arg(format!("{run}.cfg"))
                .arg(&spec_file)
                .current_dir(&specs);
            let started = Instant::now();
            let (text, _) = logged(&mut command, &out.join(format!("{run}.out")))?;
            let seconds = started.elapsed().as_secs();
            let _ = std::fs::remove_dir_all(&states);
            let stats = statistics(&text);
            match (outcome(&text, property), expect_violation) {
                (Outcome::Pass, false) => {
                    report.pass(format!("{run}: pass, {stats}, {seconds} s"));
                }
                (Outcome::Violated, true) => {
                    report.pass(format!("{run}: violated as expected, {stats}, {seconds} s"));
                }
                (Outcome::Pass, true) => {
                    report.fail(format!("{run}: passed, but its config expects a violation"));
                }
                (Outcome::Violated, false) => {
                    report.fail(format!("{run}: violated, {stats}; see {run}.out"));
                }
                (Outcome::Error(error), _) => {
                    report.fail(format!("{run}: {error}; see {run}.out"));
                }
            }
        }
    }
    Ok(report)
}

// ---------------------------------------------------------------------
// Lean
// ---------------------------------------------------------------------

/// `lake build`, then `Dns/Axioms.lean` again, whose `#print axioms` lines
/// must name only Lean's standard axioms.
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
            .args(["env", "lean", "Dns/Axioms.lean"])
            .current_dir(&paths.lean),
        &out.join("axioms.out"),
    )?;
    if !checked {
        report.fail("Dns/Axioms.lean does not check; see lean/axioms.out".to_string());
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
        let axioms = rest.trim_end_matches(']');
        let others: Vec<&str> = axioms
            .split(',')
            .map(str::trim)
            .filter(|axiom| !STANDARD_AXIOMS.contains(axiom))
            .collect();
        if !others.is_empty() {
            report.fail(format!("{theorem} rests on {}", others.join(", ")));
        }
    }
    if theorems == 0 {
        report.fail("Dns/Axioms.lean printed no axioms; see lean/axioms.out".to_string());
    } else {
        report.pass(format!(
            "axioms: {theorems} headline theorems rest on {} at most",
            STANDARD_AXIOMS.join(", ")
        ));
    }
    Ok(report)
}

// ---------------------------------------------------------------------
// Vectors and the differential test
// ---------------------------------------------------------------------

fn vectors_dir(paths: &Paths, seed: u64) -> PathBuf {
    paths.out.join("vectors").join(seed.to_string())
}

/// `lake exe gen` into `vectors/<seed>/`, emptied first so no file of an
/// older run is left.
fn vectors(paths: &Paths, seed: u64) -> Result<Report> {
    let dir = vectors_dir(paths, seed);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let mut report = Report::new("vectors");
    let log = format!("gen-{seed}.out");
    let (text, made) = logged(
        lake()
            .args(["exe", "gen"])
            .arg(&dir)
            .arg(seed.to_string())
            .current_dir(&paths.lean),
        &paths.out.join("lean").join(&log),
    )?;
    if made {
        let files: Vec<&str> = text.lines().filter(|l| l.contains(".json")).collect();
        report.pass(format!("seed {seed}: {}", files.join(", ")));
    } else {
        report.fail(format!("seed {seed}: lake exe gen; see lean/{log}"));
    }
    Ok(report)
}

/// For each of `seeds`, the vectors, then `cargo test --test dns_vectors`
/// with `DNS_VECTORS` naming them. Each kind's line of the test's output
/// goes in the report, after its seed.
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
            Command::new(cargo)
                .args(["test", "--test", "dns_vectors", "--", "--nocapture"])
                .env("DNS_VECTORS", vectors_dir(paths, seed))
                .current_dir(&paths.root),
            &paths.out.join(&log),
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
        let failed = kinds.iter().any(|line| !line.contains(", 0 disagree"));
        if !passed && !failed {
            report.fail(format!(
                "seed {seed}: cargo test --test dns_vectors; see {log}"
            ));
        }
        if kinds.is_empty() && passed {
            report.fail(format!(
                "seed {seed}: the differential test ran no kind; see {log}"
            ));
        }
    }
    Ok(report)
}

/// One step of `dns-verify all`.
type Step = fn(&Paths) -> Result<Report>;

/// Every step, each run even when one before it failed, and the summary.
fn all(paths: &Paths) -> Result {
    let steps: [(&'static str, Step); 3] = [
        ("tlc", |paths| tlc(paths, None, None)),
        ("lean", lean),
        ("diff", |paths| diff(paths, &SEEDS.collect::<Vec<_>>())),
    ];
    let mut reports = Vec::new();
    for (step, run) in steps {
        let report = run(paths).unwrap_or_else(|error| {
            let mut report = Report::new(step);
            report.fail(error.to_string());
            report
        });
        report.print();
        reports.push(report);
    }
    let mut summary = String::from("cargo xtask dns-verify all\n\n");
    for report in &reports {
        let _ = writeln!(summary, "{}", report.heading());
    }
    for report in &reports {
        let _ = writeln!(summary, "\n{}", report.step);
        for line in &report.lines {
            let _ = writeln!(summary, "  {line}");
        }
    }
    std::fs::create_dir_all(&paths.out)?;
    let file = paths.out.join("SUMMARY.txt");
    std::fs::write(&file, summary)?;
    println!("summary: {}", file.display());
    let failed: Vec<&str> = reports
        .iter()
        .filter(|r| r.failures > 0)
        .map(|r| r.step)
        .collect();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("dns-verify all: {} failed", failed.join(", ")).into())
    }
}
