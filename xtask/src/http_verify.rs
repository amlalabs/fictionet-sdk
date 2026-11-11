//! `cargo xtask http-verify`: the Lean 4 proofs of Fictionet's HTTP/1
//! framing in `verification/http/lean/`, and the differential test that
//! holds the Rust decoders to the Lean model.
//!
//! | Command | Does |
//! | --- | --- |
//! | `http-verify lean` | `lake build`, then the axioms of every headline theorem |
//! | `http-verify vectors [seed]` | the Lean model's test vectors, from `seed`, or from each of seeds 1 to 8 when left out |
//! | `http-verify diff [seed]` | the vectors, then `tests/http1_vectors.rs` against them, for each seed, every request vector and two fixed heads also served and costed |
//! | `http-verify resources` | the resource properties: the counted Kani harnesses, and the TLC configs of `Assembly.tla` and `SendHold.tla` |
//! | `http-verify all` | `lean` and `diff`, with a summary in `SUMMARY.txt` |
//!
//! Everything is written under a fresh run directory in `http-verify/` in
//! Cargo's target directory (`CARGO_TARGET_DIR`, or `target/`): Lean's
//! output in `lean/`, the vectors of each seed in `vectors/<seed>/`, and
//! the differential test's output in `diff-<seed>.out`. The vectors are
//! made again on every run and never committed. Lake is `$LAKE`, or `lake`;
//! Lake runs under a 6 GiB memory cap and the test under an 8 GiB one.
//!
//! The TLA+ models of the same folder are run one config at a time, as
//! `verification/http/README.md` says.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Result;
use crate::lean_vectors::Report;
use crate::resources;

/// The counter's own check and the constant the bounds use. The
/// head-assembly harnesses in `verification/http/kani/resources.rs` did
/// not finish in an hour each, and the body-collection harnesses in
/// `verification/http/kani/collect.rs` run CBMC out of 14 GiB
/// (`verification/http/README.md`).
const KANI_RESOURCES: [&str; 2] = [
    "counting::proofs::the_counter_sees_every_allocation",
    "stdlib::protocols::http1::resource_proofs::a_backing_is_within_its_constant",
];

/// The configs that check the joins and the send holds, each with the
/// result its first line names: the code, and the controls.
const TLC_RESOURCES: [(&str, &[&str]); 2] = [
    (
        "Assembly",
        &[
            "Assembly_head_base.cfg",
            "Assembly_head_long_base.cfg",
            "Assembly_block_base.cfg",
            "Assembly_block_budgetmoves_base.cfg",
            "Assembly_body_base.cfg",
            "Assembly_body_length_base.cfg",
            "Assembly_block_moving.cfg",
            "Assembly_body_moving.cfg",
            "Assembly_head_without_double.cfg",
            "Assembly_head_without_largestwhenrefused.cfg",
            "Assembly_head_without_chargefirst.cfg",
            "Assembly_body_without_double.cfg",
            "Assembly_head_budgetmoves.cfg",
            "Assembly_block_without_chargewhole.cfg",
            "Assembly_body_without_chargewhole.cfg",
        ],
    ),
    (
        "SendHold",
        &[
            "SendHold_base.cfg",
            "SendHold_receive_base.cfg",
            "SendHold_without_stalldeadline.cfg",
            "SendHold_without_topupcredit.cfg",
            "SendHold_without_returncreditwhenfreed.cfg",
        ],
    ),
];

/// The axioms a headline theorem may rest on: Lean's own, and no `sorryAx`.
const STANDARD_AXIOMS: [&str; 3] = ["propext", "Quot.sound", "Classical.choice"];

/// The seeds of the vectors when none is given.
const SEEDS: std::ops::RangeInclusive<u64> = 1..=8;

/// Runs `http-verify` with the arguments after it.
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
        ["resources"] => return resource_properties(&paths),
        ["all"] => return all(&paths),
        _ => {
            return Err(
                "expected http-verify lean, vectors [seed], diff [seed], resources, or all".into(),
            );
        }
    };
    report.print();
    report.result("http-verify")
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
    /// `verification/http/lean`.
    lean: PathBuf,
    /// The run directory in `http-verify/` in Cargo's target directory.
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
            lean: root.join("verification").join("http").join("lean"),
            out: crate::verification_run(&target.join("http-verify"))?,
            root,
        })
    }

    fn vectors(&self, seed: u64) -> PathBuf {
        self.out.join("vectors").join(seed.to_string())
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

/// `program` in a user scope with a memory cap.
fn scoped(memory: &str, program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new("systemd-run");
    command.args([
        "--user",
        "--scope",
        "-q",
        "--slice=fictionet-work.slice",
        "-p",
    ]);
    command.arg(format!("MemoryMax={memory}"));
    command.args(["-p", "MemorySwapMax=0", "--setenv=PATH"]);
    command.arg(program);
    command
}

fn lake() -> Command {
    scoped(
        "6G",
        std::env::var_os("LAKE").unwrap_or_else(|| "lake".into()),
    )
}

/// `lake build`, then `Http/Axioms.lean`: every headline theorem rests on
/// the standard axioms at most.
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
            .args(["env", "lean", "Http/Axioms.lean"])
            .current_dir(&paths.lean),
        &out.join("axioms.out"),
    )?;
    if !checked {
        report.fail("Http/Axioms.lean does not check; see lean/axioms.out".to_string());
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
        report.fail("Http/Axioms.lean printed no axioms; see lean/axioms.out".to_string());
    } else {
        report.pass(format!(
            "axioms: {theorems} headline theorems rest on {} at most",
            STANDARD_AXIOMS.join(", ")
        ));
    }
    Ok(report)
}

/// Builds and runs `gen` into `vectors/<seed>/`.
fn vectors(paths: &Paths, seed: u64) -> Result<Report> {
    let dir = paths.vectors(seed);
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
        let files: Vec<&str> = text.lines().filter(|l| l.contains(".json")).collect();
        report.pass(format!("seed {seed}: {}", files.join(", ")));
    } else {
        report.fail(format!("seed {seed}: generator execution; see lean/{log}"));
    }
    Ok(report)
}

/// For each of `seeds`, the vectors, then `cargo test --test http1_vectors`
/// with `HTTP1_VECTORS` naming them.
fn diff(paths: &Paths, seeds: &[u64]) -> Result<Report> {
    let mut report = Report::new("diff");
    for &seed in seeds {
        let made = vectors(paths, seed)?;
        let failed = made.failures > 0;
        report.absorb(made);
        if failed {
            continue;
        }
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let log = format!("diff-{seed}.out");
        let (text, passed) = logged(
            scoped("8G", cargo)
                .args(["test", "-p", "fictionet", "--test", "http1_vectors"])
                .args(["--", "--nocapture", "--test-threads=1"])
                .env("HTTP1_VECTORS", paths.vectors(seed))
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
        // The served requests and heads are held to cost bounds
        // (verification/resources/cost.rs): a line for each kind; a bound
        // broken fails the test, and its log names the step.
        let costed = resources::costs(&mut report, &format!("seed {seed}"), &text);
        if passed && costed == 0 {
            report.fail(format!("seed {seed}: no session was costed; see {log}"));
        }
        if !passed && kinds.iter().all(|line| line.contains(", 0 disagree")) {
            report.fail(format!(
                "seed {seed}: cargo test --test http1_vectors; see {log}"
            ));
        }
        if kinds.is_empty() && passed {
            report.fail(format!(
                "seed {seed}: the test printed no case counts; see {log}"
            ));
        }
    }
    Ok(report)
}

/// The resource properties (verification/README.md): the counted Kani
/// harnesses, then each TLC config of [`TLC_RESOURCES`], output in
/// `kani.out` and `<config>.out` of the run directory.
fn resource_properties(paths: &Paths) -> Result {
    let mut report = Report::new("resources");
    report.absorb(resources::kani(
        &paths.root,
        &paths.out,
        "fictionet",
        &KANI_RESOURCES,
        "14G",
    )?);
    let tla = paths.root.join("verification").join("http").join("tla");
    for (module, configs) in TLC_RESOURCES {
        report.absorb(resources::tlc(
            &paths.root,
            &paths.out,
            &tla,
            module,
            configs,
        )?);
    }
    report.print();
    report.result("http-verify")
}

/// `lean` and `diff` over [`SEEDS`], with `SUMMARY.txt`.
fn all(paths: &Paths) -> Result {
    let reports = [
        lean(paths).unwrap_or_else(|error| failed("lean", error)),
        diff(paths, &SEEDS.collect::<Vec<_>>()).unwrap_or_else(|error| failed("diff", error)),
    ];
    let mut summary = String::from("cargo xtask http-verify all\n\n");
    for report in &reports {
        report.print();
        let _ = writeln!(summary, "{}", report.heading());
    }
    for report in &reports {
        let _ = writeln!(summary, "\n{}", report.step);
        for line in &report.lines {
            let _ = writeln!(summary, "  {line}");
        }
    }
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
        Err(format!("http-verify all: {} failed", failed.join(", ")).into())
    }
}

fn failed(step: &'static str, error: Box<dyn std::error::Error + Send + Sync>) -> Report {
    let mut report = Report::new(step);
    report.fail(error.to_string());
    report
}
