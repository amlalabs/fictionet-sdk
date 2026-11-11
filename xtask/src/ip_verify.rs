//! `cargo xtask ip-verify`: the Lean 4 proofs about the IP, UDP and ICMP
//! code in `verification/packet-udp/lean`, and the differential test
//! `tests/ip_vectors.rs` that holds the Rust code to the Lean reference.
//!
//! | Command | Does |
//! | --- | --- |
//! | `ip-verify lean` | `lake build`, then the axioms of every headline theorem in `Ip/Axioms.lean` |
//! | `ip-verify vectors [seed]` | the Lean reference's test vectors, from `seed`, or from each of seeds 1 to 8 when left out |
//! | `ip-verify diff [seed]` | the vectors, then `tests/ip_vectors.rs` against them, for each seed, with each reassembly step costed |
//! | `ip-verify all` | `lean` and `diff`, with a summary in `SUMMARY.txt` |
//! | `ip-verify resources` | the resource properties of TCP and below: the counted Kani harnesses, `Holding.tla`'s configs, and the costed sessions |
//!
//! Everything is written under a fresh run directory in `ip-verify/` in
//! Cargo's target directory (`CARGO_TARGET_DIR`, or `target/`): Lean's
//! output in `lean/`, the vectors of each seed in `vectors/<seed>/`, and
//! the differential test's output in `diff-<seed>.out`. The vectors are
//! made again on every run and never committed. Lake is `$LAKE`, or
//! `lake`.
//!
//! A kind whose Lean module writes no vector file yet is reported as not
//! yet written, not as a pass. This task runs Lean and Cargo as child
//! processes with no memory cap of its own: run it under one, as
//! `verification/packet-udp/lean/README.md` shows.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Result;
use crate::lean_vectors::{self, scoped};
use crate::resources;

/// The axioms a headline theorem may rest on: Lean's own, and no `sorryAx`.
const STANDARD_AXIOMS: [&str; 3] = ["propext", "Quot.sound", "Classical.choice"];

/// The seeds of the vectors when none is given. Each seed draws other
/// octets, lengths and mutations, so several seeds reach cases one misses.
const SEEDS: std::ops::RangeInclusive<u64> = 1..=8;

const COMMAND: &str = "ip-verify";

/// The harnesses reach a `Budget`, whose wakers are trait objects: Kani
/// limits their calls to the types that make one, as the layer's budget
/// harnesses do (verification/layer/VERIFICATION.md).
const RESTRICT_VTABLE: &[&str] = &["-Z", "restrict-vtable"];

/// The counted Kani harnesses in `fictionet`: the counter's own check,
/// and a UDP socket paying before it keeps. Not listed, because they do not
/// finish within 14 GiB and 25 minutes (verification/packet-udp/README.md,
/// "Kani"): the three reassembly harnesses in `ip.rs`'s `resource_proofs`
/// and `a_third_datagram_is_paid_before_it_is_kept`.
const KANI_FICTIONET: [&str; 3] = [
    "counting::proofs::the_counter_sees_every_allocation",
    "stdlib::network::udp::sockets::resource_proofs::the_first_datagram_is_paid_before_it_is_kept",
    "stdlib::network::udp::sockets::resource_proofs::a_second_datagram_is_paid_before_it_is_kept",
];

/// The counted Kani harnesses in the vendored smoltcp: the counter's own
/// check, that the stubs see what smoltcp allocates. The stores' harnesses
/// in `socket::tcp::resource_proofs` do not finish within 14 GiB and 25
/// minutes (verification/packet-udp/README.md, "Kani"), so they are not
/// listed.
const KANI_SMOLTCP: [&str; 1] = ["counting::proofs::the_counter_sees_every_allocation"];

/// `Holding.tla`'s configs: the code, and a control for each order it keeps.
const TLC_HOLDING: [&str; 5] = [
    "Holding_base.cfg",
    "Holding_without_roomfirst.cfg",
    "Holding_without_movefirst.cfg",
    "Holding_without_chargefirst.cfg",
    "Holding_without_headers.cfg",
];

/// The costed sessions: the package, the test target, and the filter.
const SESSIONS: [(&str, &str, &str); 3] = [
    ("fictionet", "--test=it", "net_resources"),
    (
        "fictionet",
        "--lib",
        "listen::tests::a_packet_longer_than_a_block_is_paid_from_the_sandboxs_budget",
    ),
    ("smoltcp", "--lib", "store_costs"),
];

/// Runs `ip-verify` with the arguments after it.
pub fn run(args: &[String]) -> Result {
    let paths = Paths::new()?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
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
        ["resources"] => {
            let report = resources(&paths)?;
            report.print();
            report.result(COMMAND)
        }
        _ => Err("expected ip-verify lean, vectors [seed], diff [seed], all, or resources".into()),
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
    /// `verification/packet-udp/lean`.
    lean: PathBuf,
    /// The run directory under `ip-verify/` in Cargo's target directory.
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
            lean: root.join("verification").join("packet-udp").join("lean"),
            out: crate::verification_run(&target.join("ip-verify"))?,
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
            Err(format!("ip-verify {}: {} failed", self.step, self.failures).into())
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

fn lake() -> Command {
    Command::new(std::env::var_os("LAKE").unwrap_or_else(|| "lake".into()))
}

/// `lake build`, then `Ip/Axioms.lean` again, whose `#print axioms` lines
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
            .args(["env", "lean", "Ip/Axioms.lean"])
            .current_dir(&paths.lean),
        &out.join("axioms.out"),
    )?;
    if !checked {
        report.fail("Ip/Axioms.lean does not check; see lean/axioms.out".to_string());
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
        report.fail("Ip/Axioms.lean printed no axioms; see lean/axioms.out".to_string());
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

/// Builds and runs `gen` into `vectors/<seed>/`, emptied first so no file
/// of an older run is left, and names the files it wrote.
fn vectors(paths: &Paths, seed: u64) -> Result<Report> {
    let dir = vectors_dir(paths, seed);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let mut report = Report::new("vectors");
    let log = format!("gen-{seed}.out");
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
    let (_, made) = logged(
        lake()
            .args(["env", ".lake/build/bin/gen"])
            .arg(&dir)
            .arg(seed.to_string())
            .current_dir(&paths.lean),
        &paths.out.join("lean").join(&log),
    )?;
    if !made {
        report.fail(format!("seed {seed}: generator execution; see lean/{log}"));
        return Ok(report);
    }
    let mut files: Vec<String> = std::fs::read_dir(&dir)?
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .collect();
    files.sort();
    if files.is_empty() {
        report.fail(format!("seed {seed}: the generator wrote no vector file"));
    } else {
        report.pass(format!("seed {seed}: {}", files.join(", ")));
    }
    Ok(report)
}

/// For each of `seeds`, the vectors, then `cargo test --test ip_vectors`
/// with `IP_VECTORS` naming them. Each kind's line of the test's output
/// goes in the report, after its seed: its case count, or that its vectors
/// are not yet written.
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
                .args([
                    "test",
                    "-p",
                    "fictionet",
                    "--test",
                    "ip_vectors",
                    "--",
                    "--nocapture",
                ])
                .env("IP_VECTORS", vectors_dir(paths, seed))
                .current_dir(&paths.root),
            &paths.out.join(&log),
        )?;
        let mut ran = 0;
        for line in text.lines() {
            if line.ends_with(", 0 disagree") {
                ran += 1;
                report.pass(format!("seed {seed}: {line}"));
            } else if line.ends_with(": no vector file, not yet written") {
                report.pass(format!("seed {seed}: {line}"));
            }
        }
        if !passed {
            report.fail(format!(
                "seed {seed}: cargo test --test ip_vectors; see {log}"
            ));
        } else if ran == 0 {
            report.fail(format!(
                "seed {seed}: the differential test checked no kind; see {log}"
            ));
        }
    }
    Ok(report)
}

/// One step of `ip-verify all`.
type Step = fn(&Paths) -> Result<Report>;

/// Every step, each run even when one before it failed, and the summary.
fn all(paths: &Paths) -> Result {
    let steps: [(&'static str, Step); 2] = [
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
    let mut summary = String::from("cargo xtask ip-verify all\n\n");
    for report in &reports {
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
        Err(format!("ip-verify all: {} failed", failed.join(", ")).into())
    }
}

/// The resource properties of TCP and below (verification/packet-udp/README.md,
/// "Resource properties"): the counted Kani harnesses, `Holding.tla`'s
/// configs, and the costed sessions, each of which must pass.
fn resources(paths: &Paths) -> Result<lean_vectors::Report> {
    let mut report = lean_vectors::Report::new("resources");
    report.absorb(resources::kani_with(
        &paths.root,
        &paths.out.join("fictionet"),
        "fictionet",
        RESTRICT_VTABLE,
        &KANI_FICTIONET,
    )?);
    report.absorb(resources::kani_with(
        &paths.root,
        &paths.out.join("smoltcp"),
        "smoltcp",
        RESTRICT_VTABLE,
        &KANI_SMOLTCP,
    )?);
    report.absorb(resources::tlc(
        &paths.root,
        &paths.out,
        &paths.root.join("verification/packet-udp/tla"),
        "Holding",
        &TLC_HOLDING,
    )?);
    let mut sessions = lean_vectors::Report::new("sessions");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    for (package, target, filter) in SESSIONS {
        let log = paths
            .out
            .join(format!("{package}-{}.out", target.trim_start_matches("--")));
        let (text, ran) = logged(
            scoped(&cargo, "8G")
                .args(["test", "-p", package, target, filter, "--", "--nocapture"])
                .current_dir(&paths.root),
            &log,
        )?;
        for line in text.lines().filter_map(|line| line.split_once("cost: ")) {
            sessions.pass(line.1.to_string());
        }
        if ran {
            sessions.pass(format!("{package} {target} {filter}: passed"));
        } else {
            sessions.fail(format!(
                "{package} {target} {filter}: see {}",
                log.display()
            ));
        }
    }
    report.absorb(sessions);
    Ok(report)
}
