//! `cargo xtask hpack-verify`: the Lean 4 model of HPACK in
//! `verification/hpack-grpc/lean`, and the differential test that holds the
//! Rust code to it.
//!
//! | Command | Does |
//! | --- | --- |
//! | `hpack-verify lean` | `lake build`, then the axioms of every headline theorem |
//! | `hpack-verify vectors [seed]` | the model's vectors, from `seed`, or from each of seeds 1 to 8 when left out |
//! | `hpack-verify diff [seed]` | the vectors, then `tests/hpack_vectors.rs` against them, for each seed |
//!
//! Output goes under a fresh run directory in `hpack-verify/` in Cargo's
//! target directory: Lean's in `lean/`, the vectors of each seed in
//! `vectors/<seed>/`, the test's in `diff-<seed>.out`. The vectors are made
//! again on every run and never committed.

use crate::Result;
use crate::lean_vectors::{self, Project, Report};

/// The seeds of the vectors when none is given. Each seed draws other
/// strings, blocks, sessions and encoder steps.
const SEEDS: std::ops::RangeInclusive<u64> = 1..=8;

const COMMAND: &str = "hpack-verify";

/// Runs `hpack-verify` with the arguments after it.
pub fn run(args: &[String]) -> Result {
    let project = Project::new(
        COMMAND,
        "hpack-grpc",
        "Hpack/Axioms.lean",
        "hpack_vectors",
        "HPACK_VECTORS",
    )?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let report = match args.as_slice() {
        ["lean"] => lean_vectors::lean(&project)?,
        ["vectors", seed @ ..] if seed.len() <= 1 => {
            let mut report = Report::new("vectors");
            for seed in seeds_of(seed)? {
                report.absorb(lean_vectors::vectors(&project, seed)?);
            }
            report
        }
        ["diff", seed @ ..] if seed.len() <= 1 => lean_vectors::diff(&project, &seeds_of(seed)?)?,
        _ => return Err("expected hpack-verify lean, vectors [seed], or diff [seed]".into()),
    };
    report.print();
    report.result(COMMAND)
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
