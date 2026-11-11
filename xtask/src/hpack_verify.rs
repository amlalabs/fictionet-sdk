//! `cargo xtask hpack-verify`: the Lean 4 model of HPACK in
//! `verification/hpack-grpc/lean`, and the differential test that holds the
//! Rust code to it.
//!
//! | Command | Does |
//! | --- | --- |
//! | `hpack-verify lean` | `lake build`, then the axioms of every headline theorem |
//! | `hpack-verify vectors [seed]` | the model's vectors, from `seed`, or from each of seeds 1 to 8 when left out |
//! | `hpack-verify diff [seed]` | the vectors, then `tests/hpack_vectors.rs` against them, for each seed, with each block's cost held to its bounds |
//! | `hpack-verify resources` | the resource properties: the counted Kani harnesses, and `HpackSync.tla`'s configs that check the tables' storage |
//!
//! Output goes under a fresh run directory in `hpack-verify/` in Cargo's
//! target directory: Lean's in `lean/`, the vectors of each seed in
//! `vectors/<seed>/`, the test's in `diff-<seed>.out`. The vectors are made
//! again on every run and never committed.

use crate::Result;
use crate::lean_vectors::{self, Project, Report};
use crate::resources;

/// The seeds of the vectors when none is given. Each seed draws other
/// strings, blocks, sessions and encoder steps.
const SEEDS: std::ops::RangeInclusive<u64> = 1..=8;

const COMMAND: &str = "hpack-verify";

/// The counter's own check, the constant the bounds use, then each table
/// insertion within its charge.
const KANI_RESOURCES: [&str; 10] = [
    "counting::proofs::the_counter_sees_every_allocation",
    "stdlib::protocols::hpack::resource_proofs::the_longest_static_name_is_counted",
    "stdlib::protocols::hpack::resource_proofs::decoding_a_literal_name_stays_within_its_charge",
    "stdlib::protocols::hpack::resource_proofs::decoding_a_dynamic_name_stays_within_its_charge",
    "stdlib::protocols::hpack::resource_proofs::decoding_a_static_name_stays_within_its_charge",
    "stdlib::protocols::hpack::resource_proofs::encoding_into_an_empty_table_stays_within_its_charge",
    "stdlib::protocols::hpack::resource_proofs::encoding_into_a_table_of_one_stays_within_its_charge",
    "stdlib::protocols::hpack::resource_proofs::encoding_into_a_table_of_two_stays_within_its_charge",
    "stdlib::protocols::hpack::resource_proofs::encoding_into_a_table_of_three_stays_within_its_charge",
    "stdlib::protocols::hpack::resource_proofs::encoding_into_a_table_of_four_stays_within_its_charge",
];

/// The configs that check the stores: the code, and a control for each
/// end that inserts before it evicts.
const TLC_RESOURCES: [&str; 5] = [
    "HpackSync_base.cfg",
    "HpackSync_server_base.cfg",
    "HpackSync_adversary_base.cfg",
    "HpackSync_adversary_without_evictfirst.cfg",
    "HpackSync_without_encevictfirst.cfg",
];

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
        ["resources"] => {
            let mut report = Report::new("resources");
            report.absorb(resources::kani(
                &project.root,
                &project.out,
                "fictionet",
                &KANI_RESOURCES,
            )?);
            report.absorb(resources::tlc(
                &project.root,
                &project.out,
                &project.root.join("verification/hpack-grpc/tla"),
                "HpackSync",
                &TLC_RESOURCES,
            )?);
            report
        }
        _ => {
            return Err(
                "expected hpack-verify lean, vectors [seed], diff [seed], or resources".into(),
            );
        }
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
