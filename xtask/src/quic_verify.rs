//! `cargo xtask quic-verify`: the QUIC verification in `verification/quic`.
//!
//! | Command | Does |
//! | --- | --- |
//! | `quic-verify resources` | the resource properties of version negotiation: the counted Kani harnesses, and `VersionResources.tla`'s configs |
//!
//! Output goes under a fresh run directory in `quic-verify/` in Cargo's
//! target directory. The replays that cost the real key derivation and a
//! server's Retry run with the engine's tests (`initial_key_derivations_stay_within_their_charge`,
//! `a_server_retry_allocates_nothing_beyond_its_buffer`).

use std::path::{Path, PathBuf};

use crate::Result;
use crate::lean_vectors::Report;
use crate::resources;

const COMMAND: &str = "quic-verify";

/// The engine's package.
const PACKAGE: &str = "fictionet-quinn-proto";

/// The harnesses call key and token traits through `dyn`.
const UNSTABLE: [&str; 1] = ["restrict-vtable"];

/// The counter's own check, then every storage of version negotiation:
/// key derivations charged first, Retry and Version Negotiation packets
/// and tokens in the send buffer, a client's Retry copy within its charge,
/// and the version rules without allocation.
const KANI_RESOURCES: [&str; 14] = [
    "counting::proofs::the_counter_sees_every_allocation",
    "connection::negotiation::negotiation_storage_proofs::other_initial_keys_are_charged_before_they_are_derived",
    "connection::negotiation::negotiation_storage_proofs::installed_keys_free_the_old_ones_before_the_charge_goes",
    "connection::negotiation::negotiation_storage_proofs::a_key_charge_is_all_or_nothing",
    "connection::negotiation::negotiation_storage_proofs::negotiation_decisions_allocate_nothing",
    "packet::retry::retry_storage_proofs::a_server_tags_a_retry_in_its_send_buffer",
    "packet::retry::retry_storage_proofs::a_client_copies_a_retry_only_within_its_charge",
    "endpoint::version_negotiation_proofs::version_negotiation_is_written_in_the_send_buffer",
    "token::token_storage_proofs::a_retry_token_is_sealed_in_place",
    "token::token_storage_proofs::a_returned_token_never_allocates",
    "version::first_flight::first_flight_storage_proofs::the_transport_parameter_offer_is_read_in_place",
    "version::version_storage_proofs::version_choices_allocate_nothing",
    "version::version_storage_proofs::version_information_is_encoded_in_place",
    "transport_parameters::version_information_proofs::version_information_body_checks_the_connection_without_allocating",
];

/// The code, a control for each flag of the model, and the states each
/// path reaches.
const TLC_RESOURCES: [&str; 10] = [
    "VersionResources_base.cfg",
    "VersionResources_without_chargefirst.cfg",
    "VersionResources_without_coverderivation.cfg",
    "VersionResources_without_freefirst.cfg",
    "VersionResources_without_chargerederive.cfg",
    "VersionResources_without_chargeretrycopy.cfg",
    "VersionResources_without_honorrefusal.cfg",
    "VersionResources_reaches_refusal.cfg",
    "VersionResources_reaches_upgrade.cfg",
    "VersionResources_reaches_restart.cfg",
];

/// Runs `quic-verify` with the arguments after it.
pub fn run(args: &[String]) -> Result {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let report = match args.as_slice() {
        ["resources"] => {
            let (root, out) = paths()?;
            let mut report = Report::new("resources");
            report.absorb(resources::kani(
                &root,
                &out,
                PACKAGE,
                &UNSTABLE,
                &KANI_RESOURCES,
            )?);
            report.absorb(resources::tlc(
                &root,
                &out,
                &root.join("verification/quic/tla"),
                "VersionResources",
                &TLC_RESOURCES,
            )?);
            report
        }
        _ => return Err("expected quic-verify resources".into()),
    };
    report.print();
    report.result(COMMAND)
}

/// The repository, and a fresh run directory in `quic-verify/` in Cargo's
/// target directory.
fn paths() -> Result<(PathBuf, PathBuf)> {
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
    let out = crate::verification_run(&target.join(COMMAND))?;
    Ok((root, out))
}
