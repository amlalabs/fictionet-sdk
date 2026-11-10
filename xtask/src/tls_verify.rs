//! `cargo xtask tls-verify`: the vendored rustls checked against the TLS
//! models in `verification/tls-rfc/`.
//!
//! | Command | Does |
//! | --- | --- |
//! | `tls-verify lean` | builds the Lean proofs in `verification/tls-rfc/lean` (record checks before decryption, nonce uniqueness and the order of records on the wire), fails on a proof left as `sorry`, and checks that each headline theorem rests only on Lean's standard axioms |
//! | `tls-verify vectors [seed]` | writes the Lean model's vectors (`lake exe gen`) and replays them against the real rustls: `record_vectors` (`rustls/src/budget/tests/record_vectors.rs`) and `nonce_vectors` (`rustls/src/common_state/nonce_vectors.rs`); the seed defaults to 1 |
//! | `tls-verify handshake-trace` | logs real handshakes of the vendored server (`rustls/src/server/hs_trace.rs`) and checks each log against `verification/tls-rfc/tla/Handshake.tla` with `HandshakeTrace.tla` (`tls_verify_handshake.rs`) |
//! | `tls-verify record-trace` | logs a real budgeted server and client under seeded schedules (`rustls/src/budget/record_trace.rs`) and checks each log against `verification/tls-rfc/tla/Record.tla` with `RecordTrace.tla` (`tls_verify_record.rs`) |
//!
//! Everything is written under a fresh run directory in `tls-verify/` in
//! Cargo's target directory (`CARGO_TARGET_DIR`, or `target/`). `LAKE`
//! names `lake` (`lake` when unset).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Result;

/// Runs `tls-verify` with the arguments after it.
pub fn run(args: &[String]) -> Result {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["lean"] => lean(&Paths::new()?),
        ["vectors"] => vectors(&Paths::new()?, 1),
        ["vectors", seed] => vectors(&Paths::new()?, seed.parse()?),
        ["handshake-trace"] => crate::tls_verify_handshake::trace(),
        ["record-trace"] => crate::tls_verify_record::record(),
        _ => {
            Err("expected tls-verify lean, vectors [seed], handshake-trace or record-trace".into())
        }
    }
}

/// Where the sources are and where the results go.
struct Paths {
    root: PathBuf,
    lean: PathBuf,
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
            lean: root.join("verification").join("tls-rfc").join("lean"),
            out: crate::verification_run(&target.join("tls-verify"))?,
            root,
        })
    }
}

fn lake() -> Command {
    Command::new(std::env::var_os("LAKE").unwrap_or_else(|| "lake".into()))
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

/// Lean's standard axioms: what a finished proof may rest on.
const STANDARD_AXIOMS: [&str; 3] = ["propext", "Classical.choice", "Quot.sound"];

fn lean(paths: &Paths) -> Result {
    let (log, built) = logged(
        lake().arg("build").current_dir(&paths.lean),
        &paths.out.join("build.out"),
    )?;
    if !built {
        return Err(format!(
            "lake build failed; see {}",
            paths.out.join("build.out").display()
        )
        .into());
    }
    if log
        .lines()
        .any(|line| line.contains("declaration uses") && line.contains("sorry"))
    {
        return Err("a proof is left as sorry".into());
    }
    let (text, checked) = logged(
        lake()
            .args(["env", "lean", "TlsRecord/Axioms.lean"])
            .current_dir(&paths.lean),
        &paths.out.join("axioms.out"),
    )?;
    if !checked {
        return Err("TlsRecord/Axioms.lean does not check".into());
    }
    let mut theorems = 0;
    for line in text.lines() {
        if line.contains("does not depend on any axioms") {
            theorems += 1;
            continue;
        }
        let Some((theorem, rest)) = line.split_once(" depends on axioms: [") else {
            continue;
        };
        theorems += 1;
        let axioms = rest.trim_end_matches(']');
        for axiom in axioms.split(", ") {
            if !STANDARD_AXIOMS.contains(&axiom) {
                return Err(format!("{theorem} depends on {axiom}").into());
            }
        }
    }
    if theorems == 0 {
        return Err("TlsRecord/Axioms.lean printed no theorems".into());
    }
    println!("lean: every proof checks; {theorems} headline theorems rest on standard axioms only");
    Ok(())
}

fn vectors(paths: &Paths, seed: u64) -> Result {
    let dir = paths.out.join("vectors").join(seed.to_string());
    std::fs::create_dir_all(&dir)?;
    let (_, made) = logged(
        lake()
            .args(["exe", "gen"])
            .arg(&dir)
            .arg(seed.to_string())
            .current_dir(&paths.lean),
        &paths.out.join("gen.out"),
    )?;
    if !made {
        return Err(format!(
            "lake exe gen failed; see {}",
            paths.out.join("gen.out").display()
        )
        .into());
    }
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let (text, passed) = logged(
        Command::new(cargo)
            .args(["test", "-p", "fictionet-rustls", "--lib", "--"])
            .args(["--ignored", "--exact", "--nocapture"])
            .args([
                "budget::tests::record_vectors::record_vectors",
                "common_state::nonce_vectors::nonce_vectors",
            ])
            .env("TLS_RECORD_VECTORS", &dir)
            .current_dir(&paths.root),
        &paths.out.join("vectors.out"),
    )?;
    for line in text.lines().filter(|line| line.ends_with(" cases")) {
        println!("vectors: {line}");
    }
    if !passed || !text.contains("2 passed") {
        return Err(format!(
            "the replay failed; see {}",
            paths.out.join("vectors.out").display()
        )
        .into());
    }
    println!("vectors: seed {seed} passed");
    Ok(())
}
