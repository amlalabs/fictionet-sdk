//! `cargo xtask tls-verify handshake-trace`: real handshakes of the
//! vendored rustls server checked against the RFC spec,
//! `verification/tls-rfc/tla/Handshake.tla`.
//!
//! Runs `hs_trace` in rustls's own tests, which logs each handshake as the
//! server saw it (every message, and the epoch its record decrypted
//! under), then checks each log with `HandshakeTrace.tla`. A `HsLog_*` log
//! passes when TLC reports `LogUnfinished` violated: a state with every
//! entry consumed is reachable, so the log is a behavior of the spec. A
//! `HsDeparture_*` log records a known departure of rustls from the RFC and
//! passes when TLC finds no such state; if it ever becomes a behavior, the
//! departure was fixed and the run says so.
//!
//! Everything is written under a fresh run directory in
//! `tls-verify-handshake/` in Cargo's target directory (`CARGO_TARGET_DIR`,
//! or `target/`): the logs and the specs in `traces/`, TLC's output in
//! `tlc/`, and its state files in `states/`.
//!
//! TLC runs as `$JAVA -Xmx2g -cp $TLA2TOOLS tlc2.TLC -workers 2`. `TLA2TOOLS`
//! names `tla2tools.jar`, and `JAVA` a Java 11 or later (`java` when unset).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::Result;

/// Where the sources are and where the results go.
struct Paths {
    root: PathBuf,
    tla: PathBuf,
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
            tla: root.join("verification").join("tls-rfc").join("tla"),
            out: crate::verification_run(&target.join("tls-verify-handshake"))?,
            root,
        })
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

/// The logs of every handshake, then each checked by TLC.
pub fn trace() -> Result {
    let paths = Paths::new()?;
    let traces = paths.out.join("traces");
    let temp = paths.out.join("temp");
    std::fs::create_dir_all(&temp)?;
    std::fs::create_dir_all(&traces)?;
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let (text, ok) = logged(
        Command::new(cargo)
            .args(["test", "-p", "fictionet-rustls", "--lib", "hs_trace"])
            .env("FICTIONET_TLS_TRACE_DIR", &traces)
            .current_dir(&paths.root),
        &paths.out.join("hs_trace.out"),
    )?;
    if !ok {
        return Err(format!("the hs_trace test failed:\n{text}").into());
    }
    for spec in ["Handshake.tla", "HandshakeTrace.tla"] {
        std::fs::copy(paths.tla.join(spec), traces.join(spec))?;
    }
    let jar = std::env::var_os("TLA2TOOLS").ok_or("TLA2TOOLS must name tla2tools.jar")?;
    let java = std::env::var_os("JAVA").unwrap_or_else(|| "java".into());
    let mut logs: Vec<(String, bool)> = std::fs::read_dir(&traces)?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().is_some_and(|e| e == "cfg"))
        .filter_map(|path| path.file_stem().and_then(|s| s.to_str()).map(str::to_owned))
        .filter_map(|name| {
            let departure = name.starts_with("HsDeparture_");
            (departure || name.starts_with("HsLog_")).then_some((name, departure))
        })
        .collect();
    logs.sort();
    if logs.iter().all(|(_, departure)| *departure) {
        return Err("the hs_trace test wrote no logs".into());
    }
    let mut failures = 0;
    for (name, departure) in &logs {
        let entries = std::fs::read_to_string(traces.join(format!("{name}.tla")))?
            .lines()
            .filter(|line| line.trim_start().starts_with("[d |->"))
            .count();
        let started = Instant::now();
        let (text, _) = logged(
            Command::new(&java)
                .arg("-Xmx2g")
                .arg(format!("-Djava.io.tmpdir={}", temp.display()))
                .arg("-cp")
                .arg(&jar)
                .args(["tlc2.TLC", "-workers", "2", "-metadir"])
                .arg(paths.out.join("states").join(name))
                .args(["-config", &format!("{name}.cfg"), &format!("{name}.tla")])
                .current_dir(&traces),
            &paths.out.join("tlc").join(format!("{name}.out")),
        )?;
        let seconds = started.elapsed().as_secs();
        let accepted = text.contains("Invariant LogUnfinished is violated");
        let rejected = text.contains("Model checking completed. No error has been found.");
        match (departure, accepted, rejected) {
            (false, true, _) => {
                println!("{name}: {entries} entries, a behavior of the spec, {seconds} s")
            }
            (true, _, true) => println!(
                "{name}: {entries} entries, not a behavior of the spec (known departure), {seconds} s"
            ),
            (false, _, true) => {
                failures += 1;
                println!("FAILED: {name}: the spec cannot follow this log");
            }
            (true, true, _) => {
                failures += 1;
                println!("FAILED: {name}: the departure is gone; move it to the HsLog runs");
            }
            _ => {
                failures += 1;
                let error = text
                    .lines()
                    .find(|line| line.starts_with("Error:"))
                    .unwrap_or("TLC did not finish");
                println!("FAILED: {name}: {error}");
            }
        }
    }
    if failures == 0 {
        println!("handshake-trace: passed, {} logs", logs.len());
        Ok(())
    } else {
        Err(format!(
            "tls-verify handshake-trace: {failures} of {} logs failed",
            logs.len()
        )
        .into())
    }
}
