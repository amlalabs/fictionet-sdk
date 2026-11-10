//! The record layer's trace check, for `cargo xtask tls-verify record-trace`:
//! runs `record_trace` in the vendored rustls's own tests, which logs a
//! real server (paid from a budget that refuses on demand) and client
//! through seeded schedules, then checks each log against the RFC model
//! `verification/tls-rfc/tla/Record.tla` with `RecordTrace.tla`.
//!
//! A log passes when TLC finds a behavior of the model that consumes all
//! of it: the invariant `TraceIncomplete` is then violated, and no other
//! invariant is. Everything is written under a fresh run directory in
//! `tls-verify-record/` in Cargo's target directory: the logs and specs in
//! `traces/`, TLC's output in `tlc/`, its state files in `states/`.
//!
//! TLC runs as `$JAVA -Xmx2g -cp $TLA2TOOLS tlc2.TLC -workers 2`.

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
            out: crate::verification_run(&target.join("tls-verify-record"))?,
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

/// Whether TLC's output says the whole log was explained: the one
/// violation is TraceIncomplete's.
fn explained(text: &str) -> bool {
    let violations: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("Error: Invariant ") && line.ends_with(" is violated."))
        .collect();
    violations == ["Error: Invariant TraceIncomplete is violated."]
}

/// The logs of every seed, then each checked by TLC.
pub fn record() -> Result {
    let paths = Paths::new()?;
    let traces = paths.out.join("traces");
    let temp = paths.out.join("temp");
    std::fs::create_dir_all(&temp)?;
    std::fs::create_dir_all(&traces)?;
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let (text, ok) = logged(
        Command::new(cargo)
            .args(["test", "-p", "fictionet-rustls", "--lib", "record_trace"])
            .env("FICTIONET_RECORD_TRACE_DIR", &traces)
            .current_dir(&paths.root),
        &paths.out.join("record_trace.out"),
    )?;
    if !ok {
        return Err(format!("the record_trace test failed:\n{text}").into());
    }
    for spec in ["Record.tla", "RecordTrace.tla"] {
        std::fs::copy(paths.tla.join(spec), traces.join(spec))?;
    }
    let jar = std::env::var_os("TLA2TOOLS").ok_or("TLA2TOOLS must name tla2tools.jar")?;
    let java = std::env::var_os("JAVA").unwrap_or_else(|| "java".into());
    let mut logs: Vec<PathBuf> = std::fs::read_dir(&traces)?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| {
            path.extension().is_some_and(|e| e == "cfg")
                && path
                    .file_stem()
                    .is_some_and(|s| s.to_string_lossy().starts_with("RecLog_"))
        })
        .collect();
    logs.sort();
    if logs.is_empty() {
        return Err("the record_trace test wrote no logs".into());
    }
    let mut failures = 0;
    let mut total = 0;
    for config in &logs {
        let name = config
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or("a log name is UTF-8")?;
        let entries = std::fs::read_to_string(traces.join(format!("{name}.tla")))?
            .lines()
            .filter(|line| line.trim_start().starts_with("[a |->"))
            .count();
        total += entries;
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
        if explained(&text) {
            println!("{name}: {entries} entries explained, {seconds} s");
        } else {
            failures += 1;
            let error = text
                .lines()
                .find(|line| line.starts_with("Error:"))
                .unwrap_or("no behavior of Record consumes the whole log");
            println!("FAILED: {name}: {error}");
        }
    }
    if failures == 0 {
        println!("record: passed, {} logs, {total} entries", logs.len());
        Ok(())
    } else {
        Err(format!(
            "tls-verify record: {failures} of {} logs failed",
            logs.len()
        )
        .into())
    }
}
