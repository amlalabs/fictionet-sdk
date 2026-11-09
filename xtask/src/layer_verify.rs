//! `cargo xtask layer-verify`: the layer foundation's routing code checked
//! against its TLA+ model, `verification/layer/tla/Route.tla`.
//!
//! | Command | Does |
//! | --- | --- |
//! | `layer-verify trace` | runs `route_trace` in the library's tests, which logs every step the real `Chain`, `Switch` and `Driver` take under abstract layers for each seed, then replays each log against the model with `RouteTrace.tla` |
//!
//! Everything is written under `layer-verify/` in Cargo's target directory
//! (`CARGO_TARGET_DIR`, or `target/`): the logs and the specs in `traces/`,
//! TLC's output in `tlc/`, and its state files in `states/`.
//!
//! TLC runs as `$JAVA -Xmx2g -cp $TLA2TOOLS tlc2.TLC -workers 2`. `TLA2TOOLS`
//! names `tla2tools.jar`, and `JAVA` a Java 11 or later (`java` when unset).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::Result;

/// Runs `layer-verify` with the arguments after it.
pub fn run(args: &[String]) -> Result {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["trace"] => trace(),
        _ => Err("expected layer-verify trace".into()),
    }
}

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
            tla: root.join("verification").join("layer").join("tla"),
            out: target.join("layer-verify"),
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

/// The logs of every seed, then each replayed by TLC.
fn trace() -> Result {
    let paths = Paths::new()?;
    let traces = paths.out.join("traces");
    if traces.exists() {
        std::fs::remove_dir_all(&traces)?;
    }
    std::fs::create_dir_all(&traces)?;
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let (text, ok) = logged(
        Command::new(cargo)
            .args(["test", "-p", "fictionet", "--lib", "route_trace"])
            .env("FICTIONET_ROUTE_TRACE_DIR", &traces)
            .current_dir(&paths.root),
        &paths.out.join("route_trace.out"),
    )?;
    if !ok {
        return Err(format!("the route_trace test failed:\n{text}").into());
    }
    for spec in ["Route.tla", "RouteTrace.tla"] {
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
                    .is_some_and(|s| s.to_string_lossy().starts_with("RouteLog_"))
        })
        .collect();
    logs.sort();
    if logs.is_empty() {
        return Err("the route_trace test wrote no logs".into());
    }
    let mut failures = 0;
    for config in &logs {
        let name = config
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or("a log name is UTF-8")?;
        let entries = std::fs::read_to_string(traces.join(format!("{name}.tla")))?
            .lines()
            .filter(|line| line.trim_start().starts_with("[a |->"))
            .count();
        let started = Instant::now();
        let (text, _) = logged(
            Command::new(&java)
                .args(["-Xmx2g", "-cp"])
                .arg(&jar)
                .args(["tlc2.TLC", "-workers", "2", "-metadir"])
                .arg(paths.out.join("states").join(name))
                .args(["-config", &format!("{name}.cfg"), &format!("{name}.tla")])
                .current_dir(&traces),
            &paths.out.join("tlc").join(format!("{name}.out")),
        )?;
        let seconds = started.elapsed().as_secs();
        if text.contains("Model checking completed. No error has been found.") {
            println!("{name}: {entries} entries replayed, {seconds} s");
        } else {
            failures += 1;
            let error = text
                .lines()
                .find(|line| line.starts_with("Error:"))
                .unwrap_or("TLC did not finish");
            println!("FAILED: {name}: {error}");
        }
    }
    if failures == 0 {
        println!("trace: passed, {} logs", logs.len());
        Ok(())
    } else {
        Err(format!(
            "layer-verify trace: {failures} of {} logs failed",
            logs.len()
        )
        .into())
    }
}
