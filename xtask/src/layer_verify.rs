//! `cargo xtask layer-verify`: the layer foundation's routing code checked
//! against its TLA+ model, `verification/layer/tla/Route.tla`, and the
//! resource properties of the runtime and layer machinery, SSH and
//! WebSocket (verification/README.md, "Resource properties").
//!
//! | Command | Does |
//! | --- | --- |
//! | `layer-verify trace` | runs `route_trace` in the library's tests, which logs every step the real `Chain`, `Switch` and `Driver` take under abstract layers for each seed, then replays each log against the model with `RouteTrace.tla` |
//! | `layer-verify resources` | the Kani harnesses in [`KANI_RESOURCES`] with every allocation counted, TLC on the configs in [`TLC_RESOURCES`], and the costed replays: the SSH coverage traces and the tests in [`COSTED_TESTS`] |
//!
//! Everything is written under a fresh run directory in `layer-verify/`
//! in Cargo's target directory
//! (`CARGO_TARGET_DIR`, or `target/`): the logs and the specs in `traces/`,
//! TLC's output in `tlc/`, and its state files in `states/`.
//!
//! TLC runs as `$JAVA -Xmx2g -cp $TLA2TOOLS tlc2.TLC -workers 2` (4 GiB for
//! the resource configs). `TLA2TOOLS` names `tla2tools.jar`, and `JAVA` a
//! Java 11 or later (`java` when unset).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::Result;
use crate::lean_vectors::{Report, scoped};
use crate::resources;

/// The counted Kani harnesses: the counter itself, the charged containers
/// growing through a reallocation, the report store, a WebSocket message
/// assembled in fragments, and an SSH packet decoded before keys.
const KANI_RESOURCES: [&str; 11] = [
    "counting::proofs::the_counter_sees_every_allocation",
    "stdlib::layer::resource_proofs::a_full_charged_deque_grows_within_a_tight_budget",
    "stdlib::layer::resource_proofs::a_full_charged_vec_grows_within_a_tight_budget",
    "stdlib::layer::resource_proofs::charged_bytes_grow_within_their_budget_100",
    "stdlib::layer::resource_proofs::charged_bytes_grow_within_their_budget_160",
    "stdlib::layer::resource_proofs::kept_reports_are_charged_to_the_store",
    "stdlib::layer::resource_proofs::reports_past_the_store_are_omitted_with_nothing_kept",
    "stdlib::protocols::websocket::resource_proofs::a_message_of_two_fragments_stays_within_its_limit",
    "stdlib::protocols::websocket::resource_proofs::a_message_of_three_fragments_stays_within_its_limit",
    "stdlib::protocols::ssh::transport::resource_proofs::decoding_a_short_plain_packet_copies_only_the_packet",
    "stdlib::protocols::ssh::transport::resource_proofs::decoding_a_longer_plain_packet_copies_only_the_packet",
];

/// The resource models, each with its directory, module and configs: the
/// code, and a control for each property that the code before its fix, or
/// with a check removed, must violate.
const TLC_RESOURCES: [(&str, &str, &[&str]); 4] = [
    (
        "verification/layer/tla",
        "Growth",
        &[
            "Growth_base.cfg",
            "Growth_without_chargemove.cfg",
            "Growth_places_without_chargemove.cfg",
        ],
    ),
    (
        "verification/world-net/tla",
        "Memory",
        &[
            "Memory_base.cfg",
            "Memory_without_countfirst.cfg",
            "Memory_without_recordcost.cfg",
            "Memory_agentonpair.cfg",
            "Memory_without_chargereportfirst.cfg",
        ],
    ),
    (
        "verification/websocket/tla",
        "Assembly",
        &[
            "Assembly_base.cfg",
            "Assembly_without_clamp.cfg",
            "Assembly_without_checkfirst.cfg",
            "Assembly_without_heldiscapacity.cfg",
        ],
    ),
    (
        "verification/ssh-layer/tla",
        "TransportMemory",
        &[
            "TransportMemory_base.cfg",
            "TransportMemory_without_chargecopyfirst.cfg",
            "TransportMemory_without_chargescratch.cfg",
        ],
    ),
];

/// The costed tests of `tests/it`: queued packets against what their
/// queues count, and WebSocket messages in fragments, each step costed.
const COSTED_TESTS: [&str; 2] = ["world_memory::", "websocket_costs::"];

/// Runs `layer-verify` with the arguments after it.
pub fn run(args: &[String]) -> Result {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["trace"] => trace(),
        ["resources"] => resources(),
        _ => Err("expected layer-verify trace or resources".into()),
    }
}

/// The counted Kani harnesses, the resource configs, and the costed
/// replays.
fn resources() -> Result {
    let paths = Paths::new()?;
    let mut report = Report::new("resources");
    // Each harness in a `cargo kani` of its own, its log in a directory
    // of its own: run together, one after another, the deque's ran out of
    // 14 GiB, though alone it fits.
    for harness in KANI_RESOURCES {
        let name = harness.rsplit("::").next().unwrap_or(harness);
        report.absorb(resources::kani(
            &paths.root,
            &paths.out.join("kani").join(name),
            "fictionet",
            &[harness],
            "14G",
        )?);
    }
    for (dir, module, configs) in TLC_RESOURCES {
        report.absorb(resources::tlc(
            &paths.root,
            &paths.out,
            &paths.root.join(dir),
            module,
            configs,
        )?);
    }
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let replays: [(&str, Vec<&str>); 2] = [
        (
            "ssh-replay",
            vec![
                "--lib",
                "--",
                "--nocapture",
                "--exact",
                "stdlib::protocols::ssh::transport::replay::transport_traces_replay_on_the_production_transport",
            ],
        ),
        (
            "costed-tests",
            [
                vec!["--test", "it", "--", "--nocapture"],
                COSTED_TESTS.to_vec(),
            ]
            .concat(),
        ),
    ];
    for (name, args) in replays {
        let (text, ok) = crate::lean_vectors::logged(
            scoped(&cargo, "14G")
                .args(["test", "-p", "fictionet", "--features", "tokio"])
                .args(&args)
                .current_dir(&paths.root),
            &paths.out.join(format!("{name}.out")),
        )?;
        let costs: Vec<&str> = text.lines().filter(|l| l.starts_with("cost:")).collect();
        if ok && !costs.is_empty() {
            for line in costs {
                report.pass(format!("{name}: {line}"));
            }
            if name == "costed-tests" {
                report.pass(format!(
                    "{name}: {}",
                    text.lines()
                        .find(|l| l.starts_with("test result:"))
                        .unwrap_or("no result line")
                ));
            }
        } else {
            report.fail(format!("{name}: failed; see {name}.out"));
        }
    }
    report.print();
    report.result("layer-verify")
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
            out: crate::verification_run(&target.join("layer-verify"))?,
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
    let temp = paths.out.join("temp");
    std::fs::create_dir_all(&temp)?;
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
        let (text, success) = logged(
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
        if success && text.contains("Model checking completed. No error has been found.") {
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
