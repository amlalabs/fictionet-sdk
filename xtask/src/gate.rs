//! The light checks share Cargo's cache and preserve each command's failure.

use std::path::Path;
use std::process::Command;
use std::time::Instant;

use crate::Result;

pub fn run(args: &[String]) -> Result {
    let dry_run = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => false,
        ["--dry-run"] => true,
        _ => return Err("expected gate [--dry-run]".into()),
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask lives in the repository")?;
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| root.join("target"));
    let target = if target.is_absolute() {
        target
    } else {
        root.join(target)
    };
    let jobs = std::env::var_os("CARGO_BUILD_JOBS").unwrap_or_else(|| "8".into());
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    // Cargo serializes builds in this directory. Formatting and test execution
    // can overlap other work without multiplying compiler processes or caches.
    let lanes: &[&[&[&str]]] = &[
        &[&["fmt", "--all", "--", "--check"]],
        &[
            &[
                "clippy",
                "--locked",
                "--workspace",
                "--all-targets",
                "--features",
                "xtask/host-tools",
                "--",
                "-D",
                "warnings",
            ],
            &[
                "nextest",
                "run",
                "--locked",
                "--workspace",
                "--features",
                "xtask/host-tools",
            ],
            &[
                "test",
                "--locked",
                "--workspace",
                "--features",
                "xtask/host-tools",
                "--doc",
            ],
        ],
        &[&[
            "build",
            "--locked",
            "-p",
            "fictionet",
            "--lib",
            "--no-default-features",
            "--target",
            "wasm32-unknown-unknown",
        ]],
    ];
    println!("Cargo target: {}", target.display());
    if dry_run {
        for (lane, commands) in lanes.iter().enumerate() {
            for args in *commands {
                println!("lane {}: cargo {}", lane + 1, args.join(" "));
            }
        }
        return Ok(());
    }
    // Keep another gate from replacing test binaries between build and execution.
    // This lock is separate from Cargo's build lock, which children must acquire.
    std::fs::create_dir_all(&target)?;
    let gate_lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(target.join("fictionet-gate.lock"))?;
    gate_lock.lock()?;
    std::thread::scope(|scope| {
        let handles: Vec<_> = lanes
            .iter()
            .map(|commands| {
                let cargo = &cargo;
                let target = &target;
                let jobs = &jobs;
                scope.spawn(move || {
                    let mut failures = Vec::new();
                    for args in *commands {
                        let started = Instant::now();
                        let status = Command::new(cargo)
                            .args(*args)
                            .current_dir(root)
                            .env("CARGO_TARGET_DIR", target)
                            .env("CARGO_BUILD_JOBS", jobs)
                            .status();
                        println!(
                            "cargo {}: {:.1}s",
                            args.join(" "),
                            started.elapsed().as_secs_f64()
                        );
                        match status {
                            Ok(status) if status.success() => {}
                            Ok(status) => {
                                failures.push(format!("cargo {}: {status}", args.join(" ")))
                            }
                            Err(error) => {
                                failures.push(format!("cargo {}: {error}", args.join(" ")))
                            }
                        }
                    }
                    failures
                })
            })
            .collect();
        let mut failures = Vec::new();
        for handle in handles {
            match handle.join() {
                Ok(errors) => failures.extend(errors),
                Err(_) => failures.push("a gate worker panicked".into()),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("\n").into())
        }
    })
}

/// Batch explicitly selected passing harnesses in one compiler invocation.
pub fn kani(args: &[String]) -> Result {
    let [package, target, harnesses @ ..] = args else {
        return Err("expected kani PACKAGE lib|tests HARNESS...".into());
    };
    if !matches!(target.as_str(), "lib" | "tests") || harnesses.is_empty() {
        return Err("expected kani PACKAGE lib|tests HARNESS...".into());
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask lives in the repository")?;
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new("systemd-run");
    command.args([
        "--user",
        "--scope",
        "-q",
        "--slice=fictionet-work.slice",
        "-p",
        "MemoryMax=12G",
        "-p",
        "MemorySwapMax=0",
    ]);
    command.arg(cargo).args([
        "kani", "-p", package, "-Z", "stubbing", "-j", "1", "--exact",
    ]);
    command.arg(format!("--{target}"));
    for harness in harnesses {
        command.arg("--harness").arg(harness);
    }
    let status = command
        .current_dir(root)
        .env("CARGO_BUILD_JOBS", "8")
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("grouped Kani run failed: {status}").into())
    }
}
