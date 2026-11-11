//! Waits for room in the work slice before a `cargo kani` starts.
//!
//! Every Kani run goes into `fictionet-work.slice`. When the runs in the
//! slice together pass its `MemoryHigh`, the kernel reclaims from all of
//! them at once: on November 11, 2026, with four Kani runs and the other
//! work there, the slice sat at its `MemoryHigh` of 44 GiB, and each CBMC
//! process ran a sixth of a core, five sixths of that in the kernel's
//! reclaim, so it did its own work at about 3% of a core. So a run takes
//! one of `MemoryHigh / memory` slots first, the slots shared by every
//! worktree of the user, and waits while all are taken.
//!
//! A run also holds its Cargo target directory alone. Kani rewrites each
//! harness's goto binary in place under `target/kani/`, so two runs in one
//! target directory overwrite each other's files mid-run and the second
//! fails in `goto-instrument` (exit 6). Runs in different worktrees, with
//! different target directories, still run side by side.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::Result;

/// A taken slot and the run's target directory, both held until dropped.
pub struct Slot {
    _target: File,
    _slot: File,
}

/// Waits for the target directory of a run from `root`, then for a slot
/// for a run capped at `memory` (systemd's form, such as `14G`), and holds
/// both. The directory comes first so that a run waiting on another run in
/// the same directory does not keep a slot from runs elsewhere.
pub fn take(root: &Path, memory: &str) -> Result<Slot> {
    let target = target_lock(root)?;
    let slot = slot(memory)?;
    Ok(Slot {
        _target: target,
        _slot: slot,
    })
}

/// Locks `kani.lock` in the target directory Cargo will use from `root`:
/// `CARGO_TARGET_DIR`, else `root/target`.
fn target_lock(root: &Path) -> Result<File> {
    let dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .map(|dir| {
            if dir.is_absolute() {
                dir
            } else {
                root.join(dir)
            }
        })
        .unwrap_or_else(|| root.join("target"));
    std::fs::create_dir_all(&dir)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("kani.lock"))?;
    if file.try_lock().is_err() {
        println!(
            "waiting for another Kani run in {} to finish",
            dir.display()
        );
        file.lock()?;
    }
    Ok(file)
}

/// Waits for one of the slice's slots for a run capped at `memory`.
fn slot(memory: &str) -> Result<File> {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("fictionet-kani");
    std::fs::create_dir_all(&dir)?;
    let slots = (slice_memory()? / bytes(memory)?).max(1);
    let mut said = false;
    loop {
        for n in 0..slots {
            let file = OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(dir.join(format!("slot-{n}")))?;
            if file.try_lock().is_ok() {
                return Ok(file);
            }
        }
        if !said {
            println!("waiting for one of {slots} Kani slots in fictionet-work.slice");
            said = true;
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

/// The slice's `MemoryHigh`, else its `MemoryMax`, else the machine's.
fn slice_memory() -> Result<u64> {
    for property in ["MemoryHigh", "MemoryMax"] {
        let out = Command::new("systemctl")
            .args([
                "--user",
                "show",
                "fictionet-work.slice",
                "-p",
                property,
                "--value",
            ])
            .output()?;
        if let Ok(value) = String::from_utf8_lossy(&out.stdout).trim().parse::<u64>() {
            return Ok(value);
        }
    }
    let meminfo = std::fs::read_to_string("/proc/meminfo")?;
    let kib = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|rest| {
            rest.trim()
                .trim_end_matches("kB")
                .trim()
                .parse::<u64>()
                .ok()
        })
        .ok_or("no MemTotal in /proc/meminfo")?;
    Ok(kib * 1024)
}

/// `14G` and the like as bytes.
fn bytes(memory: &str) -> Result<u64> {
    let (digits, unit) = memory.split_at(memory.len() - 1);
    let shift = match unit {
        "K" => 10,
        "M" => 20,
        "G" => 30,
        "T" => 40,
        _ => return Err(format!("memory {memory}: expected a K, M, G or T suffix").into()),
    };
    Ok(digits.parse::<u64>()? << shift)
}
