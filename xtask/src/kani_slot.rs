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

use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use crate::Result;

/// A taken slot, held until dropped.
pub struct Slot {
    _file: File,
}

/// Waits for a slot for a run capped at `memory` (systemd's form, such as
/// `14G`), and holds it.
pub fn take(memory: &str) -> Result<Slot> {
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
                return Ok(Slot { _file: file });
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
