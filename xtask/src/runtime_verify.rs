//! `cargo xtask runtime-verify`: the TLA+ models of the runtime in
//! `verification/runtime/tla`, checked with the TLC runner of
//! `mptcp-verify`.
//!
//! | Command | Does |
//! | --- | --- |
//! | `runtime-verify tlc [spec] [config]` | TLC with every property of each passing config together, and each ablation property separately with its expected violation |
//!
//! TLC's output goes under `runtime-verify/tlc/` in Cargo's target
//! directory (`CARGO_TARGET_DIR`, or `target/`). TLC runs as `$JAVA -Xmx6g
//! -cp $TLA2TOOLS tlc2.TLC`.

use crate::{Result, mptcp_verify};

/// Runs `runtime-verify` with the arguments after it.
pub fn run(args: &[String]) -> Result {
    let (root, target) = mptcp_verify::repository()?;
    let models = root.join("verification").join("runtime").join("tla");
    let out = target.join("runtime-verify");
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["tlc", filter @ ..] if filter.len() <= 2 => {
            let report = mptcp_verify::tlc(
                &models,
                &out,
                filter.first().copied(),
                filter.get(1).copied(),
            )?;
            report.print();
            report.result("runtime-verify")
        }
        _ => Err("expected runtime-verify tlc [spec] [config]".into()),
    }
}
