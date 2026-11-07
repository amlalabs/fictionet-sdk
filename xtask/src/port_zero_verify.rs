//! `cargo xtask port-zero-verify`: TLC over the models of literal TCP port 0
//! in `verification/tcp-port-zero/`, which its README describes. It uses the
//! runner of `mptcp-verify tlc`: each config's properties are checked
//! together, and the negative control, the config with an
//! `\* expect violation:` line, must fail on exactly that property.
//! Everything is written under `port-zero-verify/` in Cargo's target
//! directory, and `JAVA` and `TLA2TOOLS` name the JDK and `tla2tools.jar`
//! as for `mptcp-verify`.

use crate::{Result, mptcp_verify};

/// Runs `port-zero-verify`, which takes no arguments.
pub fn run(args: &[String]) -> Result {
    if !args.is_empty() {
        return Err("port-zero-verify takes no arguments".into());
    }
    let (root, target) = mptcp_verify::repository()?;
    let models = root.join("verification").join("tcp-port-zero");
    let report = mptcp_verify::tlc(&models, &target.join("port-zero-verify"), None, None)?;
    report.print();
    report.result("port-zero-verify")
}
