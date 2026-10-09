//! The dashboard's own JavaScript tests (`dashboard/groups.test.js`), run
//! with node. Skipped, with a note, where node is not installed, except
//! under CI (`CI` set), where a missing node fails the test.

use std::process::Command;

#[test]
fn dashboard_js() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let out = match Command::new("node")
        .args(["--test", "dashboard/groups.test.js"])
        .current_dir(dir)
        .output()
    {
        Ok(out) => out,
        Err(e) => {
            requirements::skip(&format!("node is not installed ({e})"));
            return;
        }
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{text}");
    assert!(
        text.contains("# fail 0") || text.contains("fail 0"),
        "{text}"
    );
}

#[path = "common/requirements.rs"]
mod requirements;

#[test]
fn missing_node_fails_in_ci() {
    requirements::fails_in_ci("dashboard_js", "node is not installed");
}
