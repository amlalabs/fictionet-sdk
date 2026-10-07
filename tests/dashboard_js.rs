//! The dashboard's own JavaScript tests (`dashboard/groups.test.js`), run
//! with node. Skipped, with a note, where node is not installed, except
//! under CI (`CI` set), where a missing node fails the test.

use std::process::Command;

#[test]
fn dashboard_js() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let out = match Command::new("node").args(["--test", "dashboard/groups.test.js"]).current_dir(dir).output() {
        Ok(out) => out,
        Err(e) => {
            assert!(std::env::var_os("CI").is_none(), "node is required under CI: {e}");
            eprintln!("skipped: node is not installed ({e})");
            return;
        }
    };
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "{text}");
    assert!(text.contains("# fail 0") || text.contains("fail 0"), "{text}");
}
