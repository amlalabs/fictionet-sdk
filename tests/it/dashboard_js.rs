//! All of the dashboard's JavaScript test files (`dashboard/`), run
//! with node and Chromium. Set `CHROMIUM` if the browser is not named
//! `chromium`.

use std::process::Command;

#[test]
fn dashboard_js() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let out = Command::new("node")
        .args(["--test", "dashboard/"])
        .current_dir(dir)
        .output()
        .expect("node is not installed");
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
