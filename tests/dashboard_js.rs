//! All of the dashboard's JavaScript test files (`dashboard/`), run
//! with node and Chromium. Missing tools skip with a note locally and fail
//! under CI (`CI` set). Set `CHROMIUM` if the browser is not named `chromium`.

use std::process::Command;

#[test]
fn dashboard_js() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let out = match Command::new("node")
        .args(["--test", "dashboard/"])
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

fn chromium_fails_in_ci(chromium: &str) {
    for ci in [None, Some(""), Some("1")] {
        let mut command = Command::new("node");
        command
            .args([
                "--test",
                "--test-reporter=tap",
                "dashboard/browser.test.mjs",
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .env("CHROMIUM", chromium)
            .env_remove("CI");
        if let Some(value) = ci {
            command.env("CI", value);
        }
        let output = match command.output() {
            Ok(output) => output,
            Err(e) => {
                requirements::skip(&format!("node is not installed ({e})"));
                return;
            }
        };
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.status.success(), ci.is_none(), "{text}");
        assert!(text.contains("Chromium is unavailable"), "{text}");
        assert_eq!(text.contains("# SKIP"), ci.is_none(), "{text}");
    }
}

#[test]
fn missing_chromium_fails_in_ci() {
    chromium_fails_in_ci("/fictionet-test-no-chromium");
}

#[test]
fn unlaunchable_chromium_fails_in_ci() {
    // Node accepts --version but rejects the browser launch flags.
    chromium_fails_in_ci("node");
}

#[cfg(unix)]
#[test]
fn broken_chromium_probe_fails_in_ci() {
    // A nonzero probe exit and an executable that cannot be run both skip locally.
    chromium_fails_in_ci("false");
    chromium_fails_in_ci(env!("CARGO_MANIFEST_DIR"));
}
