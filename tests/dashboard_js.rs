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

/// Runs the browser test with `CHROMIUM` set and `CI` unset, empty or set.
/// Returns whether node passed and its output, or `None` when node is missing.
fn browser_test(chromium: &str, ci: Option<&str>) -> Option<(bool, String)> {
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
            return None;
        }
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Some((output.status.success(), text))
}

fn chromium_fails_in_ci(chromium: &str) {
    for ci in [None, Some(""), Some("1")] {
        let Some((success, text)) = browser_test(chromium, ci) else {
            return;
        };
        assert_eq!(success, ci.is_none(), "{text}");
        assert!(text.contains("Chromium is unavailable"), "{text}");
        assert_eq!(text.contains("# SKIP"), ci.is_none(), "{text}");
    }
}

/// Once the `--version` probe passes, Chromium is installed, so an early exit
/// fails the test even outside CI.
fn chromium_exit_fails(chromium: &str, exit: &str) {
    for ci in [None, Some(""), Some("1")] {
        let Some((success, text)) = browser_test(chromium, ci) else {
            return;
        };
        assert!(!success, "{text}");
        assert!(
            text.contains(&format!(
                "Chromium exited before reporting a result ({exit})"
            )),
            "{text}"
        );
        assert!(!text.contains("Chromium is unavailable"), "{text}");
        assert!(!text.contains("# SKIP"), "{text}");
    }
}

#[test]
fn missing_chromium_fails_in_ci() {
    chromium_fails_in_ci("/fictionet-test-no-chromium");
}

#[test]
fn unlaunchable_chromium_fails() {
    // Node accepts --version but rejects the browser launch flags with exit code 9.
    chromium_exit_fails("node", "code 9, signal null");
}

#[cfg(unix)]
#[test]
fn crashing_chromium_fails() {
    use std::os::unix::fs::PermissionsExt;

    // A browser that answers the probe and then dies of a signal, like a Chromium crash.
    let dir = std::env::temp_dir().join(format!("fn-dashboard-js-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let chromium = dir.join("chromium");
    std::fs::write(
        &chromium,
        "#!/bin/sh\n[ \"$1\" = --version ] && exec echo 'Chromium 1.0'\nkill -KILL $$\n",
    )
    .unwrap();
    std::fs::set_permissions(&chromium, std::fs::Permissions::from_mode(0o755)).unwrap();
    chromium_exit_fails(chromium.to_str().unwrap(), "code null, signal SIGKILL");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn broken_chromium_probe_fails_in_ci() {
    // A nonzero probe exit and an executable that cannot be run both skip locally.
    chromium_fails_in_ci("false");
    chromium_fails_in_ci(env!("CARGO_MANIFEST_DIR"));
}
