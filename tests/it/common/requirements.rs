use std::process::Command;

/// Skips a test locally and fails with the reason when CI is set.
pub fn skip(reason: &str) {
    assert!(std::env::var_os("CI").is_none(), "{reason}");
    eprintln!("skipped: {reason}");
}

/// A missing executable may skip locally, but must fail even with an empty CI value.
pub fn fails_in_ci(test: &str, reason: &str) {
    for ci in [None, Some(""), Some("1")] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", test, "--nocapture"]);
        command
            .env("PATH", "/fictionet-test-no-programs")
            .env_remove("CI");
        if let Some(value) = ci {
            command.env("CI", value);
        }
        let output = command.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("running 1 test"), "{output:?}");
        assert_eq!(output.status.success(), ci.is_none(), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        if ci.is_some() {
            assert!(stderr.contains(reason), "{output:?}");
        } else {
            assert!(stderr.contains(&format!("skipped: {reason}")), "{output:?}");
        }
    }
}
