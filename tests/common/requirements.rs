use std::process::Command;

/// A missing executable may skip locally, but must fail even with an empty CI value.
pub fn fails_in_ci(test: &str) {
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
    }
}
