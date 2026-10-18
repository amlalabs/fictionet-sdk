//! The rustfmt check that the golden and layout tests share.

use std::{path::PathBuf, process::Command};

pub fn check_rustfmt(files: &[PathBuf]) {
    for chunk in files.chunks(32) {
        let result = Command::new("rustfmt")
            .args(["--edition", "2024", "--check"])
            .args(chunk)
            .output()
            .expect("rustfmt is not on PATH");
        assert!(
            result.status.success(),
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
