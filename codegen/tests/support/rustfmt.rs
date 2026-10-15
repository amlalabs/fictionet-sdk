use crate::requirements;
use std::{io::ErrorKind, path::PathBuf, process::Command};

pub fn check_rustfmt(files: &[PathBuf]) {
    for chunk in files.chunks(32) {
        let result = match Command::new("rustfmt")
            .args(["--edition", "2024", "--check"])
            .args(chunk)
            .output()
        {
            Ok(result) => result,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                requirements::skip("rustfmt is not on PATH");
                return;
            }
            Err(error) => panic!("cannot launch rustfmt: {error}"),
        };
        assert!(
            result.status.success(),
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
