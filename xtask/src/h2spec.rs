use crate::process::{ChildGuard, Result, capture, cmd, poll};
use crate::vm::download;
use regex::Regex;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

const VERSION: &str = "v2.6.0";
const ARCHIVE: &str = "h2spec_linux_amd64.tar.gz";
const SHA256: &str = "157ee0de702e01ad40e752dbf074b366027e550c8e7504f9450da2809e279318";

pub fn run(args: &[String]) -> Result {
    let section = match args {
        [] => None,
        [section] if !section.starts_with('-') => Some(section.as_str()),
        _ => return Err("usage: cargo xtask h2spec [section]".into()),
    };
    let h2spec = fetch()?;
    let mut world = ChildGuard(
        cmd(
            "cargo",
            &[
                "run",
                "--locked",
                "-p",
                "fictionet",
                "--features",
                "tokio",
                "--example",
                "h2spec_world",
            ],
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?,
    );
    let mut lines = BufReader::new(world.0.stdout.take().ok_or("missing world stdout")?).lines();
    let mut port = |name: &str| -> Result<String> {
        let line = lines
            .next()
            .ok_or("the world exited before it was ready")??;
        match line
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix(' '))
        {
            Some(port) if port.parse::<u16>().is_ok() => Ok(port.to_owned()),
            _ => Err(format!("unexpected line from the world: {line}").into()),
        }
    };
    let tls = port("tls")?;
    let h2c = port("h2c")?;
    let mut summaries = Vec::new();
    for (name, port, flags) in [
        ("TLS", &tls, &["--tls", "--insecure"][..]),
        ("h2c", &h2c, &[]),
    ] {
        println!("h2spec {VERSION} over {name}");
        // Strict mode runs every case, including those for SHOULDs.
        let mut command = Command::new(&h2spec);
        command
            .args(flags)
            .args(["--strict", "--host", "127.0.0.1", "--port", port])
            .args(section);
        summaries.push((name, check(&mut command)?));
    }
    // Closing its standard input stops the world.
    drop(world.0.stdin.take());
    let stopped = poll(Duration::from_secs(10), Duration::from_millis(100), || {
        Ok(world.0.try_wait()?.is_some())
    })?;
    let mut passed = true;
    for (name, (ok, summary)) in summaries {
        println!("{name}: {summary}");
        passed &= ok;
    }
    if !stopped {
        return Err("the world did not stop within 10 s".into());
    }
    let status = world.0.wait()?;
    if !status.success() {
        return Err(format!("the world exited with {status}").into());
    }
    if !passed {
        return Err("h2spec found failures".into());
    }
    Ok(())
}

/// Downloads h2spec into the target directory once and returns the
/// binary's path. It has a directory of its own, where nothing else runs.
fn fetch() -> Result<PathBuf> {
    if !(cfg!(target_os = "linux") && cfg!(target_arch = "x86_64")) {
        return Err(format!(
            "h2spec {VERSION} is published for Linux on x86_64 only, not {} on {}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
        .into());
    }
    let metadata: serde_json::Value = serde_json::from_str(&capture(&mut cmd(
        "cargo",
        &["metadata", "--locked", "--no-deps", "--format-version", "1"],
    ))?)?;
    let dir = PathBuf::from(
        metadata["target_directory"]
            .as_str()
            .ok_or("cargo metadata gave no target directory")?,
    )
    .join(format!("h2spec-{VERSION}"));
    let archive = dir.join(ARCHIVE);
    download(
        &format!("https://github.com/summerwind/h2spec/releases/download/{VERSION}/{ARCHIVE}"),
        &archive,
        "sha256sum",
        SHA256,
    )?;
    let binary = dir.join("h2spec");
    if !binary.is_file() {
        let output = cmd("tar", &["-xzOf"])
            .arg(&archive)
            .arg("h2spec")
            .output()?;
        if !output.status.success() {
            return Err(format!("extracting h2spec: {}", crate::process::combined(&output)).into());
        }
        let part = binary.with_extension("part");
        fs::write(&part, output.stdout)?;
        fs::set_permissions(&part, fs::Permissions::from_mode(0o755))?;
        fs::rename(part, &binary)?;
    }
    Ok(binary)
}

/// Runs h2spec, showing its output as it comes. Returns whether every case
/// ran and passed, and h2spec's summary line.
fn check(command: &mut Command) -> Result<(bool, String)> {
    let mut child = ChildGuard(command.stdout(Stdio::piped()).spawn()?);
    let mut stdout = child.0.stdout.take().ok_or("missing h2spec stdout")?;
    let mut output = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        let n = stdout.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        // h2spec redraws each case's line in place, so pass partial lines on.
        std::io::stdout().write_all(&buffer[..n])?;
        std::io::stdout().flush()?;
        output.extend_from_slice(&buffer[..n]);
    }
    let status = child.0.wait()?;
    let text = String::from_utf8_lossy(&output);
    let pattern = Regex::new(r"(\d+) tests, (\d+) passed, (\d+) skipped, (\d+) failed")?;
    let Some(summary) = pattern.captures_iter(&text).last() else {
        return Ok((
            false,
            format!("h2spec printed no summary and exited with {status}"),
        ));
    };
    // A skipped case means the world's answer was too short to test with.
    let ok = status.success() && &summary[3] == "0" && &summary[4] == "0";
    Ok((ok, summary[0].to_owned()))
}
