use crate::process::{Result, capture, cmd, run as execute};
use std::collections::BTreeSet;

pub fn run(args: &[String]) -> Result {
    if args == ["--check"] {
        let targets = targets()?;
        println!("{} fuzz targets, each with a binary", targets.len());
        return Ok(());
    }
    let (selection, extra) = match args.split_first() {
        Some((first, rest)) if !first.starts_with('-') => (Some(first.as_str()), rest),
        _ => (None, args),
    };
    let seconds = selection.filter(|s| s.bytes().all(|b| b.is_ascii_digit()));
    let single = selection.filter(|_| seconds.is_none());
    let listed = capture(&mut cmd("cargo", &["+nightly", "fuzz", "list"]))?;
    let targets: BTreeSet<_> = listed.split_whitespace().map(str::to_string).collect();
    if targets.is_empty() {
        return Err("fuzz target discovery returned no targets".into());
    }
    if let Some(target) = single
        && !targets.contains(target)
    {
        return Err(format!("unknown fuzz target: {target}").into());
    }
    let mut failures = Vec::new();
    for target in &targets {
        if single.is_some_and(|name| name != target) {
            continue;
        }
        println!("Running {target}");
        let corpus = format!("fuzz/corpus/{target}");
        std::fs::create_dir_all(crate::root().join(&corpus))?;
        let mut command = cmd("cargo", &["+nightly", "fuzz", "run", "-O", "-a"]);
        command.env("CARGO_TARGET_DIR", crate::root().join("target/fuzz"));
        command.args([target, &corpus, "--"]);
        if single.is_none() {
            command.arg(format!("-max_total_time={}", seconds.unwrap_or("60")));
        }
        command.args(extra);
        if let Err(error) = execute(&mut command) {
            eprintln!("{target}: {error}");
            failures.push(target.as_str());
        }
    }
    if !failures.is_empty() {
        return Err(format!(
            "{} fuzz targets failed: {}",
            failures.len(),
            failures.join(" ")
        )
        .into());
    }
    Ok(())
}

fn targets() -> Result<BTreeSet<String>> {
    let metadata: serde_json::Value = serde_json::from_str(&capture(&mut cmd(
        "cargo",
        &[
            "metadata",
            "--locked",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
            "fuzz/Cargo.toml",
        ],
    ))?)?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or("missing fuzz packages")?;
    let package = packages
        .iter()
        .find(|p| p["name"] == "fictionet-fuzz")
        .ok_or("missing fictionet-fuzz package")?;
    let mut targets = BTreeSet::new();
    let mut problems = Vec::new();
    for target in package["targets"]
        .as_array()
        .ok_or("missing fuzz targets")?
    {
        if target["kind"]
            .as_array()
            .is_some_and(|k| k.iter().any(|v| v == "bin"))
        {
            let name = target["name"].as_str().ok_or("missing target name")?;
            if !crate::root()
                .join(format!("fuzz/fuzz_targets/{name}.rs"))
                .is_file()
            {
                problems.push(format!("{name} has no source file"));
            }
            targets.insert(name.to_string());
        }
    }
    for entry in std::fs::read_dir(crate::root().join("fuzz/fuzz_targets"))? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "rs") {
            let name = path
                .file_stem()
                .and_then(|n| n.to_str())
                .ok_or("invalid fuzz source name")?;
            if !targets.contains(name) {
                problems.push(format!("{name} has no binary in fuzz/Cargo.toml"));
            }
        }
    }
    if targets.is_empty() {
        problems.push("fuzz target discovery returned no targets".into());
    }
    if !problems.is_empty() {
        return Err(problems.join("\n").into());
    }
    Ok(targets)
}
