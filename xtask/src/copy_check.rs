//! `cargo xtask copy-check`: the stdlib still compiles once it is copied out
//! of the SDK. A user may copy any stdlib module into a crate of their own,
//! so its files may reach other modules only through the SDK's public API
//! and their own relative paths.

use crate::process::{Result, capture, cmd, run as execute};
use serde_json::Value;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

/// The capture adapters in `src/observe` that a user may copy with the
/// stdlib, as the stdlib docs describe.
const OBSERVE: &[&str] = &["conversation", "http2", "protocols", "tls"];

pub fn run(args: &[String]) -> Result {
    if !args.is_empty() {
        return Err("usage: cargo xtask copy-check".into());
    }
    let metadata: Value = serde_json::from_str(&capture(&mut cmd(
        "cargo",
        &["metadata", "--locked", "--no-deps", "--format-version", "1"],
    ))?)?;
    let target = Path::new(
        metadata["target_directory"]
            .as_str()
            .ok_or("cargo metadata gave no target directory")?,
    );
    let sdk = metadata["packages"]
        .as_array()
        .and_then(|packages| packages.iter().find(|p| p["name"] == "fictionet"))
        .ok_or("cargo metadata has no fictionet package")?;

    let root = crate::root();
    let dir = target.join("copy-check");
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    copy_tree(&root.join("src/stdlib"), &dir.join("src/stdlib"))?;
    fs::create_dir_all(dir.join("src/observe"))?;
    for name in OBSERVE {
        let file = format!("src/observe/{name}.rs");
        fs::copy(root.join(&file), dir.join(&file))?;
    }
    // protocols.rs keeps its presenters in a folder of their own.
    copy_tree(
        &root.join("src/observe/protocols"),
        &dir.join("src/observe/protocols"),
    )?;
    // The web module's docs include these diagrams by relative path.
    copy_tree(&root.join("docs/diagrams"), &dir.join("docs/diagrams"))?;
    // The SDK's lock file keeps the copy on the versions the SDK is tested with.
    fs::copy(root.join("Cargo.lock"), dir.join("Cargo.lock"))?;
    fs::write(dir.join("Cargo.toml"), manifest(sdk, root)?)?;
    let mut lib = String::from(
        "//! The SDK's stdlib and capture adapters, copied by `cargo xtask copy-check`.\n\
         #![deny(warnings)]\n\n\
         pub mod stdlib;\n\n\
         fictionet::cfg_observe! {\n    pub mod observe {\n",
    );
    for name in OBSERVE {
        writeln!(lib, "        pub mod {name};")?;
    }
    lib.push_str("    }\n}\n");
    fs::write(dir.join("src/lib.rs"), lib)?;

    // Without the SDK's features, and with all of them, so both sides of
    // every feature gate compile in the copy.
    let all: Vec<String> = sdk["features"]
        .as_object()
        .ok_or("cargo metadata gave no features for fictionet")?
        .keys()
        .filter(|name| *name != "default")
        .map(|name| format!("fictionet/{name}"))
        .collect();
    for features in [String::new(), all.join(",")] {
        let mut command = cmd("cargo", &["build", "--lib", "--manifest-path"]);
        command
            .arg(dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(target);
        if !features.is_empty() {
            command.args(["--features", &features]);
        }
        println!(
            "Building the copy with {}",
            if features.is_empty() {
                "no SDK features"
            } else {
                &features
            }
        );
        execute(&mut command)?;
    }
    Ok(())
}

/// The copy's manifest: the SDK's own dependencies, none of them optional,
/// so the copied code finds every crate the SDK's features use.
fn manifest(sdk: &Value, root: &Path) -> Result<String> {
    let mut out = String::from(
        "[package]\nname = \"fictionet-copy-check\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n\n\
         # A workspace of its own, though it sits under the SDK's target directory.\n\
         [workspace]\n\n\
         # The stdlib checks its bookkeeping under `--cfg fuzzing`.\n\
         [lints.rust]\nunexpected_cfgs = { level = \"warn\", check-cfg = [\"cfg(fuzzing)\"] }\n\n\
         # Built as the SDK's workspace builds them, so the two share dependency builds.\n\
         [profile.dev.package.\"*\"]\nopt-level = 2\n\n\
         [profile.dev.package.fictionet]\nopt-level = 0\n\n",
    );
    let mut sections: Vec<(String, Vec<String>)> = Vec::new();
    for dep in sdk["dependencies"]
        .as_array()
        .ok_or("cargo metadata gave no dependencies for fictionet")?
    {
        if !dep["kind"].is_null() {
            continue;
        }
        let name = dep["name"].as_str().ok_or("dependency without a name")?;
        let req = dep["req"].as_str().ok_or("dependency without a version")?;
        let mut line = match dep["rename"].as_str() {
            Some(rename) => format!("{rename} = {{ package = {name:?}, version = {req:?}"),
            None => format!("{name} = {{ version = {req:?}"),
        };
        if dep["uses_default_features"] == false {
            line.push_str(", default-features = false");
        }
        let features: Vec<String> = dep["features"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|f| f.as_str().map(|f| format!("{f:?}")))
            .collect();
        if !features.is_empty() {
            write!(line, ", features = [{}]", features.join(", "))?;
        }
        line.push_str(" }");
        let section = match dep["target"].as_str() {
            Some(target) => format!("[target.'{target}'.dependencies]"),
            None => "[dependencies]".to_string(),
        };
        match sections.iter_mut().find(|(s, _)| *s == section) {
            Some((_, lines)) => lines.push(line),
            None => sections.push((section, vec![line])),
        }
    }
    let path = root.to_str().ok_or("the SDK's path is not UTF-8")?;
    match sections.iter_mut().find(|(s, _)| s == "[dependencies]") {
        Some((_, lines)) => lines.insert(
            0,
            format!("fictionet = {{ path = {path:?}, default-features = false }}"),
        ),
        None => return Err("fictionet has no plain dependencies".into()),
    }
    for (section, lines) in sections {
        writeln!(out, "{section}")?;
        for line in lines {
            writeln!(out, "{line}")?;
        }
        out.push('\n');
    }
    Ok(out)
}

fn copy_tree(from: &Path, to: &Path) -> Result {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            copy_tree(&path, &to.join(entry.file_name()))?;
        } else {
            fs::copy(&path, to.join(entry.file_name()))?;
        }
    }
    Ok(())
}
