mod libraries;
mod microvm;

use crate::process::{Result, run as execute};
use crate::vm::{self, quote};
use std::fs;
use std::io::IsTerminal;
use std::path::Path;
use std::time::Instant;

pub fn run(args: &[String]) -> Result {
    let dir = crate::root().join("demos/guest");
    let demos = demos(&dir)?;
    let binaries = binaries(&crate::root().join("demos/src/bin"))?;
    if args.is_empty() {
        println!("in-process demos: {}", binaries.join(", "));
        println!("VM scripts: {}", demos.join(", "));
        println!(
            "cargo xtask demo <name> [preview]; cargo xtask demo assets downloads everything; cargo xtask demo libraries downloads browser libraries only"
        );
        return Ok(());
    }
    if let [action, path] = args
        && action == "open"
    {
        let path = std::fs::canonicalize(path)?;
        if !path.is_file() {
            return Err("the page bootstrap is not a file".into());
        }
        let status = std::process::Command::new("chromium")
            .args(["--password-store=basic", "--use-mock-keychain"])
            .arg(format!("--app=file://{}", path.display()))
            .status()?;
        if !status.success() {
            return Err(format!("Chromium exited with {status}").into());
        }
        return Ok(());
    }
    if args == ["assets"] {
        return microvm::assets();
    }
    if args == ["libraries"] {
        return libraries::assets();
    }
    if let [name, rest @ ..] = args
        && binaries.contains(name)
    {
        let rest = rest.strip_prefix(&[String::from("--")]).unwrap_or(rest);
        // A preview serves the page without a VM: it needs only the
        // browser libraries, and no downloads folder.
        let preview = rest.first().is_some_and(|arg| arg == "preview");
        if preview {
            libraries::assets()?;
        } else {
            microvm::assets()?;
        }
        microvm::build(name)?;
        return microvm::launch(name, !preview, rest);
    }
    let usage = format!(
        "usage: cargo xtask demo [assets|libraries|{}]",
        binaries
            .iter()
            .chain(demos.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join("|")
    );
    let [name] = args else {
        return Err(usage.into());
    };
    if !demos.contains(name) {
        return Err(format!("unknown demo: {name}\n{usage}").into());
    }
    let script = fs::read_to_string(dir.join(format!("{name}.sh")))?;
    let targets: Vec<String> = script
        .lines()
        .filter_map(|line| line.strip_prefix("# needs: "))
        .flat_map(str::split_whitespace)
        .map(String::from)
        .collect();
    let all = Instant::now();
    vm::with_vm(|vm| {
        vm.sync()?;
        let start = Instant::now();
        vm.build(&targets)?;
        eprintln!("Built in {:.1} s", start.elapsed().as_secs_f64());
        let start = Instant::now();
        let mut command = vm.ssh()?;
        if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
            command.arg("-t");
        }
        command.arg("root@127.0.0.1").arg(format!(
            "KIND_NODE_IMAGE={} bash /src/demos/guest/{name}.sh",
            quote(vm::KIND_NODE),
        ));
        let result = execute(&mut command);
        eprintln!(
            "cargo xtask demo {name}: {} in {:.1} s; {:.1} s including boot and build",
            if result.is_ok() { "PASSED" } else { "FAILED" },
            start.elapsed().as_secs_f64(),
            all.elapsed().as_secs_f64()
        );
        result
    })
}

/// The demos are the scripts in demos/guest with a `# needs:` line.
fn demos(dir: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "sh")
            && fs::read_to_string(&path)?
                .lines()
                .any(|line| line.starts_with("# needs: "))
        {
            names.push(
                path.file_stem()
                    .ok_or("a script without a name")?
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
    names.sort();
    Ok(names)
}

/// In-process demos use ordinary binary module directories.
fn binaries(dir: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.join("main.rs").is_file() {
            names.push(
                path.file_name()
                    .ok_or("a binary without a name")?
                    .to_string_lossy()
                    .into_owned(),
            );
        } else if path.extension().is_some_and(|e| e == "rs") {
            names.push(
                path.file_stem()
                    .ok_or("a binary without a name")?
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
    names.sort();
    Ok(names)
}
