mod corpus;
mod libraries;
mod microvm;

use crate::process::{Result, run as execute};
use crate::vm::{self, quote};
use std::fs;
use std::io::IsTerminal;
use std::path::Path;
use std::time::Instant;

pub fn run(args: &[String]) -> Result {
    let dir = crate::root().join("demos");
    let demos = demos(&dir)?;
    let binaries = binaries(&crate::root().join("demos"))?;
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
            return Err("the page's address file is not a file".into());
        }
        microvm::build("open")?;
        return microvm::launch("open", false, &[path.display().to_string()]);
    }
    if args == ["assets"] {
        return microvm::assets();
    }
    if let [name, rest @ ..] = args
        && name == "corpus"
    {
        return corpus::run(rest);
    }
    if args == ["libraries"] {
        return libraries::assets();
    }
    if let [name, rest @ ..] = args
        && binaries.contains(name)
    {
        let rest = rest.strip_prefix(&[String::from("--")]).unwrap_or(rest);
        // A preview serves the page without a VM or its downloads.
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
    let script = fs::read_to_string(dir.join(name).join("guest.sh"))?;
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
            "KIND_NODE_IMAGE={} bash /src/demos/{name}/guest.sh",
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

/// VM demos own a guest script with a `# needs:` line.
fn demos(dir: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        let folder = entry?.path();
        let path = folder.join("guest.sh");
        if path.is_file()
            && fs::read_to_string(&path)?
                .lines()
                .any(|line| line.starts_with("# needs: "))
        {
            names.push(
                folder
                    .file_name()
                    .ok_or("a script without a demo folder")?
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
    names.sort();
    Ok(names)
}

/// Each in-process demo is a binary module directory. A single-file
/// binary, such as `open`, is a tool and not a demo.
fn binaries(dir: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.join("app/src/main.rs").is_file() {
            names.push(
                path.file_name()
                    .ok_or("a binary without a name")?
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
    names.sort();
    Ok(names)
}
