use crate::process::{Result, run as execute};
use crate::vm::{self, quote};
use std::fs;
use std::io::IsTerminal;
use std::path::Path;
use std::time::Instant;

pub fn run(args: &[String]) -> Result {
    let dir = crate::root().join("demos/guest");
    let demos = demos(&dir)?;
    let usage = format!("usage: cargo xtask demo <{}>", demos.join("|"));
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
            "FICTIONET_DASHBOARD_PORT={} DASHBOARD_SECONDS={} KIND_NODE_IMAGE={} bash /src/demos/guest/{name}.sh",
            quote(&vm.read("run/dashboard-port")?),
            quote(&std::env::var("DASHBOARD_SECONDS").unwrap_or_default()),
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
