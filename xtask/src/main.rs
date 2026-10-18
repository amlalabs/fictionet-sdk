mod copy_check;
mod demo;
mod docker;
mod eval;
mod fuzz;
mod h2spec;
mod images;
mod k8s;
mod microvm;
mod process;
mod scan;
mod vm;

use process::Result;
use std::path::Path;

fn root() -> &'static Path {
    static ROOT: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        std::env::var_os("FICTIONET_ROOT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap()
                    .to_path_buf()
            })
    })
}

fn main() {
    if let Err(error) = main_result() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn main_result() -> Result {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (command, args) = args
        .split_first()
        .map_or(("help", &[][..]), |(c, a)| (c.as_str(), a));
    match command {
        "images" => images::run(args),
        "docker" => docker::run(args),
        "eval" => eval::run(args),
        "k8s" => k8s::run(args),
        "microvm" => microvm::run(args),
        "vm" | "demo" => {
            let _interrupts = process::Interrupts::new()?;
            if command == "vm" {
                vm::run(args)
            } else {
                demo::run(args)
            }
        }
        "copy-check" => copy_check::run(args),
        "fuzz" => fuzz::run(args),
        "h2spec" => h2spec::run(args),
        "scan" => scan::run(args),
        "help" | "--help" | "-h" if args.is_empty() => {
            println!(
                "cargo xtask images [artifactory|hosted]\n\
                      cargo xtask docker <ping|tcpudp|proxy|web>\n\
                      cargo xtask eval <border|fakewiki|adaptive-web|artifactory> [options]\n\
                      cargo xtask k8s [tun|proxy]\n\
                      cargo xtask microvm [assets | build]\n\
                      cargo xtask vm [--fetch | nested [--fetch] | up | down | prepare | sync | build | test | ssh | status | clean]\n\
                      cargo xtask demo <name>  (demos/README.md lists them)\n\
                      cargo xtask copy-check\n\
                      cargo xtask fuzz [--check | <target> | <seconds>] [libFuzzer arguments...]\n\
                      cargo xtask h2spec [section]\n\
                      cargo xtask scan [output directory]"
            );
            Ok(())
        }
        _ => Err(format!(
            "unknown command or arguments: {command} {}; use cargo xtask --help",
            args.join(" ")
        )
        .into()),
    }
}
