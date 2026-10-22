mod bless;
mod copy_check;
mod demo;
mod docker;
mod eval;
mod fuzz;
mod h2spec;
mod images;
mod k8s;
mod process;
mod vm;

use process::Result;
use std::path::Path;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
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
        "bless" if args.is_empty() => bless::run(),
        "images" => images::run(args),
        "docker" => docker::run(args),
        "eval" => eval::run(args),
        "k8s" => k8s::run(args),
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
        "help" | "--help" | "-h" if args.is_empty() => {
            println!(
                "cargo xtask bless\n\
                      cargo xtask images [artifactory|hosted]\n\
                      cargo xtask docker <ping|tcpudp|proxy|web>\n\
                      cargo xtask eval <border|fakewiki|web|artifactory> [options]\n\
                      cargo xtask k8s [tun|proxy]\n\
                      cargo xtask vm [--fetch | nested [--fetch] | up | down | prepare | sync | build | test | ssh | status | clean]\n\
                      cargo xtask demo [name [preview] | assets | libraries]  (no arguments lists demos)\n\
                      cargo xtask copy-check\n\
                      cargo xtask fuzz [--check | <target> | <seconds>] [libFuzzer arguments...]\n\
                      cargo xtask h2spec [section]"
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
