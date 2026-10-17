mod docker;
mod fuzz;
mod images;
mod k8s;
mod process;
mod scan;

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
        "images" => images::run(args),
        "docker" => docker::run(args),
        "k8s" => k8s::run(args),
        "fuzz" => fuzz::run(args),
        "scan" => scan::run(args),
        "help" | "--help" | "-h" if args.is_empty() => {
            println!(
                "cargo xtask images [artifactory|hosted]\n\
                      cargo xtask docker <ping|tcpudp|proxy|web>\n\
                      cargo xtask k8s [tun|proxy]\n\
                      cargo xtask fuzz [--check | <target> | <seconds>] [libFuzzer arguments...]\n\
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
