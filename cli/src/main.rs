//! The `fictionet` command. Its subcommands: `attach`, with the types
//! `tun`, `tap`, `http_proxy` and `socks5`; `ready`, a probe for attach's ready
//! file; `wait-blocked`, which waits until a pod's NetworkPolicy blocks its
//! direct traffic; `observe`, the observe API from a shell; and `dashboard`, which
//! serves the dashboard app. See the crate docs, `fictionet::guide::attaching`
//! and `fictionet_observe`.
//!
//! Exit status of `attach`: 0 when the world closed the connection (or,
//! for `tap`, when QEMU closed its connection) or after `--help`, 1 on an error, 2 on bad arguments, 3 when the world
//! refused the attachment, and 128 plus the signal number on SIGTERM,
//! SIGINT or SIGHUP.
//!
//! Exit status of `ready <path>`: 0 if the path exists, 1 if not, 2 on bad
//! arguments.
//!
//! Exit status of `wait-blocked`: 0 once every address is unreachable for
//! three rounds before the timeout, 1 if the deadline expires first, 2 on
//! bad arguments.

mod args;
mod blocked;
mod config;
mod dashboard;
mod lifecycle;
mod linux;
mod netlink;
mod observe;
mod proxy;
mod tap;
mod tun;
mod world;

use lifecycle::exit_on_signals;

const USAGE: &str = "\
usage: fictionet attach --world unix:<path> --name <name> --type tun|tap|http_proxy|socks5 [flags]
       fictionet --version
       fictionet ready <path>
       fictionet wait-blocked [--api-server] [--timeout <seconds>] [<ip:port>...]
       fictionet observe --observation unix:<path> [<request>]
       fictionet dashboard --observation unix:<path> --token-file <path> [--listen <address:port>]

Run `fictionet attach --help` for the flags, and `fictionet observe --help`
for observation requests. --observation names the Unix socket a world serves
with fictionet_observe::serve. Run `fictionet dashboard --help` for browser access.
`fictionet ready <path>` exits 0 if <path> exists, and 1 if not. Use it as
a probe on attach's --ready-file, in an image with no shell.
`fictionet wait-blocked` exits 0 once the addresses stop answering, such as
when a NetworkPolicy takes effect. Run `fictionet wait-blocked --help`.";

const READY_USAGE: &str = "usage: fictionet ready <path>

Exits 0 if <path> exists, and 1 if not.";

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match argv.first().map(String::as_str) {
        Some("attach") => {
            let parsed = match args::parse_attach(&argv[1..]) {
                Ok(args::Parsed::Help) => {
                    println!("{}", args::ATTACH_USAGE);
                    return;
                }
                Err(msg) => {
                    eprintln!("fictionet attach: {msg}");
                    std::process::exit(2);
                }
                Ok(parsed) => parsed,
            };
            let result = match parsed {
                args::Parsed::Run(a) => {
                    exit_on_signals(a.ready_file.as_deref());
                    tun::run(a)
                }
                args::Parsed::Proxy(p) => {
                    exit_on_signals(p.ready_file.as_deref());
                    proxy::run(p)
                }
                args::Parsed::Tap(t) => {
                    // The ready file is handed to the handler later, once
                    // this attach owns the VM link.
                    exit_on_signals(None);
                    tap::run(t)
                }
                args::Parsed::Help => unreachable!("handled above"),
            };
            if let Err(failure) = result {
                match &failure {
                    world::Failure::Refused(reason) => {
                        eprintln!("fictionet attach: the world refused: {reason}")
                    }
                    world::Failure::Error(msg) => eprintln!("fictionet attach: {msg}"),
                }
                std::process::exit(failure.status());
            }
        }
        Some("ready") => match &argv[1..] {
            [flag] if flag == "-h" || flag == "--help" => println!("{READY_USAGE}"),
            [path] if !path.starts_with('-') => {
                if std::fs::symlink_metadata(path).is_err() {
                    eprintln!("fictionet ready: {path} does not exist");
                    std::process::exit(1);
                }
            }
            _ => {
                eprintln!("{READY_USAGE}");
                std::process::exit(2);
            }
        },
        Some("wait-blocked") => std::process::exit(blocked::main(&argv[1..])),
        Some("observe") => std::process::exit(observe::main(&argv[1..])),
        Some("dashboard") => std::process::exit(dashboard::main(&argv[1..])),
        Some("--version") if argv.len() == 1 => println!("fictionet {}", env!("CARGO_PKG_VERSION")),
        Some("-h" | "--help") => println!("{USAGE}"),
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
}
