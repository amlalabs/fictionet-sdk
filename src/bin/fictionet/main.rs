//! The `fictionet` command. Its subcommands: `attach`, with the types
//! `tun`, `tap`, `https_proxy` and `socks5`; `ready`, a probe for attach's ready
//! file; `wait-blocked`, which waits until a pod's NetworkPolicy blocks its
//! direct traffic; `observe`, the observe API from a shell; and `dashboard`, which
//! serves the dashboard app. See the crate docs, `fictionet::attaching`
//! and `fictionet::observe`.
//!
//! Exit status of `attach`: 0 when the world closed the connection (or,
//! for `tap`, when QEMU closed its connection) or after `--help`, 1 on an error, 2 on bad arguments, 3 when the world
//! refused the attachment, and 128 plus the signal number on SIGTERM,
//! SIGINT or SIGHUP.
//!
//! Exit status of `ready <path>`: 0 if the path exists, 1 if not, 2 on bad
//! arguments.
//!
//! Exit status of `wait-blocked`: 0 once every address is unreachable, 1
//! if one is still reachable at the timeout, 2 on bad arguments.

mod addresses;
mod args;
mod blocked;
mod dashboard;
mod ether;
mod netlink;
mod observe;
mod proxy;
mod tap;
mod tun;
mod world;

const USAGE: &str = "\
usage: fictionet attach --world unix:<path> --name <name> --type tun|tap|https_proxy|socks5 [flags]
       fictionet ready <path>
       fictionet wait-blocked [--api-server] [--timeout <seconds>] [<ip:port>...]
       fictionet observe --world unix:<path> [<request>]
       fictionet dashboard --world unix:<path> [--listen <address:port>]

Run `fictionet attach --help` for the flags, and `fictionet observe --help`
for the requests an observer can make.
`fictionet ready <path>` exits 0 if <path> exists, and 1 if not. Use it as
a probe on attach's --ready-file, in an image with no shell.
`fictionet wait-blocked` exits 0 once the addresses stop answering, such as
when a NetworkPolicy takes effect. Run `fictionet wait-blocked --help`.
`fictionet --world` (running a world) is not implemented in this binary yet.";

static READY_FILE: std::sync::OnceLock<std::ffi::CString> = std::sync::OnceLock::new();

/// A socket file to remove on a signal: `--type tap`'s, while it listens.
static SOCKET_FILE: std::sync::OnceLock<std::ffi::CString> = std::sync::OnceLock::new();
static SOCKET_FILE_LIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The device and inode of [`SOCKET_FILE`], so the handler removes only
/// the file attach made.
static SOCKET_FILE_ID: std::sync::OnceLock<(u64, u64)> = std::sync::OnceLock::new();

/// Has the signal handler remove `path`, until [`keep_on_signal`], if it
/// is still the file with device and inode `id`. Only one path is ever
/// set.
pub(crate) fn remove_on_signal(path: &std::path::Path, id: (u64, u64)) {
    use std::os::unix::ffi::OsStrExt;
    if let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) {
        let _ = SOCKET_FILE.set(c);
        let _ = SOCKET_FILE_ID.set(id);
        SOCKET_FILE_LIVE.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Has the signal handler remove the ready file at `path`. `--type tap`
/// calls it once it owns its VM link, so that a second attach, refused,
/// leaves the first one's ready file alone. Only one path is ever set.
pub(crate) fn remove_ready_on_signal(path: &std::path::Path) {
    use std::os::unix::ffi::OsStrExt;
    if let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) {
        let _ = READY_FILE.set(c);
    }
}

/// A netlink request the signal handler sends before exiting: `--type
/// tap --vm tap:<name>` removes its redirect from the VM's device with it.
static NETLINK_ON_SIGNAL: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();

/// Has the signal handler send `msg` to the kernel's route netlink. Only
/// one message is ever set.
pub(crate) fn netlink_on_signal(msg: Vec<u8>) {
    let _ = NETLINK_ON_SIGNAL.set(msg);
}

/// Stops the signal handler removing the path given to
/// [`remove_on_signal`].
pub(crate) fn keep_on_signal() {
    SOCKET_FILE_LIVE.store(false, std::sync::atomic::Ordering::SeqCst);
}

/// Ends the process on SIGTERM, SIGINT and SIGHUP. The kernel then closes
/// the tun fd, which removes the device, or the proxy's listening socket,
/// and the world socket, which the world reads as a detach. A handler is needed because attach is often
/// process 1 in a container, and process 1 ignores signals it has no
/// handler for.
/// The ready file is removed too, so a healthcheck stops passing.
fn exit_on_signals(ready_file: Option<&std::path::Path>) {
    if let Some(path) = ready_file {
        remove_ready_on_signal(path);
    }
    extern "C" fn on_signal(sig: libc::c_int) {
        if let Some(path) = READY_FILE.get() {
            // SAFETY: unlink is async-signal-safe. A OnceLock read returns
            // the path only once it is fully set, which may be after the
            // handler was installed.
            unsafe { libc::unlink(path.as_ptr()) };
        }
        if SOCKET_FILE_LIVE.load(std::sync::atomic::Ordering::SeqCst)
            && let (Some(path), Some(&(dev, ino))) = (SOCKET_FILE.get(), SOCKET_FILE_ID.get())
        {
            // SAFETY: as above; an atomic load and OnceLock reads that
            // completed before the flag was set are signal-safe, and so is
            // lstat.
            unsafe {
                let mut st: libc::stat = std::mem::zeroed();
                if libc::lstat(path.as_ptr(), &mut st) == 0 && st.st_dev == dev && st.st_ino == ino {
                    libc::unlink(path.as_ptr());
                }
            }
        }
        if let Some(msg) = NETLINK_ON_SIGNAL.get() {
            // SAFETY: socket, sendto and close are async-signal-safe; the
            // message was built before it was set. The kernel handles a
            // route netlink request inside sendto, so no answer is awaited.
            unsafe {
                let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE);
                if fd >= 0 {
                    let mut kernel: libc::sockaddr_nl = std::mem::zeroed();
                    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
                    libc::sendto(
                        fd,
                        msg.as_ptr().cast(),
                        msg.len(),
                        0,
                        (&raw const kernel).cast(),
                        std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                    );
                    libc::close(fd);
                }
            }
        }
        // SAFETY: _exit is async-signal-safe.
        unsafe { libc::_exit(128 + sig) };
    }
    for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        // SAFETY: installs a handler that only calls _exit.
        unsafe { libc::signal(sig, on_signal as *const () as libc::sighandler_t) };
    }
}

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
                    world::Failure::Refused(reason) => eprintln!("fictionet attach: the world refused: {reason}"),
                    world::Failure::Error(msg) => eprintln!("fictionet attach: {msg}"),
                }
                std::process::exit(failure.status());
            }
        }
        Some("ready") => match &argv[1..] {
            [path] if !path.starts_with('-') => {
                if std::fs::symlink_metadata(path).is_err() {
                    eprintln!("fictionet ready: {path} does not exist");
                    std::process::exit(1);
                }
            }
            _ => {
                eprintln!("usage: fictionet ready <path>");
                std::process::exit(2);
            }
        },
        Some("wait-blocked") => std::process::exit(blocked::main(&argv[1..])),
        Some("observe") => std::process::exit(observe::main(&argv[1..])),
        Some("dashboard") => std::process::exit(dashboard::main(&argv[1..])),
        Some("-h" | "--help") => println!("{USAGE}"),
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
}
