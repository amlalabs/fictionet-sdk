//! `fictionet wait-blocked`: waits until the sandbox's own network can no
//! longer reach the given addresses.
//!
//! With a proxy type on Kubernetes, the pod keeps its `eth0`, and the
//! chart's deny-all NetworkPolicy is what keeps the agent off it. A CNI may
//! start enforcing a new policy some time after the pod starts. The chart
//! runs this as an init container just before the agent's container, so
//! the agent starts only once a direct connection to the API server (and
//! to any other address given) fails, several times in a row.

use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

pub(crate) const USAGE: &str = "\
usage: fictionet wait-blocked [--api-server] [--timeout <seconds>] [<ip:port>...]

Tries a TCP connection to each address every half second, and exits 0 once
every one of them has failed (refused, unreachable or timed out after 1 s)
3 rounds in a row. A connection that succeeds, or any other failure (such
as no socket being available), starts the count again.
Exits 1 if that has not happened within --timeout seconds (default 120),
and 2 on bad arguments.

  --api-server         also try the Kubernetes API server, from
                       KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT
  --timeout <seconds>  how long to wait, at least 1
  <ip:port>            an address, such as 1.1.1.1:443 or [2606:4700::1111]:443";

/// How long one connection attempt may take before it counts as blocked.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
/// The pause between rounds.
const INTERVAL: Duration = Duration::from_millis(500);
/// How many rounds in a row every address must fail.
const ROUNDS: u32 = 3;

struct Args {
    addresses: Vec<SocketAddr>,
    timeout: Duration,
}

fn parse(argv: &[String], env: impl Fn(&str) -> Option<String>) -> Result<Args, String> {
    let mut addresses = Vec::new();
    let mut timeout = Duration::from_secs(120);
    let mut it = argv.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--api-server" => {
                let host = env("KUBERNETES_SERVICE_HOST")
                    .ok_or("--api-server: KUBERNETES_SERVICE_HOST is not set")?;
                let port = env("KUBERNETES_SERVICE_PORT")
                    .ok_or("--api-server: KUBERNETES_SERVICE_PORT is not set")?;
                let ip = host.parse::<std::net::IpAddr>().map_err(|_| {
                    format!("--api-server: KUBERNETES_SERVICE_HOST is {host:?}, not an IP address")
                })?;
                let port = port.parse::<u16>().map_err(|_| {
                    format!("--api-server: KUBERNETES_SERVICE_PORT is {port:?}, not a port")
                })?;
                addresses.push(SocketAddr::new(ip, port));
            }
            "--timeout" => {
                let v = it.next().ok_or("--timeout needs a value")?;
                let secs = v.parse::<u64>().ok().filter(|&s| s >= 1).ok_or_else(|| {
                    format!("--timeout: {v:?} is not a whole number of seconds, at least 1")
                })?;
                timeout = Duration::from_secs(secs);
            }
            a if a.starts_with('-') => return Err(format!("unknown flag {a}")),
            a => addresses.push(
                a.parse()
                    .map_err(|_| format!("{a:?} is not an ip:port address"))?,
            ),
        }
    }
    if addresses.is_empty() {
        return Err("give at least one address, or --api-server".into());
    }
    Ok(Args { addresses, timeout })
}

/// What one connection attempt showed.
#[derive(Debug, Clone, PartialEq)]
enum Outcome {
    /// The connection was made: the address is reachable.
    Open,
    /// It timed out, or was refused or unreachable, as when a policy drops
    /// or rejects the packets.
    Blocked,
    /// It failed in a way a policy does not cause, such as no socket being
    /// available. This does not count as blocked.
    Unknown(String),
}

/// Sorts a failed connection: only a timeout, a refusal and an
/// unreachable host or network count as blocked.
fn classify(e: &std::io::Error) -> Outcome {
    use std::io::ErrorKind::*;
    match e.kind() {
        TimedOut | ConnectionRefused | HostUnreachable | NetworkUnreachable => Outcome::Blocked,
        _ => Outcome::Unknown(e.to_string()),
    }
}

fn probe(a: SocketAddr) -> Outcome {
    // A socket that cannot even be made says nothing about the network.
    let family = if a.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: socket takes no pointers; the descriptor is closed at once.
    let fd = unsafe { libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Outcome::Unknown(format!(
            "making a socket: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fd is a descriptor this function just made.
    unsafe { libc::close(fd) };
    match TcpStream::connect_timeout(&a, CONNECT_TIMEOUT) {
        Ok(_) => Outcome::Open,
        Err(e) => classify(&e),
    }
}

/// Each address with what trying it showed, tried all at once.
fn try_all(addresses: &[SocketAddr]) -> Vec<(SocketAddr, Outcome)> {
    std::thread::scope(|s| {
        let tries: Vec<_> = addresses
            .iter()
            .map(|&a| s.spawn(move || (a, probe(a))))
            .collect();
        tries
            .into_iter()
            .zip(addresses)
            .map(|(t, &a)| {
                t.join()
                    .unwrap_or((a, Outcome::Unknown("the probe thread panicked".into())))
            })
            .collect()
    })
}

fn list(addresses: &[SocketAddr]) -> String {
    addresses
        .iter()
        .map(SocketAddr::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The addresses that are not blocked, and why, for the log.
fn describe(outcomes: &[(SocketAddr, Outcome)]) -> String {
    outcomes
        .iter()
        .filter_map(|(a, o)| match o {
            Outcome::Open => Some(format!("{a} still reachable")),
            Outcome::Unknown(why) => {
                Some(format!("{a} failed ({why}), which does not show a block"))
            }
            Outcome::Blocked => None,
        })
        .collect::<Vec<_>>()
        .join("; ")
}

pub(crate) fn main(argv: &[String]) -> i32 {
    if matches!(argv, [a] if a == "--help" || a == "-h") {
        println!("{USAGE}");
        return 0;
    }
    let args = match parse(argv, |k| std::env::var(k).ok()) {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("fictionet wait-blocked: {msg}\n{USAGE}");
            return 2;
        }
    };
    let start = Instant::now();
    let mut failed_rounds = 0;
    let mut last = String::new();
    loop {
        let outcomes = try_all(&args.addresses);
        let now = describe(&outcomes);
        if now.is_empty() {
            failed_rounds += 1;
            if failed_rounds >= ROUNDS {
                eprintln!(
                    "fictionet wait-blocked: {} unreachable {ROUNDS} times in a row, after {:.1} s",
                    list(&args.addresses),
                    start.elapsed().as_secs_f64()
                );
                return 0;
            }
        } else {
            failed_rounds = 0;
            if now != last {
                eprintln!("fictionet wait-blocked: {now}; waiting");
            }
        }
        if start.elapsed() >= args.timeout {
            eprintln!(
                "fictionet wait-blocked: after {} s, {}. Check that the cluster's CNI enforces NetworkPolicy, \
                 and that no other policy allows this pod's traffic",
                args.timeout.as_secs(),
                if now.is_empty() {
                    last.as_str()
                } else {
                    now.as_str()
                },
            );
            return 1;
        }
        last = now;
        std::thread::sleep(INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_addresses_and_the_api_server() {
        let env = |k: &str| match k {
            "KUBERNETES_SERVICE_HOST" => Some("fd00:10:96::1".to_string()),
            "KUBERNETES_SERVICE_PORT" => Some("443".to_string()),
            _ => None,
        };
        let a = parse(
            &args(&["--api-server", "1.1.1.1:443", "--timeout", "5"]),
            env,
        )
        .unwrap();
        assert_eq!(
            a.addresses,
            [
                "[fd00:10:96::1]:443".parse().unwrap(),
                "1.1.1.1:443".parse().unwrap()
            ]
        );
        assert_eq!(a.timeout, Duration::from_secs(5));
    }

    #[test]
    fn only_a_timeout_refusal_or_unreachable_counts_as_blocked() {
        use std::io::{Error, ErrorKind};
        for kind in [
            ErrorKind::TimedOut,
            ErrorKind::ConnectionRefused,
            ErrorKind::HostUnreachable,
            ErrorKind::NetworkUnreachable,
        ] {
            assert_eq!(classify(&Error::from(kind)), Outcome::Blocked, "{kind:?}");
        }
        for errno in [
            libc::EPERM,
            libc::EACCES,
            libc::EMFILE,
            libc::EADDRNOTAVAIL,
            libc::ENOBUFS,
        ] {
            assert!(
                matches!(
                    classify(&Error::from_raw_os_error(errno)),
                    Outcome::Unknown(_)
                ),
                "{errno}"
            );
        }
    }

    #[test]
    fn refuses_bad_arguments() {
        let none = |_: &str| None;
        for (argv, want) in [
            (&[][..], "at least one address"),
            (&["--api-server"][..], "KUBERNETES_SERVICE_HOST is not set"),
            (&["example.com:443"][..], "not an ip:port"),
            (&["1.1.1.1:443", "--timeout", "0"][..], "at least 1"),
            (&["--timeout"][..], "needs a value"),
            (&["--nope"][..], "unknown flag"),
        ] {
            let err = parse(&args(argv), none).err().unwrap();
            assert!(err.contains(want), "{argv:?}: {err}");
        }
    }
}
