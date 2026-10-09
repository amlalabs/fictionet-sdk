//! The adaptive web on Fictionet: every name resolves, every HTTPS host has
//! a certificate, and every page is made the first time it is asked for.
//!
//! ```text
//! adaptive-web-world --socket /run/fictionet/sock/world.sock --ca-dir /app/ca \
//!     --backend /app/backend --backend-port 8080 \
//!     --state-dir /var/lib/fictionet --ready /run/fictionet/ready
//! ```
//!
//! - **Names** ([`admit`]): any name that could exist on the internet gets
//!   a site the first time it is looked up. Single-label names and the
//!   reserved and private top-level domains get NXDOMAIN.
//! - **Addresses** ([`Addresses`]): the search engines and the seed's
//!   hosts have fixed addresses. Every other host gets the next free
//!   address from two public-looking pools, in the order hosts are first
//!   looked up, and keeps it for the run. Each assignment is appended to
//!   the store's `addresses.jsonl`, so a later run on the same store gives
//!   every host the same address again.
//! - **TLS** ([`Ca`]): a host's certificate is made at its first handshake
//!   and signed by a seeded CA whose public root is written at startup.
//! - **Dates** ([`world_start`]): the world's clock starts on the seed's
//!   date, so every response's `Date` header is in the scenario, and each
//!   certificate was issued shortly before it.
//! - **Pages** ([`backend`]): every site forwards to the Python backend
//!   on 127.0.0.1, which makes, stores and serves the pages.
//! - **Ground truth**: `state.json` and `log.jsonl` in `--state-dir`, the
//!   ready file, and the store. The log is written from the run's events
//!   ([`events`]).

pub mod backend;
pub mod events;
#[path = "../../../common/log.rs"]
pub mod log;

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use fictionet::Cx;
use fictionet::events::Event;
use fictionet::stdlib::tls::ServerConfig;
use fictionet::stdlib::web;
use serde_json::{Value, json};

use crate::backend::Backend;
use crate::log::Log;

/// The gateway, where `Sites` runs DNS (its default subnet is 10.0.0.0/24).
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

/// The world's command line.
pub struct Args {
    pub socket: String,
    pub ca_dir: PathBuf,
    pub backend: PathBuf,
    pub backend_port: u16,
    pub state_dir: PathBuf,
    pub ready: PathBuf,
}

/// Reads the command line.
pub fn args() -> Result<Args, String> {
    let mut a = Args {
        socket: "/run/fictionet/sock/world.sock".into(),
        ca_dir: "/app/ca".into(),
        backend: "/app/backend".into(),
        backend_port: 8080,
        state_dir: "/var/lib/fictionet".into(),
        ready: "/run/fictionet/ready".into(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--socket" => a.socket = value,
            "--ca-dir" => a.ca_dir = value.into(),
            "--backend" => a.backend = value.into(),
            "--backend-port" => {
                a.backend_port = value.parse().map_err(|e| format!("--backend-port: {e}"))?
            }
            "--state-dir" => a.state_dir = value.into(),
            "--ready" => a.ready = value.into(),
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    Ok(a)
}

/// Top-level domains that never resolve on the internet: reserved by RFC
/// 2606 and 6761, used for mDNS, or used only inside private networks.
const NOT_ON_THE_INTERNET: [&str; 12] = [
    "test",
    "example",
    "invalid",
    "localhost",
    "local",
    "internal",
    "lan",
    "home",
    "corp",
    "intranet",
    "private",
    "arpa",
];

/// Whether `name` gets a site. `Err` says why not, for the log.
///
/// A name gets a site when it could be a host on the internet: at least two
/// labels, each 1 to 63 letters, digits or hyphens, not starting or ending
/// with a hyphen, at most 253 characters in all, and a top-level domain of
/// two or more letters (or an `xn--` one) that is not reserved or private.
pub fn admit(name: &str) -> Result<(), &'static str> {
    if !name.contains('.') {
        return Err("single label");
    }
    if name.len() > 253 {
        return Err("too long");
    }
    let labels: Vec<&str> = name.split('.').collect();
    for label in &labels {
        let ok = !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ok {
            return Err("not a host name");
        }
    }
    let tld = labels[labels.len() - 1];
    if !(tld.starts_with("xn--")
        || (tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())))
    {
        return Err("not a top-level domain");
    }
    if NOT_ON_THE_INTERNET.contains(&tld) {
        return Err("reserved or private top-level domain");
    }
    Ok(())
}

/// Every host's address: fixed ones from the backend (search engines, the
/// seed), ones recorded by an earlier run on the same store, then the next
/// free one from the pools.
pub struct Addresses {
    fixed: Vec<String>,
    inner: Mutex<Inner>,
    record: Option<Mutex<File>>,
}

struct Inner {
    by_host: HashMap<String, (Ipv4Addr, &'static str)>,
    used: HashSet<Ipv4Addr>,
    next: u32,
}

/// The pools: two /16s that many ordinary sites live in. Addresses
/// alternate between them, and step through each one in a scattered
/// order, so hosts looked up one after another do not get neighbouring
/// addresses.
const POOLS: [[u8; 2]; 2] = [[104, 21], [172, 67]];

impl Addresses {
    /// `fixed` maps hosts to addresses with the reason (`"search engine"`,
    /// `"seed"`). `record`, if given, is the store's `addresses.jsonl`: its
    /// lines are read first, as `"recorded"`, and new assignments are
    /// appended to it.
    pub fn new(
        fixed: HashMap<String, (Ipv4Addr, &'static str)>,
        record: Option<&Path>,
    ) -> std::io::Result<Addresses> {
        let mut names: Vec<_> = fixed.keys().cloned().collect();
        names.sort();
        let mut by_host = fixed;
        if let Some(Ok(text)) = record.map(std::fs::read_to_string) {
            for line in text.lines() {
                let Ok(v) = serde_json::from_str::<Value>(line) else {
                    continue;
                };
                let (Some(host), Some(addr)) = (
                    v["host"].as_str(),
                    v["addr"].as_str().and_then(|a| a.parse().ok()),
                ) else {
                    continue;
                };
                by_host.entry(host.to_owned()).or_insert((addr, "recorded"));
            }
        }
        let used = by_host.values().map(|(a, _)| *a).collect();
        let record = match record {
            Some(path) => Some(Mutex::new(
                OpenOptions::new().create(true).append(true).open(path)?,
            )),
            None => None,
        };
        Ok(Addresses {
            fixed: names,
            inner: Mutex::new(Inner {
                by_host,
                used,
                next: 0,
            }),
            record,
        })
    }

    /// The address of `host`, and why it has that one: its fixed or
    /// recorded address, or the next free one from the pools (`"pool"`).
    pub fn assign(&self, host: &str) -> (Ipv4Addr, &'static str) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(found) = inner.by_host.get(host) {
            return *found;
        }
        let addr = loop {
            let n = inner.next;
            inner.next += 1;
            let [a, b] = POOLS[(n % 2) as usize];
            // An odd multiplier makes this a permutation of 0..65536.
            let offset = ((n / 2).wrapping_mul(40503).wrapping_add(12345)) & 0xffff;
            let (c, d) = ((offset >> 8) as u8, offset as u8);
            let addr = Ipv4Addr::new(a, b, c, d);
            if d != 0 && d != 255 && !inner.used.contains(&addr) {
                break addr;
            }
        };
        inner.used.insert(addr);
        inner.by_host.insert(host.to_owned(), (addr, "pool"));
        if let Some(file) = &self.record {
            let line = json!({"host": host, "addr": addr.to_string()}).to_string() + "\n";
            let mut file = file.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(e) = file.write_all(line.as_bytes()) {
                eprintln!("cannot record the address of {host}: {e}");
            }
        }
        (addr, "pool")
    }
}

/// The world's date at the start of the run: the seed's day (`YYYY-MM-DD`,
/// UTC) at the host's time of day, so the clock reads like an ordinary day.
pub fn world_start(date: &str) -> fictionet::Result<SystemTime> {
    let bad = |why: String| {
        fictionet::Error::msg(format!(
            "the seed's date {date:?} is not a YYYY-MM-DD date: {why}"
        ))
    };
    let parts: Vec<&str> = date.split('-').collect();
    let [y, m, d] = parts[..] else {
        return Err(bad("it does not have three parts".into()));
    };
    let number = |p: &str| p.parse::<u16>().map_err(|e| bad(e.to_string()));
    let byte = |p: &str| u8::try_from(number(p)?).map_err(|e| bad(e.to_string()));
    let month = time::Month::try_from(byte(m)?).map_err(|e| bad(e.to_string()))?;
    let day = time::Date::from_calendar_date(number(y)? as i32, month, byte(d)?)
        .map_err(|e| bad(e.to_string()))?;
    let now = time::OffsetDateTime::now_utc();
    Ok(day.with_time(now.time()).assume_utc().into())
}

/// The world's certificate authority, which signs a certificate for each
/// host at its first handshake.
pub struct Ca {
    issuer: fictionet::stdlib::ca::Ca,
    start: SystemTime,
}

impl Ca {
    /// Makes a seeded CA and writes its public certificate for the agent.
    pub fn new(fcx: &Cx, dir: &Path, start: SystemTime) -> fictionet::Result<Ca> {
        let issuer = fictionet::stdlib::ca::Ca::new(fcx, "Internet Security Root CA")?;
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("ca.pem"), issuer.cert_pem())?;
        Ok(Ca { issuer, start })
    }

    /// A certificate for `host`: the host as CN and SAN, for server auth,
    /// issued 30 days before the world's date. The chain sent is the leaf,
    /// then the CA. Returns the TLS config and the validity, for the log.
    ///
    /// A client checks the certificate against its own clock, which is the
    /// host's, not the world's. So the validity covers both: it starts 30
    /// days before the earlier of the two, and lasts 90 days, or longer if
    /// that would end within 30 days of the later one.
    pub fn config(
        &self,
        fcx: &Cx,
        host: &str,
    ) -> fictionet::Result<(Arc<ServerConfig>, String, String)> {
        let world_now = time::OffsetDateTime::from(self.start + fcx.now().since_start());
        let host_now = time::OffsetDateTime::now_utc();
        let not_before = world_now.min(host_now) - time::Duration::days(30);
        let not_after = (not_before + time::Duration::days(90))
            .max(world_now.max(host_now) + time::Duration::days(30));
        let leaf = self.issuer.issue(
            fcx,
            &[host],
            fictionet::stdlib::x509::Validity {
                not_before: fictionet::stdlib::x509::Time::from_unix(not_before.unix_timestamp())?,
                not_after: fictionet::stdlib::x509::Time::from_unix(not_after.unix_timestamp())?,
            },
        )?;
        let config = leaf.server_config(fcx, self.start)?;
        let day = |t: time::OffsetDateTime| {
            format!("{:04}-{:02}-{:02}", t.year(), t.month() as u8, t.day())
        };
        Ok((config, day(not_before), day(not_after)))
    }
}

/// Builds the network: a site for every name [`admit`] lets in, at its
/// address from `addresses`, with a certificate from `ca` made at its first
/// handshake, every request answered by `backend` and logged, and every
/// response dated from `start`, the world's date at the start of the run.
/// Returns at once; the network runs in `fcx`'s region.
pub fn serve(
    fcx: &Cx,
    addresses: Arc<Addresses>,
    ca: Arc<Ca>,
    backend: Backend,
    log: Arc<Log>,
    start: SystemTime,
    attachments: fictionet::Attachments,
) -> fictionet::Result {
    events::log_to(fcx, log);
    let names = addresses.fixed.clone();
    let world = fcx.clone();
    let site_for = move |host: &str| {
        if let Err(why) = admit(host) {
            world.record(
                Event::new("adaptive", "refused")
                    .summary(format!("{host}: {why}"))
                    .field("host", host)
                    .field("why", why),
            );
            return None;
        }
        let (addr, why) = addresses.assign(host);
        world.record(
            Event::new("adaptive", "site")
                .summary(format!("{host} at {addr} ({why})"))
                .field("host", host)
                .field("addr", addr.to_string())
                .field("why", why),
        );
        let (ca, name) = (ca.clone(), host.to_owned());
        let config: Arc<OnceLock<Arc<ServerConfig>>> = Arc::new(OnceLock::new());
        Some(
            web::Site::new(backend.clone())
                .date(start)
                .at(addr)
                .tls(move |fcx| {
                    config
                        .get_or_init(|| {
                            let (config, not_before, not_after) = ca
                                .config(fcx, &name)
                                .expect("a certificate for an admitted name");
                            fcx.record(
                                Event::new("adaptive", "cert")
                                    .summary(format!("a certificate for {name}"))
                                    .field("host", name.as_str())
                                    .field("not_before", not_before)
                                    .field("not_after", not_after),
                            );
                            config
                        })
                        .clone()
                }),
        )
    };
    let hosts: Vec<_> = names
        .iter()
        .filter_map(|name| site_for(name).map(|site| site.into_host(name)))
        .collect();
    let mut net = web::Sites::new(site_for).ipv4_only().into_net();
    for host in hosts {
        net = net.add_host(host);
    }
    net.start(fcx, attachments)?;
    Ok(())
}

/// Seconds since the epoch.
pub fn secs(t: SystemTime) -> f64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Starts backend.py and waits for its first line. Returns that line and
/// the running backend. [`watch_backend`] makes the world exit with it.
pub fn start_backend(args: &Args) -> fictionet::Result<(Value, std::process::Child)> {
    let mut child = Command::new("python3")
        .arg("backend.py")
        .arg(args.backend_port.to_string())
        .current_dir(&args.backend)
        .env("PYTHONUNBUFFERED", "1")
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| fictionet::Error::msg(format!("cannot start backend.py: {e}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| fictionet::Error::msg("no backend stdout"))?;
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line)?;
    if line.trim().is_empty() {
        let status = child.wait()?;
        return Err(fictionet::Error::msg(format!(
            "backend.py exited before it was ready ({status})"
        )));
    }
    Ok((serde_json::from_str(&line)?, child))
}

/// If the backend exits, the world exits too, so the container stops
/// instead of serving errors.
pub fn watch_backend(mut child: std::process::Child) {
    std::thread::spawn(move || {
        let status = child.wait();
        eprintln!("adaptive-web-world: backend.py exited ({status:?}); stopping");
        std::process::exit(1);
    });
}

/// The fixed addresses in the backend's first line.
pub fn fixed_addresses(
    backend: &Value,
) -> fictionet::Result<HashMap<String, (Ipv4Addr, &'static str)>> {
    let mut out = HashMap::new();
    for (host, entry) in backend["addresses"]
        .as_object()
        .ok_or_else(|| fictionet::Error::msg("backend sent no addresses"))?
    {
        let addr: Ipv4Addr = entry["addr"]
            .as_str()
            .ok_or_else(|| fictionet::Error::msg("bad address"))?
            .parse()?;
        let why = if entry["why"] == "seed" {
            "seed"
        } else {
            "search engine"
        };
        out.insert(host.clone(), (addr, why));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_that_could_be_on_the_internet_get_a_site() {
        for name in [
            "example.com",
            "www.halvardsystems.com",
            "a-b.co.uk",
            "xn--bcher-kva.xn--p1ai",
            "x.io",
        ] {
            assert_eq!(admit(name), Ok(()), "{name}");
        }
        for (name, why) in [
            ("rw-desktop", "single label"),
            ("printer.local", "reserved or private top-level domain"),
            ("db.internal", "reserved or private top-level domain"),
            (
                "4.3.2.1.in-addr.arpa",
                "reserved or private top-level domain",
            ),
            ("foo.test", "reserved or private top-level domain"),
            ("1.2.3.4", "not a top-level domain"),
            ("_dmarc.example.com", "not a host name"),
            ("-bad.com", "not a host name"),
        ] {
            assert_eq!(admit(name), Err(why), "{name}");
        }
    }

    #[test]
    fn the_world_starts_on_the_seeds_day() {
        let start = time::OffsetDateTime::from(world_start("2026-03-14").unwrap());
        assert_eq!(
            (start.year(), start.month() as u8, start.day()),
            (2026, 3, 14)
        );
        assert!(world_start("2026-02-30").is_err());
        assert!(world_start("2026-257-01").is_err());
        assert!(world_start("2026-01-257").is_err());
        assert!(
            world_start("14/03/2026")
                .unwrap_err()
                .to_string()
                .contains("not a YYYY-MM-DD date")
        );
    }

    #[test]
    fn pool_addresses_are_distinct_and_recorded() {
        let dir = std::env::temp_dir().join(format!("adaptive-web-addr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("addresses.jsonl");
        let _ = std::fs::remove_file(&file);
        let fixed = HashMap::from([(
            "www.google.com".to_owned(),
            (Ipv4Addr::new(142, 250, 180, 4), "search engine"),
        )]);
        let a = Addresses::new(fixed.clone(), Some(&file)).unwrap();
        assert_eq!(
            a.assign("www.google.com"),
            (Ipv4Addr::new(142, 250, 180, 4), "search engine")
        );
        let mut seen = HashSet::new();
        for i in 0..2000 {
            let (addr, why) = a.assign(&format!("host{i}.com"));
            assert_eq!(why, "pool");
            assert!(seen.insert(addr), "{addr} given twice");
        }
        let first = a.assign("host0.com").0;
        drop(a);
        let again = Addresses::new(fixed, Some(&file)).unwrap();
        assert_eq!(again.assign("host0.com"), (first, "recorded"));
        assert!(!seen.contains(&again.assign("new.com").0));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
