//! The adaptive web on Fictionet: every name resolves, every HTTPS host has
//! a certificate, and every page is made the first time it is asked for.
//!
//! ```text
//! adaptive-web-world --seed halvard-cve --socket /run/fictionet/sock/world.sock \
//!     --ca-dir /app/ca --state-dir /var/lib/fictionet --ready /run/fictionet/ready
//! ```
//!
//! - **Names** ([`admit`]): any name that could exist on the internet gets
//!   a site the first time it is looked up. Single-label names and the
//!   reserved and private top-level domains get NXDOMAIN.
//! - **Addresses** ([`Addresses`]): the search engines and the seed's
//!   hosts have fixed addresses. Every other host gets the next free
//!   address from two public-looking pools, in the order hosts are first
//!   looked up, and keeps it for the run. Each assignment is appended to
//!   the store's `addresses.jsonl`, so a later run, or another world, on
//!   the same store gives every host the same address. Unreadable or
//!   corrupt history fails startup. An append failure refuses the host and
//!   fails finalization.
//! - **TLS** ([`Ca`]): a host's certificate is made at its first handshake
//!   and signed by a seeded CA whose public root is written at startup.
//! - **Dates** ([`world_start`]): the world's clock starts on the seed's
//!   date, so every response's `Date` header is in the scenario, and each
//!   certificate was issued shortly before it.
//! - **Pages** ([`pages`]): searches and pages, made by the offline
//!   generator or a model, kept in a store, and checked for consistency
//!   with what the world already said. [`handler`] answers every site from
//!   them.
//! - **Ground truth**: `state.json` and `log.jsonl` in `--state-dir`, the
//!   ready file, and the store. The log is written from the run's events
//!   ([`events`]).
//!
//! An in-process [`World`] keeps its addresses, pages and CA in memory.
//! This example sends its log to standard output, and turns generation off
//! once the network is up.
//!
//! ```no_run
//! use std::sync::Arc;
//! use adaptive_web_world::{World, world_start};
//! use adaptive_web_world::{events::LogObserver, search::Searches};
//! use adaptive_web_world::pages::{Command, Seed};
//! use example_common::log::Log;
//! use fictionet::events::Fanout;
//!
//! # fn main() -> fictionet::Result {
//! let seed = Seed::builtin("halvard-cve")?;
//! let start = world_start(&seed.date)?;
//! let searches = Arc::new(Searches::from_seed(&seed));
//! let log = Arc::new(Log::new(Box::new(std::io::stdout()), &[], |s| s));
//! let observer = Arc::new(Fanout::new(vec![
//!     searches.clone(),
//!     Arc::new(LogObserver { log: log.clone() }),
//! ]));
//! let options = fictionet::RunOptions::new(fictionet::Seed::from_u64(7))
//!     .observer(observer);
//! let output = log.clone();
//! fictionet::block_on(fictionet::run(options, |cx| async move {
//!     let world = World::new(&cx, seed, start)?;
//!     let root_pem = world.ca.cert_pem();
//!     let (attacher, attachments) = fictionet::attachments();
//!     world.serve(&cx, log.clone(), attachments)?;
//!     // Start a guest with root_pem and attacher here.
//!     let pages = &world.pages;
//!     let applied = pages.apply(&cx, Command::SetGeneration {
//!         generate: false,
//!         expected_revision: pages.generation().revision,
//!     }).unwrap();
//!     assert_eq!(applied.revision, 1);
//!     cx.cancelled().await;
//!     Ok(())
//! }))?;
//! output.finish()?;
//! # Ok(())
//! # }
//! ```

pub mod events;
mod files;
pub mod handler;
pub mod pages;
pub mod route;
pub mod search;

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

use fictionet::Cx;
use fictionet::stdlib::services::tls::ServerConfig;
use fictionet::stdlib::web;
use serde::{Deserialize, Serialize};

use example_common::log::Log;
use files::{Appended, FileLock};
use pages::Pages;

/// The gateway, where `Sites` runs DNS (its default subnet is 10.0.0.0/24).
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

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

/// Every host's address: fixed ones (search engines, the seed), ones
/// recorded on the same store, then the next free one from the pools.
/// Recorded history must be readable and consistent. New addresses are
/// published only after their records have been written. Worlds sharing a
/// store assign under `store.lock`, after reading what the others
/// recorded, so each address goes to one host.
pub struct Addresses {
    fixed: Vec<String>,
    inner: Mutex<Inner>,
}

struct Inner {
    by_host: HashMap<String, (Ipv4Addr, &'static str)>,
    used: HashSet<Ipv4Addr>,
    /// The host each recorded address was recorded for.
    recorded: HashMap<Ipv4Addr, String>,
    next: u32,
    failure: Option<(io::ErrorKind, String)>,
    /// The store's `addresses.jsonl` and `store.lock`, for a world with a
    /// store.
    record: Option<Record>,
}

struct Record {
    lines: Appended,
    lock: std::fs::File,
}

/// One line of `addresses.jsonl`.
#[derive(Serialize, Deserialize)]
struct Assigned {
    host: String,
    addr: Ipv4Addr,
}

impl Inner {
    /// Applies what this and other worlds have appended to
    /// `addresses.jsonl` since it was last read. The caller holds
    /// `store.lock`.
    fn read_on(&mut self) -> io::Result<()> {
        let Some(record) = &mut self.record else {
            return Ok(());
        };
        let (by_host, used, recorded) = (&mut self.by_host, &mut self.used, &mut self.recorded);
        record.lines.read_on(true, |line: Assigned| {
            let Assigned { host, addr } = line;
            if let Some(previous) = recorded.get(&addr)
                && *previous != host
            {
                return Err(format!("{addr} is recorded for both {previous} and {host}"));
            }
            recorded.insert(addr, host.clone());
            if let Some((previous, _)) = by_host.get(&host) {
                if *previous != addr {
                    return Err(format!("{host} has both {previous} and {addr}"));
                }
                return Ok(());
            }
            if !used.insert(addr) {
                return Err(format!("{addr} is already assigned to another host"));
            }
            by_host.insert(host, (addr, "recorded"));
            Ok(())
        })
    }
}

/// The pools: two /16s that many ordinary sites live in. Addresses
/// alternate between them, and step through each one in a scattered
/// order, so hosts looked up one after another do not get neighbouring
/// addresses.
const POOLS: [[u8; 2]; 2] = [[104, 21], [172, 67]];

impl Addresses {
    /// `fixed` maps hosts to addresses with the reason (`"search engine"`,
    /// `"seed"`). With `store`, the store's directory, its
    /// `addresses.jsonl` is read first, as `"recorded"`, and new
    /// assignments are appended to it. A missing file starts a new record.
    /// Other read errors, invalid records and conflicting assignments fail
    /// construction.
    pub fn new(
        fixed: HashMap<String, (Ipv4Addr, &'static str)>,
        store: Option<&Path>,
    ) -> io::Result<Addresses> {
        let mut names: Vec<_> = fixed.keys().cloned().collect();
        names.sort();
        let record = store
            .map(|root| {
                Ok::<_, io::Error>(Record {
                    lines: Appended::open(&root.join("addresses.jsonl"))?,
                    lock: files::store_lock(root)?,
                })
            })
            .transpose()?;
        let mut inner = Inner {
            used: fixed.values().map(|(a, _)| *a).collect(),
            by_host: fixed,
            recorded: HashMap::new(),
            next: 0,
            failure: None,
            record,
        };
        let held = (inner.record.as_ref())
            .map(|r| FileLock::take(&r.lock))
            .transpose()?;
        inner.read_on()?;
        drop(held);
        Ok(Addresses {
            fixed: names,
            inner: Mutex::new(inner),
        })
    }

    /// The address of `host`, and why it has that one: its fixed or
    /// recorded address, or the next free one from the pools (`"pool"`).
    /// Returns `Ok(None)` after one full traversal if the pools are exhausted.
    /// An append failure returns an error without publishing the address.
    /// Later calls for unrecorded hosts return the same error; fixed and
    /// already recorded hosts still answer.
    pub fn assign(&self, host: &str) -> io::Result<Option<(Ipv4Addr, &'static str)>> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(found) = inner.by_host.get(host) {
            return Ok(Some(*found));
        }
        if let Some((kind, reason)) = &inner.failure {
            return Err(io::Error::new(*kind, reason.clone()));
        }
        let _held = (inner.record.as_ref())
            .map(|r| FileLock::take(&r.lock))
            .transpose()?;
        inner.read_on()?;
        if let Some(found) = inner.by_host.get(host) {
            return Ok(Some(*found));
        }
        let Some(addr) = (0..131_072).find_map(|_| {
            let n = inner.next;
            inner.next = (inner.next + 1) % 131_072;
            let [a, b] = POOLS[(n % 2) as usize];
            // An odd multiplier makes this a permutation of 0..65536.
            let offset = ((n / 2).wrapping_mul(40503).wrapping_add(12345)) & 0xffff;
            let (c, d) = ((offset >> 8) as u8, offset as u8);
            let addr = Ipv4Addr::new(a, b, c, d);
            if d != 0 && d != 255 && !inner.used.contains(&addr) {
                Some(addr)
            } else {
                None
            }
        }) else {
            return Ok(None);
        };
        let line = Assigned {
            host: host.to_owned(),
            addr,
        };
        let appended = match &mut inner.record {
            Some(record) => record.lines.append(&line),
            None => Ok(()),
        };
        if let Err(e) = appended {
            inner.failure = Some((e.kind(), e.to_string()));
            return Err(e);
        }
        inner.used.insert(addr);
        inner.recorded.insert(addr, host.to_owned());
        inner.by_host.insert(host.to_owned(), (addr, "pool"));
        Ok(Some((addr, "pool")))
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
    issuer: fictionet::stdlib::services::ca::Ca,
    start: SystemTime,
}

impl Ca {
    /// Makes a seeded CA and writes its public certificate for the agent.
    pub fn new(fcx: &Cx, dir: &Path, start: SystemTime) -> fictionet::Result<Ca> {
        let ca = Self::in_memory(fcx, start)?;
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("ca.pem"), ca.cert_pem())?;
        Ok(ca)
    }

    /// Makes a seeded CA without writing files, for an in-process world.
    pub fn in_memory(fcx: &Cx, start: SystemTime) -> fictionet::Result<Ca> {
        Ok(Ca {
            issuer: fictionet::stdlib::services::ca::Ca::new(fcx, "Internet Security Root CA")?,
            start,
        })
    }

    /// Returns the public root certificate in PEM format for a guest to trust.
    pub fn cert_pem(&self) -> String {
        self.issuer.cert_pem()
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
            fictionet::stdlib::protocols::x509::Validity {
                not_before: fictionet::stdlib::protocols::x509::Time::from_unix(
                    not_before.unix_timestamp(),
                )?,
                not_after: fictionet::stdlib::protocols::x509::Time::from_unix(
                    not_after.unix_timestamp(),
                )?,
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
/// handshake, every request answered by `pages` and logged, and every
/// response dated from `start`, the world's date at the start of the run.
/// Returns at once; the network runs in `fcx`'s region.
pub fn serve(
    fcx: &Cx,
    addresses: Arc<Addresses>,
    ca: Arc<Ca>,
    pages: Arc<Pages>,
    log: Arc<Log>,
    start: SystemTime,
    attachments: fictionet::Attachments,
) -> fictionet::Result {
    net(fcx, addresses, ca, pages, log, start, |_| None).start(fcx, attachments)
}

/// Builds an unstarted network, giving the caller first choice of each name.
/// Claimed names bypass adaptive addresses, certificates and site events.
pub fn net(
    fcx: &Cx,
    addresses: Arc<Addresses>,
    ca: Arc<Ca>,
    pages: Arc<Pages>,
    log: Arc<Log>,
    start: SystemTime,
    forward: impl Fn(&str) -> Option<web::Site> + Send + Sync + 'static,
) -> fictionet::stdlib::world::net::Net {
    let handler = handler::Handler::new(fcx, pages);
    log.attach(fcx);
    let names = addresses.fixed.clone();
    let world = fcx.clone();
    let site_for = move |host: &str| {
        if let Some(site) = forward(host) {
            return Some(site);
        }
        if let Err(why) = admit(host) {
            world.emit("adaptive", "refused", |event| {
                event
                    .summary(format_args!("{host}: {why}"))
                    .field("host", host)
                    .field("why", why)
            });
            return None;
        }
        let (addr, why) = match addresses.assign(host) {
            Ok(Some(assigned)) => assigned,
            Ok(None) => {
                world.emit("adaptive", "refused", |event| {
                    event
                        .field("host", host)
                        .field("why", "address pool exhausted")
                });
                return None;
            }
            Err(e) => {
                let why = format!("cannot record the address: {e}");
                world.emit("adaptive", "refused", |event| {
                    event.field("host", host).field("why", why.as_str())
                });
                log.fail(why);
                return None;
            }
        };
        world.emit("adaptive", "site", |event| {
            event
                .summary(format_args!("{host} at {addr} ({why})"))
                .field("host", host)
                .field("addr", addr.to_string())
                .field("why", why)
        });
        let (ca, name) = (ca.clone(), host.to_owned());
        let config: Arc<OnceLock<Arc<ServerConfig>>> = Arc::new(OnceLock::new());
        Some(
            web::Site::new(handler.clone())
                .date(start)
                .at(addr)
                .tls_with(move |fcx| {
                    config
                        .get_or_init(|| {
                            let (config, not_before, not_after) = ca
                                .config(fcx, &name)
                                .expect("a certificate for an admitted name");
                            fcx.emit("adaptive", "cert", |event| {
                                event
                                    .summary(format_args!("a certificate for {name}"))
                                    .field("host", name.as_str())
                                    .field("not_before", not_before)
                                    .field("not_after", not_after)
                            });
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
    net
}

/// A world kept in memory, made from one seed: a new CA, the seed's fixed
/// addresses and its pages with the offline generator, dated from `start`,
/// usually [`world_start`] of the seed's date. The executable keeps a store
/// and may use a model instead.
pub struct World {
    pub ca: Arc<Ca>,
    pub addresses: Arc<Addresses>,
    pub pages: Arc<Pages>,
    pub start: SystemTime,
}

impl World {
    pub fn new(fcx: &Cx, seed: pages::Seed, start: SystemTime) -> fictionet::Result<World> {
        Ok(World {
            ca: Arc::new(Ca::in_memory(fcx, start)?),
            addresses: Arc::new(Addresses::new(seed.fixed_addresses(), None)?),
            pages: Arc::new(Pages::new(seed)),
            start,
        })
    }

    /// The world's unstarted network, as [`net`] builds it.
    pub fn net(
        &self,
        fcx: &Cx,
        log: Arc<Log>,
        forward: impl Fn(&str) -> Option<web::Site> + Send + Sync + 'static,
    ) -> fictionet::stdlib::world::net::Net {
        net(
            fcx,
            self.addresses.clone(),
            self.ca.clone(),
            self.pages.clone(),
            log,
            self.start,
            forward,
        )
    }

    /// Starts the world's network, as [`serve`] does.
    pub fn serve(
        &self,
        fcx: &Cx,
        log: Arc<Log>,
        attachments: fictionet::Attachments,
    ) -> fictionet::Result {
        self.net(fcx, log, |_| None).start(fcx, attachments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("adaptive-web-{name}-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn corrupt_record() {
        let dir = test_dir("corrupt-record");
        let path = dir.join("addresses.jsonl");
        let fixed = HashMap::from([(
            "fixed.com".into(),
            (Ipv4Addr::new(142, 250, 180, 4), "seed"),
        )]);
        let first = "{\"host\":\"first.com\",\"addr\":\"104.21.48.57\"}\n";
        for bad in [
            "garbage",
            "",
            "null",
            "[]",
            "{}",
            r#"{"host":1,"addr":"104.21.48.58"}"#,
            r#"{"host":"second.com","addr":"not an address"}"#,
            r#"{"host":"first.com","addr":"104.21.48.58"}"#,
            r#"{"host":"second.com","addr":"104.21.48.57"}"#,
            r#"{"host":"fixed.com","addr":"104.21.48.58"}"#,
            r#"{"host":"second.com","addr":"142.250.180.4"}"#,
            r#"{"host":"partial.com","addr":"104.21."#,
        ] {
            std::fs::write(&path, format!("{first}{bad}\n")).unwrap();
            let error = Addresses::new(fixed.clone(), Some(&dir)).err().unwrap();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{bad}");
            let reason = error.to_string();
            assert!(reason.contains(path.to_str().unwrap()), "{reason}");
            assert!(reason.contains("line 2"), "{reason}");
        }
        std::fs::write(&path, format!("{first}{first}")).unwrap();
        let addresses = Addresses::new(fixed, Some(&dir)).unwrap();
        assert_eq!(
            addresses.assign("first.com").unwrap(),
            Some((Ipv4Addr::new(104, 21, 48, 57), "recorded"))
        );
        let fixed = HashMap::from([
            ("first.com".into(), (Ipv4Addr::new(104, 21, 48, 57), "seed")),
            (
                "second.com".into(),
                (Ipv4Addr::new(104, 21, 48, 57), "seed"),
            ),
        ]);
        assert!(Addresses::new(fixed.clone(), Some(&dir)).is_ok());
        std::fs::write(
            &path,
            format!("{first}{}", first.replace("first.com", "second.com")),
        )
        .unwrap();
        let error = Addresses::new(fixed, Some(&dir)).err().unwrap();
        assert!(error.to_string().contains("line 2"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Worlds on one store read what the others recorded before they
    /// assign, so each address goes to one host and every world agrees.
    #[test]
    fn worlds_sharing_a_record_agree() {
        let dir = test_dir("shared-record");
        let a = Addresses::new(HashMap::new(), Some(&dir)).unwrap();
        let b = Addresses::new(HashMap::new(), Some(&dir)).unwrap();
        let first = a.assign("first.com").unwrap().unwrap().0;
        let second = b.assign("second.com").unwrap().unwrap().0;
        assert_ne!(first, second);
        assert_eq!(b.assign("first.com").unwrap(), Some((first, "recorded")));
        assert_eq!(a.assign("second.com").unwrap(), Some((second, "recorded")));
        let later = Addresses::new(HashMap::new(), Some(&dir)).unwrap();
        assert_eq!(
            later.assign("first.com").unwrap(),
            Some((first, "recorded"))
        );
        assert_eq!(
            later.assign("second.com").unwrap(),
            Some((second, "recorded"))
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unreadable_record() {
        let dir = test_dir("unreadable-record");
        let path = dir.join("addresses.jsonl");
        std::fs::write(&path, [0xff]).unwrap();
        let error = Addresses::new(HashMap::new(), Some(&dir)).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains(path.to_str().unwrap()));
        assert_eq!(std::fs::read(&path).unwrap(), [0xff]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    struct FailingWriter(Arc<AtomicUsize>);
    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other("injected address write failure"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Addresses on a store in `dir` that append to `writer`.
    fn writing_to(
        fixed: HashMap<String, (Ipv4Addr, &'static str)>,
        dir: &Path,
        writer: impl Write + Send + 'static,
    ) -> Addresses {
        let addresses = Addresses::new(fixed, Some(dir)).unwrap();
        let mut inner = addresses.inner.lock().unwrap();
        inner
            .record
            .as_mut()
            .unwrap()
            .lines
            .set_writer(Box::new(writer));
        drop(inner);
        addresses
    }

    #[test]
    fn failing_writer() {
        let dir = test_dir("failing-writer");
        let fixed_addr = Ipv4Addr::new(142, 250, 180, 4);
        let recorded_addr = Ipv4Addr::new(172, 67, 48, 57);
        let fixed = HashMap::from([("fixed.com".into(), (fixed_addr, "seed"))]);
        std::fs::write(
            dir.join("addresses.jsonl"),
            "{\"host\":\"recorded.com\",\"addr\":\"172.67.48.57\"}\n",
        )
        .unwrap();
        let writes = Arc::new(AtomicUsize::new(0));
        let addresses = writing_to(fixed, &dir, FailingWriter(writes.clone()));
        let error = addresses.assign("first.com").unwrap_err();
        assert_eq!(error.to_string(), "injected address write failure");
        for host in ["first.com", "second.com"] {
            let later = addresses.assign(host).unwrap_err();
            assert_eq!(later.kind(), error.kind());
            assert_eq!(later.to_string(), error.to_string());
        }
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        assert_eq!(
            addresses.assign("fixed.com").unwrap(),
            Some((fixed_addr, "seed"))
        );
        assert_eq!(
            addresses.assign("recorded.com").unwrap(),
            Some((recorded_addr, "recorded"))
        );
        let inner = addresses.inner.lock().unwrap();
        assert_eq!(inner.by_host.len(), 2);
        assert!(!inner.by_host.contains_key("first.com"));
        assert_eq!(inner.used, HashSet::from([fixed_addr, recorded_addr]));
        drop(inner);
        std::fs::remove_dir_all(dir).unwrap();
    }

    struct PartialWriter {
        file: std::fs::File,
        wrote: bool,
    }
    impl Write for PartialWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.wrote {
                return Err(io::Error::other("injected partial append failure"));
            }
            self.wrote = true;
            self.file.write(&bytes[..bytes.len() / 2])
        }
        fn flush(&mut self) -> io::Result<()> {
            self.file.flush()
        }
    }

    #[test]
    fn restart_after_failed_append() {
        let dir = test_dir("failed-append");
        let path = dir.join("addresses.jsonl");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        let addresses = writing_to(HashMap::new(), &dir, PartialWriter { file, wrote: false });
        assert!(addresses.assign("first.com").is_err());
        assert!(addresses.inner.lock().unwrap().by_host.is_empty());
        let partial = std::fs::read(&path).unwrap();
        assert!(!partial.is_empty());
        assert!(addresses.assign("second.com").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), partial);
        drop(addresses);
        let error = Addresses::new(HashMap::new(), Some(&dir)).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let reason = error.to_string();
        assert!(reason.contains(path.to_str().unwrap()), "{reason}");
        assert!(reason.contains("line 1"), "{reason}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The store's lock is held while `addresses.jsonl` is read, so every
    /// line in it is finished. One without its newline was cut short.
    #[test]
    fn a_record_without_its_newline_is_corrupt() {
        let dir = test_dir("record-without-newline");
        let path = dir.join("addresses.jsonl");
        let first = r#"{"host":"first.com","addr":"104.21.48.57"}"#;
        std::fs::write(&path, first).unwrap();
        let error = Addresses::new(HashMap::new(), Some(&dir)).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let reason = error.to_string();
        assert!(
            reason.contains("line 1: the line is unfinished"),
            "{reason}"
        );
        std::fs::write(&path, format!("{first}\n")).unwrap();
        let addresses = Addresses::new(HashMap::new(), Some(&dir)).unwrap();
        assert_eq!(
            addresses.assign("first.com").unwrap(),
            Some((Ipv4Addr::new(104, 21, 48, 57), "recorded"))
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn serve_latches_a_failed_record() {
        use fictionet::stdlib::{
            protocols::dns::{op::ResponseCode, rr::RecordType},
            world::sandbox::machine,
        };

        let dir = test_dir("serve-failed-record");
        let path = dir.join("log.jsonl");
        let store = dir.join("store");
        std::fs::create_dir(&store).unwrap();
        let log = Arc::new(Log::new(
            Box::new(std::fs::File::create(&path).unwrap()),
            &[],
            |s| s,
        ));
        let output = log.clone();
        fictionet::block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1))
                .observer(Arc::new(events::LogObserver { log: log.clone() })),
            move |fcx| async move {
                let failing = FailingWriter(Arc::new(AtomicUsize::new(0)));
                let addresses = Arc::new(writing_to(HashMap::new(), &store, failing));
                let start = SystemTime::UNIX_EPOCH;
                let ca = Arc::new(Ca {
                    issuer: fictionet::stdlib::services::ca::Ca::new(&fcx, "Test CA")?,
                    start,
                });
                let (attacher, attachments) = fictionet::attachments();
                let seed = pages::Seed::builtin("halvard-cve")?;
                serve(
                    &fcx,
                    addresses.clone(),
                    ca,
                    Arc::new(Pages::new(seed)),
                    output.clone(),
                    start,
                    attachments,
                )?;
                let m = machine(&fcx, attacher.attach("agent")?, Ipv4Addr::new(10, 0, 0, 2));
                let answer = m
                    .lookup(&fcx, GATEWAY.into(), "new.com", RecordType::A)
                    .await?;
                assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
                assert!(answer.answers.is_empty());
                assert!(addresses.inner.lock().unwrap().by_host.is_empty());
                assert!(output.health().is_err());
                fcx.cancel();
                Ok(())
            },
        ))
        .unwrap();
        assert_eq!(
            log.health().unwrap_err().to_string(),
            "cannot record the address: injected address write failure"
        );
        assert!(log.finish().is_err());
        let lines: Vec<Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(lines.iter().any(|line| line["type"] == "refused"
            && line["host"] == "new.com"
            && line["why"] == "cannot record the address: injected address write failure"));
        assert!(lines.iter().all(|line| line["type"] != "site"));
        std::fs::remove_dir_all(dir).unwrap();
    }

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
    fn exhausted_pool_refuses_without_allocating_or_recording() {
        let a = Addresses::new(HashMap::new(), None).unwrap();
        {
            let mut inner = a.inner.lock().unwrap();
            for [first, second] in POOLS {
                for third in 0..=255 {
                    for fourth in 1..=254 {
                        inner
                            .used
                            .insert(Ipv4Addr::new(first, second, third, fourth));
                    }
                }
            }
        }
        assert_eq!(a.assign("full.com").unwrap(), None);
        assert!(a.inner.lock().unwrap().by_host.is_empty());
        let freed = Ipv4Addr::new(104, 21, 0, 1);
        a.inner.lock().unwrap().used.remove(&freed);
        assert_eq!(a.assign("last.com").unwrap(), Some((freed, "pool")));
        assert_eq!(a.assign("last.com").unwrap(), Some((freed, "pool")));
        assert_eq!(a.assign("full.com").unwrap(), None);
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
        let a = Addresses::new(fixed.clone(), Some(&dir)).unwrap();
        assert_eq!(
            a.assign("www.google.com").unwrap(),
            Some((Ipv4Addr::new(142, 250, 180, 4), "search engine"))
        );
        let mut seen = HashSet::new();
        for i in 0..2000 {
            let (addr, why) = a.assign(&format!("host{i}.com")).unwrap().unwrap();
            assert_eq!(why, "pool");
            assert!(seen.insert(addr), "{addr} given twice");
        }
        let first = a.assign("host0.com").unwrap().unwrap().0;
        drop(a);
        let again = Addresses::new(fixed, Some(&dir)).unwrap();
        assert_eq!(
            again.assign("host0.com").unwrap(),
            Some((first, "recorded"))
        );
        assert!(!seen.contains(&again.assign("new.com").unwrap().unwrap().0));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
