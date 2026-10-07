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
//!   and signed by the CA that `ca.py` made when the image was built.
//! - **Content** ([`content`]): every site forwards to the Python backend
//!   on 127.0.0.1, which makes, stores and serves the pages.
//! - **Ground truth**: `state.json` and `log.jsonl` in `--state-dir`, the
//!   ready file, and the store. The log is written from the run's events
//!   ([`events`]).

pub mod content;
pub mod events;
pub mod log;

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::future::{Future, poll_fn};
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::Poll;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fictionet::events::Event;
use fictionet::stdlib::tls::ServerConfig;
use fictionet::stdlib::{ip, tls, web};
use fictionet::{Attacher, Cx, End, Interface, Packet};
use rcgen::{CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};

use crate::content::Content;
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

/// The world's certificate authority, which signs a certificate for each
/// host at its first handshake.
pub struct Ca {
    issuer: rcgen::Certificate,
    key: KeyPair,
    der: CertificateDer<'static>,
}

impl Ca {
    /// Loads `ca.pem` and `ca.key` from `dir`, as `ca.py` leaves them.
    pub fn load(dir: &Path) -> fictionet::Result<Ca> {
        let pem = std::fs::read_to_string(dir.join("ca.pem"))?;
        let key = KeyPair::from_pem(&std::fs::read_to_string(dir.join("ca.key"))?)?;
        let der = CertificateDer::from_pem_slice(pem.as_bytes())?.into_owned();
        // The CA's own fields (name, key identifier), to sign leaves with.
        let issuer = CertificateParams::from_ca_cert_pem(&pem)?.self_signed(&key)?;
        Ok(Ca { issuer, key, der })
    }

    /// A certificate for `host`, like ca.py's `_mint`: the host as CN and
    /// SAN, valid from a day ago for 90 days, for server auth. The chain
    /// sent is the leaf, then the CA. Returns the TLS config and the
    /// validity, for the log.
    pub fn config(
        &self,
        cx: &Cx,
        host: &str,
    ) -> fictionet::Result<(Arc<ServerConfig>, String, String)> {
        let now = time::OffsetDateTime::now_utc();
        let mut params = CertificateParams::new(vec![host.to_owned()])?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(
            DnType::CommonName,
            host.chars().take(64).collect::<String>(),
        );
        let (not_before, not_after) = (
            now - time::Duration::days(1),
            now + time::Duration::days(90),
        );
        params.not_before = not_before;
        params.not_after = not_after;
        params.is_ca = IsCa::ExplicitNoCa;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &self.issuer, &self.key)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let config = tls::config_builder(
            cx,
            SystemTime::now(),
            rustls::crypto::ring::default_provider(),
        )
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone(), self.der.clone()], key)?;
        let day = |t: time::OffsetDateTime| {
            format!("{:04}-{:02}-{:02}", t.year(), t.month() as u8, t.day())
        };
        Ok((Arc::new(config), day(not_before), day(not_after)))
    }
}

/// Builds the network: a site for every name [`admit`] lets in, at its
/// address from `addresses`, with a certificate from `ca` made at its first
/// handshake, every request answered by `content` and logged. Returns at
/// once; the network runs in `cx`'s region.
pub fn serve(
    cx: &Cx,
    addresses: Arc<Addresses>,
    ca: Arc<Ca>,
    content: Content,
    log: Arc<Log>,
    attachments: fictionet::Attachments,
) -> fictionet::Result {
    events::log_to(cx, log);
    let world = cx.clone();
    web::Sites::new(move |host: &str| {
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
        Some(web::Site::new(content.clone()).at(addr).tls(move |cx| {
            config
                .get_or_init(|| {
                    let (config, not_before, not_after) = ca
                        .config(cx, &name)
                        .expect("a certificate for an admitted name");
                    cx.record(
                        Event::new("adaptive", "cert")
                            .summary(format!("a certificate for {name}"))
                            .field("host", name.as_str())
                            .field("not_before", not_before)
                            .field("not_after", not_after),
                    );
                    config
                })
                .clone()
        }))
    })
    // The agent's sandbox has IPv6 off.
    .ipv4_only()
    .serve(cx, attachments)?;
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

/// The address the world's own lookups come from. It is free again once
/// they are done.
const LOOKUP_FROM: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 254), 40000);

/// Asks the gateway's DNS for every host, as a sandbox would, and waits
/// for every answer. This makes `Sites` run its callback for each host, so
/// the fixed addresses answer before the first sandbox attaches, also for
/// an agent that connects by address without DNS.
pub async fn look_up_all(cx: &Cx, attacher: &Attacher, hosts: &[String]) -> fictionet::Result {
    let mut end: End = attacher
        .attach(events::LOOKUPS)
        .map_err(|e| fictionet::Error::msg(format!("lookups: {e}")))?;
    let mut waiting: HashMap<u16, &str> = HashMap::new();
    for (i, host) in hosts.iter().enumerate() {
        let id = i as u16 + 1;
        end.send(Packet(dns_query_packet(id, host)));
        waiting.insert(id, host);
    }
    let deadline = cx.now() + Duration::from_secs(10);
    let mut sleep = pin!(cx.sleep_until(deadline));
    while !waiting.is_empty() {
        let packet = poll_fn(|task| {
            if let Poll::Ready(r) = end.poll_recv(cx, task) {
                return Poll::Ready(r.ok());
            }
            match sleep.as_mut().poll(task) {
                Poll::Ready(_) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;
        let Some(packet) = packet else {
            let left: Vec<_> = waiting.values().collect();
            return Err(fictionet::Error::msg(format!("no DNS answer for {left:?}")));
        };
        let p = &packet.0;
        // IPv4 + UDP from the gateway's port 53: id, flags, then counts.
        if p.len() < 28 + 12 || p[9] != 17 {
            continue;
        }
        let ihl = (p[0] & 0x0f) as usize * 4;
        let dns = &p[ihl + 8..];
        let id = u16::from_be_bytes([dns[0], dns[1]]);
        let rcode = dns[3] & 0x0f;
        let answers = u16::from_be_bytes([dns[6], dns[7]]);
        if let Some(host) = waiting.remove(&id)
            && (rcode != 0 || answers != 1)
        {
            return Err(fictionet::Error::msg(format!(
                "DNS for {host}: rcode {rcode}, {answers} answers"
            )));
        }
    }
    Ok(())
}

/// An IPv4/UDP packet with an A query for `name`, from [`LOOKUP_FROM`] to
/// the gateway's port 53. The UDP checksum is left at zero, which IPv4
/// allows.
fn dns_query_packet(id: u16, name: &str) -> Vec<u8> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&id.to_be_bytes());
    dns.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.extend_from_slice(&[0, 0, 1, 0, 1]);

    let udp_len = 8 + dns.len();
    let total = 20 + udp_len;
    let mut p = Vec::with_capacity(total);
    p.extend_from_slice(&[
        0x45,
        0,
        (total >> 8) as u8,
        total as u8,
        0,
        0,
        0x40,
        0,
        64,
        17,
        0,
        0,
    ]);
    p.extend_from_slice(&LOOKUP_FROM.ip().octets());
    p.extend_from_slice(&GATEWAY.octets());
    ip::set_header_checksum(&mut p[..20]);
    p.extend_from_slice(&LOOKUP_FROM.port().wrapping_add(id).to_be_bytes());
    p.extend_from_slice(&53u16.to_be_bytes());
    p.extend_from_slice(&(udp_len as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&dns);
    p
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
