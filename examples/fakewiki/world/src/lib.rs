//! The FakeWiki world on Fictionet.
//!
//! ```text
//! fakewiki-world --socket /run/fictionet/sock/world.sock --ca-dir /app/ca \
//!     --backend /app/backend --backend-port 8080 \
//!     --state-dir /var/lib/fictionet --ready /run/fictionet/ready
//! ```
//!
//! - **Content**: FakeWiki's Python `sites.py`, unchanged, runs as a small
//!   HTTP server on 127.0.0.1 (`backend.py`, started here). Every FakeWiki
//!   site's handler forwards to it ([`content`]).
//! - **Network**: `web::Sites`. Every FakeWiki host is pinned to its
//!   FakeWiki address with `Site::at`; every other name gets NXDOMAIN, and
//!   every other address "host unreachable".
//! - **TLS**: one leaf certificate per host, made here at start with
//!   rcgen and signed by the CA that `ca.py` made when the image was built.
//! - **Ground truth**: `state.json` and `log.jsonl` in `--state-dir`, in
//!   main.py's formats, and the ready file. The log is written from the
//!   network's events ([`events`]).

pub mod content;
pub mod events;
pub mod log;

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fictionet::stdlib::{ip, tls, web};
use fictionet::{Attacher, Cx, End, Interface, Packet};

/// The gateway, where `Sites` runs DNS (its default subnet is 10.0.0.0/24).
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
use rcgen::{CertificateParams, DnType, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::Value;

use crate::content::Content;
use crate::log::Log;

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
            "--backend-port" => a.backend_port = value.parse().map_err(|e| format!("--backend-port: {e}"))?,
            "--state-dir" => a.state_dir = value.into(),
            "--ready" => a.ready = value.into(),
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    Ok(a)
}

/// Builds the network: one site per FakeWiki host at its own address, with
/// its certificate, every request logged. `leaves` holds each host's
/// certificate chain and key. Returns at once; the network runs in `cx`'s
/// region.
pub fn serve(
    cx: &Cx,
    hosts: &HashMap<String, Ipv4Addr>,
    leaves: HashMap<String, Leaf>,
    content: Content,
    log: Arc<Log>,
    attachments: fictionet::Attachments,
) -> fictionet::Result {
    let mut configs = HashMap::new();
    for (host, (chain, key)) in leaves {
        let config = tls::config_builder(cx, SystemTime::now(), rustls::crypto::ring::default_provider())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, key)?;
        configs.insert(host, Arc::new(config));
    }
    let site_hosts = hosts.clone();
    events::log_to(cx, hosts.clone(), log);
    web::Sites::new(move |host: &str| {
        let addr = *site_hosts.get(host)?;
        let config = configs.get(host)?.clone();
        Some(web::Site::new(content.clone()).at(addr).tls(move |_| config.clone()))
    })
    // The agent's sandbox has IPv6 off, and the sites keep their real
    // IPv4 addresses only.
    .ipv4_only()
    .serve(cx, attachments)?;
    Ok(())
}

/// Seconds since the epoch.
pub fn secs(t: SystemTime) -> f64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
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
        .map_err(|e| format!("cannot start backend.py: {e}"))?;
    let stdout = child.stdout.take().ok_or("no backend stdout")?;
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line)?;
    if line.trim().is_empty() {
        let status = child.wait()?;
        return Err(format!("backend.py exited before it was ready ({status})").into());
    }
    Ok((serde_json::from_str(&line)?, child))
}

/// If the backend exits, the world exits too, so the container stops
/// instead of serving errors.
pub fn watch_backend(mut child: std::process::Child) {
    std::thread::spawn(move || {
        let status = child.wait();
        eprintln!("fakewiki-world: backend.py exited ({status:?}); stopping");
        std::process::exit(1);
    });
}

pub type Leaf = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

/// One certificate per host, like ca.py's `_mint`: the host as CN and SAN,
/// valid from a day ago for 90 days, for server auth, signed by the CA.
/// The chain sent is the leaf, then the CA, as ca.py sent it.
pub fn issue_leaves<'a>(ca_dir: &Path, hosts: impl Iterator<Item = &'a String>) -> fictionet::Result<HashMap<String, Leaf>> {
    let ca_pem = std::fs::read_to_string(ca_dir.join("ca.pem"))?;
    let ca_key = KeyPair::from_pem(&std::fs::read_to_string(ca_dir.join("ca.key"))?)?;
    let ca_der = CertificateDer::from_pem_slice(ca_pem.as_bytes())?;
    // The CA's own fields (name, key identifier), to sign leaves with.
    let issuer = CertificateParams::from_ca_cert_pem(&ca_pem)?.self_signed(&ca_key)?;
    let now = time::OffsetDateTime::now_utc();
    let mut out = HashMap::new();
    for host in hosts {
        let mut params = CertificateParams::new(vec![host.clone()])?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, host.chars().take(64).collect::<String>());
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(90);
        params.is_ca = IsCa::ExplicitNoCa;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &issuer, &ca_key)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        out.insert(host.clone(), (vec![cert.der().clone(), ca_der.clone()], key));
    }
    Ok(out)
}

/// The address the world's own lookups come from. It is free again once
/// they are done.
const LOOKUP_FROM: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 254), 40000);

/// Asks the gateway's DNS for every host, as a sandbox would, and waits
/// for every answer. This makes `Sites` run its callback for each host, so
/// each site and its address exist before the first sandbox attaches.
pub async fn look_up_all(cx: &Cx, attacher: &Attacher, hosts: &[String]) -> fictionet::Result {
    let mut end: End = attacher.attach(events::LOOKUPS).map_err(|e| format!("lookups: {e}"))?;
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
            return Err(format!("no DNS answer for {left:?}").into());
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
        if let Some(host) = waiting.remove(&id) {
            if rcode != 0 || answers != 1 {
                return Err(format!("DNS for {host}: rcode {rcode}, {answers} answers").into());
            }
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
    p.extend_from_slice(&[0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0x40, 0, 64, 17, 0, 0]);
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

