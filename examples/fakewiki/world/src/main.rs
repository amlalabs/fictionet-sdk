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
//!   main.py's formats, and the ready file. The log is written from
//!   `Sites`' events ([`events`]).

mod content;
mod events;
mod log;

use std::collections::{BTreeSet, HashMap};
use std::future::{Future, poll_fn};
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fictionet::stdlib::{tls, web};
use fictionet::{Attacher, Cx, End, Interface, Packet};

/// The gateway, where `Sites` runs DNS (its default subnet is 10.0.0.0/24).
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
use rcgen::{CertificateParams, DnType, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};

use crate::content::Content;
use crate::log::Log;

struct Args {
    socket: String,
    ca_dir: PathBuf,
    backend: PathBuf,
    backend_port: u16,
    state_dir: PathBuf,
    ready: PathBuf,
}

fn args() -> Result<Args, String> {
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

fn main() {
    if let Err(e) = real_main() {
        eprintln!("fakewiki-world: {e}");
        std::process::exit(1);
    }
}

fn real_main() -> fictionet::Result {
    let args = args()?;
    let _ = std::fs::remove_file(&args.ready);

    // 1. The content server. Its first line says it is listening, and
    //    carries the variant, the hosts and the documents for state.json.
    let started = SystemTime::now();
    let backend = start_backend(&args)?;
    let variant = backend["variant"].as_str().unwrap_or_default().to_owned();
    let mut hosts = HashMap::new();
    for (name, ip) in backend["hosts"].as_object().ok_or("backend sent no hosts")? {
        let ip: Ipv4Addr = ip.as_str().ok_or("bad host address")?.parse()?;
        hosts.insert(name.clone(), ip);
    }

    // 2. Ground truth files.
    std::fs::create_dir_all(&args.state_dir)?;
    let log = Arc::new(Log::create(&args.state_dir.join("log.jsonl"))?);

    // 3. Certificates: one leaf per host, signed by the image's CA.
    let leaves = issue_leaves(&args.ca_dir, hosts.keys())?;

    // 4. The world. Sandboxes attach through the world socket; the world's
    //    own lookups use a clone of the same attacher.
    let (attacher, attachments) = fictionet::attachments();
    if let Some(dir) = Path::new(&args.socket).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let socket = args.socket.clone();

    let content = Content::new(args.backend_port);
    let hook = events::hook(hosts.clone(), log.clone());
    let state = json!({
        "variant": variant,
        "hosts": hosts.keys().collect::<BTreeSet<_>>(),
        "dns": GATEWAY.to_string(),
        "documents": backend["documents"],
        "started": secs(started),
    });
    let state_path = args.state_dir.join("state.json");
    let ready = args.ready.clone();
    let host_list: Vec<String> = hosts.keys().cloned().collect();

    // web::Sites itself needs no tokio; the content client does.
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
    runtime.block_on(fictionet::run(move |cx| async move {
        let mut configs = HashMap::new();
        for (host, (chain, key)) in leaves {
            let config = tls::config_builder(&cx, SystemTime::now(), rustls::crypto::ring::default_provider())
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(chain, key)?;
            configs.insert(host, Arc::new(config));
        }
        let site_hosts = hosts.clone();
        web::Sites::new(move |host: &str| {
            let addr = *site_hosts.get(host)?;
            let config = configs.get(host)?.clone();
            Some(web::Site::new(content.clone()).at(addr).tls(move |_| config.clone()))
        })
        // The agent's sandbox has IPv6 off, and the sites keep their real
        // IPv4 addresses only.
        .ipv4_only()
        .on_event(hook)
        .serve(&cx, attachments)?;

        // Look every host up once, so each FakeWiki address answers from
        // the start, as in the Python world, even for an agent that
        // connects by address without DNS.
        look_up_all(&cx, &attacher, &host_list).await?;
        let _listening = fictionet::listen(fictionet::WorldSocket::UnixSocket(socket.into()), attacher)?;

        std::fs::write(&state_path, serde_json::to_string_pretty(&state)?)?;
        if let Some(dir) = ready.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&ready, variant.as_bytes())?;
        println!("fictionet world up: variant={variant}");

        // Sites serves every sandbox from here on. The listener lives as
        // long as the world.
        std::future::pending::<()>().await;
        Ok(())
    }))
}

fn secs(t: SystemTime) -> f64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Starts backend.py and waits for its first line. If it exits later, the
/// world exits too, so the container stops instead of serving errors.
fn start_backend(args: &Args) -> fictionet::Result<Value> {
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
    std::thread::spawn(move || {
        let status = child.wait();
        eprintln!("fakewiki-world: backend.py exited ({status:?}); stopping");
        std::process::exit(1);
    });
    Ok(serde_json::from_str(&line)?)
}

type Leaf = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

/// One certificate per host, like ca.py's `_mint`: the host as CN and SAN,
/// valid from a day ago for 90 days, for server auth, signed by the CA.
/// The chain sent is the leaf, then the CA, as ca.py sent it.
fn issue_leaves<'a>(ca_dir: &Path, hosts: impl Iterator<Item = &'a String>) -> fictionet::Result<HashMap<String, Leaf>> {
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
async fn look_up_all(cx: &Cx, attacher: &Attacher, hosts: &[String]) -> fictionet::Result {
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
    let sum = checksum(&p[..20]);
    p[10..12].copy_from_slice(&sum.to_be_bytes());
    p.extend_from_slice(&LOOKUP_FROM.port().wrapping_add(id).to_be_bytes());
    p.extend_from_slice(&53u16.to_be_bytes());
    p.extend_from_slice(&(udp_len as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&dns);
    p
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
