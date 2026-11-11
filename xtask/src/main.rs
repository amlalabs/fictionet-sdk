#![deny(unsafe_code)]

//! Host tooling for demo images and offline web captures, and the
//! verification of Fictionet's DNS, MPTCP, HPACK, QUIC and layer routing.

#[cfg(feature = "host-tools")]
mod capture;
mod dns_verify;
mod gate;
#[cfg(feature = "host-tools")]
mod honeypot_aws;
mod hpack_verify;
mod http_verify;
#[cfg(feature = "host-tools")]
mod image;
mod ip_verify;
mod kani_slot;
mod layer_verify;
mod lean_vectors;
mod mptcp_verify;
mod qpack_verify;
mod quic_verify;
mod resources;
#[cfg(feature = "shibboleth")]
mod shibboleth_infer;
mod tcp_rfc_verify;
mod tls_verify;
mod tls_verify_handshake;
mod tls_verify_record;
#[cfg(feature = "host-tools")]
mod web;
#[cfg(feature = "host-tools")]
mod workstation;

#[cfg(feature = "host-tools")]
use std::path::PathBuf;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn main() -> Result {
    #[cfg(feature = "host-tools")]
    if std::env::var_os(honeypot_aws::MUSL_CC).is_some() {
        return honeypot_aws::musl_cc();
    }
    let mut args = std::env::args().skip(1);
    let task = args.next().ok_or(
        "expected gate, dns-verify, http-verify, mptcp-verify, hpack-verify, qpack-verify, quic-verify, layer-verify or a host command",
    )?;
    #[cfg(feature = "shibboleth")]
    if task == "shibboleth-infer" {
        return shibboleth_infer::run(&args.collect::<Vec<_>>());
    }
    if task == "kani" {
        return gate::kani(&args.collect::<Vec<_>>());
    }
    if task == "gate" {
        return gate::run(&args.collect::<Vec<_>>());
    }
    if task == "mptcp-verify" {
        return mptcp_verify::run(&args.collect::<Vec<_>>());
    }
    if task == "tcp-rfc-verify" {
        return tcp_rfc_verify::run(&args.collect::<Vec<_>>());
    }
    if task == "quic-verify" {
        return quic_verify::run(&args.collect::<Vec<_>>());
    }
    if task == "qpack-verify" {
        return qpack_verify::run(&args.collect::<Vec<_>>());
    }
    if task == "hpack-verify" {
        return hpack_verify::run(&args.collect::<Vec<_>>());
    }
    if task == "http-verify" {
        return http_verify::run(&args.collect::<Vec<_>>());
    }
    if task == "dns-verify" {
        return dns_verify::run(&args.collect::<Vec<_>>());
    }
    if task == "layer-verify" {
        return layer_verify::run(&args.collect::<Vec<_>>());
    }
    if task == "tls-verify" {
        return tls_verify::run(&args.collect::<Vec<_>>());
    }
    if task == "ip-verify" {
        return ip_verify::run(&args.collect::<Vec<_>>());
    }
    if !matches!(
        task.as_str(),
        "search-web" | "search-requisites" | "search-capture" | "search-image" | "honeypot-aws"
    ) {
        return Err(format!("unknown task: {task}").into());
    }
    #[cfg(feature = "host-tools")]
    if task == "honeypot-aws" {
        return honeypot_aws::run(&args.collect::<Vec<_>>());
    }
    #[cfg(feature = "host-tools")]
    {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(host(&task, args))
    }
    #[cfg(not(feature = "host-tools"))]
    {
        Err(
            format!("{task} requires host tools; run cargo xtask-host {task} with its arguments")
                .into(),
        )
    }
}

#[cfg(feature = "host-tools")]
async fn host(task: &str, mut args: impl Iterator<Item = String>) -> Result {
    let downloads = PathBuf::from(args.next().ok_or("missing downloads directory")?);
    if task == "search-web" {
        let step = match args.next().as_deref() {
            None => web::Step::All,
            Some("--documents") => web::Step::Documents,
            Some("--index") => web::Step::Index,
            _ => return Err("expected --documents or --index".into()),
        };
        if args.next().is_some() {
            return Err("unexpected argument".into());
        }
        return web::build(&downloads, step).await;
    }
    if task == "search-requisites" {
        return capture::requisites(&downloads, &args.collect::<Vec<_>>()).await;
    }
    if task == "search-capture" {
        let selection = args
            .next()
            .ok_or("expected --research or Python with pip (Python 3.12)")?;
        if selection == "--urls" {
            let urls = args.collect::<Vec<_>>();
            if urls.is_empty() {
                return Err("missing capture URLs".into());
            }
            return capture::urls(&downloads, &urls).await;
        }
        let python = (selection != "--research").then(|| PathBuf::from(selection));
        if args.next().is_some() {
            return Err("unexpected argument".into());
        }
        return capture::run(&downloads, python.as_deref()).await;
    }
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    image::build(&downloads).await
}

/// Reserve a run directory without overwriting another invocation's artifacts.
fn verification_run(parent: &std::path::Path) -> Result<std::path::PathBuf> {
    std::fs::create_dir_all(parent)?;
    for counter in 0.. {
        let path = parent.join(format!("run-{}-{counter}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => {
                println!("Verification output: {}", path.display());
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    unreachable!()
}
