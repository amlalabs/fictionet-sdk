#![deny(unsafe_code)]

//! Host tooling for demo images and offline web captures, and the
//! verification of Fictionet's DNS, MPTCP, HPACK and layer routing.

#[cfg(feature = "host-tools")]
mod capture;
mod dns_verify;
mod gate;
mod hpack_verify;
mod http_verify;
#[cfg(feature = "host-tools")]
mod honeypot_vm;
#[cfg(feature = "host-tools")]
mod image;
mod layer_verify;
mod lean_vectors;
mod mptcp_verify;
#[cfg(feature = "host-tools")]
mod rawnic;
#[cfg(feature = "host-tools")]
// This module owns the host syscall boundary.
#[allow(unsafe_code)]
mod ssh_connect;
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
    let mut args = std::env::args().skip(1);
    let task = args.next().ok_or(
        "expected gate, dns-verify, http-verify, mptcp-verify, hpack-verify, layer-verify or a host command",
    )?;
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
    if !matches!(
        task.as_str(),
        "ssh-connect"
            | "rawnic"
            | "egress"
            | "honeypot-vm"
            | "search-web"
            | "search-requisites"
            | "search-capture"
            | "search-image"
    ) {
        return Err(format!("unknown task: {task}").into());
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
    if task == "ssh-connect" {
        return ssh_connect::run(&args.collect::<Vec<_>>()).await;
    }
    let downloads = PathBuf::from(args.next().ok_or("missing downloads directory")?);
    if task == "honeypot-vm" {
        if args.next().is_some() {
            return Err("unexpected argument".into());
        }
        return honeypot_vm::run(downloads);
    }
    if task == "rawnic" || task == "egress" {
        if args.next().is_some() {
            return Err("unexpected argument".into());
        }
        return rawnic::run(downloads, task == "egress");
    }
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
