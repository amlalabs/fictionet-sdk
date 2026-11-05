//! Host tooling for demo images and offline web captures.

mod capture;
mod honeypot_diff;
mod honeypot_probe;
mod image;
mod mptcp_verify;
mod rawnic;
mod web;
mod workstation;

use std::path::PathBuf;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() -> Result {
    let mut args = std::env::args().skip(1);
    let task = args
        .next()
        .ok_or("expected search-image or search-capture")?;
    if task == "honeypot-diff" {
        return honeypot_diff::run(&args.collect::<Vec<_>>()).await;
    }
    if task == "honeypot-probe" {
        let profile = honeypot_diff::Profile::parse(&args.next().ok_or("missing probe profile")?)?;
        let directory = PathBuf::from(args.next().ok_or("missing probe output directory")?);
        let selection = match args.next().as_deref() {
            None => honeypot_probe::Selection::All,
            Some("--defaults") => honeypot_probe::Selection::Defaults,
            Some("--ip-options") => honeypot_probe::Selection::IpOptions,
            _ => return Err("expected --defaults or --ip-options".into()),
        };
        if args.next().is_some() {
            return Err("unexpected probe argument".into());
        }
        return honeypot_probe::run(&directory, selection, profile);
    }
    if task == "mptcp-verify" {
        return mptcp_verify::run(&args.collect::<Vec<_>>());
    }
    let downloads = PathBuf::from(args.next().ok_or("missing downloads directory")?);
    if task == "rawnic" {
        if args.next().is_some() {
            return Err("unexpected argument".into());
        }
        return rawnic::run(downloads);
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
    if task != "search-image" {
        return Err("expected search-image or search-capture".into());
    }
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    image::build(&downloads).await
}
