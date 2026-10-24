//! Host tooling for demo images and offline web captures.

mod capture;
mod image;
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
    if task == "search-capture" {
        let selection = args
            .next()
            .ok_or("expected --research or Python with pip (Python 3.12)")?;
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
