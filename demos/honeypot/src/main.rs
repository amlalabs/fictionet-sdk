//! Runs the honeypot world on its socket, appending to its log and packet
//! capture. See the crate's README for the command line and setup.

use std::fs::{File, OpenOptions};
use std::io::BufWriter;
use std::path::Path;

use honeypot_world::observe::Sinks;
use honeypot_world::{Args, Clock};

/// Opens `path` to append to, so a restart keeps what came before. A
/// pcapng file may hold several sections, one per run.
fn append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn main() -> fictionet::Result {
    let args = Args::parse(std::env::args().skip(1))?;
    let sinks = Sinks {
        log: Box::new(BufWriter::new(append(&args.log)?)),
        pcap: Box::new(BufWriter::new(append(&args.pcap)?)),
    };
    let (_listening, attachments) = fictionet::Listening::bind(args.world.clone())?;
    let address_v6 = args
        .config
        .address_v6
        .map(|address_v6| format!(" and {address_v6}"))
        .unwrap_or_default();
    println!(
        "honeypot at {}{address_v6} on {}, logging to {} and {}",
        args.config.address,
        args.world,
        args.log.display(),
        args.pcap.display()
    );
    let clock = Clock::starting_now();
    fictionet::block_on(fictionet::run(fictionet::Seed::random(), move |fcx| {
        let started = honeypot_world::start(&fcx, &args.config, clock, sinks, attachments);
        async move { started.map(drop) }
    }))
}
