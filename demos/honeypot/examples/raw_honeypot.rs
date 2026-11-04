//! Runs only in a disposable Linux guest with a dedicated virtio PCI NIC.

#[cfg(target_os = "linux")]
fn main() -> fictionet::Result {
    use fictionet_host::raw::RawPump;
    use fictionet_host::virtio::{PciAddress, VirtioNet};
    use honeypot_world::{Args, Clock, observe::Sinks};
    use std::fs::OpenOptions;
    use std::io::BufWriter;

    let mut arguments = std::env::args().skip(1);
    let address: PciAddress = arguments
        .next()
        .ok_or_else(|| fictionet::Error::msg("expected PCI address and raw log path"))?
        .parse()?;
    let raw_path = arguments
        .next()
        .ok_or_else(|| fictionet::Error::msg("expected raw log path"))?;
    let args = Args::parse(arguments)?;
    let append = |path: &std::path::Path| OpenOptions::new().create(true).append(true).open(path);
    let raw_log = Box::new(BufWriter::new(append(std::path::Path::new(&raw_path))?));
    let sinks = Sinks {
        log: Box::new(BufWriter::new(append(&args.log)?)),
        pcap: Box::new(BufWriter::new(append(&args.pcap)?)),
    };
    let (pump, attachment) = RawPump::attach(VirtioNet::open(address)?)?;
    let clock = Clock::starting_now();
    println!(
        "raw honeypot at {} via {} on {address}",
        args.config.address, args.config.gateway
    );
    let result = fictionet::block_on(fictionet::run(fictionet::Seed::random(), move |fcx| {
        let started =
            honeypot_world::start_raw(&fcx, &args.config, clock, sinks, attachment, raw_log);
        async move { started.map(drop) }
    }));
    let stopped = pump.shutdown();
    result?;
    stopped?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the raw honeypot requires a Linux guest");
    std::process::exit(1);
}
