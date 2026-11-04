//! Receives complete Ethernet frames from a dedicated virtio NIC in a guest.
//!
//! The host pump owns device polling; the world only awaits frame arrivals.

#[cfg(target_os = "linux")]
fn main() -> fictionet::Result {
    use fictionet_host::{VirtioNet, raw::RawPump};

    let mut args = std::env::args().skip(1);
    let address = args
        .next()
        .ok_or_else(|| fictionet::Error::msg("expected PCI address and frame count"))?
        .parse()?;
    let count: usize = args
        .next()
        .ok_or_else(|| fictionet::Error::msg("expected frame count"))?
        .parse()?;
    if count == 0 || args.next().is_some() {
        return Err(fictionet::Error::msg(
            "expected PCI address and positive frame count",
        ));
    }
    let (pump, mut raw) = RawPump::attach(VirtioNet::open(address)?)?;
    let result = fictionet::block_on(fictionet::run(
        fictionet::Seed::from_u64(0),
        move |fcx| async move {
            for _ in 0..count {
                let frame = raw.recv(&fcx).await?;
                println!("received {} Ethernet bytes", frame.0.len());
                fcx.yield_now().await?;
            }
            Ok(())
        },
    ));
    let shutdown = pump.shutdown();
    result.and(shutdown)
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the raw virtio world requires Linux");
    std::process::exit(1);
}
