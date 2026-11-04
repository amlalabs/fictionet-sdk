//! Echoes complete Ethernet frames from an already assigned virtio NIC.
//!
//! Run only inside the disposable QEMU guest. The first argument is the
//! PCI address and the second is the number of frames to echo.

#[cfg(target_os = "linux")]
fn main() -> fictionet::Result {
    use fictionet_host::virtio::VirtioNet;
    use std::time::{Duration, Instant};

    let mut args = std::env::args().skip(1);
    let address = args
        .next()
        .ok_or_else(|| fictionet::Error::msg("expected PCI address and frame count"))?;
    let count: usize = args
        .next()
        .ok_or_else(|| fictionet::Error::msg("expected frame count"))?
        .parse()
        .map_err(|_| fictionet::Error::msg("frame count must be a positive integer"))?;
    if count == 0 || args.next().is_some() {
        return Err(fictionet::Error::msg(
            "expected PCI address and positive frame count",
        ));
    }
    let mut nic = VirtioNet::open(&address)?;
    fictionet::block_on(fictionet::run(
        fictionet::Seed::from_u64(0),
        move |fcx| async move {
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut frame = [0u8; 2048];
            let mut pending = None;
            let mut sent = 0;
            while sent < count {
                if Instant::now() >= deadline {
                    return Err(fictionet::Error::msg("raw frame echo timed out"));
                }
                if pending.is_none() {
                    pending = nic.receive(&mut frame)?;
                }
                if let Some(len) = pending
                    && nic.transmit(&frame[..len])?
                {
                    pending = None;
                    sent += 1;
                }
                // The driver polls hardware. Yield so other world tasks run,
                // keeping the receive buffer intact while transmit is full.
                fcx.yield_now().await?;
            }
            while !nic.transmit_idle()? {
                if Instant::now() >= deadline {
                    return Err(fictionet::Error::msg("raw transmit completion timed out"));
                }
                fcx.yield_now().await?;
            }
            println!("echoed {sent} complete Ethernet frames");
            Ok(())
        },
    ))
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the raw virtio world requires Linux");
    std::process::exit(1);
}
