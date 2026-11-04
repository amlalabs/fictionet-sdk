//! A world that receives and returns the guest's complete Ethernet frames.

use fictionet_host::virtio::VirtioNet;
use std::time::{Duration, Instant};

pub fn run(mut nic: VirtioNet, expected: usize) -> fictionet::Result {
    fictionet::block_on(fictionet::run(
        fictionet::Seed::from_u64(0),
        move |fcx| async move {
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut frame = [0u8; 2048];
            let mut pending = None;
            let mut echoed = 0;
            println!("RAWNIC READY");
            while echoed < expected {
                if Instant::now() >= deadline {
                    return Err(fictionet::Error::msg("world raw frame echo timed out"));
                }
                if pending.is_none() {
                    pending = nic.receive(&mut frame)?;
                }
                // Preserve even malformed headers and unknown EtherTypes.
                // Packet is an IP contract, so raw bytes never go through it.
                if let Some(len) = pending
                    && nic.transmit(&frame[..len])?
                {
                    pending = None;
                    echoed += 1;
                }
                fcx.yield_now().await?;
            }
            loop {
                if Instant::now() >= deadline {
                    return Err(fictionet::Error::msg("raw frame acknowledgment timed out"));
                }
                if let Some(len) = nic.receive(&mut frame)? {
                    let mut acknowledgement = [0x5a; 60];
                    acknowledgement[..6].copy_from_slice(&nic.mac_address());
                    if frame[..len] != acknowledgement {
                        return Err(fictionet::Error::msg("unexpected raw frame acknowledgment"));
                    }
                    return Ok(());
                }
                fcx.yield_now().await?;
            }
        },
    ))
}
