//! Ethernet frames between one guest and its attachment.

use super::net::RxQueue;
use fictionet::stdlib::network::ethernet::{Family, FromVm, Link};
use fictionet::{Cx, End, Interface, InterfaceExt, Packet, RecvError};
use tokio::sync::mpsc::UnboundedReceiver;

/// Moves frames between the guest (through the backend) and the world,
/// answering ARP and the link-local questions itself, as the CLI's TAP
/// lowering does.
pub async fn run(
    mut to_world: UnboundedReceiver<Vec<u8>>,
    rx: RxQueue,
    mut sandbox: End,
    fcx: Cx,
    family: Family<std::net::Ipv4Addr>,
) {
    let mut link =
        Link::new(family, Family::Off, super::MTU).expect("Guest::validate built this card");
    loop {
        tokio::select! {
            frame = to_world.recv() => {
                let Some(frame) = frame else { break };
                match link.frame_from_vm(&frame) {
                    FromVm::World(packet) => sandbox.send(Packet(packet.to_vec())),
                    FromVm::Answer(reply) => rx.push(reply),
                    FromVm::Drop(_) => {}
                }
            }
            packet = sandbox.recv(&fcx) => {
                match packet {
                    Ok(packet) => {
                        if let Some(header) = link.to_vm(&packet.0) {
                            let mut frame = header.to_vec();
                            frame.extend_from_slice(&packet.0);
                            rx.push(frame);
                        }
                    }
                    Err(RecvError::Closed | RecvError::Cancelled) => break,
                }
            }
        }
    }
}
