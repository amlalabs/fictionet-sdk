//! The guest's network card, joined to the world: Ethernet frames from the
//! VM's socket go through the stdlib's Ethernet lowering into the
//! sandbox's attachment, and the world's packets come back as frames.
//!
//! The lowering learns the guest's MAC and answers ARP itself. DHCP goes
//! to the world, which hands out the address, so the link holds no lease
//! of its own. IPv6 is off for now.

use std::io;
use std::os::fd::OwnedFd;

use fictionet::stdlib::network::ethernet::stream::{Decoder, Outbox};
use fictionet::stdlib::network::ethernet::{Family, FromVm, Link, Why};
use fictionet::{Cx, End, Interface, InterfaceExt, Packet, RecvError};
use tokio::net::UnixStream;

/// How much may wait to be written to the VM. A burst from the world past
/// this is dropped, as a full network card queue would drop it.
const OUTBOX: usize = 4 << 20;

/// The IP MTU of the guest's card.
pub const MTU: u16 = 1500;

/// What the link dropped, by reason, and what did not fit the queue to the
/// VM.
#[derive(Debug, Default)]
pub struct Drops {
    pub from_vm: Vec<(Why, u64)>,
    pub to_vm: u64,
}

impl Drops {
    fn count(&mut self, why: Why) {
        if why == Why::Handled {
            return;
        }
        match self.from_vm.iter_mut().find(|(w, _)| *w == why) {
            Some((_, n)) => *n += 1,
            None => self.from_vm.push((why, 1)),
        }
    }
}

/// Moves frames and packets both ways until the VM closes its socket or
/// the world's region is cancelled.
pub async fn run(net: OwnedFd, mut sandbox: End, fcx: Cx) -> io::Result<Drops> {
    let socket = std::os::unix::net::UnixStream::from(net);
    socket.set_nonblocking(true)?;
    let socket = UnixStream::from_std(socket)?;
    let mut link = Link::new(Family::FromWorld, Family::Off, MTU);
    let mut decoder = Decoder::new();
    let mut outbox = Outbox::new(OUTBOX);
    let mut drops = Drops::default();
    enum Ready {
        Read,
        Write,
        Packet(Result<Packet, RecvError>),
    }
    loop {
        // Each branch only says what is ready, so the work below can use
        // everything the waits borrowed.
        let ready = tokio::select! {
            r = socket.readable() => { r?; Ready::Read }
            r = socket.writable(), if !outbox.is_empty() => { r?; Ready::Write }
            p = sandbox.recv(&fcx) => Ready::Packet(p),
        };
        match ready {
            Ready::Read => match socket.try_read(decoder.spare()) {
                Ok(0) => return Ok(drops),
                Ok(n) => {
                    decoder.filled(n);
                    while let Some(frame) = decoder
                        .next_frame()
                        .map_err(|e| io::Error::other(format!("a frame length of {}", e.0)))?
                    {
                        match link.frame_from_vm(frame) {
                            FromVm::World(packet) => sandbox.send(Packet(packet.to_vec())),
                            FromVm::Answer(frame) => {
                                if !outbox.push(&[&frame]) {
                                    drops.to_vm += 1;
                                }
                            }
                            FromVm::Drop(why) => drops.count(why),
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => return Ok(drops),
                Err(e) => return Err(e),
            },
            Ready::Write => match socket.try_write(outbox.pending()) {
                Ok(n) => outbox.written(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    return Ok(drops);
                }
                Err(e) => return Err(e),
            },
            Ready::Packet(Ok(packet)) => match link.to_vm(&packet.0) {
                Some(header) => {
                    if !outbox.push(&[&header, &packet.0]) {
                        drops.to_vm += 1;
                    }
                }
                None => drops.to_vm += 1,
            },
            Ready::Packet(Err(RecvError::Closed | RecvError::Cancelled)) => return Ok(drops),
        }
    }
}
