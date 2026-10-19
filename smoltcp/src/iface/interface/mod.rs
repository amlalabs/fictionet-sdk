mod ipv4;
mod ipv6;
mod tcp;
#[cfg(test)]
mod tests;

use super::socket_set::SocketSet;
use crate::phy::{Device, RxToken, TxToken};
use crate::rand::Rand;
use crate::socket::PollAt;
use crate::time::Instant;
use crate::wire::*;
use core::result::Result;

/// Whether egress may have changed a socket's state.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PollResult {
    None,
    SocketStateChanged,
}

/// A TCP interface over whole IP packets.
pub struct Interface {
    pub(crate) inner: InterfaceInner,
}

/// Clock, addresses, MTU, and entropy shared by TCP sockets.
pub struct InterfaceInner {
    mtu: usize,
    now: Instant,
    rand: Rand,
    ip_addr: IpCidr,
}

/// Configuration for a simulated host's TCP interface.
pub struct Config {
    /// The host address.
    pub ip_addr: IpCidr,
    /// Seed for TCP initial sequence numbers.
    pub random_seed: u64,
}

impl Interface {
    pub fn new(config: Config, device: &mut (impl Device + ?Sized), now: Instant) -> Self {
        assert!(config.ip_addr.address().is_unicast() || config.ip_addr.address().is_unspecified());
        let mut rand = Rand::new(config.random_seed);
        // Preserve the sequence of random values used by existing simulations.
        while rand.rand_u16() == 0 {}
        Self {
            inner: InterfaceInner {
                mtu: device.capabilities().max_transmission_unit,
                now,
                rand,
                ip_addr: config.ip_addr,
            },
        }
    }

    /// Context for connecting a TCP socket.
    pub fn context(&mut self) -> &mut InterfaceInner {
        &mut self.inner
    }

    /// Transmit at most one packet per socket, stopping when the device is full.
    pub fn poll_egress(
        &mut self,
        timestamp: Instant,
        device: &mut (impl Device + ?Sized),
        sockets: &mut SocketSet<'_>,
    ) -> PollResult {
        self.inner.now = timestamp;
        let mut result = PollResult::None;
        for (_, socket) in sockets.iter_mut() {
            let sent: Result<(), ()> = socket.dispatch(&mut self.inner, |inner, (ip, tcp)| {
                let token = device.transmit(inner.now).ok_or(())?;
                inner.dispatch_ip(token, ip, tcp);
                result = PollResult::SocketStateChanged;
                Ok(())
            });
            if sent.is_err() {
                break;
            }
        }
        result
    }

    /// Receive one whole IP packet and send an immediate TCP reply if needed.
    pub fn poll_ingress_single(
        &mut self,
        timestamp: Instant,
        device: &mut (impl Device + ?Sized),
        sockets: &mut SocketSet<'_>,
    ) {
        self.inner.now = timestamp;
        if let Some((rx, tx)) = device.receive(timestamp) {
            rx.consume(|bytes| {
                if let Some((ip, tcp)) = self.inner.process_ip(sockets, bytes) {
                    self.inner.dispatch_ip(tx, ip, tcp);
                }
            });
        }
    }

    /// Update the clock before socket operations.
    pub fn poll_maintenance(&mut self, timestamp: Instant) {
        self.inner.now = timestamp;
    }

    /// Earliest time a socket needs egress, or `None` if all await input.
    pub fn poll_at(&mut self, timestamp: Instant, sockets: &SocketSet<'_>) -> Option<Instant> {
        self.inner.now = timestamp;
        sockets
            .iter()
            .filter_map(|(_, socket)| match socket.poll_at(&mut self.inner) {
                PollAt::Ingress => None,
                PollAt::Time(at) => Some(at),
                PollAt::Now => Some(Instant::ZERO),
            })
            .min()
    }
}

impl InterfaceInner {
    pub(crate) fn now(&self) -> Instant {
        self.now
    }
    pub(crate) fn ip_mtu(&self) -> usize {
        self.mtu
    }
    pub(crate) fn rand(&mut self) -> &mut Rand {
        &mut self.rand
    }

    #[cfg(test)]
    pub(crate) fn set_now(&mut self, now: Instant) {
        self.now = now;
    }

    #[cfg(test)]
    pub(crate) fn set_ip_addr(&mut self, addr: IpCidr) {
        self.ip_addr = addr;
    }

    pub(crate) fn has_ip_addr(&self, addr: impl Into<IpAddress>) -> bool {
        let addr = addr.into();
        self.ip_addr.address() == addr
    }

    fn process_ip<'a>(
        &mut self,
        sockets: &mut SocketSet,
        bytes: &'a [u8],
    ) -> Option<(IpRepr, TcpRepr<'a>)> {
        bytes.first()?;
        match IpVersion::of_packet(bytes).ok()? {
            IpVersion::Ipv4 => self.process_ipv4(sockets, &Ipv4Packet::new_checked(bytes).ok()?),
            IpVersion::Ipv6 => self.process_ipv6(sockets, &Ipv6Packet::new_checked(bytes).ok()?),
        }
    }

    fn dispatch_ip(&mut self, token: impl TxToken, ip: IpRepr, tcp: TcpRepr) {
        assert!(!ip.dst_addr().is_unspecified());
        if ip.buffer_len() > self.mtu {
            return;
        }
        token.consume(ip.buffer_len(), |bytes| {
            ip.emit(&mut *bytes);
            tcp.emit(
                &mut TcpPacket::new_unchecked(&mut bytes[ip.header_len()..]),
                &ip.src_addr(),
                &ip.dst_addr(),
            );
        });
    }
}
