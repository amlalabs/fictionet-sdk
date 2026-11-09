mod ipv4;
mod ipv6;
mod tcp;
#[cfg(test)]
mod tests;

use super::socket_set::{SocketHandle, SocketSet};
use crate::phy::{Device, RxToken, TxToken};
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

/// Clock, addresses, MTU, and initial sequence numbers shared by TCP
/// sockets.
pub struct InterfaceInner {
    mtu: usize,
    now: Instant,
    initial_seq: InitialSeq,
    ip_addr: IpAddress,
    ignore_malformed_options: bool,
    reset_closed_ports: bool,
    ingress_target: Option<SocketHandle>,
}

/// Picks the initial sequence number of a connection from its local and
/// remote endpoints and the time, as RFC 6528 has it: a keyed hash of the
/// endpoints plus a clock, so that what one connection shows of its
/// number tells nothing of another's.
pub type InitialSeq = Box<dyn Fn(IpEndpoint, IpEndpoint, Instant) -> u32 + Send + Sync>;

/// Configuration for a simulated host's TCP interface.
pub struct Config {
    /// The host address.
    pub ip_addr: IpAddress,
    /// Each new connection's initial sequence number.
    pub initial_seq: InitialSeq,
}

impl Interface {
    pub fn new(config: Config, device: &mut (impl Device + ?Sized), now: Instant) -> Self {
        assert!(config.ip_addr.is_unicast() || config.ip_addr.is_unspecified());
        Self {
            inner: InterfaceInner {
                mtu: device.capabilities().max_transmission_unit,
                now,
                initial_seq: config.initial_seq,
                ip_addr: config.ip_addr,
                ignore_malformed_options: false,
                reset_closed_ports: true,
                ingress_target: None,
            },
        }
    }

    /// Selects whether a malformed option list retains its valid prefix.
    pub fn set_ignore_malformed_options(&mut self, ignore: bool) {
        self.inner.ignore_malformed_options = ignore;
    }

    /// Selects whether a segment that no socket accepts gets a RST, as
    /// RFC 9293 section 3.10.7.1 says of the CLOSED state, or nothing.
    /// The default is a RST.
    pub fn set_reset_closed_ports(&mut self, reset: bool) {
        self.inner.reset_closed_ports = reset;
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
        let count = sockets.prepare(&mut self.inner, timestamp);
        for _ in 0..count {
            let Some(handle) = sockets.next_ready() else {
                break;
            };
            let socket = sockets.get_mut(handle);
            let sent: Result<(), ()> = socket.dispatch(&mut self.inner, |inner, (ip, tcp)| {
                let token = device.transmit(inner.now).ok_or(())?;
                inner.dispatch_ip(token, ip, tcp);
                result = PollResult::SocketStateChanged;
                Ok(())
            });
            sockets.dispatched(handle, sent.is_err());
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

    /// Try a known connection before the general socket lookup. Packet
    /// validation and socket acceptance still apply.
    pub fn poll_ingress_targeted(
        &mut self,
        timestamp: Instant,
        device: &mut (impl Device + ?Sized),
        sockets: &mut SocketSet<'_>,
        target: SocketHandle,
    ) {
        self.inner.ingress_target = Some(target);
        self.poll_ingress_single(timestamp, device, sockets);
        self.inner.ingress_target = None;
    }

    /// Update the clock before socket operations.
    pub fn poll_maintenance(&mut self, timestamp: Instant) {
        self.inner.now = timestamp;
    }

    /// Earliest time a socket needs egress, or `None` if all await input.
    pub fn poll_at(&mut self, timestamp: Instant, sockets: &mut SocketSet<'_>) -> Option<Instant> {
        self.inner.now = timestamp;
        sockets.schedule(&mut self.inner);
        sockets.next_deadline()
    }
}

impl InterfaceInner {
    pub(crate) fn now(&self) -> Instant {
        self.now
    }
    pub(crate) fn ip_mtu(&self) -> usize {
        self.mtu
    }
    /// The initial sequence number of a connection from `local` to
    /// `remote` that starts now.
    pub(crate) fn initial_seq(&self, local: IpEndpoint, remote: IpEndpoint) -> TcpSeqNumber {
        TcpSeqNumber((self.initial_seq)(local, remote, self.now) as i32)
    }

    #[cfg(test)]
    pub(crate) fn set_now(&mut self, now: Instant) {
        self.now = now;
    }

    #[cfg(test)]
    pub(crate) fn set_ip_addr(&mut self, addr: IpAddress) {
        self.ip_addr = addr;
    }

    pub(crate) fn has_ip_addr(&self, addr: impl Into<IpAddress>) -> bool {
        let addr = addr.into();
        self.ip_addr == addr
    }

    fn process_ip<'a>(
        &mut self,
        sockets: &mut SocketSet,
        bytes: &'a [u8],
    ) -> Option<(IpRepr, TcpRepr<'a>)> {
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
