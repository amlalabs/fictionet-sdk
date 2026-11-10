//! Explicit clock, address, and sequence-number context for TCP sockets.
use crate::time::Instant;
use crate::wire::*;

/// Picks each connection's initial sequence number from its endpoints and time.
pub type InitialSeq = Box<dyn Fn(IpEndpoint, IpEndpoint, Instant) -> u32 + Send + Sync>;

/// The local address and initial sequence-number source.
pub struct Config {
    pub ip_addr: IpAddress,
    pub initial_seq: InitialSeq,
}

/// State shared by sockets belonging to one endpoint.
pub struct Context {
    pub(crate) mtu: usize,
    pub(crate) now: Instant,
    pub(crate) initial_seq: InitialSeq,
    pub(crate) ip_addr: IpAddress,
    #[cfg(test)]
    pub(crate) ignore_malformed_options: bool,
    #[cfg(test)]
    pub(crate) reset_closed_ports: bool,
    #[cfg(test)]
    pub(crate) ingress_target: Option<super::SocketHandle>,
}

impl Context {
    pub fn new(config: Config, mtu: usize, now: Instant) -> Self {
        assert!(config.ip_addr.is_unicast() || config.ip_addr.is_unspecified());
        Self {
            mtu,
            now,
            initial_seq: config.initial_seq,
            ip_addr: config.ip_addr,
            #[cfg(test)]
            ignore_malformed_options: false,
            #[cfg(test)]
            reset_closed_ports: true,
            #[cfg(test)]
            ingress_target: None,
        }
    }
    /// Advance the endpoint's explicit simulation clock.
    pub fn set_now(&mut self, now: Instant) {
        self.now = now;
    }
    pub(crate) fn now(&self) -> Instant {
        self.now
    }
    pub(crate) fn ip_mtu(&self) -> usize {
        self.mtu
    }
    pub(crate) fn initial_seq(&self, local: IpEndpoint, remote: IpEndpoint) -> TcpSeqNumber {
        TcpSeqNumber((self.initial_seq)(local, remote, self.now) as i32)
    }
    pub fn has_ip_addr(&self, addr: impl Into<IpAddress>) -> bool {
        self.ip_addr == addr.into()
    }
    #[cfg(test)]
    pub(crate) fn set_ip_addr(&mut self, addr: IpAddress) {
        self.ip_addr = addr;
    }
}
