//! An IP policy installed under unchanged world applications using only
//! public SDK contracts. Validation and reassembly remain the standard IP
//! layer's; this implementation owns the outgoing hop-limit policy.

use std::convert::Infallible;

use fictionet::stdlib::layer::{
    Admit, Chunk, Datagram, Env, Layer, PacketCommand, PacketEvent, Packets,
};
use fictionet::stdlib::network::ip::set_header_checksum;
use fictionet::stdlib::network::packet::{Ingress, IpLayer, IpPacket, IpReport};
use fictionet::time::Instant;

/// An independently configured hop limit for every outgoing IP packet,
/// including packets produced by TCP and UDP and IP's own error replies.
pub struct HopLimit {
    inner: IpLayer,
    hops: u8,
}

impl HopLimit {
    /// Constructs an IP layer with the selected nonzero hop limit.
    pub fn new(hops: std::num::NonZeroU8) -> Self {
        Self {
            inner: IpLayer::host(),
            hops: hops.get(),
        }
    }
}

impl Layer for HopLimit {
    type Lower = Packets<Datagram<Ingress>, Chunk>;
    type Upper = Packets<IpPacket, Chunk>;
    type Report = IpReport;
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = Infallible;

    fn report_bytes(report: &IpReport) -> Option<usize> {
        IpLayer::report_bytes(report)
    }

    fn is_terminal(&self) -> bool {
        self.inner.is_terminal()
    }

    fn on_event(
        &mut self,
        env: &mut Env<'_, IpReport>,
        event: PacketEvent<Datagram<Ingress>>,
    ) -> Result<Admit<PacketEvent<Datagram<Ingress>>>, Infallible> {
        self.inner.on_event(env, event)
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, IpReport>,
        command: PacketCommand<Chunk>,
    ) -> Result<Admit<PacketCommand<Chunk>>, Infallible> {
        self.inner.on_command(env, command)
    }

    fn on_timer(&mut self, env: &mut Env<'_, IpReport>, timer: ()) -> Result<(), Infallible> {
        self.inner.on_timer(env, timer)
    }

    fn take_command(&mut self) -> Option<PacketCommand<Chunk>> {
        let command = self.inner.take_command()?;
        let PacketCommand::Send(bytes) = command else {
            return Some(command);
        };
        let mut bytes = bytes.into_vec();
        match bytes.first().map(|version| version >> 4) {
            Some(4) if bytes.len() >= 20 => {
                let header_len = usize::from(bytes[0] & 15) * 4;
                if (20..=bytes.len()).contains(&header_len) {
                    bytes[8] = self.hops;
                    set_header_checksum(&mut bytes[..header_len]);
                }
            }
            Some(6) if bytes.len() >= 40 => bytes[7] = self.hops,
            _ => {}
        }
        Some(PacketCommand::Send(Chunk::new(bytes)))
    }

    fn take_event(&mut self) -> Option<PacketEvent<IpPacket>> {
        self.inner.take_event()
    }

    fn deadline(&self) -> Option<(Instant, ())> {
        self.inner.deadline()
    }
}
