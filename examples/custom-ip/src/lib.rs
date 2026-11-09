//! A copied IP layer installed under unchanged world applications using only
//! public SDK contracts. It owns validation, fragment reassembly, buffering,
//! deadlines, and the outgoing hop-limit policy. It never constructs `IpLayer`.

use fictionet::Packet;
use fictionet::stdlib::layer::{
    Admit, Chunk, CommandOf, Datagram, Env, EventOf, Layer, PacketCommand, PacketEvent, Packets,
};
use fictionet::stdlib::network::ip::{Header, Intake, Reassembly, set_header_checksum};
use fictionet::stdlib::network::packet::{Ingress, IpPacket, IpReport, Origin, Scope};
use fictionet::time::Instant;
use std::convert::Infallible;

/// A replacement IP layer that applies its hop limit to transport output and
/// its own ICMP replies while preserving the packet's allocation charge.
pub struct HopLimit {
    scope: Scope,
    hops: u8,
    reassembly: Reassembly,
    up: Option<PacketEvent<IpPacket>>,
    answer: Option<Chunk>,
    down: Option<PacketCommand<Chunk>>,
    input_closed: bool,
    output_closed: bool,
}

impl HopLimit {
    /// Constructs a replacement IP layer with the selected nonzero hop limit.
    pub fn new(hops: std::num::NonZeroU8) -> Self {
        Self {
            scope: Scope::ROOT,
            hops: hops.get(),
            reassembly: Reassembly::default(),
            up: None,
            answer: None,
            down: None,
            input_closed: false,
            output_closed: false,
        }
    }

    /// The network it serves.
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// Takes in one raw packet the layer has room for.
    fn take_in(&mut self, env: &mut Env<'_, IpReport>, raw: Datagram<Ingress>) {
        let (bytes, ingress) = raw.into_parts();
        if ingress.scope != self.scope {
            env.report(IpReport::OtherScope {
                scope: ingress.scope,
            });
            return;
        }
        let bytes = bytes.into_vec();
        let before = Header::parse(&bytes);
        let fragment = before.as_ref().is_some_and(|h| h.fragment.is_some());
        let original = (!fragment
            && before
                .as_ref()
                .is_some_and(|h| h.src.is_ipv6() && h.payload.start != 40))
        .then(|| Chunk::new(bytes.clone()));
        match self.reassembly.push(Packet(bytes), env.now()) {
            Intake::Whole(Packet(whole)) => {
                let origin = match original {
                    _ if fragment => Origin::Reassembled,
                    Some(original) if original.len() != whole.len() => {
                        Origin::Normalized { original }
                    }
                    _ => Origin::Arrived,
                };
                if let Ok(packet) = IpPacket::checked(Chunk::new(whole), ingress, origin) {
                    self.up = Some(PacketEvent::Packet(packet));
                }
            }
            Intake::Waiting => {}
            Intake::Refused { answer, .. } => {
                let answer = answer.filter(|_| !self.output_closed);
                env.report(IpReport::Refused {
                    answered: answer.is_some(),
                });
                self.answer = answer.map(|Packet(bytes)| Chunk::new(bytes));
            }
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

    fn report_bytes(_: &IpReport) -> Option<usize> {
        Some(0)
    }

    fn is_terminal(&self) -> bool {
        self.input_closed && self.output_closed
    }

    fn on_event(
        &mut self,
        env: &mut Env<'_, IpReport>,
        event: EventOf<Self::Lower>,
    ) -> Result<Admit<EventOf<Self::Lower>>, Infallible> {
        if self.input_closed {
            return Ok(Admit::Closed(event));
        }
        if self.up.is_some() || self.answer.is_some() {
            return Ok(Admit::Blocked(event));
        }
        match event {
            PacketEvent::Packet(raw) => self.take_in(env, raw),
            PacketEvent::Ended => {
                self.input_closed = true;
                self.up = Some(PacketEvent::Ended);
            }
        }
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        _env: &mut Env<'_, IpReport>,
        command: CommandOf<Self::Upper>,
    ) -> Result<Admit<CommandOf<Self::Upper>>, Infallible> {
        if self.output_closed {
            return Ok(Admit::Closed(command));
        }
        if self.down.is_some() {
            return Ok(Admit::Blocked(command));
        }
        self.output_closed = matches!(command, PacketCommand::End);
        self.down = Some(command);
        Ok(Admit::Taken)
    }

    fn on_timer(&mut self, env: &mut Env<'_, IpReport>, (): ()) -> Result<(), Infallible> {
        self.reassembly.expire(env.now());
        Ok(())
    }

    fn take_command(&mut self, env: &mut Env<'_, Self::Report>) -> Option<CommandOf<Self::Lower>> {
        let chunk = self.answer.as_mut().or(match &mut self.down {
            Some(PacketCommand::Send(chunk)) => Some(chunk),
            _ => None,
        });
        if let Some(chunk) = chunk {
            let bytes = chunk.make_mut(env.budget())?;
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
        }
        self.answer
            .take()
            .map(PacketCommand::Send)
            .or_else(|| self.down.take())
    }

    fn take_event(&mut self) -> Option<EventOf<Self::Upper>> {
        self.up.take()
    }

    fn deadline(&self) -> Option<(Instant, ())> {
        self.reassembly.next_expiry().map(|at| (at, ()))
    }
}
