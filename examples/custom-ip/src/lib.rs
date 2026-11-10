//! A copied IP layer installed under unchanged world applications using only
//! public SDK contracts. It owns validation, fragment reassembly, buffering,
//! deadlines, and the outgoing hop-limit policy. It never constructs `IpLayer`.

use fictionet::stdlib::layer::{
    Admit, Chunk, CommandOf, Env, EventOf, Layer, PacketCommand, PacketEvent, Packets,
};
use fictionet::stdlib::network::ip::{Header, Intake, Reassembly, set_header_checksum};
use fictionet::stdlib::network::packet::{CheckedIpPacket, IpReport, Origin};
use fictionet::time::Instant;
use std::convert::Infallible;

/// A replacement IP layer that applies its hop limit to transport output and
/// its own ICMP replies while preserving the packet's allocation charge.
pub struct HopLimit {
    hops: u8,
    reassembly: Reassembly,
    up: Option<PacketEvent<CheckedIpPacket>>,
    answer: Option<Chunk>,
    down: Option<PacketCommand<Chunk>>,
    input_closed: bool,
    output_closed: bool,
}

impl HopLimit {
    /// Constructs a replacement IP layer with the selected nonzero hop limit.
    pub fn new(hops: std::num::NonZeroU8) -> Self {
        Self {
            hops: hops.get(),
            reassembly: Reassembly::default(),
            up: None,
            answer: None,
            down: None,
            input_closed: false,
            output_closed: false,
        }
    }

    /// Takes in one raw packet the layer has room for.
    fn take_in(&mut self, env: &mut Env<'_, IpReport>, bytes: Chunk) {
        let before = Header::parse(&bytes);
        let fragment = before.as_ref().is_some_and(|h| h.fragment.is_some());
        let original = (!fragment
            && before
                .as_ref()
                .is_some_and(|h| h.src.is_ipv6() && h.payload.start != 40))
        .then(|| bytes.clone());
        match self.reassembly.push(bytes, env.now()) {
            Intake::Whole(whole) => {
                let origin = match (fragment, original) {
                    (true, _) => Origin::Reassembled,
                    (false, Some(original)) if original.len() != whole.len() => {
                        Origin::Normalized { original }
                    }
                    _ => Origin::Arrived,
                };
                match CheckedIpPacket::checked(whole, origin) {
                    Ok(packet) => self.up = Some(PacketEvent::Packet(packet)),
                    Err(_) => env.report(IpReport::Malformed),
                }
            }
            Intake::Waiting => {}
            Intake::Discarded => env.report(IpReport::Malformed),
            Intake::Refused { answer, .. } => {
                let answer = answer.filter(|_| !self.output_closed);
                env.report(IpReport::Refused {
                    answered: answer.is_some(),
                });
                self.answer = answer;
            }
        }
    }
}

impl Layer for HopLimit {
    type Lower = Packets<Chunk, Chunk>;
    type Upper = Packets<CheckedIpPacket, Chunk>;
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

    fn on_timer(&mut self, env: &mut Env<'_, IpReport>, (): ()) -> Result<bool, Infallible> {
        self.reassembly.expire(env.now());
        Ok(true)
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

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::layer::{Budget, Driver};
    use fictionet::stdlib::network::ip;
    use fictionet::{Seed, SeededEntropy};
    use std::sync::Arc;

    #[test]
    fn malformed_input_is_reported_without_reaching_transports() {
        let mut fragment = ip::packet(
            "10.0.0.2".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            ip::protocol::UDP,
            &[0; 9],
        )
        .to_vec();
        fragment[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        ip::set_header_checksum(&mut fragment[..20]);
        let mut driver = Driver::new(
            HopLimit::new(std::num::NonZeroU8::new(32).unwrap()),
            Arc::new(SeededEntropy::new(Seed::from_u64(1))),
            Budget::unlimited(),
            Instant::ZERO,
        );
        for bytes in [vec![0x45], fragment] {
            assert!(matches!(
                driver.deliver(PacketEvent::Packet(Chunk::unpaid(bytes))),
                Ok(Admit::Taken)
            ));
            driver.send_above(|_| panic!("malformed input reached a transport"));
            assert!(matches!(
                driver.observations().drain().collect::<Vec<_>>().as_slice(),
                [IpReport::Malformed]
            ));
        }
    }
}
