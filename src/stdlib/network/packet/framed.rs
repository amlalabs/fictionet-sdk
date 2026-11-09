//! A byte stream carrying whole packets with a four-byte big-endian length.

use super::Ingress;
use core::convert::Infallible;
use fictionet::stdlib::layer::{
    Admit, ByteStream, Charge, Chunk, Datagram, Env, Layer, PacketCommand, PacketEvent, Packets,
    StreamCommand, StreamEvent,
};

/// A stream tunnel's packet boundaries. Arrival metadata belongs to the
/// tunnel owner and is never read from the peer's bytes.
/// The payload kind is raw IP, without a link header; an inner [`super::IpLayer`]
/// validates the packet. This format does not imply another tunnel protocol.
///
/// Holds at most one packet in each direction, plus a partial length prefix.
/// Packets may be empty. Lengths above 65,575 bytes (a full IPv6 packet)
/// and truncated frames fail the tunnel. Buffered bytes are budgeted before
/// allocation. Backpressure retains input ownership, including when a read
/// contains several frames.
pub struct Framed {
    ingress: Ingress,
    prefix: [u8; 4],
    prefix_len: usize,
    body: Vec<u8>,
    charge: Option<Charge>,
    size: Option<usize>,
    packet: Option<PacketEvent<Datagram<Ingress>>>,
    output: Option<StreamCommand>,
    ended: bool,
    output_end: bool,
}

/// Why a packet stream could not continue.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The length exceeds the largest supported IP packet.
    TooLong,
    /// Input ended inside a length prefix or packet.
    Truncated,
    /// The packet's storage does not fit the allocation budget.
    Budget,
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::TooLong => "packet frame is too long",
            Self::Truncated => "packet frame is truncated",
            Self::Budget => "packet frame exceeds its memory budget",
        })
    }
}
impl core::error::Error for FrameError {}

impl Framed {
    /// Frames for one network and interface, identified by `ingress`.
    pub fn new(ingress: Ingress) -> Self {
        Self {
            ingress,
            prefix: [0; 4],
            prefix_len: 0,
            body: Vec::new(),
            charge: None,
            size: None,
            packet: None,
            output: None,
            ended: false,
            output_end: false,
        }
    }
}

impl Layer for Framed {
    type Lower = ByteStream;
    type Upper = Packets<Datagram<Ingress>, Chunk>;
    type Report = Infallible;
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = FrameError;

    fn on_event(
        &mut self,
        env: &mut Env<'_, Infallible>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, FrameError> {
        if matches!(event, StreamEvent::Written(_)) {
            return Ok(Admit::Taken);
        }
        if matches!(event, StreamEvent::Reset) {
            self.body = Vec::new();
            self.charge = None;
            self.size = None;
            self.prefix_len = 0;
            // The packets above end once: a reset after the stream's end,
            // which a peer may send, ends nothing more.
            if !self.ended {
                self.packet = Some(PacketEvent::Ended);
            }
            self.output = None;
            self.ended = true;
            self.output_end = true;
            return Ok(Admit::Taken);
        }
        if self.ended {
            return Ok(Admit::Closed(event));
        }
        if self.packet.is_some() {
            return Ok(Admit::Blocked(event));
        }
        let StreamEvent::Data(mut bytes) = event else {
            if self.prefix_len > 0 || self.size.is_some() {
                return Err(FrameError::Truncated);
            }
            self.ended = true;
            self.packet = Some(PacketEvent::Ended);
            return Ok(Admit::Taken);
        };
        if self.prefix_len < 4 {
            let count = (4 - self.prefix_len).min(bytes.len());
            self.prefix[self.prefix_len..self.prefix_len + count].copy_from_slice(&bytes[..count]);
            self.prefix_len += count;
            bytes.advance(count);
            if self.prefix_len < 4 {
                return Ok(Admit::Taken);
            }
        }
        let size = u32::from_be_bytes(self.prefix) as usize;
        if size > 65_575 {
            return Err(FrameError::TooLong);
        }
        if self.size.is_none() {
            self.charge = Some(env.budget().charge(size).ok_or(FrameError::Budget)?);
            self.body = Vec::with_capacity(size);
            self.size = Some(size);
        }
        let count = (size - self.body.len()).min(bytes.len());
        self.body.extend_from_slice(&bytes[..count]);
        bytes.advance(count);
        if self.body.len() == size {
            let packet = Chunk::with_charge(
                core::mem::take(&mut self.body),
                self.charge.take().expect("reserved frame"),
            );
            self.packet = Some(PacketEvent::Packet(Datagram::new(packet, self.ingress)));
            self.prefix_len = 0;
            self.size = None;
        }
        Ok(if bytes.is_empty() {
            Admit::Taken
        } else {
            Admit::Partial(StreamEvent::Data(bytes))
        })
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, Infallible>,
        command: PacketCommand<Chunk>,
    ) -> Result<Admit<PacketCommand<Chunk>>, FrameError> {
        if self.output_end {
            return Ok(Admit::Closed(command));
        }
        if self.output.is_some() {
            return Ok(Admit::Blocked(command));
        }
        self.output = Some(match command {
            PacketCommand::Send(packet) => {
                if packet.len() > 65_575 {
                    return Err(FrameError::TooLong);
                }
                let charge = env
                    .budget()
                    .charge(packet.len() + 4)
                    .ok_or(FrameError::Budget)?;
                let mut frame = Vec::with_capacity(packet.len() + 4);
                frame.extend_from_slice(&(packet.len() as u32).to_be_bytes());
                frame.extend_from_slice(&packet);
                StreamCommand::Write(Chunk::with_charge(frame, charge))
            }
            PacketCommand::End => {
                self.output_end = true;
                StreamCommand::End
            }
        });
        Ok(Admit::Taken)
    }
    fn take_command(&mut self) -> Option<StreamCommand> {
        self.output.take()
    }
    fn take_event(&mut self) -> Option<PacketEvent<Datagram<Ingress>>> {
        self.packet.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::Seed;
    use fictionet::stdlib::layer::{Budget, Harness};

    #[test]
    fn end_and_reset_refuse_later_packets() {
        for reset in [false, true] {
            let mut stack = Harness::new(Seed::from_u64(1), Framed::new(Ingress::default()));
            if reset {
                assert!(stack.driver().deliver(StreamEvent::Reset).unwrap().moved());
            } else {
                assert!(stack.driver().command(PacketCommand::End).unwrap().moved());
            }
            stack.settle().unwrap();
            let Admit::Closed(PacketCommand::Send(packet)) = stack
                .driver()
                .command(PacketCommand::Send(Chunk::new(b"late".to_vec())))
                .unwrap()
            else {
                panic!("output has ended");
            };
            assert_eq!(&*packet, b"late");
            assert!(stack.output().is_empty());
        }
    }

    /// A peer may reset a stream after its end. The packets above end once.
    #[test]
    fn a_reset_after_the_end_ends_the_packets_once() {
        let mut stack = Harness::new(Seed::from_u64(1), Framed::new(Ingress::default()));
        let mut ends = 0;
        for event in [StreamEvent::Ended, StreamEvent::Reset] {
            let _ = stack.driver().deliver(event).unwrap();
            stack.settle().unwrap();
            stack.driver().send_above(|event| {
                ends += usize::from(matches!(event, PacketEvent::Ended));
                Admit::Taken
            });
        }
        assert_eq!(ends, 1);
    }

    #[test]
    fn held_output_preserves_frames_across_partial_and_zero_writes() {
        let mut stack = Harness::new(Seed::from_u64(1), Framed::new(Ingress::default()));
        stack.withhold();
        assert!(
            stack
                .driver()
                .command(PacketCommand::Send(Chunk::new(b"first".to_vec())))
                .unwrap()
                .moved()
        );
        stack.settle().unwrap();
        assert!(
            stack
                .driver()
                .command(PacketCommand::Send(Chunk::new(b"second".to_vec())))
                .unwrap()
                .moved()
        );
        let third = PacketCommand::Send(Chunk::new(b"third".to_vec()));
        let Admit::Blocked(third) = stack.driver().command(third).unwrap() else {
            panic!("both output places are occupied");
        };
        assert!(stack.output().is_empty());
        stack.allow(2).unwrap();
        assert_eq!(stack.take_output(), [0, 0]);
        stack.allow_all().unwrap();
        assert_eq!(stack.take_output(), b"\0\x05first\0\0\0\x06second");
        assert!(stack.driver().command(third).unwrap().moved());
        stack.settle().unwrap();
        assert_eq!(stack.take_output(), b"\0\0\0\x05third");
    }

    #[test]
    fn all_stream_cuts_preserve_packet_boundaries_and_empty_packets() {
        let packets: [&[u8]; 3] = [b"first", b"", b"last packet"];
        let wire: Vec<_> = packets
            .iter()
            .flat_map(|bytes| {
                (bytes.len() as u32)
                    .to_be_bytes()
                    .into_iter()
                    .chain(bytes.iter().copied())
            })
            .collect();
        for cut in 0..=wire.len() {
            let ingress = Ingress {
                link: 17,
                ..Ingress::default()
            };
            let budget = Budget::new(4096);
            let mut stack =
                Harness::with_budget(Seed::from_u64(1), Framed::new(ingress), budget.clone());
            let mut received = Vec::new();
            for bytes in [&wire[..cut], &wire[cut..]] {
                stack.push(bytes).unwrap();
                for _ in 0..4 {
                    stack.driver().send_above(|event| {
                        if let PacketEvent::Packet(packet) = event {
                            assert_eq!(*packet.meta(), ingress);
                            received.push(packet.into_parts().0.into_vec());
                        }
                        Admit::Taken
                    });
                    stack.settle().unwrap();
                }
            }
            assert_eq!(received, packets);
            assert_eq!(stack.unread(), 0);
            drop(stack);
            assert_eq!(budget.used(), 0);
        }
    }

    #[test]
    fn truncated_and_oversized_frames_fail_before_payload_allocation() {
        for bytes in [&[0, 0][..], &[0, 0, 0, 2, 1]] {
            let mut stack = Harness::new(Seed::from_u64(1), Framed::new(Ingress::default()));
            stack.push(bytes).unwrap();
            assert_eq!(stack.end(), Err(FrameError::Truncated));
        }
        let mut stack = Harness::with_budget(
            Seed::from_u64(1),
            Framed::new(Ingress::default()),
            Budget::new(1024),
        );
        assert_eq!(
            stack.push(&u32::MAX.to_be_bytes()),
            Err(FrameError::TooLong)
        );
        let mut stack = Harness::with_budget(
            Seed::from_u64(1),
            Framed::new(Ingress::default()),
            Budget::new(1024),
        );
        assert_eq!(stack.push(&2048u32.to_be_bytes()), Err(FrameError::Budget));
    }
}
