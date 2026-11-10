//! A byte stream carrying whole packets with a four-byte big-endian length.

use core::convert::Infallible;
use fictionet::stdlib::layer::{
    Admit, ByteStream, ChargedBytes, Chunk, Env, Layer, PacketCommand, PacketEvent, Packets,
    StreamCommand, StreamEvent,
};

/// A stream tunnel's packet boundaries. It hands up raw packets for the
/// tunnel's own endpoint, so the tunnel's network gets an IP layer of its
/// own; nothing about where a packet came from is read from the peer's
/// bytes. The payload kind is raw IP, without a link header; the inner
/// [`super::IpLayer`] validates the packet. This format does not imply
/// another tunnel protocol.
///
/// Holds at most one packet in each direction, plus a partial length prefix.
/// Packets may be empty. Lengths above 65,575 bytes (a full IPv6 packet)
/// and truncated frames fail the tunnel. Buffered bytes are budgeted before
/// allocation. A refused reservation returns the offered input or output
/// unchanged as [`Admit::Blocked`]. Backpressure retains input ownership,
/// including when a read contains several frames.
#[derive(Default)]
pub struct Framed {
    prefix: [u8; 4],
    prefix_len: usize,
    /// The packet being read, in room for exactly the length its prefix
    /// gave, paid for before it was allocated.
    body: Option<ChargedBytes>,
    packet: Option<PacketEvent<Chunk>>,
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
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::TooLong => "packet frame is too long",
            Self::Truncated => "packet frame is truncated",
        })
    }
}
impl core::error::Error for FrameError {}

impl Framed {
    /// Frames raw IP packets for the tunnel owner's input path.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Layer for Framed {
    type Lower = ByteStream;
    type Upper = Packets<Chunk, Chunk>;
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
            self.body = None;
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
            if self.prefix_len > 0 || self.body.is_some() {
                return Err(FrameError::Truncated);
            }
            self.ended = true;
            self.packet = Some(PacketEvent::Ended);
            return Ok(Admit::Taken);
        };
        let count = (4 - self.prefix_len).min(bytes.len());
        let mut prefix = self.prefix;
        prefix[self.prefix_len..self.prefix_len + count].copy_from_slice(&bytes[..count]);
        if self.prefix_len + count < 4 {
            self.prefix = prefix;
            self.prefix_len += count;
            return Ok(Admit::Taken);
        }
        let size = u32::from_be_bytes(prefix) as usize;
        if size > 65_575 {
            return Err(FrameError::TooLong);
        }
        let body = match &mut self.body {
            Some(body) => body,
            None => {
                let Some(body) = ChargedBytes::with_capacity(env.budget(), size) else {
                    return Ok(Admit::Blocked(StreamEvent::Data(bytes)));
                };
                self.body.insert(body)
            }
        };
        self.prefix = prefix;
        self.prefix_len = 4;
        bytes.advance(count);
        let count = body.room().min(bytes.len());
        body.extend_within(&bytes[..count])
            .expect("the input fits in the reserved body");
        bytes.advance(count);
        if body.room() == 0
            && let Some(body) = self.body.take()
        {
            self.packet = Some(PacketEvent::Packet(Chunk::from(body)));
            self.prefix_len = 0;
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
                let Some(mut frame) = ChargedBytes::with_capacity(env.budget(), packet.len() + 4)
                else {
                    return Ok(Admit::Blocked(PacketCommand::Send(packet)));
                };
                frame
                    .extend_within(&(packet.len() as u32).to_be_bytes())
                    .and_then(|()| frame.extend_within(&packet))
                    .expect("the prefix and packet fit in the reserved frame");
                StreamCommand::Write(Chunk::from(frame))
            }
            PacketCommand::End => {
                self.output_end = true;
                StreamCommand::End
            }
        });
        Ok(Admit::Taken)
    }
    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
        self.output.take()
    }
    fn take_event(&mut self) -> Option<PacketEvent<Chunk>> {
        self.packet.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::Seed;
    use fictionet::stdlib::layer::{Budget, Harness};

    #[test]
    fn writes_wait_for_memory_without_losing_or_repeating_packets() {
        for len in 0..32 {
            let expected: Vec<_> = (0..len).collect();
            let budget = Budget::new(4096);
            let mut stack = Harness::with_budget(Seed::from_u64(1), Framed::new(), budget.clone());
            let packet = Chunk::from(ChargedBytes::copy_of(&budget, &expected).unwrap());
            let pointer = packet.as_ptr();
            let paid = budget.used();
            let held = budget.charge(budget.limit() - paid).unwrap();
            let mut command = PacketCommand::Send(packet);
            for _ in 0..3 {
                let Admit::Blocked(PacketCommand::Send(packet)) =
                    stack.driver().command(command).unwrap()
                else {
                    panic!("a packet without room must wait");
                };
                assert_eq!(&*packet, expected);
                assert_eq!(packet.as_ptr(), pointer);
                assert_eq!(budget.used(), held.bytes() + paid);
                command = PacketCommand::Send(packet);
                stack.settle().unwrap();
                assert!(stack.output().is_empty());
            }
            drop(held);
            assert!(matches!(
                stack.driver().command(command).unwrap(),
                Admit::Taken
            ));
            stack.settle().unwrap();
            stack.settle().unwrap();
            let output = stack.output();
            let size = u32::from_be_bytes(output[..4].try_into().unwrap()) as usize;
            assert_eq!(size, expected.len());
            assert_eq!(&output[4..], expected);
            drop(stack);
            assert_eq!(budget.used(), 0);
        }
    }

    #[test]
    fn input_waits_for_memory_at_every_prefix_cut() {
        let expected: Vec<_> = (0..32).collect();
        let wire: Vec<_> = (expected.len() as u32)
            .to_be_bytes()
            .into_iter()
            .chain(expected.iter().copied())
            .collect();
        for cut in 0..=4 {
            let budget = Budget::new(4096);
            let mut stack = Harness::with_budget(Seed::from_u64(1), Framed::new(), budget.clone());
            let held = budget.charge(budget.limit()).unwrap();
            stack.push(&wire[..cut]).unwrap();
            stack.push(&wire[cut..]).unwrap();
            assert_eq!(budget.used(), held.bytes());
            assert!(stack.layer().packet.is_none());
            assert!(stack.layer().body.is_none());
            drop(held);
            stack.settle().unwrap();
            let mut received = Vec::new();
            stack.driver().send_above(|event| {
                if let PacketEvent::Packet(packet) = event {
                    received.push(packet.into_vec());
                }
                Admit::Taken
            });
            stack.settle().unwrap();
            assert_eq!(received, vec![expected.clone()]);
            assert!(stack.layer().packet.is_none());
            assert_eq!(stack.unread(), 0);
            drop(stack);
            assert_eq!(budget.used(), 0);
        }
    }

    #[test]
    fn end_and_reset_refuse_later_packets() {
        for reset in [false, true] {
            let mut stack = Harness::new(Seed::from_u64(1), Framed::new());
            if reset {
                assert!(stack.driver().deliver(StreamEvent::Reset).unwrap().moved());
            } else {
                assert!(stack.driver().command(PacketCommand::End).unwrap().moved());
            }
            stack.settle().unwrap();
            let Admit::Closed(PacketCommand::Send(packet)) = stack
                .driver()
                .command(PacketCommand::Send(Chunk::unpaid(b"late".to_vec())))
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
        let mut stack = Harness::new(Seed::from_u64(1), Framed::new());
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
        let mut stack = Harness::new(Seed::from_u64(1), Framed::new());
        stack.withhold();
        assert!(
            stack
                .driver()
                .command(PacketCommand::Send(Chunk::unpaid(b"first".to_vec())))
                .unwrap()
                .moved()
        );
        stack.settle().unwrap();
        assert!(
            stack
                .driver()
                .command(PacketCommand::Send(Chunk::unpaid(b"second".to_vec())))
                .unwrap()
                .moved()
        );
        let third = PacketCommand::Send(Chunk::unpaid(b"third".to_vec()));
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
            let budget = Budget::new(4096);
            let mut stack = Harness::with_budget(Seed::from_u64(1), Framed::new(), budget.clone());
            let mut received = Vec::new();
            for bytes in [&wire[..cut], &wire[cut..]] {
                stack.push(bytes).unwrap();
                for _ in 0..4 {
                    stack.driver().send_above(|event| {
                        if let PacketEvent::Packet(packet) = event {
                            received.push(packet.into_vec());
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
            let mut stack = Harness::new(Seed::from_u64(1), Framed::new());
            stack.push(bytes).unwrap();
            assert_eq!(stack.end(), Err(FrameError::Truncated));
        }
        let mut stack = Harness::with_budget(Seed::from_u64(1), Framed::new(), Budget::new(1024));
        assert_eq!(
            stack.push(&u32::MAX.to_be_bytes()),
            Err(FrameError::TooLong)
        );
        let budget = Budget::new(1024);
        let mut stack = Harness::with_budget(Seed::from_u64(1), Framed::new(), budget.clone());
        let prefix = ((budget.limit() + 1) as u32).to_be_bytes();
        // The stack charges through its driver's view of the budget.
        let mark = stack.driver().refusals();
        let Admit::Blocked(StreamEvent::Data(bytes)) = stack
            .driver()
            .deliver(StreamEvent::Data(Chunk::unpaid(prefix.to_vec())))
            .unwrap()
        else {
            panic!("memory refusal leaves the input with its sender");
        };
        assert_eq!(&*bytes, &prefix);
        assert!(stack.layer().body.is_none());
        assert_eq!(stack.layer().prefix_len, 0);
        assert_eq!(budget.used(), 0);
        // A body larger than the whole limit can never be paid: the runner
        // reads the refusal as starved and ends the tunnel.
        let starved = stack
            .driver()
            .budget()
            .starved_since(mark)
            .expect("a need over the limit");
        assert!(starved.need > starved.limit);
    }
}
