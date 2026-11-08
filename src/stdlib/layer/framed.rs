use core::convert::Infallible;
use core::marker::PhantomData;

use fictionet::stdlib::codec::{Decode, Fail, Stream, Wire};
use fictionet::stdlib::layer::{
    Admit, ByteStream, Charge, Chunk, Env, Layer, MessageCommand, MessageEvent, Messages,
    StreamCommand, StreamEvent,
};

/// What a framed byte stream hands up: the next item, or why framing
/// stopped.
pub type Decoded<D> = Result<<D as Decode>::Item, Fail<<D as Decode>::Error>>;

/// The message port [`Framed`] offers: items of `D` up, values of `O`
/// down.
pub type Framing<D, O> = Messages<Decoded<D>, O>;

/// A byte stream framed into messages: decoded with `D` coming up, written
/// as [`Wire`] values of `O` going down. Modbus/TCP, a length-prefixed
/// RPC, line protocols.
///
/// A protocol that reads whole messages goes on top of this with
/// [`Chain`](super::Chain), so it never handles bytes, buffers or partial
/// writes itself.
///
/// Coming up, each item is one [`MessageEvent::Message`]. If the decoder
/// fails, the failure comes up as one `Message(Err(_))`, and then
/// [`MessageEvent::Ended`]: no reader can find the next message in what
/// follows, and the protocol above decides what to answer. The peer ending
/// its direction, or resetting the connection, also ends the input. A
/// decoder that ends ([`Step::End`](fictionet::stdlib::codec::Step::End))
/// ends the input too; a protocol whose framing changes at a boundary uses
/// [`Switch`](super::Switch) instead.
///
/// Going down, each value is written whole, after the ones before.
/// [`MessageCommand::End`] ends the direction after them.
///
/// The decoder's buffer and state are charged to the connection's
/// [`Budget`](super::Budget) before bytes are buffered, and each written
/// value carries its own charge until the transport takes it.
pub struct Framed<D: Decode, O> {
    stream: Stream<D>,
    charge: Option<Charge>,
    out: Option<Chunk>,
    /// The upper side asked to end the direction.
    end: bool,
    end_sent: bool,
    /// No more input comes from below: the peer ended or reset it, or the
    /// decoder failed or ended.
    input_over: bool,
    ended_sent: bool,
    reset: bool,
    sent: PhantomData<fn(O)>,
}

impl<D: Decode, O> Framed<D, O> {
    /// Frames with `decoder`, buffering at most its capacity.
    pub fn new(decoder: D) -> Framed<D, O> {
        Framed {
            stream: Stream::new(decoder),
            charge: None,
            out: None,
            end: false,
            end_sent: false,
            input_over: false,
            ended_sent: false,
            reset: false,
            sent: PhantomData,
        }
    }

    /// Charges the buffer as it may grow and the decoder's state. The
    /// buffer never grows past its limit, so charging the limit is enough
    /// before taking bytes.
    fn charge(&mut self, env: &Env<'_, Infallible>) -> Result<(), FramedError<O>>
    where
        O: Wire,
    {
        let need = self
            .stream
            .limit()
            .max(self.stream.allocated())
            .saturating_add(self.stream.held());
        let fits = match &mut self.charge {
            Some(charge) => charge.set(need),
            None => {
                self.charge = env.budget().charge(need);
                self.charge.is_some()
            }
        };
        if fits {
            Ok(())
        } else {
            Err(FramedError::Budget)
        }
    }
}

impl<D, O> Layer for Framed<D, O>
where
    D: Decode,
    D::Error: Clone,
    O: Wire,
{
    type Lower = ByteStream;
    type Upper = Framing<D, O>;
    type Report = Infallible;
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = FramedError<O>;

    fn on_event(
        &mut self,
        env: &mut Env<'_, Infallible>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, FramedError<O>> {
        match event {
            // The protocol above hears nothing of write completion.
            StreamEvent::Written(_) => Ok(Admit::Taken),
            event if self.input_over || self.stream.is_eof() => Ok(Admit::Closed(event)),
            StreamEvent::Data(mut chunk) => {
                if chunk.is_empty() {
                    return Ok(Admit::Taken);
                }
                self.charge(env)?;
                let n = self.stream.push(&chunk);
                if n == 0 {
                    return Ok(Admit::Blocked(StreamEvent::Data(chunk)));
                }
                chunk.advance(n);
                Ok(if chunk.is_empty() {
                    Admit::Taken
                } else {
                    Admit::Partial(StreamEvent::Data(chunk))
                })
            }
            StreamEvent::Ended => {
                // What is buffered is still decoded.
                self.stream.end();
                Ok(Admit::Taken)
            }
            StreamEvent::Reset => {
                self.reset = true;
                self.input_over = true;
                self.out = None;
                Ok(Admit::Taken)
            }
        }
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, Infallible>,
        command: MessageCommand<O>,
    ) -> Result<Admit<MessageCommand<O>>, FramedError<O>> {
        if self.reset || self.end {
            return Ok(Admit::Closed(command));
        }
        match command {
            MessageCommand::Send(value) => {
                if self.out.is_some() {
                    return Ok(Admit::Blocked(MessageCommand::Send(value)));
                }
                let mut bytes = Vec::new();
                value.write(&mut bytes).map_err(FramedError::Write)?;
                let charge = env
                    .budget()
                    .charge(bytes.capacity())
                    .ok_or(FramedError::Budget)?;
                self.out = Some(Chunk::with_charge(bytes, charge));
                Ok(Admit::Taken)
            }
            MessageCommand::End => {
                self.end = true;
                Ok(Admit::Taken)
            }
        }
    }

    fn take_command(&mut self) -> Option<StreamCommand> {
        if self.reset {
            return None;
        }
        if let Some(chunk) = self.out.take() {
            return Some(StreamCommand::Write(chunk));
        }
        if self.end && !self.end_sent {
            self.end_sent = true;
            return Some(StreamCommand::End);
        }
        None
    }

    fn take_event(&mut self) -> Option<MessageEvent<Decoded<D>>> {
        if self.ended_sent {
            return None;
        }
        if !self.input_over {
            match self.stream.next() {
                Some(Ok(item)) => return Some(MessageEvent::Message(Ok(item))),
                Some(Err(fail)) => {
                    self.input_over = true;
                    return Some(MessageEvent::Message(Err(fail)));
                }
                None if self.stream.is_done() => self.input_over = true,
                None => return None,
            }
        }
        self.ended_sent = true;
        Some(MessageEvent::Ended)
    }
}

/// Why [`Framed`] gave up on its connection.
pub enum FramedError<O: Wire> {
    /// The connection's budget had no room for the decoder's buffer or a
    /// written value.
    Budget,
    /// The protocol above sent a value its wire format cannot hold.
    Write(O::WriteError),
}

impl<O: Wire> core::fmt::Debug for FramedError<O> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FramedError::Budget => f.write_str("Budget"),
            FramedError::Write(e) => f.debug_tuple("Write").field(&format_args!("{e}")).finish(),
        }
    }
}

impl<O: Wire> core::fmt::Display for FramedError<O> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FramedError::Budget => f.write_str("the connection's budget has no room"),
            FramedError::Write(_) => f.write_str("a value could not be written"),
        }
    }
}

impl<O: Wire> core::error::Error for FramedError<O> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            FramedError::Budget => None,
            FramedError::Write(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    //! A frame echo on top of [`Framed`], over Modbus/TCP framing. The
    //! tests compare what comes out with what went in, never fixed bytes.

    use super::*;
    use fictionet::Seed;
    use fictionet::stdlib::codec::Frames;
    use fictionet::stdlib::layer::{Budget, Chain, Harness, Side, Top};
    use fictionet::stdlib::protocols::modbus::{self, Frame};

    type Port = Framing<Frames<Frame>, Frame>;

    /// Answers every frame with itself, one at a time, and ends its
    /// direction once its input is over.
    #[derive(Default)]
    struct Echo {
        reply: Option<Frame>,
        over: bool,
        end_sent: bool,
        failures: usize,
    }

    impl Layer for Echo {
        type Lower = Port;
        type Upper = Top;
        type Report = Infallible;
        type Timer = ();
        type Work = Infallible;
        type Done = Infallible;
        type Error = Infallible;

        fn on_event(
            &mut self,
            _env: &mut Env<'_, Infallible>,
            event: MessageEvent<Decoded<Frames<Frame>>>,
        ) -> Result<Admit<MessageEvent<Decoded<Frames<Frame>>>>, Infallible> {
            if self.over {
                return Ok(Admit::Closed(event));
            }
            match event {
                MessageEvent::Message(Ok(frame)) => {
                    if self.reply.is_some() {
                        return Ok(Admit::Blocked(MessageEvent::Message(Ok(frame))));
                    }
                    self.reply = Some(frame);
                }
                MessageEvent::Message(Err(_)) => self.failures += 1,
                MessageEvent::Ended => self.over = true,
            }
            Ok(Admit::Taken)
        }

        fn on_command(
            &mut self,
            _env: &mut Env<'_, Infallible>,
            command: Infallible,
        ) -> Result<Admit<Infallible>, Infallible> {
            match command {}
        }

        fn take_command(&mut self) -> Option<MessageCommand<Frame>> {
            if let Some(frame) = self.reply.take() {
                return Some(MessageCommand::Send(frame));
            }
            if self.over && !self.end_sent {
                self.end_sent = true;
                return Some(MessageCommand::End);
            }
            None
        }

        fn take_event(&mut self) -> Option<Infallible> {
            None
        }
    }

    type Stack = Chain<Framed<Frames<Frame>, Frame>, Echo>;

    fn stack() -> Stack {
        Chain::new(Framed::new(Frames::new()), Echo::default())
    }

    fn frames(count: u16) -> Vec<Frame> {
        (0..count)
            .map(|i| Frame {
                transaction: i,
                unit: 1,
                pdu: vec![0x03, 0, i as u8, 0, 1 + (i % 7) as u8],
            })
            .collect()
    }

    fn wire(frames: &[Frame]) -> Vec<u8> {
        frames
            .iter()
            .flat_map(|f| f.to_bytes().expect("a test frame is valid"))
            .collect()
    }

    /// Every frame in `bytes`, which must hold nothing else.
    fn read(mut bytes: &[u8]) -> Vec<Frame> {
        let mut out = Vec::new();
        while !bytes.is_empty() {
            let (frame, used) = Frame::parse_prefix(bytes)
                .expect("the output is Modbus")
                .expect("the output holds whole frames");
            out.push(frame);
            bytes = &bytes[used..];
        }
        out
    }

    #[test]
    fn every_cut_of_the_input_gets_every_frame_back_in_order() {
        let sent = frames(3);
        let input = wire(&sent);
        for cut in 0..=input.len() {
            for (first, second) in [(cut, input.len()), (cut / 2, cut)] {
                let mut h = Harness::new(Seed::from_u64(1), stack());
                h.push(&input[..first]).unwrap();
                h.push(&input[first..second]).unwrap();
                h.push(&input[second..]).unwrap();
                h.end().unwrap();
                assert_eq!(read(h.output()), sent, "cut at {first} and {second}");
                assert!(h.ended(), "the end of input comes back as an end");
                assert_eq!(h.unread(), 0);
            }
        }
    }

    #[test]
    fn a_peer_that_stops_reading_backs_input_up_and_loses_nothing() {
        let sent = frames(40);
        let mut h = Harness::new(Seed::from_u64(2), stack());
        h.withhold();
        h.push(&wire(&sent)).unwrap();
        assert!(h.output().is_empty(), "the transport took nothing");
        assert!(h.unread() > 0, "input waits with its sender");
        let mut rounds = 0;
        while h.output().len() < wire(&sent).len() {
            h.allow(3).unwrap();
            rounds += 1;
            assert!(rounds < 10_000, "output stopped coming");
        }
        assert_eq!(read(h.output()), sent);
        assert_eq!(h.unread(), 0);
    }

    #[test]
    fn a_framing_error_comes_up_once_after_the_frames_before_it() {
        let sent = frames(2);
        let mut input = wire(&sent);
        // A protocol identifier that is not Modbus.
        input.extend_from_slice(&[0, 9, 0, 7, 0, 2, 1, 3]);
        input.extend_from_slice(&wire(&frames(1)));
        let mut h = Harness::new(Seed::from_u64(3), stack());
        h.push(&input).unwrap();
        assert_eq!(read(h.output()), sent, "the frames before it are answered");
        assert_eq!(h.layer().upper().failures, 1);
        assert!(
            h.ended(),
            "no frame can be found after it, so input is over"
        );
    }

    #[test]
    fn input_cut_short_by_the_peer_is_a_failure_then_the_end() {
        let sent = frames(1);
        let mut input = wire(&sent);
        input.extend_from_slice(&wire(&frames(2))[..9]);
        let mut h = Harness::new(Seed::from_u64(4), stack());
        h.push(&input).unwrap();
        assert!(!h.ended());
        h.end().unwrap();
        assert_eq!(read(h.output()), sent);
        assert_eq!(h.layer().upper().failures, 1);
        assert!(h.ended());
    }

    #[test]
    fn a_budget_without_room_for_the_buffer_gives_up_before_taking_bytes() {
        let small = Budget::new(modbus::MAX_FRAME - 1);
        let mut h = Harness::with_budget(Seed::from_u64(5), stack(), small.clone());
        assert!(matches!(
            h.push(&wire(&frames(1))),
            Err(Side::Lower(FramedError::Budget))
        ));
        assert_eq!(small.used(), 0, "nothing stays charged");

        let roomy = Budget::new(1 << 16);
        let mut h = Harness::with_budget(Seed::from_u64(5), stack(), roomy.clone());
        h.push(&wire(&frames(4))).unwrap();
        assert!(roomy.used() >= modbus::MAX_FRAME, "the buffer is charged");
        drop(h);
        assert_eq!(roomy.used(), 0, "every charge comes back");
    }
}
