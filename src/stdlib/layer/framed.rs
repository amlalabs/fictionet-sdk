use core::convert::Infallible;
use core::marker::PhantomData;

use fictionet::stdlib::codec::{Decode, Fail, Stream, Wire};
use fictionet::stdlib::layer::{
    Admit, Budget, ByteStream, Charge, Chunk, Env, Layer, MessageCommand, MessageEvent, Messages,
    StreamCommand, StreamEvent,
};

/// A wire writer whose output allocation is known before writing.
/// Implementations write only through the supplied bounded destination.
pub trait BoundedWire: Wire {
    /// Maximum output capacity needed by `write_bounded`, computed without allocating.
    fn write_bound(&self) -> Result<usize, Self::WriteError>;

    /// Writes without allocating outside the destination. Exceeding its bound
    /// is a connection error even if the implementation returns success.
    fn write_bounded(&self, out: &mut BoundedWriter<'_>) -> Result<(), Self::WriteError>;
}

/// A fixed allocation for a codec's output. Writes past its end are refused;
/// the framing layer detects that failure even if the codec ignores it.
pub struct BoundedWriter<'a> {
    bytes: &'a mut [u8],
    written: usize,
    exceeded: bool,
}

impl<'a> BoundedWriter<'a> {
    /// Writes into this slice without growing it.
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            bytes,
            written: 0,
            exceeded: false,
        }
    }

    /// Appends one byte, or marks the writer as exceeded.
    pub fn push(&mut self, byte: u8) {
        self.extend_from_slice(&[byte]);
    }

    /// Appends all bytes, or marks the writer as exceeded without copying.
    /// Once exceeded, it accepts no further bytes.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        if self.exceeded || bytes.len() > self.bytes.len() - self.written {
            self.exceeded = true;
            return;
        }
        let end = self.written + bytes.len();
        self.bytes[self.written..end].copy_from_slice(bytes);
        self.written = end;
    }

    /// The number written, or an error if any write exceeded the capacity.
    pub fn finish(self) -> Result<usize, WriteFailure<Infallible>> {
        if self.exceeded {
            Err(WriteFailure::Bound)
        } else {
            Ok(self.written)
        }
    }
}

/// Why a bounded encoding could not be completed.
#[derive(Debug)]
pub enum WriteFailure<E> {
    /// The value is not representable in its format.
    Value(E),
    /// The writer attempted more bytes than its declared bound.
    Bound,
}

impl<E: core::fmt::Display> core::fmt::Display for WriteFailure<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Value(error) => error.fmt(f),
            Self::Bound => f.write_str("the codec exceeded its output bound"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for WriteFailure<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Value(error) => Some(error),
            Self::Bound => None,
        }
    }
}

/// A decoder with a bound on allocations produced by its next step.
/// The bound covers owned items. Errors must not allocate, and decoding
/// must not grow retained state; use a layer with explicit reservations
/// for stateful decoding that allocates.
pub trait BoundedDecode: Decode {
    /// Maximum additional allocated bytes while decoding the next item.
    fn allocation_bound(&self) -> usize;
}

/// An owned value and the reservation that follows its allocation.
#[derive(Debug)]
pub struct Owned<T> {
    value: T,
    charge: Charge,
}

impl<T> Owned<T> {
    /// Attaches a reservation acquired before constructing the value.
    pub fn new(value: T, charge: Charge) -> Self {
        Self { value, charge }
    }

    /// Transfers both the value and its reservation to another owner.
    pub fn into_parts(self) -> (T, Charge) {
        (self.value, self.charge)
    }

    /// Reserved allocation bytes.
    pub fn charged(&self) -> usize {
        self.charge.bytes()
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Owned<T> {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl<T> core::ops::Deref for Owned<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

/// What a framed byte stream hands up: the next item, or why framing
/// stopped.
pub type Decoded<D> = Result<Owned<<D as Decode>::Item>, Fail<<D as Decode>::Error>>;

/// The message port [`Framed`] offers: items of `D` up, values of `O`
/// down.
pub type Framing<D, O> = Messages<Decoded<D>, Owned<O>>;

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
    budget: Option<Budget>,
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
            budget: None,
            out: None,
            end: false,
            end_sent: false,
            input_over: false,
            ended_sent: false,
            reset: false,
            sent: PhantomData,
        }
    }

    /// The bytes taken from below and not decoded. After a framing
    /// failure, what the decoder could not read.
    pub fn unread(&self) -> &[u8] {
        self.stream.unread()
    }

    /// Charges the buffer as it may grow and the decoder's state. The
    /// buffer's limit follows the decoder's capacity on the next push, and
    /// the buffer keeps a consumed prefix until it is as long as what is
    /// left, so it grows to at most twice that limit: charging that is
    /// enough before taking bytes.
    fn charge(&mut self, env: &Env<'_, Infallible>) -> Result<(), FramedError<O>>
    where
        O: Wire,
    {
        self.budget = Some(env.budget().clone());
        let limit = self.stream.limit().max(self.stream.decoder().capacity());
        let need = limit
            .saturating_mul(2)
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
    D: BoundedDecode,
    D::Error: Clone,
    O: BoundedWire,
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
        command: MessageCommand<Owned<O>>,
    ) -> Result<Admit<MessageCommand<Owned<O>>>, FramedError<O>> {
        if self.reset || self.end {
            return Ok(Admit::Closed(command));
        }
        match command {
            MessageCommand::Send(value) => {
                if self.out.is_some() {
                    return Ok(Admit::Blocked(MessageCommand::Send(value)));
                }
                let bound = value
                    .write_bound()
                    .map_err(|e| FramedError::Write(WriteFailure::Value(e)))?;
                let charge = env.budget().charge(bound).ok_or(FramedError::Budget)?;
                let mut bytes = vec![0; bound];
                let mut writer = BoundedWriter::new(&mut bytes);
                value
                    .write_bounded(&mut writer)
                    .map_err(|e| FramedError::Write(WriteFailure::Value(e)))?;
                let written = writer
                    .finish()
                    .map_err(|_| FramedError::Write(WriteFailure::Bound))?;
                bytes.truncate(written);
                self.out = Some(Chunk::with_charge(bytes, charge));
                Ok(Admit::Taken)
            }
            MessageCommand::End => {
                self.end = true;
                Ok(Admit::Taken)
            }
        }
    }

    fn advance(&mut self, env: &mut Env<'_, Infallible>) -> Result<bool, Self::Error> {
        if self.budget.is_none() {
            self.charge(env)?;
        }
        Ok(false)
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
            let budget = self.budget.as_ref()?;
            let bound = self.stream.decoder().allocation_bound();
            let Some(charge) = budget.charge(bound) else {
                self.input_over = true;
                return Some(MessageEvent::Message(Err(Fail::Refused {
                    unread: self.stream.buffered(),
                    limit: budget.limit(),
                })));
            };
            match self.stream.next() {
                Some(Ok(item)) => return Some(MessageEvent::Message(Ok(Owned::new(item, charge)))),
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
    Write(WriteFailure<O::WriteError>),
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

#[cfg(kani)]
#[path = "../../../verification/layer-runtime/kani/mod.rs"]
mod proofs;

#[cfg(test)]
pub(crate) mod tests {
    //! A frame echo on top of [`Framed`], over Modbus/TCP framing. The
    //! tests compare what comes out with what went in, never fixed bytes.

    use super::*;
    use fictionet::Seed;
    use fictionet::stdlib::codec::Frames;
    use fictionet::stdlib::layer::{Budget, Chain, Harness, Side, Top};
    use fictionet::stdlib::protocols::modbus::{self, Frame};

    pub(crate) type Port = Framing<Frames<Frame>, Frame>;

    /// Answers every frame with itself, one at a time, and ends its
    /// direction once its input is over.
    #[derive(Default)]
    pub(crate) struct Echo {
        reply: Option<Owned<Frame>>,
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

        fn take_command(&mut self) -> Option<MessageCommand<Owned<Frame>>> {
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

    pub(crate) type Stack = Chain<Framed<Frames<Frame>, Frame>, Echo>;

    pub(crate) fn stack() -> Stack {
        Chain::new(Framed::new(Frames::new()), Echo::default())
    }

    pub(crate) fn frames(count: u16) -> Vec<Frame> {
        (0..count)
            .map(|i| Frame {
                transaction: i,
                unit: 1,
                pdu: vec![0x03, 0, i as u8, 0, 1 + (i % 7) as u8],
            })
            .collect()
    }

    pub(crate) fn wire(frames: &[Frame]) -> Vec<u8> {
        frames
            .iter()
            .flat_map(|f| f.to_bytes().expect("a test frame is valid"))
            .collect()
    }

    /// Every frame in `bytes`, which must hold nothing else.
    pub(crate) fn read(mut bytes: &[u8]) -> Vec<Frame> {
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
    fn a_writer_exceeding_its_bound_fails_only_its_connection() {
        struct Oversized;
        impl Wire for Oversized {
            type ParseError = NoError;
            type WriteError = NoError;
            fn parse(_: &[u8]) -> Result<Self, NoError> {
                Ok(Self)
            }
            fn write(&self, out: &mut Vec<u8>) -> Result<(), NoError> {
                out.extend_from_slice(&[1, 2, 3]);
                Ok(())
            }
        }
        impl BoundedWire for Oversized {
            fn write_bounded(&self, out: &mut BoundedWriter<'_>) -> Result<(), NoError> {
                out.extend_from_slice(&[1, 2, 3]);
                Ok(())
            }
            fn write_bound(&self) -> Result<usize, NoError> {
                Ok(2)
            }
        }
        let budget = Budget::new(64);
        let mut d = super::super::Driver::new(
            Framed::<_, Oversized>::new(Widens { widened: false }),
            std::sync::Arc::new(fictionet::SeededEntropy::new(Seed::from_u64(8))),
            budget.clone(),
            fictionet::time::Instant::ZERO,
        );
        let value = Owned::new(Oversized, budget.charge(0).unwrap());
        assert!(matches!(
            d.command(MessageCommand::Send(value)),
            Err(FramedError::Write(_))
        ));
        assert_eq!(budget.used(), 0);
        assert!(d.layer_mut().take_command().is_none());
        let mut sibling = Harness::new(Seed::from_u64(9), stack());
        let sent = frames(2);
        sibling.push(&wire(&sent)).unwrap();
        assert_eq!(read(sibling.output()), sent);
    }

    #[test]
    fn output_is_reserved_before_the_writer_runs() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static WROTE: AtomicBool = AtomicBool::new(false);
        struct Large;
        impl Wire for Large {
            type ParseError = NoError;
            type WriteError = NoError;
            fn parse(_: &[u8]) -> Result<Self, NoError> {
                Ok(Self)
            }
            fn write(&self, out: &mut Vec<u8>) -> Result<(), NoError> {
                WROTE.store(true, Ordering::Relaxed);
                out.extend_from_slice(&[0; 64]);
                Ok(())
            }
        }
        impl BoundedWire for Large {
            fn write_bounded(&self, out: &mut BoundedWriter<'_>) -> Result<(), NoError> {
                WROTE.store(true, Ordering::Relaxed);
                out.extend_from_slice(&[0; 64]);
                Ok(())
            }
            fn write_bound(&self) -> Result<usize, NoError> {
                Ok(64)
            }
        }
        let budget = Budget::new(63);
        let mut d = super::super::Driver::new(
            Framed::<_, Large>::new(Widens { widened: false }),
            std::sync::Arc::new(fictionet::SeededEntropy::new(Seed::from_u64(8))),
            budget.clone(),
            fictionet::time::Instant::ZERO,
        );
        let value = Owned::new(Large, budget.charge(0).unwrap());
        assert!(matches!(
            d.command(MessageCommand::Send(value)),
            Err(FramedError::Budget)
        ));
        assert!(!WROTE.load(Ordering::Relaxed));
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn a_decoded_value_keeps_its_reservation_after_the_decoder_is_dropped() {
        let budget = Budget::new(4096);
        let mut d = super::super::Driver::new(
            Framed::<_, Frame>::new(Frames::<Frame>::new()),
            std::sync::Arc::new(fictionet::SeededEntropy::new(Seed::from_u64(9))),
            budget.clone(),
            fictionet::time::Instant::ZERO,
        );
        assert!(matches!(
            d.deliver(StreamEvent::Data(Chunk::new(wire(&frames(1)))))
                .unwrap(),
            Admit::Taken
        ));
        let MessageEvent::Message(Ok(value)) = d.layer_mut().take_event().unwrap() else {
            panic!("a frame")
        };
        assert!(value.charged() >= value.pdu.capacity());
        drop(d);
        assert_eq!(budget.used(), value.charged());
        drop(value);
        assert_eq!(budget.used(), 0);
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

    /// The decoder's buffer keeps a consumed prefix until it is as long as
    /// what is left, so it can grow to twice its limit. Here a small frame
    /// and most of a big one fill the limit; the small frame is answered,
    /// and the rest of the big one makes the buffer grow past the limit.
    #[test]
    fn the_budget_covers_everything_the_buffer_grows_to() {
        let budget = Budget::new(1 << 16);
        let mut h = Harness::with_budget(Seed::from_u64(6), stack(), budget.clone());
        let mut sent = frames(1);
        sent.push(Frame {
            transaction: 9,
            unit: 1,
            pdu: vec![0x10; modbus::MAX_PDU],
        });
        let input = wire(&sent);
        h.push(&input[..modbus::MAX_FRAME]).unwrap();
        h.push(&input[modbus::MAX_FRAME..]).unwrap();
        assert_eq!(read(h.output()), sent);
        let framed = h.layer().lower();
        let holds = framed.stream.allocated() + framed.stream.held();
        assert!(
            budget.used() >= holds,
            "the budget is charged {} for a buffer of {holds}",
            budget.used()
        );
    }

    #[derive(Clone, Debug)]
    pub(crate) struct NoError;
    impl core::fmt::Display for NoError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("no error")
        }
    }
    impl core::error::Error for NoError {}

    /// One-byte items. After the first, it needs room for sixteen bytes.
    struct Widens {
        widened: bool,
    }

    impl BoundedDecode for Widens {
        fn allocation_bound(&self) -> usize {
            0
        }
    }

    impl Decode for Widens {
        type Item = u8;
        type Error = NoError;
        const NAME: &'static str = "widens";
        fn capacity(&self) -> usize {
            if self.widened { 16 } else { 4 }
        }
        fn decode(
            &mut self,
            input: &[u8],
            _eof: bool,
        ) -> Result<fictionet::stdlib::codec::Step<u8>, NoError> {
            use fictionet::stdlib::codec::Step;
            Ok(match input.first() {
                Some(&b) => {
                    self.widened = true;
                    Step::Item(b, 1)
                }
                None => Step::Need,
            })
        }
    }

    /// A decoder may raise its capacity as it reads; the buffer follows it
    /// on the next push, so the charge before that push must too.
    #[test]
    fn the_budget_covers_a_capacity_the_decoder_raised() {
        use fictionet::SeededEntropy;
        use fictionet::stdlib::layer::Driver;
        use fictionet::time::Instant;
        use std::sync::Arc;
        let budget = Budget::new(1 << 16);
        let framed: Framed<Widens, Frame> = Framed::new(Widens { widened: false });
        let entropy = Arc::new(SeededEntropy::new(Seed::from_u64(7)));
        let mut d = Driver::new(framed, entropy, budget.clone(), Instant::ZERO);
        assert!(matches!(
            d.deliver(StreamEvent::Data(Chunk::new(vec![1]))),
            Ok(Admit::Taken)
        ));
        assert!(matches!(
            d.layer_mut().take_event(),
            Some(MessageEvent::Message(Ok(value))) if *value == 1
        ));
        let _ = d
            .deliver(StreamEvent::Data(Chunk::new(vec![2; 16])))
            .unwrap();
        let holds = d.layer().stream.allocated() + d.layer().stream.held();
        assert!(
            budget.used() >= holds,
            "the budget is charged {} for a buffer of {holds}",
            budget.used()
        );
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
