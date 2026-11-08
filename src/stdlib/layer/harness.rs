use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use fictionet::stdlib::layer::{
    Admit, Budget, ByteStream, Chunk, Driver, Layer, StreamCommand, StreamEvent,
};
use fictionet::time::Instant;
use fictionet::{Seed, SeededEntropy};

/// How many rounds a harness call makes before it calls the stack stuck:
/// a stack that keeps moving with no new input never settles.
const ROUNDS: usize = 1 << 20;

/// Runs a stack over a byte stream with no runtime, for tests and fuzz
/// targets.
///
/// The harness plays the peer and the transport. It gives the stack the
/// peer's bytes and keeps what the stack refuses until the stack takes it.
/// It takes the stack's output only as fast as the test allows
/// ([`withhold`](Self::withhold), [`allow`](Self::allow),
/// [`allow_all`](Self::allow_all)), taking part of a write when it has room
/// for part, and reports each byte it takes as written. The clock stands
/// still until [`advance`](Self::advance) moves it, and entropy comes from a
/// seeded stream. Every call runs the stack until nothing more moves.
pub struct Harness<L: Layer<Lower = ByteStream>> {
    driver: Driver<L>,
    /// What the peer sent that the stack has not taken.
    input: VecDeque<StreamEvent>,
    /// Bytes the transport took that the stack has not heard about.
    unreported: u64,
    output: Vec<u8>,
    /// Bytes the transport may still take; `None` for any number.
    room: Option<usize>,
    ended: bool,
    reset: bool,
}

impl<L: Layer<Lower = ByteStream>> Harness<L> {
    /// Runs `layer` at time zero, with entropy from `seed` and no limit on
    /// what it holds.
    pub fn new(seed: Seed, layer: L) -> Harness<L> {
        Harness::with_budget(seed, layer, Budget::unlimited())
    }

    /// The same, charging `budget`.
    pub fn with_budget(seed: Seed, layer: L, budget: Budget) -> Harness<L> {
        let entropy = Arc::new(SeededEntropy::new(seed));
        Harness {
            driver: Driver::new(layer, entropy, budget, Instant::ZERO),
            input: VecDeque::new(),
            unreported: 0,
            output: Vec::new(),
            room: None,
            ended: false,
            reset: false,
        }
    }

    /// The peer sends `bytes`.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), L::Error> {
        if !bytes.is_empty() {
            let chunk = Chunk::new(bytes.to_vec());
            self.input.push_back(StreamEvent::Data(chunk));
        }
        self.settle()
    }

    /// The peer will send nothing more.
    pub fn end(&mut self) -> Result<(), L::Error> {
        self.input.push_back(StreamEvent::Ended);
        self.settle()
    }

    /// From now on the transport takes nothing.
    pub fn withhold(&mut self) {
        self.room = Some(0);
    }

    /// Lets the transport take `bytes` more.
    pub fn allow(&mut self, bytes: usize) -> Result<(), L::Error> {
        if let Some(room) = &mut self.room {
            *room = room.saturating_add(bytes);
        }
        self.settle()
    }

    /// From now on the transport takes everything.
    pub fn allow_all(&mut self) -> Result<(), L::Error> {
        self.room = None;
        self.settle()
    }

    /// Moves the clock by `d`. Timers that come due go off in order, each
    /// at its own time.
    pub fn advance(&mut self, d: Duration) -> Result<(), L::Error> {
        let until = self.driver.now() + d;
        while let Some(at) = self.driver.deadline().filter(|at| *at <= until) {
            self.driver.set_now(at);
            self.settle()?;
            if self.driver.deadline() == Some(at) {
                // The stack keeps that timer due; its steps are bounded.
                break;
            }
        }
        self.driver.set_now(until);
        self.settle()
    }

    /// Gives the stack the result of work it asked for.
    pub fn complete(&mut self, done: L::Done) -> Result<(), L::Error> {
        self.driver.complete(done)?;
        self.settle()
    }

    /// The next piece of work the stack asks for.
    pub fn work(&mut self) -> Option<L::Work> {
        self.driver.take_work()
    }

    /// Every byte the transport took.
    pub fn output(&self) -> &[u8] {
        &self.output
    }

    /// Takes the bytes the transport took so far.
    pub fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.output)
    }

    /// Bytes the peer sent that the stack has not taken yet.
    pub fn unread(&self) -> usize {
        self.input
            .iter()
            .map(|event| match event {
                StreamEvent::Data(chunk) => chunk.len(),
                _ => 0,
            })
            .sum()
    }

    /// Whether the stack ended its direction.
    pub fn ended(&self) -> bool {
        self.ended
    }

    /// Whether the stack reset the connection.
    pub fn was_reset(&self) -> bool {
        self.reset
    }

    /// The stack.
    pub fn layer(&self) -> &L {
        self.driver.layer()
    }

    /// The driver, for what the harness does not wrap.
    pub fn driver(&mut self) -> &mut Driver<L> {
        &mut self.driver
    }

    /// Runs the stack until nothing more moves.
    pub fn settle(&mut self) -> Result<(), L::Error> {
        for _ in 0..ROUNDS {
            let mut moved = false;
            if self.unreported > 0 {
                match self.driver.deliver(StreamEvent::Written(self.unreported))? {
                    Admit::Blocked(_) => {}
                    _ => {
                        self.unreported = 0;
                        moved = true;
                    }
                }
            }
            while let Some(event) = self.input.pop_front() {
                match self.driver.deliver(event)? {
                    Admit::Taken | Admit::Closed(_) => moved = true,
                    Admit::Partial(rest) => {
                        self.input.push_front(rest);
                        moved = true;
                        break;
                    }
                    Admit::Blocked(event) => {
                        self.input.push_front(event);
                        break;
                    }
                }
            }
            moved |= self.driver.run()?;
            let Harness {
                driver,
                unreported,
                output,
                room,
                ended,
                reset,
                ..
            } = self;
            moved |= driver.send_below(|command| match command {
                _ if *ended || *reset => Admit::Closed(command),
                StreamCommand::Write(mut chunk) => {
                    let n = chunk.len().min(room.unwrap_or(usize::MAX));
                    if n == 0 && !chunk.is_empty() {
                        return Admit::Blocked(StreamCommand::Write(chunk));
                    }
                    output.extend_from_slice(&chunk[..n]);
                    chunk.advance(n);
                    *unreported += n as u64;
                    if let Some(room) = room {
                        *room -= n;
                    }
                    if chunk.is_empty() {
                        Admit::Taken
                    } else {
                        Admit::Partial(StreamCommand::Write(chunk))
                    }
                }
                StreamCommand::End => {
                    *ended = true;
                    Admit::Taken
                }
                StreamCommand::Reset => {
                    *reset = true;
                    Admit::Taken
                }
            });
            if !moved {
                return Ok(());
            }
        }
        panic!("the stack kept moving with no new input");
    }
}
