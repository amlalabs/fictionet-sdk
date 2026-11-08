use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use fictionet::stdlib::layer::{
    Admit, Budget, ByteStream, Chunk, Driver, Layer, StreamCommand, StreamEvent,
};
use fictionet::time::Instant;
use fictionet::{Entropy, Seed, SeededEntropy};

/// How many rounds a harness call makes before it calls the stack stuck:
/// a stack that keeps moving with no new input never settles.
const ROUNDS: usize = 1 << 20;

/// Does a stack's work for a [`Harness`]: whatever polls the futures that
/// a layer's [`Work`](Layer::Work) carries, which neither a layer nor the
/// harness ever does.
///
/// [`services::stack::Polling`](fictionet::stdlib::services::stack::Polling)
/// is the one the live runners use, with or without a world.
pub trait Worker<L: Layer>: Send {
    /// Takes the stack's new work from `driver`, moves all of it on once,
    /// and gives the stack what finished. Returns whether anything moved.
    fn work(&mut self, driver: &mut Driver<L>) -> Result<bool, L::Error>;

    /// How much work is running.
    fn running(&self) -> usize;

    /// The entropy of the world the work runs in, which the stack then
    /// draws from instead of the harness's seed. `None` keeps the seed.
    fn entropy(&self) -> Option<Arc<dyn Entropy>> {
        None
    }

    /// The time of the world the work runs in, which the harness's clock
    /// then follows. `None` for a clock that moves only when the test
    /// moves it.
    fn now(&self) -> Option<Instant> {
        None
    }
}

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
///
/// The stack's work waits for the test ([`work`](Self::work),
/// [`complete`](Self::complete)), unless the harness has a
/// [`Worker`] ([`with_worker`](Self::with_worker)): then the worker does it
/// each time the harness runs the stack.
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
    /// Whether the stack refused input as closed.
    input_closed: bool,
    worker: Option<Box<dyn Worker<L>>>,
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
            input_closed: false,
            worker: None,
        }
    }

    /// From now on `worker` does the stack's work, each time the harness
    /// runs the stack. A worker in a world gives the stack that world's
    /// entropy and clock: give it before anything runs.
    pub fn with_worker(mut self, worker: impl Worker<L> + 'static) -> Harness<L> {
        if let Some(entropy) = worker.entropy() {
            let now = worker.now().unwrap_or(self.driver.now());
            self.driver.rebind(entropy, now);
        }
        self.worker = Some(Box::new(worker));
        self
    }

    /// How much of the stack's work the worker is doing.
    pub fn jobs(&self) -> usize {
        self.worker.as_ref().map_or(0, |worker| worker.running())
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
        assert!(
            self.worker
                .as_ref()
                .and_then(|worker| worker.now())
                .is_none(),
            "the world moves the clock of a harness in a world"
        );
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

    /// Whether the stack refused the peer's input as closed: it will read
    /// nothing more.
    pub fn input_closed(&self) -> bool {
        self.input_closed
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
        if let Some(now) = self.worker.as_ref().and_then(|worker| worker.now()) {
            self.driver.set_now(now);
        }
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
            if let Some(worker) = &mut self.worker {
                moved |= worker.work(&mut self.driver)?;
            }
            while let Some(event) = self.input.pop_front() {
                match self.driver.deliver(event)? {
                    Admit::Taken => moved = true,
                    Admit::Closed(_) => {
                        self.input_closed = true;
                        moved = true;
                    }
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
