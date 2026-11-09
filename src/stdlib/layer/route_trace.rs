//! The routing code run against its TLA+ model.
//!
//! `verification/layer/tla/Route.tla` describes how `Chain`, `Switch` and
//! the `Driver` move bytes between abstract layers: every entry point may
//! answer an offer in any way rule 1 allows, and every advance may move any
//! prefix of what a layer holds. This test runs the real
//! `Chain<L, Switch<A, B>>` and `Driver` with three layers of exactly that
//! kind, whose every choice comes from a seed. It checks the model's
//! conservation properties on the bytes that come out of the real code, and
//! it writes every choice as a log that `RouteTrace.tla` replays against the
//! model (`cargo xtask layer-verify trace`), so each run of the code is
//! checked to be a behavior of the model, step by step.
//!
//! Every byte is a token: the n-th byte sent from below is `n`, and so is the
//! n-th byte sent from above, as in the model.

use std::cell::RefCell;
use std::collections::{BTreeSet, VecDeque};
use std::convert::Infallible;
use std::fmt::Write as _;
use std::rc::Rc;
use std::sync::Arc;

use super::*;
use fictionet::stdlib::codec::Lcg;
use fictionet::{Seed, SeededEntropy};

/// The seeds a run of the test covers.
const SEEDS: u64 = 32;
/// Owner actions drawn from the seed before everything is drained.
const OWNER_STEPS: usize = 48;
/// The most bytes sent each way; the model's `NU` and `ND`.
const MOST_BYTES: u8 = 6;

/// One recorded step: an owner action, or a call into an abstract layer
/// while the stack runs.
#[derive(Debug, Clone, Default)]
struct Entry {
    action: &'static str,
    /// The answer: -1 for Closed, 0 for Blocked, `n` for a prefix of `n`
    /// bytes taken or moved.
    k: i64,
    /// What an advance moved: `up`, `down`, `use`, `done` or `none`.
    which: &'static str,
    /// The bytes offered, each its own token.
    chunk: Vec<u8>,
    /// The handover's chunking of what `A` held from below and from above.
    below: Vec<usize>,
    above: Vec<usize>,
}

/// Draws every choice from the seed and keeps the log.
struct Recorder {
    lcg: Lcg,
    /// The stack is running: calls into the layers are the model's
    /// internal steps and are logged.
    inside: bool,
    /// Every answer takes everything and every advance moves everything:
    /// the end of a run, when the lines drain.
    draining: bool,
    /// The tokens `A` used as its own protocol.
    used: Vec<u8>,
    /// The tokens a Closed answer dropped, each way.
    up_dropped: BTreeSet<u8>,
    down_dropped: BTreeSet<u8>,
    log: Vec<Entry>,
}

impl Recorder {
    fn new(seed: u64) -> Recorder {
        Recorder {
            lcg: Lcg::new(seed),
            inside: false,
            draining: false,
            used: Vec::new(),
            up_dropped: BTreeSet::new(),
            down_dropped: BTreeSet::new(),
            log: Vec::new(),
        }
    }

    fn choose(&mut self, options: usize) -> usize {
        self.lcg.index(options)
    }

    /// An answer to an offer of `len` bytes, from the model's
    /// `Answers(c, mayClose)`.
    fn answer(&mut self, len: usize, may_close: bool) -> i64 {
        if self.draining {
            return len as i64;
        }
        let options = len + 1 + usize::from(may_close);
        let pick = self.choose(options);
        if pick == len + 1 { -1 } else { pick as i64 }
    }

    /// How many of `len` bytes an advance moves: a nonempty prefix.
    fn prefix(&mut self, len: usize) -> usize {
        if self.draining {
            len
        } else {
            1 + self.choose(len)
        }
    }

    /// Cuts `bytes` into nonempty chunks, as the model's `Splits`.
    fn splits(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut chunks = Vec::new();
        let mut rest = bytes;
        while !rest.is_empty() {
            let n = self.prefix(rest.len());
            chunks.push(rest[..n].to_vec());
            rest = &rest[n..];
        }
        chunks
    }

    fn record(&mut self, entry: Entry) {
        self.log.push(entry);
    }
}

/// Which abstract layer: `L` below the switch, `A` before it hands over,
/// `B` after.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    L,
    A,
    B,
}

/// What `A` negotiated: nothing but the shared recorder for `B`.
struct Negotiated {
    rec: Rc<RefCell<Recorder>>,
}

/// A layer that answers as the model's layers may: every entry point takes
/// all, a prefix, nothing (Blocked) or nothing for good (Closed), and every
/// advance moves any prefix of one of its buffers, or nothing.
struct Abstract {
    role: Role,
    rec: Rc<RefCell<Recorder>>,
    /// Bytes taken from below and not yet moved on.
    up_in: Vec<u8>,
    /// Chunks ready for whoever is above.
    up_out: VecDeque<Vec<u8>>,
    /// Bytes taken from above and not yet moved on.
    down_in: Vec<u8>,
    /// Chunks ready for whoever is below.
    down_out: VecDeque<Vec<u8>>,
    /// `A` reached its boundary.
    done: bool,
}

impl Abstract {
    fn new(role: Role, rec: Rc<RefCell<Recorder>>) -> Abstract {
        Abstract {
            role,
            rec,
            up_in: Vec::new(),
            up_out: VecDeque::new(),
            down_in: Vec::new(),
            down_out: VecDeque::new(),
            done: false,
        }
    }

    /// Whether the layer holds nothing.
    fn is_empty(&self) -> bool {
        self.up_in.is_empty()
            && self.up_out.is_empty()
            && self.down_in.is_empty()
            && self.down_out.is_empty()
    }
}

/// Applies answer `k` to `chunk`: the taken prefix goes to `into`, and a
/// Closed answer drops the whole chunk (Route.tla `Dropped`).
fn apply(k: i64, mut chunk: Chunk, into: &mut Vec<u8>, dropped: &mut BTreeSet<u8>) -> Admit<Chunk> {
    match k {
        -1 => {
            dropped.extend(chunk.iter());
            Admit::Closed(chunk)
        }
        0 => Admit::Blocked(chunk),
        k => {
            let k = k as usize;
            into.extend_from_slice(&chunk[..k]);
            chunk.advance(k);
            if chunk.is_empty() {
                Admit::Taken
            } else {
                Admit::Partial(chunk)
            }
        }
    }
}

/// Moves a prefix of `n` bytes from `from` to the end of `to`.
fn move_prefix(from: &mut Vec<u8>, to: &mut VecDeque<Vec<u8>>, n: usize) {
    to.push_back(from.drain(..n).collect());
}

impl Layer for Abstract {
    type Lower = ByteStream;
    type Upper = ByteStream;
    type Report = ();
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;

    fn on_event(
        &mut self,
        _: &mut Env<'_, ()>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Infallible> {
        let StreamEvent::Data(chunk) = event else {
            unreachable!("the owner sends data only")
        };
        let mut rec = self.rec.borrow_mut();
        // Past its boundary A takes nothing more (Route.tla EventAnswers).
        let k = if self.role == Role::A && self.done {
            0
        } else {
            rec.answer(chunk.len(), self.role != Role::A)
        };
        if rec.inside {
            let action = match self.role {
                Role::L => unreachable!("L gets events from the owner only"),
                Role::A => "AEvent",
                Role::B => "BEvent",
            };
            rec.record(Entry {
                action,
                k,
                chunk: chunk.to_vec(),
                ..Entry::default()
            });
        }
        Ok(apply(k, chunk, &mut self.up_in, &mut rec.up_dropped).map(StreamEvent::Data))
    }

    fn on_command(
        &mut self,
        _: &mut Env<'_, ()>,
        command: StreamCommand,
    ) -> Result<Admit<StreamCommand>, Infallible> {
        let StreamCommand::Write(chunk) = command else {
            unreachable!("the owner sends writes only")
        };
        let mut rec = self.rec.borrow_mut();
        let k = if self.role == Role::A && self.done {
            0
        } else {
            rec.answer(chunk.len(), self.role != Role::A)
        };
        if rec.inside {
            let action = match self.role {
                Role::L => "LCommand",
                Role::A => unreachable!("A gets commands from the owner only"),
                Role::B => "BCommand",
            };
            rec.record(Entry {
                action,
                k,
                chunk: chunk.to_vec(),
                ..Entry::default()
            });
        }
        Ok(apply(k, chunk, &mut self.down_in, &mut rec.down_dropped).map(StreamCommand::Write))
    }

    fn advance(&mut self, _: &mut Env<'_, ()>) -> Result<bool, Infallible> {
        let mut rec = self.rec.borrow_mut();
        let mut options: Vec<&'static str> = vec!["none"];
        if !(self.role == Role::A && self.done) {
            if !self.up_in.is_empty() {
                options.push("up");
                if self.role == Role::A {
                    options.push("use");
                }
            }
            if !self.down_in.is_empty() {
                options.push("down");
            }
            if self.role == Role::A {
                options.push("done");
            }
        }
        let which = if rec.draining {
            // Everything moves on; A reaches its boundary once it is empty.
            ["up", "down", "done"]
                .into_iter()
                .find(|w| options.contains(w))
                .unwrap_or("none")
        } else {
            options[rec.choose(options.len())]
        };
        let k = match which {
            "up" => {
                let k = rec.prefix(self.up_in.len());
                move_prefix(&mut self.up_in, &mut self.up_out, k);
                k
            }
            "use" => {
                let k = rec.prefix(self.up_in.len());
                rec.used.extend(self.up_in.drain(..k));
                k
            }
            "down" => {
                let k = rec.prefix(self.down_in.len());
                move_prefix(&mut self.down_in, &mut self.down_out, k);
                k
            }
            "done" => {
                self.done = true;
                0
            }
            _ => 0,
        };
        let action = match self.role {
            Role::L => "LAdvance",
            Role::A => "AAdvance",
            Role::B => "BAdvance",
        };
        rec.record(Entry {
            action,
            k: k as i64,
            which,
            ..Entry::default()
        });
        Ok(which != "none")
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
        self.down_out
            .pop_front()
            .map(|bytes| StreamCommand::Write(Chunk::new(bytes)))
    }

    fn take_event(&mut self) -> Option<StreamEvent> {
        self.up_out
            .pop_front()
            .map(|bytes| StreamEvent::Data(Chunk::new(bytes)))
    }
}

impl Handoff for Abstract {
    type Next = Negotiated;

    /// Route.tla StepH: once past the boundary with every output taken, the
    /// leftovers go over in any chunking.
    fn handover(&mut self) -> Option<Handover<Negotiated, ByteStream, ByteStream>> {
        if !self.done || !self.up_out.is_empty() || !self.down_out.is_empty() {
            return None;
        }
        let mut rec = self.rec.borrow_mut();
        let below = rec.splits(&self.up_in);
        let above = rec.splits(&self.down_in);
        rec.record(Entry {
            action: "Handover",
            below: below.iter().map(Vec::len).collect(),
            above: above.iter().map(Vec::len).collect(),
            ..Entry::default()
        });
        drop(rec);
        self.up_in.clear();
        self.down_in.clear();
        Some(Handover {
            next: Negotiated {
                rec: self.rec.clone(),
            },
            below: below
                .into_iter()
                .map(|bytes| StreamEvent::Data(Chunk::new(bytes)))
                .collect(),
            above: above
                .into_iter()
                .map(|bytes| StreamCommand::Write(Chunk::new(bytes)))
                .collect(),
        })
    }
}

impl Successor<Negotiated> for Abstract {
    fn succeed(next: Negotiated) -> Abstract {
        Abstract::new(Role::B, next.rec)
    }
}

type Stack = Chain<Abstract, Switch<Abstract, Abstract>>;

/// The owner of the stack: the harness of the model, which injects bytes,
/// delivers them, takes output and runs the driver.
struct Owner {
    rec: Rc<RefCell<Recorder>>,
    driver: Driver<Stack>,
    nu: u8,
    nd: u8,
    next_up: u8,
    next_down: u8,
    in_q: VecDeque<Vec<u8>>,
    cmd_q: VecDeque<Vec<u8>>,
    top_out: Vec<u8>,
    bottom_out: Vec<u8>,
}

/// The owner's queue after answer `k` to its first chunk (Route.tla
/// `OwnerQueue`).
fn owner_queue(queue: &mut VecDeque<Vec<u8>>, k: i64) {
    let chunk = queue.pop_front().expect("the queue had a chunk");
    match k {
        0 => queue.push_front(chunk),
        k if (k as usize) < chunk.len() => queue.push_front(chunk[k as usize..].to_vec()),
        _ => {}
    }
}

/// The answer an `Admit` stands for, to a chunk of `len` bytes.
fn answer_of<T>(admit: &Admit<T>, len: usize, rest: impl Fn(&T) -> usize) -> i64 {
    match admit {
        Admit::Taken => len as i64,
        Admit::Partial(t) => (len - rest(t)) as i64,
        Admit::Blocked(_) => 0,
        Admit::Closed(_) => -1,
    }
}

impl Owner {
    fn new(seed: u64) -> Owner {
        let rec = Rc::new(RefCell::new(Recorder::new(seed)));
        let nu = 1 + rec.borrow_mut().choose(usize::from(MOST_BYTES)) as u8;
        let nd = 1 + rec.borrow_mut().choose(usize::from(MOST_BYTES)) as u8;
        let stack = Chain::new(
            Abstract::new(Role::L, rec.clone()),
            Switch::new(Abstract::new(Role::A, rec.clone())),
        );
        let driver = Driver::new(
            stack,
            Arc::new(SeededEntropy::new(Seed::from_u64(seed))),
            Budget::unlimited(),
            Instant::ZERO,
        );
        Owner {
            rec,
            driver,
            nu,
            nd,
            next_up: 1,
            next_down: 1,
            in_q: VecDeque::new(),
            cmd_q: VecDeque::new(),
            top_out: Vec::new(),
            bottom_out: Vec::new(),
        }
    }

    fn inject_up(&mut self) {
        let left = usize::from(self.nu - self.next_up + 1);
        let k = self.rec.borrow_mut().prefix(left);
        let chunk: Vec<u8> = (self.next_up..self.next_up + k as u8).collect();
        self.next_up += k as u8;
        self.in_q.push_back(chunk);
        self.rec.borrow_mut().record(Entry {
            action: "InjectUp",
            k: k as i64,
            ..Entry::default()
        });
    }

    fn inject_down(&mut self) {
        let left = usize::from(self.nd - self.next_down + 1);
        let k = self.rec.borrow_mut().prefix(left);
        let chunk: Vec<u8> = (self.next_down..self.next_down + k as u8).collect();
        self.next_down += k as u8;
        self.cmd_q.push_back(chunk);
        self.rec.borrow_mut().record(Entry {
            action: "InjectDown",
            k: k as i64,
            ..Entry::default()
        });
    }

    /// Route.tla Deliver: the first chunk of the input queue to the stack.
    fn deliver(&mut self) {
        let chunk = self.in_q.front().expect("input waits").clone();
        let admit = self
            .driver
            .deliver(StreamEvent::Data(Chunk::new(chunk.clone())))
            .unwrap_or_else(|e| match e {});
        let k = answer_of(&admit, chunk.len(), |event| match event {
            StreamEvent::Data(rest) => rest.len(),
            _ => unreachable!(),
        });
        owner_queue(&mut self.in_q, k);
        self.rec.borrow_mut().record(Entry {
            action: "Deliver",
            k,
            chunk,
            ..Entry::default()
        });
    }

    /// Route.tla Command: the first chunk of the command queue to the stack.
    fn command(&mut self) {
        let chunk = self.cmd_q.front().expect("a command waits").clone();
        let admit = self
            .driver
            .command(StreamCommand::Write(Chunk::new(chunk.clone())))
            .unwrap_or_else(|e| match e {});
        let k = answer_of(&admit, chunk.len(), |command| match command {
            StreamCommand::Write(rest) => rest.len(),
            _ => unreachable!(),
        });
        owner_queue(&mut self.cmd_q, k);
        self.rec.borrow_mut().record(Entry {
            action: "Command",
            k,
            chunk,
            ..Entry::default()
        });
    }

    /// Route.tla SendBelow, once per item the driver offers.
    fn send_below(&mut self) {
        let Owner {
            rec,
            driver,
            bottom_out,
            ..
        } = self;
        driver.send_below(|command| {
            let StreamCommand::Write(chunk) = command else {
                unreachable!("the stack writes only")
            };
            let k = rec.borrow_mut().answer(chunk.len(), true);
            rec.borrow_mut().record(Entry {
                action: "SendBelow",
                k,
                chunk: chunk.to_vec(),
                ..Entry::default()
            });
            apply(k, chunk, bottom_out, &mut rec.borrow_mut().down_dropped)
                .map(StreamCommand::Write)
        });
    }

    /// Route.tla SendAbove, once per item the driver offers.
    fn send_above(&mut self) {
        let Owner {
            rec,
            driver,
            top_out,
            ..
        } = self;
        driver.send_above(|event| {
            let StreamEvent::Data(chunk) = event else {
                unreachable!("the stack passes data only")
            };
            let k = rec.borrow_mut().answer(chunk.len(), true);
            rec.borrow_mut().record(Entry {
                action: "SendAbove",
                k,
                chunk: chunk.to_vec(),
                ..Entry::default()
            });
            apply(k, chunk, top_out, &mut rec.borrow_mut().up_dropped).map(StreamEvent::Data)
        });
    }

    /// Route.tla StartRun and the steps to its end.
    fn run(&mut self) {
        {
            let mut rec = self.rec.borrow_mut();
            rec.record(Entry {
                action: "Run",
                ..Entry::default()
            });
            rec.inside = true;
        }
        self.driver.run().unwrap_or_else(|e| match e {});
        self.rec.borrow_mut().inside = false;
        assert!(
            !self.driver.exhausted(),
            "a run of a few bytes never needs the step limit"
        );
    }

    /// One owner action drawn from the seed, among those enabled.
    fn step(&mut self) {
        let mut options: Vec<&str> = vec!["run", "send_below", "send_above"];
        if self.next_up <= self.nu {
            options.push("inject_up");
        }
        if self.next_down <= self.nd {
            options.push("inject_down");
        }
        if !self.in_q.is_empty() {
            options.push("deliver");
        }
        if !self.cmd_q.is_empty() {
            options.push("command");
        }
        let pick = self.rec.borrow_mut().choose(options.len());
        match options[pick] {
            "run" => self.run(),
            "send_below" => self.send_below(),
            "send_above" => self.send_above(),
            "inject_up" => self.inject_up(),
            "inject_down" => self.inject_down(),
            "deliver" => self.deliver(),
            _ => self.command(),
        }
    }

    /// Sends what is left, takes everything and runs until nothing moves.
    fn drain(&mut self) {
        self.rec.borrow_mut().draining = true;
        while self.next_up <= self.nu {
            self.inject_up();
        }
        while self.next_down <= self.nd {
            self.inject_down();
        }
        for _ in 0..64 {
            while !self.in_q.is_empty() {
                self.deliver();
            }
            while !self.cmd_q.is_empty() {
                self.command();
            }
            self.run();
            self.send_below();
            self.send_above();
            if self.quiet() {
                return;
            }
        }
        let log = &self.rec.borrow().log;
        panic!(
            "the stack did not drain; the log ends {:?}",
            &log[log.len().saturating_sub(12)..]
        );
    }

    /// Whether every layer is empty and every byte has arrived.
    fn quiet(&self) -> bool {
        let rec = self.rec.borrow();
        let chain = self.driver.layer();
        let switch = chain.upper();
        let inner = switch.first().or_else(|| switch.then()).expect("a phase");
        chain.lower().is_empty()
            && inner.is_empty()
            && !self.driver.holds_output()
            && self.top_out.len() + rec.used.len() + rec.up_dropped.len() == usize::from(self.nu)
            && self.bottom_out.len() + rec.down_dropped.len() == usize::from(self.nd)
    }

    /// The order the top and the bottom saw: the order sent.
    fn check_order(&self) {
        assert!(
            self.top_out.windows(2).all(|w| w[0] < w[1]),
            "the top saw bytes out of order: {:?}",
            self.top_out
        );
        assert!(
            self.bottom_out.windows(2).all(|w| w[0] < w[1]),
            "the bottom saw bytes out of order: {:?}",
            self.bottom_out
        );
    }

    /// Route.tla UpConserved and DownConserved, once every line is empty:
    /// every byte is in exactly one place.
    fn check_conserved(&self) {
        let rec = self.rec.borrow();
        let top: BTreeSet<u8> = self.top_out.iter().copied().collect();
        let used: BTreeSet<u8> = rec.used.iter().copied().collect();
        assert_eq!(
            top.len(),
            self.top_out.len(),
            "a byte reached the top twice"
        );
        assert!(top.is_disjoint(&used) && top.is_disjoint(&rec.up_dropped));
        assert!(used.is_disjoint(&rec.up_dropped));
        let all: BTreeSet<u8> = (1..=self.nu).collect();
        assert_eq!(
            &(&top | &used) | &rec.up_dropped,
            all,
            "a byte from below was lost"
        );
        let bottom: BTreeSet<u8> = self.bottom_out.iter().copied().collect();
        assert_eq!(
            bottom.len(),
            self.bottom_out.len(),
            "a byte reached the bottom twice"
        );
        assert!(bottom.is_disjoint(&rec.down_dropped));
        let all: BTreeSet<u8> = (1..=self.nd).collect();
        assert_eq!(
            &bottom | &rec.down_dropped,
            all,
            "a byte from above was lost"
        );
        let handovers = rec.log.iter().filter(|e| e.action == "Handover").count();
        assert!(handovers <= 1, "the switch handed over {handovers} times");
    }
}

/// The log as a TLA+ module that `RouteTrace.tla` replays, and the config
/// that checks it.
fn tla_module(name: &str, owner: &Owner) -> (String, String) {
    let rec = owner.rec.borrow();
    let seq = |items: &[usize]| {
        let inner: Vec<String> = items.iter().map(|n| n.to_string()).collect();
        format!("<<{}>>", inner.join(", "))
    };
    let mut module = format!("---- MODULE {name} ----\nEXTENDS RouteTrace\nTraceLog == <<\n");
    for (at, entry) in rec.log.iter().enumerate() {
        let comma = if at + 1 < rec.log.len() { "," } else { "" };
        let chunk: Vec<usize> = entry.chunk.iter().map(|b| usize::from(*b)).collect();
        let _ = writeln!(
            module,
            "  [a |-> \"{}\", k |-> {}, w |-> \"{}\", c |-> {}, sb |-> {}, sa |-> {}]{comma}",
            entry.action,
            entry.k,
            if entry.which.is_empty() {
                "none"
            } else {
                entry.which
            },
            seq(&chunk),
            seq(&entry.below),
            seq(&entry.above),
        );
    }
    module.push_str(">>\n====\n");
    let config = format!(
        "SPECIFICATION TraceSpec\n\
         CONSTANTS\n    NU = {}\n    ND = {}\n    Log <- TraceLog\n    \
         KeepBlocked = TRUE\n    KeepRest = TRUE\n    BlockedIsStill = TRUE\n    \
         LeftoversFirst = TRUE\n    RestFirst = TRUE\n    MoveAbove = TRUE\n    \
         SwitchOnce = TRUE\n    DriverKeepsRest = TRUE\n    UrgentBypass = TRUE\n\
         INVARIANTS\n    UpConserved\n    DownConserved\n    HandoverOnce\n\
         CHECK_DEADLOCK TRUE\n",
        owner.nu, owner.nd
    );
    (module, config)
}

/// Every seed: the real routing code under the model's abstract layers
/// keeps every byte once and in order. With `FICTIONET_ROUTE_TRACE_DIR`
/// set, each run's log is written there for `RouteTrace.tla`.
#[test]
fn routing_through_chain_switch_and_driver_is_a_behavior_of_the_model() {
    let out = std::env::var_os("FICTIONET_ROUTE_TRACE_DIR").map(std::path::PathBuf::from);
    if let Some(dir) = &out {
        std::fs::create_dir_all(dir).expect("the trace directory");
    }
    for seed in 0..SEEDS {
        let mut owner = Owner::new(seed);
        for _ in 0..OWNER_STEPS {
            owner.step();
            owner.check_order();
        }
        owner.drain();
        owner.check_order();
        owner.check_conserved();
        if let Some(dir) = &out {
            let name = format!("RouteLog_{seed}");
            let (module, config) = tla_module(&name, &owner);
            std::fs::write(dir.join(format!("{name}.tla")), module).expect("the log module");
            std::fs::write(dir.join(format!("{name}.cfg")), config).expect("the log config");
        }
    }
}
