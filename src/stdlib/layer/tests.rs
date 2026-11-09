//! Small layers that exercise the foundation, and the stacks they make:
//!
//! - a transform over a byte stream with an application on top
//!   (`Chain<Mask, Echo>`);
//! - a multiplexed connection with an application on every child and one
//!   on its control port (`Chain<Chain<Toy, Children<Answer, Ctl>>, Pong>`);
//! - a negotiated change at run time (`Switch<Echo, Tunnel>`).
//!
//! The tests check relations, never fixed bytes: what comes out against
//! what went in, the same transcript cut in different places, and credit
//! and charges that add up.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::convert::Infallible;
use std::time::Duration;

use super::*;
use fictionet::stdlib::codec::{Ending, Lines, Stream};
use fictionet::stdlib::services::stack::{BoxError, Boxed, Job};
use fictionet::{Entropy, Seed, SeededEntropy};

// ---------------------------------------------------------------------------
// A transform: every byte XORed with a key, both ways

/// A stand-in for TLS: a byte stream above and below, a bounded buffer
/// each way, ends and write completions passed through.
struct Mask {
    key: u8,
    room: usize,
    up: Vec<u8>,
    down: Vec<u8>,
    written: u64,
    peer_ended: bool,
    ended_up: bool,
    end: bool,
    end_sent: bool,
}

impl Mask {
    fn new(key: u8, room: usize) -> Mask {
        Mask {
            key,
            room,
            up: Vec::new(),
            down: Vec::new(),
            written: 0,
            peer_ended: false,
            ended_up: false,
            end: false,
            end_sent: false,
        }
    }

    fn apply(key: u8, bytes: &[u8]) -> Vec<u8> {
        bytes.iter().map(|b| b ^ key).collect()
    }

    /// Takes what fits of `chunk` into `buf`.
    fn take(key: u8, room: usize, buf: &mut Vec<u8>, mut chunk: Chunk) -> Admit<Chunk> {
        let n = chunk.len().min(room.saturating_sub(buf.len()));
        if n == 0 && !chunk.is_empty() {
            return Admit::Blocked(chunk);
        }
        buf.extend(chunk[..n].iter().map(|b| b ^ key));
        chunk.advance(n);
        if chunk.is_empty() {
            Admit::Taken
        } else {
            Admit::Partial(chunk)
        }
    }
}

impl Layer for Mask {
    type Lower = ByteStream;
    type Upper = ByteStream;
    type Report = ();
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = Infallible;

    fn on_event(
        &mut self,
        _env: &mut Env<'_, ()>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Infallible> {
        Ok(match event {
            StreamEvent::Data(chunk) if self.peer_ended => Admit::Closed(StreamEvent::Data(chunk)),
            StreamEvent::Data(chunk) => {
                Mask::take(self.key, self.room, &mut self.up, chunk).map(StreamEvent::Data)
            }
            // One byte below is one byte above.
            StreamEvent::Written(n) => {
                self.written += n;
                Admit::Taken
            }
            StreamEvent::Ended | StreamEvent::Reset if self.peer_ended => Admit::Closed(event),
            StreamEvent::Ended | StreamEvent::Reset => {
                self.peer_ended = true;
                Admit::Taken
            }
        })
    }

    fn on_command(
        &mut self,
        _env: &mut Env<'_, ()>,
        command: StreamCommand,
    ) -> Result<Admit<StreamCommand>, Infallible> {
        Ok(match command {
            _ if self.end => Admit::Closed(command),
            StreamCommand::Write(chunk) => {
                Mask::take(self.key, self.room, &mut self.down, chunk).map(StreamCommand::Write)
            }
            StreamCommand::End | StreamCommand::Reset => {
                self.end = true;
                Admit::Taken
            }
        })
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
        if !self.down.is_empty() {
            return Some(StreamCommand::Write(Chunk::new(std::mem::take(
                &mut self.down,
            ))));
        }
        if self.end && !self.end_sent {
            self.end_sent = true;
            return Some(StreamCommand::End);
        }
        None
    }

    fn take_event(&mut self) -> Option<StreamEvent> {
        if self.written > 0 {
            return Some(StreamEvent::Written(std::mem::take(&mut self.written)));
        }
        if !self.up.is_empty() {
            return Some(StreamEvent::Data(Chunk::new(std::mem::take(&mut self.up))));
        }
        if self.peer_ended && !self.ended_up {
            self.ended_up = true;
            return Some(StreamEvent::Ended);
        }
        None
    }
}

// ---------------------------------------------------------------------------
// An application: each line back, reversed

const LINE: usize = 48;

#[derive(Debug, PartialEq, Eq)]
enum EchoError {
    /// The budget could not hold what the echo reserves.
    Budget,
    /// The transport reported more bytes written than were handed to it.
    Credit,
    /// The line buffer broke its contract.
    Decode,
}

/// Answers each line with the line reversed, until a line that is its
/// upgrade word, which it answers with [`Echo::ACCEPTED`] and then hands the
/// connection over. It reserves its buffers from the budget before it takes
/// any input, and its replies carry their share of that charge.
struct Echo {
    lines: Stream<Lines>,
    room: usize,
    out: Vec<u8>,
    ready: Option<Chunk>,
    reserve: Option<Charge>,
    upgrade: Option<&'static [u8]>,
    boundary: bool,
    handed: bool,
    sent: u64,
    acked: u64,
    peer_ended: bool,
    drained: bool,
    end_sent: bool,
}

/// What [`Echo`] negotiated: a tunnel.
struct Upgraded;

impl Echo {
    const ACCEPTED: &'static [u8] = b"OK\n";

    fn new(room: usize) -> Echo {
        assert!(room > LINE + 1);
        Echo {
            lines: Stream::new(Lines::new(LINE, Ending::LfOrCrlf)),
            room,
            out: Vec::new(),
            ready: None,
            reserve: None,
            upgrade: None,
            boundary: false,
            handed: false,
            sent: 0,
            acked: 0,
            peer_ended: false,
            drained: false,
            end_sent: false,
        }
    }

    fn upgrading(room: usize, word: &'static [u8]) -> Echo {
        Echo {
            upgrade: Some(word),
            ..Echo::new(room)
        }
    }

    /// The answer to one line.
    fn reply(line: &[u8]) -> Vec<u8> {
        let mut reply: Vec<u8> = line.iter().rev().copied().collect();
        reply.push(b'\n');
        reply
    }

    /// What the echo answers to `input`, computed from the lines.
    fn replies(input: &[u8]) -> Vec<u8> {
        input
            .split_inclusive(|b| *b == b'\n')
            .flat_map(|line| Echo::reply(line.strip_suffix(b"\n").unwrap_or(line)))
            .collect()
    }

    /// The bytes it reserves: its line buffer and its reply buffer.
    fn reservation(&self) -> usize {
        self.lines.limit() + self.room
    }
}

impl Layer for Echo {
    type Lower = ByteStream;
    type Upper = Top;
    /// The length of each line answered.
    type Report = usize;
    fn report_bytes(_: &usize) -> Option<usize> {
        Some(0)
    }
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = EchoError;

    fn on_event(
        &mut self,
        env: &mut Env<'_, usize>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, EchoError> {
        if self.reserve.is_none() {
            let charge = env.budget().charge(self.reservation());
            self.reserve = Some(charge.ok_or(EchoError::Budget)?);
        }
        Ok(match event {
            StreamEvent::Written(n) => {
                self.acked += n;
                if self.acked > self.sent {
                    return Err(EchoError::Credit);
                }
                Admit::Taken
            }
            _ if self.peer_ended => Admit::Closed(event),
            // Past the boundary, input belongs to the successor.
            _ if self.boundary => Admit::Blocked(event),
            StreamEvent::Data(mut chunk) => {
                let n = self.lines.push(&chunk);
                if n == 0 {
                    return Ok(Admit::Blocked(StreamEvent::Data(chunk)));
                }
                chunk.advance(n);
                if chunk.is_empty() {
                    Admit::Taken
                } else {
                    Admit::Partial(StreamEvent::Data(chunk))
                }
            }
            StreamEvent::Ended | StreamEvent::Reset => {
                self.peer_ended = true;
                self.lines.end();
                Admit::Taken
            }
        })
    }

    fn on_command(
        &mut self,
        _env: &mut Env<'_, usize>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, EchoError> {
        match command {}
    }

    fn advance(&mut self, env: &mut Env<'_, usize>) -> Result<bool, EchoError> {
        let reservation = self.reservation();
        let Some(reserve) = &mut self.reserve else {
            return Ok(false);
        };
        // A reply that went below took part of the reservation with it.
        if !reserve.set(reservation) {
            return Ok(false);
        }
        if self.out.capacity() == 0 {
            self.out.reserve_exact(self.room);
        }
        let mut moved = false;
        while !self.boundary && self.out.len() + LINE < self.room {
            match self.lines.next() {
                Some(Ok(Ok(line))) => {
                    env.report(line.len());
                    if Some(line.as_slice()) == self.upgrade {
                        self.out.extend_from_slice(Echo::ACCEPTED);
                        self.boundary = true;
                    } else {
                        self.out.extend(Echo::reply(&line));
                    }
                }
                Some(Ok(Err(_))) => self.out.extend_from_slice(b"?\n"),
                Some(Err(_)) => return Err(EchoError::Decode),
                None => {
                    self.drained = self.peer_ended;
                    break;
                }
            }
            moved = true;
        }
        if self.ready.is_none() && !self.out.is_empty() {
            let bytes = std::mem::take(&mut self.out);
            let share = bytes.capacity().min(reserve.bytes());
            let charge = reserve
                .split(share)
                .expect("the reservation holds the share");
            self.ready = Some(Chunk::with_charge(bytes, charge));
            moved = true;
        }
        Ok(moved)
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
        if let Some(chunk) = self.ready.take() {
            self.sent += chunk.len() as u64;
            return Some(StreamCommand::Write(chunk));
        }
        if self.drained && self.out.is_empty() && !self.end_sent && !self.boundary {
            self.end_sent = true;
            return Some(StreamCommand::End);
        }
        None
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}

impl Handoff for Echo {
    type Next = Upgraded;

    fn handover(&mut self) -> Option<Handover<Upgraded, ByteStream, Top>> {
        if !self.boundary || self.handed || !self.out.is_empty() || self.ready.is_some() {
            return None;
        }
        self.handed = true;
        let mut below = Vec::new();
        if !self.lines.unread().is_empty() {
            below.push(StreamEvent::Data(Chunk::new(self.lines.unread().to_vec())));
        }
        if self.peer_ended {
            below.push(StreamEvent::Ended);
        }
        Some(Handover {
            next: Upgraded,
            below,
            above: Vec::new(),
        })
    }
}

/// What runs after the echo's upgrade: every byte back with its case
/// flipped, as soon as it comes.
struct Tunnel {
    out: Vec<u8>,
    taken: u64,
    peer_ended: bool,
    end_sent: bool,
}

impl Tunnel {
    const ROOM: usize = 16;

    fn flip(bytes: &[u8]) -> Vec<u8> {
        Mask::apply(0x20, bytes)
    }
}

impl Successor<Upgraded> for Tunnel {
    fn succeed(_: Upgraded) -> Tunnel {
        Tunnel {
            out: Vec::new(),
            taken: 0,
            peer_ended: false,
            end_sent: false,
        }
    }
}

impl Layer for Tunnel {
    type Lower = ByteStream;
    type Upper = Top;
    type Report = ();
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = Infallible;

    fn on_event(
        &mut self,
        _env: &mut Env<'_, ()>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Infallible> {
        Ok(match event {
            StreamEvent::Written(_) => Admit::Taken,
            _ if self.peer_ended => Admit::Closed(event),
            StreamEvent::Data(chunk) => {
                let before = self.out.len();
                let admit = Mask::take(0x20, Tunnel::ROOM, &mut self.out, chunk);
                self.taken += (self.out.len() - before) as u64;
                admit.map(StreamEvent::Data)
            }
            StreamEvent::Ended | StreamEvent::Reset => {
                self.peer_ended = true;
                Admit::Taken
            }
        })
    }

    fn on_command(
        &mut self,
        _env: &mut Env<'_, ()>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
        if !self.out.is_empty() {
            return Some(StreamCommand::Write(Chunk::new(std::mem::take(
                &mut self.out,
            ))));
        }
        if self.peer_ended && !self.end_sent {
            self.end_sent = true;
            return Some(StreamCommand::End);
        }
        None
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}

// ---------------------------------------------------------------------------
// A timed application

/// Sends one byte every `every`, counting from when it starts.
struct Beat {
    timers: Timers<()>,
    every: Duration,
    started: bool,
    out: Vec<u8>,
}

impl Layer for Beat {
    type Lower = ByteStream;
    type Upper = Top;
    type Report = ();
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = Infallible;

    fn on_event(
        &mut self,
        _env: &mut Env<'_, ()>,
        _event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Infallible> {
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        _env: &mut Env<'_, ()>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }

    fn on_timer(&mut self, env: &mut Env<'_, ()>, timer: ()) -> Result<(), Infallible> {
        if self.timers.fire(&timer, env.now()) {
            self.out.push(b'.');
            self.timers.set((), env.now() + self.every);
        }
        Ok(())
    }

    fn advance(&mut self, env: &mut Env<'_, ()>) -> Result<bool, Infallible> {
        if self.started {
            return Ok(false);
        }
        self.started = true;
        self.timers.set((), env.now() + self.every);
        Ok(true)
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
        (!self.out.is_empty())
            .then(|| StreamCommand::Write(Chunk::new(std::mem::take(&mut self.out))))
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }

    fn deadline(&self) -> Option<(Instant, ())> {
        self.timers.next()
    }
}

// ---------------------------------------------------------------------------
// A multiplexed connection

/// One part of an exchange on a child: a head, body bytes, the end.
#[derive(Debug)]
enum Part {
    Head(Vec<u8>),
    Body(Vec<u8>),
    End,
}

impl Credited for Part {
    fn credit(&self) -> u64 {
        match self {
            Part::Body(bytes) => bytes.len() as u64,
            Part::Head(_) | Part::End => 0,
        }
    }
}

/// A child's port: exchanges, not bytes.
struct Exchange;

impl Port for Exchange {
    type Event = Part;
    type Command = Part;
}

/// The connection's control port: pings up, pongs down.
type Ctl = Messages<u32, u32>;

const OPEN: u8 = 1;
const DATA: u8 = 2;
const END: u8 = 3;
const CREDIT: u8 = 4;
const PING: u8 = 5;
const PONG: u8 = 6;
const CLOSE: u8 = 7;

/// A frame of the toy mux protocol: kind, child, length, payload.
fn frame(kind: u8, id: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![kind];
    f.extend(id.to_be_bytes());
    f.extend((payload.len() as u16).to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// The first whole frame of `bytes`, and its length.
fn split_frame(bytes: &[u8]) -> Option<(u8, u16, &[u8], usize)> {
    let head = bytes.get(..5)?;
    let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
    let payload = bytes.get(5..5 + len)?;
    Some((
        head[0],
        u16::from_be_bytes([head[1], head[2]]),
        payload,
        5 + len,
    ))
}

fn number(payload: &[u8]) -> u32 {
    u32::from_be_bytes(payload.try_into().expect("a four-byte number"))
}

#[derive(Debug, PartialEq, Eq)]
enum ToyError {
    Kind,
    Unknown,
    Window,
    Credit,
    Twice,
    Full,
    Unsupported,
}

/// What the peer may send on a child before it is granted more.
const PEER_WINDOW: u64 = 64;

/// One child of the toy mux.
struct Lane {
    peer: u16,
    /// What the peer sent that has not gone up.
    pending: VecDeque<Part>,
    /// Credit the upper side granted for this child's events.
    up_credit: u64,
    /// What the peer may still send.
    window: u64,
    /// What this side may still send, as the peer granted.
    send: u64,
    ended_in: bool,
    ended_out: bool,
}

/// A multiplexed connection over a byte stream: children opened by the
/// peer, flow control both ways, and pings answered by whatever is on its
/// control port.
struct Toy {
    input: Vec<u8>,
    out: Vec<u8>,
    lanes: Slots<Lane>,
    by_peer: BTreeMap<u16, ChildId>,
    up: VecDeque<MuxEvent<Exchange, Ctl>>,
    peer_ended: bool,
    turn: usize,
}

impl Toy {
    const INPUT: usize = 64;
    const OUTPUT: usize = 128;
    const UP: usize = 16;

    fn new(limit: usize) -> Toy {
        Toy {
            input: Vec::new(),
            out: Vec::new(),
            lanes: Slots::new(limit),
            by_peer: BTreeMap::new(),
            up: VecDeque::new(),
            peer_ended: false,
            turn: 0,
        }
    }

    fn lane(&mut self, peer: u16) -> Result<(ChildId, &mut Lane), ToyError> {
        let id = *self.by_peer.get(&peer).ok_or(ToyError::Unknown)?;
        Ok((
            id,
            self.lanes.get_mut(id).expect("mapped children are live"),
        ))
    }

    fn frame_in(&mut self, kind: u8, peer: u16, payload: &[u8]) -> Result<(), ToyError> {
        match kind {
            OPEN => {
                if self.by_peer.contains_key(&peer) {
                    return Err(ToyError::Twice);
                }
                let lane = Lane {
                    peer,
                    pending: VecDeque::from([Part::Head(payload.to_vec())]),
                    up_credit: 0,
                    window: PEER_WINDOW,
                    send: 0,
                    ended_in: false,
                    ended_out: false,
                };
                let child = self.lanes.insert(lane).map_err(|_| ToyError::Full)?;
                self.by_peer.insert(peer, child.id());
                self.up.push_back(MuxEvent::Opened(child, (), u64::MAX));
            }
            DATA => {
                let (_, lane) = self.lane(peer)?;
                let len = payload.len() as u64;
                if len > lane.window {
                    return Err(ToyError::Window);
                }
                lane.window -= len;
                lane.pending.push_back(Part::Body(payload.to_vec()));
            }
            END => self.lane(peer)?.1.pending.push_back(Part::End),
            CREDIT => {
                if let Ok((id, lane)) = self.lane(peer) {
                    let units = u64::from(number(payload));
                    lane.send += units;
                    self.up.push_back(MuxEvent::Credit(id, units));
                }
            }
            PING => {
                let event = MessageEvent::Message(number(payload));
                self.up.push_back(MuxEvent::Control(event));
            }
            CLOSE => {
                if let Some(id) = self.by_peer.remove(&peer) {
                    self.lanes.remove(id);
                    self.up.push_back(MuxEvent::Closed(id));
                }
            }
            _ => return Err(ToyError::Kind),
        }
        Ok(())
    }

    /// Forgets a child once both directions have ended.
    fn finish(&mut self, id: ChildId) {
        if let Some(lane) = self.lanes.get(id)
            && lane.ended_in
            && lane.ended_out
        {
            self.by_peer.remove(&lane.peer);
            self.lanes.remove(id);
            self.up.push_back(MuxEvent::Closed(id));
        }
    }
}

impl Layer for Toy {
    type Lower = ByteStream;
    type Upper = Mux<Exchange, Ctl>;
    type Report = ();
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = ToyError;

    fn on_event(
        &mut self,
        _env: &mut Env<'_, ()>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, ToyError> {
        Ok(match event {
            StreamEvent::Written(_) => Admit::Taken,
            _ if self.peer_ended => Admit::Closed(event),
            StreamEvent::Data(mut chunk) => {
                let n = chunk.len().min(Toy::INPUT - self.input.len());
                if n == 0 {
                    return Ok(Admit::Blocked(StreamEvent::Data(chunk)));
                }
                self.input.extend_from_slice(&chunk[..n]);
                chunk.advance(n);
                if chunk.is_empty() {
                    Admit::Taken
                } else {
                    Admit::Partial(StreamEvent::Data(chunk))
                }
            }
            StreamEvent::Ended | StreamEvent::Reset => {
                self.peer_ended = true;
                Admit::Taken
            }
        })
    }

    fn on_command(
        &mut self,
        _env: &mut Env<'_, ()>,
        command: MuxCommand<Exchange, Ctl>,
    ) -> Result<Admit<MuxCommand<Exchange, Ctl>>, ToyError> {
        let size = match command.op() {
            MuxOp::Child(_, Part::Body(bytes)) => 5 + bytes.len(),
            _ => 9,
        };
        if self.out.len() + size > Toy::OUTPUT {
            return Ok(Admit::Blocked(command));
        }
        let child = match command.op() {
            MuxOp::Child(id, _) | MuxOp::Credit(id, _) | MuxOp::Close(id) => Some(*id),
            MuxOp::Control(_) => None,
        };
        // A child that is gone takes nothing, and never will.
        if child.is_some_and(|id| !self.lanes.contains(id)) {
            return Ok(Admit::Closed(command));
        }
        match command.into_op() {
            MuxOp::Child(_, Part::Head(_)) => return Err(ToyError::Unsupported),
            MuxOp::Child(id, Part::Body(bytes)) => {
                let lane = self.lanes.get_mut(id).expect("checked above");
                let len = bytes.len() as u64;
                if len > lane.send {
                    return Err(ToyError::Credit);
                }
                lane.send -= len;
                self.out.extend(frame(DATA, lane.peer, &bytes));
            }
            MuxOp::Child(id, Part::End) => {
                let lane = self.lanes.get_mut(id).expect("checked above");
                lane.ended_out = true;
                self.out.extend(frame(END, lane.peer, &[]));
                self.finish(id);
            }
            MuxOp::Credit(id, units) => {
                let lane = self.lanes.get_mut(id).expect("checked above");
                lane.up_credit += units;
                lane.window += units;
                let units = u32::try_from(units).map_err(|_| ToyError::Credit)?;
                self.out
                    .extend(frame(CREDIT, lane.peer, &units.to_be_bytes()));
            }
            MuxOp::Close(id) => {
                let lane = self.lanes.remove(id).expect("checked above");
                self.by_peer.remove(&lane.peer);
                self.out.extend(frame(CLOSE, lane.peer, &[]));
            }
            MuxOp::Control(MessageCommand::Send(n)) => {
                self.out.extend(frame(PONG, 0, &n.to_be_bytes()));
            }
            MuxOp::Control(MessageCommand::End) => {}
        }
        Ok(Admit::Taken)
    }

    fn advance(&mut self, _env: &mut Env<'_, ()>) -> Result<bool, ToyError> {
        let mut moved = false;
        while self.up.len() < Toy::UP {
            let Some((kind, peer, payload, used)) = split_frame(&self.input) else {
                break;
            };
            let payload = payload.to_vec();
            self.input.drain(..used);
            self.frame_in(kind, peer, &payload)?;
            moved = true;
        }
        Ok(moved)
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
        (!self.out.is_empty())
            .then(|| StreamCommand::Write(Chunk::new(std::mem::take(&mut self.out))))
    }

    fn take_event(&mut self) -> Option<MuxEvent<Exchange, Ctl>> {
        if let Some(event) = self.up.pop_front() {
            return Some(event);
        }
        let ids: Vec<ChildId> = self.lanes.ids().collect();
        for k in 0..ids.len() {
            let id = ids[(self.turn + k) % ids.len()];
            let lane = self.lanes.get_mut(id).expect("listed children are live");
            let Some(cost) = lane.pending.front().map(Credited::credit) else {
                continue;
            };
            if cost > lane.up_credit {
                continue;
            }
            lane.up_credit -= cost;
            let part = lane.pending.pop_front().expect("looked at above");
            if matches!(part, Part::End) {
                lane.ended_in = true;
            }
            self.turn = (self.turn + k + 1) % ids.len();
            self.finish(id);
            return Some(MuxEvent::Child(id, part));
        }
        None
    }
}

/// The application on each child: it collects the body and answers it in
/// capitals, in pieces. A child whose head is `slow` asks the world for
/// work first and reads nothing until the work is done.
#[derive(Default)]
struct Answer {
    body: Vec<u8>,
    waiting: bool,
    ask: bool,
    reply: VecDeque<Part>,
}

impl Answer {
    const PIECE: usize = 16;

    fn capitals(body: &[u8]) -> Vec<u8> {
        body.to_ascii_uppercase()
    }
}

impl Layer for Answer {
    type Lower = Exchange;
    type Upper = Top;
    type Report = ();
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = Infallible;

    fn on_event(&mut self, _env: &mut Env<'_, ()>, part: Part) -> Result<Admit<Part>, Infallible> {
        Ok(match part {
            Part::Head(head) => {
                self.waiting = head == b"slow";
                self.ask = self.waiting;
                Admit::Taken
            }
            _ if self.waiting => Admit::Blocked(part),
            Part::Body(bytes) => {
                self.body.extend(bytes);
                Admit::Taken
            }
            Part::End => {
                let answer = Answer::capitals(&self.body);
                for piece in answer.chunks(Answer::PIECE) {
                    self.reply.push_back(Part::Body(piece.to_vec()));
                }
                self.reply.push_back(Part::End);
                Admit::Taken
            }
        })
    }

    fn on_command(
        &mut self,
        _env: &mut Env<'_, ()>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }

    fn on_done(&mut self, _env: &mut Env<'_, ()>, _done: ()) -> Result<(), Infallible> {
        self.waiting = false;
        Ok(())
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<Part> {
        self.reply.pop_front()
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }

    fn take_work(&mut self) -> Option<()> {
        std::mem::take(&mut self.ask).then_some(())
    }
}

/// The application on the control port: a pong for each ping.
#[derive(Default)]
struct Pong {
    pongs: VecDeque<u32>,
}

impl Layer for Pong {
    type Lower = Ctl;
    type Upper = Top;
    type Report = ();
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = Infallible;

    fn on_event(
        &mut self,
        _env: &mut Env<'_, ()>,
        event: MessageEvent<u32>,
    ) -> Result<Admit<MessageEvent<u32>>, Infallible> {
        Ok(match event {
            MessageEvent::Message(_) if self.pongs.len() >= 4 => Admit::Blocked(event),
            MessageEvent::Message(n) => {
                self.pongs.push_back(n);
                Admit::Taken
            }
            MessageEvent::Ended => Admit::Taken,
        })
    }

    fn on_command(
        &mut self,
        _env: &mut Env<'_, ()>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<MessageCommand<u32>> {
        self.pongs.pop_front().map(MessageCommand::Send)
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}

// ---------------------------------------------------------------------------
// The stacks

/// A transform over a byte stream, with an application over its plaintext.
type Masked = Chain<Mask, Echo>;
/// A mux with an application on each child exchange and one on its control
/// port.
type Muxed = Chain<Chain<Toy, Children<Answer, Ctl>>, Pong>;
/// A line protocol that can hand its connection to a tunnel.
type Gated = Switch<Echo, Tunnel>;

const KEY: u8 = 0x5a;

fn masked(room: usize) -> Masked {
    Chain::new(Mask::new(KEY, 8), Echo::new(room))
}

fn muxed() -> Muxed {
    Chain::new(
        Chain::new(
            Toy::new(8),
            Children::new(8, 64, |_, (), _| Some(Answer::default())),
        ),
        Pong::default(),
    )
}

fn gated() -> Gated {
    Switch::new(Echo::upgrading(64, b"CONNECT"))
}

/// The work a muxed stack asks for, as the child it is for.
fn work_child(work: Side<Side<(), ChildWork<()>>, ()>) -> ChildId {
    match work {
        Side::Lower(Side::Upper(work)) => work.id(),
        _ => panic!("only children ask for work"),
    }
}

fn done_for(id: ChildId) -> Side<Side<(), (ChildId, ())>, ()> {
    Side::Lower(Side::Upper((id, ())))
}

/// Chunk sizes from 1 to 7 that add up to `len`, drawn from `seed`.
fn cuts(len: usize, seed: u64) -> Vec<usize> {
    let entropy = SeededEntropy::new(Seed::from_u64(seed));
    let mut sizes = Vec::new();
    let mut left = len;
    while left > 0 {
        let n = 1 + entropy.random_below(left.min(7) as u64) as usize;
        sizes.push(n);
        left -= n;
    }
    sizes
}

/// Every way to cut `input` that the tests try: whole, in two at every
/// point, and in seeded small pieces.
fn segmentations(input: &[u8]) -> Vec<Vec<&[u8]>> {
    let mut all = vec![vec![input]];
    for at in 1..input.len() {
        all.push(vec![&input[..at], &input[at..]]);
    }
    for seed in 0..32 {
        let mut rest = input;
        let mut pieces = Vec::new();
        for n in cuts(input.len(), seed) {
            let (piece, tail) = rest.split_at(n);
            pieces.push(piece);
            rest = tail;
        }
        all.push(pieces);
    }
    all
}

/// The frames a peer of the toy mux saw, by what they mean.
#[derive(Debug, Default, PartialEq, Eq)]
struct Seen {
    bodies: BTreeMap<u16, Vec<u8>>,
    ended: BTreeSet<u16>,
    pongs: Vec<u32>,
    /// Kind and child of every frame, in order.
    order: Vec<(u8, u16)>,
}

impl Seen {
    fn of(mut bytes: &[u8]) -> Seen {
        let mut seen = Seen::default();
        while let Some((kind, id, payload, used)) = split_frame(bytes) {
            match kind {
                DATA => seen
                    .bodies
                    .entry(id)
                    .or_default()
                    .extend_from_slice(payload),
                END => {
                    seen.ended.insert(id);
                }
                PONG => seen.pongs.push(number(payload)),
                _ => {}
            }
            seen.order.push((kind, id));
            bytes = &bytes[used..];
        }
        assert!(bytes.is_empty(), "the output ends in a whole frame");
        seen
    }

    /// Where the first frame of `kind` for child `id` is.
    fn first(&self, kind: u8, id: u16) -> Option<usize> {
        self.order.iter().position(|k| *k == (kind, id))
    }
}

// ---------------------------------------------------------------------------
// Transform with an application

#[test]
fn a_transform_under_an_application_answers_the_same_at_every_cut() {
    let input = b"alpha\nbeta gamma\n\nthe quick brown fox jumps over\nz\n";
    let expected = Echo::replies(input);
    let masked_input = Mask::apply(KEY, input);
    let mut answers = BTreeSet::new();
    for pieces in segmentations(&masked_input) {
        let mut h = Harness::new(Seed::from_u64(1), masked(64));
        for piece in pieces {
            h.push(piece).unwrap();
        }
        h.end().unwrap();
        let plain = Mask::apply(KEY, h.output());
        assert_eq!(plain, expected);
        assert!(
            h.ended(),
            "the end of input reaches the application and back"
        );
        assert_eq!(h.unread(), 0);
        answers.insert(plain);
    }
    assert_eq!(answers.len(), 1);
}

#[test]
fn withheld_output_loses_nothing_and_credits_each_byte_once() {
    let input: Vec<u8> = (0..40)
        .flat_map(|i| format!("line number {i}\n").into_bytes())
        .collect();
    let expected = Echo::replies(&input);

    let mut h = Harness::new(Seed::from_u64(2), masked(LINE + 2));
    h.withhold();
    h.push(&Mask::apply(KEY, &input)).unwrap();
    assert!(h.output().is_empty(), "the transport took nothing");
    assert!(
        h.unread() > 0,
        "input backs up to its sender instead of piling up"
    );
    let backed_up = h.unread();

    // Zero bytes allowed moves nothing.
    h.allow(0).unwrap();
    assert!(h.output().is_empty());
    assert_eq!(h.unread(), backed_up);

    // Then a few bytes at a time, never more than the transport allows.
    let mut step = 0;
    while h.output().len() < expected.len() {
        let before = h.output().len();
        let allowed = step % 5;
        h.allow(allowed).unwrap();
        assert!(h.output().len() - before <= allowed);
        step += 1;
        assert!(step < 100_000, "output stopped coming");
    }
    h.end().unwrap();
    h.allow_all().unwrap();
    assert_eq!(Mask::apply(KEY, h.output()), expected);
    assert!(h.ended());
    let echo = h.layer().upper();
    assert_eq!(echo.sent, h.output().len() as u64);
    assert_eq!(
        echo.acked, echo.sent,
        "every byte the transport took is credited once"
    );
}

#[test]
fn charges_move_with_output_and_come_back() {
    let budget = Budget::new(1 << 20);
    let mut h = Harness::with_budget(Seed::from_u64(3), Echo::new(64), budget.clone());
    let reservation = h.layer().reservation();
    h.withhold();
    h.push(b"one\ntwo\n").unwrap();
    // A reply the transport has not taken still holds its charge.
    assert!(h.driver().holds_output());
    assert!(budget.used() > reservation);
    h.allow_all().unwrap();
    assert_eq!(budget.used(), reservation);
    drop(h);
    assert_eq!(budget.used(), 0);

    // A budget that cannot hold the reservation refuses before anything
    // is taken, and keeps nothing charged.
    let small = Budget::new(reservation - 1);
    let mut h = Harness::with_budget(Seed::from_u64(3), Echo::new(64), small.clone());
    assert_eq!(h.push(b"one\n"), Err(EchoError::Budget));
    assert_eq!(small.used(), 0);
}

#[test]
fn timers_fire_through_a_chain_each_at_its_own_time() {
    let every = Duration::from_millis(250);
    let beat = Beat {
        timers: Timers::new(),
        every,
        started: false,
        out: Vec::new(),
    };
    let mut h = Harness::new(Seed::from_u64(4), Chain::new(Mask::new(KEY, 8), beat));
    h.push(&[]).unwrap();
    let elapsed = every * 7 + every / 2;
    h.advance(elapsed).unwrap();
    let beats = (elapsed.as_millis() / every.as_millis()) as usize;
    assert_eq!(Mask::apply(KEY, h.output()), vec![b'.'; beats]);
    // The next beat is due one period after the last, not after the advance.
    let next = h.driver().deadline().unwrap();
    assert_eq!(next, Instant::ZERO + every * (beats as u32 + 1));
}

#[test]
fn timers_break_ties_by_arming_order() {
    let at = Instant::ZERO + Duration::from_secs(1);
    let mut timers = Timers::new();
    timers.set('a', at);
    timers.set('b', at);
    timers.set('c', Instant::ZERO);
    assert_eq!(timers.next(), Some((Instant::ZERO, 'c')));
    assert!(timers.fire(&'c', Instant::ZERO));
    assert_eq!(timers.next(), Some((at, 'a')));
    assert!(!timers.fire(&'a', Instant::ZERO), "not due yet");
    timers.set('a', at);
    assert_eq!(
        timers.next(),
        Some((at, 'b')),
        "arming again moves a timer back"
    );
    assert!(timers.cancel(&'b'));
    assert_eq!(timers.next().map(|(_, t)| t), Some('a'));
}

#[test]
fn reports_are_bounded_and_never_hold_up_the_protocol() {
    let input = b"a\nbb\nccc\ndddd\neeeee\n";
    let mut h = Harness::new(Seed::from_u64(5), Echo::new(64));
    h.driver().keep_observations(2);
    h.push(input).unwrap();
    assert_eq!(h.output(), Echo::replies(input));
    let lines = input
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .count();
    let kept: Vec<usize> = h.driver().observations().drain().collect();
    assert_eq!(kept.len(), 2);
    assert_eq!(h.driver().observations().omitted(), (lines - 2) as u64);
}

// ---------------------------------------------------------------------------
// Negotiated change

#[test]
fn an_upgrade_hands_the_coalesced_suffix_over_once() {
    let before = b"one\n";
    let suffix = b"Tunnel Bytes\nand more";
    let input = [&before[..], b"CONNECT\n", suffix].concat();
    let expected = [
        Echo::replies(before),
        Echo::ACCEPTED.to_vec(),
        Tunnel::flip(suffix),
    ]
    .concat();
    for pieces in segmentations(&input) {
        let mut h = Harness::new(Seed::from_u64(6), gated());
        for piece in pieces {
            h.push(piece).unwrap();
        }
        h.end().unwrap();
        assert_eq!(h.output(), expected);
        assert!(h.ended());
        let tunnel = h.layer().then().expect("the switch happened");
        assert_eq!(
            tunnel.taken,
            suffix.len() as u64,
            "each byte reaches the tunnel once"
        );
    }
}

#[test]
fn an_upgrade_under_backpressure_keeps_the_old_answer_first() {
    let suffix = b"abcdefghijklmnopqrstuvwxyz";
    let input = [&b"CONNECT\n"[..], suffix].concat();
    let expected = [Echo::ACCEPTED.to_vec(), Tunnel::flip(suffix)].concat();
    let mut h = Harness::new(Seed::from_u64(7), gated());
    h.withhold();
    h.push(&input).unwrap();
    h.end().unwrap();
    assert!(h.output().is_empty());
    let mut step = 0;
    while !h.ended() {
        h.allow(step % 3).unwrap();
        step += 1;
        assert!(step < 10_000, "output stopped coming");
    }
    assert_eq!(h.output(), expected);
    assert_eq!(h.layer().then().unwrap().taken, suffix.len() as u64);
}

// ---------------------------------------------------------------------------
// Multiplexed children

fn credit(id: u16, units: u32) -> Vec<u8> {
    frame(CREDIT, id, &units.to_be_bytes())
}

fn exchange(id: u16, head: &[u8], body: &[u8]) -> Vec<u8> {
    [
        frame(OPEN, id, head),
        frame(DATA, id, body),
        frame(END, id, &[]),
    ]
    .concat()
}

#[test]
fn a_child_waiting_on_work_holds_up_neither_siblings_nor_control() {
    let mut h = Harness::new(Seed::from_u64(8), muxed());
    let input = [
        exchange(1, b"slow", b"first child"),
        credit(1, 1000),
        exchange(2, b"fast", b"second child"),
        credit(2, 1000),
        frame(PING, 0, &7u32.to_be_bytes()),
    ]
    .concat();
    h.push(&input).unwrap();
    let seen = Seen::of(h.output());
    assert_eq!(
        seen.bodies.get(&2),
        Some(&Answer::capitals(b"second child"))
    );
    assert!(seen.ended.contains(&2));
    assert_eq!(seen.pongs, [7]);
    assert!(
        !seen.bodies.contains_key(&1),
        "the slow child has not answered"
    );

    let id = work_child(h.work().expect("the slow child asked for work"));
    assert!(h.work().is_none());
    h.complete(done_for(id)).unwrap();
    let seen = Seen::of(h.output());
    assert_eq!(seen.bodies.get(&1), Some(&Answer::capitals(b"first child")));
    assert!(seen.ended.contains(&1));
    assert!(seen.first(PONG, 0) < seen.first(DATA, 1));
    assert!(seen.first(END, 2) < seen.first(DATA, 1));
}

#[test]
fn a_child_without_credit_waits_while_siblings_and_control_go_on() {
    let mut h = Harness::new(Seed::from_u64(9), muxed());
    let input = [
        exchange(1, b"fast", b"held back"),
        exchange(2, b"fast", b"goes ahead"),
        credit(2, 1000),
        frame(PING, 0, &9u32.to_be_bytes()),
    ]
    .concat();
    h.push(&input).unwrap();
    let seen = Seen::of(h.output());
    assert_eq!(seen.bodies.get(&2), Some(&Answer::capitals(b"goes ahead")));
    assert_eq!(seen.pongs, [9]);
    assert!(!seen.bodies.contains_key(&1));

    // Less credit than the next piece: the piece is not split.
    h.push(&credit(1, 3)).unwrap();
    assert!(!Seen::of(h.output()).bodies.contains_key(&1));

    h.push(&credit(1, 1000)).unwrap();
    let seen = Seen::of(h.output());
    assert_eq!(seen.bodies.get(&1), Some(&Answer::capitals(b"held back")));
    assert!(seen.ended.contains(&1));
}

#[test]
fn work_for_a_closed_child_reaches_nothing() {
    let mut h = Harness::new(Seed::from_u64(10), muxed());
    h.push(&[exchange(1, b"slow", b"old"), credit(1, 100)].concat())
        .unwrap();
    let old = work_child(h.work().unwrap());
    // The peer closes the child, then opens another under the same number,
    // which takes the same slot.
    h.push(&frame(CLOSE, 1, &[])).unwrap();
    h.push(&[exchange(1, b"slow", b"new"), credit(1, 100)].concat())
        .unwrap();
    let new = work_child(h.work().unwrap());
    assert_ne!(old, new);

    h.complete(done_for(old)).unwrap();
    assert!(
        Seen::of(h.output()).bodies.is_empty(),
        "the old child's work woke nothing"
    );
    h.complete(done_for(new)).unwrap();
    assert_eq!(
        Seen::of(h.output()).bodies.get(&1),
        Some(&Answer::capitals(b"new"))
    );
}

#[test]
fn a_mux_transcript_means_the_same_however_it_is_cut() {
    let input = [
        credit(1, 0),
        exchange(1, b"fast", b"one"),
        credit(1, 500),
        exchange(2, b"fast", b"two two"),
        frame(PING, 0, &1u32.to_be_bytes()),
        credit(2, 500),
        exchange(3, b"fast", b"three three three"),
        credit(3, 500),
        frame(PING, 0, &2u32.to_be_bytes()),
    ]
    .concat();
    let mut meanings = Vec::new();
    for pieces in segmentations(&input) {
        let mut h = Harness::new(Seed::from_u64(11), muxed());
        for piece in pieces {
            h.push(piece).unwrap();
        }
        let mut seen = Seen::of(h.output());
        seen.order.clear();
        meanings.push(seen);
    }
    let first = &meanings[0];
    assert_eq!(
        first.bodies.get(&3),
        Some(&Answer::capitals(b"three three three"))
    );
    assert_eq!(first.ended.len(), 3);
    assert_eq!(first.pongs, [1, 2]);
    assert!(meanings.iter().all(|m| m == first));
}

#[test]
fn a_mux_refuses_commands_for_a_child_that_is_gone() {
    let mut driver = Driver::new(
        Toy::new(4),
        std::sync::Arc::new(SeededEntropy::new(Seed::from_u64(12))),
        Budget::unlimited(),
        Instant::ZERO,
    );
    let open = frame(OPEN, 5, b"head");
    let _ = driver.deliver(StreamEvent::Data(Chunk::new(open))).unwrap();
    driver.run().unwrap();
    let Some(MuxEvent::Opened(child, (), u64::MAX)) = driver.layer_mut().take_event() else {
        panic!("the child opened");
    };
    let close = frame(CLOSE, 5, &[]);
    let _ = driver
        .deliver(StreamEvent::Data(Chunk::new(close)))
        .unwrap();
    driver.run().unwrap();
    // The peer closed it; the handle is still here, and goes nowhere.
    let command: MuxCommand<Exchange, Ctl> = child.send(Part::End);
    assert!(matches!(driver.command(command), Ok(Admit::Closed(_))));
}

#[test]
fn slots_never_answer_to_a_stale_or_foreign_id() {
    let mut slots = Slots::new(2);
    let a = slots.insert('a').unwrap();
    let b = slots.insert('b').unwrap();
    assert!(slots.insert('c').is_err(), "the limit holds");
    let old = a.id();
    assert_eq!(slots.remove(old), Some('a'));
    let c = slots.insert('c').unwrap();
    assert_ne!(c.id(), old, "a reused slot has a new generation");
    assert_eq!(slots.get(old), None);
    assert_eq!(slots.remove(old), None);
    assert_eq!(slots.get(c.id()), Some(&'c'));
    assert_eq!(slots.ids().count(), 2);

    let mut other = Slots::new(2);
    let d = other.insert('d').unwrap();
    assert_eq!(
        slots.get(d.id()),
        None,
        "another connection's id finds nothing"
    );
    assert_eq!(other.get(b.id()), None);
}

// ---------------------------------------------------------------------------
// Depth: a composition that grows while it runs stays within MAX_DEPTH

/// `layer` inside as many boxes as make it `depth` deep. Every box is a
/// real level of calls.
fn boxed_to<L>(layer: L, depth: usize) -> Boxed<L::Lower, L::Upper>
where
    L: Layer + Send + 'static,
    L::Report: core::fmt::Debug + Send + 'static,
    L::Work: Job<Done = L::Done>,
    L::Done: Send + 'static,
    L::Error: Into<BoxError> + Send + Sync + 'static,
{
    let mut stack = Boxed::new(layer);
    while stack.depth() < depth {
        stack = Boxed::new(stack);
    }
    stack
}

/// A layer that takes nothing and, as soon as it runs, hands its carrier
/// to the successor it holds, if it holds one.
struct Hands(Option<Boxed>);

impl Layer for Hands {
    type Lower = ByteStream;
    type Upper = Top;
    type Report = ();
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = Infallible;
    fn on_event(
        &mut self,
        _: &mut Env<'_, ()>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Infallible> {
        Ok(Admit::Blocked(event))
    }
    fn on_command(
        &mut self,
        _: &mut Env<'_, ()>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }
    fn take_command(&mut self, _: &mut Env<'_, ()>) -> Option<StreamCommand> {
        None
    }
    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
}

impl Handoff for Hands {
    type Next = Boxed;
    fn handover(&mut self) -> Option<Handover<Boxed, ByteStream, Top>> {
        Some(Handover {
            next: self.0.take()?,
            below: Vec::new(),
            above: Vec::new(),
        })
    }
}

impl Successor<Boxed> for Boxed {
    fn succeed(next: Boxed) -> Boxed {
        next
    }
}

/// A switch two chains down whose successor is `depth` deep.
fn switching_to(depth: usize) -> Chain<Mask, Chain<Mask, Switch<Hands, Boxed>>> {
    let successor = boxed_to(Hands(None), depth);
    Chain::new(
        Mask::new(KEY, 8),
        Chain::new(Mask::new(KEY, 8), Switch::new(Hands(Some(successor)))),
    )
}

/// [`Muxed`] with boxed children.
type DeepMuxed = Chain<Chain<Toy, Children<Boxed<Exchange, Top>, Ctl>>, Pong>;

/// A mux one chain down, under the application on its control port, with
/// children `depth` deep.
fn muxed_to(depth: usize) -> DeepMuxed {
    Chain::new(
        Chain::new(
            Toy::new(8),
            Children::new(8, 64, move |_, (), _| {
                Some(boxed_to(Answer::default(), depth))
            }),
        ),
        Pong::default(),
    )
}

#[test]
fn a_successor_must_fit_where_its_switch_sits() {
    // The switch is two levels down and is a level itself, so what it
    // hands over to may be MAX_DEPTH - 3 deep.
    let fits = MAX_DEPTH - 3;
    let drive = |stack| {
        Driver::new(
            stack,
            std::sync::Arc::new(SeededEntropy::new(Seed::from_u64(3))),
            Budget::unlimited(),
            Instant::ZERO,
        )
    };
    let mut driver = drive(switching_to(fits));
    let before = driver.layer().depth();
    driver.run().unwrap();
    assert!(driver.layer().depth() > before, "the switch handed over");
    assert_eq!(driver.layer().depth(), MAX_DEPTH);

    let mut deeper = drive(switching_to(fits + 1));
    let handed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| deeper.run()));
    assert!(handed.is_err(), "a successor one level too deep was kept");
}

#[test]
fn a_child_must_fit_where_its_router_sits() {
    // The router is two levels down and is a level itself, so its
    // children may be MAX_DEPTH - 3 deep.
    let fits = MAX_DEPTH - 3;
    let open = frame(OPEN, 1, b"fast");
    let mut h = Harness::new(Seed::from_u64(8), muxed_to(fits));
    h.push(&open).unwrap();
    assert_eq!(h.layer().depth(), MAX_DEPTH, "the child is open");
    h.push(
        &[
            frame(DATA, 1, b"deep child"),
            frame(END, 1, &[]),
            credit(1, 1000),
        ]
        .concat(),
    )
    .unwrap();
    assert_eq!(
        Seen::of(h.output()).bodies.get(&1),
        Some(&Answer::capitals(b"deep child"))
    );

    let mut deeper = Harness::new(Seed::from_u64(8), muxed_to(fits + 1));
    let opened = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| deeper.push(&open)));
    assert!(opened.is_err(), "a child one level too deep was made");
}

#[test]
fn a_later_layer_must_fit_where_its_later_sits() {
    let entropy = SeededEntropy::new(Seed::from_u64(0));
    let budget = Budget::unlimited();
    let mut reports = Observations::new(0);
    let mut env = Env::new(Instant::ZERO, &entropy, &budget, &mut reports);
    // A `Later` two levels down, as the upper part of a chain inside a
    // chain, is a level itself: what it holds may be MAX_DEPTH - 3 deep.
    let fits = MAX_DEPTH - 3;
    let mut later = Later::new();
    env.part(|env| env.part(|env| later.set(env, boxed_to(Hands(None), fits))));
    assert_eq!(later.depth() + 2, MAX_DEPTH);

    let mut deeper = Later::new();
    let set = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.part(|env| env.part(|env| deeper.set(env, boxed_to(Hands(None), fits + 1))));
    }));
    assert!(set.is_err(), "a layer one level too deep was set");
}
