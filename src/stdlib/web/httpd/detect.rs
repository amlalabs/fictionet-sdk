//! Telling HTTP/2 from HTTP/1 on a connection.

use std::convert::Infallible;
use std::time::Duration;

use fictionet::stdlib::layer::{
    Admit, ByteStream, Charge, Chunk, Env, Handoff, Handover, Layer, Side, StreamCommand,
    StreamEvent, Successor, Switch, Top,
};
use fictionet::stdlib::protocols::http2::PREFACE;
use fictionet::time::Instant;

use super::Servers;
use super::http2::Http2Server;
use super::native::{Http1, Upgraded};

/// What serves a connection once its version is known: HTTP/1, which may
/// hand on to a tunnel or to HTTP/2, or HTTP/2 from the start.
pub type Versions = Side<Switch<Http1, Upgraded>, Http2Server>;

/// HTTP for one connection: over TLS, the version ALPN chose; without
/// TLS, [`Detect`] until the version is known, then that version's server.
/// [`serve_connection`](super::serve_connection) runs it.
pub type Http = Side<Versions, Switch<Detect, Versions>>;

impl Successor<Versions> for Versions {
    fn succeed(versions: Versions) -> Versions {
        versions
    }
}

/// Reads no more of a connection's first bytes than it takes to tell
/// HTTP/2's preface (HTTP/2 with prior knowledge) from HTTP/1, then makes
/// the server it chose and hands it those bytes, and everything after them.
///
/// It holds at most the 24 bytes of the preface. The first byte that
/// differs from it chooses HTTP/1, as does the client's end inside it; the
/// whole preface chooses HTTP/2. A client that has not chosen by the
/// first-bytes deadline is closed with nothing written.
pub struct Detect {
    first: Vec<u8>,
    charge: Option<Charge>,
    timeout: Option<Duration>,
    deadline: Option<Instant>,
    servers: Option<Servers>,
    chosen: Option<bool>,
    peer_ended: bool,
    out: Option<StreamCommand>,
    closed: bool,
}

impl Detect {
    /// Reads the first bytes, for at most `timeout` from the first call,
    /// then makes the version they chose from `servers`.
    pub(super) fn new(timeout: Duration, servers: Servers) -> Self {
        Self {
            first: Vec::new(),
            charge: None,
            timeout: Some(timeout),
            deadline: None,
            servers: Some(servers),
            chosen: None,
            peer_ended: false,
            out: None,
            closed: false,
        }
    }

    fn start(&mut self, env: &mut Env<'_, Infallible>) {
        if let Some(timeout) = self.timeout.take() {
            self.deadline = Some(env.now() + timeout);
        }
    }

    fn undecided(&self) -> bool {
        self.chosen.is_none() && !self.closed
    }
}

impl Layer for Detect {
    type Lower = ByteStream;
    type Upper = Top;
    type Report = Infallible;
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;

    fn on_event(
        &mut self,
        env: &mut Env<'_, Infallible>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Infallible> {
        self.start(env);
        if self.closed {
            return Ok(Admit::Closed(event));
        }
        if self.chosen.is_some() {
            return Ok(Admit::Blocked(event));
        }
        match event {
            StreamEvent::Data(mut chunk) => {
                if self.charge.is_none() {
                    self.charge = env.budget().charge(PREFACE.len());
                    if self.charge.is_none() {
                        self.closed = true;
                        self.out = Some(StreamCommand::End);
                        return Ok(Admit::Closed(StreamEvent::Data(chunk)));
                    }
                    self.first.reserve_exact(PREFACE.len());
                }
                let (taken, chosen) = scan(&mut self.first, &chunk);
                self.chosen = chosen;
                chunk.advance(taken);
                Ok(if chunk.is_empty() {
                    Admit::Taken
                } else {
                    Admit::Partial(StreamEvent::Data(chunk))
                })
            }
            // An end inside the preface goes to HTTP/1, which answers a
            // cut-off head.
            StreamEvent::Ended => {
                self.peer_ended = true;
                self.chosen = Some(false);
                Ok(Admit::Taken)
            }
            StreamEvent::Written(_) => Ok(Admit::Taken),
            StreamEvent::Reset => {
                self.closed = true;
                Ok(Admit::Taken)
            }
        }
    }

    fn on_command(
        &mut self,
        _: &mut Env<'_, Infallible>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, Infallible> {
        match command {}
    }

    fn on_timer(&mut self, env: &mut Env<'_, Infallible>, _: ()) -> Result<bool, Infallible> {
        if !self.undecided() || self.deadline.is_none_or(|at| at > env.now()) {
            return Ok(false);
        }
        // Past the first-bytes deadline: close with nothing written.
        self.deadline = None;
        self.closed = true;
        self.out = Some(StreamCommand::End);
        Ok(true)
    }

    fn advance(&mut self, env: &mut Env<'_, Infallible>) -> Result<bool, Infallible> {
        let fresh = self.timeout.is_some();
        self.start(env);
        Ok(fresh)
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<StreamCommand> {
        self.out.take()
    }

    fn take_event(&mut self) -> Option<Infallible> {
        None
    }

    fn is_terminal(&self) -> bool {
        self.closed && self.out.is_none()
    }

    fn deadline(&self) -> Option<(Instant, ())> {
        self.deadline
            .filter(|_| self.undecided())
            .map(|at| (at, ()))
    }
}

/// Reads `bytes` into `first`, the bytes read so far, until they tell the
/// versions apart: how many it took, and HTTP/2 (`true`) or HTTP/1 once
/// known. The byte that differs from the preface is taken, so HTTP/1 reads
/// it from `first`; what is not taken comes after.
fn scan(first: &mut Vec<u8>, bytes: &[u8]) -> (usize, Option<bool>) {
    for (taken, &byte) in bytes.iter().enumerate() {
        first.push(byte);
        if !PREFACE.starts_with(first) {
            return (taken + 1, Some(false));
        }
        if first.len() == PREFACE.len() {
            return (taken + 1, Some(true));
        }
    }
    (bytes.len(), None)
}

/// Bounded proofs over [`scan`], run with `cargo kani`.
#[cfg(kani)]
#[path = "../../../../verification/http2-layer/kani/detect.rs"]
mod proofs;

impl Handoff for Detect {
    type Next = Versions;

    fn handover(&mut self) -> Option<Handover<Versions, ByteStream, Top>> {
        let h2 = self.chosen?;
        if self.closed {
            return None;
        }
        let servers = self.servers.take()?;
        let mut below = Vec::new();
        if !self.first.is_empty() {
            let bytes = std::mem::take(&mut self.first);
            below.push(StreamEvent::Data(match self.charge.take() {
                Some(charge) => Chunk::with_charge(bytes, charge),
                None => Chunk::new(bytes),
            }));
        }
        if self.peer_ended {
            below.push(StreamEvent::Ended);
        }
        self.closed = true;
        Some(Handover {
            next: servers.make(h2),
            below,
            above: Vec::new(),
        })
    }
}
