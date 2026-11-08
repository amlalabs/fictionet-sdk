//! Drivers with no runtime: servers in memory, recorded exchanges, and a
//! loop that runs an engine against either on a virtual clock.
//!
//! A [`MemoryNet`] holds engines by address and carries each transmit to
//! the engine at its address at once, so a resolver can iterate through
//! a whole hierarchy of [`AuthorityEngine`](super::authority::AuthorityEngine)s
//! with no sockets and no tasks. It keeps every exchange it carries, and
//! [`MemoryNet::recording`] hands them over as a [`Recording`] that
//! answers the same questions in another run. [`drive`] runs an engine
//! on client queries until each is answered.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use fictionet::Entropy;
use fictionet::stdlib::network::Transport;
use fictionet::stdlib::protocols::dns::op::{Message, Query};
use fictionet::stdlib::protocols::dns::{Parsed, Request, read_message};
use fictionet::time::Instant;

use super::exchange::{
    Action, Answer, Client, ClientQuery, Engine, ExchangeFailure, Input, Transmit,
};
use super::lookup::{Looked, Lookup};

/// Something that carries an engine's transmits and says what came back.
pub trait Exchanges {
    /// What `transmit`, sent at `now`, brings back for the engine: a reply,
    /// a failure, or nothing, which the engine sees as a timeout.
    fn exchange(&mut self, transmit: &Transmit, now: Instant, entropy: &dyn Entropy) -> Vec<Input>;
}

/// One exchange a client made with a server, as it was carried.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Exchange {
    /// The server asked.
    pub server: SocketAddr,
    /// How it was asked.
    pub transport: Transport,
    /// The query, as sent.
    pub query: Vec<u8>,
    /// What came of it.
    pub outcome: Outcome,
}

/// What a client saw of one exchange.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// The server's reply, as it arrived.
    Reply(Vec<u8>),
    /// The server could not be reached.
    Unreachable,
    /// No reply came.
    Timeout,
}

/// What a server's lookups give, in memory.
type Upstream = Box<dyn FnMut(&Lookup) -> Looked>;

/// Servers by address, in memory. Transmits are delivered at once.
pub struct MemoryNet {
    servers: BTreeMap<IpAddr, Server>,
    upstream: Option<Upstream>,
    lose: Option<Loss>,
    exchanges: Vec<Exchange>,
}

/// A script that says which transmits are lost.
type Loss = Box<dyn FnMut(&Transmit) -> bool>;

/// One server engine and its own clock, which only moves forward.
struct Server {
    engine: Box<dyn Engine>,
    clock: Instant,
}

impl MemoryNet {
    /// A network with no servers.
    pub fn new() -> MemoryNet {
        MemoryNet {
            servers: BTreeMap::new(),
            upstream: None,
            lose: None,
            exchanges: Vec::new(),
        }
    }

    /// Runs `engine` as the server at `addr`. A transmit to an address
    /// with no server fails as unreachable.
    pub fn serve(&mut self, addr: IpAddr, engine: impl Engine + 'static) {
        self.servers.insert(
            addr,
            Server {
                engine: Box::new(engine),
                clock: Instant::ZERO,
            },
        );
    }

    /// Where the servers' lookups of other servers are answered, at once.
    /// Without it no lookup is answered, and each server's deadline
    /// decides.
    pub fn upstream(&mut self, upstream: impl FnMut(&Lookup) -> Looked + 'static) {
        self.upstream = Some(Box::new(upstream));
    }

    /// Loses every transmit `script` says to: no reply comes, so the
    /// sender times out. For tests that need a lossy network.
    pub fn lose(&mut self, script: impl FnMut(&Transmit) -> bool + 'static) {
        self.lose = Some(Box::new(script));
    }

    /// Every exchange carried so far, as a recording another run can play
    /// back.
    pub fn recording(&self) -> Recording {
        Recording::new(self.exchanges.clone())
    }

    /// What the server at `transmit`'s address replies, running its engine
    /// until it answers or has nothing left to wait for.
    fn deliver(&mut self, transmit: &Transmit, now: Instant, entropy: &dyn Entropy) -> Outcome {
        let Some(server) = self.servers.get_mut(&transmit.to.ip()) else {
            return Outcome::Unreachable;
        };
        server.clock = server.clock.max(now);
        let unspecified = match transmit.to {
            SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let client = Client {
            peer: SocketAddr::new(unspecified, 0),
            local: transmit.to,
            transport: transmit.transport,
            connection: None,
            sandbox: None,
        };
        let query = ClientQuery {
            client,
            bytes: transmit.bytes.clone(),
        };
        let mut inputs = vec![Input::Query(query)];
        loop {
            for input in inputs.drain(..) {
                server.engine.handle(input, server.clock, entropy);
            }
            while let Some(action) = server.engine.poll() {
                match action {
                    Action::Answer(Answer { bytes, .. }) => return Outcome::Reply(bytes),
                    Action::Lookup { token, lookup } => {
                        if let Some(upstream) = &mut self.upstream {
                            let looked = upstream(&lookup);
                            inputs.push(Input::Looked { token, looked });
                        }
                    }
                    Action::Send(_) | Action::Abandon(_) | Action::Event(_) => {}
                }
            }
            if !inputs.is_empty() {
                continue;
            }
            match server.engine.next_deadline() {
                Some(deadline) => {
                    server.clock = server.clock.max(deadline);
                    inputs.push(Input::Tick);
                }
                None => return Outcome::Timeout,
            }
        }
    }
}

impl Default for MemoryNet {
    fn default() -> MemoryNet {
        MemoryNet::new()
    }
}

impl Exchanges for MemoryNet {
    fn exchange(&mut self, transmit: &Transmit, now: Instant, entropy: &dyn Entropy) -> Vec<Input> {
        let lost = self.lose.as_mut().is_some_and(|lose| lose(transmit));
        let outcome = if lost {
            Outcome::Timeout
        } else {
            self.deliver(transmit, now, entropy)
        };
        self.exchanges.push(Exchange {
            server: transmit.to,
            transport: transmit.transport,
            query: transmit.bytes.clone(),
            outcome: outcome.clone(),
        });
        completion(transmit, outcome)
    }
}

/// Exchanges recorded from an earlier run, answered by server and
/// question.
///
/// A transmit is answered with the recorded reply to the same question
/// (name, ignoring case, type, and class) sent to the same server over
/// the same transport, decoded and written again with the transmit's ID
/// and question. A question it does not hold gets nothing, which the
/// engine sees as a timeout.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recording {
    exchanges: Vec<Exchange>,
}

impl Recording {
    /// A recording of `exchanges`.
    pub fn new(exchanges: Vec<Exchange>) -> Recording {
        Recording { exchanges }
    }

    /// The exchanges, in the order they were recorded.
    pub fn exchanges(&self) -> &[Exchange] {
        &self.exchanges
    }

    /// What the recording holds for `question` sent as `transmit`.
    fn find(&self, transmit: &Transmit, question: &Query) -> Option<&Outcome> {
        self.exchanges.iter().find_map(|exchange| {
            let same = exchange.server == transmit.to
                && exchange.transport == transmit.transport
                && question_of(&exchange.query).is_some_and(|asked| {
                    asked.name() == question.name()
                        && asked.query_type() == question.query_type()
                        && asked.query_class() == question.query_class()
                });
            same.then_some(&exchange.outcome)
        })
    }
}

impl Exchanges for Recording {
    fn exchange(
        &mut self,
        transmit: &Transmit,
        _now: Instant,
        _entropy: &dyn Entropy,
    ) -> Vec<Input> {
        let Parsed::Request(request) = Request::parse(&transmit.bytes, transmit.transport) else {
            return Vec::new();
        };
        let outcome = match self.find(transmit, &request.question) {
            None | Some(Outcome::Timeout) => return Vec::new(),
            Some(Outcome::Unreachable) => Outcome::Unreachable,
            Some(Outcome::Reply(reply)) => match answered(reply, &request) {
                Some(bytes) => Outcome::Reply(bytes),
                None => return Vec::new(),
            },
        };
        completion(transmit, outcome)
    }
}

/// `reply` written again with `request`'s ID and question, as the server
/// would have sent it to that request. `None` for a reply that does not
/// decode or write.
fn answered(reply: &[u8], request: &Request) -> Option<Vec<u8>> {
    let mut message = read_message(reply).ok()?;
    message.metadata.id = request.message.metadata.id;
    message.queries = vec![request.question.clone()];
    message.to_vec().ok()
}

fn question_of(query: &[u8]) -> Option<Query> {
    Message::from_vec(query).ok()?.queries.into_iter().next()
}

/// The input `outcome` gives the engine that sent `transmit`.
fn completion(transmit: &Transmit, outcome: Outcome) -> Vec<Input> {
    match outcome {
        Outcome::Reply(bytes) => vec![Input::Reply {
            token: transmit.token,
            from: transmit.to,
            transport: transmit.transport,
            bytes,
        }],
        Outcome::Unreachable => vec![Input::Failed {
            token: transmit.token,
            failure: ExchangeFailure::Unreachable,
        }],
        Outcome::Timeout => Vec::new(),
    }
}

/// Runs `engine` on `queries`, all sent at `start`, until it has nothing
/// left to wait for, advancing a virtual clock to each deadline it asks
/// for. Transmits go through `net` and come back at once. Returns the
/// answers in the order the engine gave them.
pub fn drive(
    engine: &mut impl Engine,
    net: &mut impl Exchanges,
    queries: Vec<ClientQuery>,
    start: Instant,
    entropy: &dyn Entropy,
) -> Vec<Answer> {
    let mut now = start;
    let mut inputs: Vec<Input> = queries.into_iter().map(Input::Query).collect();
    let mut answers = Vec::new();
    loop {
        for input in std::mem::take(&mut inputs) {
            engine.handle(input, now, entropy);
            while let Some(action) = engine.poll() {
                match action {
                    Action::Send(transmit) => {
                        inputs.extend(net.exchange(&transmit, now, entropy));
                    }
                    Action::Answer(answer) => answers.push(answer),
                    Action::Lookup { .. } | Action::Abandon(_) | Action::Event(_) => {}
                }
            }
        }
        if !inputs.is_empty() {
            continue;
        }
        match engine.next_deadline() {
            Some(deadline) => {
                now = now.max(deadline);
                inputs.push(Input::Tick);
            }
            None => return answers,
        }
    }
}
