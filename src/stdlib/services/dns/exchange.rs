//! What passes between a DNS engine and the code that drives it: client
//! queries and answers, the exchanges and lookups an engine starts with
//! other servers, and the tokens and generations that tie each completion
//! to the exchange and the session it belongs to.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use fictionet::Entropy;
use fictionet::stdlib::protocols::dns::op::{Message, MessageType, Query};
use fictionet::stdlib::protocols::dns::read_message;
use fictionet::stdlib::services::serve::{Sandbox, Transport};
use fictionet::time::Instant;

use super::clock::WallClock;
use super::event::{Event, Unmatched};
use super::lookup::{Looked, Lookup};

/// A session of a namespace. Generations only grow: a world advances its
/// namespace when a session changes, and the engines it drives follow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(pub u64);

/// Names one outstanding exchange. Engines issue tokens; drivers carry
/// them back unchanged with the exchange's completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Token {
    generation: Generation,
    exchange: u64,
}

impl Token {
    /// The generation the token was issued in.
    pub fn generation(&self) -> Generation {
        self.generation
    }
}

/// Issues an engine's tokens: each one new, each in the engine's current
/// generation.
#[derive(Clone, Debug)]
pub struct Tokens {
    generation: Generation,
    next: u64,
}

impl Tokens {
    /// Tokens in generation 0.
    pub fn new() -> Tokens {
        Tokens {
            generation: Generation(0),
            next: 0,
        }
    }

    /// A token this value has never issued, in the current generation.
    pub fn issue(&mut self) -> Token {
        let token = Token {
            generation: self.generation,
            exchange: self.next,
        };
        self.next += 1;
        token
    }

    /// The current generation.
    pub fn generation(&self) -> Generation {
        self.generation
    }

    /// Moves to `generation`, if it is above the current one. Returns
    /// whether it was. Exchange numbers keep counting, so no token repeats.
    pub fn advance(&mut self, generation: Generation) -> bool {
        let newer = generation > self.generation;
        if newer {
            self.generation = generation;
        }
        newer
    }
}

impl Default for Tokens {
    fn default() -> Tokens {
        Tokens::new()
    }
}

/// Bytes an engine wants carried to a server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmit {
    /// The exchange these bytes start.
    pub token: Token,
    /// The server.
    pub to: SocketAddr,
    /// How to carry them.
    pub transport: Transport,
    /// One DNS message.
    pub bytes: Vec<u8>,
}

/// Who asked: enough for a driver to send the answer back.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Client {
    /// The client's address.
    pub peer: SocketAddr,
    /// The server address the client asked.
    pub local: SocketAddr,
    /// How the query arrived. DNS over TLS and over HTTPS are streams, so
    /// they arrive as [`Transport::Tcp`].
    pub transport: Transport,
    /// The driver's number for the client's connection, for streams.
    pub connection: Option<u64>,
    /// The sandbox the client is, if it is one.
    pub sandbox: Option<Sandbox>,
}

/// One query from a client, as it arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientQuery {
    /// Who asked.
    pub client: Client,
    /// The query's octets.
    pub bytes: Vec<u8>,
}

/// One reply for a client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// Who it is for.
    pub client: Client,
    /// The reply's octets, within what the client's transport carries.
    pub bytes: Vec<u8>,
}

/// How an exchange failed without a reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExchangeFailure {
    /// The server's address could not be reached, such as by an ICMP
    /// unreachable or a family the machine has no route for.
    Unreachable,
    /// The server refused the connection, such as by a TCP reset.
    Refused,
    /// The connection closed before the reply came.
    Closed,
}

/// What a driver hands an engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Input {
    /// A query from a client.
    Query(ClientQuery),
    /// Bytes that came back for an exchange.
    Reply {
        /// The exchange's token, as the transmit carried it.
        token: Token,
        /// Where the bytes came from.
        from: SocketAddr,
        /// How they came.
        transport: Transport,
        /// One DNS message.
        bytes: Vec<u8>,
    },
    /// An exchange that ended without a reply.
    Failed {
        /// The exchange's token, as the transmit carried it.
        token: Token,
        /// How it ended.
        failure: ExchangeFailure,
    },
    /// What a lookup gave.
    Looked {
        /// The lookup's token, as [`Action::Lookup`] carried it.
        token: Token,
        /// What came of it.
        looked: Looked,
    },
    /// The client's connection is gone: drop what only it was waiting for.
    Gone(Client),
    /// `now` reached a deadline the engine asked for.
    Tick,
}

/// What an engine asks its driver to do, or tells it happened.
///
/// Actions and events leave through one queue, so a driver sees an event
/// before any action that follows it.
#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    /// Carry these bytes to a server.
    Send(Transmit),
    /// Put this lookup to the upstream, and hand back what it gave as
    /// [`Input::Looked`] with the token.
    Lookup {
        /// The lookup's token.
        token: Token,
        /// The lookup.
        lookup: Lookup,
    },
    /// Send this reply to a client.
    Answer(Answer),
    /// The engine no longer wants this exchange: stop carrying it. A
    /// completion that arrives anyway is ignored.
    Abandon(Token),
    /// Something the world may want to see.
    Event(Event),
}

/// What a reply must repeat of the query an engine sent, for item 4 of
/// the [`Engine`] contract.
pub(super) struct Sent<'a> {
    /// The server the query went to.
    pub(super) to: SocketAddr,
    /// How it went.
    pub(super) transport: Transport,
    /// The query's ID and question. `None` when the query did not decode,
    /// so no reply can match it.
    pub(super) asked: Option<(u16, &'a Query)>,
    /// Whether the QNAME must come back in the exact case it was sent, as
    /// when its case was randomised (draft-vixie-dnsext-dns0x20).
    pub(super) exact_case: bool,
}

/// The exchange `token` names among `exchanges`, if it is outstanding in
/// the current generation of `tokens`.
pub(super) fn outstanding<'a, X>(
    tokens: &Tokens,
    exchanges: &'a BTreeMap<Token, X>,
    token: Token,
) -> Result<&'a X, Unmatched> {
    if token.generation() < tokens.generation() {
        return Err(Unmatched::OldGeneration);
    }
    exchanges.get(&token).ok_or(Unmatched::NotOutstanding)
}

/// The reply `bytes`, if it answers the query `sent` describes: it came
/// from the server the query went to, over the same transport, and is a
/// response with the query's ID and its one question (RFC 5452 §9.1).
/// Otherwise why it does not, checked in that order.
pub(super) fn matching(
    sent: &Sent<'_>,
    from: SocketAddr,
    transport: Transport,
    bytes: &[u8],
) -> Result<Message, Unmatched> {
    if from != sent.to || transport != sent.transport {
        return Err(Unmatched::WrongPeer);
    }
    let reply = read_message(bytes).map_err(|_| Unmatched::Malformed)?;
    if reply.metadata.message_type != MessageType::Response {
        return Err(Unmatched::Malformed);
    }
    let Some((id, asked)) = sent.asked else {
        return Err(Unmatched::WrongQuestion);
    };
    if reply.metadata.id != id {
        return Err(Unmatched::WrongId);
    }
    let same = |got: &Query| {
        let name = if sent.exact_case {
            got.name().eq_case(asked.name())
        } else {
            got.name() == asked.name()
        };
        name && got.query_type() == asked.query_type() && got.query_class() == asked.query_class()
    };
    match reply.queries.as_slice() {
        [got] if same(got) => Ok(reply),
        _ => Err(Unmatched::WrongQuestion),
    }
}

/// The event for a completion that changed nothing, and why.
pub(super) fn ignored(
    at: Instant,
    token: Token,
    from: Option<SocketAddr>,
    why: Unmatched,
) -> Action {
    Action::Event(Event::Ignored {
        at,
        token,
        from,
        why,
    })
}

/// A session of a namespace: its generation and the wall clock its
/// signatures are checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Session {
    /// The session's generation.
    pub generation: Generation,
    /// The date the session's run stands for.
    pub clock: WallClock,
}

/// The shape every DNS engine has.
///
/// An engine keeps this contract, which `Exchanges.tla` models:
///
/// 1. No method blocks, reads a clock, touches a socket, or draws
///    randomness except from the `entropy` argument.
/// 2. Each `handle` call's `now` is at least the last one's. A driver calls
///    `handle(Input::Tick, now)` once `now` reaches [`next_deadline`].
/// 3. Every [`Action::Send`] and [`Action::Lookup`] carries a token the
///    engine never issued before, in its current generation.
/// 4. A completion changes state only if its token is outstanding and of
///    the current generation, it came from the transmit's address over its
///    transport, and the reply's ID and question are the query's
///    (RFC 5452 §9.1); for a lookup, only if a response's question is the
///    lookup's. Anything else changes nothing and emits
///    [`Event::Ignored`].
/// 5. [`advance`] to a newer generation makes every outstanding exchange
///    obsolete: the engine abandons each, drops what the old generation
///    learned, and restarts the client queries still waiting.
/// 6. Client queries that need the same work wait on it together, and
///    [`Input::Gone`] drops only the waits of that client.
/// 7. Every accepted query gets one answer, provided the driver keeps
///    delivering ticks, unless the engine stays silent on purpose, as a
///    server that never replies does.
/// 8. The actions are a function of the inputs, the `now` values, and the
///    entropy bytes.
///
/// [`next_deadline`]: Engine::next_deadline
/// [`advance`]: Engine::advance
pub trait Engine {
    /// Takes one input at `now`.
    fn handle(&mut self, input: Input, now: Instant, entropy: &dyn Entropy);
    /// The next action or event, in the order the engine queued them.
    fn poll(&mut self) -> Option<Action>;
    /// When the engine next needs [`Input::Tick`], if ever.
    fn next_deadline(&self) -> Option<Instant>;
    /// Starts a new session, if `session` is newer than the current one:
    /// no exchange started before may change state after.
    fn advance(&mut self, session: Session);
    /// The current generation.
    fn generation(&self) -> Generation;
}
