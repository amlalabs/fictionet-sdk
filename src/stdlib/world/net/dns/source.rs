//! Where a server's own questions go, and the session a world's DNS
//! programs answer for.

use std::collections::HashMap;
use std::future::{Future, ready};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use fictionet::Cx;
use fictionet::stdlib::protocols::dns::op::Message;
use fictionet::stdlib::protocols::dns::rr::{DNSClass, LowerName, RecordType};
use fictionet::stdlib::protocols::dns::{Parsed, Request, restore};
use fictionet::stdlib::services::dns::authority::{Ask, Observed};
use fictionet::stdlib::services::dns::{Generation, Session, WallClock};
use fictionet::stdlib::services::serve::Transport;
use fictionet::sync::Mutex;
use fictionet::time::Instant;

/// What a real client sees when it sends a server a question: the answers
/// a world writes itself, recorded exchanges, or the internet's.
///
/// [`Authoritative`](super::Authoritative) sends its authority's own
/// questions here, such as a relay's question to the real server at its
/// address. This is the one asynchronous step of serving DNS, at the edge,
/// outside the engines.
///
/// A source decides nothing about what may be asked: the agent in a
/// sandbox chooses the names it asks about, and a question that reaches a
/// real server is a channel out to whoever runs it. A world puts its
/// policy in front with [`Only`].
pub trait Source: Send + Sync + 'static {
    /// What a client of `ask.server` sees when it sends `ask.query`: the
    /// reply as it arrived, an unreachable server, or nothing in time. The
    /// future may finish on a host thread that waits for the internet;
    /// only its waker crosses back.
    fn ask<'a>(
        &'a self,
        fcx: &'a Cx,
        ask: Ask,
    ) -> Pin<Box<dyn Future<Output = Observed> + Send + 'a>>;
}

impl<S: Source + ?Sized> Source for Arc<S> {
    fn ask<'a>(
        &'a self,
        fcx: &'a Cx,
        ask: Ask,
    ) -> Pin<Box<dyn Future<Output = Observed> + Send + 'a>> {
        (**self).ask(fcx, ask)
    }
}

/// A source that asks only the questions `policy` allows, and gives
/// [`Observed::Timeout`] for the rest without asking, as a server that
/// never replies.
///
/// The policy sees every question: those for the root, top-level
/// domains, and `arpa`, the lookups of name servers' addresses, the
/// targets of aliases, and the DS and DNSKEY sets of a chain of trust
/// alike. No kind of question passes by itself, since a guest can put any
/// name it likes to an authority, and every label of a minimised question
/// is still a name the guest chose.
pub struct Only<S, P> {
    policy: P,
    source: S,
}

impl<S: Source, P: Fn(&Ask) -> bool + Send + Sync + 'static> Only<S, P> {
    /// `source`, asked only what `policy` allows.
    pub fn new(policy: P, source: S) -> Only<S, P> {
        Only { policy, source }
    }
}

impl<S: Source, P: Fn(&Ask) -> bool + Send + Sync + 'static> Source for Only<S, P> {
    fn ask<'a>(
        &'a self,
        fcx: &'a Cx,
        ask: Ask,
    ) -> Pin<Box<dyn Future<Output = Observed> + Send + 'a>> {
        if (self.policy)(&ask) {
            self.source.ask(fcx, ask)
        } else {
            Box::pin(ready(Observed::Timeout))
        }
    }
}

/// What makes two queries one question for a source that answers from
/// replies it holds: the name, ignoring case, the type, the class, and
/// what the reply must carry because of the query's EDNS. A query with an
/// OPT record gets one back and a query without gets none (RFC 6891 §7),
/// and only DO brings DNSSEC records (RFC 3225 §3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Question {
    /// The name, in lowercase.
    pub name: LowerName,
    /// The type.
    pub qtype: RecordType,
    /// The class.
    pub qclass: DNSClass,
    /// Whether the query had an OPT record.
    pub edns: bool,
    /// Whether it set DO.
    pub dnssec_ok: bool,
}

impl Question {
    /// The question `request` asks.
    pub fn of(request: &Request) -> Question {
        Question {
            name: LowerName::new(request.question.name()),
            qtype: request.question.query_type(),
            qclass: request.question.query_class(),
            edns: request.edns.is_some(),
            dnssec_ok: request.edns.is_some_and(|edns| edns.dnssec_ok),
        }
    }
}

/// A source that keeps each reply for the smallest TTL among its records,
/// and answers the same question to the same server from it until then,
/// with the asker's ID and question case put back
/// ([`restore`]).
///
/// Two asks are the same when they are the same [`Question`] with the
/// same RD and CD bits, sent to the same server over the same transport.
/// A reply with no records, or one truncated (RFC 2181 §9), is not kept.
/// A kept reply goes out as it arrived, its TTLs as they were, and the
/// server's engine fits it to each asker's size. The resolvers of a world
/// already cache, so a world adds this only when the same question
/// reaches its source from many of them.
pub struct Cached<S> {
    source: S,
    replies: Mutex<HashMap<Kept, (Vec<u8>, Instant)>>,
}

/// What makes two asks the same for [`Cached`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Kept {
    server: SocketAddr,
    transport: Transport,
    question: Question,
    rd: bool,
    cd: bool,
}

impl<S: Source> Cached<S> {
    /// `source`, with its replies kept.
    pub fn new(source: S) -> Cached<S> {
        Cached {
            source,
            replies: Mutex::new(HashMap::new()),
        }
    }
}

impl<S: Source> Source for Cached<S> {
    fn ask<'a>(
        &'a self,
        fcx: &'a Cx,
        ask: Ask,
    ) -> Pin<Box<dyn Future<Output = Observed> + Send + 'a>> {
        Box::pin(async move {
            let Parsed::Request(request) = Request::parse(&ask.query, ask.transport) else {
                return self.source.ask(fcx, ask).await;
            };
            let question = Kept {
                server: ask.server,
                transport: ask.transport,
                question: Question::of(&request),
                rd: request.rd,
                cd: request.cd,
            };
            let now = fcx.now();
            {
                let mut replies = self.replies.lock();
                match replies.get(&question) {
                    Some((reply, until)) if *until > now => {
                        if let Ok(bytes) = restore(reply, &request) {
                            return Observed::Reply(bytes);
                        }
                    }
                    Some(_) => {
                        replies.remove(&question);
                    }
                    None => {}
                }
            }
            let observed = self.source.ask(fcx, ask).await;
            if let Observed::Reply(bytes) = &observed
                && let Some(ttl) = smallest_ttl(bytes)
                && ttl > 0
            {
                let until = now + Duration::from_secs(u64::from(ttl));
                self.replies.lock().insert(question, (bytes.clone(), until));
            }
            observed
        })
    }
}

/// The smallest TTL among a reply's records, other than its OPT record.
/// `None` for a reply that does not parse, is truncated, or has no
/// records.
fn smallest_ttl(reply: &[u8]) -> Option<u32> {
    let message = Message::from_vec(reply).ok()?;
    if message.metadata.truncation {
        return None;
    }
    message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals)
        .map(|record| record.ttl)
        .min()
}

/// The session a world's DNS programs answer for: a generation that only
/// grows, and the date its signatures are checked against.
///
/// A world advances it when its session changes, such as when a run
/// switches from live pages to a capture. Every program given the
/// namespace moves to the new session before its next input: each
/// engine abandons what it was waiting for, a resolver empties its cache
/// and starts the queries still waiting again, and nothing that completes
/// for the old session can change the new one. Guests keep their own
/// caches until the TTLs run out; a session change cannot reach them.
#[derive(Clone)]
pub struct Namespace {
    session: Arc<Mutex<Session>>,
}

impl Namespace {
    /// A namespace in generation 0, whose dates come from `clock`.
    pub fn new(clock: WallClock) -> Namespace {
        Namespace {
            session: Arc::new(Mutex::new(Session {
                generation: Generation(0),
                clock,
            })),
        }
    }

    /// Starts a new session whose dates come from `clock`, and returns it.
    pub fn advance(&self, clock: WallClock) -> Session {
        let mut session = self.session.lock();
        *session = Session {
            generation: Generation(session.generation.0 + 1),
            clock,
        };
        *session
    }

    /// The current session.
    pub fn current(&self) -> Session {
        *self.session.lock()
    }
}

/// State that belongs to one session, such as what relayed replies named
/// in it: it starts afresh when a later session uses it, so nothing one
/// session learned reaches the next.
pub struct PerSession<T> {
    state: Mutex<(Generation, T)>,
}

impl<T: Default> PerSession<T> {
    /// Fresh state for generation 0.
    pub fn new() -> PerSession<T> {
        PerSession {
            state: Mutex::new((Generation(0), T::default())),
        }
    }

    /// `f` with the state of session `generation`, made afresh first when
    /// the state belongs to an earlier session.
    pub fn with<R>(&self, generation: Generation, f: impl FnOnce(&mut T) -> R) -> R {
        let mut state = self.state.lock();
        if state.0 != generation {
            *state = (generation, T::default());
        }
        f(&mut state.1)
    }
}

impl<T: Default> Default for PerSession<T> {
    fn default() -> PerSession<T> {
        PerSession::new()
    }
}
