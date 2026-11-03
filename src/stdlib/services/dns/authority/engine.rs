//! The engine that runs one authoritative server: it parses queries, asks
//! the authority, has the authority's lookups made and filed, and puts
//! every reply through the server front.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;

use fictionet::Entropy;
use fictionet::stdlib::protocols::dns::dnssec::Validation;
use fictionet::stdlib::protocols::dns::op::ResponseCode;
use fictionet::stdlib::protocols::dns::read_message;
use fictionet::stdlib::protocols::dns::rr::{DNSClass, RecordType};
use fictionet::stdlib::protocols::dns::{Ede, EdeCode, Parsed, Request};
use fictionet::time::Instant;

use super::super::event::{Event, LookupOutcome, QueryFlags, ReplyFlags, Unmatched};
use super::super::exchange::{
    Action, Answer, Client, ClientQuery, Engine, Generation, Input, Session, Token, Tokens,
    ignored, outstanding,
};
use super::super::lookup::{Looked, Lookup};
use super::super::records::rrsets;
use super::{Authority, ServerConfig, Step, bare_reply};

/// Runs the authoritative server at one address.
///
/// For each client query the engine:
///
/// 1. Parses it with [`Request::parse`]. Bytes that get no reply get
///    none; a rejected query gets the rejection.
/// 2. Queues [`Event::Query`].
/// 3. Answers REFUSED to a zone transfer when the server does not offer
///    them, whatever its class (RFC 5936 §2.2), and to a class other than
///    IN, CH, and ANY. Answers another CHAOS-class question from the
///    server's [`identity`](ServerConfig::identity), or from the
///    authority when the server has none.
/// 4. Asks the authority. For [`Step::Need`] it queues [`Action::Lookup`]
///    under a fresh token and waits up to
///    [`ask_timeout`](ServerConfig::ask_timeout). When the lookup ends, it
///    has the authority [file](Authority::file) what came of it, queues
///    [`Event::Looked`], and asks the authority again. Requests that need
///    the same lookup wait on one. A request that needs a lookup it
///    already made gets no reply: what the upstream gave did not settle
///    the fact, or the upstream gave nothing, and the server stays silent
///    as a server that cannot answer does.
/// 5. Sends the reply through the server front and [`fit`](fictionet::stdlib::protocols::dns::fit),
///    after [`Event::Reply`].
///
/// The engine keeps the contract of [`Engine`]. What a lookup gave counts
/// only when its token is outstanding and current, and a response only
/// when its question is the lookup's.
pub struct AuthorityEngine<A: Authority> {
    authority: A,
    server: ServerConfig,
    local: SocketAddr,
    tokens: Tokens,
    lookups: BTreeMap<Token, Pending>,
    queue: VecDeque<Action>,
    now: Instant,
}

/// One lookup the engine is waiting on, and the requests waiting on it.
struct Pending {
    lookup: Lookup,
    deadline: Instant,
    waiters: Vec<Waiter>,
}

/// A request waiting for a lookup.
struct Waiter {
    request: Request,
    client: Client,
    /// The lookups made for this request so far.
    looked: Vec<Lookup>,
}

impl<A: Authority> AuthorityEngine<A> {
    /// The server at `local`, answering with `authority` behind the front
    /// of `server`, in generation 0.
    pub fn new(authority: A, server: ServerConfig, local: SocketAddr) -> AuthorityEngine<A> {
        AuthorityEngine {
            authority,
            server,
            local,
            tokens: Tokens::new(),
            lookups: BTreeMap::new(),
            queue: VecDeque::new(),
            now: Instant::ZERO,
        }
    }

    fn query(&mut self, query: ClientQuery) {
        let ClientQuery { client, bytes } = query;
        let req = match Request::parse(&bytes, client.transport) {
            Parsed::Silent => return,
            Parsed::Reject(reject) => {
                let bytes = self.server.render_reject(reject, client.transport);
                return self.answer(client, bytes);
            }
            Parsed::Request(req) => req,
        };
        self.queue.push_back(Action::Event(Event::Query {
            at: self.now,
            server: self.local,
            client: client.clone(),
            question: req.question.clone(),
            flags: QueryFlags {
                rd: req.rd,
                cd: req.cd,
                ad: req.ad,
            },
            edns: req.edns,
        }));

        let transfer = matches!(
            req.question.query_type(),
            RecordType::AXFR | RecordType::IXFR
        );
        let response = match req.question.query_class() {
            DNSClass::IN | DNSClass::ANY | DNSClass::CH if transfer && !self.server.transfer => {
                Some(bare_reply(&req, ResponseCode::Refused, None))
            }
            DNSClass::CH => match self.server.render_chaos(&req) {
                Some(bytes) => return self.answer(client, bytes),
                None => None,
            },
            DNSClass::IN | DNSClass::ANY => None,
            _ => {
                let ede = self.server.ede.then_some(EdeCode::NOT_AUTHORITATIVE);
                Some(bare_reply(&req, ResponseCode::Refused, ede))
            }
        };
        match response {
            Some(response) => {
                let bytes = self.server.render(&req, response);
                self.answer(client, bytes);
            }
            None => self.step(Waiter {
                request: req,
                client,
                looked: Vec::new(),
            }),
        }
    }

    /// Asks the authority about `waiter`'s request and acts on its step.
    fn step(&mut self, waiter: Waiter) {
        let step =
            self.authority
                .respond(&waiter.request, self.local, &self.server, &waiter.client);
        match step {
            Step::Reply(response) => {
                let bytes = self.server.render(&waiter.request, response);
                self.answer(waiter.client, bytes);
            }
            // The lookup already gave what it could, and the fact is still
            // not held: the server cannot answer without guessing.
            Step::Need(lookup) if waiter.looked.contains(&lookup) => {}
            Step::Need(lookup) => self.park(lookup, waiter),
            Step::Silent => {}
        }
    }

    /// Makes `waiter` wait for `lookup`: on the lookup already pending, or
    /// on a new one.
    fn park(&mut self, lookup: Lookup, waiter: Waiter) {
        if let Some(pending) = self.lookups.values_mut().find(|p| p.lookup == lookup) {
            pending.waiters.push(waiter);
            return;
        }
        let token = self.tokens.issue();
        self.queue.push_back(Action::Lookup {
            token,
            lookup: lookup.clone(),
        });
        self.lookups.insert(
            token,
            Pending {
                lookup,
                deadline: self.now + self.server.ask_timeout,
                waiters: vec![waiter],
            },
        );
    }

    /// Why `looked` does not end `token`'s lookup, if it does not.
    fn unmatched(&self, token: Token, looked: &Looked) -> Option<Unmatched> {
        let pending = match outstanding(&self.tokens, &self.lookups, token) {
            Ok(pending) => pending,
            Err(why) => return Some(why),
        };
        match looked {
            Looked::Response(response) if !pending.lookup.answered_by(response) => {
                Some(Unmatched::WrongQuestion)
            }
            Looked::Response(_) | Looked::Unreachable | Looked::NoReply => None,
        }
    }

    fn ignore(&mut self, token: Token, from: Option<SocketAddr>, why: Unmatched) {
        self.queue.push_back(ignored(self.now, token, from, why));
    }

    /// Ends `token`'s lookup with `looked`: has the authority file it,
    /// then asks the authority again for each request that waited on it.
    fn complete(&mut self, token: Token, looked: Looked) {
        let Some(pending) = self.lookups.remove(&token) else {
            return;
        };
        self.authority
            .file(&pending.lookup, &looked, token.generation());
        let outcome = match &looked {
            Looked::Response(response) => LookupOutcome::Response {
                rcode: response.metadata.response_code,
            },
            Looked::Unreachable => LookupOutcome::Unreachable,
            Looked::NoReply => LookupOutcome::NoReply,
        };
        self.queue.push_back(Action::Event(Event::Looked {
            at: self.now,
            lookup: pending.lookup.clone(),
            outcome,
        }));
        for mut waiter in pending.waiters {
            waiter.looked.push(pending.lookup.clone());
            self.step(waiter);
        }
    }

    /// Queues [`Event::Reply`] and the answer `bytes` for `client`.
    fn answer(&mut self, client: Client, bytes: Vec<u8>) {
        let event = reply_event(self.now, self.local, client.clone(), &bytes);
        self.queue.push_back(Action::Event(event));
        self.queue
            .push_back(Action::Answer(Answer { client, bytes }));
    }
}

impl<A: Authority> Engine for AuthorityEngine<A> {
    fn handle(&mut self, input: Input, now: Instant, _entropy: &dyn Entropy) {
        self.now = now;
        match input {
            Input::Query(query) => self.query(query),
            Input::Looked { token, looked } => match self.unmatched(token, &looked) {
                None => self.complete(token, looked),
                Some(why) => self.ignore(token, None, why),
            },
            // The engine starts no exchanges of bytes, so no token of one
            // is its own.
            Input::Reply { token, from, .. } => {
                let why = outstanding(&self.tokens, &self.lookups, token)
                    .err()
                    .unwrap_or(Unmatched::NotOutstanding);
                self.ignore(token, Some(from), why);
            }
            Input::Failed { token, .. } => {
                let why = outstanding(&self.tokens, &self.lookups, token)
                    .err()
                    .unwrap_or(Unmatched::NotOutstanding);
                self.ignore(token, None, why);
            }
            Input::Gone(client) => {
                let mut emptied = Vec::new();
                for (token, pending) in &mut self.lookups {
                    pending.waiters.retain(|waiter| waiter.client != client);
                    if pending.waiters.is_empty() {
                        emptied.push(*token);
                    }
                }
                for token in emptied {
                    self.lookups.remove(&token);
                    self.queue.push_back(Action::Abandon(token));
                }
            }
            Input::Tick => {
                let expired: Vec<Token> = self
                    .lookups
                    .iter()
                    .filter(|(_, pending)| pending.deadline <= now)
                    .map(|(token, _)| *token)
                    .collect();
                for token in expired {
                    self.queue.push_back(Action::Abandon(token));
                    self.complete(token, Looked::NoReply);
                }
            }
        }
    }

    fn poll(&mut self) -> Option<Action> {
        self.queue.pop_front()
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.lookups.values().map(|pending| pending.deadline).min()
    }

    /// Starts the authority's new session, so its learned zones drop what
    /// they learned; abandons every pending lookup; and asks the authority
    /// again, with no lookups made, for each request that waited, so it
    /// is answered from the new session. The deadlines of the lookups this
    /// starts count from the time of the last input. An authoritative
    /// server checks no signatures, so the session's clock changes nothing
    /// here.
    fn advance(&mut self, session: Session) {
        if !self.tokens.advance(session.generation) {
            return;
        }
        self.authority.advance(session.generation);
        let lookups = std::mem::take(&mut self.lookups);
        for token in lookups.keys() {
            self.queue.push_back(Action::Abandon(*token));
        }
        for pending in lookups.into_values() {
            for waiter in pending.waiters {
                self.step(Waiter {
                    looked: Vec::new(),
                    ..waiter
                });
            }
        }
    }

    fn generation(&self) -> Generation {
        self.tokens.generation()
    }
}

/// The event for a reply of `bytes` sent to `client`.
fn reply_event(at: Instant, server: SocketAddr, client: Client, bytes: &[u8]) -> Event {
    let size = u16::try_from(bytes.len()).expect("a reply fits a DNS message's 65535 octets");
    let message = read_message(bytes).expect("every reply the engine sends decodes");
    let ede = message.edns.as_ref().and_then(|edns| {
        edns.options()
            .as_ref()
            .iter()
            .find_map(|(_, option)| Ede::from_option(option))
            .map(|ede| ede.code)
    });
    Event::Reply {
        at,
        server,
        client,
        question: message.queries.first().cloned(),
        rcode: message.metadata.response_code,
        flags: ReplyFlags::of(&message.metadata),
        answers: rrsets(&message.answers),
        validation: Validation::NotPerformed,
        ede,
        cached: false,
        size,
    }
}
