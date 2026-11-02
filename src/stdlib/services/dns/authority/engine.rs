//! The engine that runs one authoritative server: it parses queries, asks
//! the authority, carries the authority's own questions, and puts every
//! reply through the server front.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;

use fictionet::Entropy;
use fictionet::stdlib::protocols::dns::dnssec::Validation;
use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
use fictionet::stdlib::protocols::dns::op::{Header, Message, MessageType, Query, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::RData;
use fictionet::stdlib::protocols::dns::rr::{DNSClass, Record, RecordSet, RecordType};
use fictionet::stdlib::protocols::dns::serialize::binary::{BinDecodable, BinDecoder};
use fictionet::stdlib::protocols::dns::{Ede, EdeCode, Parsed, Request};
use fictionet::stdlib::services::serve::Transport;
use fictionet::time::Instant;

use super::super::event::{Event, ObservedKind, QueryFlags, ReplyFlags, Unmatched};
use super::super::exchange::{
    Action, Answer, Client, ClientQuery, Engine, ExchangeFailure, Generation, Input, Session,
    Token, Tokens, Transmit,
};
use super::{Ask, Authority, Known, Observed, ServerConfig, Step, bare_reply};

/// Runs the authoritative server at one address.
///
/// For each client query the engine:
///
/// 1. Parses it with [`Request::parse`]. Bytes that get no reply get
///    none; a rejected query gets the rejection.
/// 2. Queues [`Event::Query`].
/// 3. Answers a CHAOS-class question from the server's
///    [`identity`](ServerConfig::identity), or from the authority when
///    the server has none. A class other than IN, CH, and ANY gets
///    REFUSED, and so does a zone transfer when the server does not
///    offer them.
/// 4. Asks the authority. For [`Step::Need`] it sends the question under a
///    fresh token, waits up to [`ask_timeout`](ServerConfig::ask_timeout),
///    records what came of it, and asks the authority again. Requests
///    that need the same question wait on one exchange.
/// 5. Sends the reply through the server front and [`fit`](fictionet::stdlib::protocols::dns::fit),
///    or a verbatim reply as it is, after [`Event::Reply`].
///
/// The engine keeps the contract of [`Engine`]. A reply to an exchange
/// counts only when its token is outstanding and current, it came from
/// the address and over the transport the question went to, and its ID
/// and question are the question's.
pub struct AuthorityEngine<A: Authority> {
    authority: A,
    server: ServerConfig,
    local: SocketAddr,
    tokens: Tokens,
    exchanges: BTreeMap<Token, Exchange>,
    queue: VecDeque<Action>,
    now: Instant,
}

/// One question the engine asked another server, and the requests waiting
/// on it.
struct Exchange {
    ask: Ask,
    /// The ID and question of the ask's query, which a reply must repeat.
    /// `None` when the authority's query does not decode, so no reply can
    /// match.
    asked: Option<(u16, Query)>,
    deadline: Instant,
    waiters: Vec<Waiter>,
}

/// A request waiting for an exchange.
struct Waiter {
    request: Request,
    client: Client,
    known: Observations,
}

/// What one request's asks gave so far.
#[derive(Default)]
struct Observations(Vec<(Ask, Observed)>);

impl Known for Observations {
    fn get(&self, ask: &Ask) -> Option<&Observed> {
        self.0
            .iter()
            .find(|(asked, _)| asked == ask)
            .map(|(_, observed)| observed)
    }
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
            exchanges: BTreeMap::new(),
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
            DNSClass::CH => self.server.chaos(&req),
            DNSClass::IN | DNSClass::ANY if transfer && !self.server.transfer => {
                Some(bare_reply(&req, ResponseCode::Refused, None))
            }
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
                known: Observations::default(),
            }),
        }
    }

    /// Asks the authority about `waiter`'s request and acts on its step.
    fn step(&mut self, waiter: Waiter) {
        let step = self.authority.respond(
            &waiter.request,
            self.local,
            &self.server,
            &waiter.client,
            &waiter.known,
        );
        let Waiter {
            request,
            client,
            known,
        } = waiter;
        let bytes = match step {
            Step::Reply(response) => self.server.render(&request, response),
            Step::Verbatim(bytes) => match self.server.verbatim(&request, bytes) {
                Some(bytes) => bytes,
                None => self.server_failure(&request),
            },
            // An authority that asks again for what it knows would never
            // finish, so the request fails instead.
            Step::Need(ask) if known.get(&ask).is_some() => self.server_failure(&request),
            Step::Need(ask) => {
                return self.park(
                    ask,
                    Waiter {
                        request,
                        client,
                        known,
                    },
                );
            }
            Step::Silent => return,
        };
        self.answer(client, bytes);
    }

    fn server_failure(&self, request: &Request) -> Vec<u8> {
        self.server
            .render(request, bare_reply(request, ResponseCode::ServFail, None))
    }

    /// Makes `waiter` wait for `ask`: on the exchange already asking it,
    /// or on a new one.
    fn park(&mut self, ask: Ask, waiter: Waiter) {
        if let Some(exchange) = self.exchanges.values_mut().find(|ex| ex.ask == ask) {
            exchange.waiters.push(waiter);
            return;
        }
        let token = self.tokens.issue();
        let asked = Message::from_vec(&ask.query)
            .ok()
            .and_then(|query| Some((query.metadata.id, query.queries.first()?.clone())));
        self.queue.push_back(Action::Send(Transmit {
            token,
            to: ask.server,
            transport: ask.transport,
            bytes: ask.query.clone(),
        }));
        self.exchanges.insert(
            token,
            Exchange {
                ask,
                asked,
                deadline: self.now + self.server.ask_timeout,
                waiters: vec![waiter],
            },
        );
    }

    /// The exchange `token` names, if it is outstanding in the current
    /// generation.
    fn outstanding(&self, token: Token) -> Result<&Exchange, Unmatched> {
        if token.generation() < self.tokens.generation() {
            return Err(Unmatched::OldGeneration);
        }
        self.exchanges.get(&token).ok_or(Unmatched::NotOutstanding)
    }

    /// The RCODE of a reply that answers `token`'s exchange, or why it
    /// does not (RFC 5452 §9.1).
    fn matching(
        &self,
        token: Token,
        from: SocketAddr,
        transport: Transport,
        bytes: &[u8],
    ) -> Result<ResponseCode, Unmatched> {
        let exchange = self.outstanding(token)?;
        if from != exchange.ask.server || transport != exchange.ask.transport {
            return Err(Unmatched::WrongPeer);
        }
        let reply = Message::from_vec(bytes).map_err(|_| Unmatched::Malformed)?;
        if reply.metadata.message_type != MessageType::Response {
            return Err(Unmatched::Malformed);
        }
        let Some((id, question)) = &exchange.asked else {
            return Err(Unmatched::WrongQuestion);
        };
        if reply.metadata.id != *id {
            return Err(Unmatched::WrongId);
        }
        let same = |asked: &Query| {
            asked.name() == question.name()
                && asked.query_type() == question.query_type()
                && asked.query_class() == question.query_class()
        };
        match reply.queries.as_slice() {
            [asked] if same(asked) => Ok(reply.metadata.response_code),
            _ => Err(Unmatched::WrongQuestion),
        }
    }

    fn ignore(&mut self, token: Token, from: Option<SocketAddr>, why: Unmatched) {
        self.queue.push_back(Action::Event(Event::Ignored {
            at: self.now,
            token,
            from,
            why,
        }));
    }

    /// Ends `token`'s exchange with `observed`, and asks the authority
    /// again for each request that waited on it.
    fn complete(&mut self, token: Token, observed: Observed, kind: ObservedKind) {
        let Some(exchange) = self.exchanges.remove(&token) else {
            return;
        };
        self.queue.push_back(Action::Event(Event::Asked {
            at: self.now,
            ask: exchange.ask.clone(),
            observed: kind,
        }));
        for mut waiter in exchange.waiters {
            waiter
                .known
                .0
                .push((exchange.ask.clone(), observed.clone()));
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
            Input::Reply {
                token,
                from,
                transport,
                bytes,
            } => match self.matching(token, from, transport, &bytes) {
                Ok(rcode) => {
                    let kind = ObservedKind::Reply { rcode };
                    self.complete(token, Observed::Reply(bytes), kind);
                }
                Err(why) => self.ignore(token, Some(from), why),
            },
            Input::Failed { token, failure } => match self.outstanding(token) {
                Ok(_) => {
                    // A server that cannot be reached, refuses the
                    // connection, or closes it unanswered is, to a client,
                    // a server it cannot reach.
                    let (observed, kind) = match failure {
                        ExchangeFailure::Unreachable
                        | ExchangeFailure::Refused
                        | ExchangeFailure::Closed => {
                            (Observed::Unreachable, ObservedKind::Unreachable)
                        }
                    };
                    self.complete(token, observed, kind);
                }
                Err(why) => self.ignore(token, None, why),
            },
            Input::Gone(client) => {
                let mut emptied = Vec::new();
                for (token, exchange) in &mut self.exchanges {
                    exchange.waiters.retain(|waiter| waiter.client != client);
                    if exchange.waiters.is_empty() {
                        emptied.push(*token);
                    }
                }
                for token in emptied {
                    self.exchanges.remove(&token);
                    self.queue.push_back(Action::Abandon(token));
                }
            }
            Input::Tick => {
                let expired: Vec<Token> = self
                    .exchanges
                    .iter()
                    .filter(|(_, exchange)| exchange.deadline <= now)
                    .map(|(token, _)| *token)
                    .collect();
                for token in expired {
                    self.queue.push_back(Action::Abandon(token));
                    self.complete(token, Observed::Timeout, ObservedKind::Timeout);
                }
            }
        }
    }

    fn poll(&mut self) -> Option<Action> {
        self.queue.pop_front()
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.exchanges
            .values()
            .map(|exchange| exchange.deadline)
            .min()
    }

    /// Abandons every outstanding exchange and asks the authority again,
    /// knowing nothing, for each request that waited, so it is answered
    /// from the new session. The deadlines of the exchanges this starts
    /// count from the time of the last input. An authoritative server
    /// checks no signatures, so the session's clock changes nothing here.
    fn advance(&mut self, session: Session) {
        if !self.tokens.advance(session.generation) {
            return;
        }
        let exchanges = std::mem::take(&mut self.exchanges);
        for token in exchanges.keys() {
            self.queue.push_back(Action::Abandon(*token));
        }
        for exchange in exchanges.into_values() {
            for waiter in exchange.waiters {
                self.step(Waiter {
                    known: Observations::default(),
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
    let (question, rcode, flags, answers, ede) = match Message::from_vec(bytes) {
        Ok(message) => {
            let ede = message.edns.as_ref().and_then(|edns| {
                edns.options()
                    .as_ref()
                    .iter()
                    .find_map(|(_, option)| Ede::from_option(option))
                    .map(|ede| ede.code)
            });
            (
                message.queries.first().cloned(),
                message.metadata.response_code,
                ReplyFlags::of(&message.metadata),
                rrsets(&message.answers),
                ede,
            )
        }
        // A verbatim reply hickory cannot decode still has a header.
        Err(_) => {
            let header = Header::read(&mut BinDecoder::new(bytes))
                .expect("every reply the engine sends has a header");
            (
                None,
                header.metadata.response_code,
                ReplyFlags::of(&header.metadata),
                Vec::new(),
                None,
            )
        }
    };
    Event::Reply {
        at,
        server,
        client,
        question,
        rcode,
        flags,
        answers,
        validation: Validation::NotPerformed,
        ede,
        cached: false,
        size,
    }
}

/// `records` gathered into RRsets in order of first appearance, each
/// RRSIG with the RRset it covers.
fn rrsets(records: &[Record]) -> Vec<RecordSet> {
    let mut sets: Vec<RecordSet> = Vec::new();
    for record in records {
        let covered = match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => Some(rrsig.input().type_covered),
            _ => None,
        };
        let rtype = covered.unwrap_or(record.record_type());
        let index = sets.iter().position(|set| {
            set.name() == &record.name
                && set.record_type() == rtype
                && set.dns_class() == record.dns_class
        });
        let index = index.unwrap_or_else(|| {
            let mut set = RecordSet::with_ttl(record.name.clone(), rtype, record.ttl);
            set.set_dns_class(record.dns_class);
            sets.push(set);
            sets.len() - 1
        });
        match covered {
            Some(_) => sets[index].insert_rrsig(record.clone()),
            None => {
                sets[index].insert(record.clone(), 0);
            }
        }
    }
    sets
}
