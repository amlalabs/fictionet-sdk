//! The recursive resolver: answers clients from its local zones, its
//! cache, and the authoritative servers it asks, and validates what it
//! learns.
//!
//! [`Resolver`] is an [`Engine`]: a driver hands it client queries,
//! replies, and ticks, and carries out the exchanges it asks for. How the
//! queries travel is the driver's business, so the same engine resolves
//! through zones in memory ([`memory`](super::memory)), through packets in
//! a world's network, or through recorded exchanges.
//!
//! For each client query the resolver:
//!
//! 1. Parses it with [`Request::parse`] and queues [`Event::Query`].
//! 2. Answers a CHAOS-class question from its
//!    [`identity`](Config::identity).
//! 3. Asks its local zones that hold QNAME, deepest first and at equal
//!    depth the one added last. The first that knows the answer gives it;
//!    a zone that does not know passes the question on.
//! 4. Answers from its cache, or starts or joins a resolution: the
//!    iteration of RFC 1034 §5.3.3 from the root servers down, following
//!    aliases, looking up name servers that came without glue, and
//!    fetching the DS and DNSKEY sets that validation needs.
//! 5. Renders the answer for this client: its ID, flags, EDNS, question
//!    case, and TTLs counted down.
//!
//! The standards it follows:
//!
//! | RFC | What it sets here |
//! | --- | --- |
//! | RFC 1034 §5.3.3 | Iteration, and a bound on the work one question costs |
//! | RFC 1035 §7.4, RFC 2181 §5, §8, §9 | What is cached, at which TTL, and never from truncated replies |
//! | RFC 2181 §5.4.1 | Ranks; glue and referral data never answer a client |
//! | RFC 2308 | Negative answers cached with their SOA, TTLs counted down |
//! | RFC 4035 §3.2, §4, §5; RFC 6840 §5 | Validation, DO and CD upstream, AD and CD toward clients |
//! | RFC 5452 §9 | Random IDs; replies accepted only from the address asked with the ID and question sent |
//! | RFC 6891 | EDNS toward servers and clients |
//! | RFC 7766 | TCP after a truncated reply |
//! | RFC 8020 | Nothing exists below a cached Secure NXDOMAIN |
//! | RFC 8109 | Priming from root hints |
//! | RFC 8198 | Negative answers synthesized from validated NSEC records |
//! | RFC 8767 | Serving stale data |
//! | RFC 8914 | Extended DNS Errors |
//! | RFC 9156 | QNAME minimisation |
//! | RFC 9462 | `resolver.arpa` from the resolver's encrypted endpoints |
//! | RFC 9520 | Failures cached apart from negatives; each server asked at most three times per transport |

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use fictionet::Entropy;
use fictionet::stdlib::protocols::dns::dnssec::{Ring, Validation, Verify};
use fictionet::stdlib::protocols::dns::op::ResponseCode;
use fictionet::stdlib::protocols::dns::rr::{DNSClass, LowerName, RecordType};
use fictionet::stdlib::protocols::dns::{Parsed, Request};
use fictionet::time::Instant;

use super::authority::{ServerConfig, bare_reply};
use super::clock::WallClock;
use super::event::{Event, QueryFlags};
use super::exchange::{Action, Client, ClientQuery, Engine, Generation, Input, Session, Tokens};
use super::zone::{Answered, ZoneData, answer, special};

mod cache;
mod config;
mod front;
mod resolution;
mod servers;

pub use cache::{Cache, Entry, FailureKind, Key, Limits, Negative, Offer, Rank};
pub use config::{Config, Minimise, NameServer, ROOT_SERVERS, Stale, Work, root_hints};

use resolution::{AskerId, CheckId, Graph, LookupId, Outcome, Subject, TreeId};
use servers::Servers;

/// A recursive resolver, as an engine.
///
/// It keeps the contract of [`Engine`]. Every exchange it starts has a
/// fresh token, a random ID, and, with
/// [`case_randomise`](Config::case_randomise), a random case in its
/// QNAME; a reply counts only from the address and over the transport the
/// query went to, with that ID and question. Client queries that need the
/// same lookups wait on them together, and [`Input::Gone`] drops only
/// what no remaining client needs. [`Engine::advance`] abandons every
/// exchange, empties the cache, restarts the queries still waiting, and
/// checks signatures against the new session's clock from then on.
///
/// `V` checks signatures; [`Ring`] checks them with the algorithms ring
/// implements.
pub struct Resolver<V: Verify = Ring> {
    config: Config,
    /// The front's view of `config`, for the header and EDNS rules
    /// authoritative servers and resolvers share.
    server: ServerConfig,
    /// The local zones, in the order they were added.
    local: Vec<Arc<dyn ZoneData>>,
    verify: V,
    clock: WallClock,
    tokens: Tokens,
    cache: Cache,
    /// The round trips of the servers it asked.
    servers: Servers,
    graph: Graph,
    askers: BTreeMap<AskerId, Asker>,
    /// Client queries a new session restarts, on the next input.
    restart: Vec<AskerId>,
    queue: VecDeque<Action>,
    now: Instant,
}

/// One client query being answered.
struct Asker {
    client: Client,
    request: Request,
    /// Whether answers must be validated: anchors are set and the client
    /// did not set CD.
    validate: bool,
    /// Whether the answer may come only from the cache: RD was clear.
    cache_only: bool,
    /// What the answer is made of so far: aliases, then the data, negative,
    /// or failure they lead to.
    pieces: Vec<Piece>,
    /// What the query waits for.
    wait: AskerWait,
    /// When the query arrived, for serving stale data to a slow
    /// resolution.
    since: Instant,
    /// Whether stale data was already looked for after the client timeout.
    stale_tried: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AskerWait {
    Nothing,
    Lookup(LookupId),
    Checks(BTreeSet<CheckId>),
}

/// One step of an answer: an alias, or what the question finally found.
#[derive(Clone, Debug)]
struct Piece {
    outcome: Outcome,
    /// What validation established, per RRset or denial the piece holds.
    checks: Vec<(Subject, Validation)>,
    /// Whether it came from the cache.
    cached: bool,
    /// Whether it is expired data served under RFC 8767.
    stale: bool,
    /// When the TTLs in `outcome` were current.
    at: Instant,
}

impl Piece {
    /// What validation established for the whole piece: its worst result.
    fn validation(&self) -> Validation {
        self.checks
            .iter()
            .map(|(_, validation)| *validation)
            .fold(Validation::Secure, worse)
    }
}

/// The worse of two validation results, for an answer made of several
/// RRsets: Bogus, then Indeterminate, then not performed, then Insecure,
/// then Secure.
fn worse(a: Validation, b: Validation) -> Validation {
    fn badness(v: &Validation) -> u8 {
        match v {
            Validation::Secure => 0,
            Validation::Insecure(_) => 1,
            Validation::NotPerformed => 2,
            Validation::Indeterminate => 3,
            Validation::Bogus(_) => 4,
        }
    }
    if badness(&b) > badness(&a) { b } else { a }
}

impl<V: Verify> Resolver<V> {
    /// A resolver behaving as `config`, checking signatures with `verify`
    /// against dates from `clock`, in generation 0.
    pub fn new(config: Config, verify: V, clock: WallClock) -> Resolver<V> {
        let server = ServerConfig {
            identity: Some(config.identity.clone()),
            payload: config.payload,
            ede: config.ede,
            any: config.any,
            transfer: false,
            ask_timeout: config.retransmit,
            recursion_available: true,
        };
        let mut local = config.local.clone();
        if !config.ddr.is_empty() {
            let zone = special::resolver_arpa(config.ddr.clone(), config.ddr_ttl);
            local.push(Arc::new(zone));
        }
        let servers = Servers::new(config.retransmit, config.server_ttl);
        let limits = Limits {
            max_ttl: config.max_ttl,
            max_negative_ttl: config.max_negative_ttl,
            failure_ttl: config.failure_ttl,
            stale: config
                .serve_stale
                .map_or(std::time::Duration::ZERO, |stale| stale.max_stale),
        };
        Resolver {
            config,
            server,
            local,
            verify,
            clock,
            tokens: Tokens::new(),
            cache: Cache::new(limits),
            servers,
            graph: Graph::default(),
            askers: BTreeMap::new(),
            restart: Vec::new(),
            queue: VecDeque::new(),
            now: Instant::ZERO,
        }
    }

    /// The cache, to look at what the resolver has learned.
    pub fn cache(&self) -> &Cache {
        &self.cache
    }

    fn query(&mut self, query: ClientQuery, entropy: &dyn Entropy) {
        let ClientQuery { client, bytes } = query;
        let request = match Request::parse(&bytes, client.transport) {
            Parsed::Silent => return,
            Parsed::Reject(reject) => {
                let bytes = self.server.render_reject(reject, client.transport);
                return self.send_answer(client, bytes, Validation::NotPerformed, false);
            }
            Parsed::Request(request) => request,
        };
        self.queue.push_back(Action::Event(Event::Query {
            at: self.now,
            server: client.local,
            client: client.clone(),
            question: request.question.clone(),
            flags: QueryFlags {
                rd: request.rd,
                cd: request.cd,
                ad: request.ad,
            },
            edns: request.edns,
        }));

        let qtype = request.question.query_type();
        match request.question.query_class() {
            DNSClass::CH => {
                let bytes = self
                    .server
                    .render_chaos(&request)
                    .expect("a resolver's server front has its identity");
                return self.send_answer(client, bytes, Validation::NotPerformed, false);
            }
            DNSClass::IN if !matches!(qtype, RecordType::AXFR | RecordType::IXFR) => {}
            _ => {
                let refused = bare_reply(&request, ResponseCode::Refused, None);
                let bytes = self.render_response(&request, refused);
                return self.send_answer(client, bytes, Validation::NotPerformed, false);
            }
        }

        if let Some(bytes) = self.answer_locally(&request) {
            return self.send_answer(client, bytes, Validation::NotPerformed, false);
        }
        if !request.rd && !self.config.rd0_from_cache {
            let refused = bare_reply(&request, ResponseCode::Refused, None);
            let bytes = self.render_response(&request, refused);
            return self.send_answer(client, bytes, Validation::NotPerformed, false);
        }

        let id = self.graph.asker();
        let asker = Asker {
            validate: self.config.anchors.is_some() && !request.cd,
            cache_only: !request.rd,
            client,
            request,
            pieces: Vec::new(),
            wait: AskerWait::Nothing,
            since: self.now,
            stale_tried: false,
        };
        self.askers.insert(id, asker);
        self.graph.hold(TreeId::of(id));
        self.step_asker(id, entropy);
    }

    /// The reply from the local zones that hold QNAME, if one knows it:
    /// deepest zone first, and at equal depth the zone added last.
    fn answer_locally(&self, request: &Request) -> Option<Vec<u8>> {
        let qname = LowerName::new(request.question.name());
        let mut zones: Vec<(usize, &Arc<dyn ZoneData>)> = self
            .local
            .iter()
            .enumerate()
            .filter(|(_, zone)| zone.apex().zone_of(&qname))
            .collect();
        zones.sort_by_key(|(index, zone)| std::cmp::Reverse((zone.apex().num_labels(), *index)));
        zones.into_iter().find_map(|(_, zone)| {
            match answer(&*zone.view(&request.question), request, self.config.any) {
                Answered::Response(response) => Some(self.render_local(request, response)),
                Answered::Unknown { .. } => None,
            }
        })
    }

    /// Moves the client query `id` on as far as it can go now: along its
    /// aliases, then through validation, then to its answer.
    fn step_asker(&mut self, id: AskerId, entropy: &dyn Entropy) {
        loop {
            let Some(asker) = self.askers.get(&id) else {
                return;
            };
            if asker.wait != AskerWait::Nothing {
                return;
            }
            let next = match asker.pieces.last() {
                None => Some(asker.request.question.name().to_lowercase()),
                Some(Piece {
                    outcome: Outcome::Alias { target, .. },
                    ..
                }) => Some(target.clone()),
                Some(_) => None,
            };
            let Some(name) = next else {
                break;
            };
            let qtype = asker.request.question.query_type();
            let depth = u8::try_from(asker.pieces.len()).unwrap_or(u8::MAX);
            let looped = asker.pieces.iter().any(|piece| match &piece.outcome {
                Outcome::Alias { cname, .. } => *cname.name() == name,
                _ => false,
            });
            let key = Key::new(LowerName::new(&name), qtype, DNSClass::IN);
            if looped || depth > self.config.work.depth {
                // An alias chain that comes back to a name it passed, or
                // runs past the work bound, fails (RFC 1034 §5.3.3).
                self.push_piece(id, Outcome::Failure(FailureKind::WorkExceeded), false);
                break;
            }
            if asker.cache_only {
                // A query with RD clear may not start the lookups a
                // validation needs, so data no check has validated is
                // answered as if the cache did not hold it, never handed
                // to a client that asked for validation (RFC 4035 §4.7).
                let validate = asker.validate;
                let unchecked = |found: &resolution::Found| {
                    validate
                        && found
                            .checks
                            .iter()
                            .any(|(_, validation)| *validation == Validation::NotPerformed)
                };
                match self.cached(&key) {
                    Some(found) if !unchecked(&found) => self.push_found(id, found),
                    _ => return self.answer_referral(id),
                }
                continue;
            }
            match self.depend(
                resolution::Node::Asker(id),
                key,
                TreeId::of(id),
                depth,
                entropy,
            ) {
                resolution::Dep::Ready(found) => self.push_found(id, *found),
                resolution::Dep::Waiting(lookup) => {
                    if let Some(asker) = self.askers.get_mut(&id) {
                        asker.wait = AskerWait::Lookup(lookup);
                    }
                    return;
                }
                resolution::Dep::Cycle | resolution::Dep::TooDeep => {
                    self.push_piece(id, Outcome::Failure(FailureKind::WorkExceeded), false);
                }
            }
        }
        self.serve_stale_on_failure(id);
        self.validate_asker(id, entropy);
    }

    fn push_found(&mut self, id: AskerId, found: resolution::Found) {
        let Some(asker) = self.askers.get_mut(&id) else {
            return;
        };
        asker.pieces.push(Piece {
            checks: found.checks,
            outcome: found.outcome,
            cached: found.cached,
            stale: false,
            at: self.now,
        });
    }

    fn push_piece(&mut self, id: AskerId, outcome: Outcome, cached: bool) {
        let checks = resolution::subjects(&outcome)
            .into_iter()
            .map(|subject| (subject, Validation::NotPerformed))
            .collect();
        self.push_found(
            id,
            resolution::Found {
                outcome,
                checks,
                cached,
            },
        );
    }

    /// Replaces a failed last piece with expired data for its question,
    /// when the configuration serves stale data and the cache still holds
    /// some (RFC 8767 §4).
    fn serve_stale_on_failure(&mut self, id: AskerId) {
        if self.config.serve_stale.is_none() {
            return;
        }
        let Some(asker) = self.askers.get(&id) else {
            return;
        };
        if !matches!(
            asker.pieces.last(),
            Some(Piece {
                outcome: Outcome::Failure(_),
                ..
            })
        ) {
            return;
        }
        let name = match asker.pieces.iter().rev().nth(1) {
            Some(Piece {
                outcome: Outcome::Alias { target, .. },
                ..
            }) => target.clone(),
            _ => asker.request.question.name().to_lowercase(),
        };
        let key = Key::new(
            LowerName::new(&name),
            asker.request.question.query_type(),
            DNSClass::IN,
        );
        if let Some(found) = self.stale_found(&key) {
            let now = self.now;
            if let Some(asker) = self.askers.get_mut(&id) {
                asker.pieces.pop();
                asker.pieces.push(Piece {
                    checks: found.checks,
                    outcome: found.outcome,
                    cached: true,
                    stale: true,
                    at: now,
                });
            }
        }
    }

    /// Starts the validations the answer of client query `id` still needs,
    /// and answers it once there are none.
    fn validate_asker(&mut self, id: AskerId, entropy: &dyn Entropy) {
        let Some(asker) = self.askers.get(&id) else {
            return;
        };
        let mut waiting = BTreeSet::new();
        if asker.validate && !asker.cache_only {
            let needed: Vec<(usize, usize, Subject, Outcome, u8)> = asker
                .pieces
                .iter()
                .enumerate()
                .filter(|(_, piece)| !piece.stale)
                .flat_map(|(index, piece)| {
                    piece
                        .checks
                        .iter()
                        .enumerate()
                        .filter(|(_, (_, validation))| *validation == Validation::NotPerformed)
                        .map(move |(at, (subject, _))| {
                            let depth = u8::try_from(index).unwrap_or(u8::MAX);
                            (index, at, subject.clone(), piece.outcome.clone(), depth)
                        })
                })
                .collect();
            for (index, at, subject, outcome, depth) in needed {
                match self.check(
                    resolution::Node::Asker(id),
                    subject,
                    &outcome,
                    TreeId::of(id),
                    depth,
                    entropy,
                ) {
                    resolution::CheckStart::Done(validation) => {
                        if let Some(asker) = self.askers.get_mut(&id) {
                            asker.pieces[index].checks[at].1 = validation;
                        }
                    }
                    resolution::CheckStart::Waiting(check) => {
                        waiting.insert(check);
                    }
                }
            }
        }
        if waiting.is_empty() {
            self.answer_asker(id, entropy);
        } else if let Some(asker) = self.askers.get_mut(&id) {
            asker.wait = AskerWait::Checks(waiting);
        }
    }

    /// What a lookup the client query `id` waited for found.
    fn asker_looked(
        &mut self,
        id: AskerId,
        lookup: LookupId,
        found: resolution::Found,
        entropy: &dyn Entropy,
    ) {
        let Some(asker) = self.askers.get_mut(&id) else {
            return;
        };
        if asker.wait != AskerWait::Lookup(lookup) {
            return;
        }
        asker.wait = AskerWait::Nothing;
        self.push_found(id, found);
        self.step_asker(id, entropy);
    }

    /// What a validation the client query `id` waited for established.
    fn asker_checked(
        &mut self,
        id: AskerId,
        check: CheckId,
        subject: &Subject,
        validation: Validation,
        entropy: &dyn Entropy,
    ) {
        let Some(asker) = self.askers.get_mut(&id) else {
            return;
        };
        let AskerWait::Checks(waiting) = &mut asker.wait else {
            return;
        };
        if !waiting.remove(&check) {
            return;
        }
        for piece in &mut asker.pieces {
            for (have, result) in &mut piece.checks {
                if have == subject && *result == Validation::NotPerformed {
                    *result = validation;
                }
            }
        }
        if waiting.is_empty() {
            asker.wait = AskerWait::Nothing;
            self.answer_asker(id, entropy);
        }
    }

    /// Answers client query `id` from its pieces, unless a record in them
    /// ran out while the rest was resolved, such as a CNAME whose TTL
    /// ended while its target was chased. An answer never carries a record
    /// past its TTL, so the chain is then followed again from the
    /// question, as the cache has it now. The work spent so far stays
    /// counted against the question.
    fn answer_asker(&mut self, id: AskerId, entropy: &dyn Entropy) {
        if self.ran_out(id) {
            if let Some(asker) = self.askers.get_mut(&id) {
                asker.pieces.clear();
                asker.wait = AskerWait::Nothing;
            }
            return self.step_asker(id, entropy);
        }
        self.send_pieces(id);
    }

    /// Whether a fresh piece of client query `id` holds a record whose TTL
    /// has ended by now. Data with TTL 0 serves the answer it came in
    /// (RFC 1035 §7.4), and stale data is served past its TTL on purpose
    /// (RFC 8767), so neither counts.
    fn ran_out(&self, id: AskerId) -> bool {
        let Some(asker) = self.askers.get(&id) else {
            return false;
        };
        let max_ttl = self.config.max_ttl;
        asker
            .pieces
            .iter()
            .filter(|piece| !piece.stale)
            .any(|piece| {
                piece.outcome.records().iter().any(|set| {
                    let ttl = std::time::Duration::from_secs(u64::from(set.ttl())).min(max_ttl);
                    !ttl.is_zero() && piece.at + ttl <= self.now
                })
            })
    }

    /// Answers client query `id` from its pieces as they are, and forgets
    /// it.
    fn send_pieces(&mut self, id: AskerId) {
        let Some(asker) = self.askers.remove(&id) else {
            return;
        };
        self.graph.release(TreeId::of(id));
        let (bytes, validation, cached) = self.render_pieces(&asker);
        self.send_answer(asker.client, bytes, validation, cached);
    }

    /// Answers client query `id`, whose RD was clear and whose question
    /// the cache cannot answer, with the closest delegation the cache
    /// holds, as a server answering from its cache does.
    fn answer_referral(&mut self, id: AskerId) {
        let Some(asker) = self.askers.remove(&id) else {
            return;
        };
        self.graph.release(TreeId::of(id));
        let bytes = self.render_referral(&asker.request);
        self.send_answer(asker.client, bytes, Validation::NotPerformed, true);
    }

    /// Serves stale data to client queries that waited longer than the
    /// client timeout of RFC 8767 §5, and lets their resolutions go on.
    fn stale_timeouts(&mut self) {
        let Some(stale) = self.config.serve_stale else {
            return;
        };
        let due: Vec<(AskerId, LookupId)> = self
            .askers
            .iter()
            .filter(|(_, asker)| {
                !asker.stale_tried && asker.since + stale.client_timeout <= self.now
            })
            .filter_map(|(id, asker)| match asker.wait {
                AskerWait::Lookup(lookup) => Some((*id, lookup)),
                _ => None,
            })
            .collect();
        for (id, lookup) in due {
            let Some(asker) = self.askers.get_mut(&id) else {
                continue;
            };
            asker.stale_tried = true;
            let Some(key) = self.graph.lookup_key(lookup) else {
                continue;
            };
            let Some(found) = self.stale_found(&key) else {
                continue;
            };
            self.graph.refresh(lookup, resolution::Node::Asker(id));
            let now = self.now;
            if let Some(asker) = self.askers.get_mut(&id) {
                asker.wait = AskerWait::Nothing;
                asker.pieces.push(Piece {
                    checks: found.checks,
                    outcome: found.outcome,
                    cached: true,
                    stale: true,
                    at: now,
                });
            }
            self.send_pieces(id);
        }
    }

    /// Drops the client queries of `client` and what only they needed.
    fn gone(&mut self, client: &Client) {
        let ids: Vec<AskerId> = self
            .askers
            .iter()
            .filter(|(_, asker)| asker.client == *client)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.askers.remove(&id);
            self.graph.release(TreeId::of(id));
            self.forget(resolution::Node::Asker(id));
        }
    }

    /// Queues [`Event::Reply`] and the answer `bytes` for `client`.
    fn send_answer(
        &mut self,
        client: Client,
        bytes: Vec<u8>,
        validation: Validation,
        cached: bool,
    ) {
        let event = front::reply_event(self.now, client.clone(), &bytes, validation, cached);
        self.queue.push_back(Action::Event(event));
        self.queue
            .push_back(Action::Answer(super::exchange::Answer { client, bytes }));
    }

    /// Takes what became ready and hands it on, until nothing is left.
    fn run(&mut self, entropy: &dyn Entropy) {
        while let Some(ready) = self.graph.ready.pop_front() {
            match ready {
                resolution::Ready::Looked {
                    to,
                    lookup,
                    key,
                    found,
                    bounded,
                } => match to {
                    resolution::Node::Asker(id) => self.asker_looked(id, lookup, *found, entropy),
                    resolution::Node::Lookup(id) => {
                        self.lookup_looked(id, lookup, &key, *found, bounded, entropy)
                    }
                    resolution::Node::Check(id) => self.check_looked(id, lookup, *found, entropy),
                    resolution::Node::Refresh => {}
                },
                resolution::Ready::Checked {
                    to,
                    check,
                    subject,
                    validation,
                } => {
                    if let resolution::Node::Asker(id) = to {
                        self.asker_checked(id, check, &subject, validation, entropy);
                    }
                }
            }
        }
    }
}

impl<V: Verify> Engine for Resolver<V> {
    fn handle(&mut self, input: Input, now: Instant, entropy: &dyn Entropy) {
        self.now = now;
        for id in std::mem::take(&mut self.restart) {
            self.graph.hold(TreeId::of(id));
            self.step_asker(id, entropy);
        }
        match input {
            Input::Query(query) => self.query(query, entropy),
            Input::Reply {
                token,
                from,
                transport,
                bytes,
            } => self.reply(token, from, transport, &bytes, entropy),
            Input::Failed { token, failure } => self.failed(token, failure, entropy),
            Input::Gone(client) => self.gone(&client),
            Input::Tick => {
                self.expire(entropy);
                self.stale_timeouts();
            }
        }
        self.run(entropy);
    }

    fn poll(&mut self) -> Option<Action> {
        self.queue.pop_front()
    }

    fn next_deadline(&self) -> Option<Instant> {
        let exchanges = self.graph.next_deadline();
        let stale = self.config.serve_stale.and_then(|stale| {
            self.askers
                .values()
                .filter(|asker| !asker.stale_tried && matches!(asker.wait, AskerWait::Lookup(_)))
                .map(|asker| asker.since + stale.client_timeout)
                .min()
        });
        let restart = (!self.restart.is_empty()).then_some(self.now);
        [exchanges, stale, restart].into_iter().flatten().min()
    }

    /// Abandons every outstanding exchange, empties the cache, and starts
    /// every client query still waiting again from the beginning, so it is
    /// answered from the new session. Signatures are checked against the
    /// session's clock from then on. The work of the restarted queries is
    /// counted afresh. Starting them draws IDs from entropy, which
    /// `advance` has none of, so they start on the next input, and
    /// [`next_deadline`](Engine::next_deadline) asks for one at once.
    fn advance(&mut self, session: Session) {
        if !self.tokens.advance(session.generation) {
            return;
        }
        self.clock = session.clock;
        for token in self.graph.clear() {
            self.queue.push_back(Action::Abandon(token));
        }
        self.cache.advance(session.generation);
        self.servers.clear();
        let ids: Vec<AskerId> = self.askers.keys().copied().collect();
        for id in &ids {
            if let Some(asker) = self.askers.get_mut(id) {
                asker.pieces.clear();
                asker.wait = AskerWait::Nothing;
                asker.stale_tried = false;
                asker.since = self.now;
            }
        }
        self.restart = ids;
    }

    fn generation(&self) -> Generation {
        self.tokens.generation()
    }
}
