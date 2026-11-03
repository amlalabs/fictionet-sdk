//! Capture the DNS a copied session needs beside its pages: every exchange
//! the world's resolver makes to resolve the captured hosts, asked of the
//! real servers.
//!
//! The walk runs the same resolver engine the world runs, with Unbound's
//! configuration and only IPv4, as Search's network has. The public
//! resolver presets minimise and ask for DNSSEC records as that
//! configuration does, so one walk holds what they ask too. Its questions go,
//! as lookups, to the internet through [`Live`] and are kept by [`Capture`], so the
//! capture holds the priming, the referrals, the minimised steps, the DS
//! and DNSKEY sets of each chain, and the addresses of name servers that
//! referrals named without glue: what the world's resolvers ask when they
//! resolve the same names from [`Replay`](fictionet_extras::dns::Replay).

use std::collections::{BTreeSet, VecDeque};
use std::future::{Future, poll_fn};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::SystemTime;

use fictionet::stdlib::protocols::dns::dnssec::Ring;
use fictionet::stdlib::protocols::dns::op::{Message, MessageType, OpCode, Query, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RecordType};
use fictionet::stdlib::protocols::dns::{Parsed, Request};
use fictionet::stdlib::services::dns::resolver::{Config, Resolver};
use fictionet::stdlib::services::dns::{
    Action, Client, ClientQuery, Engine, ExchangeFailure, Input, Looked, Lookup, Token, Transmit,
    WallClock,
};
use fictionet::stdlib::services::serve::Transport;
use fictionet::stdlib::world::net::dns::Upstream;
use fictionet::sync::Mutex;
use fictionet::{Cx, RaceError, Seed};
use fictionet_extras::dns::{Capture, Replay};
use fictionet_extras::models::{Provider, oauth::Login};
use fictionet_host::dns::Live;

use crate::Result;

/// The record types a guest asks for a host it is about to visit: its
/// addresses, and the HTTPS record browsers ask for beside them
/// (RFC 9460).
const TYPES: [RecordType; 3] = [RecordType::A, RecordType::AAAA, RecordType::HTTPS];

/// How many client questions the walk keeps open at once, so the host is
/// not asked to hold a socket for every question of a large corpus.
const WINDOW: usize = 64;

/// Records the DNS of `hosts`, every host the corpus serves, and of the
/// names the world needs in every session (the model providers', their
/// login servers', the NTP server's, and the search engines'), into a new
/// archive in `root`. Fails if one of those required names does not
/// resolve.
pub async fn record(root: &Path, hosts: &[String]) -> Result {
    let required = [
        Provider::Anthropic,
        Provider::OpenAi,
        Provider::ChatGpt,
        Provider::OpenRouter,
        Provider::Gemini,
    ]
    .map(Provider::host)
    .into_iter()
    .chain([Login::Claude, Login::Codex].map(Login::host))
    .chain([web_world::ntp::HOST])
    .chain(web_world::route::SEARCH_HOSTS)
    .map(fqdn)
    .collect::<Result<BTreeSet<_>>>()?;
    let mut names = hosts
        .iter()
        .map(|host| fqdn(host))
        .collect::<Result<BTreeSet<_>>>()?;
    names.extend(required.iter().cloned());

    let stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_nanos();
    let path = Replay::capture_file(root, stamp);
    let names: Vec<Name> = names.into_iter().collect();
    let count = names.len();
    let failed = Arc::new(Mutex::new(Vec::new()));
    let failures = failed.clone();
    fictionet::run(Seed::random(), move |fcx| async move {
        let capture = Capture::new(Live::new());
        let failed = walk(&fcx, &capture, &names).await?;
        *failures.lock() = failed;
        capture.write(&path)?;
        Ok(())
    })
    .await
    .map_err(|error| error.to_string())?;

    let mut missing = Vec::new();
    for (name, kind, rcode) in failed.lock().iter() {
        eprintln!("DNS unavailable: {name} {kind}: {rcode}");
        if *kind == RecordType::A && required.contains(name) {
            missing.push(format!("{name} does not resolve: {rcode}"));
        }
    }
    if !missing.is_empty() {
        return Err(missing.join("\n").into());
    }
    println!("Captured DNS for {count} names");
    Ok(())
}

fn fqdn(host: &str) -> Result<Name> {
    let mut name = Name::from_ascii(host)?;
    name.set_fqdn(true);
    Ok(name)
}

/// One exchange the resolver started, on its way through the upstream.
struct Flight<'a> {
    token: Token,
    /// What it brings back for the resolver ([`flight`]).
    input: Pin<Box<dyn Future<Output = Option<Input>> + Send + 'a>>,
}

/// Resolves each of `names` for each of [`TYPES`] with Unbound's
/// configuration, carrying the resolver's questions through `upstream` on
/// the run's real clock. Returns the questions that got an RCODE other
/// than NOERROR.
async fn walk(
    fcx: &Cx,
    upstream: &impl Upstream,
    names: &[Name],
) -> fictionet::Result<Vec<(Name, RecordType, ResponseCode)>> {
    let mut config = Config::unbound();
    config.hints.retain(|(_, address)| address.is_ipv4());
    // Dates for the signatures: the host's date now, at the run's instant now.
    let clock = WallClock {
        start: SystemTime::now() - fcx.now().since_start(),
    };
    let mut engine = Resolver::new(config, Ring, clock);

    let questions: Vec<(Name, RecordType)> = names
        .iter()
        .flat_map(|name| TYPES.map(|kind| (name.clone(), kind)))
        .collect();
    let mut pending: VecDeque<ClientQuery> = questions
        .iter()
        .enumerate()
        .map(|(index, (name, kind))| client_query(fcx, index, name, *kind))
        .collect::<fictionet::Result<_>>()?;
    let mut open = 0;
    let mut failed = Vec::new();
    let mut flights: Vec<Flight<'_>> = Vec::new();
    let mut inputs = Vec::new();
    loop {
        while open < WINDOW
            && let Some(query) = pending.pop_front()
        {
            inputs.push(Input::Query(query));
            open += 1;
        }
        let now = fcx.now();
        for input in inputs.drain(..) {
            engine.handle(input, now, fcx);
        }
        while let Some(action) = engine.poll() {
            match action {
                // Search's network has no IPv6, so a transmit to an IPv6
                // server fails at once, as on a machine with no IPv6 route.
                Action::Send(transmit) if transmit.to.is_ipv6() => inputs.push(Input::Failed {
                    token: transmit.token,
                    failure: ExchangeFailure::Unreachable,
                }),
                Action::Send(transmit) => flights.push(flight(fcx, upstream, transmit)),
                Action::Answer(answer) => {
                    open -= 1;
                    let rcode = Message::from_vec(&answer.bytes)
                        .map_or(ResponseCode::FormErr, |reply| reply.metadata.response_code);
                    if rcode != ResponseCode::NoError
                        && let Some(index) = answer.client.connection
                    {
                        let (name, kind) = &questions[index as usize];
                        failed.push((name.clone(), *kind, rcode));
                    }
                }
                Action::Abandon(token) => flights.retain(|flight| flight.token != token),
                Action::Lookup { .. } | Action::Event(_) => {}
            }
        }
        if !inputs.is_empty() {
            continue;
        }
        let deadline = engine.next_deadline();
        if flights.is_empty() && deadline.is_none() {
            if open > 0 {
                return Err(fictionet::Error::msg(
                    "the resolver stopped with questions unanswered",
                ));
            }
            if pending.is_empty() {
                return Ok(failed);
            }
            continue;
        }
        let landed = poll_fn(|cx| {
            for (index, flight) in flights.iter_mut().enumerate() {
                if let Poll::Ready(input) = flight.input.as_mut().poll(cx) {
                    return Poll::Ready((index, input));
                }
            }
            Poll::Pending
        });
        match fcx.race(deadline, landed).await {
            Ok((index, input)) => {
                flights.swap_remove(index);
                inputs.extend(input);
            }
            Err(RaceError::Deadline) => inputs.push(Input::Tick),
            Err(RaceError::Cancelled) => {
                return Err(fictionet::Error::msg("the walk was cancelled"));
            }
        }
    }
}

/// A client's recursive question for `name` and `kind`, numbered `index`
/// by its connection so its answer can be told apart. It arrives over TCP,
/// so no answer is truncated.
fn client_query(
    fcx: &Cx,
    index: usize,
    name: &Name,
    kind: RecordType,
) -> fictionet::Result<ClientQuery> {
    let mut message = Message::new(fcx.random_u64() as u16, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name.clone(), kind));
    let local = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 53);
    Ok(ClientQuery {
        client: Client {
            peer: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            local,
            transport: Transport::Tcp,
            connection: Some(index as u64),
            sandbox: None,
        },
        bytes: message.to_vec()?,
    })
}

/// Starts carrying `transmit` through `upstream`, as a lookup of its
/// question at its server.
///
/// The walk's resolver does not say which zone it asks about, and a
/// capture keeps only the server and the question, so each lookup names
/// the root as its zone. The response goes back to the resolver written
/// again with the query's ID and question, as the server's reply to it.
/// A transmit that is no question gets nothing, and the resolver's
/// deadline decides.
fn flight<'a>(fcx: &'a Cx, upstream: &'a impl Upstream, transmit: Transmit) -> Flight<'a> {
    let token = transmit.token;
    let input = async move {
        let Parsed::Request(request) = Request::parse(&transmit.bytes, transmit.transport) else {
            return None;
        };
        let mut lookup = Lookup::new(
            transmit.to,
            LowerName::from(Name::root()),
            &request.question,
        );
        lookup.recursion_desired = request.rd;
        match upstream.lookup(fcx, lookup).await {
            Looked::Response(mut response) => {
                response.metadata.id = request.message.metadata.id;
                response.queries = vec![request.question.clone()];
                Some(Input::Reply {
                    token,
                    from: transmit.to,
                    transport: transmit.transport,
                    bytes: response.to_vec().ok()?,
                })
            }
            Looked::Unreachable => Some(Input::Failed {
                token,
                failure: ExchangeFailure::Unreachable,
            }),
            Looked::NoReply => None,
        }
    };
    Flight {
        token,
        input: Box::pin(input),
    }
}
