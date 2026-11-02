//! Capture the DNS a copied session needs beside its pages: every exchange
//! the world's resolver makes to resolve the captured hosts, asked of the
//! real servers.
//!
//! The walk runs the same resolver engine the world runs, with Unbound's
//! configuration and only IPv4, as Search's network has. The public
//! resolver presets minimise and ask for DNSSEC records as that
//! configuration does, so one walk holds what they ask too. Its questions go
//! to the internet through [`Live`] and are kept by [`Capture`], so the
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
use fictionet::stdlib::protocols::dns::rr::{Name, RecordType};
use fictionet::stdlib::services::dns::authority::{Ask, Observed};
use fictionet::stdlib::services::dns::resolver::{Config, Resolver};
use fictionet::stdlib::services::dns::{
    Action, Client, ClientQuery, Engine, ExchangeFailure, Input, Token, Transmit, WallClock,
};
use fictionet::stdlib::services::serve::Transport;
use fictionet::stdlib::world::net::dns::Source;
use fictionet::sync::Mutex;
use fictionet::{Cx, RaceError, Seed};
use fictionet_extras::dns::Capture;
use fictionet_extras::models::{Provider, oauth::Login};
use fictionet_extras::warc::Archive;
use fictionet_host::dns::Live;

use crate::Result;

/// The record types a guest asks for a host it is about to visit: its
/// addresses, and the HTTPS record browsers ask for beside them
/// (RFC 9460).
const TYPES: [RecordType; 3] = [RecordType::A, RecordType::AAAA, RecordType::HTTPS];

/// How many client questions the walk keeps open at once, so the host is
/// not asked to hold a socket for every question of a large corpus.
const WINDOW: usize = 64;

/// Records the DNS of every host captured in `root`, and of the names the
/// world needs in every session (the model providers', their login
/// servers', and the NTP server's), into a new archive in `root`. Fails if
/// one of those required names does not resolve.
pub async fn record(root: &Path) -> Result {
    let mut hosts = BTreeSet::new();
    for url in Archive::directory(root)?.urls() {
        if let Some(host) = url::Url::parse(url)?.domain() {
            hosts.insert(host.to_ascii_lowercase());
        }
    }
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
    let path = root.join(format!("zz-dns-{stamp}.warc.gz"));
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

/// One exchange the resolver started, on its way through the source.
struct Flight<'a> {
    token: Token,
    to: SocketAddr,
    transport: Transport,
    reply: Pin<Box<dyn Future<Output = Observed> + Send + 'a>>,
}

/// Resolves each of `names` for each of [`TYPES`] with Unbound's
/// configuration, carrying the resolver's questions through `source` on
/// the run's real clock. Returns the questions that got an RCODE other
/// than NOERROR.
async fn walk(
    fcx: &Cx,
    source: &impl Source,
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
                Action::Send(transmit) => flights.push(flight(fcx, source, transmit)),
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
                Action::Event(_) => {}
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
                if let Poll::Ready(observed) = flight.reply.as_mut().poll(cx) {
                    return Poll::Ready((index, observed));
                }
            }
            Poll::Pending
        });
        match fcx.race(deadline, landed).await {
            Ok((index, observed)) => {
                let flight = flights.swap_remove(index);
                inputs.extend(completion(&flight, observed));
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

/// Starts carrying `transmit` through `source`.
fn flight<'a>(fcx: &'a Cx, source: &'a impl Source, transmit: Transmit) -> Flight<'a> {
    let ask = Ask {
        server: transmit.to,
        transport: transmit.transport,
        query: transmit.bytes,
    };
    Flight {
        token: transmit.token,
        to: transmit.to,
        transport: transmit.transport,
        reply: source.ask(fcx, ask),
    }
}

/// What `observed` tells the engine about `flight`. Silence tells it
/// nothing: its own deadline decides.
fn completion(flight: &Flight<'_>, observed: Observed) -> Option<Input> {
    match observed {
        Observed::Reply(bytes) => Some(Input::Reply {
            token: flight.token,
            from: flight.to,
            transport: flight.transport,
            bytes,
        }),
        Observed::Unreachable => Some(Input::Failed {
            token: flight.token,
            failure: ExchangeFailure::Unreachable,
        }),
        Observed::Timeout => None,
    }
}
