//! Capture the DNS a copied session needs beside its pages: every lookup
//! the world's servers make of the real servers to resolve the captured
//! hosts.
//!
//! The walk runs the same network a session runs: a [`Mirror`] serving
//! learned copies of the real hierarchy at the root and
//! `gtld-servers.net` addresses and at every name server address the
//! copies name, and a resolver with Unbound's configuration, as the
//! session's gateway has, on a network with only IPv4, as Search's is.
//! The resolver asks the copies, and the copies look up what they lack
//! through [`Capture`] over the host's [`Internet`]. So the capture holds
//! exactly the lookups a session's servers make for the same questions:
//! the priming, the referrals, the minimised steps, the DS and DNSKEY sets
//! of each chain, and the addresses of name servers that referrals named
//! without glue, which a Copied session plays back from
//! [`Replay`]. The public resolver presets
//! minimise and ask for DNSSEC records as that configuration does, so one
//! walk holds what they ask too.

use std::collections::BTreeSet;
use std::future::{Future, poll_fn};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::SystemTime;

use fictionet::stdlib::protocols::dns::op::{Message, MessageType, OpCode, Query, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::{Name, RecordType};
use fictionet::stdlib::services::dns::authority::Identity;
use fictionet::stdlib::services::dns::{Client, WallClock};
use fictionet::stdlib::services::serve::Transport;
use fictionet::stdlib::world::net::Net;
use fictionet::stdlib::world::net::dns::internet;
use fictionet::stdlib::world::net::dns::{Recursive, ResolverHandle, Upstream};
use fictionet::sync::Mutex;
use fictionet::{Cx, Seed};
use fictionet_extras::dns::mirror::Mirror;
use fictionet_extras::dns::{Capture, Replay, roots, unbound};
use fictionet_extras::models::{Provider, oauth::Login};
use fictionet_host::dns::Internet;

use crate::Result;

/// The record types a guest asks for a host it is about to visit: its
/// addresses, and the HTTPS record browsers ask for beside them
/// (RFC 9460).
const TYPES: [RecordType; 3] = [RecordType::A, RecordType::AAAA, RecordType::HTTPS];

/// How many client questions the walk keeps open at once, so the host is
/// not asked to hold a socket for every question of a large corpus.
const WINDOW: usize = 64;

/// Where the walk's resolver runs: an address of the documentation range
/// (RFC 5737), which no real name server has, so the mirror never places
/// a server there.
const RESOLVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);

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
        let capture = Arc::new(Capture::new(Internet::new()));
        let failed = walk(&fcx, capture.clone(), &names).await?;
        *failures.lock() = failed;
        capture.write(&path)?;
        // The network runs until the run is stopped.
        fcx.cancel();
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

/// One client question on its way through the walk's resolver: its index
/// in the walk's questions, and what the resolver answers.
type Asked<'a> = Pin<Box<dyn Future<Output = (usize, Option<Vec<u8>>)> + Send + 'a>>;

/// Resolves each of `names` for each of [`TYPES`] through a resolver with
/// Unbound's configuration on a network whose real hierarchy is copied
/// from `upstream` by a [`Mirror`], on the run's real clock. Returns the
/// questions that got an RCODE other than NOERROR, or no answer.
async fn walk(
    fcx: &Cx,
    upstream: Arc<dyn Upstream>,
    names: &[Name],
) -> fictionet::Result<Vec<(Name, RecordType, ResponseCode)>> {
    // Dates for the signatures: the host's date now, at the run's instant now.
    let clock = WallClock {
        start: SystemTime::now() - fcx.now().since_start(),
    };
    let net = Net::new(fictionet_extras::network::cdn_pools())
        .ipv4_only()
        .drop_unrouted();
    let mirror = roots::seed(Mirror::new(upstream, net.handle()));
    let recursive = Recursive::new(unbound::config(), clock);
    let resolver = recursive.handle();
    let (_attacher, attachments) = fictionet::attachments();
    // What the servers say about themselves does not reach the capture.
    net.hosts(internet::root_servers(|server, host| {
        let letter = roots::letter_at(server.v4).expect("a root letter");
        host.program(mirror.server(letter.front(Identity::none())))
    }))
    .hosts(roots::gtld_servers(|_, host| {
        host.program(mirror.server(roots::gtld_front(Identity::none())))
    }))
    .host("resolver", |host| {
        host.at(RESOLVER).ipv4_only().program(recursive)
    })
    .start(fcx, attachments)?;
    // Each program starts in a task of its own, and the resolver's handle
    // gives nothing until it runs. The walk waits for it with the question
    // the resolver asks first itself: the root's NS RRset (RFC 8109).
    while ask(fcx, &resolver, 0, &Name::root(), RecordType::NS)?
        .await
        .1
        .is_none()
    {
        fcx.yield_now().await?;
    }

    let questions: Vec<(Name, RecordType)> = names
        .iter()
        .flat_map(|name| TYPES.map(|kind| (name.clone(), kind)))
        .collect();
    let mut pending = 0..questions.len();
    let mut open: Vec<Asked<'_>> = Vec::new();
    let mut failed = Vec::new();
    loop {
        while open.len() < WINDOW
            && let Some(index) = pending.next()
        {
            let (name, kind) = &questions[index];
            open.push(ask(fcx, &resolver, index, name, *kind)?);
        }
        if open.is_empty() {
            return Ok(failed);
        }
        let (at, (index, answer)) = poll_fn(|cx| {
            for (at, asked) in open.iter_mut().enumerate() {
                if let Poll::Ready(answered) = asked.as_mut().poll(cx) {
                    return Poll::Ready((at, answered));
                }
            }
            Poll::Pending
        })
        .await;
        drop(open.swap_remove(at));
        let rcode = answer.map_or(ResponseCode::ServFail, |bytes| {
            Message::from_vec(&bytes)
                .map_or(ResponseCode::FormErr, |reply| reply.metadata.response_code)
        });
        if rcode != ResponseCode::NoError {
            let (name, kind) = &questions[index];
            failed.push((name.clone(), *kind, rcode));
        }
    }
}

/// Puts a client's recursive question for `name` and `kind`, number
/// `index` of the walk, to `resolver`. It arrives over TCP, so no answer
/// is truncated.
fn ask<'a>(
    fcx: &'a Cx,
    resolver: &'a ResolverHandle,
    index: usize,
    name: &Name,
    kind: RecordType,
) -> fictionet::Result<Asked<'a>> {
    let mut message = Message::new(fcx.random_u64() as u16, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name.clone(), kind));
    let bytes = message.to_vec()?;
    let client = Client {
        peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        local: SocketAddr::new(IpAddr::V4(RESOLVER), 53),
        transport: Transport::Tcp,
        connection: None,
        sandbox: None,
    };
    Ok(Box::pin(async move {
        (index, resolver.query(fcx, client, bytes).await)
    }))
}
