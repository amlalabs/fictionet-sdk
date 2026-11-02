//! Which DNS questions may leave the world for the real servers, and where
//! they go in each session.
//!
//! The world relays the real hierarchy ([`net`](crate::net)): machines at
//! the root and `gtld-servers.net` addresses, and at every name server
//! address a relayed reply names, pass on what the real server there
//! answers. So the guest sees each site's real address and real
//! signatures, whether it asks the gateway, a public resolver, or a root
//! server itself. [`Outbound`] is the world's policy for the questions
//! those relays put to the real servers, and [`SessionSource`] is where
//! the questions it allows go: the internet, or in a Copied session the
//! DNS captured with the pages.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use fictionet::Cx;
use fictionet::stdlib::protocols::dns::op::Message;
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData, Record};
use fictionet::stdlib::protocols::dns::{Parsed, Request, Response};
use fictionet::stdlib::services::dns::authority::{Ask, Observed};
use fictionet::stdlib::services::dns::{Client, Generation};
use fictionet::stdlib::world::net::dns::Source;
use fictionet::stdlib::world::net::dns::internet::Egress;
use fictionet::sync::{Mutex, MutexGuard};
use fictionet_extras::dns::Replay;
use fictionet_host::dns::Live;

use crate::pages::{Pages, Source as Mode};

/// Top-level domains that never resolve on the internet: reserved by RFC
/// 2606 and 6761, used for mDNS, or used only inside private networks.
const NOT_ON_THE_INTERNET: [&str; 12] = [
    "test",
    "example",
    "invalid",
    "localhost",
    "local",
    "internal",
    "lan",
    "home",
    "corp",
    "intranet",
    "private",
    "arpa",
];

/// How long the world waits for the host's public address: the five
/// seconds a stub resolver waits for its first reply (`timeout:5` in
/// resolv.conf(5)).
const EGRESS_WAIT: Duration = Duration::from_secs(5);

/// Whether `name` gets a site. `Err` says why not, for the log.
///
/// A name gets a site when it could be a host on the internet: at least two
/// labels, each 1 to 63 letters, digits or hyphens, not starting or ending
/// with a hyphen, at most 253 characters in all, and a top-level domain of
/// two or more letters (or an `xn--` one) that is not reserved or private.
pub fn admit(name: &str) -> Result<(), &'static str> {
    if !name.contains('.') {
        return Err("single label");
    }
    if name.len() > 253 {
        return Err("too long");
    }
    let labels: Vec<&str> = name.split('.').collect();
    for label in &labels {
        let ok = !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ok {
            return Err("not a host name");
        }
    }
    let tld = labels[labels.len() - 1];
    if !(tld.starts_with("xn--")
        || (tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())))
    {
        return Err("not a top-level domain");
    }
    if NOT_ON_THE_INTERNET.contains(&tld) {
        return Err("reserved or private top-level domain");
    }
    Ok(())
}

/// `name` as a host name: lowercase, without the trailing dot.
fn host(name: &LowerName) -> String {
    name.to_string().trim_end_matches('.').to_owned()
}

/// The question name of `ask`, or `None` for bytes that are no question.
fn question(ask: &Ask) -> Option<LowerName> {
    match Request::parse(&ask.query, ask.transport) {
        Parsed::Request(request) => Some(LowerName::new(request.question.name())),
        Parsed::Reject(_) | Parsed::Silent => None,
    }
}

/// How many labels `name` has, a `*` label among them, which
/// [`Name::num_labels`] leaves out.
fn labels(name: &Name) -> usize {
    name.iter().count()
}

/// `name` and every name above it, up to the root.
fn and_above(name: &LowerName) -> impl Iterator<Item = LowerName> {
    let name = Name::from(name.clone());
    (0..=labels(&name))
        .rev()
        .map(move |labels| LowerName::new(&name.trim_to(labels)))
}

/// The targets of the NS and CNAME records in a reply's answer and
/// authority sections, with the owner of each CNAME. A DNAME brings the
/// CNAME it synthesizes (RFC 6672 §2.3), whose target is below the
/// DNAME's, so the DNAME's own target is among the names above it.
fn targets(message: &Message) -> impl Iterator<Item = (LowerName, Option<LowerName>)> + '_ {
    message
        .answers
        .iter()
        .chain(&message.authorities)
        .filter_map(|record: &Record| match &record.data {
            RData::NS(ns) => Some((LowerName::new(&ns.0), None)),
            RData::CNAME(cname) => {
                Some((LowerName::new(&cname.0), Some(LowerName::new(&record.name))))
            }
            _ => None,
        })
}

// ---------------------------------------------------------------------------
// The outbound policy

/// The world's policy for questions to the real servers: Live's boundary
/// (`admit` and [`Pages::serves_host`]) and the names a resolver must ask
/// on the way to a name inside it.
///
/// [`policy`](Self::policy) sees every question a relay would put to a
/// real server: the gateway's, the public resolvers', and a guest's own to
/// a root or top-level domain server alike. It decides from the question
/// and the session alone, never from what a guest asked before. A
/// question's name may leave when:
///
/// 1. it passes `admit` and the session serves it, or it is a name the
///    world serves in every session (the model gateway's and the time
///    server's). Live-Depth uses Live's boundary here: DNS stays real,
///    and the site's machine refuses names outside the depth;
/// 2. it is above a name rule 1 lets out: the root and every single label,
///    which the root servers answer, and in the live modes any name with
///    a host name below it, or in Copied the names above captured hosts.
///    Priming, referrals, minimised questions, and the DS and DNSKEY sets
///    of a chain of trust need these;
/// 3. it is one or more underscore labels (RFC 8552), such as `_dmarc` or
///    `_25._tcp`, above a name rule 1 lets out;
/// 4. it is a reverse name under `in-addr.arpa` (at most four decimal
///    labels, RFC 1035 §3.5) or `ip6.arpa` (at most 32 nibble labels,
///    RFC 3596 §2.5), or a name above one, `arpa` included;
/// 5. the real hierarchy named it, or a name below it, while answering a
///    question this session: an NS target, or a CNAME target, in a relayed
///    reply.
///
/// In Live and Edited every name `admit` takes passes rule 1, so the
/// names rules 2 to 4 add are no channel the live web lacks: they reach
/// only the root, top-level domain, and reverse zone operators, or the
/// operator of a name the guest could already ask about. Names under
/// rule 5 were chosen by those operators, not by the guest.
///
/// [`observer`](Self::observer) feeds rule 5 from the relays' replies. The
/// names it learned are forgotten when the session changes.
#[derive(Clone)]
pub struct Outbound {
    inner: Arc<OutboundInner>,
}

struct OutboundInner {
    pages: Arc<Pages>,
    /// The names the world serves in every session.
    always: HashSet<LowerName>,
    named: Mutex<Named>,
}

/// What the real hierarchy named this session.
struct Named {
    /// The session these names belong to.
    generation: Generation,
    /// Every NS and CNAME target relayed replies gave, and every name
    /// above one.
    below: HashSet<LowerName>,
    /// The owners of the CNAME records relayed replies gave, by target.
    aliases: HashMap<LowerName, HashSet<LowerName>>,
}

impl Outbound {
    /// The policy for the sessions of `pages`, with `always` the names the
    /// world serves in every session.
    pub fn new(pages: Arc<Pages>, always: impl IntoIterator<Item = LowerName>) -> Outbound {
        let generation = pages.namespace().current().generation;
        Outbound {
            inner: Arc::new(OutboundInner {
                pages,
                always: always.into_iter().collect(),
                named: Mutex::new(Named {
                    generation,
                    below: HashSet::new(),
                    aliases: HashMap::new(),
                }),
            }),
        }
    }

    /// The predicate for [`Only`](fictionet::stdlib::world::net::dns::Only):
    /// whether `ask` may reach a real server. A question that does not
    /// parse names nothing and stays in the world.
    pub fn policy(&self) -> impl Fn(&Ask) -> bool + Send + Sync + 'static {
        let outbound = self.clone();
        move |ask| question(ask).is_some_and(|name| outbound.allows(&name))
    }

    /// The observer for [`Mirror::observe`](fictionet::stdlib::world::net::dns::internet::Mirror::observe):
    /// learns the NS and CNAME targets of each relayed reply.
    pub fn observer(&self) -> impl Fn(&Request, &Client, &Response) + Send + Sync + 'static {
        let outbound = self.clone();
        move |_request, _client, response| outbound.learn(&response.message)
    }

    /// Whether the session lets `name` out by rule 1: the names it gives
    /// sites.
    pub fn admits(&self, name: &LowerName) -> bool {
        let inner = &self.inner;
        if inner.always.contains(name) {
            return true;
        }
        let text = host(name);
        admit(&text).is_ok()
            && match inner.pages.source() {
                Mode::Copied => inner.pages.serves_host(&text),
                Mode::Live | Mode::LiveDepth | Mode::Edited => true,
            }
    }

    /// The names relayed replies gave as aliases of `target` this session,
    /// through any number of CNAME records.
    pub fn aliases(&self, target: &LowerName) -> Vec<LowerName> {
        let named = self.named();
        let mut found: Vec<LowerName> = Vec::new();
        let mut pending = vec![target.clone()];
        while let Some(name) = pending.pop() {
            for owner in named.aliases.get(&name).into_iter().flatten() {
                if owner != target && !found.contains(owner) {
                    found.push(owner.clone());
                    pending.push(owner.clone());
                }
            }
        }
        found
    }

    /// Whether a question for `name` may reach a real server.
    fn allows(&self, name: &LowerName) -> bool {
        self.admits(name)
            || self.above_admitted(name)
            || self.underscored(name)
            || reverse(name)
            || self.named().below.contains(name)
    }

    /// Rule 2: whether `name` is above a name rule 1 lets out.
    fn above_admitted(&self, name: &LowerName) -> bool {
        if labels(name) <= 1 {
            return true;
        }
        let inner = &self.inner;
        match inner.pages.source() {
            Mode::Copied => {
                inner.pages.serves_below(&host(name))
                    || inner.always.iter().any(|always| name.zone_of(always))
            }
            // A name is above a host name exactly when one more label
            // makes it one.
            Mode::Live | Mode::LiveDepth | Mode::Edited => {
                admit(&format!("a.{}", host(name))).is_ok()
            }
        }
    }

    /// Rule 3: whether `name` is underscore labels above a name rule 1
    /// lets out.
    fn underscored(&self, name: &LowerName) -> bool {
        let count = labels(name);
        let underscored = name
            .iter()
            .take_while(|label| label.first() == Some(&b'_'))
            .count();
        underscored > 0
            && underscored < count
            && self.admits(&LowerName::new(&name.trim_to(count - underscored)))
    }

    /// Notes the targets `message`, a relayed reply, names.
    fn learn(&self, message: &Message) {
        let mut named = self.named();
        for (target, owner) in targets(message) {
            if let Some(owner) = owner {
                named
                    .aliases
                    .entry(target.clone())
                    .or_default()
                    .insert(owner);
            }
            named.below.extend(and_above(&target));
        }
    }

    /// What the hierarchy named this session, emptied first if the
    /// session changed.
    fn named(&self) -> MutexGuard<'_, Named> {
        let generation = self.inner.pages.namespace().current().generation;
        let mut named = self.inner.named.lock();
        if named.generation != generation {
            named.generation = generation;
            named.below.clear();
            named.aliases.clear();
        }
        named
    }
}

/// Rule 4: whether `name` is a well-formed reverse name, or a name above
/// one.
fn reverse(name: &LowerName) -> bool {
    let labels: Vec<&[u8]> = name.iter().collect();
    let Some((b"arpa", rest)) = labels.split_last().map(|(last, rest)| (*last, rest)) else {
        return false;
    };
    match rest.split_last().map(|(zone, below)| (*zone, below)) {
        None => true,
        // Each label is one octet of the address in decimal (RFC 1035 §3.5).
        Some((b"in-addr", octets)) => {
            octets.len() <= 4
                && octets.iter().all(|label| {
                    (1..=3).contains(&label.len())
                        && label.iter().all(u8::is_ascii_digit)
                        && std::str::from_utf8(label)
                            .ok()
                            .and_then(|text| text.parse::<u16>().ok())
                            .is_some_and(|octet| octet <= 255)
                })
        }
        // Each label is one hexadecimal nibble (RFC 3596 §2.5).
        Some((b"ip6", nibbles)) => {
            nibbles.len() <= 32
                && nibbles
                    .iter()
                    .all(|label| label.len() == 1 && label[0].is_ascii_hexdigit())
        }
        Some(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Where the questions go

/// Where the relays' questions go in each session: the internet, asked
/// from the host, in Live, Live-Depth, and Edited; in Copied the DNS
/// captured with the pages, so names resolve as they did when the pages
/// were copied.
///
/// A Copied session answers a question its capture lacks with silence, so
/// a resolver caches a failure, not a negative answer. The exception is a
/// question about a name the world serves in every session (the model
/// gateway's, the time server's, and the search engines'), a name above
/// one, or a name server or alias target the hierarchy named while
/// answering one: those go to the internet, or the agent would lose its
/// model and its clock.
///
/// The source is chosen again each time the world's namespace advances,
/// for the mode the new session runs in.
pub struct SessionSource {
    pages: Arc<Pages>,
    needed: Arc<[LowerName]>,
    current: Mutex<(Generation, Arc<dyn Source>)>,
}

impl SessionSource {
    /// The source for the sessions of `pages`, with `needed` the names
    /// that resolve in every session.
    pub fn new(pages: Arc<Pages>, needed: impl IntoIterator<Item = LowerName>) -> SessionSource {
        let needed: Arc<[LowerName]> = needed.into_iter().collect();
        let generation = pages.namespace().current().generation;
        let source = session(&pages, &needed);
        SessionSource {
            pages,
            needed,
            current: Mutex::new((generation, source)),
        }
    }

    /// The source for the session now.
    fn current(&self) -> Arc<dyn Source> {
        let generation = self.pages.namespace().current().generation;
        let mut current = self.current.lock();
        if current.0 != generation {
            *current = (generation, session(&self.pages, &self.needed));
        }
        current.1.clone()
    }
}

impl Source for SessionSource {
    fn ask<'a>(
        &'a self,
        fcx: &'a Cx,
        ask: Ask,
    ) -> Pin<Box<dyn Future<Output = Observed> + Send + 'a>> {
        let source = self.current();
        Box::pin(async move { source.ask(fcx, ask).await })
    }
}

/// The source for a session of `pages` in the mode it runs in now.
fn session(pages: &Pages, needed: &Arc<[LowerName]>) -> Arc<dyn Source> {
    let live = pages.live_dns();
    match (pages.source(), pages.copied_dns()) {
        (Mode::Copied, Some(replay)) => Arc::new(Copied {
            replay,
            live,
            needed: Mutex::new(needed.iter().flat_map(and_above).collect()),
        }),
        _ => live,
    }
}

/// A Copied session's source: the capture, and the internet for the names
/// that resolve in every session.
struct Copied {
    replay: Arc<Replay>,
    live: Arc<Live>,
    /// The names that resolve in every session, the name servers and
    /// alias targets the hierarchy named for them, and every name above
    /// one of those.
    needed: Mutex<HashSet<LowerName>>,
}

impl Source for Copied {
    fn ask<'a>(
        &'a self,
        fcx: &'a Cx,
        ask: Ask,
    ) -> Pin<Box<dyn Future<Output = Observed> + Send + 'a>> {
        Box::pin(async move {
            let needed = question(&ask).is_some_and(|name| self.needed.lock().contains(&name));
            let observed = match self.replay.ask(fcx, ask.clone()).await {
                Observed::Timeout if needed => self.live.ask(fcx, ask).await,
                observed => observed,
            };
            if needed
                && let Observed::Reply(bytes) = &observed
                && let Ok(message) = Message::from_vec(bytes)
            {
                let mut names = self.needed.lock();
                for (target, _) in targets(&message) {
                    names.extend(and_above(&target));
                }
            }
            observed
        })
    }
}

impl Pages {
    /// The host's public IPv4 address, as the real authorities see the
    /// world's questions: what `ns1.google.com` says the address of a
    /// question from this host is. The world's whoami answers give it.
    pub async fn egress(&self, fcx: &Cx) -> fictionet::Result<Egress> {
        let live = self.live_dns();
        let found = fcx
            .race(Some(fcx.now() + EGRESS_WAIT), live.egress(fcx))
            .await;
        match found {
            Ok(Some(std::net::IpAddr::V4(address))) => Ok(Egress(address)),
            Ok(Some(std::net::IpAddr::V6(_))) | Ok(None) | Err(_) => Err(fictionet::Error::msg(
                "The host's public IPv4 address is unknown: ns1.google.com did not tell it",
            )),
        }
    }
}
