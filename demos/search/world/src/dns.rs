//! Which DNS questions may leave the world for the real servers, and where
//! they go in each session.
//!
//! The world copies the real hierarchy ([`net`](crate::net)): machines at
//! the root and `gtld-servers.net` addresses, and at every name server
//! address the copied records name, answer from records copied from the
//! real server there. So the guest sees each site's real address and real
//! signatures, whether it asks the gateway, a public resolver, or a root
//! server itself. [`Outbound`] is the world's policy for the lookups
//! those servers make of the real servers, and [`SessionSource`] is where
//! the lookups it allows go: the internet, or in a Copied session the
//! DNS captured with the pages.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use fictionet::Cx;
use fictionet::stdlib::protocols::dns::label_count;
use fictionet::stdlib::protocols::dns::op::Message;
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData, Record};
use fictionet::stdlib::services::dns::zone::Filing;
use fictionet::stdlib::services::dns::{Looked, Lookup};
use fictionet::stdlib::world::net::dns::internet::{Egress, Location};
use fictionet::stdlib::world::net::dns::{PerSession, Upstream};
use fictionet::sync::Mutex;
use fictionet_extras::dns::Replay;
use fictionet_host::dns::Internet;

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
    if !labels.iter().all(|label| host_label(label)) {
        return Err("not a host name");
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

/// Whether `label` may be part of a host name: 1 to 63 letters, digits,
/// or hyphens, not starting or ending with a hyphen (RFC 1123 §2.1).
fn host_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// `name` as a host name: lowercase, without the trailing dot.
pub(crate) fn host(name: &LowerName) -> String {
    name.to_ascii().trim_end_matches('.').to_owned()
}

/// `name` and every name above it, up to the root.
fn and_above(name: &LowerName) -> impl Iterator<Item = LowerName> {
    let name = Name::from(name.clone());
    (0..=label_count(&name))
        .rev()
        .map(move |labels| LowerName::new(&name.trim_to(labels)))
}

/// The NS and CNAME targets `records` name, and every name above one.
fn named_and_above<'a>(
    records: impl Iterator<Item = &'a Record> + 'a,
) -> impl Iterator<Item = LowerName> + 'a {
    targets(records).flat_map(|(target, _)| and_above(&target).collect::<Vec<_>>())
}

/// The records of a response's answer and authority sections.
fn answer_and_authority(message: &Message) -> impl Iterator<Item = &Record> {
    message.answers.iter().chain(&message.authorities)
}

/// The records of the RRsets `filing` kept.
fn filed(filing: &Filing) -> impl Iterator<Item = &Record> {
    filing
        .sets
        .iter()
        .flat_map(|set| set.records_without_rrsigs())
}

/// The targets of the NS and CNAME `records`, with the owner of each
/// CNAME. A DNAME brings the CNAME it synthesizes (RFC 6672 §2.3), whose
/// target is below the DNAME's, so the DNAME's own target is among the
/// names above it.
fn targets<'a>(
    records: impl Iterator<Item = &'a Record> + 'a,
) -> impl Iterator<Item = (LowerName, Option<LowerName>)> + 'a {
    records.filter_map(|record: &Record| match &record.data {
        RData::NS(ns) => Some((LowerName::new(&ns.0), None)),
        RData::CNAME(cname) => Some((LowerName::new(&cname.0), Some(LowerName::new(&record.name)))),
        _ => None,
    })
}

// ---------------------------------------------------------------------------
// The outbound policy

/// The world's policy for questions to the real servers: in the live
/// modes any name; in Copied the captured hosts (`admit` and
/// [`Pages::serves_host`]) and the names a resolver must ask on the way to
/// them.
///
/// [`policy`](Self::policy) sees every lookup a mirrored server would make
/// of a real server, for the gateway's questions, the public resolvers',
/// and a guest's own to a root or top-level domain server alike. It
/// decides from the question and the session alone, never from what a
/// guest asked before. A question's name may leave when:
///
/// 1. it passes `admit` and the session serves it, or it is a name the
///    world serves in every session (the model gateway's and the time
///    server's). Live-Depth uses Live's boundary here: DNS stays real,
///    and the site's machine refuses names outside the depth;
/// 2. it is the root or a single label, which the root servers answer; in
///    the live modes, any name at all, whatever its labels or top-level
///    domain; in Copied, a name above a captured host. Priming,
///    referrals, minimised questions, and the DS and DNSKEY sets of a
///    chain of trust need these;
/// 3. it has an underscore label (RFC 8552), and any labels below that
///    one, above a name rule 1 lets out: `_dmarc`, `_25._tcp`, a DKIM
///    selector's `google._domainkey`, or a BIMI `default._bimi`;
/// 4. it is a reverse name under `in-addr.arpa` (at most four decimal
///    labels, RFC 1035 §3.5) or `ip6.arpa` (at most 32 nibble labels,
///    RFC 3596 §2.5), or a name above one, `arpa` included;
/// 5. the real hierarchy named it, or a name below it, while answering a
///    question this session: an NS target, or a CNAME target, in the
///    records a mirrored zone filed.
///
/// In the live modes every name `admit` takes passes rule 1, so any host
/// name under any domain already leaves, and a name with other labels
/// reaches the same operators: the names rules 2 to 4 add are no channel
/// the live web lacks. In Copied they reach only the root, top-level
/// domain, and reverse zone operators, or the operator of a name the
/// guest could already ask about. Names under rule 5 were chosen by those
/// operators, not by the guest.
///
/// [`observer`](Self::observer) feeds rule 5 from the records the mirrored
/// zones file, which are what their servers answer with. The names it
/// learned are forgotten when the session changes.
#[derive(Clone)]
pub struct Outbound {
    inner: Arc<OutboundInner>,
}

struct OutboundInner {
    pages: Arc<Pages>,
    /// The names the world serves in every session.
    always: HashSet<LowerName>,
    named: PerSession<Named>,
}

/// What the real hierarchy named this session.
#[derive(Default)]
struct Named {
    /// Every NS and CNAME target the mirrored zones filed, and every name
    /// above one.
    below: HashSet<LowerName>,
    /// The owners of the CNAME records the mirrored zones filed, by target.
    aliases: HashMap<LowerName, HashSet<LowerName>>,
}

impl Outbound {
    /// The policy for the sessions of `pages`, with `always` the names the
    /// world serves in every session.
    pub fn new(pages: Arc<Pages>, always: impl IntoIterator<Item = LowerName>) -> Outbound {
        Outbound {
            inner: Arc::new(OutboundInner {
                pages,
                always: always.into_iter().collect(),
                named: PerSession::new(),
            }),
        }
    }

    /// The predicate for [`Only`](fictionet::stdlib::world::net::dns::Only):
    /// whether `lookup` may reach a real server.
    pub fn policy(&self) -> impl Fn(&Lookup) -> bool + Send + Sync + 'static {
        let outbound = self.clone();
        move |lookup| outbound.allows(&LowerName::new(lookup.question.name()))
    }

    /// The observer for [`Mirror::observe`](fictionet::stdlib::world::net::dns::internet::Mirror::observe):
    /// learns the NS and CNAME targets of the records each mirrored zone
    /// files.
    pub fn observer(&self) -> impl Fn(&Filing) + Send + Sync + 'static {
        let outbound = self.clone();
        move |filing| outbound.learn(filing)
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

    /// The names the mirrored zones filed as aliases of `target` this
    /// session, through any number of CNAME records.
    pub fn aliases(&self, target: &LowerName) -> Vec<LowerName> {
        self.named(|named| {
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
        })
    }

    /// Whether a question for `name` may reach a real server.
    fn allows(&self, name: &LowerName) -> bool {
        self.admits(name)
            || self.on_the_way(name)
            || self.underscored(name)
            || reverse(name)
            || self.named(|named| named.below.contains(name))
    }

    /// Rule 2: whether a resolver may ask `name` on its way down the
    /// hierarchy: the root or a single label, any name in the live modes,
    /// or a name above a captured host in Copied.
    fn on_the_way(&self, name: &LowerName) -> bool {
        if label_count(name) <= 1 {
            return true;
        }
        let inner = &self.inner;
        match inner.pages.source() {
            Mode::Copied => {
                inner.pages.serves_below(&host(name))
                    || inner.always.iter().any(|always| name.zone_of(always))
            }
            // Any name, under any top-level domain, so the real servers
            // answer it as they would the guest: the root servers answer
            // for reserved domains too, NXDOMAIN for `internal` or
            // `example` included, and a label that is no host name label,
            // such as `x_y` or `*`, gets the zone's own NXDOMAIN or
            // wildcard answer.
            Mode::Live | Mode::LiveDepth | Mode::Edited => true,
        }
    }

    /// Rule 3: whether `name` has an underscore label, with any labels
    /// below it, above a name rule 1 lets out.
    fn underscored(&self, name: &LowerName) -> bool {
        let all: Vec<&[u8]> = name.iter().collect();
        let Some(leaf) = all.iter().rposition(|label| label.first() == Some(&b'_')) else {
            return false;
        };
        let above = all.len() - leaf - 1;
        above > 0 && self.admits(&LowerName::new(&name.trim_to(above)))
    }

    /// Notes the targets the records `filing` kept name.
    fn learn(&self, filing: &Filing) {
        self.named(|named| {
            for (target, owner) in targets(filed(filing)) {
                if let Some(owner) = owner {
                    named.aliases.entry(target).or_default().insert(owner);
                }
            }
            named.below.extend(named_and_above(filed(filing)));
        })
    }

    /// `f` with what the hierarchy named this session.
    fn named<R>(&self, f: impl FnOnce(&mut Named) -> R) -> R {
        let generation = self.inner.pages.namespace().current().generation;
        self.inner.named.with(generation, f)
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

/// Where the world's lookups go in each session: the internet, asked
/// from the host, in Live, Live-Depth, and Edited; in Copied the DNS
/// captured with the pages, so names resolve as they did when the pages
/// were copied.
///
/// A Copied session gives a lookup its capture lacks no reply, so the
/// server that needed it stays silent and a resolver caches a failure,
/// not a negative answer. The exception is a lookup of a name the world
/// serves in every session (the model gateway's and the time server's),
/// a name above one, or a name server or alias target the hierarchy
/// named while answering one: those go to the internet, or the agent
/// would lose its model and its clock.
///
/// The source is chosen again each time the world's namespace advances,
/// for the mode the new session runs in.
///
/// The world's resolvers check signatures against a Copied session's
/// clock, which stands at the capture, so the internet's answers for the
/// names that resolve in every session, signed today, would fail that
/// check. Those names, and the alias targets the hierarchy named for
/// them, are the resolvers' negative trust anchors in a Copied session
/// ([`negative_anchors`](SessionSource::negative_anchors)): they are not
/// validated. The model gateway's and the time server's zones are
/// unsigned, so for those names the guest gets the answers it would get
/// anyway; an alias target in a signed zone answers without AD.
pub struct SessionSource {
    pages: Arc<Pages>,
    needed: Arc<[LowerName]>,
    /// The source the session uses, chosen when it first asks.
    current: PerSession<Option<Chosen>>,
}

/// The source a session uses, and its Copied source when it runs from a
/// capture.
#[derive(Clone)]
struct Chosen {
    source: Arc<dyn Upstream>,
    copied: Option<Arc<Copied>>,
}

impl SessionSource {
    /// The source for the sessions of `pages`, with `needed` the names
    /// that resolve in every session.
    pub fn new(pages: Arc<Pages>, needed: impl IntoIterator<Item = LowerName>) -> SessionSource {
        SessionSource {
            pages,
            needed: needed.into_iter().collect(),
            current: PerSession::new(),
        }
    }

    /// The source for the session now.
    fn current(&self) -> Chosen {
        let generation = self.pages.namespace().current().generation;
        self.current.with(generation, |current| {
            current
                .get_or_insert_with(|| session(&self.pages, &self.needed))
                .clone()
        })
    }

    /// The predicate for [`Config::negative_anchors`](fictionet::stdlib::services::dns::resolver::Config::negative_anchors):
    /// in a Copied session, the names whose answers may come from the
    /// internet, signed today; in the other modes, none.
    pub fn negative_anchors(
        self: &Arc<Self>,
    ) -> impl Fn(&LowerName) -> bool + Send + Sync + 'static {
        let sessions = self.clone();
        move |name| {
            sessions
                .current()
                .copied
                .is_some_and(|copied| copied.fresh.lock().contains(name))
        }
    }
}

impl Upstream for SessionSource {
    fn lookup<'a>(
        &'a self,
        fcx: &'a Cx,
        lookup: Lookup,
    ) -> Pin<Box<dyn Future<Output = Looked> + Send + 'a>> {
        let source = self.current().source;
        Box::pin(async move { source.lookup(fcx, lookup).await })
    }
}

/// The source for a session of `pages` in the mode it runs in now.
fn session(pages: &Pages, needed: &Arc<[LowerName]>) -> Chosen {
    let internet = pages.live_dns();
    match (pages.source(), pages.copied_dns()) {
        (Mode::Copied, Some(replay)) => {
            let copied = Arc::new(Copied {
                replay,
                internet,
                needed: Mutex::new(needed.iter().flat_map(and_above).collect()),
                fresh: Mutex::new(needed.iter().cloned().collect()),
            });
            Chosen {
                source: copied.clone(),
                copied: Some(copied),
            }
        }
        _ => Chosen {
            source: internet,
            copied: None,
        },
    }
}

/// A Copied session's source: the capture, and the internet for the names
/// that resolve in every session.
struct Copied {
    replay: Arc<Replay>,
    internet: Arc<Internet>,
    /// The names that resolve in every session, the name servers and
    /// alias targets the hierarchy named for them, and every name above
    /// one of those.
    needed: Mutex<HashSet<LowerName>>,
    /// The names that resolve in every session and the alias targets the
    /// hierarchy named for them, whose answers may come from the internet.
    fresh: Mutex<HashSet<LowerName>>,
}

impl Upstream for Copied {
    fn lookup<'a>(
        &'a self,
        fcx: &'a Cx,
        lookup: Lookup,
    ) -> Pin<Box<dyn Future<Output = Looked> + Send + 'a>> {
        Box::pin(async move {
            let name = LowerName::new(lookup.question.name());
            let needed = self.needed.lock().contains(&name);
            let looked = match self.replay.lookup(fcx, lookup.clone()).await {
                Looked::NoReply if needed => self.internet.lookup(fcx, lookup).await,
                looked => looked,
            };
            if needed && let Looked::Response(message) = &looked {
                self.needed
                    .lock()
                    .extend(named_and_above(answer_and_authority(message)));
                let mut fresh = self.fresh.lock();
                for (target, owner) in targets(answer_and_authority(message)) {
                    if owner.is_some_and(|owner| fresh.contains(&owner)) {
                        fresh.insert(target);
                    }
                }
            }
            looked
        })
    }
}

impl Pages {
    /// The host's public IPv4 address, as the real authorities see the
    /// world's questions: what `ns1.google.com` says the address of a
    /// question from this host is. The world's whoami answers give it.
    /// `None` when the host cannot ask, as on a network that lets DNS
    /// reach only its own resolver or has no IPv4: the world runs all the
    /// same, and leaves those names to the real hierarchy.
    pub async fn egress(&self, fcx: &Cx) -> Option<Egress> {
        let internet = self.live_dns();
        let found = fcx
            .race(Some(fcx.now() + EGRESS_WAIT), internet.egress(fcx))
            .await;
        match found {
            Ok(Some(std::net::IpAddr::V4(address))) => Some(Egress(address)),
            Ok(Some(std::net::IpAddr::V6(_))) | Ok(None) | Err(_) => {
                eprintln!(
                    "The host's public IPv4 address is unknown: ns1.google.com did not tell it"
                );
                None
            }
        }
    }

    /// Where the host is on the internet, as the root, `gtld-servers.net`,
    /// and public resolver servers it reaches describe themselves, so
    /// their answers agree with `egress` wherever the host runs.
    pub async fn location(&self, fcx: &Cx, egress: Option<Egress>) -> Location {
        let internet = self.live_dns();
        Location::measured(fcx, &*internet, egress, EGRESS_WAIT).await
    }
}
