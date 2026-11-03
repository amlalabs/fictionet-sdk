//! DNS servers as programs on the world's hosts: authoritative servers and
//! recursive resolvers that answer over real packets, where their own
//! questions go, and the namespace a world advances when its session
//! changes.
//!
//! The engines in [`services::dns`](fictionet::stdlib::services::dns)
//! decide every answer and touch no socket. The programs here run them on
//! a machine: [`Authoritative`] runs an
//! [`Authority`](fictionet::stdlib::services::dns::authority::Authority) and
//! [`Recursive`] runs a [`Resolver`](fictionet::stdlib::services::dns::resolver::Resolver),
//! each on UDP and TCP port 53 of every machine of the host that runs it
//! ([`Host::program`](super::Host::program)). A resolver's questions to
//! other servers leave the machine as packets, so it resolves through
//! authoritative programs on other hosts, or through a real server
//! attached with [`Net::route`](super::Net::route), and the network's
//! dissector sees each exchange. An authority's own questions, such as a
//! relay's, go to a [`Source`].
//!
//! The network's gateway is such a host: [`Net::gateway`](super::Net::gateway)
//! says what runs there, and by default it is a resolver with no route to
//! the internet that answers the names the hosts declare
//! ([`Declared`](super::Declared)). [`placing`] is a root zone whose names
//! are hosts placed when a name is first asked, for worlds whose hosts
//! come into being as they are looked up.
//!
//! [`internet`] has the internet's servers as presets that return hosts:
//! the root and `gtld-servers.net` servers, the public resolvers, and a
//! [`Mirror`](internet::Mirror) that relays the real hierarchy. A world
//! that adds none of them has no internet.
//!
//! [`encrypted`] puts DNS over TLS and DNS over HTTPS in front of a
//! resolver: the same engines and caches answer them as answer port 53.
//!
//! A gateway that knows a few names and has no internet:
//!
//! ```
//! # use std::time::SystemTime;
//! # use fictionet::{Attachments, Cx, Result};
//! # use fictionet::stdlib::services::dns::{WallClock, resolver::Config};
//! # use fictionet::stdlib::world::net::{Net, dns::Recursive};
//! # async fn world(fcx: Cx, attachments: Attachments) -> Result {
//! let clock = WallClock { start: SystemTime::UNIX_EPOCH };
//! Net::new()
//!     .host("www", |h| h.dns_name("intranet.corp.test"))
//!     .gateway(move |h, declared| h.program(Recursive::new(declared.over(Config::gateway()), clock)))
//!     .start(&fcx, attachments)?;
//! # Ok(())
//! # }
//! ```
//!
//! | Item | What it is |
//! | --- | --- |
//! | [`Authoritative`] | A program that runs an authority on port 53, with its questions to other servers going to a [`Source`]. |
//! | [`Recursive`] | A program that runs a resolver on port 53, one engine per address or per what [`Recursive::partition`] picks. |
//! | [`ResolverHandle`] | Puts queries from other fronts, such as DNS over TLS, to a running [`Recursive`]. |
//! | [`Source`] | What a real client sees when it asks a server a question: a world's own answers, recorded exchanges, or the internet. |
//! | [`Only`] | A source that asks only what the world's policy allows, and times out on the rest. |
//! | [`Cached`] | A source that keeps replies for their smallest TTL. |
//! | [`Question`] | What makes two queries one question for a source that answers from replies it holds. |
//! | [`carry`] | Takes a query an engine sends to a source and gives back the engine's next input. |
//! | [`Namespace`] | The session a world's DNS programs answer for; advancing it starts a new one everywhere. |
//! | [`PerSession`] | State that belongs to one session and starts afresh in the next. |
//! | [`placing`] | A root zone that places a host for a name the first time the name is asked. |
//! | [`internet`] | The root, `gtld-servers.net`, and public resolver hosts, and a mirror of the real hierarchy. |
//! | [`encrypted`] | DNS over TLS on port 853 and DNS over HTTPS on port 443 for a running [`Recursive`]. |

use std::sync::Arc;

use fictionet::stdlib::protocols::dns::op::Query;
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RecordSet};
use fictionet::stdlib::services::dns::zone::{View, ZoneData, special};
use fictionet::sync::Mutex;

use super::hosts::Facts;
use super::{Host, NetHandle, normalize};

pub mod encrypted;
pub mod internet;
mod program;
mod source;

pub use program::{Authoritative, Recursive, ResolverHandle};
pub use source::{Cached, Namespace, Only, PerSession, Question, Source, carry};

/// How long resolvers may keep the addresses of a host placed by
/// [`placing`], in seconds: Unbound's default TTL for `local-data`.
pub(super) const HOST_TTL: u32 = 3600;

/// The TTL and negative TTL of the root zone of [`placing`]: a name given
/// no host may get one later, so a negative answer is kept only briefly.
const PLACING_NEGATIVE_TTL: u32 = 60;

/// A root zone whose names are the network's hosts, where a host is placed
/// with [`NetHandle::add_host`] the first time its name is asked, as a
/// resolver's local zone.
///
/// `host_for` gets a name in lowercase without the trailing dot
/// (`en.wikipedia.org`) and returns the host for it, or `None` if no host
/// has that name. The host answers to the name, which is added to its
/// names if it lacks it. A question asks `host_for` about its own name
/// only, and only when no host has declared that name yet, so one lookup
/// places at most one host. A name given no host is asked again the next
/// time, so names may come into being as the world runs.
///
/// The zone answers every name the network's hosts declare
/// ([`Declared`](super::Declared)), whether `host_for` placed them or not.
/// A name with a declared name below it exists as an empty non-terminal,
/// which answers NODATA when `host_for` gives it no host. A name is
/// NXDOMAIN only while neither it nor a name below it is declared. The
/// root is never asked, nor is a name whose first label is `*`, which is
/// no host name: the zone has no wildcards. A host that cannot be placed
/// counts as `None`. Negative answers carry an SOA whose TTL and minimum
/// are 60 seconds, so resolvers, the guest's among them, keep a name given
/// no host only briefly.
///
/// `host_for` is world code: it runs while the resolver that asked waits,
/// and while the zone holds its own lock, so it must return quickly. It
/// may place hosts of its own with the same handle.
pub fn placing<F>(handle: NetHandle, host_for: F) -> impl ZoneData
where
    F: Fn(&str) -> Option<Host> + Send + Sync + 'static,
{
    let root = Name::root();
    let (soa, ns) = special::local_apex(&root, PLACING_NEGATIVE_TTL);
    Placing {
        root: LowerName::new(&root),
        soa,
        ns,
        handle,
        host_for,
        placing: Mutex::new(()),
    }
}

/// The zone [`placing`] returns.
struct Placing<F> {
    root: LowerName,
    soa: RecordSet,
    ns: RecordSet,
    handle: NetHandle,
    host_for: F,
    /// Held while a question asks `host_for` and places its host, so two
    /// questions for one name place one host.
    placing: Mutex<()>,
}

impl<F> ZoneData for Placing<F>
where
    F: Fn(&str) -> Option<Host> + Send + Sync + 'static,
{
    fn apex(&self) -> &LowerName {
        &self.root
    }

    fn view(&self, question: &Query) -> Arc<dyn View + Send + Sync> {
        let qname = LowerName::new(question.name());
        let Ok(shared) = self.handle.shared() else {
            return Arc::new(Facts::unknown(self.root.clone()));
        };
        let _placing = self.placing.lock();
        // A `*` label is no host name (RFC 1123 §2.1), so the zone has no
        // wildcards (RFC 4592) and a name with no host stays NXDOMAIN.
        let asks = !qname.is_root()
            && !qname.is_wildcard()
            && !shared.world.lock().declared.contains_key(&qname);
        if asks {
            let text = normalize(&qname.to_ascii());
            if let Some(mut host) = (self.host_for)(&text) {
                if !host.names.contains(&text) {
                    host.names.insert(0, text);
                }
                // A host that cannot be placed counts as no host.
                let _ = self.handle.add_host(host);
            }
        }
        let apex_sets = [self.soa.clone(), self.ns.clone()];
        let world = shared.world.lock();
        Arc::new(world.view(self.root.clone(), self.soa.clone(), &apex_sets, &qname))
    }
}
