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
//! | [`Namespace`] | The session a world's DNS programs answer for; advancing it starts a new one everywhere. |
//! | [`placing`] | A root zone that places a host for a name the first time the name is asked. |
//! | [`internet`] | The root, `gtld-servers.net`, and public resolver hosts, and a mirror of the real hierarchy. |
//! | [`encrypted`] | DNS over TLS on port 853 and DNS over HTTPS on port 443 for a running [`Recursive`]. |

use fictionet::stdlib::protocols::dns::rr::rdata::{NS, SOA};
use fictionet::stdlib::protocols::dns::rr::{LowerName, Name, RData, Record, RecordSet};
use fictionet::stdlib::services::dns::zone::{Fact, Lazy, Provider};

use super::{Host, NetHandle, normalize};

pub mod encrypted;
pub mod internet;
mod program;
mod source;

pub use program::{Authoritative, Recursive, ResolverHandle};
pub use source::{Cached, Namespace, Only, PerSession, Question, Source};

/// The TTL of a locally served zone's SOA and NS records (RFC 6303 §3).
const LOCAL_TTL: u32 = 10800;

/// How long resolvers may keep the addresses of a host placed by
/// [`placing`], in seconds: Unbound's default TTL for `local-data`.
pub(super) const HOST_TTL: u32 = 3600;

/// The TTL and negative TTL of the root zone of [`placing`]: a name given
/// no host may get one later, so a negative answer is kept only briefly.
const PLACING_NEGATIVE_TTL: u32 = 60;

/// The SOA of a zone a resolver serves itself at `apex`, as Unbound gives
/// its own (RFC 6303 §3): the apex as MNAME, `nobody.invalid.` as RNAME,
/// serial 1, refresh 3600, retry 1200, expire 604800, and `minimum`.
fn local_soa(apex: &Name, minimum: u32) -> SOA {
    let rname = Name::from_ascii("nobody.invalid.").expect("a valid name");
    SOA::new(apex.clone(), rname, 1, 3600, 1200, 604800, minimum)
}

/// The SOA and NS RRsets of a zone a resolver serves itself at `apex`,
/// with the TTL and minimum of RFC 6303 §3. The NS target is the apex, as
/// in Unbound's `localhost.` zone.
pub(super) fn local_zone(apex: &Name) -> (RecordSet, RecordSet) {
    let rrset = |rdata: RData| {
        let mut set = RecordSet::with_ttl(apex.clone(), rdata.record_type(), LOCAL_TTL);
        set.set_records(vec![Record::from_rdata(apex.clone(), LOCAL_TTL, rdata)]);
        set
    };
    (
        rrset(RData::SOA(local_soa(apex, LOCAL_TTL))),
        rrset(RData::NS(NS(apex.clone()))),
    )
}

/// A root zone whose names are hosts, each placed with
/// [`NetHandle::add_host`] the first time its name is asked, as a resolver's
/// local zone.
///
/// `host_for` gets a name in lowercase without the trailing dot
/// (`en.wikipedia.org`) and returns the host for it, or `None` if no host
/// has that name. The host answers to the name, which is added to its
/// names if it lacks it. The zone keeps each placed host's A and AAAA
/// records for the run; a name given no host is asked again the next
/// time, so names may come into being as the world runs. A question asks
/// about every name on its path from the root down, so `com` and
/// `example.com` are asked before `www.example.com`, and a host placed
/// for a name makes each name above it exist as an empty non-terminal,
/// which answers NODATA, whatever `host_for` said about it. A name is
/// NXDOMAIN only while neither it nor a name below it has a host. The root is never asked, nor is a name whose first label is
/// `*`, which is no host name: the zone has no wildcards.
/// A host that cannot be placed counts as `None`. Negative answers carry
/// an SOA whose TTL and minimum are 60 seconds, so resolvers, the guest's
/// among them, keep a name given no host only briefly.
///
/// `host_for` is world code: it runs while the resolver that asked waits,
/// and while the zone holds its own lock, so it must return quickly. It
/// may place hosts of its own with the same handle.
pub fn placing<F>(handle: NetHandle, host_for: F) -> Lazy<impl Provider>
where
    F: Fn(&str) -> Option<Host> + Send + Sync + 'static,
{
    let root = Name::root();
    let (_, ns) = local_zone(&root);
    let provider = move |name: &LowerName| {
        // A `*` label is no host name (RFC 1123 §2.1), so the zone has no
        // wildcards (RFC 4592) and a name with no host stays NXDOMAIN.
        if name.is_wildcard() {
            return Fact::Absent;
        }
        let text = normalize(&name.to_string());
        let Some(mut host) = host_for(&text) else {
            return Fact::Absent;
        };
        if !host.names.contains(&text) {
            host.names.insert(0, text);
        }
        match handle.add_host(host) {
            Ok(placed) => Fact::Present(placed.rrsets(&Name::from(name.clone()), HOST_TTL)),
            Err(_) => Fact::Absent,
        }
    };
    let soa = local_soa(&root, PLACING_NEGATIVE_TTL);
    Lazy::new(root, soa, ns, PLACING_NEGATIVE_TTL, provider)
}
