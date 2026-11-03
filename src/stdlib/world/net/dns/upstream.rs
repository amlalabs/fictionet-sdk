//! Where a world's lookups of real servers go: the one asynchronous step
//! of serving DNS, at the edge, outside the engines.

use std::future::{Future, ready};
use std::pin::Pin;
use std::sync::Arc;

use fictionet::Cx;
use fictionet::stdlib::services::dns::{Looked, Lookup};

/// What real servers answer the lookups of a world's servers: the
/// internet's servers, recorded responses, or answers a world writes
/// itself.
///
/// [`Authoritative`](super::Authoritative) puts its authority's
/// [lookups](Lookup) here, such as a learned zone's question to a real
/// server of the zone, and files what comes back as records. An upstream
/// never answers a client: what it gives is data, and the world's own
/// engines build every reply from it.
///
/// An upstream asks every question with an OPT record that sets DO, so
/// RRSIGs and NSEC and NSEC3 records come back (RFC 3225 §3), and that
/// asks for the server's NSID (RFC 5001). It checks that a response
/// answers the question it sent (RFC 5452 §9.1), and gives it decoded.
///
/// An upstream decides nothing about what may be asked: the agent in a
/// sandbox chooses the names its servers look up, and a question that
/// reaches a real server is a channel out to whoever runs it. A world
/// puts its policy in front with [`Only`].
pub trait Upstream: Send + Sync + 'static {
    /// What `lookup.server` gives for `lookup.question`. The future may
    /// finish on a host thread that waits for the internet; only its
    /// waker crosses back.
    fn lookup<'a>(
        &'a self,
        fcx: &'a Cx,
        lookup: Lookup,
    ) -> Pin<Box<dyn Future<Output = Looked> + Send + 'a>>;
}

impl<U: Upstream + ?Sized> Upstream for Arc<U> {
    fn lookup<'a>(
        &'a self,
        fcx: &'a Cx,
        lookup: Lookup,
    ) -> Pin<Box<dyn Future<Output = Looked> + Send + 'a>> {
        (**self).lookup(fcx, lookup)
    }
}

/// An upstream that makes only the lookups `policy` allows, and gives
/// [`Looked::NoReply`] for the rest without asking, as a server that
/// never replies. The server that needed the fact then stays silent.
///
/// The policy sees every lookup: those for the root, top-level domains,
/// and `arpa`, the addresses of name servers, the targets of aliases, and
/// the DS and DNSKEY sets of a chain of trust alike. No kind of lookup
/// passes by itself, since a guest can put any name it likes to a world's
/// server, and every label of a minimised question is still a name the
/// guest chose.
pub struct Only<U, P> {
    policy: P,
    upstream: U,
}

impl<U: Upstream, P: Fn(&Lookup) -> bool + Send + Sync + 'static> Only<U, P> {
    /// `upstream`, asked only what `policy` allows.
    pub fn new(policy: P, upstream: U) -> Only<U, P> {
        Only { policy, upstream }
    }
}

impl<U: Upstream, P: Fn(&Lookup) -> bool + Send + Sync + 'static> Upstream for Only<U, P> {
    fn lookup<'a>(
        &'a self,
        fcx: &'a Cx,
        lookup: Lookup,
    ) -> Pin<Box<dyn Future<Output = Looked> + Send + 'a>> {
        if (self.policy)(&lookup) {
            self.upstream.lookup(fcx, lookup)
        } else {
            Box::pin(ready(Looked::NoReply))
        }
    }
}
