//! An authority whose replies a callback sees before they leave.

use std::net::SocketAddr;

use fictionet::stdlib::protocols::dns::{Request, Response};

use super::super::exchange::{Client, Generation};
use super::super::lookup::{Looked, Lookup};
use super::{Authority, ServerConfig, Step};

/// The callback [`Observe`] calls.
type Observer = dyn Fn(&Request, &Client, &Response) + Send + Sync;

/// Answers as `A` does, and calls a function with each reply before the
/// engine sends it.
///
/// A world uses it to act on what its servers say, such as placing a site
/// machine at an address the first time a reply gives it out, or to feed
/// its own observation stream. The callback sees the authority's reply
/// before the server front adds its header and EDNS details. Lookups and
/// filing go to `A` unseen.
pub struct Observe<A: Authority> {
    authority: A,
    observer: Box<Observer>,
}

impl<A: Authority> Observe<A> {
    /// `authority`, with `observer` called on each of its replies.
    pub fn new(
        authority: A,
        observer: impl Fn(&Request, &Client, &Response) + Send + Sync + 'static,
    ) -> Observe<A> {
        Observe {
            authority,
            observer: Box::new(observer),
        }
    }
}

impl<A: Authority> Authority for Observe<A> {
    fn respond(
        &self,
        req: &Request,
        local: SocketAddr,
        server: &ServerConfig,
        client: &Client,
    ) -> Step {
        let step = self.authority.respond(req, local, server, client);
        if let Step::Reply(response) = &step {
            (self.observer)(req, client, response);
        }
        step
    }

    fn file(&self, lookup: &Lookup, looked: &Looked, generation: Generation) {
        self.authority.file(lookup, looked, generation);
    }

    fn advance(&self, generation: Generation) {
        self.authority.advance(generation);
    }
}
