//! An authority whose replies a callback sees before they leave.

use std::net::SocketAddr;

use fictionet::stdlib::protocols::dns::op::Message;
use fictionet::stdlib::protocols::dns::{Request, Response};

use super::super::exchange::Client;
use super::{Authority, Known, ServerConfig, Step};

/// The callback [`Observe`] calls.
type Observer = dyn Fn(&Request, &Client, &Response) + Send + Sync;

/// Answers as `A` does, and calls a function with each reply before the
/// engine sends it.
///
/// A world uses it to act on what its servers say, such as placing a site
/// machine at an address the first time a reply gives it out, or to feed
/// its own observation stream. The callback sees the authority's reply
/// before the server front adds its header and EDNS details. A verbatim
/// reply is decoded for it; one that does not decode is sent without the
/// callback seeing it.
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
        known: &dyn Known,
    ) -> Step {
        let step = self.authority.respond(req, local, server, client, known);
        match &step {
            Step::Reply(response) => (self.observer)(req, client, response),
            Step::Verbatim(bytes) => {
                if let Ok(message) = Message::from_vec(bytes) {
                    let response = Response {
                        message,
                        required_additional: 0,
                    };
                    (self.observer)(req, client, &response);
                }
            }
            Step::Need(_) | Step::Silent => {}
        }
        step
    }
}
