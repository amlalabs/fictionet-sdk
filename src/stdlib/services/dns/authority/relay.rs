//! A server that answers what the real server at its own address answers.

use std::net::SocketAddr;

use fictionet::stdlib::protocols::dns::rr::rdata::opt::EdnsCode;
use fictionet::stdlib::protocols::dns::{Request, restore};

use super::super::exchange::Client;
use super::{Ask, Authority, Known, Observed, ServerConfig, Step};

/// Passes on what the real server at the relay's own address answers.
///
/// The relay asks the client's question again, as the client's own
/// message, over the client's transport, to its own address; the driver's
/// source decides how that question travels. The reply goes back with
/// only the client's ID and question case put back by [`restore`], so
/// every record, flag, and option reaches the client as the real server
/// sent it, HTTPS and SVCB records with `ech=` values included.
///
/// The server's identity decides who speaks for the instance. Behind a
/// front with an [`identity`](ServerConfig::identity), as a preset root
/// letter has, the NSID option is left out of the relayed question, and
/// the front answers CHAOS questions and gives the NSID. Behind a front
/// without one, CHAOS questions and NSID requests go to the real server
/// as well, so the real instance answers both.
///
/// When the real server cannot be reached or does not answer in time, the
/// relay stays silent, as the real server would look to the client. A
/// reply that does not answer the client's question gets silence too.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Relay;

impl Relay {
    /// A relay.
    pub fn new() -> Relay {
        Relay
    }
}

impl Authority for Relay {
    fn respond(
        &self,
        req: &Request,
        local: SocketAddr,
        server: &ServerConfig,
        _client: &Client,
        known: &dyn Known,
    ) -> Step {
        // The client's message as parsed, written again: the same
        // question in the same case, the same flags, and the same EDNS.
        // A server with an identity of its own gives its own NSID, so the
        // real server is not asked for one.
        let mut message = req.message.clone();
        if server.identity.is_some()
            && let Some(edns) = &mut message.edns
        {
            edns.options_mut().remove(EdnsCode::NSID);
        }
        let Ok(query) = message.to_vec() else {
            return Step::Silent;
        };
        let ask = Ask {
            server: local,
            transport: req.transport,
            query,
        };
        match known.get(&ask) {
            None => Step::Need(ask),
            Some(Observed::Reply(reply)) => match restore(reply, req) {
                Ok(bytes) => Step::Verbatim(bytes),
                Err(_) => Step::Silent,
            },
            Some(Observed::Unreachable | Observed::Timeout) => Step::Silent,
        }
    }
}
