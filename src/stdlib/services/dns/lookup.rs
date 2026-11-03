//! What an authoritative server asks the real servers of a zone it
//! copies, and what came of it.
//!
//! A world never passes a DNS message from a real server on to a client.
//! A server whose zone data is [learned](super::zone::Learned) answers
//! from records it holds, and when a reply needs a fact it does not hold
//! it asks one real server of the zone a [`Lookup`]. The driver puts the
//! lookup to its upstream, outside the engine, and hands back what came
//! of it as [`Looked`]; the response is filed into the zone as records,
//! and the server answers from those.

use std::net::SocketAddr;

use fictionet::stdlib::protocols::dns::op::{Message, MessageType, Query};
use fictionet::stdlib::protocols::dns::rr::LowerName;

/// One question put to a real server of a zone, with the zone it is
/// about. Two lookups are the same when every field is, so requests that
/// need the same fact wait on one lookup.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Lookup {
    /// The real server asked.
    pub server: SocketAddr,
    /// The apex of the zone the response is filed into.
    pub zone: LowerName,
    /// The question, its name in lowercase.
    pub question: Query,
    /// Whether the question asks the server to recurse (RD,
    /// RFC 1035 §4.1.1). An authority's lookups never do; only a question
    /// to a resolver, such as the whoami question of
    /// [`Location::measured`](fictionet::stdlib::world::net::dns::internet::Location::measured),
    /// sets it.
    pub recursion_desired: bool,
}

impl Lookup {
    /// A lookup of `question` at `server` for the zone at `zone`, without
    /// recursion. The question's name is put in lowercase.
    pub fn new(server: SocketAddr, zone: LowerName, question: &Query) -> Lookup {
        let mut question = question.clone();
        question.set_name(question.name().to_lowercase());
        Lookup {
            server,
            zone,
            question,
            recursion_desired: false,
        }
    }

    /// Whether `response` answers this lookup: a response with one
    /// question, the lookup's, its name compared without regard to case
    /// (RFC 4343 §3).
    pub fn answered_by(&self, response: &Message) -> bool {
        let asked = &self.question;
        response.metadata.message_type == MessageType::Response
            && matches!(response.queries.as_slice(), [got]
                if got.name() == asked.name()
                    && got.query_type() == asked.query_type()
                    && got.query_class() == asked.query_class())
    }
}

/// What a lookup gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Looked {
    /// The server's response, decoded.
    Response(Message),
    /// The server could not be reached, or refused the connection.
    Unreachable,
    /// No response came: the server stayed silent, or the world's policy
    /// kept the question from leaving.
    NoReply,
}
