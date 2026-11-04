//! What an authoritative server asks another server of a zone for a fact
//! it does not hold, and what came of it.
//!
//! A world never passes a DNS message from another server on to a
//! client. An authority answers from records it holds, and when a reply
//! needs a fact it does not hold it may ask one server of the zone a
//! [`Lookup`]. The driver puts the
//! lookup to its upstream, outside the engine, and hands back what came
//! of it as [`Looked`]; the response is filed into the zone as records,
//! and the server answers from those.

use std::net::SocketAddr;

use fictionet::stdlib::protocols::dns::op::{Edns, Message, MessageType, OpCode, Query};
use fictionet::stdlib::protocols::dns::rr::LowerName;

/// One question put to a server of a zone, with the zone it is about.
/// Two lookups are the same when every field is, so requests that need
/// the same fact wait on one lookup.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Lookup {
    /// The server asked.
    pub server: SocketAddr,
    /// The apex of the zone the response is filed into.
    pub zone: LowerName,
    /// The question, its name in lowercase.
    pub question: Query,
}

impl Lookup {
    /// The UDP payload size the query of a lookup advertises: the size the
    /// DNS Flag Day 2020 settled on (RFC 6891 §6.2.5).
    pub const PAYLOAD: u16 = 1232;

    /// A lookup of `question` at `server` for the zone at `zone`. It asks
    /// without recursion, as an authority's question to another
    /// authority does. The question's name is put in lowercase.
    pub fn new(server: SocketAddr, zone: LowerName, question: &Query) -> Lookup {
        let mut question = question.clone();
        question.set_name(question.name().to_lowercase());
        Lookup {
            server,
            zone,
            question,
        }
    }

    /// The query this lookup stands for, with ID `id`: its question,
    /// without recursion, and an OPT record with a [`PAYLOAD`](Lookup::PAYLOAD)
    /// payload and DO set, so RRSIGs and NSEC and NSEC3 records come back
    /// (RFC 3225 §3). Every upstream sends this, and a capture records it.
    pub fn query(&self, id: u16) -> Message {
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.add_query(self.question.clone());
        let mut edns = Edns::new();
        edns.set_max_payload(Lookup::PAYLOAD).set_dnssec_ok(true);
        message.set_edns(edns);
        message
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
