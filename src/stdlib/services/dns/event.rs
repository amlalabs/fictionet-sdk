//! What DNS engines report as they work.
//!
//! Engines queue events beside their actions, and drivers hand them to
//! whatever the world registered. The SDK picks no sink, and an event no
//! one watches costs only its construction.

use std::net::SocketAddr;

use fictionet::stdlib::protocols::dns::dnssec::Validation;
use fictionet::stdlib::protocols::dns::op::{Metadata, Query, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::RecordSet;
use fictionet::stdlib::protocols::dns::{EdeCode, EdnsIn};
use fictionet::stdlib::services::serve::Transport;
use fictionet::time::Instant;

use super::exchange::{Client, ExchangeFailure, Token};
use super::lookup::Lookup;

/// Something an engine did or saw.
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    /// A client's query passed [`Request::parse`](fictionet::stdlib::protocols::dns::Request::parse).
    /// An engine queues it before any exchange the query causes.
    Query {
        /// When it arrived.
        at: Instant,
        /// The server address it was sent to.
        server: SocketAddr,
        /// Who sent it.
        client: Client,
        /// Its question, in the client's case.
        question: Query,
        /// Its header flags.
        flags: QueryFlags,
        /// Its EDNS, if it had an OPT record.
        edns: Option<EdnsIn>,
    },
    /// A reply went to a client.
    Reply {
        /// When it was sent.
        at: Instant,
        /// The server address it came from.
        server: SocketAddr,
        /// Who it went to.
        client: Client,
        /// The question it answers, as its question section carries it.
        /// `None` for a reply with no question, such as FORMERR for a query
        /// that did not parse.
        question: Option<Query>,
        /// Its RCODE, with the OPT record's high bits.
        rcode: ResponseCode,
        /// Its header flags.
        flags: ReplyFlags,
        /// The RRsets of its answer section.
        answers: Vec<RecordSet>,
        /// What the engine established about the answer's authenticity.
        /// Authoritative servers do not validate, so theirs is
        /// [`Validation::NotPerformed`].
        validation: Validation,
        /// The first Extended DNS Error it carried (RFC 8914).
        ede: Option<EdeCode>,
        /// Whether a resolver answered it from its cache.
        cached: bool,
        /// Its length in octets.
        size: u16,
    },
    /// A resolver's exchange with another server ended.
    Upstream {
        /// When it ended.
        at: Instant,
        /// The exchange.
        token: Token,
        /// The server asked.
        to: SocketAddr,
        /// How it was asked.
        transport: Transport,
        /// The question, in the case it was sent with.
        question: Query,
        /// How it ended.
        outcome: UpstreamOutcome,
    },
    /// An authority's lookup ended, and what it gave was filed.
    Looked {
        /// When it ended.
        at: Instant,
        /// The lookup.
        lookup: Lookup,
        /// What came of it.
        outcome: LookupOutcome,
    },
    /// A completion that changed nothing: its token was not outstanding or
    /// was of an older generation, or the reply came from another address
    /// or over another transport than the query went, or did not carry the
    /// query's ID and question (RFC 5452 §9.1), as rule 4 of the
    /// [`Engine`](super::Engine) contract says.
    Ignored {
        /// When it arrived.
        at: Instant,
        /// The token it carried.
        token: Token,
        /// Where it came from, for a reply.
        from: Option<SocketAddr>,
        /// Why it changed nothing.
        why: Unmatched,
    },
}

/// The header flags of a query.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QueryFlags {
    /// Recursion desired.
    pub rd: bool,
    /// Checking disabled.
    pub cd: bool,
    /// Authentic data, which in a query asks for AD in the reply
    /// (RFC 6840 §5.7).
    pub ad: bool,
}

/// The header flags of a reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReplyFlags {
    /// Authoritative answer.
    pub aa: bool,
    /// Truncated.
    pub tc: bool,
    /// Recursion desired, copied from the query.
    pub rd: bool,
    /// Recursion available.
    pub ra: bool,
    /// Authentic data.
    pub ad: bool,
    /// Checking disabled, copied from the query.
    pub cd: bool,
}

impl ReplyFlags {
    /// The flags in a reply's header.
    pub fn of(metadata: &Metadata) -> ReplyFlags {
        ReplyFlags {
            aa: metadata.authoritative,
            tc: metadata.truncation,
            rd: metadata.recursion_desired,
            ra: metadata.recursion_available,
            ad: metadata.authentic_data,
            cd: metadata.checking_disabled,
        }
    }
}

/// How a resolver's exchange with another server ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UpstreamOutcome {
    /// A matching reply came back.
    Reply {
        /// Its RCODE.
        rcode: ResponseCode,
        /// Whether it had TC set.
        truncated: bool,
        /// Its length in octets.
        size: u16,
    },
    /// The exchange failed without a reply.
    Failed(ExchangeFailure),
    /// No reply came in time.
    Timeout,
}

/// How an authority's lookup ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LookupOutcome {
    /// A response with this RCODE.
    Response {
        /// Its RCODE.
        rcode: ResponseCode,
    },
    /// The server could not be reached.
    Unreachable,
    /// No response came: the server stayed silent, the world's policy
    /// kept the question in, or the server's deadline passed.
    NoReply,
}

/// Why a completion changed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Unmatched {
    /// Its token is from a session before the current one.
    OldGeneration,
    /// Its token is not outstanding: the exchange already completed, was
    /// abandoned, or was never started.
    NotOutstanding,
    /// The reply came from another address than the transmit went to, or
    /// over another transport.
    WrongPeer,
    /// The reply's ID is not the query's.
    WrongId,
    /// The reply's question is not the query's.
    WrongQuestion,
    /// The bytes are not a DNS response.
    Malformed,
}
