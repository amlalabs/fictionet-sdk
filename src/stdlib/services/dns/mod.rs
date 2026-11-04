//! DNS engines: the code that decides what a DNS server answers, with no
//! I/O.
//!
//! Nothing here reads a clock, draws randomness, holds a future, or
//! touches a socket. Time comes in as an [`Instant`](fictionet::time::Instant)
//! argument, dates from a [`WallClock`] value, and the bytes on the wire
//! from whoever drives the code. The same answers come out however the
//! questions travel.
//!
//! [`zone`] holds what a server knows: zones whose facts are present,
//! known absent, or unknown, and the authoritative answer over them.
//! [`authority`] holds what a server at an address answers, and the
//! [`AuthorityEngine`](authority::AuthorityEngine) that runs one.
//! [`resolver`] holds the recursive [`Resolver`](resolver::Resolver),
//! which answers clients from local zones, its cache, and the servers it
//! asks, and validates what it learns. [`memory`] drives engines with no
//! runtime: servers in memory, recorded exchanges, and a virtual clock.
//! A server whose zone data is [learned](zone::Learned) from real servers
//! asks one of them a typed [`Lookup`] for a fact it does not hold; its
//! driver hands back what came of it ([`Looked`]), which is filed as
//! records. No message from a real server reaches a client.
//!
//! Every engine has the shape of [`Engine`]: a driver hands it
//! [inputs](Input) with the time, and takes [actions](Action) and
//! [events](Event) from one queue. An engine names each exchange it
//! starts with a [`Token`] of the current [`Generation`]; when the world's
//! session changes, the driver [advances](Engine::advance) the engine,
//! and nothing that completes for an older generation can change the new
//! one.
//!
//! The standards this module follows:
//!
//! | RFC | What it sets here |
//! | --- | --- |
//! | RFC 1034 §4.2, §4.3.2 | Zones, cuts, glue, and the authoritative answer |
//! | RFC 1035 §5 | Master files ([`Zone::from_master`](zone::Zone::from_master)) |
//! | RFC 1912 §2.4 | No CNAME at a zone's apex |
//! | RFC 2181 §5, §8, §10 | RRsets without duplicates and with one TTL below 2^31; CNAME and alias rules |
//! | RFC 2308 §3 | Negative answers carry the SOA with TTL min(SOA TTL, MINIMUM) |
//! | RFC 3225 §3 | Replies copy the query's DO bit |
//! | RFC 3597 | Unknown record types in master files |
//! | RFC 4035 §3.1, §3.2.1 | RRSIGs and denial records only for DO, DS from the parent side |
//! | RFC 4343 §4.1 | Replies keep the question's case |
//! | RFC 4592 | Wildcards |
//! | RFC 4892 §2 | CHAOS-class names a server answers about itself |
//! | RFC 5001 | NSID, only when asked |
//! | RFC 5452 §9.1 | A reply counts only from the address asked, with the query's ID and question |
//! | RFC 5155 §7.2 | NSEC3 denial records |
//! | RFC 6303, RFC 6761, RFC 6762, RFC 7686, RFC 8375, RFC 9462, RFC 9665 | Locally served zones ([`zone::special`]) |
//! | RFC 6604 §2 | The RCODE after a CNAME chain |
//! | RFC 6672 | DNAME |
//! | RFC 6891 §6.1.2, §6.1.4, §7 | No OPT without one in the query; unknown options and flags ignored |
//! | RFC 8020 | Nothing exists below a name that does not exist |
//! | RFC 8482 §4 | Answers to QTYPE ANY |
//! | RFC 8914 §4.21 | REFUSED with Extended DNS Error 20 outside the hosted zones |
//! | RFC 8976 | ZONEMD records in master files |
//! | RFC 9471 §3 | Glue in referrals |
//!
//! The resolver follows more; [`resolver`] lists them.

pub mod authority;
mod clock;
mod event;
mod exchange;
mod lookup;
pub mod memory;
mod records;
pub mod resolver;
pub mod zone;

pub use clock::WallClock;
pub use event::{Event, LookupOutcome, QueryFlags, ReplyFlags, Unmatched, UpstreamOutcome};
pub use exchange::{
    Action, Answer, Client, ClientQuery, Engine, ExchangeFailure, Generation, Input, Session,
    Token, Tokens, Transmit,
};
pub use lookup::{Looked, Lookup};
