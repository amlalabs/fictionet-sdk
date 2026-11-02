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
//! | RFC 3597 | Unknown record types in master files |
//! | RFC 4035 §3.1, §3.2.1 | RRSIGs and denial records only for DO, DS from the parent side |
//! | RFC 4592 | Wildcards |
//! | RFC 5155 §7.2 | NSEC3 denial records |
//! | RFC 6303, RFC 6761, RFC 7686, RFC 8375, RFC 9462 | Locally served zones ([`zone::special`]) |
//! | RFC 6604 §2 | The RCODE after a CNAME chain |
//! | RFC 6672 | DNAME |
//! | RFC 8020 | Nothing exists below a name that does not exist |
//! | RFC 8482 §4 | Answers to QTYPE ANY |
//! | RFC 8976 | ZONEMD records in master files |
//! | RFC 9471 §3 | Glue in referrals |

mod clock;
pub mod zone;

pub use clock::WallClock;
