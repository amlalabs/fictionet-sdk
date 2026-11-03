//! DNS: the `hickory-proto` crate, re-exported, and the wire rules a
//! server needs that hickory leaves out.
//!
//! Use this module to read and answer DNS queries in a world that runs its
//! own DNS server. If the world is a set of websites,
//! [`web::Sites`](fictionet::stdlib::web::Sites) already runs one for you.
//! [`net::Net`](fictionet::stdlib::world::net::Net) runs a recursive resolver
//! like Unbound at each gateway, on UDP and TCP port 53, which answers the
//! names the network's hosts declare and has no route to the internet. Its
//! engines are in [`services::dns`](fictionet::stdlib::services::dns), and
//! the programs that run them on a host, authoritative servers among them,
//! are in [`net::dns`](fictionet::stdlib::world::net::dns).
//!
//! A DNS message is plain data: a [`Message`](op::Message) with public
//! `queries` and `answers` lists. hickory's `dnssec-ring` feature is on, so
//! DNSKEY, DS, RRSIG, NSEC, and NSEC3 records are typed too. Around those
//! types this module adds what a server does with a message on the wire:
//!
//! | Item | What it does |
//! | --- | --- |
//! | [`Queries`] | Frames messages, one per datagram or after a two-octet length on a stream (RFC 1035 §4.2.2). |
//! | [`Request::parse`] | Checks a query in one fixed order and gives a request, a rejection to send, or silence. |
//! | [`read_message`] | Reads a message as hickory does, and also with records whose RDATA is empty (RFC 3597 §4). |
//! | [`fit`] | Writes a reply within the requestor's size: whole RRsets, needed data first, TC only when that data does not fit. |
//! | [`Ede`], [`Nsid`], [`Padding`] | EDNS options hickory carries as raw bytes or its own type (RFC 8914, 5001, 7830). |
//! | [`label_count`], [`dname_substitute`] | Counts a name's labels with a leading `*`, and makes the name a DNAME substitutes (RFC 6672 §2.2). |
//!
//! A world's DNS server is a zone and an authoritative server program on
//! a host, which apply these rules on every reply: the engines in
//! [`services::dns`](fictionet::stdlib::services::dns) answer, and
//! [`Authoritative`](fictionet::stdlib::world::net::dns::Authoritative)
//! runs them on UDP and TCP port 53. Which names exist, and whether
//! answers are wrong, slow or missing, is all up to world code. This
//! server knows one zone, `stripe.com`, with `api.stripe.com` in it.
//! Every other name in the zone gets NXDOMAIN with the zone's SOA in the
//! authority section, which a resolver needs to cache the negative answer
//! (RFC 2308 §3), a name outside the zone is refused, and a query with
//! EDNS gets EDNS back (RFC 6891 §7):
//!
//! ```no_run
//! use std::net::Ipv4Addr;
//! use std::sync::Arc;
//!
//! use fictionet::stdlib::services::dns::authority::{ServerConfig, Zones};
//! use fictionet::stdlib::services::dns::zone::{Zone, ZoneData};
//! use fictionet::stdlib::world::net::Net;
//! use fictionet::stdlib::world::net::dns::Authoritative;
//! use fictionet::{Attachments, Cx, Result};
//!
//! async fn world(fcx: Cx, attachments: Attachments) -> Result {
//!     let zone = Zone::from_master(
//!         "$ORIGIN stripe.com.
//! $TTL 300
//! @   SOA ns1 hostmaster 2026110101 7200 3600 1209600 300
//! @   NS  ns1
//! ns1 A   104.18.32.5
//! api A   104.18.32.7
//! ",
//!         None,
//!     )?;
//!     let zones = Zones::new(vec![Arc::new(zone) as Arc<dyn ZoneData>]);
//!     let server = Authoritative::new(zones, ServerConfig::generic());
//!     Net::new()
//!         .host("ns1", |h| h.at(Ipv4Addr::new(104, 18, 32, 5)).program(server))
//!         .start(&fcx, attachments)?;
//!     Ok(())
//! }
//! ```
//!
//! A server with rules of its own, such as one that answers EDNS versions
//! above 0 the way Cloudflare's resolver does, writes an
//! [`Authority`](fictionet::stdlib::services::dns::authority::Authority)
//! or wraps one, and keeps the rules above through the same front.

pub use hickory_proto::*;

pub mod dnssec;
mod fit;
mod framing;
mod names;
mod options;
mod request;

pub use fit::{Fitted, Limit, Response, fit};
pub use framing::{Framing, Queries, stream_framed};
pub use names::{dname_substitute, label_count};
pub use options::{Ede, EdeCode, Nsid, Padding};
pub use request::{EdnsIn, Parsed, Request, read_message};
