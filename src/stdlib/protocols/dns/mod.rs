//! DNS: the `hickory-proto` crate, re-exported, and the wire rules a
//! server or relay needs that hickory leaves out.
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
//! | [`fit`] | Writes a reply within the requestor's size: whole RRsets, needed data first, TC only when that data does not fit. |
//! | [`restore`] | Gives a relayed reply the client's ID and question case and changes nothing else. |
//! | [`Ede`], [`Nsid`], [`Padding`] | EDNS options hickory carries as raw bytes or its own type (RFC 8914, 5001, 7830). |
//!
//! A DNS server is a loop on a UDP socket from
//! [`udp::endpoint`](fictionet::stdlib::network::udp::endpoint). Which names exist, and
//! whether answers are wrong, slow or missing, is all up to world code.
//! This server knows one zone, `stripe.com`, with one name in it,
//! `api.stripe.com`. Every other name in the zone gets NXDOMAIN with the
//! zone's SOA in the authority section, which a resolver needs to cache
//! the negative answer (RFC 2308 §3). A name outside the zone is refused:
//!
//! ```no_run
//! use fictionet::prelude::*;
//! use fictionet::stdlib::protocols::dns::op::{Message, ResponseCode};
//! use fictionet::stdlib::protocols::dns::rr::rdata::{A, SOA};
//! use fictionet::stdlib::protocols::dns::rr::{Name, RData, Record};
//! use fictionet::stdlib::protocols::dns::{Limit, Parsed, Request, Response, fit};
//! use fictionet::stdlib::services::serve::Transport;
//! use fictionet::{Cx, Result, stdlib::network::udp};
//!
//! async fn serve_dns(fcx: &Cx, socket: &mut udp::Socket) -> Result {
//!     let zone = Name::from_ascii("stripe.com.")?;
//!     let api = Name::from_ascii("api.stripe.com.")?;
//!     let soa = SOA::new(
//!         Name::from_ascii("ns1.stripe.com.")?,
//!         Name::from_ascii("hostmaster.stripe.com.")?,
//!         2026110101, 7200, 3600, 1209600, 300,
//!     );
//!     while let Ok((bytes, from)) = socket.recv(fcx).await {
//!         let request = match Request::parse(&bytes, Transport::Udp) {
//!             Parsed::Request(request) => request,
//!             Parsed::Reject(reply) => {
//!                 socket.send_to(&reply.to_vec()?, from);
//!                 continue;
//!             }
//!             Parsed::Silent => continue,
//!         };
//!
//!         let mut reply = Message::response(request.message.metadata.id, request.message.metadata.op_code);
//!         reply.metadata.authoritative = true;
//!         reply.metadata.recursion_desired = request.rd;
//!         reply.add_query(request.question.clone());
//!         let name = request.question.name();
//!         if *name == api {
//!             let ip = A("104.18.32.7".parse()?);
//!             reply.add_answer(Record::from_rdata(name.clone(), 300, RData::A(ip)));
//!         } else if zone.zone_of(name) {
//!             reply.metadata.response_code = ResponseCode::NXDomain;
//!             reply.add_authority(Record::from_rdata(zone.clone(), 300, RData::SOA(soa.clone())));
//!         } else {
//!             reply.metadata.authoritative = false;
//!             reply.metadata.response_code = ResponseCode::Refused;
//!         }
//!
//!         let limit = Limit::for_request(&request, 1232);
//!         let response = Response { message: reply, required_additional: 0 };
//!         socket.send_to(&fit(&response, limit)?.bytes, from);
//!     }
//!     Ok(())
//! }
//! ```

pub use hickory_proto::*;

pub mod dnssec;
mod fit;
mod framing;
mod options;
mod relay;
mod request;

pub use fit::{Fitted, Limit, Response, fit};
pub use framing::{Framing, Queries, stream_framed};
pub use options::{Ede, EdeCode, Nsid, Padding};
pub use relay::{RelayError, restore};
pub use request::{EdnsIn, Parsed, Request};
