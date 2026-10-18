//! `web::Sites`, in one process. Each test plays one or more sandboxes:
//! raw packets on the attachment's cable, or a machine built from stdlib
//! parts (`split_protocols`, `tcp::endpoint`, `udp::endpoint`) with a
//! rustls client and a hyper client on top.

use crate::common::io;
use fictionet_test_support::certs;
use fictionet_test_support::hyper_io;
use hyper_io::{Exec, Io};

use crate::common::world as run_world;
use fictionet::stdlib::world::sandbox::{TlsClient, TlsError};
use fictionet_test_support::{Done, timeout};

#[path = "web/admission.rs"]
mod admission;
#[path = "web/dns_dhcp.rs"]
mod dns_dhcp;
#[path = "web/events.rs"]
mod events;
#[path = "web/fixture.rs"]
mod fixture;
#[path = "web/http_serving.rs"]
mod http_serving;
#[path = "web/ipv6.rs"]
mod ipv6;
#[path = "web/sites.rs"]
mod sites;

use certs::certs;
use fictionet::stdlib::world::sandbox::Machine;
use fictionet::stdlib::world::sandbox::machine;
use fictionet_test_support::within;
use fixture::{
    BIG, BOTH_ADDR, Client, DEFAULT_ADDR, DUAL_ADDR, DUAL_ADDR6, EVENTS_ADDR, Env, GATEWAY, Plain,
    SECURE_ADDR, SHORT, TLS_DEFAULT_ADDR, V6ONLY_ADDR6, bind_by_ping, default_machine, dns, ipv4,
    lookup, parse, parse_dns, ping, plain_client, recv_within, sites, tls_connect, udp, world,
};

use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use axum::Extension;
use bytes::Bytes;
use fictionet::events::{Event as Entry, EventLog, Fields, Sandbox};
use fictionet::prelude::*;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::dns::op::{Message, MessageType, OpCode, Query, ResponseCode};
use fictionet::stdlib::protocols::dns::rr::{Name, RData, RecordType};
use fictionet::stdlib::services::tls;
use fictionet::stdlib::{
    network::{ConnError, Connection, ip, tcp},
    protocols::{dhcp, http1},
    web,
};
use fictionet::{Attacher, Cx, End, Interface, Packet, Seed, block_on, lab, run};
use http::{HeaderMap, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Empty, Full};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, RootCertStore};
