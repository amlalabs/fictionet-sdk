//! QUIC version 2 and version negotiation between two engines
//!
//! Each test checks the versions both connections settle on, the versions
//! of the long headers that crossed the wire, and that 1-RTT data flows,
//! which needs both sides to derive the same version's keys.

use super::*;
use crate::crypto::rustls::QuicClientConfig;
use crate::version::{VersionList, QUIC_V1, QUIC_V2};
use rustls::client::WebPkiServerVerifier;

/// A pair whose server endpoint accepts `server_versions`, most preferred first
fn pair_with_server_versions(server_versions: &[u32]) -> Pair {
    let mut server_endpoint = EndpointConfig::default();
    server_endpoint.supported_versions(server_versions.to_vec());
    let client = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);
    let server = Endpoint::new(
        Arc::new(server_endpoint),
        Some(Arc::new(server_config())),
        true,
        None,
    );
    Pair::new_from_endpoint(client, server)
}

fn client_in(version: u32, preferred: &[u32]) -> ClientConfig {
    let mut config = client_config();
    config
        .version(version)
        .preferred_versions(VersionList::new(preferred).unwrap());
    config
}

/// Versions of the long header datagrams `sender` sent
fn sent_by(pair: &Pair, sender: Side) -> Vec<u32> {
    pair.long_versions
        .iter()
        .filter(|(side, _)| *side == sender)
        .map(|&(_, version)| version)
        .collect()
}

/// Send a message each way over a fresh bidirectional stream
fn exchange(pair: &mut Pair, client_ch: ConnectionHandle, server_ch: ConnectionHandle) {
    const REQUEST: &[u8] = b"request over version negotiation";
    const RESPONSE: &[u8] = b"response";
    let s = pair.client_streams(client_ch).open(Dir::Bi).unwrap();
    pair.client_send(client_ch, s).write(REQUEST).unwrap();
    pair.client_send(client_ch, s).finish().unwrap();
    pair.drive();
    assert_matches!(
        pair.server_streams(server_ch).accept(Dir::Bi),
        Some(stream) if stream == s
    );
    let mut recv = pair.server_recv(server_ch, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(chunks.next(usize::MAX), Ok(Some(chunk)) if chunk.bytes[..] == *REQUEST);
    let _ = chunks.finalize();
    pair.server_send(server_ch, s).write(RESPONSE).unwrap();
    pair.server_send(server_ch, s).finish().unwrap();
    pair.drive();
    let mut recv = pair.client_recv(client_ch, s);
    let mut chunks = recv.read(false).unwrap();
    assert_matches!(chunks.next(usize::MAX), Ok(Some(chunk)) if chunk.bytes[..] == *RESPONSE);
    let _ = chunks.finalize();
}

fn assert_versions(
    pair: &mut Pair,
    client_ch: ConnectionHandle,
    server_ch: ConnectionHandle,
    version: u32,
) {
    assert_eq!(pair.client_conn_mut(client_ch).version(), version);
    assert_eq!(pair.server_conn_mut(server_ch).version(), version);
}

#[test]
fn a_version_2_first_flight_completes_in_version_2() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect_with(client_in(QUIC_V2, &[QUIC_V2]));
    assert_versions(&mut pair, client_ch, server_ch, QUIC_V2);
    exchange(&mut pair, client_ch, server_ch);
    assert!(!pair.long_versions.is_empty());
    assert!(pair
        .long_versions
        .iter()
        .all(|&(_, version)| version == QUIC_V2));
}

#[test]
fn a_server_preferring_version_2_upgrades_a_version_1_first_flight() {
    let _guard = subscribe();
    let mut pair = pair_with_server_versions(&[QUIC_V2, QUIC_V1]);
    let (client_ch, server_ch) = pair.connect_with(client_in(QUIC_V1, &[QUIC_V2, QUIC_V1]));
    assert_versions(&mut pair, client_ch, server_ch, QUIC_V2);
    exchange(&mut pair, client_ch, server_ch);

    let client = sent_by(&pair, Side::Client);
    let server = sent_by(&pair, Side::Server);
    assert_eq!(
        client[0], QUIC_V1,
        "the first flight is in the original version"
    );
    // The server sends all its CRYPTO data in the negotiated version.
    assert!(
        server.iter().all(|&version| version == QUIC_V2),
        "{server:x?}"
    );
    // After learning the version, the client sends only version 2.
    let switched = client
        .iter()
        .position(|&version| version == QUIC_V2)
        .unwrap();
    assert!(client[switched..].iter().all(|&version| version == QUIC_V2));
}

#[test]
fn a_server_keeps_version_1_unless_the_client_offers_version_2() {
    let _guard = subscribe();
    let mut pair = pair_with_server_versions(&[QUIC_V2, QUIC_V1]);
    let (client_ch, server_ch) = pair.connect_with(client_in(QUIC_V1, &[QUIC_V1]));
    assert_versions(&mut pair, client_ch, server_ch, QUIC_V1);
    exchange(&mut pair, client_ch, server_ch);
    assert!(pair
        .long_versions
        .iter()
        .all(|&(_, version)| version == QUIC_V1));

    // A server preferring version 1 keeps it even when version 2 is offered.
    let mut pair = Pair::default();
    let (client_ch, server_ch) = pair.connect_with(client_in(QUIC_V1, &[QUIC_V2, QUIC_V1]));
    assert_versions(&mut pair, client_ch, server_ch, QUIC_V1);
}

#[test]
fn a_version_2_retry_is_followed_in_version_2() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    pair.server.handle_incoming = Box::new(validate_incoming);
    let (client_ch, server_ch) = pair.connect_with(client_in(QUIC_V2, &[QUIC_V2]));
    assert_versions(&mut pair, client_ch, server_ch, QUIC_V2);
    exchange(&mut pair, client_ch, server_ch);
    // The Retry is the server's first datagram.
    assert_eq!(sent_by(&pair, Side::Server)[0], QUIC_V2);
    assert!(pair
        .long_versions
        .iter()
        .all(|&(_, version)| version == QUIC_V2));
}

#[test]
fn a_retry_stays_in_the_original_version_before_an_upgrade() {
    let _guard = subscribe();
    let mut pair = pair_with_server_versions(&[QUIC_V2, QUIC_V1]);
    pair.server.handle_incoming = Box::new(validate_incoming);
    let (client_ch, server_ch) = pair.connect_with(client_in(QUIC_V1, &[QUIC_V2, QUIC_V1]));
    assert_versions(&mut pair, client_ch, server_ch, QUIC_V2);
    exchange(&mut pair, client_ch, server_ch);
    let client = sent_by(&pair, Side::Client);
    let server = sent_by(&pair, Side::Server);
    // Retry and the Initial carrying its token use the original version
    // (RFC 9369 section 4.1); the answer to that Initial upgrades.
    assert_eq!(&client[..2], &[QUIC_V1, QUIC_V1]);
    assert_eq!(server[0], QUIC_V1);
    assert!(
        server[1..].iter().all(|&version| version == QUIC_V2),
        "{server:x?}"
    );
}

#[test]
fn version_negotiation_moves_the_client_to_a_version_the_server_lists() {
    let _guard = subscribe();
    let mut pair = pair_with_server_versions(&[QUIC_V2]);
    let (client_ch, server_ch) = pair.connect_with(client_in(QUIC_V1, &[QUIC_V1, QUIC_V2]));
    assert_versions(&mut pair, client_ch, server_ch, QUIC_V2);
    exchange(&mut pair, client_ch, server_ch);
    let client = sent_by(&pair, Side::Client);
    let server = sent_by(&pair, Side::Server);
    assert_eq!(client[0], QUIC_V1);
    assert_eq!(server[0], 0, "a Version Negotiation packet");
    assert!(
        client[1..].iter().all(|&version| version == QUIC_V2),
        "{client:x?}"
    );
    assert!(
        server[1..].iter().all(|&version| version == QUIC_V2),
        "{server:x?}"
    );
}

/// RFC 9368 section 2.3, Figure 1: incompatible negotiation into a version
/// the server then upgrades from. The downgrade check judges the version
/// the client attempted after Version Negotiation, not the one the server
/// upgraded to, so this genuine negotiation completes.
#[test]
fn version_negotiation_followed_by_a_compatible_upgrade_completes() {
    let _guard = subscribe();
    const DRAFT: u32 = 0xff00_0020;
    let mut client_endpoint = EndpointConfig::default();
    client_endpoint.supported_versions(vec![QUIC_V2, QUIC_V1, DRAFT]);
    let client = Endpoint::new(Arc::new(client_endpoint), None, true, None);
    let mut server_endpoint = EndpointConfig::default();
    server_endpoint.supported_versions(vec![QUIC_V1, QUIC_V2]);
    let server = Endpoint::new(
        Arc::new(server_endpoint),
        Some(Arc::new(server_config())),
        true,
        None,
    );
    let mut pair = Pair::new_from_endpoint(client, server);
    // The server cannot read the draft, lists 1 and 2, the client restarts
    // in its preferred 2 and the server, preferring 1, upgrades to 1.
    let (client_ch, server_ch) = pair.connect_with(client_in(DRAFT, &[QUIC_V2, QUIC_V1, DRAFT]));
    assert_versions(&mut pair, client_ch, server_ch, QUIC_V1);
    exchange(&mut pair, client_ch, server_ch);
    let client = sent_by(&pair, Side::Client);
    let server = sent_by(&pair, Side::Server);
    assert_eq!(client[0], DRAFT);
    assert_eq!(server[0], 0, "a Version Negotiation packet");
    assert_eq!(client[1], QUIC_V2, "the restart uses the chosen version");
    assert!(
        server[1..].iter().all(|&version| version == QUIC_V1),
        "{server:x?}"
    );
}

#[test]
fn a_client_without_a_listed_version_gives_up() {
    let _guard = subscribe();
    let mut pair = pair_with_server_versions(&[QUIC_V2]);
    let client_ch = pair.begin_connect(client_in(QUIC_V1, &[QUIC_V1]));
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::VersionMismatch
        })
    );
}

/// The client's first datagram, held back, with its connection IDs
fn intercept_first_flight(pair: &mut Pair) -> (ConnectionId, ConnectionId) {
    pair.client.drive(pair.time, pair.server.addr);
    let (_, datagram) = pair.client.outbound.pop_front().unwrap();
    pair.client.outbound.clear();
    let dcid_len = usize::from(datagram[5]);
    let dcid = ConnectionId::new(&datagram[6..6 + dcid_len]);
    let scid_len = usize::from(datagram[6 + dcid_len]);
    let scid = ConnectionId::new(&datagram[7 + dcid_len..7 + dcid_len + scid_len]);
    (dcid, scid)
}

/// A Version Negotiation packet answering a client's first flight
fn version_negotiation(dcid: ConnectionId, scid: ConnectionId, versions: &[u32]) -> BytesMut {
    let mut packet = BytesMut::new();
    packet.extend_from_slice(&[0xc5, 0, 0, 0, 0]);
    packet.extend_from_slice(&[scid.len() as u8]);
    packet.extend_from_slice(&scid);
    packet.extend_from_slice(&[dcid.len() as u8]);
    packet.extend_from_slice(&dcid);
    for version in versions {
        packet.extend_from_slice(&version.to_be_bytes());
    }
    packet
}

#[test]
fn a_forged_version_negotiation_is_caught_by_the_servers_versions() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let client_ch = pair.begin_connect(client_in(QUIC_V2, &[QUIC_V2, QUIC_V1]));
    let (dcid, scid) = intercept_first_flight(&mut pair);
    // An attacker claims the server speaks only version 1.
    let forged = version_negotiation(dcid, scid, &[QUIC_V1]);
    pair.client.inbound.push_back((pair.time, None, forged));
    pair.drive();
    // The server lists both versions, so the client would have kept 2.
    let lost =
        iter::from_fn(|| pair.client_conn_mut(client_ch).poll()).find_map(|event| match event {
            Event::ConnectionLost { reason } => Some(reason),
            _ => None,
        });
    assert_matches!(
        lost,
        Some(ConnectionError::TransportError(TransportError {
            code: TransportErrorCode::VERSION_NEGOTIATION_ERROR,
            ..
        }))
    );
}

#[test]
fn version_negotiation_listing_the_original_version_is_ignored() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let client_ch = pair.begin_connect(client_in(QUIC_V1, &[QUIC_V2, QUIC_V1]));
    let (dcid, scid) = intercept_first_flight(&mut pair);
    let forged = version_negotiation(dcid, scid, &[QUIC_V1, QUIC_V2]);
    pair.client.inbound.push_back((pair.time, None, forged));
    pair.drive();
    // The lost first flight is sent again in version 1 and succeeds.
    let server_ch = pair.server.assert_accept();
    pair.finish_connect(client_ch, server_ch);
    assert_versions(&mut pair, client_ch, server_ch, QUIC_V1);
}

/// Whether the client's pending first datagram, an Initial in `version`,
/// carries a ClientHello offering a session ticket: the pre_shared_key
/// extension (RFC 8446 section 4.2.11)
fn first_flight_offers_a_ticket(pair: &mut Pair, version: u32) -> bool {
    use crate::coding::BufExt;
    use bytes::Buf;

    pair.client.drive(pair.time, pair.server.addr);
    let (_, datagram) = pair.client.outbound.front().unwrap();
    let (decode, _) = PartialDecode::new(
        datagram[..].into(),
        &FixedLengthConnectionIdParser::new(0),
        &[version],
        // A resuming client may grease the fixed bit (RFC 9287).
        true,
    )
    .unwrap();
    let suite =
        crate::crypto::rustls::initial_suite_from_provider(&Arc::new(default_provider())).unwrap();
    let tls_version = match version {
        QUIC_V2 => rustls::quic::Version::V2,
        _ => rustls::quic::Version::V1,
    };
    let keys =
        crate::crypto::rustls::initial_keys(tls_version, *decode.dst_cid(), Side::Server, &suite);
    let mut packet = decode.finish(Some(&*keys.header.remote)).unwrap();
    let number = packet.header.number().unwrap().expand(0);
    packet
        .payload
        .decrypt(&*keys.packet.remote, number, &packet.header_data)
        .unwrap();
    let mut frames = &packet.payload[..];
    // The first flight opens with the ClientHello's CRYPTO frame.
    assert_eq!(frames.get_var().unwrap(), 0x06);
    assert_eq!(frames.get_var().unwrap(), 0);
    let len = frames.get_var().unwrap() as usize;
    let mut hello = &frames[..len];
    hello.advance(4 + 2 + 32);
    let session_id = hello.get_u8() as usize;
    hello.advance(session_id);
    let suites = hello.get_u16() as usize;
    hello.advance(suites);
    let compression = hello.get_u8() as usize;
    hello.advance(compression);
    let extensions_len = hello.get_u16() as usize;
    let mut extensions = &hello[..extensions_len];
    while extensions.has_remaining() {
        let kind = extensions.get_u16();
        let len = extensions.get_u16() as usize;
        if kind == 41 {
            return true;
        }
        extensions.advance(len);
    }
    false
}

#[test]
fn session_tickets_resume_only_their_own_version() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let first = |pair: &mut Pair, config: ClientConfig| {
        let client_ch = pair.begin_connect(config);
        pair.drive();
        pair.server.assert_accept();
        pair.client.connections.get_mut(&client_ch).unwrap().close(
            pair.time,
            VarInt(0),
            [][..].into(),
        );
        pair.drive();
        pair.client.addr = SocketAddr::new(
            Ipv6Addr::LOCALHOST.into(),
            CLIENT_PORTS.lock().unwrap().next().unwrap(),
        );
    };
    let v1 = client_in(QUIC_V1, &[QUIC_V1]);
    let v2 = client_in(QUIC_V2, &[QUIC_V2]);
    // One crypto configuration, so one session store, for every connection.
    let v2 = ClientConfig {
        crypto: v1.crypto.clone(),
        ..v2
    };
    first(&mut pair, v1.clone());
    // A version 1 ticket does not start a version 2 connection's 0-RTT.
    let client_ch = pair.begin_connect(v2.clone());
    assert!(!pair.client_conn_mut(client_ch).has_0rtt());
    assert!(!first_flight_offers_a_ticket(&mut pair, QUIC_V2));
    pair.drive();
    pair.server.assert_accept();
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(0), [][..].into());
    pair.drive();
    pair.client.addr = SocketAddr::new(
        Ipv6Addr::LOCALHOST.into(),
        CLIENT_PORTS.lock().unwrap().next().unwrap(),
    );
    // The version 2 connection left a version 2 ticket, which does.
    let client_ch = pair.begin_connect(v2);
    assert!(pair.client_conn_mut(client_ch).has_0rtt());
    assert!(first_flight_offers_a_ticket(&mut pair, QUIC_V2));
    pair.drive();
    assert!(pair.client_conn_mut(client_ch).accepted_0rtt());
    assert_eq!(pair.client_conn_mut(client_ch).version(), QUIC_V2);
}

/// A client session store that relabels every ticket it hands out as a
/// version 2 ticket, as a client ignoring RFC 9369 section 5 would
#[derive(Debug)]
struct Relabel(rustls::client::ClientSessionMemoryCache);

impl rustls::client::ClientSessionStore for Relabel {
    fn set_kx_hint(&self, name: rustls::pki_types::ServerName<'static>, group: rustls::NamedGroup) {
        self.0.set_kx_hint(name, group)
    }

    fn kx_hint(&self, name: &rustls::pki_types::ServerName<'_>) -> Option<rustls::NamedGroup> {
        self.0.kx_hint(name)
    }

    fn set_tls12_session(
        &self,
        name: rustls::pki_types::ServerName<'static>,
        value: rustls::client::Tls12ClientSessionValue,
    ) {
        self.0.set_tls12_session(name, value)
    }

    fn tls12_session(
        &self,
        name: &rustls::pki_types::ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        self.0.tls12_session(name)
    }

    fn remove_tls12_session(&self, name: &rustls::pki_types::ServerName<'static>) {
        self.0.remove_tls12_session(name)
    }

    fn insert_tls13_ticket(
        &self,
        name: rustls::pki_types::ServerName<'static>,
        value: rustls::client::Tls13ClientSessionValue,
    ) {
        self.0.insert_tls13_ticket(name, value)
    }

    fn take_tls13_ticket(
        &self,
        name: &rustls::pki_types::ServerName<'static>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        let mut ticket = self.0.take_tls13_ticket(name)?;
        ticket.set_quic_version(rustls::quic::Version::V2);
        // The remembered server parameters name the version too.
        let mut params =
            TransportParameters::read(Side::Client, &mut &ticket.quic_params()[..]).unwrap();
        if let Some(info) = params.version_information.as_mut() {
            info.chosen = QUIC_V2;
        }
        let mut bytes = Vec::new();
        params.write(&mut bytes);
        ticket.set_quic_params(&bytes);
        Some(ticket)
    }
}

#[test]
fn a_server_refuses_a_ticket_from_another_version() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let mut crypto = QuicClientConfig::inner(
        WebPkiServerVerifier::builder_with_provider(
            Arc::new({
                let mut roots = rustls::RootCertStore::empty();
                roots.add(CERTIFIED_KEY.cert.der().clone()).unwrap();
                roots
            }),
            crate::crypto::rustls::configured_provider(),
        )
        .build()
        .unwrap(),
    );
    crypto.resumption = rustls::client::Resumption::store(Arc::new(Relabel(
        rustls::client::ClientSessionMemoryCache::new(8),
    )));
    let crypto: Arc<dyn crypto::ClientConfig> =
        Arc::new(QuicClientConfig::try_from(crypto).unwrap());
    let config = |version| {
        let mut config = client_in(version, &[version]);
        config.crypto = crypto.clone();
        config
    };

    let client_ch = pair.begin_connect(config(QUIC_V1));
    pair.drive();
    pair.server.assert_accept();
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(0), [][..].into());
    pair.drive();
    pair.client.addr = SocketAddr::new(
        Ipv6Addr::LOCALHOST.into(),
        CLIENT_PORTS.lock().unwrap().next().unwrap(),
    );

    // The client offers the version 1 ticket, labelled 2, with 0-RTT.
    let client_ch = pair.begin_connect(config(QUIC_V2));
    assert!(pair.client_conn_mut(client_ch).has_0rtt());
    pair.drive();
    // The server's ticket records version 1, so it runs a full handshake.
    let server_ch = pair.server.assert_accept();
    assert!(!pair.client_conn_mut(client_ch).accepted_0rtt());
    assert_versions(&mut pair, client_ch, server_ch, QUIC_V2);
    exchange(&mut pair, client_ch, server_ch);
}
