//! Traffic the honeypot's server starts: a TCP and a UDP exchange with a
//! peer through the same attachment the internet comes in by, then an
//! inbound HTTP request on that attachment.

use std::net::{Ipv4Addr, SocketAddr};

use fictionet::Cx;
use fictionet::stdlib::network::{Connection, ConnectionExt, ip};
use fictionet::stdlib::world::net::Endpoints;
use honeypot_world::Honeypot;

use super::capture::{Capture, endpoints};

/// The server that starts the exchanges.
pub const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
/// The server it starts them with.
pub const PEER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

const PORT: u16 = 18081;
const TCP_BYTES: usize = 4096;
const UDP_BYTES: usize = 1024;

/// The peer's answer to a challenge: its bytes reversed and flipped.
fn answer(bytes: &mut [u8]) {
    bytes.reverse();
    for byte in bytes {
        *byte ^= 0xa5;
    }
}

async fn read_exact(fcx: &Cx, connection: &mut impl Connection, mut bytes: &mut [u8]) {
    while !bytes.is_empty() {
        let count = connection.read(fcx, bytes).await.unwrap();
        assert_ne!(count, 0, "the peer closed before its whole answer");
        bytes = &mut bytes[count..];
    }
}

async fn exchange(fcx: &Cx, machine: Endpoints) -> fictionet::Result {
    let remote = SocketAddr::new(PEER.into(), PORT);
    let mut sent = vec![0; TCP_BYTES];
    fcx.fill_random(&mut sent);
    let mut tcp = machine.tcp.connect(fcx, remote).await?;
    assert_eq!(tcp.local_addr().ip(), CLIENT);
    assert_eq!(tcp.peer_addr(), remote);
    tcp.write_all(fcx, &sent).await?;
    let mut received = vec![0; sent.len()];
    read_exact(fcx, &mut tcp, &mut received).await;
    answer(&mut sent);
    assert_eq!(received, sent, "TCP answer");

    let mut udp = machine.udp.bind(0)?;
    sent.resize(UDP_BYTES, 0);
    fcx.fill_random(&mut sent);
    udp.send_to(&sent, remote);
    let (received, from) = udp.recv(fcx).await?;
    answer(&mut sent);
    assert_eq!(from, remote);
    assert_eq!(received, sent, "UDP answer");
    Ok(())
}

async fn peer(
    fcx: Cx,
    machine: Endpoints,
    ready: tokio::sync::oneshot::Sender<()>,
) -> fictionet::Result {
    let mut listener = machine.tcp.listen(PORT)?;
    let mut udp = machine.udp.bind(PORT)?;
    let _ = ready.send(());
    let mut tcp = listener.accept(&fcx).await?;
    assert_eq!(tcp.peer_addr().ip(), CLIENT);
    let mut bytes = vec![0; TCP_BYTES];
    read_exact(&fcx, &mut tcp, &mut bytes).await;
    answer(&mut bytes);
    tcp.write_all(&fcx, &bytes).await?;

    let (mut bytes, from) = udp.recv(&fcx).await?;
    assert_eq!(from.ip(), CLIENT);
    assert_eq!(bytes.len(), UDP_BYTES);
    answer(&mut bytes);
    udp.send_to(&bytes, from);

    let mut inbound = machine
        .tcp
        .connect(&fcx, SocketAddr::new(CLIENT.into(), 80))
        .await?;
    inbound
        .write_all(
            &fcx,
            b"GET / HTTP/1.1\r\nHost: decoy\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut status = [0; 12];
    read_exact(&fcx, &mut inbound, &mut status).await;
    assert_eq!(&status, b"HTTP/1.1 200", "inbound HTTP status line");
    Ok(())
}

/// Runs the exchanges from `client`'s server to `remote`'s, and the
/// inbound HTTP request back, and waits for both sides to finish.
pub async fn exchanges(fcx: &Cx, client: &Honeypot, remote: &Honeypot) -> fictionet::Result {
    let remote = endpoints(remote).await?;
    let client = endpoints(client).await?;
    let (ready, waiting) = tokio::sync::oneshot::channel();
    let (done, finished) = tokio::sync::oneshot::channel();
    fcx.spawn(move |fcx| async move {
        peer(fcx, remote, ready).await?;
        let _ = done.send(());
        Ok(())
    });
    waiting.await?;
    exchange(fcx, client).await?;
    finished.await?;
    Ok(())
}

/// Checks that the client's capture holds the SYN it sent, the SYN-ACK
/// that came back, and the UDP datagrams both ways, all with valid
/// transport checksums.
pub fn check(pcap: &Capture) {
    let mut seen = [false; 4];
    for packet in pcap.packets() {
        let header = ip::Header::parse_whole(&packet).expect("captured IP packet");
        let outbound = header.src == CLIENT && header.dst == PEER;
        let inbound = header.src == PEER && header.dst == CLIENT;
        if (!outbound && !inbound) || !matches!(header.protocol, 6 | 17) {
            continue;
        }
        let payload = header.payload(&packet);
        assert_eq!(
            ip::transport_checksum(header.src, header.dst, header.protocol, payload),
            0,
            "captured transport checksum"
        );
        if header.protocol == 6 && payload.len() >= 20 {
            seen[0] |=
                outbound && payload[2..4] == PORT.to_be_bytes() && payload[13] & 0x12 == 0x02;
            seen[1] |= inbound && payload[..2] == PORT.to_be_bytes() && payload[13] & 0x12 == 0x12;
        }
        if header.protocol == 17 && payload.len() == UDP_BYTES + 8 {
            seen[2] |= outbound && payload[2..4] == PORT.to_be_bytes();
            seen[3] |= inbound && payload[..2] == PORT.to_be_bytes();
        }
    }
    assert_eq!(seen, [true; 4], "SYN out, SYN-ACK in, UDP out, UDP in");
}
