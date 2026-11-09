//! Guest-only initiated traffic through the honeypot's packet backends.

use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use fictionet::Interface;
use fictionet::prelude::*;
use fictionet::stdlib::world::net::Endpoints;
use honeypot_world::{Clock, Config, Honeypot, observe::Sinks};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const PEER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const PORT: u16 = 18081;
const TCP_BYTES: usize = 4096;
const UDP_BYTES: usize = 1024;

#[derive(Clone, Default)]
pub(super) struct Capture(pub(super) Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn config(address: Ipv4Addr, gateway: Ipv4Addr) -> Config {
    Config {
        address,
        gateway,
        ..Config::default()
    }
}

fn sinks(capture: &Capture) -> Sinks {
    Sinks {
        log: Box::new(io::sink()),
        pcap: Box::new(capture.clone()),
    }
}

pub(super) fn endpoints(
    honeypot: &Honeypot,
) -> fictionet::Result<tokio::sync::oneshot::Receiver<Endpoints>> {
    let (send, receive) = tokio::sync::oneshot::channel();
    let send = Mutex::new(Some(send));
    honeypot.program(move |_fcx: fictionet::Cx, endpoints: Endpoints| {
        let _ = send.lock().unwrap().take().unwrap().send(endpoints);
        async { Ok(()) }
    })?;
    Ok(receive)
}

fn answer(bytes: &mut [u8]) {
    bytes.reverse();
    for byte in bytes {
        *byte ^= 0xa5;
    }
}

async fn read_exact(
    fcx: &fictionet::Cx,
    connection: &mut impl fictionet::stdlib::network::Connection,
    mut bytes: &mut [u8],
) -> fictionet::Result {
    while !bytes.is_empty() {
        let count = connection.read(fcx, bytes).await?;
        if count == 0 {
            return Err(fictionet::Error::msg(
                "peer closed before its complete payload",
            ));
        }
        bytes = &mut bytes[count..];
    }
    Ok(())
}

async fn exchange(fcx: &fictionet::Cx, machine: Endpoints) -> fictionet::Result {
    let remote = SocketAddr::new(PEER.into(), PORT);
    let mut sent = vec![0; TCP_BYTES];
    fcx.fill_random(&mut sent);
    let mut tcp = machine.tcp.connect(fcx, remote).await?;
    if tcp.local_addr().ip() != CLIENT || tcp.peer_addr() != remote {
        return Err(fictionet::Error::msg(
            "outbound TCP used the wrong addresses",
        ));
    }
    tcp.write_all(fcx, &sent).await?;
    let mut received = vec![0; sent.len()];
    read_exact(fcx, &mut tcp, &mut received).await?;
    answer(&mut sent);
    if received != sent {
        return Err(fictionet::Error::msg("TCP challenge reply differs"));
    }
    let mut udp = machine.udp.bind(0)?;
    sent.resize(UDP_BYTES, 0);
    fcx.fill_random(&mut sent);
    udp.send_to(&sent, remote);
    let (received, from) = udp.recv(fcx).await?;
    answer(&mut sent);
    if from != remote || received != sent {
        return Err(fictionet::Error::msg("UDP challenge reply differs"));
    }
    println!(
        "Initiated TCP {} -> {remote}: {TCP_BYTES} bytes verified; UDP {} -> {remote}: {UDP_BYTES} bytes verified",
        tcp.local_addr(),
        udp.local_addr()
    );
    Ok(())
}

async fn peer(
    fcx: fictionet::Cx,
    machine: Endpoints,
    ready: tokio::sync::oneshot::Sender<()>,
) -> fictionet::Result {
    let mut listener = machine.tcp.listen(PORT)?;
    let mut udp = machine.udp.bind(PORT)?;
    let _ = ready.send(());
    let mut tcp = listener.accept(&fcx).await?;
    if tcp.peer_addr().ip() != CLIENT {
        return Err(fictionet::Error::msg("peer saw wrong TCP source"));
    }
    let mut bytes = vec![0; TCP_BYTES];
    read_exact(&fcx, &mut tcp, &mut bytes).await?;
    answer(&mut bytes);
    tcp.write_all(&fcx, &bytes).await?;
    let (mut bytes, from) = udp.recv(&fcx).await?;
    if from.ip() != CLIENT || bytes.len() != UDP_BYTES {
        return Err(fictionet::Error::msg("peer saw wrong UDP datagram"));
    }
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
    read_exact(&fcx, &mut inbound, &mut status).await?;
    if &status != b"HTTP/1.1 200" {
        return Err(fictionet::Error::msg("inbound HTTP service failed"));
    }
    println!("Guest peer verified inbound HTTP still serves on the same attachment");
    Ok(())
}

fn evidence(capture: &Capture) -> fictionet::Result {
    use fictionet::stdlib::{codec::le32, network::ip};
    let bytes = capture.0.lock().unwrap();
    let mut blocks = bytes.as_slice();
    let mut seen = [false; 4];
    while !blocks.is_empty() {
        let length =
            le32(blocks, 4).ok_or_else(|| fictionet::Error::msg("truncated pcap"))? as usize;
        if length < 12 || length > blocks.len() || le32(blocks, length - 4) != Some(length as u32) {
            return Err(fictionet::Error::msg("invalid pcap block"));
        }
        let block = &blocks[..length];
        blocks = &blocks[length..];
        if le32(block, 0) != Some(6) {
            continue;
        }
        let count =
            le32(block, 20).ok_or_else(|| fictionet::Error::msg("missing packet length"))? as usize;
        let packet = block
            .get(28..28 + count)
            .ok_or_else(|| fictionet::Error::msg("truncated packet"))?;
        let header = ip::Header::parse_whole(packet)
            .ok_or_else(|| fictionet::Error::msg("invalid IP packet"))?;
        let outbound = header.src == CLIENT && header.dst == PEER;
        let inbound = header.src == PEER && header.dst == CLIENT;
        if (!outbound && !inbound) || !matches!(header.protocol, 6 | 17) {
            continue;
        }
        let payload = header.payload(packet);
        if ip::transport_checksum(header.src, header.dst, header.protocol, payload) != 0 {
            return Err(fictionet::Error::msg("bad transport checksum in capture"));
        }
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
    if !seen.into_iter().all(|value| value) {
        return Err(fictionet::Error::msg(format!(
            "attachment lacks initiated SYN, returning SYN-ACK or bidirectional UDP: {seen:?}"
        )));
    }
    println!(
        "Same attachment capture verified initiated SYN, returned SYN-ACK and both UDP directions"
    );
    Ok(())
}

async fn simulated_exchange(
    fcx: &fictionet::Cx,
    client: &Honeypot,
    remote: &Honeypot,
) -> fictionet::Result {
    let remote = endpoints(remote)?.await?;
    let client = endpoints(client)?.await?;
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

async fn world() -> fictionet::Result {
    let capture = Capture::default();
    let captured = capture.clone();
    fictionet::run(fictionet::Seed::random(), move |fcx| async move {
        let (client_attach, clients) = fictionet::attachments();
        let (peer_attach, peers) = fictionet::attachments();
        let mut client_end = client_attach.attach(honeypot_world::INTERNET)?;
        let mut peer_end = peer_attach.attach(honeypot_world::INTERNET)?;
        let client = honeypot_world::start(
            &fcx,
            &config(CLIENT, PEER),
            Clock::starting_now(),
            sinks(&captured),
            clients,
        )?;
        let remote = honeypot_world::start(
            &fcx,
            &config(PEER, CLIENT),
            Clock::starting_now(),
            sinks(&Capture::default()),
            peers,
        )?;
        fcx.spawn(move |fcx| async move {
            let _owners = (client_attach, peer_attach);
            loop {
                tokio::select! {
                    packet = client_end.recv(&fcx) => peer_end.send(packet?),
                    packet = peer_end.recv(&fcx) => client_end.send(packet?),
                }
            }
        });
        simulated_exchange(&fcx, &client, &remote).await?;
        fcx.cancel();
        Ok(())
    })
    .await?;
    evidence(&capture)
}

pub(super) fn prepare_device(device: &str) -> fictionet::Result<fictionet_host::VirtioNet> {
    let path = format!("/sys/bus/pci/devices/{device}");
    if std::path::Path::new(&format!("{path}/driver")).exists() {
        std::fs::write(format!("{path}/driver/unbind"), device)?;
    }
    std::fs::write(format!("{path}/driver_override"), "vfio-pci")?;
    std::fs::write("/sys/bus/pci/drivers_probe", device)?;
    Ok(fictionet_host::VirtioNet::open(device.parse()?)?)
}

async fn vfio() -> fictionet::Result {
    use fictionet_host::raw::RawPump;
    let (client_pump, client_raw) = RawPump::attach(prepare_device("0000:00:03.0")?)?;
    let (peer_pump, peer_raw) = RawPump::attach(prepare_device("0000:00:04.0")?)?;
    let capture = Capture::default();
    let captured = capture.clone();
    let result = fictionet::run(fictionet::Seed::random(), move |fcx| async move {
        let client = honeypot_world::start_raw(
            &fcx,
            &config(CLIENT, PEER),
            Clock::starting_now(),
            sinks(&captured),
            client_raw,
            Box::new(io::sink()),
        )?;
        let remote = honeypot_world::start_raw(
            &fcx,
            &config(PEER, CLIENT),
            Clock::starting_now(),
            sinks(&Capture::default()),
            peer_raw,
            Box::new(io::sink()),
        )?;
        simulated_exchange(&fcx, &client, &remote).await?;
        fcx.cancel();
        Ok(())
    })
    .await;
    let client_stopped = client_pump.shutdown();
    let peer_stopped = peer_pump.shutdown();
    result?;
    client_stopped?;
    peer_stopped?;
    evidence(&capture)
}

pub(super) fn prepare_tun(peer: Ipv4Addr) -> fictionet::Result<fictionet_host::tun::Tun> {
    use fictionet_host::tun::{Mode, Tun};
    let device = Tun::open("egress", Mode::Create)?;
    let control = std::net::UdpSocket::bind("0.0.0.0:0")?;
    for (operation, address) in [
        (libc::SIOCSIFADDR, peer),
        (libc::SIOCSIFNETMASK, Ipv4Addr::new(255, 255, 255, 0)),
    ] {
        // SAFETY: the initialized request holds a complete IPv4 sockaddr and a terminated interface name.
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        request.ifr_name[..6].copy_from_slice(&[
            b'e' as i8, b'g' as i8, b'r' as i8, b'e' as i8, b's' as i8, b's' as i8,
        ]);
        let mut data = [0; 14];
        // sockaddr stores the IPv4 port in the first two data bytes, then
        // the four address bytes, followed by eight zero padding bytes.
        for (byte, octet) in data[2..6].iter_mut().zip(address.octets()) {
            *byte = octet as libc::c_char;
        }
        request.ifr_ifru.ifru_addr = libc::sockaddr {
            sa_family: libc::AF_INET as libc::sa_family_t,
            sa_data: data,
        };
        // SAFETY: the control descriptor is live and request is a complete mutable ifreq.
        if unsafe { libc::ioctl(control.as_raw_fd(), operation, &mut request) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    Ok(device)
}

async fn tun() -> fictionet::Result {
    let device = prepare_tun(PEER)?;
    let listener = tokio::net::TcpListener::bind((PEER, PORT)).await?;
    let udp = tokio::net::UdpSocket::bind((PEER, PORT)).await?;
    let capture = Capture::default();
    let captured = capture.clone();
    fictionet::run(fictionet::Seed::random(), move |fcx| async move {
        let (attacher, attachments) = fictionet::attachments();
        let end = attacher.attach(honeypot_world::INTERNET)?;
        fcx.spawn(move |fcx| async move {
            let _owner = attacher;
            device.relay(fcx, end).await
        });
        let client = honeypot_world::start(
            &fcx,
            &config(CLIENT, PEER),
            Clock::starting_now(),
            sinks(&captured),
            attachments,
        )?;
        let client = endpoints(&client)?.await?;
        let kernel_peer = async move {
            let (mut tcp, from) = listener.accept().await?;
            if from.ip() != CLIENT {
                return Err(fictionet::Error::msg("kernel peer saw wrong TCP source"));
            }
            let mut bytes = vec![0; TCP_BYTES];
            tcp.read_exact(&mut bytes).await?;
            answer(&mut bytes);
            tcp.write_all(&bytes).await?;
            let mut bytes = vec![0; UDP_BYTES + 1];
            let (count, from) = udp.recv_from(&mut bytes).await?;
            if from.ip() != CLIENT || count != UDP_BYTES {
                return Err(fictionet::Error::msg("kernel peer saw wrong UDP datagram"));
            }
            bytes.truncate(count);
            answer(&mut bytes);
            udp.send_to(&bytes, from).await?;
            let mut inbound = tokio::net::TcpStream::connect((CLIENT, 80)).await?;
            inbound
                .write_all(b"GET / HTTP/1.1\r\nHost: decoy\r\nConnection: close\r\n\r\n")
                .await?;
            let mut status = [0; 12];
            inbound.read_exact(&mut status).await?;
            if &status != b"HTTP/1.1 200" {
                return Err(fictionet::Error::msg(
                    "kernel peer could not use inbound HTTP",
                ));
            }
            println!("Guest kernel peer verified inbound HTTP still serves through TUN");
            Ok(())
        };
        tokio::try_join!(exchange(&fcx, client), kernel_peer)?;
        fcx.cancel();
        Ok(())
    })
    .await?;
    evidence(&capture)
}

async fn exercise(
    name: &str,
    operation: impl std::future::Future<Output = fictionet::Result>,
) -> fictionet::Result {
    println!("Starting {name} outbound exchange");
    tokio::time::timeout(std::time::Duration::from_secs(30), operation).await??;
    println!("Completed {name} outbound and inbound exchanges");
    Ok(())
}

pub fn run() -> fictionet::Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            exercise("world attachment", world()).await?;
            exercise("TUN", tun()).await?;
            exercise("VFIO virtio-net through an isolated QEMU hub", vfio()).await?;
            super::port_zero::run().await
        })
}
