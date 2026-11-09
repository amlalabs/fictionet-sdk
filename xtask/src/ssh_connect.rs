//! OpenSSH ProxyCommand through a world's relay socket and simulated TCP.
//! Destination ports are literal wire ports, including zero.

use std::fs::File;
use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use fictionet::Interface;
use fictionet::prelude::*;
use fictionet::relay::{self, Hello, Message, unix};
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::{ip, tcp, udp};
use fictionet::stdlib::protocols::dhcp;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

pub async fn run(args: &[String]) -> crate::Result {
    let [world, address, port] = args else {
        return Err(
            "usage: cargo xtask-host ssh-connect WORLD_UNIX_SOCKET IPV4_ADDRESS PORT".into(),
        );
    };
    let target = SocketAddr::new(address.parse::<Ipv4Addr>()?.into(), port.parse()?);
    let seed = fictionet::Seed::random();
    let name = format!(
        "ssh-{}-{:02x}{:02x}{:02x}{:02x}",
        std::process::id(),
        seed.0[0],
        seed.0[1],
        seed.0[2],
        seed.0[3]
    );
    let socket = handshake(world, name).await?;
    fictionet::run(seed, move |fcx| async move {
        let (mut stack, relay_end) = fictionet::pair_with_limit(1 << 20);
        fcx.spawn(move |fcx| relay_packets(fcx, relay_end, socket));
        let source =
            tokio::time::timeout(Duration::from_secs(10), lease(&fcx, &mut stack)).await??;
        let (tcp_end, _udp, _icmp, _other) = ip::split_protocols(&fcx, stack);
        let endpoint = tcp::endpoint(&fcx, tcp_end, source.into());
        let conn =
            tokio::time::timeout(Duration::from_secs(10), endpoint.connect(&fcx, target)).await??;
        let result = bridge(conn.into_tokio(&fcx)).await;
        fcx.cancel();
        result.map_err(Into::into)
    })
    .await?;
    Ok(())
}

async fn handshake(path: &str, name: String) -> crate::Result<AsyncFd<OwnedFd>> {
    let fd = unix::connect(path)?;
    unix::set_nonblocking(fd.as_raw_fd(), true)?;
    // The registration owns the descriptor until it is deregistered.
    let socket = unsafe { AsyncFd::register(fd)? };
    let hello = Message::Hello(Hello {
        version: relay::VERSION,
        mtu: 1500,
        kind: "ssh_proxy".into(),
        name,
    })
    .encode();
    tokio::time::timeout(relay::HANDSHAKE_TIMEOUT, async {
        loop {
            let mut guard = socket.writable().await?;
            match guard.try_io(|fd| unix::send(fd.get_ref().as_raw_fd(), &hello, true)) {
                Ok(result) => {
                    result?;
                    break;
                }
                Err(_) => continue,
            }
        }
        let mut bytes = vec![0; relay::MAX_MESSAGE + 1];
        let len = receive(&socket, &mut bytes).await?;
        match relay::decode(&bytes[..len])? {
            Message::Accept => Ok::<_, Box<dyn std::error::Error + Send + Sync>>(()),
            Message::Refuse(reason) => Err(format!("world refused attachment: {reason}").into()),
            _ => Err("world did not accept the relay handshake".into()),
        }
    })
    .await??;
    Ok(socket)
}

async fn receive(socket: &AsyncFd<OwnedFd>, bytes: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut guard = socket.readable().await?;
        match guard.try_io(|fd| unix::recv(fd.get_ref().as_raw_fd(), bytes, true)) {
            Ok(Ok(n)) if n <= relay::MAX_MESSAGE && n > 0 => return Ok(n),
            Ok(Ok(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "world relay closed or oversized message",
                ));
            }
            Ok(Err(error)) => return Err(error),
            Err(_) => (),
        }
    }
}

async fn relay_packets(
    fcx: fictionet::Cx,
    mut end: fictionet::End,
    socket: AsyncFd<OwnedFd>,
) -> fictionet::Result {
    let mut bytes = vec![0; relay::MAX_MESSAGE + 1];
    let mut pending: Option<fictionet::Packet> = None;
    loop {
        tokio::select! {
            _ = fcx.cancelled() => return Ok(()),
            packet = end.recv(&fcx), if pending.is_none() => pending = Some(packet?),
            ready = socket.writable(), if pending.is_some() => {
                let mut guard = ready?;
                let packet = pending.as_ref().expect("pending packet enables this branch");
                if let Ok(result) = guard.try_io(|fd| unix::send_parts(fd.get_ref().as_raw_fd(), &[&[relay::PACKET], &packet.0], true)) {
                    result?;
                    pending = None;
                }
            }
            read = receive(&socket, &mut bytes) => {
                let len = read?;
                let Message::Packet(packet) = relay::decode(&bytes[..len])? else {
                    return Err(fictionet::Error::msg("unexpected world relay message"));
                };
                end.send(fictionet::Packet(packet.to_vec()));
            }
        }
    }
}

async fn lease(fcx: &fictionet::Cx, end: &mut fictionet::End) -> fictionet::Result<Ipv4Addr> {
    let mut request = dhcp::Message::new(dhcp::BOOTREQUEST, fcx.random_u64() as u32);
    fcx.fill_random(&mut request.chaddr[..6]);
    request.chaddr[0] = (request.chaddr[0] | 2) & !1;
    request.flags = 0x8000;
    request.push(dhcp::opt::MESSAGE_TYPE, [dhcp::DISCOVER]);
    send_dhcp(end, &request)?;
    let offer = read_dhcp(fcx, end, &request, dhcp::OFFER).await?;
    let server = offer
        .option_addr(dhcp::opt::SERVER_ID)
        .ok_or_else(|| fictionet::Error::msg("DHCP offer has no server identifier"))?;
    request.options.clear();
    request.push(dhcp::opt::MESSAGE_TYPE, [dhcp::REQUEST]);
    request.push(dhcp::opt::REQUESTED_IP, offer.yiaddr.octets());
    request.push(dhcp::opt::SERVER_ID, server.octets());
    send_dhcp(end, &request)?;
    let ack = read_dhcp(fcx, end, &request, dhcp::ACK).await?;
    if ack.yiaddr != offer.yiaddr
        || ack.yiaddr.is_unspecified()
        || ack.option_addr(dhcp::opt::SERVER_ID) != Some(server)
    {
        return Err(fictionet::Error::msg(
            "DHCP acknowledgement differs from the offer",
        ));
    }
    Ok(ack.yiaddr)
}

fn send_dhcp(end: &mut fictionet::End, request: &dhcp::Message) -> fictionet::Result {
    let payload = request.to_bytes()?;
    let src = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), dhcp::CLIENT_PORT);
    let dst = SocketAddr::new(Ipv4Addr::BROADCAST.into(), dhcp::SERVER_PORT);
    let mut datagram = vec![0; udp::encoded_len(src.ip(), dst.ip(), payload.len())?];
    udp::encode(src, dst, &payload, &mut datagram)?;
    end.send(ip::packet(src.ip(), dst.ip(), ip::protocol::UDP, &datagram));
    Ok(())
}

async fn read_dhcp(
    fcx: &fictionet::Cx,
    end: &mut fictionet::End,
    request: &dhcp::Message,
    expected: u8,
) -> fictionet::Result<dhcp::Message> {
    loop {
        let packet = end.recv(fcx).await?;
        let Some(header) = ip::Header::parse_whole(&packet.0) else {
            continue;
        };
        if header.protocol != ip::protocol::UDP {
            continue;
        }
        let Some(datagram) = udp::Datagram::parse(header.payload(&packet.0)) else {
            continue;
        };
        if datagram.source_port() != dhcp::SERVER_PORT
            || datagram.destination_port() != dhcp::CLIENT_PORT
            || !datagram.checksum_ok(header.src, header.dst)
        {
            continue;
        }
        let Ok(reply) = dhcp::Message::parse(datagram.payload()) else {
            continue;
        };
        if reply.op == dhcp::BOOTREPLY && reply.xid == request.xid && reply.chaddr == request.chaddr
        {
            if reply.message_type() == Some(expected) {
                return Ok(reply);
            }
            if reply.message_type() == Some(dhcp::NAK) {
                return Err(fictionet::Error::msg("world refused DHCP lease"));
            }
        }
    }
}

struct Input(AsyncFd<File>);

impl AsyncRead for Input {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut ready = std::task::ready!(self.0.poll_read_ready(cx))?;
            match ready.try_io(|fd| fd.get_ref().read(buf.initialize_unfilled())) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_) => (),
            }
        }
    }
}

async fn bridge(
    stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
) -> io::Result<()> {
    let input = File::from(std::io::stdin().as_fd().try_clone_to_owned()?);
    unix::set_nonblocking(input.as_raw_fd(), true)?;
    // The file owns the input pipe throughout its registration.
    let mut input = Input(unsafe { AsyncFd::register(input)? });
    let mut output =
        tokio::fs::File::from_std(File::from(std::io::stdout().as_fd().try_clone_to_owned()?));
    let (mut read, mut write) = tokio::io::split(stream);
    let upload = async {
        tokio::io::copy(&mut input, &mut write).await?;
        write.shutdown().await?;
        std::future::pending::<io::Result<()>>().await
    };
    let download = async {
        tokio::io::copy(&mut read, &mut output).await?;
        output.flush().await
    };
    tokio::select! { result = upload => result, result = download => result }
}
