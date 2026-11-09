//! Interface readiness and the single IP pass shared by host transports.

use std::future::poll_fn;
use std::net::IpAddr;
use std::sync::Arc;
use std::task::Poll;

use fictionet::stdlib::layer::{
    Admit, Budget, Chunk, Datagram, Driver, PacketCommand, PacketEvent,
};
use fictionet::{Cx, Interface, Packet};

use super::packet::{Factory, Ingress, IpPacket, Opening, Stack, Transport};
use super::{icmp, tcp, udp};
use fictionet::stdlib::services::stack::Jobs;

pub(crate) async fn drive(
    fcx: Cx,
    mut interface: impl Interface,
    mut tcp: Option<tcp::PacketDriver>,
    mut udp: Option<udp::PacketDriver>,
    ping: Option<(IpAddr, icmp::Options)>,
    layer: Stack,
) -> fictionet::Result {
    let mut ip = Driver::new(layer, Arc::new(fcx.clone()), Budget::unlimited(), fcx.now());
    ip.keep_observations(0);
    let mut timer = fictionet::Timer::new(&fcx);
    let mut held: Option<IpPacket> = None;
    let mut raw = None;
    let mut output = Vec::new();
    let mut outgoing = std::collections::VecDeque::new();
    let mut jobs = Jobs::new();
    let mut closed = false;
    poll_fn(|cx| {
        if fcx.is_cancelled() {
            return Poll::Ready(Ok(()));
        }
        ip.set_now(fcx.now());
        let mut busy = false;
        let mut deadlines = [None; 3];
        for turn in 0..64 {
            if outgoing.len() < 128
                && let Some(tcp) = &mut tcp
            {
                let (more, deadline) = tcp.poll(cx, &mut output);
                busy |= more;
                deadlines[1] = deadline;
            }
            if outgoing.len() < 128
                && let Some(udp) = &mut udp
            {
                let (more, deadline) = udp.poll(cx, &mut output);
                busy |= more;
                deadlines[2] = deadline;
            }
            outgoing.extend(
                output
                    .drain(..)
                    .map(|packet| PacketCommand::Send(Chunk::new(packet))),
            );
            while let Some(command) = outgoing.pop_front() {
                if let Admit::Blocked(command) = ip
                    .command(command)
                    .map_err(|e| fictionet::Error::msg(e.to_string()))?
                {
                    outgoing.push_front(command);
                    break;
                }
            }
            if let Some(packet) = held.take() {
                match packet.transport() {
                    Transport::Tcp => {
                        if let Some(tcp) = &mut tcp
                            && let Admit::Blocked(PacketEvent::Packet(packet)) = tcp.deliver(packet)
                        {
                            held = Some(packet);
                            busy = true;
                            break;
                        }
                    }
                    Transport::Udp => {
                        if let Some(udp) = &mut udp {
                            udp.deliver(packet);
                        }
                    }
                    _ => {
                        if let Some((addr, options)) = &ping
                            && let Some(reply) =
                                options.echo_reply(&Packet(packet.bytes().to_vec()), *addr)
                        {
                            outgoing.push_back(PacketCommand::Send(Chunk::new(reply.0)));
                        }
                    }
                }
            }
            ip.run().map_err(|e| fictionet::Error::msg(e.to_string()))?;
            jobs.take(&mut ip);
            jobs.poll(Some(&fcx), cx, |done| ip.complete(done))
                .map_err(|e| fictionet::Error::msg(e.to_string()))?;
            if jobs.budget_exhausted() {
                return Poll::Ready(Err(fictionet::Error::msg(
                    "packet stack work budget exhausted",
                )));
            }
            ip.send_below(|command| {
                if let PacketCommand::Send(bytes) = command {
                    interface.send(Packet(bytes.into_vec()));
                }
                Admit::Taken
            });
            ip.send_above(|event| {
                if held.is_some() {
                    return Admit::Blocked(event);
                }
                if let PacketEvent::Packet(packet) = event {
                    held = Some(packet);
                }
                Admit::Taken
            });
            if held.is_some() {
                busy = turn == 63;
                continue;
            }
            if raw.is_none() && !closed {
                match interface.poll_recv(&fcx, cx) {
                    Poll::Ready(Ok(packet)) => {
                        raw = Some(PacketEvent::Packet(Datagram::new(
                            Chunk::new(packet.0),
                            Ingress::default(),
                        )));
                    }
                    Poll::Ready(Err(_)) => {
                        closed = true;
                        raw = Some(PacketEvent::Ended);
                    }
                    Poll::Pending => {}
                }
            }
            if let Some(event) = raw.take() {
                if let Admit::Blocked(event) = ip
                    .deliver(event)
                    .map_err(|e| fictionet::Error::msg(e.to_string()))?
                {
                    raw = Some(event);
                }
                busy = turn == 63;
            } else {
                break;
            }
        }
        if closed && raw.is_none() && held.is_none() {
            return Poll::Ready(Ok(()));
        }
        deadlines[0] = ip.deadline();
        if busy || !outgoing.is_empty() || raw.is_some() || held.is_some() || ip.exhausted() {
            cx.waker().wake_by_ref();
        }
        match deadlines.into_iter().flatten().min() {
            Some(deadline) if timer.poll_until(cx, deadline).is_ready() => {
                timer.clear();
                cx.waker().wake_by_ref();
            }
            Some(_) => {}
            None => timer.clear(),
        }
        Poll::Pending
    })
    .await
}

/// Stages both transports without starting progress or publishing a route.
pub(crate) fn prepare(
    fcx: &Cx,
    interface: impl Interface,
    addr: IpAddr,
    options: tcp::Options,
    icmp: icmp::Options,
    factory: &Factory,
    tcp_factory: &tcp::Factory,
) -> (
    tcp::Endpoint,
    udp::Endpoint,
    impl Future<Output = fictionet::Result> + Send + 'static,
) {
    let (tcp, tcp_driver) = tcp::prepare_transport(fcx, addr, options, tcp_factory);
    let (udp, udp_driver) = udp::prepare_transport(fcx, addr);
    let layer = factory.build(Opening {
        cx: fcx.clone(),
        addr,
        budget: Budget::unlimited(),
    });
    let task = drive(
        fcx.clone(),
        interface,
        Some(tcp_driver),
        Some(udp_driver),
        Some((addr, icmp)),
        layer,
    );
    (tcp, udp, task)
}
