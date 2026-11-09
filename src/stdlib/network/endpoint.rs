//! Interface readiness and the single IP pass shared by host transports.

use std::future::poll_fn;
use std::net::IpAddr;
use std::sync::Arc;
use std::task::Poll;

use fictionet::stdlib::layer::{Admit, Budget, Chunk, Driver, PacketCommand, PacketEvent};
use fictionet::{Cx, Interface, Packet};

use super::Transport;
use super::packet::{CheckedIpPacket, Factory, Opening, Sort, Stack};
use super::{icmp, tcp, udp};
use fictionet::stdlib::services::stack::Jobs;

/// Where the dispatcher sends one packet its IP layer handed up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Destination {
    /// The TCP transport.
    Tcp,
    /// The UDP transport.
    Udp,
    /// The host's ping answers: ICMP that quotes neither transport.
    Icmp,
}

/// Where a packet the host's IP layer handed up goes. The layer is
/// replaceable ([`Factory`]), but its upper port carries only
/// [`CheckedIpPacket`]s, so every packet here passed the host's checks.
fn destination(packet: &CheckedIpPacket) -> Destination {
    match packet.sort() {
        Sort::Transport(Transport::Tcp) => Destination::Tcp,
        Sort::Transport(Transport::Udp) => Destination::Udp,
        Sort::Icmp | Sort::Other(_) => Destination::Icmp,
    }
}

#[cfg(kani)]
#[path = "../../../verification/world-layers/kani/dispatch.rs"]
mod proofs;

/// Runs one host's packets: `interface` below, one IP layer, and the
/// transports above it.
pub(crate) async fn drive(
    fcx: Cx,
    mut interface: impl Interface,
    mut tcp: Option<tcp::PacketDriver>,
    mut udp: Option<udp::PacketDriver>,
    ping: Option<(IpAddr, icmp::Options)>,
    layer: Stack,
) -> fictionet::Result {
    // IP uses its engine limits; application byte budgets cover their transport children.
    let mut ip = Driver::new(layer, Arc::new(fcx.clone()), Budget::unlimited(), fcx.now());
    ip.keep_observations(0);
    let mut timer = fictionet::Timer::new(&fcx);
    let mut held: Option<CheckedIpPacket> = None;
    let mut raw = None;
    let mut output = Vec::new();
    let mut outgoing = std::collections::VecDeque::new();
    let mut jobs = Jobs::new();
    let mut closed = false;
    poll_fn(|cx| {
        if fcx.is_cancelled() {
            return Poll::Ready(Ok(()));
        }
        let now = fcx.now();
        ip.set_now(now);
        let mut busy = false;
        let mut deadlines = [None; 3];
        // Whether the transports may have something new since their last
        // pass: a wake, a packet for them, or a pass that left work or
        // filled the output queue.
        let mut dirty = true;
        let mut drained = false;
        for turn in 0..64 {
            let mut moved = false;
            let mut more = false;
            let mut transport = false;
            // The IP layer may hold only a packet or so: when it refuses,
            // it passes what it holds below and is offered the rest again,
            // so a walk's output goes down in the same turn.
            let mut retries = outgoing.len();
            while let Some(command) = outgoing.pop_front() {
                let Admit::Blocked(command) = ip
                    .command(command)
                    .map_err(|e| fictionet::Error::msg(e.to_string()))?
                else {
                    moved = true;
                    continue;
                };
                outgoing.push_front(command);
                let ran = ip.run().map_err(|e| fictionet::Error::msg(e.to_string()))?;
                if retries == 0 || !(send_below(&mut ip, &mut interface) || ran) {
                    break;
                }
                retries -= 1;
                moved = true;
            }
            moved |= ip.run().map_err(|e| fictionet::Error::msg(e.to_string()))?;
            jobs.take(&mut ip);
            moved |= jobs
                .poll(Some(&fcx), cx, |done| ip.complete(done))
                .map_err(|e| fictionet::Error::msg(e.to_string()))?;
            if jobs.budget_exhausted() {
                return Poll::Ready(Err(fictionet::Error::msg(
                    "packet stack work budget exhausted",
                )));
            }
            moved |= send_below(&mut ip, &mut interface);
            moved |= ip.send_above(|event| {
                if held.is_some() {
                    return Admit::Blocked(event);
                }
                if let PacketEvent::Packet(packet) = event {
                    held = Some(packet);
                }
                Admit::Taken
            });
            if let Some(packet) = held.take() {
                let mut accepted = true;
                match destination(&packet) {
                    Destination::Tcp => {
                        if let Some(tcp) = &mut tcp {
                            dirty = true;
                            if let Admit::Blocked(PacketEvent::Packet(packet)) =
                                tcp.deliver(packet, now)
                            {
                                held = Some(packet);
                                accepted = false;
                                transport = true;
                            }
                        }
                    }
                    Destination::Udp => {
                        if let Some(udp) = &mut udp {
                            dirty = true;
                            udp.deliver(packet, now);
                        }
                    }
                    Destination::Icmp if outgoing.len() >= 128 => {
                        held = Some(packet);
                        accepted = false;
                        transport = true;
                    }
                    Destination::Icmp => {
                        if let Some((addr, options)) = &ping
                            && let Some(reply) =
                                options.echo_reply(&Packet(packet.bytes().to_vec()), *addr)
                        {
                            outgoing.push_back(PacketCommand::Send(Chunk::new(reply.0)));
                        }
                    }
                }
                moved |= accepted;
            }
            // Once the interface had nothing, it holds this task's waker
            // and wakes it for the next packet, so it is not asked again in
            // this poll.
            if drained {
                transport = true;
            } else if held.is_none() && raw.is_none() && !closed {
                match interface.poll_recv(&fcx, cx) {
                    Poll::Ready(Ok(packet)) => {
                        moved = true;
                        raw = Some(PacketEvent::Packet(Chunk::new(packet.0)));
                    }
                    Poll::Ready(Err(_)) => {
                        moved = true;
                        closed = true;
                        raw = Some(PacketEvent::Ended);
                    }
                    Poll::Pending => {
                        transport = true;
                        drained = true;
                    }
                }
            }
            if let Some(event) = raw.take() {
                match ip
                    .deliver(event)
                    .map_err(|e| fictionet::Error::msg(e.to_string()))?
                {
                    Admit::Blocked(event) => {
                        raw = Some(event);
                        transport = true;
                    }
                    _ => moved = true,
                }
            }
            // Batch ingress before walking every transport connection. A
            // blocked carrier or an exhausted visit still gets a transport
            // pass, including its timers and application work. A pass with
            // nothing new for the transports would find nothing to do.
            if dirty && (transport || closed || turn == 63) {
                let room = 128usize.saturating_sub(outgoing.len());
                let mut pending = false;
                if let Some(tcp) = &mut tcp {
                    let (work, deadline) = tcp.poll(cx, &mut output, room, now)?;
                    pending |= work;
                    deadlines[1] = deadline;
                }
                if let Some(udp) = &mut udp {
                    let (work, deadline) = udp.poll(cx, &mut output, room, now)?;
                    pending |= work;
                    deadlines[2] = deadline;
                }
                more |= pending;
                dirty = pending || output.len() >= room;
                moved |= !output.is_empty();
                outgoing.extend(output.drain(..).map(PacketCommand::Send));
            }
            if !moved && !more {
                break;
            }
            busy = turn == 63;
        }
        if closed && raw.is_none() && held.is_none() {
            return Poll::Ready(Ok(()));
        }
        deadlines[0] = ip.deadline();
        if busy || ip.exhausted() {
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

/// Sends what the IP layer has for the interface, which takes every packet.
fn send_below(ip: &mut Driver<Stack>, interface: &mut impl Interface) -> bool {
    ip.send_below(|command| {
        if let PacketCommand::Send(bytes) = command {
            interface.send(Packet(bytes.into_vec()));
        }
        Admit::Taken
    })
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
