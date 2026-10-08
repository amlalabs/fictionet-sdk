//! Just enough rtnetlink to set up one device: bring it up with an MTU, add
//! addresses, add a default route. And to take another link out of the
//! way: list its routes and addresses, delete them, and set it down. For
//! `--type tap --vm tap:<name>`, also traffic control: an ingress qdisc and
//! a filter that redirects every frame to another device.
//! Written by hand on `libc`, with no netlink crate. Each change asks for
//! an ack, and a kernel error comes back as an `io::Error`.

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

// Message types and flags (linux/netlink.h, linux/rtnetlink.h).
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWLINK: u16 = 16;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_MULTI: u16 = 0x2;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLA_F_NESTED: u16 = 0x8000;
const RTM_NEWQDISC: u16 = 36;
const RTM_DELQDISC: u16 = 37;
const RTM_NEWTFILTER: u16 = 44;

// Traffic control (linux/rtnetlink.h, linux/pkt_sched.h, linux/pkt_cls.h,
// linux/tc_act/tc_mirred.h).
const TCA_KIND: u16 = 1;
const TCA_OPTIONS: u16 = 2;
const TC_H_INGRESS: u32 = 0xffff_fff1;
const INGRESS_HANDLE: u32 = 0xffff_0000;
const TCA_MATCHALL_ACT: u16 = 2;
const TCA_ACT_KIND: u16 = 1;
const TCA_ACT_OPTIONS: u16 = 2;
const TCA_MIRRED_PARMS: u16 = 2;
const TC_ACT_STOLEN: i32 = 4;
const TCA_EGRESS_REDIR: i32 = 1;
const ETH_P_ALL: u16 = 0x0003;

// Link attributes (linux/if_link.h).
const IFLA_MTU: u16 = 4;
const IFLA_AF_SPEC: u16 = 26;
const IFLA_INET6_ADDR_GEN_MODE: u16 = 8;
const IN6_ADDR_GEN_MODE_NONE: u8 = 1;

// Address attributes (linux/if_addr.h).
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;
const IFA_F_NODAD: u32 = 0x02;

// Route attributes and values (linux/rtnetlink.h).
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_TABLE: u16 = 15;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;
const RTNH_F_ONLINK: u32 = 4;

const IFF_UP: u32 = 0x1;

/// A request being built: the netlink header, a fixed body, then attributes.
pub(crate) struct Request {
    buf: Vec<u8>,
}

impl Request {
    /// A change: the kernel acks it.
    fn new(kind: u16, flags: u16, body: &[u8]) -> Request {
        Request::with_flags(kind, flags | NLM_F_REQUEST | NLM_F_ACK, body)
    }

    fn with_flags(kind: u16, flags: u16, body: &[u8]) -> Request {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&0u32.to_ne_bytes()); // length, set in finish()
        buf.extend_from_slice(&kind.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&1u32.to_ne_bytes()); // sequence number
        buf.extend_from_slice(&0u32.to_ne_bytes()); // port id: the kernel
        buf.extend_from_slice(body);
        pad(&mut buf);
        Request { buf }
    }

    fn attr(&mut self, kind: u16, data: &[u8]) -> &mut Self {
        self.buf
            .extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(data);
        pad(&mut self.buf);
        self
    }

    pub(crate) fn finish(mut self) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

fn pad(buf: &mut Vec<u8>) {
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

/// An attribute with attributes inside it, as bytes.
fn nested(attrs: &[(u16, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (kind, data) in attrs {
        out.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(data);
        pad(&mut out);
    }
    out
}

fn family(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => libc::AF_INET as u8,
        IpAddr::V6(_) => libc::AF_INET6 as u8,
    }
}

fn octets(addr: &IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

fn link_request(index: u32, flags: u32) -> Request {
    let mut body = Vec::with_capacity(16);
    body.push(libc::AF_UNSPEC as u8);
    body.push(0);
    body.extend_from_slice(&0u16.to_ne_bytes()); // device type
    body.extend_from_slice(&(index as i32).to_ne_bytes());
    body.extend_from_slice(&flags.to_ne_bytes()); // flags
    body.extend_from_slice(&flags.to_ne_bytes()); // which flags change
    Request::new(RTM_NEWLINK, 0, &body)
}

/// `RTM_NEWLINK`: no IPv6 link-local address on this device, so a sandbox
/// with `--no-ip-addr-v6` sends no IPv6 packets of its own. It must be
/// sent before [`link_up`]: the kernel makes the address when the device
/// comes up, and applies this setting after the flags of the same message.
pub(crate) fn no_ipv6_link_local(index: u32) -> Request {
    let mut req = link_request(index, 0);
    let inet6 = nested(&[(IFLA_INET6_ADDR_GEN_MODE, &[IN6_ADDR_GEN_MODE_NONE])]);
    let spec = nested(&[(libc::AF_INET6 as u16 | NLA_F_NESTED, &inet6)]);
    req.attr(IFLA_AF_SPEC | NLA_F_NESTED, &spec);
    req
}

/// `RTM_NEWLINK`: sets the link down (clears `IFF_UP`).
pub(crate) fn link_down(index: u32) -> Request {
    let mut body = Vec::with_capacity(16);
    body.push(libc::AF_UNSPEC as u8);
    body.push(0);
    body.extend_from_slice(&0u16.to_ne_bytes());
    body.extend_from_slice(&(index as i32).to_ne_bytes());
    body.extend_from_slice(&0u32.to_ne_bytes()); // flags: IFF_UP cleared
    body.extend_from_slice(&IFF_UP.to_ne_bytes()); // which flags change
    Request::new(RTM_NEWLINK, 0, &body)
}

/// `RTM_NEWLINK`: sets the MTU and brings the device up.
pub(crate) fn link_up(index: u32, mtu: u32) -> Request {
    let mut req = link_request(index, IFF_UP);
    req.attr(IFLA_MTU, &mtu.to_ne_bytes());
    req
}

/// A `struct tcmsg` for `index`.
fn tcmsg(index: u32, handle: u32, parent: u32, info: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(20);
    body.extend_from_slice(&[libc::AF_UNSPEC as u8, 0, 0, 0]);
    body.extend_from_slice(&(index as i32).to_ne_bytes());
    body.extend_from_slice(&handle.to_ne_bytes());
    body.extend_from_slice(&parent.to_ne_bytes());
    body.extend_from_slice(&info.to_ne_bytes());
    body
}

/// `RTM_NEWQDISC`: an ingress qdisc on the device (`tc qdisc add dev X
/// ingress`).
pub(crate) fn add_ingress(index: u32) -> Request {
    let mut req = Request::new(
        RTM_NEWQDISC,
        NLM_F_CREATE | NLM_F_EXCL,
        &tcmsg(index, INGRESS_HANDLE, TC_H_INGRESS, 0),
    );
    req.attr(TCA_KIND, b"ingress\0");
    req
}

/// `RTM_DELQDISC`: removes the device's ingress qdisc and every filter on
/// it (`tc qdisc del dev X ingress`).
pub(crate) fn del_ingress(index: u32) -> Request {
    Request::new(
        RTM_DELQDISC,
        0,
        &tcmsg(index, INGRESS_HANDLE, TC_H_INGRESS, 0),
    )
}

/// `RTM_NEWTFILTER`: on the device's ingress, a filter that takes every
/// frame and sends it out of device `to` instead (`tc filter add dev X
/// ingress matchall action mirred egress redirect dev Y`).
pub(crate) fn redirect_ingress(index: u32, to: u32) -> Request {
    // Priority 1, every protocol (in network byte order).
    let info = (1u32 << 16) | ETH_P_ALL.to_be() as u32;
    let mut req = Request::new(
        RTM_NEWTFILTER,
        NLM_F_CREATE | NLM_F_EXCL,
        &tcmsg(index, 0, INGRESS_HANDLE, info),
    );
    req.attr(TCA_KIND, b"matchall\0");
    // struct tc_mirred: index, capab, action, refcnt, bindcnt, eaction,
    // ifindex.
    let mut parms = Vec::with_capacity(28);
    for v in [0i32, 0, TC_ACT_STOLEN, 0, 0, TCA_EGRESS_REDIR, to as i32] {
        parms.extend_from_slice(&v.to_ne_bytes());
    }
    let mirred = nested(&[(TCA_MIRRED_PARMS, &parms)]);
    let action = nested(&[
        (TCA_ACT_KIND, b"mirred\0"),
        (TCA_ACT_OPTIONS | NLA_F_NESTED, &mirred),
    ]);
    // Actions are a list, numbered from 1.
    let actions = nested(&[(1 | NLA_F_NESTED, &action)]);
    let options = nested(&[(TCA_MATCHALL_ACT | NLA_F_NESTED, &actions)]);
    req.attr(TCA_OPTIONS | NLA_F_NESTED, &options);
    req
}

/// `RTM_NEWLINK`: brings the device up without changing anything else.
pub(crate) fn set_up(index: u32) -> Request {
    link_request(index, IFF_UP)
}

/// `RTM_NEWADDR`: adds `addr/prefix` to the device.
pub(crate) fn add_address(index: u32, addr: IpAddr, prefix: u8) -> Request {
    let body = [
        &[family(&addr), prefix, 0, RT_SCOPE_UNIVERSE][..],
        &index.to_ne_bytes()[..],
    ]
    .concat();
    let mut req = Request::new(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &body);
    let bytes = octets(&addr);
    req.attr(IFA_LOCAL, &bytes);
    req.attr(IFA_ADDRESS, &bytes);
    if addr.is_ipv6() {
        // A tun device has no neighbors to ask, so there is nothing to
        // detect a duplicate with. Without this the address could stay
        // tentative for a moment and the first packets would fail.
        req.attr(IFA_FLAGS, &IFA_F_NODAD.to_ne_bytes());
    }
    req
}

/// `RTM_NEWROUTE`: the default route through `gateway` on the device. The
/// route is on-link, so the gateway need not be inside the address's
/// prefix: a tun device has no neighbors to resolve anyway.
pub(crate) fn add_default_route(index: u32, gateway: IpAddr) -> Request {
    let mut body = vec![
        family(&gateway),
        0, // destination prefix length: the default route
        0,
        0,
        RT_TABLE_MAIN,
        RTPROT_STATIC,
        RT_SCOPE_UNIVERSE,
        RTN_UNICAST,
    ];
    body.extend_from_slice(&RTNH_F_ONLINK.to_ne_bytes());
    let mut req = Request::new(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &body);
    req.attr(RTA_GATEWAY, &octets(&gateway));
    req.attr(RTA_OIF, &index.to_ne_bytes());
    req
}

/// `RTM_GETROUTE` with `NLM_F_DUMP`: every route in every table, IPv4
/// and IPv6.
pub(crate) fn dump_routes() -> Request {
    // struct rtmsg, all zero but the family.
    let body = [libc::AF_UNSPEC as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    Request::with_flags(RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, &body)
}

/// `RTM_GETADDR` with `NLM_F_DUMP`: every address, IPv4 and IPv6.
pub(crate) fn dump_addresses() -> Request {
    // struct ifaddrmsg, all zero but the family.
    let body = [libc::AF_UNSPEC as u8, 0, 0, 0, 0, 0, 0, 0];
    Request::with_flags(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, &body)
}

/// The attributes of a netlink message after its fixed body of `fixed`
/// bytes, as (type, data) pairs. Stops at the first malformed one.
fn attrs(msg: &[u8], fixed: usize) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut rest = msg.get(16 + fixed..).unwrap_or(&[]);
    while rest.len() >= 4 {
        let len = u16::from_ne_bytes([rest[0], rest[1]]) as usize;
        let kind = u16::from_ne_bytes([rest[2], rest[3]]) & 0x3fff;
        if len < 4 || len > rest.len() {
            break;
        }
        out.push((kind, &rest[4..len]));
        rest = &rest[((len + 3) & !3).min(rest.len())..];
    }
    out
}

/// One route from a dump.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Route {
    /// The dumped message, header included.
    msg: Vec<u8>,
    /// Its output device (`RTA_OIF`), if it has one.
    pub(crate) oif: Option<u32>,
}

/// One address from a dump.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Address {
    msg: Vec<u8>,
    pub(crate) index: u32,
    pub(crate) addr: Option<IpAddr>,
}

const RTMSG_LEN: usize = 12;
const IFADDRMSG_LEN: usize = 8;

fn ip_from(family: u8, data: &[u8]) -> Option<IpAddr> {
    match (family as i32, data.len()) {
        (libc::AF_INET, 4) => Some(IpAddr::from(<[u8; 4]>::try_from(data).ok()?)),
        (libc::AF_INET6, 16) => Some(IpAddr::from(<[u8; 16]>::try_from(data).ok()?)),
        _ => None,
    }
}

impl Route {
    pub(crate) fn parse(msg: &[u8]) -> Option<Route> {
        if msg.len() < 16 + RTMSG_LEN {
            return None;
        }
        let oif = attrs(msg, RTMSG_LEN)
            .into_iter()
            .find(|(k, d)| *k == RTA_OIF && d.len() == 4)
            .map(|(_, d)| u32::from_ne_bytes(d.try_into().unwrap()));
        Some(Route {
            msg: msg.to_vec(),
            oif,
        })
    }

    /// `RTM_DELROUTE` for this route. It keeps the route's own `rtmsg`
    /// (family, prefix, table, protocol, scope, type) and the attributes
    /// that pick it out: destination, gateway, device, table and metric.
    /// The kernel deletes the route that matches all of them.
    pub(crate) fn delete(&self) -> Request {
        let mut body = self.msg[16..16 + RTMSG_LEN].to_vec();
        // rtm_flags: keep only "on link", which the match looks at.
        let flags = u32::from_ne_bytes(body[8..12].try_into().unwrap()) & RTNH_F_ONLINK;
        body[8..12].copy_from_slice(&flags.to_ne_bytes());
        let mut req = Request::new(RTM_DELROUTE, 0, &body);
        for (kind, data) in attrs(&self.msg, RTMSG_LEN) {
            if matches!(
                kind,
                RTA_DST | RTA_GATEWAY | RTA_OIF | RTA_TABLE | RTA_PRIORITY
            ) {
                req.attr(kind, data);
            }
        }
        req
    }

    /// The route as `ip route` would name it, for messages.
    pub(crate) fn describe(&self) -> String {
        let family = self.msg[16];
        let prefix = self.msg[17];
        let mut dst = None;
        let mut via = None;
        for (kind, data) in attrs(&self.msg, RTMSG_LEN) {
            match kind {
                RTA_DST => dst = ip_from(family, data),
                RTA_GATEWAY => via = ip_from(family, data),
                _ => {}
            }
        }
        let mut out = match dst {
            Some(d) => format!("{d}/{prefix}"),
            None if prefix == 0 => "default".to_owned(),
            None => format!("?/{prefix}"),
        };
        if let Some(v) = via {
            out.push_str(&format!(" via {v}"));
        }
        out
    }
}

impl Address {
    pub(crate) fn parse(msg: &[u8]) -> Option<Address> {
        if msg.len() < 16 + IFADDRMSG_LEN {
            return None;
        }
        let family = msg[16];
        let index = u32::from_ne_bytes(msg[20..24].try_into().unwrap());
        let found = attrs(msg, IFADDRMSG_LEN);
        let pick = |want: u16| {
            found
                .iter()
                .find(|(k, _)| *k == want)
                .and_then(|(_, d)| ip_from(family, d))
        };
        let addr = pick(IFA_LOCAL).or_else(|| pick(IFA_ADDRESS));
        Some(Address {
            msg: msg.to_vec(),
            index,
            addr,
        })
    }

    /// `RTM_DELADDR` for this address: its `ifaddrmsg` and its
    /// `IFA_LOCAL` and `IFA_ADDRESS`.
    pub(crate) fn delete(&self) -> Request {
        let body = self.msg[16..16 + IFADDRMSG_LEN].to_vec();
        let mut req = Request::new(RTM_DELADDR, 0, &body);
        for (kind, data) in attrs(&self.msg, IFADDRMSG_LEN) {
            if matches!(kind, IFA_LOCAL | IFA_ADDRESS) {
                req.attr(kind, data);
            }
        }
        req
    }
}

/// A route netlink socket.
pub(crate) struct Netlink {
    fd: OwnedFd,
}

impl Netlink {
    pub(crate) fn open() -> io::Result<Netlink> {
        // SAFETY: plain syscall; the fd is owned from here.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: an all-zero sockaddr_nl is valid and means "the kernel picks".
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let r = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const addr).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Netlink { fd })
    }

    fn send(&self, req: Request) -> io::Result<()> {
        let msg = req.finish();
        // SAFETY: an all-zero sockaddr_nl with the family set addresses the kernel.
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let n = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                msg.as_ptr().cast(),
                msg.len(),
                0,
                (&raw const kernel).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn recv<'a>(&self, buf: &'a mut [u8]) -> io::Result<&'a [u8]> {
        loop {
            // SAFETY: `buf` is valid for writes of its length.
            let n =
                unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            return Ok(&buf[..n as usize]);
        }
    }

    /// Sends a dump request and returns every message of the answer,
    /// each with its header.
    pub(crate) fn dump(&self, req: Request) -> io::Result<Vec<Vec<u8>>> {
        self.send(req)?;
        let mut buf = vec![0u8; 32768];
        let mut out = Vec::new();
        loop {
            let reply = self.recv(&mut buf)?;
            if reply.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "netlink dump ended early",
                ));
            }
            if split_dump(reply, &mut out)? {
                return Ok(out);
            }
        }
    }

    /// Sends one request and waits for its ack.
    pub(crate) fn call(&self, req: Request) -> io::Result<()> {
        self.send(req)?;
        let mut buf = vec![0u8; 8192];
        loop {
            if let Some(result) = parse_ack(self.recv(&mut buf)?) {
                return result;
            }
        }
    }
}

/// Splits one datagram of a dump answer into its messages, appending them
/// to `out`. Returns true once `NLMSG_DONE` is seen.
pub(crate) fn split_dump(mut reply: &[u8], out: &mut Vec<Vec<u8>>) -> io::Result<bool> {
    while reply.len() >= 16 {
        let len = u32::from_ne_bytes(reply[0..4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(reply[4..6].try_into().unwrap());
        let flags = u16::from_ne_bytes(reply[6..8].try_into().unwrap());
        if len < 16 || len > reply.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed netlink reply",
            ));
        }
        match kind {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                let code = if len >= 20 {
                    i32::from_ne_bytes(reply[16..20].try_into().unwrap())
                } else {
                    -libc::EIO
                };
                if code != 0 {
                    return Err(io::Error::from_raw_os_error(-code));
                }
                return Ok(true);
            }
            _ => out.push(reply[..len].to_vec()),
        }
        if flags & NLM_F_MULTI == 0 {
            // A single answer, not a multipart one: it is complete.
            return Ok(true);
        }
        reply = &reply[((len + 3) & !3).min(reply.len())..];
    }
    Ok(false)
}

/// Finds the ack in a reply. `None` if the reply holds none.
pub(crate) fn parse_ack(mut reply: &[u8]) -> Option<io::Result<()>> {
    while reply.len() >= 16 {
        let len = u32::from_ne_bytes(reply[0..4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(reply[4..6].try_into().unwrap());
        if len < 16 || len > reply.len() {
            return Some(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed netlink reply",
            )));
        }
        if kind == NLMSG_ERROR {
            if len < 20 {
                return Some(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "short netlink error",
                )));
            }
            let code = i32::from_ne_bytes(reply[16..20].try_into().unwrap());
            return Some(if code == 0 {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(-code))
            });
        }
        let step = (len + 3) & !3;
        reply = &reply[step.min(reply.len())..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_request_layout() {
        let msg = add_address(7, "10.0.0.2".parse().unwrap(), 24).finish();
        // header (16) + ifaddrmsg (8) + IFA_LOCAL (8) + IFA_ADDRESS (8)
        assert_eq!(msg.len(), 40);
        assert_eq!(u32::from_ne_bytes(msg[0..4].try_into().unwrap()), 40);
        assert_eq!(
            u16::from_ne_bytes(msg[4..6].try_into().unwrap()),
            RTM_NEWADDR
        );
        assert_eq!(&msg[16..20], &[libc::AF_INET as u8, 24, 0, 0]);
        assert_eq!(u32::from_ne_bytes(msg[20..24].try_into().unwrap()), 7);
        assert_eq!(&msg[24..32], &[8, 0, 2, 0, 10, 0, 0, 2][..]);
    }

    #[test]
    fn route_request_layout() {
        let msg = add_default_route(3, "fd00::1".parse().unwrap()).finish();
        // header (16) + rtmsg (12) + RTA_GATEWAY (20) + RTA_OIF (8)
        assert_eq!(msg.len(), 56);
        assert_eq!(msg[16], libc::AF_INET6 as u8);
        assert_eq!(msg[17], 0);
        assert_eq!(
            u32::from_ne_bytes(msg[24..28].try_into().unwrap()),
            RTNH_F_ONLINK
        );
    }

    #[test]
    fn link_request_is_aligned() {
        for msg in [link_up(2, 1400).finish(), no_ipv6_link_local(2).finish()] {
            assert_eq!(msg.len() % 4, 0);
            assert_eq!(
                u32::from_ne_bytes(msg[0..4].try_into().unwrap()) as usize,
                msg.len()
            );
        }
    }

    #[test]
    fn acks_and_errors() {
        let mut ack = vec![0u8; 36];
        ack[0..4].copy_from_slice(&36u32.to_ne_bytes());
        ack[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        assert!(parse_ack(&ack).unwrap().is_ok());
        ack[16..20].copy_from_slice(&(-libc::EEXIST).to_ne_bytes());
        assert_eq!(
            parse_ack(&ack).unwrap().unwrap_err().raw_os_error(),
            Some(libc::EEXIST)
        );
        assert!(parse_ack(&[]).is_none());
    }

    /// A message as the kernel sends it in a dump: header, fixed body,
    /// attributes.
    fn dumped(kind: u16, body: &[u8], attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut req = Request::with_flags(kind, NLM_F_MULTI, body);
        for (k, d) in attrs {
            req.attr(*k, d);
        }
        req.finish()
    }

    fn rtmsg(
        family: u8,
        dst_len: u8,
        table: u8,
        protocol: u8,
        scope: u8,
        kind: u8,
        flags: u32,
    ) -> Vec<u8> {
        let mut b = vec![family, dst_len, 0, 0, table, protocol, scope, kind];
        b.extend_from_slice(&flags.to_ne_bytes());
        b
    }

    #[test]
    fn link_down_clears_only_up() {
        let msg = link_down(5).finish();
        // header (16) + ifinfomsg (16), no attributes
        assert_eq!(msg.len(), 32);
        assert_eq!(
            u16::from_ne_bytes(msg[4..6].try_into().unwrap()),
            RTM_NEWLINK
        );
        assert_eq!(i32::from_ne_bytes(msg[20..24].try_into().unwrap()), 5);
        assert_eq!(
            u32::from_ne_bytes(msg[24..28].try_into().unwrap()),
            0,
            "flags"
        );
        assert_eq!(
            u32::from_ne_bytes(msg[28..32].try_into().unwrap()),
            IFF_UP,
            "change mask"
        );
    }

    #[test]
    fn dump_requests_ask_for_a_dump_without_an_ack() {
        for (msg, kind, body) in [
            (dump_routes().finish(), RTM_GETROUTE, 12),
            (dump_addresses().finish(), RTM_GETADDR, 8),
        ] {
            assert_eq!(msg.len(), 16 + body);
            assert_eq!(u16::from_ne_bytes(msg[4..6].try_into().unwrap()), kind);
            assert_eq!(
                u16::from_ne_bytes(msg[6..8].try_into().unwrap()),
                NLM_F_REQUEST | NLM_F_DUMP
            );
            assert_eq!(msg[16], libc::AF_UNSPEC as u8);
        }
    }

    #[test]
    fn a_dumped_default_route_is_deleted_by_its_own_fields() {
        // default via 10.244.0.1 dev eth0 (index 2), as a pod has it, with
        // a cache-info attribute the delete must leave out.
        let body = rtmsg(
            libc::AF_INET as u8,
            0,
            RT_TABLE_MAIN,
            3,
            RT_SCOPE_UNIVERSE,
            RTN_UNICAST,
            0x10 | RTNH_F_ONLINK,
        );
        let msg = dumped(
            RTM_NEWROUTE,
            &body,
            &[
                (RTA_TABLE, &254u32.to_ne_bytes()),
                (RTA_GATEWAY, &[10, 244, 0, 1]),
                (RTA_OIF, &2u32.to_ne_bytes()),
                (12, &[0; 16]),
            ],
        );
        let route = Route::parse(&msg).unwrap();
        assert_eq!(route.oif, Some(2));
        assert_eq!(route.describe(), "default via 10.244.0.1");

        let del = route.delete().finish();
        assert_eq!(
            u16::from_ne_bytes(del[4..6].try_into().unwrap()),
            RTM_DELROUTE
        );
        assert_eq!(
            u16::from_ne_bytes(del[6..8].try_into().unwrap()),
            NLM_F_REQUEST | NLM_F_ACK
        );
        // The rtmsg is kept, but of its flags only "on link".
        assert_eq!(&del[16..24], &body[..8]);
        assert_eq!(
            u32::from_ne_bytes(del[24..28].try_into().unwrap()),
            RTNH_F_ONLINK
        );
        let kinds: Vec<u16> = attrs(&del, RTMSG_LEN).iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds, vec![RTA_TABLE, RTA_GATEWAY, RTA_OIF]);
        assert_eq!(
            u32::from_ne_bytes(del[0..4].try_into().unwrap()) as usize,
            del.len()
        );
    }

    #[test]
    fn a_dumped_v6_prefix_route_names_itself() {
        let body = rtmsg(
            libc::AF_INET6 as u8,
            64,
            RT_TABLE_MAIN,
            2,
            RT_SCOPE_UNIVERSE,
            RTN_UNICAST,
            0,
        );
        let dst: [u8; 16] = "fe80::".parse::<std::net::Ipv6Addr>().unwrap().octets();
        let msg = dumped(
            RTM_NEWROUTE,
            &body,
            &[
                (RTA_DST, &dst),
                (RTA_PRIORITY, &256u32.to_ne_bytes()),
                (RTA_OIF, &7u32.to_ne_bytes()),
            ],
        );
        let route = Route::parse(&msg).unwrap();
        assert_eq!(route.oif, Some(7));
        assert_eq!(route.describe(), "fe80::/64");
        let kinds: Vec<u16> = attrs(&route.delete().finish(), RTMSG_LEN)
            .iter()
            .map(|(k, _)| *k)
            .collect();
        assert_eq!(kinds, vec![RTA_DST, RTA_PRIORITY, RTA_OIF]);
        // A route with no device is kept apart from the link's.
        let msg = dumped(RTM_NEWROUTE, &body, &[(RTA_DST, &dst)]);
        assert_eq!(Route::parse(&msg).unwrap().oif, None);
        assert!(Route::parse(&msg[..20]).is_none());
    }

    #[test]
    fn a_dumped_address_is_deleted_by_its_addresses() {
        // 10.244.0.5/24 on index 2, with a label and cache info left out of
        // the delete.
        let body = [libc::AF_INET as u8, 24, 0, RT_SCOPE_UNIVERSE, 2, 0, 0, 0];
        let msg = dumped(
            RTM_NEWADDR,
            &body,
            &[
                (IFA_ADDRESS, &[10, 244, 0, 5]),
                (IFA_LOCAL, &[10, 244, 0, 5]),
                (3, b"eth0\0"),
                (6, &[0; 16]),
            ],
        );
        let a = Address::parse(&msg).unwrap();
        assert_eq!(a.index, 2);
        assert_eq!(a.addr, Some("10.244.0.5".parse().unwrap()));
        let del = a.delete().finish();
        assert_eq!(
            u16::from_ne_bytes(del[4..6].try_into().unwrap()),
            RTM_DELADDR
        );
        assert_eq!(&del[16..24], &body);
        let kinds: Vec<u16> = attrs(&del, IFADDRMSG_LEN).iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds, vec![IFA_ADDRESS, IFA_LOCAL]);
        // IPv6 has only IFA_ADDRESS.
        let v6 = "fe80::1".parse::<std::net::Ipv6Addr>().unwrap().octets();
        let msg = dumped(
            RTM_NEWADDR,
            &[libc::AF_INET6 as u8, 64, 0x80, 253, 2, 0, 0, 0],
            &[(IFA_ADDRESS, &v6)],
        );
        assert_eq!(
            Address::parse(&msg).unwrap().addr,
            Some("fe80::1".parse().unwrap())
        );
    }

    #[test]
    fn dumps_are_split_until_done() {
        let a = dumped(RTM_NEWROUTE, &[0; 12], &[(RTA_OIF, &1u32.to_ne_bytes())]);
        let b = dumped(RTM_NEWROUTE, &[0; 12], &[]);
        let mut done = vec![0u8; 20];
        done[0..4].copy_from_slice(&20u32.to_ne_bytes());
        done[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
        done[6..8].copy_from_slice(&NLM_F_MULTI.to_ne_bytes());

        let mut out = Vec::new();
        assert!(!split_dump(&[a.clone(), b.clone()].concat(), &mut out).unwrap());
        assert!(split_dump(&done, &mut out).unwrap());
        assert_eq!(out, vec![a, b]);

        // An error in place of the dump.
        let mut e = vec![0u8; 36];
        e[0..4].copy_from_slice(&36u32.to_ne_bytes());
        e[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        e[16..20].copy_from_slice(&(-libc::EPERM).to_ne_bytes());
        assert_eq!(
            split_dump(&e, &mut out).unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
        // A length past the end is malformed.
        let mut bad = done.clone();
        bad[0..4].copy_from_slice(&64u32.to_ne_bytes());
        assert!(split_dump(&bad, &mut out).is_err());
    }
}
