//! `fictionet attach --type tap`: a virtual machine's network card.
//!
//! The VM's Ethernet frames reach attach in one of two ways:
//!
//! - `--vm qemu:<path>`: QEMU's `-netdev stream` sends them over a Unix
//!   stream socket that attach listens on. No TAP device and no privileges
//!   are needed.
//! - `--vm tap:<name>`: the VM program (Firecracker, Cloud Hypervisor, or
//!   QEMU with `-netdev tap`) holds the TAP device `<name>`. A TAP device
//!   has only one file side, so attach makes a second one and has the
//!   kernel redirect every frame between the two with traffic control.
//!
//! Either way, attach answers the link-local questions itself (ARP, IPv6
//! neighbor discovery, and DHCP when the address flags are given), strips
//! the Ethernet header from the VM's IP packets on their way to the world,
//! and adds one to the world's packets on their way back.

use std::ffi::CString;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};

use fictionet::relay::{self, Message, unix};
use fictionet::stdlib::dhcp;

use crate::addresses;
use crate::args::{Family, TapArgs, VmLink};
use crate::ether::{self, Decoder, Frame, Mac, Outbox, Upper};
use crate::netlink::{self, Netlink};
use crate::tun;
use crate::world::{self, Failure, Greeting, err};

/// The VM's side of the link, as attach sees it: what to do with each
/// frame from the VM, and how to frame each packet from the world. It does
/// no I/O, so the tests drive it directly.
pub(crate) struct Link {
    v4: Family<Ipv4Addr>,
    v6: Family<Ipv6Addr>,
    mtu: u16,
    /// The VM's MAC, learned from its first frame.
    vm: Option<Mac>,
}

/// What to do with one frame from the VM.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FromVm<'a> {
    /// Send this IP packet to the world.
    World(&'a [u8]),
    /// Send this frame back to the VM: an answer attach gives itself.
    Answer(Vec<u8>),
    /// Drop the frame.
    Drop(Why),
}

/// Why a frame from the VM was dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Why {
    /// Shorter than its headers, an IP header that does not add up, or a
    /// transport attach cannot read (see [`ether::Unreadable`]).
    Malformed,
    /// Longer than the MTU allows.
    TooBig,
    /// From a MAC other than the VM's first one.
    OtherSource,
    /// To a unicast MAC other than attach's.
    NotForUs,
    /// Neither ARP, IPv4 nor IPv6 (VLAN tags and LLDP, for example).
    OtherType,
    /// A link-local message attach handled, or chose not to answer.
    Handled,
    /// An IP packet from a source other than the address attach handed
    /// out.
    Spoofed,
}

impl Link {
    pub(crate) fn new(v4: Family<Ipv4Addr>, v6: Family<Ipv6Addr>, mtu: u16) -> Link {
        Link { v4, v6, mtu, vm: None }
    }

    pub(crate) fn vm_mac(&self) -> Option<Mac> {
        self.vm
    }

    fn own_v4(&self) -> Option<Ipv4Addr> {
        match &self.v4 {
            Family::Serve(l) => Some(l.addr.addr),
            _ => None,
        }
    }

    fn own_v6(&self) -> Option<Ipv6Addr> {
        match &self.v6 {
            Family::Serve(l) => Some(l.addr.addr),
            _ => None,
        }
    }

    /// Decides what to do with one frame from the VM.
    pub(crate) fn frame_from_vm<'a>(&mut self, frame: &'a [u8]) -> FromVm<'a> {
        let Some(f) = Frame::parse(frame) else { return FromVm::Drop(Why::Malformed) };
        if frame.len() > ether::HEADER + self.mtu as usize {
            return FromVm::Drop(Why::TooBig);
        }
        if ether::is_group(&f.src) || f.src == [0; 6] {
            return FromVm::Drop(Why::OtherSource);
        }
        match self.vm {
            None => self.vm = Some(f.src),
            Some(vm) if vm != f.src => return FromVm::Drop(Why::OtherSource),
            Some(_) => {}
        }
        if !ether::is_group(&f.dst) && f.dst != ether::GATEWAY_MAC {
            return FromVm::Drop(Why::NotForUs);
        }
        match f.ethertype {
            ether::ARP => match ether::arp_reply(f.payload, f.src, self.own_v4()) {
                Some(reply) => FromVm::Answer(reply),
                None => FromVm::Drop(Why::Handled),
            },
            ether::IPV4 => match ether::ip_packet(ether::IPV4, f.payload) {
                Some(p) => self.ipv4(p, f.src),
                None => FromVm::Drop(Why::Malformed),
            },
            ether::IPV6 => match ether::ip_packet(ether::IPV6, f.payload) {
                Some(p) => self.ipv6(p, f.src),
                None => FromVm::Drop(Why::Malformed),
            },
            _ => FromVm::Drop(Why::OtherType),
        }
    }

    fn ipv4<'a>(&self, p: &'a [u8], vm: Mac) -> FromVm<'a> {
        let Ok(upper) = ether::upper(p) else { return FromVm::Drop(Why::Malformed) };
        match upper {
            Upper::Udp { port: dhcp::SERVER_PORT, payload: request } => {
                return match &self.v4 {
                    Family::Serve(lease) => match addresses::dhcp4(lease, self.mtu, request) {
                        Some((packet, broadcast)) => {
                            let to = if broadcast { ether::BROADCAST } else { vm };
                            FromVm::Answer(ether::frame(to, ether::GATEWAY_MAC, ether::IPV4, &packet))
                        }
                        None => FromVm::Drop(Why::Handled),
                    },
                    Family::FromWorld => FromVm::World(p),
                    Family::Off => FromVm::Drop(Why::Handled),
                };
            }
            // Attach does not put fragments back together, so it answers no
            // fragmented DHCP request, and lets none past when it owns DHCP.
            // The rest of the request cannot be put together in the world
            // without this first fragment.
            Upper::UdpFragment { port: dhcp::SERVER_PORT } if self.v4 != Family::FromWorld => {
                return FromVm::Drop(Why::Handled);
            }
            _ => {}
        }
        // Packets from 0.0.0.0, such as a multicast report sent before the
        // VM has an address, stay on the link: they cannot be answered.
        let src = ether::source_v4(p);
        if src.is_unspecified() && self.v4 != Family::FromWorld {
            return FromVm::Drop(Why::Handled);
        }
        match self.own_v4() {
            Some(own) if src != own => FromVm::Drop(Why::Spoofed),
            _ => FromVm::World(p),
        }
    }

    fn ipv6<'a>(&self, p: &'a [u8], vm: Mac) -> FromVm<'a> {
        let Ok(upper) = ether::upper(p) else { return FromVm::Drop(Why::Malformed) };
        match upper {
            // Neighbor discovery is never fragmented (RFC 6980), and only
            // makes sense on the link.
            Upper::Icmp6 { kind, fragment: true, .. } if ether::is_neighbor_discovery(kind) => {
                return FromVm::Drop(Why::Handled);
            }
            Upper::Icmp6 { kind: ether::NEIGHBOR_SOLICITATION, .. } => {
                return match ether::neighbor_advert(p, vm, self.own_v6()) {
                    Some(reply) => FromVm::Answer(reply),
                    None => FromVm::Drop(Why::Handled),
                };
            }
            Upper::Icmp6 { kind: ether::ROUTER_SOLICITATION, .. } => {
                return match &self.v6 {
                    Family::Serve(_) => match self.router_advert() {
                        Some(ra) => FromVm::Answer(ra),
                        None => FromVm::Drop(Why::Handled),
                    },
                    Family::FromWorld => FromVm::World(p),
                    Family::Off => FromVm::Drop(Why::Handled),
                };
            }
            // Advertisements and redirects only make sense on the link.
            Upper::Icmp6 { kind, .. } if ether::is_neighbor_discovery(kind) => {
                return FromVm::Drop(Why::Handled);
            }
            Upper::Udp { port: addresses::DHCP6_SERVER_PORT, payload: request } => {
                return match &self.v6 {
                    Family::Serve(lease) => match addresses::dhcp6(lease, request) {
                        Some(answer) => {
                            let packet = addresses::dhcp6_packet(p, &answer);
                            FromVm::Answer(ether::frame(vm, ether::GATEWAY_MAC, ether::IPV6, &packet))
                        }
                        None => FromVm::Drop(Why::Handled),
                    },
                    Family::FromWorld => FromVm::World(p),
                    Family::Off => FromVm::Drop(Why::Handled),
                };
            }
            // As for DHCP over IPv4: no answer to a fragment, and none past
            // when attach owns DHCPv6.
            Upper::UdpFragment { port: addresses::DHCP6_SERVER_PORT } if self.v6 != Family::FromWorld => {
                return FromVm::Drop(Why::Handled);
            }
            _ => {}
        }
        // Link-scope traffic, such as multicast listener reports, stays on
        // the link, unless the world was left to set up IPv6.
        let src = ether::source_v6(p);
        if self.v6 != Family::FromWorld && (src.is_unspecified() || src.is_unicast_link_local()) {
            return FromVm::Drop(Why::Handled);
        }
        match self.own_v6() {
            Some(own) if src != own => FromVm::Drop(Why::Spoofed),
            _ => FromVm::World(p),
        }
    }

    /// Whether attach hands out IPv6 addresses, and so sends router
    /// advertisements. Cheap, unlike building one with
    /// [`router_advert`](Link::router_advert).
    pub(crate) fn advertises(&self) -> bool {
        matches!(self.v6, Family::Serve(_))
    }

    /// A router advertisement frame, when attach hands out IPv6 addresses.
    pub(crate) fn router_advert(&self) -> Option<Vec<u8>> {
        let Family::Serve(lease) = &self.v6 else { return None };
        let ra = addresses::router_advert(lease, self.mtu);
        let (dst, _) = ether::destination(&ra, self.vm)?;
        Some(ether::frame(dst, ether::GATEWAY_MAC, ether::IPV6, &ra))
    }

    /// The Ethernet header for a packet from the world, or `None` to drop
    /// it: it is not IPv4 or IPv6, or is longer than the MTU.
    pub(crate) fn to_vm(&self, packet: &[u8]) -> Option<[u8; ether::HEADER]> {
        if packet.len() > self.mtu as usize {
            return None;
        }
        let (dst, ethertype) = ether::destination(packet, self.vm)?;
        Some(ether::header(dst, ether::GATEWAY_MAC, ethertype))
    }
}

/// Runs attach to the end. `Ok` means the VM's side or the world closed
/// its connection.
pub(crate) fn run(args: TapArgs) -> Result<(), Failure> {
    let mut lock = None;
    let result = match &args.vm {
        VmLink::Qemu(path) => run_qemu(&args, path, &mut lock),
        VmLink::Tap(name) => run_device(&args, name, &mut lock),
    };
    // The ready file is this attach's only once it holds the lock: an
    // attach that failed to take it leaves the running one's file alone.
    if lock.is_some() && let Some(path) = &args.ready_file {
        let _ = std::fs::remove_file(path);
    }
    // The lock is held until the process exits, which releases it. Until
    // then a new attach cannot start, so neither this cleanup nor the
    // signal handler can touch a new attach's ready file or redirect.
    std::mem::forget(lock);
    match result? {
        End::Qemu => eprintln!("fictionet attach: QEMU closed the connection; {} detached", args.name),
        End::DeviceGone(name) => eprintln!("fictionet attach: {name} was removed; {} detached", args.name),
        End::World => eprintln!("fictionet attach: the world closed the connection"),
    }
    Ok(())
}

fn greeting<'a>(args: &'a TapArgs) -> Greeting<'a> {
    Greeting { world: &args.world, world_wait: args.world_wait, kind: "tap", name: &args.name, mtu: args.mtu }
}

/// Marks this attach as the owner of its VM link: from here on, the ready
/// file is this attach's to clear, write and remove, on exit and on a
/// signal.
fn take_ready_file(args: &TapArgs, lock: &mut Option<OwnedFd>, held: OwnedFd) {
    *lock = Some(held);
    world::clear_ready_file(args.ready_file.as_deref());
    if let Some(path) = &args.ready_file {
        crate::remove_ready_on_signal(path);
    }
}

/// `--vm qemu:<path>`: takes the socket path's lock, listens, connects to
/// the world, then serves QEMU's one connection.
fn run_qemu(args: &TapArgs, path: &Path, lock: &mut Option<OwnedFd>) -> Result<End, Failure> {
    take_ready_file(args, lock, lock_path(path)?);
    let listener = listen(path).map_err(|e| Failure::Error(format!("listening at {}: {e}", path.display())))?;
    // Until QEMU connects, the socket file goes with this process.
    let mut unlink = Some(Unlink::new(path).map_err(err("checking the socket file"))?);
    let sock = world::handshake(&greeting(args))?;
    eprintln!("fictionet attach: {} attached; waiting for QEMU at {}", args.name, path.display());
    world::write_ready_file(args.ready_file.as_deref(), &args.name)?;
    let Some(vm) = accept(&listener, sock.as_raw_fd())? else { return Ok(End::World) };
    // One connection only: the socket file goes now, so a second QEMU
    // cannot connect, and a restarted attach can make a new one at the
    // same path.
    drop(listener);
    drop(unlink.take());
    eprintln!("fictionet attach: QEMU connected");
    let mut port = Port::Stream { fd: vm, decoder: Decoder::new(), outbox: Outbox::new(OUTBOX) };
    relay_and_report(args, &mut port, sock.as_raw_fd())
}

/// `--vm tap:<name>`: makes attach's own TAP device, redirects frames
/// between it and the VM's, then connects to the world.
fn run_device(args: &TapArgs, name: &str, lock: &mut Option<OwnedFd>) -> Result<End, Failure> {
    // Enter the namespace first, while the process has one thread.
    if let Some(netns) = &args.netns {
        tun::enter_netns(netns).map_err(err(&format!("entering the network namespace {}", netns.display())))?;
    }
    let vm_index = tun::index_of(name).map_err(|e| {
        Failure::Error(format!(
            "no device {name} ({e}). Make the VM's TAP device first, as the VM program's user: \
             ip tuntap add dev {name} mode tap user <user>"
        ))
    })?;
    take_ready_file(args, lock, lock_device(name, vm_index)?);
    let (fd, own) = open_tap(name)?;
    let own_index = tun::index_of(&own).map_err(err(&format!("finding {own}")))?;
    let mirror = Mirror::set_up(vm_index, name, own_index, &own, args.mtu)
        .map_err(|e| Failure::Error(format!("redirecting frames between {name} and {own}: {e}")))?;
    eprintln!("fictionet attach: frames from {name} go to {own}, and back");
    let sock = world::handshake(&greeting(args))?;
    eprintln!("fictionet attach: {} attached through {name}", args.name);
    world::write_ready_file(args.ready_file.as_deref(), &args.name)?;
    let mut port = Port::Device { fd, buf: vec![0u8; 65_536 + ether::HEADER], name: name.to_owned(), index: vm_index };
    let end = relay_and_report(args, &mut port, sock.as_raw_fd());
    drop(mirror);
    end
}

fn relay_and_report(args: &TapArgs, port: &mut Port, world: RawFd) -> Result<End, Failure> {
    let mut link = Link::new(args.v4.clone(), args.v6.clone(), args.mtu);
    let (end, stats) = relay(&mut link, port, world)?;
    stats.report();
    Ok(end)
}

/// Makes attach's own TAP device, with no offloads: the kernel finishes
/// checksums and splits large frames before attach reads them. Its name is
/// the VM's device's with `-fn` added, if that fits, else the kernel picks
/// one. Closing the returned fd removes the device.
fn open_tap(vm_dev: &str) -> Result<(OwnedFd, String), Failure> {
    let fd = tun::open_tun_file()?;
    let want = format!("{vm_dev}-fn");
    let want = if want.len() <= 15 { want } else { "fntap%d".to_owned() };
    let mut ifr = [0u8; 40];
    ifr[..want.len()].copy_from_slice(want.as_bytes());
    ifr[16..18].copy_from_slice(&(IFF_TAP | tun::IFF_NO_PI).to_ne_bytes());
    // SAFETY: `ifr` is as large as struct ifreq.
    if unsafe { libc::ioctl(fd.as_raw_fd(), tun::TUNSETIFF as _, ifr.as_mut_ptr()) } < 0 {
        let e = io::Error::last_os_error();
        return Err(Failure::Error(format!("creating the TAP device {want} (does attach have CAP_NET_ADMIN?): {e}")));
    }
    let len = ifr[..16].iter().position(|&b| b == 0).unwrap_or(16);
    Ok((fd, String::from_utf8_lossy(&ifr[..len]).into_owned()))
}

const IFF_TAP: libc::c_short = 0x0002;

/// The redirect between the VM's TAP device and attach's: an ingress qdisc
/// on each, with a filter that sends every frame out of the other. Dropping
/// it sets the VM's device down, so the kernel drops the VM's frames
/// instead of handing them to the namespace's IP stack, then removes its
/// qdisc. Attach's device goes with its fd.
struct Mirror {
    vm: u32,
}

/// One step of [`Mirror::set_up`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// Set the VM's device down. While it is down, the kernel refuses
    /// every frame the VM program writes to it, so none reaches the
    /// namespace's IP stack before the redirect is in place.
    VmDown,
    /// No IPv6 on this device, so the namespace's own stack sends nothing
    /// on it and takes no router advertisement from the VM. It fails
    /// harmlessly where IPv6 is off.
    NoIpv6(u32),
    /// Set the MTU of attach's device and bring it up.
    OwnUp,
    /// Remove a qdisc an earlier attach left on the VM's device.
    ClearVm,
    AddIngress(u32),
    Redirect { from: u32, to: u32 },
    /// Bring the VM's device up, once both redirects are in place.
    VmUp,
}

/// The steps of [`Mirror::set_up`], in order. The VM's device goes down
/// first and comes up last.
fn mirror_steps(vm: u32, own: u32) -> [Step; 10] {
    [
        Step::VmDown,
        Step::NoIpv6(vm),
        Step::NoIpv6(own),
        Step::OwnUp,
        Step::ClearVm,
        Step::AddIngress(vm),
        Step::Redirect { from: vm, to: own },
        Step::AddIngress(own),
        Step::Redirect { from: own, to: vm },
        Step::VmUp,
    ]
}

impl Mirror {
    fn set_up(vm: u32, vm_name: &str, own: u32, own_name: &str, mtu: u16) -> io::Result<Mirror> {
        let nl = Netlink::open()?;
        // The cleanup is in place before anything changes: dropping the
        // guard, or SIGTERM, SIGINT and SIGHUP (whose handler does the same
        // as dropping it), set the VM's device down and remove its qdisc.
        crate::netlink_on_signal([netlink::link_down(vm).finish(), netlink::del_ingress(vm).finish()].concat());
        let mirror = Mirror { vm };
        for step in mirror_steps(vm, own) {
            match step {
                Step::VmDown => {
                    nl.call(netlink::link_down(vm)).map_err(|e| context(e, "setting the VM's device down"))?;
                }
                Step::NoIpv6(index) => {
                    let name = if index == vm { vm_name } else { own_name };
                    let _ = nl.call(netlink::no_ipv6_link_local(index));
                    let _ = std::fs::write(format!("/proc/sys/net/ipv6/conf/{name}/disable_ipv6"), "1");
                }
                Step::OwnUp => {
                    nl.call(netlink::link_up(own, mtu as u32)).map_err(|e| context(e, "bringing up attach's device"))?;
                }
                Step::ClearVm => {
                    let _ = nl.call(netlink::del_ingress(vm));
                }
                Step::AddIngress(index) => {
                    nl.call(netlink::add_ingress(index)).map_err(|e| context(e, "adding an ingress qdisc"))?;
                }
                Step::Redirect { from, to } => {
                    nl.call(netlink::redirect_ingress(from, to)).map_err(|e| {
                        context(e, "adding the redirect (are the kernel modules cls_matchall and act_mirred there?)")
                    })?;
                }
                Step::VmUp => {
                    nl.call(netlink::set_up(vm)).map_err(|e| context(e, "bringing up the VM's device"))?;
                }
            }
        }
        Ok(mirror)
    }
}

impl Drop for Mirror {
    fn drop(&mut self) {
        if let Ok(nl) = Netlink::open() {
            let _ = nl.call(netlink::link_down(self.vm));
            let _ = nl.call(netlink::del_ingress(self.vm));
        }
    }
}

fn context(e: io::Error, what: &str) -> io::Error {
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

/// Takes the lock for a QEMU socket path: an exclusive `flock` on
/// `<path>.lock`, made with mode 0600 if it is missing, and held until
/// attach exits. One attach at a time owns a socket path, so a second one
/// stops here, before it touches the socket or the ready file. The lock
/// is on the file, not its name, so another spelling of the same path
/// finds it too. The file stays after attach exits; the kernel releases
/// the lock however attach ends.
fn lock_path(path: &Path) -> Result<OwnedFd, Failure> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut lock = path.as_os_str().to_owned();
    lock.push(".lock");
    let lock = Path::new(&lock);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(lock)
        .map_err(|e| Failure::Error(format!("opening the lock file {}: {e}", lock.display())))?;
    let fd = OwnedFd::from(file);
    // SAFETY: plain syscall on an fd we own.
    if unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::WouldBlock {
            return Err(Failure::Error(format!(
                "another attach is using {} (it holds {})",
                path.display(),
                lock.display()
            )));
        }
        return Err(Failure::Error(format!("locking {}: {e}", lock.display())));
    }
    Ok(fd)
}

/// Takes the lock for the VM's TAP device: a Unix socket bound to an
/// abstract name made from the device's index, in the device's network
/// namespace. One attach at a time owns a device, so a second one stops
/// here, before it touches the device, its redirect or the ready file.
/// The kernel frees the name however attach ends.
fn lock_device(name: &str, index: u32) -> Result<OwnedFd, Failure> {
    // SAFETY: plain syscall; the fd is owned from here.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(err("making the device lock")(io::Error::last_os_error()));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let id = format!("attach-tap/{index}");
    // SAFETY: an all-zero sockaddr_un is valid.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // sun_path[0] stays 0: an abstract name, with no file.
    for (dst, src) in addr.sun_path[1..].iter_mut().zip(id.as_bytes()) {
        *dst = *src as libc::c_char;
    }
    let len = std::mem::size_of::<libc::sa_family_t>() + 1 + id.len();
    // SAFETY: `addr` is a valid sockaddr_un of `len` bytes.
    if unsafe { libc::bind(fd.as_raw_fd(), (&raw const addr).cast(), len as libc::socklen_t) } < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EADDRINUSE) {
            return Err(Failure::Error(format!("another attach is using {name}")));
        }
        return Err(err("taking the device lock")(e));
    }
    Ok(fd)
}

/// Removes the socket file when dropped, and tells the signal handler to
/// remove it too while it lives. Either removes it only while it is still
/// the file attach made, so a newer attach's socket at the same path stays.
struct Unlink<'a> {
    path: &'a Path,
    id: (u64, u64),
}

impl<'a> Unlink<'a> {
    fn new(path: &'a Path) -> io::Result<Unlink<'a>> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(path)?;
        let id = (meta.dev(), meta.ino());
        crate::remove_on_signal(path, id);
        Ok(Unlink { path, id })
    }
}

impl Drop for Unlink<'_> {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        crate::keep_on_signal();
        if std::fs::symlink_metadata(self.path).is_ok_and(|m| (m.dev(), m.ino()) == self.id) {
            let _ = std::fs::remove_file(self.path);
        }
    }
}

/// Which side ended the relay.
enum End {
    /// QEMU closed its socket.
    Qemu,
    /// The VM's TAP device was removed.
    DeviceGone(String),
    /// The world closed its connection.
    World,
}

/// Listens on a Unix stream socket at `path`, mode 0600, so only attach's
/// user can connect. The caller holds the path's lock ([`lock_path`]), so
/// no other attach is listening there. A socket file left by an attach
/// that has exited is replaced. One that a live socket of another program
/// is bound to, as `/proc/net/unix` lists them, or any other file, is an
/// error.
fn listen(path: &Path) -> io::Result<OwnedFd> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::other("the path holds a NUL byte"))?;
    // SAFETY: plain syscall; the fd is owned from here.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let (addr, len) = sockaddr(&c)?;
    let bind = || {
        // The file is made with mode 0600. umask is per process, and attach
        // has one thread here.
        // SAFETY: plain syscalls; `addr` is a valid sockaddr_un.
        let old = unsafe { libc::umask(0o177) };
        let r = unsafe { libc::bind(fd.as_raw_fd(), (&raw const addr).cast(), len) };
        let e = io::Error::last_os_error();
        unsafe { libc::umask(old) };
        if r < 0 { Err(e) } else { Ok(()) }
    };
    match bind() {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EADDRINUSE) => {
            use std::os::unix::fs::FileTypeExt;
            let meta = std::fs::symlink_metadata(path)?;
            if !meta.file_type().is_socket() {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "the path exists and is not a socket"));
            }
            if socket_bound_at(path)? {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "a live socket is bound there, by a program other than attach",
                ));
            }
            std::fs::remove_file(path)?;
            bind()?;
        }
        Err(e) => return Err(e),
    }
    // SAFETY: plain syscall.
    if unsafe { libc::listen(fd.as_raw_fd(), 1) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Whether a socket in this network namespace is bound to `path`, as
/// `/proc/net/unix` lists them, by the path given or its absolute form.
fn socket_bound_at(path: &Path) -> io::Result<bool> {
    let list = std::fs::read("/proc/net/unix")?;
    let absolute = std::path::absolute(path)?;
    let want = [path.as_os_str().as_bytes(), absolute.as_os_str().as_bytes()];
    Ok(list.split(|&b| b == b'\n').skip(1).filter_map(bound_path).any(|p| want.contains(&p)))
}

/// The path in one line of `/proc/net/unix`: everything after its seven
/// fixed fields, spaces included. `None` for an unnamed socket.
fn bound_path(line: &[u8]) -> Option<&[u8]> {
    let mut rest = line;
    for _ in 0..7 {
        let start = rest.iter().position(|&b| b != b' ')?;
        rest = &rest[start..];
        let end = rest.iter().position(|&b| b == b' ')?;
        rest = &rest[end..];
    }
    let start = rest.iter().position(|&b| b != b' ')?;
    Some(&rest[start..])
}

fn sockaddr(path: &CString) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    // SAFETY: an all-zero sockaddr_un is valid.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_bytes();
    if bytes.is_empty() || bytes.len() >= addr.sun_path.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "the socket path must be 1 to 107 bytes"));
    }
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }
    let len = std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1;
    Ok((addr, len as libc::socklen_t))
}

/// Waits for QEMU to connect. `None` if the world closed its connection
/// first. Packets the world sends meanwhile are dropped, since there is no
/// VM to take them yet. Any other message ends attach with an error, as it
/// does once QEMU is connected.
fn accept(listener: &OwnedFd, world: RawFd) -> Result<Option<OwnedFd>, Failure> {
    let mut buf = vec![0u8; relay::MAX_MESSAGE + 1];
    loop {
        let mut fds = [
            libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: world, events: libc::POLLIN, revents: 0 },
        ];
        // SAFETY: `fds` is valid for the call.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Failure::Error(format!("poll: {e}")));
        }
        if fds[1].revents != 0 {
            loop {
                match unix::recv(world, &mut buf, true) {
                    Ok(0) => return Ok(None),
                    Ok(n) => {
                        world_packet(&buf[..n])?;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => return Ok(None),
                    Err(e) => return Err(Failure::Error(format!("reading from the world: {e}"))),
                }
            }
        }
        if fds[0].revents != 0 {
            // SAFETY: plain syscall; the fd is owned from here.
            let fd = unsafe {
                libc::accept4(
                    listener.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                )
            };
            if fd < 0 {
                let e = io::Error::last_os_error();
                if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted) {
                    continue;
                }
                return Err(Failure::Error(format!("accepting QEMU's connection: {e}")));
            }
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            unix::raise_buffers(fd.as_raw_fd());
            return Ok(Some(fd));
        }
    }
}

/// Counts of what the relay dropped.
#[derive(Default)]
struct Stats {
    /// Frames from the VM, by reason (handled link-local frames are not
    /// counted).
    from_vm: Vec<(Why, u64)>,
    /// Packets for the world that did not fit its connection's buffer.
    to_world_full: u64,
    /// Packets from the world that were not IP, or were over the MTU.
    from_world_bad: u64,
    /// Frames for the VM that did not fit the queue to QEMU.
    to_vm_full: u64,
}

impl Stats {
    fn drop_from_vm(&mut self, why: Why) {
        if why == Why::Handled {
            return;
        }
        match self.from_vm.iter_mut().find(|(w, _)| *w == why) {
            Some((_, n)) => *n += 1,
            None => self.from_vm.push((why, 1)),
        }
    }

    fn report(&self) {
        for (why, n) in &self.from_vm {
            let what = match why {
                Why::Malformed => "malformed",
                Why::TooBig => "over the MTU",
                Why::OtherSource => "from another MAC",
                Why::NotForUs => "for another MAC",
                Why::OtherType => "not ARP, IPv4 or IPv6",
                Why::Spoofed => "from an address attach did not hand out",
                Why::Handled => continue,
            };
            eprintln!("fictionet attach: {n} frames from the VM dropped: {what}");
        }
        if self.to_world_full > 0 {
            eprintln!("fictionet attach: {} packets to the world dropped on a full buffer", self.to_world_full);
        }
        if self.to_vm_full > 0 {
            eprintln!("fictionet attach: {} frames to the VM dropped on a full queue", self.to_vm_full);
        }
        if self.from_world_bad > 0 {
            eprintln!("fictionet attach: {} packets from the world dropped: not IP, or over the MTU", self.from_world_bad);
        }
    }
}

/// At most this many messages move one way before the other way gets a
/// turn.
const BATCH: usize = 64;

/// How much may wait to be written to QEMU. A burst from the world past
/// this is dropped, as a full network card queue would drop it.
const OUTBOX: usize = 4 << 20;

/// How often attach sends a router advertisement without being asked,
/// when it hands out IPv6 addresses. It is well inside the advertised
/// router lifetime of 30 minutes.
const RA_EVERY: Duration = Duration::from_secs(600);

/// The VM's end of the relay.
enum Port {
    /// QEMU's stream socket: frames with a length prefix, written through a
    /// queue because one frame may go out in pieces.
    Stream { fd: OwnedFd, decoder: Decoder, outbox: Outbox },
    /// Attach's TAP device: one frame per read and per write.
    Device {
        fd: OwnedFd,
        buf: Vec<u8>,
        /// The VM's device, checked every second: when it goes, so does
        /// the VM.
        name: String,
        index: u32,
    },
}

impl Port {
    fn fd(&self) -> RawFd {
        match self {
            Port::Stream { fd, .. } | Port::Device { fd, .. } => fd.as_raw_fd(),
        }
    }

    /// Sends one frame made of `parts` to the VM. `Ok(false)` if it was
    /// dropped on a full queue.
    fn send(&mut self, parts: &[&[u8]]) -> Result<bool, Failure> {
        match self {
            Port::Stream { outbox, .. } => Ok(outbox.push(parts)),
            Port::Device { fd, .. } => {
                let mut stack = [libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; 2];
                let heap: Vec<libc::iovec>;
                let iov: &[libc::iovec] = if parts.len() <= stack.len() {
                    for (v, p) in stack.iter_mut().zip(parts) {
                        *v = libc::iovec { iov_base: p.as_ptr() as *mut _, iov_len: p.len() };
                    }
                    &stack[..parts.len()]
                } else {
                    heap = parts.iter().map(|p| libc::iovec { iov_base: p.as_ptr() as *mut _, iov_len: p.len() }).collect();
                    &heap
                };
                // SAFETY: the iovecs point into `parts`, valid for the call.
                let n = unsafe { libc::writev(fd.as_raw_fd(), iov.as_ptr(), iov.len() as libc::c_int) };
                if n >= 0 {
                    return Ok(true);
                }
                let e = io::Error::last_os_error();
                match e.raw_os_error() {
                    Some(libc::EAGAIN | libc::ENOBUFS | libc::EINTR) => Ok(false),
                    // The kernel refused this one frame.
                    Some(libc::EINVAL | libc::EMSGSIZE) => Ok(false),
                    _ => Err(err("writing to attach's TAP device")(e)),
                }
            }
        }
    }
}

/// How often attach checks that the VM's TAP device is still there.
const DEVICE_CHECK: Duration = Duration::from_secs(1);

/// Moves frames and packets both ways until the VM's side or the world
/// closes its connection.
fn relay(link: &mut Link, port: &mut Port, world: RawFd) -> Result<(End, Stats), Failure> {
    let mut stats = Stats::default();
    let mut from_world = vec![0u8; relay::MAX_MESSAGE + 1];
    let mut learned = false;
    // A first advertisement right away: a VM that kept running while attach
    // restarted asks for none.
    let mut next_ra = Instant::now();
    let mut next_check = Instant::now() + DEVICE_CHECK;
    let vm = port.fd();
    loop {
        let now = Instant::now();
        if now >= next_ra
            && let Some(ra) = link.router_advert()
        {
            if !port.send(&[&ra])? {
                stats.to_vm_full += 1;
            }
            next_ra = now + RA_EVERY;
        }
        if let Port::Device { name, index, .. } = port
            && now >= next_check
        {
            if tun::index_of(name).ok() != Some(*index) {
                return Ok((End::DeviceGone(name.clone()), stats));
            }
            next_check = now + DEVICE_CHECK;
        }
        if let Port::Stream { outbox, .. } = port
            && !outbox.is_empty()
            && !flush(vm, outbox)?
        {
            return Ok((End::Qemu, stats));
        }

        let mut wake: Option<Instant> = None;
        if link.advertises() {
            wake = Some(next_ra);
        }
        if matches!(port, Port::Device { .. }) {
            wake = Some(wake.map_or(next_check, |w| w.min(next_check)));
        }
        let timeout = match wake {
            Some(at) => at.saturating_duration_since(Instant::now()).as_millis().min(i32::MAX as u128) as i32,
            None => -1,
        };
        let vm_events = match port {
            Port::Stream { outbox, .. } if !outbox.is_empty() => libc::POLLIN | libc::POLLOUT,
            _ => libc::POLLIN,
        };
        let mut fds = [
            libc::pollfd { fd: vm, events: vm_events, revents: 0 },
            libc::pollfd { fd: world, events: libc::POLLIN, revents: 0 },
        ];
        // SAFETY: `fds` is valid for the call.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout) } < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Failure::Error(format!("poll: {e}")));
        }

        if fds[1].revents != 0 {
            for _ in 0..BATCH {
                let n = match unix::recv(world, &mut from_world, true) {
                    Ok(0) => return Ok((End::World, stats)),
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => return Ok((End::World, stats)),
                    Err(e) => return Err(Failure::Error(format!("reading from the world: {e}"))),
                };
                let p = world_packet(&from_world[..n])?;
                match link.to_vm(p) {
                    Some(h) => {
                        if !port.send(&[&h, p])? {
                            stats.to_vm_full += 1;
                        }
                    }
                    None => stats.from_world_bad += 1,
                }
            }
        }

        if fds[0].revents & (libc::POLLERR | libc::POLLNVAL) != 0 && matches!(port, Port::Device { .. }) {
            return Err(Failure::Error("attach's TAP device failed".into()));
        }
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            // Answers wait here until the batch is read; past OUTBOX bytes,
            // more are dropped, as the queue to the VM would drop them.
            let mut answers: Vec<Vec<u8>> = Vec::new();
            let mut answer_bytes = 0;
            for _ in 0..BATCH {
                let mut handle = |frame: &[u8], stats: &mut Stats| -> Result<Option<End>, Failure> {
                    match link.frame_from_vm(frame) {
                        FromVm::World(p) => match unix::send_parts(world, &[&[relay::PACKET], p], true) {
                            Ok(()) => {}
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.raw_os_error() == Some(libc::ENOBUFS) => {
                                stats.to_world_full += 1;
                            }
                            Err(e) if matches!(e.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset) => {
                                return Ok(Some(End::World));
                            }
                            Err(e) => return Err(Failure::Error(format!("sending to the world: {e}"))),
                        },
                        FromVm::Answer(f) => {
                            if answer_bytes + f.len() > OUTBOX {
                                stats.to_vm_full += 1;
                            } else {
                                answer_bytes += f.len();
                                answers.push(f);
                            }
                        }
                        FromVm::Drop(why) => stats.drop_from_vm(why),
                    }
                    Ok(None)
                };
                match port {
                    Port::Stream { fd, decoder, .. } => {
                        let spare = decoder.spare();
                        // SAFETY: `spare` is valid for writes of its length.
                        let n = unsafe { libc::read(fd.as_raw_fd(), spare.as_mut_ptr().cast(), spare.len()) };
                        if n < 0 {
                            let e = io::Error::last_os_error();
                            match e.kind() {
                                io::ErrorKind::WouldBlock => break,
                                io::ErrorKind::Interrupted => continue,
                                io::ErrorKind::ConnectionReset => return Ok((End::Qemu, stats)),
                                _ => return Err(Failure::Error(format!("reading QEMU's socket: {e}"))),
                            }
                        }
                        if n == 0 {
                            return Ok((End::Qemu, stats));
                        }
                        decoder.filled(n as usize);
                        loop {
                            let frame = match decoder.next_frame() {
                                Ok(Some(f)) => f,
                                Ok(None) => break,
                                Err(ether::TooLong(len)) => {
                                    return Err(Failure::Error(format!(
                                        "QEMU's socket sent a frame length of {len} bytes; is it a -netdev stream socket?"
                                    )));
                                }
                            };
                            if let Some(end) = handle(frame, &mut stats)? {
                                return Ok((end, stats));
                            }
                        }
                    }
                    Port::Device { fd, buf, .. } => {
                        // SAFETY: `buf` is valid for writes of its length.
                        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
                        if n < 0 {
                            let e = io::Error::last_os_error();
                            match e.kind() {
                                io::ErrorKind::WouldBlock => break,
                                io::ErrorKind::Interrupted => continue,
                                _ => return Err(Failure::Error(format!("reading attach's TAP device: {e}"))),
                            }
                        }
                        if let Some(end) = handle(&buf[..n as usize], &mut stats)? {
                            return Ok((end, stats));
                        }
                    }
                }
            }
            for f in answers {
                if !port.send(&[&f])? {
                    stats.to_vm_full += 1;
                }
            }
            if !learned && let Some(mac) = link.vm_mac() {
                learned = true;
                let m = mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
                eprintln!("fictionet attach: the VM's MAC is {m}");
            }
        }
    }
}

/// Reads one message from the world. After `accept`, the relay protocol
/// allows only `packet`: anything else, a message the protocol cannot
/// decode, or one longer than its limit ends attach with an error.
fn world_packet(msg: &[u8]) -> Result<&[u8], Failure> {
    if msg.len() > relay::MAX_MESSAGE {
        return Err(Failure::Error("the world sent a message longer than 65,536 bytes".into()));
    }
    match relay::decode(msg) {
        Ok(Message::Packet(p)) => Ok(p),
        Ok(other) => Err(Failure::Error(format!("the world sent {other:?} after accept; closing"))),
        Err(e) => Err(Failure::Error(format!("the world sent a bad message: {e}; closing"))),
    }
}

/// Writes what the outbox holds, as far as QEMU's socket takes it.
/// `false` if QEMU closed the connection.
fn flush(vm: RawFd, outbox: &mut Outbox) -> Result<bool, Failure> {
    while !outbox.is_empty() {
        let p = outbox.pending();
        // SAFETY: `p` is valid for reads of its length. MSG_NOSIGNAL: a
        // closed socket is an error here, not a SIGPIPE.
        let n = unsafe { libc::send(vm, p.as_ptr().cast(), p.len(), libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
        if n < 0 {
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::WouldBlock => return Ok(true),
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => return Ok(false),
                _ => return Err(err("writing to QEMU's socket")(e)),
            }
        }
        outbox.written(n as usize);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{Cidr, Lease};
    use fictionet::stdlib::codec::Wire;
    use crate::ether::tests::{VM, solicitation};

    fn served() -> Link {
        Link::new(
            Family::Serve(Lease {
                addr: Cidr { addr: Ipv4Addr::new(10, 0, 0, 2), prefix: 24 },
                gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
                dns: Some(Ipv4Addr::new(10, 0, 0, 1)),
            }),
            Family::Serve(Lease {
                addr: Cidr { addr: "fd00::2".parse().unwrap(), prefix: 64 },
                gateway: Some("fd00::1".parse().unwrap()),
                dns: None,
            }),
            1500,
        )
    }

    fn eth(src: Mac, dst: Mac, ethertype: u16, payload: &[u8]) -> Vec<u8> {
        ether::frame(dst, src, ethertype, payload)
    }

    fn discover() -> Vec<u8> {
        let mut m = dhcp::Message::new(dhcp::BOOTREQUEST, 7);
        m.chaddr[..6].copy_from_slice(&VM);
        m.push(dhcp::opt::MESSAGE_TYPE, [dhcp::DISCOVER]);
        let p = ether::udp4(Ipv4Addr::UNSPECIFIED, 68, Ipv4Addr::BROADCAST, 67, &m.to_bytes().unwrap());
        eth(VM, ether::BROADCAST, ether::IPV4, &p)
    }

    #[test]
    fn learns_the_vm_mac_and_drops_other_sources() {
        let mut link = served();
        let ping = ether::ipv4(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1), 1, &[8, 0, 0, 0]);
        let f = eth(VM, ether::GATEWAY_MAC, ether::IPV4, &ping);
        assert_eq!(link.frame_from_vm(&f), FromVm::World(&ping[..]), "padding trimmed");
        assert_eq!(link.vm_mac(), Some(VM));
        let other = eth([0x52, 0, 0, 0, 0, 9], ether::GATEWAY_MAC, ether::IPV4, &ping);
        assert_eq!(link.frame_from_vm(&other), FromVm::Drop(Why::OtherSource));
        let group = eth([0x01, 0, 0, 0, 0, 9], ether::GATEWAY_MAC, ether::IPV4, &ping);
        assert_eq!(Link::new(Family::Off, Family::Off, 1500).frame_from_vm(&group), FromVm::Drop(Why::OtherSource));
        let elsewhere = eth(VM, [0x52, 0, 0, 0, 0, 1], ether::IPV4, &ping);
        assert_eq!(link.frame_from_vm(&elsewhere), FromVm::Drop(Why::NotForUs));
        assert_eq!(link.frame_from_vm(&eth(VM, ether::GATEWAY_MAC, 0x8100, &ping)), FromVm::Drop(Why::OtherType));
        assert_eq!(link.frame_from_vm(&f[..13]), FromVm::Drop(Why::Malformed));
        let mut lying = ping.clone();
        lying[2..4].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(link.frame_from_vm(&eth(VM, ether::GATEWAY_MAC, ether::IPV4, &lying)), FromVm::Drop(Why::Malformed));
    }

    #[test]
    fn the_vm_device_stays_down_until_both_redirects_are_in_place() {
        let steps = mirror_steps(7, 8);
        assert_eq!(steps[0], Step::VmDown, "down before anything else changes");
        assert_eq!(steps[steps.len() - 1], Step::VmUp, "up after everything else");
        let at = |s: Step| steps.iter().position(|&x| x == s).unwrap();
        assert!(at(Step::Redirect { from: 7, to: 8 }) < at(Step::VmUp));
        assert!(at(Step::Redirect { from: 8, to: 7 }) < at(Step::VmUp));
        assert!(at(Step::ClearVm) < at(Step::AddIngress(7)));
        assert!(at(Step::NoIpv6(7)) < at(Step::VmUp) && at(Step::NoIpv6(8)) < at(Step::OwnUp));
    }

    #[test]
    fn frames_over_the_mtu_are_dropped_both_ways() {
        let mut link = served();
        let big = ether::udp4(Ipv4Addr::new(10, 0, 0, 2), 1, Ipv4Addr::new(10, 0, 0, 1), 2, &[0; 1472]);
        assert_eq!(big.len(), 1500);
        assert!(matches!(link.frame_from_vm(&eth(VM, ether::GATEWAY_MAC, ether::IPV4, &big)), FromVm::World(_)));
        let bigger = ether::udp4(Ipv4Addr::new(10, 0, 0, 2), 1, Ipv4Addr::new(10, 0, 0, 1), 2, &[0; 1473]);
        assert_eq!(link.frame_from_vm(&eth(VM, ether::GATEWAY_MAC, ether::IPV4, &bigger)), FromVm::Drop(Why::TooBig));
        assert!(link.to_vm(&big).is_some());
        assert!(link.to_vm(&bigger).is_none());
        assert!(link.to_vm(&[0x10; 40]).is_none(), "not IP");
    }

    #[test]
    fn proc_net_unix_paths_keep_their_spaces() {
        let line = b"0000000000000000: 00000002 00000000 00010000 0001 01 4242 /tmp/vm one.sock";
        assert_eq!(bound_path(line), Some(&b"/tmp/vm one.sock"[..]));
        let unnamed = b"0000000000000000: 00000003 00000000 00000000 0001 03 4243";
        assert_eq!(bound_path(unnamed), None);
    }

    #[test]
    fn dhcp_is_answered_passed_or_dropped_by_the_flags() {
        let mut link = served();
        let FromVm::Answer(offer) = link.frame_from_vm(&discover()) else { panic!("no offer") };
        let f = Frame::parse(&offer).unwrap();
        assert_eq!((f.dst, f.src), (ether::BROADCAST, ether::GATEWAY_MAC));
        let (port, payload) = ether::udp_to(f.payload).unwrap();
        assert_eq!(port, 68);
        let m = dhcp::Message::parse(payload).unwrap();
        assert_eq!(m.yiaddr, Ipv4Addr::new(10, 0, 0, 2));

        let d = discover();
        let mut world = Link::new(Family::FromWorld, Family::Off, 1500);
        assert!(matches!(world.frame_from_vm(&d), FromVm::World(_)));
        let mut off = Link::new(Family::Off, Family::Off, 1500);
        assert_eq!(off.frame_from_vm(&d), FromVm::Drop(Why::Handled));
    }

    #[test]
    fn served_addresses_are_the_only_sources_passed() {
        let mut link = served();
        let spoof = ether::ipv4(Ipv4Addr::new(10, 0, 0, 77), Ipv4Addr::new(10, 0, 0, 1), 1, &[]);
        assert_eq!(link.frame_from_vm(&eth(VM, ether::GATEWAY_MAC, ether::IPV4, &spoof)), FromVm::Drop(Why::Spoofed));
        let spoof6 = ether::udp6("fd00::77".parse().unwrap(), 1, "fd00::1".parse().unwrap(), 2, &[]);
        assert_eq!(link.frame_from_vm(&eth(VM, ether::GATEWAY_MAC, ether::IPV6, &spoof6)), FromVm::Drop(Why::Spoofed));
        // A multicast listener report: a hop-by-hop header with a router
        // alert, then ICMPv6 type 143.
        let mld = ether::ipv6(
            ether::link_local(VM),
            "ff02::16".parse().unwrap(),
            0,
            1,
            &[ether::ICMPV6, 0, 5, 2, 0, 0, 1, 0, 143, 0, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(link.frame_from_vm(&eth(VM, [0x33, 0x33, 0, 0, 0, 0x16], ether::IPV6, &mld)), FromVm::Drop(Why::Handled));
        let ok6 = ether::udp6("fd00::2".parse().unwrap(), 1, "fd00::1".parse().unwrap(), 2, &[]);
        assert!(matches!(link.frame_from_vm(&eth(VM, ether::GATEWAY_MAC, ether::IPV6, &ok6)), FromVm::World(_)));
        // With the address left to the world, any source goes to the world,
        // which decides.
        let mut world = Link::new(Family::FromWorld, Family::FromWorld, 1500);
        assert!(matches!(world.frame_from_vm(&eth(VM, ether::GATEWAY_MAC, ether::IPV4, &spoof)), FromVm::World(_)));
    }

    #[test]
    fn neighbor_discovery_stays_on_the_link() {
        let mut link = served();
        let ll = ether::link_local(VM);
        let ns = solicitation(ll, "fd00::1".parse().unwrap(), 255);
        let FromVm::Answer(na) = link.frame_from_vm(&eth(VM, [0x33, 0x33, 0xff, 0, 0, 1], ether::IPV6, &ns)) else {
            panic!("no advertisement")
        };
        assert_eq!(Frame::parse(&na).unwrap().payload[40], ether::NEIGHBOR_ADVERTISEMENT);

        let rs = ether::icmp6(ll, "ff02::2".parse().unwrap(), vec![ether::ROUTER_SOLICITATION, 0, 0, 0, 0, 0, 0, 0]);
        let rs_frame = eth(VM, [0x33, 0x33, 0, 0, 0, 2], ether::IPV6, &rs);
        let FromVm::Answer(ra) = link.frame_from_vm(&rs_frame) else { panic!("no advertisement") };
        let f = Frame::parse(&ra).unwrap();
        assert_eq!(f.dst, [0x33, 0x33, 0, 0, 0, 1]);
        assert_eq!(f.payload[40], ether::ROUTER_ADVERTISEMENT);
        // Left to the world, the solicitation goes there; turned off, nowhere.
        let mut world = Link::new(Family::Off, Family::FromWorld, 1500);
        assert!(matches!(world.frame_from_vm(&rs_frame), FromVm::World(_)));
        assert!(world.router_advert().is_none());
        assert!(!world.advertises());
        assert!(link.advertises());
        let mut off = Link::new(Family::Off, Family::Off, 1500);
        assert_eq!(off.frame_from_vm(&rs_frame), FromVm::Drop(Why::Handled));
        // An advertisement from the VM never leaves the link.
        let ra_from_vm = ether::icmp6(ll, "ff02::1".parse().unwrap(), vec![ether::ROUTER_ADVERTISEMENT, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(link.frame_from_vm(&eth(VM, [0x33, 0x33, 0, 0, 0, 1], ether::IPV6, &ra_from_vm)), FromVm::Drop(Why::Handled));
        // Also behind a hop-by-hop header, with the world left to set up IPv6.
        let mut ext = vec![ether::ICMPV6, 0, 1, 4, 0, 0, 0, 0];
        ext.extend_from_slice(&ra_from_vm[40..]);
        let hidden = ether::ipv6(ll, "ff02::1".parse().unwrap(), 0, 255, &ext);
        let mut world = Link::new(Family::Off, Family::FromWorld, 1500);
        assert_eq!(world.frame_from_vm(&eth(VM, [0x33, 0x33, 0, 0, 0, 1], ether::IPV6, &hidden)), FromVm::Drop(Why::Handled));
    }

    #[test]
    fn dhcp6_is_answered_to_the_vm() {
        let mut link = served();
        let mut solicit = vec![1, 0, 0, 1];
        solicit.extend_from_slice(&[0, 1, 0, 10, 0, 3, 0, 1]);
        solicit.extend_from_slice(&VM);
        solicit.extend_from_slice(&[0, 3, 0, 12, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        let p = ether::udp6(ether::link_local(VM), 546, "ff02::1:2".parse().unwrap(), 547, &solicit);
        let FromVm::Answer(adv) = link.frame_from_vm(&eth(VM, [0x33, 0x33, 0, 1, 0, 2], ether::IPV6, &p)) else {
            panic!("no advertise")
        };
        let f = Frame::parse(&adv).unwrap();
        assert_eq!(f.dst, VM);
        let (port, payload) = ether::udp_to(f.payload).unwrap();
        assert_eq!((port, payload[0]), (546, 2));
    }

    #[test]
    fn arp_for_the_gateway() {
        let mut link = served();
        let mut a = vec![0, 1, 8, 0, 6, 4, 0, 1];
        a.extend_from_slice(&VM);
        a.extend_from_slice(&[10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1]);
        let FromVm::Answer(reply) = link.frame_from_vm(&eth(VM, ether::BROADCAST, ether::ARP, &a)) else { panic!("no reply") };
        assert_eq!(&Frame::parse(&reply).unwrap().payload[8..18], &[0x02, 0x66, 0x6e, 0, 0, 1, 10, 0, 0, 1]);
    }

    /// `n` destination options headers in front of `inner`, whose protocol
    /// is `proto`, in an IPv6 packet with hop limit 255.
    fn behind_options(src: Ipv6Addr, dst: Ipv6Addr, n: usize, proto: u8, inner: &[u8]) -> Vec<u8> {
        let mut ext = Vec::new();
        for i in 0..n {
            ext.extend_from_slice(&[if i + 1 == n { proto } else { 60 }, 0, 1, 4, 0, 0, 0, 0]);
        }
        ext.extend_from_slice(inner);
        ether::ipv6(src, dst, if n == 0 { proto } else { 60 }, 255, &ext)
    }

    /// The first `cut` bytes of `packet`'s payload as an IPv6 first
    /// fragment, and the rest as the second.
    fn fragments6(packet: &[u8], cut: usize) -> (Vec<u8>, Vec<u8>) {
        let (src, dst) = (ether::source_v6(packet), Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap()));
        let body = &packet[40..];
        let mut first = vec![packet[6], 0, 0, 1, 0, 0, 0, 42];
        first.extend_from_slice(&body[..cut]);
        let mut second = vec![packet[6], 0];
        second.extend_from_slice(&(cut as u16).to_be_bytes());
        second.extend_from_slice(&[0, 0, 0, 42]);
        second.extend_from_slice(&body[cut..]);
        (ether::ipv6(src, dst, 44, packet[7], &first), ether::ipv6(src, dst, 44, packet[7], &second))
    }

    /// The first `cut` bytes of `packet`'s payload as an IPv4 first
    /// fragment, and the rest as the second.
    fn fragments4(packet: &[u8], cut: usize) -> (Vec<u8>, Vec<u8>) {
        let (src, dst) = (ether::source_v4(packet), Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]));
        let mut first = ether::ipv4(src, dst, packet[9], &packet[20..20 + cut]);
        first[6] = 0x20;
        let mut second = ether::ipv4(src, dst, packet[9], &packet[20 + cut..]);
        second[6..8].copy_from_slice(&((cut / 8) as u16).to_be_bytes());
        (first, second)
    }

    #[test]
    fn control_messages_behind_any_extension_headers_stay_on_the_link() {
        let ll = ether::link_local(VM);
        let all: Ipv6Addr = "ff02::1".parse().unwrap();
        let ra = ether::icmp6(ll, all, vec![ether::ROUTER_ADVERTISEMENT, 0, 0, 0, 64, 0, 0, 0]);
        let to_all = [0x33, 0x33, 0, 0, 0, 1];
        for v6 in [Family::FromWorld, Family::Off] {
            let mut link = Link::new(Family::Off, v6, 1500);
            for n in [1, 8, 9, 30] {
                let p = behind_options(ll, all, n, ether::ICMPV6, &ra[40..]);
                assert_eq!(link.frame_from_vm(&eth(VM, to_all, ether::IPV6, &p)), FromVm::Drop(Why::Handled), "{n}");
            }
            // Behind an authentication header.
            let mut ah = vec![ether::ICMPV6, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            ah.extend_from_slice(&ra[40..]);
            let p = ether::ipv6(ll, all, 51, 255, &ah);
            assert_eq!(link.frame_from_vm(&eth(VM, to_all, ether::IPV6, &p)), FromVm::Drop(Why::Handled));
            // A redirect in a first fragment.
            let redirect = ether::icmp6(ll, all, [vec![ether::REDIRECT, 0, 0, 0], vec![0; 36]].concat());
            let (first, _) = fragments6(&redirect, 8);
            assert_eq!(link.frame_from_vm(&eth(VM, to_all, ether::IPV6, &first)), FromVm::Drop(Why::Handled));
            // A chain that cannot be read is dropped, not passed on.
            let cut = ether::ipv6(ll, all, 60, 255, &[ether::ICMPV6, 3, 0, 0, 0, 0, 0, 0]);
            assert_eq!(link.frame_from_vm(&eth(VM, to_all, ether::IPV6, &cut)), FromVm::Drop(Why::Malformed));
        }
    }

    #[test]
    fn a_fragmented_neighbor_solicitation_is_not_answered() {
        let mut link = served();
        let ns = solicitation(ether::link_local(VM), "fd00::1".parse().unwrap(), 255);
        let (first, _) = fragments6(&ns, 24);
        assert_eq!(
            link.frame_from_vm(&eth(VM, [0x33, 0x33, 0xff, 0, 0, 1], ether::IPV6, &first)),
            FromVm::Drop(Why::Handled)
        );
        // An atomic fragment (offset 0, no more fragments) is not answered
        // either, and a router solicitation in one does not reach the world.
        let atomic = |p: &[u8]| {
            let mut body = vec![p[6], 0, 0, 0, 0, 0, 0, 9];
            body.extend_from_slice(&p[40..]);
            ether::ipv6(ether::source_v6(p), Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).unwrap()), 44, 255, &body)
        };
        let to = [0x33, 0x33, 0xff, 0, 0, 1];
        assert_eq!(link.frame_from_vm(&eth(VM, to, ether::IPV6, &atomic(&ns))), FromVm::Drop(Why::Handled));
        let ll = ether::link_local(VM);
        let rs = ether::icmp6(ll, "ff02::2".parse().unwrap(), vec![ether::ROUTER_SOLICITATION, 0, 0, 0, 0, 0, 0, 0]);
        let mut world = Link::new(Family::Off, Family::FromWorld, 1500);
        let to = [0x33, 0x33, 0, 0, 0, 2];
        assert_eq!(world.frame_from_vm(&eth(VM, to, ether::IPV6, &atomic(&rs))), FromVm::Drop(Why::Handled));
    }

    #[test]
    fn fragmented_dhcp_is_never_answered_and_passes_only_when_left_to_the_world() {
        // A DISCOVER from a static address, split in two.
        let mut m = dhcp::Message::new(dhcp::BOOTREQUEST, 7);
        m.chaddr[..6].copy_from_slice(&VM);
        m.push(dhcp::opt::MESSAGE_TYPE, [dhcp::DISCOVER]);
        let whole = ether::udp4(Ipv4Addr::new(10, 0, 0, 2), 68, Ipv4Addr::BROADCAST, 67, &m.to_bytes().unwrap());
        let (first, second) = fragments4(&whole, 64);
        let frame = |p: &[u8]| eth(VM, ether::BROADCAST, ether::IPV4, p);
        let mut off = Link::new(Family::Off, Family::Off, 1500);
        assert_eq!(off.frame_from_vm(&frame(&whole)), FromVm::Drop(Why::Handled));
        assert_eq!(off.frame_from_vm(&frame(&first)), FromVm::Drop(Why::Handled), "--no-ip-addr");
        // The second fragment alone carries no UDP header, and the world
        // cannot put the request together without the first.
        assert!(matches!(off.frame_from_vm(&frame(&second)), FromVm::World(_)));
        let mut link = served();
        assert_eq!(link.frame_from_vm(&frame(&first)), FromVm::Drop(Why::Handled), "attach answers no fragment");
        let mut world = Link::new(Family::FromWorld, Family::Off, 1500);
        assert!(matches!(world.frame_from_vm(&frame(&first)), FromVm::World(_)), "left to the world");
        // A first fragment cut inside the UDP header cannot be read.
        let (stub, _) = fragments4(&whole, 0);
        assert_eq!(off.frame_from_vm(&frame(&stub)), FromVm::Drop(Why::Malformed));
    }

    #[test]
    fn a_first_fragment_of_a_dhcp6_solicit_gets_no_answer() {
        let mut solicit = vec![1, 0, 0, 1];
        solicit.extend_from_slice(&[0, 1, 0, 10, 0, 3, 0, 1]);
        solicit.extend_from_slice(&VM);
        solicit.extend_from_slice(&[0, 3, 0, 12, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
        solicit.extend_from_slice(&[0; 80]);
        let whole = ether::udp6(ether::link_local(VM), 546, "ff02::1:2".parse().unwrap(), 547, &solicit);
        let (first, _) = fragments6(&whole, 48);
        let to = [0x33, 0x33, 0, 1, 0, 2];
        let mut link = served();
        assert_eq!(link.frame_from_vm(&eth(VM, to, ether::IPV6, &first)), FromVm::Drop(Why::Handled));
        let mut off = Link::new(Family::Off, Family::Off, 1500);
        assert_eq!(off.frame_from_vm(&eth(VM, to, ether::IPV6, &first)), FromVm::Drop(Why::Handled));
        let mut world = Link::new(Family::Off, Family::FromWorld, 1500);
        assert!(matches!(world.frame_from_vm(&eth(VM, to, ether::IPV6, &first)), FromVm::World(_)));
        // A UDP length that does not fit the packet is not clamped to it.
        let mut lying = whole.clone();
        lying[44..46].copy_from_slice(&200u16.to_be_bytes());
        assert_eq!(link.frame_from_vm(&eth(VM, to, ether::IPV6, &lying)), FromVm::Drop(Why::Malformed));
    }

    #[test]
    fn world_packets_get_the_vm_or_group_mac() {
        let mut link = served();
        let to_vm = ether::ipv4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2), 1, &[]);
        assert_eq!(link.to_vm(&to_vm).unwrap()[..6], ether::BROADCAST, "before the VM's MAC is known");
        link.frame_from_vm(&discover());
        let h = link.to_vm(&to_vm).unwrap();
        assert_eq!(h, ether::header(VM, ether::GATEWAY_MAC, ether::IPV4));
    }
}
