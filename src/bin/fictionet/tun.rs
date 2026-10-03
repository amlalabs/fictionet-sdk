//! `fictionet attach --type tun`: a TUN device in the sandbox's network
//! namespace, relayed to the world over its Unix socket.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use fictionet::relay::{self, Message, unix};

use crate::args::{AttachArgs, ResolvConf};
use crate::netlink::{self, Netlink};
use crate::world::{self, Failure, Greeting, err};

/// Runs attach to the end. `Ok` means the world closed the connection.
pub(crate) fn run(args: AttachArgs) -> Result<(), Failure> {
    world::clear_ready_file(args.ready_file.as_deref());

    // Enter the sandbox's namespace first, so the device is made there.
    // This must happen while the process has one thread.
    if let Some(netns) = &args.netns {
        enter_netns(netns).map_err(err(&format!("entering the network namespace {}", netns.display())))?;
    }

    for link in &args.down_links {
        take_down(link).map_err(|e| Failure::Error(format!("--down-link {link}: {e}")))?;
        eprintln!("fictionet attach: {link} is down, with no routes or addresses");
    }

    let (tun, dev) = open_tun()?;
    configure(&args, &dev).map_err(|e| Failure::Error(format!("configuring {dev}: {e}")))?;

    let sock = world::handshake(&Greeting {
        world: &args.world,
        world_wait: args.world_wait,
        kind: "tun",
        name: &args.name,
        mtu: args.mtu,
    })?;
    eprintln!("fictionet attach: {} attached as {dev}", args.name);

    if let Some(path) = resolv_conf_path(&args) {
        write_resolv_conf(&path, &args.dns_servers()).map_err(|e| {
            Failure::Error(format!(
                "writing the DNS servers to {}: {e}. Give --resolv-conf another path, or \
                 --no-resolv-conf to leave DNS to the harness",
                path.display()
            ))
        })?;
    }
    world::write_ready_file(args.ready_file.as_deref(), &args.name)?;

    let result = relay_packets(tun.as_raw_fd(), sock.as_raw_fd());
    if let Some(path) = &args.ready_file {
        let _ = fs::remove_file(path);
    }
    // Closing the tun fd removes the device: it was never made persistent.
    drop(tun);
    drop(sock);
    match result {
        Ok(stats) => {
            eprintln!("fictionet attach: the world closed the connection; {dev} removed");
            if stats.dropped > 0 {
                eprintln!("fictionet attach: {} packets dropped on full buffers", stats.dropped);
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

pub(crate) fn enter_netns(path: &Path) -> io::Result<()> {
    let file = fs::File::open(path)?;
    // SAFETY: plain syscall on an fd we own.
    if unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const TUNGETIFF: libc::c_ulong = 0x8004_54d2;
const IFF_TUN: libc::c_short = 0x0001;
pub(crate) const IFF_NO_PI: libc::c_short = 0x1000;

const TUN_PATH: &str = "/dev/net/tun";

/// Opens `/dev/net/tun`. If the node is missing, as in a Kubernetes
/// container that was given no devices, attach makes it first (character
/// device 10:200). That needs `CAP_MKNOD`, and the runtime's device rules
/// must allow the device: runc's own rules do, except in runc 1.2.0 to
/// 1.2.3.
pub(crate) fn open_tun_file() -> Result<OwnedFd, Failure> {
    let open = || {
        let path = c"/dev/net/tun";
        // SAFETY: plain syscall; the fd is owned from here.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if fd < 0 { Err(io::Error::last_os_error()) } else { Ok(unsafe { OwnedFd::from_raw_fd(fd) }) }
    };
    let blocked = |e: io::Error| {
        Failure::Error(format!(
            "opening {TUN_PATH}: {e}. The container runtime's device rules do not allow the tun \
             device (char 10:200). Give the container the device (docker --device /dev/net/tun), or \
             check the runtime: runc 1.2.0 to 1.2.3 leave tun out of their default rules"
        ))
    };
    match open() {
        Ok(fd) => return Ok(fd),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => return Err(blocked(e)),
        Err(e) => return Err(Failure::Error(format!("opening {TUN_PATH}: {e}"))),
    }
    make_tun_node().map_err(|e| {
        Failure::Error(format!(
            "{TUN_PATH} is missing, and attach could not make it: {e}. Give attach CAP_MKNOD, \
             or give the container the device (docker --device /dev/net/tun)"
        ))
    })?;
    eprintln!("fictionet attach: made {TUN_PATH} (char 10:200)");
    open().map_err(blocked)
}

/// `mkdir -p /dev/net` and `mknod /dev/net/tun c 10 200`, mode 0666 as
/// udev makes it.
fn make_tun_node() -> io::Result<()> {
    match fs::create_dir("/dev/net") {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(context(e, "making /dev/net")),
    }
    let path = c"/dev/net/tun";
    // SAFETY: plain syscall on a valid C string.
    let r = unsafe { libc::mknod(path.as_ptr(), libc::S_IFCHR | 0o666, libc::makedev(10, 200)) };
    if r < 0 {
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::AlreadyExists {
            return Err(e);
        }
    }
    Ok(())
}

/// Creates a tun device without packet info. The kernel picks the name
/// (`tun0`, `tun1`, ...). The device is removed when the fd is closed.
fn open_tun() -> Result<(OwnedFd, String), Failure> {
    let fd = open_tun_file()?;
    make_tun_device(fd).map_err(err("creating the tun device (does attach have CAP_NET_ADMIN?)"))
}

fn make_tun_device(fd: OwnedFd) -> io::Result<(OwnedFd, String)> {
    // struct ifreq: a 16-byte name, then a union; flags are a short at 16.
    let mut ifr = [0u8; 40];
    ifr[16..18].copy_from_slice(&(IFF_TUN | IFF_NO_PI).to_ne_bytes());
    // SAFETY: `ifr` is as large as struct ifreq.
    if unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, ifr.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if ifr[0] == 0 {
        // gVisor makes the device but does not write its name back. Ask
        // for it.
        // SAFETY: `ifr` is as large as struct ifreq.
        if unsafe { libc::ioctl(fd.as_raw_fd(), TUNGETIFF as _, ifr.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let len = ifr[..16].iter().position(|&b| b == 0).unwrap_or(16);
    if len == 0 {
        return Err(io::Error::other("the kernel gave the tun device no name"));
    }
    let name = String::from_utf8_lossy(&ifr[..len]).into_owned();
    Ok((fd, name))
}

/// `--down-link`: deletes every route through `link` (IPv4 and IPv6, in
/// every table), then its addresses, then sets it down. The routes are
/// deleted one by one rather than left to the link going down, so the
/// result does not depend on what the kernel does then.
fn take_down(link: &str) -> io::Result<()> {
    let index = index_of(link).map_err(|e| context(e, "no such link"))?;
    let nl = Netlink::open()?;
    let routes = nl.dump(netlink::dump_routes()).map_err(|e| context(e, "listing the routes"))?;
    for route in routes.iter().filter_map(|m| netlink::Route::parse(m)) {
        if route.oif != Some(index) {
            continue;
        }
        match nl.call(route.delete()) {
            Ok(()) => {}
            // Gone already: deleting an earlier one took it too.
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
            Err(e) => return Err(context(e, &format!("deleting the route {}", route.describe()))),
        }
    }
    let addresses = nl.dump(netlink::dump_addresses()).map_err(|e| context(e, "listing the addresses"))?;
    for address in addresses.iter().filter_map(|m| netlink::Address::parse(m)) {
        if address.index != index {
            continue;
        }
        match nl.call(address.delete()) {
            Ok(()) => {}
            Err(e) if matches!(e.raw_os_error(), Some(libc::EADDRNOTAVAIL | libc::ESRCH)) => {}
            Err(e) => {
                let what = address.addr.map(|a| a.to_string()).unwrap_or_else(|| "an address".into());
                return Err(context(e, &format!("deleting the address {what}")));
            }
        }
    }
    nl.call(netlink::link_down(index)).map_err(|e| context(e, "setting it down"))?;
    Ok(())
}

pub(crate) fn index_of(dev: &str) -> io::Result<u32> {
    let c = std::ffi::CString::new(dev).unwrap();
    // SAFETY: `c` is a valid C string.
    let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if index == 0 { Err(io::Error::last_os_error()) } else { Ok(index) }
}

/// Sets the MTU, addresses and default routes, and brings the device up.
fn configure(args: &AttachArgs, dev: &str) -> io::Result<()> {
    let index = index_of(dev)?;
    let nl = Netlink::open()?;
    let no_v6 = args.ip_addr_v6.value().is_none() && args.gateway_v6.value().is_none();
    if no_v6 {
        // Without IPv6 the kernel may refuse this (IPv6 turned off on the
        // device), and then there is no link-local address anyway.
        let _ = nl.call(netlink::no_ipv6_link_local(index));
    }
    nl.call(netlink::link_up(index, args.mtu as u32)).map_err(|e| context(e, "bringing the device up"))?;
    if let Some(a) = args.ip_addr.value() {
        nl.call(netlink::add_address(index, IpAddr::V4(a.addr), a.prefix))
            .map_err(|e| context(e, "adding the IPv4 address"))?;
    }
    if let Some(a) = args.ip_addr_v6.value() {
        nl.call(netlink::add_address(index, IpAddr::V6(a.addr), a.prefix)).map_err(|e| {
            context(e, "adding the IPv6 address (is IPv6 turned off? set the sysctl net.ipv6.conf.default.disable_ipv6=0)")
        })?;
    }
    if let Some(gw) = args.gateway.value() {
        nl.call(netlink::add_default_route(index, IpAddr::V4(*gw))).map_err(|e| default_route_error(e, "IPv4"))?;
    }
    if let Some(gw) = args.gateway_v6.value() {
        nl.call(netlink::add_default_route(index, IpAddr::V6(*gw))).map_err(|e| default_route_error(e, "IPv6"))?;
    }
    Ok(())
}

/// `EEXIST` here means another link already has the default route, as
/// every Kubernetes pod's `eth0` does. Say how to clear it.
fn default_route_error(e: io::Error, family: &str) -> io::Error {
    if e.raw_os_error() == Some(libc::EEXIST) {
        return io::Error::new(
            e.kind(),
            format!(
                "adding the {family} default route: another link already has one ({e}). \
                 Give --down-link <ifname> for that link (in a Kubernetes pod, --down-link eth0), \
                 or remove its default route first"
            ),
        );
    }
    context(e, &format!("adding the {family} default route"))
}

fn context(e: io::Error, what: &str) -> io::Error {
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

/// Where `--dns` goes: the `--resolv-conf` path, nowhere with
/// `--no-resolv-conf`, and otherwise attach's own `/etc/resolv.conf`, or with
/// `--netns`, `/etc/netns/<name>/resolv.conf`, which `ip netns exec` mounts
/// over `/etc/resolv.conf`.
fn resolv_conf_path(args: &AttachArgs) -> Option<PathBuf> {
    match &args.resolv_conf {
        ResolvConf::Off => None,
        ResolvConf::Path(path) => Some(path.clone()),
        ResolvConf::Default => Some(match args.netns.as_ref().and_then(|p| p.file_name()) {
            Some(name) => Path::new("/etc/netns").join(name).join("resolv.conf"),
            None => PathBuf::from("/etc/resolv.conf"),
        }),
    }
}

pub(crate) fn resolv_conf(servers: &[IpAddr]) -> String {
    let mut out = String::from("# Written by fictionet attach.\n");
    for s in servers {
        out.push_str(&format!("nameserver {s}\n"));
    }
    out
}

/// Writes the DNS servers to `path`, making its directory if needed. The
/// file is rewritten in place, never replaced: Docker bind-mounts
/// `/etc/resolv.conf`, so a new file could not take its place. A container
/// that joins attach's network with `network_mode: "service:..."` has the
/// same host file mounted, so it sees the change too.
/// With both `--no-dns` and `--no-dns-v6`, the file lists no servers.
fn write_resolv_conf(path: &Path, servers: &[IpAddr]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut f = OpenOptions::new().write(true).create(true).truncate(true).open(path)?;
    f.write_all(resolv_conf(servers).as_bytes())?;
    f.flush()
}

#[derive(Default)]
struct Stats {
    dropped: u64,
}

/// At most this many packets move one way before the other way gets a turn.
const BATCH: usize = 64;

/// Moves packets both ways until the world closes the connection.
fn relay_packets(tun: RawFd, sock: RawFd) -> Result<Stats, Failure> {
    let mut stats = Stats::default();
    let mut from_tun = vec![0u8; 65_536];
    let mut from_world = vec![0u8; relay::MAX_MESSAGE + 1];
    loop {
        let mut fds = [
            libc::pollfd { fd: tun, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: sock, events: libc::POLLIN, revents: 0 },
        ];
        // SAFETY: `fds` is valid for the call.
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Failure::Error(format!("poll: {e}")));
        }

        if fds[1].revents != 0 {
            for _ in 0..BATCH {
                let n = match unix::recv(sock, &mut from_world, true) {
                    Ok(0) => return Ok(stats),
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => return Ok(stats),
                    Err(e) => return Err(Failure::Error(format!("reading from the world: {e}"))),
                };
                if n > relay::MAX_MESSAGE {
                    return Err(Failure::Error("the world sent a message longer than 65,536 bytes".into()));
                }
                match relay::decode(&from_world[..n]) {
                    Ok(Message::Packet(p)) => {
                        // SAFETY: `p` is valid for reads of its length.
                        let w = unsafe { libc::write(tun, p.as_ptr().cast(), p.len()) };
                        if w < 0 {
                            // A full queue drops the packet. So does a packet
                            // the kernel will not take (EINVAL: not IPv4 or
                            // IPv6), which a world may send on purpose.
                            stats.dropped += 1;
                        }
                    }
                    Ok(other) => {
                        return Err(Failure::Error(format!("the world sent {other:?} after accept; closing")));
                    }
                    Err(e) => return Err(Failure::Error(format!("the world sent a bad message: {e}; closing"))),
                }
            }
        }

        if fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(Failure::Error("the tun device failed".into()));
        }
        if fds[0].revents & libc::POLLIN != 0 {
            for _ in 0..BATCH {
                // SAFETY: `from_tun` is valid for writes of its length.
                let n = unsafe { libc::read(tun, from_tun.as_mut_ptr().cast(), from_tun.len()) };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    match e.kind() {
                        io::ErrorKind::WouldBlock => break,
                        io::ErrorKind::Interrupted => continue,
                        _ => return Err(Failure::Error(format!("reading the tun device: {e}"))),
                    }
                }
                let packet = &from_tun[..n as usize];
                match unix::send_parts(sock, &[&[relay::PACKET], packet], true) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.raw_os_error() == Some(libc::ENOBUFS) => {
                        stats.dropped += 1;
                    }
                    Err(e)
                        if matches!(e.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset) =>
                    {
                        return Ok(stats);
                    }
                    Err(e) => return Err(Failure::Error(format!("sending to the world: {e}"))),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_run(args: &[String]) -> AttachArgs {
        match crate::args::parse_attach(args).unwrap() {
            crate::args::Parsed::Run(a) => a,
            other => panic!("parsed as {other:?}"),
        }
    }

    #[test]
    fn resolv_conf_lists_servers_in_order() {
        let s = resolv_conf(&["10.0.0.1".parse().unwrap(), "fd00::1".parse().unwrap()]);
        assert_eq!(s, "# Written by fictionet attach.\nnameserver 10.0.0.1\nnameserver fd00::1\n");
        assert_eq!(resolv_conf(&[]), "# Written by fictionet attach.\n");
    }

    #[test]
    fn resolv_conf_goes_under_etc_netns_with_netns() {
        let line = "--world unix:/w --name a --type tun --no-ip-addr --no-gateway --no-dns \
                    --no-ip-addr-v6 --no-gateway-v6 --no-dns-v6";
        let mut v: Vec<String> = line.split_whitespace().map(String::from).collect();
        let a = parse_run(&v);
        assert_eq!(resolv_conf_path(&a), Some(PathBuf::from("/etc/resolv.conf")));
        v.extend(["--netns".into(), "/run/netns/abc".into()]);
        let a = parse_run(&v);
        assert_eq!(resolv_conf_path(&a), Some(PathBuf::from("/etc/netns/abc/resolv.conf")));

        // --resolv-conf wins, with or without --netns.
        let mut w = v.clone();
        w.extend(["--resolv-conf".into(), "/run/agent/resolv.conf".into()]);
        let a = parse_run(&w);
        assert_eq!(resolv_conf_path(&a), Some(PathBuf::from("/run/agent/resolv.conf")));

        // --no-resolv-conf: no file at all.
        v.push("--no-resolv-conf".into());
        let a = parse_run(&v);
        assert_eq!(resolv_conf_path(&a), None);
    }

    #[test]
    fn resolv_conf_is_rewritten_in_place_and_its_directory_made() {
        let dir = std::env::temp_dir().join(format!("fictionet-resolv-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("a/b/resolv.conf");
        write_resolv_conf(&path, &["10.0.0.1".parse().unwrap()]).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "# Written by fictionet attach.\nnameserver 10.0.0.1\n");

        // A second write keeps the same file (the same inode), as a bind
        // mount of it needs.
        use std::os::unix::fs::MetadataExt;
        let before = fs::metadata(&path).unwrap().ino();
        write_resolv_conf(&path, &[]).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().ino(), before);
        assert_eq!(fs::read_to_string(&path).unwrap(), "# Written by fictionet attach.\n");
        fs::remove_dir_all(&dir).unwrap();
    }
}
