//! `fictionet attach --type tun`: a TUN device in the sandbox's network
//! namespace, relayed to the world over its Unix socket.

use std::fs;
use std::io::{self, Write};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use fictionet::relay::{self, unix};

use crate::config::{AttachArgs, ResolvConf};
use crate::linux::{enter_netns, index_of, open_tun};
use crate::netlink::{self, Netlink};
use crate::world::{self, Failure, Greeting, context, err};

/// Runs attach to the end. `Ok` means the world closed the connection.
pub(crate) fn run(args: AttachArgs) -> Result<(), Failure> {
    let resolv_path = resolv_conf_path(&args).map_err(|e| Failure::Error(e.to_string()))?;
    world::clear_ready_file(args.ready_file.as_deref());

    // Enter the sandbox's namespace first, so the device is made there.
    // This must happen while the process has one thread.
    if let Some(netns) = &args.netns {
        enter_netns(netns).map_err(err(&format!(
            "entering the network namespace {}",
            netns.display()
        )))?;
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

    if let Some(path) = resolv_path {
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
                eprintln!(
                    "fictionet attach: {} packets dropped on full buffers",
                    stats.dropped
                );
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// `--down-link`: deletes every route through `link` (IPv4 and IPv6, in
/// every table), then its addresses, then sets it down. The routes are
/// deleted one by one rather than left to the link going down, so the
/// result does not depend on what the kernel does then.
fn take_down(link: &str) -> io::Result<()> {
    let index = index_of(link).map_err(|e| context(e, "no such link"))?;
    let nl = Netlink::open()?;
    let routes = nl
        .dump(netlink::dump_routes())
        .map_err(|e| context(e, "listing the routes"))?;
    for route in routes.iter().filter_map(|m| netlink::Route::parse(m)) {
        if route.oif != Some(index) {
            continue;
        }
        match nl.call(route.delete()) {
            Ok(()) => {}
            // Gone already: deleting an earlier one took it too.
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
            Err(e) => {
                return Err(context(
                    e,
                    &format!("deleting the route {}", route.describe()),
                ));
            }
        }
    }
    let addresses = nl
        .dump(netlink::dump_addresses())
        .map_err(|e| context(e, "listing the addresses"))?;
    for address in addresses.iter().filter_map(|m| netlink::Address::parse(m)) {
        if address.index != index {
            continue;
        }
        match nl.call(address.delete()) {
            Ok(()) => {}
            Err(e) if matches!(e.raw_os_error(), Some(libc::EADDRNOTAVAIL | libc::ESRCH)) => {}
            Err(e) => {
                let what = address
                    .addr
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "an address".into());
                return Err(context(e, &format!("deleting the address {what}")));
            }
        }
    }
    nl.call(netlink::link_down(index))
        .map_err(|e| context(e, "setting it down"))?;
    Ok(())
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
    nl.call(netlink::link_up(index, args.mtu as u32))
        .map_err(|e| context(e, "bringing the device up"))?;
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
        nl.call(netlink::add_default_route(index, IpAddr::V4(*gw)))
            .map_err(|e| default_route_error(e, "IPv4"))?;
    }
    if let Some(gw) = args.gateway_v6.value() {
        nl.call(netlink::add_default_route(index, IpAddr::V6(*gw)))
            .map_err(|e| default_route_error(e, "IPv6"))?;
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

/// Where `--dns` goes: the `--resolv-conf` path, nowhere with
/// `--no-resolv-conf`, and otherwise attach's own `/etc/resolv.conf`, or with
/// a named `--netns`, `/etc/netns/<name>/resolv.conf`, which `ip netns exec`
/// mounts over `/etc/resolv.conf`. Other namespaces require an explicit policy.
fn resolv_conf_path(args: &AttachArgs) -> io::Result<Option<PathBuf>> {
    Ok(match &args.resolv_conf {
        ResolvConf::Off => None,
        ResolvConf::Path(path) => Some(path.clone()),
        ResolvConf::Default => Some(match &args.netns {
            None => PathBuf::from("/etc/resolv.conf"),
            Some(path) if matches!(path.parent(), Some(p) if p == Path::new("/run/netns") || p == Path::new("/var/run/netns")) => {
                Path::new("/etc/netns")
                    .join(
                        path.file_name()
                            .ok_or_else(|| io::Error::other("missing namespace name"))?,
                    )
                    .join("resolv.conf")
            }
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--netns outside /run/netns or /var/run/netns requires --resolv-conf or --no-resolv-conf",
                ));
            }
        }),
    })
}

pub(crate) fn resolv_conf(servers: &[IpAddr]) -> String {
    let mut out = String::from("# Written by attach.\n");
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
/// Attach runs as root, so it never writes through a symlink or a hard
/// link at `path` (see [`world::open_own_file`]).
fn write_resolv_conf(path: &Path, servers: &[IpAddr]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut f = world::open_own_file(path, false)?;
    f.set_len(0)?;
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
            libc::pollfd {
                fd: tun,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: sock,
                events: libc::POLLIN,
                revents: 0,
            },
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

        if fds[1].revents != 0
            && !world::read_packets(sock, &mut from_world, Some(BATCH), |p| {
                // SAFETY: `p` is valid for reads of its length.
                let w = unsafe { libc::write(tun, p.as_ptr().cast(), p.len()) };
                if w < 0 {
                    // A full queue drops the packet. So does a packet
                    // the kernel will not take (EINVAL: not IPv4 or
                    // IPv6), which a world may send on purpose.
                    stats.dropped += 1;
                }
                Ok(())
            })?
        {
            return Ok(stats);
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
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.raw_os_error() == Some(libc::ENOBUFS) =>
                    {
                        stats.dropped += 1;
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                        ) =>
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

    /// A symlink at the resolv.conf path is an error, and its target is
    /// left alone.
    #[test]
    fn resolv_conf_is_never_written_through_a_symlink() {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("fn-resolv-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("shadow");
        fs::write(&target, "keep\n").unwrap();
        let path = dir.join("resolv.conf");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let servers = ["10.0.0.1".parse().unwrap()];
        let e = write_resolv_conf(&path, &servers).unwrap_err();
        assert!(e.to_string().contains("symlink"), "{e}");
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep\n");
        // A plain file is rewritten in place.
        let plain = dir.join("plain.conf");
        fs::write(
            &plain,
            "an older and longer file than the new one\n".repeat(4),
        )
        .unwrap();
        write_resolv_conf(&plain, &servers).unwrap();
        assert_eq!(fs::read_to_string(&plain).unwrap(), resolv_conf(&servers));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolv_conf_lists_servers_in_order() {
        let s = resolv_conf(&["10.0.0.1".parse().unwrap(), "fd00::1".parse().unwrap()]);
        assert_eq!(
            s,
            "# Written by attach.\nnameserver 10.0.0.1\nnameserver fd00::1\n"
        );
        assert_eq!(resolv_conf(&[]), "# Written by attach.\n");
    }

    #[test]
    fn resolv_conf_goes_under_etc_netns_with_netns() {
        let line = "--world unix:/w --name a --type tun --no-ip-addr --no-gateway --no-dns \
                    --no-ip-addr-v6 --no-gateway-v6 --no-dns-v6";
        let mut v: Vec<String> = line.split_whitespace().map(String::from).collect();
        let a = parse_run(&v);
        assert_eq!(
            resolv_conf_path(&a).unwrap(),
            Some(PathBuf::from("/etc/resolv.conf"))
        );
        v.extend(["--netns".into(), "/run/netns/abc".into()]);
        let a = parse_run(&v);
        assert_eq!(
            resolv_conf_path(&a).unwrap(),
            Some(PathBuf::from("/etc/netns/abc/resolv.conf"))
        );

        let mut alias = v.clone();
        *alias.last_mut().unwrap() = "/var/run/netns/abc".into();
        assert_eq!(
            resolv_conf_path(&parse_run(&alias)).unwrap(),
            Some("/etc/netns/abc/resolv.conf".into())
        );

        // --resolv-conf wins, with or without --netns.
        let mut w = v.clone();
        w.extend(["--resolv-conf".into(), "/run/agent/resolv.conf".into()]);
        let a = parse_run(&w);
        assert_eq!(
            resolv_conf_path(&a).unwrap(),
            Some(PathBuf::from("/run/agent/resolv.conf"))
        );

        // --no-resolv-conf: no file at all.
        v.push("--no-resolv-conf".into());
        let a = parse_run(&v);
        assert_eq!(resolv_conf_path(&a).unwrap(), None);
    }

    #[test]
    fn unnamed_netns_requires_explicit_resolver_policy() {
        let line = "--world unix:/w --name a --type tun --no-ip-addr --no-gateway --no-dns \
                    --no-ip-addr-v6 --no-gateway-v6 --no-dns-v6 --netns /proc/1234/ns/net";
        let v: Vec<String> = line.split_whitespace().map(String::from).collect();
        let a = parse_run(&v);
        let error = resolv_conf_path(&a).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("--resolv-conf or --no-resolv-conf")
        );
        let mut explicit = v.clone();
        explicit.extend(["--resolv-conf".into(), "/tmp/resolv.conf".into()]);
        assert_eq!(
            resolv_conf_path(&parse_run(&explicit)).unwrap(),
            Some("/tmp/resolv.conf".into())
        );
        let mut off = v;
        off.push("--no-resolv-conf".into());
        assert_eq!(resolv_conf_path(&parse_run(&off)).unwrap(), None);
    }

    #[test]
    fn resolv_conf_is_rewritten_in_place_and_its_directory_made() {
        let dir = std::env::temp_dir().join(format!("fictionet-resolv-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("a/b/resolv.conf");
        write_resolv_conf(&path, &["10.0.0.1".parse().unwrap()]).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "# Written by attach.\nnameserver 10.0.0.1\n"
        );

        // A second write keeps the same file (the same inode), as a bind
        // mount of it needs.
        use std::os::unix::fs::MetadataExt;
        let before = fs::metadata(&path).unwrap().ino();
        write_resolv_conf(&path, &[]).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().ino(), before);
        assert_eq!(fs::read_to_string(&path).unwrap(), "# Written by attach.\n");
        fs::remove_dir_all(&dir).unwrap();
    }
}
