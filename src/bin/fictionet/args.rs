//! The flags of `fictionet attach`, parsed by hand.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

/// One address setting: a value (`--dns 10.0.0.1`), turned off
/// (`--no-dns`), or left out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Setting<T> {
    /// Set by attach.
    Value(T),
    /// Turned off with the flag's `--no-` form.
    Off,
    /// Left out: the world should supply it, by DHCP or router
    /// advertisements.
    FromWorld,
}

impl<T> Setting<T> {
    pub(crate) fn value(&self) -> Option<&T> {
        match self {
            Setting::Value(v) => Some(v),
            _ => None,
        }
    }
}

/// Where attach writes the DNS servers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ResolvConf {
    /// Left out: `/etc/resolv.conf`, or `/etc/netns/<name>/resolv.conf`
    /// with `--netns`.
    Default,
    /// `--resolv-conf <path>`: this file instead.
    Path(PathBuf),
    /// `--no-resolv-conf`: no file. DNS is up to the harness.
    Off,
}

/// An address with its prefix length, such as `10.0.0.2/24`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Cidr<A> {
    pub(crate) addr: A,
    pub(crate) prefix: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AttachArgs {
    /// The path of the world's Unix socket.
    pub(crate) world: String,
    pub(crate) name: String,
    pub(crate) netns: Option<PathBuf>,
    pub(crate) ip_addr: Setting<Cidr<Ipv4Addr>>,
    pub(crate) gateway: Setting<Ipv4Addr>,
    pub(crate) dns: Setting<Ipv4Addr>,
    pub(crate) ip_addr_v6: Setting<Cidr<Ipv6Addr>>,
    pub(crate) gateway_v6: Setting<Ipv6Addr>,
    pub(crate) dns_v6: Setting<Ipv6Addr>,
    pub(crate) mtu: u16,
    pub(crate) ready_file: Option<PathBuf>,
    pub(crate) resolv_conf: ResolvConf,
    /// Links to clear and set down before `tun0` is set up, in order.
    pub(crate) down_links: Vec<String>,
    /// How long to wait for the world's socket. Zero: try once.
    pub(crate) world_wait: std::time::Duration,
}

/// The two proxy types. Each listens on a TCP port and turns proxied
/// connections into the sandbox's packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProxyKind {
    /// HTTP proxy: CONNECT, and plain-HTTP requests in absolute form.
    Http,
    /// SOCKS5: CONNECT, with username and password.
    Socks5,
}

impl ProxyKind {
    /// The type's name, as `--type` takes it and `hello` carries it.
    pub(crate) fn name(self) -> &'static str {
        match self {
            ProxyKind::Http => "https_proxy",
            ProxyKind::Socks5 => "socks5",
        }
    }
}

/// The flags of `--type https_proxy` and `--type socks5`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ProxyArgs {
    pub(crate) kind: ProxyKind,
    /// The path of the world's Unix socket.
    pub(crate) world: String,
    pub(crate) name: String,
    /// Where the proxy listens.
    pub(crate) listen: SocketAddr,
    /// The file that holds the sandbox's token.
    pub(crate) token_file: PathBuf,
    /// The sandbox's address: the source of the packets attach makes.
    pub(crate) ip_addr: Ipv4Addr,
    /// The world's DNS server.
    pub(crate) dns: Ipv4Addr,
    pub(crate) ready_file: Option<PathBuf>,
    pub(crate) world_wait: std::time::Duration,
}

/// How attach gives a VM one address family (IPv4 or IPv6), for
/// `--type tap`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Family<A> {
    /// `--ip-addr` (or `--ip-addr-v6`) was given: attach answers the VM's
    /// DHCP (and, for IPv6, router solicitations) itself, and passes only
    /// packets from that address.
    Serve(Lease<A>),
    /// All three flags of the family were left out: the VM's DHCP goes to
    /// the world like any other packet.
    FromWorld,
    /// `--no-ip-addr` (or `--no-ip-addr-v6`): attach gives no address and
    /// drops the VM's DHCP. A static address set inside the VM still works.
    Off,
}

/// What attach hands out by DHCP for one family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Lease<A> {
    pub(crate) addr: Cidr<A>,
    /// The default gateway, or `None` with `--no-gateway`.
    pub(crate) gateway: Option<A>,
    /// The DNS server, or `None` with `--no-dns`.
    pub(crate) dns: Option<A>,
}

/// How the VM's frames reach attach (`--vm`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum VmLink {
    /// `qemu:<path>`: the Unix socket QEMU's `-netdev stream` connects to.
    Qemu(PathBuf),
    /// `tap:<name>`: the TAP device the VM program holds. Attach makes a
    /// second TAP device and has the kernel pass frames between the two.
    Tap(String),
}

/// The flags of `--type tap`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TapArgs {
    /// The path of the world's Unix socket.
    pub(crate) world: String,
    pub(crate) name: String,
    pub(crate) vm: VmLink,
    /// The network namespace the VM's TAP device is in, for `tap:<name>`.
    pub(crate) netns: Option<PathBuf>,
    pub(crate) v4: Family<Ipv4Addr>,
    pub(crate) v6: Family<Ipv6Addr>,
    pub(crate) mtu: u16,
    pub(crate) ready_file: Option<PathBuf>,
    pub(crate) world_wait: std::time::Duration,
}

pub(crate) const ATTACH_USAGE: &str = "\
usage: fictionet attach --world unix:<path> --name <name> --type tun
           [--netns <path>]
           [--ip-addr <cidr> | --no-ip-addr] [--gateway <ip> | --no-gateway]
           [--dns <ip> | --no-dns]
           [--ip-addr-v6 <cidr> | --no-ip-addr-v6] [--gateway-v6 <ip> | --no-gateway-v6]
           [--dns-v6 <ip> | --no-dns-v6]
           [--mtu <n>] [--ready-file <path>]
           [--resolv-conf <path> | --no-resolv-conf]
           [--down-link <ifname>]... [--world-wait <seconds>]
       fictionet attach --world unix:<path> --name <name> --type tap
           --vm qemu:<path> | --vm tap:<ifname> [--netns <path>]
           [--ip-addr <cidr> --gateway <ip> --dns <ip> | --no-ip-addr]
           [--ip-addr-v6 <cidr> --gateway-v6 <ip> --dns-v6 <ip> | --no-ip-addr-v6]
           [--mtu <n>] [--ready-file <path>] [--world-wait <seconds>]
       fictionet attach --world unix:<path> --name <name> --type https_proxy|socks5
           --listen <ip:port> --token-file <path> --ip-addr <ip> --dns <ip>
           [--ready-file <path>] [--world-wait <seconds>]

Each address setting takes a value, or is turned off with its --no- form.
With --type tun, every address setting must be given, as a value or
with its --no- form. With --type tap, attach hands the VM the addresses
it is given by DHCP, DHCPv6 and router advertisements. For a family with
none of its three settings, the VM's own DHCP goes to the world.

The DNS servers (--dns, --dns-v6) are written to /etc/resolv.conf, or with
--netns to /etc/netns/<name>/resolv.conf, which `ip netns exec <name>`
mounts over /etc/resolv.conf. --resolv-conf writes them to <path> instead.
--no-resolv-conf writes no file, and leaves DNS to the harness.

--down-link <ifname> takes another link out of the way first, such as a
Kubernetes pod's eth0: attach deletes its routes and addresses (IPv4 and
IPv6) and sets it down. Give it once per link.

--world-wait <seconds> keeps trying to connect to the world's socket for
that long, for a world that starts at the same time as attach. Without it,
attach tries once.

--type https_proxy and --type socks5 make no device. Attach listens on
--listen as an HTTP proxy or a SOCKS5 proxy, and turns each proxied
connection into packets from --ip-addr (a plain address, such as
10.0.0.2). It looks names up with the world's DNS server, --dns. Clients
must give the token in --token-file as the password in the proxy URL:
http://fictionet:<token>@host:port or socks5h://fictionet:<token>@host:port.
These types take no --gateway, --netns, --mtu, --down-link, --resolv-conf
or IPv6 flag: there is no device, route or resolv.conf to set.

--type tap connects a QEMU virtual machine. Attach listens on the Unix
socket <path>, and QEMU connects to it with
  -netdev stream,id=n0,server=off,addr.type=unix,addr.path=<path>
  -device virtio-net-pci,netdev=n0
Attach answers the VM's ARP and IPv6 neighbor discovery itself, and moves
its IP packets to and from the world. The address flags are what attach
hands the VM by DHCP (and, for IPv6, router advertisements and DHCPv6):
--gateway and --dns each take a value or their --no- form when --ip-addr
is given. Leave all three of a family out, and the VM's DHCP goes to the
world instead. --no-ip-addr gives no address and drops the VM's DHCP.
Attach serves one connection, and exits when QEMU closes it.
--vm tap:<ifname> is for VM programs that only take a TAP device, such as
Firecracker and Cloud Hypervisor. The device must exist (ip tuntap add),
in attach's network namespace or the one --netns names. Attach makes a
second TAP device and has the kernel redirect every frame between the
two, so it needs CAP_NET_ADMIN there. It exits when the device is
removed, or when the world closes the connection.
--type tap takes no --down-link or resolv.conf flag: the VM sets up its
own network.

A flag's value is the next argument, or follows = (--mtu=1400). A next
argument that starts with -- is read as a flag, so a value that starts
with -- must use =, as in --resolv-conf=--odd-name.";

/// The flags that take no value.
const SWITCHES: [&str; 7] = [
    "--no-ip-addr",
    "--no-gateway",
    "--no-dns",
    "--no-ip-addr-v6",
    "--no-gateway-v6",
    "--no-dns-v6",
    "--no-resolv-conf",
];

/// Checks a link name the way the kernel does: 1 to 15 bytes, with no
/// `/`, `:` or whitespace, and not `.` or `..`.
fn parse_ifname(s: &str) -> Option<String> {
    let ok = !s.is_empty()
        && s.len() < 16
        && s != "."
        && s != ".."
        && !s.bytes().any(|b| b == b'/' || b == b':' || b.is_ascii_whitespace());
    ok.then(|| s.to_owned())
}

fn parse_value<T>(flag: &str, value: &str, parse: impl Fn(&str) -> Option<T>) -> Result<T, String> {
    parse(value).ok_or_else(|| format!("{flag}: cannot read {value:?}"))
}

fn parse_cidr<A: std::str::FromStr>(s: &str, max: u8) -> Option<Cidr<A>> {
    let (addr, prefix) = s.split_once('/')?;
    let prefix: u8 = prefix.parse().ok()?;
    if prefix > max {
        return None;
    }
    Some(Cidr { addr: addr.parse().ok()?, prefix })
}

/// One address setting while the flags are read: its value, and whether
/// its `--no-` form was given.
struct Pending<T> {
    flag: &'static str,
    value: Option<T>,
    off: bool,
}

impl<T> Pending<T> {
    fn new(flag: &'static str) -> Pending<T> {
        Pending { flag, value: None, off: false }
    }

    fn finish(self) -> Result<Setting<T>, String> {
        match (self.value, self.off) {
            (Some(_), true) => Err(format!("give {flag} or --no-{name}, not both", flag = self.flag, name = &self.flag[2..])),
            (Some(v), false) => Ok(Setting::Value(v)),
            (None, true) => Ok(Setting::Off),
            (None, false) => Ok(Setting::FromWorld),
        }
    }
}

/// The flags in `group` that were left out, with both of their forms, such
/// as `--dns (or --no-dns)`.
fn left_out(group: &[(&str, bool)]) -> Vec<String> {
    group.iter().filter(|(_, missing)| *missing).map(|(flag, _)| format!("{flag} (or --no-{})", &flag[2..])).collect()
}

/// What the arguments after `attach` ask for.
// Made once per run, so the size of `Run` does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Parsed {
    /// `--help` or `-h`: print [`ATTACH_USAGE`] and exit 0.
    Help,
    /// Run attach with these flags.
    Run(AttachArgs),
    /// Run a proxy type with these flags.
    Proxy(ProxyArgs),
    /// Run `--type tap` with these flags.
    Tap(TapArgs),
}

/// Parses the arguments after `attach`.
///
/// A flag's value is the next argument, or follows `=` in the same one.
/// A next argument that starts with `--` is read as a flag, not a value,
/// so `--resolv-conf --no-resolv-conf` is an error. A value that really
/// starts with `--` goes after `=`: `--resolv-conf=--odd-name`.
pub(crate) fn parse_attach(args: &[String]) -> Result<Parsed, String> {
    let mut world = None;
    let mut name = None;
    let mut kind = None;
    let mut netns = None;
    let mut ip_addr: Pending<String> = Pending::new("--ip-addr");
    let mut gateway = Pending::new("--gateway");
    let mut dns = Pending::new("--dns");
    let mut ip_addr_v6 = Pending::new("--ip-addr-v6");
    let mut gateway_v6 = Pending::new("--gateway-v6");
    let mut dns_v6 = Pending::new("--dns-v6");
    let mut mtu: u16 = 1500;
    let mut ready_file = None;
    let mut resolv_conf_path = None;
    let mut no_resolv_conf = false;
    let mut down_links: Vec<String> = Vec::new();
    let mut world_wait = std::time::Duration::ZERO;
    let mut listen = None;
    let mut token_file = None;
    let mut vm = None;
    // Every flag given, for the checks of each type.
    let mut given: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_owned(), Some(v.to_owned())),
            _ => (arg.clone(), None),
        };
        if flag == "-h" || flag == "--help" {
            return Ok(Parsed::Help);
        }
        given.push(flag.clone());
        if SWITCHES.contains(&flag.as_str()) {
            if inline.is_some() {
                return Err(format!("{flag} takes no value"));
            }
            match flag.as_str() {
                "--no-ip-addr" => ip_addr.off = true,
                "--no-gateway" => gateway.off = true,
                "--no-dns" => dns.off = true,
                "--no-ip-addr-v6" => ip_addr_v6.off = true,
                "--no-gateway-v6" => gateway_v6.off = true,
                "--no-dns-v6" => dns_v6.off = true,
                _ => no_resolv_conf = true,
            }
            i += 1;
            continue;
        }
        let value = match inline {
            Some(v) => v,
            None => {
                i += 1;
                match args.get(i) {
                    Some(v) if !v.starts_with("--") => v.clone(),
                    _ => return Err(format!("{flag} needs a value")),
                }
            }
        };
        match flag.as_str() {
            "--world" => world = Some(value),
            "--name" => name = Some(value),
            "--type" => kind = Some(value),
            "--netns" => netns = Some(PathBuf::from(value)),
            "--ip-addr" => ip_addr.value = Some(value),
            "--gateway" => gateway.value = Some(parse_value(&flag, &value, |s| s.parse().ok())?),
            "--dns" => dns.value = Some(parse_value(&flag, &value, |s| s.parse().ok())?),
            "--ip-addr-v6" => ip_addr_v6.value = Some(parse_value(&flag, &value, |s| parse_cidr(s, 128))?),
            "--gateway-v6" => gateway_v6.value = Some(parse_value(&flag, &value, |s| s.parse().ok())?),
            "--dns-v6" => dns_v6.value = Some(parse_value(&flag, &value, |s| s.parse().ok())?),
            "--mtu" => {
                mtu = value.parse().map_err(|_| format!("--mtu: cannot read {value:?}"))?;
                if mtu < 1280 {
                    // IPv6 needs 1280, and the kernel refuses less on a
                    // device with IPv6.
                    return Err("--mtu must be at least 1280".into());
                }
            }
            "--ready-file" => ready_file = Some(PathBuf::from(value)),
            "--resolv-conf" => {
                if value.is_empty() {
                    return Err("--resolv-conf needs a path".into());
                }
                resolv_conf_path = Some(PathBuf::from(value));
            }
            "--down-link" => {
                let name = parse_value(&flag, &value, parse_ifname)?;
                if !down_links.contains(&name) {
                    down_links.push(name);
                }
            }
            "--world-wait" => {
                let secs: u32 = parse_value(&flag, &value, |s| s.parse().ok())?;
                world_wait = std::time::Duration::from_secs(secs.into());
            }
            "--listen" => listen = Some(parse_value(&flag, &value, |s| s.parse::<SocketAddr>().ok())?),
            "--token-file" => {
                if value.is_empty() {
                    return Err("--token-file needs a path".into());
                }
                token_file = Some(PathBuf::from(value));
            }
            "--vm" => vm = Some(value),
            "--port" => {
                return Err("there is no --port: give --listen <ip:port>, such as --listen 127.0.0.1:8080".into());
            }
            other => return Err(format!("unknown flag {other}\n\n{ATTACH_USAGE}")),
        }
        i += 1;
    }

    let world = world.ok_or("--world is required")?;
    let world = crate::observe::world_path(&world)?;
    let name = name.ok_or("--name is required")?;
    if name.is_empty() || name.len() > 255 {
        return Err("--name must be 1 to 255 bytes".into());
    }
    let proxy = match kind.as_deref() {
        Some("tun") => None,
        Some("https_proxy") => Some(ProxyKind::Http),
        Some("socks5") => Some(ProxyKind::Socks5),
        Some("tap") => {
            let f = TapFlags { given: &given, vm, netns, ip_addr, gateway, dns, ip_addr_v6, gateway_v6, dns_v6 };
            return parse_tap(world, name, f, mtu, ready_file, world_wait);
        }
        Some(other @ ("wireguard" | "tailscale")) => {
            return Err(format!("--type {other} is not implemented yet; tun, tap, https_proxy and socks5 are"));
        }
        Some(other) => return Err(format!("unknown --type {other:?}")),
        None => return Err("--type is required: tun, tap, https_proxy or socks5".into()),
    };
    if let Some(kind) = proxy {
        let flags = ProxyFlags { given: &given, ip_addr, dns, listen, token_file };
        return parse_proxy(kind, world, name, flags, ready_file, world_wait);
    }
    if given.iter().any(|g| g == "--vm") {
        return Err("--vm is only for --type tap".into());
    }
    for flag in ["--listen", "--token-file"] {
        if given.iter().any(|g| g == flag) {
            return Err(format!("{flag} is only for --type https_proxy and --type socks5"));
        }
    }
    let ip_addr = Pending {
        flag: ip_addr.flag,
        value: ip_addr.value.map(|v| parse_value("--ip-addr", &v, |s| parse_cidr(s, 32))).transpose()?,
        off: ip_addr.off,
    };
    let resolv_conf = match (resolv_conf_path, no_resolv_conf) {
        (Some(_), true) => return Err("give --resolv-conf or --no-resolv-conf, not both".into()),
        (Some(path), false) => ResolvConf::Path(path),
        (None, true) => ResolvConf::Off,
        (None, false) => ResolvConf::Default,
    };
    let (ip_addr, gateway, dns) = (ip_addr.finish()?, gateway.finish()?, dns.finish()?);
    let (ip_addr_v6, gateway_v6, dns_v6) = (ip_addr_v6.finish()?, gateway_v6.finish()?, dns_v6.finish()?);

    // Left out means "ask the world". This build cannot ask yet.
    let missing_v4 = left_out(&[
        ("--ip-addr", ip_addr == Setting::FromWorld),
        ("--gateway", gateway == Setting::FromWorld),
        ("--dns", dns == Setting::FromWorld),
    ]);
    if !missing_v4.is_empty() {
        return Err(format!(
            "{} left out: these would come from the world by DHCP, but DHCP is not implemented yet. \
             Give each one a value, or turn it off with its --no- form.",
            missing_v4.join(", ")
        ));
    }
    let missing_v6 = left_out(&[
        ("--ip-addr-v6", ip_addr_v6 == Setting::FromWorld),
        ("--gateway-v6", gateway_v6 == Setting::FromWorld),
        ("--dns-v6", dns_v6 == Setting::FromWorld),
    ]);
    if !missing_v6.is_empty() {
        return Err(format!(
            "{} left out: these would come from the world by router advertisements, which are not \
             implemented yet. Give each one a value, or turn it off with its --no- form.",
            missing_v6.join(", ")
        ));
    }

    Ok(Parsed::Run(AttachArgs {
        world,
        name,
        netns,
        ip_addr,
        gateway,
        dns,
        ip_addr_v6,
        gateway_v6,
        dns_v6,
        mtu,
        ready_file,
        resolv_conf,
        down_links,
        world_wait,
    }))
}

/// The flags `--type tap` reads, as [`parse_attach`] collected them.
struct TapFlags<'a> {
    /// Every flag given, by name.
    given: &'a [String],
    vm: Option<String>,
    netns: Option<PathBuf>,
    ip_addr: Pending<String>,
    gateway: Pending<Ipv4Addr>,
    dns: Pending<Ipv4Addr>,
    ip_addr_v6: Pending<Cidr<Ipv6Addr>>,
    gateway_v6: Pending<Ipv6Addr>,
    dns_v6: Pending<Ipv6Addr>,
}

/// The rest of [`parse_attach`] for `--type tap`.
fn parse_tap(
    world: String,
    name: String,
    f: TapFlags<'_>,
    mtu: u16,
    ready_file: Option<PathBuf>,
    world_wait: std::time::Duration,
) -> Result<Parsed, String> {
    let refused: [(&[&str], &str); 3] = [
        (&["--down-link"], "attach changes no link"),
        (&["--resolv-conf", "--no-resolv-conf"], "the VM writes its own resolv.conf, from the DNS server it gets by DHCP"),
        (&["--listen", "--token-file"], "those are for --type https_proxy and --type socks5"),
    ];
    for (flags, why) in refused {
        if let Some(flag) = f.given.iter().find(|g| flags.contains(&g.as_str())) {
            return Err(format!("--type tap takes no {flag}: {why}"));
        }
    }
    let vm = f.vm.ok_or(
        "--type tap needs --vm qemu:<path> (the Unix socket QEMU connects to) or --vm tap:<ifname> (the VM's TAP device)",
    )?;
    let vm = match vm.split_once(':') {
        // A sockaddr_un holds a path of at most 107 bytes.
        Some(("qemu", path)) if path.len() > 107 => {
            return Err("--vm: the socket path must be at most 107 bytes".into());
        }
        Some(("qemu", path)) if !path.is_empty() => VmLink::Qemu(PathBuf::from(path)),
        Some(("tap", name)) => VmLink::Tap(
            parse_ifname(name).ok_or_else(|| format!("--vm tap:<ifname>: {name:?} is not a link name"))?,
        ),
        _ => return Err(format!("--vm must be qemu:<path> or tap:<ifname>, not {vm:?}")),
    };
    if matches!(vm, VmLink::Qemu(_)) && f.netns.is_some() {
        return Err("--type tap takes --netns only with --vm tap:<ifname>; QEMU's socket needs no namespace".into());
    }
    let ip_addr = Pending {
        flag: f.ip_addr.flag,
        value: f.ip_addr.value.map(|v| parse_value("--ip-addr", &v, |s| parse_cidr(s, 32))).transpose()?,
        off: f.ip_addr.off,
    };
    let v4 = tap_family(ip_addr.finish()?, f.gateway.finish()?, f.dns.finish()?, ["--ip-addr", "--gateway", "--dns"])?;
    let v6 = tap_family(
        f.ip_addr_v6.finish()?,
        f.gateway_v6.finish()?,
        f.dns_v6.finish()?,
        ["--ip-addr-v6", "--gateway-v6", "--dns-v6"],
    )?;
    if let Family::Serve(l) = &v4 {
        if !(8..=30).contains(&l.addr.prefix) {
            return Err("--ip-addr: for --type tap, the prefix must be from /8 to /30, so the VM shares a subnet with its gateway".into());
        }
        if let Some(gw) = l.gateway {
            let mask = crate::addresses::mask4(l.addr.prefix);
            if u32::from(gw) & mask != u32::from(l.addr.addr) & mask || gw == l.addr.addr {
                return Err(format!("--gateway {gw} must be another address in the subnet of --ip-addr {}/{}", l.addr.addr, l.addr.prefix));
            }
        }
    }
    if let Family::Serve(l) = &v6
        && l.addr.prefix > 64
    {
        return Err("--ip-addr-v6: for --type tap, the prefix must be at most /64, the subnet the VM is told is on its link".into());
    }
    Ok(Parsed::Tap(TapArgs { world, name, vm, netns: f.netns, v4, v6, mtu, ready_file, world_wait }))
}

/// One family's three flags, for `--type tap`. With the address, the other
/// two must each be given or turned off: attach hands them out with it.
/// Without it, they must be left out too.
fn tap_family<A: Copy + PartialEq>(
    addr: Setting<Cidr<A>>,
    gateway: Setting<A>,
    dns: Setting<A>,
    [addr_flag, gw_flag, dns_flag]: [&str; 3],
) -> Result<Family<A>, String> {
    match addr {
        Setting::Value(addr) => {
            let missing = left_out(&[(gw_flag, gateway == Setting::FromWorld), (dns_flag, dns == Setting::FromWorld)]);
            if !missing.is_empty() {
                return Err(format!(
                    "{} left out: with {addr_flag}, attach hands the VM its address, gateway and DNS server \
                     by DHCP, so give each one a value or turn it off with its --no- form",
                    missing.join(", ")
                ));
            }
            Ok(Family::Serve(Lease { addr, gateway: gateway.value().copied(), dns: dns.value().copied() }))
        }
        Setting::FromWorld | Setting::Off => {
            let off = addr == Setting::Off;
            for (flag, set) in [(gw_flag, gateway.value().is_some()), (dns_flag, dns.value().is_some())] {
                if set {
                    return Err(format!(
                        "{flag} needs {addr_flag}: for --type tap, attach hands out the gateway and DNS server \
                         by DHCP along with the address. Give {addr_flag} too, or leave all three out so the \
                         VM's DHCP goes to the world"
                    ));
                }
            }
            if off {
                Ok(Family::Off)
            } else if gateway == Setting::Off || dns == Setting::Off {
                Err(format!(
                    "--no-{} needs --no-{} or {addr_flag}: leave all three out so the VM's DHCP goes to the world",
                    if gateway == Setting::Off { &gw_flag[2..] } else { &dns_flag[2..] },
                    &addr_flag[2..]
                ))
            } else {
                Ok(Family::FromWorld)
            }
        }
    }
}

/// The flags a proxy type reads, as [`parse_attach`] collected them.
struct ProxyFlags<'a> {
    /// Every flag given, by name.
    given: &'a [String],
    ip_addr: Pending<String>,
    dns: Pending<Ipv4Addr>,
    listen: Option<SocketAddr>,
    token_file: Option<PathBuf>,
}

/// The rest of [`parse_attach`] for the proxy types: what they need, and
/// the `tun` flags they refuse.
fn parse_proxy(
    kind: ProxyKind,
    world: String,
    name: String,
    f: ProxyFlags<'_>,
    ready_file: Option<PathBuf>,
    world_wait: std::time::Duration,
) -> Result<Parsed, String> {
    let t = kind.name();
    // Flags that set up a device, routes or resolv.conf. A proxy type has
    // none of these, so each is refused rather than ignored.
    let refused: [(&[&str], &str); 7] = [
        (&["--vm"], "that is for --type tap"),
        (&["--gateway", "--no-gateway"], "attach makes the packets itself, and there are no routes to set"),
        (&["--netns"], "attach makes no device, so it enters no namespace"),
        (&["--down-link"], "attach makes no device and changes no link"),
        (&["--mtu"], "attach's TCP sends packets of at most 1,500 bytes"),
        (&["--resolv-conf", "--no-resolv-conf"], "attach looks names up itself, and writes no resolv.conf"),
        (
            &["--ip-addr-v6", "--gateway-v6", "--dns-v6", "--no-ip-addr-v6", "--no-gateway-v6", "--no-dns-v6"],
            "it is IPv4 only",
        ),
    ];
    for (flags, why) in refused {
        if let Some(flag) = f.given.iter().find(|g| flags.contains(&g.as_str())) {
            return Err(format!("--type {t} takes no {flag}: {why}"));
        }
    }
    let listen = f.listen.ok_or_else(|| format!("--type {t} needs --listen <ip:port>, such as --listen 127.0.0.1:8080"))?;
    let token_file = f
        .token_file
        .ok_or_else(|| format!("--type {t} needs --token-file <path>: the sandbox's token, which clients must give"))?;
    let ip_addr = match f.ip_addr.finish()? {
        Setting::Value(v) => match v.parse::<Ipv4Addr>() {
            Ok(a) => a,
            Err(_) if v.contains('/') => {
                return Err(format!("--type {t} takes --ip-addr without a prefix length, such as 10.0.0.2, not {v:?}"));
            }
            Err(_) => return Err(format!("--ip-addr: cannot read {v:?}")),
        },
        _ => return Err(format!("--type {t} needs --ip-addr <ip>: the source address of the packets attach makes")),
    };
    let dns = match f.dns.finish()? {
        Setting::Value(v) => v,
        _ => return Err(format!("--type {t} needs --dns <ip>: the world's DNS server, where attach looks names up")),
    };
    Ok(Parsed::Proxy(ProxyArgs { kind, world, name, listen, token_file, ip_addr, dns, ready_file, world_wait }))
}

impl AttachArgs {
    /// The DNS servers to write to `resolv.conf`, IPv4 first.
    pub(crate) fn dns_servers(&self) -> Vec<IpAddr> {
        let mut out = Vec::new();
        if let Some(a) = self.dns.value() {
            out.push(IpAddr::V4(*a));
        }
        if let Some(a) = self.dns_v6.value() {
            out.push(IpAddr::V6(*a));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    /// Parses `args` and expects flags to run with, not help.
    fn parse_attach(args: &[String]) -> Result<AttachArgs, String> {
        match super::parse_attach(args)? {
            Parsed::Run(a) => Ok(a),
            other => panic!("parsed as {other:?}"),
        }
    }

    const FULL: &str = "--world unix:/run/w.sock --name abc --type tun --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 \
                        --dns 10.0.0.1 --ip-addr-v6 fd00::2/64 --gateway-v6 fd00::1 --no-dns-v6";

    const ALL_OFF: &str = "--world unix:/w --name a --type tun --no-ip-addr --no-gateway --no-dns \
                           --no-ip-addr-v6 --no-gateway-v6 --no-dns-v6";

    #[test]
    fn full_flags() {
        let a = parse_attach(&args(FULL)).unwrap();
        assert_eq!(a.world, "/run/w.sock");
        assert_eq!(a.name, "abc");
        assert_eq!(a.ip_addr, Setting::Value(Cidr { addr: Ipv4Addr::new(10, 0, 0, 2), prefix: 24 }));
        assert_eq!(a.gateway, Setting::Value(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(a.ip_addr_v6.value().unwrap().prefix, 64);
        assert_eq!(a.dns_v6, Setting::Off);
        assert_eq!(a.mtu, 1500);
        assert_eq!(a.dns_servers(), vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]);
        assert_eq!(a.resolv_conf, ResolvConf::Default);
    }

    #[test]
    fn every_setting_off() {
        let a = parse_attach(&args(ALL_OFF)).unwrap();
        for off in [a.ip_addr == Setting::Off, a.gateway == Setting::Off, a.dns == Setting::Off] {
            assert!(off);
        }
        for off in [a.ip_addr_v6 == Setting::Off, a.gateway_v6 == Setting::Off, a.dns_v6 == Setting::Off] {
            assert!(off);
        }
        assert!(a.dns_servers().is_empty());
    }

    #[test]
    fn equals_form_and_mtu() {
        let a = parse_attach(&args(&format!("{FULL} --mtu=9000 --ready-file=/tmp/r"))).unwrap();
        assert_eq!(a.mtu, 9000);
        assert_eq!(a.ready_file, Some(PathBuf::from("/tmp/r")));
    }

    #[test]
    fn left_out_flags_name_dhcp_or_ra_and_both_forms() {
        let e = parse_attach(&args("--world unix:/w --name abc --type tun")).unwrap_err();
        assert!(e.contains("--ip-addr (or --no-ip-addr), --gateway (or --no-gateway), --dns (or --no-dns) left out"), "{e}");
        assert!(e.contains("DHCP is not implemented yet"), "{e}");
        let e = parse_attach(&args("--world unix:/w --name abc --type tun --no-ip-addr --no-gateway --no-dns"))
            .unwrap_err();
        assert!(e.contains("--dns-v6 (or --no-dns-v6)"), "{e}");
        assert!(e.contains("router advertisements"), "{e}");
    }

    #[test]
    fn a_flag_and_its_no_form_clash() {
        let e = parse_attach(&args(&format!("{FULL} --no-dns"))).unwrap_err();
        assert!(e.contains("give --dns or --no-dns, not both"), "{e}");
        let e = parse_attach(&args(&format!("{ALL_OFF} --ip-addr-v6 fd00::2/64"))).unwrap_err();
        assert!(e.contains("give --ip-addr-v6 or --no-ip-addr-v6, not both"), "{e}");
        let e = parse_attach(&args(&format!("{FULL} --no-gateway=1"))).unwrap_err();
        assert!(e.contains("--no-gateway takes no value"), "{e}");
    }

    #[test]
    fn none_is_no_longer_special() {
        let bad = |flag: &str| parse_attach(&args(&format!("{ALL_OFF} {flag} none"))).unwrap_err();
        for flag in ["--ip-addr", "--gateway", "--dns", "--ip-addr-v6", "--gateway-v6", "--dns-v6"] {
            assert!(bad(flag).contains(&format!("{flag}: cannot read \"none\"")), "{flag}");
        }
    }

    #[test]
    fn resolv_conf_flags() {
        let a = parse_attach(&args(&format!("{FULL} --resolv-conf /run/dns/resolv.conf"))).unwrap();
        assert_eq!(a.resolv_conf, ResolvConf::Path(PathBuf::from("/run/dns/resolv.conf")));
        let a = parse_attach(&args(&format!("{FULL} --resolv-conf=/x"))).unwrap();
        assert_eq!(a.resolv_conf, ResolvConf::Path(PathBuf::from("/x")));
        // Any value is a path, even one called "none".
        let a = parse_attach(&args(&format!("{FULL} --resolv-conf none"))).unwrap();
        assert_eq!(a.resolv_conf, ResolvConf::Path(PathBuf::from("none")));
        // --no-resolv-conf takes no value, so the next flag is read as a flag.
        let a = parse_attach(&args(&format!("--no-resolv-conf {FULL}"))).unwrap();
        assert_eq!(a.resolv_conf, ResolvConf::Off);
        assert_eq!(a.world, "/run/w.sock");

        let bad = |extra: &str| parse_attach(&args(&format!("{FULL} {extra}"))).unwrap_err();
        assert!(bad("--resolv-conf /x --no-resolv-conf").contains("not both"));
        assert!(bad("--no-resolv-conf --resolv-conf /x").contains("not both"));
        assert!(bad("--no-resolv-conf=yes").contains("takes no value"));
        assert!(bad("--resolv-conf=").contains("needs a path"));
        assert!(bad("--resolv-conf").contains("needs a value"));
        // A next argument that starts with -- is a flag, never the path.
        let e = parse_attach(&args(&format!("{FULL} --resolv-conf --no-resolv-conf"))).unwrap_err();
        assert!(e.contains("--resolv-conf needs a value"), "{e}");
        let e = parse_attach(&args(&format!("--resolv-conf {FULL}"))).unwrap_err();
        assert!(e.contains("--resolv-conf needs a value"), "{e}");
        // After =, any path is taken as it is.
        let a = parse_attach(&args(&format!("{FULL} --resolv-conf=--no-resolv-conf"))).unwrap();
        assert_eq!(a.resolv_conf, ResolvConf::Path(PathBuf::from("--no-resolv-conf")));
    }

    #[test]
    fn no_flag_takes_another_flag_as_its_value() {
        for flag in [
            "--world",
            "--name",
            "--type",
            "--netns",
            "--ip-addr",
            "--gateway",
            "--dns",
            "--ip-addr-v6",
            "--gateway-v6",
            "--dns-v6",
            "--mtu",
            "--ready-file",
            "--resolv-conf",
            "--down-link",
            "--world-wait",
            "--listen",
            "--token-file",
        ] {
            let e = parse_attach(&args(&format!("{flag} {FULL}"))).unwrap_err();
            assert_eq!(e, format!("{flag} needs a value"));
        }
        // A single dash is not a flag here, so "-" can still be a value.
        let a = parse_attach(&args(&format!("{FULL} --ready-file -"))).unwrap();
        assert_eq!(a.ready_file, Some(PathBuf::from("-")));
        // And after =, a value may start with --.
        let a = parse_attach(&args(&format!("{FULL} --ready-file=--r"))).unwrap();
        assert_eq!(a.ready_file, Some(PathBuf::from("--r")));
    }

    #[test]
    fn down_link_repeats_and_keeps_order() {
        let a = parse_attach(&args(FULL)).unwrap();
        assert!(a.down_links.is_empty());
        let a = parse_attach(&args(&format!("{FULL} --down-link eth0 --down-link=net1 --down-link eth0"))).unwrap();
        assert_eq!(a.down_links, vec!["eth0".to_owned(), "net1".to_owned()]);
        let bad = |v: &str| parse_attach(&args(&format!("{FULL} --down-link={v}"))).unwrap_err();
        for v in ["", "a/b", "a:1", ".", "..", "sixteen-bytes-ab"] {
            assert!(bad(v).contains("--down-link: cannot read"), "{v:?}");
        }
        // Fifteen bytes is the longest name the kernel takes.
        let a = parse_attach(&args(&format!("{FULL} --down-link fifteen-bytes-a"))).unwrap();
        assert_eq!(a.down_links, vec!["fifteen-bytes-a".to_owned()]);
        let e = parse_attach(&args(&format!("{FULL} --down-link"))).unwrap_err();
        assert_eq!(e, "--down-link needs a value");
    }

    #[test]
    fn world_wait_takes_whole_seconds() {
        let a = parse_attach(&args(FULL)).unwrap();
        assert_eq!(a.world_wait, std::time::Duration::ZERO);
        let a = parse_attach(&args(&format!("{FULL} --world-wait 60"))).unwrap();
        assert_eq!(a.world_wait, std::time::Duration::from_secs(60));
        let bad = |v: &str| parse_attach(&args(&format!("{FULL} --world-wait={v}"))).unwrap_err();
        for v in ["", "-1", "1.5", "1s", "x"] {
            assert!(bad(v).contains("--world-wait: cannot read"), "{v:?}");
        }
    }

    #[test]
    fn help_is_not_an_error() {
        for h in ["--help", "-h"] {
            assert_eq!(super::parse_attach(&args(h)), Ok(Parsed::Help));
            assert_eq!(super::parse_attach(&args(&format!("{FULL} {h}"))), Ok(Parsed::Help));
        }
    }

    #[test]
    fn bad_values() {
        let bad = |extra: &str| parse_attach(&args(&format!("{FULL} {extra}"))).unwrap_err();
        assert!(bad("--ip-addr 10.0.0.2").contains("--ip-addr"));
        assert!(bad("--ip-addr 10.0.0.2/33").contains("--ip-addr"));
        assert!(bad("--gateway fd00::1").contains("--gateway"));
        assert!(bad("--mtu 500").contains("1280"));
        assert!(bad("--bogus 1").contains("unknown flag"));
        let e = parse_attach(&args(&FULL.replace("unix:/run/w.sock", "tls:example.com:7000"))).unwrap_err();
        assert!(e.contains("expected unix:<path>"), "{e}");
        let e = parse_attach(&args(&FULL.replace("--type tun", "--type wireguard"))).unwrap_err();
        assert!(e.contains("tun, tap, https_proxy and socks5 are"), "{e}");
        let long = "x".repeat(256);
        let e = parse_attach(&args(&FULL.replace("--name abc", &format!("--name {long}")))).unwrap_err();
        assert!(e.contains("1 to 255"));
    }

    const PROXY: &str = "--world unix:/run/w.sock --name m3 --type https_proxy --listen 127.0.0.1:8080 \
                         --token-file /run/token --ip-addr 10.0.0.2 --dns 10.0.0.1";

    fn parse_proxy(line: &str) -> Result<ProxyArgs, String> {
        match super::parse_attach(&args(line))? {
            Parsed::Proxy(p) => Ok(p),
            other => panic!("parsed as {other:?}"),
        }
    }

    #[test]
    fn proxy_flags() {
        let p = parse_proxy(PROXY).unwrap();
        assert_eq!(p.kind, ProxyKind::Http);
        assert_eq!(p.world, "/run/w.sock");
        assert_eq!(p.listen, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(p.token_file, PathBuf::from("/run/token"));
        assert_eq!(p.ip_addr, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(p.dns, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(p.ready_file, None);
        let p = parse_proxy(&format!("{} --ready-file /r --world-wait 5", PROXY.replace("https_proxy", "socks5"))).unwrap();
        assert_eq!(p.kind, ProxyKind::Socks5);
        assert_eq!(p.ready_file, Some(PathBuf::from("/r")));
        assert_eq!(p.world_wait, std::time::Duration::from_secs(5));
        let p = parse_proxy(&PROXY.replace("127.0.0.1:8080", "[::]:1080")).unwrap();
        assert_eq!(p.listen, "[::]:1080".parse().unwrap());
    }

    #[test]
    fn proxy_types_refuse_tun_flags() {
        let bad = |extra: &str| parse_proxy(&format!("{PROXY} {extra}")).unwrap_err();
        let e = bad("--gateway 10.0.0.1");
        assert_eq!(e, "--type https_proxy takes no --gateway: attach makes the packets itself, and there are no routes to set");
        assert!(bad("--no-gateway").contains("takes no --no-gateway"));
        assert!(bad("--netns /run/netns/a").contains("takes no --netns"));
        assert!(bad("--down-link eth0").contains("takes no --down-link"));
        assert!(bad("--mtu 1400").contains("takes no --mtu"));
        assert!(bad("--no-resolv-conf").contains("takes no --no-resolv-conf"));
        assert!(bad("--resolv-conf /x").contains("takes no --resolv-conf"));
        assert!(bad("--no-ip-addr-v6").contains("IPv4 only"));
        assert!(bad("--dns-v6 fd00::1").contains("IPv4 only"));
        let e = parse_proxy(&format!("{} --gateway 10.0.0.1", PROXY.replace("https_proxy", "socks5"))).unwrap_err();
        assert!(e.starts_with("--type socks5 takes no --gateway"), "{e}");
    }

    #[test]
    fn proxy_types_need_their_flags() {
        let without = |flag: &str| {
            let words: Vec<&str> = PROXY.split_whitespace().collect();
            let i = words.iter().position(|w| *w == flag).unwrap();
            let line: Vec<&str> = words[..i].iter().chain(&words[i + 2..]).copied().collect();
            parse_proxy(&line.join(" ")).unwrap_err()
        };
        assert!(without("--listen").contains("needs --listen <ip:port>"));
        assert!(without("--token-file").contains("needs --token-file"));
        assert!(without("--ip-addr").contains("needs --ip-addr <ip>"));
        assert!(without("--dns").contains("needs --dns <ip>"));
        let e = parse_proxy(&PROXY.replace("10.0.0.2", "10.0.0.2/24")).unwrap_err();
        assert!(e.contains("without a prefix length"), "{e}");
        assert!(parse_proxy(&PROXY.replace("--ip-addr 10.0.0.2", "--no-ip-addr")).unwrap_err().contains("needs --ip-addr"));
        let e = parse_proxy(&PROXY.replace("127.0.0.1:8080", "8080")).unwrap_err();
        assert!(e.contains("--listen: cannot read"), "{e}");
        let e = parse_proxy(&PROXY.replace("--listen 127.0.0.1:8080", "--port 8080")).unwrap_err();
        assert!(e.contains("give --listen <ip:port>"), "{e}");
    }

    #[test]
    fn tun_refuses_proxy_flags() {
        let e = parse_attach(&args(&format!("{FULL} --listen 127.0.0.1:1"))).unwrap_err();
        assert!(e.contains("--listen is only for --type https_proxy"), "{e}");
        let e = parse_attach(&args(&format!("{FULL} --token-file /t"))).unwrap_err();
        assert!(e.contains("--token-file is only for"), "{e}");
    }

    const TAP: &str = "--world unix:/run/w.sock --name vm1 --type tap --vm qemu:/run/vm1.sock";

    fn parse_tap(line: &str) -> Result<TapArgs, String> {
        match super::parse_attach(&args(line))? {
            Parsed::Tap(t) => Ok(t),
            other => panic!("parsed as {other:?}"),
        }
    }

    #[test]
    fn tap_with_no_address_flags_leaves_dhcp_to_the_world() {
        let t = parse_tap(TAP).unwrap();
        assert_eq!(t.vm, VmLink::Qemu(PathBuf::from("/run/vm1.sock")));
        assert_eq!((t.v4, t.v6), (Family::FromWorld, Family::FromWorld));
        assert_eq!(t.mtu, 1500);
    }

    #[test]
    fn tap_serves_the_address_flags() {
        let t = parse_tap(&format!(
            "{TAP} --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 \
             --ip-addr-v6 fd00::2/64 --no-gateway-v6 --dns-v6 fd00::1 --mtu 9000 --ready-file /r"
        ))
        .unwrap();
        let v4 = Lease {
            addr: Cidr { addr: Ipv4Addr::new(10, 0, 0, 2), prefix: 24 },
            gateway: Some(Ipv4Addr::new(10, 0, 0, 1)),
            dns: Some(Ipv4Addr::new(10, 0, 0, 1)),
        };
        assert_eq!(t.v4, Family::Serve(v4));
        let Family::Serve(v6) = t.v6 else { panic!("{:?}", t.v6) };
        assert_eq!((v6.gateway, v6.dns), (None, Some("fd00::1".parse().unwrap())));
        assert_eq!(t.mtu, 9000);
        let t = parse_tap(&format!("{TAP} --no-ip-addr --no-ip-addr-v6 --no-gateway-v6 --no-dns-v6")).unwrap();
        assert_eq!((t.v4, t.v6), (Family::Off, Family::Off));
    }

    #[test]
    fn tap_address_flags_go_together() {
        let bad = |extra: &str| parse_tap(&format!("{TAP} {extra}")).unwrap_err();
        let e = bad("--ip-addr 10.0.0.2/24 --gateway 10.0.0.1");
        assert!(e.starts_with("--dns (or --no-dns) left out: with --ip-addr"), "{e}");
        let e = bad("--gateway 10.0.0.1");
        assert!(e.starts_with("--gateway needs --ip-addr"), "{e}");
        let e = bad("--no-ip-addr --dns 10.0.0.1");
        assert!(e.starts_with("--dns needs --ip-addr"), "{e}");
        let e = bad("--no-dns-v6");
        assert!(e.starts_with("--no-dns-v6 needs --no-ip-addr-v6 or --ip-addr-v6"), "{e}");
        let e = bad("--ip-addr 10.0.0.2/24 --gateway 10.0.1.1 --no-dns");
        assert!(e.contains("must be another address in the subnet"), "{e}");
        let e = bad("--ip-addr 10.0.0.2/24 --gateway 10.0.0.2 --no-dns");
        assert!(e.contains("must be another address in the subnet"), "{e}");
        assert!(bad("--ip-addr 10.0.0.2/32 --no-gateway --no-dns").contains("from /8 to /30"));
        assert!(bad("--ip-addr 10.0.0.2/0 --no-gateway --no-dns").contains("from /8 to /30"));
        assert!(bad("--ip-addr 10.0.0.2/0 --gateway 10.0.0.1 --no-dns").contains("from /8 to /30"));
        assert!(bad("--ip-addr-v6 fd00::2/120 --no-gateway-v6 --no-dns-v6").contains("at most /64"));
    }

    #[test]
    fn tap_needs_a_qemu_socket_and_refuses_device_flags() {
        let e = parse_tap("--world unix:/w --name vm1 --type tap").unwrap_err();
        assert!(e.contains("needs --vm qemu:<path>"), "{e}");
        let e = parse_tap(&TAP.replace("qemu:", "firecracker:")).unwrap_err();
        assert!(e.contains("--vm must be qemu:<path> or tap:<ifname>"), "{e}");
        let t = parse_tap(&format!("{} --netns /run/netns/vm1", TAP.replace("qemu:/run/vm1.sock", "tap:tap0"))).unwrap();
        assert_eq!((t.vm, t.netns), (VmLink::Tap("tap0".into()), Some(PathBuf::from("/run/netns/vm1"))));
        assert!(parse_tap(&TAP.replace("qemu:/run/vm1.sock", "tap:a/b")).unwrap_err().contains("is not a link name"));
        let e = parse_tap(&format!("{TAP} --netns /run/netns/vm1")).unwrap_err();
        assert!(e.contains("--netns only with --vm tap:<ifname>"), "{e}");
        assert!(parse_tap(&TAP.replace("qemu:/run/vm1.sock", "qemu:")).is_err());
        let long = format!("qemu:/{}", "x".repeat(107));
        assert!(parse_tap(&TAP.replace("qemu:/run/vm1.sock", &long)).unwrap_err().contains("at most 107 bytes"));
        let bad = |extra: &str| parse_tap(&format!("{TAP} {extra}")).unwrap_err();
        assert!(bad("--down-link eth0").starts_with("--type tap takes no --down-link"));
        assert!(bad("--no-resolv-conf").starts_with("--type tap takes no --no-resolv-conf"));
        assert!(bad("--listen 127.0.0.1:1").starts_with("--type tap takes no --listen"));
        // And the other types refuse --vm.
        let e = parse_attach(&args(&format!("{FULL} --vm qemu:/x"))).unwrap_err();
        assert_eq!(e, "--vm is only for --type tap");
        let e = parse_proxy(&format!("{PROXY} --vm qemu:/x")).unwrap_err();
        assert!(e.starts_with("--type https_proxy takes no --vm"), "{e}");
    }
}
