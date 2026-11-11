//! What the host says about the data interface, and the checks that must
//! pass before the honeypot takes it over.
//!
//! The facts come from sysfs, procfs, `getifaddrs(3)` and two ethtool
//! ioctls. The checks are pure functions of them. The only changes made to
//! the interface are its MTU and its channel count.

use std::fmt;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::str::FromStr;

/// The MTU the data interface runs at: the most an internet gateway
/// carries, and what the honeypot's Ethernet host assumes.
pub const MTU: u32 = 1500;
/// The driver of an EC2 Elastic Network Adapter.
pub const DRIVER: &str = "ena";

/// A Linux interface name: 1 to 15 bytes, not `.` or `..`, with no `/`,
/// `:` or whitespace (`dev_valid_name` in `net/core/dev.c`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceName(String);

impl InterfaceName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An interface name the kernel would not accept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidName(pub String);

impl fmt::Display for InvalidName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} is not a Linux interface name", self.0)
    }
}

impl std::error::Error for InvalidName {}

impl FromStr for InterfaceName {
    type Err = InvalidName;

    fn from_str(name: &str) -> Result<Self, InvalidName> {
        let valid = (1..libc::IFNAMSIZ).contains(&name.len())
            && name != "."
            && name != ".."
            && !name
                .bytes()
                .any(|b| b == b'/' || b == b':' || b.is_ascii_whitespace() || b == 0);
        if valid {
            Ok(Self(name.to_owned()))
        } else {
            Err(InvalidName(name.to_owned()))
        }
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The driver as `ETHTOOL_GDRVINFO` reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Driver {
    pub name: String,
    pub version: String,
    pub firmware: String,
    pub bus: String,
}

/// Queue channels as `ETHTOOL_GCHANNELS` reports them. ENA has only
/// combined channels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Channels {
    pub combined: u32,
    pub max_combined: u32,
    pub rx: u32,
    pub tx: u32,
}

/// One route in the main routing table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub interface: String,
    pub destination: IpAddr,
    pub prefix: u8,
}

impl Route {
    pub fn is_default(&self) -> bool {
        self.prefix == 0
    }

    fn contains(&self, address: IpAddr) -> bool {
        match (self.destination, address) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{} dev {}",
            self.destination, self.prefix, self.interface
        )
    }
}

/// An established kernel TCP connection, such as the SSH session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Connection {
    pub local: SocketAddr,
    pub peer: SocketAddr,
}

/// Everything the startup checks read about the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facts {
    pub name: InterfaceName,
    pub ifindex: u32,
    pub mac: [u8; 6],
    pub up: bool,
    pub mtu: u32,
    /// Receive queues the kernel has for the interface.
    pub rx_queues: u32,
    pub driver: Driver,
    pub channels: Channels,
    /// Every address on every interface, by interface name.
    pub addresses: Vec<(String, IpAddr)>,
    /// The main routing table, both families.
    pub routes: Vec<Route>,
    /// Established TCP connections.
    pub connections: Vec<Connection>,
}

/// Why a connection runs over the named interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Path {
    /// Its local address is on the interface.
    LocalAddress,
    /// The route to its peer uses the interface.
    Route(Route),
}

/// A reason not to take the interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The default route uses it: it is the management path.
    DefaultRoute(Route),
    /// An established connection, such as the SSH session, runs over it.
    Connection(Connection, Path),
    /// A route uses it. The data interface carries none.
    Route(Route),
    /// It has an address. The data interface has none.
    Address(IpAddr),
    /// It is not an ENA.
    Driver(String),
    /// It is administratively down.
    Down,
    /// Its MTU is not 1500.
    Mtu(u32),
    /// It has more or fewer than one receive queue, so one socket would not
    /// see every frame.
    ReceiveQueues(u32),
    /// Its channel setting is not one combined channel within half the
    /// device maximum, which ENA needs to attach XDP.
    Channels(Channels),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefaultRoute(route) => write!(f, "it carries the default route ({route})"),
            Self::Connection(connection, Path::LocalAddress) => write!(
                f,
                "it carries the connection {} to {}, whose local address is on it",
                connection.local, connection.peer
            ),
            Self::Connection(connection, Path::Route(route)) => write!(
                f,
                "it carries the connection {} to {}, routed by {route}",
                connection.local, connection.peer
            ),
            Self::Route(route) => write!(f, "a route uses it ({route})"),
            Self::Address(address) => write!(f, "it has the address {address}"),
            Self::Driver(driver) => write!(f, "its driver is {driver:?}, not {DRIVER:?}"),
            Self::Down => f.write_str("it is down"),
            Self::Mtu(mtu) => write!(f, "its MTU is {mtu}, not {MTU}"),
            Self::ReceiveQueues(queues) => write!(f, "it has {queues} receive queues, not 1"),
            Self::Channels(channels) => write!(
                f,
                "it has {} combined channels of at most {}; XDP needs 1, at most half the maximum",
                channels.combined, channels.max_combined
            ),
        }
    }
}

/// Reasons the interface may be the management path. Checked before
/// anything on the host changes.
pub fn management_refusals(facts: &Facts) -> Vec<Refusal> {
    let name = facts.name.as_str();
    let mut refusals = Vec::new();
    for route in facts.routes.iter().filter(|route| route.interface == name) {
        refusals.push(if route.is_default() {
            Refusal::DefaultRoute(route.clone())
        } else {
            Refusal::Route(route.clone())
        });
    }
    for connection in &facts.connections {
        let local = facts
            .addresses
            .iter()
            .any(|(interface, address)| interface == name && *address == connection.local.ip());
        if local {
            refusals.push(Refusal::Connection(*connection, Path::LocalAddress));
        } else if let Some(route) = route_to(&facts.routes, connection.peer.ip())
            && route.interface == name
        {
            refusals.push(Refusal::Connection(*connection, Path::Route(route.clone())));
        }
    }
    refusals.extend(
        facts
            .addresses
            .iter()
            .filter(|(interface, _)| interface == name)
            .map(|(_, address)| Refusal::Address(*address)),
    );
    if facts.driver.name != DRIVER {
        refusals.push(Refusal::Driver(facts.driver.name.clone()));
    }
    if !facts.up {
        refusals.push(Refusal::Down);
    }
    refusals
}

/// Reasons the interface does not fit one socket on one queue at MTU 1500.
/// Checked after setting the MTU and channels, on facts read back.
pub fn fit_refusals(facts: &Facts) -> Vec<Refusal> {
    let mut refusals = Vec::new();
    if facts.mtu != MTU {
        refusals.push(Refusal::Mtu(facts.mtu));
    }
    if facts.rx_queues != 1 {
        refusals.push(Refusal::ReceiveQueues(facts.rx_queues));
    }
    let channels = facts.channels;
    if channels.combined != 1
        || channels.rx != 0
        || channels.tx != 0
        || 2 * channels.combined > channels.max_combined
    {
        refusals.push(Refusal::Channels(channels));
    }
    refusals
}

/// The longest-prefix route for `address`.
fn route_to(routes: &[Route], address: IpAddr) -> Option<&Route> {
    routes
        .iter()
        .filter(|route| route.contains(address))
        .max_by_key(|route| route.prefix)
}

/// Parses `/proc/net/route`: the IPv4 main table. Fields are hexadecimal
/// in host byte order. Only routes marked up (`RTF_UP`) count.
fn parse_ipv4_routes(text: &str) -> io::Result<Vec<Route>> {
    let mut routes = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [interface, destination, _gateway, flags, _, _, _, mask, ..] = fields[..] else {
            return Err(malformed("/proc/net/route", line));
        };
        let hex = |field: &str| {
            u32::from_str_radix(field, 16).map_err(|_| malformed("/proc/net/route", line))
        };
        if hex(flags)? & libc::RTF_UP as u32 == 0 {
            continue;
        }
        let mask = u32::from_be_bytes(hex(mask)?.to_ne_bytes());
        if mask.leading_ones() + mask.trailing_zeros() != 32 {
            return Err(malformed("/proc/net/route", line));
        }
        routes.push(Route {
            interface: interface.to_owned(),
            destination: IpAddr::V4(Ipv4Addr::from(hex(destination)?.to_ne_bytes())),
            prefix: mask.leading_ones() as u8,
        });
    }
    Ok(routes)
}

/// Parses `/proc/net/ipv6_route`: destination and prefix length in
/// hexadecimal, network byte order, and the device last.
fn parse_ipv6_routes(text: &str) -> io::Result<Vec<Route>> {
    let mut routes = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [destination, prefix, .., flags, interface] = fields[..] else {
            return Err(malformed("/proc/net/ipv6_route", line));
        };
        let destination = u128::from_str_radix(destination, 16)
            .map_err(|_| malformed("/proc/net/ipv6_route", line))?;
        let prefix =
            u8::from_str_radix(prefix, 16).map_err(|_| malformed("/proc/net/ipv6_route", line))?;
        let flags =
            u32::from_str_radix(flags, 16).map_err(|_| malformed("/proc/net/ipv6_route", line))?;
        if flags & libc::RTF_UP as u32 == 0 || prefix > 128 {
            continue;
        }
        routes.push(Route {
            interface: interface.to_owned(),
            destination: IpAddr::V6(Ipv6Addr::from(destination)),
            prefix,
        });
    }
    Ok(routes)
}

/// Parses `/proc/net/tcp` or `/proc/net/tcp6` for established
/// connections. Addresses are 32-bit words printed in host byte order.
fn parse_tcp(text: &str) -> io::Result<Vec<Connection>> {
    const ESTABLISHED: &str = "01";
    let mut connections = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [_, local, peer, state, ..] = fields[..] else {
            return Err(malformed("/proc/net/tcp", line));
        };
        if state != ESTABLISHED {
            continue;
        }
        let address = |field: &str| -> io::Result<SocketAddr> {
            let (ip, port) = field
                .split_once(':')
                .ok_or_else(|| malformed("/proc/net/tcp", line))?;
            let port =
                u16::from_str_radix(port, 16).map_err(|_| malformed("/proc/net/tcp", line))?;
            let mut bytes = Vec::with_capacity(16);
            for word in ip.as_bytes().chunks(8) {
                let word = std::str::from_utf8(word)
                    .ok()
                    .and_then(|word| u32::from_str_radix(word, 16).ok())
                    .ok_or_else(|| malformed("/proc/net/tcp", line))?;
                bytes.extend_from_slice(&word.to_ne_bytes());
            }
            let ip = match bytes.len() {
                4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap())),
                16 => {
                    let v6 = Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap());
                    v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
                }
                _ => return Err(malformed("/proc/net/tcp", line)),
            };
            Ok(SocketAddr::new(ip, port))
        };
        connections.push(Connection {
            local: address(local)?,
            peer: address(peer)?,
        });
    }
    Ok(connections)
}

fn malformed(file: &str, line: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unexpected line in {file}: {line:?}"),
    )
}

/// A file under procfs, or empty text when the file is absent (IPv6 off).
fn read_optional(path: &str) -> io::Result<String> {
    match fs::read_to_string(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        other => other,
    }
}

fn sysfs(name: &InterfaceName, attribute: &str) -> io::Result<String> {
    fs::read_to_string(format!("/sys/class/net/{name}/{attribute}"))
        .map(|text| text.trim().to_owned())
}

fn sysfs_number(name: &InterfaceName, attribute: &str, radix: u32) -> io::Result<u32> {
    let text = sysfs(name, attribute)?;
    let digits = text.strip_prefix("0x").unwrap_or(&text);
    u32::from_str_radix(digits, radix).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected /sys/class/net/{name}/{attribute}: {text:?}"),
        )
    })
}

fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let bytes: Vec<u8> = text
        .split(':')
        .map(|byte| u8::from_str_radix(byte, 16).ok())
        .collect::<Option<_>>()?;
    bytes.try_into().ok()
}

/// The main routing table, both families.
pub fn routes() -> io::Result<Vec<Route>> {
    let mut routes = parse_ipv4_routes(&fs::read_to_string("/proc/net/route")?)?;
    routes.extend(parse_ipv6_routes(&read_optional("/proc/net/ipv6_route")?)?);
    Ok(routes)
}

/// Reads every fact the checks need.
pub fn read(name: &InterfaceName) -> io::Result<Facts> {
    let mac = sysfs(name, "address")?;
    let mac = parse_mac(&mac).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected MAC address for {name}: {mac:?}"),
        )
    })?;
    let rx_queues = fs::read_dir(format!("/sys/class/net/{name}/queues"))?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("rx-"))
        .count() as u32;
    let ethtool = Ethtool::open(name)?;
    let routes = routes()?;
    let mut connections = parse_tcp(&fs::read_to_string("/proc/net/tcp")?)?;
    connections.extend(parse_tcp(&read_optional("/proc/net/tcp6")?)?);
    Ok(Facts {
        name: name.clone(),
        ifindex: sysfs_number(name, "ifindex", 10)?,
        mac,
        up: sysfs_number(name, "flags", 16)? & libc::IFF_UP as u32 != 0,
        mtu: sysfs_number(name, "mtu", 10)?,
        rx_queues,
        driver: ethtool.driver()?,
        channels: ethtool.channels()?.into(),
        addresses: addresses()?,
        routes,
        connections,
    })
}

/// Sets the interface's MTU through sysfs.
pub fn set_mtu(name: &InterfaceName, mtu: u32) -> io::Result<()> {
    fs::write(format!("/sys/class/net/{name}/mtu"), format!("{mtu}\n"))
}

/// Sets the interface to `combined` combined channels, keeping the rest.
pub fn set_combined_channels(name: &InterfaceName, combined: u32) -> io::Result<()> {
    let ethtool = Ethtool::open(name)?;
    let mut channels = ethtool.channels()?;
    channels.combined_count = combined;
    ethtool.set_channels(channels)
}

/// Every address on every interface, from `getifaddrs(3)`.
fn addresses() -> io::Result<Vec<(String, IpAddr)>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `list` is a valid place for the result pointer.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut addresses = Vec::new();
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: `entry` is a node of the list getifaddrs returned, which
        // stays allocated until freeifaddrs below.
        let node = unsafe { &*entry };
        entry = node.ifa_next;
        if node.ifa_addr.is_null() || node.ifa_name.is_null() {
            continue;
        }
        // SAFETY: `ifa_name` is a NUL-terminated string in the list.
        let name = unsafe { std::ffi::CStr::from_ptr(node.ifa_name) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: `ifa_addr` is non-null and points to a sockaddr whose
        // family says which larger struct it is.
        let family = i32::from(unsafe { (*node.ifa_addr).sa_family });
        let address = match family {
            libc::AF_INET => {
                // SAFETY: an AF_INET address is a `sockaddr_in`.
                let sin = unsafe { &*node.ifa_addr.cast::<libc::sockaddr_in>() };
                IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)))
            }
            libc::AF_INET6 => {
                // SAFETY: an AF_INET6 address is a `sockaddr_in6`.
                let sin6 = unsafe { &*node.ifa_addr.cast::<libc::sockaddr_in6>() };
                IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr))
            }
            _ => continue,
        };
        addresses.push((name, address));
    }
    // SAFETY: `list` came from getifaddrs and is freed once; no reference
    // into it outlives this point.
    unsafe { libc::freeifaddrs(list) };
    Ok(addresses)
}

const ETHTOOL_GDRVINFO: u32 = 0x03;
const ETHTOOL_GCHANNELS: u32 = 0x3c;
const ETHTOOL_SCHANNELS: u32 = 0x3d;

/// `struct ethtool_drvinfo`.
#[repr(C)]
struct EthtoolDrvinfo {
    cmd: u32,
    driver: [u8; 32],
    version: [u8; 32],
    fw_version: [u8; 32],
    bus_info: [u8; 32],
    erom_version: [u8; 32],
    reserved2: [u8; 12],
    n_priv_flags: u32,
    n_stats: u32,
    testinfo_len: u32,
    eedump_len: u32,
    regdump_len: u32,
}

/// `struct ethtool_channels`.
#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct EthtoolChannels {
    cmd: u32,
    max_rx: u32,
    max_tx: u32,
    max_other: u32,
    max_combined: u32,
    rx_count: u32,
    tx_count: u32,
    other_count: u32,
    combined_count: u32,
}

impl From<EthtoolChannels> for Channels {
    fn from(channels: EthtoolChannels) -> Self {
        Self {
            combined: channels.combined_count,
            max_combined: channels.max_combined,
            rx: channels.rx_count,
            tx: channels.tx_count,
        }
    }
}

/// Ethtool requests for one interface, over a datagram socket.
struct Ethtool {
    socket: OwnedFd,
    name: [libc::c_char; libc::IFNAMSIZ],
}

impl Ethtool {
    fn open(name: &InterfaceName) -> io::Result<Self> {
        // SAFETY: socket takes only scalars.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socket returned a fresh descriptor nothing else owns.
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut bytes = [0 as libc::c_char; libc::IFNAMSIZ];
        for (slot, byte) in bytes.iter_mut().zip(name.as_str().bytes()) {
            *slot = byte as libc::c_char;
        }
        Ok(Self {
            socket,
            name: bytes,
        })
    }

    /// Runs one ethtool command whose request and reply are `T`, which
    /// starts with its `u32` command number.
    ///
    /// # Safety
    ///
    /// `T` must be the ethtool struct the command in its first field reads
    /// and writes, with no pointer fields.
    unsafe fn request<T>(&self, data: &mut T) -> io::Result<()> {
        // SAFETY: an all-zero ifreq is valid: a name and a union of plain
        // data and a pointer, which is set below.
        let mut ifreq: libc::ifreq = unsafe { std::mem::zeroed() };
        ifreq.ifr_name = self.name;
        ifreq.ifr_ifru.ifru_data = (data as *mut T).cast();
        // SAFETY: `ifreq` names the interface and points at `data`, which
        // is the struct the command expects (caller's contract) and stays
        // live and exclusive for the call.
        let result =
            unsafe { libc::ioctl(self.socket.as_raw_fd(), libc::SIOCETHTOOL as _, &mut ifreq) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn driver(&self) -> io::Result<Driver> {
        // SAFETY: all-zero bytes are a valid `ethtool_drvinfo`.
        let mut info: EthtoolDrvinfo = unsafe { std::mem::zeroed() };
        info.cmd = ETHTOOL_GDRVINFO;
        // SAFETY: GDRVINFO reads and writes `struct ethtool_drvinfo`.
        unsafe { self.request(&mut info)? };
        let text = |bytes: &[u8]| {
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            String::from_utf8_lossy(&bytes[..end]).into_owned()
        };
        Ok(Driver {
            name: text(&info.driver),
            version: text(&info.version),
            firmware: text(&info.fw_version),
            bus: text(&info.bus_info),
        })
    }

    fn channels(&self) -> io::Result<EthtoolChannels> {
        let mut channels = EthtoolChannels {
            cmd: ETHTOOL_GCHANNELS,
            max_rx: 0,
            max_tx: 0,
            max_other: 0,
            max_combined: 0,
            rx_count: 0,
            tx_count: 0,
            other_count: 0,
            combined_count: 0,
        };
        // SAFETY: GCHANNELS reads and writes `struct ethtool_channels`.
        unsafe { self.request(&mut channels)? };
        Ok(channels)
    }

    fn set_channels(&self, mut channels: EthtoolChannels) -> io::Result<()> {
        channels.cmd = ETHTOOL_SCHANNELS;
        // SAFETY: SCHANNELS reads `struct ethtool_channels`.
        unsafe { self.request(&mut channels) }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A data ENA as Stage 6 provisions it, beside a management ENA.
    pub fn provisioned() -> Facts {
        Facts {
            name: "ens6".parse().unwrap(),
            ifindex: 3,
            mac: [0x0a, 0, 0, 0, 0, 2],
            up: true,
            mtu: 1500,
            rx_queues: 1,
            driver: Driver {
                name: "ena".into(),
                version: "6.12.0".into(),
                firmware: String::new(),
                bus: "0000:00:06.0".into(),
            },
            channels: Channels {
                combined: 1,
                max_combined: 2,
                rx: 0,
                tx: 0,
            },
            addresses: vec![
                ("lo".into(), "127.0.0.1".parse().unwrap()),
                ("ens5".into(), "10.0.1.10".parse().unwrap()),
            ],
            routes: vec![route("ens5", "0.0.0.0", 0), route("ens5", "10.0.1.0", 24)],
            connections: vec![Connection {
                local: "10.0.1.10:22".parse().unwrap(),
                peer: "198.51.100.7:51234".parse().unwrap(),
            }],
        }
    }

    fn route(interface: &str, destination: &str, prefix: u8) -> Route {
        Route {
            interface: interface.into(),
            destination: destination.parse().unwrap(),
            prefix,
        }
    }

    #[test]
    fn interface_names_follow_the_kernel_rules() {
        for good in ["ens6", "eth0", "a", "fifteen-chars-x"] {
            assert!(good.parse::<InterfaceName>().is_ok(), "{good}");
        }
        for bad in [
            "",
            ".",
            "..",
            "has/slash",
            "has:colon",
            "has space",
            "sixteen-chars-xx",
        ] {
            assert!(bad.parse::<InterfaceName>().is_err(), "{bad}");
        }
    }

    #[test]
    fn a_provisioned_data_interface_passes() {
        let facts = provisioned();
        assert_eq!(management_refusals(&facts), []);
        assert_eq!(fit_refusals(&facts), []);
    }

    #[test]
    fn the_management_interface_is_refused() {
        let mut facts = provisioned();
        facts.name = "ens5".parse().unwrap();
        let refusals = management_refusals(&facts);
        assert!(refusals.contains(&Refusal::DefaultRoute(route("ens5", "0.0.0.0", 0))));
        assert!(refusals.contains(&Refusal::Route(route("ens5", "10.0.1.0", 24))));
        assert!(refusals.contains(&Refusal::Address("10.0.1.10".parse().unwrap())));
        assert!(refusals.contains(&Refusal::Connection(
            facts.connections[0],
            Path::LocalAddress
        )));
    }

    #[test]
    fn an_ssh_session_routed_over_the_interface_is_refused() {
        let mut facts = provisioned();
        // The session's local address is elsewhere, but its peer is reached
        // through ens6 by a more specific route.
        facts.routes.push(route("ens6", "198.51.100.0", 24));
        let refusals = management_refusals(&facts);
        assert!(refusals.contains(&Refusal::Connection(
            facts.connections[0],
            Path::Route(route("ens6", "198.51.100.0", 24))
        )));
        assert!(refusals.contains(&Refusal::Route(route("ens6", "198.51.100.0", 24))));
    }

    #[test]
    fn a_default_route_on_the_interface_is_refused() {
        let mut facts = provisioned();
        facts.routes.push(route("ens6", "::", 0));
        assert_eq!(
            management_refusals(&facts),
            [Refusal::DefaultRoute(route("ens6", "::", 0))]
        );
    }

    #[test]
    fn an_address_on_the_interface_is_refused() {
        let mut facts = provisioned();
        let link_local: IpAddr = "fe80::8ff:feff:fe00:2".parse().unwrap();
        facts.addresses.push(("ens6".into(), link_local));
        assert_eq!(management_refusals(&facts), [Refusal::Address(link_local)]);
    }

    #[test]
    fn other_drivers_and_a_down_link_are_refused() {
        let mut facts = provisioned();
        facts.driver.name = "virtio_net".into();
        facts.up = false;
        assert_eq!(
            management_refusals(&facts),
            [Refusal::Driver("virtio_net".into()), Refusal::Down]
        );
    }

    #[test]
    fn jumbo_mtu_and_extra_queues_do_not_fit() {
        let mut facts = provisioned();
        facts.mtu = 9001;
        facts.rx_queues = 2;
        facts.channels.combined = 2;
        assert_eq!(
            fit_refusals(&facts),
            [
                Refusal::Mtu(9001),
                Refusal::ReceiveQueues(2),
                Refusal::Channels(facts.channels)
            ]
        );
    }

    #[test]
    fn one_channel_must_be_at_most_half_the_maximum() {
        let mut facts = provisioned();
        facts.channels.max_combined = 1;
        assert_eq!(fit_refusals(&facts), [Refusal::Channels(facts.channels)]);
    }

    #[test]
    fn ipv4_routes_parse_from_host_order_hex() {
        let text = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                    ens5\t00000000\t01010A0A\t0003\t0\t0\t512\t00000000\t0\t0\t0\n\
                    ens5\t00010A0A\t00000000\t0001\t0\t0\t512\t00FFFFFF\t0\t0\t0\n\
                    ens6\t00020A0A\t00000000\t0000\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(
            parse_ipv4_routes(text).unwrap(),
            [route("ens5", "0.0.0.0", 0), route("ens5", "10.10.1.0", 24)]
        );
    }

    #[test]
    fn ipv6_routes_parse_with_the_device_last() {
        let text = "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     ens5\n\
                    00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n";
        assert_eq!(
            parse_ipv6_routes(text).unwrap(),
            [route("ens5", "fe80::", 64)]
        );
    }

    #[test]
    fn tcp_tables_yield_established_connections() {
        let v4 = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                  0: 0A01000A:0016 07643364:C842 01 00000000:00000000 02:000A3D1E 00000000     0        0 1 1\n\
                  1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1\n";
        assert_eq!(
            parse_tcp(v4).unwrap(),
            [Connection {
                local: "10.0.1.10:22".parse().unwrap(),
                peer: "100.51.100.7:51266".parse().unwrap(),
            }]
        );
        let v6 = "  sl  local_address                         remote_address                        st\n\
                  0: 0000000000000000FFFF00000A01000A:0016 0000000000000000FFFF000007643364:C842 01 0\n";
        assert_eq!(
            parse_tcp(v6).unwrap(),
            [Connection {
                local: "10.0.1.10:22".parse().unwrap(),
                peer: "100.51.100.7:51266".parse().unwrap(),
            }]
        );
    }

    #[test]
    fn ethtool_structs_match_the_uapi_layout() {
        assert_eq!(size_of::<EthtoolChannels>(), 36);
        assert_eq!(size_of::<EthtoolDrvinfo>(), 196);
    }
}
