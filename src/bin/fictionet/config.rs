//! The settings each attach type runs with, which `args` reads from the
//! flags, and the values the commands share: the socket path in
//! `--world`, and an IPv4 netmask.

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
            ProxyKind::Http => "http_proxy",
            ProxyKind::Socks5 => "socks5",
        }
    }
}

/// The flags of `--type http_proxy` and `--type socks5`.
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

/// The socket path in `--world unix:<path>`, parsed as a
/// [`WorldSocket`](fictionet::WorldSocket).
pub(crate) fn world_path(world: &str) -> Result<String, String> {
    match world.parse::<fictionet::WorldSocket>() {
        Ok(fictionet::WorldSocket::UnixSocket(path)) => path
            .into_os_string()
            .into_string()
            .map_err(|p| format!("--world: {} is not UTF-8", p.display())),
        Ok(other) => Err(format!(
            "--world {other} is not supported here; use unix:<path>"
        )),
        Err(e) => Err(format!("--world: {e}")),
    }
}

/// The netmask of an IPv4 prefix length, 0 to 32.
pub(crate) fn mask4(prefix: u8) -> u32 {
    let IpAddr::V4(mask) = (fictionet::stdlib::route::Prefix {
        addr: Ipv4Addr::UNSPECIFIED.into(),
        len: prefix,
    })
    .mask() else {
        unreachable!("an IPv4 prefix has an IPv4 mask")
    };
    u32::from(mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks() {
        assert_eq!(mask4(0), 0);
        assert_eq!(mask4(24), 0xffff_ff00);
        assert_eq!(mask4(32), u32::MAX);
    }
}
