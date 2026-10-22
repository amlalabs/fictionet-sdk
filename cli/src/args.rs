//! Each attachment type has its own command and flags.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use crate::config::{AttachArgs, ProxyArgs, ProxyKind, ResolvConf, TapArgs, VmLink};
use clap::{Args, Parser, Subcommand};
use fictionet::stdlib::network::ethernet::{Cidr, Family, Lease};

#[derive(Parser)]
#[command(name = "fictionet attach", disable_version_flag = true)]
struct Attach {
    #[command(subcommand)]
    kind: Kind,
}

#[derive(Subcommand)]
enum Kind {
    /// Make a TUN device in a sandbox network namespace.
    Tun(Tun),
    /// Connect a virtual machine through Ethernet.
    Tap(Tap),
    /// Listen as an HTTP proxy, authenticated with the sandbox token.
    HttpProxy(Proxy),
    /// Listen as a SOCKS5 proxy, authenticated with the sandbox token.
    Socks5(Proxy),
}

#[derive(Args)]
struct Common {
    #[arg(long, value_parser = crate::config::world_path)]
    world: String,
    #[arg(long, value_parser = parse_name)]
    name: String,
    #[arg(long)]
    ready_file: Option<PathBuf>,
    /// Seconds to keep trying the world's socket. Zero tries once.
    #[arg(long, default_value_t = 0)]
    world_wait: u32,
}

#[derive(Args)]
struct Tun {
    #[command(flatten)]
    common: Common,
    #[arg(long)]
    netns: Option<PathBuf>,
    #[arg(long, value_parser = parse_v4)]
    ip_addr: Option<Cidr<Ipv4Addr>>,
    #[arg(long)]
    gateway: Option<Ipv4Addr>,
    #[arg(long)]
    dns: Option<Ipv4Addr>,
    #[arg(long, value_parser = parse_v6)]
    ip_addr_v6: Option<Cidr<Ipv6Addr>>,
    #[arg(long)]
    gateway_v6: Option<Ipv6Addr>,
    #[arg(long)]
    dns_v6: Option<Ipv6Addr>,
    #[arg(long, default_value_t = 1500, value_parser = clap::value_parser!(u16).range(1280..))]
    mtu: u16,
    #[arg(long, conflicts_with = "no_resolv_conf", value_parser = parse_path)]
    resolv_conf: Option<PathBuf>,
    #[arg(long)]
    no_resolv_conf: bool,
    #[arg(long, value_parser = parse_ifname)]
    down_link: Vec<String>,
}

#[derive(Args)]
struct Tap {
    #[command(flatten)]
    common: Common,
    #[arg(long, value_parser = parse_vm)]
    vm: VmLink,
    #[arg(long)]
    netns: Option<PathBuf>,
    /// Supply an IPv4 lease. Omit to pass the VM's DHCP to the world.
    #[arg(long, value_parser = parse_v4, conflicts_with = "no_ip_addr")]
    ip_addr: Option<Cidr<Ipv4Addr>>,
    #[arg(long, requires = "ip_addr")]
    gateway: Option<Ipv4Addr>,
    #[arg(long, requires = "ip_addr")]
    dns: Option<Ipv4Addr>,
    /// Disable IPv4 leases and drop the VM's DHCP.
    #[arg(long)]
    no_ip_addr: bool,
    #[arg(long, value_parser = parse_v6, conflicts_with = "no_ip_addr_v6")]
    ip_addr_v6: Option<Cidr<Ipv6Addr>>,
    #[arg(long, requires = "ip_addr_v6")]
    gateway_v6: Option<Ipv6Addr>,
    #[arg(long, requires = "ip_addr_v6")]
    dns_v6: Option<Ipv6Addr>,
    #[arg(long)]
    no_ip_addr_v6: bool,
    #[arg(long, default_value_t = 1500, value_parser = clap::value_parser!(u16).range(1280..))]
    mtu: u16,
}

#[derive(Args)]
struct Proxy {
    #[command(flatten)]
    common: Common,
    #[arg(long)]
    listen: SocketAddr,
    #[arg(long, value_parser = parse_path)]
    token_file: PathBuf,
    #[arg(long)]
    ip_addr: Ipv4Addr,
    #[arg(long)]
    dns: Ipv4Addr,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Parsed {
    Help(String),
    Run(AttachArgs),
    Proxy(ProxyArgs),
    Tap(TapArgs),
}

pub(crate) fn parse_attach(args: &[String]) -> Result<Parsed, String> {
    let parsed = match Attach::try_parse_from(
        std::iter::once("fictionet attach".to_owned()).chain(args.iter().cloned()),
    ) {
        Ok(parsed) => parsed,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            return Ok(Parsed::Help(error.to_string()));
        }
        Err(error) => return Err(error.to_string()),
    };
    Ok(match parsed.kind {
        Kind::Tun(t) => {
            let mut down_links = Vec::new();
            for link in t.down_link {
                if !down_links.contains(&link) {
                    down_links.push(link);
                }
            }
            Parsed::Run(AttachArgs {
                world: t.common.world,
                name: t.common.name,
                ready_file: t.common.ready_file,
                world_wait: Duration::from_secs(t.common.world_wait.into()),
                netns: t.netns,
                ip_addr: t.ip_addr,
                gateway: t.gateway,
                dns: t.dns,
                ip_addr_v6: t.ip_addr_v6,
                gateway_v6: t.gateway_v6,
                dns_v6: t.dns_v6,
                mtu: t.mtu,
                down_links,
                resolv_conf: match (t.resolv_conf, t.no_resolv_conf) {
                    (Some(path), _) => ResolvConf::Path(path),
                    (None, true) => ResolvConf::Off,
                    (None, false) => ResolvConf::Default,
                },
            })
        }
        Kind::Tap(t) => {
            if matches!(t.vm, VmLink::Qemu(_)) && t.netns.is_some() {
                return Err("attach tap takes --netns only with --vm tap:<ifname>".into());
            }
            if let Some(addr) = t.ip_addr {
                if !(8..=30).contains(&addr.prefix) {
                    return Err("--ip-addr: the prefix must be from /8 to /30".into());
                }
                if let Some(gw) = t.gateway {
                    let subnet = fictionet::stdlib::network::route::Prefix {
                        addr: addr.addr.into(),
                        len: addr.prefix,
                    };
                    if !subnet.contains(gw.into()) || gw == addr.addr {
                        return Err(format!(
                            "--gateway {gw} must be another address in the subnet of --ip-addr {}/{}",
                            addr.addr, addr.prefix
                        ));
                    }
                }
            }
            if let Some(addr) = t.ip_addr_v6
                && addr.prefix > 64
            {
                return Err("--ip-addr-v6: the prefix must be at most /64".into());
            }
            Parsed::Tap(TapArgs {
                world: t.common.world,
                name: t.common.name,
                ready_file: t.common.ready_file,
                world_wait: Duration::from_secs(t.common.world_wait.into()),
                vm: t.vm,
                netns: t.netns,
                mtu: t.mtu,
                v4: family(t.ip_addr, t.gateway, t.dns, t.no_ip_addr),
                v6: family(t.ip_addr_v6, t.gateway_v6, t.dns_v6, t.no_ip_addr_v6),
            })
        }
        Kind::HttpProxy(p) => Parsed::Proxy(proxy(ProxyKind::Http, p)),
        Kind::Socks5(p) => Parsed::Proxy(proxy(ProxyKind::Socks5, p)),
    })
}

fn proxy(kind: ProxyKind, p: Proxy) -> ProxyArgs {
    ProxyArgs {
        kind,
        world: p.common.world,
        name: p.common.name,
        ready_file: p.common.ready_file,
        world_wait: Duration::from_secs(p.common.world_wait.into()),
        listen: p.listen,
        token_file: p.token_file,
        ip_addr: p.ip_addr,
        dns: p.dns,
    }
}

fn family<A>(addr: Option<Cidr<A>>, gateway: Option<A>, dns: Option<A>, off: bool) -> Family<A> {
    match addr {
        Some(addr) => Family::Serve(Lease { addr, gateway, dns }),
        None if off => Family::Off,
        None => Family::FromWorld,
    }
}

fn parse_name(s: &str) -> Result<String, String> {
    if s.is_empty() || s.len() > 255 {
        Err("name must be 1 to 255 bytes".into())
    } else {
        Ok(s.to_owned())
    }
}

fn parse_path(s: &str) -> Result<PathBuf, String> {
    if s.is_empty() {
        Err("needs a path".into())
    } else {
        Ok(s.into())
    }
}

fn parse_ifname(s: &str) -> Result<String, String> {
    if !s.is_empty()
        && s.len() < 16
        && s != "."
        && s != ".."
        && !s
            .bytes()
            .any(|b| b == b'/' || b == b':' || b.is_ascii_whitespace())
    {
        Ok(s.to_owned())
    } else {
        Err(format!("{s:?} is not a link name"))
    }
}

fn parse_vm(s: &str) -> Result<VmLink, String> {
    match s.split_once(':') {
        Some(("qemu", path)) if path.len() > 107 => {
            Err("the socket path must be at most 107 bytes".into())
        }
        Some(("qemu", path)) if !path.is_empty() => Ok(VmLink::Qemu(path.into())),
        Some(("tap", name)) => parse_ifname(name).map(VmLink::Tap),
        _ => Err("--vm must be qemu:<path> or tap:<ifname>".into()),
    }
}

fn parse_cidr<A: std::str::FromStr>(s: &str, max: u8) -> Result<Cidr<A>, String> {
    let (addr, prefix) = s
        .split_once('/')
        .ok_or("expected an address with a prefix length")?;
    let prefix = prefix.parse::<u8>().map_err(|_| "invalid prefix length")?;
    if prefix > max {
        return Err("invalid prefix length".into());
    }
    Ok(Cidr {
        addr: addr.parse().map_err(|_| "invalid IP address")?,
        prefix,
    })
}
fn parse_v4(s: &str) -> Result<Cidr<Ipv4Addr>, String> {
    parse_cidr(s, 32)
}
fn parse_v6(s: &str) -> Result<Cidr<Ipv6Addr>, String> {
    parse_cidr(s, 128)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(s: &str) -> Result<Parsed, String> {
        parse_attach(&s.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
    }

    #[test]
    fn tun_omitted_addresses_are_off() {
        let Parsed::Run(t) = parse("tun --world unix:/w --name agent").unwrap() else {
            panic!()
        };
        assert_eq!(t.ip_addr, None);
        assert_eq!(t.ip_addr_v6, None);
        assert!(t.dns_servers().is_empty());
        assert_eq!(t.mtu, 1500);
    }

    #[test]
    fn tun_reads_both_families_and_device_flags() {
        let Parsed::Run(t) = parse("tun --world unix:/w --name agent --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 --ip-addr-v6 fd00::2/64 --gateway-v6 fd00::1 --dns-v6 fd00::1 --mtu=9000 --down-link eth0 --down-link net1 --down-link eth0 --resolv-conf=--odd --world-wait 4").unwrap() else { panic!() };
        assert_eq!(t.ip_addr.unwrap().prefix, 24);
        assert_eq!(t.ip_addr_v6.unwrap().prefix, 64);
        assert_eq!(
            t.dns_servers(),
            [
                "10.0.0.1".parse::<std::net::IpAddr>().unwrap(),
                "fd00::1".parse().unwrap()
            ]
        );
        assert_eq!(t.down_links, ["eth0", "net1"]);
        assert_eq!(t.mtu, 9000);
        assert_eq!(t.resolv_conf, ResolvConf::Path("--odd".into()));
        assert_eq!(t.world_wait, Duration::from_secs(4));
    }

    #[test]
    fn commands_reject_other_types_flags() {
        for command in ["http-proxy", "socks5"] {
            let base = format!(
                "{command} --world unix:/w --name a --listen 127.0.0.1:0 --token-file /t --ip-addr 10.0.0.2 --dns 10.0.0.1"
            );
            let Parsed::Proxy(p) = parse(&base).unwrap() else {
                panic!()
            };
            assert_eq!(
                p.kind,
                if command == "socks5" {
                    ProxyKind::Socks5
                } else {
                    ProxyKind::Http
                }
            );
            for flag in [
                "--gateway 10.0.0.1",
                "--netns /n",
                "--mtu 1400",
                "--vm qemu:/v",
                "--ip-addr-v6 fd00::2/64",
            ] {
                assert!(
                    parse(&format!("{base} {flag}")).is_err(),
                    "{command}: {flag}"
                );
            }
        }
        assert!(parse("tap --world unix:/w --name a --vm qemu:/v --resolv-conf /r").is_err());
        assert!(parse("tun --world unix:/w --name a --listen 127.0.0.1:0").is_err());
    }

    #[test]
    fn tap_distinguishes_supplied_forwarded_and_disabled_leases() {
        let base = "tap --world unix:/w --name a --vm tap:vm0 --netns /n";
        let Parsed::Tap(t) = parse(base).unwrap() else {
            panic!()
        };
        assert_eq!(t.v4, Family::FromWorld);
        assert_eq!(t.v6, Family::FromWorld);
        let Parsed::Tap(t) = parse(&format!(
            "{base} --ip-addr 10.0.0.2/24 --dns 10.0.0.1 --no-ip-addr-v6"
        ))
        .unwrap() else {
            panic!()
        };
        let Family::Serve(lease) = t.v4 else { panic!() };
        assert_eq!(lease.gateway, None);
        assert_eq!(lease.dns, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(t.v6, Family::Off);
        assert!(parse(&format!("{base} --gateway 10.0.0.1")).is_err());
        assert!(parse(&format!("{base} --no-ip-addr --ip-addr 10.0.0.2/24")).is_err());
    }

    #[test]
    fn rejects_invalid_addresses_and_device_settings() {
        for extra in [
            "--mtu 1279",
            "--ip-addr 10.0.0.2/33",
            "--ip-addr-v6 fd00::2/129",
            "--down-link a/b",
            "--resolv-conf /r --no-resolv-conf",
            "--resolv-conf=",
            "--resolv-conf --no-resolv-conf",
        ] {
            assert!(
                parse(&format!("tun --world unix:/w --name a {extra}")).is_err(),
                "{extra}"
            );
        }
        for extra in [
            "--ip-addr 10.0.0.2/31",
            "--ip-addr 10.0.0.2/24 --gateway 10.1.0.1",
            "--ip-addr 10.0.0.2/24 --gateway 10.0.0.2",
            "--ip-addr-v6 fd00::2/65",
            "--netns /n",
        ] {
            assert!(
                parse(&format!(
                    "tap --world unix:/w --name a --vm qemu:/v {extra}"
                ))
                .is_err(),
                "{extra}"
            );
        }
    }

    #[test]
    fn each_command_has_help_and_required_fields() {
        assert!(matches!(parse("--help"), Ok(Parsed::Help(_))));
        for command in ["tun", "tap", "http-proxy", "socks5"] {
            assert!(matches!(
                parse(&format!("{command} --help")),
                Ok(Parsed::Help(_))
            ));
            assert!(parse(command).is_err());
        }
        assert!(parse("--world unix:/w --name a --type tun").is_err());
    }
}
