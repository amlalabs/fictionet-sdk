//! nmap's XML reports, including compact closed-port summaries.
use serde::Deserialize;
use std::net::Ipv4Addr;

#[derive(Debug, Deserialize)]
#[serde(rename = "nmaprun")]
pub struct Report {
    #[serde(rename = "host", default)]
    pub hosts: Vec<Host>,
    pub runstats: RunStats,
}
#[derive(Debug, Deserialize)]
pub struct RunStats {
    pub finished: Finished,
    pub hosts: Counts,
}
#[derive(Debug, Deserialize)]
pub struct Finished {
    #[serde(rename = "@exit")]
    pub exit: String,
}
#[derive(Debug, Deserialize)]
pub struct Counts {
    #[serde(rename = "@up")]
    pub up: usize,
}
#[derive(Debug, Deserialize)]
pub struct Host {
    pub status: Status,
    #[serde(rename = "address", default)]
    pub addresses: Vec<Address>,
    #[serde(default)]
    pub ports: Ports,
    #[serde(default)]
    pub os: Os,
}
impl Host {
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        self.addresses
            .iter()
            .find(|a| a.kind == "ipv4")
            .and_then(|a| a.addr.parse().ok())
    }
}
#[derive(Debug, Deserialize)]
pub struct Address {
    #[serde(rename = "@addr")]
    pub addr: String,
    #[serde(rename = "@addrtype")]
    pub kind: String,
}
#[derive(Debug, Deserialize)]
pub struct Status {
    #[serde(rename = "@state")]
    pub state: String,
    #[serde(rename = "@reason", default)]
    pub reason: String,
}
#[derive(Debug, Default, Deserialize)]
pub struct Ports {
    #[serde(rename = "port", default)]
    pub rows: Vec<Port>,
    #[serde(rename = "extraports", default)]
    pub extra: Vec<Extra>,
}
#[derive(Debug, Deserialize)]
pub struct Port {
    #[serde(rename = "@protocol")]
    pub protocol: String,
    #[serde(rename = "@portid")]
    pub port: u16,
    pub state: Status,
    #[serde(default)]
    pub service: Service,
}
#[derive(Debug, Default, Deserialize)]
pub struct Service {
    #[serde(rename = "@name", default)]
    pub name: String,
    #[serde(rename = "@product", default)]
    pub product: String,
    #[serde(rename = "@version", default)]
    pub version: String,
    #[serde(rename = "@extrainfo", default)]
    pub extra_info: String,
}
#[derive(Debug, Deserialize)]
pub struct Extra {
    #[serde(rename = "@state")]
    pub state: String,
    #[serde(rename = "@count")]
    pub count: usize,
    #[serde(rename = "extrareasons", default)]
    pub reasons: Vec<Reason>,
}
#[derive(Debug, Deserialize)]
pub struct Reason {
    #[serde(rename = "@reason")]
    pub reason: String,
    #[serde(rename = "@count")]
    pub count: usize,
}
#[derive(Debug, Default, Deserialize)]
pub struct Os {
    #[serde(rename = "osmatch", default)]
    pub matches: Vec<OsMatch>,
}
#[derive(Debug, Deserialize)]
pub struct OsMatch {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@accuracy")]
    pub accuracy: u8,
}

pub fn parse(xml: &str) -> Result<Report, quick_xml::DeError> {
    quick_xml::de::from_str(xml)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    // These XML files are examples until recordings from a KVM run replace them.
    pub const DISCOVERY: &str = include_str!("data/discovery.xml");
    pub const SERVICES: &str = include_str!("data/services.xml");
    pub const OS: &str = include_str!("data/os.xml");

    #[test]
    fn reads_discovery_services_and_os_matches() {
        let discovery = parse(DISCOVERY).unwrap();
        assert_eq!(discovery.hosts.len(), 5);
        assert_eq!(discovery.runstats.hosts.up, 5);
        assert!(discovery.hosts.iter().all(|h| h.status.state == "up"));
        let report = parse(SERVICES).unwrap();
        let server = report
            .hosts
            .iter()
            .find(|h| h.ipv4() == Some(scan_world::SERVER_ADDR))
            .unwrap();
        let ssh = &server.ports.rows[0];
        assert_eq!(ssh.port, 22);
        assert_eq!(ssh.protocol, "tcp");
        assert_eq!(ssh.state.state, "open");
        assert_eq!(ssh.service.name, "ssh");
        assert_eq!(ssh.service.product, "OpenSSH");
        assert_eq!(ssh.service.version, "9.6p1");
        assert_eq!(ssh.service.extra_info, "Ubuntu Linux; protocol 2.0");
        assert_eq!(server.ports.extra[0].count, 1022);
        assert_eq!(server.ports.extra[0].reasons[0].reason, "resets");
        let report = parse(OS).unwrap();
        assert_eq!(report.hosts[0].os.matches[0].name, "Linux 5.X & 6.X");
        assert_eq!(report.hosts[0].os.matches[0].accuracy, 96);
        assert!(report.hosts[1].os.matches.is_empty());
    }

    #[test]
    fn rejects_truncated_and_invalid_reports() {
        for text in ["", "<nmaprun><host>", "<nmaprun></nmaprun>"] {
            assert!(parse(text).is_err());
        }
        assert!(parse(&OS.replace("accuracy=\"96\"", "accuracy=\"many\"")).is_err());
    }
}
