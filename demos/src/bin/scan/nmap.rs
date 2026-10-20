//! nmap's XML reports: hosts, ports with nmap's service names, compact
//! closed-port summaries, and OS matches.
use serde::Deserialize;
use std::net::Ipv4Addr;

/// One `nmaprun` element.
#[derive(Debug, Deserialize)]
#[serde(rename = "nmaprun")]
pub struct Report {
    /// The command line nmap recorded.
    #[serde(rename = "@args", default)]
    pub args: String,
    /// The start time, in Unix seconds.
    #[serde(rename = "@start", default)]
    pub start: u64,
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
    /// The end time, in Unix seconds.
    #[serde(rename = "@time", default)]
    pub time: u64,
    /// The elapsed time nmap reported, in seconds.
    #[serde(rename = "@elapsed", default)]
    pub elapsed: f64,
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
    /// Present when the scan ran OS detection. No `osmatch` means no match.
    pub os: Option<Os>,
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
    // nmap's reports from a KVM run of the demo, one per scripted step.
    pub const DISCOVERY: &str = include_str!("data/discovery.xml");
    pub const SERVICES: &str = include_str!("data/services.xml");
    pub const OS: &str = include_str!("data/os.xml");

    /// The OS report with every `osmatch` removed from one host, which is what
    /// nmap writes when it makes no match. The recorded run matched every host.
    pub fn os_without_match(host: &str) -> String {
        // The host's own element, not the hint nmap writes before the scan.
        let address = format!("<address addr=\"{host}\" addrtype=\"ipv4\"/>");
        let start = OS
            .match_indices("<host ")
            .map(|(at, _)| at)
            .find(|&at| {
                let end = at + OS[at..].find("</host>").unwrap();
                OS[at..end].contains(&address)
            })
            .unwrap();
        let open = start + OS[start..].find("<os>").unwrap();
        let close = open + OS[open..].find("</os>").unwrap();
        let kept: String = OS[open..close]
            .lines()
            .filter(|line| !line.starts_with("<osmatch") && !line.starts_with("<osclass"))
            .filter(|line| !line.starts_with("</osmatch>") && !line.starts_with("<cpe>"))
            .collect::<Vec<_>>()
            .join("\n");
        format!("{}{kept}\n{}", &OS[..open], &OS[close..])
    }

    #[test]
    fn reads_the_recorded_discovery_services_and_os_matches() {
        let discovery = parse(DISCOVERY).unwrap();
        assert_eq!(
            discovery.args,
            "nmap -sn -n -oX notes/office-1.xml 10.0.0.0/24"
        );
        assert_eq!(discovery.start, 1_792_462_616);
        assert_eq!(discovery.runstats.finished.time, 1_792_462_620);
        assert_eq!(discovery.runstats.finished.elapsed, 3.54);
        assert_eq!(discovery.hosts.len(), 5);
        assert_eq!(discovery.runstats.hosts.up, 5);
        assert!(
            discovery.hosts.iter().all(|h| h.status.state == "up"
                && h.status.reason == "echo-reply"
                && h.os.is_none())
        );
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
        assert_eq!(ssh.state.reason, "syn-ack");
        assert_eq!(ssh.service.name, "ssh");
        assert_eq!(ssh.service.product, "OpenSSH");
        assert_eq!(ssh.service.version, "9.6p1 Ubuntu 3ubuntu13.20");
        assert_eq!(ssh.service.extra_info, "Ubuntu Linux; protocol 2.0");
        assert_eq!(server.ports.extra[0].count, 1022);
        assert_eq!(server.ports.extra[0].reasons[0].reason, "reset");
        let mail = &report.hosts[1];
        assert_eq!(mail.ports.rows[0].service.product, "Postfix smtpd");
        assert!(report.hosts.iter().all(|h| h.os.is_none()));
        let report = parse(OS).unwrap();
        assert_eq!(report.hosts.len(), 5);
        let www = report.hosts[0].os.as_ref().unwrap();
        assert_eq!(www.matches.len(), 10);
        assert_eq!(
            www.matches[0].name,
            "OpenWrt 0.9 - 7.09 (Linux 2.4.30 - 2.4.34)"
        );
        assert_eq!(www.matches[0].accuracy, 91);
        let server = report.hosts[4].os.as_ref().unwrap();
        assert_eq!(server.matches.len(), 1);
        assert_eq!(server.matches[0].name, "Linux 5.0 - 5.5");
        assert_eq!(server.matches[0].accuracy, 100);
    }

    #[test]
    fn a_host_without_osmatch_has_os_detection_and_no_match() {
        let report = parse(&os_without_match("10.0.0.12")).unwrap();
        let files = report
            .hosts
            .iter()
            .find(|h| h.ipv4() == Some(Ipv4Addr::new(10, 0, 0, 12)))
            .unwrap();
        assert!(files.os.as_ref().unwrap().matches.is_empty());
        assert!(
            report
                .hosts
                .iter()
                .filter(|h| h.ipv4() != files.ipv4())
                .all(|h| !h.os.as_ref().unwrap().matches.is_empty())
        );
    }

    #[test]
    fn rejects_truncated_and_invalid_reports() {
        for text in ["", "<nmaprun><host>", "<nmaprun></nmaprun>"] {
            assert!(parse(text).is_err());
        }
        assert!(parse(&OS.replace("accuracy=\"100\"", "accuracy=\"many\"")).is_err());
    }
}
