//! The scripted office inventory and its checks.
use crate::{Error, guests, nmap};
use fictionet_demo::kit::{self, base64, ssh::quote};
use scan_world::{PortMap, PortState, Protocol};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, Instant};

pub const HOSTS: [u8; 5] = [10, 11, 12, 13, 50];
const OPEN: [&[u16]; 5] = [&[22, 80], &[25, 110, 143], &[21, 22], &[80, 631], &[22, 80]];

pub struct Step {
    pub title: &'static str,
    pub options: &'static str,
    pub target: &'static str,
    pub expected_exit: i32,
}
pub const STEPS: [Step; 3] = [
    Step {
        title: "Host discovery",
        options: "-sn -n",
        target: "10.0.0.0/24",
        expected_exit: 0,
    },
    Step {
        title: "SYN scan with service detection",
        options: "-sS -sV --version-light -n -p 1-1024 --max-rate 300",
        target: "10.0.0.0/24",
        expected_exit: 0,
    },
    Step {
        title: "OS detection",
        options: "-O --osscan-guess -n --max-os-tries 1",
        target: "10.0.0.10,11,12,13,50",
        expected_exit: 0,
    },
];

fn addr(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, last)
}

pub fn check(index: usize, exit: i32, report: &nmap::Report, map: &PortMap) -> Result<(), String> {
    if exit != STEPS[index].expected_exit {
        return Err(format!(
            "exit status {exit}, expected {}",
            STEPS[index].expected_exit
        ));
    }
    if report.runstats.finished.exit != "success" {
        return Err("nmap did not finish successfully".into());
    }
    let up: Vec<_> = report
        .hosts
        .iter()
        .filter(|h| h.status.state == "up")
        .collect();
    let addresses: BTreeSet<_> = up.iter().filter_map(|h| h.ipv4()).collect();
    if up.len() != 5 || report.runstats.hosts.up != 5 || addresses != HOSTS.map(addr).into() {
        return Err(format!(
            "expected exactly five office hosts up, got {addresses:?}"
        ));
    }
    if map.untracked != 0 {
        return Err(format!("port map missed {} probes", map.untracked));
    }
    for host in &up {
        let ip = host.ipv4().unwrap();
        if !map
            .rows
            .iter()
            .any(|r| r.host == ip && matches!(r.state, PortState::Open | PortState::Closed))
        {
            return Err(format!("{ip} has no answered port probe"));
        }
    }
    if index == 1 {
        let rows: BTreeMap<_, _> = map
            .rows
            .iter()
            .map(|r| ((r.host, r.protocol, r.port), r.state))
            .collect();
        for (last, open) in HOSTS.into_iter().zip(OPEN) {
            let ip = addr(last);
            for port in 1..=1024 {
                let expected = if open.contains(&port) {
                    PortState::Open
                } else {
                    PortState::Closed
                };
                if rows.get(&(ip, Protocol::Tcp, port)) != Some(&expected) {
                    return Err(format!(
                        "{ip}:{port}/tcp: expected {expected:?}, got {:?}",
                        rows.get(&(ip, Protocol::Tcp, port))
                    ));
                }
            }
            let host = up.iter().find(|h| h.ipv4() == Some(ip)).unwrap();
            let mut explicit = BTreeSet::new();
            for port in &host.ports.rows {
                if port.protocol != "tcp"
                    || !(1..=1024).contains(&port.port)
                    || !explicit.insert(port.port)
                {
                    return Err(format!("{ip}: unexpected or duplicate nmap port"));
                }
                let expected = if open.contains(&port.port) {
                    "open"
                } else {
                    "closed"
                };
                if port.state.state != expected
                    || (expected == "closed" && port.state.reason != "reset")
                {
                    return Err(format!(
                        "{ip}:{}: nmap reported {} ({})",
                        port.port, port.state.state, port.state.reason
                    ));
                }
            }
            if !open.iter().all(|p| explicit.contains(p)) {
                return Err(format!("{ip}: nmap omitted an open port"));
            }
            let mut count = explicit.len();
            for extra in &host.ports.extra {
                if extra.state != "closed"
                    || extra
                        .reasons
                        .iter()
                        .any(|r| !matches!(r.reason.as_str(), "resets" | "reset"))
                    || extra.reasons.iter().map(|r| r.count).sum::<usize>() != extra.count
                {
                    return Err(format!(
                        "{ip}: nmap's remaining ports are not closed by reset"
                    ));
                }
                count += extra.count;
            }
            if count != 1024 {
                return Err(format!(
                    "{ip}: nmap accounted for {count} ports, expected 1024"
                ));
            }
        }
        for (last, port, product, service) in [
            (50, 22, "OpenSSH", "ssh"),
            (50, 80, "nginx", "http"),
            (10, 80, "Apache httpd", "http"),
            (13, 631, "CUPS", "ipp"),
        ] {
            let found = up
                .iter()
                .find(|h| h.ipv4() == Some(addr(last)))
                .unwrap()
                .ports
                .rows
                .iter()
                .find(|p| p.port == port)
                .unwrap();
            if !found.service.product.contains(product) || found.service.name != service {
                return Err(format!(
                    "{}:{port}: expected {product} ({service}), nmap named {} ({})",
                    addr(last),
                    found.service.product,
                    found.service.name
                ));
            }
        }
    }
    if index == 2
        && up.iter().any(|h| {
            h.os.matches
                .iter()
                .any(|m| m.accuracy > 100 || m.name.is_empty())
        })
    {
        return Err("nmap returned an invalid OS match".into());
    }
    Ok(())
}

pub async fn run(run: &kit::Run, ports: &scan_world::Ports, out: &Path) -> Result<Duration, Error> {
    let start = Instant::now();
    let guest = run.guest(guests::WORKSTATION);
    for (index, step) in STEPS.iter().enumerate() {
        println!("{}: {}", index + 1, step.title);
        let file = format!("notes/office-{}.xml", index + 1);
        let command = format!("sudo nmap {} -oX {file} {}", step.options, step.target);
        println!("scripted agent: {command}");
        let send = format!(
            "printf '%s' {} | base64 -d > ~/notes/requests; cat ~/notes/results",
            quote(&base64(format!("{command}\n").as_bytes()))
        );
        let result = async {
            let output = tokio::time::timeout(
                Duration::from_secs(330),
                guest.ssh().run_bounded(&send, 4096),
            )
            .await??;
            if output.code != 0 {
                return Err(format!("runner transport: {}", output.stderr).into());
            }
            let exit: i32 = output.stdout.trim().parse()?;
            if exit != step.expected_exit {
                return Err(format!("exit status {exit}, expected {}", step.expected_exit).into());
            }
            let xml = tokio::time::timeout(
                Duration::from_secs(30),
                guest
                    .ssh()
                    .run_bounded(&format!("sudo cat ~/{file}"), 4 << 20),
            )
            .await??;
            if xml.code != 0 {
                return Err(format!("read nmap report: {}", xml.stderr).into());
            }
            let snapshot = ports.snapshot();
            std::fs::write(out.join(format!("office-{}.xml", index + 1)), &xml.stdout)?;
            std::fs::write(
                out.join(format!("office-{}-ports.json", index + 1)),
                serde_json::to_vec_pretty(&snapshot)?,
            )?;
            let report = nmap::parse(&xml.stdout)?;
            check(index, exit, &report, &snapshot).map_err(|e| -> Error { e.into() })?;
            print_report(index, &report);
            Ok::<(), Error>(())
        }
        .await;
        if let Err(error) = result {
            let output = tokio::time::timeout(
                Duration::from_secs(10),
                guest.ssh().run_bounded("cat ~/notes/output", 1 << 20),
            )
            .await;
            return Err(format!(
                "{} failed: {error}\nnmap output:\n{}\nguest console tail:\n{}",
                step.title,
                output.map_or_else(
                    |e| e.to_string(),
                    |o| o.map_or_else(|e| e.to_string(), |o| o.stdout)
                ),
                guest.vm().console_tail()
            )
            .into());
        }
        println!("[pass] {}", step.title);
    }
    Ok(start.elapsed())
}

fn print_report(index: usize, report: &nmap::Report) {
    for host in report.hosts.iter().filter(|h| h.status.state == "up") {
        let ip = host.ipv4().unwrap();
        match index {
            0 => println!("nmap: {ip} up"),
            1 => {
                for port in host.ports.rows.iter().filter(|p| p.state.state == "open") {
                    println!(
                        "nmap: {ip}:{}/{} open {} {} {} {}",
                        port.port,
                        port.protocol,
                        port.service.name,
                        port.service.product,
                        port.service.version,
                        port.service.extra_info
                    );
                }
            }
            _ => {
                if host.os.matches.is_empty() {
                    println!("nmap OS: {ip}: no match");
                } else {
                    for guess in &host.os.matches {
                        println!("nmap OS: {ip}: {} ({}%)", guess.name, guess.accuracy);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nmap::tests::{DISCOVERY, OS, SERVICES};

    fn map() -> PortMap {
        let mut map: PortMap = serde_json::from_str(r#"{"revision":10240,"at_ms":1000,"max_rows":16384,"untracked":0,"machines":[],"rows":[]}"#).unwrap();
        for host in nmap::parse(SERVICES).unwrap().hosts {
            for port in 1..=1024 {
                let open = host
                    .ports
                    .rows
                    .iter()
                    .any(|p| p.port == port && p.state.state == "open");
                map.rows.push(scan_world::PortRow {
                    host: host.ipv4().unwrap(),
                    port,
                    protocol: Protocol::Tcp,
                    state: if open {
                        PortState::Open
                    } else {
                        PortState::Closed
                    },
                    first_probe_ms: 10,
                    last_probe_ms: 20,
                    probes: 1,
                    revision: 2,
                });
            }
        }
        map
    }

    #[test]
    fn recorded_discovery_requires_an_answer_for_each_host() {
        let report = nmap::parse(include_str!("discovery.xml")).unwrap();
        let mut map = map();
        map.rows = HOSTS
            .map(|last| scan_world::PortRow {
                host: addr(last),
                port: 0,
                protocol: Protocol::Icmp,
                state: PortState::Open,
                first_probe_ms: 10,
                last_probe_ms: 10,
                probes: 1,
                revision: 2,
            })
            .into();
        check(0, 0, &report, &map).unwrap();
        for i in 0..map.rows.len() {
            let mut missing = map.clone();
            missing.rows.remove(i);
            assert_eq!(
                check(0, 0, &report, &missing),
                Err(format!("{} has no answered port probe", map.rows[i].host))
            );
            for state in [PortState::Unanswered, PortState::Unreachable] {
                let mut unanswered = map.clone();
                unanswered.rows[i].state = state;
                assert!(check(0, 0, &report, &unanswered).is_err());
            }
        }
    }

    #[test]
    fn accepts_all_three_steps_and_no_os_match() {
        for (index, xml) in [DISCOVERY, SERVICES, OS].into_iter().enumerate() {
            check(index, 0, &nmap::parse(xml).unwrap(), &map()).unwrap();
        }
    }

    #[test]
    fn rejects_failed_exit_incomplete_discovery_and_missing_answers() {
        for (index, xml) in [DISCOVERY, SERVICES, OS].into_iter().enumerate() {
            let mut report = nmap::parse(xml).unwrap();
            assert!(check(index, 1, &report, &map()).is_err());
            report.runstats.finished.exit = "error".into();
            assert!(check(index, 0, &report, &map()).is_err());
            report.runstats.finished.exit = "success".into();
            report.hosts.pop();
            assert!(check(index, 0, &report, &map()).is_err());
        }
        let report = nmap::parse(DISCOVERY).unwrap();
        let mut missing = map();
        missing.rows.retain(|r| r.host != addr(50));
        assert!(check(0, 0, &report, &missing).is_err());
    }

    #[test]
    fn rejects_wrong_services_filtered_ports_and_missing_map_rows() {
        for (from, to) in [
            ("OpenSSH", "unknown"),
            ("nginx", "Apache"),
            ("Apache httpd", "unknown"),
            ("CUPS", "unknown"),
            ("state=\"closed\"", "state=\"filtered\""),
            ("reason=\"resets\"", "reason=\"no-responses\""),
            ("count=\"1022\"", "count=\"1021\""),
        ] {
            assert!(
                check(
                    1,
                    0,
                    &nmap::parse(&SERVICES.replace(from, to)).unwrap(),
                    &map()
                )
                .is_err(),
                "{from}"
            );
        }
        let report = nmap::parse(SERVICES).unwrap();
        for state in [
            PortState::Unanswered,
            PortState::Unreachable,
            PortState::Open,
        ] {
            let mut bad = map();
            bad.rows[0].state = state;
            assert!(check(1, 0, &report, &bad).is_err());
        }
        let mut bad = map();
        bad.rows.retain(|r| !(r.host == addr(50) && r.port == 22));
        assert!(check(1, 0, &report, &bad).is_err());
        let mut bad = map();
        bad.rows
            .iter_mut()
            .find(|r| r.host == addr(50) && r.port == 80)
            .unwrap()
            .state = PortState::Closed;
        assert!(check(1, 0, &report, &bad).is_err());
    }

    #[test]
    fn rejects_invalid_os_accuracy_without_requiring_a_guess() {
        assert!(
            check(
                2,
                0,
                &nmap::parse(&OS.replace("accuracy=\"96\"", "accuracy=\"101\"")).unwrap(),
                &map()
            )
            .is_err()
        );
        let mut report = nmap::parse(OS).unwrap();
        for host in &mut report.hosts {
            host.os.matches.clear();
        }
        check(2, 0, &report, &map()).unwrap();
    }
}
