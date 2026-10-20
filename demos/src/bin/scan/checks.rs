//! The gate's checks of the page's own API, read with the bearer as a
//! browser reads it: the port map and banners, nmap's reports, the story
//! and the discovery moment.
use crate::Error;
use crate::page::{self, Reports, StepState, Story};
use crate::story::{HOSTS, addr};
use fictionet_demo::kit::client::PageClient;
use fictionet_observe::page::Snapshot;
use scan_world::{PortMap, PortState, Protocol, SERVER_ADDR};
use serde::de::DeserializeOwned;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

/// The three topics as the page serves them.
pub struct Topics {
    pub ports: PortMap,
    pub reports: Reports,
    pub story: Story,
}

/// Reads the page's topics and the moment's events through its API.
pub async fn read(client: &PageClient) -> Result<(Topics, serde_json::Value), Error> {
    let topics = Topics {
        ports: topic(client, page::PORTS).await?,
        reports: topic(client, page::SERVICES).await?,
        story: topic(client, page::OFFICE).await?,
    };
    let reply = client
        .request(
            "GET",
            "/api/event-table/all-five-hosts-answered",
            None,
            true,
        )
        .await?;
    if reply.status != 200 {
        return Err(format!("moment events: {}", reply.status_line).into());
    }
    Ok((topics, serde_json::from_slice(&reply.body)?))
}

/// Reads one state topic by its panel title.
async fn topic<T: DeserializeOwned>(client: &PageClient, title: &str) -> Result<T, Error> {
    let path = format!("/api/state/{}", title.to_ascii_lowercase());
    let reply = client.request("GET", &path, None, true).await?;
    if reply.status != 200 {
        return Err(format!("{path}: {}", reply.status_line).into());
    }
    let snapshot: Snapshot<T> = serde_json::from_slice(&reply.body)?;
    if snapshot.status.too_large {
        return Err(format!("{path}: a publication exceeded its size limit").into());
    }
    snapshot
        .value
        .ok_or_else(|| format!("{path}: nothing published yet").into())
}

/// Checks what the page shows after the story. Returns a one-line summary.
pub fn check(topics: &Topics, moment: &serde_json::Value) -> Result<String, String> {
    let map = &topics.ports;
    let five: BTreeSet<Ipv4Addr> = HOSTS.map(addr).into();
    let answered = |host: Ipv4Addr| {
        map.rows
            .iter()
            .any(|r| r.host == host && matches!(r.state, PortState::Open | PortState::Closed))
    };
    if let Some(host) = five.iter().find(|h| !answered(**h)) {
        return Err(format!("port map: {host} has no answered row"));
    }
    let others: BTreeSet<Ipv4Addr> = map
        .rows
        .iter()
        .map(|r| r.host)
        .filter(|h| !five.contains(h))
        .collect();
    if others.is_empty() {
        return Err("port map: no probes to other addresses".into());
    }
    for host in &others {
        let rows = || map.rows.iter().filter(|r| r.host == *host);
        if answered(*host) || !rows().any(|r| r.state == PortState::Unreachable) {
            return Err(format!("port map: {host} is not only unreachable"));
        }
    }
    for port in [22, 80] {
        if !map.rows.iter().any(|r| {
            (r.host, r.protocol, r.port, r.state)
                == (SERVER_ADDR, Protocol::Tcp, port, PortState::Open)
        }) {
            return Err(format!("port map: {SERVER_ADDR}:{port} is not open"));
        }
    }
    let banner = |port| {
        map.banners
            .iter()
            .find(|b| b.host == SERVER_ADDR && b.port == port)
            .ok_or(format!("port map: no banner for {SERVER_ADDR}:{port}"))
    };
    let ssh = banner(22)?;
    if !ssh.text.starts_with("SSH-2.0-OpenSSH_") {
        return Err(format!("{SERVER_ADDR}:22 banner is {:?}", ssh.text));
    }
    let web = banner(80)?;
    if !web
        .server
        .as_deref()
        .is_some_and(|s| s.starts_with("nginx"))
    {
        return Err(format!("{SERVER_ADDR}:80 server is {:?}", web.server));
    }
    let steps = &topics.reports.steps;
    if steps.len() != 3 {
        return Err(format!("nmap reports: {} steps, expected 3", steps.len()));
    }
    for step in steps {
        let up: BTreeSet<_> = step
            .hosts
            .iter()
            .filter(|h| h.state == "up")
            .map(|h| h.addr)
            .collect();
        if up != five || step.up != 5 {
            return Err(format!("nmap reports: {} found {up:?} up", step.title));
        }
    }
    if let Some(host) = steps[2].hosts.iter().find(|h| h.os.is_none()) {
        return Err(format!("nmap reports: no OS entry for {}", host.addr));
    }
    if let Some(step) = topics
        .story
        .steps
        .iter()
        .find(|s| s.state != StepState::Done || s.exit != Some(0))
    {
        return Err(format!("story: {} is {:?}", step.title, step.state));
    }
    let rows = moment["rows"].as_array().map_or(&[][..], Vec::as_slice);
    let [event] = rows else {
        return Err(format!("moment: {} events, expected one", rows.len()));
    };
    let hosts: BTreeSet<Ipv4Addr> = event["fields"]["hosts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|h| h.as_str()?.parse().ok())
        .collect();
    if hosts != five {
        return Err(format!("moment: hosts {hosts:?}"));
    }
    let no_match = steps[2]
        .hosts
        .iter()
        .filter(|h| h.os.as_ref().is_some_and(Vec::is_empty))
        .count();
    Ok(format!(
        "five hosts answered, {} other addresses unreachable, {} banners \
         ({SERVER_ADDR}:22 {:?}, :80 {:?}), three nmap reports with {} OS matches \
         and {no_match} with no match, every step done, moment at {:.1} s",
        others.len(),
        map.banners.len(),
        ssh.text,
        web.server.as_deref().unwrap_or_default(),
        5 - no_match,
        event["at"].as_f64().unwrap_or_default(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::tests::{recorded_discovery, recorded_reports};
    use scan_world::{Banner, PortRow};

    fn topics() -> (Topics, serde_json::Value) {
        let mut ports = recorded_discovery();
        for (port, text, server) in [
            (22, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20", None),
            (80, "HTTP/1.1 200 OK", Some("nginx/1.24.0 (Ubuntu)")),
        ] {
            ports.rows.push(PortRow {
                host: SERVER_ADDR,
                port,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                first_probe_ms: 50_000,
                last_probe_ms: 60_000,
                probes: 3,
                revision: 2000,
            });
            ports.banners.push(Banner {
                host: SERVER_ADDR,
                port,
                text: text.into(),
                server: server.map(Into::into),
                at_ms: 60_000,
                revision: 2001,
            });
        }
        let mut story = Story::scripted();
        for step in &mut story.steps {
            step.state = StepState::Done;
            step.exit = Some(0);
        }
        let moment = serde_json::json!({"rows": [{"at": 40.2, "fields": {"hosts":
            ["10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.50"]}}]});
        (
            Topics {
                ports,
                reports: recorded_reports(),
                story,
            },
            moment,
        )
    }

    #[test]
    fn recorded_topics_pass() {
        let (topics, moment) = topics();
        let summary = check(&topics, &moment).unwrap();
        assert!(summary.starts_with("five hosts answered, 251 other addresses unreachable"));
        assert!(summary.contains("5 OS matches and 0 with no match"));
    }

    #[test]
    fn each_missing_piece_fails() {
        let (good, moment) = topics();
        let fails = |change: &dyn Fn(&mut Topics, &mut serde_json::Value)| {
            let mut topics = Topics {
                ports: good.ports.clone(),
                reports: good.reports.clone(),
                story: good.story.clone(),
            };
            let mut moment = moment.clone();
            change(&mut topics, &mut moment);
            check(&topics, &moment).unwrap_err()
        };
        assert_eq!(
            fails(&|t, _| t.ports.rows.retain(|r| r.host != addr(12))),
            "port map: 10.0.0.12 has no answered row"
        );
        assert!(
            fails(&|t, _| t.ports.rows.retain(|r| HOSTS.map(addr).contains(&r.host)))
                .contains("no probes to other addresses")
        );
        assert!(
            fails(&|t, _| t.ports.rows[0].state = PortState::Closed)
                .contains("is not only unreachable")
        );
        assert!(fails(&|t, _| t.ports.rows.retain(|r| r.port != 80)).contains(":80 is not open"));
        assert!(
            fails(&|t, _| {
                t.ports.banners.pop();
            })
            .contains("no banner for 10.0.0.50:80")
        );
        assert!(
            fails(&|t, _| t.ports.banners[0].text = "SSH-2.0-dropbear".into())
                .contains("22 banner")
        );
        assert!(fails(&|t, _| t.ports.banners[1].server = None).contains("80 server"));
        assert!(
            fails(&|t, _| {
                t.reports.steps.pop();
            })
            .contains("2 steps")
        );
        assert!(
            fails(&|t, _| {
                t.reports.steps[1].hosts.pop();
            })
            .contains("found")
        );
        assert!(fails(&|t, _| t.reports.steps[2].hosts[3].os = None).contains("no OS entry"));
        assert!(fails(&|t, _| t.story.steps[2].state = StepState::Failed).contains("story"));
        assert!(fails(&|_, m| *m = serde_json::json!({"rows": []})).contains("0 events"));
        assert!(
            fails(&|_, m| m["rows"][0]["fields"]["hosts"] = serde_json::json!([]))
                .contains("moment: hosts")
        );
        let (mut topics, moment) = topics();
        topics.reports.steps[2].hosts[3].os = Some(vec![]);
        assert!(
            check(&topics, &moment)
                .unwrap()
                .contains("4 OS matches and 1 with no match")
        );
    }
}
