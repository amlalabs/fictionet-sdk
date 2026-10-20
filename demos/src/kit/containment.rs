//! Read-only startup probes over the guest's admin SSH session.
//! No probe installs packages or writes files on the guest.
//!
//! A network probe is contained when Left the box shows the world's own
//! answer to it, added while the probe ran: a world site or service served
//! it, the world refused it, the world had no route for it, or the world's
//! DNS had no such name. Worlds built on `Net` report all of these. A world
//! that answers some packets itself before they reach its `Net` reports an
//! address where nothing answers as `path.unreachable`, naming the sandbox
//! in a `sandbox` field, as Border's path does for addresses with no
//! machine. A guest with no route for the IPv6 probe's address is contained
//! for IPv6.

use std::time::Duration;

use fictionet_observe::DashboardHandle;
use fictionet_observe::egress::{Destination, EgressSnapshot, Outcome};
use fictionet_observe::page::{Containment, ProbeOutcome, ProbeResult, ProxySetting};

use super::ssh::{Output, Session};

/// One bounded command and the destination its observations must name.
pub struct Probe {
    /// Panel label.
    pub name: &'static str,
    /// Command sent to SSH without creating a file.
    pub command: &'static str,
    /// Address and port, hostname, or configuration source.
    pub destination: &'static str,
    /// Maximum duration, including opening the SSH channel.
    pub timeout: Duration,
    kind: Kind,
}
#[derive(Clone, Copy)]
enum Kind {
    Dns,
    Http,
    /// An HTTP probe that first asks the guest for a route to its address.
    Ipv6,
    Routes,
    Proxy,
}

/// What the IPv6 probe prints when the guest has no route to its address.
const NO_IPV6_ROUTE: &str = "No IPv6 route";
/// What a probe says when its guest lacks the tool or setting it reads.
const MISSING_TOOL: &str = "Required tool or configuration is missing from this guest image.";
/// What a proxy probe says when it finds no proxy setting.
const NO_PROXY: &str = "No proxy settings set";

/// Commands suitable for an unmodified Ubuntu cloud image. Missing tools are
/// reported as results; they are never installed by a probe.
pub const PROBES: &[Probe] = &[
    Probe {
        name: "Public DNS at 8.8.8.8",
        command: "dig +time=2 +tries=1 @8.8.8.8 example.com",
        destination: "8.8.8.8:53",
        timeout: Duration::from_secs(10),
        kind: Kind::Dns,
    },
    Probe {
        name: "Public DNS at 1.1.1.1",
        command: "dig +time=2 +tries=1 @1.1.1.1 example.com",
        destination: "1.1.1.1:53",
        timeout: Duration::from_secs(10),
        kind: Kind::Dns,
    },
    Probe {
        name: "Raw public IP",
        command: "curl --noproxy '*' --max-time 5 -sS -o /dev/null -w 'HTTP %{http_code}\\n' https://1.1.1.1",
        destination: "1.1.1.1:443",
        timeout: Duration::from_secs(10),
        kind: Kind::Http,
    },
    Probe {
        name: "Public IPv6",
        command: "ip -6 route get 2606:4700:4700::1111 >/dev/null 2>&1 || echo 'No IPv6 route'; curl --noproxy '*' --max-time 5 -6 -sS -o /dev/null -w 'HTTP %{http_code}\\n' 'https://[2606:4700:4700::1111]'",
        destination: "[2606:4700:4700::1111]:443",
        timeout: Duration::from_secs(10),
        kind: Kind::Ipv6,
    },
    Probe {
        name: "Direct public site",
        command: "curl --noproxy '*' --max-time 5 -sS -o /dev/null -w 'HTTP %{http_code}\\n' https://www.google.com",
        destination: "www.google.com",
        timeout: Duration::from_secs(10),
        kind: Kind::Http,
    },
    Probe {
        name: "IPv6 routes",
        command: "ip -6 route",
        destination: "IPv6 routing table",
        timeout: Duration::from_secs(10),
        kind: Kind::Routes,
    },
    Probe {
        name: "Proxy environment",
        command: "env | grep -iE '^(http_proxy|https_proxy|all_proxy|no_proxy)='; test $? -le 1",
        destination: "environment",
        timeout: Duration::from_secs(10),
        kind: Kind::Proxy,
    },
    Probe {
        name: "System proxy environment",
        command: "grep -iE '^(http_proxy|https_proxy|all_proxy|no_proxy)=' /etc/environment; test $? -le 1",
        destination: "/etc/environment",
        timeout: Duration::from_secs(10),
        kind: Kind::Proxy,
    },
    Probe {
        name: "Apt proxy settings",
        command: "apt-config dump | grep -i proxy; test $? -le 1",
        destination: "apt configuration",
        timeout: Duration::from_secs(10),
        kind: Kind::Proxy,
    },
];

/// Requires every declared probe exactly once for each guest.
pub fn complete(probes: &Containment, guests: &[&str]) -> bool {
    probes.probes.len() == guests.len() * PROBES.len()
        && guests.iter().all(|guest| {
            PROBES.iter().all(|probe| {
                probes
                    .probes
                    .iter()
                    .filter(|result| {
                        result.guest == *guest
                            && result.name == probe.name
                            && result.command == probe.command
                            && result.destination == probe.destination
                    })
                    .count()
                    == 1
            })
        })
}

/// Only configuration probes may report facts without a containment result.
pub fn passed(probes: &Containment, guests: &[&str]) -> bool {
    !guests.is_empty()
        && complete(probes, guests)
        && probes.probes.iter().all(|result| {
            PROBES
                .iter()
                .find(|probe| probe.name == result.name)
                .is_some_and(|probe| {
                    result.outcome
                        == if matches!(probe.kind, Kind::Routes | Kind::Proxy) {
                            ProbeOutcome::Fact
                        } else {
                            ProbeOutcome::Contained
                        }
                })
        })
}

/// Runs each probe once and compares only observations added during that probe.
/// SSH errors and deadlines become results.
pub async fn run(session: &Session, guest: &str, dashboard: &DashboardHandle) -> Containment {
    let mut results = Containment::default();
    for probe in PROBES {
        let before = dashboard.egress();
        let output =
            tokio::time::timeout(probe.timeout, session.run_bounded(probe.command, 16 << 10)).await;
        let after = dashboard.egress();
        let result = match output {
            Ok(Ok(output)) => parse(probe, guest, &output, &before, &after),
            Ok(Err(error)) => result(probe, guest, error.to_string(), error.to_string()),
            Err(_) => parse(
                probe,
                guest,
                &Output {
                    code: 124,
                    stdout: String::new(),
                    stderr: "Probe timed out".into(),
                },
                &before,
                &after,
            ),
        };
        results.probes.push(result);
    }
    results
}

/// A result not determined yet: what the guest got in full and in one line.
fn result(probe: &Probe, guest: &str, guest_result: String, summary: String) -> ProbeResult {
    ProbeResult {
        guest: guest.into(),
        name: probe.name.into(),
        command: probe.command.into(),
        destination: probe.destination.into(),
        outcome: ProbeOutcome::Unknown,
        summary,
        guest_result,
        world_answer: "No matching world observation".into(),
        proxies: vec![],
    }
}

fn same(a: &Destination, b: &Destination) -> bool {
    a.sandbox == b.sandbox
        && a.address == b.address
        && a.transport == b.transport
        && a.outcome == b.outcome
        && a.by == b.by
}

fn matches(probe: &Probe, row: &Destination) -> bool {
    row.address == probe.destination
        || row.name.as_deref() == Some(probe.destination)
        || probe
            .destination
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|socket| {
                row.address
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip == socket.ip())
            })
}

/// Parses a recorded guest output against before and after projection snapshots.
/// A successful guest response requires a matching answered request, not merely
/// a connection or an old row. A TLS handshake the guest aborted because it did
/// not trust the certificate (curl's exit 60) is answered by the world's refusal
/// of a new connection. Loss prevents a missing observation from proving that a
/// probe escaped. The result's summary is the line that says what the guest
/// got: the status line of an answer, curl's error or a timeout, else the
/// exit status.
pub fn parse(
    probe: &Probe,
    guest: &str,
    output: &Output,
    before: &EgressSnapshot,
    after: &EgressSnapshot,
) -> ProbeResult {
    let text = format!("{}{}", output.stdout, output.stderr);
    let exit = format!("Exit {}", output.code);
    // The status line the probes print when a server answered, `HTTP 200`.
    // curl prints `HTTP 000` when it got no answer.
    let http_line = output.stdout.lines().find(|line| {
        line.strip_prefix("HTTP ").is_some_and(|code| {
            code.parse::<u16>()
                .is_ok_and(|code| (100..600).contains(&code))
        })
    });
    let summary = http_line
        .or_else(|| {
            text.lines().map(str::trim).find(|line| {
                line.starts_with("curl:")
                    || line.contains("timed out")
                    || line.contains("no servers could be reached")
            })
        })
        .map_or_else(
            || exit.clone(),
            |line| line.trim_start_matches([';', ' ']).into(),
        );
    let mut result = result(probe, guest, format!("{exit}\n{text}"), summary);
    if output.code == 127
        || text.contains("not found")
        || text.contains("No such file or directory")
    {
        result.outcome = ProbeOutcome::MissingTool;
        result.guest_result = format!("{MISSING_TOOL}\n{text}");
        result.summary = MISSING_TOOL.into();
        return result;
    }
    if matches!(probe.kind, Kind::Routes | Kind::Proxy) {
        if output.code != 0 {
            if output.code == 124 {
                result.outcome = ProbeOutcome::TimedOut;
            }
            return result;
        }
        result.outcome = ProbeOutcome::Fact;
        result.world_answer = "Configuration only".into();
        if matches!(probe.kind, Kind::Proxy) {
            result.proxies = proxies(&output.stdout);
            if result.proxies.is_empty() {
                result.guest_result = NO_PROXY.into();
                result.summary = NO_PROXY.into();
            }
        }
        return result;
    }
    let http_answer = http_line.is_some();
    // Curl's exit 60: a server showed a certificate the guest does not trust.
    let tls_answer = output.code == 60 && !http_answer;
    let answered = match probe.kind {
        Kind::Dns => text.contains("status:") && text.contains("SERVER:"),
        Kind::Http | Kind::Ipv6 => http_answer || tls_answer,
        _ => false,
    };
    let no_route =
        matches!(probe.kind, Kind::Ipv6) && output.stdout.lines().any(|line| line == NO_IPV6_ROUTE);
    let rows: Vec<_> = after
        .destinations
        .iter()
        .filter(|row| row.sandbox == guest && matches(probe, row))
        .filter_map(|row| {
            let old = before.destinations.iter().find(|old| same(old, row));
            let requests = row
                .requests
                .saturating_sub(old.map_or(0, |old| old.requests));
            let unanswered = row
                .unanswered
                .saturating_sub(old.map_or(0, |old| old.unanswered));
            let connections = row
                .connections
                .saturating_sub(old.map_or(0, |old| old.connections));
            let changed =
                requests > 0 || connections > 0 || row.packets > old.map_or(0, |old| old.packets);
            changed.then_some((row, requests.saturating_sub(unanswered), connections))
        })
        .collect();
    result.world_answer = rows
        .iter()
        .map(|(row, _, _)| match row.outcome {
            Outcome::Forwarded => format!("forwarded by the world to {}", row.by),
            Outcome::Served => format!("answered by {}", row.by),
            Outcome::Refused => format!("refused: {}", row.by),
            Outcome::NoRoute => format!("no route: {}", row.by),
        })
        .collect::<Vec<_>>()
        .join("; ");
    let dns_refused = after.lookups.iter().any(|lookup| {
        lookup.sandbox == guest
            && lookup.name == probe.destination
            && matches!(
                lookup.answer.as_str(),
                "no such name" | "no A record" | "no AAAA record"
            )
            && lookup.count
                > before
                    .lookups
                    .iter()
                    .find(|old| {
                        old.sandbox == lookup.sandbox
                            && old.name == lookup.name
                            && old.answer == lookup.answer
                    })
                    .map_or(0, |old| old.count)
    });
    if dns_refused && rows.is_empty() {
        result.world_answer = "the world's DNS refused the name".into();
    }
    let accounted = rows.iter().any(|(row, answers, connections)| {
        matches!(
            row.outcome,
            Outcome::Served | Outcome::Forwarded | Outcome::Refused
        ) && *answers > 0
            || tls_answer && row.outcome == Outcome::Refused && *connections > 0
    });
    let forwarded = rows
        .iter()
        .any(|(row, _, _)| row.outcome == Outcome::Forwarded);
    result.outcome = if answered && !accounted {
        if after.complete() {
            ProbeOutcome::NotContained
        } else {
            ProbeOutcome::Unknown
        }
    } else if forwarded {
        ProbeOutcome::Forwarded
    } else if !rows.is_empty() || dns_refused || no_route {
        ProbeOutcome::Contained
    } else if output.code == 124 || output.code == 28 || text.contains("timed out") {
        ProbeOutcome::TimedOut
    } else {
        ProbeOutcome::Unknown
    };
    if no_route && rows.is_empty() && result.outcome == ProbeOutcome::Contained {
        result.world_answer = "no route: the guest has no IPv6 route".into();
    }
    if result.world_answer.is_empty() {
        result.world_answer = if after.complete() {
            "No matching world observation"
        } else {
            "World observations are incomplete"
        }
        .into();
    }
    result
}

fn proxies(text: &str) -> Vec<ProxySetting> {
    text.lines()
        .filter_map(|line| {
            let (name, value) = line.split_once('=').or_else(|| line.split_once(' '))?;
            let destination = value.trim().trim_end_matches(';').trim_matches(['\'', '"']);
            if destination.is_empty() {
                return None;
            }
            Some(ProxySetting {
                name: name.into(),
                destination: destination.into(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::events::{ConnInfo, Event, Observation, Observer, Sandbox, Stamp, Stream};
    use fictionet::time::Instant;
    use fictionet_observe::egress::Egress;
    use std::sync::Arc;

    fn output(code: i32, text: &str) -> Output {
        Output {
            code,
            stdout: text.into(),
            stderr: String::new(),
        }
    }

    fn observation(probe: &Probe, outcome: &str) -> EgressSnapshot {
        let egress = Egress::default();
        let local = probe
            .destination
            .parse()
            .unwrap_or_else(|_| "203.0.113.1:443".parse().unwrap());
        let conn = ConnInfo::new(1, local, "10.0.2.15:40000".parse().unwrap()).from_sandbox(Some(
            Sandbox {
                id: 1,
                name: Arc::from("workstation"),
                addr: Some("10.0.2.15".parse().unwrap()),
                addr_v6: None,
            },
        ));
        if probe.destination.parse::<std::net::SocketAddr>().is_err() {
            let query = Event::new("dns", "query")
                .conn(&conn)
                .field("name", probe.destination)
                .field("answer", "addr")
                .field("addr", local.ip().to_string());
            egress.observe(
                Stamp {
                    stream: Stream::Events,
                    seq: 1,
                    at: Instant::ZERO,
                },
                Observation::Event(&query),
            );
        }
        let event = match outcome {
            "no_route" => Event::new("net", "blocked")
                .field("why", "NoRoute")
                .field("dst", local.ip().to_string())
                .field("dst_port", u32::from(local.port()))
                .field("protocol", 6u32),
            "refused" => Event::new("http", "request")
                .field("host", probe.destination)
                .field("answer", "misdirected"),
            "tls_alert" => Event::new("tls", "handshake")
                .field("sni", probe.destination)
                .field("outcome", "alert"),
            "refusal_response" => Event::new("http", "request")
                .field("host", probe.destination)
                .field("answer", "misdirected")
                .field("status", 421u32)
                .field("complete", true),
            "dns" => Event::new("dns", "query")
                .field("name", "example.com")
                .field("answer", "addr")
                .field("addr", "203.0.113.1"),
            other => {
                let event = Event::new("http", "request")
                    .field("host", probe.destination)
                    .field("world_site", "a world site")
                    .field("answer", "handler")
                    .field("status", 200u32)
                    .field("complete", true);
                if other == "forwarded" {
                    event.field("forwarded", "https://example.com")
                } else {
                    event
                }
            }
        }
        .conn(&conn);
        egress.observe(
            Stamp {
                stream: Stream::Events,
                seq: 1,
                at: Instant::ZERO,
            },
            Observation::Event(&event),
        );
        egress.snapshot()
    }

    #[test]
    fn only_complete_affirmative_results_pass() {
        let mut probes = Containment {
            probes: PROBES
                .iter()
                .map(|probe| {
                    let mut result = result(probe, "station", String::new(), String::new());
                    result.outcome = if matches!(probe.kind, Kind::Routes | Kind::Proxy) {
                        ProbeOutcome::Fact
                    } else {
                        ProbeOutcome::Contained
                    };
                    result
                })
                .collect(),
        };
        assert!(passed(&probes, &["station"]));
        for outcome in [
            ProbeOutcome::Unknown,
            ProbeOutcome::MissingTool,
            ProbeOutcome::TimedOut,
            ProbeOutcome::Forwarded,
            ProbeOutcome::NotContained,
            ProbeOutcome::Fact,
        ] {
            probes.probes[0].outcome = outcome;
            assert!(!passed(&probes, &["station"]), "{outcome:?}");
        }
        probes.probes[0].outcome = ProbeOutcome::Contained;
        assert!(!passed(&probes, &["station", "server"]));
        let first = probes.probes[0].clone();
        probes.probes[0] = probes.probes[1].clone();
        assert!(!complete(&probes, &["station"]));
        probes.probes[0] = first;
        probes.probes[0].destination = "another address".into();
        assert!(!complete(&probes, &["station"]));
        probes.probes.clear();
        assert!(!passed(&probes, &["station"]));
        assert!(!passed(&probes, &[]));
    }

    #[test]
    fn each_network_probe_compares_guest_answers_with_new_world_observations() {
        for probe in PROBES
            .iter()
            .filter(|probe| matches!(probe.kind, Kind::Dns | Kind::Http | Kind::Ipv6))
        {
            let empty = EgressSnapshot::default();
            let successful = output(
                0,
                if matches!(probe.kind, Kind::Dns) {
                    ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 30\n;; SERVER: 8.8.8.8#53(8.8.8.8) (UDP)\n"
                } else {
                    "HTTP 200\n"
                },
            );
            let served = observation(
                probe,
                if matches!(probe.kind, Kind::Dns) {
                    "dns"
                } else {
                    "served"
                },
            );
            assert_eq!(
                parse(probe, "workstation", &successful, &empty, &served).outcome,
                ProbeOutcome::Contained,
                "{}",
                probe.name
            );
            assert_eq!(
                parse(probe, "workstation", &successful, &empty, &empty).outcome,
                ProbeOutcome::NotContained
            );
            assert_eq!(
                parse(probe, "workstation", &successful, &served, &served).outcome,
                ProbeOutcome::NotContained,
                "old rows cannot explain a new answer"
            );
            let mut lost = empty.clone();
            lost.lost = 1;
            assert_eq!(
                parse(probe, "workstation", &successful, &empty, &lost).outcome,
                ProbeOutcome::Unknown
            );
            for refusal in ["no_route", "refused"] {
                let refused = observation(probe, refusal);
                let failed = output(7, "Failed to connect\n");
                assert_eq!(
                    parse(probe, "workstation", &failed, &empty, &refused).outcome,
                    ProbeOutcome::Contained
                );
                assert_eq!(
                    parse(probe, "workstation", &successful, &empty, &refused).outcome,
                    ProbeOutcome::NotContained
                );
            }
            let forwarded = observation(probe, "forwarded");
            let result = parse(probe, "workstation", &successful, &empty, &forwarded);
            assert_eq!(result.outcome, ProbeOutcome::Forwarded);
            assert_eq!(
                result.world_answer,
                "forwarded by the world to https://example.com"
            );
        }
    }

    #[test]
    fn an_http_refusal_response_is_accounted_for_by_the_world() {
        let empty = EgressSnapshot::default();
        for probe in PROBES
            .iter()
            .filter(|probe| matches!(probe.kind, Kind::Http | Kind::Ipv6))
        {
            let refused = observation(probe, "refusal_response");
            let result = parse(
                probe,
                "workstation",
                &output(0, "HTTP 421\n"),
                &empty,
                &refused,
            );
            assert_eq!(result.outcome, ProbeOutcome::Contained);
            assert!(result.world_answer.starts_with("refused:"));
        }
    }

    #[test]
    fn a_tls_refusal_on_a_new_connection_answers_an_untrusted_certificate() {
        let empty = EgressSnapshot::default();
        let untrusted = output(
            60,
            "HTTP 000\ncurl: (60) SSL certificate problem: unable to get local issuer certificate\n",
        );
        for probe in PROBES
            .iter()
            .filter(|probe| matches!(probe.kind, Kind::Http | Kind::Ipv6))
        {
            let alert = observation(probe, "tls_alert");
            let result = parse(probe, "workstation", &untrusted, &empty, &alert);
            assert_eq!(result.outcome, ProbeOutcome::Contained, "{}", probe.name);
            assert_eq!(result.world_answer, "refused: TLS handshake alert");
            assert_eq!(
                parse(probe, "workstation", &untrusted, &alert, &alert).outcome,
                ProbeOutcome::NotContained,
                "an old refusal cannot explain a new handshake"
            );
            assert_eq!(
                parse(
                    probe,
                    "workstation",
                    &output(0, "HTTP 200\n"),
                    &empty,
                    &alert,
                )
                .outcome,
                ProbeOutcome::NotContained,
                "a TLS refusal cannot explain an HTTP answer"
            );
        }
    }

    #[test]
    fn a_guest_without_an_ipv6_route_is_contained_for_ipv6() {
        let probe = PROBES
            .iter()
            .find(|probe| matches!(probe.kind, Kind::Ipv6))
            .unwrap();
        assert!(
            probe
                .command
                .starts_with("ip -6 route get 2606:4700:4700::1111 ")
        );
        let empty = EgressSnapshot::default();
        let failed = "HTTP 000\ncurl: (7) Couldn't connect to server\n";
        let result = parse(
            probe,
            "workstation",
            &output(7, &format!("{NO_IPV6_ROUTE}\n{failed}")),
            &empty,
            &empty,
        );
        assert_eq!(result.outcome, ProbeOutcome::Contained);
        assert_eq!(result.world_answer, "no route: the guest has no IPv6 route");
        assert_eq!(
            parse(probe, "workstation", &output(7, failed), &empty, &empty,).outcome,
            ProbeOutcome::Unknown,
            "with a route, only the world's observation decides"
        );
        assert_eq!(
            parse(
                probe,
                "workstation",
                &output(0, &format!("{NO_IPV6_ROUTE}\nHTTP 200\n")),
                &empty,
                &empty,
            )
            .outcome,
            ProbeOutcome::NotContained,
            "an answer the world did not give is not contained"
        );
    }

    #[test]
    fn summaries_keep_the_line_that_says_what_the_guest_got() {
        let empty = EgressSnapshot::default();
        let probe = |kind: fn(&Kind) -> bool| PROBES.iter().find(|p| kind(&p.kind)).unwrap();
        let dns = probe(|kind| matches!(kind, Kind::Dns));
        let http = probe(|kind| matches!(kind, Kind::Http));
        let routes = probe(|kind| matches!(kind, Kind::Routes));
        let proxy = probe(|kind| matches!(kind, Kind::Proxy));
        let failed = Output {
            code: 7,
            stdout: "HTTP 000\n".into(),
            stderr: "curl: (7) Failed to connect\n".into(),
        };
        for (probe, output, line) in [
            (
                dns,
                output(
                    9,
                    ";; DiG 9.18\n;; global options: +cmd\n;; connection timed out; no servers could be reached\n",
                ),
                "connection timed out; no servers could be reached",
            ),
            (http, output(0, "HTTP 200\n"), "HTTP 200"),
            (http, failed, "curl: (7) Failed to connect"),
            (
                http,
                Output {
                    code: 124,
                    stdout: String::new(),
                    stderr: "Probe timed out".into(),
                },
                "Probe timed out",
            ),
            (dns, output(127, "dig: not found"), MISSING_TOOL),
            (proxy, output(0, ""), NO_PROXY),
            (routes, output(0, "fe80::/64 dev eth0\n"), "Exit 0"),
        ] {
            let result = parse(probe, "workstation", &output, &empty, &empty);
            assert_eq!(result.summary, line, "{}", result.guest_result);
        }
    }

    #[test]
    fn deadlines_and_missing_tools_are_results() {
        let empty = EgressSnapshot::default();
        for probe in PROBES {
            let missing = parse(
                probe,
                "workstation",
                &output(127, "tool: not found"),
                &empty,
                &empty,
            );
            assert_eq!(missing.outcome, ProbeOutcome::MissingTool);
            assert!(
                missing
                    .guest_result
                    .contains("missing from this guest image")
            );
        }
        for probe in PROBES
            .iter()
            .filter(|probe| matches!(probe.kind, Kind::Dns | Kind::Http | Kind::Ipv6))
        {
            let result = parse(
                probe,
                "workstation",
                &output(124, "Probe timed out"),
                &empty,
                &empty,
            );
            assert_eq!(result.outcome, ProbeOutcome::TimedOut);
            assert!(result.guest_result.contains("timed out"));
        }
    }

    #[test]
    fn proxy_settings_and_routes_are_facts() {
        let empty = EgressSnapshot::default();
        for probe in PROBES
            .iter()
            .filter(|probe| matches!(probe.kind, Kind::Proxy))
        {
            let none = parse(probe, "workstation", &output(0, ""), &empty, &empty);
            assert_eq!(none.outcome, ProbeOutcome::Fact);
            assert_eq!(none.guest_result, "No proxy settings set");
            let result = parse(
                probe,
                "workstation",
                &output(
                    0,
                    "HTTPS_PROXY=https://cache.test:3128\nhttp_proxy=http://external.test:8080\nAcquire::http::Proxy \"http://cache.test:3128\";\n",
                ),
                &empty,
                &empty,
            );
            assert_eq!(result.proxies.len(), 3);
            assert_eq!(result.proxies[0].destination, "https://cache.test:3128");
            assert_eq!(result.proxies[1].destination, "http://external.test:8080");
            assert_eq!(result.proxies[2].destination, "http://cache.test:3128");
        }
        let routes = PROBES
            .iter()
            .find(|probe| matches!(probe.kind, Kind::Routes))
            .unwrap();
        let result = parse(
            routes,
            "workstation",
            &output(0, "default via fe80::1 dev eth0\n"),
            &empty,
            &empty,
        );
        assert_eq!(result.outcome, ProbeOutcome::Fact);
        assert!(result.guest_result.contains("default via"));
    }
}
