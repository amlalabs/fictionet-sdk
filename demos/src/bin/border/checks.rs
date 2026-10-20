//! Output checks shared by the story and its tests.

use border_world::{
    certs::LAB_CA_NAME,
    routing::RouteState,
    scenario::{BANK_ADDR, ROGUE_CA_NAME, Scenario},
};
use fictionet_demo::kit::ssh::Output;
use std::net::Ipv4Addr;

/// Checks traceroute's numbered replies against a complete expected path.
pub fn route(text: &str, expected: &[Ipv4Addr]) -> bool {
    let mut hops = Vec::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        let Some(index) = words.next().and_then(|s| s.parse::<usize>().ok()) else {
            continue;
        };
        if index != hops.len() + 1 {
            return false;
        }
        let Some(address) = words.next().and_then(|s| s.parse::<Ipv4Addr>().ok()) else {
            return false;
        };
        hops.push(address);
    }
    hops == expected
}

/// Checks BIRD's imported prefixes against `expected`, rejecting missing and
/// unexpected routes.
pub fn routes(text: &str, expected: &[&str]) -> bool {
    let mut prefixes: Vec<_> = text
        .lines()
        .filter_map(|line| {
            let first = line.split_whitespace().next()?;
            let (address, length) = first.split_once('/')?;
            address.parse::<Ipv4Addr>().ok()?;
            length.parse::<u8>().ok()?;
            Some(first)
        })
        .collect();
    prefixes.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    prefixes == expected
}

/// Checks a bank-check step's output against what the world routes and
/// serves under `scenario`, which is routed for the step's mode.
pub fn check(step: &str, output: &Output, scenario: &Scenario) -> bool {
    let hijacked = scenario.hijacked();
    let state = RouteState::new(scenario, 0, 0);
    let text = format!("{}{}", output.stdout, output.stderr);
    if step == "balance" && hijacked {
        return output.code == 60 && text.contains("SSL certificate problem");
    }
    if output.code != 0 {
        return false;
    }
    match step {
        "signin" | "signin-insecure" => text.contains("You are signed in."),
        "balance" => serde_json::from_str::<serde_json::Value>(&output.stdout)
            .is_ok_and(|v| v["balance_gbp"].as_f64() == Some(4120.55) && v["currency"] == "GBP"),
        "route" => {
            let mut expected = state.bank_hops;
            expected.push(BANK_ADDR);
            route(&text, &expected)
        }
        "bgp 2" | "bgp 3" => routes(
            &text,
            &state
                .routes
                .iter()
                .map(|r| r.prefix.as_str())
                .collect::<Vec<_>>(),
        ),
        "cert" | "cert -k" => text.lines().any(|line| {
            line.contains("issuer:")
                && line.contains(if hijacked { ROGUE_CA_NAME } else { LAB_CA_NAME })
        }),
        "hold" => {
            text.contains("Persistent HTTPS request: 200")
                && [
                    "ConnectionResetError",
                    "BrokenPipeError",
                    "RemoteDisconnected",
                ]
                .iter()
                .any(|error| {
                    text.contains(&format!("Persistent HTTPS connection failed: {error}:"))
                })
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use border_world::scenario::Variant;
    fn output(code: i32, text: &str) -> Output {
        Output {
            code,
            stdout: text.into(),
            stderr: String::new(),
        }
    }
    #[test]
    fn checks_accept_complete_outputs_and_reject_incomplete_or_failed_steps() {
        let scenario = crate::control::scenario();
        let mode = |hijacked: bool| {
            scenario.routed(if hijacked {
                Variant::Hijack
            } else {
                Variant::Legitimate
            })
        };
        let normal = "traceroute to 84.21.44.10 (84.21.44.10), 30 hops max\n 1 192.168.1.1 2.1 ms\n 2 84.21.44.1 18.2 ms\n 3 84.21.44.10 24.2 ms\n";
        let hijack = "traceroute to 84.21.44.10 (84.21.44.10), 30 hops max\n 1 192.168.1.1 2.1 ms\n 2 84.21.44.1 18.2 ms\n 3 45.144.30.1 46.2 ms\n 4 84.21.44.10 52.2 ms\n";
        let two = "BIRD 2.14 ready.\n84.21.44.0/24 unicast [provider 10:30:01] * (100) [AS65001i]\n via 84.21.44.1 on eth0\n45.144.30.0/24 unicast [provider 10:30:01] * (100) [AS65002i]\n";
        let three = format!("{two}84.21.44.0/25 unicast [provider 10:30:01] * (100) [AS65002i]\n");
        for (step, text, hijacked, code) in [
            ("route", normal, false, 0),
            ("route", hijack, true, 0),
            ("bgp 2", two, false, 0),
            ("bgp 3", &three, true, 0),
            (
                "balance",
                "curl: (60) SSL certificate problem: self-signed certificate in certificate chain",
                true,
                60,
            ),
            (
                "cert",
                "* issuer: CN=Internet Security Root CA\n* SSL certificate verify ok.",
                false,
                0,
            ),
            ("cert -k", "* issuer: CN=Anchorpoint Root CA R1", true, 0),
            (
                "hold",
                "Persistent HTTPS request: 200\nPersistent HTTPS connection failed: ConnectionResetError: [Errno 104] Connection reset by peer",
                true,
                0,
            ),
            ("signin", "<p>You are signed in.</p>", false, 0),
            ("signin-insecure", "<p>You are signed in.</p>", true, 0),
            (
                "balance",
                "{\"balance_gbp\":4120.55,\"currency\":\"GBP\"}",
                false,
                0,
            ),
        ] {
            let scenario = mode(hijacked);
            assert!(check(step, &output(code, text), &scenario), "{step}");
            assert!(!check(step, &output(124, text), &scenario), "{step}");
            assert!(!check(step, &output(code, ""), &scenario), "{step}");
        }
        assert!(!check("route", &output(0, normal), &mode(true)));
        assert!(!check("route", &output(0, hijack), &mode(false)));
        assert!(!check(
            "route",
            &output(0, &normal.replace("192.168.1.1", "*")),
            &mode(false)
        ));
        assert!(!check("bgp 3", &output(0, two), &mode(true)));
        assert!(!check("bgp 2", &output(0, &three), &mode(false)));
        assert!(!check(
            "cert",
            &output(0, "issuer: CN=Anchorpoint Root CA R1"),
            &mode(false)
        ));
        assert!(!check(
            "hold",
            &output(0, "Persistent HTTPS request: 200\nTimeoutError: timed out"),
            &mode(true)
        ));
    }
}
