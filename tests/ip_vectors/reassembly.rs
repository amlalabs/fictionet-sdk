//! The `reassembly` vectors (see `verification/packet-udp/lean/Ip`).
//!
//! Each case is a run of steps, each with its time, on a fresh
//! `Reassembly`: a packet for `Reassembly::push`, or no packet for the timer
//! (`Reassembly::expire`). Every step's result must be what the Lean model
//! makes of it: the whole packet's bytes, waiting, discarded, or refused.
//! After each step every first fragment kept for a Time Exceeded answer is
//! taken (`Reassembly::take_expired`) and must be the ones the model keeps,
//! byte for byte. The order of several kept in one step is not compared:
//! the code keeps them by deadline, the model by its table's order. The
//! answer built for each (`reassembly_time_exceeded`) must be ICMP Time
//! Exceeded, code 1, from the fragment's destination, quoting its start.

use fictionet::Packet;
use fictionet::stdlib::network::ip::{
    Header, Intake, Reassembly, destination, reassembly_time_exceeded, source,
};
use fictionet::time::{Duration, Instant};
use serde_json::Value;

use crate::support::cases;

/// Bytes from a string of hex digits.
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// What a step should make of its packet.
#[derive(Debug, PartialEq)]
enum Expect {
    Whole(Vec<u8>),
    Waiting,
    Discarded,
    Refused,
}

fn expected(value: &Value) -> Expect {
    match value {
        Value::String(s) if s == "waiting" => Expect::Waiting,
        Value::String(s) if s == "discarded" => Expect::Discarded,
        Value::String(s) if s == "refused" => Expect::Refused,
        Value::Object(o) => Expect::Whole(hex(o["whole"].as_str().unwrap())),
        other => panic!("unknown expectation {other}"),
    }
}

fn got(intake: Intake) -> Expect {
    match intake {
        Intake::Whole(Packet(bytes)) => Expect::Whole(bytes),
        Intake::Waiting => Expect::Waiting,
        Intake::Discarded => Expect::Discarded,
        Intake::Refused { .. } => Expect::Refused,
    }
}

/// A short form of a result for a failure message.
fn brief(e: &Expect) -> String {
    match e {
        Expect::Whole(b) => format!("Whole({} bytes)", b.len()),
        other => format!("{other:?}"),
    }
}

/// Checks the answer to a kept first fragment, if one is sent.
fn check_answer(first: &Packet) -> Result<(), String> {
    let Some(Packet(answer)) = reassembly_time_exceeded(first) else {
        return Ok(());
    };
    let h = Header::parse_whole(&answer).ok_or("an answer that does not read")?;
    let (Some(from), Some(to)) = (destination(&first.0), source(&first.0)) else {
        return Err("an answer to a fragment with no addresses".into());
    };
    if (h.src, h.dst) != (from, to) {
        return Err(format!("an answer from {} to {}", h.src, h.dst));
    }
    let icmp = h.payload(&answer);
    let kind = if from.is_ipv4() { 11 } else { 3 };
    if icmp.len() < 8 || (icmp[0], icmp[1]) != (kind, 1) {
        return Err("not Time Exceeded, code 1".into());
    }
    if !first.0.starts_with(&icmp[8..]) {
        return Err("a quote that is not the fragment's start".into());
    }
    Ok(())
}

#[test]
fn reassembly_matches_the_lean_model() {
    let mut disagree = Vec::new();
    let mut kept = 0;
    cases("reassembly", |case| {
        let name = case["name"].as_str().unwrap();
        let mut r = Reassembly::default();
        for (i, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            let now =
                Instant::from_since_start(Duration::from_millis(step["at_ms"].as_u64().unwrap()));
            let packet = hex(step["packet"].as_str().unwrap());
            let mut problems = Vec::new();
            if packet.is_empty() {
                r.expire(now);
            } else {
                let result = got(r.push(Packet(packet), now));
                let want = expected(&step["expect"]);
                if result != want {
                    problems.push(format!(
                        "got {}, the model says {}",
                        brief(&result),
                        brief(&want)
                    ));
                }
            }
            let mut firsts = Vec::new();
            while let Some(first) = r.take_expired() {
                if let Err(e) = check_answer(&first) {
                    problems.push(e);
                }
                firsts.push(first.0);
            }
            let mut want: Vec<Vec<u8>> = step["expired"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| hex(v.as_str().unwrap()))
                .collect();
            kept += want.len();
            firsts.sort();
            want.sort();
            if firsts != want {
                problems.push(format!(
                    "kept {} first fragments, the model {}",
                    firsts.len(),
                    want.len()
                ));
            }
            if !problems.is_empty() {
                disagree.push(format!("{name}, step {i}: {}", problems.join("; ")));
                break;
            }
        }
    });
    println!("reassembly: {kept} first fragments kept for answers");
    assert!(
        disagree.is_empty(),
        "{} cases disagree:\n{}",
        disagree.len(),
        disagree.join("\n")
    );
}
