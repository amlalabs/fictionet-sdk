//! The `reassembly` vectors (see `verification/packet-udp/lean/Ip`).
//!
//! Each case is a run of packets, each with its time, fed one at a time to
//! a fresh `Reassembly` through `Reassembly::push`. Every step's result
//! must be what the Lean model of `push` makes of it: the whole packet's
//! bytes, waiting, discarded, or refused.

use fictionet::Packet;
use fictionet::stdlib::network::ip::{Intake, Reassembly};
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

#[test]
fn reassembly_matches_the_lean_model() {
    let mut disagree = Vec::new();
    cases("reassembly", |case| {
        let name = case["name"].as_str().unwrap();
        let mut r = Reassembly::default();
        for (i, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            let now =
                Instant::from_since_start(Duration::from_millis(step["at_ms"].as_u64().unwrap()));
            let packet = hex(step["packet"].as_str().unwrap());
            let result = got(r.push(Packet(packet), now));
            let want = expected(&step["expect"]);
            if result != want {
                disagree.push(format!(
                    "{name}, step {i}: got {}, the model says {}",
                    brief(&result),
                    brief(&want)
                ));
                break;
            }
        }
    });
    assert!(
        disagree.is_empty(),
        "{} cases disagree:\n{}",
        disagree.len(),
        disagree.join("\n")
    );
}
