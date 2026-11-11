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
//!
//! Every step is also costed (verification/resources/cost.rs): the
//! reassembly holds no more than `Reassembly::MOST_HELD` at any moment,
//! besides what a step hands out, and a step asks the allocator for no
//! more than [`PUSH`] or [`EXPIRE`] allows. The constants are in
//! verification/packet-udp/README.md, "Resource properties".

use fictionet::Chunk;
use fictionet::stdlib::network::ip::{
    Header, Intake, Reassembly, destination, reassembly_time_exceeded, source,
};
use fictionet::time::{Duration, Instant};
use serde_json::Value;

use crate::alloc::unmeasured;
use crate::cost::{Charged, Costs, Linear};
use crate::support::cases;

/// A push's linear bound. The packet is built inside the step from its
/// hex digits, one allocation of its bytes and a chunk's header, so that
/// freeing it is the step's; then its data and first fragment's headers
/// are copied once each, at most its bytes again. An entry added to a
/// `BTreeMap` may split a node at every level: three trees, at most 8
/// levels, at most 2 KiB a node.
const PUSH: Linear = Linear {
    num: 2,
    den: 1,
    fixed: 3 * 8 * 2048 + Chunk::HEADER,
};

/// An expiry's bound, on the bytes counted before it: it copies nothing
/// and asks only for the nodes that keep the first fragments, which their
/// count covers, never more than their packets counted.
const EXPIRE: Linear = Linear {
    num: 1,
    den: 1,
    fixed: 0,
};

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

/// Whether `intake` is what `want` says, compared in place.
fn agrees(intake: &Intake, want: &Expect) -> bool {
    match (intake, want) {
        (Intake::Whole(whole), Expect::Whole(bytes)) => whole[..] == bytes[..],
        (Intake::Waiting, Expect::Waiting)
        | (Intake::Discarded, Expect::Discarded)
        | (Intake::Refused { .. }, Expect::Refused) => true,
        _ => false,
    }
}

/// A short form of a result for a failure message.
fn brief(intake: &Intake) -> String {
    match intake {
        Intake::Whole(b) => format!("Whole({} bytes)", b.len()),
        Intake::Waiting => "Waiting".into(),
        Intake::Discarded => "Discarded".into(),
        Intake::Refused { .. } => "Refused".into(),
    }
}

fn brief_want(e: &Expect) -> String {
    match e {
        Expect::Whole(b) => format!("Whole({} bytes)", b.len()),
        other => format!("{other:?}"),
    }
}

/// What a step hands out for its taker to pay for: a whole packet, which
/// for IPv6 is built and then copied without its extension headers (two
/// packets at most), or a refused packet and its answer, each in a chunk
/// of its own.
fn handed_out(intake: &Intake) -> usize {
    match intake {
        Intake::Whole(whole) => 2 * (whole.len() + Chunk::HEADER),
        Intake::Waiting | Intake::Discarded => 0,
        Intake::Refused { packet, answer } => {
            2 * (packet.len() + Chunk::HEADER)
                + answer.as_ref().map_or(0, |a| a.len() + Chunk::HEADER)
        }
    }
}

/// Checks the answer to a kept first fragment, if one is sent.
fn check_answer(first: &[u8]) -> Result<(), String> {
    let Some(answer) = reassembly_time_exceeded(first) else {
        return Ok(());
    };
    let answer = answer.to_vec();
    let h = Header::parse_whole(&answer).ok_or("an answer that does not read")?;
    let (Some(from), Some(to)) = (destination(first), source(first)) else {
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
    if !first.starts_with(&icmp[8..]) {
        return Err("a quote that is not the fragment's start".into());
    }
    Ok(())
}

#[test]
fn reassembly_matches_the_lean_model() {
    let mut disagree = Vec::new();
    let mut kept = 0;
    let mut all = Costs::new("reassembly");
    cases("reassembly", |case| {
        let name = case["name"].as_str().unwrap();
        let mut costs = Costs::new(name);
        let mut r = Reassembly::default();
        for (i, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            let now =
                Instant::from_since_start(Duration::from_millis(step["at_ms"].as_u64().unwrap()));
            let digits = step["packet"].as_str().unwrap();
            let mut problems = Vec::new();
            if digits.is_empty() {
                costs.step(r.counted(), Reassembly::MOST_HELD, EXPIRE, || {
                    r.expire(now);
                    Charged {
                        value: (),
                        charged: 0,
                        moved: 0,
                    }
                });
            } else {
                let want = expected(&step["expect"]);
                let got = costs.step(digits.len() / 2, Reassembly::MOST_HELD, PUSH, || {
                    let intake = r.push(Chunk::unpaid(hex(digits)), now);
                    let value = (!agrees(&intake, &want)).then(|| brief(&intake));
                    Charged {
                        value,
                        charged: handed_out(&intake),
                        moved: 0,
                    }
                });
                if let Some(got) = got {
                    problems.push(format!("got {got}, the model says {}", brief_want(&want)));
                }
            }
            let mut firsts = Vec::new();
            loop {
                let first = costs.step(0, Reassembly::MOST_HELD, EXPIRE, || {
                    let first = r.take_expired();
                    let charged = first.as_ref().map_or(0, |f| f.len() + Chunk::HEADER);
                    // Kept for the comparison outside the count, so that
                    // only the reassembly's own bytes stay counted.
                    let copy = first.as_deref().map(|f| unmeasured(|| f.to_vec()));
                    drop(first);
                    Charged {
                        value: copy,
                        charged,
                        moved: 0,
                    }
                });
                let Some(first) = first else { break };
                if let Err(e) = check_answer(&first) {
                    problems.push(e);
                }
                firsts.push(first);
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
        all.absorb(&costs);
    });
    println!("reassembly: {kept} first fragments kept for answers");
    all.print();
    assert!(
        disagree.is_empty(),
        "{} cases disagree:\n{}",
        disagree.len(),
        disagree.join("\n")
    );
}
