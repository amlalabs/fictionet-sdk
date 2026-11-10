//! Differential checks of the HTTP/1 decoders against the executable Lean
//! model in `verification/http/lean/Http/Wire.lean`. Run through
//! `cargo xtask http-verify diff`, which writes the vectors and names their
//! directory in `HTTP1_VECTORS`.
//!
//! Each vector is replayed twice: with the whole input pushed at once, and
//! in random pieces. Both must give the model's events and stop.
use fictionet::stdlib::codec::{Decode, Fail, Stream};
use fictionet::stdlib::protocols::http1::{
    Event, Limits, RequestEvents, RequestHead, ResponseEvents, ResponseHead, Version,
};
use serde_json::{Value, json};

fn cases(kind: &str, mut check: impl FnMut(usize, &Value) -> Option<String>) {
    let dir = std::env::var_os("HTTP1_VECTORS").expect("run cargo xtask http-verify diff");
    let path = std::path::Path::new(&dir).join(format!("{kind}.json"));
    let data: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let cases = data.as_array().unwrap();
    assert!(!cases.is_empty(), "empty {kind} vectors");
    let mut disagree = Vec::new();
    for (i, case) in cases.iter().enumerate() {
        if let Some(why) = check(i, case) {
            disagree.push(why);
        }
    }
    println!("{kind}: {} cases, {} disagree", cases.len(), disagree.len());
    for why in disagree.iter().take(5) {
        println!("{why}");
    }
    assert!(
        disagree.is_empty(),
        "{kind}: the Rust decoder and the model disagree"
    );
}

fn bytes(value: &Value) -> Vec<u8> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| u8::try_from(v.as_u64().unwrap()).unwrap())
        .collect()
}

fn n(value: &Value, key: &str) -> usize {
    usize::try_from(value[key].as_u64().unwrap()).unwrap()
}

fn limits(v: &Value) -> Limits {
    Limits {
        start_line: n(v, "start_line"),
        header_line: n(v, "header_line"),
        headers: n(v, "headers"),
        head: n(v, "head"),
        body_chunk: n(v, "body_chunk"),
        ..Limits::default()
    }
}

/// splitmix64, for the piece sizes.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        usize::try_from(z % u64::try_from(n.max(1)).unwrap()).unwrap()
    }
}

fn version(v: Version) -> &'static str {
    v.as_str()
}

/// Feeds `input` to a `Stream` over `decoder`, whole or in random pieces,
/// with the end of input after it when `eof`, and describes what comes out
/// as the model does.
fn replay<H, D>(
    decoder: D,
    input: &[u8],
    eof: bool,
    mut pieces: Option<&mut Rng>,
    head: impl Fn(&H, u64) -> Value,
    failed: impl Fn(&D::Error) -> Value,
) -> (Vec<Value>, Value)
where
    D: Decode<Item = Event<H>>,
    D::Error: Clone,
{
    let mut stream = Stream::new(decoder);
    let mut events = Vec::new();
    let mut fed = 0;
    let drain = |stream: &mut Stream<D>, events: &mut Vec<Value>| -> Option<Value> {
        while let Some(result) = stream.next_span() {
            match result {
                Ok((Event::Head(h), range)) => events.push(json!({ "head": head(&h, range.end) })),
                Ok((Event::Body(b), _)) => events.push(json!({ "body": b })),
                Ok((Event::Done, range)) => events.push(json!({ "done": range.end })),
                Err(Fail::Protocol(e)) => return Some(json!({ "failed": failed(&e) })),
                Err(Fail::Truncated { .. }) => return Some(json!({ "truncated": true })),
                Err(other) => return Some(json!({ "other": format!("{other:?}") })),
            }
        }
        None
    };
    loop {
        let end = match pieces.as_deref_mut() {
            Some(rng) if fed < input.len() => fed + 1 + rng.below(input.len() - fed),
            _ => input.len(),
        };
        let taken = stream.push(&input[fed..end]);
        fed += taken;
        if let Some(stop) = drain(&mut stream, &mut events) {
            return (events, stop);
        }
        if fed == input.len() || stream.is_done() {
            break;
        }
        if taken == 0 && stream.buffered() >= stream.limit() {
            return (
                events,
                json!({ "other": "the buffer filled while the decoder waited" }),
            );
        }
    }
    if eof {
        stream.end();
        if let Some(stop) = drain(&mut stream, &mut events) {
            return (events, stop);
        }
    }
    let offset = stream.offset();
    let stop = if stream.is_done() {
        json!({ "ended": offset })
    } else {
        json!({ "waiting": offset })
    };
    (events, stop)
}

/// Replays one case whole and in pieces; the disagreement, if any.
fn compare(
    i: usize,
    case: &Value,
    run: impl Fn(Option<&mut Rng>) -> (Vec<Value>, Value),
) -> Option<String> {
    let expected = (
        case["events"].as_array().unwrap().clone(),
        case["stop"].clone(),
    );
    let whole = run(None);
    if whole != expected {
        return Some(format!(
            "case {i} whole: input {:?} eof {}\n  rust:  {:?}\n  model: {:?}",
            String::from_utf8_lossy(&bytes(&case["input"])),
            case["eof"],
            whole,
            expected
        ));
    }
    let mut rng = Rng(u64::try_from(i).unwrap());
    let pieces = run(Some(&mut rng));
    if pieces != expected {
        return Some(format!(
            "case {i} in pieces: input {:?}\n  rust:  {:?}\n  model: {:?}",
            String::from_utf8_lossy(&bytes(&case["input"])),
            pieces,
            expected
        ));
    }
    None
}

#[test]
fn requests() {
    cases("requests", |i, case| {
        let input = bytes(&case["input"]);
        let eof = case["eof"].as_bool().unwrap();
        compare(i, case, |pieces| {
            replay(
                RequestEvents::with_limits(limits(&case["limits"])),
                &input,
                eof,
                pieces,
                |h: &RequestHead, end| {
                    json!({
                        "method": h.method().as_bytes(),
                        "target": h.target().as_bytes(),
                        "version": version(h.version()),
                        "status": 0,
                        "end": end,
                    })
                },
                |e| json!(format!("{:?}", e.reason())),
            )
        })
    });
}

#[test]
fn responses() {
    cases("responses", |i, case| {
        let input = bytes(&case["input"]);
        let eof = case["eof"].as_bool().unwrap();
        compare(i, case, |pieces| {
            let mut decoder = ResponseEvents::with_limits(limits(&case["limits"]));
            for method in case["methods"].as_array().unwrap() {
                decoder.expect_method(method.as_str().unwrap()).unwrap();
            }
            replay(
                decoder,
                &input,
                eof,
                pieces,
                |h: &ResponseHead, end| {
                    json!({
                        "method": [],
                        "target": [],
                        "version": version(h.version),
                        "status": h.status,
                        "end": end,
                    })
                },
                |e| json!(format!("{e:?}")),
            )
        })
    });
}
