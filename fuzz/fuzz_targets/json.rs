//! JSON texts and streams of them, as a world playing a web API or a
//! JSON-RPC server reads them.
#![no_main]

use fictionet::stdlib::json::{self, Decoder, Value};
use libfuzzer_sys::fuzz_target;

/// Every value the decoder gives, up to and including its first error.
fn decode(data: &[u8], bytewise: bool) -> Vec<Result<Value, json::Error>> {
    let mut d = Decoder::new();
    let mut out = Vec::new();
    let chunks: Vec<&[u8]> = if bytewise { data.chunks(1).collect() } else { vec![data] };
    for chunk in chunks {
        d.feed(chunk);
        while let Some(v) = d.next_value() {
            let stop = v.is_err();
            out.push(v);
            if stop {
                return out;
            }
        }
    }
    out
}

/// A value written reads back the same, and writes the same text again.
fn round_trip(v: &Value) {
    let text = v.write().unwrap();
    let back = json::parse(text.as_bytes()).unwrap();
    assert_eq!(&back, v);
    assert_eq!(back.write().unwrap(), text);
}

fuzz_target!(|data: &[u8]| {
    // The input as one JSON text.
    if let Ok(v) = json::parse(data) {
        round_trip(&v);
    }
    // The input as a stream, split two ways: all at once, and a byte at
    // a time.
    let whole = decode(data, false);
    assert_eq!(whole, decode(data, true));
    for v in whole.iter().flatten() {
        round_trip(v);
    }
});
