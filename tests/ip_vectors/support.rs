//! Reading the vector files.

use serde_json::Value;

/// Calls `check` on every case of `<kind>.json`, and fails if there is none.
pub fn cases(kind: &str, mut check: impl FnMut(&Value)) {
    let dir = std::env::var_os("IP_VECTORS").expect("run cargo xtask ip-verify diff");
    let path = std::path::Path::new(&dir).join(format!("{kind}.json"));
    let data: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let cases = data.as_array().unwrap();
    assert!(!cases.is_empty(), "empty {kind} vectors");
    for case in cases {
        check(case);
    }
    println!("{kind}: {} cases, 0 disagree", cases.len());
}

/// An array of octets.
#[allow(dead_code)]
pub fn bytes(value: &Value) -> Vec<u8> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| u8::try_from(v.as_u64().unwrap()).unwrap())
        .collect()
}
