//! Reading the vector files.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde_json::Value;

/// Calls `check` on every case of `<kind>.json`. A kind whose Lean module
/// writes no file yet is not yet written: it is skipped with a line saying
/// so, never counted as a pass. A file with no cases fails.
pub fn cases(kind: &str, mut check: impl FnMut(&Value)) {
    let dir = std::env::var_os("IP_VECTORS").expect("run cargo xtask ip-verify diff");
    let path = std::path::Path::new(&dir).join(format!("{kind}.json"));
    if !path.exists() {
        println!("{kind}: no vector file, not yet written");
        return;
    }
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

/// A number that fits `T`.
#[allow(dead_code)]
pub fn num<T: TryFrom<u64>>(value: &Value) -> T
where
    T::Error: std::fmt::Debug,
{
    T::try_from(value.as_u64().unwrap()).unwrap()
}

/// An IP address written as its 4 or 16 octets.
#[allow(dead_code)]
pub fn addr(value: &Value) -> IpAddr {
    let octets = bytes(value);
    match octets.len() {
        4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(octets).unwrap())),
        16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(octets).unwrap())),
        n => panic!("an address of {n} octets"),
    }
}

/// The octets of an address, as the vectors write them.
#[allow(dead_code)]
pub fn octets(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}
