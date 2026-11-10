//! The `ext6` vectors (see `verification/packet-udp/lean/Ip/Ext6.lean`):
//! IPv6 packets with extension-header chains, and what the Lean walk
//! `chain6` (proved equal to the RFC 8200 and RFC 7112 decision) makes of
//! each, as a destination checks it, as `Header::parse` and
//! `Header::parse_truncated` read it, and as `strip_extension_headers`
//! takes its headers out.

use fictionet::stdlib::network::ip::{Header, Reject, strip_extension_headers};
use serde_json::Value;

use crate::support;

/// The header fields compared: protocol, upper-layer start, end, length
/// and fragment (identification, offset, more).
type Fields = (u8, usize, usize, usize, Option<(u32, usize, bool)>);

/// A walk's result from the vector: a header's fields, or a refusal.
fn reference(value: &Value) -> Result<Fields, Reject> {
    match value["reject"].as_str() {
        Some("discard") => return Err(Reject::Discard),
        Some(_) => {
            return Err(Reject::Problem {
                code: value["code"].as_u64().unwrap() as u8,
                pointer: value["pointer"].as_u64().unwrap() as u32,
            });
        }
        None => {}
    }
    let n = |key: &str| value[key].as_u64().unwrap() as usize;
    let frag = (!value["frag"].is_null()).then(|| {
        let f = &value["frag"];
        (
            f["id"].as_u64().unwrap() as u32,
            f["offset"].as_u64().unwrap() as usize,
            f["more"].as_bool().unwrap(),
        )
    });
    Ok((n("proto") as u8, n("upper"), n("end"), n("length"), frag))
}

/// The same fields of a header the Rust read.
fn fields(h: &Header) -> Fields {
    (
        h.protocol,
        h.payload.start,
        h.payload.end,
        h.length,
        h.fragment.map(|f| (f.id, f.offset, f.more)),
    )
}

#[test]
fn extension_headers_match_the_lean_walk() {
    support::cases("ext6", |case| {
        let packet = support::bytes(&case["packet"]);
        let check = Header::check(&packet).map(|h| fields(&h));
        assert_eq!(check, reference(&case["check"]), "check {packet:?}");
        for (key, read) in [
            ("parse", Header::parse(&packet)),
            ("truncated", Header::parse_truncated(&packet)),
        ] {
            let want = (!case[key].is_null()).then(|| reference(&case[key]).unwrap());
            assert_eq!(read.map(|h| fields(&h)), want, "{key} {packet:?}");
        }
        let strip = &case["strip"];
        let want = if strip["none"].as_bool() == Some(true) {
            Ok(None)
        } else if strip["packet"].is_array() {
            Ok(Some(support::bytes(&strip["packet"])))
        } else {
            Err(reference(strip).unwrap_err())
        };
        assert_eq!(strip_extension_headers(&packet), want, "strip {packet:?}");
    });
}
