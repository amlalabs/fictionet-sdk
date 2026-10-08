//! SDP session descriptions, as a world playing a SIP phone or a WebRTC
//! peer reads them.
#![no_main]

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::contract;

use fictionet::stdlib::sdp::harness::check_attribute;
use fictionet::stdlib::sdp::{
    Attribute, MAX_LINE_LEN, MAX_LINES, SessionDescription, SessionDescriptions,
};
use fictionet::stdlib::test_support::decode_all;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(SessionDescriptions::new, data, 2 * (MAX_LINE_LEN + 2));
    contract::check_decode_with_held_limit(
        SessionDescriptions::new,
        data,
        fictionet::stdlib::sdp::MAX_LEN,
    );
    contract::check_wire::<SessionDescription>(data);
    // The input as one attribute value, as a trickled ICE candidate comes
    // on its own, not inside a description. The helpers refuse values
    // longer than a line before copying them.
    if let Ok(v) = std::str::from_utf8(data) {
        for name in ["rtpmap", "fmtp", "candidate"] {
            check_attribute(&Attribute::new(name, v));
        }
    }

    // Adapter consistency only: Wire::parse also uses SessionDescriptions.
    let whole = SessionDescription::parse(data);
    let expected = match &whole {
        Ok(description) => (vec![description.clone()], None),
        Err(error) => (
            vec![],
            Some(fictionet::stdlib::codec::Fail::Protocol(*error)),
        ),
    };
    assert_eq!(decode_all(SessionDescriptions::new, data), expected);

    let Ok(desc) = whole else { return };
    // A description read can be written, and reads back the same. The
    // writer never needs more room than the reader allowed: r= and z=
    // lines keep their units, and MAX_LEN counts line endings as CRLF.
    contract::check_wire_value(&desc);
    let mut invalid = desc.clone();
    invalid.name.push('\n');
    contract::check_wire_value(&invalid);
    let bytes = desc.to_bytes().unwrap();
    assert!(bytes.iter().filter(|&&b| b == b'\n').count() <= MAX_LINES);
    assert_eq!(SessionDescription::parse(&bytes), Ok(desc.clone()));

    // So can each typed attribute.
    for m in &desc.media {
        let _ = desc.direction(m);
        for a in &m.attributes {
            check_attribute(a);
        }
    }
});
