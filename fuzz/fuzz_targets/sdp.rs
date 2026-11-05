//! SDP session descriptions, as a world playing a SIP phone or a WebRTC
//! peer reads them.
#![no_main]

use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};

use fictionet::stdlib::protocols::sdp::harness::check_attribute;
use fictionet::stdlib::protocols::sdp::{
    Attribute, MAX_LINE_LEN, MAX_LINES, SessionDescription, SessionDescriptions,
};
use fictionet::stdlib::test_support::decode_all;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        decode_chunks(
            &mut Stream::new(SessionDescriptions::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * (MAX_LINE_LEN + 2));
                assert!(s.held() <= fictionet::stdlib::protocols::sdp::MAX_LEN);
            }
        ),
        decode_all(SessionDescriptions::new, data),
    );
    if let Ok(value) = <SessionDescription as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
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
    let _ = assert_write(&desc);
    let mut invalid = desc.clone();
    invalid.name.push('\n');
    let _ = assert_write(&invalid);
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
