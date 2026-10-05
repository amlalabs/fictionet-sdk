//! SDP session descriptions, as a world playing a SIP phone or a WebRTC
//! peer reads them.
#![no_main]

use fictionet::stdlib::sdp::{Candidate, Decoder, Fmtp, RtpMap, SessionDescription};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The body, read two ways: all at once, and a byte at a time.
    let whole = SessionDescription::parse(data);
    let mut bytewise = Decoder::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
    }
    assert_eq!(bytewise.finish(), whole);

    let Ok(desc) = whole else { return };
    // A description read can be written, and reads back the same.
    let bytes = desc.to_bytes().unwrap();
    assert_eq!(SessionDescription::parse(&bytes), Ok(desc.clone()));

    // So can each typed attribute.
    for m in &desc.media {
        let _ = desc.direction(m);
        for a in &m.attributes {
            if let Ok(r) = RtpMap::from_attribute(a) {
                assert_eq!(RtpMap::from_attribute(&r.to_attribute().unwrap()), Ok(r));
            }
            if let Ok(f) = Fmtp::from_attribute(a) {
                let _ = f.parameters();
                assert_eq!(Fmtp::from_attribute(&f.to_attribute().unwrap()), Ok(f));
            }
            if let Ok(c) = Candidate::from_attribute(a) {
                assert_eq!(Candidate::from_attribute(&c.to_attribute().unwrap()), Ok(c));
            }
        }
    }
});
