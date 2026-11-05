#![no_main]
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_all, decode_chunks};
use fictionet::stdlib::{codec::Wire, protocols::http2};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    http2::harness::check_actions(data);
    let bytes = &data[..data.len().min(4096)];
    assert_eq!(
        decode_chunks(
            &mut Stream::new(http2::Inputs::with_limit(4096)),
            chunks(bytes, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(|| http2::Inputs::with_limit(4096), bytes),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(http2::Inputs::client_side(4096)),
            chunks(bytes, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(|| http2::Inputs::client_side(4096), bytes),
    );
    if let Ok(value) = <http2::FrameHeader as Wire>::parse(bytes) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <http2::Frame as Wire>::parse(bytes) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <http2::Data as Wire>::parse(bytes) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <http2::Headers as Wire>::parse(bytes) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <http2::Priority as Wire>::parse(bytes) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <http2::Reset as Wire>::parse(bytes) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <http2::Settings as Wire>::parse(bytes) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <http2::PushPromise as Wire>::parse(bytes) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <http2::Ping as Wire>::parse(bytes) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <http2::GoAway as Wire>::parse(bytes) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <http2::WindowUpdate as Wire>::parse(bytes) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <http2::Continuation as Wire>::parse(bytes) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <http2::Unknown as Wire>::parse(bytes) {
        let _ = assert_write(&value);
    }
    // Capture checks stay below the oversized read-ahead policy threshold.
    assert_eq!(
        decode_chunks(
            &mut Stream::new(fictionet::stdlib::dissect::http2::Capture::new(4096)),
            chunks(bytes, &[1, 7, 64]),
            |_| {}
        ),
        decode_all(
            || fictionet::stdlib::dissect::http2::Capture::new(4096),
            bytes
        ),
    );
    let mut framed = http2::Settings {
        flags: 0,
        entries: vec![],
    }
    .to_bytes()
    .unwrap();
    framed.extend_from_slice(bytes);
    for client in [false, true] {
        let mut c = if client {
            http2::Session::client_side(Default::default())
        } else {
            http2::Session::server_side(Default::default())
        };
        if client {
            assert_eq!(c.push(http2::PREFACE), http2::PREFACE.len());
            while c.next().is_some() {}
        }
        for part in framed.chunks(7) {
            let mut rest = part;
            while !rest.is_empty() {
                let n = c.push(rest);
                rest = &rest[n..];
                while c.next().is_some() {}
                assert!(n > 0);
            }
        }
        c.end();
        while c.next().is_some() {}
        assert!(c.is_done());
        c.lost();
        assert_eq!(c.held(), 0);
    }
});
