#![no_main]
use fictionet::stdlib::{
    codec::{Wire, contract},
    http2,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let bytes = &data[..data.len().min(4096)];
    contract::check_decode(|| http2::Frames::with_limit(4096), bytes);
    contract::check_decode(|| http2::Frames::client_side(4096), bytes);
    contract::check_wire::<http2::FrameHeader>(bytes);
    contract::check_wire::<http2::Frame>(bytes);
    contract::check_wire::<http2::Data>(bytes);
    contract::check_wire::<http2::Headers>(bytes);
    contract::check_wire::<http2::Priority>(bytes);
    contract::check_wire::<http2::Reset>(bytes);
    contract::check_wire::<http2::Settings>(bytes);
    contract::check_wire::<http2::PushPromise>(bytes);
    contract::check_wire::<http2::Ping>(bytes);
    contract::check_wire::<http2::GoAway>(bytes);
    contract::check_wire::<http2::WindowUpdate>(bytes);
    contract::check_wire::<http2::Continuation>(bytes);
    contract::check_wire::<http2::Unknown>(bytes);
    // Capture checks stay below the oversized read-ahead policy threshold.
    contract::check_decode(|| fictionet::observe::http2::Capture::new(4096), bytes);
    let mut framed = http2::Settings {
        flags: 0,
        entries: vec![],
    }
    .to_bytes()
    .unwrap();
    framed.extend_from_slice(bytes);
    for client in [false, true] {
        let mut c = if client {
            http2::Connection::client_side(Default::default())
        } else {
            http2::Connection::server_side(Default::default())
        };
        if client {
            let _ = c.push(http2::PREFACE);
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
