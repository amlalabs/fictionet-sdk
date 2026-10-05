//! BGP-4 messages, as a world playing a router reads them, in two-octet
//! and four-octet AS sessions.
#![no_main]

use fictionet::stdlib::bgp::{Context, Decoder, Frame, Message, Open, Update};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new();
    whole.feed(data);
    let mut frames = Vec::new();
    while let Some(Ok(f)) = whole.next_frame() {
        frames.push(f);
    }
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(Ok(f)) = bytewise.next_frame() {
            again.push(f);
        }
    }
    assert_eq!(frames, again);

    // Any bytes as the body of each message type, too.
    let bodies = (1..=6).map(|kind| Frame { kind, body: data.to_vec() });
    for f in frames.iter().cloned().chain(bodies) {
        for ctx in [Context { four_octet_as: false }, Context { four_octet_as: true }] {
            match Message::decode(&f, &ctx) {
                // A message read can be written, and reads back the same.
                Ok(m) => {
                    let bytes = m.to_bytes(&ctx).unwrap();
                    let (back, used) = Frame::parse(&bytes).unwrap().unwrap();
                    assert_eq!(used, bytes.len());
                    assert_eq!(Message::decode(&back, &ctx), Ok(m));
                }
                // An error's notification can always be sent.
                Err(e) => {
                    let n = Message::Notification(e.notification());
                    assert!(n.to_bytes(&ctx).is_ok());
                }
            }
        }
    }
    // The body readers on their own, given bodies of any length: what
    // they read can be written, and their errors can be sent.
    let ctx = Context { four_octet_as: true };
    let read = [Open::parse(data).map(Message::Open), Update::parse(data, &ctx).map(Message::Update)];
    for r in read {
        match r {
            Ok(m) => assert!(m.to_bytes(&ctx).is_ok()),
            Err(e) => assert!(Message::Notification(e.notification()).to_bytes(&ctx).is_ok()),
        }
    }
});
