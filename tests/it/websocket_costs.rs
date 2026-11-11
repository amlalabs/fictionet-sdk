//! WebSocket messages in fragments, every decoding step costed
//! (verification/README.md, "Resource properties"; the bounds are in
//! verification/websocket/README.md, "Resource properties").
//!
//! Each session is one [`Messages`] decoder taking one message, then a
//! second, as fragments of the sizes below, every split of each message
//! into up to four fragments. A step is one frame through `decode`. Its
//! charge is what the decoder says it holds before the step (`held()`),
//! and the step's own is its scratch: the frame's payload, copied out of
//! the input, and a new allocation for the message, at most the limit,
//! while the old one is live. The step may ask for no more than its
//! payload and the limit.

use crate::common::cost::{Charged, Costs, Linear};
use fictionet::stdlib::codec::{Decode, Side, Step};
use fictionet::stdlib::protocols::websocket::Messages;

/// The decoder's limit.
const LIMIT: usize = 64;

/// Fragment sizes: empty, small, around half and the whole limit.
const SIZES: [usize; 7] = [0, 1, 3, 7, 16, 33, 64];

/// An unmasked frame from a server: opcode, FIN and `len` bytes.
fn frame(opcode: u8, fin: bool, len: usize) -> Vec<u8> {
    let mut bytes = vec![opcode | if fin { 0x80 } else { 0 }, len as u8];
    bytes.resize(2 + len, b'a');
    bytes
}

/// Every split into up to four fragments that fits the limit.
fn splits() -> Vec<Vec<usize>> {
    let mut all = Vec::new();
    let mut next = vec![Vec::new()];
    for _ in 0..4 {
        let mut longer = Vec::new();
        for split in &next {
            for size in SIZES {
                let mut split: Vec<usize> = split.clone();
                split.push(size);
                if split.iter().sum::<usize>() <= LIMIT {
                    all.push(split.clone());
                    longer.push(split);
                }
            }
        }
        next = longer;
    }
    all
}

#[test]
fn message_fragments_stay_within_their_charge_and_copy_linearly() {
    let mut all = Costs::new("websocket messages");
    let splits = splits();
    for (i, split) in splits.iter().enumerate() {
        // Text and binary alike: the opcode does not change the storage.
        let opcode = if i % 2 == 0 { 0x1 } else { 0x2 };
        let frames: Vec<Vec<u8>> = (0..2)
            .flat_map(|_| {
                split.iter().enumerate().map(|(at, &len)| {
                    frame(
                        if at == 0 { opcode } else { 0x0 },
                        at + 1 == split.len(),
                        len,
                    )
                })
            })
            .collect();
        let mut costs = Costs::new(format!("websocket fragments {split:?}"));
        let mut decoder = costs.step(
            0,
            0,
            Linear {
                num: 0,
                den: 1,
                fixed: 0,
            },
            || Charged {
                value: Messages::for_receiver(Side::Client).with_limit(LIMIT),
                charged: 0,
                moved: 0,
            },
        );
        for bytes in &frames {
            let held = decoder.held();
            let payload = bytes.len() - 2;
            let scratch = Linear {
                num: 1,
                den: 1,
                fixed: LIMIT,
            };
            let step = costs.step(payload, held, scratch, || {
                let step = decoder.decode(bytes, false);
                // What the step hands out is the receiver's.
                let step = step.map(|step| matches!(step, Step::Item(..)));
                Charged {
                    value: step,
                    charged: payload + LIMIT,
                    moved: 0,
                }
            });
            assert!(step.is_ok(), "{split:?}: {step:?}");
            assert!(decoder.held() <= LIMIT, "{split:?}: held() past the limit");
        }
        all.absorb(&costs);
    }
    println!("cost: {}", all.summary());
}
