//! Kani proofs over the checksum flags of the core `Packet`. Compiled only
//! under `cargo kani -p fictionet`, as a child module of `src/packet.rs`,
//! which is the only module that can set a flag.

use super::*;

/// What a step did to the packet.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    /// The stack marked it verified.
    Verified,
    /// `make_mut` changed a byte.
    Edit,
    /// `header_mut` changed a byte of the IP header.
    HeaderEdit,
    /// It was cloned, or taken apart into its chunk and made again.
    Moved,
}

/// After any three steps of verifying, editing, editing the header,
/// cloning and taking the chunk out and back, a flag is set only if the
/// stack set it and no later edit could have changed what it covers: any
/// `make_mut` clears both flags, `header_mut` clears `ip_header` and keeps
/// `transport`, and moving the packet keeps both. Equality ignores flags,
/// and an edit that changed a byte changes the bytes compared.
#[kani::proof]
#[kani::unwind(5)]
fn checksum_flags_clear_on_any_byte_change() {
    let budget = Budget::new(64);
    let bytes: [u8; 2] = kani::any();
    let mut packet = Packet::new(bytes.to_vec());
    let mut ip_header = false;
    let mut transport = false;
    for _ in 0..3 {
        let step = match kani::any::<u8>() % 4 {
            0 => Step::Verified,
            1 => Step::Edit,
            2 => Step::HeaderEdit,
            _ => Step::Moved,
        };
        match step {
            Step::Verified => {
                let set = Checksums {
                    ip_header: kani::any(),
                    transport: kani::any(),
                };
                packet = Packet::verified(packet.into_chunk(), set);
                (ip_header, transport) = (set.ip_header, set.transport);
            }
            Step::Edit => {
                let before = packet.clone();
                let value: u8 = kani::any();
                let edited = packet.make_mut(&budget).unwrap();
                edited[0] = value;
                assert_eq!(packet == before, before[0] == value);
                assert_eq!(
                    before.checksums(),
                    Checksums {
                        ip_header,
                        transport
                    }
                );
                (ip_header, transport) = (false, false);
            }
            Step::HeaderEdit => {
                let value: u8 = kani::any();
                packet.header_mut(&budget).unwrap()[0] = value;
                ip_header = false;
            }
            Step::Moved => {
                if kani::any() {
                    packet = packet.clone();
                } else {
                    let flags = packet.checksums();
                    packet = Packet::verified(packet.into_chunk(), flags);
                }
            }
        }
        assert_eq!(
            packet.checksums(),
            Checksums {
                ip_header,
                transport
            }
        );
    }
    // A packet made from outside carries no flag, whatever its bytes.
    assert_eq!(
        Packet::from_chunk(packet.into_chunk()).checksums(),
        Checksums::default()
    );
}
