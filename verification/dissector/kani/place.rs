//! Kani proofs over `Place::locate` in src/stdlib/dissect/present.rs, which
//! decides whether a decoded item points into the packet shown or gets a
//! buffer of its own. Compiled only under `cargo kani`, as a child module
//! of present.rs.

use super::*;

/// The longest item the harness places.
const ITEM: usize = 3;

/// For any run of stream bytes (its stream offset, buffer, offset in that
/// buffer, or none, and length) and any item (its stream offset and up to
/// three bytes), `locate` either points into the run, and then the item's
/// bytes are exactly bytes of the run at the same distance from its start,
/// or gives the item a new buffer holding exactly its bytes. A run with no
/// offset, which is how an end that comes in another packet or none is
/// placed, never points anywhere.
#[kani::proof]
#[kani::unwind(5)]
fn an_item_points_only_at_its_own_bytes() {
    let at = Place {
        stream_start: kani::any(),
        buf: kani::any(),
        offset: kani::any(),
        len: kani::any(),
    };
    let start: u64 = kani::any();
    let bytes: [u8; ITEM] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= ITEM);
    let mut packet = Decoded::default();
    let (buf, base) = at.locate(&mut packet, start, &bytes[..n], "item");
    if packet.extra.is_empty() {
        let offset = at.offset.unwrap();
        assert_eq!(buf, at.buf);
        let delta = start - at.stream_start;
        assert!(delta + n as u64 <= at.len as u64);
        assert_eq!((base - offset) as u64, delta);
        assert!(base.checked_add(n).is_some());
    } else {
        assert_eq!(packet.extra.len(), 1);
        assert_eq!((buf, base), (1, 0));
        assert!(packet.extra[0].1 == bytes[..n]);
    }
}
