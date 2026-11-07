//! `signed_frame_prefix`: for every header, limit and input, the result is
//! exactly one of a complete frame whose payload is the input after the
//! header, a request for more bytes, or a refusal known from the header alone.

use super::bytes;
use fictionet::stdlib::codec::signed_frame_prefix;

#[kani::proof]
#[kani::unwind(10)]
fn signed_frame_prefix_partitions_every_input() {
    let (input, len) = bytes::<8>();
    let input = &input[..len];
    let limit: usize = kani::any();
    let result = signed_frame_prefix(input, limit, |length| length);
    let Some(header) = input.get(..4) else {
        assert_eq!(result, Ok(None));
        return;
    };
    let length = i32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    match result {
        Err(refused) => {
            assert_eq!(refused, length);
            assert!(length < 0 || usize::try_from(length).unwrap() > limit);
        }
        Ok(None) => {
            assert!(length >= 0);
            let payload = usize::try_from(length).unwrap();
            assert!(payload <= limit);
            assert!(len < 4 + payload);
        }
        Ok(Some((payload, used))) => {
            assert!(length >= 0);
            let declared = usize::try_from(length).unwrap();
            assert!(declared <= limit);
            assert_eq!(used, 4 + declared);
            assert!(used <= len);
            assert_eq!(payload, &input[4..used]);
        }
    }
}
