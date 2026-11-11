use super::*;

#[kani::proof]
fn datagram_wire_limits_are_independent_of_storage() {
    let encoded_size: usize = kani::any();
    let window: Option<usize> = kani::any();
    let result = receive_window(encoded_size, window);
    let permitted = match window {
        Some(limit) => limit != 0 && encoded_size <= limit && encoded_size <= u16::MAX as usize,
        None => false,
    };
    assert_eq!(result.is_ok(), permitted);
    if let Ok(limit) = result {
        assert_eq!(Some(limit), window);
    }
}
