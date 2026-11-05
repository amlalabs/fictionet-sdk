//! MPTCP options, as a world playing a Multipath TCP host reads them from
//! the TCP headers a peer sends.
#![no_main]

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::mptcp::{Error, MAX_LEN, MptcpOption};
use fictionet::stdlib::test_support::assert_write;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The bytes as an option's data. An option read writes back at the
    // same length and reads back the same.
    if let Ok(value) = <MptcpOption as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    match MptcpOption::parse(data) {
        Ok(option) => {
            assert!(data.len() + 2 <= MAX_LEN);
            let bytes = option.to_bytes().unwrap();
            assert_eq!(bytes.len(), data.len());
            assert_eq!(bytes[0] >> 4, option.subtype());
        }
        Err(Error::TooLong(n)) => assert_eq!(n, data.len() + 2),
        Err(Error::NoSubtype) => assert!(data.is_empty()),
        Err(_) => {}
    }
    // Every prefix reads or fails without a panic.
    for n in 0..data.len().min(MAX_LEN) {
        if let Ok(value) = <MptcpOption as Wire>::parse(&data[..n]) {
            let _ = assert_write(&value);
        }
    }
});
