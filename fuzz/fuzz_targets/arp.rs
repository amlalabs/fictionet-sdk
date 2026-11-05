//! ARP packets for IPv4 over Ethernet, as a host or router on the link
//! reads them.
#![no_main]

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::arp::{LEN, Packet};
use fictionet::stdlib::test_support::assert_write;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = <Packet as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(p) = Packet::receive(data) {
        // A packet read writes back as the bytes it came from.
        assert_eq!(&p.encode()[..], &data[..LEN]);
        assert_eq!(Packet::parse(&data[..LEN]), Ok(p));
    }
});
