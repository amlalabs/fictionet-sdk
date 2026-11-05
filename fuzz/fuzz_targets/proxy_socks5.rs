//! The SOCKS5 proxy door (`fictionet attach --type socks5`), where the
//! agent is the client: the greeting, the username/password login and the
//! request, read from a stream in pieces of any size.
#![no_main]

use fictionet::stdlib::codec::{Stream, Wire};
use fictionet::stdlib::protocols::socks::{
    AuthRequest, ClientMessages, Greeting, MAX_MESSAGE, Request,
};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_all, decode_chunks};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: fictionet_fuzz::doors::Input| {
    assert_eq!(
        decode_chunks(
            &mut Stream::new(ClientMessages::new()),
            chunks(&input.bytes, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_MESSAGE);
            }
        ),
        decode_all(ClientMessages::new, &input.bytes),
    );
    if let Ok(value) = <Greeting as Wire>::parse(&input.bytes) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <AuthRequest as Wire>::parse(&input.bytes) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Request as Wire>::parse(&input.bytes) {
        let _ = assert_write(&value);
    }
    fictionet_fuzz::doors::socks5(input);
});
