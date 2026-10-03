//! The SOCKS5 proxy door (`fictionet attach --type socks5`), where the
//! agent is the client: the greeting, the username/password login and the
//! request, read from a stream in pieces of any size.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: fictionet_fuzz::doors::Input| fictionet_fuzz::doors::socks5(input));
