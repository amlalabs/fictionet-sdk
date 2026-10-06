//! Compile the mail modules in a consumer crate with a sibling codec.

use fictionet::stdlib::codec::{self, Wire};

#[allow(dead_code)]
#[path = "../src/stdlib/imap.rs"]
mod imap;
#[allow(dead_code)]
#[path = "../src/stdlib/pop3.rs"]
mod pop3;
#[allow(dead_code)]
#[path = "../src/stdlib/smtp.rs"]
mod smtp;

#[test]
fn copied_modules_use_the_sibling_codec() {
    assert_eq!(
        smtp::Reply::new(250, "Queued").to_bytes().unwrap(),
        b"250 Queued\r\n"
    );
    assert_eq!(
        pop3::Reply::ok("ready").to_bytes().unwrap(),
        b"+OK ready\r\n"
    );
    assert_eq!(
        imap::Response::greeting("ready").to_bytes().unwrap(),
        b"* OK ready\r\n"
    );
}
