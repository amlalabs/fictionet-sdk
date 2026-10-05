//! DHCPv6 messages, as a world playing a DHCPv6 server reads them from UDP
//! datagrams and from TCP streams, and the answers it builds from them.
#![no_main]

use fictionet::stdlib::dhcpv6::{Decoder, Duid, MAX_MESSAGE, Message, msg};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The bytes as one datagram. A message read writes back the same
    // bytes, and so does any message it relays.
    if let Ok(m) = Message::parse(data) {
        assert_eq!(m.to_bytes(), data);
        let mut inner = m.relayed();
        // Each relay layer is shorter than the one around it, so this ends.
        while let Some(Ok(i)) = inner {
            let bytes = i.to_bytes();
            assert_eq!(Message::parse(&bytes).as_ref(), Ok(&i));
            inner = i.relayed();
        }
        // Answers built from it read back the same.
        let answer = m.answer(msg::REPLY, &Duid::en(32473, b"fuzz"));
        assert_eq!(Message::parse(&answer.to_bytes()).as_ref(), Ok(&answer));
        // A long Interface-Id can leave no room for the answer, so the
        // Relay-reply may lose its Relay Message. It still reads back.
        let reply = m.relay_reply(&answer).to_bytes();
        assert_eq!(Message::parse(&reply).map(|r| r.to_bytes()), Ok(reply));
        let forward = Message::relay_forward(&m, m.hop_count.wrapping_add(1), m.link_address, m.peer_address);
        let bytes = forward.to_bytes();
        assert!(bytes.len() <= MAX_MESSAGE);
        assert!(Message::parse(&bytes).is_ok());
    }

    // The bytes as a TCP stream, split two ways: all at once, and a byte
    // at a time. Both give the same messages and errors.
    let mut whole = Decoder::new();
    whole.feed(data);
    let messages: Vec<_> = std::iter::from_fn(|| whole.next_message()).collect();
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        bytewise.feed(std::slice::from_ref(b));
        while let Some(r) = bytewise.next_message() {
            again.push(r);
        }
    }
    assert_eq!(messages, again);
    assert_eq!(whole.buffered(), bytewise.buffered());
    for m in messages.into_iter().flatten() {
        let mut d = Decoder::new();
        d.feed(&m.to_tcp_bytes());
        assert_eq!(d.next_message(), Some(Ok(m)));
    }
});
