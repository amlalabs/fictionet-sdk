//! DHCPv6 messages, as a world playing a DHCPv6 server reads them from UDP
//! datagrams and from TCP streams, and the answers it builds from them.
#![no_main]

use fictionet::stdlib::dhcpv6::{Decoder, Duid, HOP_COUNT_LIMIT, MAX_BUFFERED, MAX_MESSAGE, Message, msg};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The bytes as one datagram. A message read writes back the same
    // bytes, and so does any message it relays.
    if let Ok(m) = Message::parse(data) {
        assert_eq!(m.to_bytes(), data);
        // Each relay layer is shorter than the one around it, so this ends;
        // like a server, it stops after a few more layers than relay agents
        // pass on, since each one reads the inner bytes again.
        let mut inner = m.relayed();
        for _ in 0..4 * usize::from(HOP_COUNT_LIMIT) {
            let Some(Ok(i)) = inner else { break };
            let bytes = i.to_bytes();
            assert_eq!(Message::parse(&bytes).as_ref(), Ok(&i));
            assert_eq!(i.try_to_bytes(), Some(bytes));
            inner = i.relayed();
        }
        // Answers built from it read back the same.
        let answer = m.answer(msg::REPLY, &Duid::en(32473, b"fuzz"));
        assert_eq!(Message::parse(&answer.to_bytes()).as_ref(), Ok(&answer));
        assert_eq!(answer.try_to_bytes(), Some(answer.to_bytes()));
        // A long Interface-Id can leave no room for the answer, so the
        // Relay-reply may lose its Relay Message. It still reads back, and
        // when the checked writer gives bytes, they carry the answer.
        let relay_reply = m.relay_reply(&answer);
        let reply = relay_reply.to_bytes();
        if let Some(checked) = relay_reply.try_to_bytes() {
            assert_eq!(checked, reply);
            assert_eq!(Message::parse(&reply).ok().and_then(|r| r.relayed()), Some(Ok(answer.clone())));
        }
        assert_eq!(Message::parse(&reply).map(|r| r.to_bytes()), Ok(reply));
        let forward = Message::relay_forward(&m, m.hop_count.wrapping_add(1), m.link_address, m.peer_address);
        let bytes = forward.to_bytes();
        assert!(bytes.len() <= MAX_MESSAGE);
        assert!(Message::parse(&bytes).is_ok());
    }

    // The bytes as a TCP stream, split two ways: in pieces as large as the
    // decoder takes, and a byte at a time. Both give the same messages and
    // errors.
    let mut whole = Decoder::new();
    let mut messages = Vec::new();
    let mut fed = 0;
    loop {
        fed += whole.feed(&data[fed..]);
        assert!(whole.buffered() <= MAX_BUFFERED);
        let before = messages.len();
        messages.extend(std::iter::from_fn(|| whole.next_message()));
        if messages.len() == before {
            break;
        }
    }
    assert_eq!(fed, data.len());
    let mut bytewise = Decoder::new();
    let mut again = Vec::new();
    for b in data {
        assert_eq!(bytewise.feed(std::slice::from_ref(b)), 1);
        while let Some(r) = bytewise.next_message() {
            again.push(r);
        }
    }
    assert_eq!(messages, again);
    assert_eq!(whole.buffered(), bytewise.buffered());
    for m in messages.into_iter().flatten() {
        let mut d = Decoder::new();
        let framed = m.to_tcp_bytes();
        assert_eq!(d.feed(&framed), framed.len());
        assert_eq!(d.next_message(), Some(Ok(m)));
    }
});
