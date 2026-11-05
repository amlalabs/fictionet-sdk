//! DHCPv6 messages, as a world playing a DHCPv6 server reads them from UDP
//! datagrams and from TCP streams, and the answers it builds from them.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::dhcpv6::{
    DhcpOption, Duid, Frame, HOP_COUNT_LIMIT, MAX_BUFFERED, MAX_MESSAGE, Message, msg,
};
use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::test_support::{assert_write, chunks, decode_chunks};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Message>::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_BUFFERED);
            }
        ),
        decode_all(Frames::<Message>::new, data),
    );
    if let Ok(value) = <Duid as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Message as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Frame as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let mut built = Message::new(data.first().copied().unwrap_or(1), 7);
    built.transaction = u32::MAX;
    built.options.push(DhcpOption::Other {
        code: u16::from(data.first().copied().unwrap_or(0)),
        data: data.iter().take(MAX_MESSAGE + 1).copied().collect(),
    });
    let _ = assert_write(&built);
    built.transaction = 7;
    let _ = assert_write(&Frame(built));
    // The bytes as one datagram. A message read writes back the same
    // bytes, and so does any message it relays.
    if let Ok(m) = Message::parse(data) {
        assert_eq!(m.to_bytes().unwrap(), data);
        // Each relay layer is shorter than the one around it, so this ends;
        // like a server, it stops after a few more layers than relay agents
        // pass on, since each one reads the inner bytes again.
        let mut inner = m.relayed();
        for _ in 0..4 * usize::from(HOP_COUNT_LIMIT) {
            let Some(Ok(i)) = inner else { break };
            let bytes = i.to_bytes().unwrap();
            assert_eq!(Message::parse(&bytes).as_ref(), Ok(&i));
            let _ = assert_write(&i);
            inner = i.relayed();
        }
        // Answers built from it read back the same.
        let answer = m.answer(msg::REPLY, &Duid::en(32473, b"fuzz"));
        let _ = assert_write(&answer);
        if let Ok(relay_reply) = m.relay_reply(&answer) {
            let _ = assert_write(&relay_reply);
            if let Ok(bytes) = relay_reply.to_bytes() {
                assert_eq!(Message::parse(&bytes).unwrap().relayed(), Some(Ok(answer)));
            }
        }
        let forward = Message::relay_forward(
            &m,
            m.hop_count.saturating_add(1),
            m.link_address,
            m.peer_address,
        )
        .unwrap();
        let _ = assert_write(&forward);
    }
    for message in decode_all(Frames::<Message>::new, data)
        .0
        .into_iter()
        .flatten()
    {
        let _ = assert_write(&Frame(message));
    }
});
