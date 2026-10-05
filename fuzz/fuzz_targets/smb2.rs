//! SMB2 frames, compound chains and bodies, as a world playing a file
//! server on port 445 reads them, and values built from the bytes, as a
//! world writes them.
#![no_main]

use fictionet::stdlib::smb2::{
    ChainedPayload, Compressed, Decoder, ErrorResponse, FrameError, HEADER_LEN, IoctlResponse, MAX_BUFFERED,
    MAX_MESSAGE, NegotiateContext, NegotiateResponse, Packet, ReadRequest, Request, Response, Transform,
    TreeConnectRequest, WriteRequest, command, frame, parse_chain, parse_frame, status,
};
use libfuzzer_sys::fuzz_target;

/// Feeds `data` whole or a byte at a time, taking payloads out after each
/// feed, as a world does. Every payload, then the error that broke the
/// stream, if one did. The chunks are walked, not collected, so a large
/// input costs no more than itself.
fn split(data: &[u8], bytewise: bool) -> (Vec<Vec<u8>>, Option<FrameError>) {
    let mut decoder = Decoder::new();
    let mut payloads = Vec::new();
    for chunk in data.chunks(if bytewise { 1 } else { data.len().max(1) }) {
        let mut rest = chunk;
        while !rest.is_empty() {
            let took = decoder.feed(rest);
            assert!(decoder.buffered() <= MAX_BUFFERED);
            rest = &rest[took..];
            let mut progress = took > 0;
            while let Some(r) = decoder.next_frame() {
                match r {
                    Ok(p) => payloads.push(p),
                    Err(e) => return (payloads, Some(e)),
                }
                progress = true;
            }
            // A full decoder always gives a payload or an error.
            assert!(progress);
        }
    }
    (payloads, None)
}

/// Whether a body written back is no longer than the one read, or no
/// longer than its own StructureSize. Then a message read whole always fits
/// MAX_MESSAGE when written back. A CREATE may grow by 7 bytes, when its
/// last create context put its data before its name.
fn no_longer(command: u16, new: &[u8], old: &[u8]) -> bool {
    let slack = if command == command::CREATE { 7 } else { 0 };
    new.len() <= old.len() + slack
        || new.get(..2).is_some_and(|s| new.len() <= usize::from(u16::from_le_bytes([s[0], s[1]])))
}

/// A payload read every way there is. Whatever reads is written back, and
/// reads back the same. A compound chain writes back byte for byte.
fn payload(data: &[u8], status: u32) {
    let Ok(packet) = Packet::parse(data) else { return };
    let bytes = packet.to_bytes().unwrap();
    assert!(bytes.len() <= MAX_MESSAGE);
    assert_eq!(Packet::parse(&bytes), Ok(packet.clone()));
    let Packet::Smb2(messages) = packet else { return };
    assert_eq!(bytes, data);
    for m in &messages {
        if let Ok(req) = m.request() {
            let body = req.to_body().unwrap();
            assert!(no_longer(m.header.command, &body, &m.body));
            assert_eq!(Request::parse(m.header.command, &body), Ok(req));
        }
        for s in [m.header.status, status] {
            if let Ok(resp) = Response::parse(m.header.command, s, &m.body) {
                let body = resp.to_body(m.header.command, s).unwrap();
                assert!(no_longer(m.header.command, &body, &m.body));
                assert_eq!(Response::parse(m.header.command, s, &body), Ok(resp));
            }
        }
    }
}

/// The public readers called directly, not through Packet::parse: each
/// refuses a payload past MAX_MESSAGE, and what each reads writes back the
/// same.
fn entry_points(data: &[u8]) {
    let too_long = data.len() > MAX_MESSAGE;
    if let Ok(messages) = parse_chain(data) {
        assert!(!too_long);
        assert_eq!(Packet::Smb2(messages).to_bytes().unwrap(), data);
    }
    if let Ok(t) = Transform::parse(data) {
        assert!(!too_long);
        assert_eq!(t.flags, 1);
        assert!(!t.data.is_empty());
        assert_eq!(Transform::parse(&t.to_bytes().unwrap()), Ok(t));
    }
    if let Ok(c) = Compressed::parse(data) {
        assert!(!too_long);
        assert_eq!(Compressed::parse(&c.to_bytes().unwrap()), Ok(c));
    }
}

/// Bytes read as a body alone, under a command and status taken from the
/// first bytes.
fn body(data: &[u8]) {
    let [c, s, rest @ ..] = data else { return };
    let command = u16::from(*c % 0x16);
    let status = [0, 0x8000_0005, 0xc000_0016, 0xc000_0022, 0x103, 0x10c, 0xc000_000d][usize::from(*s % 7)];
    if let Ok(req) = Request::parse(command, rest) {
        let back = req.to_body().unwrap();
        assert!(no_longer(command, &back, rest));
        assert_eq!(Request::parse(command, &back), Ok(req));
    }
    if let Ok(resp) = Response::parse(command, status, rest) {
        let back = resp.to_body(command, status).unwrap();
        assert!(no_longer(command, &back, rest));
        assert_eq!(Response::parse(command, status, &back), Ok(resp));
    }
}

/// Reads the next `n` bytes of `data`, or zeros past its end.
struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn take(&mut self, n: usize) -> Vec<u8> {
        let n = n.min(self.0.len());
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        head.to_vec()
    }

    fn byte(&mut self) -> u8 {
        self.take(1).first().copied().unwrap_or(0)
    }

    fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.byte(), self.byte()])
    }
}

/// Values a world might build, from the bytes, not from a reader. Each the
/// writer takes must read back the same, and the layouts MS-SMB2 fixes are
/// checked against the specification directly, not against this module's
/// reader.
fn constructed(data: &[u8]) {
    let mut b = Bytes(data);
    let mut lens = || usize::from(b.byte() % 24);
    let (input_len, output_len, info_len, name_len) = (lens(), lens(), lens(), lens());
    let mut b = Bytes(data.get(4..).unwrap_or_default());

    // 2.2.32: the output starts at InputOffset + InputCount rounded up to 8.
    let ioctl = Response::Ioctl(IoctlResponse {
        ctl_code: 1,
        input: b.take(input_len),
        output: b.take(output_len),
        ..Default::default()
    });
    let s = [0, status::BUFFER_OVERFLOW, status::INVALID_PARAMETER][usize::from(b.byte() % 3)];
    if let Ok(body) = ioctl.to_body(command::IOCTL, s) {
        let at = |i: usize| u32::from_le_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]);
        if at(36) != 0 {
            assert_eq!(at(32), (at(24) + at(28)).next_multiple_of(8));
        }
        assert_eq!(Response::parse(command::IOCTL, s, &body), Ok(ioctl));
    }

    // 2.2.2: error data holds the error contexts its count claims.
    let error = Response::Error(ErrorResponse { context_count: b.byte() % 4, data: b.take(name_len * 2) });
    if let Ok(body) = error.to_body(command::CREATE, status::ACCESS_DENIED) {
        assert_eq!(Response::parse(command::CREATE, status::ACCESS_DENIED, &body), Ok(error));
    }

    // 2.2.42.2.1: payloads that need OriginalPayloadSize have its 4 bytes.
    let chained = Compressed::Chained {
        original_size: 1,
        payloads: vec![ChainedPayload { algorithm: u16::from(b.byte() % 7), flags: 1, data: b.take(info_len % 8) }],
    };
    if let Ok(bytes) = chained.to_bytes() {
        assert_eq!(Compressed::parse(&bytes), Ok(chained));
    }

    // 2.2.41: a transform header has flags 1 and a message after it.
    let transform = Transform { flags: b.u16() % 3, data: b.take(info_len % 3), ..Default::default() };
    match transform.to_bytes() {
        Ok(bytes) => assert_eq!(Packet::parse(&bytes), Ok(Packet::Transform(transform))),
        Err(_) => assert!(transform.flags != 1 || transform.data.is_empty()),
    }

    // 2.2.9.1: an extended TREE_CONNECT puts the path after the extension.
    let path = b.take(name_len * 2).chunks(2).map(|c| u16::from(c[0])).collect();
    let tree = Request::TreeConnect(TreeConnectRequest { flags: b.u16() % 8, path });
    let body = tree.to_body().unwrap();
    assert_eq!(Request::parse(command::TREE_CONNECT, &body), Ok(tree));

    // 2.2.19 and 2.2.21: channel information only with a channel.
    let channel = u32::from(b.byte() % 3);
    let info = b.take(info_len);
    let read = Request::Read(ReadRequest { channel, channel_info: info.clone(), ..Default::default() });
    let write = Request::Write(WriteRequest {
        channel,
        channel_info: info.clone(),
        data: b.take(input_len),
        ..Default::default()
    });
    for req in [read, write] {
        match req.to_body() {
            Ok(body) => assert_eq!(Request::parse(req.command(), &body), Ok(req)),
            Err(_) => assert!(channel == 0 && !info.is_empty()),
        }
    }

    // 3.2.5.2: an SMB 3.1.1 response carries one preauth context.
    let kinds: Vec<u16> = b.take(3).iter().map(|k| u16::from(k % 4)).collect();
    let contexts = kinds.iter().map(|&kind| NegotiateContext { kind, data: vec![1, 0] }).collect();
    let negotiate = Response::Negotiate(NegotiateResponse { dialect: 0x311, contexts, ..Default::default() });
    if let Ok(body) = negotiate.to_body(command::NEGOTIATE, 0) {
        assert_eq!(kinds.iter().filter(|&&k| k == 1).count(), 1);
        assert_eq!(Response::parse(command::NEGOTIATE, 0, &body), Ok(negotiate));
    }
}

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time. Both
    // give the same payloads and the same error.
    let (payloads, err) = split(data, false);
    assert_eq!(split(data, true), (payloads.clone(), err));
    for p in &payloads {
        // A payload read can be framed, and reads back the same.
        let bytes = frame(p).unwrap();
        assert_eq!(parse_frame(&bytes), Ok(Some((&p[..], bytes.len()))));
        payload(p, 0);
    }
    // Any bytes as a payload on their own, through each reader, and as a
    // body.
    payload(data, 0xc000_0016);
    entry_points(data);
    body(data);
    if data.len() > HEADER_LEN {
        body(&data[HEADER_LEN - 2..]);
    }
    // Values built from the bytes.
    constructed(data);
});
