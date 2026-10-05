//! OpenVPN packets, as a world playing an OpenVPN server reads them from
//! UDP datagrams and TCP streams, and as it builds them to write.
#![no_main]

use fictionet::stdlib::openvpn::{
    Ack, Control, ControlBody, ControlKind, Decoder, EncodeError, Error, FrameError, MAX_HMAC_LEN, MAX_PACKET, Packet,
    TlsAuth, TlsCrypt, Wrapping, frame, split_first_byte, split_tcp,
};
use libfuzzer_sys::fuzz_target;

const WRAPPINGS: [Wrapping; 6] = [
    Wrapping::None,
    Wrapping::TlsAuth { hmac_len: 0 },
    Wrapping::TlsAuth { hmac_len: 20 },
    Wrapping::TlsAuth { hmac_len: 32 },
    Wrapping::TlsAuth { hmac_len: MAX_HMAC_LEN },
    Wrapping::TlsCrypt,
];

/// Feeds all of `bytes` in pieces of `step`, taking packets out as they
/// come, and returns them, the error included. The decoder never holds
/// more than its capacity.
fn split_stream(bytes: &[u8], step: usize) -> (Vec<Result<Vec<u8>, FrameError>>, usize) {
    let mut d = Decoder::new();
    let mut out = Vec::new();
    for mut piece in bytes.chunks(step) {
        loop {
            let before = out.len();
            let n = d.feed(piece);
            piece = &piece[n..];
            assert!(d.buffered() <= Decoder::CAPACITY);
            while let Some(p) = d.next_packet() {
                let failed = p.is_err();
                out.push(p);
                if failed {
                    return (out, d.buffered());
                }
            }
            if piece.is_empty() {
                break;
            }
            // Bytes were left over, so the decoder was full and must have
            // given a packet.
            assert!(n > 0 || out.len() > before);
        }
    }
    (out, d.buffered())
}

/// Reads fields for a built packet from the front of the input.
struct Fields<'a>(&'a [u8]);

impl Fields<'_> {
    fn u8(&mut self) -> u8 {
        let Some((&b, rest)) = self.0.split_first() else { return 0 };
        self.0 = rest;
        b
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }

    /// A length byte, times `scale`, and then that many bytes.
    fn sized(&mut self, scale: usize) -> Vec<u8> {
        let n = usize::from(self.u8()) * scale;
        self.bytes(n)
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let n = n.min(self.0.len());
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        head.to_vec()
    }
}

/// A packet built from the input's bytes, with fields in and out of range.
fn build(data: &[u8]) -> Packet {
    let mut f = Fields(data);
    let what = f.u8();
    let key_id = f.u8() % 10;
    let session_id = [f.u8(); 8];
    match what % 4 {
        0 => Packet::DataV1 { key_id, payload: f.sized(1) },
        1 => {
            let peer_id = f.u32() >> (f.u8() % 9);
            Packet::DataV2 { key_id, peer_id, payload: f.sized(1) }
        }
        2 => {
            let kind = ControlKind::ALL[usize::from(f.u8()) % ControlKind::ALL.len()];
            let tls_auth = f.u8().is_multiple_of(2).then(|| {
                let hmac_len = usize::from(f.u8() % 70);
                TlsAuth { hmac: f.bytes(hmac_len), packet_id: f.u32(), net_time: f.u32() }
            });
            let ack = f.u8().is_multiple_of(2).then(|| {
                let count = f.u8() % 11;
                Ack { ids: (0..count).map(|_| f.u32()).collect(), remote_session_id: [f.u8(); 8] }
            });
            let message_id = if f.u8().is_multiple_of(2) { 0 } else { f.u32() };
            let payload = f.sized(1);
            let c = Control { session_id, tls_auth, ack, message_id, payload };
            Packet::Control { kind, key_id, body: ControlBody::Plain(c) }
        }
        _ => {
            let kind = ControlKind::ALL[usize::from(f.u8()) % ControlKind::ALL.len()];
            let (packet_id, net_time) = (f.u32(), f.u32());
            let mut tag = [0; 32];
            tag.fill(f.u8());
            let ciphertext = f.sized(5);
            let c = TlsCrypt { session_id, packet_id, net_time, tag, ciphertext };
            Packet::Control { kind, key_id, body: ControlBody::TlsCrypt(c) }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // The bytes as one UDP datagram, read with each wrapping.
    for w in WRAPPINGS {
        if let Ok(p) = Packet::parse(data, w) {
            // A packet read is written back byte for byte.
            assert_eq!(p.to_bytes().as_deref(), Ok(data));
            assert_eq!(Packet::parse(data, p.wrapping()), Ok(p.clone()));
            let tcp = p.to_tcp_bytes().unwrap();
            let (inner, used) = split_tcp(&tcp).unwrap().unwrap();
            assert_eq!(inner, data);
            assert_eq!(used, tcp.len());
        }
    }

    // A wrapping with an HMAC too long refuses every control packet.
    let too_long = Wrapping::TlsAuth { hmac_len: MAX_HMAC_LEN + 1 };
    if let Some(&first) = data.first()
        && data.len() <= MAX_PACKET
        && ControlKind::from_opcode(split_first_byte(first).0).is_some()
    {
        assert_eq!(Packet::parse(data, too_long), Err(Error::HmacLen(MAX_HMAC_LEN + 1)));
    } else if let Ok(p) = Packet::parse(data, too_long) {
        assert_eq!(p.wrapping(), Wrapping::None);
    }

    // The bytes as a TCP stream, split two ways: all at once, and a byte at
    // a time. Both give the same packets, the same error and the same bytes
    // left over.
    let (packets, left) = split_stream(data, data.len().max(1));
    assert_eq!(split_stream(data, 1), (packets.clone(), left));

    for bytes in packets.iter().flatten() {
        // A packet taken from the stream frames back the same.
        let framed = frame(bytes).unwrap();
        assert_eq!(split_tcp(&framed), Ok(Some((&bytes[..], framed.len()))));
        for w in WRAPPINGS {
            if let Ok(p) = Packet::parse(bytes, w) {
                assert_eq!(p.to_bytes().as_ref(), Ok(bytes));
            }
        }
    }

    // A packet built from the bytes is written and read back as the same
    // value, or refused.
    let p = build(data);
    match p.to_bytes() {
        Ok(b) => {
            assert!(!b.is_empty() && b.len() <= MAX_PACKET);
            assert_eq!(Packet::parse(&b, p.wrapping()), Ok(p.clone()));
            assert_eq!(p.to_tcp_bytes().map(|t| t[2..].to_vec()), Ok(b));
        }
        Err(e) => {
            assert_eq!(p.to_tcp_bytes(), Err(e));
            if let EncodeError::KeyId(k) = e {
                assert!(k > 7);
            }
        }
    }
});
