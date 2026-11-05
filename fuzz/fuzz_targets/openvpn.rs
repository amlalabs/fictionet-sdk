//! OpenVPN packets, as a world playing an OpenVPN server reads them from
//! UDP datagrams and TCP streams, and as it builds them to write.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Stream;
use fictionet::stdlib::codec::{Decode, Wire};
use fictionet::stdlib::protocols::openvpn::Frame;
use fictionet::stdlib::protocols::openvpn::{
    Ack, Authenticated, Control, ControlBody, ControlKind, Encrypted, Error, MAX_HMAC_LEN,
    MAX_PACKET, MAX_TCP_FRAME, Packet, TlsAuth, TlsCrypt, Wrapping, split_first_byte,
};
use fictionet::stdlib::test_support::{assert_write, chunks, decode_all, decode_chunks};
use libfuzzer_sys::fuzz_target;

const WRAPPINGS: [Wrapping; 6] = [
    Wrapping::None,
    Wrapping::TlsAuth { hmac_len: 0 },
    Wrapping::TlsAuth { hmac_len: 20 },
    Wrapping::TlsAuth { hmac_len: 32 },
    Wrapping::TlsAuth {
        hmac_len: MAX_HMAC_LEN,
    },
    Wrapping::TlsCrypt,
];

/// Reads fields for a built packet from the front of the input.
struct Fields<'a>(&'a [u8]);

impl Fields<'_> {
    fn u8(&mut self) -> u8 {
        let Some((&b, rest)) = self.0.split_first() else {
            return 0;
        };
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
        0 => Packet::DataV1 {
            key_id,
            payload: f.sized(1),
        },
        1 => {
            let peer_id = f.u32() >> (f.u8() % 9);
            Packet::DataV2 {
                key_id,
                peer_id,
                payload: f.sized(1),
            }
        }
        2 => {
            let kind = ControlKind::ALL[usize::from(f.u8()) % ControlKind::ALL.len()];
            let tls_auth = f.u8().is_multiple_of(2).then(|| {
                let hmac_len = usize::from(f.u8() % 70);
                TlsAuth {
                    hmac: f.bytes(hmac_len),
                    packet_id: f.u32(),
                    net_time: f.u32(),
                }
            });
            let ack = f.u8().is_multiple_of(2).then(|| {
                let count = f.u8() % 11;
                Ack {
                    ids: (0..count).map(|_| f.u32()).collect(),
                    remote_session_id: [f.u8(); 8],
                }
            });
            let message_id = if f.u8().is_multiple_of(2) { 0 } else { f.u32() };
            let payload = f.sized(1);
            let c = Control {
                session_id,
                tls_auth,
                ack,
                message_id,
                payload,
            };
            Packet::Control {
                kind,
                key_id,
                body: ControlBody::Plain(c),
            }
        }
        _ => {
            let kind = ControlKind::ALL[usize::from(f.u8()) % ControlKind::ALL.len()];
            let (packet_id, net_time) = (f.u32(), f.u32());
            let mut tag = [0; 32];
            tag.fill(f.u8());
            let ciphertext = f.sized(5);
            let c = TlsCrypt {
                session_id,
                packet_id,
                net_time,
                tag,
                ciphertext,
            };
            Packet::Control {
                kind,
                key_id,
                body: ControlBody::TlsCrypt(c),
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Frame>::new()),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 2 * MAX_TCP_FRAME);
            }
        ),
        decode_all(Frames::<Frame>::new, data),
    );
    assert_eq!(
        decode_chunks(
            &mut Stream::new(Frames::<Frame>::with_limit(usize::from(
                data.first().copied().unwrap_or(0)
            ))),
            chunks(data, &[1, 7, 64]),
            |s| {
                assert!(s.allocated() <= 514);
            }
        ),
        decode_all(
            || Frames::<Frame>::with_limit(usize::from(data.first().copied().unwrap_or(0))),
            data
        ),
    );
    if let Ok(value) = <Frame as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Packet as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Authenticated<0> as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Authenticated<20> as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Authenticated<32> as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Authenticated<64> as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    if let Ok(value) = <Encrypted as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let _ = assert_write(&Frame(data[..data.len().min(MAX_PACKET + 1)].to_vec()));
    for wrapping in WRAPPINGS {
        assert_eq!(
            decode_chunks(
                &mut Stream::new(
                    Frames::<Frame>::new().map(|frame| Packet::parse_with(&frame.0, wrapping))
                ),
                chunks(data, &[1, 7, 64]),
                |s| {
                    assert!(s.allocated() <= 2 * MAX_TCP_FRAME);
                }
            ),
            decode_all(
                || Frames::<Frame>::new().map(|frame| Packet::parse_with(&frame.0, wrapping)),
                data
            ),
        );
    }
    for wrapping in [Wrapping::None, Wrapping::TlsCrypt]
        .into_iter()
        .chain((0..=MAX_HMAC_LEN).map(|hmac_len| Wrapping::TlsAuth { hmac_len }))
    {
        if let Ok(packet) = Packet::parse_with(data, wrapping) {
            let mut bytes = Vec::new();
            packet.write_with(wrapping, &mut bytes).unwrap();
            assert_eq!(bytes, data);
        }
    }
    let too_long = Wrapping::TlsAuth {
        hmac_len: MAX_HMAC_LEN + 1,
    };
    if let Ok(packet) = Packet::parse_with(data, too_long) {
        assert_eq!(packet.wrapping(), Wrapping::None);
        assert_eq!(packet.to_bytes().unwrap(), data);
    }
    if let Some(&first) = data.first()
        && data.len() <= MAX_PACKET
        && ControlKind::from_opcode(split_first_byte(first).0).is_some()
    {
        assert_eq!(
            Packet::parse_with(data, too_long),
            Err(Error::HmacLen(MAX_HMAC_LEN + 1))
        );
    }
    let packet = build(data);
    let _ = assert_write(&packet);
    let _ = assert_write(&Authenticated::<0>(packet.clone()));
    let _ = assert_write(&Authenticated::<20>(packet.clone()));
    let _ = assert_write(&Authenticated::<32>(packet.clone()));
    let _ = assert_write(&Authenticated::<64>(packet.clone()));
    if let Ok(value) = <Authenticated<65> as Wire>::parse(data) {
        let _ = assert_write(&value);
    }
    let _ = assert_write(&Authenticated::<65>(packet.clone()));
    for wrapping in WRAPPINGS.into_iter().chain([packet.wrapping(), too_long]) {
        let mut bytes = Vec::new();
        let result = packet.write_with(wrapping, &mut bytes);
        let mut appended = vec![0xa5, 0x5a];
        assert_eq!(packet.write_with(wrapping, &mut appended), result);
        assert_eq!(&appended[..2], &[0xa5, 0x5a]);
        match result {
            Ok(()) => {
                assert_eq!(&appended[2..], bytes);
                assert_eq!(Packet::parse_with(&bytes, wrapping), Ok(packet.clone()));
            }
            Err(error) => {
                assert_eq!(error, Error::Unwritable);
                assert!(bytes.is_empty());
                assert_eq!(appended.len(), 2);
            }
        }
    }
    let _ = assert_write(&Encrypted(packet));
});
