//! OpenVPN packets, as a world playing an OpenVPN server reads them from
//! UDP datagrams and TCP streams, and as it builds them to write.
#![no_main]

use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{Decode, Wire};
use fictionet::stdlib::openvpn::Frame;
use fictionet::stdlib::openvpn::{
    Ack, Authenticated, Control, ControlBody, ControlKind, Encrypted, Error, MAX_HMAC_LEN,
    MAX_PACKET, MAX_TCP_FRAME, Packet, TlsAuth, TlsCrypt, Wrapping, split_first_byte,
};
use fictionet::stdlib::test_support::contract;
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
    contract::check_decode_with_alloc_limit(Frames::<Frame>::new, data, 2 * MAX_TCP_FRAME);
    contract::check_decode_with_alloc_limit(
        || Frames::<Frame>::with_limit(usize::from(data.first().copied().unwrap_or(0))),
        data,
        514,
    );
    contract::check_wire::<Frame>(data);
    contract::check_wire::<Packet>(data);
    contract::check_wire::<Authenticated<0>>(data);
    contract::check_wire::<Authenticated<20>>(data);
    contract::check_wire::<Authenticated<32>>(data);
    contract::check_wire::<Authenticated<64>>(data);
    contract::check_wire::<Encrypted>(data);
    contract::check_wire_value(&Frame(data[..data.len().min(MAX_PACKET + 1)].to_vec()));
    for wrapping in WRAPPINGS {
        contract::check_decode_with_alloc_limit(
            || Frames::<Frame>::new().map(|frame| Packet::parse_with(&frame.0, wrapping)),
            data,
            2 * MAX_TCP_FRAME,
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
    contract::check_wire_value(&packet);
    contract::check_wire_value(&Authenticated::<0>(packet.clone()));
    contract::check_wire_value(&Authenticated::<20>(packet.clone()));
    contract::check_wire_value(&Authenticated::<32>(packet.clone()));
    contract::check_wire_value(&Authenticated::<64>(packet.clone()));
    contract::check_wire::<Authenticated<65>>(data);
    contract::check_wire_value(&Authenticated::<65>(packet.clone()));
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
    contract::check_wire_value(&Encrypted(packet));
});
