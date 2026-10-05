//! RADIUS packets, attributes and their values, as a world playing a
//! RADIUS server reads them, and packets and values built from the bytes,
//! as a world writes them.
#![no_main]

use std::net::{Ipv4Addr, Ipv6Addr};

use fictionet::stdlib::radius::{
    Attribute, Code, DataType, Decoder, Evs, Extended, MAX_BUFFERED, MAX_PACKET, MAX_VALUE, Packet, PacketError,
    RESERVED_EXTENDED_TYPES, TooLong, Value, Vsa,
};
use libfuzzer_sys::fuzz_target;

/// Feeds `data` in chunks, taking packets out after each feed, as a world
/// does. Every packet, then the error that broke the stream, if one did.
fn split(data: &[u8], bytewise: bool) -> (Vec<Packet>, Option<PacketError>) {
    let mut decoder = Decoder::new();
    let mut packets = Vec::new();
    let chunks: Vec<&[u8]> = if bytewise { data.chunks(1).collect() } else { vec![data] };
    for chunk in chunks {
        let mut rest = chunk;
        while !rest.is_empty() {
            let took = decoder.feed(rest);
            assert!(decoder.buffered() <= MAX_BUFFERED);
            rest = &rest[took..];
            let mut progress = took > 0;
            while let Some(r) = decoder.next_packet() {
                match r {
                    Ok(p) => packets.push(p),
                    Err(e) => return (packets, Some(e)),
                }
                progress = true;
            }
            // A full decoder always gives a packet or an error.
            assert!(progress);
        }
    }
    (packets, None)
}

/// Takes bytes off the front of the fuzzer's input.
struct Input<'a>(&'a [u8]);

impl<'a> Input<'a> {
    fn byte(&mut self) -> Option<u8> {
        let (b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(*b)
    }
    fn u16(&mut self) -> Option<usize> {
        Some(usize::from(u16::from_be_bytes([self.byte()?, self.byte()?])))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes([self.byte()?, self.byte()?, self.byte()?, self.byte()?]))
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let n = n.min(self.0.len());
        let (b, rest) = self.0.split_at(n);
        self.0 = rest;
        b.to_vec()
    }
    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let mut a = [0; N];
        for b in &mut a {
            *b = self.byte()?;
        }
        Some(a)
    }
    /// A value of any variant, including ones no reader gives, such as
    /// values longer than an attribute holds.
    fn value(&mut self, depth: u8) -> Option<Value> {
        let len = self.u16()? % 600;
        Some(match self.byte()? % 16 {
            0 => Value::Text(String::from_utf8_lossy(&self.bytes(len)).into_owned()),
            1 => Value::String(self.bytes(len)),
            2 => Value::Address(Ipv4Addr::from(self.u32()?)),
            3 => Value::Integer(self.u32()?),
            4 => Value::Enum(self.u32()?),
            5 => Value::Time(self.u32()?),
            6 => Value::Integer64(u64::from_be_bytes(self.array()?)),
            7 => Value::Ipv6Address(Ipv6Addr::from(self.array::<16>()?)),
            8 => Value::Ipv6Prefix { length: self.byte()?, prefix: Ipv6Addr::from(self.array::<16>()?) },
            9 => Value::Ipv4Prefix { length: self.byte()?, prefix: Ipv4Addr::from(self.u32()?) },
            10 => Value::InterfaceId(self.array()?),
            11 => Value::Vsa(Vsa { vendor: self.u32()?, data: self.bytes(len) }),
            12 => Value::Evs(Evs { vendor: self.u32()?, evs_type: self.byte()?, data: self.bytes(len) }),
            13 => Value::Extended { ext_type: self.byte()?, data: self.bytes(len) },
            14 => Value::LongExtended { ext_type: self.byte()?, more: self.byte()? & 1 == 1, data: self.bytes(len) },
            _ if depth < 2 => {
                let mut tlvs = Vec::new();
                for _ in 0..self.byte()? % 4 {
                    let kind = self.byte()?;
                    let n = self.byte()?;
                    tlvs.push(Attribute { kind, value: self.bytes(usize::from(n) + 20) });
                }
                Value::Tlv(tlvs)
            }
            _ => Value::String(Vec::new()),
        })
    }
}

/// Builds packets and values from the bytes through the public API, and
/// checks every writer gives only what its reader takes back unchanged.
fn construct(data: &[u8]) -> Option<()> {
    let mut input = Input(data);
    let mut p = Packet::new(Code::from_u8(input.byte()?), input.byte()?, input.array()?);
    for _ in 0..input.byte()? % 64 {
        let kind = input.byte()?;
        match input.byte()? % 4 {
            // A value through the typed constructor.
            0 => {
                let v = input.value(0)?;
                if let Some(bytes) = v.to_bytes() {
                    assert!(bytes.len() <= MAX_VALUE);
                    assert!(Value::decode(v.data_type(), &bytes).is_ok());
                }
                if let Some(a) = Attribute::from_value(kind, &v) {
                    assert_eq!(a.decode().as_ref(), Ok(&v));
                    let _ = p.push(a);
                }
                let t = v.data_type();
                if let Some(a) = Attribute::from_value_as(kind, t, &v) {
                    assert_eq!(Value::decode(t, &a.value).as_ref(), Ok(&v));
                }
            }
            // Raw bytes, straight into the public field: any length.
            1 => {
                let n = input.u16()? % 400;
                p.attributes.push(Attribute { kind, value: input.bytes(n) });
            }
            // An extended value.
            2 => {
                let n = input.u16()? % 4200;
                let e = Extended { kind, ext_type: input.byte()?, data: input.bytes(n) };
                let before = p.clone();
                match p.push_extended(&e) {
                    Ok(()) => assert!(e.ext_type < RESERVED_EXTENDED_TYPES),
                    Err(TooLong) => assert_eq!(p, before),
                }
            }
            // Raw bytes through push.
            _ => {
                let n = input.u16()? % 300;
                let a = Attribute { kind, value: input.bytes(n) };
                let fits = a.value.len() <= MAX_VALUE && p.encoded_len() + 2 + a.value.len() <= MAX_PACKET;
                assert_eq!(p.push(a).is_ok(), fits);
            }
        }
    }
    // A packet is written whole or not at all.
    match p.to_bytes() {
        Ok(bytes) => {
            assert_eq!(bytes.len(), p.encoded_len());
            assert_eq!(Packet::parse(&bytes).as_ref(), Ok(&p));
        }
        Err(TooLong) => {
            assert!(p.encoded_len() > MAX_PACKET || p.attributes.iter().any(|a| a.value.len() > MAX_VALUE))
        }
    }
    Some(())
}

fuzz_target!(|data: &[u8]| {
    // The bytes as one datagram.
    if let Ok(p) = Packet::parse(data) {
        // A packet read can be written, and reads back the same.
        let bytes = p.to_bytes().expect("a packet read can be written");
        assert_eq!(Packet::parse(&bytes).as_ref(), Ok(&p));
        for a in &p.attributes {
            // A value read as its type writes back to bytes that read the same.
            if let Ok(v) = a.decode() {
                let t = a.info().map_or(DataType::String, |i| i.data_type);
                let written = v.to_bytes().expect("a value read can be written");
                assert_eq!(Value::decode(t, &written), Ok(v.clone()));
                // A value read can be put in an attribute again, with the
                // same bytes it came in or bytes that read the same.
                let again = Attribute::from_value(a.kind, &v).expect("a value read can be written");
                assert_eq!(again.decode().as_ref(), Ok(&v));
                if let Value::Vsa(vsa) = &v
                    && let Ok(subs) = vsa.sub_attributes()
                {
                    assert_eq!(Vsa::from_sub_attributes(vsa.vendor, &subs).as_ref(), Some(vsa));
                }
            }
            for t in [DataType::Tlv, DataType::Ipv6Prefix, DataType::Ipv4Prefix, DataType::Evs] {
                if let Ok(v) = Value::decode(t, &a.value) {
                    assert_eq!(Value::decode(t, &v.to_bytes().expect("a value read can be written")), Ok(v));
                }
            }
        }
        // The valid extended attributes, joined, split again and joined
        // again. Reserved Extended-Types are read but not written.
        let ext: Vec<Extended> =
            p.extended().into_iter().flatten().filter(|e| e.ext_type < RESERVED_EXTENDED_TYPES).collect();
        let mut q = Packet::new(p.code, p.identifier, p.authenticator);
        for e in &ext {
            q.push_extended(e).unwrap();
        }
        let again: Vec<Extended> = q.extended().into_iter().map(Result::unwrap).collect();
        assert_eq!(again, ext);
        let _ = p.reply(p.code).to_bytes().expect("a reply to a packet read can be written");
    }

    // The bytes as instructions for building packets and values.
    let _ = construct(data);

    // The bytes as a RADIUS over TCP stream, split two ways: all at once,
    // and a byte at a time.
    assert_eq!(split(data, false), split(data, true));
});
