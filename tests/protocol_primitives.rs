use fictionet::stdlib::{
    codec::{self, Wire},
    dhcpv6, json, protobuf, spnego,
};

#[derive(Debug, PartialEq, Eq)]
enum Error {
    Short,
    Count(usize),
    Field { byte: u8 },
}
fictionet::error_display!(Error, f, {
    Self::Short => f.write_str("short"),
    Self::Count(n) => write!(f, "{n:04}"),
    Self::Field { byte } => write!(f, "{byte:#04x}"),
});
fictionet::codec_from!(Error, codec::Truncated, |_| Error::Short);
fictionet::codec_from!(Error, codec::Trailing, |e| Error::Count(e.0));
fictionet::fixed_fields!(Field, take, array; Error, Error::Short;
    from_le_bytes, to_le_bytes; u8, u16, i32);
fictionet::open_enum! {
    /// A test code with a reserved gap.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Code: u16 {
        /// The named value.
        Named = 3,
        ; /// An uninterpreted code.
        Other,
    }
    [/// Returns the numeric code.
    ] [/// Reads the numeric code.
    ]
}

#[test]
fn declarations_preserve_formatting_payloads_and_fields() {
    assert_eq!(Error::Short.to_string(), "short");
    assert_eq!(Error::Count(7).to_string(), "0007");
    assert_eq!(Error::Field { byte: 15 }.to_string(), "0x0f");
    assert!(std::error::Error::source(&Error::Short).is_none());
    assert_eq!(Error::from(codec::Truncated), Error::Short);
    assert_eq!(Error::from(codec::Trailing(12)), Error::Count(12));
    let mut input = &[0x34, 0x12, 0xff][..];
    assert_eq!(take::<u16>(&mut input), Ok(0x1234));
    assert_eq!(take::<u16>(&mut input), Err(Error::Short));
    assert_eq!(input, &[0xff]);
    assert_eq!(u8::get(&[1, 2]), Err(Error::Short));
    let mut out = vec![9];
    (-2i32).put(&mut out);
    assert_eq!(out, [9, 0xfe, 0xff, 0xff, 0xff]);
    assert_eq!(Code::from_code(3), Code::Named);
    assert_eq!(Code::from_code(4), Code::Other(4));
    assert_eq!(Code::Other(3).code(), 3);
}

fn same_encoding<T: Wire>(value: &T, valid: bool)
where
    T::WriteError: PartialEq,
{
    let mut out = Vec::new();
    let written = value.write(&mut out).map(|()| out);
    assert_eq!(written.is_ok(), valid);
    assert_eq!(value.to_bytes(), written);
}

#[test]
fn owned_encodings_match_appending_on_success_and_failure() {
    let mut message = dhcpv6::Message::new(dhcpv6::msg::SOLICIT, 1);
    same_encoding(&message, true);
    message.transaction = u32::MAX;
    same_encoding(&message, false);
    same_encoding(&json::Value::String("quoted \" text".into()), true);
    same_encoding(&json::Value::String("x".repeat(json::MAX_SIZE)), false);
    same_encoding(&spnego::NegotiationToken::Resp(Default::default()), true);
    same_encoding(&spnego::NegotiationToken::Init(Default::default()), false);
    same_encoding(
        &spnego::InitialContextToken {
            mech: spnego::Mech::Ntlm,
            inner: vec![1, 2],
        },
        true,
    );
    same_encoding(
        &spnego::InitialContextToken {
            mech: spnego::Mech::Ntlm,
            inner: vec![0; spnego::MAX_TOKEN],
        },
        false,
    );
}

#[test]
fn scalar_lookup_skips_later_fields_with_another_wire_type() {
    let message = protobuf::Message::parse(&[
        8, 7, 13, 1, 0, 0, 0, 9, 2, 0, 0, 0, 0, 0, 0, 0, 10, 1, 3, 8, 9,
    ])
    .unwrap();
    assert_eq!(message.uint64(1), Some(9));
    assert_eq!(message.fixed32(1), Some(1));
    assert_eq!(message.fixed64(1), Some(2));
    assert_eq!(message.bytes(1), Some(&[3][..]));
    assert_eq!(message.all(1).count(), 5);
}

#[test]
fn spnego_frame_validation_keeps_framing_only_and_rolls_back() {
    for bytes in [
        vec![0xa0, 0],
        vec![],
        vec![0xa0, 1],
        vec![0xa0, 0, 0],
        vec![0xa0, 0x80, 0, 0],
        vec![0; spnego::MAX_TOKEN + 1],
    ] {
        let expected = spnego::Frame::parse(&bytes).map(|_| ());
        let mut out = vec![7, 8];
        assert_eq!(spnego::Frame(bytes.clone()).write(&mut out), expected);
        if expected.is_ok() {
            assert_eq!(&out[2..], bytes);
        } else {
            assert_eq!(out, [7, 8]);
        }
    }
}
