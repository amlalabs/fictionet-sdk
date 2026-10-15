//! Check the file-local support code used by every generated module.
use fictionet::stdlib::codec::{Decode, Step};
const MAX_ALLOCATION: usize = 32;
const MAX_DEPTH: usize = 4;
const MAX_MESSAGE: usize = 128;
const MAX_NODES: usize = 8;
fictionet::stdlib::codec::generated_runtime!(
    Error,
    __wire,
    MAX_MESSAGE,
    MAX_DEPTH,
    MAX_ALLOCATION,
    MAX_NODES
);

#[derive(Debug, PartialEq)]
struct Broken<const SAMPLES: bool>;
impl<const SAMPLES: bool> __wire::Codec for Broken<SAMPLES> {
    fn read(_: &mut __wire::Reader<'_>, _: bool) -> Result<Self, Error> {
        Err(Error::Value)
    }
    fn encode(&self, _: &mut __wire::Writer, _: bool) -> Result<(), Error> {
        Err(Error::Value)
    }
    fn sample(_: &mut __wire::Sampler) -> Result<Self, Error> {
        if SAMPLES { Ok(Self) } else { Err(Error::Value) }
    }
}
impl<const SAMPLES: bool> fictionet::stdlib::codec::Wire for Broken<SAMPLES> {
    type ParseError = Error;
    type WriteError = Error;
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        __wire::parse(bytes, false)
    }
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        __wire::write(self, out, false)
    }
}

#[test]
#[should_panic(expected = "no writable sample")]
fn contract_test_must_not_skip_every_sample() {
    __wire::check::<Broken<false>>().unwrap();
}

#[test]
#[should_panic(expected = "no writable sample")]
fn contract_test_must_not_skip_every_write() {
    __wire::check::<Broken<true>>().unwrap();
}

#[derive(Debug, PartialEq)]
struct Bit(bool);
impl __wire::Codec for Bit {
    fn read(r: &mut __wire::Reader<'_>, le: bool) -> Result<Self, Error> {
        match r.scalar::<u8>(le)? {
            0 => Ok(Self(false)),
            1 => Ok(Self(true)),
            _ => Err(Error::Value),
        }
    }
    fn encode(&self, w: &mut __wire::Writer, le: bool) -> Result<(), Error> {
        w.scalar(u8::from(self.0), le)
    }
    fn sample(s: &mut __wire::Sampler) -> Result<Self, Error> {
        Ok(Self(s.ranged(0, 1) != 0))
    }
}
impl Bit {
    fn write_frame(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        __wire::write_frame(self, out, &[], 1, false, false)
    }
}

struct AlwaysRejecting;
impl Decode for AlwaysRejecting {
    type Item = Bit;
    type Error = Error;
    const NAME: &'static str = "always rejecting";
    fn capacity(&self) -> usize {
        MAX_MESSAGE + 1
    }
    fn decode(&mut self, _: &[u8], _: bool) -> Result<Step<Bit>, Error> {
        Err(Error::Header)
    }
}

struct WrongItem;
impl Decode for WrongItem {
    type Item = Bit;
    type Error = Error;
    const NAME: &'static str = "wrong item";
    fn capacity(&self) -> usize {
        MAX_MESSAGE + 1
    }
    fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<Bit>, Error> {
        match __wire::frame(input, &[], 1, false, false)? {
            Step::Item(Bit(value), used) => Ok(Step::Item(Bit(!value), used)),
            step => Ok(step),
        }
    }
}

struct EarlyTerminal(bool);
impl Decode for EarlyTerminal {
    type Item = Bit;
    type Error = Error;
    const NAME: &'static str = "early terminal";
    fn capacity(&self) -> usize {
        MAX_MESSAGE + 1
    }
    fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<Bit>, Error> {
        if self.0 {
            return Ok(Step::End);
        }
        let step = __wire::frame(input, &[], 1, false, false)?;
        self.0 = matches!(step, Step::Item(_, _));
        Ok(step)
    }
}

#[test]
#[should_panic(expected = "known-valid input failed to decode")]
fn always_rejecting_decoder() {
    __wire::check_stream(|| AlwaysRejecting, Bit::write_frame, 1);
}

#[test]
#[should_panic(expected = "decoded items differ from expected")]
fn wrong_item_decoder() {
    __wire::check_stream(|| WrongItem, Bit::write_frame, 1);
}

#[test]
#[should_panic(expected = "decoded items differ from expected")]
fn early_terminal_decoder() {
    __wire::check_stream(|| EarlyTerminal(false), Bit::write_frame, 1);
}

#[test]
fn every_flag_width_uses_value_errors() {
    for width in [1, 2, 4, 8] {
        for little in [false, true] {
            for flag in [0u64, 1, 2, 255] {
                let data = if little {
                    flag.to_le_bytes()
                } else {
                    flag.to_be_bytes()
                };
                let data = if little {
                    &data[..width]
                } else {
                    &data[8 - width..]
                };
                let result = __wire::Reader::new(data).optional(width, little, |_| Ok(7));
                assert_eq!(
                    result,
                    match flag {
                        0 => Ok(None),
                        1 => Ok(Some(7)),
                        _ => Err(Error::Value),
                    }
                );
            }
        }
    }
}

#[test]
fn group_checks_input_before_reserving() {
    let mut reader = __wire::Reader::new(&[0, 16, 0, 0, 0]);
    assert_eq!(
        reader.group(4, 1 << 20, 1, false, |r| r.text(1, 255, false)),
        Err(Error::Truncated)
    );
    // Zero-byte entries can still be parsed from an empty body.
    assert_eq!(
        __wire::Reader::new(&[3]).group(1, 3, 0, false, |_| Ok(())),
        Ok(vec![(); 3])
    );
}

/// A float with a declared range, and one with a range and a finite null.
#[derive(Debug, PartialEq)]
struct Ranged(f64, Option<f32>);
impl __wire::Codec for Ranged {
    fn read(r: &mut __wire::Reader<'_>, le: bool) -> Result<Self, Error> {
        Ok(Self(
            r.ranged(-1.0, 1.0, le)?,
            r.nullable_range(9.0, -1.0, 1.0, le)?,
        ))
    }
    fn encode(&self, w: &mut __wire::Writer, le: bool) -> Result<(), Error> {
        w.ranged(self.0, -1.0, 1.0, le)?;
        w.nullable_range(&self.1, 9.0, -1.0, 1.0, le)
    }
    fn sample(_: &mut __wire::Sampler) -> Result<Self, Error> {
        Ok(Self(0.5, None))
    }
}

#[test]
fn float_ranges_refuse_nan() {
    let bytes = |a: f64, b: f32| [&a.to_le_bytes()[..], &b.to_le_bytes()].concat();
    let parse = |a, b| __wire::parse::<Ranged>(&bytes(a, b), true);
    assert_eq!(parse(0.5, 9.0), Ok(Ranged(0.5, None)));
    assert_eq!(parse(0.5, -1.0), Ok(Ranged(0.5, Some(-1.0))));
    for nan in [f64::NAN, -f64::NAN, f64::from_bits(0x7ff0_0000_0000_0001)] {
        assert_eq!(parse(nan, 9.0), Err(Error::Value));
        assert_eq!(parse(0.5, nan as f32), Err(Error::Value));
        for value in [Ranged(nan, None), Ranged(0.5, Some(nan as f32))] {
            let mut out = vec![7];
            assert_eq!(__wire::write(&value, &mut out, true), Err(Error::Value));
            assert_eq!(out, [7]);
        }
    }
}

const NULL: u16 = 0x1234;

#[derive(Debug, PartialEq)]
struct NullableRef(u16, Option<u16>);
impl __wire::Codec for NullableRef {
    fn read(r: &mut __wire::Reader<'_>, le: bool) -> Result<Self, Error> {
        Ok(Self(
            r.scalar(le)?,
            r.nullable_ref(NULL, le, |r| r.scalar(le))?,
        ))
    }
    fn encode(&self, w: &mut __wire::Writer, le: bool) -> Result<(), Error> {
        w.scalar(self.0, le)?;
        w.nullable_ref(&self.1, NULL, le, |w, v| w.scalar(*v, le))
    }
    fn sample(_: &mut __wire::Sampler) -> Result<Self, Error> {
        Ok(Self(0, None))
    }
}

#[test]
fn nullable_ref_preserves_presence() {
    for le in [false, true] {
        for prefix in [0, NULL] {
            for optional in [None, Some(0), Some(NULL.swap_bytes()), Some(u16::MAX)] {
                let value = NullableRef(prefix, optional);
                let mut out = vec![7, 8, 9];
                __wire::write(&value, &mut out, le).unwrap();
                assert_eq!(&out[..3], &[7, 8, 9]);
                assert_eq!(__wire::parse::<NullableRef>(&out[3..], le), Ok(value));
            }
        }
    }
}

#[test]
fn nullable_ref_null_collision_is_transactional() {
    for le in [false, true] {
        for prefix in [0, NULL] {
            let value = NullableRef(prefix, Some(NULL));
            let mut out = vec![7, 8, 9];
            assert_eq!(__wire::write(&value, &mut out, le), Err(Error::Value));
            assert_eq!(out, [7, 8, 9]);
        }
    }
}
