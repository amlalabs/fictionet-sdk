//! Check the file-local support code used by every generated module.
const MAX_ALLOCATION: usize = 32;
const MAX_DEPTH: usize = 4;
const MAX_MESSAGE: usize = 128;
const MAX_NODES: usize = 8;
include!("../src/runtime.txt");

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
