use fictionet::stdlib::codec::{
    Carry, Decode, Demux, Fail, Layered, Pipe, PipeError, Step, Wire, contract, test_support,
};
use fictionet::stdlib::grpc::{Code, Error, HEADER_LEN, Message, Messages, fail_status};
use std::collections::BTreeMap;

const MESSAGE_LIMIT: usize = 8;
const MAX_STREAMS: usize = 5;
const MAX_BYTES: usize = MAX_STREAMS * (HEADER_LEN + MESSAGE_LIMIT);
const MAX_DATA: usize = 64;
const H2_HEADER_LEN: usize = 9;

type Key = (u8, u32);
type Calls = Demux<Key, Messages>;
type Results = BTreeMap<Key, Vec<Result<Message, Fail<Error>>>>;

#[test]
fn partial_message_prefix_ends_the_call_with_internal() {
    for prefix in 1..HEADER_LEN {
        let (_, failure) = test_support::decode_all(Messages::new, &vec![0; prefix]);
        let failure = failure.unwrap();
        assert_eq!(failure, Fail::Truncated { unread: prefix });
        assert_eq!(fail_status(&failure).code, Code::Internal);
    }
}

// Payloads already extracted by HTTP/2, as in design section 5.3.
// No padding is included. Each direction has its own stream ID space.
struct Data<'a> {
    key: Key,
    payload: &'a [u8],
    end: bool,
}

fn frames() -> [Data<'static>; 11] {
    [
        Data {
            key: (0, 1),
            payload: &[0, 0],
            end: false,
        },
        Data {
            key: (0, 3),
            payload: &[1, 0, 0],
            end: false,
        },
        Data {
            key: (0, 5),
            payload: &[0, 0, 0, 0],
            end: false,
        },
        Data {
            key: (0, 1),
            payload: &[0, 0, 5, b'a'],
            end: false,
        },
        Data {
            key: (0, 3),
            payload: &[0, 3, 0xff],
            end: false,
        },
        // Only the final header byte arrives. There is no oversized body.
        Data {
            key: (0, 5),
            payload: &[9],
            end: false,
        },
        Data {
            key: (0, 7),
            payload: &[0, 0, 0, 0, 4, b't'],
            end: true,
        },
        Data {
            key: (1, 1),
            payload: &[0, 0, 0, 0, 1, b'r'],
            end: true,
        },
        // Finishes the first body, then carries two complete messages.
        // This payload is larger than one gRPC driver's buffer.
        Data {
            key: (0, 1),
            payload: &[
                b'b', b'c', b'd', b'e', 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, b'x', b'y',
            ],
            end: false,
        },
        Data {
            key: (0, 3),
            payload: &[0, 0x7f],
            end: true,
        },
        Data {
            key: (0, 1),
            payload: &[],
            end: true,
        },
    ]
}

fn drain(calls: &mut Calls, results: &mut Results) {
    while let Some((key, result)) = calls.next() {
        results.entry(key).or_default().push(result);
        assert!(calls.total() <= MAX_BYTES);
    }
}

fn route(chunk_size: usize) {
    let mut calls = Calls::new(MAX_STREAMS, MAX_BYTES, |_| {
        Messages::with_limit(MESSAGE_LIMIT)
    });
    let mut results = Results::new();
    let mut saw_backpressure = false;
    for frame in frames() {
        assert!(frame.payload.len() <= MAX_DATA);
        for chunk in fictionet::stdlib::codec::test_support::chunks(frame.payload, &[chunk_size]) {
            let mut rest = chunk;
            while !rest.is_empty() {
                let n = calls.push(&frame.key, rest);
                assert!(n > 0, "shared budget must allow this fixture to progress");
                saw_backpressure |= n < rest.len();
                rest = rest.get(n..).unwrap();
                assert!(calls.total() <= MAX_BYTES);
                drain(&mut calls, &mut results);
            }
        }
        if frame.key == (0, 5) && frame.payload == [9] {
            // Failure is visible before END_STREAM and before any body bytes.
            let stream = calls.get_mut(&frame.key).unwrap();
            assert_eq!(
                stream.failed(),
                Some(&Fail::Protocol(Error::TooLarge {
                    length: 9,
                    limit: MESSAGE_LIMIT
                }))
            );
            assert_eq!(stream.buffered(), HEADER_LEN);
            assert_eq!(stream.held(), 0);
        }
        if frame.end {
            calls.end(&frame.key);
            drain(&mut calls, &mut results);
            assert!(calls.get_mut(&frame.key).unwrap().is_done());
        }
    }
    if chunk_size == MAX_DATA {
        assert!(saw_backpressure);
    }
    let expected = BTreeMap::from([
        (
            (0, 1),
            vec![
                Ok(Message {
                    compressed: false,
                    data: b"abcde".to_vec(),
                }),
                Ok(Message::default()),
                Ok(Message {
                    compressed: false,
                    data: b"xy".to_vec(),
                }),
            ],
        ),
        (
            (0, 3),
            vec![Ok(Message {
                compressed: true,
                data: vec![0xff, 0, 0x7f],
            })],
        ),
        (
            (0, 5),
            vec![Err(Fail::Protocol(Error::TooLarge {
                length: 9,
                limit: MESSAGE_LIMIT,
            }))],
        ),
        ((0, 7), vec![Err(Fail::Truncated { unread: 6 })]),
        (
            (1, 1),
            vec![Ok(Message {
                compressed: false,
                data: b"r".to_vec(),
            })],
        ),
    ]);
    assert_eq!(results, expected);
    assert_eq!(calls.len(), MAX_STREAMS);
    assert_eq!(calls.total(), HEADER_LEN + 6);
    assert_eq!(calls.next(), None);

    for (key, items) in &results {
        for message in items.iter().flatten() {
            // The writer round-trips through the decoder bytewise.
            let bytes = message.to_bytes().unwrap();
            contract::check_decode_with_alloc_limit(
                || Messages::with_limit(MESSAGE_LIMIT),
                &bytes,
                2 * (HEADER_LEN + MESSAGE_LIMIT),
            );
            let (decoded, failure) =
                test_support::decode_all(|| Messages::with_limit(MESSAGE_LIMIT), &bytes);
            assert_eq!(failure, None);
            assert_eq!(decoded, std::slice::from_ref(message));
        }
        assert!(calls.remove(key).is_some());
    }
    assert_eq!(calls.total(), 0);
    assert!(calls.is_empty());
}

#[test]
fn interleaved_http2_data_through_demux() {
    route(MAX_DATA);
}

#[test]
fn interleaved_http2_data_one_byte_at_a_time() {
    route(1);
}

// A test-only reader for unpadded DATA frames on one HTTP/2 stream.
// It accepts at most MAX_DATA payload bytes and stops at END_STREAM.
struct DataFrames {
    stream: u32,
    ended: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BadData;

impl core::fmt::Display for BadData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid test DATA frame")
    }
}

impl core::error::Error for BadData {}

impl Decode for DataFrames {
    type Item = Vec<u8>;
    type Error = BadData;
    const NAME: &'static str = "test HTTP/2 DATA";

    fn capacity(&self) -> usize {
        H2_HEADER_LEN + MAX_DATA
    }

    fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<Self::Item>, BadData> {
        if self.ended {
            return Ok(Step::End);
        }
        let Some(&[a, b, c, kind, flags, s0, s1, s2, s3]) = input.get(..H2_HEADER_LEN) else {
            return Ok(Step::Need);
        };
        let length = usize::try_from(u32::from_be_bytes([0, a, b, c])).map_err(|_| BadData)?;
        let stream = u32::from_be_bytes([s0, s1, s2, s3]);
        if length > MAX_DATA || kind != 0 || flags > 1 || stream != self.stream {
            return Err(BadData);
        }
        let end = H2_HEADER_LEN.checked_add(length).ok_or(BadData)?;
        let Some(payload) = input.get(H2_HEADER_LEN..end) else {
            return Ok(Step::Need);
        };
        self.ended = flags == 1;
        Ok(Step::Item(payload.to_vec(), end))
    }
}

fn data_bytes(stream: u32, payloads: &[(&[u8], bool)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (payload, end) in payloads {
        assert!(payload.len() <= MAX_DATA);
        let length = u32::try_from(payload.len()).unwrap().to_be_bytes();
        out.extend_from_slice(length.get(1..).unwrap());
        out.extend_from_slice(&[0, u8::from(*end)]);
        out.extend_from_slice(&stream.to_be_bytes());
        out.extend_from_slice(payload);
    }
    out
}

#[test]
fn pipe_carries_http2_data_across_frames_and_checks_inner_eof() {
    let make = || {
        Pipe::new(
            DataFrames {
                stream: 1,
                ended: false,
            },
            Messages::with_limit(MESSAGE_LIMIT),
            Carry::Bytes,
        )
    };
    let cases = [
        (
            data_bytes(
                1,
                &[
                    (&[0, 0], false),
                    (&[0, 0, 3, b'a'], false),
                    (&[b'b', b'c', 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, b'z'], true),
                ],
            ),
            vec![
                Message {
                    compressed: false,
                    data: b"abc".to_vec(),
                },
                Message {
                    compressed: true,
                    data: vec![],
                },
                Message {
                    compressed: false,
                    data: b"z".to_vec(),
                },
            ],
            None,
        ),
        (
            data_bytes(1, &[(&[0, 0], false), (&[0, 0, 9], false)]),
            vec![],
            Some(Fail::Protocol(Error::TooLarge {
                length: 9,
                limit: MESSAGE_LIMIT,
            })),
        ),
        (
            data_bytes(1, &[(&[0, 0], false), (&[0, 0, 4, b'x'], true)]),
            vec![],
            Some(Fail::Truncated { unread: 6 }),
        ),
    ];
    for (bytes, expected, failure) in cases {
        contract::check_decode(make, &bytes);
        let (items, failed) = test_support::decode_all(make, &bytes);
        assert_eq!(
            items,
            expected
                .iter()
                .cloned()
                .map(Layered::Inner)
                .collect::<Vec<_>>()
        );
        assert_eq!(failed, failure.map(|e| Fail::Protocol(PipeError::Inner(e))));
    }
}
