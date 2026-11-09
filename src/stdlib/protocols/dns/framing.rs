//! DNS message framing: one message per datagram, or each message after a
//! two-octet length on a stream (RFC 1035 §4.2.2, RFC 7766 §8).

use fictionet::stdlib::codec::{Collect, CollectError, Decode, Step, Wire};
use fictionet::stdlib::layer::{BoundedDecode, BoundedWire};

/// How a transport frames DNS messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Framing {
    /// One message per datagram, as over UDP.
    Datagram,
    /// Each message after its length as two octets in network order, as
    /// over TCP and TLS.
    Stream,
}

/// `message` after its length as two octets in network order, as a stream
/// carries it (RFC 1035 §4.2.2). `None` for a message longer than the
/// 65535 octets the length counts.
pub fn stream_framed(message: &[u8]) -> Option<Vec<u8>> {
    let len = u16::try_from(message.len()).ok()?;
    let mut framed = Vec::with_capacity(2 + message.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(message);
    Some(framed)
}

/// DNS messages framed as one per datagram, or with the two-octet length
/// prefix over a stream (RFC 1035 §4.2.2). Each item is one message's
/// bytes, unparsed.
pub struct Queries {
    framing: Framing,
    datagram: Collect<Vec<u8>, true>,
}

impl Queries {
    /// A decoder for messages framed by `framing`.
    pub fn new(framing: Framing) -> Queries {
        Queries {
            framing,
            datagram: Collect::bytes(usize::from(u16::MAX)),
        }
    }
}

impl Decode for Queries {
    type Item = Vec<u8>;
    type Error = CollectError<core::convert::Infallible>;
    const NAME: &'static str = "DNS message";

    fn capacity(&self) -> usize {
        // The longest stream message: its two-octet length, then 65535 octets.
        2 + usize::from(u16::MAX)
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Vec<u8>>, Self::Error> {
        if self.framing == Framing::Datagram {
            return self.datagram.decode(input, eof);
        }
        let Some(prefix) = input.get(..2) else {
            return Ok(Step::Need);
        };
        let end = 2 + usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
        Ok(match input.get(2..end) {
            Some(message) => Step::Item(message.to_vec(), end),
            None => Step::Need,
        })
    }
}

/// Each message is one allocation of at most 65535 octets.
impl BoundedDecode for Queries {
    fn allocation_bound(&self) -> usize {
        usize::from(u16::MAX)
    }
}

/// A DNS message as a stream carries it: after its length as two octets
/// in network order (RFC 1035 §4.2.2). The value is the message alone;
/// writing it adds the length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamMessage(pub Vec<u8>);

/// Why bytes are not a [`StreamMessage`], or a message cannot be one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamMessageError {
    /// The length does not count the octets that follow it.
    Length,
    /// The message is longer than the 65535 octets the length counts.
    TooLong,
}

impl core::fmt::Display for StreamMessageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            StreamMessageError::Length => "the length does not count the message",
            StreamMessageError::TooLong => "a DNS message longer than a stream carries",
        })
    }
}

impl core::error::Error for StreamMessageError {}

impl StreamMessage {
    fn encode(&self, mut append: impl FnMut(&[u8])) -> Result<(), StreamMessageError> {
        let len = u16::try_from(self.0.len()).map_err(|_| StreamMessageError::TooLong)?;
        append(&len.to_be_bytes());
        append(&self.0);
        Ok(())
    }
}

impl Wire for StreamMessage {
    type ParseError = StreamMessageError;
    type WriteError = StreamMessageError;

    fn parse(b: &[u8]) -> Result<StreamMessage, StreamMessageError> {
        let (prefix, message) = b.split_at_checked(2).ok_or(StreamMessageError::Length)?;
        if usize::from(u16::from_be_bytes([prefix[0], prefix[1]])) != message.len() {
            return Err(StreamMessageError::Length);
        }
        Ok(StreamMessage(message.to_vec()))
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), StreamMessageError> {
        self.encode(|bytes| out.extend_from_slice(bytes))
    }
}

impl BoundedWire for StreamMessage {
    fn write_bounded(
        &self,
        out: &mut fictionet::stdlib::layer::BoundedWriter<'_>,
    ) -> Result<(), StreamMessageError> {
        self.encode(|bytes| out.extend_from_slice(bytes))
    }
    fn write_bound(&self) -> Result<usize, StreamMessageError> {
        u16::try_from(self.0.len()).map_err(|_| StreamMessageError::TooLong)?;
        Ok(2 + self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_datagram_is_one_message_at_its_end() {
        let mut queries = Queries::new(Framing::Datagram);
        assert_eq!(queries.decode(b"abc", false).unwrap(), Step::Need);
        assert_eq!(
            queries.decode(b"abc", true).unwrap(),
            Step::Item(b"abc".to_vec(), 3)
        );
        assert_eq!(queries.decode(b"", true).unwrap(), Step::End);
    }

    #[test]
    fn a_stream_message_follows_its_length() {
        let mut queries = Queries::new(Framing::Stream);
        assert_eq!(queries.decode(&[0], false).unwrap(), Step::Need);
        assert_eq!(queries.decode(&[0, 3, b'a'], false).unwrap(), Step::Need);
        assert_eq!(
            queries.decode(&[0, 3, b'a', b'b', b'c', 0], false).unwrap(),
            Step::Item(b"abc".to_vec(), 5)
        );
        assert_eq!(
            queries.decode(&[0, 0], false).unwrap(),
            Step::Item(Vec::new(), 2)
        );
        assert_eq!(queries.capacity(), 65537);
    }

    #[test]
    fn a_framed_message_reads_back_and_one_too_long_is_refused() {
        let framed = stream_framed(b"abc").unwrap();
        assert_eq!(framed, [0, 3, b'a', b'b', b'c']);
        let mut queries = Queries::new(Framing::Stream);
        assert_eq!(
            queries.decode(&framed, false).unwrap(),
            Step::Item(b"abc".to_vec(), 5)
        );
        assert!(stream_framed(&vec![0; 65535]).is_some());
        assert_eq!(stream_framed(&vec![0; 65536]), None);
    }

    #[test]
    fn a_stream_message_reads_back_as_the_queries_reader_reads_it() {
        for len in [0, 1, 12, 512, 65535] {
            let message = StreamMessage((0..len).map(|i| i as u8).collect());
            let bytes = message.to_bytes().unwrap();
            assert_eq!(bytes.len(), message.write_bound().unwrap());
            assert_eq!(StreamMessage::parse(&bytes).unwrap(), message);
            let mut queries = Queries::new(Framing::Stream);
            assert_eq!(
                queries.decode(&bytes, false).unwrap(),
                Step::Item(message.0.clone(), bytes.len())
            );
            // Cut short or with more after it, the length no longer counts it.
            if let Some((_, short)) = bytes.split_last() {
                assert!(StreamMessage::parse(short).is_err());
            }
            let mut long = bytes.clone();
            long.push(0);
            assert!(StreamMessage::parse(&long).is_err());
        }
        let too_long = StreamMessage(vec![0; 65536]);
        let mut out = Vec::new();
        assert!(too_long.write(&mut out).is_err());
        assert!(out.is_empty());
        assert!(too_long.write_bound().is_err());
    }
}
