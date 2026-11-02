//! DNS message framing: one message per datagram, or each message after a
//! two-octet length on a stream (RFC 1035 §4.2.2, RFC 7766 §8).

use fictionet::stdlib::codec::{Collect, CollectError, Decode, Step};

/// How a transport frames DNS messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Framing {
    /// One message per datagram, as over UDP.
    Datagram,
    /// Each message after its length as two octets in network order, as
    /// over TCP and TLS.
    Stream,
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
}
