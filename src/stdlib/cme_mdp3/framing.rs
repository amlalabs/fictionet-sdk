//! MDP 3.0 packets and message framing, written by hand around the
//! generated messages of the parent module.

use super::{Error, Message};

/// Bytes in the binary packet header: `MsgSeqNum` and `SendingTime`.
pub const PACKET_HEADER: usize = 12;
/// Bytes in the `MsgSize` field before each message.
pub const MESSAGE_SIZE: usize = 2;
/// Largest packet: the largest UDP payload over IPv4.
pub const MAX_PACKET: usize = 65_507;
/// Most messages in one packet. A message takes at least ten bytes, its
/// size field and the eight-byte SBE message header.
pub const MAX_PACKET_MESSAGES: usize = (MAX_PACKET - PACKET_HEADER) / 10;

// Packets and messages share the generated `Error`. A packet or message
// past a limit is `Error::Limit`, input that ends within a packet header,
// a size field, or a message is `Error::Truncated`, and a `MsgSize` below
// two, which cannot hold the field itself, is `Error::Layout`. The stream
// decoder [`Messages`] yields a refused message as an `Error` item and
// goes on; only a size below two ends it, as [`FrameError::Size`].

/// Why [`Messages`] stopped: the fault that leaves no next message to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// A `MsgSize` below two, which cannot hold the field itself.
    Size,
}
impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Size => f.write_str("MsgSize below two"),
        }
    }
}
impl std::error::Error for FrameError {}

/// The binary packet header that starts every MDP 3.0 UDP packet.
/// Both fields are little-endian.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PacketHeader {
    /// `MsgSeqNum`: the packet's sequence number on its channel and feed.
    pub sequence: u32,
    /// `SendingTime`: nanoseconds since the Unix epoch when the packet was sent.
    pub sending_time: u64,
}

/// One MDP 3.0 UDP packet: the binary packet header, then messages, each
/// after a little-endian `MsgSize` that counts the size field itself.
#[derive(Clone, Debug, PartialEq)]
pub struct Packet {
    /// Sequence number and sending time.
    pub header: PacketHeader,
    /// Messages in packet order. At most [`MAX_PACKET_MESSAGES`].
    pub messages: Vec<Message>,
}

impl fictionet::stdlib::codec::Wire for Packet {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one whole datagram. Refuses packets over [`MAX_PACKET`], a
    /// truncated header or message, sizes below two, and every message the
    /// generated [`Message`] refuses.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        use fictionet::stdlib::codec::{Decode, Step};
        if bytes.len() > MAX_PACKET {
            return Err(Error::Limit);
        }
        let header = bytes.get(..PACKET_HEADER).ok_or(Error::Truncated)?;
        let (sequence, sending_time) = header.split_at(4);
        let header = PacketHeader {
            sequence: u32::from_le_bytes(sequence.try_into().map_err(|_| Error::Truncated)?),
            sending_time: u64::from_le_bytes(
                sending_time.try_into().map_err(|_| Error::Truncated)?,
            ),
        };
        let mut rest = bytes.get(PACKET_HEADER..).unwrap_or_default();
        let mut messages = Vec::new();
        while !rest.is_empty() {
            if messages.len() >= MAX_PACKET_MESSAGES {
                return Err(Error::Limit);
            }
            let step = Messages
                .decode(rest, true)
                .map_err(|FrameError::Size| Error::Layout)?;
            let Step::Item(message, used) = step else {
                return Err(Error::Truncated);
            };
            messages.push(message?);
            rest = rest.get(used..).ok_or(Error::Truncated)?;
        }
        Ok(Self { header, messages })
    }

    /// Appends the packet. Refuses more than [`MAX_PACKET_MESSAGES`]
    /// messages, packets over [`MAX_PACKET`], and every message the
    /// generated [`Message`] refuses. Errors leave `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.messages.len() > MAX_PACKET_MESSAGES {
            return Err(Error::Limit);
        }
        let mut packet = Vec::new();
        packet.extend_from_slice(&self.header.sequence.to_le_bytes());
        packet.extend_from_slice(&self.header.sending_time.to_le_bytes());
        for message in &self.messages {
            Messages::write(message, &mut packet)?;
            if packet.len() > MAX_PACKET {
                return Err(Error::Limit);
            }
        }
        out.try_reserve(packet.len()).map_err(|_| Error::Limit)?;
        out.extend_from_slice(&packet);
        Ok(())
    }
}

/// Size-prefixed messages, the layout of a packet after its header.
/// Each `MsgSize` counts its own two bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct Messages;
impl Messages {
    /// Appends a size and a message. Refuses messages that do not fit a
    /// two-byte size and every message [`Message`] refuses. Errors leave
    /// `out` unchanged.
    pub fn write(message: &Message, out: &mut Vec<u8>) -> Result<(), Error> {
        use fictionet::stdlib::codec::Wire;
        let body = message.to_bytes()?;
        let size = body
            .len()
            .checked_add(MESSAGE_SIZE)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or(Error::Limit)?;
        out.try_reserve(usize::from(size))
            .map_err(|_| Error::Limit)?;
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&body);
        Ok(())
    }
}
impl fictionet::stdlib::codec::Decode for Messages {
    type Item = Result<Message, Error>;
    type Error = FrameError;
    const NAME: &'static str = "CME MDP 3.0";

    fn capacity(&self) -> usize {
        usize::from(u16::MAX)
    }

    /// Reads one message. A message the generated [`Message`] refuses is
    /// an `Err` item, and reading goes on after it, since `MsgSize` frames
    /// the next one. Only a size below two ends the stream. Partial
    /// messages return `Need`, including at EOF. Holds no input.
    fn decode(
        &mut self,
        input: &[u8],
        _eof: bool,
    ) -> Result<fictionet::stdlib::codec::Step<Self::Item>, FrameError> {
        use fictionet::stdlib::codec::{Step, Wire};
        let Some(&[low, high]) = input.get(..MESSAGE_SIZE) else {
            return Ok(Step::Need);
        };
        let size = usize::from(u16::from_le_bytes([low, high]));
        if size < MESSAGE_SIZE {
            return Err(FrameError::Size);
        }
        let Some(body) = input.get(MESSAGE_SIZE..size) else {
            return Ok(Step::Need);
        };
        Ok(Step::Item(Message::parse(body), size))
    }
}

#[cfg(test)]
mod framing_tests {
    use super::super::{__wire, AdminHeartbeat12};
    use super::*;
    use fictionet::stdlib::codec::Wire;
    use fictionet::stdlib::test_support::contract;

    fn sample(seed: u64) -> Option<Message> {
        <Message as __wire::Codec>::sample(&mut __wire::Sampler::seed(seed)).ok()
    }

    #[test]
    fn heartbeat_packet_bytes() {
        let packet = Packet {
            header: PacketHeader {
                sequence: 7,
                sending_time: 0x0102_0304_0506_0708,
            },
            messages: vec![Message::AdminHeartbeat12(AdminHeartbeat12 {})],
        };
        let bytes = packet.to_bytes().unwrap();
        assert_eq!(
            bytes,
            [
                7, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1, // packet header
                10, 0, // MsgSize, counting itself
                0, 0, 12, 0, 1, 0, 13, 0, // blockLength, templateId, schemaId, version
            ]
        );
        assert_eq!(Packet::parse(&bytes).unwrap(), packet);
        for (at, error) in [(12, Error::Layout), (16, Error::Header)] {
            let mut bad = bytes.clone();
            bad[at] = if at == 12 { 1 } else { 13 };
            assert_eq!(Packet::parse(&bad), Err(error));
        }
        assert_eq!(Packet::parse(&bytes[..21]), Err(Error::Truncated));
        assert_eq!(Packet::parse(&bytes[..11]), Err(Error::Truncated));
    }

    #[test]
    fn a_refused_message_does_not_end_the_stream() {
        use fictionet::stdlib::codec::{Stream, finish, pump};
        let heartbeat = Message::AdminHeartbeat12(AdminHeartbeat12 {});
        let mut good = Vec::new();
        Messages::write(&heartbeat, &mut good).unwrap();
        // An unknown templateId, then trailing bytes after a known message,
        // as a newer schema's extra group would leave. MsgSize frames both.
        let mut unknown = good.clone();
        unknown[4] = 0xff;
        let mut longer = good.clone();
        longer[0] += 3;
        longer.extend_from_slice(&[1, 2, 3]);
        let bytes = [&good[..], &unknown, &good, &longer, &good].concat();
        let mut stream = Stream::new(Messages);
        let mut items = Vec::new();
        assert_eq!(
            pump(&mut stream, &bytes, |m| items.push(m)),
            Ok(bytes.len())
        );
        finish(&mut stream, |m| items.push(m)).unwrap();
        assert_eq!(
            items,
            [
                Ok(heartbeat.clone()),
                Message::parse(&unknown[MESSAGE_SIZE..]),
                Ok(heartbeat.clone()),
                Message::parse(&longer[MESSAGE_SIZE..]),
                Ok(heartbeat),
            ]
        );
        assert!(items[1].is_err() && items[3].is_err());
        assert!(stream.failed().is_none());
        // A size below two cannot frame the next message, so it ends the stream.
        let mut stream = Stream::new(Messages);
        assert!(pump(&mut stream, &[1, 0, 0, 0], |_| ()).is_err());
        assert_eq!(
            stream.failed(),
            Some(&fictionet::stdlib::codec::Fail::Protocol(FrameError::Size))
        );
    }

    #[test]
    fn packets_and_frames_keep_the_contracts() {
        let mut stream = Vec::new();
        let mut messages = Vec::new();
        for seed in 0..64 {
            if let Some(message) = sample(seed) {
                Messages::write(&message, &mut stream).unwrap();
                messages.push(message);
            }
        }
        assert!(messages.len() > 32);
        let expected: Vec<_> = messages.iter().cloned().map(Ok).collect();
        contract::check_decoded(
            || Messages,
            &stream,
            &expected,
            usize::MAX,
            4 * usize::from(u16::MAX),
        );
        let packet = Packet {
            header: PacketHeader {
                sequence: 1,
                sending_time: 2,
            },
            messages,
        };
        contract::check_wire_value(&packet);
        let bytes = packet.to_bytes().unwrap();
        let mut rng = fictionet::stdlib::codec::Lcg::new(9);
        for _ in 0..256 {
            let mut mutated = bytes.clone();
            let at = rng.index(mutated.len());
            mutated[at] = rng.next() as u8;
            contract::check_wire::<Packet>(&mutated);
            contract::check_decode(|| Messages, &mutated[PACKET_HEADER..]);
        }
        let mut too_many = packet.clone();
        too_many.messages =
            vec![Message::AdminHeartbeat12(AdminHeartbeat12 {}); MAX_PACKET_MESSAGES + 1];
        let mut out = vec![3];
        assert_eq!(too_many.write(&mut out), Err(Error::Limit));
        assert_eq!(out, [3]);
    }
}
