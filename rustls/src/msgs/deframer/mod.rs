use core::mem;

use crate::error::{Error, InvalidMessage};
use crate::msgs::codec::Reader;
use crate::msgs::message::{
    read_opaque_message_header, InboundOpaqueMessage, MessageError, HEADER_SIZE,
};

pub(crate) mod buffers;
pub(crate) mod handshake;

/// A deframer of TLS wire messages.
///
/// Returns `Some(Ok(_))` containing each `InboundOpaqueMessage` deframed
/// from the buffer.
///
/// Returns `None` if no further messages can be deframed from the
/// buffer.  More data is required for further progress.
///
/// Returns `Some(Err(_))` if the peer is not talking TLS, but some
/// other protocol.  The caller should abort the connection, because
/// the deframer cannot recover.
///
/// Call `bytes_consumed()` to learn how many bytes the iterator has
/// processed from the front of the original buffer.  This is only updated
/// when a message is successfully deframed (ie. `Some(Ok(_))` is returned).
pub(crate) struct DeframerIter<'a> {
    buf: &'a mut [u8],
    consumed: usize,
}

impl<'a> DeframerIter<'a> {
    /// Make a new `DeframerIter`
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, consumed: 0 }
    }

    /// How many bytes were processed successfully from the front
    /// of the buffer passed to `new()`?
    pub(crate) fn bytes_consumed(&self) -> usize {
        self.consumed
    }
}

/// Where the record that starts at `from` in `buffer` ends: once its 5-byte
/// header is there, checked as the deframer checks it, the end it says;
/// before that, the end of the header. So a reader grows no further than a
/// header it has checked allows.
///
/// Fails on a header no record may have: an unknown content type, a
/// version that is not 3.x, an empty record that may not be empty, or a
/// length past the most a record may carry.
pub(crate) fn record_end(buffer: &[u8], from: usize) -> Result<usize, Error> {
    let rest = buffer.get(from..).unwrap_or_default();
    match read_header(rest) {
        Some(Ok(len)) => Ok(from + HEADER_SIZE + usize::from(len)),
        Some(Err(err)) => Err(err),
        None => Ok(from + HEADER_SIZE),
    }
}

/// The length a record's header at the start of `bytes` says, `None` while
/// the header is incomplete, or why it is no record's header.
fn read_header(bytes: &[u8]) -> Option<Result<u16, Error>> {
    let mut reader = Reader::init(bytes);
    match read_opaque_message_header(&mut reader) {
        Ok((_, _, len)) => Some(Ok(len)),
        Err(MessageError::TooShortForHeader | MessageError::TooShortForLength) => None,
        Err(err) => Some(Err(invalid_header(err).into())),
    }
}

fn invalid_header(err: MessageError) -> InvalidMessage {
    match err {
        MessageError::TooShortForHeader | MessageError::TooShortForLength => {
            InvalidMessage::MessageTooShort
        }
        MessageError::InvalidEmptyPayload => InvalidMessage::InvalidEmptyPayload,
        MessageError::MessageTooLarge => InvalidMessage::MessageTooLarge,
        MessageError::InvalidContentType => InvalidMessage::InvalidContentType,
        MessageError::UnknownProtocolVersion => InvalidMessage::UnknownProtocolVersion,
    }
}

impl<'a> Iterator for DeframerIter<'a> {
    type Item = Result<InboundOpaqueMessage<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut reader = Reader::init(self.buf);

        let (typ, version, len) = match read_opaque_message_header(&mut reader) {
            Ok(header) => header,
            Err(MessageError::TooShortForHeader | MessageError::TooShortForLength) => {
                return None;
            }
            Err(err) => return Some(Err(invalid_header(err).into())),
        };

        let end = HEADER_SIZE + len as usize;

        self.buf.get(HEADER_SIZE..end)?;

        // we now have a TLS header and body on the front of `self.buf`.  remove
        // it from the front.
        let (consumed, remainder) = mem::take(&mut self.buf).split_at_mut(end);
        self.buf = remainder;
        self.consumed += end;

        Some(Ok(InboundOpaqueMessage::new(
            typ,
            version,
            &mut consumed[HEADER_SIZE..],
        )))
    }
}

pub fn fuzz_deframer(data: &[u8]) {
    let mut buf = data.to_vec();
    let mut iter = DeframerIter::new(&mut buf);

    for message in iter.by_ref() {
        if message.is_err() {
            break;
        }
    }

    assert!(iter.bytes_consumed() <= buf.len());
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use std::prelude::v1::*;

    use super::*;
    use crate::ContentType;

    #[test]
    fn iterator_empty_before_header_received() {
        assert!(DeframerIter::new(&mut []).next().is_none());
        assert!(DeframerIter::new(&mut [0x16]).next().is_none());
        assert!(DeframerIter::new(&mut [0x16, 0x03]).next().is_none());
        assert!(DeframerIter::new(&mut [0x16, 0x03, 0x03]).next().is_none());
        assert!(DeframerIter::new(&mut [0x16, 0x03, 0x03, 0x00])
            .next()
            .is_none());
        assert!(DeframerIter::new(&mut [0x16, 0x03, 0x03, 0x00, 0x01])
            .next()
            .is_none());
    }

    #[test]
    fn iterate_one_message() {
        let mut buffer = [0x17, 0x03, 0x03, 0x00, 0x01, 0x00];
        let mut iter = DeframerIter::new(&mut buffer);
        assert_eq!(
            iter.next().unwrap().unwrap().typ,
            ContentType::ApplicationData
        );
        assert_eq!(iter.bytes_consumed(), 6);
        assert!(iter.next().is_none());
    }

    #[test]
    fn iterate_two_messages() {
        let mut buffer = [
            0x16, 0x03, 0x03, 0x00, 0x01, 0x00, 0x17, 0x03, 0x03, 0x00, 0x01, 0x00,
        ];
        let mut iter = DeframerIter::new(&mut buffer);
        assert_eq!(iter.next().unwrap().unwrap().typ, ContentType::Handshake);
        assert_eq!(iter.bytes_consumed(), 6);
        assert_eq!(
            iter.next().unwrap().unwrap().typ,
            ContentType::ApplicationData
        );
        assert_eq!(iter.bytes_consumed(), 12);
        assert!(iter.next().is_none());
    }

    #[test]
    fn iterator_invalid_protocol_version_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-version.bin").to_vec();
        let mut iter = DeframerIter::new(&mut buffer);
        assert_eq!(
            iter.next().unwrap().err(),
            Some(Error::InvalidMessage(
                InvalidMessage::UnknownProtocolVersion
            ))
        );
    }

    #[test]
    fn iterator_invalid_content_type_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-contenttype.bin").to_vec();
        let mut iter = DeframerIter::new(&mut buffer);
        assert_eq!(
            iter.next().unwrap().err(),
            Some(Error::InvalidMessage(InvalidMessage::InvalidContentType))
        );
    }

    #[test]
    fn iterator_excess_message_length_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-length.bin").to_vec();
        let mut iter = DeframerIter::new(&mut buffer);
        assert_eq!(
            iter.next().unwrap().err(),
            Some(Error::InvalidMessage(InvalidMessage::MessageTooLarge))
        );
    }

    #[test]
    fn iterator_zero_message_length_rejected() {
        let mut buffer = include_bytes!("../../testdata/deframer-invalid-empty.bin").to_vec();
        let mut iter = DeframerIter::new(&mut buffer);
        assert_eq!(
            iter.next().unwrap().err(),
            Some(Error::InvalidMessage(InvalidMessage::InvalidEmptyPayload))
        );
    }

    #[test]
    fn iterator_over_many_messages() {
        let client_hello = include_bytes!("../../testdata/deframer-test.1.bin");
        let mut buffer = Vec::with_capacity(3 * client_hello.len());
        buffer.extend(client_hello);
        buffer.extend(client_hello);
        buffer.extend(client_hello);
        let mut iter = DeframerIter::new(&mut buffer);
        let mut count = 0;

        for message in iter.by_ref() {
            let message = message.unwrap();
            assert_eq!(ContentType::Handshake, message.typ);
            count += 1;
        }

        assert_eq!(count, 3);
        assert_eq!(client_hello.len() * 3, iter.bytes_consumed());
    }

    #[test]
    fn exercise_fuzz_deframer() {
        fuzz_deframer(&[0xff, 0xff, 0xff, 0xff, 0xff]);
        for prefix in 0..7 {
            fuzz_deframer(&[0x16, 0x03, 0x03, 0x00, 0x01, 0xff][..prefix]);
        }
    }
}
