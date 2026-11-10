//! Unbuffered connection API

use alloc::vec::Vec;
use core::num::NonZeroUsize;
use core::ops::Range;
use core::{fmt, mem};
#[cfg(feature = "std")]
use std::error::Error as StdError;

use super::UnbufferedConnectionCommon;
use crate::client::ClientConnectionData;
use crate::enums::ContentType;
use crate::msgs::deframer::buffers::DeframerSliceBuffer;
use crate::msgs::deframer::buffers::Locator;
use crate::msgs::deframer::record_end;
use crate::server::ServerConnectionData;
use crate::Error;

impl UnbufferedConnectionCommon<ClientConnectionData> {
    /// Processes the TLS records in `incoming_tls` buffer until a new [`UnbufferedStatus`] is
    /// reached.
    pub fn process_tls_records<'c, 'i>(
        &'c mut self,
        incoming_tls: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, ClientConnectionData> {
        self.process_tls_records_common(incoming_tls, |_| false, |_, _| unreachable!())
    }
}

impl UnbufferedConnectionCommon<ServerConnectionData> {
    /// Processes the TLS records in `incoming_tls` buffer until a new [`UnbufferedStatus`] is
    /// reached.
    pub fn process_tls_records<'c, 'i>(
        &'c mut self,
        incoming_tls: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, ServerConnectionData> {
        self.process_tls_records_common(
            incoming_tls,
            |conn| conn.peek_early_data().is_some(),
            |conn, incoming_tls| ReadEarlyData::new(conn, incoming_tls).into(),
        )
    }
}

impl<Data> UnbufferedConnectionCommon<Data> {
    fn process_tls_records_common<'c, 'i>(
        &'c mut self,
        incoming_tls: &'i mut [u8],
        mut early_data_available: impl FnMut(&mut Self) -> bool,
        early_data_state: impl FnOnce(&'c mut Self, &'i mut [u8]) -> ConnectionState<'c, 'i, Data>,
    ) -> UnbufferedStatus<'c, 'i, Data> {
        let mut buffer = DeframerSliceBuffer::new(incoming_tls);
        let mut buffer_progress = self.core.hs_deframer.progress();

        // Output that went unpaid fails the connection: a record after the
        // one lost would leave a gap the peer refuses.
        if let Err(e) = self.core.common_state.output_paid() {
            self.core.state = Err(e.clone());
            return UnbufferedStatus {
                discard: 0,
                state: Err(e),
            };
        }

        let (discard, state) = loop {
            if early_data_available(self) {
                break (
                    buffer.pending_discard(),
                    early_data_state(self, incoming_tls),
                );
            }

            if !self.core.common_state.sendable_tls.is_empty() {
                break (buffer.pending_discard(), EncodeTlsData::new(self).into());
            }

            // Room for the most output the next message can make, charged
            // before it is taken, so that its processing, which cannot be
            // undone, never runs out of room halfway. Without room the
            // message waits where it is.
            let filled = buffer.filled_mut();
            let next = match record_end(filled, buffer_progress.processed()) {
                Ok(end) => end <= filled.len(),
                // The deframer refuses it, with an alert from the room kept
                // for the final alert.
                Err(_) => false,
            };
            // A connection that failed reads nothing more: what it queued
            // still goes out.
            let reading =
                !self.core.common_state.has_received_close_notify && self.core.state.is_ok();
            let unprocessed = reading && (self.core.hs_deframer.has_message_ready() || next);
            if unprocessed && !self.core.common_state.reserve_step() {
                break (buffer.pending_discard(), ConnectionState::BlockedBudget);
            }

            // Where the bytes `deframe` is given start in `incoming_tls`.
            let base = buffer.pending_discard();
            let locator = Locator::new(buffer.filled_mut());
            let deframer_output = if !reading {
                None
            } else {
                match self
                    .core
                    .deframe(None, buffer.filled_mut(), &mut buffer_progress)
                {
                    Err(err) => {
                        buffer.queue_discard(buffer_progress.take_discard());
                        self.core.common_state.release_step();
                        // A record that does not decrypt or frame fails the
                        // connection, as a message that does not process does.
                        self.core.state = Err(err.clone());
                        return UnbufferedStatus {
                            discard: buffer.pending_discard(),
                            state: Err(err),
                        };
                    }
                    Ok(r) => r,
                }
            };

            if let Some(msg) = deframer_output {
                // Application data is decrypted in place: where its plaintext is.
                let plaintext = (msg.typ == ContentType::ApplicationData)
                    .then(|| locator.locate(msg.payload))
                    .map(|range| base + range.start..base + range.end);
                let mut state =
                    match mem::replace(&mut self.core.state, Err(Error::HandshakeNotComplete)) {
                        Ok(state) => state,
                        Err(e) => {
                            buffer.queue_discard(buffer_progress.take_discard());
                            self.core.state = Err(e.clone());
                            self.core.common_state.release_step();
                            return UnbufferedStatus {
                                discard: buffer.pending_discard(),
                                state: Err(e),
                            };
                        }
                    };

                let processed = self
                    .core
                    .process_msg(msg, state, None)
                    .and_then(|new| self.core.common_state.output_paid().map(|()| new));
                // What the message made is paid from the room; the rest of
                // the room goes back.
                self.core.common_state.release_step();
                match processed {
                    Ok(new) => state = new,

                    Err(e) => {
                        buffer.queue_discard(buffer_progress.take_discard());
                        self.core.state = Err(e.clone());
                        return UnbufferedStatus {
                            discard: buffer.pending_discard(),
                            state: Err(e),
                        };
                    }
                }
                self.core.state = Ok(state);

                // The state took the record's plaintext: it stays where it was
                // decrypted, in the caller's buffer, and goes to the caller as
                // a range of it. The record is discarded once it is handled.
                let kept = mem::take(&mut self.core.common_state.plaintext_kept);
                if let (true, Some(payload)) = (kept, plaintext) {
                    let record = AppDataRecord {
                        discard: buffer_progress.take_discard(),
                        payload,
                    };
                    break (
                        buffer.pending_discard(),
                        ReadTraffic::new(self, incoming_tls, record).into(),
                    );
                }

                buffer.queue_discard(buffer_progress.take_discard());
                continue;
            }

            // Records that failed trial decryption are done with: they are
            // not tried again on the next call.
            buffer.queue_discard(buffer_progress.take_discard());
            self.core.common_state.release_step();
            // Once what a failed connection queued is out, it stays failed.
            if let (false, Err(e)) = (self.wants_write, &self.core.state) {
                return UnbufferedStatus {
                    discard: buffer.pending_discard(),
                    state: Err(e.clone()),
                };
            }
            if self.wants_write {
                break (
                    buffer.pending_discard(),
                    TransmitTlsData { conn: self }.into(),
                );
            } else if self.core.common_state.has_received_close_notify
                && !self.emitted_peer_closed_state
            {
                self.emitted_peer_closed_state = true;
                break (buffer.pending_discard(), ConnectionState::PeerClosed);
            } else if self.core.common_state.has_received_close_notify
                && self.core.common_state.has_sent_close_notify
            {
                break (buffer.pending_discard(), ConnectionState::Closed);
            } else if self.core.common_state.may_send_application_data {
                break (
                    buffer.pending_discard(),
                    ConnectionState::WriteTraffic(WriteTraffic { conn: self }),
                );
            } else {
                break (buffer.pending_discard(), ConnectionState::BlockedHandshake);
            }
        };

        UnbufferedStatus {
            discard,
            state: Ok(state),
        }
    }
}

/// The current status of the `UnbufferedConnection*`
#[must_use]
#[derive(Debug)]
pub struct UnbufferedStatus<'c, 'i, Data> {
    /// Number of bytes to discard
    ///
    /// After the `state` field of this object has been handled, `discard` bytes must be
    /// removed from the *front* of the `incoming_tls` buffer that was passed to
    /// the [`UnbufferedConnectionCommon::process_tls_records`] call that returned this object.
    ///
    /// This discard operation MUST happen *before*
    /// [`UnbufferedConnectionCommon::process_tls_records`] is called again.
    pub discard: usize,

    /// The current state of the handshake process
    ///
    /// This value MUST be handled prior to calling
    /// [`UnbufferedConnectionCommon::process_tls_records`] again. See the documentation on the
    /// variants of [`ConnectionState`] for more details.
    pub state: Result<ConnectionState<'c, 'i, Data>, Error>,
}

/// The state of the [`UnbufferedConnectionCommon`] object
#[non_exhaustive] // for forwards compatibility; to support caller-side certificate verification
pub enum ConnectionState<'c, 'i, Data> {
    /// One, or more, application data records are available
    ///
    /// See [`ReadTraffic`] for more details on how to use the enclosed object to access
    /// the received data.
    ReadTraffic(ReadTraffic<'c, 'i, Data>),

    /// Connection has been cleanly closed by the peer.
    ///
    /// This state is encountered at most once by each connection -- it is
    /// "edge" triggered, rather than "level" triggered.
    ///
    /// It delimits the data received from the peer, meaning you can be sure you
    /// have received all the data the peer sent.
    ///
    /// No further application data will be received from the peer, so no further
    /// `ReadTraffic` states will be produced.
    ///
    /// However, it is possible to _send_ further application data via `WriteTraffic`
    /// states, or close the connection cleanly by calling
    /// [`WriteTraffic::queue_close_notify()`].
    PeerClosed,

    /// Connection has been cleanly closed by both us and the peer.
    ///
    /// This is a terminal state.  No other states will be produced for this
    /// connection.
    Closed,

    /// One, or more, early (RTT-0) data records are available
    ReadEarlyData(ReadEarlyData<'c, 'i, Data>),

    /// A Handshake record is ready for encoding
    ///
    /// Call [`EncodeTlsData::encode`] on the enclosed object, providing an `outgoing_tls`
    /// buffer to store the encoding
    EncodeTlsData(EncodeTlsData<'c, Data>),

    /// Previously encoded handshake records need to be transmitted
    ///
    /// Transmit the contents of the `outgoing_tls` buffer that was passed to previous
    /// [`EncodeTlsData::encode`] calls to the peer.
    ///
    /// After transmitting the contents, call [`TransmitTlsData::done`] on the enclosed object.
    /// The transmitted contents MUST not be sent to the peer more than once so they SHOULD be
    /// discarded at this point.
    ///
    /// At some stages of the handshake process, it's possible to send application-data alongside
    /// handshake records. Call [`TransmitTlsData::may_encrypt_app_data`] on the enclosed
    /// object to probe if that's allowed.
    TransmitTlsData(TransmitTlsData<'c, Data>),

    /// More TLS data is needed to continue with the handshake
    ///
    /// Request more data from the peer and append the contents to the `incoming_tls` buffer that
    /// was passed to [`UnbufferedConnectionCommon::process_tls_records`].
    BlockedHandshake,

    /// The connection's [`BufferBudget`](crate::budget::BufferBudget) has no room for the
    /// output the next message may make
    ///
    /// The message waits where it is: call
    /// [`UnbufferedConnectionCommon::process_tls_records`] again, with the same buffer, once
    /// the budget has room. A connection without a budget never reaches this state.
    BlockedBudget,

    /// The handshake process has been completed.
    ///
    /// [`WriteTraffic::encrypt`] can be called on the enclosed object to encrypt application
    /// data into an `outgoing_tls` buffer. Similarly, [`WriteTraffic::queue_close_notify`] can
    /// be used to encrypt a close_notify alert message into a buffer to signal the peer that the
    /// connection is being closed. Data written into `outgoing_buffer` by either method MAY be
    /// transmitted to the peer during this state.
    ///
    /// Once this state has been reached, data MAY be requested from the peer and appended to an
    /// `incoming_tls` buffer that will be passed to a future
    /// [`UnbufferedConnectionCommon::process_tls_records`] invocation. When enough data has been
    /// appended to `incoming_tls`, [`UnbufferedConnectionCommon::process_tls_records`] will yield
    /// the [`ConnectionState::ReadTraffic`] state.
    WriteTraffic(WriteTraffic<'c, Data>),
}

impl<'c, 'i, Data> From<ReadTraffic<'c, 'i, Data>> for ConnectionState<'c, 'i, Data> {
    fn from(v: ReadTraffic<'c, 'i, Data>) -> Self {
        Self::ReadTraffic(v)
    }
}

impl<'c, 'i, Data> From<ReadEarlyData<'c, 'i, Data>> for ConnectionState<'c, 'i, Data> {
    fn from(v: ReadEarlyData<'c, 'i, Data>) -> Self {
        Self::ReadEarlyData(v)
    }
}

impl<'c, Data> From<EncodeTlsData<'c, Data>> for ConnectionState<'c, '_, Data> {
    fn from(v: EncodeTlsData<'c, Data>) -> Self {
        Self::EncodeTlsData(v)
    }
}

impl<'c, Data> From<TransmitTlsData<'c, Data>> for ConnectionState<'c, '_, Data> {
    fn from(v: TransmitTlsData<'c, Data>) -> Self {
        Self::TransmitTlsData(v)
    }
}

impl<Data> fmt::Debug for ConnectionState<'_, '_, Data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadTraffic(..) => f.debug_tuple("ReadTraffic").finish(),

            Self::PeerClosed => write!(f, "PeerClosed"),

            Self::Closed => write!(f, "Closed"),

            Self::ReadEarlyData(..) => f.debug_tuple("ReadEarlyData").finish(),

            Self::EncodeTlsData(..) => f.debug_tuple("EncodeTlsData").finish(),

            Self::TransmitTlsData(..) => f.debug_tuple("TransmitTlsData").finish(),

            Self::BlockedHandshake => f.debug_tuple("BlockedHandshake").finish(),

            Self::BlockedBudget => f.debug_tuple("BlockedBudget").finish(),

            Self::WriteTraffic(..) => f.debug_tuple("WriteTraffic").finish(),
        }
    }
}

/// An application data record was decrypted where it arrived, in the
/// `incoming_tls` buffer: its plaintext is a range of that buffer.
pub struct ReadTraffic<'c, 'i, Data> {
    _conn: &'c mut UnbufferedConnectionCommon<Data>,
    incoming_tls: &'i [u8],
    record: Option<AppDataRecord>,
}

impl<'c, 'i, Data> ReadTraffic<'c, 'i, Data> {
    fn new(
        conn: &'c mut UnbufferedConnectionCommon<Data>,
        incoming_tls: &'i [u8],
        record: AppDataRecord,
    ) -> Self {
        Self {
            _conn: conn,
            incoming_tls,
            record: Some(record),
        }
    }

    /// The record decrypted, once: its plaintext is at
    /// [`AppDataRecord::payload`] in the `incoming_tls` buffer, already
    /// authenticated. `None` once it was taken; call
    /// [`UnbufferedConnectionCommon::process_tls_records`] again for the next.
    pub fn next_record(&mut self) -> Option<Result<AppDataRecord, Error>> {
        self.record.take().map(Ok)
    }

    /// The plaintext of a record [`Self::next_record`] returned, as a slice
    /// of the `incoming_tls` buffer.
    pub fn payload(&self, record: &AppDataRecord) -> &[u8] {
        &self.incoming_tls[record.payload.clone()]
    }

    /// Returns the payload size of the record not yet taken
    ///
    /// Returns `None` if it was taken, or is empty
    pub fn peek_len(&self) -> Option<NonZeroUsize> {
        self.record
            .as_ref()
            .and_then(|record| NonZeroUsize::new(record.payload.len()))
    }
}

/// Early application-data is available.
pub struct ReadEarlyData<'c, 'i, Data> {
    conn: &'c mut UnbufferedConnectionCommon<Data>,

    // for forwards compatibility; to support in-place decryption in the future
    _incoming_tls: &'i mut [u8],

    // owner of the latest chunk obtained in `next_record`, as borrowed by
    // `AppDataRecord`
    chunk: Option<Vec<u8>>,
}

impl<'c, 'i> ReadEarlyData<'c, 'i, ServerConnectionData> {
    fn new(
        conn: &'c mut UnbufferedConnectionCommon<ServerConnectionData>,
        _incoming_tls: &'i mut [u8],
    ) -> Self {
        Self {
            conn,
            _incoming_tls,
            chunk: None,
        }
    }

    /// Returns the next early data record's plaintext, which the connection
    /// kept apart from the `incoming_tls` buffer
    pub fn next_record(&mut self) -> Option<Result<&[u8], Error>> {
        self.chunk = self.conn.pop_early_data();
        self.chunk.as_deref().map(Ok)
    }

    /// returns the payload size of the next app-data record *without* decrypting it
    ///
    /// returns `None` if there are no more app-data records
    pub fn peek_len(&self) -> Option<NonZeroUsize> {
        self.conn
            .peek_early_data()
            .and_then(|ch| NonZeroUsize::new(ch.len()))
    }
}

/// A decrypted application-data record, decrypted where it arrived
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppDataRecord {
    /// Number of additional bytes to discard: the record's own
    ///
    /// This number MUST be added to the value of [`UnbufferedStatus::discard`] *prior* to the
    /// discard operation. See [`UnbufferedStatus::discard`] for more details
    pub discard: usize,

    /// Where the record's plaintext is in the `incoming_tls` buffer passed
    /// to the [`UnbufferedConnectionCommon::process_tls_records`] call that
    /// returned it, counted from its start before any discard
    pub payload: Range<usize>,
}

/// Allows encrypting app-data
pub struct WriteTraffic<'c, Data> {
    conn: &'c mut UnbufferedConnectionCommon<Data>,
}

impl<Data> WriteTraffic<'_, Data> {
    /// Encrypts `application_data` into the `outgoing_tls` buffer
    ///
    /// Returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer is too small. In the error case, `outgoing_tls` is not modified
    pub fn encrypt(
        &mut self,
        application_data: &[u8],
        outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        self.conn
            .core
            .common_state
            .request_key_update_for(application_data.into());
        self.conn.core.maybe_refresh_traffic_keys();
        self.conn
            .core
            .common_state
            .write_plaintext(application_data.into(), outgoing_tls)
    }

    /// The bytes [`Self::encrypt`] writes for `application_data_len` bytes,
    /// records queued to go before them included: the size an
    /// `outgoing_tls` buffer needs. A key update the write itself starts
    /// adds to it, and `encrypt` then says how much in its error.
    pub fn encrypted_len(&self, application_data_len: usize) -> usize {
        self.conn
            .core
            .common_state
            .encrypted_len(application_data_len)
    }

    /// The bytes [`Self::queue_close_notify`] writes, records queued to go
    /// before it included: the size an `outgoing_tls` buffer needs
    pub fn close_notify_len(&self) -> usize {
        self.conn.core.common_state.close_notify_len()
    }

    /// Encrypts a close_notify warning alert in `outgoing_tls`
    ///
    /// Returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer is too small. In the error case, `outgoing_tls` is not modified
    pub fn queue_close_notify(&mut self, outgoing_tls: &mut [u8]) -> Result<usize, EncryptError> {
        self.conn
            .core
            .common_state
            .eager_send_close_notify(outgoing_tls)
    }

    /// Arranges for a TLS1.3 `key_update` to be sent.
    ///
    /// This consumes the `WriteTraffic` state:  to actually send the message,
    /// call [`UnbufferedConnectionCommon::process_tls_records`] again which will
    /// return a `ConnectionState::EncodeTlsData` that emits the `key_update`
    /// message.
    ///
    /// See [`ConnectionCommon::refresh_traffic_keys()`] for full documentation,
    /// including why you might call this and in what circumstances it will fail.
    ///
    /// [`ConnectionCommon::refresh_traffic_keys()`]: crate::ConnectionCommon::refresh_traffic_keys
    pub fn refresh_traffic_keys(self) -> Result<(), Error> {
        self.conn.core.refresh_traffic_keys()
    }
}

/// A handshake record must be encoded
///
/// The record stays queued in the connection until [`Self::encode`] takes
/// it: dropping this state without encoding loses nothing, and the next
/// [`UnbufferedConnectionCommon::process_tls_records`] call offers it again.
pub struct EncodeTlsData<'c, Data> {
    conn: &'c mut UnbufferedConnectionCommon<Data>,
    encoded: bool,
}

impl<'c, Data> EncodeTlsData<'c, Data> {
    fn new(conn: &'c mut UnbufferedConnectionCommon<Data>) -> Self {
        Self {
            conn,
            encoded: false,
        }
    }

    /// The bytes [`Self::encode`] writes, before it has: the size an
    /// `outgoing_tls` buffer needs
    pub fn len(&self) -> usize {
        match self.encoded {
            true => 0,
            false => self
                .conn
                .core
                .common_state
                .sendable_tls
                .chunk()
                .map_or(0, <[u8]>::len),
        }
    }

    /// Whether [`Self::encode`] has nothing to write
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The bytes of every record queued to be encoded, this one included
    /// until it is: what a buffer for all of them needs
    pub fn queued_len(&self) -> usize {
        self.conn.core.common_state.sendable_tls_len()
    }

    /// Encodes a handshake record into the `outgoing_tls` buffer
    ///
    /// Returns the number of bytes that were written into `outgoing_tls`, or an error if
    /// the provided buffer is too small. In the error case, `outgoing_tls` is not modified
    pub fn encode(&mut self, outgoing_tls: &mut [u8]) -> Result<usize, EncodeError> {
        if self.encoded {
            return Err(EncodeError::AlreadyEncoded);
        }

        let required_size = self.len();
        if required_size > outgoing_tls.len() {
            return Err(InsufficientSizeError { required_size }.into());
        }

        let sendable_tls = &mut self.conn.core.common_state.sendable_tls;
        let chunk = sendable_tls
            .pop()
            .expect("a record is queued while this state lives");
        outgoing_tls[..required_size].copy_from_slice(&chunk);
        self.encoded = true;
        self.conn.wants_write = true;

        Ok(required_size)
    }
}

/// Previously encoded TLS data must be transmitted
pub struct TransmitTlsData<'c, Data> {
    pub(crate) conn: &'c mut UnbufferedConnectionCommon<Data>,
}

impl<Data> TransmitTlsData<'_, Data> {
    /// Signals that the previously encoded TLS data has been transmitted
    pub fn done(self) {
        self.conn.wants_write = false;
    }

    /// Returns an adapter that allows encrypting application data
    ///
    /// If allowed at this stage of the handshake process
    pub fn may_encrypt_app_data(&mut self) -> Option<WriteTraffic<'_, Data>> {
        if self.conn.core.common_state.may_send_application_data {
            Some(WriteTraffic { conn: self.conn })
        } else {
            None
        }
    }
}

/// Errors that may arise when encoding a handshake record
#[derive(Debug)]
pub enum EncodeError {
    /// Provided buffer was too small
    InsufficientSize(InsufficientSizeError),

    /// The handshake record has already been encoded; do not call `encode` again
    AlreadyEncoded,
}

impl From<InsufficientSizeError> for EncodeError {
    fn from(v: InsufficientSizeError) -> Self {
        Self::InsufficientSize(v)
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientSize(InsufficientSizeError { required_size }) => write!(
                f,
                "cannot encode due to insufficient size, {required_size} bytes are required"
            ),
            Self::AlreadyEncoded => "cannot encode, data has already been encoded".fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl StdError for EncodeError {}

/// Errors that may arise when encrypting application data
#[derive(Debug)]
pub enum EncryptError {
    /// Provided buffer was too small
    InsufficientSize(InsufficientSizeError),

    /// Encrypter has been exhausted
    EncryptExhausted,
}

impl From<InsufficientSizeError> for EncryptError {
    fn from(v: InsufficientSizeError) -> Self {
        Self::InsufficientSize(v)
    }
}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientSize(InsufficientSizeError { required_size }) => write!(
                f,
                "cannot encrypt due to insufficient size, {required_size} bytes are required"
            ),
            Self::EncryptExhausted => f.write_str("encrypter has been exhausted"),
        }
    }
}

#[cfg(feature = "std")]
impl StdError for EncryptError {}

/// Provided buffer was too small
#[derive(Clone, Copy, Debug)]
pub struct InsufficientSizeError {
    /// buffer must be at least this size
    pub required_size: usize,
}

#[cfg(all(test, feature = "std"))]
mod tests;
