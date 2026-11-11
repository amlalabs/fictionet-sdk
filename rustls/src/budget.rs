//! Paying for the bytes a connection's buffers hold.
//!
//! A connection made with a [`BufferBudget`] charges it before any of its
//! buffers grows: the record arriving (or a handshake message being joined),
//! the plaintext it has decrypted and not yet handed over, the plaintext
//! written before the handshake finished, and the records queued to send.
//! A received handshake message is also charged, before it is parsed, room
//! for what parsing it allocates, kept while it is
//! processed; an [`Accepted`] keeps its hello's until it is answered.
//! Each buffer holds one charge that always covers its allocation, and gives
//! back what it frees. A record's plaintext stays in the buffer the record
//! arrived in, which joins the plaintext queue with its charge: the queue's
//! charge takes it in, and the budget's total does not move. Buffers are
//! freed once empty, so an idle connection holds none.
//!
//! The one charge an idle connection keeps is the room for its final alert,
//! a fatal alert or a `close_notify`, paid before the first byte it reads:
//! that alert goes out whatever the budget says when it is sent.
//!
//! A growth the budget refuses changes nothing, and the call that wanted it
//! says so in a way that can be retried once memory frees:
//!
//! - [`ConnectionCommon::read_tls`] fails with
//!   [`io::ErrorKind::OutOfMemory`](std::io::ErrorKind::OutOfMemory) without
//!   reading anything.
//! - [`ConnectionCommon::process_new_packets`] stops before the record or
//!   message it cannot pay for, leaving it buffered, and
//!   [`CommonState::wants_budget`] says so until a later call gets past it.
//! - [`Writer`](crate::Writer) takes fewer bytes, perhaps none.
//! - [`Accepted::into_connection`] and [`Accepted::into_unbuffered`] give the
//!   [`Accepted`] back.
//! - [`ConnectionCommon::refresh_traffic_keys`] fails with
//!   [`Error::BudgetExhausted`], having queued nothing.
//!
//! The output rustls makes for a message it receives (a handshake flight, a
//! key update, an alert) cannot be refused halfway through, since the
//! handshake state has moved on by then. So before each message the
//! connection charges room for the most that message can make, and the output
//! is paid from that room. A server whose config bounds what its flight,
//! CA names and tickets take ([`ServerConfig::most_connection`]) charges
//! room for all of it, so its output never outgrows the room. Without that
//! bound, output that outgrows its room is charged directly; if that is
//! refused too, the output is dropped and the connection fails with
//! [`Error::BudgetExhausted`] rather than hold bytes nothing pays for.
//!
//! [`ConnectionCommon::read_tls`]: crate::ConnectionCommon::read_tls
//! [`ConnectionCommon::process_new_packets`]: crate::ConnectionCommon::process_new_packets
//! [`ConnectionCommon::refresh_traffic_keys`]: crate::ConnectionCommon::refresh_traffic_keys
//! [`CommonState::wants_budget`]: crate::CommonState::wants_budget
//! [`CommonState::send_close_notify`]: crate::CommonState::send_close_notify
//! [`Accepted::into_connection`]: crate::server::Accepted::into_connection
//! [`Accepted::into_unbuffered`]: crate::server::Accepted::into_unbuffered
//! [`Accepted`]: crate::server::Accepted
//! [`Error::BudgetExhausted`]: crate::Error::BudgetExhausted
//! [`ServerConfig::most_connection`]: crate::ServerConfig::most_connection

use alloc::vec::Vec;
use core::fmt;

use crate::sync::Arc;

/// Where a connection's buffers are paid from: a count of bytes that
/// refuses to go past its limit.
///
/// The connection holds what it takes in charges of its own, which give it
/// back when dropped.
pub trait BufferBudget: Send + Sync {
    /// Takes `bytes`, if they fit. Refuses, changing nothing, if not.
    fn take(&self, bytes: usize) -> bool;

    /// Gives back `bytes` taken before.
    fn give_back(&self, bytes: usize);
}

/// Bytes charged to a [`BufferBudget`], given back when dropped.
///
/// Making, growing, splitting and dropping one allocates nothing: it is the
/// budget and a count.
#[must_use = "a charge that is dropped gives its bytes back"]
pub(crate) struct BufferCharge {
    budget: Arc<dyn BufferBudget>,
    bytes: usize,
}

impl BufferCharge {
    /// A charge of nothing on `budget`.
    pub(crate) fn nothing(budget: &Arc<dyn BufferBudget>) -> Self {
        Self {
            budget: budget.clone(),
            bytes: 0,
        }
    }

    /// The bytes charged now.
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    /// Charges `to` bytes in all, if that is more than now. Refuses,
    /// changing nothing, if the budget has no room for the difference.
    fn grow_to(&mut self, to: usize) -> bool {
        if to <= self.bytes {
            return true;
        }
        if !self.budget.take(to - self.bytes) {
            return false;
        }
        self.bytes = to;
        true
    }

    /// Charges only `to` bytes, if that is less than now, giving back the
    /// rest.
    fn shrink_to(&mut self, to: usize) {
        if to < self.bytes {
            self.budget.give_back(self.bytes - to);
            self.bytes = to;
        }
    }

    /// Moves `bytes` of this charge into a new one on the same budget, as
    /// when the bytes it pays for leave the buffer. The budget's total does
    /// not change. `None`, changing nothing, if this charge holds less.
    fn split(&mut self, bytes: usize) -> Option<Self> {
        if bytes > self.bytes {
            return None;
        }
        self.bytes -= bytes;
        Some(Self {
            budget: self.budget.clone(),
            bytes,
        })
    }

    /// Takes `other` into this charge, as when the bytes it pays for join
    /// this buffer. The budget's total does not change. Gives `other` back,
    /// still charged, if it is on another budget.
    fn absorb(&mut self, mut other: Self) -> Result<(), Self> {
        if !Arc::ptr_eq(&self.budget, &other.budget) {
            return Err(other);
        }
        self.bytes += core::mem::take(&mut other.bytes);
        Ok(())
    }
}

impl Drop for BufferCharge {
    fn drop(&mut self) {
        if self.bytes != 0 {
            self.budget.give_back(self.bytes);
        }
    }
}

impl fmt::Debug for BufferCharge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BufferCharge").field(&self.bytes).finish()
    }
}

/// Bytes moved from one of a connection's buffers to another with the
/// charge that pays for their allocation, so they move without a copy.
pub(crate) struct PaidBytes {
    bytes: Vec<u8>,
    charge: Option<BufferCharge>,
}

impl PaidBytes {
    pub(crate) fn new(bytes: Vec<u8>, charge: Option<BufferCharge>) -> Self {
        Self { bytes, charge }
    }

    /// The bytes, and their charge: `None` for a connection without a
    /// budget, otherwise exactly their capacity.
    pub(crate) fn into_parts(self) -> (Vec<u8>, Option<BufferCharge>) {
        (self.bytes, self.charge)
    }
}

impl fmt::Debug for PaidBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaidBytes")
            .field("len", &self.bytes.len())
            .field("charged", &self.charge.as_ref().map(BufferCharge::bytes))
            .finish()
    }
}

/// A connection's budget, if it has one.
pub(crate) type Account = Option<Arc<dyn BufferBudget>>;

/// What one buffer's allocation is charged. Nothing is charged for a
/// connection without a budget, and every growth fits.
#[derive(Default)]
pub(crate) struct Paid(Option<BufferCharge>);

impl Paid {
    /// A charge of nothing on `account`.
    pub(crate) fn open(account: &Account) -> Self {
        Self(account.as_ref().map(BufferCharge::nothing))
    }

    /// Whether this charges a budget at all.
    #[cfg(test)]
    pub(crate) fn is_budgeted(&self) -> bool {
        self.0.is_some()
    }

    /// The bytes charged now.
    pub(crate) fn bytes(&self) -> usize {
        self.0.as_ref().map_or(0, |charge| charge.bytes())
    }

    /// Charges `more` bytes before the buffer grows by them. Refuses,
    /// changing nothing, if they do not fit.
    #[must_use = "a refused growth must not be followed by the growth"]
    pub(crate) fn grow_by(&mut self, more: usize) -> bool {
        match &mut self.0 {
            Some(charge) => {
                let to = charge.bytes() + more;
                charge.grow_to(to)
            }
            None => true,
        }
    }

    /// Gives back `less` bytes the buffer freed.
    pub(crate) fn shrink_by(&mut self, less: usize) {
        if let Some(charge) = &mut self.0 {
            let to = charge.bytes().saturating_sub(less);
            charge.shrink_to(to);
        }
    }

    /// Moves `bytes` of this charge out with the bytes it pays for.
    pub(crate) fn split(&mut self, bytes: usize) -> Option<BufferCharge> {
        self.0.as_mut()?.split(bytes)
    }

    /// Takes in the charge that pays for bytes joining this buffer.
    /// `false` if it is not a charge on this buffer's budget: it is
    /// dropped, giving its bytes back, and the bytes must go with it.
    #[must_use = "bytes whose charge was refused must be dropped with it"]
    pub(crate) fn absorb(&mut self, other: Option<BufferCharge>) -> bool {
        match (&mut self.0, other) {
            (None, None) => true,
            (Some(charge), Some(other)) => charge.absorb(other).is_ok(),
            (_, _) => false,
        }
    }
}

impl fmt::Debug for Paid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Paid").field(&self.bytes()).finish()
    }
}

/// The room charged before a handshake message is processed, for the output
/// it makes: one full record, enough for every handshake message whose size
/// the config does not set. What the config sets (a certificate chain, the
/// CA names of a certificate request, tickets) is added by
/// [`handshake_room`].
pub(crate) const HANDSHAKE_ROOM: usize = crate::msgs::message::MAX_WIRE_SIZE;

/// How many messages one received handshake message's output is made of,
/// each of which may end in a record of its own. A server's largest flight
/// in TLS 1.3 is ServerHello, ChangeCipherSpec, EncryptedExtensions,
/// CertificateRequest, Certificate, CertificateVerify and Finished; tickets
/// follow the client's Finished, in one flight.
pub(crate) const HANDSHAKE_RECORDS: usize = 8;

/// The most a record adds to its payload: the 5-byte header and the most a
/// cipher adds (TLS 1.2 GCM's 8-byte explicit nonce and 16-byte tag; TLS
/// 1.3 adds a type byte and a tag, 17 bytes).
pub(crate) const RECORD_OVERHEAD: usize = 5 + 8 + 16;

/// The room, in bytes and records, for the output of one received handshake
/// message: [`HANDSHAKE_ROOM`] for the messages whose size the config does
/// not set, and `more` bytes of the messages whose size it does, all cut
/// into records of at most `fragment` bytes of payload.
pub(crate) fn handshake_room(more: usize, fragment: usize) -> (usize, usize) {
    let payload = HANDSHAKE_ROOM + more;
    let records = HANDSHAKE_RECORDS + (payload + fragment - 1) / fragment;
    (payload + records * RECORD_OVERHEAD, records)
}

/// The bytes a certificate chain and its OCSP response take in the
/// server's Certificate (and, in TLS 1.2, CertificateStatus) message.
pub(crate) fn chain_bytes(chain: &[pki_types::CertificateDer<'_>], ocsp: Option<&[u8]>) -> usize {
    /// A certificate entry's 24-bit length and 16-bit extensions length.
    const ENTRY: usize = 3 + 2;
    /// The status_request extension around an OCSP response.
    const STATUS: usize = 4 + 1 + 3;
    chain
        .iter()
        .map(|cert| cert.as_ref().len() + ENTRY)
        .sum::<usize>()
        + ocsp.map_or(0, |ocsp| ocsp.len() + STATUS)
}

/// The room charged before a received handshake message of `len` bytes is
/// parsed, for what parsing it allocates while it is processed: the
/// message parses into lists of elements, each of which can be larger in
/// memory than on the wire.
///
/// - Per byte: an element takes at most a vector and the one byte it
///   holds for every two bytes on the wire. The smallest such elements
///   are a protocol name and a PSK binder (a one-byte length and one byte
///   of name), 25 bytes in memory; every other element of a client's
///   messages takes less per byte (a key share 33 for 5, a PSK identity
///   33 for 7, a group or a cipher suite 4 for 2). A list's vector holds
///   at most twice its elements, and while it grows its old allocation
///   is held beside the new: three times in all.
/// - Fixed: each list's first allocation holds four elements whatever
///   its length, and a hello's extensions are boxed.
pub const fn parse_room(len: usize) -> usize {
    /// A vector and the byte it holds, for two bytes on the wire.
    const ELEMENT: usize = size_of::<Vec<u8>>() + 1;
    /// The lists a ClientHello parses into, the message with the most:
    /// cipher suites, compression methods, groups, signature schemes,
    /// protocols, client and server certificate types, compression
    /// algorithms, PSK identities and binders, OCSP responder ids, CA
    /// names, key shares, the extensions kept in order, the outer ECH
    /// extensions, and the supported versions.
    const LISTS: usize = 16;
    /// The largest element of those lists, a key share.
    const LARGEST: usize = size_of::<crate::msgs::handshake::KeyShareEntry>();
    const FIXED: usize =
        LISTS * 4 * LARGEST + size_of::<crate::msgs::handshake::ClientExtensions<'static>>();
    FIXED + len * 3 * ELEMENT / 2
}

/// What the deframer's spans of a handshake message take while it is
/// joined from records, which no charge counts: the part joined so far
/// and the record arriving, coalesced at once, in the first capacity a
/// vector of them takes (four, for elements this small).
pub const JOINING_SPANS: usize = 4 * size_of::<crate::msgs::deframer::handshake::FragmentSpan>();

/// The most records one message received after the handshake makes: a
/// close_notify when the peer's records use up the read keys, a key update,
/// and an alert.
pub(crate) const CONTROL_RECORDS: usize = 3;

/// The largest payload of those records: a KeyUpdate handshake message, a
/// 4-byte header and one byte. An alert is two.
pub(crate) const CONTROL_PAYLOAD: usize = 5;

#[cfg(all(test, feature = "std"))]
pub(crate) mod tests;

#[cfg(all(test, feature = "std"))]
mod record_trace;

#[cfg(all(test, feature = "std"))]
mod costs;

#[cfg(test)]
pub(crate) mod testing {
    //! A budget for the crate's own tests.

    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::BufferBudget;
    use crate::sync::Arc;

    /// At most `limit` bytes, shared by every charge on it.
    pub(crate) struct Limit {
        used: AtomicUsize,
        limit: AtomicUsize,
        /// The most `used` has been.
        most: AtomicUsize,
    }

    impl Limit {
        pub(crate) fn new(limit: usize) -> Arc<Self> {
            Arc::new(Self {
                used: AtomicUsize::new(0),
                limit: AtomicUsize::new(limit),
                most: AtomicUsize::new(0),
            })
        }

        pub(crate) fn used(&self) -> usize {
            self.used.load(Ordering::SeqCst)
        }

        /// The most charged at once since [`Self::reset_most`], reservations
        /// held within a call included.
        pub(crate) fn most(&self) -> usize {
            self.most.load(Ordering::SeqCst)
        }

        /// Starts counting [`Self::most`] from what is charged now.
        pub(crate) fn reset_most(&self) {
            self.most.store(self.used(), Ordering::SeqCst);
        }

        pub(crate) fn set_limit(&self, limit: usize) {
            self.limit.store(limit, Ordering::SeqCst);
        }
    }

    impl BufferBudget for Limit {
        fn take(&self, bytes: usize) -> bool {
            let limit = self.limit.load(Ordering::SeqCst);
            let taken = self
                .used
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                    (used + bytes <= limit).then_some(used + bytes)
                });
            match taken {
                Ok(before) => {
                    self.most.fetch_max(before + bytes, Ordering::SeqCst);
                    true
                }
                Err(_) => false,
            }
        }

        fn give_back(&self, bytes: usize) {
            self.used.fetch_sub(bytes, Ordering::SeqCst);
        }
    }
}
