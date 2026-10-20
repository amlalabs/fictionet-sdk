use std::fmt;

use fictionet::events::{ConnInfo, KeyRef, LossReason, Stamp};

use crate::ring::{Kept, Ring};
use crate::{Bounds, LossStatus};

impl Kept for Key {
    fn stamp(&self) -> Stamp {
        self.stamp
    }
    fn size(&self) -> usize {
        Key::size(self)
    }
}

/// An owned TLS key. Debug output excludes its secret.
#[derive(Clone)]
pub struct Key {
    /// Run sequence and time.
    pub stamp: Stamp,
    /// TLS key log label.
    pub label: String,
    /// ClientHello random.
    pub client_random: Vec<u8>,
    /// Connection context, when supplied by the producer.
    pub connection: Option<ConnInfo>,
    secret: Vec<u8>,
}

impl Key {
    /// Secret bytes for an explicitly interested consumer.
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    fn size(&self) -> usize {
        size_of::<Self>()
            + self.label.len()
            + self.client_random.len()
            + self.secret.len()
            + self.connection.as_ref().map_or(0, connection_bytes)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("stamp", &self.stamp)
            .field("label", &self.label)
            .field("client_random", &self.client_random)
            .field("connection", &self.connection)
            .field("secret_len", &self.secret.len())
            .finish()
    }
}

pub(crate) fn connection_bytes(conn: &ConnInfo) -> usize {
    conn.sni
        .as_ref()
        .map_or(0, |s| s.len())
        .saturating_add(conn.alpn.as_ref().map_or(0, |s| s.len()))
        .saturating_add(conn.sandbox.as_ref().map_or(0, |s| s.name.len()))
}

#[derive(Default)]
pub(crate) struct Keys {
    pub(crate) ring: Ring<Key>,
}

impl Keys {
    pub(crate) fn push(
        &mut self,
        stamp: Stamp,
        key: KeyRef<'_>,
        bounds: Bounds,
        losses: &mut LossStatus,
        loss_streams: usize,
    ) {
        let size = size_of::<Key>()
            .saturating_add(key.label.len())
            .saturating_add(key.client_random.len())
            .saturating_add(key.secret().len())
            .saturating_add(key.connection.map_or(0, connection_bytes));
        if bounds.count == 0 || size > bounds.bytes {
            losses.record(loss_streams, stamp, LossReason::Overflow, size);
            return;
        }
        self.ring
            .make_room(size, bounds.count, bounds.bytes, |old| {
                losses.record(loss_streams, old.stamp, LossReason::Eviction, old.size());
            });
        self.ring.push(Key {
            stamp,
            label: key.label.into(),
            client_random: key.client_random.into(),
            secret: key.secret().into(),
            connection: key.connection.cloned(),
        });
    }
}

/// Renders retained keys in SSLKEYLOGFILE format.
pub fn keylog(keys: &[Key]) -> String {
    let mut output = String::new();
    for key in keys {
        push_keylog_line(&mut output, &key.label, &key.client_random, &key.secret);
    }
    output
}

/// Appends one SSLKEYLOGFILE line: the label, then the client random and
/// the secret in lowercase hex.
pub(crate) fn push_keylog_line(
    output: &mut String,
    label: &str,
    client_random: &[u8],
    secret: &[u8],
) {
    output.push_str(label);
    for bytes in [client_random, secret] {
        output.push(' ');
        crate::push_hex(output, bytes);
    }
    output.push('\n');
}
