use std::collections::BTreeMap;
use std::fmt;

use fictionet::events::{ConnInfo, KeyRef, LossReason, Stamp};

use crate::ring::{Kept, Ring};
use crate::{LossStatus, Options};

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
    /// Policy class index.
    pub class: usize,
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
    pub(crate) rings: BTreeMap<usize, Ring<Key>>,
}

impl Keys {
    pub(crate) fn push(
        &mut self,
        stamp: Stamp,
        key: KeyRef<'_>,
        index: usize,
        options: &Options,
        captures: &crate::capture::Captures,
        losses: &mut LossStatus,
    ) {
        let mut class = options.policy.classes()[index];
        class.bytes = class.bytes.min(options.bytes);
        let loss_streams = options.loss_streams;
        let size = size_of::<Key>()
            .saturating_add(key.label.len())
            .saturating_add(key.client_random.len())
            .saturating_add(key.secret().len())
            .saturating_add(key.connection.map_or(0, connection_bytes));
        let ring = self.rings.entry(index).or_default();
        if !ring.admit(stamp, class.burst) {
            losses.record(loss_streams, stamp, Some(index), LossReason::Sampling, size);
            return;
        }
        if class.count == 0 || size > class.bytes {
            losses.record(loss_streams, stamp, Some(index), LossReason::Overflow, size);
            return;
        }
        if (ring.items.len() >= class.count || ring.bytes > class.bytes - size)
            && !captures.has_random(key.client_random)
        {
            let (pinned_count, pinned_bytes) = ring
                .items
                .iter()
                .filter(|key| captures.has_random(&key.client_random))
                .fold((0usize, 0usize), |(count, bytes), key| {
                    (count + 1, bytes + key.size())
                });
            if pinned_count >= class.count || pinned_bytes > class.bytes - size {
                losses.record(loss_streams, stamp, Some(index), LossReason::Overflow, size);
                return;
            }
        }
        // Prefer keys with no bytes left in a capture, within the same bounds.
        ring.make_room(
            size,
            class.count,
            class.bytes,
            |items| {
                items
                    .iter()
                    .position(|key| !captures.has_random(&key.client_random))
                    .unwrap_or(0)
            },
            |old| {
                losses.record(
                    loss_streams,
                    old.stamp,
                    Some(old.class),
                    LossReason::Eviction,
                    old.size(),
                );
            },
        );
        ring.push(Key {
            stamp,
            class: index,
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
