use fictionet::events::{Loss, LossReason, Stamp};

/// Persistent loss totals. Sequence ranges are omitted because gaps may be disjoint.
#[derive(Clone, Debug, Default)]
pub struct LossStatus {
    /// Totals by stream and cause, within the configured stream bound.
    pub streams: Vec<Loss>,
    /// Totals whose stream could not fit in the detail budget.
    pub untracked: Vec<LossTotal>,
    stream_count: usize,
}

/// Loss whose stream detail exceeded the configured bound.
#[derive(Clone, Debug)]
pub struct LossTotal {
    /// Cause of loss.
    pub reason: LossReason,
    /// Number of affected observations.
    pub count: u64,
    /// Known affected bytes.
    pub bytes: u64,
}

impl LossStatus {
    pub(crate) fn add(&mut self, limit: usize, loss: Loss) {
        if loss.count == 0 {
            return;
        }
        if let Some(total) = self
            .streams
            .iter_mut()
            .find(|total| total.stream == loss.stream && total.reason == loss.reason)
        {
            total.count = total.count.saturating_add(loss.count);
            total.bytes = total
                .bytes
                .zip(loss.bytes)
                .map(|(a, b)| a.saturating_add(b));
        } else if self.streams.iter().any(|total| total.stream == loss.stream)
            || self.stream_count < limit
        {
            if !self.streams.iter().any(|total| total.stream == loss.stream) {
                self.stream_count += 1;
            }
            self.streams.push(Loss { seqs: None, ..loss });
        } else if let Some(total) = self
            .untracked
            .iter_mut()
            .find(|total| total.reason == loss.reason)
        {
            total.count = total.count.saturating_add(loss.count);
            total.bytes = total.bytes.saturating_add(loss.bytes.unwrap_or(0));
        } else {
            self.untracked.push(LossTotal {
                reason: loss.reason,
                count: loss.count,
                bytes: loss.bytes.unwrap_or(0),
            });
        }
    }

    pub(crate) fn record(&mut self, limit: usize, stamp: Stamp, reason: LossReason, bytes: usize) {
        self.add(
            limit,
            Loss {
                stream: stamp.stream,
                reason,
                count: 1,
                bytes: Some(bytes as u64),
                seqs: None,
            },
        );
    }
}
