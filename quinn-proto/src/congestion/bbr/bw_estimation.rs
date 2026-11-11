use std::fmt::{Debug, Display, Formatter};

use super::min_max::MinMax;
use crate::{Duration, Instant};

#[derive(Clone, Debug, Default)]
pub(crate) struct BandwidthEstimation {
    total_acked: u64,
    prev_total_acked: u64,
    acked_time: Option<Instant>,
    prev_acked_time: Option<Instant>,
    total_sent: u64,
    prev_total_sent: u64,
    sent_time: Option<Instant>,
    prev_sent_time: Option<Instant>,
    max_filter: MinMax,
    acked_at_last_window: u64,
}

impl BandwidthEstimation {
    pub(crate) fn on_sent(&mut self, now: Instant, bytes: u64) {
        self.prev_total_sent = self.total_sent;
        self.total_sent += bytes;
        self.prev_sent_time = self.sent_time;
        self.sent_time = Some(now);
    }

    pub(crate) fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        bytes: u64,
        round: u64,
        app_limited: bool,
    ) {
        self.prev_total_acked = self.total_acked;
        self.total_acked += bytes;
        self.prev_acked_time = self.acked_time;
        self.acked_time = Some(now);

        let prev_sent_time = match self.prev_sent_time {
            Some(prev_sent_time) => prev_sent_time,
            None => return,
        };

        let send_rate = match self.sent_time {
            Some(sent_time) if sent_time > prev_sent_time => Self::bw_from_delta(
                self.total_sent - self.prev_total_sent,
                sent_time - prev_sent_time,
            )
            .unwrap_or(0),
            _ => u64::MAX, // will take the min of send and ack, so this is just a skip
        };

        let ack_rate = match self.prev_acked_time {
            Some(prev_acked_time) => Self::bw_from_delta(
                self.total_acked - self.prev_total_acked,
                now - prev_acked_time,
            )
            .unwrap_or(0),
            None => 0,
        };

        let bandwidth = send_rate.min(ack_rate);
        self.update_bandwidth(round, bandwidth, app_limited);
    }

    fn update_bandwidth(&mut self, round: u64, bandwidth: u64, app_limited: bool) {
        if !app_limited || self.max_filter.get() < bandwidth {
            self.max_filter.update_max(round, bandwidth);
        }
    }

    pub(crate) fn bytes_acked_this_window(&self) -> u64 {
        self.total_acked - self.acked_at_last_window
    }

    pub(crate) fn end_acks(&mut self, _current_round: u64, _app_limited: bool) {
        self.acked_at_last_window = self.total_acked;
    }

    pub(crate) fn get_estimate(&self) -> u64 {
        self.max_filter.get()
    }

    pub(crate) fn bw_from_delta(bytes: u64, delta: Duration) -> Option<u64> {
        let window_duration_ns = delta.as_nanos();
        if window_duration_ns == 0 {
            return None;
        }
        let bytes_per_second = u128::from(bytes) * 1_000_000_000 / window_duration_ns;
        Some(bytes_per_second.min(u128::from(u64::MAX)) as u64)
    }
}

impl Display for BandwidthEstimation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:.3} MB/s",
            self.get_estimate() as f32 / (1024 * 1024) as f32
        )
    }
}

#[cfg(kani)]
#[path = "../../../../verification/quic/kani/bandwidth.rs"]
mod proofs;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(estimator: &mut BandwidthEstimation, round: u64, bytes: u64, limited: bool) {
        let now = estimator.sent_time.unwrap() + Duration::from_secs(1);
        estimator.on_sent(now, bytes);
        estimator.on_ack(now, now, bytes, round, limited);
    }

    #[test]
    fn bandwidth_tracks_a_slower_path_after_the_window_expires() {
        let mut estimator = BandwidthEstimation::default();
        let now = Instant::now();
        estimator.on_sent(now, 1000);
        estimator.on_ack(now, now, 1000, 0, false);
        sample(&mut estimator, 1, 1000, false);
        assert_eq!(estimator.get_estimate(), 1000);
        for round in 2..=12 {
            sample(&mut estimator, round, 100, false);
        }
        assert_eq!(estimator.get_estimate(), 100);
    }

    #[test]
    fn application_limited_samples_can_raise_but_not_lower_the_estimate() {
        let mut estimator = BandwidthEstimation::default();
        let now = Instant::now();
        estimator.on_sent(now, 1000);
        estimator.on_ack(now, now, 1000, 0, false);
        sample(&mut estimator, 1, 1000, false);
        sample(&mut estimator, 12, 100, true);
        assert_eq!(estimator.get_estimate(), 1000);
        sample(&mut estimator, 13, 2000, true);
        assert_eq!(estimator.get_estimate(), 2000);
    }

    #[test]
    fn bandwidth_conversion_preserves_large_counts_and_durations() {
        assert_eq!(
            BandwidthEstimation::bw_from_delta(u64::MAX, Duration::from_secs(1)),
            Some(u64::MAX)
        );
        assert_eq!(
            BandwidthEstimation::bw_from_delta(u64::MAX, Duration::from_nanos(1)),
            Some(u64::MAX)
        );
        assert_eq!(
            BandwidthEstimation::bw_from_delta(1, Duration::MAX),
            Some(0)
        );
        assert_eq!(BandwidthEstimation::bw_from_delta(1, Duration::ZERO), None);
    }
}
