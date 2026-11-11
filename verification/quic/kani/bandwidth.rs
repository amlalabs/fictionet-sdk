use super::*;
use crate::counting::{counted_proof, measure};

counted_proof! {
    #[kani::unwind(4)]
    fn bbr_bandwidth_samples_expire_without_allocating() {
        let prior: u64 = kani::any();
        let sample: u64 = kani::any();
        let app_limited: bool = kani::any();
        let (estimator, cost) = measure(|| {
            let mut estimator = BandwidthEstimation::default();
            estimator.update_bandwidth(1, prior, false);
            estimator.update_bandwidth(12, sample, app_limited);
            estimator
        });
        let expected = if app_limited && sample <= prior { prior } else { sample };
        assert_eq!(estimator.get_estimate(), expected);
        assert!(cost.peak <= 0);
        assert!(cost.requested <= 0);
    }
}

#[kani::proof]
fn bbr_bandwidth_conversion_keeps_a_full_width_byte_count() {
    let bytes: u64 = kani::any();
    assert_eq!(
        BandwidthEstimation::bw_from_delta(bytes, Duration::from_secs(1)),
        Some(bytes)
    );
    assert_eq!(
        BandwidthEstimation::bw_from_delta(bytes, Duration::ZERO),
        None
    );
    assert_eq!(
        BandwidthEstimation::bw_from_delta(bytes, Duration::MAX),
        Some(0)
    );
}

#[kani::proof]
fn bbr_bandwidth_conversion_saturates_unrepresentable_rates() {
    let bytes: u64 = kani::any();
    let result = BandwidthEstimation::bw_from_delta(bytes, Duration::from_nanos(1));
    assert_eq!(result, Some(bytes.saturating_mul(1_000_000_000)));
}
