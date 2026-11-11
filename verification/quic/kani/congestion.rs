//! BBR initializes its pacing random state only from the supplied source.

use super::*;
use rand::TryRng;

struct Entropy {
    seed: [u8; 16],
    consumed: usize,
}

impl TryRng for Entropy {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Self::Error> {
        out.copy_from_slice(&self.seed[self.consumed..self.consumed + out.len()]);
        self.consumed += out.len();
        Ok(())
    }
}

#[kani::proof]
#[kani::unwind(17)]
fn bbr_uses_supplied_entropy() {
    let seed = kani::any();
    let mut entropy = Entropy { seed, consumed: 0 };
    let bbr = Bbr::new(Arc::new(BbrConfig::default()), 1200, &mut entropy);
    let expected = Pcg32::from_seed(seed);
    assert_eq!(entropy.consumed, seed.len());
    assert_eq!(bbr.random_number_generator, expected);
}

#[kani::proof]
#[kani::unwind(17)]
fn bbr_startup_respects_its_target_window() {
    let mut rng = Pcg32::from_seed([0; 16]);
    let mut bbr = Bbr::new(Arc::new(BbrConfig::default()), 1200, &mut rng);
    let window: u64 = kani::any();
    kani::assume(window >= bbr.init_cwnd);
    bbr.cwnd = window;
    bbr.acked_bytes = bbr.init_cwnd;
    bbr.calculate_cwnd(kani::any(), 0);
    assert_eq!(bbr.cwnd, window);
    std::mem::forget(bbr);
}
