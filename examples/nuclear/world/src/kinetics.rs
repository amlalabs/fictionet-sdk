//! Six delayed groups in the prompt jump approximation.
//!
//! Fractions and decay constants are the conventional thermal U-235 six-group
//! data in Lamarsh and Baratta. Precursors are normalized to equilibrium at
//! rated fission power. The prompt lifetime is omitted: p = sum(beta_i c_i)
//! / (beta - rho), dc_i/dt = lambda_i (p - c_i). Forward Euler uses 50 ms.
//! Reactivity is limited to 0.9 beta. This approximation cannot describe a
//! prompt-critical excursion. Power above ten times rated also reaches the
//! model boundary. Both boundaries latch the plant's model_limit flag.
//!
//! Decay groups are tuning, not isotope inventories. Fractions of rated total
//! heat sum to 6.6%. After shutdown the six groups stay within 1.15 times
//! the infinite-irradiation Way-Wigner curve from 10 s to 3 hours, and within
//! 1.35 times the one-year-irradiation curve out to three days.
//! Fission supplies the remaining 93.4% of equilibrium thermal heat.

/// Delayed neutron fractions, dimensionless.
pub const BETA_GROUPS: [f64; 6] = [0.000215, 0.001424, 0.001274, 0.002568, 0.000748, 0.000273];
/// Precursor decay constants in inverse seconds.
pub const LAMBDA: [f64; 6] = [0.0124, 0.0305, 0.111, 0.301, 1.14, 3.01];
/// Total delayed neutron fraction.
pub const BETA: f64 = 0.006502;
/// Rule: fractions of rated heat assigned to the six decay groups.
const DECAY_FRACTIONS: [f64; 6] = [0.020, 0.013, 0.012, 0.008, 0.007, 0.006];
/// Rule: decay group time constants in seconds.
const DECAY_SECONDS: [f64; 6] = [2.0, 30.0, 300.0, 3000.0, 30000.0, 300000.0];

#[derive(Clone, Debug)]
pub(crate) struct Kinetics {
    pub power: f64,
    precursors: [f64; 6],
    decay: [f64; 6],
}

impl Kinetics {
    pub fn new(power: f64) -> Self {
        Self {
            power,
            precursors: [power; 6],
            decay: DECAY_FRACTIONS.map(|fraction| fraction * power),
        }
    }

    pub fn step(&mut self, rho: f64, dt: f64) -> bool {
        let limited = rho.min(0.9 * BETA);
        let source: f64 = BETA_GROUPS
            .iter()
            .zip(self.precursors)
            .map(|(b, c)| b * c)
            .sum();
        let power = source / (BETA - limited);
        self.power = power.min(10.0);
        for (c, lambda) in self.precursors.iter_mut().zip(LAMBDA) {
            *c += dt * lambda * (self.power - *c);
        }
        decay_step(&mut self.decay, self.power, dt);
        rho > limited || power > 10.0
    }

    pub fn decay_fraction(&self) -> f64 {
        self.decay.iter().sum()
    }
    pub fn thermal_fraction(&self) -> f64 {
        0.934 * self.power + self.decay_fraction()
    }
}

fn decay_step(decay: &mut [f64; 6], fission_power: f64, dt: f64) {
    for ((d, fraction), tau) in decay.iter_mut().zip(DECAY_FRACTIONS).zip(DECAY_SECONDS) {
        *d += dt * (fraction * fission_power - *d) / tau;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decay_after_shutdown() {
        let mut decay = DECAY_FRACTIONS;
        let mut step = 0;
        for (seconds, expected) in [
            (10, 4.20),
            (100, 2.98),
            (1000, 1.89),
            (3600, 1.46),
            (36000, 0.74),
            (100000, 0.46),
        ] {
            while step < seconds * 20 {
                decay_step(&mut decay, 0.0, 0.05);
                step += 1;
            }
            let measured = decay.iter().sum::<f64>() * 100.0;
            println!("{seconds} s: {measured:.6}% (target {expected}%)");
            assert!((measured / expected - 1.0).abs() < 0.03);
        }
    }

    #[test]
    fn prompt_jump_and_asymptotic_inhour_period() {
        let rho = 0.0005;
        let mut k = Kinetics::new(1.0);
        k.step(rho, 0.05);
        assert!((k.power - BETA / (BETA - rho)).abs() < 1e-12);
        // Solve rho = sum(beta_i * s / (s + lambda_i)); prompt lifetime is zero.
        let (mut lo, mut hi) = (0.0, 1.0);
        for _ in 0..100 {
            let s = (lo + hi) / 2.0;
            let r: f64 = BETA_GROUPS
                .iter()
                .zip(LAMBDA)
                .map(|(b, l)| b * s / (s + l))
                .sum();
            if r < rho {
                lo = s;
            } else {
                hi = s;
            }
        }
        let s = (lo + hi) / 2.0;
        for _ in 1..4000 {
            k.step(rho, 0.05);
        }
        let before = k.power;
        for _ in 0..1000 {
            k.step(rho, 0.05);
        }
        let measured = (k.power / before).ln() / 50.0;
        // Euler error is O(s dt); the slowest precursor's transient has had
        // over two decay times. One percent covers these discretization terms.
        assert!((measured / s - 1.0).abs() < 0.01, "{measured} versus {s}");
    }
}
