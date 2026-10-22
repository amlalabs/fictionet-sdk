//! Lumped uncovered fuel heat, steam-limited zirconium oxidation and melting.
//! Steam takes no heat from the hot node beyond the downward heat share.
use super::SevereState;
use crate::{snapshot::Truth, stages::Stage};

/// Fuel, cladding and structure mass in kg.
pub(super) const MASS_KG: f64 = 100_000.0;
/// Whole core heat capacity in MJ/K.
const CAPACITY_MJ_K: f64 = 24.0;
/// Zirconium mass in kg.
const ZIRCONIUM_KG: f64 = 17_000.0;
/// Whole core melting energy in MJ.
const MELTING_MJ: f64 = 30_000.0;
/// Rule: share of uncovered core heat reaching water below, dimensionless.
const DOWNWARD_SHARE: f64 = 0.15;
/// Rule: cladding failure temperature in C.
const CLADDING_C: f64 = 900.0;
/// Rule: core melting temperature in C.
const MELTING_C: f64 = 2500.0;
/// Rule: oxidation rate in percent per minute at each temperature in C.
const OXIDATION: [[f64; 2]; 6] = [
    [900.0, 0.0],
    [1000.0, 0.2],
    [1200.0, 1.0],
    [1400.0, 3.0],
    [1600.0, 6.0],
    [1800.0, 10.0],
];
/// Zirconium consumed per kg of steam, in kg.
const ZIRCONIUM_PER_STEAM: f64 = 2.53;
/// Hydrogen made per kg of zirconium, in kg.
const HYDROGEN_PER_ZIRCONIUM: f64 = 0.0442;
/// Oxidation heat per kg of zirconium, in MJ.
const OXIDATION_MJ_KG: f64 = 6.5;
/// Hydrogen production marking the release stage, in kg.
const HYDROGEN_RELEASE_KG: f64 = 10.0;
/// Rule: core exit steam share of hot fuel superheat, dimensionless.
const EXIT_SUPERHEAT_SHARE: f64 = 0.6;

fn oxidation_rate(temperature_c: f64) -> f64 {
    if temperature_c <= OXIDATION[0][0] {
        return 0.0;
    }
    for pair in OXIDATION.windows(2) {
        if temperature_c <= pair[1][0] {
            let share = (temperature_c - pair[0][0]) / (pair[1][0] - pair[0][0]);
            return pair[0][1] + share * (pair[1][1] - pair[0][1]);
        }
    }
    OXIDATION[OXIDATION.len() - 1][1]
}

impl SevereState {
    pub(super) fn core_coverage(&mut self, old_u: f64, fuel_c: f64, sat_c: f64, dt: f64) {
        let v = &mut self.values;
        let u = v.uncovered_percent / 100.0;
        if u > old_u {
            v.hot_fuel_c = if old_u == 0.0 {
                fuel_c
            } else {
                (v.hot_fuel_c * old_u + fuel_c * (u - old_u)) / u
            };
        } else if u < old_u && v.melted_percent == 0.0 {
            self.quench_mw = (old_u - u) * CAPACITY_MJ_K * (v.hot_fuel_c - sat_c).max(0.0) / dt;
        }
        if u == 0.0 {
            v.hot_fuel_c = sat_c;
        }
    }

    pub(super) fn core_step(
        &mut self,
        thermal_mw: f64,
        steam_kg_s: f64,
        dt: f64,
    ) -> [Option<Stage>; 3] {
        let v = &mut self.values;
        let u = v.uncovered_percent / 100.0;
        if u == 0.0 {
            self.down_mw = 0.0;
            return [None; 3];
        }
        let q_core = thermal_mw * (1.0 - self.relocated_kg / MASS_KG).max(0.0);
        let mut q_ox = 0.0;
        if v.hot_fuel_c > CLADDING_C {
            let rate = oxidation_rate(v.hot_fuel_c) / 100.0 / 60.0;
            let oxidized_kg = v.zirconium_oxidized_percent / 100.0 * ZIRCONIUM_KG;
            let available =
                (u - v.melted_percent / 100.0).max(0.0) * (ZIRCONIUM_KG - oxidized_kg).max(0.0);
            let zirconium = (rate * available).min(ZIRCONIUM_PER_STEAM * steam_kg_s.max(0.0));
            q_ox = zirconium * OXIDATION_MJ_KG;
            v.zirconium_oxidized_percent += dt * zirconium / ZIRCONIUM_KG * 100.0;
            let hydrogen = zirconium * HYDROGEN_PER_ZIRCONIUM * dt;
            v.hydrogen_generated_kg += hydrogen;
            v.hydrogen_in_primary_kg += hydrogen;
        }
        let down = if v.vessel_water_kg > 0.0 {
            DOWNWARD_SHARE
        } else {
            0.0
        };
        self.down_mw = down * u * q_core;
        let q_eff = (1.0 - down) * q_core;
        let heat = dt * (u * q_eff + q_ox);
        if v.hot_fuel_c < MELTING_C {
            v.hot_fuel_c += heat / (u * CAPACITY_MJ_K);
        } else {
            v.hot_fuel_c = MELTING_C;
            v.melted_percent = (v.melted_percent + 100.0 * heat / MELTING_MJ)
                .min(v.uncovered_percent.max(v.melted_percent));
        }
        [
            (v.hot_fuel_c >= CLADDING_C).then_some(Stage::CladdingFailure),
            (v.hydrogen_generated_kg >= HYDROGEN_RELEASE_KG).then_some(Stage::HydrogenRelease),
            (v.melted_percent > 0.0).then_some(Stage::CoreMelt),
        ]
    }

    pub(super) fn core_readings(&mut self, truth: &mut Truth, sat_c: f64) {
        let v = &mut self.values;
        v.core_exit_steam_c = if v.uncovered_percent > 0.0 {
            sat_c + EXIT_SUPERHEAT_SHARE * (v.hot_fuel_c - sat_c)
        } else {
            sat_c
        };
        if v.uncovered_percent >= 99.9 {
            truth.reactor.fuel_temperature_c = v.hot_fuel_c.min(2000.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covered_core_clears_downward_heat() {
        let mut state = SevereState::new(1000.0, 300.0);
        state.values.uncovered_percent = 25.0;
        state.core_step(20.0, 0.0, 0.05);
        assert_eq!(state.down_mw, 0.15 * 0.25 * 20.0);
        state.values.uncovered_percent = 0.0;
        state.core_step(20.0, 0.0, 0.05);
        assert_eq!(state.down_mw, 0.0);
    }

    #[test]
    fn heat_crosses_melting_temperature_before_the_next_step_melts() {
        let mut state = SevereState::new(2499.99, 300.0);
        state.values.uncovered_percent = 50.0;
        state.core_step(24.0, 0.0, 0.05);
        assert!(state.values.hot_fuel_c > MELTING_C);
        assert_eq!(state.values.melted_percent, 0.0);
        state.values.uncovered_percent = 50.0001;
        state.core_coverage(0.5, 300.0, 300.0, 0.05);
        assert!(
            state
                .core_step(24.0, 0.0, 0.05)
                .contains(&Some(Stage::CoreMelt))
        );
        assert_eq!(state.values.hot_fuel_c, MELTING_C);
    }

    #[test]
    fn flashing_steam_can_oxidize_fuel_after_the_vessel_water_reaches_zero() {
        let mut state = SevereState::new(1800.0, 300.0);
        state.values.uncovered_percent = 100.0;
        state.values.vessel_water_kg = 0.0;
        state.core_step(20.0, 0.1, 0.05);
        assert!((state.values.hydrogen_generated_kg - 0.05 * 2.53 * 0.1 * 0.0442).abs() < 1e-12);
        let hydrogen = state.values.hydrogen_generated_kg;
        state.core_step(20.0, 0.0, 0.05);
        assert_eq!(state.values.hydrogen_generated_kg, hydrogen);
    }

    #[test]
    fn recovering_coverage_carries_quench_heat_for_the_next_step() {
        let mut state = SevereState::new(1000.0, 300.0);
        state.values.uncovered_percent = 25.0;
        state.core_coverage(0.5, 300.0, 300.0, 0.05);
        assert_eq!(state.quench_mw * 0.05, 0.25 * 24.0 * 700.0);
        state.core_step(20.0, 0.0, 0.05);
        assert_eq!(state.quench_mw * 0.05, 4200.0);
        assert_eq!(state.down_mw, 0.15 * 0.25 * 20.0);
    }
}
