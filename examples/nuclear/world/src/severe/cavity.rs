//! Melt heat drives concrete ablation, hydrogen release and sump boiling.
use super::{SevereState, core::MASS_KG};
use crate::stages::Stage;

/// Cavity floor area in square meters.
const AREA_M2: f64 = 30.0;
/// Concrete ablation energy in MJ per cubic meter.
const ABLATION_MJ_M3: f64 = 4800.0;
/// Stored melt heat draw in MW.
const DRAW_MW: f64 = 20.0;
/// Rule: fraction of cavity heat entering the concrete, dimensionless.
const DOWNWARD_SHARE: f64 = 0.5;
/// Hydrogen produced per cubic meter of ablated concrete, in kg.
const HYDROGEN_KG_M3: f64 = 10.0;
/// Rule: basemat melt-through depth in meters.
const FLOOR_M: f64 = 3.0;
/// Atmospheric latent heat in kJ/kg.
const LATENT_KJ_KG: f64 = 2257.0;

impl SevereState {
    pub fn cavity_step(&mut self, decay_mw: f64, dt: f64) -> Option<Stage> {
        let v = &mut self.values;
        if v.cavity.melt_t == 0.0 {
            return None;
        }
        let draw = (self.cavity_mj / dt).min(DRAW_MW);
        self.cavity_mj -= draw * dt;
        let heat = decay_mw * (v.cavity.melt_t * 1000.0) / MASS_KG + draw;
        let depth = dt * DOWNWARD_SHARE * heat / (ABLATION_MJ_M3 * AREA_M2);
        v.cavity.ablation_m += depth;
        v.containment.hydrogen_kg += HYDROGEN_KG_M3 * AREA_M2 * depth;
        let steam = dt * (1.0 - DOWNWARD_SHARE) * heat * 1000.0 / LATENT_KJ_KG;
        self.containment_steam_kg += steam;
        self.sump_water_kg = (self.sump_water_kg - steam).max(0.0);
        (v.cavity.ablation_m >= FLOOR_M).then_some(Stage::FloorMeltThrough)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ablation_heat_and_hydrogen_follow_the_energy_balance() {
        let mut state = SevereState::new(625.0, 325.0);
        state.values.cavity.melt_t = 50.0;
        state.cavity_mj = 70_000.0;
        let mut depth = 0.0;
        for _ in 0..100 {
            state.cavity_step(20.0, 0.05);
            assert!(state.values.cavity.ablation_m > depth);
            depth = state.values.cavity.ablation_m;
            assert!((state.values.containment.hydrogen_kg - 300.0 * depth).abs() < 1e-12);
        }
        assert!((depth - 5.0 * 0.5 * 30.0 / (4800.0 * 30.0)).abs() < 1e-12);
        assert!((state.containment_steam_kg - 5.0 * 0.5 * 30.0 * 1000.0 / 2257.0).abs() < 1e-12);
    }
}
