//! Melt relocation, lower head energy balance and vessel blowdown.
//! Cavity heat and containment water and gas remain stores for their next step.
use super::{SevereState, core::MASS_KG};
use crate::{snapshot::Regime, stages::Stage, steam};

/// Rule: melted core fraction that starts relocation, in percent.
const RELOCATION_PERCENT: f64 = 20.0;
/// Rule: melt relocation rate in kg/s.
const RELOCATION_KG_S: f64 = 200.0;
/// Rule: stored melt heat in MJ/kg.
const STORED_MJ_KG: f64 = 1.4;
/// Rule: stored melt heat draw into water in MW.
const WET_DRAW_MW: f64 = 100.0;
/// Rule: stored melt heat draw into a dry lower head in MW.
const DRY_DRAW_MW: f64 = 50.0;
/// Lower head steel heat capacity in MJ/K.
const HEAD_CAPACITY_MJ_K: f64 = 30.0;
/// Rule: lower head creep rupture temperature in C.
const BREACH_C: f64 = 1100.0;
/// Rule: breach pressure above which direct heating starts, in MPa.
const DIRECT_HEATING_MPA: f64 = 2.0;
/// Rule: initial direct containment heating pressure in kPa.
const DIRECT_HEATING_KPA: f64 = 100.0;
/// Liquid enthalpy at atmospheric pressure in kJ/kg.
const ATMOSPHERIC_LIQUID_KJ_KG: f64 = 419.0;
/// Latent heat at atmospheric pressure in kJ/kg.
const ATMOSPHERIC_LATENT_KJ_KG: f64 = 2257.0;

impl SevereState {
    pub(super) fn lower_plenum_step(&mut self, decay_mw: f64, sat_c: f64, dt: f64) -> f64 {
        let v = &mut self.values;
        let wet = v.vessel_water_kg > 0.0;
        if wet {
            v.lower_head_c = sat_c;
        }
        if v.lower_plenum_melt_t == 0.0 {
            return 0.0;
        }
        let decay = decay_mw * (v.lower_plenum_melt_t * 1000.0) / MASS_KG;
        let draw = (self.lower_plenum_mj / dt).min(if wet { WET_DRAW_MW } else { DRY_DRAW_MW });
        self.lower_plenum_mj -= dt * draw;
        if wet {
            decay + draw
        } else {
            v.lower_head_c += dt * (decay + draw) / HEAD_CAPACITY_MJ_K;
            0.0
        }
    }

    pub(super) fn relocate(&mut self, dt: f64) -> Option<Stage> {
        let v = &mut self.values;
        if v.melted_percent < RELOCATION_PERCENT {
            return None;
        }
        let target = v.melted_percent / 100.0 * MASS_KG;
        let moved = (RELOCATION_KG_S * dt).min((target - self.relocated_kg).max(0.0));
        if moved == 0.0 {
            return None;
        }
        self.relocated_kg += moved;
        if v.regime == Regime::Breached {
            v.cavity.melt_t += moved / 1000.0;
            self.cavity_mj += moved * STORED_MJ_KG;
        } else {
            v.lower_plenum_melt_t += moved / 1000.0;
            self.lower_plenum_mj += moved * STORED_MJ_KG;
        }
        Some(Stage::Relocation)
    }

    pub(super) fn breach(&mut self, pressure_mpa: f64) -> Option<Stage> {
        let v = &mut self.values;
        if v.lower_head_c < BREACH_C {
            return None;
        }
        v.breach_pressure_mpa = Some(pressure_mpa);
        v.regime = Regime::Breached;
        v.cavity.melt_t += v.lower_plenum_melt_t;
        self.cavity_mj += self.lower_plenum_mj;
        v.lower_plenum_melt_t = 0.0;
        self.lower_plenum_mj = 0.0;
        let sat = steam::saturation(pressure_mpa);
        let flash = ((sat.liquid_kj_kg - ATMOSPHERIC_LIQUID_KJ_KG) / ATMOSPHERIC_LATENT_KJ_KG)
            .clamp(0.0, 1.0);
        self.containment_steam_kg += v.inventory_kg * flash;
        self.sump_water_kg += v.inventory_kg * (1.0 - flash);
        v.containment.hydrogen_kg += v.hydrogen_in_primary_kg + v.relief_tank.hydrogen_kg;
        v.relief_tank.hydrogen_kg = 0.0;
        v.hydrogen_in_primary_kg = 0.0;
        v.inventory_kg = 0.0;
        v.pressurizer_water_kg = 0.0;
        v.vessel_water_kg = 0.0;
        v.vessel_level_percent = 0.0;
        v.uncovered_percent = 100.0;
        if pressure_mpa > DIRECT_HEATING_MPA {
            v.containment.direct_heating_kpa = DIRECT_HEATING_KPA;
        }
        Some(Stage::VesselBreach)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breach_transfers_stores_and_remaining_core_keeps_melting_into_the_cavity() {
        let mut state = SevereState::new(2500.0, 300.0);
        state.values.regime = Regime::TwoPhase;
        state.values.uncovered_percent = 100.0;
        state.values.melted_percent = 30.0;
        state.relocated_kg = 30_000.0;
        state.values.lower_plenum_melt_t = 30.0;
        state.lower_plenum_mj = 10_000.0;
        state.values.lower_head_c = 1100.0;
        state.values.hydrogen_in_primary_kg = 20.0;
        state.values.relief_tank.hydrogen_kg = 10.0;
        assert_eq!(state.breach(7.0), Some(Stage::VesselBreach));
        assert_eq!(state.values.containment.hydrogen_kg, 30.0);
        assert_eq!(state.values.relief_tank.hydrogen_kg, 0.0);
        assert_eq!(state.values.hydrogen_in_primary_kg, 0.0);
        assert_eq!(state.values.cavity.melt_t, 30.0);
        assert_eq!(state.cavity_mj, 10_000.0);
        assert_eq!(state.values.lower_plenum_melt_t, 0.0);
        assert_eq!(state.lower_plenum_mj, 0.0);
        assert!((state.containment_steam_kg + state.sump_water_kg - 162_000.0).abs() < 1e-9);
        state.core_step(20.0, 0.0, 0.05);
        state.relocate(0.05);
        assert!(state.values.melted_percent > 30.0);
        assert!(state.values.cavity.melt_t > 30.0);
        assert_eq!(state.values.hydrogen_generated_kg, 0.0);
    }
}
