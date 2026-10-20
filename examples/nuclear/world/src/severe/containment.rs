//! Relief enthalpy, hydrogen transport, condensation and a lumped gas mixture.
//! Burning converts hydrogen into steam and adds a decaying pressure excess.
use super::SevereState;
use crate::{
    stages::{FailureCause, Stage},
    steam,
};

/// Containment free volume in cubic meters.
const VOLUME_M3: f64 = 35_000.0;
/// Initial air inventory in moles.
const AIR_MOL: f64 = 1.3615e6;
/// Ideal gas constant in joules per mole per kelvin.
const GAS_J_MOL_K: f64 = 8.314;
/// Hydrogen molar mass in kg/mol.
const HYDROGEN_KG_MOL: f64 = 0.002016;
/// Rule: relief tank disk rupture energy in MJ.
const DISK_MJ: f64 = 20_000.0;
/// Tank initial pressure in kPa.
const TANK_INITIAL_KPA: f64 = 100.0;
/// Tank pressure rise at disk rupture in kPa.
const TANK_RISE_KPA: f64 = 600.0;
/// Tailpipe thermal relaxation time in seconds.
const TAILPIPE_SECONDS: f64 = 20.0;
/// Tailpipe ambient temperature and flowing superheat in C.
const TAILPIPE_C: f64 = 40.0;
/// Primary hydrogen release time in seconds while relief valves flow.
const HYDROGEN_SECONDS: f64 = 600.0;
/// Structure condensation time in seconds.
const STRUCTURE_SECONDS: f64 = 3600.0;
/// Fan cooler condensation time in seconds.
const FAN_SECONDS: f64 = 900.0;
/// Burn pressure relaxation time in seconds.
const BURN_SECONDS: f64 = 30.0;
/// Direct heating pressure relaxation time in seconds.
const DIRECT_HEATING_SECONDS: f64 = 300.0;
/// Rule: hydrogen ignition threshold in percent.
const IGNITION_PERCENT: f64 = 8.0;
/// Rule: hydrogen ignition threshold during direct heating, in percent.
const HOT_IGNITION_PERCENT: f64 = 4.0;
/// Rule: direct heating pressure that lowers the ignition threshold, in kPa.
const HOT_IGNITION_KPA: f64 = 90.0;
/// Rule: steam inerting threshold in percent.
const INERT_PERCENT: f64 = 55.0;
/// Rule: hydrogen fraction that fails containment in a burn, in percent.
const FAILURE_PERCENT: f64 = 10.0;
/// Rule: containment failure pressure in kPa absolute.
const FAILURE_KPA: f64 = 700.0;
/// Burn pressure gain per percentage point of hydrogen.
const BURN_GAIN: f64 = 0.25;
/// Steam produced per kg of burned hydrogen, in kg.
const STEAM_PER_HYDROGEN: f64 = 9.0;
/// Atmospheric liquid enthalpy in kJ/kg.
const LIQUID_KJ_KG: f64 = 419.0;
/// Atmospheric latent heat in kJ/kg.
const LATENT_KJ_KG: f64 = 2257.0;

impl SevereState {
    fn containment_state(&mut self) {
        let (temperature, steam_pressure) =
            steam::atmosphere(self.containment_steam_kg / VOLUME_M3);
        let c = &mut self.values.containment;
        let kelvin = temperature + 273.15;
        let air = AIR_MOL * GAS_J_MOL_K * kelvin / VOLUME_M3 / 1000.0;
        let hydrogen =
            (c.hydrogen_kg / HYDROGEN_KG_MOL) * GAS_J_MOL_K * kelvin / VOLUME_M3 / 1000.0;
        c.temperature_c = temperature;
        c.pressure_kpa = air + steam_pressure + hydrogen + c.direct_heating_kpa + c.burn_excess_kpa;
        c.hydrogen_percent = 100.0 * hydrogen / c.pressure_kpa;
        c.steam_percent = 100.0 * steam_pressure / c.pressure_kpa;
    }

    pub fn containment_step(&mut self, dt: f64) -> [Option<Stage>; 2] {
        let v = &mut self.values;
        let hydrogen_out = if v.relief.flow_kg_s > 0.0 {
            v.hydrogen_in_primary_kg * dt / HYDROGEN_SECONDS
        } else {
            0.0
        };
        v.hydrogen_in_primary_kg -= hydrogen_out;
        if !v.relief_tank.disk_ruptured {
            self.tank_mj += dt * self.discharge.heat_mw;
            v.relief_tank.hydrogen_kg += hydrogen_out;
            if self.tank_mj >= DISK_MJ {
                v.relief_tank.disk_ruptured = true;
                v.containment.hydrogen_kg += v.relief_tank.hydrogen_kg;
                v.relief_tank.hydrogen_kg = 0.0;
            }
        } else {
            let sat = steam::saturation(self.discharge.pressure_mpa);
            let flash = ((sat.liquid_kj_kg - LIQUID_KJ_KG) / LATENT_KJ_KG).clamp(0.0, 1.0);
            self.containment_steam_kg +=
                dt * (self.discharge.steam_kg_s + self.discharge.liquid_kg_s * flash);
            self.sump_water_kg += dt * self.discharge.liquid_kg_s * (1.0 - flash);
            v.containment.hydrogen_kg += hydrogen_out;
        }
        let rate = 1.0 / STRUCTURE_SECONDS
            + if v.containment.fan_coolers_running {
                1.0 / FAN_SECONDS
            } else {
                0.0
            };
        let condensed = dt * self.containment_steam_kg * rate;
        self.containment_steam_kg -= condensed;
        self.sump_water_kg += condensed;
        self.containment_state();
        let c = &mut self.values.containment;
        c.burn_excess_kpa -= dt * c.burn_excess_kpa / BURN_SECONDS;
        c.direct_heating_kpa -= dt * c.direct_heating_kpa / DIRECT_HEATING_SECONDS;
        let ignition = if c.direct_heating_kpa > HOT_IGNITION_KPA {
            HOT_IGNITION_PERCENT
        } else {
            IGNITION_PERCENT
        };
        let mut stages = [None; 2];
        if c.failure.is_none() && c.hydrogen_percent >= ignition && c.steam_percent < INERT_PERCENT
        {
            let peak = c.pressure_kpa * (1.0 + BURN_GAIN * c.hydrogen_percent);
            c.burn_excess_kpa = peak - c.pressure_kpa;
            if c.hydrogen_percent >= FAILURE_PERCENT || peak >= FAILURE_KPA {
                c.failure = Some(FailureCause::HydrogenBurn);
                stages[0] = Some(Stage::ContainmentFailure);
            } else {
                stages[0] = Some(Stage::HydrogenBurn);
            }
            self.containment_steam_kg += STEAM_PER_HYDROGEN * c.hydrogen_kg;
            c.hydrogen_burned_kg += c.hydrogen_kg;
            c.hydrogen_kg = 0.0;
            self.containment_state();
        }
        let v = &mut self.values;
        if v.containment.failure.is_none() && v.containment.pressure_kpa >= FAILURE_KPA {
            v.containment.failure = Some(FailureCause::Overpressure);
            stages[1] = Some(Stage::ContainmentFailure);
        }
        v.relief_tank.pressure_kpa = if v.relief_tank.disk_ruptured {
            v.containment.pressure_kpa
        } else {
            TANK_INITIAL_KPA + TANK_RISE_KPA * self.tank_mj / DISK_MJ
        };
        let tailpipe = if self.discharge.steam_kg_s + self.discharge.liquid_kg_s > 0.0 {
            steam::saturation(v.relief_tank.pressure_kpa / 1000.0).temperature_c + TAILPIPE_C
        } else {
            TAILPIPE_C
        };
        v.relief.tailpipe_c += dt * (tailpipe - v.relief.tailpipe_c) / TAILPIPE_SECONDS;
        stages
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gas_mixture_matches_air_steam_and_hydrogen_reference_points() {
        let mut state = SevereState::new(625.0, 325.0);
        state.containment_state();
        let initial = state.values.containment.pressure_kpa;
        assert!((initial - 101.3).abs() < 0.1);
        assert_eq!(state.values.containment.temperature_c, 40.0);
        state.values.containment.hydrogen_kg = 100.0;
        state.containment_state();
        assert!((state.values.containment.pressure_kpa - initial - 3.69).abs() < 0.01);
        state.containment_steam_kg = 21_000.0;
        state.containment_state();
        assert!((state.values.containment.temperature_c - 100.0).abs() < 0.1);
    }

    #[test]
    fn safety_discharge_keeps_hydrogen_in_the_primary_until_relief_flows() {
        let mut state = SevereState::new(625.0, 325.0);
        state.values.hydrogen_in_primary_kg = 100.0;
        state.values.relief.safety_valve_flow_kg_s = 10.0;
        state.discharge.steam_kg_s = 10.0;
        state.discharge.heat_mw = 25.0;
        state.containment_step(0.05);
        assert_eq!(state.values.hydrogen_in_primary_kg, 100.0);
        assert_eq!(state.values.relief_tank.hydrogen_kg, 0.0);
        state.values.relief.flow_kg_s = 10.0;
        state.containment_step(0.05);
        assert!(state.values.hydrogen_in_primary_kg < 100.0);
        assert_eq!(
            state.values.hydrogen_in_primary_kg + state.values.relief_tank.hydrogen_kg,
            100.0
        );
        state.tank_mj = DISK_MJ - 0.5;
        state.containment_step(0.05);
        assert!(state.values.relief_tank.disk_ruptured);
        assert_eq!(state.values.relief_tank.hydrogen_kg, 0.0);
        assert_eq!(
            state.values.hydrogen_in_primary_kg + state.values.containment.hydrogen_kg,
            100.0
        );
        assert_eq!(
            state.values.relief_tank.pressure_kpa,
            state.values.containment.pressure_kpa
        );
        assert!(state.values.relief.tailpipe_c > 40.0);
    }

    #[test]
    fn burns_conserve_hydrogen_and_add_pressure_that_relaxes() {
        let mut state = SevereState::new(625.0, 325.0);
        state.values.containment.hydrogen_kg = 250.0;
        state.containment_state();
        let before = state.values.containment.pressure_kpa;
        assert!(
            state
                .containment_step(0.05)
                .contains(&Some(Stage::HydrogenBurn))
        );
        let c = &state.values.containment;
        assert!(c.failure.is_none());
        assert_eq!(c.hydrogen_kg, 0.0);
        assert_eq!(c.hydrogen_burned_kg, 250.0);
        assert_eq!(state.containment_steam_kg, 2250.0);
        assert!(c.pressure_kpa > before + c.burn_excess_kpa);
        let excess = c.burn_excess_kpa;
        state.containment_step(0.05);
        assert!(state.values.containment.burn_excess_kpa < excess);
    }

    #[test]
    fn steam_inerts_hydrogen_and_hot_breach_lowers_the_ignition_threshold() {
        let mut wet = SevereState::new(625.0, 325.0);
        wet.containment_steam_kg = 100_000.0;
        wet.values.containment.hydrogen_kg = 1400.0;
        wet.containment_step(0.05);
        assert!(wet.values.containment.steam_percent >= 55.0);
        assert_eq!(wet.values.containment.hydrogen_burned_kg, 0.0);
        assert_eq!(
            wet.values.containment.failure,
            Some(FailureCause::Overpressure)
        );

        let mut cool = SevereState::new(625.0, 325.0);
        cool.values.containment.hydrogen_kg = 230.0;
        cool.containment_step(0.05);
        assert_eq!(cool.values.containment.hydrogen_burned_kg, 0.0);
        cool.values.containment.direct_heating_kpa = 100.0;
        assert!(
            cool.containment_step(0.05)
                .contains(&Some(Stage::HydrogenBurn))
        );
        assert_eq!(cool.values.containment.hydrogen_burned_kg, 230.0);
    }
}
