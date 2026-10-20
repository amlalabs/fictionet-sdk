//! Lumped primary boiling, flashing, relief discharge and liquid inventory.
//! The saturated primary has one temperature. Loop seals and uneven draining
//! are omitted. Once boiling starts, cooling does not restore single phase.
use super::{INJECTION_ENTHALPY_KJ_KG, SevereState, injection_flow};
use crate::{
    plant::RATED_THERMAL_MW,
    snapshot::{Regime, Truth},
    stages::Stage,
    steam,
};

/// Full primary liquid inventory in kg.
const INVENTORY_KG: f64 = 162_000.0;
/// Full loop and vessel inventory in kg.
const LOOP_VESSEL_KG: f64 = 150_000.0;
/// Full pressurizer water mass in kg.
const PRESSURIZER_KG: f64 = 24_000.0;
/// Pressurizer water mass in kg per percentage point of level.
const WATER_PER_PERCENT: f64 = 240.0;
/// Safety valve pressure in MPa.
const SAFETY_MPA: f64 = 17.5;
/// Steam relief capacity per valve in kg/s/MPa.
const RELIEF_STEAM: f64 = 1.0;
/// Liquid relief capacity per valve in kg/s/MPa.
const RELIEF_LIQUID: f64 = 2.5;
/// Covered fuel conductance in MW/K.
const FUEL_CONDUCTANCE: f64 = 6.0;
/// Rule: vessel share of loop and vessel water, dimensionless.
const VESSEL_SHARE: f64 = 0.32;
/// Rule: loop and vessel water needed for pumped core coverage, in kg.
const PUMPED_COVER_KG: f64 = 52_500.0;
/// Rule: covered core void target in percent when boiling.
const BOILING_VOID_PERCENT: f64 = 20.0;
/// Rule: added void target in percentage points for a fully uncovered core.
const UNCOVERED_VOID_PERCENT: f64 = 80.0;
/// Void relaxation time in seconds.
const VOID_SECONDS: f64 = 5.0;

/// Discharge over one step, for the relief tank heat and mass balance.
#[derive(Clone, Debug, Default)]
pub(crate) struct Discharge {
    /// Primary pressure at discharge in MPa.
    pub pressure_mpa: f64,
    /// Steam mass flow in kg/s, including the safety valves.
    pub steam_kg_s: f64,
    /// Liquid mass flow in kg/s.
    pub liquid_kg_s: f64,
    /// Enthalpy flow in MW, using saturation properties at discharge pressure.
    pub heat_mw: f64,
}
impl Discharge {
    fn add(&mut self, steam: f64, liquid: f64, pressure_mpa: f64) {
        let sat = steam::saturation(pressure_mpa);
        if steam + liquid > 0.0 {
            self.pressure_mpa = pressure_mpa;
        }
        self.steam_kg_s += steam;
        self.liquid_kg_s += liquid;
        self.heat_mw += (steam * sat.vapor_kj_kg + liquid * sat.liquid_kj_kg) / 1000.0;
    }
}

impl SevereState {
    pub fn inventory_level_percent(&self) -> f64 {
        (self.values.inventory_kg - INVENTORY_KG) / WATER_PER_PERCENT
    }

    /// Add relief and injection to the existing single-phase pressure change.
    pub fn single_phase(&mut self, truth: &mut Truth, pressure_change: f64, valves: u8, dt: f64) {
        let p = &mut truth.primary;
        let v = &mut self.values;
        v.pressurizer_water_kg = WATER_PER_PERCENT * p.level_percent;
        let capacity = 72.0 + 0.04 * v.pressurizer_water_kg;
        let relief = RELIEF_STEAM * f64::from(valves) * p.pressure_mpa;
        let injection = if v.safety_injection.running {
            injection_flow(p.pressure_mpa)
        } else {
            0.0
        };
        let relief_pressure = p.pressure_mpa;
        v.inventory_kg += dt * (injection - relief);
        p.pressure_mpa +=
            pressure_change - dt * relief / capacity + dt * injection / WATER_PER_PERCENT * 0.1;
        let safety = (p.pressure_mpa - SAFETY_MPA).max(0.0) * capacity / dt;
        v.inventory_kg -= dt * safety;
        let safety_pressure = p.pressure_mpa;
        p.pressure_mpa = p.pressure_mpa.clamp(0.1, SAFETY_MPA);
        p.relief_open = valves > 0 || safety > 0.0;
        v.relief.flow_kg_s = relief;
        v.relief.safety_valve_flow_kg_s = safety;
        v.safety_injection.flow_kg_s = injection;
        self.discharge.add(relief, 0.0, relief_pressure);
        self.discharge.add(safety, 0.0, safety_pressure);
    }

    /// Return stage triggers at their point of calculation in this step.
    pub fn primary_step(&mut self, truth: &mut Truth, valves: u8, dt: f64) -> [Option<Stage>; 7] {
        let mut stages = [None; 7];
        let p = &mut truth.primary;
        let sat = steam::saturation(p.pressure_mpa).temperature_c;
        let boiling = self.values.regime == Regime::SinglePhase
            && (p.level_percent <= 0.0
                || truth.reactor.core_exit_c >= sat
                || p.loops.iter().any(|l| {
                    l.hot_leg_c >= sat || l.cold_leg_c >= sat || l.steam_generator_primary_c >= sat
                }));
        if boiling {
            stages[0] = Some(Stage::Boiling);
            self.values.regime = Regime::TwoPhase;
            if p.level_percent <= 0.0 {
                p.pressure_mpa = steam::saturation_pressure(truth.reactor.core_exit_c);
            }
            self.values.pressurizer_water_kg = WATER_PER_PERCENT * p.level_percent;
        }
        let target = if self.values.regime == Regime::SinglePhase {
            0.0
        } else {
            BOILING_VOID_PERCENT + UNCOVERED_VOID_PERCENT * self.values.uncovered_percent / 100.0
        };
        self.values.void_percent += dt * (target - self.values.void_percent) / VOID_SECONDS;
        match self.values.regime {
            Regime::SinglePhase => {
                self.values.hot_fuel_c = truth.reactor.fuel_temperature_c;
                self.values.core_exit_steam_c = truth.reactor.core_exit_c;
            }
            Regime::TwoPhase => self.two_phase(truth, valves, dt, &mut stages),
            Regime::Breached => {
                stages[2..5].copy_from_slice(&self.core_step(truth.reactor.thermal_mw, 0.0, dt));
                self.breached_primary(truth);
            }
        }
        stages[5] = self.relocate(dt);
        stages
    }

    fn two_phase(
        &mut self,
        truth: &mut Truth,
        valves: u8,
        dt: f64,
        stages: &mut [Option<Stage>; 7],
    ) {
        let pressure = truth.primary.pressure_mpa;
        let sat = steam::saturation(pressure);
        let decay_mw = truth.reactor.decay_heat_percent / 100.0 * RATED_THERMAL_MW;
        let q_lp = self.lower_plenum_step(decay_mw, sat.temperature_c, dt);
        let q_quench = std::mem::take(&mut self.quench_mw);
        let q_down = if self.values.vessel_water_kg > 0.0 {
            self.down_mw
        } else {
            0.0
        };
        let v = &mut self.values;
        let p = &mut truth.primary;
        let old_u = v.uncovered_percent / 100.0;
        let latent = sat.vapor_kj_kg - sat.liquid_kj_kg;
        let q_fuel = FUEL_CONDUCTANCE
            * (truth.reactor.fuel_temperature_c - sat.temperature_c).max(0.0)
            * (1.0 - v.uncovered_percent / 100.0);
        let q_sg: f64 = truth
            .secondary
            .loops
            .iter()
            .map(|l| l.heat_transfer_mw)
            .sum();
        let injection = if v.safety_injection.running {
            injection_flow(pressure)
        } else {
            0.0
        };
        let q_si = injection * (sat.liquid_kj_kg - INJECTION_ENTHALPY_KJ_KG) / 1000.0;
        let boiling = 1000.0 * (q_fuel + q_lp + q_quench + q_down - q_sg - q_si) / latent;
        let (steam, liquid) = if v.pressurizer_water_kg >= PRESSURIZER_KG - 1.0 {
            (0.0, RELIEF_LIQUID * f64::from(valves) * pressure)
        } else {
            (RELIEF_STEAM * f64::from(valves) * pressure, 0.0)
        };
        let low = (pressure - 0.1).max(0.1);
        let slope = (steam::saturation(pressure + 0.1).liquid_kj_kg
            - steam::saturation(low).liquid_kj_kg)
            / (pressure + 0.1 - low);
        let mass = v.inventory_kg;
        let space = ((PRESSURIZER_KG - v.pressurizer_water_kg) / 600.0
            + (LOOP_VESSEL_KG - (mass - v.pressurizer_water_kg)).max(0.0) / 600.0)
            .max(5.0);
        let capacity = 6.0 * space + mass * slope / latent;
        let mut dp = dt * (boiling - steam) / capacity;
        let safety = if pressure + dp > SAFETY_MPA {
            let flow = (pressure + dp - SAFETY_MPA) * capacity / dt;
            dp = SAFETY_MPA - pressure;
            flow
        } else {
            0.0
        };
        let floor = (v.containment.pressure_kpa / 1000.0).max(0.1);
        dp = dp.max(floor - pressure);
        let flash = mass * slope * (-dp) / latent;
        v.inventory_kg =
            (mass - dt * boiling - flash - dt * liquid + dt * injection).min(INVENTORY_KG);
        if v.inventory_kg < 100.0 {
            v.inventory_kg = 0.0;
        }
        p.pressure_mpa = pressure + dp;
        let venting = valves > 0 || safety > 0.0;
        let target = if venting {
            PRESSURIZER_KG.min(v.inventory_kg)
        } else {
            (v.inventory_kg - LOOP_VESSEL_KG).clamp(0.0, PRESSURIZER_KG)
        };
        v.pressurizer_water_kg += (target - v.pressurizer_water_kg).clamp(-200.0 * dt, 200.0 * dt);
        v.pressurizer_water_kg = v.pressurizer_water_kg.min(v.inventory_kg);
        p.level_percent = v.pressurizer_water_kg / WATER_PER_PERCENT;
        let loop_vessel = v.inventory_kg - v.pressurizer_water_kg;
        v.vessel_water_kg = (VESSEL_SHARE * loop_vessel).clamp(0.0, 48_000.0);
        if v.vessel_water_kg < 100.0 {
            v.vessel_water_kg = 0.0;
        }
        v.uncovered_percent = if p.loops.iter().any(|l| l.pump_speed_percent > 20.0)
            && loop_vessel >= PUMPED_COVER_KG
        {
            0.0
        } else {
            100.0 * ((28_000.0 - v.vessel_water_kg) / 15_000.0).clamp(0.0, 1.0)
        };
        v.vessel_level_percent = vessel_level(v.vessel_water_kg);
        stages[1] = (v.uncovered_percent > 0.0).then_some(Stage::CoreUncovered);
        let temperature = steam::saturation(p.pressure_mpa).temperature_c;
        v.relief.flow_kg_s = steam + liquid;
        v.relief.safety_valve_flow_kg_s = safety;
        v.safety_injection.flow_kg_s = injection;
        self.core_coverage(old_u, truth.reactor.fuel_temperature_c, temperature, dt);
        let core_steam =
            1000.0 * (q_fuel + q_lp + q_quench + q_down).max(0.0) / latent + flash.max(0.0) / dt;
        stages[2..5].copy_from_slice(&self.core_step(truth.reactor.thermal_mw, core_steam, dt));
        self.core_readings(truth, temperature);
        let p = &mut truth.primary;
        for l in &mut p.loops {
            l.hot_leg_c = temperature;
            l.cold_leg_c = temperature;
            l.steam_generator_primary_c = temperature;
        }
        truth.reactor.core_exit_c = temperature;
        p.average_temperature_c = temperature;
        p.subcooling_margin_c = 0.0;
        p.relief_open = venting;
        self.discharge.add(steam + safety, liquid, pressure);
        stages[6] = self.breach(p.pressure_mpa);
        if stages[6].is_some() {
            self.breached_primary(truth);
        }
    }

    fn breached_primary(&mut self, truth: &mut Truth) {
        let p = &mut truth.primary;
        p.pressure_mpa = (self.values.containment.pressure_kpa / 1000.0).max(0.1);
        let temperature = steam::saturation(p.pressure_mpa).temperature_c;
        for line in &mut p.loops {
            line.hot_leg_c = temperature;
            line.cold_leg_c = temperature;
            line.steam_generator_primary_c = temperature;
        }
        truth.reactor.core_exit_c = temperature;
        p.average_temperature_c = temperature;
        p.subcooling_margin_c = 0.0;
        p.level_percent = 0.0;
        p.relief_open = false;
        self.values.relief.flow_kg_s = 0.0;
        self.values.relief.safety_valve_flow_kg_s = 0.0;
        self.values.safety_injection.flow_kg_s = 0.0;
        self.core_readings(truth, temperature);
    }
}

fn vessel_level(water_kg: f64) -> f64 {
    if water_kg < 13_000.0 {
        25.0 * water_kg / 13_000.0
    } else if water_kg < 28_000.0 {
        25.0 + 30.0 * (water_kg - 13_000.0) / 15_000.0
    } else if water_kg < 38_000.0 {
        55.0 + 15.0 * (water_kg - 28_000.0) / 10_000.0
    } else {
        70.0 + 30.0 * (water_kg - 38_000.0) / 10_000.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, Plant};

    fn initial() -> (SevereState, Truth) {
        let truth = Plant::new(Config::default()).snapshot().truth;
        let severe = SevereState::new(truth.reactor.fuel_temperature_c, truth.reactor.core_exit_c);
        (severe, truth)
    }

    #[test]
    fn single_phase_relief_and_injection_balance_mass_and_pressure() {
        let (mut severe, mut truth) = initial();
        severe.values.safety_injection.running = true;
        severe.single_phase(&mut truth, 0.0, 2, 0.05);
        assert_eq!(severe.values.relief.flow_kg_s, 31.0);
        assert_eq!(severe.values.safety_injection.flow_kg_s, 45.0);
        assert!((severe.values.inventory_kg - 162_000.7).abs() < 1e-9);
        let expected = 15.5 - 0.05 * 31.0 / 552.0 + 0.05 * 45.0 / 240.0 * 0.1;
        assert!((truth.primary.pressure_mpa - expected).abs() < 1e-12);
        assert!((severe.inventory_level_percent() - 0.7 / 240.0).abs() < 1e-12);
        assert_eq!(severe.discharge.steam_kg_s, 31.0);
        assert_eq!(severe.discharge.liquid_kg_s, 0.0);
        assert!((severe.discharge.heat_mw - 31.0 * 2596.2 / 1000.0).abs() < 1e-12);
        assert!(truth.primary.relief_open);
    }

    #[test]
    fn single_phase_safety_discharge_leaves_the_inventory() {
        let (mut severe, mut truth) = initial();
        severe.single_phase(&mut truth, 2.1, 0, 0.05);
        assert_eq!(truth.primary.pressure_mpa, 17.5);
        assert!(truth.primary.relief_open);
        assert!((severe.values.relief.safety_valve_flow_kg_s - 1104.0).abs() < 1e-9);
        assert!((severe.values.inventory_kg - 161_944.8).abs() < 1e-9);
        assert_eq!(
            severe.discharge.steam_kg_s,
            severe.values.relief.safety_valve_flow_kg_s
        );
        assert!(severe.discharge.heat_mw > 0.0);
    }

    #[test]
    fn every_primary_node_can_start_boiling() {
        for node in 0..7 {
            let (mut severe, mut truth) = initial();
            let saturation = steam::saturation(truth.primary.pressure_mpa).temperature_c;
            let temperature = if node == 0 {
                &mut truth.reactor.core_exit_c
            } else {
                let line = &mut truth.primary.loops[(node - 1) / 3];
                match (node - 1) % 3 {
                    0 => &mut line.hot_leg_c,
                    1 => &mut line.cold_leg_c,
                    _ => &mut line.steam_generator_primary_c,
                }
            };
            *temperature = saturation - 0.001;
            assert_eq!(severe.primary_step(&mut truth, 0, 0.05), [None; 7]);
            if node == 0 {
                truth.reactor.core_exit_c = saturation;
            } else {
                let line = &mut truth.primary.loops[(node - 1) / 3];
                match (node - 1) % 3 {
                    0 => line.hot_leg_c = saturation,
                    1 => line.cold_leg_c = saturation,
                    _ => line.steam_generator_primary_c = saturation,
                }
            }
            assert!(
                severe
                    .primary_step(&mut truth, 0, 0.05)
                    .contains(&Some(Stage::Boiling))
            );
            assert_eq!(severe.values.regime, Regime::TwoPhase);
            assert_eq!(severe.values.void_percent, 0.2);
            let new_sat = steam::saturation(truth.primary.pressure_mpa).temperature_c;
            assert_eq!(truth.reactor.core_exit_c, new_sat);
            assert_eq!(truth.primary.average_temperature_c, new_sat);
            assert_eq!(truth.primary.subcooling_margin_c, 0.0);
            for line in &truth.primary.loops {
                assert_eq!(line.hot_leg_c, new_sat);
                assert_eq!(line.cold_leg_c, new_sat);
                assert_eq!(line.steam_generator_primary_c, new_sat);
            }
            assert!(
                !severe
                    .primary_step(&mut truth, 0, 0.05)
                    .contains(&Some(Stage::Boiling))
            );
        }
    }

    #[test]
    fn empty_pressurizer_enters_at_core_exit_saturation_pressure() {
        let (mut severe, mut truth) = initial();
        truth.primary.level_percent = 0.0;
        truth.reactor.core_exit_c = 311.0;
        truth.reactor.fuel_temperature_c = 311.0;
        for line in &mut truth.secondary.loops {
            line.heat_transfer_mw = 0.0;
        }
        assert!(
            severe
                .primary_step(&mut truth, 0, 0.05)
                .contains(&Some(Stage::Boiling))
        );
        assert_eq!(truth.primary.pressure_mpa, 10.0);
        assert_eq!(severe.values.pressurizer_water_kg, 10.0);
    }

    #[test]
    fn full_pressurizer_sends_liquid_and_pumps_delay_uncovery() {
        let (mut severe, mut truth) = initial();
        severe.values.regime = Regime::TwoPhase;
        severe.values.inventory_kg = 100_000.0;
        severe.values.pressurizer_water_kg = 24_000.0;
        truth.primary.pressure_mpa = 7.0;
        truth.reactor.fuel_temperature_c = 285.83;
        for line in &mut truth.secondary.loops {
            line.heat_transfer_mw = 0.0;
        }
        severe.primary_step(&mut truth, 1, 0.05);
        assert_eq!(truth.primary.pressure_mpa, 7.0);
        assert_eq!(severe.values.relief.flow_kg_s, 17.5);
        assert_eq!(severe.discharge.steam_kg_s, 0.0);
        assert_eq!(severe.discharge.liquid_kg_s, 17.5);
        assert_eq!(severe.discharge.heat_mw, 17.5 * 1267.0 / 1000.0);
        assert_eq!(severe.values.inventory_kg, 99_999.125);
        assert_eq!(severe.values.pressurizer_water_kg, 24_000.0);
        assert_eq!(severe.values.uncovered_percent, 0.0);
        for line in &mut truth.primary.loops {
            line.pump_speed_percent = 20.0;
        }
        assert!(
            severe
                .primary_step(&mut truth, 1, 0.05)
                .contains(&Some(Stage::CoreUncovered))
        );
        assert!(severe.values.uncovered_percent > 0.0);
    }

    #[test]
    fn condensation_refills_without_leaving_two_phase_or_crossing_pressure_floor() {
        let (mut severe, mut truth) = initial();
        severe.values.regime = Regime::TwoPhase;
        severe.values.inventory_kg = 161_999.0;
        severe.values.containment.pressure_kpa = 200.0;
        truth.primary.pressure_mpa = 0.200001;
        truth.reactor.fuel_temperature_c = 100.0;
        severe.primary_step(&mut truth, 0, 0.05);
        assert_eq!(truth.primary.pressure_mpa, 0.2);
        assert_eq!(severe.values.inventory_kg, 162_000.0);
        assert_eq!(severe.values.regime, Regime::TwoPhase);
        assert_eq!(truth.primary.subcooling_margin_c, 0.0);
    }

    #[test]
    fn vessel_level_follows_the_height_segments() {
        for (mass, level) in [
            (0.0, 0.0),
            (6500.0, 12.5),
            (13_000.0, 25.0),
            (20_500.0, 40.0),
            (28_000.0, 55.0),
            (33_000.0, 62.5),
            (38_000.0, 70.0),
            (43_000.0, 85.0),
            (48_000.0, 100.0),
        ] {
            assert_eq!(vessel_level(mass), level);
        }
    }
}
