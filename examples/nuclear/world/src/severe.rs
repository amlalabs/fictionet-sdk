//! Accident state, relief paths, injection capacity and occupied spaces.
use crate::{protection::AutomaticState, sensors::round, snapshot::*};
mod spaces;

/// Rule: break flow in kg/s at the rated header pressure of 6.9 MPa.
const BREAK_KG_S: f64 = 500.0;
/// Injection water enthalpy in kJ/kg at 30 C.
pub const INJECTION_ENTHALPY_KJ_KG: f64 = 126.0;
/// Rule: combined injection pump capacity in kg/s at 15 MPa and below.
const INJECTION_KG_S: f64 = 60.0;

pub fn relief_valves_flowing(demanded_open: bool, block_closed: bool, stuck_open: bool) -> u8 {
    if block_closed {
        0
    } else if demanded_open {
        2
    } else {
        u8::from(stuck_open)
    }
}

/// Available injection in kg/s at primary pressure in MPa.
pub fn injection_flow(pressure_mpa: f64) -> f64 {
    INJECTION_KG_S * ((17.0 - pressure_mpa) / 2.0).clamp(0.0, 1.0)
}

pub(crate) fn break_flow(pressure_mpa: f64, active: bool, isolated: bool) -> f64 {
    if active && !isolated {
        BREAK_KG_S * pressure_mpa / 6.9
    } else {
        0.0
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SevereState {
    pub values: Severe,
    pub automatic: AutomaticState,
    pub hall: spaces::Hall,
}
impl SevereState {
    pub fn new(fuel_c: f64, core_exit_c: f64) -> Self {
        Self {
            automatic: AutomaticState::default(),
            hall: spaces::Hall::default(),
            values: Severe {
                regime: Regime::SinglePhase,
                inventory_kg: 162_000.0,
                pressurizer_water_kg: 12_000.0,
                vessel_water_kg: 48_000.0,
                vessel_level_percent: 100.0,
                uncovered_percent: 0.0,
                hot_fuel_c: fuel_c,
                core_exit_steam_c: core_exit_c,
                zirconium_oxidized_percent: 0.0,
                hydrogen_generated_kg: 0.0,
                hydrogen_in_primary_kg: 0.0,
                melted_percent: 0.0,
                lower_plenum_melt_t: 0.0,
                lower_head_c: 290.0,
                breach_pressure_mpa: None,
                void_percent: 0.0,
                relief: Relief {
                    demanded_open: false,
                    flow_kg_s: 0.0,
                    safety_valve_flow_kg_s: 0.0,
                    block_closed: false,
                    tailpipe_c: 40.0,
                },
                relief_tank: ReliefTank {
                    pressure_kpa: 100.0,
                    disk_ruptured: false,
                },
                safety_injection: SafetyInjection {
                    signal: false,
                    running: false,
                    flow_kg_s: 0.0,
                },
                steam_isolation_closed: false,
                steam_break_kg_s: 0.0,
                containment: Containment {
                    pressure_kpa: 101.3,
                    temperature_c: 40.0,
                    steam_percent: 0.0,
                    hydrogen_percent: 0.0,
                    hydrogen_kg: 0.0,
                    burn_excess_kpa: 0.0,
                    direct_heating_kpa: 0.0,
                    fan_coolers_running: true,
                    failure: None,
                },
                cavity: Cavity {
                    melt_t: 0.0,
                    ablation_m: 0.0,
                },
                turbine_hall: TurbineHall {
                    steam_kg_m3: 0.0,
                    temperature_c: 30.0,
                },
            },
        }
    }

    pub fn snapshot(&self) -> Severe {
        let mut s = self.values.clone();
        for v in [
            &mut s.inventory_kg,
            &mut s.pressurizer_water_kg,
            &mut s.vessel_water_kg,
            &mut s.hydrogen_generated_kg,
            &mut s.hydrogen_in_primary_kg,
            &mut s.containment.hydrogen_kg,
        ] {
            *v = round(*v, 1.0);
        }
        for v in [
            &mut s.vessel_level_percent,
            &mut s.uncovered_percent,
            &mut s.hot_fuel_c,
            &mut s.core_exit_steam_c,
            &mut s.zirconium_oxidized_percent,
            &mut s.melted_percent,
            &mut s.lower_plenum_melt_t,
            &mut s.lower_head_c,
            &mut s.void_percent,
            &mut s.relief.flow_kg_s,
            &mut s.relief.safety_valve_flow_kg_s,
            &mut s.relief.tailpipe_c,
            &mut s.relief_tank.pressure_kpa,
            &mut s.safety_injection.flow_kg_s,
            &mut s.steam_break_kg_s,
            &mut s.containment.pressure_kpa,
            &mut s.containment.temperature_c,
            &mut s.containment.steam_percent,
            &mut s.containment.burn_excess_kpa,
            &mut s.containment.direct_heating_kpa,
            &mut s.cavity.melt_t,
            &mut s.turbine_hall.temperature_c,
        ] {
            *v = round(*v, 0.1);
        }
        s.breach_pressure_mpa = s.breach_pressure_mpa.map(|p| round(p, 0.01));
        s.containment.hydrogen_percent = round(s.containment.hydrogen_percent, 0.01);
        s.cavity.ablation_m = round(s.cavity.ablation_m, 0.001);
        s.turbine_hall.steam_kg_m3 = round(s.turbine_hall.steam_kg_m3, 0.001);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn projection_rounds_each_kind_of_quantity_without_changing_state() {
        let mut state = SevereState::new(625.0, 325.0);
        let v = &mut state.values;
        v.inventory_kg = 162000.6;
        v.hot_fuel_c = 625.16;
        v.uncovered_percent = 1.26;
        v.lower_plenum_melt_t = 1.26;
        v.breach_pressure_mpa = Some(15.516);
        v.relief.flow_kg_s = 15.56;
        v.relief_tank.pressure_kpa = 100.16;
        v.safety_injection.flow_kg_s = 59.96;
        v.containment.hydrogen_percent = 1.236;
        v.containment.hydrogen_kg = 100.6;
        v.cavity.ablation_m = 0.1236;
        v.turbine_hall.steam_kg_m3 = 0.1236;
        let snap = state.snapshot();
        for (actual, expected) in [
            (snap.inventory_kg, 162001.0),
            (snap.hot_fuel_c, 625.2),
            (snap.uncovered_percent, 1.3),
            (snap.lower_plenum_melt_t, 1.3),
            (snap.breach_pressure_mpa.unwrap(), 15.52),
            (snap.relief.flow_kg_s, 15.6),
            (snap.relief_tank.pressure_kpa, 100.2),
            (snap.safety_injection.flow_kg_s, 60.0),
            (snap.containment.hydrogen_percent, 1.24),
            (snap.containment.hydrogen_kg, 101.0),
            (snap.cavity.ablation_m, 0.124),
            (snap.turbine_hall.steam_kg_m3, 0.124),
        ] {
            assert!((actual - expected).abs() < 1e-10);
        }
        assert_eq!(state.values.inventory_kg, 162000.6);
        assert_eq!(state.values.turbine_hall.steam_kg_m3, 0.1236);
    }

    #[test]
    fn relief_paths_obey_the_block_valves_and_demand() {
        for demand in [false, true] {
            for stuck in [false, true] {
                assert_eq!(relief_valves_flowing(demand, true, stuck), 0);
            }
        }
        assert_eq!(relief_valves_flowing(true, false, false), 2);
        assert_eq!(relief_valves_flowing(true, false, true), 2);
        assert_eq!(relief_valves_flowing(false, false, true), 1);
        assert_eq!(relief_valves_flowing(false, false, false), 0);
    }
    #[test]
    fn injection_capacity_falls_to_zero_at_seventeen_mpa() {
        for (p, flow) in [
            (1.0, 60.0),
            (15.0, 60.0),
            (16.0, 30.0),
            (17.0, 0.0),
            (18.0, 0.0),
        ] {
            assert_eq!(injection_flow(p), flow);
        }
    }
}
