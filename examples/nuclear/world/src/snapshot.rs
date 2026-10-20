//! Bounded state projection. Arrays have fixed lengths, including optional
//! alarm and fault slots; no list is truncated. Values use engineering units
//! and instrument resolution. Additional temperatures use 0.1 C, reactivity
//! 0.1 pcm and heat transfer 0.1 MW. Every float needs at most 25 JSON bytes.
//! The bound includes all slots, longest enum variants and 20-digit counters.
use crate::{
    command::{Command, Mode},
    faults::Faults,
    protection::{ALARM_COUNT, AlarmEntry, Trip},
    sensors::{Channel, SENSOR_COUNT, Telemetry},
    stages::{End, FailureCause},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Reactor {
    pub neutron_power_percent: f64,
    pub thermal_mw: f64,
    pub decay_heat_percent: f64,
    pub reactivity_pcm: f64,
    pub control_rod_percent: f64,
    pub rod_demand_percent: f64,
    pub shutdown_rod_percent_inserted: f64,
    pub fuel_temperature_c: f64,
    pub core_exit_c: f64,
    pub trip: Option<Trip>,
}
impl Reactor {
    pub const MAX_JSON_BYTES: usize = 500;
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrimaryLoop {
    pub hot_leg_c: f64,
    pub cold_leg_c: f64,
    pub steam_generator_primary_c: f64,
    pub flow_percent: f64,
    pub pump_running: bool,
    pub pump_speed_percent: f64,
}
impl PrimaryLoop {
    pub const MAX_JSON_BYTES: usize = 241;
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Primary {
    pub loops: [PrimaryLoop; 2],
    pub average_temperature_c: f64,
    pub pressure_mpa: f64,
    /// Saturation temperature at primary pressure minus core exit temperature.
    /// Unrounded so the sign at the single-phase boundary is preserved.
    pub subcooling_margin_c: f64,
    pub level_percent: f64,
    pub heaters_on: bool,
    pub heater_fraction: f64,
    pub spray_percent: f64,
    pub relief_open: bool,
}
impl Primary {
    pub const MAX_JSON_BYTES: usize = 801;
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SecondaryLoop {
    pub level_percent: f64,
    pub steam_kg_s: f64,
    pub feed_kg_s: f64,
    pub feed_valve_percent: f64,
    pub heat_transfer_mw: f64,
}
impl SecondaryLoop {
    pub const MAX_JSON_BYTES: usize = 212;
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Secondary {
    pub loops: [SecondaryLoop; 2],
    pub steam_pressure_mpa: f64,
    pub feed_pumps_running: [bool; 2],
    pub auxiliary_feed_running: bool,
    pub turbine_valve_percent: f64,
    pub turbine_tripped: bool,
    pub generator_mw: f64,
    pub steam_dump_percent: f64,
    pub steam_relief_open: bool,
    pub condenser_pressure_kpa: f64,
    pub circulating_water_running: bool,
}
impl Secondary {
    pub const MAX_JSON_BYTES: usize = 823;
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Controllers {
    pub feed_level: [Mode; 2],
    pub pressurizer_pressure: Mode,
    pub steam_dump: Mode,
}
impl Controllers {
    pub const MAX_JSON_BYTES: usize = 100;
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Truth {
    pub reactor: Reactor,
    pub primary: Primary,
    pub secondary: Secondary,
    pub controllers: Controllers,
}
impl Truth {
    pub const MAX_JSON_BYTES: usize = 2275;
}
/// Field status sampled with the readings. Arrays list loop A, then loop B.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportedStatus {
    pub coolant_pumps_running: [bool; 2],
    pub feed_pumps_running: [bool; 2],
    pub auxiliary_feed_running: bool,
    pub circulating_water_running: bool,
    pub pressurizer_heaters_on: bool,
    pub pressurizer_relief_open: bool,
    pub steam_relief_open: bool,
    pub reactor_tripped: bool,
    pub turbine_tripped: bool,
}
impl ReportedStatus {
    pub const MAX_JSON_BYTES: usize = 276;
}
impl From<&Truth> for ReportedStatus {
    fn from(t: &Truth) -> Self {
        Self {
            coolant_pumps_running: t.primary.loops.each_ref().map(|l| l.pump_running),
            feed_pumps_running: t.secondary.feed_pumps_running,
            auxiliary_feed_running: t.secondary.auxiliary_feed_running,
            circulating_water_running: t.secondary.circulating_water_running,
            pressurizer_heaters_on: t.primary.heaters_on,
            pressurizer_relief_open: t.primary.relief_open,
            steam_relief_open: t.secondary.steam_relief_open,
            reactor_tripped: t.reactor.trip.is_some(),
            turbine_tripped: t.secondary.turbine_tripped,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlantSnapshot {
    pub at_ms: u64,
    pub revision: u64,
    pub operator_actions: u64,
    pub model_limit: bool,
    pub last_fault_start_ms: Option<u64>,
    pub first_action_after_fault_ms: Option<u64>,
    pub truth: Truth,
    pub readings: [Channel; SENSOR_COUNT],
    pub reported_status: ReportedStatus,
    pub telemetry: Telemetry,
    pub alarms: [Option<AlarmEntry>; ALARM_COUNT],
    pub faults: Faults,
    pub severe: Severe,
    pub stylized: Stylized,
    pub stages: [Option<u64>; 12],
    pub end: Option<End>,
    pub last_command: Option<LastCommand>,
}
impl PlantSnapshot {
    pub const MAX_JSON_BYTES: usize = 11348;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Regime {
    SinglePhase,
    TwoPhase,
    Breached,
}
impl Regime {
    pub const MAX_JSON_BYTES: usize = 14;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Relief {
    pub demanded_open: bool,
    pub flow_kg_s: f64,
    pub safety_valve_flow_kg_s: f64,
    pub block_closed: bool,
    pub tailpipe_c: f64,
}
impl Relief {
    pub const MAX_JSON_BYTES: usize = 172;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReliefTank {
    pub pressure_kpa: f64,
    pub disk_ruptured: bool,
    /// Hydrogen retained before disk rupture, in kg.
    pub hydrogen_kg: f64,
}
impl ReliefTank {
    pub const MAX_JSON_BYTES: usize = 103;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SafetyInjection {
    pub signal: bool,
    pub running: bool,
    pub flow_kg_s: f64,
}
impl SafetyInjection {
    pub const MAX_JSON_BYTES: usize = 70;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Containment {
    pub pressure_kpa: f64,
    pub temperature_c: f64,
    pub steam_percent: f64,
    pub hydrogen_percent: f64,
    pub hydrogen_kg: f64,
    /// Total hydrogen consumed by all containment burns, in kg.
    pub hydrogen_burned_kg: f64,
    pub burn_excess_kpa: f64,
    pub direct_heating_kpa: f64,
    pub fan_coolers_running: bool,
    pub failure: Option<FailureCause>,
}
impl Containment {
    pub const MAX_JSON_BYTES: usize = 402;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Cavity {
    pub melt_t: f64,
    pub ablation_m: f64,
}
impl Cavity {
    pub const MAX_JSON_BYTES: usize = 75;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TurbineHall {
    pub steam_kg_m3: f64,
    pub temperature_c: f64,
}
impl TurbineHall {
    pub const MAX_JSON_BYTES: usize = 83;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Severe {
    pub regime: Regime,
    pub inventory_kg: f64,
    pub pressurizer_water_kg: f64,
    pub vessel_water_kg: f64,
    pub vessel_level_percent: f64,
    pub uncovered_percent: f64,
    pub hot_fuel_c: f64,
    pub core_exit_steam_c: f64,
    pub zirconium_oxidized_percent: f64,
    pub hydrogen_generated_kg: f64,
    pub hydrogen_in_primary_kg: f64,
    pub melted_percent: f64,
    pub lower_plenum_melt_t: f64,
    pub lower_head_c: f64,
    pub breach_pressure_mpa: Option<f64>,
    pub void_percent: f64,
    pub relief: Relief,
    pub relief_tank: ReliefTank,
    pub safety_injection: SafetyInjection,
    pub steam_isolation_closed: bool,
    pub steam_break_kg_s: f64,
    pub containment: Containment,
    pub cavity: Cavity,
    pub turbine_hall: TurbineHall,
}
impl Severe {
    pub const MAX_JSON_BYTES: usize = 1783;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Stylized {
    pub control_room_steam: f64,
    pub release_fraction: f64,
    pub containment_dose_sv_h: f64,
}
impl Stylized {
    pub const MAX_JSON_BYTES: usize = 143;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastCommand {
    pub command: Command,
    pub at_ms: u64,
}
impl LastCommand {
    pub const MAX_JSON_BYTES: usize = 112;
}
