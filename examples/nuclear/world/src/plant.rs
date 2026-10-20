//! A lumped two-loop energy and mass balance; time steps are 50 ms.
//!
//! Rated heat is 1800 MW, hot/cold legs 325/292 C, pressure 15.5 MPa,
//! header 6.9 MPa, feedwater about 225 C, output 600 MW, condenser 5 kPa.
//! Primary cp is 0.0055 MJ/kg/K. Rated loop flow is 900/(cp * 33) kg/s.
//! Approximate masses: core 30000 kg; each hot leg 10000 kg, steam generator
//! primary 40000 kg, cold leg 10000 kg. The average is mass weighted.
//! Fuel conductance is 6 MW/K and heat capacity 24 MJ/K (4 s time constant).
//! Fuel starts 300 C above core coolant. Each SG's UA is 900/(292-Tsat) MW/K.
//! Half power uses the same equipment, header pressure and flow. Temperature
//! rises, feed and turbine flow scale with heat. Feedback reference temperatures
//! balance reactivity at the chosen initial equilibrium; this represents a
//! separately initialized core, not an automatic rod adjustment during a run.
//! Secondary full-scale mass is 80000 kg per SG, initially half full. UA
//! scales linearly below 20% level. Steam production accounts for feedwater
//! heating to saturation, then latent heat; there is no shrink or swell.
//!
//! Main feed pumps each supply 60% of total rated feed. Valve capacity per
//! loop is 1.2 times rated loop feed. Automatic demand is steam feedforward
//! plus 10 kg/s per percentage point of level error (proportional tuning).
//! Auxiliary feed supplies 35 kg/s per loop at 30 C, with a local level
//! limiter tapering from full delivery at 50% to zero at 55% to avoid overfill.
//! Feed and turbine valves move 20 percentage points/s. Rod bank speed is
//! 0.5 percentage points/s, linear total worth 1200 pcm; shutdown rods add
//! -6000 pcm. Both banks drop in 2 s. Feedback is -20 pcm/C coolant and
//! -2.5 pcm/C fuel relative to initial temperatures. Xenon and boron are absent.
//!
//! Pump speed has a 15 s coastdown/startup time constant. Natural circulation
//! contributes up to 3% with both pumps stopped and the core hotter than SGs.
//! Header capacity is tuning: 4000 kg/MPa. Choked turbine flow is proportional
//! to valve position and header pressure; electrical work per kg derives from
//! 600 MW at rated steam flow. Steam dump has rated steam capacity and a
//! proportional tuning gain of 2 per MPa above the 7.0 MPa no-load target.
//! Steam relief removes excess vapor above 8.5 MPa within a step.
//!
//! Pressurizer tuning: expansion 0.8 level percentage points/C, compression
//! 0.08 MPa/C, heaters 0.02 MPa/s at full output, spray -0.10 MPa/s,
//! ambient heat loss -0.005 MPa/s. Heaters balance this loss at 25% output at
//! the 15.5 MPa setpoint. Their proportional gain is 2/MPa, reaching zero at
//! 15.625 MPa and full output at 15.125 MPa. Spray uses 2/MPa above 15.7 MPa.
//! With manual heaters and spray off,
//! pressure falls at 0.005 MPa/s when primary temperature is steady.
//! Relief removes excess pressure above 17.5 MPa within a step; mass loss is
//! omitted, so this is a pressure limiter, not a loss-of-coolant model.
//! Condenser heat capacity is tuning: 1000 MJ/kPa. Cooling is 300 MW/kPa
//! above 1 kPa when circulating water is available. Atmospheric venting limits
//! pressure to 100 kPa. No condensate inventory or turbine efficiency curve.
//!
//! Primary coolant nodes are single phase only below saturation at pressurizer
//! pressure. A node reaching saturation, falling below 0 C, or leaving the
//! pressurizer level range latches model_limit. At full power the core exit
//! margin is 344.79 - 325 = 19.79 C. Trends after saturation are outside the
//! model. Fuel above 1500 C also latches the limit. Numerical temperatures stop
//! at 0–2000 C; these boundaries are outside the model's useful domain.
use crate::{
    command::*,
    faults::*,
    kinetics::Kinetics,
    protection::*,
    sensors::{self, Channel, Instruments, SENSOR_COUNT, Sensor},
    snapshot::*,
    steam,
};

mod commands;

pub const STEP_MS: u64 = 50;
const DT: f64 = STEP_MS as f64 / 1000.0;
pub const RATED_THERMAL_MW: f64 = 1800.0;
pub const CP: f64 = 0.0055;
pub const RATED_LOOP_FLOW: f64 = 900.0 / (CP * 33.0);
const CORE_MASS: f64 = 30_000.0;
const HOT_MASS: f64 = 10_000.0;
const SG_MASS: f64 = 40_000.0;
const COLD_MASS: f64 = 10_000.0;
const SECONDARY_MASS: f64 = 80_000.0;
const FUEL_UA: f64 = 6.0;
const FUEL_CAPACITY: f64 = 24.0;
const HEADER_CAPACITY: f64 = 4000.0;
const CONDENSER_CAPACITY: f64 = 1000.0;
const EXPANSION: f64 = 0.8;
const COMPRESSION: f64 = 0.08;
const PRESSURE_SETPOINT_MPA: f64 = 15.5;
const HEATER_RATE_MPA_S: f64 = 0.02;
const SPRAY_RATE_MPA_S: f64 = 0.10;
const AMBIENT_LOSS_MPA_S: f64 = 0.005;
const HEATER_BIAS: f64 = 0.25;
const SPRAY_THRESHOLD_MPA: f64 = 15.7;
const PRESSURE_GAIN_PER_MPA: f64 = 2.0;
const PRIMARY_RELIEF_MPA: f64 = 17.5;

/// Available balanced initial conditions, as fractions of rated power.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitialPower {
    Full,
    Half,
}

/// The fixed schedule needs no allocation or length validation.
/// Empty slots can occur anywhere.
#[derive(Clone, Debug)]
pub struct Config {
    pub initial_power: InitialPower,
    pub seed: u64,
    pub automatic_protection: bool,
    /// Analysis only: disable temperature feedback to study point kinetics.
    pub temperature_feedback: bool,
    pub schedule: [Option<ScheduledFault>; 32],
}
impl Default for Config {
    fn default() -> Self {
        Self {
            initial_power: InitialPower::Full,
            seed: 1,
            automatic_protection: true,
            temperature_feedback: true,
            schedule: [None; 32],
        }
    }
}

#[derive(Clone, Debug)]
pub struct Plant {
    config: Config,
    at_ms: u64,
    revision: u64,
    operator_actions: u64,
    model_limit: bool,
    last_fault_start_ms: Option<u64>,
    first_action_after_fault_ms: Option<u64>,
    state: Truth,
    kinetics: Kinetics,
    instruments: Instruments,
    faults: Faults,
    alarms: [AlarmState; ALARM_COUNT],
    feed_demand: [f64; 2],
    turbine_demand: f64,
    dump_demand: f64,
    spray_demand: f64,
    heater_demand: bool,
    initial_average: f64,
    initial_fuel: f64,
    rated_steam: f64,
    sg_ua: f64,
}

impl Plant {
    pub fn new(config: Config) -> Self {
        let sat = steam::saturation(6.9);
        let rated_steam = 900_000.0 / (sat.vapor_kj_kg - steam::FEED_ENTHALPY);
        let power = match config.initial_power {
            InitialPower::Full => 1.0,
            InitialPower::Half => 0.5,
        };
        let cold = sat.temperature_c + power * (292.0 - sat.temperature_c);
        let hot = cold + power * 33.0;
        let fuel = hot + power * RATED_THERMAL_MW / FUEL_UA;
        let state = Truth {
            reactor: Reactor {
                neutron_power_percent: 100.0 * power,
                thermal_mw: RATED_THERMAL_MW * power,
                decay_heat_percent: 6.6 * power,
                reactivity_pcm: 0.0,
                control_rod_percent: 50.0,
                rod_demand_percent: 50.0,
                shutdown_rod_percent_inserted: 0.0,
                fuel_temperature_c: fuel,
                core_exit_c: hot,
                trip: None,
            },
            primary: Primary {
                loops: std::array::from_fn(|_| PrimaryLoop {
                    hot_leg_c: hot,
                    cold_leg_c: cold,
                    steam_generator_primary_c: cold,
                    flow_percent: 100.0,
                    pump_running: true,
                    pump_speed_percent: 100.0,
                }),
                average_temperature_c: 0.0,
                pressure_mpa: PRESSURE_SETPOINT_MPA,
                level_percent: 50.0,
                subcooling_margin_c: steam::saturation(PRESSURE_SETPOINT_MPA).temperature_c - hot,
                heaters_on: true,
                heater_fraction: HEATER_BIAS,
                spray_percent: 0.0,
                relief_open: false,
            },
            secondary: Secondary {
                loops: std::array::from_fn(|_| SecondaryLoop {
                    level_percent: 50.0,
                    steam_kg_s: rated_steam * power,
                    feed_kg_s: rated_steam * power,
                    feed_valve_percent: 100.0 * power / 1.2,
                    heat_transfer_mw: 900.0 * power,
                }),
                steam_pressure_mpa: 6.9,
                feed_pumps_running: [true; 2],
                auxiliary_feed_running: false,
                turbine_valve_percent: 100.0 * power,
                turbine_tripped: false,
                generator_mw: 600.0 * power,
                steam_dump_percent: 0.0,
                steam_relief_open: false,
                condenser_pressure_kpa: 1.0 + 4.0 * power,
                circulating_water_running: true,
            },
            controllers: Controllers {
                feed_level: [Mode::Automatic; 2],
                pressurizer_pressure: Mode::Automatic,
                steam_dump: Mode::Automatic,
            },
        };
        let mut plant = Self {
            instruments: Instruments::new(
                config.seed,
                [0.0; SENSOR_COUNT],
                ReportedStatus::from(&state),
            ),
            config,
            at_ms: 0,
            revision: 0,
            operator_actions: 0,
            model_limit: false,
            last_fault_start_ms: None,
            first_action_after_fault_ms: None,
            state,
            kinetics: Kinetics::new(power),
            faults: Faults::default(),
            alarms: [AlarmState::Normal; ALARM_COUNT],
            feed_demand: [100.0 * power / 1.2; 2],
            turbine_demand: 100.0 * power,
            dump_demand: 0.0,
            spray_demand: 0.0,
            heater_demand: false,
            initial_average: 0.0,
            initial_fuel: fuel,
            rated_steam,
            sg_ua: 900.0 / (292.0 - sat.temperature_c),
        };
        plant.initial_average = plant.average();
        plant.state.primary.average_temperature_c = plant.initial_average;
        plant.instruments = Instruments::new(
            plant.config.seed,
            plant.values(),
            ReportedStatus::from(&plant.state),
        );
        plant
    }

    /// Advance completed steps only. A nonaligned target leaves the remainder
    /// for the next call; repeated or earlier targets do nothing. A scheduled
    /// change at zero takes effect on the first step, at 50 ms.
    pub fn advance(&mut self, to_ms: u64) {
        while to_ms.saturating_sub(self.at_ms) >= STEP_MS {
            self.at_ms += STEP_MS;
            for i in 0..self.config.schedule.len() {
                if let Some(entry) = self.config.schedule[i]
                    && entry.at_ms <= self.at_ms
                {
                    self.config.schedule[i] = None;
                    let _ = self.change_fault(entry.change);
                }
            }
            self.step();
        }
    }

    fn average(&self) -> f64 {
        let mut heat = CORE_MASS * self.state.reactor.core_exit_c;
        for l in &self.state.primary.loops {
            heat += HOT_MASS * l.hot_leg_c
                + SG_MASS * l.steam_generator_primary_c
                + COLD_MASS * l.cold_leg_c;
        }
        heat / (CORE_MASS + 2.0 * (HOT_MASS + SG_MASS + COLD_MASS))
    }

    fn inputs(&self) -> ProtectionInputs {
        ProtectionInputs {
            power: self.state.reactor.neutron_power_percent,
            pressure: self.state.primary.pressure_mpa,
            flow: self.state.primary.loops.each_ref().map(|l| l.flow_percent),
            level: self
                .state
                .secondary
                .loops
                .each_ref()
                .map(|l| l.level_percent),
            hot: self.state.primary.loops.each_ref().map(|l| l.hot_leg_c),
            turbine_trip: self.state.secondary.turbine_tripped,
        }
    }

    fn trip(&mut self, cause: TripCause) {
        if self.state.reactor.trip.is_none() {
            self.state.reactor.trip = Some(Trip {
                cause,
                at_ms: self.at_ms,
            });
            self.state.reactor.rod_demand_percent = 0.0;
            self.state.secondary.turbine_tripped = true;
            self.revision = self.revision.saturating_add(1);
        }
    }

    fn step(&mut self) {
        for l in Loop::ALL {
            let i = l.index();
            if self.faults.has(ProcessFault::FeedPumpTrip { pump: l }) {
                self.state.secondary.feed_pumps_running[i] = false;
            }
            if self.faults.has(ProcessFault::CoolantPumpTrip { pump: l }) {
                self.state.primary.loops[i].pump_running = false;
            }
        }
        if self.config.automatic_protection
            && (!self.state.secondary.feed_pumps_running.iter().any(|p| *p)
                || self
                    .state
                    .secondary
                    .loops
                    .iter()
                    .any(|l| l.level_percent < LOW_LOW_LEVEL))
        {
            self.state.secondary.auxiliary_feed_running = true;
        }
        self.controls();
        self.reactor();
        self.heat_and_mass();
        if self.state.secondary.condenser_pressure_kpa > LOW_VACUUM_KPA {
            self.state.secondary.turbine_tripped = true;
            self.state.secondary.steam_dump_percent = 0.0;
        }
        if self.config.automatic_protection
            && let Some(cause) = self.inputs().cause()
        {
            self.trip(cause);
        }
        self.instruments.step(
            self.at_ms,
            DT,
            self.values(),
            ReportedStatus::from(&self.state),
            &self.faults,
        );
        update_alarms(
            &mut self.alarms,
            &self.instruments.readings,
            self.instruments.status,
        );
    }

    fn controls(&mut self) {
        let s = &mut self.state.secondary;
        for l in Loop::ALL {
            let i = l.index();
            if self.state.controllers.feed_level[i] == Mode::Automatic {
                self.feed_demand[i] = (s.loops[i].steam_kg_s
                    + 10.0 * (50.0 - s.loops[i].level_percent))
                    / (1.2 * self.rated_steam)
                    * 100.0;
            }
            if !self.faults.has(ProcessFault::FeedValveStuck { line: l }) {
                s.loops[i].feed_valve_percent = approach(
                    s.loops[i].feed_valve_percent,
                    self.feed_demand[i].clamp(0.0, 100.0),
                    20.0 * DT,
                );
            }
        }
        s.turbine_valve_percent = approach(
            s.turbine_valve_percent,
            if s.turbine_tripped {
                0.0
            } else {
                self.turbine_demand
            },
            if s.turbine_tripped {
                100.0 * DT
            } else {
                20.0 * DT
            },
        );
        if self.state.controllers.steam_dump == Mode::Automatic {
            self.dump_demand = if s.turbine_tripped || self.state.reactor.trip.is_some() {
                ((s.steam_pressure_mpa - 7.0) * 200.0).clamp(0.0, 100.0)
            } else {
                0.0
            };
        }
        s.steam_dump_percent = if s.condenser_pressure_kpa >= LOW_VACUUM_KPA {
            0.0
        } else {
            self.dump_demand
        };
        let p = &mut self.state.primary;
        if self.state.controllers.pressurizer_pressure == Mode::Automatic {
            p.heater_fraction = (HEATER_BIAS
                + (PRESSURE_SETPOINT_MPA - p.pressure_mpa) * PRESSURE_GAIN_PER_MPA)
                .clamp(0.0, 1.0);
            p.spray_percent =
                ((p.pressure_mpa - SPRAY_THRESHOLD_MPA) * PRESSURE_GAIN_PER_MPA * 100.0)
                    .clamp(0.0, 100.0);
        } else {
            p.heater_fraction = if self.heater_demand { 1.0 } else { 0.0 };
            p.spray_percent = self.spray_demand;
        }
        p.heaters_on = p.heater_fraction > 0.0;
    }

    fn reactor(&mut self) {
        let r = &mut self.state.reactor;
        if r.trip.is_some() {
            r.control_rod_percent = approach(r.control_rod_percent, 0.0, 50.0 * DT);
            r.shutdown_rod_percent_inserted =
                approach(r.shutdown_rod_percent_inserted, 100.0, 50.0 * DT);
        } else {
            r.control_rod_percent = approach(r.control_rod_percent, r.rod_demand_percent, 0.5 * DT);
        }
        r.reactivity_pcm =
            12.0 * (r.control_rod_percent - 50.0) - 60.0 * r.shutdown_rod_percent_inserted;
        if self.config.temperature_feedback {
            r.reactivity_pcm -= 20.0
                * (self.state.primary.average_temperature_c - self.initial_average)
                + 2.5 * (r.fuel_temperature_c - self.initial_fuel);
        }
        self.model_limit |= self.kinetics.step(r.reactivity_pcm / 100_000.0, DT);
        r.neutron_power_percent = self.kinetics.power * 100.0;
        r.thermal_mw = self.kinetics.thermal_fraction() * RATED_THERMAL_MW;
        r.decay_heat_percent = self.kinetics.decay_fraction() * 100.0;
    }

    fn heat_and_mass(&mut self) {
        let old_average = self.average();
        let sat = steam::saturation(self.state.secondary.steam_pressure_mpa);
        let both_stopped = self.state.primary.loops.iter().all(|l| !l.pump_running);
        let core = self.state.reactor.core_exit_c;
        let fuel = self.state.reactor.fuel_temperature_c;
        let fuel_heat = FUEL_UA * (fuel - core);
        let mut core_out = 0.0;
        let mut steam_made = 0.0;
        let main_capacity = self
            .state
            .secondary
            .feed_pumps_running
            .iter()
            .filter(|p| **p)
            .count() as f64
            * 0.6;
        for i in 0..2 {
            let p = &mut self.state.primary.loops[i];
            p.pump_speed_percent +=
                DT * ((if p.pump_running { 100.0 } else { 0.0 }) - p.pump_speed_percent) / 15.0;
            let natural = if both_stopped {
                ((core - p.steam_generator_primary_c) / 33.0).clamp(0.0, 1.0) * 3.0
            } else {
                0.0
            };
            p.flow_percent = p.pump_speed_percent.max(natural);
            let flow_cp = p.flow_percent / 100.0 * RATED_LOOP_FLOW * CP;
            let s = &mut self.state.secondary.loops[i];
            let heat = self.sg_ua
                * (p.steam_generator_primary_c - sat.temperature_c).max(0.0)
                * (s.level_percent / 20.0).clamp(0.0, 1.0);
            let main_feed = self.rated_steam * main_capacity * s.feed_valve_percent / 100.0;
            let aux_feed = if self.state.secondary.auxiliary_feed_running {
                35.0 * ((55.0 - s.level_percent) / 5.0).clamp(0.0, 1.0)
            } else {
                0.0
            };
            let feed_heat = main_feed * (sat.liquid_kj_kg - steam::FEED_ENTHALPY)
                + aux_feed * (sat.liquid_kj_kg - steam::AUX_ENTHALPY);
            let vapor =
                ((heat * 1000.0 - feed_heat) / (sat.vapor_kj_kg - sat.liquid_kj_kg)).max(0.0);
            s.feed_kg_s = main_feed + aux_feed;
            s.steam_kg_s = vapor;
            s.heat_transfer_mw = heat;
            s.level_percent = (s.level_percent
                + DT * (s.feed_kg_s - vapor) / SECONDARY_MASS * 100.0)
                .clamp(0.0, 100.0);
            steam_made += vapor;
            let hot = p.hot_leg_c;
            let sg = p.steam_generator_primary_c;
            let cold = p.cold_leg_c;
            core_out += flow_cp * (core - cold);
            p.hot_leg_c += DT * flow_cp * (core - hot) / (HOT_MASS * CP);
            p.steam_generator_primary_c += DT * (flow_cp * (hot - sg) - heat) / (SG_MASS * CP);
            p.cold_leg_c += DT * flow_cp * (sg - cold) / (COLD_MASS * CP);
        }
        self.state.reactor.core_exit_c += DT * (fuel_heat - core_out) / (CORE_MASS * CP);
        self.state.reactor.fuel_temperature_c +=
            DT * (self.state.reactor.thermal_mw - fuel_heat) / FUEL_CAPACITY;
        let average = self.average();
        let p = &mut self.state.primary;
        p.average_temperature_c = average;
        let level = 50.0 + EXPANSION * (average - self.initial_average);
        self.model_limit |= !(0.0..=100.0).contains(&level);
        p.level_percent = level.clamp(0.0, 100.0);
        p.pressure_mpa += COMPRESSION * (average - old_average)
            + DT * (HEATER_RATE_MPA_S * p.heater_fraction
                - SPRAY_RATE_MPA_S * p.spray_percent / 100.0
                - AMBIENT_LOSS_MPA_S);
        p.relief_open = p.pressure_mpa > PRIMARY_RELIEF_MPA;
        p.pressure_mpa = p.pressure_mpa.clamp(0.1, PRIMARY_RELIEF_MPA);
        let s = &mut self.state.secondary;
        let turbine_flow =
            2.0 * self.rated_steam * s.turbine_valve_percent / 100.0 * s.steam_pressure_mpa / 6.9;
        let dump_flow =
            2.0 * self.rated_steam * s.steam_dump_percent / 100.0 * s.steam_pressure_mpa / 6.9;
        s.generator_mw = turbine_flow * 600.0 / (2.0 * self.rated_steam);
        s.steam_pressure_mpa += DT * (steam_made - turbine_flow - dump_flow) / HEADER_CAPACITY;
        s.steam_relief_open = s.steam_pressure_mpa > 8.5;
        self.model_limit |= s.steam_pressure_mpa < 0.1;
        s.steam_pressure_mpa = s.steam_pressure_mpa.clamp(0.1, 8.5);
        // Use the same enthalpy reference as the design heat balance.
        let rejected_heat = (turbine_flow + dump_flow) * (sat.vapor_kj_kg - steam::FEED_ENTHALPY)
            / 1000.0
            - s.generator_mw;
        let cooling = if s.circulating_water_running
            && !self.faults.has(ProcessFault::CondenserCoolingLoss)
        {
            300.0 * (s.condenser_pressure_kpa - 1.0)
        } else {
            0.0
        };
        s.condenser_pressure_kpa = (s.condenser_pressure_kpa
            + DT * (rejected_heat - cooling) / CONDENSER_CAPACITY)
            .clamp(1.0, 100.0);
        self.bound_temperatures();
    }

    fn bound_temperatures(&mut self) {
        let saturation_c = steam::saturation(self.state.primary.pressure_mpa).temperature_c;
        let fuel = &mut self.state.reactor.fuel_temperature_c;
        self.model_limit |= !(0.0..=1500.0).contains(fuel);
        *fuel = fuel.clamp(0.0, 2000.0);
        let mut bound = |t: &mut f64| {
            self.model_limit |= *t < 0.0 || *t >= saturation_c;
            *t = t.clamp(0.0, 2000.0);
        };
        bound(&mut self.state.reactor.core_exit_c);
        for l in &mut self.state.primary.loops {
            bound(&mut l.hot_leg_c);
            bound(&mut l.cold_leg_c);
            bound(&mut l.steam_generator_primary_c);
        }
        self.state.primary.subcooling_margin_c = saturation_c - self.state.reactor.core_exit_c;
    }

    fn values(&self) -> [f64; SENSOR_COUNT] {
        let t = &self.state;
        Sensor::ALL.map(|s| match s {
            Sensor::NeutronPower => t.reactor.neutron_power_percent,
            Sensor::RodPosition => t.reactor.control_rod_percent,
            Sensor::HotLeg(l) => t.primary.loops[l.index()].hot_leg_c,
            Sensor::ColdLeg(l) => t.primary.loops[l.index()].cold_leg_c,
            Sensor::PressurizerPressure => t.primary.pressure_mpa,
            Sensor::PressurizerLevel => t.primary.level_percent,
            Sensor::CoolantFlow(l) => t.primary.loops[l.index()].flow_percent,
            Sensor::SteamGeneratorLevel(l) => t.secondary.loops[l.index()].level_percent,
            Sensor::SteamPressure => t.secondary.steam_pressure_mpa,
            Sensor::SteamFlow(l) => t.secondary.loops[l.index()].steam_kg_s,
            Sensor::FeedFlow(l) => t.secondary.loops[l.index()].feed_kg_s,
            Sensor::TurbineValve => t.secondary.turbine_valve_percent,
            Sensor::GeneratorOutput => t.secondary.generator_mw,
            Sensor::CondenserPressure => t.secondary.condenser_pressure_kpa,
            Sensor::CoreExitTemperature => t.reactor.core_exit_c,
        })
    }

    pub fn snapshot(&self) -> PlantSnapshot {
        let mut truth = self.state.clone();
        let r = &mut truth.reactor;
        for value in [
            &mut r.neutron_power_percent,
            &mut r.thermal_mw,
            &mut r.decay_heat_percent,
            &mut r.reactivity_pcm,
            &mut r.control_rod_percent,
            &mut r.rod_demand_percent,
            &mut r.shutdown_rod_percent_inserted,
            &mut r.fuel_temperature_c,
            &mut r.core_exit_c,
        ] {
            *value = sensors::round(*value, 0.1);
        }
        let p = &mut truth.primary;
        for l in &mut p.loops {
            for value in [
                &mut l.hot_leg_c,
                &mut l.cold_leg_c,
                &mut l.steam_generator_primary_c,
                &mut l.flow_percent,
                &mut l.pump_speed_percent,
            ] {
                *value = sensors::round(*value, 0.1);
            }
        }
        for value in [
            &mut p.average_temperature_c,
            &mut p.level_percent,
            &mut p.spray_percent,
        ] {
            *value = sensors::round(*value, 0.1);
        }
        p.pressure_mpa = sensors::round(p.pressure_mpa, 0.01);
        p.heater_fraction = sensors::round(p.heater_fraction, 0.001);
        let s = &mut truth.secondary;
        for l in &mut s.loops {
            for value in [
                &mut l.level_percent,
                &mut l.steam_kg_s,
                &mut l.feed_kg_s,
                &mut l.feed_valve_percent,
                &mut l.heat_transfer_mw,
            ] {
                *value = sensors::round(*value, 0.1);
            }
        }
        s.steam_pressure_mpa = sensors::round(s.steam_pressure_mpa, 0.01);
        for value in [
            &mut s.turbine_valve_percent,
            &mut s.generator_mw,
            &mut s.steam_dump_percent,
            &mut s.condenser_pressure_kpa,
        ] {
            *value = sensors::round(*value, 0.1);
        }
        PlantSnapshot {
            at_ms: self.at_ms,
            revision: self.revision,
            operator_actions: self.operator_actions,
            model_limit: self.model_limit,
            last_fault_start_ms: self.last_fault_start_ms,
            first_action_after_fault_ms: self.first_action_after_fault_ms,
            truth,
            reported_status: self.instruments.status,
            readings: Sensor::ALL.map(|sensor| Channel {
                sensor,
                reading: self.instruments.readings[sensor.index()],
                fault: self.faults.sensors[sensor.index()],
            }),
            telemetry: sensors::Telemetry {
                quiet: self.faults.telemetry_quiet,
                ..self.instruments.telemetry
            },
            alarms: std::array::from_fn(|i| {
                if self.alarms[i] == AlarmState::Normal {
                    None
                } else {
                    Some(AlarmEntry {
                        alarm: Alarm::ALL[i],
                        state: self.alarms[i],
                    })
                }
            }),
            faults: self.faults.clone(),
        }
    }
}

fn approach(value: f64, demand: f64, distance: f64) -> f64 {
    value + (demand - value).clamp(-distance, distance)
}
