//! Modbus register map for the three controllers. Each controller answers
//! Modbus/TCP on port 502 with unit id 1. Read functions take their values from
//! a plant snapshot. Write functions decode to one plant command each.
//!
//! Addresses are zero-based. Input registers (function 4) and discrete inputs
//! (function 2) start at address 0 and fill the whole block. Coils (functions 1,
//! 5, 15) and holding registers (functions 3, 6, 16) do the same. An address past
//! a controller's block is not part of the read vector, and a write to it
//! decodes to `None`.
//!
//! Every analog value is an unsigned 16-bit count: the engineering value divided
//! by the instrument resolution, rounded half away from zero and clamped to
//! 0..=65535. A hot leg at 325.0 C reads 3250.
//!
//! Sensor-backed input registers read the reading, so a sensor fault shows in
//! the register. Discrete inputs and equipment coils (pumps, heaters, auxiliary
//! feed) read the reported status. Controller coils read the controller mode.
//! Momentary coils (trip, reset, acknowledge) read back as off, since they hold
//! no state. Holding registers read back the rod demand. The snapshot holds no
//! valve demands, so valve registers read back the valve position.
//!
//! Each input block ends with an unscaled Telemetry heartbeat count. It wraps
//! at 16 bits and holds while telemetry is quiet.
//!
//! | Controller | Address | Name | Scale |
//! | --- | --- | --- | --- |
//! | rps1 | 0 (30001) | Neutron power | 0.1 % |
//! | rps1 | 1 (30002) | Control rod position | 0.1 % |
//! | rps1 | 2 (30003) | Core exit temperature | 0.1 C |
//! | rps1 | 3 (30004) | Shutdown rod position | 0.1 % |
//! | rps1 | 4 (30005) | Telemetry heartbeat | 1 |
//! | rcs1 | 8 (30009) | Telemetry heartbeat | 1 |
//! | bop1 | 10 (30011) | Telemetry heartbeat | 1 |

use crate::command::{Command, Controller, Loop, Mode, Pump, Valve};
use crate::sensors::Sensor;
use crate::snapshot::PlantSnapshot;

/// One of the three Modbus controllers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plc {
    /// Reactor protection and rod control.
    Rps1,
    /// Reactor coolant system.
    Rcs1,
    /// Balance of plant.
    Bop1,
}

/// Source of one input register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Input {
    /// The reading of an instrument, at the instrument's resolution.
    Sensor(Sensor),
    /// The telemetry sample count.
    Heartbeat,
}

const ROD_RESOLUTION_PERCENT: f64 = 0.1;

const RPS1_INPUTS: [Input; 5] = [
    Input::Sensor(Sensor::NeutronPower),
    Input::Sensor(Sensor::RodPosition),
    Input::Sensor(Sensor::CoreExitTemperature),
    Input::Sensor(Sensor::ShutdownRodPosition),
    Input::Heartbeat,
];

const RCS1_INPUTS: [Input; 9] = [
    Input::Sensor(Sensor::HotLeg(Loop::A)),
    Input::Sensor(Sensor::HotLeg(Loop::B)),
    Input::Sensor(Sensor::ColdLeg(Loop::A)),
    Input::Sensor(Sensor::ColdLeg(Loop::B)),
    Input::Sensor(Sensor::PressurizerPressure),
    Input::Sensor(Sensor::PressurizerLevel),
    Input::Sensor(Sensor::CoolantFlow(Loop::A)),
    Input::Sensor(Sensor::CoolantFlow(Loop::B)),
    Input::Heartbeat,
];

const BOP1_INPUTS: [Input; 11] = [
    Input::Sensor(Sensor::SteamGeneratorLevel(Loop::A)),
    Input::Sensor(Sensor::SteamGeneratorLevel(Loop::B)),
    Input::Sensor(Sensor::SteamPressure),
    Input::Sensor(Sensor::SteamFlow(Loop::A)),
    Input::Sensor(Sensor::SteamFlow(Loop::B)),
    Input::Sensor(Sensor::FeedFlow(Loop::A)),
    Input::Sensor(Sensor::FeedFlow(Loop::B)),
    Input::Sensor(Sensor::TurbineValve),
    Input::Sensor(Sensor::GeneratorOutput),
    Input::Sensor(Sensor::CondenserPressure),
    Input::Heartbeat,
];

fn inputs(plc: Plc) -> &'static [Input] {
    match plc {
        Plc::Rps1 => &RPS1_INPUTS,
        Plc::Rcs1 => &RCS1_INPUTS,
        Plc::Bop1 => &BOP1_INPUTS,
    }
}

/// An analog value as an unsigned count of its resolution.
fn count(value: f64, resolution: f64) -> u16 {
    (value / resolution).round().clamp(0.0, 65_535.0) as u16
}

fn input_count(input: Input, s: &PlantSnapshot) -> u16 {
    match input {
        Input::Sensor(sensor) => count(
            s.readings[sensor.index()].reading.value,
            sensor.spec().resolution,
        ),
        Input::Heartbeat => s.telemetry.heartbeat,
    }
}

/// Input registers (function 4), from address 0.
pub fn input_registers(plc: Plc, s: &PlantSnapshot) -> Vec<u16> {
    inputs(plc)
        .iter()
        .map(|&input| input_count(input, s))
        .collect()
}

/// Discrete inputs (function 2), from address 0.
pub fn discrete_inputs(plc: Plc, s: &PlantSnapshot) -> Vec<bool> {
    let r = &s.reported_status;
    match plc {
        Plc::Rps1 => vec![r.reactor_tripped, r.turbine_tripped],
        Plc::Rcs1 => vec![
            r.coolant_pumps_running[0],
            r.coolant_pumps_running[1],
            r.pressurizer_relief_open,
            r.pressurizer_heaters_on,
        ],
        Plc::Bop1 => vec![
            r.feed_pumps_running[0],
            r.feed_pumps_running[1],
            r.auxiliary_feed_running,
            r.circulating_water_running,
            r.steam_relief_open,
            r.turbine_tripped,
        ],
    }
}

/// Coils (functions 1, 5 and 15), from address 0. Each reads back the latch or
/// mode it sets. Momentary coils read as off.
pub fn coils(plc: Plc, s: &PlantSnapshot) -> Vec<bool> {
    let r = &s.reported_status;
    let c = &s.truth.controllers;
    match plc {
        Plc::Rps1 => vec![false, false, false],
        Plc::Rcs1 => vec![
            r.coolant_pumps_running[0],
            r.coolant_pumps_running[1],
            r.pressurizer_heaters_on,
            c.pressurizer_pressure == Mode::Automatic,
        ],
        Plc::Bop1 => vec![
            r.feed_pumps_running[0],
            r.feed_pumps_running[1],
            r.auxiliary_feed_running,
            r.circulating_water_running,
            c.feed_level[0] == Mode::Automatic,
            c.feed_level[1] == Mode::Automatic,
            c.steam_dump == Mode::Automatic,
        ],
    }
}

/// Holding registers (functions 3, 6 and 16), from address 0. The rod register
/// reads the rod demand in tenths of a percent. Valve registers read the valve
/// position in permille, because the snapshot holds no valve demands.
pub fn holding_registers(plc: Plc, s: &PlantSnapshot) -> Vec<u16> {
    match plc {
        Plc::Rps1 => vec![count(
            s.truth.reactor.rod_demand_percent,
            ROD_RESOLUTION_PERCENT,
        )],
        Plc::Rcs1 => vec![count(s.truth.primary.spray_percent, 0.1)],
        Plc::Bop1 => vec![
            count(s.truth.secondary.loops[0].feed_valve_percent, 0.1),
            count(s.truth.secondary.loops[1].feed_valve_percent, 0.1),
            count(s.truth.secondary.turbine_valve_percent, 0.1),
            count(s.truth.secondary.steam_dump_percent, 0.1),
        ],
    }
}

fn valve_demand(valve: Valve, permille: u16) -> Command {
    Command::ValveDemand { valve, permille }
}

fn pump(pump: Pump, running: bool) -> Command {
    Command::Pump { pump, running }
}

fn controller(controller: Controller, on: bool) -> Command {
    let mode = if on { Mode::Automatic } else { Mode::Manual };
    Command::Controller { controller, mode }
}

/// Decodes a holding register write. Returns `None` for an address outside the
/// controller's block.
pub fn decode_register_write(plc: Plc, addr: u16, value: u16) -> Option<Command> {
    match (plc, addr) {
        (Plc::Rps1, 0) => Some(Command::RodDemand {
            tenths_percent: value,
        }),
        (Plc::Rcs1, 0) => Some(valve_demand(Valve::PressurizerSpray, value)),
        (Plc::Bop1, 0) => Some(valve_demand(Valve::Feed(Loop::A), value)),
        (Plc::Bop1, 1) => Some(valve_demand(Valve::Feed(Loop::B), value)),
        (Plc::Bop1, 2) => Some(valve_demand(Valve::Turbine, value)),
        (Plc::Bop1, 3) => Some(valve_demand(Valve::SteamDump, value)),
        _ => None,
    }
}

/// Decodes a coil write. A momentary coil decodes only when set on. Returns
/// `None` for an address outside the controller's block.
pub fn decode_coil_write(plc: Plc, addr: u16, on: bool) -> Option<Command> {
    match (plc, addr) {
        (Plc::Rps1, 0) => on.then_some(Command::ManualTrip),
        (Plc::Rps1, 1) => on.then_some(Command::ResetTrip),
        (Plc::Rps1, 2) => on.then_some(Command::AcknowledgeAlarms),
        (Plc::Rcs1, 0) => Some(pump(Pump::Coolant(Loop::A), on)),
        (Plc::Rcs1, 1) => Some(pump(Pump::Coolant(Loop::B), on)),
        (Plc::Rcs1, 2) => Some(Command::Heaters { on }),
        (Plc::Rcs1, 3) => Some(controller(Controller::PressurizerPressure, on)),
        (Plc::Bop1, 0) => Some(pump(Pump::MainFeed(Loop::A), on)),
        (Plc::Bop1, 1) => Some(pump(Pump::MainFeed(Loop::B), on)),
        (Plc::Bop1, 2) => Some(pump(Pump::AuxiliaryFeed, on)),
        (Plc::Bop1, 3) => Some(pump(Pump::CirculatingWater, on)),
        (Plc::Bop1, 4) => Some(controller(Controller::FeedLevel(Loop::A), on)),
        (Plc::Bop1, 5) => Some(controller(Controller::FeedLevel(Loop::B), on)),
        (Plc::Bop1, 6) => Some(controller(Controller::SteamDump, on)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, Plant};

    fn full_power() -> PlantSnapshot {
        Plant::new(Config::default()).snapshot()
    }

    fn assert_heartbeats(snapshot: &PlantSnapshot, expected: u16) {
        for (plc, address) in [(Plc::Rps1, 4), (Plc::Rcs1, 8), (Plc::Bop1, 10)] {
            assert_eq!(input_registers(plc, snapshot)[address], expected);
            assert_eq!(expected, snapshot.telemetry.heartbeat);
        }
    }

    #[test]
    fn telemetry_registers_start_from_the_seed() {
        let first = Plant::new(Config {
            seed: 29,
            ..Config::default()
        })
        .snapshot();
        let repeat = Plant::new(Config {
            seed: 29,
            ..Config::default()
        })
        .snapshot();
        let other = Plant::new(Config {
            seed: 30,
            ..Config::default()
        })
        .snapshot();
        assert_ne!(first.telemetry.heartbeat, 0);
        assert_ne!(first.telemetry.heartbeat, other.telemetry.heartbeat);
        assert_heartbeats(&first, repeat.telemetry.heartbeat);
    }

    #[test]
    fn telemetry_registers_hold_while_the_plant_advances() {
        use crate::command::FaultCommand;
        use crate::faults::{Fault, FaultChange};
        let mut plant = Plant::new(Config::default());
        let initial = plant.snapshot().telemetry.heartbeat;
        plant.advance(1_000);
        let before = plant.snapshot();
        assert_heartbeats(&before, initial.wrapping_add(4));
        plant
            .apply_fault(FaultCommand {
                change: FaultChange::Inject(Fault::TelemetryQuiet),
                expected_revision: before.revision,
            })
            .unwrap();
        plant.apply(Command::ManualTrip).unwrap();
        plant.advance(5_000);
        let after = plant.snapshot();
        assert!(after.at_ms > before.at_ms);
        assert_ne!(
            after.truth.reactor.neutron_power_percent,
            before.truth.reactor.neutron_power_percent
        );
        assert_heartbeats(&after, before.telemetry.heartbeat);
        for plc in [Plc::Rps1, Plc::Rcs1, Plc::Bop1] {
            assert_eq!(input_registers(plc, &before), input_registers(plc, &after));
            assert_eq!(discrete_inputs(plc, &before), discrete_inputs(plc, &after));
        }
    }

    #[test]
    fn telemetry_registers_wrap_at_sixteen_bits() {
        let mut plant = Plant::new(Config::default());
        let remaining = u64::from(u16::MAX - plant.snapshot().telemetry.heartbeat);
        plant.advance(remaining * 250);
        assert_heartbeats(&plant.snapshot(), u16::MAX);
        plant.advance((remaining + 1) * 250);
        assert_heartbeats(&plant.snapshot(), 0);
    }

    #[test]
    fn counts_use_instrument_resolution() {
        assert_eq!(count(325.0, 0.1), 3250);
        assert_eq!(count(15.50, 0.01), 1550);
        assert_eq!(count(2.5, 1.0), 3, "halves round away from zero");
        assert_eq!(count(-4.0, 0.1), 0, "negative values clamp to zero");
        assert_eq!(count(1.0e9, 0.1), 65_535, "large values clamp to the top");
    }

    #[test]
    fn full_power_hot_leg_and_pressurizer_pressure_encode_their_counts() {
        let s = full_power();
        let rcs = input_registers(Plc::Rcs1, &s);
        assert_eq!(rcs.len(), RCS1_INPUTS.len());
        assert_eq!(rcs[0], 3250, "hot leg A at 325.0 C");
        assert_eq!(rcs[1], 3250, "hot leg B at 325.0 C");
        assert_eq!(rcs[4], 1550, "pressurizer pressure at 15.50 MPa");
    }

    #[test]
    fn each_block_reads_its_sensor_channels_in_address_order() {
        let mut s = full_power();
        let values: [(Sensor, f64); 8] = [
            (Sensor::HotLeg(Loop::A), 300.0),
            (Sensor::HotLeg(Loop::B), 301.0),
            (Sensor::ColdLeg(Loop::A), 290.0),
            (Sensor::ColdLeg(Loop::B), 291.0),
            (Sensor::PressurizerPressure, 15.0),
            (Sensor::PressurizerLevel, 60.0),
            (Sensor::CoolantFlow(Loop::A), 99.0),
            (Sensor::CoolantFlow(Loop::B), 98.0),
        ];
        for (sensor, value) in values {
            s.readings[sensor.index()].reading.value = value;
        }
        assert_eq!(
            input_registers(Plc::Rcs1, &s),
            vec![
                3000,
                3010,
                2900,
                2910,
                1500,
                600,
                990,
                980,
                s.telemetry.heartbeat
            ],
        );
    }

    #[test]
    fn bop1_block_reads_steam_and_feed_channels() {
        let mut s = full_power();
        let values: [(Sensor, f64); 10] = [
            (Sensor::SteamGeneratorLevel(Loop::A), 50.0),
            (Sensor::SteamGeneratorLevel(Loop::B), 51.0),
            (Sensor::SteamPressure, 6.90),
            (Sensor::SteamFlow(Loop::A), 400.0),
            (Sensor::SteamFlow(Loop::B), 401.0),
            (Sensor::FeedFlow(Loop::A), 402.0),
            (Sensor::FeedFlow(Loop::B), 403.0),
            (Sensor::TurbineValve, 80.0),
            (Sensor::GeneratorOutput, 900.0),
            (Sensor::CondenserPressure, 5.0),
        ];
        for (sensor, value) in values {
            s.readings[sensor.index()].reading.value = value;
        }
        assert_eq!(
            input_registers(Plc::Bop1, &s),
            vec![
                500,
                510,
                690,
                4000,
                4010,
                4020,
                4030,
                800,
                9000,
                50,
                s.telemetry.heartbeat
            ],
        );
    }

    #[test]
    fn rps1_block_reads_shutdown_rod_indication() {
        let mut s = full_power();
        s.truth.reactor.shutdown_rod_percent_inserted = 25.0;
        s.readings[Sensor::ShutdownRodPosition.index()]
            .reading
            .value = 63.4;
        let regs = input_registers(Plc::Rps1, &s);
        assert_eq!(regs.len(), RPS1_INPUTS.len());
        assert_eq!(regs[3], 634);
        s.truth.reactor.shutdown_rod_percent_inserted = 100.0;
        assert_eq!(input_registers(Plc::Rps1, &s)[3], 634);
        assert_eq!(regs[4], s.telemetry.heartbeat);
    }

    #[test]
    fn sensor_fault_shows_in_the_register_because_it_reads_the_reading() {
        let mut s = full_power();
        // A stuck hot leg holds its reading at 3250 counts while the true hot leg moves.
        s.truth.primary.loops[0].hot_leg_c = 330.0;
        s.readings[Sensor::HotLeg(Loop::A).index()].reading.value = 325.0;
        assert_eq!(input_registers(Plc::Rcs1, &s)[0], 3250);
    }

    #[test]
    fn discrete_inputs_follow_reported_status() {
        let mut s = full_power();
        s.reported_status.reactor_tripped = true;
        s.reported_status.pressurizer_heaters_on = false;
        assert_eq!(discrete_inputs(Plc::Rps1, &s), vec![true, false]);
        assert_eq!(
            discrete_inputs(Plc::Rcs1, &s),
            vec![true, true, false, false],
        );
        assert_eq!(
            discrete_inputs(Plc::Bop1, &s),
            vec![true, true, false, true, false, false],
        );
    }

    #[test]
    fn coils_read_back_latches_and_controller_modes() {
        let mut s = full_power();
        assert_eq!(coils(Plc::Rps1, &s), vec![false, false, false]);
        // Full power starts with both coolant pumps, the heaters and every controller automatic.
        assert_eq!(coils(Plc::Rcs1, &s), vec![true, true, true, true]);
        // Auxiliary feed starts off; both feed pumps, circulating water and every controller run.
        assert_eq!(
            coils(Plc::Bop1, &s),
            vec![true, true, false, true, true, true, true],
        );
        s.truth.controllers.pressurizer_pressure = Mode::Manual;
        s.truth.controllers.feed_level[1] = Mode::Manual;
        assert!(!coils(Plc::Rcs1, &s)[3]);
        assert!(!coils(Plc::Bop1, &s)[5]);
    }

    #[test]
    fn rod_and_valve_holding_registers_read_back_demand_and_position() {
        let mut s = full_power();
        s.truth.reactor.rod_demand_percent = 48.0;
        assert_eq!(holding_registers(Plc::Rps1, &s), vec![480]);
        assert_eq!(holding_registers(Plc::Rcs1, &s), vec![0]);
        assert_eq!(holding_registers(Plc::Bop1, &s).len(), 4);
    }

    #[test]
    fn rod_register_write_decodes_to_rod_demand() {
        assert_eq!(
            decode_register_write(Plc::Rps1, 0, 480),
            Some(Command::RodDemand {
                tenths_percent: 480
            }),
        );
    }

    #[test]
    fn valve_register_writes_decode_to_their_valves() {
        assert_eq!(
            decode_register_write(Plc::Rcs1, 0, 250),
            Some(Command::ValveDemand {
                valve: Valve::PressurizerSpray,
                permille: 250
            }),
        );
        assert_eq!(
            decode_register_write(Plc::Bop1, 1, 600),
            Some(Command::ValveDemand {
                valve: Valve::Feed(Loop::B),
                permille: 600
            }),
        );
        assert_eq!(
            decode_register_write(Plc::Bop1, 3, 0),
            Some(Command::ValveDemand {
                valve: Valve::SteamDump,
                permille: 0
            }),
        );
    }

    #[test]
    fn register_addresses_outside_each_block_decode_to_none() {
        assert_eq!(decode_register_write(Plc::Rps1, 99, 0), None);
        assert_eq!(decode_register_write(Plc::Rps1, 1, 0), None);
        assert_eq!(decode_register_write(Plc::Rcs1, 1, 0), None);
        assert_eq!(decode_register_write(Plc::Bop1, 4, 0), None);
    }

    #[test]
    fn momentary_coils_decode_only_when_set() {
        assert_eq!(decode_coil_write(Plc::Rps1, 0, false), None);
        assert_eq!(
            decode_coil_write(Plc::Rps1, 0, true),
            Some(Command::ManualTrip)
        );
        assert_eq!(decode_coil_write(Plc::Rps1, 1, false), None);
        assert_eq!(
            decode_coil_write(Plc::Rps1, 1, true),
            Some(Command::ResetTrip)
        );
        assert_eq!(decode_coil_write(Plc::Rps1, 2, false), None);
        assert_eq!(
            decode_coil_write(Plc::Rps1, 2, true),
            Some(Command::AcknowledgeAlarms)
        );
    }

    #[test]
    fn pump_heater_and_mode_coils_decode_to_their_commands() {
        assert_eq!(
            decode_coil_write(Plc::Rcs1, 1, false),
            Some(Command::Pump {
                pump: Pump::Coolant(Loop::B),
                running: false
            }),
        );
        assert_eq!(
            decode_coil_write(Plc::Rcs1, 2, true),
            Some(Command::Heaters { on: true })
        );
        assert_eq!(
            decode_coil_write(Plc::Rcs1, 3, true),
            Some(Command::Controller {
                controller: Controller::PressurizerPressure,
                mode: Mode::Automatic
            }),
        );
        assert_eq!(
            decode_coil_write(Plc::Rcs1, 3, false),
            Some(Command::Controller {
                controller: Controller::PressurizerPressure,
                mode: Mode::Manual
            }),
        );
        assert_eq!(
            decode_coil_write(Plc::Bop1, 2, false),
            Some(Command::Pump {
                pump: Pump::AuxiliaryFeed,
                running: false
            }),
        );
        assert_eq!(
            decode_coil_write(Plc::Bop1, 6, true),
            Some(Command::Controller {
                controller: Controller::SteamDump,
                mode: Mode::Automatic
            }),
        );
    }

    #[test]
    fn coil_addresses_outside_each_block_decode_to_none() {
        assert_eq!(decode_coil_write(Plc::Rps1, 3, true), None);
        assert_eq!(decode_coil_write(Plc::Rcs1, 4, true), None);
        assert_eq!(decode_coil_write(Plc::Bop1, 7, true), None);
    }

    #[test]
    fn decoded_rod_write_moves_the_plant_and_reads_back() {
        let mut plant = Plant::new(Config::default());
        let command = decode_register_write(Plc::Rps1, 0, 480).expect("rod address");
        plant.apply(command).expect("rod demand accepted");
        plant.advance(1_000);
        let s = plant.snapshot();
        assert_eq!(holding_registers(Plc::Rps1, &s), vec![480]);
    }
}
