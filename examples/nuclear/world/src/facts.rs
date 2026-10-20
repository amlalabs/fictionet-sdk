//! Plant facts for the Fictionet event log.
//!
//! Every fact is an event from source `plant`. Each fact has a fixed short
//! list of fields, and every fact carries `at_ms`: the plant
//! time of the change. Stage and end facts use their logged first time. Facts go to a [`Sink`]: a world's
//! [`Cx`], or the driver of a Modbus connection. A sink builds a fact only
//! when a destination wants that kind, so a run without an observer builds
//! nothing.
//!
//! | Kind | Fact | Made by |
//! | --- | --- | --- |
//! | `action` | an accepted operator command | [`action`] |
//! | `rejected` | a refused operator command | [`rejected`] |
//! | `fault` | a fault started or cleared | [`fault`] |
//! | `first_action` | the first accepted command after a fault start | [`changes`] |
//! | `trip` | a reactor trip, or a turbine trip without one | [`changes`] |
//! | `stage` | a newly reached stage | [`changes`] |
//! | `end` | the first end | [`changes`] |
//! | `reset` | a scenario started at time zero | [`reset`] |
//! | `divergence` | a faulted instrument's true and reported values | [`divergence`] |
//!
//! Limits: a write's facts are held by [`Held`] until the whole write is
//! accepted. A refused write therefore logs only its rejection. A divergence
//! sample marks the start, peak, or clear of a sensor fault. The driver tracks
//! the peak at each plant step and emits at most three lines per fault.
//! The true value is the snapshot's truth at the snapshot's rounding (0.1 or
//! 0.01), not the plant's unrounded value. A reactor trip carries `tripped_ms`,
//! the plant step that latched it. `at_ms` is when the change was seen: the
//! command, or the end of the advance, that caused it.

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr};

use fictionet::Cx;
use fictionet::events::{ConnInfo, Event, Level, float};
use fictionet::stdlib::services::serve;

use crate::command::{Command, Controller, Loop, Mode, Pump, Rejection, Valve};
use crate::faults::{Fault, FaultChange, FaultTarget, ProcessFault};
use crate::protection::TripCause;
use crate::scenarios::Scenario;
use crate::sensors::{Sensor, Unit};
use crate::snapshot::{PlantSnapshot, Truth};
use crate::stages::{FailureCause, Stage};

/// The source name of every plant fact.
const SOURCE: &str = "plant";

/// Plant time with hours when needed, minutes, seconds, and tenths.
pub fn time(at_ms: u64) -> String {
    if at_ms >= 3_600_000 {
        return format!(
            "{}:{:02}:{:02}.{}",
            at_ms / 3_600_000,
            at_ms / 60_000 % 60,
            at_ms / 1_000 % 60,
            at_ms / 100 % 10
        );
    }
    format!(
        "{}:{:02}.{}",
        at_ms / 60_000,
        at_ms / 1_000 % 60,
        at_ms / 100 % 10
    )
}

/// The HMI's address. A Modbus connection from it logs its commands as `hmi`.
pub const HMI_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 40, 0, 20);

/// Who sent an operator command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The operator's HMI, at [`HMI_ADDRESS`].
    Hmi,
    /// Any other Modbus client.
    Modbus,
    /// The viewer's command port, which is not Modbus.
    Panel,
}

impl Source {
    /// The name the event logs: `hmi`, `modbus` or `panel`.
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Hmi => "hmi",
            Source::Modbus => "modbus",
            Source::Panel => "panel",
        }
    }
}

/// The source of a Modbus connection. It is `hmi` when the peer's address is
/// [`HMI_ADDRESS`]; when the peer is unknown, the sandbox's address decides.
/// Any other address is `modbus`.
pub fn source_of(conn: &ConnInfo) -> Source {
    let address = conn.peer.map(|peer| peer.ip()).or_else(|| {
        conn.sandbox
            .as_ref()
            .and_then(|sandbox| sandbox.addr)
            .map(IpAddr::V4)
    });
    if address == Some(IpAddr::V4(HMI_ADDRESS)) {
        Source::Hmi
    } else {
        Source::Modbus
    }
}

/// Where plant facts go.
pub trait Sink {
    /// Whether a destination wants facts of `kind`. Check before doing work
    /// that only a fact needs.
    fn wants(&self, kind: &'static str) -> bool;

    /// Delivers one fact of `kind`. `build` runs only when a destination wants
    /// the fact, and it receives an event that already names the source and kind.
    fn record(&self, kind: &'static str, build: impl FnOnce(Event) -> Event);
}

impl Sink for Cx {
    fn wants(&self, kind: &'static str) -> bool {
        self.event_enabled(SOURCE, kind)
    }

    fn record(&self, kind: &'static str, build: impl FnOnce(Event) -> Event) {
        self.emit(SOURCE, kind, build);
    }
}

impl<D> Sink for serve::Driver<'_, D> {
    fn wants(&self, kind: &'static str) -> bool {
        self.event_enabled(SOURCE, kind)
    }

    fn record(&self, kind: &'static str, build: impl FnOnce(Event) -> Event) {
        self.emit(SOURCE, kind, build);
    }
}

/// A sink that keeps no facts. Methods given `()` deliver nothing, and no fact
/// is built.
impl Sink for () {
    fn wants(&self, _kind: &'static str) -> bool {
        false
    }

    fn record(&self, _kind: &'static str, _build: impl FnOnce(Event) -> Event) {}
}

/// Facts held until the change that made them has stood. Dropping a `Held`
/// discards its facts. [`Held::release`] delivers them in order.
pub struct Held<'a, S> {
    sink: &'a S,
    events: RefCell<Vec<Event>>,
}

impl<'a, S: Sink> Held<'a, S> {
    /// Holds facts for `sink`.
    pub fn new(sink: &'a S) -> Self {
        Held {
            sink,
            events: RefCell::new(Vec::new()),
        }
    }

    /// Delivers the held facts to the sink, in the order they were made.
    pub fn release(self) {
        for event in self.events.into_inner() {
            let kind = event.kind;
            self.sink.record(kind, move |_| event);
        }
    }
}

impl<S: Sink> Sink for Held<'_, S> {
    fn wants(&self, kind: &'static str) -> bool {
        self.sink.wants(kind)
    }

    fn record(&self, kind: &'static str, build: impl FnOnce(Event) -> Event) {
        if self.sink.wants(kind) {
            let event = build(Event::new(SOURCE, kind));
            self.events.borrow_mut().push(event);
        }
    }
}

/// An accepted operator command, with the plant as it stands after the command.
pub fn action(sink: &impl Sink, command: Command, source: Source, after: &PlantSnapshot) {
    sink.record("action", |event| {
        let name = command_name(command);
        let event = match command {
            Command::Pump {
                pump: Pump::SafetyInjection,
                ..
            } => event.field("pump", "safety_injection"),
            _ => event,
        };
        event
            .summary(format!(
                "{} from {}",
                command_words(command),
                source_words(source)
            ))
            .field("command", name)
            .field("source", source.as_str())
            .field("operator_actions", after.operator_actions)
            .field("revision", after.revision)
            .field("at_ms", after.at_ms)
            .field("time", time(after.at_ms))
    });
}

/// A refused operator command and the reason the plant gave.
pub fn rejected(sink: &impl Sink, command: Command, source: Source, reason: Rejection, at_ms: u64) {
    sink.record("rejected", |event| {
        let name = command_name(command);
        let reason = rejection_name(reason);
        event
            .level(Level::Notice)
            .summary(format!(
                "{} from {} refused: {}",
                command_words(command),
                source_words(source),
                words(reason)
            ))
            .field("command", name)
            .field("source", source.as_str())
            .field("reason", reason)
            .field("at_ms", at_ms)
            .field("time", time(at_ms))
    });
}

/// A fault that started or cleared, with the plant as it stands after it.
pub fn fault(sink: &impl Sink, change: FaultChange, after: &PlantSnapshot) {
    sink.record("fault", |event| {
        let (kind, target) = change_parts(change);
        let summary = match &target {
            Some(target) => format!(
                "{} {}",
                sentence(target),
                if kind == "inject" {
                    "injected"
                } else {
                    "cleared"
                }
            ),
            None => "All faults cleared".into(),
        };
        let event = event
            .summary(summary)
            .field("change", kind)
            .field("at_ms", after.at_ms)
            .field("time", time(after.at_ms));
        let event = match target {
            Some(target) => event.field("target", target),
            None => event,
        };
        match after.last_fault_start_ms {
            Some(start) => event.field("last_fault_start_ms", start),
            None => event,
        }
    });
}

/// The facts one change made, from the snapshots before and after it: a
/// reactor trip, or a turbine trip without one, and the first accepted command
/// after a fault start. New stages follow time order, with array order for ties,
/// followed by the first end. Each fires once per change.
pub fn changes(sink: &impl Sink, before: &PlantSnapshot, after: &PlantSnapshot) {
    if sink.wants("stage") {
        let mut stages = Stage::ALL
            .into_iter()
            .filter_map(|stage| {
                let index = stage.index();
                after.stages[index]
                    .filter(|_| before.stages[index].is_none())
                    .map(|at| (stage, at))
            })
            .collect::<Vec<_>>();
        stages.sort_by_key(|(stage, at)| (*at, stage.index()));
        for (stage, at_ms) in stages {
            sink.record("stage", |event| {
                let name = wire_name(stage);
                let event = event
                    .level(
                        if matches!(stage, Stage::Boiling | Stage::TurbineHallSteam) {
                            Level::Notice
                        } else {
                            Level::Alarm
                        },
                    )
                    .summary(sentence(&name))
                    .field("stage", name)
                    .field("at_ms", at_ms)
                    .field("time", time(at_ms))
                    .field("operator_actions", after.operator_actions)
                    .field(
                        "last_command",
                        after
                            .last_command
                            .map_or("none", |last| command_name(last.command)),
                    );
                match after.last_command {
                    Some(last) => event.field("last_command_ms", last.at_ms),
                    None => event,
                }
            });
        }
    }
    if before.end.is_none()
        && let Some(end) = after.end
    {
        sink.record("end", |event| {
            let name = wire_name(end.stage);
            let cause = if end.stage == Stage::ContainmentFailure {
                after.severe.containment.failure
            } else {
                None
            };
            let suffix = match cause {
                Some(FailureCause::HydrogenBurn) => " from a hydrogen burn",
                Some(FailureCause::Overpressure) => " from overpressure",
                None => "",
            };
            let event = event
                .level(Level::Alarm)
                .summary(format!("End: {}{suffix}", words(&name)))
                .field("stage", name)
                .field("at_ms", end.at_ms)
                .field("time", time(end.at_ms))
                .field("operator_actions", after.operator_actions);
            match cause {
                Some(cause) => event.field("cause", wire_name(cause)),
                None => event,
            }
        });
    }

    let new_reactor_trip = match (before.truth.reactor.trip, after.truth.reactor.trip) {
        (None, Some(trip)) => Some(trip),
        _ => None,
    };
    if let Some(trip) = new_reactor_trip {
        sink.record("trip", |event| {
            let cause = cause_name(trip.cause);
            event
                .level(Level::Notice)
                .summary(format!("Reactor trip: {}", words(&cause)))
                .field("cause", cause)
                .field("tripped_ms", trip.at_ms)
                .field("at_ms", after.at_ms)
                .field("time", time(after.at_ms))
        });
    } else if !before.truth.secondary.turbine_tripped && after.truth.secondary.turbine_tripped {
        // A reactor trip also trips the turbine, so only a turbine trip without
        // a reactor trip logs here.
        sink.record("trip", |event| {
            event
                .level(Level::Notice)
                .summary("Turbine trip")
                .field("cause", "turbine_trip")
                .field("at_ms", after.at_ms)
                .field("time", time(after.at_ms))
        });
    }
    if before.first_action_after_fault_ms.is_none()
        && let Some(delay) = after.first_action_after_fault_ms
    {
        sink.record("first_action", |event| {
            event
                .summary(format!(
                    "First command {:.1} s after a fault started",
                    delay as f64 / 1_000.0
                ))
                .field("first_action_after_fault_ms", delay)
                .field("at_ms", after.at_ms)
                .field("time", time(after.at_ms))
        });
    }
}

/// A scenario starts at plant time zero.
pub fn reset(sink: &impl Sink, scenario: Scenario, speed: u16) {
    sink.record("reset", |event| {
        event
            .level(Level::Notice)
            .summary(format!("Started {}", words(&wire_name(scenario))))
            .field("scenario", wire_name(scenario))
            .field("speed", u64::from(speed))
            .field("at_ms", 0_u64)
            .field("time", time(0))
    });
}

fn wire_name(value: impl serde::Serialize) -> String {
    serde_json::to_value(value)
        .expect("wire name serializes")
        .as_str()
        .expect("wire name is text")
        .to_owned()
}

/// One sensor's true and reported values at a fault's start, peak, or clear.
pub fn divergence(
    sink: &impl Sink,
    sensor: Sensor,
    true_value: f64,
    reported: f64,
    at_ms: u64,
    phase: &'static str,
) {
    sink.record("divergence", |event| {
        let point = point_name(sensor);
        let unit = match sensor.spec().unit {
            Unit::Celsius => "°C",
            Unit::Megapascal => "MPa",
            Unit::Kilopascal => "kPa",
            Unit::KilogramsPerSecond => "kg/s",
            Unit::Megawatt => "MW",
            Unit::Percent => "%",
        };
        event
            .summary(format!(
                "{} gauge {reported:.1} {unit}, plant {true_value:.1} {unit}",
                sentence(&point)
            ))
            .field("point", point)
            .field("true_value", float(true_value))
            .field("reported_value", float(reported))
            .field("at_ms", at_ms)
            .field("time", time(at_ms))
            .field("phase", phase)
    });
}

fn words(id: &str) -> String {
    id.split('_')
        .map(|word| match word {
            "a" => "A",
            "b" => "B",
            other => other,
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn sentence(id: &str) -> String {
    let text = words(id);
    format!("{}{}", text[..1].to_uppercase(), &text[1..])
}

fn source_words(source: Source) -> &'static str {
    match source {
        Source::Hmi => "the HMI",
        Source::Modbus => "a Modbus client",
        Source::Panel => "the panel",
    }
}

fn command_words(command: Command) -> String {
    match command {
        Command::RodDemand { tenths_percent } => {
            format!("Rod demand {:.1}%", f64::from(tenths_percent) / 10.0)
        }
        Command::Relief { open } => {
            format!("Relief valves {}", if open { "opened" } else { "closed" })
        }
        Command::ReliefBlock { closed } => format!(
            "Relief block valves {}",
            if closed { "closed" } else { "opened" }
        ),
        Command::SteamIsolation { closed } => format!(
            "Steam isolation valves {}",
            if closed { "closed" } else { "opened" }
        ),
        Command::ManualTrip => "Manual trip".into(),
        Command::ResetTrip => "Trip reset".into(),
        Command::AcknowledgeAlarms => "Alarm acknowledgment".into(),
        Command::Heaters { on } => format!("Heaters {}", if on { "on" } else { "off" }),
        Command::Pump { pump, running } => {
            let name = match pump {
                Pump::Coolant(l) => format!("Coolant pump {}", words(loop_name(l))),
                Pump::MainFeed(l) => format!("Main feed pump {}", words(loop_name(l))),
                Pump::AuxiliaryFeed => "Auxiliary feed pump".into(),
                Pump::CirculatingWater => "Circulating water pump".into(),
                Pump::SafetyInjection => "Safety injection pumps".into(),
            };
            format!("{name} {}", if running { "started" } else { "stopped" })
        }
        Command::ValveDemand { valve, permille } => {
            let name = match valve {
                Valve::Feed(l) => format!("Feed valve {}", words(loop_name(l))),
                Valve::Turbine => "Turbine valve".into(),
                Valve::SteamDump => "Steam dump".into(),
                Valve::PressurizerSpray => "Pressurizer spray".into(),
            };
            format!("{name} demand {:.1}%", f64::from(permille) / 10.0)
        }
        Command::Controller { controller, mode } => {
            let name = match controller {
                Controller::FeedLevel(l) => format!("Feed level {}", words(loop_name(l))),
                Controller::PressurizerPressure => "Pressurizer pressure".into(),
                Controller::SteamDump => "Steam dump".into(),
            };
            format!(
                "{name} controller {}",
                match mode {
                    Mode::Automatic => "automatic",
                    Mode::Manual => "manual",
                }
            )
        }
    }
}

fn command_name(command: Command) -> &'static str {
    match command {
        Command::RodDemand { .. } => "rod_demand",
        Command::Relief { .. } => "relief",
        Command::ReliefBlock { .. } => "relief_block",
        Command::SteamIsolation { .. } => "steam_isolation",
        Command::ManualTrip => "manual_trip",
        Command::ResetTrip => "reset_trip",
        Command::Pump { .. } => "pump",
        Command::ValveDemand { .. } => "valve_demand",
        Command::Controller { .. } => "controller",
        Command::Heaters { .. } => "heaters",
        Command::AcknowledgeAlarms => "acknowledge_alarms",
    }
}

fn rejection_name(reason: Rejection) -> &'static str {
    match reason {
        Rejection::StaleRevision => "stale_revision",
        Rejection::OutOfRange => "out_of_range",
        Rejection::Tripped => "tripped",
        Rejection::TripConditionPresent => "trip_condition_present",
        Rejection::Faulted => "faulted",
        Rejection::WrongMode => "wrong_mode",
        Rejection::AlreadyActive => "already_active",
        Rejection::NotActive => "not_active",
    }
}

fn cause_name(cause: TripCause) -> String {
    match cause {
        TripCause::Manual => "manual".into(),
        TripCause::NeutronPowerHigh => "neutron_power_high".into(),
        TripCause::PressurizerPressureHigh => "pressurizer_pressure_high".into(),
        TripCause::PressurizerPressureLow => "pressurizer_pressure_low".into(),
        TripCause::CoolantFlowLow(l) => format!("coolant_flow_low_{}", loop_name(l)),
        TripCause::SteamGeneratorLevelLow(l) => {
            format!("steam_generator_level_low_{}", loop_name(l))
        }
        TripCause::HotLegTemperatureHigh(l) => {
            format!("hot_leg_temperature_high_{}", loop_name(l))
        }
        TripCause::TurbineTrip => "turbine_trip".into(),
    }
}

/// The change name and, when the change names one, its target.
fn change_parts(change: FaultChange) -> (&'static str, Option<String>) {
    match change {
        FaultChange::Inject(fault) => {
            let target = match fault {
                Fault::Process(process) => process_name(process),
                Fault::Sensor { sensor, .. } => point_name(sensor),
                Fault::TelemetryQuiet => "telemetry_quiet".into(),
            };
            ("inject", Some(target))
        }
        FaultChange::Clear(target) => {
            let name = match target {
                FaultTarget::Process(process) => process_name(process),
                FaultTarget::Sensor(sensor) => point_name(sensor),
                FaultTarget::TelemetryQuiet => "telemetry_quiet".into(),
            };
            ("clear", Some(name))
        }
        FaultChange::ClearAll => ("clear_all", None),
    }
}

fn process_name(fault: ProcessFault) -> String {
    match fault {
        ProcessFault::FeedPumpTrip { pump } => format!("feed_pump_trip_{}", loop_name(pump)),
        ProcessFault::CoolantPumpTrip { pump } => {
            format!("coolant_pump_trip_{}", loop_name(pump))
        }
        ProcessFault::FeedValveStuck { line } => format!("feed_valve_stuck_{}", loop_name(line)),
        ProcessFault::CondenserCoolingLoss => "condenser_cooling_loss".into(),
        ProcessFault::ReliefStuckOpen => "relief_stuck_open".into(),
        ProcessFault::SafetyInjectionFailure => "safety_injection_failure".into(),
        ProcessFault::SteamLineBreak => "steam_line_break".into(),
        ProcessFault::StationBlackout => "station_blackout".into(),
    }
}

/// The instrument's point name, with its loop suffix when it has one.
fn point_name(sensor: Sensor) -> String {
    match sensor {
        Sensor::NeutronPower => "neutron_power".into(),
        Sensor::RodPosition => "rod_position".into(),
        Sensor::ShutdownRodPosition => "shutdown_rod_position".into(),
        Sensor::HotLeg(l) => format!("hot_leg_{}", loop_name(l)),
        Sensor::ColdLeg(l) => format!("cold_leg_{}", loop_name(l)),
        Sensor::PressurizerPressure => "pressurizer_pressure".into(),
        Sensor::PressurizerLevel => "pressurizer_level".into(),
        Sensor::CoolantFlow(l) => format!("coolant_flow_{}", loop_name(l)),
        Sensor::SteamGeneratorLevel(l) => format!("steam_generator_level_{}", loop_name(l)),
        Sensor::SteamPressure => "steam_pressure".into(),
        Sensor::SteamFlow(l) => format!("steam_flow_{}", loop_name(l)),
        Sensor::FeedFlow(l) => format!("feed_flow_{}", loop_name(l)),
        Sensor::TurbineValve => "turbine_valve".into(),
        Sensor::GeneratorOutput => "generator_output".into(),
        Sensor::CondenserPressure => "condenser_pressure".into(),
        Sensor::CoreExitTemperature => "core_exit_temperature".into(),
    }
}

fn loop_name(l: Loop) -> &'static str {
    match l {
        Loop::A => "a",
        Loop::B => "b",
    }
}

/// The true value of a sensor's point, read from the snapshot's truth. This
/// matches the plant's own sensor source.
pub(crate) fn true_value_of(truth: &Truth, sensor: Sensor) -> f64 {
    let reactor = &truth.reactor;
    let primary = &truth.primary;
    let secondary = &truth.secondary;
    match sensor {
        Sensor::NeutronPower => reactor.neutron_power_percent,
        Sensor::RodPosition => reactor.control_rod_percent,
        Sensor::ShutdownRodPosition => reactor.shutdown_rod_percent_inserted,
        Sensor::HotLeg(l) => primary.loops[l.index()].hot_leg_c,
        Sensor::ColdLeg(l) => primary.loops[l.index()].cold_leg_c,
        Sensor::PressurizerPressure => primary.pressure_mpa,
        Sensor::PressurizerLevel => primary.level_percent,
        Sensor::CoolantFlow(l) => primary.loops[l.index()].flow_percent,
        Sensor::SteamGeneratorLevel(l) => secondary.loops[l.index()].level_percent,
        Sensor::SteamPressure => secondary.steam_pressure_mpa,
        Sensor::SteamFlow(l) => secondary.loops[l.index()].steam_kg_s,
        Sensor::FeedFlow(l) => secondary.loops[l.index()].feed_kg_s,
        Sensor::TurbineValve => secondary.turbine_valve_percent,
        Sensor::GeneratorOutput => secondary.generator_mw,
        Sensor::CondenserPressure => secondary.condenser_pressure_kpa,
        Sensor::CoreExitTemperature => reactor.core_exit_c,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::Trip;
    use crate::{Config, Plant};

    /// A sink that keeps every fact it is given, in order.
    #[derive(Default)]
    struct Log(RefCell<Vec<Event>>);

    impl Sink for Log {
        fn wants(&self, _kind: &'static str) -> bool {
            true
        }

        fn record(&self, kind: &'static str, build: impl FnOnce(Event) -> Event) {
            self.0.borrow_mut().push(build(Event::new(SOURCE, kind)));
        }
    }

    impl Log {
        fn of(&self, kind: &str) -> Vec<Event> {
            self.0
                .borrow()
                .iter()
                .filter(|event| event.kind == kind)
                .cloned()
                .collect()
        }
    }

    fn snapshot() -> PlantSnapshot {
        Plant::new(Config::default()).snapshot()
    }

    #[test]
    fn stage_ties_keep_array_order_and_end_follows_them() {
        let before = snapshot();
        let mut after = before.clone();
        after.at_ms = 500;
        for stage in Stage::ALL {
            after.stages[stage.index()] = Some(100);
        }
        after.stages[Stage::TurbineHallSteam.index()] = Some(50);
        after.end = Some(crate::stages::End {
            stage: Stage::ControlRoomUninhabitable,
            at_ms: 100,
        });
        let log = Log::default();
        changes(&log, &before, &after);
        changes(&log, &after, &after);
        let events = log.0.borrow();
        assert_eq!(events.len(), 13);
        let mut expected = vec![Stage::TurbineHallSteam];
        expected.extend(
            Stage::ALL
                .into_iter()
                .filter(|stage| *stage != Stage::TurbineHallSteam),
        );
        for (event, stage) in events.iter().zip(expected) {
            assert_eq!(event.kind, "stage");
            assert_eq!(event.str("stage"), Some(wire_name(stage).as_str()));
            assert_eq!(
                event.level,
                if matches!(stage, Stage::Boiling | Stage::TurbineHallSteam) {
                    Level::Notice
                } else {
                    Level::Alarm
                }
            );
        }
        let end = events.last().unwrap();
        assert_eq!(end.kind, "end");
        assert_eq!(end.level, Level::Alarm);
        assert_eq!(end.u64("at_ms"), Some(100));
        assert!(end.get("cause").is_none());
    }

    #[test]
    fn reset_names_the_scenario_speed_and_zero_time() {
        let log = Log::default();
        reset(&log, Scenario::StuckOpenRelief, 600);
        let events = log.of("reset");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].level, Level::Notice);
        assert_eq!(events[0].str("scenario"), Some("stuck_open_relief"));
        assert_eq!(events[0].u64("speed"), Some(600));
        assert_eq!(events[0].u64("at_ms"), Some(0));
        assert_eq!(events[0].str("time"), Some("0:00.0"));
    }

    #[test]
    fn source_follows_the_peer_then_the_sandbox_and_defaults_to_modbus() {
        let peer = |ip: &str| {
            ConnInfo::new(
                1,
                "10.40.0.2:502".parse().unwrap(),
                format!("{ip}:51000").parse().unwrap(),
            )
        };
        assert_eq!(source_of(&peer("10.40.0.20")), Source::Hmi);
        assert_eq!(source_of(&peer("10.40.0.30")), Source::Modbus);
        assert_eq!(source_of(&ConnInfo::default()), Source::Modbus);

        let sandboxed = ConnInfo {
            sandbox: Some(fictionet::events::Sandbox {
                id: 1,
                name: "hmi".into(),
                addr: Some(HMI_ADDRESS),
                addr_v6: None,
            }),
            ..ConnInfo::default()
        };
        assert_eq!(source_of(&sandboxed), Source::Hmi);
    }

    #[test]
    fn a_turbine_trip_without_a_reactor_trip_logs_one_trip() {
        let before = snapshot();
        let mut after = before.clone();
        after.at_ms = 3_000;
        after.truth.secondary.turbine_tripped = true;

        let log = Log::default();
        changes(&log, &before, &after);

        let trips = log.of("trip");
        assert_eq!(trips.len(), 1);
        assert_eq!(trips[0].str("cause"), Some("turbine_trip"));
        assert_eq!(trips[0].u64("at_ms"), Some(3_000));
        assert_eq!(trips[0].get("tripped_ms"), None);
    }

    #[test]
    fn a_reactor_trip_that_trips_the_turbine_logs_one_trip() {
        let before = snapshot();
        let mut after = before.clone();
        after.at_ms = 150;
        after.truth.secondary.turbine_tripped = true;
        after.truth.reactor.trip = Some(Trip {
            cause: TripCause::TurbineTrip,
            at_ms: 100,
        });

        let log = Log::default();
        changes(&log, &before, &after);

        let trips = log.of("trip");
        assert_eq!(
            trips.len(),
            1,
            "the turbine trip is part of the reactor trip"
        );
        assert_eq!(trips[0].str("cause"), Some("turbine_trip"));
        assert_eq!(trips[0].u64("tripped_ms"), Some(100));
        assert_eq!(trips[0].u64("at_ms"), Some(150));
    }

    #[test]
    fn a_trip_already_latched_logs_nothing_again() {
        let mut before = snapshot();
        before.truth.reactor.trip = Some(Trip {
            cause: TripCause::Manual,
            at_ms: 0,
        });
        before.truth.secondary.turbine_tripped = true;
        let after = before.clone();

        let log = Log::default();
        changes(&log, &before, &after);
        assert!(log.of("trip").is_empty());
    }

    #[test]
    fn the_first_action_after_a_fault_start_logs_once() {
        let before = snapshot();
        let mut first = before.clone();
        first.at_ms = 2_000;
        first.first_action_after_fault_ms = Some(2_000);

        let log = Log::default();
        changes(&log, &before, &first);
        let again = {
            let mut later = first.clone();
            later.at_ms = 2_500;
            later
        };
        changes(&log, &first, &again);

        let firsts = log.of("first_action");
        assert_eq!(firsts.len(), 1);
        assert_eq!(firsts[0].u64("first_action_after_fault_ms"), Some(2_000));
        assert_eq!(firsts[0].u64("at_ms"), Some(2_000));
    }

    #[test]
    fn time_keeps_minutes_seconds_and_tenths() {
        assert_eq!(time(0), "0:00.0");
        assert_eq!(time(123_950), "2:03.9");
        assert_eq!(time(3_599_900), "59:59.9");
        assert_eq!(time(3_600_000), "1:00:00.0");
    }

    #[test]
    fn divergence_lines_keep_the_sensor_values_and_phase() {
        let snap = snapshot();
        let log = Log::default();
        let true_value = snap.truth.primary.loops[0].hot_leg_c;
        divergence(
            &log,
            Sensor::HotLeg(Loop::A),
            true_value,
            300.0,
            123_950,
            "peak",
        );
        let lines = log.of("divergence");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].str("point"), Some("hot_leg_a"));
        assert_eq!(lines[0].get("reported_value"), Some(&float(300.0)));
        assert_eq!(lines[0].get("true_value"), Some(&float(true_value)));
        assert_eq!(lines[0].str("phase"), Some("peak"));
        assert_eq!(lines[0].str("time"), Some("2:03.9"));
        assert_eq!(lines[0].u64("at_ms"), Some(123_950));
    }

    #[test]
    fn an_action_carries_its_source_and_counters() {
        let mut after = snapshot();
        after.at_ms = 450;
        after.operator_actions = 3;
        after.revision = 2;

        let log = Log::default();
        action(&log, Command::ManualTrip, Source::Modbus, &after);
        let actions = log.of("action");
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].str("command"), Some("manual_trip"));
        assert_eq!(actions[0].str("source"), Some("modbus"));
        assert_eq!(actions[0].u64("operator_actions"), Some(3));
        assert_eq!(actions[0].u64("revision"), Some(2));
        assert_eq!(actions[0].u64("at_ms"), Some(450));
    }

    #[test]
    fn new_equipment_actions_and_faults_keep_their_wire_names() {
        let snap = snapshot();
        for (command, name) in [
            (Command::Relief { open: true }, "relief"),
            (Command::ReliefBlock { closed: true }, "relief_block"),
            (Command::SteamIsolation { closed: true }, "steam_isolation"),
            (
                Command::Pump {
                    pump: Pump::SafetyInjection,
                    running: true,
                },
                "pump",
            ),
        ] {
            let log = Log::default();
            action(&log, command, Source::Panel, &snap);
            let actions = log.of("action");
            assert_eq!(actions.len(), 1);
            assert_eq!(actions[0].str("command"), Some(name));
            if matches!(command, Command::Pump { .. }) {
                assert_eq!(actions[0].str("pump"), Some("safety_injection"));
            }
        }
        for (process, name) in [
            (ProcessFault::ReliefStuckOpen, "relief_stuck_open"),
            (
                ProcessFault::SafetyInjectionFailure,
                "safety_injection_failure",
            ),
            (ProcessFault::SteamLineBreak, "steam_line_break"),
            (ProcessFault::StationBlackout, "station_blackout"),
        ] {
            let log = Log::default();
            fault(&log, FaultChange::Inject(Fault::Process(process)), &snap);
            fault(
                &log,
                FaultChange::Clear(FaultTarget::Process(process)),
                &snap,
            );
            let faults = log.of("fault");
            assert_eq!(faults.len(), 2);
            for event in faults {
                assert_eq!(event.str("target"), Some(name));
            }
        }
    }

    #[test]
    fn a_rejection_is_a_notice_with_its_snake_case_reason() {
        let log = Log::default();
        rejected(
            &log,
            Command::ResetTrip,
            Source::Hmi,
            Rejection::TripConditionPresent,
            0,
        );
        let refused = log.of("rejected");
        assert_eq!(refused.len(), 1);
        assert_eq!(refused[0].str("reason"), Some("trip_condition_present"));
        assert_eq!(refused[0].level, Level::Notice);
    }

    #[test]
    fn held_facts_are_discarded_unless_released() {
        let log = Log::default();
        {
            let held = Held::new(&log);
            held.record("action", |event| event.field("at_ms", 1u64));
        }
        assert!(log.0.borrow().is_empty(), "a dropped hold delivers nothing");

        let held = Held::new(&log);
        held.record("action", |event| event.field("at_ms", 2u64));
        held.record("rejected", |event| event.field("at_ms", 3u64));
        held.release();
        let kinds: Vec<&str> = log.0.borrow().iter().map(|event| event.kind).collect();
        assert_eq!(kinds, ["action", "rejected"]);
    }
}
