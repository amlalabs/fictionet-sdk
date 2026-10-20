//! Plant facts for the Fictionet event log.
//!
//! Every fact is an event from source `plant`. Each fact has a fixed short
//! list of fields, at most five, and every fact carries `at_ms`: the plant
//! time of the snapshot it was read from. Facts go to a [`Sink`]: a world's
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
//! | `divergence` | a faulted instrument's true and reported values | [`divergence`] |
//!
//! Limits: a write's facts are held by [`Held`] until the whole write is
//! accepted. A refused write therefore logs only its rejection. A divergence
//! sample has one line per active sensor fault, at most 21 lines, and at most
//! one sample per [`advance`](crate::driver::Driver::advance_to) call. A
//! sample is due when the plant time crosses a multiple of [`DIVERGENCE_MS`].
//! The true value is the snapshot's truth at the snapshot's rounding (0.1 or
//! 0.01), not the plant's unrounded value. A reactor trip carries `tripped_ms`,
//! the plant step that latched it. `at_ms` is when the change was seen: the
//! command, or the end of the advance, that caused it.

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr};

use fictionet::Cx;
use fictionet::events::{ConnInfo, Event, Level, float};
use fictionet::stdlib::services::serve;

use crate::command::{Command, Loop, Rejection};
use crate::faults::{Fault, FaultChange, FaultTarget, ProcessFault};
use crate::protection::TripCause;
use crate::sensors::Sensor;
use crate::snapshot::{PlantSnapshot, Truth};

/// The source name of every plant fact.
const SOURCE: &str = "plant";

/// Plant time between divergence samples, in ms.
pub const DIVERGENCE_MS: u64 = 1_000;

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
        event
            .summary(format!("{name} from {}", source.as_str()))
            .field("command", name)
            .field("source", source.as_str())
            .field("operator_actions", after.operator_actions)
            .field("revision", after.revision)
            .field("at_ms", after.at_ms)
    });
}

/// A refused operator command and the reason the plant gave.
pub fn rejected(sink: &impl Sink, command: Command, source: Source, reason: Rejection, at_ms: u64) {
    sink.record("rejected", |event| {
        let name = command_name(command);
        let reason = rejection_name(reason);
        event
            .level(Level::Notice)
            .summary(format!("{name} from {} refused: {reason}", source.as_str()))
            .field("command", name)
            .field("source", source.as_str())
            .field("reason", reason)
            .field("at_ms", at_ms)
    });
}

/// A fault that started or cleared, with the plant as it stands after it.
pub fn fault(sink: &impl Sink, change: FaultChange, after: &PlantSnapshot) {
    sink.record("fault", |event| {
        let (kind, target) = change_parts(change);
        let summary = match &target {
            Some(target) => format!("fault {kind}: {target}"),
            None => format!("fault {kind}"),
        };
        let event = event
            .summary(summary)
            .field("change", kind)
            .field("at_ms", after.at_ms);
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
/// after a fault start. Each fires once per change.
pub fn changes(sink: &impl Sink, before: &PlantSnapshot, after: &PlantSnapshot) {
    let new_reactor_trip = match (before.truth.reactor.trip, after.truth.reactor.trip) {
        (None, Some(trip)) => Some(trip),
        _ => None,
    };
    if let Some(trip) = new_reactor_trip {
        sink.record("trip", |event| {
            let cause = cause_name(trip.cause);
            event
                .level(Level::Notice)
                .summary(format!("reactor trip: {cause}"))
                .field("cause", cause)
                .field("tripped_ms", trip.at_ms)
                .field("at_ms", after.at_ms)
        });
    } else if !before.truth.secondary.turbine_tripped && after.truth.secondary.turbine_tripped {
        // A reactor trip also trips the turbine, so only a turbine trip without
        // a reactor trip logs here.
        sink.record("trip", |event| {
            event
                .level(Level::Notice)
                .summary("turbine trip")
                .field("cause", "turbine_trip")
                .field("at_ms", after.at_ms)
        });
    }
    if before.first_action_after_fault_ms.is_none()
        && let Some(delay) = after.first_action_after_fault_ms
    {
        sink.record("first_action", |event| {
            event
                .summary(format!("first command {delay} ms after a fault start"))
                .field("first_action_after_fault_ms", delay)
                .field("at_ms", after.at_ms)
        });
    }
}

/// Whether a divergence sample falls between two plant times: the plant time
/// crosses a multiple of [`DIVERGENCE_MS`].
pub fn divergence_due(before_ms: u64, after_ms: u64) -> bool {
    before_ms / DIVERGENCE_MS != after_ms / DIVERGENCE_MS
}

/// One divergence line for each sensor fault that is active in `after`. The
/// reported value is the channel's reading; the true value is the plant's
/// truth for the same sensor.
pub fn divergence(sink: &impl Sink, after: &PlantSnapshot) {
    for channel in after
        .readings
        .iter()
        .filter(|channel| channel.fault.is_some())
    {
        sink.record("divergence", |event| {
            let point = point_name(channel.sensor);
            let true_value = true_value_of(&after.truth, channel.sensor);
            let reported = channel.reading.value;
            event
                .summary(format!(
                    "{point} reads {reported:.1} against true {true_value:.1}"
                ))
                .field("point", point)
                .field("true_value", float(true_value))
                .field("reported_value", float(reported))
                .field("at_ms", after.at_ms)
        });
    }
}

fn command_name(command: Command) -> &'static str {
    match command {
        Command::RodDemand { .. } => "rod_demand",
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
    }
}

/// The instrument's point name, with its loop suffix when it has one.
fn point_name(sensor: Sensor) -> String {
    match sensor {
        Sensor::NeutronPower => "neutron_power".into(),
        Sensor::RodPosition => "rod_position".into(),
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
fn true_value_of(truth: &Truth, sensor: Sensor) -> f64 {
    let reactor = &truth.reactor;
    let primary = &truth.primary;
    let secondary = &truth.secondary;
    match sensor {
        Sensor::NeutronPower => reactor.neutron_power_percent,
        Sensor::RodPosition => reactor.control_rod_percent,
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
    fn divergence_is_due_when_a_sample_boundary_is_crossed() {
        assert!(divergence_due(950, 1_000));
        assert!(divergence_due(999, 2_000));
        assert!(!divergence_due(0, 50));
        assert!(!divergence_due(1_000, 1_950));
    }

    #[test]
    fn divergence_lines_follow_the_active_sensor_faults() {
        let mut snap = snapshot();
        let log = Log::default();
        divergence(&log, &snap);
        assert!(log.of("divergence").is_empty(), "no fault, no line");

        // The plant puts the same fault in the fault table and in its channel.
        let stuck = crate::faults::SensorFault::Stuck { value: 3000 };
        let channel = Sensor::HotLeg(Loop::A).index();
        snap.faults.sensors[channel] = Some(stuck);
        snap.readings[channel].fault = Some(stuck);
        snap.readings[channel].reading.value = 300.0;
        divergence(&log, &snap);
        let lines = log.of("divergence");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].str("point"), Some("hot_leg_a"));
        assert_eq!(lines[0].get("reported_value"), Some(&float(300.0)));
        assert_eq!(
            lines[0].get("true_value"),
            Some(&float(snap.truth.primary.loops[0].hot_leg_c))
        );
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
