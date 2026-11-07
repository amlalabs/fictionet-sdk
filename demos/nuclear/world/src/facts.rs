//! Typed plant facts delivered to the world's observation callback.
//!
//! Each fact has a typed payload owned by this world. Each fact has a fixed short
//! list of fields, and every fact carries `at_ms`: the plant
//! time of the change. Stage and end facts use their logged first time. Facts go to a [`Sink`]: a world's
//! observation callback, shared with each Modbus controller. A sink builds a fact only
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

use fictionet::stdlib::services::serve::ConnInfo;
use serde::Serialize;
use std::sync::Arc;

use crate::command::{Command, Controller, Loop, Mode, Pump, Rejection, Valve};
use crate::faults::{Fault, FaultChange, FaultTarget, ProcessFault};
use crate::protection::TripCause;
use crate::scenarios::Scenario;
use crate::sensors::{Sensor, Unit};
use crate::snapshot::PlantSnapshot;
use crate::stages::{FailureCause, Stage};

/// Presentation severity of a plant fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Info,
    Notice,
    Alarm,
}

/// A plant observation owned by this world.
#[derive(Clone, Debug, Serialize)]
pub struct Fact {
    pub at_ms: u64,
    pub time: String,
    pub summary: String,
    pub level: Level,
    #[serde(flatten)]
    pub detail: Detail,
}

/// The fields of each kind of plant change.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Detail {
    Action {
        command: &'static str,
        source: &'static str,
        operator_actions: u64,
        revision: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        pump: Option<&'static str>,
    },
    Rejected {
        command: &'static str,
        source: &'static str,
        reason: &'static str,
    },
    Fault {
        change: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        target: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        last_fault_start_ms: Option<u64>,
    },
    Stage {
        stage: String,
        operator_actions: u64,
        last_command: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        last_command_ms: Option<u64>,
    },
    End {
        stage: String,
        operator_actions: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        cause: Option<String>,
    },
    Trip {
        cause: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        tripped_ms: Option<u64>,
    },
    FirstAction {
        first_action_after_fault_ms: u64,
    },
    Reset {
        scenario: String,
        speed: u16,
    },
    Divergence {
        point: String,
        true_value: f64,
        reported_value: f64,
        phase: &'static str,
    },
}

impl Fact {
    fn new(at_ms: u64, level: Level, summary: impl Into<String>, detail: Detail) -> Self {
        Self {
            at_ms,
            time: time(at_ms),
            summary: summary.into(),
            level,
            detail,
        }
    }
    /// The kind of change, for filtering a world's observation page.
    pub fn kind(&self) -> &'static str {
        match self.detail {
            Detail::Action { .. } => "action",
            Detail::Rejected { .. } => "rejected",
            Detail::Fault { .. } => "fault",
            Detail::Stage { .. } => "stage",
            Detail::End { .. } => "end",
            Detail::Trip { .. } => "trip",
            Detail::FirstAction { .. } => "first_action",
            Detail::Reset { .. } => "reset",
            Detail::Divergence { .. } => "divergence",
        }
    }
}

/// An optional observation callback, shared by a world's clock and services.
#[derive(Clone, Default)]
pub struct Observer(Option<Arc<dyn Fn(Fact) + Send + Sync>>);
impl Observer {
    pub fn new(receive: impl Fn(Fact) + Send + Sync + 'static) -> Self {
        Self(Some(Arc::new(receive)))
    }
}

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
pub const HMI_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 41, 0, 20);

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

/// Where plant facts go. An uninterested sink never builds a fact.
pub trait Sink {
    fn wants(&self, kind: &'static str) -> bool;
    fn record(&self, kind: &'static str, build: impl FnOnce() -> Fact);
}
impl Sink for Observer {
    fn wants(&self, _: &'static str) -> bool {
        self.0.is_some()
    }
    fn record(&self, _: &'static str, build: impl FnOnce() -> Fact) {
        if let Some(receive) = &self.0 {
            receive(build());
        }
    }
}
impl Sink for () {
    fn wants(&self, _: &'static str) -> bool {
        false
    }
    fn record(&self, _: &'static str, _: impl FnOnce() -> Fact) {}
}

/// Facts held until a whole change is accepted. Dropping them discards them.
pub struct Held<'a, S> {
    sink: &'a S,
    events: RefCell<Vec<Fact>>,
}
impl<'a, S: Sink> Held<'a, S> {
    pub fn new(sink: &'a S) -> Self {
        Self {
            sink,
            events: RefCell::new(Vec::new()),
        }
    }
    pub fn release(self) {
        for event in self.events.into_inner() {
            self.sink.record(event.kind(), move || event);
        }
    }
}
impl<S: Sink> Sink for Held<'_, S> {
    fn wants(&self, kind: &'static str) -> bool {
        self.sink.wants(kind)
    }
    fn record(&self, kind: &'static str, build: impl FnOnce() -> Fact) {
        if self.wants(kind) {
            self.events.borrow_mut().push(build());
        }
    }
}

/// An accepted operator command after the change.
pub fn action(sink: &impl Sink, command: Command, source: Source, after: &PlantSnapshot) {
    sink.record("action", || {
        Fact::new(
            after.at_ms,
            Level::Info,
            format!("{} from {}", command_words(command), source_words(source)),
            Detail::Action {
                command: command_name(command),
                source: source.as_str(),
                operator_actions: after.operator_actions,
                revision: after.revision,
                pump: matches!(
                    command,
                    Command::Pump {
                        pump: Pump::SafetyInjection,
                        ..
                    }
                )
                .then_some("safety_injection"),
            },
        )
    });
}

/// A refused command and its reason.
pub fn rejected(sink: &impl Sink, command: Command, source: Source, reason: Rejection, at_ms: u64) {
    sink.record("rejected", || {
        let reason = rejection_name(reason);
        Fact::new(
            at_ms,
            Level::Notice,
            format!(
                "{} from {} refused: {}",
                command_words(command),
                source_words(source),
                words(reason)
            ),
            Detail::Rejected {
                command: command_name(command),
                source: source.as_str(),
                reason,
            },
        )
    });
}

/// A fault that started or cleared.
pub fn fault(sink: &impl Sink, change: FaultChange, after: &PlantSnapshot) {
    sink.record("fault", || {
        let (change, target) = change_parts(change);
        let summary = target.as_ref().map_or_else(
            || "All faults cleared".into(),
            |target| {
                format!(
                    "{} {}",
                    sentence(target),
                    if change == "inject" {
                        "injected"
                    } else {
                        "cleared"
                    }
                )
            },
        );
        Fact::new(
            after.at_ms,
            Level::Info,
            summary,
            Detail::Fault {
                change,
                target,
                last_fault_start_ms: after.last_fault_start_ms,
            },
        )
    });
}

/// Report newly reached stages in time order, then an end, trip and first action.
pub fn changes(sink: &impl Sink, before: &PlantSnapshot, after: &PlantSnapshot) {
    if sink.wants("stage") {
        let mut stages = Stage::ALL
            .into_iter()
            .filter_map(|stage| {
                after.stages[stage.index()]
                    .filter(|_| before.stages[stage.index()].is_none())
                    .map(|at| (stage, at))
            })
            .collect::<Vec<_>>();
        stages.sort_by_key(|(stage, at)| (*at, stage.index()));
        for (stage, at_ms) in stages {
            sink.record("stage", || {
                let name = wire_name(stage);
                Fact::new(
                    at_ms,
                    if matches!(stage, Stage::Boiling | Stage::TurbineHallSteam) {
                        Level::Notice
                    } else {
                        Level::Alarm
                    },
                    sentence(&name),
                    Detail::Stage {
                        stage: name,
                        operator_actions: after.operator_actions,
                        last_command: after
                            .last_command
                            .map_or("none", |last| command_name(last.command)),
                        last_command_ms: after.last_command.map(|last| last.at_ms),
                    },
                )
            });
        }
    }
    if before.end.is_none()
        && let Some(end) = after.end
    {
        sink.record("end", || {
            let name = wire_name(end.stage);
            let cause = (end.stage == Stage::ContainmentFailure)
                .then_some(after.severe.containment.failure)
                .flatten();
            let suffix = match cause {
                Some(FailureCause::HydrogenBurn) => " from a hydrogen burn",
                Some(FailureCause::Overpressure) => " from overpressure",
                None => "",
            };
            Fact::new(
                end.at_ms,
                Level::Alarm,
                format!("End: {}{suffix}", words(&name)),
                Detail::End {
                    stage: name,
                    operator_actions: after.operator_actions,
                    cause: cause.map(wire_name),
                },
            )
        });
    }
    if before.truth.reactor.trip.is_none()
        && let Some(trip) = after.truth.reactor.trip
    {
        sink.record("trip", || {
            let cause = cause_name(trip.cause);
            Fact::new(
                after.at_ms,
                Level::Notice,
                format!("Reactor trip: {}", words(&cause)),
                Detail::Trip {
                    cause,
                    tripped_ms: Some(trip.at_ms),
                },
            )
        });
    } else if !before.truth.secondary.turbine_tripped && after.truth.secondary.turbine_tripped {
        sink.record("trip", || {
            Fact::new(
                after.at_ms,
                Level::Notice,
                "Turbine trip",
                Detail::Trip {
                    cause: "turbine_trip".into(),
                    tripped_ms: None,
                },
            )
        });
    }
    if before.first_action_after_fault_ms.is_none()
        && let Some(delay) = after.first_action_after_fault_ms
    {
        sink.record("first_action", || {
            Fact::new(
                after.at_ms,
                Level::Info,
                format!(
                    "First command {:.1} s after a fault started",
                    delay as f64 / 1_000.0
                ),
                Detail::FirstAction {
                    first_action_after_fault_ms: delay,
                },
            )
        });
    }
}

/// A scenario starts at plant time zero.
pub fn reset(sink: &impl Sink, scenario: Scenario, speed: u16) {
    sink.record("reset", || {
        Fact::new(
            0,
            Level::Notice,
            format!("Started {}", words(&wire_name(scenario))),
            Detail::Reset {
                scenario: wire_name(scenario),
                speed,
            },
        )
    });
}
fn wire_name(value: impl Serialize) -> String {
    serde_json::to_value(value)
        .expect("wire name serializes")
        .as_str()
        .expect("wire name is text")
        .to_owned()
}

/// One sensor's true and reported values at a fault's start, peak or clear.
pub fn divergence(
    sink: &impl Sink,
    sensor: Sensor,
    true_value: f64,
    reported: f64,
    at_ms: u64,
    phase: &'static str,
) {
    sink.record("divergence", || {
        let point = point_name(sensor);
        let unit = match sensor.spec().unit {
            Unit::Celsius => "°C",
            Unit::Megapascal => "MPa",
            Unit::Kilopascal => "kPa",
            Unit::KilogramsPerSecond => "kg/s",
            Unit::Megawatt => "MW",
            Unit::Percent => "%",
            Unit::SievertsPerHour => "Sv/h",
        };
        Fact::new(
            at_ms,
            Level::Info,
            format!(
                "{} gauge {reported:.1} {unit}, plant {true_value:.1} {unit}",
                sentence(&point)
            ),
            Detail::Divergence {
                point,
                true_value,
                reported_value: reported,
                phase,
            },
        )
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
        Sensor::CoreExitWideRange => "core_exit_wide_range".into(),
        Sensor::VesselLevel => "vessel_level".into(),
        Sensor::ContainmentPressure => "containment_pressure".into(),
        Sensor::ContainmentTemperature => "containment_temperature".into(),
        Sensor::ContainmentHydrogen => "containment_hydrogen".into(),
        Sensor::ContainmentRadiation => "containment_radiation".into(),
        Sensor::ReliefTailpipeTemperature => "relief_tailpipe_temperature".into(),
        Sensor::ReliefTankPressure => "relief_tank_pressure".into(),
        Sensor::SafetyInjectionFlow => "safety_injection_flow".into(),
        Sensor::TurbineBuildingTemperature => "turbine_building_temperature".into(),
    }
}

fn loop_name(l: Loop) -> &'static str {
    match l {
        Loop::A => "a",
        Loop::B => "b",
    }
}

/// The true value of a sensor's point, read from the snapshot. This matches
/// the plant's own sensor source.
pub(crate) fn true_value_of(snapshot: &PlantSnapshot, sensor: Sensor) -> f64 {
    let truth = &snapshot.truth;
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
        Sensor::CoreExitTemperature => snapshot.severe.core_exit_steam_c,
        Sensor::CoreExitWideRange => snapshot.severe.core_exit_steam_c,
        Sensor::VesselLevel => snapshot.severe.vessel_level_percent,
        Sensor::ContainmentPressure => snapshot.severe.containment.pressure_kpa,
        Sensor::ContainmentTemperature => snapshot.severe.containment.temperature_c,
        Sensor::ContainmentHydrogen => snapshot.severe.containment.hydrogen_percent,
        Sensor::ContainmentRadiation => snapshot.stylized.containment_dose_sv_h,
        Sensor::ReliefTailpipeTemperature => snapshot.severe.relief.tailpipe_c,
        Sensor::ReliefTankPressure => snapshot.severe.relief_tank.pressure_kpa,
        Sensor::SafetyInjectionFlow => snapshot.severe.safety_injection.flow_kg_s,
        Sensor::TurbineBuildingTemperature => snapshot.severe.turbine_hall.temperature_c,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::protection::Trip;
    use crate::{Config, Plant};

    pub(crate) type Memory = fictionet::sync::Mutex<Vec<Fact>>;
    pub(crate) fn observer(memory: &Arc<Memory>) -> Observer {
        let memory = memory.clone();
        Observer::new(move |fact| memory.lock().push(fact))
    }
    pub(crate) fn observations(memory: &Memory, kind: &str) -> Vec<serde_json::Value> {
        memory
            .lock()
            .iter()
            .filter(|fact| fact.kind() == kind)
            .map(|fact| serde_json::to_value(fact).unwrap())
            .collect()
    }

    /// A sink that keeps every fact it is given, in order.
    #[derive(Default)]
    struct Log(RefCell<Vec<serde_json::Value>>);

    impl Sink for Log {
        fn wants(&self, _kind: &'static str) -> bool {
            true
        }

        fn record(&self, _kind: &'static str, build: impl FnOnce() -> Fact) {
            self.0
                .borrow_mut()
                .push(serde_json::to_value(build()).unwrap());
        }
    }

    impl Log {
        fn of(&self, kind: &str) -> Vec<serde_json::Value> {
            self.0
                .borrow()
                .iter()
                .filter(|event| event["kind"] == kind)
                .cloned()
                .collect()
        }
    }

    fn snapshot() -> PlantSnapshot {
        Plant::new(Config::default()).snapshot()
    }

    #[test]
    fn core_exit_truth_is_the_steam_the_thermocouples_sit_in() {
        let mut snap = snapshot();
        snap.severe.core_exit_steam_c = 1_200.0;
        assert_ne!(snap.truth.reactor.core_exit_c, 1_200.0);
        assert_eq!(true_value_of(&snap, Sensor::CoreExitTemperature), 1_200.0);
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
            assert_eq!(event["kind"], "stage");
            assert_eq!(event["stage"].as_str(), Some(wire_name(stage).as_str()));
            assert_eq!(
                event["level"],
                if matches!(stage, Stage::Boiling | Stage::TurbineHallSteam) {
                    serde_json::json!(Level::Notice)
                } else {
                    serde_json::json!(Level::Alarm)
                }
            );
        }
        let end = events.last().unwrap();
        assert_eq!(end["kind"], "end");
        assert_eq!(end["level"], serde_json::json!(Level::Alarm));
        assert_eq!(end["at_ms"].as_u64(), Some(100));
        assert!(end.get("cause").is_none());
    }

    #[test]
    fn reset_names_the_scenario_speed_and_zero_time() {
        let log = Log::default();
        reset(&log, Scenario::StuckOpenRelief, 600);
        let events = log.of("reset");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["level"], serde_json::json!(Level::Notice));
        assert_eq!(events[0]["scenario"].as_str(), Some("stuck_open_relief"));
        assert_eq!(events[0]["speed"].as_u64(), Some(600));
        assert_eq!(events[0]["at_ms"].as_u64(), Some(0));
        assert_eq!(events[0]["time"].as_str(), Some("0:00.0"));
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
        assert_eq!(source_of(&peer(&HMI_ADDRESS.to_string())), Source::Hmi);
        assert_eq!(source_of(&peer("10.40.0.30")), Source::Modbus);
        assert_eq!(source_of(&ConnInfo::default()), Source::Modbus);

        let sandboxed = ConnInfo {
            sandbox: Some(fictionet::stdlib::services::serve::Sandbox {
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
        assert_eq!(trips[0]["cause"].as_str(), Some("turbine_trip"));
        assert_eq!(trips[0]["at_ms"].as_u64(), Some(3_000));
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
        assert_eq!(trips[0]["cause"].as_str(), Some("turbine_trip"));
        assert_eq!(trips[0]["tripped_ms"].as_u64(), Some(100));
        assert_eq!(trips[0]["at_ms"].as_u64(), Some(150));
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
        assert_eq!(
            firsts[0]["first_action_after_fault_ms"].as_u64(),
            Some(2_000)
        );
        assert_eq!(firsts[0]["at_ms"].as_u64(), Some(2_000));
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
        assert_eq!(lines[0]["point"].as_str(), Some("hot_leg_a"));
        assert_eq!(
            lines[0].get("reported_value"),
            Some(&serde_json::json!(300.0))
        );
        assert_eq!(
            lines[0].get("true_value"),
            Some(&serde_json::json!(true_value))
        );
        assert_eq!(lines[0]["phase"].as_str(), Some("peak"));
        assert_eq!(lines[0]["time"].as_str(), Some("2:03.9"));
        assert_eq!(lines[0]["at_ms"].as_u64(), Some(123_950));
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
        assert_eq!(actions[0]["command"].as_str(), Some("manual_trip"));
        assert_eq!(actions[0]["source"].as_str(), Some("modbus"));
        assert_eq!(actions[0]["operator_actions"].as_u64(), Some(3));
        assert_eq!(actions[0]["revision"].as_u64(), Some(2));
        assert_eq!(actions[0]["at_ms"].as_u64(), Some(450));
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
            assert_eq!(actions[0]["command"].as_str(), Some(name));
            if matches!(command, Command::Pump { .. }) {
                assert_eq!(actions[0]["pump"].as_str(), Some("safety_injection"));
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
                assert_eq!(event["target"].as_str(), Some(name));
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
        assert_eq!(
            refused[0]["reason"].as_str(),
            Some("trip_condition_present")
        );
        assert_eq!(refused[0]["level"], serde_json::json!(Level::Notice));
    }

    #[test]
    fn held_facts_are_discarded_unless_released() {
        let log = Log::default();
        {
            let held = Held::new(&log);
            action(&held, Command::ManualTrip, Source::Panel, &snapshot());
        }
        assert!(log.0.borrow().is_empty(), "a dropped hold delivers nothing");

        let held = Held::new(&log);
        action(&held, Command::ManualTrip, Source::Panel, &snapshot());
        rejected(
            &held,
            Command::ManualTrip,
            Source::Panel,
            Rejection::TripConditionPresent,
            snapshot().at_ms,
        );
        held.release();
        let kinds: Vec<String> = log
            .0
            .borrow()
            .iter()
            .map(|event| event["kind"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(kinds, ["action", "rejected"]);
    }
}
