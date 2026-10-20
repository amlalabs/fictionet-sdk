//! The scripted operator story: six steps with automatic protection off.
//!
//! The operator works through the HMI. Its commands reach the controllers over
//! Modbus, so each one is logged with source `hmi`. Faults are injected on the
//! driver. The operator reads only hmi01's HTTP view. The checks read plant
//! truth to verify each step. A step that does not happen fails the run.
//!
//! The steps, in plant time:
//!
//! 1. Full power. Power and average temperature hold.
//! 2. A normal maneuver. The operator lowers rod demand through the HMI, and
//!    the power settles lower.
//! 3. The fault. The loop B hot-leg gauge sticks at its present count, and
//!    coolant pump B trips at the same moment.
//! 4. The operator trusts the screen and does nothing about loop B. Core exit
//!    temperature rises and the subcooling margin shrinks until its alarm
//!    fires. The stuck gauge still reads normal.
//! 5. The operator reads the physics. Before the plant saturates, the operator
//!    trips the reactor from the HMI, starts auxiliary feed, and clears the
//!    fault. The plant settles onto decay heat.
//! 6. A second fault. Telemetry goes quiet, so the readings stop while the
//!    plant keeps moving. The operator clears it, and the readings resume.
//!
//! [`start_network`] builds the operations network with hmi01 and the operator's
//! console. [`clock`] moves the plant with the run clock, and it is the only
//! place the plant advances in the viewer.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use fictionet::stdlib::network::route::Prefix;
use fictionet::stdlib::protocols::http1::{self, Header, RequestHead, Version};
use fictionet::stdlib::world::sandbox::{self, Machine};
use fictionet::{Cx, Error};
use serde::Serialize;
use serde_json::{Value, json};

use crate::command::{FaultCommand, Loop};
use crate::driver::Driver;
use crate::faults::{Fault, FaultChange, FaultTarget, ProcessFault, SensorFault};
use crate::hmi;
use crate::protection::{Alarm, AlarmState};
use crate::sensors::Sensor;
use crate::snapshot::PlantSnapshot;
use crate::steam;

/// The operator's address on the operations network. It is a trusted route,
/// like hmi01, so the operator console can reach hmi01.
pub const OPERATOR: Ipv4Addr = Ipv4Addr::new(10, 40, 0, 50);

const OPERATOR_NAME: &str = "operator";

/// Plant time between plant clock ticks.
const TICK: Duration = Duration::from_millis(50);

/// Plant time between the story's looks at the plant.
const POLL: Duration = Duration::from_millis(250);

/// Plant time between published snapshots.
pub const PUBLISH_MS: u64 = 100;

/// Plant time the full power check waits for.
const FULL_POWER_CHECK_MS: u64 = 10_000;

/// Rod demand the operator takes out in step 2, in percent.
const ROD_STEP_PERCENT: f64 = 3.0;

/// Plant time after the maneuver before the story checks that power settled.
/// Power falls over tens of seconds, so the check waits for the tail to flatten.
const MANEUVER_SETTLE_MS: u64 = 90_000;

/// Window over which the story checks the settled power.
const SETTLE_WINDOW_MS: u64 = 10_000;

/// Largest change in power over the settle window that counts as settled, in percent.
const SETTLED_POWER_BAND: f64 = 0.2;

/// Smallest fall in power the maneuver must make, in percent of full power.
const MANEUVER_MIN_DROP_PERCENT: f64 = 0.5;

/// Longest time the story waits for the subcooling alarm, after the fault.
const ALARM_LIMIT_MS: u64 = 240_000;

/// Estimated subcooling margin at which the operator trips, in C. The alarm
/// sounds at 15 C, so this leaves the operator a few degrees to act.
const TRIP_MARGIN_C: f64 = 10.0;

/// Longest time the story waits for the operator's trip condition.
const TRIP_LIMIT_MS: u64 = 240_000;

/// Plant time after the trip before the story checks that the rods have dropped.
const ROD_DROP_MS: u64 = 5_000;

/// Plant time after auxiliary feed starts before the story checks for decay heat.
const DECAY_SETTLE_MS: u64 = 60_000;

/// Power, in percent, below which the plant counts as settled on decay heat.
const DECAY_POWER_LIMIT: f64 = 1.0;

/// Plant time after the quiet fault starts before the HMI is read as the baseline.
/// The HMI polls every 250 ms, so one second covers the last sample before the fault.
const QUIET_BASELINE_MS: u64 = 1_000;

/// Plant time the restored gauge must track within one degree before the next fault.
const GAUGE_TRACKING_MS: u64 = 3_000;

/// Plant time the telemetry stays quiet in step 6.
const QUIET_MS: u64 = 20_000;

/// Plant time after the quiet fault clears before the story checks that readings resume.
const RESUME_MS: u64 = 3_000;

/// One scripted operator line, labeled with plant time and step.
#[derive(Clone, Debug, Serialize)]
pub struct Line {
    pub at_ms: u64,
    pub step: u8,
    pub text: String,
}

/// What the story saw, in plant milliseconds.
#[derive(Clone, Debug, PartialEq)]
pub struct Report {
    /// When the operator lowered rod demand.
    pub maneuver_at_ms: u64,
    /// When the stuck hot-leg gauge and the coolant pump trip began.
    pub fault_at_ms: u64,
    /// When the subcooling margin alarm was seen active.
    pub alarm_at_ms: u64,
    /// When the operator tripped the reactor.
    pub trip_at_ms: u64,
    /// The delay from the fault start to the first accepted command after it.
    pub first_action_after_fault_ms: u64,
    /// When the telemetry quiet fault began.
    pub quiet_from_ms: u64,
    /// When the telemetry quiet fault cleared.
    pub quiet_to_ms: u64,
}

/// Builds the operations network: hmi01 at its fixed address, with the
/// operator's console as a trusted route. Returns the operator's machine. The
/// controllers and hmi01 start on `fcx`, so call this inside the run.
pub fn start_network(fcx: &Cx, driver: &Driver) -> Result<Machine, Error> {
    let (attacher, attachments) = fictionet::attachments();
    let operator_route = Prefix {
        addr: IpAddr::V4(OPERATOR),
        len: 32,
    };
    hmi::with_hmi(driver)
        .route(OPERATOR_NAME, operator_route)
        .start(fcx, attachments)?;
    let hmi_machine = sandbox::machine(fcx, attacher.attach(hmi::NAME)?, hmi::ADDR);
    hmi::start(fcx, hmi_machine, hmi::controllers())?;
    Ok(sandbox::machine(
        fcx,
        attacher.attach(OPERATOR_NAME)?,
        OPERATOR,
    ))
}

/// Moves the plant with the run clock. Each tick advances the driver to the
/// run's elapsed time, so plant time is run time. `publish` sees a snapshot
/// each [`PUBLISH_MS`] of plant time. The task ends without error when the run
/// is cancelled.
pub async fn clock(
    fcx: &Cx,
    driver: &Driver,
    mut publish: impl FnMut(&PlantSnapshot) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut published = None;
    loop {
        driver.advance_to(fcx, plant_ms(fcx));
        let snapshot = driver.snapshot();
        let slot = snapshot.at_ms / PUBLISH_MS;
        if published != Some(slot) {
            publish(&snapshot)?;
            published = Some(slot);
        }
        if fcx.sleep(TICK).await.is_err() {
            return Ok(());
        }
    }
}

/// The plant time of the run clock, in ms.
pub fn plant_ms(fcx: &Cx) -> u64 {
    u64::try_from(fcx.now().since_start().as_millis()).unwrap_or(u64::MAX)
}

/// Runs the six steps against `driver`, through the HMI on `operator`. `say`
/// receives the lines for each step, labeled with the plant time.
pub async fn run(
    fcx: &Cx,
    driver: &Driver,
    operator: &Machine,
    mut say: impl FnMut(Line),
) -> Result<Report, Error> {
    let hot_b = Sensor::HotLeg(Loop::B);
    let start = driver.snapshot();

    // 1. Full power.
    let initial_view = until_hmi(
        fcx,
        operator,
        FULL_POWER_CHECK_MS,
        "the initial HMI readings",
        |view| {
            Ok(["hot_leg_a", "hot_leg_b", "cold_leg_a", "cold_leg_b"]
                .iter()
                .all(|name| view["readings"][name]["value"].as_f64().is_some()))
        },
    )
    .await?;
    let initial_average = average_temperature(&initial_view)?;
    let full = wait_for(fcx, driver, FULL_POWER_CHECK_MS).await?;
    let screen = hmi_view(fcx, operator).await?;
    let power = reading(&screen, "neutron_power")?;
    let average = average_temperature(&screen)?;
    check(
        (power - 100.0).abs() < 1.0,
        format!("HMI power is not in balance: {power:.2} %"),
    )?;
    check(
        (average - initial_average).abs() < 0.5,
        format!("HMI average temperature drifts at full power: {average:.2} C"),
    )?;
    let true_power = full.truth.reactor.neutron_power_percent;
    let true_average = full.truth.primary.average_temperature_c;
    check(
        (true_power - 100.0).abs() < 1.0,
        format!("plant full power is not in balance: {true_power:.2} %"),
    )?;
    check(
        (true_average - start.truth.primary.average_temperature_c).abs() < 0.5,
        format!("plant average temperature drifts at full power: {true_average:.2} C"),
    )?;
    say(line(
        full.at_ms,
        1,
        &format!("full power: {power:.1} % power, {average:.1} C average"),
    ));

    // 2. A normal maneuver through the HMI.
    let demand = reading(&screen, "rod_demand")?;
    let target = demand - ROD_STEP_PERCENT;
    control(fcx, operator, "rod-demand", json!({ "percent": target })).await?;
    let maneuver_at = driver.snapshot().at_ms;
    say(line(
        maneuver_at,
        2,
        &format!("maneuver: rod demand from {demand:.1} % to {target:.1} % through the HMI"),
    ));
    let settled_from = wait_for(fcx, driver, maneuver_at + MANEUVER_SETTLE_MS).await?;
    let before_view = hmi_view(fcx, operator).await?;
    let settled_to = wait_for(fcx, driver, settled_from.at_ms + SETTLE_WINDOW_MS).await?;
    let before = settled_from.truth.reactor.neutron_power_percent;
    let after = settled_to.truth.reactor.neutron_power_percent;
    check(
        100.0 - before >= MANEUVER_MIN_DROP_PERCENT,
        format!("power did not fall after the maneuver: {before:.2} %"),
    )?;
    check(
        (after - before).abs() < SETTLED_POWER_BAND,
        format!("power has not settled: {before:.2} % then {after:.2} % in 10 s"),
    )?;
    let after_view = hmi_view(fcx, operator).await?;
    let shown_before = reading(&before_view, "neutron_power")?;
    let shown_after = reading(&after_view, "neutron_power")?;
    check(
        100.0 - shown_before >= MANEUVER_MIN_DROP_PERCENT,
        "HMI power did not fall after the maneuver",
    )?;
    check(
        (shown_after - shown_before).abs() < SETTLED_POWER_BAND,
        "HMI power has not settled",
    )?;
    say(line(
        settled_to.at_ms,
        2,
        &format!("power settled at {shown_after:.1} %"),
    ));

    // 3. The fault: the hot-leg gauge sticks at its present count, and coolant
    // pump B trips at the same moment.
    let now = driver.snapshot();
    let resolution = hot_b.spec().resolution;
    let stuck_count = (now.readings[hot_b.index()].reading.value / resolution).round() as i16;
    let stuck_c = f64::from(stuck_count) * resolution;
    inject(
        fcx,
        driver,
        FaultChange::Inject(Fault::Sensor {
            sensor: hot_b,
            kind: SensorFault::Stuck { value: stuck_count },
        }),
    )?;
    inject(
        fcx,
        driver,
        FaultChange::Inject(Fault::Process(ProcessFault::CoolantPumpTrip {
            pump: Loop::B,
        })),
    )?;
    let fault_at = driver.snapshot().at_ms;
    let fault_view = hmi_view(fcx, operator).await?;
    let fault_heartbeat = heartbeats(&fault_view)?[1];
    say(line(
        fault_at,
        3,
        &format!("fault: loop B hot-leg gauge sticks at {stuck_c:.1} C, and coolant pump B trips"),
    ));

    // 4. The operator does nothing about loop B. The margin alarm comes from
    // the core exit channel, which still reads true.
    let alarm_view = until_hmi(
        fcx,
        operator,
        fault_at + ALARM_LIMIT_MS,
        "the subcooling margin alarm",
        |view| {
            if heartbeats(view)?[1].wrapping_sub(fault_heartbeat) < 2 {
                return Ok(false);
            }
            check(
                (reading(view, "hot_leg_b")? / resolution).round() as i16 == stuck_count,
                "the HMI hot-leg gauge is not holding its stuck value",
            )?;
            check(
                !hmi_alarm(view, "hot_leg_high")?,
                "the HMI hot-leg alarm fired from the stuck gauge",
            )?;
            hmi_alarm(view, "subcooling_margin_low")
        },
    )
    .await?;
    let alarmed = driver.snapshot();
    check(
        alarm_active(&alarmed, Alarm::SubcoolingMarginLow),
        "the plant subcooling margin alarm is not active",
    )?;
    let gauge = &alarmed.readings[hot_b.index()];
    check(
        gauge.fault == Some(SensorFault::Stuck { value: stuck_count })
            && (gauge.reading.value / resolution).round() as i16 == stuck_count,
        "the hot-leg gauge is not holding its stuck value",
    )?;
    check(
        !alarm_active(&alarmed, Alarm::HotLegTemperatureHigh(Loop::B)),
        "the hot-leg alarm fired from the stuck gauge",
    )?;
    let true_hot_b = alarmed.truth.primary.loops[Loop::B.index()].hot_leg_c;
    check(
        true_hot_b > stuck_c + 1.0,
        format!("loop B did not heat: true hot leg {true_hot_b:.1} C against {stuck_c:.1} C"),
    )?;
    let core_exit = reading(&alarm_view, "core_exit_temperature")?;
    say(line(
        alarmed.at_ms,
        4,
        &format!(
            "subcooling margin alarm: core exit reads {core_exit:.1} C, while the loop B gauge still reads {stuck_c:.1} C against {true_hot_b:.1} C"
        ),
    ));

    // 5. The operator reads the physics: the estimated margin, from the reported
    // pressure and core exit temperature. Trip before saturation.
    let trip_view = until_hmi(
        fcx,
        operator,
        alarmed.at_ms + TRIP_LIMIT_MS,
        "the operator's trip condition",
        |view| Ok(estimated_margin_c(view)? < TRIP_MARGIN_C),
    )
    .await?;
    let trip_point = driver.snapshot();
    check(
        !trip_point.model_limit,
        "the plant reached saturation before the operator tripped",
    )?;
    control(fcx, operator, "trip", Value::Null).await?;
    let tripped = driver.snapshot();
    check(
        !tripped.model_limit,
        "the plant reached saturation during the HMI trip",
    )?;
    let trip_at = match tripped.truth.reactor.trip {
        Some(trip) => trip.at_ms,
        None => return Err(Error::msg("the HMI trip did not trip the reactor")),
    };
    say(line(
        trip_at,
        5,
        &format!(
            "operator trips the reactor from the HMI, at an estimated {:.1} C margin",
            estimated_margin_c(&trip_view)?
        ),
    ));
    let dropped = wait_for(fcx, driver, trip_at + ROD_DROP_MS).await?;
    check(
        dropped.truth.reactor.control_rod_percent < 1.0,
        format!(
            "the rods did not drop: {:.1} % withdrawn",
            dropped.truth.reactor.control_rod_percent
        ),
    )?;
    let rods = hmi_view(fcx, operator).await?;
    check(
        reading(&rods, "rod_position")? < 1.0,
        "the HMI has not confirmed the rods are in",
    )?;
    say(line(
        dropped.at_ms,
        5,
        "the rods are in; the operator starts auxiliary feed from the HMI",
    ));
    control(
        fcx,
        operator,
        "pump",
        json!({ "name": "aux-feed", "running": true }),
    )
    .await?;
    let settled = wait_for(fcx, driver, dropped.at_ms + DECAY_SETTLE_MS).await?;
    check(
        settled.truth.reactor.neutron_power_percent < DECAY_POWER_LIMIT,
        format!(
            "the plant did not settle onto decay heat: {:.2} % power",
            settled.truth.reactor.neutron_power_percent
        ),
    )?;
    say(line(
        settled.at_ms,
        5,
        &format!(
            "settled on decay heat: {:.2} % power, {:.1} % decay heat",
            settled.truth.reactor.neutron_power_percent, settled.truth.reactor.decay_heat_percent
        ),
    ));
    inject(fcx, driver, FaultChange::Clear(FaultTarget::Sensor(hot_b)))?;
    inject(
        fcx,
        driver,
        FaultChange::Clear(FaultTarget::Process(ProcessFault::CoolantPumpTrip {
            pump: Loop::B,
        })),
    )?;
    let cleared_at = driver.snapshot().at_ms;
    say(line(
        cleared_at,
        5,
        "fault cleared: loop B gauge and pump trip",
    ));
    let mut tracking_since = None;
    let (gauge, true_hot_b) = loop {
        let view = hmi_view(fcx, operator).await?;
        let snapshot = driver.snapshot();
        let gauge = reading(&view, "hot_leg_b")?;
        let true_hot_b = snapshot.truth.primary.loops[Loop::B.index()].hot_leg_c;
        check(
            snapshot.at_ms <= cleared_at + 15_000,
            "the loop B gauge did not catch up within 15 s after the faults cleared",
        )?;
        if (gauge - true_hot_b).abs() < 1.0 {
            let since = *tracking_since.get_or_insert(snapshot.at_ms);
            if snapshot.at_ms - since >= GAUGE_TRACKING_MS {
                break (gauge, true_hot_b);
            }
        } else {
            tracking_since = None;
        }
        pause(fcx).await?;
    };
    say(line(
        driver.snapshot().at_ms,
        5,
        &format!(
            "the loop B gauge reads the plant again: HMI {gauge:.1} C, true hot leg {true_hot_b:.1} C"
        ),
    ));

    // 6. A second fault: telemetry goes quiet. The readings and their sample
    // times stop while the plant moves. The HMI holds the last values it polled.
    inject(fcx, driver, FaultChange::Inject(Fault::TelemetryQuiet))?;
    let quiet_from = driver.snapshot().at_ms;
    say(line(quiet_from, 6, "fault: telemetry goes quiet"));
    // The baseline is taken after the last sample before the fault, so every
    // reading and the heartbeat hold the values they will keep through the window.
    let baseline = wait_for(fcx, driver, quiet_from + QUIET_BASELINE_MS).await?;
    let view_before = hmi_view(fcx, operator).await?;
    let hmi_before = reading(&view_before, "hot_leg_b")?;
    let heartbeat_before = heartbeats(&view_before)?;
    let quiet_end = wait_for(fcx, driver, baseline.at_ms + QUIET_MS).await?;
    check(
        quiet_end.telemetry.quiet && quiet_end.telemetry.heartbeat == baseline.telemetry.heartbeat,
        "the telemetry heartbeat moved while telemetry was quiet",
    )?;
    check(
        quiet_end
            .readings
            .iter()
            .zip(baseline.readings.iter())
            .all(|(a, b)| a.reading.sampled_at_ms == b.reading.sampled_at_ms),
        "a reading was sampled while telemetry was quiet",
    )?;
    check(
        quiet_end.truth.primary.average_temperature_c
            != baseline.truth.primary.average_temperature_c,
        "the plant did not move while telemetry was quiet",
    )?;
    let view_after = hmi_view(fcx, operator).await?;
    let hmi_after = reading(&view_after, "hot_leg_b")?;
    check(
        heartbeats(&view_after)? == heartbeat_before,
        "the HMI heartbeats moved while telemetry was quiet",
    )?;
    check(
        view_after["polls"].as_u64() > view_before["polls"].as_u64(),
        "the HMI stopped polling",
    )?;
    check(
        hmi_before == hmi_after,
        format!("the HMI gauge moved while telemetry was quiet: {hmi_before:?} then {hmi_after:?}"),
    )?;
    say(line(
        quiet_end.at_ms,
        6,
        &format!(
            "telemetry quiet: the heartbeat stays at {}; the HMI holds loop B at {:.1} C while the plant moves",
            heartbeat_before[0], hmi_after
        ),
    ));
    inject(fcx, driver, FaultChange::Clear(FaultTarget::TelemetryQuiet))?;
    let quiet_to = driver.snapshot().at_ms;
    say(line(quiet_to, 6, "fault cleared: telemetry quiet"));
    let resumed = wait_for(fcx, driver, quiet_to + RESUME_MS).await?;
    check(
        !resumed.telemetry.quiet && resumed.telemetry.heartbeat > quiet_end.telemetry.heartbeat,
        "the readings did not resume after the quiet fault cleared",
    )?;
    let resumed_view = hmi_view(fcx, operator).await?;
    check(
        heartbeats(&resumed_view)?
            .iter()
            .zip(heartbeat_before)
            .all(|(a, b)| *a != b),
        "the HMI heartbeats did not resume",
    )?;
    say(line(
        resumed.at_ms,
        6,
        "telemetry resumes; the gauges catch up",
    ));

    let first_action_after_fault_ms = tripped.first_action_after_fault_ms.ok_or_else(|| {
        Error::msg("no accepted command followed the fault, so the first action has no delay")
    })?;
    Ok(Report {
        maneuver_at_ms: maneuver_at,
        fault_at_ms: fault_at,
        alarm_at_ms: alarmed.at_ms,
        trip_at_ms: trip_at,
        first_action_after_fault_ms,
        quiet_from_ms: quiet_from,
        quiet_to_ms: quiet_to,
    })
}

fn line(at_ms: u64, step: u8, text: &str) -> Line {
    Line {
        at_ms,
        step,
        text: text.to_owned(),
    }
}

fn check(ok: bool, message: impl Into<String>) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(Error::msg(message.into()))
    }
}

fn alarm_active(snapshot: &PlantSnapshot, alarm: Alarm) -> bool {
    snapshot
        .alarms
        .iter()
        .flatten()
        .any(|entry| entry.alarm == alarm && entry.state != AlarmState::Normal)
}

/// The subcooling margin the operator can estimate from the reported values:
/// saturation at the reported pressure, minus the reported core exit temperature.
fn estimated_margin_c(view: &Value) -> Result<f64, Error> {
    Ok(
        steam::saturation(reading(view, "pressurizer_pressure")?).temperature_c
            - reading(view, "core_exit_temperature")?,
    )
}

fn average_temperature(view: &Value) -> Result<f64, Error> {
    Ok((reading(view, "hot_leg_a")?
        + reading(view, "hot_leg_b")?
        + reading(view, "cold_leg_a")?
        + reading(view, "cold_leg_b")?)
        / 4.0)
}

fn reading(view: &Value, name: &str) -> Result<f64, Error> {
    view["readings"][name]["value"]
        .as_f64()
        .ok_or_else(|| Error::msg(format!("the HMI has no reading for {name}")))
}

fn hmi_alarm(view: &Value, name: &str) -> Result<bool, Error> {
    view["alarms"]
        .as_array()
        .and_then(|alarms| alarms.iter().find(|a| a["id"] == name))
        .and_then(|alarm| alarm["state"].as_str())
        .map(|state| state != "normal")
        .ok_or_else(|| Error::msg(format!("the HMI has no alarm for {name}")))
}

fn heartbeats(view: &Value) -> Result<[u16; 3], Error> {
    let mut counts = [0; 3];
    for (index, id) in ["rps1", "rcs1", "bop1"].iter().enumerate() {
        counts[index] = view["links"]
            .as_array()
            .and_then(|links| links.iter().find(|link| link["id"] == *id))
            .and_then(|link| link["heartbeat"].as_u64())
            .and_then(|count| u16::try_from(count).ok())
            .ok_or_else(|| Error::msg(format!("the HMI has no heartbeat for {id}")))?;
    }
    Ok(counts)
}

/// Applies a fault change on the driver, logging it on `fcx`. The expected
/// revision is the plant's current one, since the story acts on what it reads.
fn inject(fcx: &Cx, driver: &Driver, change: FaultChange) -> Result<(), Error> {
    let expected_revision = driver.snapshot().revision;
    driver
        .apply_fault(
            fcx,
            FaultCommand {
                change,
                expected_revision,
            },
        )
        .map(|_| ())
        .map_err(|rejected| Error::msg(format!("the fault was refused: {:?}", rejected.reason)))
}

async fn pause(fcx: &Cx) -> Result<(), Error> {
    fcx.sleep(POLL)
        .await
        .map_err(|_| Error::msg("the run was cancelled"))
}

/// Waits until the plant reaches `at_ms` and returns its snapshot.
async fn wait_for(fcx: &Cx, driver: &Driver, at_ms: u64) -> Result<PlantSnapshot, Error> {
    loop {
        let snapshot = driver.snapshot();
        if snapshot.at_ms >= at_ms {
            return Ok(snapshot);
        }
        pause(fcx).await?;
    }
}

/// Waits until `done` holds. Fails when the plant reaches `limit_ms` first;
/// `what` names the event in the failure.
async fn until_hmi(
    fcx: &Cx,
    operator: &Machine,
    limit_ms: u64,
    what: &str,
    done: impl Fn(&Value) -> Result<bool, Error>,
) -> Result<Value, Error> {
    loop {
        let view = hmi_view(fcx, operator).await?;
        if done(&view)? {
            return Ok(view);
        }
        if plant_ms(fcx) >= limit_ms {
            return Err(Error::msg(format!(
                "{what} did not happen by {limit_ms} ms"
            )));
        }
        pause(fcx).await?;
    }
}

/// Sends a control POST to hmi01. A null body sends no fields.
async fn control(fcx: &Cx, operator: &Machine, kind: &str, body: Value) -> Result<(), Error> {
    let bytes = if body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(&body).map_err(|e| Error::msg(e.to_string()))?
    };
    let mut headers = vec![header("Host", hmi::NAME)];
    if !bytes.is_empty() {
        headers.push(header("Content-Type", "application/json"));
    }
    headers.push(header("Content-Length", &bytes.len().to_string()));
    let request = http1::Request {
        head: RequestHead {
            method: "POST".to_owned(),
            target: format!("{}{kind}", hmi::CONTROL_PREFIX),
            version: Version::Http11,
            headers,
        },
        body: bytes,
    };
    let response = exchange(fcx, operator, &request).await?;
    if response.head.status != 200 {
        return Err(Error::msg(format!(
            "the HMI refused {kind}: {} {}",
            response.head.status,
            String::from_utf8_lossy(&response.body)
        )));
    }
    Ok(())
}

/// Reads the complete HMI view over the operator connection.
async fn hmi_view(fcx: &Cx, operator: &Machine) -> Result<Value, Error> {
    let request = http1::Request {
        head: RequestHead {
            method: "GET".to_owned(),
            target: "/api/plant".to_owned(),
            version: Version::Http11,
            headers: vec![header("Host", hmi::NAME)],
        },
        body: Vec::new(),
    };
    let response = exchange(fcx, operator, &request).await?;
    check(
        response.head.status == 200,
        "the HMI plant view request failed",
    )?;
    serde_json::from_slice(&response.body).map_err(|e| Error::msg(e.to_string()))
}

fn header(name: &str, value: &str) -> Header {
    Header {
        name: name.to_owned(),
        value: value.as_bytes().to_vec(),
    }
}

/// One request on a new connection from the operator to hmi01.
async fn exchange(
    fcx: &Cx,
    operator: &Machine,
    request: &http1::Request,
) -> Result<http1::Response, Error> {
    let to = SocketAddr::new(IpAddr::V4(hmi::ADDR), hmi::PORT);
    let mut conn = operator
        .tcp
        .connect(fcx, to)
        .await
        .map_err(|e| Error::msg(format!("the operator cannot reach hmi01: {e:?}")))?;
    sandbox::request(fcx, &mut conn, request).await
}
