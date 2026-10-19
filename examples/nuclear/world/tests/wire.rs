use nuclear_world::{Config, Plant, command::*, faults::*, protection::*, sensors::*, snapshot::*};
use serde::{Serialize, de::DeserializeOwned};
use std::fmt::Debug;

fn bounded<T: Serialize + DeserializeOwned + PartialEq + Debug>(value: T, bound: usize) {
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(
        bytes.len() <= bound,
        "{} bytes > {bound}: {value:?}",
        bytes.len()
    );
    assert_eq!(serde_json::from_slice::<T>(&bytes).unwrap(), value);
}

#[test]
fn command_examples_and_unknown_fields() {
    let c: Command = serde_json::from_str(r#"{"rod_demand":{"tenths_percent":480}}"#).unwrap();
    assert_eq!(
        serde_json::to_string(&c).unwrap(),
        r#"{"rod_demand":{"tenths_percent":480}}"#
    );
    assert_eq!(serde_json::to_string(&Loop::A).unwrap(), r#""a""#);
    assert_eq!(serde_json::to_string(&Loop::B).unwrap(), r#""b""#);
    assert_eq!(
        serde_json::to_string(&ProcessFault::FeedValveStuck { line: Loop::B }).unwrap(),
        r#"{"feed_valve_stuck":{"line":"b"}}"#
    );
    assert_eq!(
        c,
        Command::RodDemand {
            tenths_percent: 480
        }
    );
    let f: FaultCommand = serde_json::from_str(r#"{"change":{"inject":{"sensor":{"sensor":{"hot_leg":"a"},"kind":{"stuck":{"value":3250}}}}},"expected_revision":0}"#).unwrap();
    assert_eq!(
        f.change,
        FaultChange::Inject(Fault::Sensor {
            sensor: Sensor::HotLeg(Loop::A),
            kind: SensorFault::Stuck { value: 3250 }
        })
    );
    assert!(
        serde_json::from_str::<FaultCommand>(
            r#"{"change":"clear_all","expected_revision":0,"extra":true}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<Command>(r#"{"pump":{"pump":{"coolant":"c"},"running":true}}"#)
            .is_err()
    );
}

#[test]
fn command_reply_and_fault_bounds_cover_variants_and_integer_extremes() {
    for l in Loop::ALL {
        bounded(l, Loop::MAX_JSON_BYTES);
        for pump in [
            Pump::Coolant(l),
            Pump::MainFeed(l),
            Pump::AuxiliaryFeed,
            Pump::CirculatingWater,
        ] {
            bounded(pump, Pump::MAX_JSON_BYTES);
            for running in [false, true] {
                bounded(Command::Pump { pump, running }, Command::MAX_JSON_BYTES);
            }
        }
        for valve in [
            Valve::Feed(l),
            Valve::Turbine,
            Valve::SteamDump,
            Valve::PressurizerSpray,
        ] {
            bounded(valve, Valve::MAX_JSON_BYTES);
            bounded(
                Command::ValveDemand {
                    valve,
                    permille: u16::MAX,
                },
                Command::MAX_JSON_BYTES,
            );
        }
        for controller in [
            Controller::FeedLevel(l),
            Controller::PressurizerPressure,
            Controller::SteamDump,
        ] {
            bounded(controller, Controller::MAX_JSON_BYTES);
            for mode in [Mode::Automatic, Mode::Manual] {
                bounded(mode, Mode::MAX_JSON_BYTES);
                bounded(
                    Command::Controller { controller, mode },
                    Command::MAX_JSON_BYTES,
                );
            }
        }
    }
    for c in [
        Command::RodDemand {
            tenths_percent: u16::MAX,
        },
        Command::ManualTrip,
        Command::ResetTrip,
        Command::Heaters { on: false },
        Command::Heaters { on: true },
        Command::AcknowledgeAlarms,
    ] {
        bounded(c, Command::MAX_JSON_BYTES);
    }
    bounded(
        Applied {
            revision: u64::MAX,
            at_ms: u64::MAX,
        },
        Applied::MAX_JSON_BYTES,
    );
    for reason in [
        Rejection::StaleRevision,
        Rejection::OutOfRange,
        Rejection::Tripped,
        Rejection::TripConditionPresent,
        Rejection::Faulted,
        Rejection::WrongMode,
        Rejection::AlreadyActive,
        Rejection::NotActive,
    ] {
        bounded(reason, Rejection::MAX_JSON_BYTES);
        bounded(
            Rejected {
                reason,
                revision: u64::MAX,
            },
            Rejected::MAX_JSON_BYTES,
        );
    }
    for process in ProcessFault::ALL {
        bounded(process, ProcessFault::MAX_JSON_BYTES);
        check_fault(Fault::Process(process), FaultTarget::Process(process));
    }
    for sensor in Sensor::ALL {
        bounded(sensor, Sensor::MAX_JSON_BYTES);
        bounded(sensor.spec().unit, Unit::MAX_JSON_BYTES);
        for kind in [
            SensorFault::Quiet,
            SensorFault::Stuck { value: i16::MIN },
            SensorFault::Stuck { value: i16::MAX },
            SensorFault::Bias { delta: i16::MIN },
            SensorFault::Bias { delta: i16::MAX },
        ] {
            bounded(kind, SensorFault::MAX_JSON_BYTES);
            check_fault(Fault::Sensor { sensor, kind }, FaultTarget::Sensor(sensor));
            let reading = Reading {
                value: -f64::MAX,
                sampled_at_ms: u64::MAX,
            };
            bounded(reading, Reading::MAX_JSON_BYTES);
            bounded(
                Channel {
                    sensor,
                    reading,
                    fault: Some(kind),
                },
                Channel::MAX_JSON_BYTES,
            );
        }
    }
    check_fault(Fault::TelemetryQuiet, FaultTarget::TelemetryQuiet);
    check_change(FaultChange::ClearAll);
    for l in Loop::ALL {
        for cause in [
            TripCause::Manual,
            TripCause::NeutronPowerHigh,
            TripCause::PressurizerPressureHigh,
            TripCause::PressurizerPressureLow,
            TripCause::CoolantFlowLow(l),
            TripCause::SteamGeneratorLevelLow(l),
            TripCause::HotLegTemperatureHigh(l),
            TripCause::TurbineTrip,
        ] {
            bounded(cause, TripCause::MAX_JSON_BYTES);
            bounded(
                Trip {
                    cause,
                    at_ms: u64::MAX,
                },
                Trip::MAX_JSON_BYTES,
            );
        }
    }
    for alarm in Alarm::ALL {
        bounded(alarm, Alarm::MAX_JSON_BYTES);
        for state in [
            AlarmState::Normal,
            AlarmState::Active,
            AlarmState::Acknowledged,
        ] {
            bounded(state, AlarmState::MAX_JSON_BYTES);
            bounded(AlarmEntry { alarm, state }, AlarmEntry::MAX_JSON_BYTES);
        }
    }
}

fn check_fault(f: Fault, target: FaultTarget) {
    bounded(f, Fault::MAX_JSON_BYTES);
    bounded(target, FaultTarget::MAX_JSON_BYTES);
    check_change(FaultChange::Inject(f));
    check_change(FaultChange::Clear(target));
}
fn check_change(change: FaultChange) {
    bounded(change, FaultChange::MAX_JSON_BYTES);
    bounded(
        FaultCommand {
            change,
            expected_revision: u64::MAX,
        },
        FaultCommand::MAX_JSON_BYTES,
    );
    bounded(
        ScheduledFault {
            change,
            at_ms: u64::MAX,
        },
        ScheduledFault::MAX_JSON_BYTES,
    );
}

#[test]
fn snapshot_bound_with_every_alarm_fault_and_maximum_numeric_width() {
    let mut p = Plant::new(Config::default());
    for f in ProcessFault::ALL {
        p.apply_fault(FaultCommand {
            expected_revision: p.snapshot().revision,
            change: FaultChange::Inject(Fault::Process(f)),
        })
        .unwrap();
    }
    for sensor in Sensor::ALL {
        p.apply_fault(FaultCommand {
            expected_revision: p.snapshot().revision,
            change: FaultChange::Inject(Fault::Sensor {
                sensor,
                kind: SensorFault::Stuck { value: 0 },
            }),
        })
        .unwrap();
    }
    p.apply_fault(FaultCommand {
        expected_revision: p.snapshot().revision,
        change: FaultChange::Inject(Fault::TelemetryQuiet),
    })
    .unwrap();
    p.advance(250);
    bounded(p.snapshot(), PlantSnapshot::MAX_JSON_BYTES);
    let mut s = p.snapshot();
    s.at_ms = u64::MAX;
    s.revision = u64::MAX;
    s.operator_actions = u64::MAX;
    s.last_fault_start_ms = Some(u64::MAX);
    s.first_action_after_fault_ms = Some(u64::MAX);
    s.truth.reactor.trip = Some(Trip {
        cause: TripCause::SteamGeneratorLevelLow(Loop::A),
        at_ms: u64::MAX,
    });
    s.reported_status = ReportedStatus {
        coolant_pumps_running: [false; 2],
        feed_pumps_running: [false; 2],
        auxiliary_feed_running: false,
        circulating_water_running: false,
        pressurizer_heaters_on: false,
        pressurizer_relief_open: false,
        steam_relief_open: false,
        reactor_tripped: false,
        turbine_tripped: false,
    };
    s.telemetry = Telemetry {
        quiet: false,
        heartbeat: u16::MAX,
        last_sample_ms: u64::MAX,
    };
    s.truth.controllers = Controllers {
        feed_level: [Mode::Automatic; 2],
        pressurizer_pressure: Mode::Automatic,
        steam_dump: Mode::Automatic,
    };
    s.alarms = Alarm::ALL.map(|alarm| {
        Some(AlarmEntry {
            alarm,
            state: AlarmState::Acknowledged,
        })
    });
    s.faults
        .sensors
        .fill(Some(SensorFault::Stuck { value: i16::MIN }));
    for channel in &mut s.readings {
        channel.fault = Some(SensorFault::Stuck { value: i16::MIN });
        channel.reading = Reading {
            value: -f64::MAX,
            sampled_at_ms: u64::MAX,
        };
    }
    // The projection normally rounds small engineering values. Testing the
    // longest finite floating representation gives a stronger byte bound.
    let mut truth = serde_json::to_value(&s.truth).unwrap();
    fn widen(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Number(n) if n.is_f64() => *value = serde_json::json!(-f64::MAX),
            serde_json::Value::Bool(b) => *b = false,
            serde_json::Value::Array(a) => {
                for v in a {
                    widen(v);
                }
            }
            serde_json::Value::Object(o) => {
                for v in o.values_mut() {
                    widen(v);
                }
            }
            _ => {}
        }
    }
    widen(&mut truth);
    s.truth = serde_json::from_value(truth).unwrap();
    bounded(s.truth.reactor.clone(), Reactor::MAX_JSON_BYTES);
    for l in &s.truth.primary.loops {
        bounded(l.clone(), PrimaryLoop::MAX_JSON_BYTES);
    }
    bounded(s.truth.primary.clone(), Primary::MAX_JSON_BYTES);
    for l in &s.truth.secondary.loops {
        bounded(l.clone(), SecondaryLoop::MAX_JSON_BYTES);
    }
    bounded(s.truth.secondary.clone(), Secondary::MAX_JSON_BYTES);
    bounded(s.truth.controllers.clone(), Controllers::MAX_JSON_BYTES);
    bounded(s.truth.clone(), Truth::MAX_JSON_BYTES);
    bounded(s.reported_status, ReportedStatus::MAX_JSON_BYTES);
    bounded(s.telemetry, Telemetry::MAX_JSON_BYTES);
    bounded(s.faults.clone(), Faults::MAX_JSON_BYTES);
    bounded(s, PlantSnapshot::MAX_JSON_BYTES);
}

#[test]
fn telemetry_heartbeat_wraps_at_sixteen_bits() {
    let mut p = Plant::new(Config::default());
    p.advance(u64::from(u16::MAX) * SAMPLE_MS);
    assert_eq!(p.snapshot().telemetry.heartbeat, u16::MAX);
    p.advance((u64::from(u16::MAX) + 1) * SAMPLE_MS);
    assert_eq!(p.snapshot().telemetry.heartbeat, 0);
}
