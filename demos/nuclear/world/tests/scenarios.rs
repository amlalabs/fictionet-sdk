use nuclear_world::{
    Config, Plant, command::*, faults::*, protection::*, sensors::*, snapshot::PlantSnapshot, steam,
};

fn plant_unprotected() -> Plant {
    Plant::new(Config {
        automatic_protection: false,
        ..Config::default()
    })
}
fn fault(p: &mut Plant, change: FaultChange) {
    p.apply_fault(FaultCommand {
        change,
        expected_revision: p.snapshot().revision,
    })
    .unwrap();
}
fn inject(p: &mut Plant, f: Fault) {
    fault(p, FaultChange::Inject(f));
}
fn loss_of_feed(p: &mut Plant) {
    for pump in Loop::ALL {
        inject(p, Fault::Process(ProcessFault::FeedPumpTrip { pump }));
    }
}
fn alarm(p: &PlantSnapshot, a: Alarm) -> AlarmState {
    p.alarms[a.index()].map_or(AlarmState::Normal, |e| e.state)
}
fn reading(p: &PlantSnapshot, s: Sensor) -> Reading {
    p.readings[s.index()].reading
}
fn close(a: f64, b: f64, tolerance: f64) {
    assert!(
        (a - b).abs() <= tolerance,
        "{a} versus {b}, tolerance {tolerance}"
    );
}

#[test]
fn full_power_equilibrium_and_heat_balance_for_ten_minutes() {
    let mut p = Plant::new(Config::default());
    let initial = p.snapshot();
    close(initial.truth.primary.subcooling_margin_c, 19.79, 1e-12);
    assert_eq!(initial.truth.primary.heater_fraction, 0.25);
    assert!(initial.truth.primary.heaters_on);
    for second in 1..=600 {
        p.advance(second * 1000);
        let s = p.snapshot();
        // Exact design balance; bands cover projection resolution, not drift.
        close(s.truth.reactor.neutron_power_percent, 100.0, 0.1);
        close(
            s.truth.primary.average_temperature_c,
            initial.truth.primary.average_temperature_c,
            0.1,
        );
        close(s.truth.primary.pressure_mpa, 15.5, 0.01);
        close(s.truth.primary.subcooling_margin_c, 19.79, 1e-10);
        close(s.truth.primary.heater_fraction, 0.25, 0.001);
        close(s.truth.primary.level_percent, 50.0, 0.1);
        close(s.truth.secondary.steam_pressure_mpa, 6.9, 0.01);
        for l in &s.truth.secondary.loops {
            close(l.level_percent, 50.0, 0.1);
        }
        assert!(s.truth.reactor.trip.is_none());
        assert!(s.alarms.iter().all(Option::is_none), "{:?}", s.alarms);
        assert!(!s.model_limit);
        let heat: f64 = s
            .truth
            .secondary
            .loops
            .iter()
            .map(|l| l.heat_transfer_mw)
            .sum();
        let enthalpy: f64 = s
            .truth
            .secondary
            .loops
            .iter()
            .map(|l| {
                l.steam_kg_s
                    * (steam::saturation(s.truth.secondary.steam_pressure_mpa).vapor_kj_kg
                        - steam::FEED_ENTHALPY)
                    / 1000.0
            })
            .sum();
        close(heat / s.truth.reactor.thermal_mw, 1.0, 0.01);
        close(enthalpy / heat, 1.0, 0.01);
    }
}

#[test]
fn deterministic_commands_and_noise_isolation() {
    let mut a = plant_unprotected();
    let mut b = plant_unprotected();
    let mut c = Plant::new(Config {
        seed: 99,
        automatic_protection: false,
        ..Config::default()
    });
    for t in (0..300_000).step_by(1000) {
        for p in [&mut a, &mut b, &mut c] {
            if t == 20_000 {
                p.apply(Command::RodDemand {
                    tenths_percent: 520,
                })
                .unwrap();
            }
            if t == 90_000 {
                inject(
                    p,
                    Fault::Process(ProcessFault::CoolantPumpTrip { pump: Loop::B }),
                );
            }
            if t == 120_000 {
                p.apply(Command::ManualTrip).unwrap();
            }
            p.advance(t + 1000);
        }
        assert_eq!(a.snapshot(), b.snapshot());
        assert_eq!(
            serde_json::to_string(&a.snapshot()).unwrap(),
            serde_json::to_string(&b.snapshot()).unwrap()
        );
        assert_eq!(a.snapshot().truth, c.snapshot().truth);
    }
    assert_ne!(a.snapshot().readings, c.snapshot().readings);
}

#[test]
fn rods_set_new_feedback_limited_equilibria() {
    for (demand, up) in [(550, true), (450, false)] {
        let mut p = Plant::new(Config::default());
        let initial = p.snapshot();
        p.apply(Command::RodDemand {
            tenths_percent: demand,
        })
        .unwrap();
        p.advance(540_000);
        let previous = p.snapshot();
        p.advance(600_000);
        let s = p.snapshot();
        assert!(s.truth.reactor.trip.is_none(), "{:?}", s.truth.reactor);
        if up {
            assert!(s.truth.reactor.neutron_power_percent > 100.5);
            assert!(
                s.truth.primary.average_temperature_c > initial.truth.primary.average_temperature_c
            );
        } else {
            assert!(s.truth.reactor.neutron_power_percent < 99.5);
            assert!(
                s.truth.primary.average_temperature_c < initial.truth.primary.average_temperature_c
            );
        }
        // After many thermal time constants the residual decay-group drift is small.
        close(
            s.truth.reactor.neutron_power_percent,
            previous.truth.reactor.neutron_power_percent,
            0.5,
        );
        close(s.truth.reactor.reactivity_pcm, 0.0, 2.0);
    }
}

#[test]
fn turbine_load_follow_uses_temperature_feedback() {
    let mut p = Plant::new(Config::default());
    let initial = p.snapshot();
    p.apply(Command::ValveDemand {
        valve: Valve::Turbine,
        permille: 800,
    })
    .unwrap();
    p.advance(540_000);
    let previous = p.snapshot();
    p.advance(600_000);
    let s = p.snapshot();
    assert!(s.truth.reactor.trip.is_none(), "{:?}", s.truth);
    assert_eq!(s.truth.reactor.control_rod_percent, 50.0);
    assert!(s.truth.primary.average_temperature_c > initial.truth.primary.average_temperature_c);
    // At ten minutes the header is about 7.61 MPa, so an 80% opening passes
    // about 88% rated flow. Warmer coolant restores zero net reactivity at
    // about 87.5% neutron power, within this 80–90% band. Residual decay heat
    // accounts for the small difference between neutron and thermal power.
    assert!(
        (80.0..90.0).contains(&s.truth.reactor.neutron_power_percent),
        "{:?}",
        s.truth
    );
    close(
        s.truth.reactor.neutron_power_percent,
        previous.truth.reactor.neutron_power_percent,
        0.5,
    );
    close(
        s.truth.reactor.thermal_mw / 1800.0,
        s.truth.secondary.generator_mw / 600.0,
        0.01,
    );
}

#[test]
fn manual_trip_rods_decay_heat_and_dump() {
    let mut p = Plant::new(Config::default());
    p.apply(Command::ManualTrip).unwrap();
    p.advance(3000);
    let s = p.snapshot();
    assert!(s.truth.reactor.neutron_power_percent < 10.0);
    assert_eq!(s.truth.reactor.control_rod_percent, 0.0);
    assert_eq!(s.truth.reactor.shutdown_rod_percent_inserted, 100.0);
    assert!(s.truth.secondary.turbine_tripped);
    for seconds in [10_u64, 100, 1000] {
        p.advance(seconds * 1000);
        let s = p.snapshot();
        let expected = 6.6 * (seconds as f64).powf(-0.2);
        assert!(
            (1.0 / 1.5..1.5).contains(&(s.truth.reactor.decay_heat_percent / expected)),
            "{seconds}: {:?}",
            s.truth.reactor
        );
        assert!(s.truth.secondary.steam_dump_percent > 0.0);
        assert_eq!(
            s.truth.reactor.trip.unwrap(),
            Trip {
                cause: TripCause::Manual,
                at_ms: 0
            }
        );
    }
}

#[test]
fn loss_of_feed_trips_on_level_and_auxiliary_feed_cools() {
    let mut p = Plant::new(Config::default());
    loss_of_feed(&mut p);
    let mut minimum = 50.0_f64;
    let mut tripped = false;
    for second in 1..=600 {
        p.advance(second * 1000);
        let s = p.snapshot();
        minimum = minimum.min(s.truth.secondary.loops[0].level_percent);
        assert!(s.truth.secondary.auxiliary_feed_running);
        if let Some(trip) = s.truth.reactor.trip {
            assert!(
                matches!(trip.cause, TripCause::SteamGeneratorLevelLow(_)),
                "{trip:?}"
            );
            tripped = true;
            for l in &s.truth.primary.loops {
                assert!(l.hot_leg_c < HIGH_HOT_LEG_C, "{:?}", s.truth);
            }
        }
    }
    assert!(minimum < LOW_LOW_LEVEL);
    assert!(tripped);
}

#[test]
fn unprotected_loss_of_feed_uncovers_tubes_and_heats_primary() {
    let mut p = plant_unprotected();
    loss_of_feed(&mut p);
    p.advance(300_000);
    let s = p.snapshot();
    assert!(s.truth.reactor.trip.is_none());
    assert!(!s.truth.secondary.auxiliary_feed_running);
    assert!(
        s.truth.secondary.loops[0].level_percent < 5.0,
        "{:?}",
        s.truth
    );
    assert!(s.truth.secondary.loops[0].heat_transfer_mw < 450.0);
    assert!(s.truth.primary.loops[0].hot_leg_c > 335.0);
    assert!(s.truth.primary.pressure_mpa > 15.5);
    assert_eq!(
        alarm(&s, Alarm::SteamGeneratorLevelLow(Loop::A)),
        AlarmState::Active
    );
    assert_eq!(
        alarm(&s, Alarm::HotLegTemperatureHigh(Loop::A)),
        AlarmState::Active
    );
}

#[test]
fn coolant_pump_coasts_before_low_flow_trip() {
    let mut p = Plant::new(Config::default());
    inject(
        &mut p,
        Fault::Process(ProcessFault::CoolantPumpTrip { pump: Loop::A }),
    );
    p.advance(50);
    let flow = p.snapshot().truth.primary.loops[0].flow_percent;
    assert!(flow > 99.0 && flow < 100.0);
    p.advance(3000);
    let s = p.snapshot();
    assert!(s.truth.primary.loops[0].flow_percent > 70.0);
    assert!(s.truth.reactor.trip.is_none());
    p.advance(10_000);
    assert_eq!(
        p.snapshot().truth.reactor.trip.unwrap().cause,
        TripCause::CoolantFlowLow(Loop::A)
    );
}

#[test]
fn manual_pressurizer_heat_spray_and_expansion() {
    let mut p = plant_unprotected();
    p.apply(Command::Controller {
        controller: Controller::PressurizerPressure,
        mode: Mode::Manual,
    })
    .unwrap();
    p.apply(Command::Heaters { on: true }).unwrap();
    p.advance(20_000);
    let heated = p.snapshot().truth.primary.pressure_mpa;
    assert!(heated > 15.7);
    p.apply(Command::Heaters { on: false }).unwrap();
    p.apply(Command::ValveDemand {
        valve: Valve::PressurizerSpray,
        permille: 500,
    })
    .unwrap();
    p.advance(40_000);
    assert!(p.snapshot().truth.primary.pressure_mpa < heated - 0.5);
    p.apply(Command::ValveDemand {
        valve: Valve::PressurizerSpray,
        permille: 0,
    })
    .unwrap();
    p.apply(Command::ValveDemand {
        valve: Valve::Turbine,
        permille: 800,
    })
    .unwrap();
    p.advance(300_000);
    let s = p.snapshot();
    assert!(s.truth.primary.level_percent > 50.0);
}

#[test]
fn condenser_cooling_loss_trips_turbine_and_blocks_dump() {
    let mut p = Plant::new(Config::default());
    inject(&mut p, Fault::Process(ProcessFault::CondenserCoolingLoss));
    p.advance(20_000);
    let s = p.snapshot();
    assert!(s.truth.secondary.condenser_pressure_kpa >= LOW_VACUUM_KPA);
    assert!(s.truth.secondary.turbine_tripped);
    assert_eq!(s.truth.secondary.steam_dump_percent, 0.0);
    assert_eq!(s.truth.reactor.trip.unwrap().cause, TripCause::TurbineTrip);
}

#[test]
fn quiet_temperature_hides_its_alarm_but_not_physics() {
    let mut p = plant_unprotected();
    let sensor = Sensor::HotLeg(Loop::A);
    let before = reading(&p.snapshot(), sensor);
    inject(
        &mut p,
        Fault::Sensor {
            sensor,
            kind: SensorFault::Quiet,
        },
    );
    loss_of_feed(&mut p);
    let mut mismatch_seen = false;
    for second in 1..=300 {
        p.advance(second * 1000);
        let s = p.snapshot();
        assert_eq!(reading(&s, sensor), before);
        assert_eq!(
            alarm(&s, Alarm::HotLegTemperatureHigh(Loop::A)),
            AlarmState::Normal
        );
        mismatch_seen |= alarm(&s, Alarm::FeedFlowLow(Loop::A)) == AlarmState::Active;
    }
    let s = p.snapshot();
    assert!(s.truth.primary.loops[0].hot_leg_c > before.value + 10.0);
    assert_eq!(
        alarm(&s, Alarm::SteamGeneratorLevelLow(Loop::A)),
        AlarmState::Active
    );
    assert!(mismatch_seen);
}

#[test]
fn stuck_bias_and_telemetry_quiet_have_distinct_freshness() {
    let mut p = Plant::new(Config::default());
    let sensor = Sensor::HotLeg(Loop::A);
    inject(
        &mut p,
        Fault::Sensor {
            sensor,
            kind: SensorFault::Stuck { value: 3000 },
        },
    );
    p.advance(1000);
    assert_eq!(
        reading(&p.snapshot(), sensor),
        Reading {
            value: 300.0,
            sampled_at_ms: 1000
        }
    );
    fault(&mut p, FaultChange::Clear(FaultTarget::Sensor(sensor)));
    inject(
        &mut p,
        Fault::Sensor {
            sensor,
            kind: SensorFault::Bias { delta: 100 },
        },
    );
    p.advance(1250);
    close(reading(&p.snapshot(), sensor).value, 335.0, 0.1);
    inject(&mut p, Fault::TelemetryQuiet);
    let before = p.snapshot();
    p.apply(Command::ManualTrip).unwrap();
    p.advance(5000);
    let quiet = p.snapshot();
    assert_eq!(quiet.readings, before.readings);
    assert_eq!(quiet.reported_status, before.reported_status);
    assert!(quiet.truth.reactor.trip.is_some());
    assert!(!quiet.reported_status.reactor_tripped);
    assert_eq!(alarm(&quiet, Alarm::ReactorTripped), AlarmState::Normal);
    assert_eq!(quiet.telemetry.heartbeat, before.telemetry.heartbeat);
    assert_eq!(
        quiet.telemetry.last_sample_ms,
        before.telemetry.last_sample_ms
    );
    assert!(quiet.truth.reactor.neutron_power_percent < 10.0);
    fault(&mut p, FaultChange::Clear(FaultTarget::TelemetryQuiet));
    p.advance(5200);
    assert_eq!(p.snapshot().telemetry.heartbeat, before.telemetry.heartbeat);
    assert!(!p.snapshot().reported_status.reactor_tripped);
    assert_eq!(
        alarm(&p.snapshot(), Alarm::ReactorTripped),
        AlarmState::Normal
    );
    p.advance(5250);
    assert!(p.snapshot().reported_status.reactor_tripped);
    assert_eq!(
        alarm(&p.snapshot(), Alarm::ReactorTripped),
        AlarmState::Active
    );
    assert_eq!(
        p.snapshot().reported_status,
        nuclear_world::snapshot::ReportedStatus::from(&p.snapshot().truth)
    );
    assert_eq!(
        p.snapshot().telemetry.heartbeat,
        before.telemetry.heartbeat.wrapping_add(1)
    );
    assert!(
        p.snapshot()
            .readings
            .iter()
            .all(|r| r.reading.sampled_at_ms == 5250)
    );
}

#[test]
fn schedule_uses_first_step_after_time_and_stable_order() {
    let mut config = Config::default();
    config.schedule[0] = Some(ScheduledFault {
        at_ms: 101,
        change: FaultChange::Inject(Fault::TelemetryQuiet),
    });
    config.schedule[1] = Some(ScheduledFault {
        at_ms: 150,
        change: FaultChange::Clear(FaultTarget::TelemetryQuiet),
    });
    config.schedule[2] = Some(ScheduledFault {
        at_ms: 151,
        change: FaultChange::Inject(Fault::TelemetryQuiet),
    });
    let mut a = Plant::new(config.clone());
    let mut b = Plant::new(config);
    a.advance(149);
    assert_eq!(a.snapshot().at_ms, 100);
    assert_eq!(a.snapshot().revision, 0);
    a.advance(150);
    assert_eq!(a.snapshot().revision, 2);
    assert!(!a.snapshot().faults.telemetry_quiet);
    assert_eq!(a.snapshot().last_fault_start_ms, Some(150));
    a.advance(200);
    b.advance(200);
    assert_eq!(a.snapshot(), b.snapshot());
    assert!(a.snapshot().faults.telemetry_quiet);
    assert_eq!(a.snapshot().last_fault_start_ms, Some(200));
    let before = a.snapshot();
    a.advance(0);
    assert_eq!(a.snapshot(), before);
}

#[test]
fn commands_reject_without_mutation_and_count_accepted_actions() {
    let mut p = Plant::new(Config::default());
    for (c, reason) in [
        (
            Command::RodDemand {
                tenths_percent: 1001,
            },
            Rejection::OutOfRange,
        ),
        (
            Command::ValveDemand {
                valve: Valve::Turbine,
                permille: 1001,
            },
            Rejection::OutOfRange,
        ),
        (Command::Heaters { on: true }, Rejection::WrongMode),
    ] {
        let before = p.snapshot();
        assert_eq!(
            p.apply(c).unwrap_err(),
            Rejected {
                reason,
                revision: 0
            }
        );
        assert_eq!(p.snapshot(), before);
    }
    p.apply(Command::ManualTrip).unwrap();
    assert_eq!(p.snapshot().revision, 1);
    assert_eq!(p.snapshot().operator_actions, 1);
    assert_eq!(
        p.apply(Command::RodDemand {
            tenths_percent: 1000
        })
        .unwrap_err()
        .reason,
        Rejection::Tripped
    );
    assert_eq!(
        p.apply(Command::ResetTrip).unwrap_err().reason,
        Rejection::TripConditionPresent
    );
    inject(
        &mut p,
        Fault::Process(ProcessFault::FeedPumpTrip { pump: Loop::A }),
    );
    assert_eq!(
        p.apply(Command::Pump {
            pump: Pump::MainFeed(Loop::A),
            running: true
        })
        .unwrap_err()
        .reason,
        Rejection::Faulted
    );
    assert_eq!(
        p.apply_fault(FaultCommand {
            expected_revision: 1,
            change: FaultChange::ClearAll
        })
        .unwrap_err()
        .reason,
        Rejection::StaleRevision
    );
    p.advance(10_000);
    p.apply(Command::AcknowledgeAlarms).unwrap();
    assert_eq!(p.snapshot().first_action_after_fault_ms, Some(10_000));
    assert_eq!(p.snapshot().operator_actions, 2);
    p.apply(Command::ResetTrip).unwrap();
    let s = p.snapshot();
    assert_eq!(s.revision, 3);
    assert_eq!(s.operator_actions, 3);
    assert_eq!(s.truth.reactor.control_rod_percent, 0.0);
    assert_eq!(s.truth.reactor.shutdown_rod_percent_inserted, 0.0);
}

#[test]
fn alarm_acknowledgment_clearing_and_deadband() {
    let mut p = plant_unprotected();
    let sensor = Sensor::PressurizerPressure;
    let a = Alarm::PressurizerPressureHigh;
    for (count, expected) in [
        (1630, AlarmState::Active),
        (1610, AlarmState::Acknowledged),
        (1590, AlarmState::Normal),
        (1610, AlarmState::Normal),
    ] {
        inject(
            &mut p,
            Fault::Sensor {
                sensor,
                kind: SensorFault::Stuck { value: count },
            },
        );
        p.advance(p.snapshot().at_ms + 250);
        assert_eq!(alarm(&p.snapshot(), a), expected);
        if expected == AlarmState::Active {
            p.apply(Command::AcknowledgeAlarms).unwrap();
            assert_eq!(alarm(&p.snapshot(), a), AlarmState::Acknowledged);
        }
        fault(&mut p, FaultChange::Clear(FaultTarget::Sensor(sensor)));
    }
}

#[test]
fn stuck_feed_valve_holds_and_cleared_pump_can_restart() {
    let mut p = plant_unprotected();
    p.apply(Command::Controller {
        controller: Controller::FeedLevel(Loop::A),
        mode: Mode::Manual,
    })
    .unwrap();
    let position = p.snapshot().truth.secondary.loops[0].feed_valve_percent;
    inject(
        &mut p,
        Fault::Process(ProcessFault::FeedValveStuck { line: Loop::A }),
    );
    assert_eq!(
        p.apply(Command::ValveDemand {
            valve: Valve::Feed(Loop::A),
            permille: 0
        })
        .unwrap_err()
        .reason,
        Rejection::Faulted
    );
    p.advance(1000);
    assert_eq!(
        p.snapshot().truth.secondary.loops[0].feed_valve_percent,
        position
    );
    fault(&mut p, FaultChange::ClearAll);
    p.apply(Command::ValveDemand {
        valve: Valve::Feed(Loop::A),
        permille: 0,
    })
    .unwrap();
    p.advance(2000);
    assert!(p.snapshot().truth.secondary.loops[0].feed_valve_percent < position);
    let f = ProcessFault::CoolantPumpTrip { pump: Loop::A };
    inject(&mut p, Fault::Process(f));
    p.advance(3000);
    fault(&mut p, FaultChange::Clear(FaultTarget::Process(f)));
    assert!(!p.snapshot().truth.primary.loops[0].pump_running);
    p.apply(Command::Pump {
        pump: Pump::Coolant(Loop::A),
        running: true,
    })
    .unwrap();
    p.advance(4000);
    assert!(p.snapshot().truth.primary.loops[0].pump_running);
}

#[test]
fn protection_sees_through_quiet_telemetry_and_model_limit_latches() {
    let mut p = Plant::new(Config::default());
    inject(&mut p, Fault::TelemetryQuiet);
    loss_of_feed(&mut p);
    p.advance(120_000);
    assert!(p.snapshot().truth.reactor.trip.is_some());
    let mut p = Plant::new(Config {
        automatic_protection: false,
        temperature_feedback: false,
        ..Config::default()
    });
    p.apply(Command::RodDemand {
        tenths_percent: 1000,
    })
    .unwrap();
    p.advance(120_000);
    assert!(p.snapshot().model_limit);
    p.apply(Command::ManualTrip).unwrap();
    p.advance(130_000);
    assert!(p.snapshot().model_limit);
}

#[test]
fn half_power_is_a_balanced_initial_condition() {
    let mut p = Plant::new(Config {
        initial_power: nuclear_world::InitialPower::Half,
        ..Config::default()
    });
    let initial = p.snapshot();
    p.advance(600_000);
    let s = p.snapshot();
    close(s.truth.reactor.neutron_power_percent, 50.0, 0.1);
    close(s.truth.reactor.thermal_mw, 900.0, 0.1);
    close(s.truth.secondary.generator_mw, 300.0, 0.1);
    close(
        s.truth.primary.average_temperature_c,
        initial.truth.primary.average_temperature_c,
        0.1,
    );
    close(s.truth.primary.pressure_mpa, 15.5, 0.01);
    close(s.truth.primary.heater_fraction, 0.25, 0.001);
    assert!(s.truth.primary.heaters_on);
    close(s.truth.secondary.steam_pressure_mpa, 6.9, 0.01);
    assert!(s.truth.reactor.trip.is_none());
    assert!(s.alarms.iter().all(Option::is_none));
    assert!(!s.model_limit);
}

#[test]
fn natural_circulation_remains_after_both_pumps_coast_down() {
    let mut p = plant_unprotected();
    for pump in Loop::ALL {
        inject(
            &mut p,
            Fault::Process(ProcessFault::CoolantPumpTrip { pump }),
        );
    }
    p.apply(Command::ManualTrip).unwrap();
    p.advance(300_000);
    let s = p.snapshot();
    for l in &s.truth.primary.loops {
        assert_eq!(l.pump_speed_percent, 0.0);
        assert!(s.truth.reactor.core_exit_c > l.steam_generator_primary_c);
        assert!(l.flow_percent > 0.0 && l.flow_percent <= 3.0);
    }
}

#[test]
fn temperature_lag_bias_range_and_fault_rejections() {
    let mut p = plant_unprotected();
    p.apply(Command::ManualTrip).unwrap();
    assert_eq!(
        p.apply(Command::RodDemand { tenths_percent: 10 })
            .unwrap_err()
            .reason,
        Rejection::Tripped
    );
    p.advance(3000);
    let s = p.snapshot();
    assert!(reading(&s, Sensor::CoreExitTemperature).value > s.truth.reactor.core_exit_c + 0.1);
    let sensor = Sensor::PressurizerPressure;
    inject(
        &mut p,
        Fault::Sensor {
            sensor,
            kind: SensorFault::Bias { delta: i16::MAX },
        },
    );
    p.advance(3250);
    assert_eq!(reading(&p.snapshot(), sensor).value, sensor.spec().max);
    let before = p.snapshot();
    assert_eq!(
        p.apply_fault(FaultCommand {
            expected_revision: before.revision,
            change: FaultChange::Inject(Fault::Sensor {
                sensor,
                kind: SensorFault::Quiet
            })
        })
        .unwrap_err()
        .reason,
        Rejection::AlreadyActive
    );
    assert_eq!(p.snapshot(), before);
    fault(&mut p, FaultChange::ClearAll);
    let before = p.snapshot();
    assert_eq!(
        p.apply_fault(FaultCommand {
            expected_revision: before.revision,
            change: FaultChange::Inject(Fault::Sensor {
                sensor,
                kind: SensorFault::Stuck { value: -1 }
            })
        })
        .unwrap_err()
        .reason,
        Rejection::OutOfRange
    );
    assert_eq!(p.snapshot(), before);
    p.advance(3500);
    assert!(reading(&p.snapshot(), sensor).value < sensor.spec().max);
}

#[test]
fn manual_heaters_balance_ambient_loss_only_when_powered() {
    for initial_power in [
        nuclear_world::InitialPower::Full,
        nuclear_world::InitialPower::Half,
    ] {
        let mut p = Plant::new(Config {
            initial_power,
            ..Config::default()
        });
        p.apply(Command::Controller {
            controller: Controller::PressurizerPressure,
            mode: Mode::Manual,
        })
        .unwrap();
        p.apply(Command::Heaters { on: false }).unwrap();
        p.advance(20_000);
        let cold = p.snapshot().truth.primary;
        assert!(!cold.heaters_on);
        assert_eq!(cold.spray_percent, 0.0);
        close(cold.pressure_mpa, 15.4, 0.01);
        p.apply(Command::Heaters { on: true }).unwrap();
        p.advance(40_000);
        let hot = p.snapshot().truth.primary;
        assert!(hot.heaters_on);
        assert_eq!(hot.spray_percent, 0.0);
        close(hot.pressure_mpa, 15.7, 0.01);
    }
}

#[test]
fn first_action_delay_survives_later_commands_and_resets_on_new_fault() {
    let mut p = plant_unprotected();
    p.apply(Command::AcknowledgeAlarms).unwrap();
    assert_eq!(p.snapshot().first_action_after_fault_ms, None);
    p.advance(1000);
    inject(&mut p, Fault::TelemetryQuiet);
    p.advance(2000);
    assert_eq!(p.snapshot().first_action_after_fault_ms, None);
    assert_eq!(
        p.apply(Command::Heaters { on: false }).unwrap_err().reason,
        Rejection::WrongMode
    );
    assert_eq!(p.snapshot().first_action_after_fault_ms, None);
    p.apply(Command::AcknowledgeAlarms).unwrap();
    assert_eq!(p.snapshot().first_action_after_fault_ms, Some(1000));
    p.advance(3000);
    p.apply(Command::AcknowledgeAlarms).unwrap();
    assert_eq!(p.snapshot().first_action_after_fault_ms, Some(1000));
    assert!(
        p.apply_fault(FaultCommand {
            change: FaultChange::Inject(Fault::TelemetryQuiet),
            expected_revision: p.snapshot().revision,
        })
        .is_err()
    );
    assert_eq!(p.snapshot().first_action_after_fault_ms, Some(1000));
    inject(
        &mut p,
        Fault::Sensor {
            sensor: Sensor::CoreExitTemperature,
            kind: SensorFault::Quiet,
        },
    );
    assert_eq!(p.snapshot().last_fault_start_ms, Some(3000));
    assert_eq!(p.snapshot().first_action_after_fault_ms, None);
    fault(&mut p, FaultChange::ClearAll);
    assert_eq!(p.snapshot().first_action_after_fault_ms, None);
    p.advance(3500);
    p.apply(Command::AcknowledgeAlarms).unwrap();
    assert_eq!(p.snapshot().first_action_after_fault_ms, Some(500));
}

#[test]
fn boiling_starts_at_the_first_crossing() {
    let mut p = plant_unprotected();
    loss_of_feed(&mut p);
    let mut previous_margin = p.snapshot().truth.primary.subcooling_margin_c;
    for at_ms in (50..=600_000).step_by(50) {
        p.advance(at_ms);
        let s = p.snapshot();
        let margin = s.truth.primary.subcooling_margin_c;
        assert!(!s.model_limit);
        if let Some(boiling_at) = s.stages[nuclear_world::stages::Stage::Boiling.index()] {
            assert_eq!(boiling_at, at_ms);
            assert!(previous_margin > 0.0);
            assert!(margin <= 0.0 && margin > -0.1, "{margin}");
            assert!(s.truth.reactor.trip.is_none());
            p.apply(Command::ManualTrip).unwrap();
            p.advance(at_ms + 60_000);
            assert!(!p.snapshot().model_limit);
            assert_eq!(
                p.snapshot().severe.regime,
                nuclear_world::snapshot::Regime::TwoPhase
            );
            return;
        }
        assert!(margin > 0.0);
        previous_margin = margin;
    }
    panic!("primary did not reach saturation");
}

#[test]
fn stuck_core_exit_hides_subcooling_alarm() {
    let mut live = plant_unprotected();
    let mut stuck = plant_unprotected();
    inject(
        &mut stuck,
        Fault::Sensor {
            sensor: Sensor::CoreExitTemperature,
            kind: SensorFault::Stuck { value: 3250 },
        },
    );
    loss_of_feed(&mut live);
    loss_of_feed(&mut stuck);
    live.advance(300_000);
    stuck.advance(300_000);
    assert_eq!(live.snapshot().truth, stuck.snapshot().truth);
    assert!(live.snapshot().truth.primary.subcooling_margin_c < 15.0);
    assert_eq!(
        alarm(&live.snapshot(), Alarm::SubcoolingMarginLow),
        AlarmState::Active
    );
    assert_eq!(
        alarm(&stuck.snapshot(), Alarm::SubcoolingMarginLow),
        AlarmState::Normal
    );
    fault(
        &mut stuck,
        FaultChange::Clear(FaultTarget::Sensor(Sensor::CoreExitTemperature)),
    );
    stuck.advance(300_250);
    assert_eq!(
        alarm(&stuck.snapshot(), Alarm::SubcoolingMarginLow),
        AlarmState::Active
    );
}

#[test]
fn subcooling_alarm_uses_reported_pressure_and_temperature_with_deadband() {
    let mut p = plant_unprotected();
    inject(
        &mut p,
        Fault::Sensor {
            sensor: Sensor::CoreExitTemperature,
            kind: SensorFault::Stuck { value: 3300 },
        },
    );
    for (pressure, expected) in [
        (1550, AlarmState::Active),
        (1560, AlarmState::Acknowledged),
        (1600, AlarmState::Normal),
        (1560, AlarmState::Normal),
    ] {
        inject(
            &mut p,
            Fault::Sensor {
                sensor: Sensor::PressurizerPressure,
                kind: SensorFault::Stuck { value: pressure },
            },
        );
        p.advance(p.snapshot().at_ms + 250);
        close(p.snapshot().truth.primary.subcooling_margin_c, 19.79, 1e-10);
        assert_eq!(alarm(&p.snapshot(), Alarm::SubcoolingMarginLow), expected);
        if expected == AlarmState::Active {
            p.apply(Command::AcknowledgeAlarms).unwrap();
        }
        fault(
            &mut p,
            FaultChange::Clear(FaultTarget::Sensor(Sensor::PressurizerPressure)),
        );
    }
}

#[test]
fn equipment_status_samples_with_readings_while_modes_stay_live() {
    let mut p = plant_unprotected();
    let before = p.snapshot().reported_status;
    inject(&mut p, Fault::TelemetryQuiet);
    for line in Loop::ALL {
        for pump in [Pump::Coolant(line), Pump::MainFeed(line)] {
            p.apply(Command::Pump {
                pump,
                running: false,
            })
            .unwrap();
        }
    }
    p.apply(Command::Pump {
        pump: Pump::AuxiliaryFeed,
        running: true,
    })
    .unwrap();
    p.apply(Command::Pump {
        pump: Pump::CirculatingWater,
        running: false,
    })
    .unwrap();
    p.apply(Command::Controller {
        controller: Controller::PressurizerPressure,
        mode: Mode::Manual,
    })
    .unwrap();
    p.apply(Command::Heaters { on: false }).unwrap();
    p.apply(Command::ManualTrip).unwrap();
    p.advance(250);
    let quiet = p.snapshot();
    assert_eq!(quiet.reported_status, before);
    assert_eq!(quiet.truth.controllers.pressurizer_pressure, Mode::Manual);
    for a in [
        Alarm::FeedPumpTripped,
        Alarm::CoolantPumpTripped,
        Alarm::ReactorTripped,
        Alarm::TurbineTripped,
    ] {
        assert_eq!(alarm(&quiet, a), AlarmState::Normal);
    }
    fault(&mut p, FaultChange::Clear(FaultTarget::TelemetryQuiet));
    p.advance(450);
    assert_eq!(p.snapshot().reported_status, before);
    p.advance(500);
    let live = p.snapshot();
    let status = live.reported_status;
    assert_eq!(status.coolant_pumps_running, [false; 2]);
    assert_eq!(status.feed_pumps_running, [false; 2]);
    assert!(status.auxiliary_feed_running);
    assert!(!status.circulating_water_running);
    assert!(!status.pressurizer_heaters_on);
    assert!(status.reactor_tripped);
    assert!(status.turbine_tripped);
    for a in [
        Alarm::FeedPumpTripped,
        Alarm::CoolantPumpTripped,
        Alarm::ReactorTripped,
        Alarm::TurbineTripped,
    ] {
        assert_eq!(alarm(&live, a), AlarmState::Active);
    }
}

#[test]
fn quiet_telemetry_hides_each_relief_valve_until_sampling_resumes() {
    for primary in [false, true] {
        let mut p = plant_unprotected();
        if primary {
            p.apply(Command::Controller {
                controller: Controller::PressurizerPressure,
                mode: Mode::Manual,
            })
            .unwrap();
            p.apply(Command::Heaters { on: true }).unwrap();
        } else {
            p.apply(Command::ValveDemand {
                valve: Valve::Turbine,
                permille: 0,
            })
            .unwrap();
        }
        inject(&mut p, Fault::TelemetryQuiet);
        p.advance(200_000);
        let s = p.snapshot();
        assert!(if primary {
            s.truth.primary.relief_open
        } else {
            s.truth.secondary.steam_relief_open
        });
        assert!(!s.reported_status.pressurizer_relief_open);
        assert!(!s.reported_status.steam_relief_open);
        assert_eq!(alarm(&s, Alarm::ReliefValveOpen), AlarmState::Normal);
        fault(&mut p, FaultChange::Clear(FaultTarget::TelemetryQuiet));
        p.advance(200_250);
        let s = p.snapshot();
        assert!(if primary {
            s.reported_status.pressurizer_relief_open
        } else {
            s.reported_status.steam_relief_open
        });
        assert_eq!(alarm(&s, Alarm::ReliefValveOpen), AlarmState::Active);
    }
}

#[test]
fn primary_saturation_rows_follow_if97_and_endpoints_clamp() {
    // IF97 saturation calculations before rounding to table resolution.
    for (pressure, temperature, liquid, vapor) in [
        (12.0, 324.678304, 1491.327052, 2685.582734),
        (14.0, 336.669369, 1570.878476, 2638.093448),
        (15.5, 344.791552, 1629.850299, 2596.216721),
        (16.0, 347.356534, 1649.671943, 2580.804428),
        (17.0, 352.293440, 1690.035825, 2547.412768),
        (18.0, 356.991813, 1732.023366, 2509.529689),
    ] {
        let sat = steam::saturation(pressure);
        close(sat.temperature_c, temperature, 0.005);
        close(sat.liquid_kj_kg, liquid, 0.05);
        close(sat.vapor_kj_kg, vapor, 0.05);
    }
    assert_eq!(steam::saturation(0.0), steam::saturation(0.1));
    assert_eq!(steam::saturation(20.0), steam::saturation(18.0));
    close(
        steam::saturation(15.75).temperature_c,
        (344.79 + 347.36) / 2.0,
        1e-12,
    );
}
