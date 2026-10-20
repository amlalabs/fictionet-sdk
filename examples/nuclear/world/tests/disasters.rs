use nuclear_world::{Config, Plant, command::*, faults::*, scenarios::Scenario, stages::Stage};

fn fault(plant: &mut Plant, change: FaultChange) {
    plant
        .apply_fault(FaultCommand {
            change,
            expected_revision: plant.snapshot().revision,
        })
        .unwrap();
}

fn stage_time(label: &str, actual: u64, target: u64, tolerance: u64) {
    println!("{label}: {actual} ms; target {target} ms within {tolerance} ms");
    assert!(
        actual.abs_diff(target) <= tolerance,
        "{label}: {actual} ms; target {target} ms within {tolerance} ms"
    );
}

#[test]
fn loss_of_feed_boils_without_reaching_the_model_limit() {
    let mut config = Scenario::Normal.config();
    config.automatic_protection = false;
    for (slot, pump) in config.schedule.iter_mut().zip(Loop::ALL) {
        *slot = Some(ScheduledFault {
            at_ms: 0,
            change: FaultChange::Inject(Fault::Process(ProcessFault::FeedPumpTrip { pump })),
        });
    }
    let mut plant = Plant::new(config);
    let mut boiling = None;
    for at in (50..=300_000).step_by(50) {
        plant.advance(at);
        let snap = plant.snapshot();
        assert!(!snap.model_limit, "model limit at {at} ms");
        if boiling.is_none()
            && let Some(time) = snap.stages[Stage::Boiling.index()]
        {
            stage_time("Loss of feed boiling", time, 105_000, 6_000);
            boiling = Some(time);
        }
    }
    assert!(boiling.is_some());
}

fn primary_until_uncovered(
    scenario: Scenario,
    boiling_target: u64,
    boiling_tolerance: u64,
    safety_target: Option<u64>,
    uncovered_target: Option<u64>,
) {
    let mut plant = Plant::new(scenario.config());
    let mut boiling = None;
    let mut safety = None;
    let mut inventory_min = 162_000.0_f64;
    let mut inventory_max = 0.0_f64;
    let mut pressure_min = f64::INFINITY;
    let mut pressure_max = 0.0_f64;
    for at in (50..=6 * 3_600_000).step_by(50) {
        plant.advance(at);
        let snap = plant.snapshot();
        let severe = &snap.severe;
        assert!(!snap.model_limit, "{scenario:?}: model limit at {at} ms");
        assert!(
            (0.0..=162_000.0).contains(&severe.inventory_kg),
            "{scenario:?}: inventory {} kg at {at} ms",
            severe.inventory_kg
        );
        inventory_min = inventory_min.min(severe.inventory_kg);
        inventory_max = inventory_max.max(severe.inventory_kg);
        if boiling.is_none()
            && let Some(time) = snap.stages[Stage::Boiling.index()]
        {
            stage_time(
                &format!("{scenario:?} boiling"),
                time,
                boiling_target,
                boiling_tolerance,
            );
            boiling = Some(time);
        }
        if safety.is_none() && severe.relief.safety_valve_flow_kg_s > 0.0 {
            safety = Some(at);
            if let Some(target) = safety_target {
                stage_time(
                    &format!("{scenario:?} safety valves"),
                    at,
                    target,
                    target / 10,
                );
            }
        }
        if scenario == Scenario::StuckOpenRelief {
            assert!(!snap.reported_status.pressurizer_relief_open);
            if (20 * 60_000..=70 * 60_000).contains(&at) {
                let pressure = snap.truth.primary.pressure_mpa;
                assert!((6.5..=7.5).contains(&pressure), "{pressure} MPa at {at} ms");
                pressure_min = pressure_min.min(pressure);
                pressure_max = pressure_max.max(pressure);
            }
            if (15 * 60_000..=74 * 60_000).contains(&at) {
                assert_eq!(severe.pressurizer_water_kg, 24_000.0, "at {at} ms");
                assert!(severe.relief.flow_kg_s > 0.0);
                assert!(snap.truth.primary.relief_open);
            }
        }
        if let Some(time) = snap.stages[Stage::CoreUncovered.index()] {
            assert!(boiling.is_some());
            if let Some(target) = uncovered_target {
                stage_time(
                    &format!("{scenario:?} core uncovered"),
                    time,
                    target,
                    target / 10,
                );
            } else {
                println!("{scenario:?} core uncovered: {time} ms");
            }
            if safety_target.is_some() {
                assert!(safety.is_some());
            }
            println!(
                "{scenario:?} inventory: {inventory_min} to {inventory_max} kg; bounds 0 to 162000 kg"
            );
            if scenario == Scenario::StuckOpenRelief {
                println!(
                    "Stuck relief pressure: {pressure_min} to {pressure_max} MPa; bounds 6.5 to 7.5 MPa"
                );
                println!(
                    "Pressurizer: 24000 kg from 15 to 74 min; reported relief closed throughout"
                );
            }
            return;
        }
    }
    panic!("{scenario:?}: core did not uncover within six hours");
}

#[test]
fn stuck_relief_drains_the_vessel_behind_a_closed_light_and_full_pressurizer() {
    primary_until_uncovered(
        Scenario::StuckOpenRelief,
        426_000,
        43_000,
        None,
        Some(4_464_000),
    );
}

#[test]
fn unattended_loop_boils_and_lifts_safety_valves_before_uncovering() {
    primary_until_uncovered(
        Scenario::LoopBUnattended,
        52_800,
        6_000,
        Some(3_066_000),
        Some(5_802_000),
    );
}

#[test]
fn blackout_boils_and_lifts_safety_valves_before_uncovering() {
    primary_until_uncovered(
        Scenario::StationBlackout,
        713_500,
        71_350,
        Some(4_164_000),
        None,
    );
}

#[test]
fn steam_break_fills_the_hall_at_the_design_time() {
    let mut plant = Plant::new(Scenario::SteamLineBreak.config());
    plant.advance(60_000);
    let snap = plant.snapshot();
    let at = snap.stages[Stage::TurbineHallSteam.index()].expect("hall steam stage");
    println!("Hall steam: {at} ms; target 54000 ms within 6000 ms");
    assert!(at.abs_diff(54_000) <= 6_000, "hall stage at {at} ms");
    assert!(snap.severe.turbine_hall.steam_kg_m3 >= 0.3);
    assert!(snap.severe.turbine_hall.temperature_c > 65.0);
    assert!(snap.end.is_none());
}

#[test]
fn isolation_stops_the_break_and_hall_vents() {
    let mut plant = Plant::new(Scenario::SteamLineBreak.config());
    plant.advance(30_000);
    let before = plant.snapshot();
    assert!(before.severe.steam_break_kg_s > 0.0);
    plant
        .apply(Command::SteamIsolation { closed: true })
        .unwrap();
    plant.advance(30_050);
    let stopped = plant.snapshot();
    assert_eq!(stopped.severe.steam_break_kg_s, 0.0);
    assert_eq!(stopped.truth.secondary.generator_mw, 0.0);
    plant.advance(330_050);
    let after = plant.snapshot();
    let loss = 100.0
        * (1.0 - after.severe.turbine_hall.steam_kg_m3 / stopped.severe.turbine_hall.steam_kg_m3);
    println!("Hall vent loss: {loss:.4}%; target 63% within 2 points");
    assert!((loss - 63.0).abs() <= 2.0, "hall loss {loss}%");
    assert_eq!(after.severe.steam_break_kg_s, 0.0);
    assert_eq!(after.truth.secondary.generator_mw, 0.0);
    assert!(after.truth.secondary.steam_relief_open);
}

#[test]
fn protection_isolates_on_the_step_after_low_header_pressure() {
    let mut plant = Plant::new(Config {
        automatic_protection: true,
        ..Scenario::SteamLineBreak.config()
    });
    for at in (50..=120_000).step_by(50) {
        let before = plant.snapshot();
        plant.advance(at);
        let after = plant.snapshot();
        if after.severe.steam_isolation_closed {
            assert!(!before.severe.steam_isolation_closed);
            assert!(before.truth.secondary.steam_pressure_mpa <= 4.5);
            assert!(after.truth.secondary.steam_pressure_mpa <= 4.51);
            assert_eq!(after.severe.steam_break_kg_s, 0.0);
            println!(
                "Automatic isolation: {at} ms, preceding header {} MPa",
                before.truth.secondary.steam_pressure_mpa
            );
            plant.advance(at + 1000);
            assert_eq!(plant.snapshot().severe.steam_break_kg_s, 0.0);
            return;
        }
    }
    panic!("steam isolation did not close in 120 seconds");
}

#[test]
fn blackout_forces_ac_equipment_and_refuses_starts_before_mode_checks() {
    let mut plant = Plant::new(Config::default());
    for pump in [Pump::AuxiliaryFeed, Pump::SafetyInjection] {
        plant
            .apply(Command::Pump {
                pump,
                running: true,
            })
            .unwrap();
    }
    fault(
        &mut plant,
        FaultChange::Inject(Fault::Process(ProcessFault::StationBlackout)),
    );
    let pumps = [
        Pump::Coolant(Loop::A),
        Pump::Coolant(Loop::B),
        Pump::MainFeed(Loop::A),
        Pump::MainFeed(Loop::B),
        Pump::AuxiliaryFeed,
        Pump::CirculatingWater,
        Pump::SafetyInjection,
    ];
    for pump in pumps {
        assert_eq!(
            plant
                .apply(Command::Pump {
                    pump,
                    running: true
                })
                .unwrap_err()
                .reason,
            Rejection::Faulted
        );
    }
    assert_eq!(
        plant
            .apply(Command::Heaters { on: true })
            .unwrap_err()
            .reason,
        Rejection::Faulted
    );
    for command in [
        Command::Relief { open: true },
        Command::ReliefBlock { closed: true },
        Command::SteamIsolation { closed: true },
    ] {
        plant.apply(command).unwrap();
    }
    for at in [50, 1000] {
        plant.advance(at);
        let snap = plant.snapshot();
        assert!(snap.truth.primary.loops.iter().all(|l| !l.pump_running));
        assert_eq!(snap.truth.secondary.feed_pumps_running, [false; 2]);
        assert!(!snap.truth.secondary.auxiliary_feed_running);
        assert!(!snap.truth.secondary.circulating_water_running);
        assert!(!snap.severe.safety_injection.running);
        assert!(!snap.truth.primary.heaters_on);
        assert_eq!(snap.truth.primary.heater_fraction, 0.0);
        assert!(!snap.severe.containment.fan_coolers_running);
        assert!(
            snap.severe.relief.demanded_open
                && snap.severe.relief.block_closed
                && snap.severe.steam_isolation_closed
        );
    }
    fault(
        &mut plant,
        FaultChange::Clear(FaultTarget::Process(ProcessFault::StationBlackout)),
    );
    plant.advance(1050);
    let cleared = plant.snapshot();
    assert!(cleared.truth.primary.loops.iter().all(|l| !l.pump_running));
    assert_eq!(cleared.truth.secondary.feed_pumps_running, [false; 2]);
    assert!(!cleared.truth.secondary.auxiliary_feed_running);
    assert!(!cleared.truth.secondary.circulating_water_running);
    assert!(!cleared.severe.safety_injection.running);
    assert!(!cleared.truth.primary.heaters_on);
    for pump in pumps {
        plant
            .apply(Command::Pump {
                pump,
                running: true,
            })
            .unwrap();
    }
    plant
        .apply(Command::Controller {
            controller: Controller::PressurizerPressure,
            mode: Mode::Manual,
        })
        .unwrap();
    plant.apply(Command::Heaters { on: true }).unwrap();
    plant.advance(1100);
    assert!(plant.snapshot().truth.primary.heaters_on);
    assert!(plant.snapshot().severe.containment.fan_coolers_running);
}

#[test]
fn injection_failure_stops_pumps_and_refuses_a_start() {
    let mut plant = Plant::new(Config::default());
    plant
        .apply(Command::Pump {
            pump: Pump::SafetyInjection,
            running: true,
        })
        .unwrap();
    fault(
        &mut plant,
        FaultChange::Inject(Fault::Process(ProcessFault::SafetyInjectionFailure)),
    );
    assert_eq!(
        plant
            .apply(Command::Pump {
                pump: Pump::SafetyInjection,
                running: true
            })
            .unwrap_err()
            .reason,
        Rejection::Faulted
    );
    plant.advance(50);
    assert!(!plant.snapshot().severe.safety_injection.running);
    fault(
        &mut plant,
        FaultChange::Clear(FaultTarget::Process(ProcessFault::SafetyInjectionFailure)),
    );
    plant.advance(100);
    assert!(!plant.snapshot().severe.safety_injection.running);
    plant
        .apply(Command::Pump {
            pump: Pump::SafetyInjection,
            running: true,
        })
        .unwrap();
    plant.advance(150);
    assert!(plant.snapshot().severe.safety_injection.running);
}

#[test]
fn accepted_commands_alone_update_last_command() {
    let mut plant = Plant::new(Config::default());
    assert!(plant.snapshot().last_command.is_none());
    plant.advance(100);
    let command = Command::Relief { open: true };
    plant.apply(command).unwrap();
    let last = plant.snapshot().last_command.unwrap();
    assert_eq!(last.command, command);
    assert_eq!(last.at_ms, 100);
    assert!(
        plant
            .apply(Command::RodDemand {
                tenths_percent: 1001
            })
            .is_err()
    );
    fault(
        &mut plant,
        FaultChange::Inject(Fault::Process(ProcessFault::ReliefStuckOpen)),
    );
    assert_eq!(plant.snapshot().last_command, Some(last));
}
