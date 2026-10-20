use nuclear_world::{Config, Plant, command::*, faults::*, scenarios::Scenario, stages::Stage};

fn fault(plant: &mut Plant, change: FaultChange) {
    plant
        .apply_fault(FaultCommand {
            change,
            expected_revision: plant.snapshot().revision,
        })
        .unwrap();
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
