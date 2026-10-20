use nuclear_world::{
    Config, Plant,
    command::*,
    faults::*,
    scenarios::Scenario,
    snapshot::{PlantSnapshot, Regime},
    stages::{FailureCause, Stage},
};

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

fn core_to_breach(scenario: Scenario, targets_minutes: [f64; 6]) {
    let stages = [
        Stage::CoreUncovered,
        Stage::CladdingFailure,
        Stage::HydrogenRelease,
        Stage::CoreMelt,
        Stage::Relocation,
        Stage::VesselBreach,
    ];
    let mut plant = Plant::new(scenario.config());
    let mut seen = [false; 6];
    let mut melted = 0.0;
    let mut hydrogen_at_breach = None;
    let mut max_exit_error = 0.0_f64;
    let mut cavity_at_breach = None;
    let mut melted_at_breach = None;
    for at in (50..=6 * 3_600_000).step_by(50) {
        plant.advance(at);
        let snap = plant.snapshot();
        let severe = &snap.severe;
        if !seen[5] {
            assert!(!snap.model_limit, "{scenario:?}: model limit at {at} ms");
        }
        assert!(
            severe.melted_percent >= melted,
            "{scenario:?}: melt fell from {melted} to {} at {at} ms",
            severe.melted_percent
        );
        melted = severe.melted_percent;
        if severe.uncovered_percent > 0.0 {
            let sat = snap.truth.reactor.core_exit_c;
            let expected = sat + 0.6 * (severe.hot_fuel_c - sat);
            let error = (severe.core_exit_steam_c - expected).abs();
            max_exit_error = max_exit_error.max(error);
            // Each of the three temperatures rounds to a tenth of a degree.
            assert!(
                error <= 0.100000001,
                "{scenario:?}: exit error {error} at {at} ms"
            );
        }
        for (i, stage) in stages.into_iter().enumerate() {
            if !seen[i]
                && let Some(time) = snap.stages[stage.index()]
            {
                let target = (targets_minutes[i] * 60_000.0).round() as u64;
                stage_time(
                    &format!("{scenario:?} {stage:?}"),
                    time,
                    target,
                    target / 10,
                );
                seen[i] = true;
                if stage == Stage::CoreMelt && scenario == Scenario::LoopBUnattended {
                    let hydrogen = severe.hydrogen_generated_kg;
                    println!(
                        "LoopBUnattended hydrogen at melt: {hydrogen} kg; target 180 within 40 kg"
                    );
                    assert!((hydrogen - 180.0).abs() <= 40.0);
                }
                if stage == Stage::VesselBreach {
                    let pressure = severe.breach_pressure_mpa.expect("breach pressure");
                    println!("{scenario:?} breach pressure: {pressure} MPa; target above 2 MPa");
                    assert!(pressure > 2.0);
                    if scenario == Scenario::StuckOpenRelief {
                        println!(
                            "StuckOpenRelief breach pressure: {pressure} MPa; target below 10 MPa"
                        );
                        assert!(pressure < 10.0);
                    }
                    assert_eq!(severe.regime, Regime::Breached);
                    assert_eq!(severe.inventory_kg, 0.0);
                    assert_eq!(severe.vessel_water_kg, 0.0);
                    assert_eq!(severe.uncovered_percent, 100.0);
                    assert_eq!(severe.lower_plenum_melt_t, 0.0);
                    assert_eq!(severe.hydrogen_in_primary_kg, 0.0);
                    let accounted = severe.hydrogen_in_primary_kg
                        + severe.relief_tank.hydrogen_kg
                        + severe.containment.hydrogen_kg
                        + severe.containment.hydrogen_burned_kg;
                    assert!((severe.hydrogen_generated_kg - accounted).abs() <= 1.0);
                    assert_eq!(severe.containment.direct_heating_kpa, 100.0);
                    hydrogen_at_breach = Some(severe.hydrogen_generated_kg);
                    cavity_at_breach = Some(severe.cavity.melt_t);
                    melted_at_breach = Some(severe.melted_percent);
                }
            }
        }
        if let Some(hydrogen) = hydrogen_at_breach {
            assert_eq!(severe.hydrogen_generated_kg, hydrogen);
            assert_eq!(severe.regime, Regime::Breached);
            assert_eq!(severe.hydrogen_in_primary_kg, 0.0);
            assert_eq!(severe.inventory_kg, 0.0);
            assert!(snap.truth.reactor.fuel_temperature_c <= 2000.0);
        }
    }
    assert!(
        seen.into_iter().all(|stage| stage),
        "{scenario:?}: missing stage"
    );
    let severe = plant.snapshot().severe;
    // Both snapshots round to 0.1 t. One 50 ms relocation step moves 0.01 t
    // at 200 kg/s, so allow 0.11 t for rounding and one step of transfer.
    assert!(
        (severe.cavity.melt_t - severe.melted_percent).abs() <= 0.11,
        "{scenario:?}: cavity {} t at six hours; melted {}%",
        severe.cavity.melt_t,
        severe.melted_percent
    );
    if melted_at_breach.unwrap() < 100.0 {
        println!("{scenario:?}: melt remained in the core at breach");
        assert!(
            severe.cavity.melt_t > cavity_at_breach.unwrap(),
            "{scenario:?}: cavity {} t at breach, {} t at six hours",
            cavity_at_breach.unwrap(),
            severe.cavity.melt_t
        );
    } else {
        println!("{scenario:?}: the whole core had melted at breach");
    }
    assert!(severe.containment.direct_heating_kpa < 0.1);
    println!(
        "{scenario:?}: melt never decreased over six hours; no model limit through breach; maximum exit error {max_exit_error:.6} C, limit 0.1 C"
    );
}

#[test]
fn unattended_core_heats_melts_and_breaches() {
    core_to_breach(
        Scenario::LoopBUnattended,
        [96.7, 108.8, 113.5, 119.9, 122.0, 140.1],
    );
}

#[test]
fn stuck_relief_core_heats_melts_and_breaches() {
    core_to_breach(
        Scenario::StuckOpenRelief,
        [74.4, 89.2, 94.5, 104.9, 106.7, 154.1],
    );
}

#[test]
fn blackout_core_heats_melts_and_breaches() {
    core_to_breach(
        Scenario::StationBlackout,
        [97.3, 117.9, 124.5, 129.8, 131.8, 151.3],
    );
}

#[test]
fn returning_injection_keeps_the_wet_lower_head_at_saturation_for_six_hours() {
    let mut plant = Plant::new(Scenario::InjectionReturns.config());
    let mut wet_steps = 0;
    let mut max_head_error = 0.0_f64;
    for at in (50..=6 * 3_600_000).step_by(50) {
        plant.advance(at);
        let snap = plant.snapshot();
        assert!(
            snap.stages[Stage::VesselBreach.index()].is_none(),
            "breach at {at} ms"
        );
        assert_ne!(snap.severe.regime, Regime::Breached);
        assert!(snap.severe.breach_pressure_mpa.is_none());
        if snap.stages[Stage::Relocation.index()].is_some() && snap.severe.vessel_water_kg > 0.0 {
            wet_steps += 1;
            let error = (snap.severe.lower_head_c - snap.truth.reactor.core_exit_c).abs();
            max_head_error = max_head_error.max(error);
            assert!(error <= 1.0, "lower head error {error} C at {at} ms");
        }
    }
    assert!(wet_steps > 0);
    assert!(plant.snapshot().severe.lower_plenum_melt_t > 0.0);
    println!(
        "InjectionReturns: no breach in six hours; {wet_steps} wet steps after relocation; maximum lower head error {max_head_error:.6} C, limit 1 C"
    );
}

fn run_to_end(
    scenario: Scenario,
    action: Option<(u64, &[Command])>,
    horizon: u64,
) -> (PlantSnapshot, Option<u64>) {
    let mut plant = Plant::new(scenario.config());
    let mut disk_at = None;
    let mut depth = 0.0;
    for at in (60_000..=horizon).step_by(60_000) {
        let before = plant.clone();
        plant.advance(at);
        let snap = plant.snapshot();
        assert!(snap.severe.cavity.ablation_m >= depth);
        depth = snap.severe.cavity.ablation_m;
        if disk_at.is_none() && snap.severe.relief_tank.disk_ruptured {
            let mut crossing = before.clone();
            for step in ((at - 60_000 + 50)..=at).step_by(50) {
                crossing.advance(step);
                if crossing.snapshot().severe.relief_tank.disk_ruptured {
                    disk_at = Some(step);
                    break;
                }
            }
        }
        if let Some(end) = snap.end {
            plant = before;
            plant.advance(end.at_ms);
            return (plant.snapshot(), disk_at);
        }
        if let Some((when, commands)) = action
            && at == when
        {
            for command in commands {
                plant.apply(*command).unwrap();
            }
        }
    }
    (plant.snapshot(), disk_at)
}

fn check_stages(snap: &PlantSnapshot, expected: &[(Stage, u64, u64)]) {
    let mut previous = 0;
    for &(stage, target, pinned) in expected {
        let at = snap.stages[stage.index()].unwrap_or_else(|| panic!("missing {stage:?}"));
        stage_time(
            &format!("{stage:?}"),
            at,
            target,
            if target < 60_000 { 6000 } else { target / 10 },
        );
        assert_eq!(at, pinned, "{stage:?} changed its exact step");
        assert!(at >= previous, "{stage:?} out of order");
        previous = at;
    }
    for stage in Stage::ALL {
        assert_eq!(
            snap.stages[stage.index()].is_some(),
            expected.iter().any(|(s, _, _)| *s == stage),
            "unexpected stage {stage:?}"
        );
    }
}

fn acceptance(
    scenario: Scenario,
    expected: &[(Stage, u64, u64)],
    cause: Option<FailureCause>,
    disk_target: Option<u64>,
    breach_target: Option<f64>,
) {
    let (snap, disk) = run_to_end(scenario, None, 24 * 3_600_000);
    println!("{scenario:?}");
    if scenario == Scenario::InjectionReturns {
        println!(
            "InjectionReturns at 24 hours: primary {} MPa; core exit {} C; vessel level {}%; containment {} kPa",
            snap.truth.primary.pressure_mpa,
            snap.severe.core_exit_steam_c,
            snap.severe.vessel_level_percent,
            snap.severe.containment.pressure_kpa
        );
    }
    check_stages(&snap, expected);
    assert_eq!(
        snap.end.map(|e| e.stage),
        scenario.expected_end().map(|(stage, _)| stage)
    );
    assert_eq!(snap.severe.containment.failure, cause);
    if let Some(end) = snap.end {
        assert_eq!(snap.at_ms, end.at_ms);
    } else {
        assert_eq!(snap.at_ms, 24 * 3_600_000);
    }
    if let Some(target) = disk_target {
        stage_time(
            "Tank disk",
            disk.expect("disk rupture"),
            target,
            target / 10,
        );
    }
    if let Some(target) = breach_target {
        let pressure = snap.severe.breach_pressure_mpa.expect("breach pressure");
        println!("Breach: {pressure} MPa; target {target} MPa within 10%");
        assert!((pressure - target).abs() <= target / 10.0);
    }
    if matches!(
        scenario,
        Scenario::LoopBUnattended | Scenario::StationBlackout
    ) {
        assert_eq!(
            snap.stages[Stage::VesselBreach.index()],
            snap.stages[Stage::ContainmentFailure.index()]
        );
    }
    let (again, again_disk) = run_to_end(scenario, None, 24 * 3_600_000);
    assert_eq!(snap.stages, again.stages);
    assert_eq!(snap, again);
    assert_eq!(disk, again_disk);
}

#[test]
fn unattended_acceptance_and_replay() {
    acceptance(
        Scenario::LoopBUnattended,
        &[
            (Stage::Boiling, 53_000, 52_750),
            (Stage::CoreUncovered, 5_804_000, 5_803_500),
            (Stage::CladdingFailure, 6_526_000, 6_526_100),
            (Stage::HydrogenRelease, 6_808_000, 6_808_200),
            (Stage::CoreMelt, 7_196_000, 7_195_700),
            (Stage::Relocation, 7_321_000, 7_321_300),
            (Stage::VesselBreach, 8_406_000, 8_405_800),
            (Stage::ContainmentFailure, 8_406_000, 8_405_800),
        ],
        Some(FailureCause::HydrogenBurn),
        Some(3_306_000),
        Some(17.5),
    );
}

#[test]
fn steam_break_acceptance_and_replay() {
    acceptance(
        Scenario::SteamLineBreak,
        &[
            (Stage::TurbineHallSteam, 54_000, 54_050),
            (Stage::ControlRoomUninhabitable, 138_400, 138_450),
        ],
        None,
        None,
        None,
    );
}

#[test]
fn stuck_relief_acceptance_and_replay() {
    acceptance(
        Scenario::StuckOpenRelief,
        &[
            (Stage::Boiling, 426_000, 426_000),
            (Stage::CoreUncovered, 4_464_000, 4_464_100),
            (Stage::CladdingFailure, 5_352_000, 5_352_400),
            (Stage::HydrogenRelease, 5_670_000, 5_670_450),
            (Stage::CoreMelt, 6_296_000, 6_295_600),
            (Stage::Relocation, 6_402_000, 6_402_450),
            (Stage::HydrogenBurn, 7_858_000, 7_857_800),
            (Stage::VesselBreach, 9_244_000, 9_244_350),
            (Stage::FloorMeltThrough, 74_608_000, 74_607_950),
        ],
        None,
        Some(792_000),
        Some(4.3),
    );
}

#[test]
fn blackout_acceptance_and_replay() {
    acceptance(
        Scenario::StationBlackout,
        &[
            (Stage::Boiling, 714_000, 713_500),
            (Stage::CoreUncovered, 5_838_000, 5_838_200),
            (Stage::CladdingFailure, 7_075_000, 7_075_450),
            (Stage::HydrogenRelease, 7_472_000, 7_471_850),
            (Stage::CoreMelt, 7_791_000, 7_790_800),
            (Stage::Relocation, 7_909_000, 7_909_400),
            (Stage::VesselBreach, 9_079_000, 9_078_750),
            (Stage::ContainmentFailure, 9_079_000, 9_078_750),
        ],
        Some(FailureCause::Overpressure),
        Some(4_422_000),
        Some(17.5),
    );
}

#[test]
fn returning_injection_acceptance_and_replay() {
    acceptance(
        Scenario::InjectionReturns,
        &[
            (Stage::Boiling, 426_000, 426_000),
            (Stage::CoreUncovered, 4_464_000, 4_464_100),
            (Stage::CladdingFailure, 5_352_000, 5_352_400),
            (Stage::HydrogenRelease, 5_670_000, 5_670_450),
            (Stage::CoreMelt, 6_296_000, 6_295_600),
            (Stage::Relocation, 6_402_000, 6_402_450),
            (Stage::HydrogenBurn, 7_859_000, 7_859_250),
        ],
        None,
        Some(792_000),
        None,
    );
}

#[test]
fn normal_values_and_replay() {
    let mut normal = Plant::new(Scenario::Normal.config());
    normal.advance(600_000);
    let snap = normal.snapshot();
    assert_eq!(snap.stylized.control_room_steam, 0.0);
    assert_eq!(snap.stylized.containment_dose_sv_h, 0.001);
    acceptance(Scenario::Normal, &[], None, None, None);
}

#[test]
fn cladding_release_raises_dose_and_relief_burn_stays_below_failure_pressure() {
    let mut plant = Plant::new(Scenario::StuckOpenRelief.config());
    plant.advance(90 * 60_000);
    let cladding = plant.snapshot().stages[Stage::CladdingFailure.index()].unwrap();
    plant.advance(cladding + 600_000);
    let dose = plant.snapshot().stylized.containment_dose_sv_h;
    println!("Dose ten minutes after cladding: {dose} Sv/h; target above 1 Sv/h");
    assert!(dose > 1.0);
    for at in ((cladding + 600_050)..=145 * 60_000).step_by(50) {
        let before = plant.snapshot();
        plant.advance(at);
        let after = plant.snapshot();
        if after.stages[Stage::HydrogenBurn.index()].is_some() {
            let peak = before.severe.containment.pressure_kpa
                * (1.0 + 0.25 * before.severe.containment.hydrogen_percent);
            println!("Survived burn peak: {peak:.3} kPa; target below 700 kPa");
            assert!(peak < 700.0);
            assert!(after.severe.containment.burn_excess_kpa > 0.0);
            assert!(after.severe.containment.pressure_kpa > before.severe.containment.pressure_kpa);
            assert!(after.severe.containment.failure.is_none());
            return;
        }
    }
    panic!("no burn within the time window");
}

#[test]
fn feed_and_bleed_keeps_the_core_covered_for_twelve_hours() {
    let (snap, disk) = run_to_end(
        Scenario::LoopBUnattended,
        Some((
            30 * 60_000,
            &[
                Command::Pump {
                    pump: Pump::SafetyInjection,
                    running: true,
                },
                Command::Relief { open: true },
            ],
        )),
        12 * 3_600_000,
    );
    check_stages(&snap, &[(Stage::Boiling, 53_000, 52_750)]);
    assert_eq!(snap.at_ms, 12 * 3_600_000);
    assert!(snap.end.is_none());
    assert_eq!(snap.severe.uncovered_percent, 0.0);
    println!("Feed and bleed tank disk: {disk:?} ms");
    println!("Feed and bleed: no stage after boiling in twelve hours");
}

#[test]
fn block_valves_keep_the_core_covered_for_twelve_hours() {
    let (snap, disk) = run_to_end(
        Scenario::StuckOpenRelief,
        Some((20 * 60_000, &[Command::ReliefBlock { closed: true }])),
        12 * 3_600_000,
    );
    check_stages(&snap, &[(Stage::Boiling, 426_000, 426_000)]);
    assert_eq!(snap.at_ms, 12 * 3_600_000);
    assert!(snap.end.is_none());
    assert_eq!(snap.severe.uncovered_percent, 0.0);
    println!("Block valves tank disk: {disk:?} ms");
    println!("Block valves: no stage after boiling in twelve hours");
}

#[test]
fn bleed_without_feed_ends_at_the_floor() {
    let (snap, disk) = run_to_end(
        Scenario::LoopBUnattended,
        Some((30 * 60_000, &[Command::Relief { open: true }])),
        24 * 3_600_000,
    );
    assert_eq!(
        snap.stages,
        [
            Some(52_750),
            Some(2_934_300),
            Some(3_510_950),
            Some(3_723_800),
            Some(4_003_000),
            Some(4_048_800),
            Some(4_425_000),
            Some(5_468_750),
            None,
            Some(52_646_400),
            None,
            None
        ]
    );
    println!("Bleed without feed tank disk: {disk:?} ms");
    for stage in Stage::ALL {
        if let Some(at) = snap.stages[stage.index()] {
            println!("Bleed without feed {stage:?}: {at} ms");
        }
    }
    stage_time(
        "Core uncovered",
        snap.stages[Stage::CoreUncovered.index()].unwrap(),
        2_934_000,
        293_400,
    );
    let end = snap.end.expect("floor end");
    assert_eq!(end.stage, Stage::FloorMeltThrough);
    stage_time("Floor melt through", end.at_ms, 52_795_000, 5_279_500);
    let pressure = snap.severe.breach_pressure_mpa.unwrap();
    println!("Bleed without feed breach: {pressure} MPa; target 7.5 MPa within 10%");
    assert!((pressure - 7.5).abs() <= 0.75);
    assert!(snap.severe.containment.failure.is_none());
    assert!(
        snap.stages[Stage::HydrogenBurn.index()]
            .is_none_or(|t| t > snap.stages[Stage::VesselBreach.index()].unwrap())
    );
}

#[test]
fn blackout_relief_changes_the_end_to_a_hydrogen_burn() {
    let (snap, disk) = run_to_end(
        Scenario::StationBlackout,
        Some((20 * 60_000, &[Command::Relief { open: true }])),
        24 * 3_600_000,
    );
    assert_eq!(
        snap.stages,
        [
            Some(713_500),
            Some(2_348_350),
            Some(3_321_900),
            Some(3_552_900),
            Some(3_837_200),
            Some(3_877_950),
            Some(4_262_350),
            None,
            Some(10_520_400),
            None,
            None,
            None
        ]
    );
    println!("Blackout relief tank disk: {disk:?} ms");
    for stage in Stage::ALL {
        if let Some(at) = snap.stages[stage.index()] {
            println!("Blackout relief {stage:?}: {at} ms");
        }
    }
    stage_time(
        "Core uncovered",
        snap.stages[Stage::CoreUncovered.index()].unwrap(),
        2_348_000,
        234_800,
    );
    let end = snap.end.expect("containment end");
    assert_eq!(end.stage, Stage::ContainmentFailure);
    assert_eq!(
        snap.severe.containment.failure,
        Some(FailureCause::HydrogenBurn)
    );
    stage_time("Containment failure", end.at_ms, 10_509_000, 1_050_900);
}
