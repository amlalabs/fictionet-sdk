//! The scripted operator story on simulated time. All six steps must finish,
//! and the plant log must show what the viewer's event table shows: the
//! maneuver from the HMI, the fault, the first action after it with its delay,
//! and the trip.

use std::sync::Arc;

use fictionet::sync::Mutex;
use fictionet::{RunOptions, Seed, block_on, lab};
use fictionet_observe::Memory;
use nuclear_world::Config;
use nuclear_world::driver::Driver;
use nuclear_world::story::{self, Report};

#[test]
fn the_scripted_story_completes_and_the_log_shows_it() -> fictionet::Result {
    let memory = Arc::new(Memory::default());
    let driver = Driver::new(Config {
        automatic_protection: false,
        ..Config::default()
    });
    let outcome: Arc<Mutex<Option<Result<Report, fictionet::Error>>>> = Arc::new(Mutex::new(None));
    let stored = outcome.clone();
    let spoken = Arc::new(Mutex::new(Vec::new()));
    let collected = spoken.clone();
    let options = RunOptions::new(Seed::from_u64(1)).observer(memory.clone());
    block_on(lab(options, move |cx| async move {
        let operator = story::start_network(&cx, &driver)?;
        let clock_driver = driver.clone();
        cx.spawn(move |cx| async move { story::clock(&cx, &clock_driver, |_| Ok(())).await });
        let story_driver = driver.clone();
        cx.spawn(move |cx| async move {
            let report = story::run(&cx, &story_driver, &operator, |line| {
                collected.lock().push(line)
            })
            .await;
            *stored.lock() = Some(report);
            cx.cancel();
            Ok(())
        });
        Ok(())
    }))?;

    let report = outcome
        .lock()
        .take()
        .ok_or_else(|| fictionet::Error::msg("the story did not finish"))?
        .map_err(|error| fictionet::Error::msg(format!("the story failed: {error}")))?;

    let spoken = spoken.lock();
    assert!(spoken.windows(2).all(|pair| pair[0].at_ms <= pair[1].at_ms));
    let mut steps: Vec<_> = spoken.iter().map(|line| line.step).collect();
    steps.dedup();
    assert_eq!(steps, vec![1, 2, 3, 4, 5, 6]);
    let at = |prefix: &str| {
        spoken
            .iter()
            .find(|line| line.text.starts_with(prefix))
            .unwrap()
            .at_ms
    };
    assert_eq!(at("maneuver:"), report.maneuver_at_ms);
    assert_eq!(at("fault: loop B"), report.fault_at_ms);
    assert_eq!(at("subcooling margin alarm:"), report.alarm_at_ms);
    assert_eq!(at("operator trips"), report.trip_at_ms);
    assert_eq!(at("fault: telemetry"), report.quiet_from_ms);
    assert_eq!(at("fault cleared: telemetry"), report.quiet_to_ms);

    // The maneuver, the trip, and the auxiliary feed start all come from the HMI.
    let actions = memory.checked_of("plant", "action")?;
    assert_eq!(actions[0].u64("at_ms"), Some(report.maneuver_at_ms));
    let commands: Vec<_> = actions
        .iter()
        .map(|a| (a.str("command"), a.str("source")))
        .collect();
    assert_eq!(
        commands,
        vec![
            (Some("rod_demand"), Some("hmi")),
            (Some("manual_trip"), Some("hmi")),
            (Some("pump"), Some("hmi")),
        ],
        "the operator's three commands, all from the HMI"
    );

    // The fault starts with the stuck gauge and the pump trip, and clears later.
    let faults = memory.checked_of("plant", "fault")?;
    let starts: Vec<_> = faults
        .iter()
        .filter(|f| f.str("change") == Some("inject"))
        .map(|f| (f.str("target"), f.u64("at_ms")))
        .collect();
    assert_eq!(starts[0], (Some("hot_leg_b"), Some(report.fault_at_ms)));
    assert_eq!(
        starts[1],
        (Some("coolant_pump_trip_b"), Some(report.fault_at_ms))
    );
    assert_eq!(
        faults
            .iter()
            .filter(|f| f.str("change") == Some("clear"))
            .count(),
        3,
        "the loop B gauge, the pump, and telemetry clear"
    );

    for clear in faults
        .iter()
        .filter(|f| f.str("change") == Some("clear") && f.str("target") != Some("telemetry_quiet"))
    {
        assert!(report.quiet_from_ms >= clear.u64("at_ms").unwrap() + 3_000);
    }
    assert_eq!(
        starts[2],
        (Some("telemetry_quiet"), Some(report.quiet_from_ms))
    );

    // One first action after the fault, with the delay the report gives.
    let first = memory.checked_of("plant", "first_action")?;
    assert_eq!(first.len(), 1, "one first action per fault start");
    assert_eq!(
        first[0].u64("first_action_after_fault_ms"),
        Some(report.first_action_after_fault_ms)
    );
    assert_eq!(
        report.first_action_after_fault_ms,
        report.trip_at_ms - report.fault_at_ms,
        "the operator's first action is the trip"
    );

    // The trip is manual, after the fault and the alarm, and before the end of the story.
    let trips = memory.checked_of("plant", "trip")?;
    assert_eq!(trips.len(), 1);
    assert_eq!(trips[0].str("cause"), Some("manual"));
    assert_eq!(trips[0].u64("tripped_ms"), Some(report.trip_at_ms));
    assert!(report.fault_at_ms < report.alarm_at_ms);
    assert!(report.alarm_at_ms <= report.trip_at_ms);
    assert!(report.trip_at_ms < report.quiet_from_ms);
    assert!(report.quiet_from_ms < report.quiet_to_ms);

    // The divergence lines show the stuck gauge and its true twin during the fault.
    let lines = memory.checked_of("plant", "divergence")?;
    assert!(
        lines
            .iter()
            .any(|line| line.str("point") == Some("hot_leg_b")),
        "the stuck gauge is logged as diverging"
    );
    Ok(())
}
