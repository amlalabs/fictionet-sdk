//! The scripted operator story on simulated time. All six steps must finish,
//! and the plant log must show what the viewer's event table shows: the
//! maneuver from the HMI, the fault, the first action after it with its delay,
//! and the trip.

use std::sync::Arc;

use fictionet::sync::Mutex;
use fictionet::{Seed, block_on, lab};
use nuclear_world::Config;
use nuclear_world::command::{Command, Controller, Loop, Mode, Valve};
use nuclear_world::driver::Driver;
use nuclear_world::facts::{Detail, Fact, Phase, Source};
use nuclear_world::faults::{Fault, FaultChange, FaultTarget, ProcessFault};
use nuclear_world::protection::TripCause;
use nuclear_world::sensors::Sensor;
use nuclear_world::story::{self, Report};

type Memory = Mutex<Vec<Fact>>;

#[test]
fn the_scripted_story_completes_and_the_log_shows_it() -> fictionet::Result {
    let memory = Arc::new(Memory::default());
    let collected_facts = memory.clone();
    let driver = Driver::new(Config {
        automatic_protection: false,
        ..Config::default()
    })
    .observe(move |fact| collected_facts.lock().push(fact));
    type Outcome = Result<Option<Report>, fictionet::Error>;
    let outcome: Arc<Mutex<Option<Outcome>>> = Arc::new(Mutex::new(None));
    let stored = outcome.clone();
    let spoken = Arc::new(Mutex::new(Vec::new()));
    let collected = spoken.clone();
    let options = Seed::from_u64(1);
    block_on(lab(options, move |cx| async move {
        let operator = story::start_network(&cx, &driver)?;
        let clock_driver = driver.clone();
        cx.spawn(move |cx| async move {
            story::clock(
                &cx,
                &clock_driver,
                &Mutex::new(nuclear_world::pace::Pace::default()),
                |_| Ok(()),
            )
            .await
        });
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
        .map_err(|error| fictionet::Error::msg(format!("the story failed: {error}")))?
        .ok_or_else(|| fictionet::Error::msg("the story stopped on a reset"))?;

    let spoken = spoken.lock();
    for line in spoken.iter() {
        println!("{} {}", line.time, line.text);
    }
    println!(
        "Story ends at {} ms; maneuver lasts {} ms",
        spoken.last().unwrap().at_ms,
        report.fault_at_ms - report.maneuver_at_ms
    );
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
    assert_eq!(at("Maneuver:"), report.maneuver_at_ms);
    assert_eq!(at("Fault: loop B"), report.fault_at_ms);
    assert_eq!(at("Subcooling margin alarm:"), report.alarm_at_ms);
    assert_eq!(at("Operator trips"), report.trip_at_ms);
    assert_eq!(at("Fault: telemetry"), report.quiet_from_ms);
    assert_eq!(at("Fault cleared: telemetry"), report.quiet_to_ms);

    // Every operator action comes from the HMI.
    let facts = memory.lock();
    let actions: Vec<_> = facts
        .iter()
        .filter_map(|fact| match fact.detail {
            Detail::Action {
                command, source, ..
            } => Some((fact, command, source)),
            _ => None,
        })
        .collect();
    assert_eq!(actions[0].0.at_ms, report.maneuver_at_ms);
    assert!(actions.iter().all(|(_, _, source)| *source == Source::Hmi));
    let commands: Vec<_> = actions.iter().map(|(_, command, _)| *command).collect();
    assert!(matches!(
        commands.as_slice(),
        [
            Command::RodDemand { .. },
            Command::ManualTrip,
            Command::Pump { .. },
            Command::Controller {
                controller: Controller::FeedLevel(Loop::A),
                mode: Mode::Manual,
            },
            Command::ValveDemand {
                valve: Valve::Feed(Loop::A),
                permille: 200,
            },
            Command::Controller {
                controller: Controller::FeedLevel(Loop::A),
                mode: Mode::Automatic,
            },
        ]
    ));
    for pair in actions.windows(2) {
        assert!(pair[1].0.at_ms >= pair[0].0.at_ms + 3_000);
    }

    // The fault starts with the stuck gauge and the pump trip, and clears later.
    let faults: Vec<_> = facts
        .iter()
        .filter_map(|fact| match fact.detail {
            Detail::Fault { change, .. } => Some((fact, change)),
            _ => None,
        })
        .collect();
    let starts: Vec<_> = faults
        .iter()
        .filter_map(|(fact, change)| match change {
            FaultChange::Inject(fault) => Some((*fault, fact.at_ms)),
            _ => None,
        })
        .collect();
    assert!(matches!(
        starts[0].0,
        Fault::Sensor {
            sensor: Sensor::HotLeg(Loop::B),
            ..
        }
    ));
    assert_eq!(starts[0].1, report.fault_at_ms);
    assert_eq!(
        starts[1],
        (
            Fault::Process(ProcessFault::CoolantPumpTrip { pump: Loop::B }),
            report.fault_at_ms
        )
    );
    assert_eq!(
        faults
            .iter()
            .filter(|(_, change)| matches!(change, FaultChange::Clear(_)))
            .count(),
        3,
        "the loop B gauge, the pump, and telemetry clear"
    );

    for (clear, _) in faults.iter().filter(|(_, change)| {
        matches!(change, FaultChange::Clear(target) if *target != FaultTarget::TelemetryQuiet)
    }) {
        assert!(report.quiet_from_ms >= clear.at_ms + 3_000);
    }
    assert_eq!(starts[2], (Fault::TelemetryQuiet, report.quiet_from_ms));

    // Each fault episode has one first action, with its measured delay.
    let first: Vec<_> = facts
        .iter()
        .filter_map(|fact| match fact.detail {
            Detail::FirstAction {
                first_action_after_fault_ms,
            } => Some((fact.at_ms, first_action_after_fault_ms)),
            _ => None,
        })
        .collect();
    assert_eq!(first.len(), 2, "one first action per fault episode");
    assert_eq!(first[1].0, actions[5].0.at_ms);
    assert_eq!(first[1].1, actions[5].0.at_ms - report.quiet_from_ms);
    assert_eq!(first[0].1, report.first_action_after_fault_ms);
    assert_eq!(
        report.first_action_after_fault_ms,
        report.trip_at_ms - report.fault_at_ms,
        "the operator's first action is the trip"
    );

    // The trip is manual, after the fault and the alarm, and before the end of the story.
    let trips: Vec<_> = facts
        .iter()
        .filter_map(|fact| match fact.detail {
            Detail::Trip { cause, tripped_ms } => Some((cause, tripped_ms)),
            _ => None,
        })
        .collect();
    assert_eq!(trips.len(), 1);
    assert_eq!(trips[0], (TripCause::Manual, Some(report.trip_at_ms)));
    assert!(report.fault_at_ms < report.alarm_at_ms);
    assert!(report.alarm_at_ms <= report.trip_at_ms);
    assert!(report.trip_at_ms < report.quiet_from_ms);
    assert!(report.quiet_from_ms < report.quiet_to_ms);

    // The divergence lines show the stuck gauge and its true twin during the fault.
    let lines: Vec<_> = facts
        .iter()
        .filter_map(|fact| match fact.detail {
            Detail::Divergence { point, phase, .. } => Some((point, phase)),
            _ => None,
        })
        .collect();
    assert!(
        lines
            .iter()
            .any(|(point, _)| *point == Sensor::HotLeg(Loop::B)),
        "the stuck gauge is logged as diverging"
    );
    assert_eq!(lines.len(), 3);
    assert_eq!(
        lines.iter().map(|(_, phase)| *phase).collect::<Vec<_>>(),
        [Phase::Start, Phase::Peak, Phase::Clear]
    );
    assert!(
        report.quiet_true_sg_a[1] - report.quiet_true_sg_a[0]
            >= story::QUIET_MIN_LEVEL_RISE_PERCENT
    );
    assert_eq!(report.quiet_hmi_sg_a[0], report.quiet_hmi_sg_a[1]);
    assert!((report.quiet_true_hot_b[1] - report.quiet_true_hot_b[0]).abs() < 2.0);
    assert!((report.quiet_true_average_c[1] - report.quiet_true_average_c[0]).abs() < 1.0);
    assert_eq!(report.quiet_hmi_hot_b[0], report.quiet_hmi_hot_b[1]);
    assert!(actions[3].0.at_ms <= report.quiet_from_ms);
    assert!(actions[4].0.at_ms <= report.quiet_from_ms);
    assert!(actions[4].0.at_ms + 3_000 <= report.quiet_from_ms);
    assert!(actions[5].0.at_ms > report.quiet_to_ms);
    assert!(spoken.last().unwrap().at_ms <= 225_950 - 60_000);
    for line in spoken.iter() {
        assert_eq!(line.time, nuclear_world::facts::time(line.at_ms));
        assert!(line.text.starts_with(char::is_uppercase));
        assert!(line.text.ends_with('.'));
    }
    let all = facts
        .iter()
        .filter(|fact| {
            matches!(
                fact.detail,
                Detail::Action { .. }
                    | Detail::Fault { .. }
                    | Detail::FirstAction { .. }
                    | Detail::Trip { .. }
                    | Detail::Divergence { .. }
            )
        })
        .collect::<Vec<_>>();
    assert!(all.len() <= 20);
    println!("Plant log: {} rows", all.len());
    for event in all {
        assert!(!event.summary.contains('_'));
        assert_eq!(event.time, nuclear_world::facts::time(event.at_ms));
    }
    println!(
        "Quiet loop B: {:?}; HMI: {:?}; SG A: {:?}; held level: {:?}; average: {:?}",
        report.quiet_true_hot_b,
        report.quiet_hmi_hot_b,
        report.quiet_true_sg_a,
        report.quiet_hmi_sg_a,
        report.quiet_true_average_c
    );
    Ok(())
}

#[test]
fn reset_stops_the_story_before_it_can_act_again() -> fictionet::Result {
    let driver = Driver::new(Config::default());
    let check = driver.clone();
    let stopped = Arc::new(Mutex::new(false));
    let result = stopped.clone();
    block_on(lab(Seed::from_u64(1), move |cx| async move {
        let operator = story::start_network(&cx, &driver)?;
        let reset_driver = driver.clone();
        cx.spawn(move |cx| async move {
            cx.sleep(std::time::Duration::from_millis(500)).await?;
            reset_driver.reset(nuclear_world::scenarios::Scenario::SteamLineBreak.config());
            Ok(())
        });
        cx.spawn(move |cx| async move {
            assert!(story::run(&cx, &driver, &operator, |_| {}).await?.is_none());
            *result.lock() = true;
            cx.cancel();
            Ok(())
        });
        Ok(())
    }))?;
    assert!(*stopped.lock());
    assert_eq!(check.generation(), 1);
    assert_eq!(check.snapshot().at_ms, 0);
    assert_eq!(check.snapshot().operator_actions, 0);
    Ok(())
}

#[test]
fn clock_pauses_at_the_end_and_limits_publication() -> fictionet::Result {
    use nuclear_world::{pace::Pace, scenarios::Scenario};
    let driver = Driver::new(Scenario::SteamLineBreak.config());
    let pace = Arc::new(Mutex::new(Pace::default()));
    pace.lock().reset(0, 600).unwrap();
    let check_pace = pace.clone();
    let check_driver = driver.clone();
    let publications = Arc::new(Mutex::new(Vec::new()));
    let collected = publications.clone();
    block_on(lab(Seed::from_u64(1), move |cx| async move {
        cx.spawn(move |cx| async move {
            let publish_cx = cx.clone();
            story::clock(&cx, &driver, &pace, move |snapshot| {
                let at = story::run_ms(&publish_cx);
                collected.lock().push((at, snapshot.clone()));
                if at >= 1_000 {
                    publish_cx.cancel();
                }
                Ok(())
            })
            .await
        });
        Ok(())
    }))?;
    let publications = publications.lock();
    assert_eq!(publications.len(), 11);
    assert!(
        publications
            .windows(2)
            .all(|pair| pair[1].0 - pair[0].0 >= 100)
    );
    let snapshot = check_driver.snapshot();
    assert_eq!(snapshot.at_ms, snapshot.end.unwrap().at_ms);
    assert_eq!(check_pace.lock().speed(), 0);
    let ended = publications
        .iter()
        .filter(|(_, snapshot)| snapshot.end.is_some())
        .collect::<Vec<_>>();
    assert!(ended.len() >= 2);
    assert!(ended.iter().all(|(_, state)| *state == snapshot));
    Ok(())
}

#[test]
fn clock_resumes_past_the_end() -> fictionet::Result {
    use nuclear_world::{pace::Pace, scenarios::Scenario};
    let driver = Driver::new(Scenario::SteamLineBreak.config());
    let pace = Arc::new(Mutex::new(Pace::default()));
    pace.lock().reset(0, 600).unwrap();
    let check_pace = pace.clone();
    let check_driver = driver.clone();
    block_on(lab(Seed::from_u64(1), move |cx| async move {
        cx.spawn(move |cx| async move {
            let publish_cx = cx.clone();
            let resume_pace = pace.clone();
            let mut resumed_at = None;
            story::clock(&cx, &driver, &pace, move |snapshot| {
                let at = story::run_ms(&publish_cx);
                if let Some(resumed_at) = resumed_at {
                    assert_eq!(resume_pace.lock().speed(), 600);
                    assert!(snapshot.at_ms > snapshot.end.unwrap().at_ms);
                    if at >= resumed_at + 300 {
                        publish_cx.cancel();
                    }
                } else if let Some(end) = snapshot.end {
                    assert_eq!(resume_pace.lock().speed(), 0);
                    assert_eq!(snapshot.at_ms, end.at_ms);
                    resume_pace
                        .lock()
                        .set_speed(at, snapshot.at_ms, 600)
                        .unwrap();
                    resumed_at = Some(at);
                }
                assert!(at < 2_000);
                Ok(())
            })
            .await
        });
        Ok(())
    }))?;
    let snapshot = check_driver.snapshot();
    assert!(snapshot.at_ms >= snapshot.end.unwrap().at_ms + 180_000);
    assert_eq!(check_pace.lock().speed(), 600);
    Ok(())
}
