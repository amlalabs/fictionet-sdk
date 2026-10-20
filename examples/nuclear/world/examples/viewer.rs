//! The control room viewer: the plant on the wall clock, the operator network,
//! the scripted story, and a control room page on the loopback interface.
//!
//! Run `cargo run --example viewer` and open the printed address. Plant time is
//! run time, so one plant second is one second. The scripted story starts at
//! once. It reads hmi01 and publishes its steps in the first inspector panel.
//! Page moments mark the plant actions and faults. Ctrl-C stops the viewer.
//!
//! `--gate` ends the run when the story completes. The exit status is nonzero
//! when the story fails, so CI and the screenshot runs can wait for it.
//!
//! The page loads Three.js from the browser libraries. Run
//! `cargo xtask demo libraries` before building, or the 3D boards report it.

use std::error::Error as StdError;
use std::time::Duration;

use fictionet::{Cx, RunOptions, Seed};
use fictionet_observe::page::{
    Column, CommandLimits, CommandPort, EventFilter, Format, Page, StateLimits, StateTopic,
};
use fictionet_observe::{DashboardObserver, DashboardOptions};
use nuclear_world::command::{Applied, Command, FaultCommand, Rejected};
use nuclear_world::driver::Driver;
use nuclear_world::facts::{self, Source};
use nuclear_world::snapshot::PlantSnapshot;
use nuclear_world::{Config, story};

/// The reply to a plant or fault command: what the plant accepted, or why it refused.
type Reply = Result<Applied, Rejected>;

const JS: &str = "text/javascript; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";

const CONTROL_ROOM: &str = include_str!("../../viewer/control-room.mjs");
const CONTROL_BOARD: &str = include_str!("../../viewer/control-board.mjs");
const BOARD_LAYOUT: &str = include_str!("../../viewer/board-layout.mjs");
const ROOM_MOTION: &str = include_str!("../../viewer/room-motion.mjs");
const INSTRUMENTS: &str = include_str!("../../viewer/instruments.mjs");
const KNOBS: &str = include_str!("../../viewer/knobs.mjs");
const PLANT_SCENE: &str = include_str!("../../viewer/plant-scene.mjs");
const VIEWER_CSS: &str = include_str!("../../viewer/viewer.css");
const CONTROL_ROOM_CSS: &str = include_str!("../../viewer/control-room.css");

/// The module the page loads for the control room. A custom panel gets only its
/// module, state and title, so this entry adds the two command paths the knobs
/// post to, and the stylesheets the panel needs.
const ENTRY: &str = r#"import { mount as mountRoom } from '../assets/nuclear/control-room.mjs';

for (const href of ['/assets/nuclear/viewer.css', '/assets/nuclear/control-room.css']) {
  if (!document.querySelector(`link[href="${href}"]`)) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = href;
    document.head.append(link);
  }
}

export function mount(root, services, options) {
  return mountRoom(root, services, {
    ...options,
    command: '/api/command/plant',
    faults: '/api/command/faults',
  });
}
"#;

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError>> {
    let gate = gate_flag()?;
    let driver = Driver::new(Config {
        automatic_protection: false,
        ..Config::default()
    });
    let dashboard = DashboardObserver::new(DashboardOptions::demo());
    let state = StateTopic::<PlantSnapshot>::new(StateLimits::default());
    let lines_topic = StateTopic::<Vec<story::Line>>::new(StateLimits::default());
    let plant = CommandPort::<Command, Reply>::new(CommandLimits::default());
    let faults = CommandPort::<FaultCommand, Reply>::new(CommandLimits::default());
    let log = EventFilter {
        source: Some("plant".into()),
        ..EventFilter::default()
    };
    let server = Page::new("Nuclear unit 1 control room", dashboard.handle())
        .custom("Control room", ENTRY, state.clone())
        .workspace("Control room")
        .command("plant", plant.clone())
        .command("faults", faults.clone())
        .table(
            "Scripted operator",
            lines_topic.clone(),
            vec![
                Column::new("Plant ms", "/at_ms").format(Format::Number),
                Column::new("Step", "/step").format(Format::Number),
                Column::new("Text", "/text"),
            ],
        )
        .inspector_first("Scripted operator")
        .event_table("Plant log", log, plant_log_columns())
        .moment(
            "Maneuver",
            moment("action", Some(("command", "rod_demand"))),
        )
        .moment(
            "Stuck gauge",
            moment("fault", Some(("target", "hot_leg_b"))),
        )
        .moment("First action", moment("first_action", None))
        .moment("Reactor trip", moment("trip", None))
        .moment(
            "Telemetry quiet",
            moment("fault", Some(("target", "telemetry_quiet"))),
        )
        .asset("nuclear/control-room.mjs", JS, CONTROL_ROOM)
        .asset("nuclear/control-board.mjs", JS, CONTROL_BOARD)
        .asset("nuclear/board-layout.mjs", JS, BOARD_LAYOUT)
        .asset("nuclear/room-motion.mjs", JS, ROOM_MOTION)
        .asset("nuclear/instruments.mjs", JS, INSTRUMENTS)
        .asset("nuclear/knobs.mjs", JS, KNOBS)
        .asset("nuclear/plant-scene.mjs", JS, PLANT_SCENE)
        .asset("nuclear/viewer.css", CSS, VIEWER_CSS)
        .asset("nuclear/control-room.css", CSS, CONTROL_ROOM_CSS)
        .bind_loopback(0)
        .await?;
    println!("Control room: {}", server.url());
    println!("Scripted operator story: automatic protection is off.");

    let (story_done, mut story_result) = tokio::sync::oneshot::channel();
    let mut run = tokio::spawn(fictionet::run(
        RunOptions::new(Seed::from_u64(1)).observer(dashboard.observer()),
        move |cx| async move {
            let operator = story::start_network(&cx, &driver)?;

            let clock_driver = driver.clone();
            let publisher = state.clone();
            let publish_cx = cx.clone();
            cx.spawn(move |cx| async move {
                story::clock(&cx, &clock_driver, move |snapshot| {
                    publisher
                        .publish(publish_cx.now(), snapshot)
                        .map(|_| ())
                        .map_err(|error| {
                            fictionet::Error::msg(format!(
                                "the control room state did not publish: {error:?}"
                            ))
                        })
                })
                .await
            });

            let plant_driver = driver.clone();
            cx.spawn(move |cx| async move {
                while let Some(command) = cx.race(None, plant.recv()).await? {
                    let reply = apply_plant(&cx, &plant_driver, command.command);
                    command.reply(&cx, reply);
                }
                Ok(())
            });

            let fault_driver = driver.clone();
            cx.spawn(move |cx| async move {
                while let Some(command) = cx.race(None, faults.recv()).await? {
                    let reply = fault_driver.apply_fault(&cx, command.command);
                    command.reply(&cx, reply);
                }
                Ok(())
            });

            let story_driver = driver.clone();
            cx.spawn(move |cx| async move {
                let mut lines = Vec::new();
                let mut publish_error = None;
                let report = story::run(&cx, &story_driver, &operator, |line| {
                    println!(
                        "scripted: {:>7.1} s  step {}  {}",
                        line.at_ms as f64 / 1000.0,
                        line.step,
                        line.text
                    );
                    lines.push(line);
                    if let Err(error) = lines_topic.publish(cx.now(), &lines) {
                        publish_error = Some(fictionet::Error::msg(format!(
                            "the operator lines did not publish: {error:?}"
                        )));
                    }
                })
                .await
                .and_then(|report| publish_error.map_or(Ok(report), Err));
                let _ = story_done.send(report.map_err(|error| error.to_string()));
                Ok(())
            });
            Ok(())
        },
    ));

    let finished = tokio::select! {
        result = &mut story_result => {
            result.map_err(|_| "the story stopped without a result")?
        }
        ended = &mut run => return Err(run_ended(ended)),
    };
    match &finished {
        Ok(report) => println!(
            "scripted story complete: fault at {:.1} s, trip at {:.1} s, first action {:.1} s after the fault, telemetry quiet from {:.1} s to {:.1} s",
            report.fault_at_ms as f64 / 1000.0,
            report.trip_at_ms as f64 / 1000.0,
            report.first_action_after_fault_ms as f64 / 1000.0,
            report.quiet_from_ms as f64 / 1000.0,
            report.quiet_to_ms as f64 / 1000.0,
        ),
        Err(error) => eprintln!("scripted story failed: {error}"),
    }

    if gate {
        server.shutdown(Duration::from_secs(2)).await;
        run.abort();
        return finished.map(|_| ()).map_err(Into::into);
    }
    println!("Serving the control room until Ctrl-C.");
    tokio::select! {
        result = tokio::signal::ctrl_c() => result?,
        ended = &mut run => return Err(run_ended(ended)),
    }
    server.shutdown(Duration::from_secs(2)).await;
    run.abort();
    Ok(())
}

/// Applies a plant command from the control room. An accepted action is logged
/// with source `panel`, and a refusal is logged with its reason.
fn apply_plant(cx: &Cx, driver: &Driver, command: Command) -> Reply {
    match driver.apply(cx, command) {
        Ok(applied) => {
            facts::action(cx, command, Source::Panel, &driver.snapshot());
            Ok(applied)
        }
        Err(rejected) => {
            let at_ms = driver.snapshot().at_ms;
            facts::rejected(cx, command, Source::Panel, rejected.reason, at_ms);
            Err(rejected)
        }
    }
}

fn moment(kind: &str, field: Option<(&str, &str)>) -> EventFilter {
    EventFilter {
        source: Some("plant".into()),
        kind: Some(kind.into()),
        field: field.map(|(key, value)| (key.into(), value.into())),
        ..EventFilter::default()
    }
}

fn plant_log_columns() -> Vec<Column> {
    vec![
        Column::new("Plant ms", "/fields/at_ms").format(Format::Number),
        Column::new("Kind", "/kind"),
        Column::new("Event", "/summary"),
    ]
}

fn gate_flag() -> Result<bool, Box<dyn StdError>> {
    match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => Ok(false),
        [flag] if flag == "--gate" => Ok(true),
        _ => Err("usage: cargo run --example viewer -- [--gate]".into()),
    }
}

/// The error for a run that ended while the viewer waited on the story.
fn run_ended(ended: Result<fictionet::Result, tokio::task::JoinError>) -> Box<dyn StdError> {
    match ended {
        Ok(Ok(())) => "the run ended before the story finished".into(),
        Ok(Err(error)) => format!("the run failed: {error}").into(),
        Err(error) => format!("the run task failed: {error}").into(),
    }
}
