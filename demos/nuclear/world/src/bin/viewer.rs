//! The Three.js control room with typed snapshots, commands, and plant facts.
//!
//! Run `cargo run -p nuclear-world --bin viewer`. The scripted operator starts
//! immediately; starting a scenario stops it. `--gate` exits after the story,
//! with a failing exit status if the story fails or is interrupted.
//!
//! `/state` streams the plant snapshot, scripted lines, and plant facts.
//! The page mounts the control boards and plant scene from `viewer/` and
//! loads pinned Three.js modules from jsDelivr, requiring browser internet
//! access. The HMI and Modbus controllers run on the simulated network.

use std::error::Error as StdError;
use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::Html,
    routing::{get, post},
};
use fictionet::{Cx, Seed};
use nuclear_world::command::{Applied, Command, FaultCommand, Rejected};
use nuclear_world::driver::Driver;
use nuclear_world::facts::{self, Fact, Source};
use nuclear_world::pace::{Pace, Reply as ScenarioReply, ScenarioCommand};
use nuclear_world::snapshot::PlantSnapshot;
use nuclear_world::{Config, story};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot, watch};

type Reply = Result<Applied, Rejected>;
type Logs = Arc<Mutex<(Vec<Fact>, Vec<story::Line>)>>;

#[derive(Clone, Serialize)]
struct View {
    plant: PlantSnapshot,
    facts: Vec<Fact>,
    story: Vec<story::Line>,
}

fn publish(state: &watch::Sender<View>, snapshot: &PlantSnapshot, logs: &Logs) {
    let logs = logs.lock().unwrap();
    state.send_replace(View {
        plant: snapshot.clone(),
        facts: logs.0.clone(),
        story: logs.1.clone(),
    });
}

enum Control {
    Plant(Command, oneshot::Sender<Reply>),
    Fault(FaultCommand, oneshot::Sender<Reply>),
    Scenario(ScenarioCommand, oneshot::Sender<ScenarioReply>),
}

/// Commands are applied by the world; a dropped world releases waiting requests.
async fn ask<R>(
    sender: mpsc::UnboundedSender<Control>,
    command: impl FnOnce(oneshot::Sender<R>) -> Control,
) -> Result<Json<R>, StatusCode> {
    let (reply, result) = oneshot::channel();
    sender
        .send(command(reply))
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    result
        .await
        .map(Json)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
}

fn router(state: watch::Receiver<View>, commands: mpsc::UnboundedSender<Control>) -> Router {
    Router::new()
        .route("/", get(|| async { Html(include_str!("../../../viewer/index.html")) }))
        .route("/viewer.mjs", get(|| async {
            ([("content-type", "text/javascript; charset=utf-8")], include_str!("../../../viewer/viewer.mjs"))
        }))
        .route("/control-room.mjs", get(|| async {
            ([("content-type", "text/javascript; charset=utf-8")], include_str!("../../../viewer/control-room.mjs"))
        }))
        .route("/control-board.mjs", get(|| async {
            ([("content-type", "text/javascript; charset=utf-8")], include_str!("../../../viewer/control-board.mjs"))
        }))
        .route("/desk-screens.mjs", get(|| async {
            ([("content-type", "text/javascript; charset=utf-8")], include_str!("../../../viewer/desk-screens.mjs"))
        }))
        .route("/board-layout.mjs", get(|| async {
            ([("content-type", "text/javascript; charset=utf-8")], include_str!("../../../viewer/board-layout.mjs"))
        }))
        .route("/room-motion.mjs", get(|| async {
            ([("content-type", "text/javascript; charset=utf-8")], include_str!("../../../viewer/room-motion.mjs"))
        }))
        .route("/look.mjs", get(|| async {
            ([("content-type", "text/javascript; charset=utf-8")], include_str!("../../../viewer/look.mjs"))
        }))
        .route("/meters.mjs", get(|| async {
            ([("content-type", "text/javascript; charset=utf-8")], include_str!("../../../viewer/meters.mjs"))
        }))
        .route("/instruments.mjs", get(|| async {
            ([("content-type", "text/javascript; charset=utf-8")], include_str!("../../../viewer/instruments.mjs"))
        }))
        .route("/knobs.mjs", get(|| async {
            ([("content-type", "text/javascript; charset=utf-8")], include_str!("../../../viewer/knobs.mjs"))
        }))
        .route("/plant-scene.mjs", get(|| async {
            ([("content-type", "text/javascript; charset=utf-8")], include_str!("../../../viewer/plant-scene.mjs"))
        }))
        .route("/viewer.css", get(|| async {
            ([("content-type", "text/css; charset=utf-8")], include_str!("../../../viewer/viewer.css"))
        }))
        .route("/control-room.css", get(|| async {
            ([("content-type", "text/css; charset=utf-8")], include_str!("../../../viewer/control-room.css"))
        }))
        .route("/api/command/plant", post(|State(tx): State<mpsc::UnboundedSender<Control>>, Json(command): Json<Command>| async move {
            ask(tx, |reply| Control::Plant(command, reply)).await
        }))
        .route("/api/command/faults", post(|State(tx): State<mpsc::UnboundedSender<Control>>, Json(command): Json<FaultCommand>| async move {
            ask(tx, |reply| Control::Fault(command, reply)).await
        }))
        .route("/api/command/scenario", post(|State(tx): State<mpsc::UnboundedSender<Control>>, Json(command): Json<ScenarioCommand>| async move {
            ask(tx, |reply| Control::Scenario(command, reply)).await
        }))
        .with_state(commands)
        .merge(fictionet::stdlib::page::state(state))
}

fn apply_plant(driver: &Driver, command: Command) -> Reply {
    match driver.apply(&driver.facts(), command) {
        Ok(applied) => {
            facts::action(&driver.facts(), command, Source::Panel, &driver.snapshot());
            Ok(applied)
        }
        Err(rejected) => {
            facts::rejected(
                &driver.facts(),
                command,
                Source::Panel,
                rejected.reason,
                driver.snapshot().at_ms,
            );
            Err(rejected)
        }
    }
}

fn apply_control(cx: &Cx, driver: &Driver, pace: &fictionet::sync::Mutex<Pace>, command: Control) {
    match command {
        Control::Plant(command, reply) => {
            let _ = reply.send(apply_plant(driver, command));
        }
        Control::Fault(command, reply) => {
            let _ = reply.send(driver.apply_fault(&driver.facts(), command));
        }
        Control::Scenario(command, reply) => {
            let applied = pace
                .lock()
                .apply(command, story::run_ms(cx), driver.snapshot().at_ms);
            if let Ok(applied) = applied
                && let Some(scenario) = applied.scenario
            {
                driver.reset(scenario.config());
                facts::reset(&driver.facts(), scenario, applied.speed);
            }
            let _ = reply.send(applied);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError>> {
    let gate = match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => false,
        [flag] if flag == "--gate" => true,
        _ => return Err("usage: cargo run -p nuclear-world --bin viewer -- [--gate]".into()),
    };
    let logs: Logs = Arc::default();
    let fact_log = logs.clone();
    let driver = Driver::new(Config {
        automatic_protection: false,
        ..Config::default()
    })
    .observe(move |fact| {
        let mut logs = fact_log.lock().unwrap();
        logs.0.push(fact);
    });
    let (state, snapshots) = watch::channel(View {
        plant: driver.snapshot(),
        facts: Vec::new(),
        story: Vec::new(),
    });
    let (commands, mut incoming) = mpsc::unbounded_channel();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    println!("Control room: http://{}", listener.local_addr()?);
    let app = router(snapshots, commands);
    let mut server = tokio::spawn(async move { axum::serve(listener, app).await });
    let (story_done, mut story_result) = oneshot::channel();
    let mut run = tokio::spawn(fictionet::run(Seed::from_u64(1), move |cx| async move {
        let pace = Arc::new(fictionet::sync::Mutex::new(Pace::default()));
        let generation = driver.generation();
        let operator = story::start_network(&cx, &driver)?;
        let clock_driver = driver.clone();
        let clock_pace = pace.clone();
        let clock_logs = logs.clone();
        let publisher = state.clone();
        cx.spawn(move |cx| async move {
            story::clock(&cx, &clock_driver, &clock_pace, move |snapshot| {
                publish(&publisher, snapshot, &clock_logs);
                Ok(())
            })
            .await
        });
        let control_driver = driver.clone();
        let control_logs = logs.clone();
        cx.spawn(move |cx| async move {
            while let Some(command) = cx.race(None, incoming.recv()).await? {
                apply_control(&cx, &control_driver, &pace, command);
                publish(&state, &control_driver.snapshot(), &control_logs);
            }
            Ok(())
        });
        cx.spawn(move |cx| async move {
            if driver.generation() != generation {
                let _ = story_done.send(Ok(None));
                return Ok(());
            }
            let report = story::run(&cx, &driver, &operator, |line| {
                println!("scripted: {} {}", line.time, line.text);
                logs.lock().unwrap().1.push(line);
            })
            .await;
            let _ = story_done.send(report.map_err(|error| error.to_string()));
            Ok(())
        });
        Ok(())
    }));

    let result: Result<(), Box<dyn StdError>> = async {
        let finished = tokio::select! {
            result = &mut story_result => result.map_err(|_| "the story stopped without a result")?,
            ended = &mut run => return Err(format!("the world ended: {ended:?}").into()),
            ended = &mut server => return Err(format!("the page server ended: {ended:?}").into()),
            signal = tokio::signal::ctrl_c() => {
                signal?;
                return if gate { Err("the story was interrupted".into()) } else { Ok(()) };
            }
        };
        match &finished {
            Ok(Some(_)) => println!("Scripted operator story complete."),
            Ok(None) => println!("Scripted operator stopped: a scenario started."),
            Err(error) => eprintln!("Scripted operator failed: {error}"),
        }
        if gate {
            return finished
                .and_then(|report| report.ok_or_else(|| "the story was stopped".into()))
                .map(|_| ())
                .map_err(Into::into);
        }
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            ended = &mut run => return Err(format!("the world ended: {ended:?}").into()),
            ended = &mut server => return Err(format!("the page server ended: {ended:?}").into()),
        }
        Ok(())
    }
    .await;
    run.abort();
    server.abort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use nuclear_world::faults::FaultChange;
    use tower_service::Service;

    async fn post_command<R: serde::de::DeserializeOwned>(
        app: &mut Router,
        path: &str,
        command: &impl Serialize,
    ) -> R {
        let response = app
            .call(
                http::Request::post(path)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(command).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_success());
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    #[tokio::test]
    async fn applied_commands_publish_state_and_stale_faults_leave_it_unchanged() {
        let driver = Driver::new(Config::default());
        let original = driver.snapshot();
        let (state, mut snapshots) = watch::channel(View {
            plant: original.clone(),
            facts: Vec::new(),
            story: Vec::new(),
        });
        let (commands, mut incoming) = mpsc::unbounded_channel();
        let mut app = router(snapshots.clone(), commands);
        let world = tokio::spawn(fictionet::run(Seed::from_u64(1), move |cx| async move {
            let pace = fictionet::sync::Mutex::new(Pace::default());
            let logs = Arc::default();
            while let Some(command) = incoming.recv().await {
                apply_control(&cx, &driver, &pace, command);
                publish(&state, &driver.snapshot(), &logs);
            }
            Ok(())
        }));
        let applied: Reply =
            post_command(&mut app, "/api/command/plant", &Command::ManualTrip).await;
        assert!(applied.is_ok());
        snapshots.changed().await.unwrap();
        let tripped = snapshots.borrow_and_update().plant.clone();
        assert!(tripped.truth.reactor.trip.is_some());
        assert!(tripped.revision > original.revision);
        let refused: Reply = post_command(
            &mut app,
            "/api/command/faults",
            &FaultCommand {
                change: FaultChange::ClearAll,
                expected_revision: original.revision,
            },
        )
        .await;
        assert!(refused.is_err());
        snapshots.changed().await.unwrap();
        assert_eq!(snapshots.borrow().plant, tripped);
        let reset: ScenarioReply = post_command(
            &mut app,
            "/api/command/scenario",
            &ScenarioCommand::Start {
                scenario: nuclear_world::scenarios::Scenario::Normal,
                speed: None,
            },
        )
        .await;
        assert!(reset.is_ok());
        snapshots.changed().await.unwrap();
        assert!(snapshots.borrow().plant.truth.reactor.trip.is_none());
        drop(app);
        world.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn commands_to_a_stopped_world_fail_without_waiting() {
        let (commands, incoming) = mpsc::unbounded_channel();
        drop(incoming);
        assert!(
            ask(commands, |reply| Control::Plant(Command::ManualTrip, reply))
                .await
                .is_err()
        );
    }
}
