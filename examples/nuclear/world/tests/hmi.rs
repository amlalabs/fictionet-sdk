//! hmi01 on the operations network. It polls the three controllers, serves the
//! mimic page and the plant's values, and carries control POSTs to the
//! controllers. The operator console is a trusted sandbox here too. An
//! ordinary sandbox on the operations subnet cannot reach hmi01 at all.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use fictionet::stdlib::network::route::Prefix;
use fictionet::stdlib::network::{ConnError, ConnectionExt};
use fictionet::stdlib::protocols::http1::{self, Header, RequestHead, Version};
use fictionet::stdlib::world::sandbox::{self, Machine};
use fictionet::sync::Mutex;
use fictionet::{Attacher, Cx, Error, RunOptions, Seed};
use nuclear_world::Config;
use nuclear_world::driver::Driver;
use nuclear_world::hmi::{self, Held};
use nuclear_world::registers::{self, Plc};
use nuclear_world::sensors::Sensor;
use serde_json::{Value, json};

const OPERATOR: Ipv4Addr = Ipv4Addr::new(10, 40, 0, 50);
const VISITOR: Ipv4Addr = Ipv4Addr::new(10, 40, 0, 52);

/// The network with hmi01 and the trusted operator console.
struct World {
    attacher: Attacher,
    operator: Machine,
    held: Arc<Mutex<Held>>,
}

fn start_world(fcx: &Cx, driver: &Driver) -> Result<World, Error> {
    start_world_with_controllers(fcx, driver, hmi::controllers())
}

fn start_world_with_controllers(
    fcx: &Cx,
    driver: &Driver,
    controllers: hmi::Controllers,
) -> Result<World, Error> {
    let (attacher, attachments) = fictionet::attachments();
    let operator_route = Prefix {
        addr: IpAddr::V4(OPERATOR),
        len: 32,
    };
    hmi::with_hmi(driver)
        .route("operator", operator_route)
        .start(fcx, attachments)?;
    let hmi_machine = sandbox::machine(fcx, attacher.attach(hmi::NAME)?, hmi::ADDR);
    let held = hmi::start(fcx, hmi_machine, controllers)?;
    let operator = sandbox::machine(fcx, attacher.attach("operator")?, OPERATOR);
    Ok(World {
        attacher,
        operator,
        held,
    })
}

fn header(name: &str, value: &str) -> Header {
    Header {
        name: name.to_owned(),
        value: value.as_bytes().to_vec(),
    }
}

fn get(target: &str) -> http1::Request {
    http1::Request {
        head: RequestHead {
            method: "GET".to_owned(),
            target: target.to_owned(),
            version: Version::Http11,
            headers: vec![header("Host", "hmi01")],
        },
        body: Vec::new(),
    }
}

fn post(target: &str, body: &Value) -> http1::Request {
    let bytes = serde_json::to_vec(body).expect("the body is JSON");
    http1::Request {
        head: RequestHead {
            method: "POST".to_owned(),
            target: target.to_owned(),
            version: Version::Http11,
            headers: vec![
                header("Host", "hmi01"),
                header("Content-Type", "application/json"),
                header("Content-Length", &bytes.len().to_string()),
            ],
        },
        body: bytes,
    }
}

/// One request on a new connection from `from`.
async fn send(fcx: &Cx, from: &Machine, request: &http1::Request) -> http1::Response {
    let to = SocketAddr::new(hmi::ADDR.into(), hmi::PORT);
    let mut conn = from
        .tcp
        .connect(fcx, to)
        .await
        .expect("hmi01 accepts HTTP on port 80");
    sandbox::request(fcx, &mut conn, request)
        .await
        .expect("hmi01 answers the request")
}

fn json_body(response: &http1::Response) -> Value {
    serde_json::from_slice(&response.body).expect("the body is JSON")
}

async fn plant(fcx: &Cx, operator: &Machine) -> Value {
    let response = send(fcx, operator, &get("/api/plant")).await;
    assert_eq!(response.head.status, 200);
    json_body(&response)
}

/// Waits for hmi01 to finish a poll cycle after the one numbered `after`, and
/// returns its view. The bound turns a hung poll into a failure.
async fn next_poll(fcx: &Cx, operator: &Machine, after: u64) -> Value {
    for _ in 0..400 {
        let view = plant(fcx, operator).await;
        if view["polls"].as_u64().unwrap_or(0) > after {
            return view;
        }
        fcx.sleep(Duration::from_millis(50))
            .await
            .expect("the run is not cancelled");
    }
    panic!("hmi01 finished no poll cycle after {after}");
}

fn value(view: &Value, reading: &str) -> f64 {
    view["readings"][reading]["value"]
        .as_f64()
        .unwrap_or_else(|| panic!("no value for {reading}: {view}"))
}

fn assert_close(actual: f64, expected: f64, tolerance: f64, what: &str) {
    assert!(
        (actual - expected).abs() <= tolerance,
        "{what}: the HMI shows {actual}, the plant has {expected}"
    );
}

#[test]
fn hmi_serves_the_mimic_page_and_its_assets() {
    let result = fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(3)),
        |fcx| async move {
            let driver = Driver::new(Config::default());
            driver.advance_to(&(), 2_000);
            let world = start_world(&fcx, &driver)?;

            let page = send(&fcx, &world.operator, &get("/")).await;
            assert_eq!(page.head.status, 200);
            assert_eq!(
                content_type(&page),
                Some("text/html; charset=utf-8".to_owned())
            );
            let html = String::from_utf8_lossy(&page.body);
            assert!(html.contains("<main id=\"hmi\""), "the page has the screen");
            assert!(html.contains("hmi.mjs"), "the page loads the script");

            let script = send(&fcx, &world.operator, &get("/hmi.mjs")).await;
            assert_eq!(script.head.status, 200);
            assert_eq!(
                content_type(&script),
                Some("text/javascript; charset=utf-8".to_owned())
            );
            let style = send(&fcx, &world.operator, &get("/hmi.css")).await;
            assert_eq!(style.head.status, 200);
            assert_eq!(
                content_type(&style),
                Some("text/css; charset=utf-8".to_owned())
            );

            let missing = send(&fcx, &world.operator, &get("/nothing")).await;
            assert_eq!(missing.head.status, 404);
            fcx.cancel();
            Ok(())
        },
    ));
    result.unwrap();
}

fn content_type(response: &http1::Response) -> Option<String> {
    response
        .head
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-type"))
        .map(|h| String::from_utf8_lossy(&h.value).into_owned())
}

#[test]
fn poll_holds_each_controller_block_and_plant_json_matches_the_snapshot() {
    let result = fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(4)),
        |fcx| async move {
            let driver = Driver::new(Config::default());
            driver.advance_to(&(), 2_000);
            let world = start_world(&fcx, &driver)?;
            let view = next_poll(&fcx, &world.operator, 0).await;

            for reading in view["readings"].as_object().unwrap().values() {
                assert!(!reading["tag"].as_str().unwrap().is_empty());
            }
            assert_eq!(
                view["plant_time"],
                hmi::plant_time(view["clock_ms"].as_u64().unwrap())
            );
            assert!(
                view["links"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|link| link["error"].is_null())
            );
            let trend = send(
                &fcx,
                &world.operator,
                &get("/api/trend?point=neutron_power&minutes=10"),
            )
            .await;
            assert_eq!(trend.head.status, 200);
            let trend = json_body(&trend);
            assert_eq!(trend["point"], "neutron_power");
            let samples = trend["samples"].as_array().unwrap();
            assert!(!samples.is_empty());
            assert_eq!(
                samples.last().unwrap()["value"],
                view["readings"]["neutron_power"]["value"]
            );
            assert!(samples[0]["clock_ms"].is_u64());
            for query in ["", "&minutes=no", "&minutes=0", "&minutes=-1"] {
                let reply = send(
                    &fcx,
                    &world.operator,
                    &get(&format!("/api/trend?point=neutron_power{query}")),
                )
                .await;
                assert_eq!(reply.head.status, 200);
                assert!(!json_body(&reply)["samples"].as_array().unwrap().is_empty());
            }
            let missing = send(&fcx, &world.operator, &get("/api/trend?point=missing")).await;
            assert_eq!(missing.head.status, 404);
            let snapshot = driver.snapshot();
            // The blocks the HMI holds are the controllers' own blocks.
            {
                let held = world.held.lock();
                for plc in [Plc::Rps1, Plc::Rcs1, Plc::Bop1] {
                    let block = &held.blocks[match plc {
                        Plc::Rps1 => 0,
                        Plc::Rcs1 => 1,
                        Plc::Bop1 => 2,
                    }];
                    assert!(block.online, "{plc:?} is online");
                    assert_eq!(
                        block.input,
                        registers::input_registers(plc, &snapshot),
                        "{plc:?} input registers"
                    );
                    assert_eq!(
                        block.discrete,
                        registers::discrete_inputs(plc, &snapshot),
                        "{plc:?} discrete inputs"
                    );
                    assert_eq!(
                        block.coils,
                        registers::coils(plc, &snapshot),
                        "{plc:?} coils"
                    );
                    assert_eq!(
                        block.holding,
                        registers::holding_registers(plc, &snapshot),
                        "{plc:?} holding registers"
                    );
                }
            }

            // Engineering values agree with the plant's own readings, to one
            // instrument count.
            let reading = |sensor: Sensor| snapshot.readings[sensor.index()].reading.value;
            assert!(view["readings"].get("reactivity").is_none());
            assert_close(
                value(&view, "shutdown_rods"),
                reading(Sensor::ShutdownRodPosition),
                0.05,
                "shutdown rods",
            );
            assert_eq!(world.held.lock().blocks[0].input.len(), 5);
            assert_eq!(
                world.held.lock().blocks[0].input[4],
                snapshot.telemetry.heartbeat
            );
            assert_close(
                value(&view, "pressurizer_pressure"),
                reading(Sensor::PressurizerPressure),
                0.005,
                "pressurizer pressure",
            );
            assert_close(
                value(&view, "neutron_power"),
                reading(Sensor::NeutronPower),
                0.05,
                "neutron power",
            );
            assert_close(
                value(&view, "hot_leg_a"),
                reading(Sensor::HotLeg(nuclear_world::command::Loop::A)),
                0.05,
                "hot leg A",
            );
            assert_close(
                value(&view, "pressurizer_pressure"),
                15.5,
                0.05,
                "pressurizer pressure near 15.5 MPa at full power",
            );
            assert_close(
                value(&view, "neutron_power"),
                100.0,
                1.0,
                "neutron power near 100 %",
            );

            assert_eq!(view["status"]["reactor_tripped"], json!(false));
            assert_eq!(view["status"]["coolant_pump_a"], json!(true));
            assert_eq!(view["modes"]["pressurizer"], json!("automatic"));
            assert_eq!(view["links"][1]["online"], json!(true));
            assert_eq!(
                view["readings"]["pressurizer_pressure"]["unit"],
                json!("MPa")
            );
            assert_eq!(
                view["readings"]["pressurizer_pressure"]["stale"],
                json!(false)
            );
            // No alarm is active at steady full power.
            for alarm in view["alarms"].as_array().expect("an alarm list") {
                assert_eq!(alarm["state"], json!("normal"), "{alarm}");
            }
            fcx.cancel();
            Ok(())
        },
    ));
    result.unwrap();
}

#[test]
fn a_control_post_changes_the_plant_and_the_next_poll_shows_it() {
    let result = fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(5)),
        |fcx| async move {
            let driver = Driver::new(Config::default());
            driver.advance_to(&(), 2_000);
            let world = start_world(&fcx, &driver)?;
            let before = next_poll(&fcx, &world.operator, 0).await;
            assert_eq!(
                value(&before, "rod_demand"),
                50.0,
                "full power starts at 50 %"
            );

            let posted = send(
                &fcx,
                &world.operator,
                &post("/api/control/rod-demand", &json!({ "percent": 40.0 })),
            )
            .await;
            assert_eq!(
                posted.head.status,
                200,
                "{}",
                String::from_utf8_lossy(&posted.body)
            );
            assert_eq!(json_body(&posted), json!({ "ok": true }));
            assert_eq!(
                driver.snapshot().operator_actions,
                1,
                "one accepted operator action"
            );

            driver.advance_to(&(), 6_000);
            let after =
                next_poll(&fcx, &world.operator, before["polls"].as_u64().unwrap_or(0)).await;
            assert_eq!(
                value(&after, "rod_demand"),
                40.0,
                "the next poll holds the new demand"
            );
            let snapshot = driver.snapshot();
            assert_eq!(snapshot.truth.reactor.rod_demand_percent, 40.0);
            assert_close(
                value(&after, "neutron_power"),
                snapshot.readings[Sensor::NeutronPower.index()]
                    .reading
                    .value,
                0.05,
                "neutron power after the rods move",
            );
            assert!(
                value(&after, "neutron_power") < value(&before, "neutron_power"),
                "inserted rods lower the power"
            );
            fcx.cancel();
            Ok(())
        },
    ));
    result.unwrap();
}

#[test]
fn a_refused_control_comes_back_as_the_controllers_exception() {
    let result = fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(6)),
        |fcx| async move {
            let driver = Driver::new(Config::default());
            driver.advance_to(&(), 2_000);
            let world = start_world(&fcx, &driver)?;
            next_poll(&fcx, &world.operator, 0).await;

            // Feed valve A is under automatic control, so the controller
            // refuses a demand for it: illegal data value, code 3.
            let refused = send(
                &fcx,
                &world.operator,
                &post(
                    "/api/control/valve",
                    &json!({ "name": "feed-a", "percent": 30.0 }),
                ),
            )
            .await;
            assert_eq!(refused.head.status, 400);
            let body = json_body(&refused);
            assert_eq!(body["ok"], json!(false));
            assert_eq!(body["exception"], json!(3));
            assert_eq!(body["reason"], json!("illegal data value"));
            assert_eq!(
                driver.snapshot().operator_actions,
                0,
                "a refused write is no action"
            );

            let unknown = send(
                &fcx,
                &world.operator,
                &post("/api/control/shutdown", &json!({})),
            )
            .await;
            assert_eq!(unknown.head.status, 400);
            fcx.cancel();
            Ok(())
        },
    ));
    result.unwrap();
}

#[test]
fn a_pump_stop_shows_in_status_and_its_alarm_clears_on_acknowledge() {
    let result = fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(7)),
        |fcx| async move {
            let driver = Driver::new(Config::default());
            driver.advance_to(&(), 2_000);
            let world = start_world(&fcx, &driver)?;
            let before = next_poll(&fcx, &world.operator, 0).await;

            let stop = send(
                &fcx,
                &world.operator,
                &post(
                    "/api/control/pump",
                    &json!({ "name": "coolant-b", "running": false }),
                ),
            )
            .await;
            assert_eq!(stop.head.status, 200);
            driver.advance_to(&(), 4_000);
            let stopped =
                next_poll(&fcx, &world.operator, before["polls"].as_u64().unwrap_or(0)).await;
            assert_eq!(stopped["status"]["coolant_pump_b"], json!(false));
            assert_eq!(alarm_state(&stopped, "coolant_pump_stopped"), "active");
            let in_time = stopped["alarms"]
                .as_array()
                .unwrap()
                .iter()
                .find(|a| a["id"] == "coolant_pump_stopped")
                .unwrap()["in_ms"]
                .clone();
            assert_eq!(in_time, stopped["clock_ms"]);

            let ack = send(
                &fcx,
                &world.operator,
                &post("/api/control/acknowledge", &json!({})),
            )
            .await;
            assert_eq!(ack.head.status, 200);
            let acknowledged = next_poll(
                &fcx,
                &world.operator,
                stopped["polls"].as_u64().unwrap_or(0),
            )
            .await;
            assert_eq!(
                alarm_state(&acknowledged, "coolant_pump_stopped"),
                "acknowledged"
            );
            assert_eq!(
                acknowledged["alarms"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|a| a["id"] == "coolant_pump_stopped")
                    .unwrap()["in_ms"],
                in_time
            );
            assert_eq!(
                driver.snapshot().operator_actions,
                2,
                "stop and acknowledge"
            );
            fcx.cancel();
            Ok(())
        },
    ));
    result.unwrap();
}

fn alarm_state<'a>(view: &'a Value, id: &str) -> &'a str {
    view["alarms"]
        .as_array()
        .and_then(|alarms| alarms.iter().find(|a| a["id"] == json!(id)))
        .and_then(|a| a["state"].as_str())
        .unwrap_or_else(|| panic!("no alarm {id} in {view}"))
}

#[test]
fn an_ordinary_sandbox_cannot_reach_hmi01() {
    let result = fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(8)),
        |fcx| async move {
            let driver = Driver::new(Config::default());
            driver.advance_to(&(), 2_000);
            let world = start_world(&fcx, &driver)?;
            let visitor = sandbox::machine(&fcx, world.attacher.attach("visitor")?, VISITOR);
            // Packets to the operations subnet, other than the gateway's, are
            // dropped by the sandbox filter, so the connection never opens.
            let refused = visitor
                .tcp
                .connect(&fcx, SocketAddr::new(hmi::ADDR.into(), hmi::PORT))
                .await
                .err();
            assert_eq!(
                refused,
                Some(ConnError::TimedOut),
                "the SYN is dropped, so the visitor never reaches hmi01"
            );
            fcx.cancel();
            Ok(())
        },
    ));
    result.unwrap();
}

#[test]
fn telemetry_heartbeats_hold_across_polls_and_resume_after_clearing() {
    use nuclear_world::command::FaultCommand;
    use nuclear_world::faults::{Fault, FaultChange, FaultTarget};
    fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(9)),
        |fcx| async move {
            let driver = Driver::new(Config::default());
            driver.advance_to(&(), 2_000);
            let world = start_world(&fcx, &driver)?;
            let before = next_poll(&fcx, &world.operator, 0).await;
            let counts = |view: &Value| {
                view["links"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|link| link["heartbeat"].as_u64().unwrap())
                    .collect::<Vec<_>>()
            };
            let held_counts = counts(&before);
            assert_eq!(
                held_counts,
                vec![u64::from(driver.snapshot().telemetry.heartbeat); 3]
            );
            driver
                .apply_fault(
                    &fcx,
                    FaultCommand {
                        change: FaultChange::Inject(Fault::TelemetryQuiet),
                        expected_revision: driver.snapshot().revision,
                    },
                )
                .unwrap();
            let mut polls = before["polls"].as_u64().unwrap();
            for at_ms in [3_000, 4_000, 5_000, 6_000] {
                driver.advance_to(&(), at_ms);
                let view = next_poll(&fcx, &world.operator, polls).await;
                let next = view["polls"].as_u64().unwrap();
                assert!(next > polls);
                assert_eq!(counts(&view), held_counts);
                polls = next;
            }
            assert_eq!(driver.snapshot().at_ms, 6_000);
            driver
                .apply_fault(
                    &fcx,
                    FaultCommand {
                        change: FaultChange::Clear(FaultTarget::TelemetryQuiet),
                        expected_revision: driver.snapshot().revision,
                    },
                )
                .unwrap();
            driver.advance_to(&(), 7_000);
            let resumed = next_poll(&fcx, &world.operator, polls).await;
            assert!(
                counts(&resumed)
                    .iter()
                    .zip(&held_counts)
                    .all(|(a, b)| a > b)
            );
            fcx.cancel();
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn site_clock_follows_elapsed_time_across_civil_boundaries() {
    assert_eq!(hmi::plant_time(0), "2026-03-14T08:00:00.000Z");
    assert_eq!(hmi::plant_time(12_500), "2026-03-14T08:00:12.500Z");
    assert_eq!(hmi::plant_time(16 * 3_600_000), "2026-03-15T00:00:00.000Z");
    assert_eq!(hmi::plant_time(18 * 86_400_000), "2026-04-01T08:00:00.000Z");
    assert_eq!(
        hmi::plant_time(293 * 86_400_000),
        "2027-01-01T08:00:00.000Z"
    );
    assert_eq!(
        hmi::plant_time(717 * 86_400_000),
        "2028-02-29T08:00:00.000Z"
    );
    assert_eq!(
        hmi::plant_time(718 * 86_400_000),
        "2028-03-01T08:00:00.000Z"
    );
}

#[test]
fn history_is_bounded_and_failed_reads_are_gaps() {
    let mut held = Held::default();
    held.blocks[0].online = true;
    held.blocks[0].read_ms = Some(0);
    held.blocks[0].input = vec![1000; 5];
    for n in 0..hmi::HISTORY_CAPACITY + 7 {
        held.clock_ms = Some(n as u64 * hmi::POLL_MS);
        held.sample();
    }
    let samples = held.trend("neutron_power", 10).unwrap();
    assert_eq!(samples.len(), hmi::HISTORY_CAPACITY);
    assert_eq!(samples[0].clock_ms, 7 * hmi::POLL_MS);
    assert_eq!(samples[0].value, Some(100.0));
    let recent = held.trend("neutron_power", 1).unwrap();
    assert_eq!(recent.len(), 241);
    assert_eq!(recent[0].clock_ms, held.clock_ms.unwrap() - 60_000);
    held.blocks[0].online = false;
    held.clock_ms = held.clock_ms.map(|time| time + hmi::POLL_MS);
    held.sample();
    assert_eq!(
        held.trend("neutron_power", 10)
            .unwrap()
            .last()
            .unwrap()
            .value,
        None
    );
    assert!(held.trend("missing", 10).is_none());
}

#[test]
fn failed_controller_links_serve_classified_reasons() {
    fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(10)),
        |fcx| async move {
            let driver = Driver::new(Config::default());
            let mut controllers = hmi::controllers();
            controllers.rcs1.set_port(5999);
            controllers.bop1 = SocketAddr::new(OPERATOR.into(), 5998);
            controllers
                .rps1
                .set_ip(Ipv4Addr::new(192, 168, 95, 99).into());
            let (attacher, attachments) = fictionet::attachments();
            hmi::with_hmi(&driver)
                .route(
                    "operator",
                    Prefix {
                        addr: OPERATOR.into(),
                        len: 32,
                    },
                )
                .route(
                    "disconnected-controller",
                    Prefix {
                        addr: controllers.rps1.ip(),
                        len: 32,
                    },
                )
                .start(&fcx, attachments)?;
            let _disconnected = attacher.attach("disconnected-controller")?;
            let machine = sandbox::machine(&fcx, attacher.attach(hmi::NAME)?, hmi::ADDR);
            hmi::start(&fcx, machine, controllers)?;
            let operator = sandbox::machine(&fcx, attacher.attach("operator")?, OPERATOR);
            let mut listener = operator.tcp.listen(5998)?;
            fcx.spawn(move |fcx| async move {
                let mut conn = listener.accept(&fcx).await?;
                let mut request = [0; 64];
                conn.read(&fcx, &mut request).await?;
                conn.write_all(&fcx, &[0, 1, 0, 1, 0, 2, 1, 3]).await?;
                Ok(())
            });
            let view = next_poll(&fcx, &operator, 0).await;
            assert_eq!(view["links"][0]["error"], "timeout");
            assert_eq!(view["links"][1]["error"], "refused");
            assert_eq!(view["links"][0]["online"], false);
            assert_eq!(view["links"][1]["online"], false);
            assert_eq!(view["links"][2]["error"], "bad reply");
            assert_eq!(view["links"][2]["online"], false);
            fcx.cancel();
            Ok(())
        },
    ))
    .unwrap();
}
