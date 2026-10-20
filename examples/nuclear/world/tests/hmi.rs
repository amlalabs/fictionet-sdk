//! hmi01 on the operations network. It polls the four controllers, serves the
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
    start_world_at(fcx, driver, controllers, hmi::Site::default())
}

fn start_world_at(
    fcx: &Cx,
    driver: &Driver,
    controllers: hmi::Controllers,
    site: hmi::Site,
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
    let held = hmi::start(fcx, hmi_machine, controllers, site, driver)?;
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
    send_at(fcx, from, request, hmi::Site::default()).await
}

async fn send_at(
    fcx: &Cx,
    from: &Machine,
    request: &http1::Request,
    site: hmi::Site,
) -> http1::Response {
    let to = SocketAddr::new(hmi::ADDR.into(), hmi::PORT);
    let mut conn = from
        .tcp
        .connect(fcx, to)
        .await
        .expect("hmi01 accepts HTTP on port 80");
    let before = fcx.now().since_start().as_millis() as i64;
    let response = sandbox::request(fcx, &mut conn, request)
        .await
        .expect("hmi01 answers the request");
    let after = fcx.now().since_start().as_millis() as i64;
    let header = |name: &str| {
        response
            .head
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| String::from_utf8(h.value.clone()).unwrap())
            .unwrap_or_else(|| panic!("missing {name} header"))
    };
    assert_eq!(header("Server"), "GoAhead-Webs");
    let expected_date = |at| {
        let time = hmi::Site {
            utc_offset_seconds: 0,
            ..site
        }
        .timestamp(at);
        format!("Sat, 14 Mar 2026 {} GMT", &time[11..19])
    };
    let date = header("Date");
    assert!(
        date == expected_date(before) || date == expected_date(after),
        "{date}"
    );
    for text in std::iter::once(String::from_utf8_lossy(&response.body).into_owned()).chain(
        response
            .head
            .headers
            .iter()
            .map(|h| String::from_utf8_lossy(&h.value).into_owned()),
    ) {
        for forbidden in [
            "clock_ms",
            "read_ms",
            "in_ms",
            "\"polls\"",
            "Elapsed ",
            "last poll ",
            "simulator",
            "evaluation",
        ] {
            assert!(!text.contains(forbidden), "served {forbidden}");
        }
    }
    response
}

fn json_body(response: &http1::Response) -> Value {
    serde_json::from_slice(&response.body).expect("the body is JSON")
}

async fn plant(fcx: &Cx, operator: &Machine) -> Value {
    let response = send(fcx, operator, &get("/api/plant")).await;
    assert_eq!(response.head.status, 200);
    json_body(&response)
}

/// Waits for hmi01 to finish a poll cycle after the update timestamp `after`, and
/// returns its view. The bound turns a hung poll into a failure.
async fn next_poll(fcx: &Cx, operator: &Machine, after: &str) -> Value {
    for _ in 0..400 {
        let view = plant(fcx, operator).await;
        if view["plant_time"].as_str().is_some_and(|time| time > after) {
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
            let wrong_method = send(&fcx, &world.operator, &post("/api/plant", &json!({}))).await;
            assert_eq!(wrong_method.head.status, 405);
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
            let first_history = send(
                &fcx,
                &world.operator,
                &get("/api/trend?point=hot_leg_a&minutes=10"),
            )
            .await;
            let first_history = json_body(&first_history);
            let samples = first_history["samples"].as_array().unwrap();
            assert_eq!(samples.len(), hmi::HISTORY_CAPACITY);
            for (n, sample) in samples.iter().enumerate() {
                assert_eq!(
                    sample["time"],
                    hmi::Site::default().timestamp(-600_000 + n as i64 * 250)
                );
                assert!(sample["value"].as_f64().is_some());
            }
            let view = next_poll(&fcx, &world.operator, "").await;

            for reading in view["readings"].as_object().unwrap().values() {
                assert!(!reading["tag"].as_str().unwrap().is_empty());
            }
            assert_eq!(
                view["plant_time"],
                hmi::Site::default().timestamp(world.held.lock().clock_ms.unwrap())
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
            assert_eq!(samples.len(), hmi::HISTORY_CAPACITY);
            assert_eq!(
                samples.last().unwrap()["value"],
                view["readings"]["neutron_power"]["value"]
            );
            assert!(samples[0]["time"].as_str().unwrap().ends_with("+00:00"));
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
                for plc in [Plc::Rps1, Plc::Rcs1, Plc::Bop1, Plc::Pam1] {
                    let block = &held.blocks[match plc {
                        Plc::Rps1 => 0,
                        Plc::Rcs1 => 1,
                        Plc::Bop1 => 2,
                        Plc::Pam1 => 3,
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
            let before = next_poll(&fcx, &world.operator, "").await;
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
            let after = next_poll(
                &fcx,
                &world.operator,
                before["plant_time"].as_str().unwrap(),
            )
            .await;
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
            next_poll(&fcx, &world.operator, "").await;

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
            let before = next_poll(&fcx, &world.operator, "").await;

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
            let stopped = next_poll(
                &fcx,
                &world.operator,
                before["plant_time"].as_str().unwrap(),
            )
            .await;
            assert_eq!(stopped["status"]["coolant_pump_b"], json!(false));
            assert_eq!(alarm_state(&stopped, "coolant_pump_stopped"), "active");
            let in_time = stopped["alarms"]
                .as_array()
                .unwrap()
                .iter()
                .find(|a| a["id"] == "coolant_pump_stopped")
                .unwrap()["arrived_at"]
                .clone();
            assert_eq!(in_time, stopped["plant_time"]);

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
                stopped["plant_time"].as_str().unwrap(),
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
                    .unwrap()["arrived_at"],
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
            let before = next_poll(&fcx, &world.operator, "").await;
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
                vec![u64::from(driver.snapshot().telemetry.heartbeat); 4]
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
            let mut updated = before["plant_time"].as_str().unwrap().to_owned();
            for at_ms in [3_000, 4_000, 5_000, 6_000] {
                driver.advance_to(&(), at_ms);
                let view = next_poll(&fcx, &world.operator, &updated).await;
                let next = view["plant_time"].as_str().unwrap().to_owned();
                assert!(next > updated);
                assert_eq!(counts(&view), held_counts);
                updated = next;
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
            let resumed = next_poll(&fcx, &world.operator, &updated).await;
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
    assert_eq!(
        hmi::Site::default().timestamp(0),
        "2026-03-14T07:43:12.000+00:00"
    );
    assert_eq!(
        hmi::Site::default().timestamp(12_500),
        "2026-03-14T07:43:24.500+00:00"
    );
    assert_eq!(
        hmi::Site::default().timestamp((16 * 3600 + 16 * 60 + 48) * 1000),
        "2026-03-15T00:00:00.000+00:00"
    );
    assert_eq!(
        hmi::Site::default().timestamp(18 * 86_400_000),
        "2026-04-01T07:43:12.000+00:00"
    );
    assert_eq!(
        hmi::Site::default().timestamp(293 * 86_400_000),
        "2027-01-01T07:43:12.000+00:00"
    );
    assert_eq!(
        hmi::Site::default().timestamp(717 * 86_400_000),
        "2028-02-29T07:43:12.000+00:00"
    );
    assert_eq!(
        hmi::Site::default().timestamp(718 * 86_400_000),
        "2028-03-01T07:43:12.000+00:00"
    );
}

#[test]
fn history_is_bounded_and_failed_reads_are_gaps() {
    let mut held = Held::default();
    held.blocks[0].online = true;
    held.blocks[0].read_ms = Some(0);
    held.blocks[0].input = vec![1000; 5];
    for n in 0..hmi::HISTORY_CAPACITY + 7 {
        held.clock_ms = Some(n as i64 * hmi::POLL_MS as i64);
        held.sample();
    }
    let samples = held.trend("neutron_power", 10).unwrap();
    assert_eq!(samples.len(), hmi::HISTORY_CAPACITY);
    assert_eq!(
        samples[0].time,
        hmi::Site::default().timestamp(7 * hmi::POLL_MS as i64)
    );
    assert_eq!(samples[0].value, Some(100.0));
    let recent = held.trend("neutron_power", 1).unwrap();
    assert_eq!(recent.len(), 241);
    assert_eq!(
        recent[0].time,
        hmi::Site::default().timestamp(held.clock_ms.unwrap() - 60_000)
    );
    held.blocks[0].online = false;
    held.clock_ms = held.clock_ms.map(|time| time + hmi::POLL_MS as i64);
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
            hmi::start(&fcx, machine, controllers, hmi::Site::default(), &driver)?;
            let operator = sandbox::machine(&fcx, attacher.attach("operator")?, OPERATOR);
            let mut listener = operator.tcp.listen(5998)?;
            fcx.spawn(move |fcx| async move {
                let mut conn = listener.accept(&fcx).await?;
                let mut request = [0; 64];
                conn.read(&fcx, &mut request).await?;
                conn.write_all(&fcx, &[0, 1, 0, 1, 0, 2, 1, 3]).await?;
                Ok(())
            });
            let view = next_poll(&fcx, &operator, "").await;
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

#[test]
fn site_clock_preserves_offsets_and_negative_history_times() {
    let site = hmi::Site {
        utc_offset_seconds: 19_800,
        zone: "IST",
        ..hmi::Site::default()
    };
    assert_eq!(site.timestamp(0), "2026-03-14T13:13:12.000+05:30");
    assert_eq!(site.timestamp(-600_000), "2026-03-14T13:03:12.000+05:30");
    let west = hmi::Site {
        utc_offset_seconds: -28_800,
        zone: "PST",
        ..site
    };
    assert_eq!(west.timestamp(0), "2026-03-13T23:43:12.000-08:00");
    assert_eq!(west.timestamp(-1), "2026-03-13T23:43:11.999-08:00");
}

#[test]
fn configured_site_clock_reaches_http_and_json() {
    fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(11)),
        |fcx| async move {
            let driver = Driver::new(Config::default());
            let site = hmi::Site {
                epoch: 1_773_475_115,
                zone: "IST",
                utc_offset_seconds: 19_800,
            };
            let world = start_world_at(&fcx, &driver, hmi::controllers(), site)?;
            fcx.sleep(Duration::from_millis(1500)).await.unwrap();
            let response = send_at(&fcx, &world.operator, &get("/api/plant"), site).await;
            let view = json_body(&response);
            assert_eq!(view["zone"], "IST");
            assert_eq!(
                view["plant_time"],
                site.timestamp(world.held.lock().clock_ms.unwrap())
            );
            assert!(view["plant_time"].as_str().unwrap().ends_with("+05:30"));
            assert!(
                view["links"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|link| link["updated_at"].as_str().unwrap().ends_with("+05:30"))
            );
            fcx.cancel();
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn emergency_posts_write_the_controller_coils() {
    fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(32)),
        |fcx| async move {
            let driver = Driver::new(Config::default());
            let world = start_world(&fcx, &driver)?;
            for (path, body, plc, address) in [
                ("relief", json!({"open": true}), Plc::Rcs1, 4),
                ("relief-block", json!({"closed": true}), Plc::Rcs1, 5),
                (
                    "pump",
                    json!({"name": "safety-injection", "running": true}),
                    Plc::Rcs1,
                    6,
                ),
                ("steam-isolation", json!({"closed": true}), Plc::Bop1, 7),
            ] {
                let response = send(
                    &fcx,
                    &world.operator,
                    &post(&format!("/api/control/{path}"), &body),
                )
                .await;
                assert_eq!(
                    response.head.status,
                    200,
                    "{path}: {}",
                    String::from_utf8_lossy(&response.body)
                );
                driver.advance_to(&(), driver.snapshot().at_ms + 250);
                assert!(registers::coils(plc, &driver.snapshot())[address]);
            }
            fcx.cancel();
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn failed_safety_injection_post_returns_the_controller_exception() {
    use nuclear_world::{
        command::FaultCommand,
        faults::{Fault, FaultChange, ProcessFault},
    };
    fictionet::block_on(fictionet::lab(
        RunOptions::new(Seed::from_u64(33)),
        |fcx| async move {
            let driver = Driver::new(Config::default());
            driver
                .apply_fault(
                    &(),
                    FaultCommand {
                        change: FaultChange::Inject(Fault::Process(
                            ProcessFault::SafetyInjectionFailure,
                        )),
                        expected_revision: 0,
                    },
                )
                .unwrap();
            let world = start_world(&fcx, &driver)?;
            let response = send(
                &fcx,
                &world.operator,
                &post(
                    "/api/control/pump",
                    &json!({"name": "safety-injection", "running": true}),
                ),
            )
            .await;
            assert_eq!(response.head.status, 409);
            let body = json_body(&response);
            assert_eq!(body["exception"], 4);
            assert_eq!(body["reason"], "server device failure");
            assert_eq!(driver.snapshot().operator_actions, 0);
            fcx.cancel();
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn post_accident_api_scales_freezes_and_reports_sensor_faults() {
    use nuclear_world::{
        command::FaultCommand,
        faults::{Fault, FaultChange, SensorFault},
    };
    fictionet::block_on(fictionet::lab(RunOptions::new(Seed::from_u64(35)), |fcx| async move {
        let driver = Driver::new(Config::default());
        let world = start_world(&fcx, &driver)?;
        let first = next_poll(&fcx, &world.operator, "").await;
        assert_close(value(&first, "containment_pressure"), 101.3, 0.1, "containment pressure");
        let specs = [
            ("core_exit_wide_range", "TE-413W", "C"), ("vessel_level", "LT-480", "%"),
            ("containment_pressure", "PT-934", "kPa"), ("containment_temperature", "TE-935", "C"),
            ("containment_hydrogen", "AT-936", "%"), ("containment_radiation", "RE-937", "Sv/h"),
            ("relief_tailpipe_temperature", "TE-463", "C"), ("relief_tank_pressure", "PT-472", "kPa"),
            ("safety_injection_flow", "FT-940", "kg/s"), ("turbine_building_temperature", "TE-951", "C"),
        ];
        for (name, tag, unit) in specs {
            let sensor: Sensor = serde_json::from_value(json!(name)).unwrap();
            assert_close(value(&first, name), driver.snapshot().readings[sensor.index()].reading.value, 0.001, name);
            assert_eq!(first["readings"][name]["tag"], tag);
            assert_eq!(first["readings"][name]["unit"], unit);
        }
        assert_eq!(first["links"].as_array().unwrap().len(), 4);
        assert_eq!(first["links"][3]["id"], "pam1");
        assert_eq!(first["links"][3]["online"], true);
        for (name, expected) in [("safety_injection", false), ("relief_block_closed", false), ("steam_isolation_closed", false), ("fan_coolers", true)] {
            assert_eq!(first["status"][name], expected);
        }
        for (name, counts) in [("containment_pressure", 2345), ("containment_hydrogen", 234), ("containment_radiation", 123)] {
            driver.apply_fault(&(), FaultCommand { change: FaultChange::Inject(Fault::Sensor { sensor: serde_json::from_value(json!(name)).unwrap(), kind: SensorFault::Stuck { value: counts } }), expected_revision: driver.snapshot().revision }).unwrap();
        }
        driver.advance_to(&(), 1000);
        let changed = next_poll(&fcx, &world.operator, first["plant_time"].as_str().unwrap()).await;
        assert_eq!(value(&changed, "containment_pressure"), 234.5);
        assert_eq!(value(&changed, "containment_hydrogen"), 2.34);
        assert_eq!(value(&changed, "containment_radiation"), 1.23);
        driver.apply_fault(&(), FaultCommand { change: FaultChange::Inject(Fault::TelemetryQuiet), expected_revision: driver.snapshot().revision }).unwrap();
        driver.advance_to(&(), 2000);
        let frozen = next_poll(&fcx, &world.operator, changed["plant_time"].as_str().unwrap()).await;
        for (name, _, _) in specs { assert_eq!(value(&frozen, name), value(&changed, name)); }
        println!("HMI containment pressure: 101.3 kPa initially; fault 234.5 kPa, hydrogen 2.34%, radiation 1.23 Sv/h; all ten channels held during telemetry quiet");
        fcx.cancel();
        Ok(())
    })).unwrap();
}
