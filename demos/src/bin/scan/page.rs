//! The scan page: its world data and its three panels.
//!
//! One world task publishes three topics. `Ports` is the world's port map,
//! with its banners. `Services` is nmap's report for each finished step, as
//! its XML gave it. `Office` is the scripted story: each step's command,
//! state and exit status. The task also marks the moment every office
//! machine has answered a probe, with one `scan.discovered` fact.
//!
//! The panels are ES modules served as assets under `/assets/scan/`. Each
//! panel reads its own topic and the topics of the other two by path.
use crate::{nmap, script};
use fictionet::Cx;
use fictionet::stdlib::protocols::json::Value;
use fictionet_observe::page::{EventFilter, Page, StateLimits, StateTopic};
use scan_world::{PortMap, PortState, Tap};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The page title says the agent is scripted, where it shows on first load.
pub const TITLE: &str = "Office scan · scripted agent";
/// The panel showing the story strip and the office map.
pub const OFFICE: &str = "Office";
/// The panel showing the host-by-port heatmap.
pub const PORTS: &str = "Ports";
/// The panel showing banners beside nmap's names and OS guesses.
pub const SERVICES: &str = "Services";
/// The story moment: every office machine has answered a probe.
pub const DISCOVERED: &str = "All five hosts answered";

/// How often the world task looks for changes, so it publishes at most four
/// times a second however fast nmap probes.
const TICK: Duration = Duration::from_millis(250);

/// A scripted step's progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Waiting,
    Running,
    Done,
    Failed,
}

/// One scripted step, as the agent types it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoryStep {
    pub title: String,
    pub command: String,
    pub state: StepState,
    /// The command's exit status, once it has finished.
    pub exit: Option<i32>,
}

/// The scripted story.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Story {
    pub steps: Vec<StoryStep>,
}

impl Story {
    /// Every step waiting.
    pub fn scripted() -> Self {
        Self {
            steps: script::STEPS
                .iter()
                .enumerate()
                .map(|(index, step)| StoryStep {
                    title: step.title.into(),
                    command: script::command(index),
                    state: StepState::Waiting,
                    exit: None,
                })
                .collect(),
        }
    }
}

/// nmap's report for one finished step.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StepReport {
    pub title: String,
    /// The command line nmap recorded.
    pub args: String,
    /// Start and end, in Unix seconds, from the guest's clock.
    pub start: u64,
    pub end: u64,
    /// nmap's elapsed time in seconds.
    pub elapsed: f64,
    /// nmap's exit status word, such as "success".
    pub exit: String,
    /// How many hosts nmap counted up.
    pub up: usize,
    pub hosts: Vec<HostReport>,
}

/// One host in nmap's report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostReport {
    pub addr: Ipv4Addr,
    /// nmap's state, such as "up", and the reason it gave.
    pub state: String,
    pub reason: String,
    /// The ports nmap listed one by one.
    pub ports: Vec<PortReport>,
    /// The ports nmap summarized, such as 1,022 closed by reset.
    pub summarized: Vec<Summary>,
    /// None when the step ran no OS detection; empty when nmap made no match.
    pub os: Option<Vec<OsGuess>>,
}

/// One port nmap listed, with nmap's name for its service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortReport {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub reason: String,
    pub service: String,
    pub product: String,
    pub version: String,
    pub extra_info: String,
}

/// Ports nmap summarized in one state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub state: String,
    pub count: usize,
    /// Reasons with their counts, such as "reset".
    pub reasons: Vec<(String, usize)>,
}

/// One of nmap's OS guesses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsGuess {
    pub name: String,
    pub accuracy: u8,
}

/// nmap's reports for the finished steps.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Reports {
    pub steps: Vec<StepReport>,
}

impl StepReport {
    pub fn new(title: &str, report: &nmap::Report) -> Self {
        Self {
            title: title.into(),
            args: report.args.clone(),
            start: report.start,
            end: report.runstats.finished.time,
            elapsed: report.runstats.finished.elapsed,
            exit: report.runstats.finished.exit.clone(),
            up: report.runstats.hosts.up,
            hosts: report
                .hosts
                .iter()
                .filter_map(|host| {
                    Some(HostReport {
                        addr: host.ipv4()?,
                        state: host.status.state.clone(),
                        reason: host.status.reason.clone(),
                        ports: host
                            .ports
                            .rows
                            .iter()
                            .map(|p| PortReport {
                                port: p.port,
                                protocol: p.protocol.clone(),
                                state: p.state.state.clone(),
                                reason: p.state.reason.clone(),
                                service: p.service.name.clone(),
                                product: p.service.product.clone(),
                                version: p.service.version.clone(),
                                extra_info: p.service.extra_info.clone(),
                            })
                            .collect(),
                        summarized: host
                            .ports
                            .extra
                            .iter()
                            .map(|e| Summary {
                                state: e.state.clone(),
                                count: e.count,
                                reasons: e
                                    .reasons
                                    .iter()
                                    .map(|r| (r.reason.clone(), r.count))
                                    .collect(),
                            })
                            .collect(),
                        os: host.os.as_ref().map(|os| {
                            os.matches
                                .iter()
                                .map(|m| OsGuess {
                                    name: m.name.clone(),
                                    accuracy: m.accuracy,
                                })
                                .collect()
                        }),
                    })
                })
                .collect(),
        }
    }
}

/// The story and nmap's reports, written as the story runs and published by
/// the world task.
#[derive(Clone)]
pub struct Progress(Arc<Mutex<Written>>);

struct Written {
    version: u64,
    story: Story,
    reports: Reports,
}

impl Progress {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Written {
            version: 1,
            story: Story::scripted(),
            reports: Reports::default(),
        })))
    }

    /// Marks a step running.
    pub fn start(&self, index: usize) {
        let mut written = self.0.lock().unwrap();
        written.story.steps[index].state = StepState::Running;
        written.version += 1;
    }

    /// Marks a step finished, with nmap's report when there is one.
    pub fn finish(&self, index: usize, exit: Option<i32>, report: Option<StepReport>, ok: bool) {
        let mut written = self.0.lock().unwrap();
        let step = &mut written.story.steps[index];
        step.state = if ok {
            StepState::Done
        } else {
            StepState::Failed
        };
        step.exit = exit;
        if let Some(report) = report {
            written.reports.steps.push(report);
        }
        written.version += 1;
    }

    fn changed(&self, since: u64) -> Option<(u64, Story, Reports)> {
        let written = self.0.lock().unwrap();
        (written.version != since).then(|| {
            (
                written.version,
                written.story.clone(),
                written.reports.clone(),
            )
        })
    }
}

/// The page's three topics.
#[derive(Clone)]
pub struct Topics {
    pub ports: StateTopic<PortMap>,
    pub story: StateTopic<Story>,
    pub reports: StateTopic<Reports>,
}

impl Topics {
    pub fn new() -> Self {
        Self {
            ports: StateTopic::new(StateLimits {
                max_bytes: PortMap::MAX_JSON_BYTES,
                deltas: 16,
            }),
            story: StateTopic::new(StateLimits::default()),
            reports: StateTopic::new(StateLimits {
                max_bytes: 1 << 20,
                deltas: 0,
            }),
        }
    }

    /// Adds the Office, Ports and Services panels, their assets, the story
    /// moment and the standard panels.
    pub fn compose(&self, page: Page) -> Page {
        let module = |name: &str| format!("export {{ mount }} from '../assets/scan/{name}.mjs';");
        page.custom(OFFICE, module("office"), self.story.clone())
            .custom(PORTS, module("ports"), self.ports.clone())
            .custom(SERVICES, module("services"), self.reports.clone())
            .inspector_first(OFFICE)
            .asset(
                "scan/model.mjs",
                "text/javascript",
                include_str!("model.mjs"),
            )
            .asset(
                "scan/office.mjs",
                "text/javascript",
                include_str!("office.mjs"),
            )
            .asset(
                "scan/ports.mjs",
                "text/javascript",
                include_str!("ports.mjs"),
            )
            .asset(
                "scan/services.mjs",
                "text/javascript",
                include_str!("services.mjs"),
            )
            .asset("scan/scan.css", "text/css", include_str!("scan.css"))
            .moment(
                DISCOVERED,
                EventFilter {
                    source: Some("scan".into()),
                    kind: Some("discovered".into()),
                    ..EventFilter::default()
                },
            )
            .standard_panels()
    }
}

/// Whether every office machine has a row nmap got an answer for.
pub fn all_answered(map: &PortMap) -> bool {
    map.machines.iter().all(|machine| {
        map.rows.iter().any(|row| {
            row.host == machine.addr && matches!(row.state, PortState::Open | PortState::Closed)
        })
    })
}

/// Starts the world task that publishes the topics and marks the moment.
pub fn publish(cx: &Cx, ports: Tap, topics: Topics, progress: Progress) {
    cx.spawn(move |cx| async move {
        let mut published: Option<(u64, u64, u64)> = None;
        let mut version = 0;
        let mut discovered = false;
        loop {
            let latest = ports.changes_since(u64::MAX);
            let marks = (latest.revision, latest.untracked, latest.untracked_banners);
            if published != Some(marks) {
                let from = published.map(|(revision, ..)| revision);
                let (map, changes) = ports.snapshot_with_changes(from.unwrap_or(0));
                // A refused publication sets the topic's too_large status,
                // which the panels show; the previous map stays.
                let _ = match from {
                    None => topics.ports.publish(cx.now(), &map),
                    Some(_) => topics.ports.publish_with_delta(cx.now(), &map, &changes),
                };
                published = Some((map.revision, map.untracked, map.untracked_banners));
                if !discovered && all_answered(&map) {
                    discovered = true;
                    let hosts: Vec<Value> = map
                        .machines
                        .iter()
                        .map(|m| Value::from(m.addr.to_string()))
                        .collect();
                    let at_ms = cx.now().since_start().as_millis() as u64;
                    cx.emit("scan", "discovered", |e| {
                        e.level(fictionet::events::Level::Notice)
                            .summary(DISCOVERED)
                            .field("hosts", hosts)
                            .field("at_ms", at_ms)
                    });
                }
            }
            if let Some((next, story, reports)) = progress.changed(version) {
                let _ = topics.story.publish(cx.now(), &story);
                let _ = topics.reports.publish(cx.now(), &reports);
                version = next;
            }
            cx.sleep(TICK).await?;
        }
    });
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::nmap::tests::{DISCOVERY, OS, SERVICES};

    /// The world's port map after discovery in a KVM run of the demo. That run
    /// predates banners, so the two banner fields are added here.
    pub fn recorded_discovery() -> PortMap {
        let mut value: serde_json::Value =
            serde_json::from_str(include_str!("data/discovery-ports.json")).unwrap();
        value["untracked_banners"] = 0.into();
        value["banners"] = serde_json::json!([]);
        serde_json::from_value(value).unwrap()
    }

    pub fn recorded_reports() -> Reports {
        Reports {
            steps: [DISCOVERY, SERVICES, OS]
                .into_iter()
                .zip(&script::STEPS)
                .map(|(xml, step)| StepReport::new(step.title, &nmap::parse(xml).unwrap()))
                .collect(),
        }
    }

    #[test]
    fn reports_keep_nmap_names_summaries_and_no_os_until_detection() {
        let reports = recorded_reports();
        let [discovery, services, os] = &reports.steps[..] else {
            panic!("three steps");
        };
        assert_eq!(discovery.up, 5);
        assert_eq!(discovery.exit, "success");
        assert_eq!(
            (discovery.start, discovery.end),
            (1_792_462_616, 1_792_462_620)
        );
        assert!(discovery.hosts.iter().all(|h| h.os.is_none()));
        let server = services
            .hosts
            .iter()
            .find(|h| h.addr == scan_world::SERVER_ADDR)
            .unwrap();
        assert_eq!(
            server.ports[1],
            PortReport {
                port: 80,
                protocol: "tcp".into(),
                state: "open".into(),
                reason: "syn-ack".into(),
                service: "http".into(),
                product: "nginx".into(),
                version: "1.24.0".into(),
                extra_info: "Ubuntu".into(),
            }
        );
        assert_eq!(
            server.summarized,
            [Summary {
                state: "closed".into(),
                count: 1022,
                reasons: vec![("reset".into(), 1022)],
            }]
        );
        let guesses = |addr: Ipv4Addr| {
            os.hosts
                .iter()
                .find(|h| h.addr == addr)
                .unwrap()
                .os
                .clone()
                .unwrap()
        };
        assert_eq!(guesses(scan_world::SERVER_ADDR).len(), 1);
        assert_eq!(guesses(Ipv4Addr::new(10, 0, 0, 10)).len(), 10);
        let no_match = StepReport::new(
            "OS detection",
            &nmap::parse(&nmap::tests::os_without_match("10.0.0.13")).unwrap(),
        );
        let printer = no_match
            .hosts
            .iter()
            .find(|h| h.addr == Ipv4Addr::new(10, 0, 0, 13))
            .unwrap();
        assert_eq!(printer.os, Some(vec![]));
    }

    #[test]
    fn progress_marks_steps_and_appends_reports() {
        let progress = Progress::new();
        let (first, story, reports) = progress.changed(0).unwrap();
        assert!(story.steps.iter().all(|s| s.state == StepState::Waiting));
        assert_eq!(story.steps[1].command, script::command(1));
        assert!(reports.steps.is_empty());
        assert!(progress.changed(first).is_none());
        progress.start(0);
        let (second, story, _) = progress.changed(first).unwrap();
        assert_eq!(story.steps[0].state, StepState::Running);
        let report = recorded_reports().steps.remove(0);
        progress.finish(0, Some(0), Some(report.clone()), true);
        progress.start(1);
        progress.finish(1, Some(1), None, false);
        let (_, story, reports) = progress.changed(second).unwrap();
        assert_eq!(story.steps[0].state, StepState::Done);
        assert_eq!(story.steps[0].exit, Some(0));
        assert_eq!(story.steps[1].state, StepState::Failed);
        assert_eq!(story.steps[1].exit, Some(1));
        assert_eq!(story.steps[2].state, StepState::Waiting);
        assert_eq!(reports.steps, [report]);
    }

    #[test]
    fn discovery_needs_an_answer_from_every_machine() {
        let map = recorded_discovery();
        assert!(all_answered(&map));
        for machine in &map.machines {
            let mut missing = map.clone();
            for row in missing.rows.iter_mut().filter(|r| r.host == machine.addr) {
                row.state = PortState::Unreachable;
            }
            assert!(!all_answered(&missing), "{}", machine.addr);
        }
    }

    /// Reads one event from the page's state stream for `topic` after `cursor`.
    async fn stream_event(url: &str, topic: &str, cursor: u64) -> (String, serde_json::Value) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (authority, token) = url
            .strip_prefix("http://")
            .and_then(|s| s.split_once("/#token="))
            .unwrap();
        let mut conn = tokio::net::TcpStream::connect(authority).await.unwrap();
        let head = format!(
            "GET /api/states/stream?topics={topic}&after={topic}:{cursor} HTTP/1.1\r\n\
             Host: {authority}\r\nAuthorization: Bearer {token}\r\n\r\n"
        );
        conn.write_all(head.as_bytes()).await.unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0; 1 << 16];
        loop {
            let n = conn.read(&mut chunk).await.unwrap();
            assert_ne!(n, 0, "the stream closed before an event");
            bytes.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&bytes);
            let Some(start) = text.find("\nevent: ") else {
                continue;
            };
            let event = &text[start + 8..];
            let Some((name, rest)) = event.split_once('\n') else {
                continue;
            };
            let Some(data) = rest.strip_prefix("data: ") else {
                continue;
            };
            let Some((data, _)) = data.split_once('\n') else {
                continue;
            };
            return (name.to_owned(), serde_json::from_str(data).unwrap());
        }
    }

    #[test]
    fn the_world_task_publishes_the_map_with_deltas_each_report_and_the_moment() {
        use crate::client::{Scanner, serve_server};
        use fictionet_demo::kit::client::PageClient;
        use fictionet_observe::page::Host;
        use fictionet_observe::{DashboardObserver, DashboardOptions};
        use std::sync::mpsc;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let dashboard = DashboardObserver::new(DashboardOptions::demo());
            let topics = Topics::new();
            let progress = Progress::new();
            let server = topics
                .compose(
                    Page::new(TITLE, dashboard.handle())
                        .host(Host::new("workstation").sandbox(scan_world::SCANNER))
                        .host(Host::new("office").sandbox(scan_world::SERVER)),
                )
                .bind_loopback(0)
                .await
                .unwrap();
            // The world stops after each step until the test has read the page.
            let (finished, steps) = mpsc::channel::<usize>();
            let (read, reads) = mpsc::channel::<()>();
            let observer = dashboard.observer();
            let (world_topics, world_progress) = (topics.clone(), progress.clone());
            let world = std::thread::spawn(move || {
                fictionet::block_on(fictionet::lab(
                    fictionet::RunOptions::new(fictionet::Seed::from_u64(5)).observer(observer),
                    move |cx| async move {
                        let (attacher, attachments) = fictionet::attachments();
                        let ports = scan_world::start(&cx, scan_world::office(), attachments)?;
                        publish(&cx, ports, world_topics, world_progress.clone());
                        serve_server(&cx, attacher.attach(scan_world::SERVER)?);
                        let mut scanner =
                            Scanner::attach(&cx, attacher.attach(scan_world::SCANNER)?);
                        let reports = recorded_reports().steps;
                        let mut up = Vec::new();
                        for (index, report) in reports.into_iter().enumerate() {
                            world_progress.start(index);
                            match index {
                                0 => up = scanner.sweep(&cx, Duration::ZERO).await?,
                                1 => {
                                    let open =
                                        scanner.scan(&cx, &up, 1..=1024, Duration::ZERO).await?;
                                    scanner.banners(&cx, &open).await?;
                                }
                                _ => {}
                            }
                            world_progress.finish(index, Some(0), Some(report), true);
                            cx.sleep(TICK * 2).await?;
                            finished.send(index).unwrap();
                            reads.recv().unwrap();
                        }
                        // The publishing task runs until the run ends.
                        cx.cancel();
                        Ok(())
                    },
                ))
            });
            let client = PageClient::from_url(server.url()).unwrap();
            client.bootstrap().await.unwrap();
            let get = |path: &'static str| {
                let client = &client;
                async move {
                    let reply = client.request("GET", path, None, true).await.unwrap();
                    assert_eq!(reply.status, 200, "{path}");
                    serde_json::from_slice::<serde_json::Value>(&reply.body).unwrap()
                }
            };
            for index in 0..3 {
                let reached = tokio::task::block_in_place(|| steps.recv().unwrap());
                assert_eq!(reached, index);
                let reports = get("/api/state/services").await;
                let listed = reports["value"]["steps"].as_array().unwrap();
                assert_eq!(listed.len(), index + 1, "a report after each step");
                assert_eq!(listed[index]["title"], script::STEPS[index].title);
                let story = get("/api/state/office").await;
                assert_eq!(story["value"]["steps"][index]["state"], "done");
                let map = get("/api/state/ports").await;
                if index == 0 {
                    let summary = map["value"]["rows"].as_array().unwrap().len();
                    assert_eq!(summary, 256, "one echo row per address");
                }
                read.send(()).unwrap();
            }
            world.join().unwrap().unwrap();

            let (published, moment) = crate::checks::read(&client).await.unwrap();
            let summary = crate::checks::check(&published, &moment).unwrap();
            assert!(
                summary.starts_with("five hosts answered, 251 other addresses unreachable"),
                "{summary}"
            );
            assert_eq!(published.ports.banners.len(), 11);
            let (name, event) =
                stream_event(server.url(), "ports", topics.ports.revision() - 1).await;
            assert_eq!(name, "delta");
            let delta: scan_world::PortChanges =
                serde_json::from_value(event["delta"].clone()).unwrap();
            assert_eq!(delta.revision, published.ports.revision);
            assert!(delta.from_revision < delta.revision);
            for row in &delta.rows {
                assert!(row.revision > delta.from_revision);
                assert!(published.ports.rows.contains(row));
            }
            let (name, _) = stream_event(server.url(), "ports", 0).await;
            assert_eq!(name, "snapshot");
        });
    }
}
