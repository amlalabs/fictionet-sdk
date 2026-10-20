//! `artifactory preview`: the page without a VM. An in-process client
//! replays each step's requests and door probes against the world in
//! `fictionet::run`, so the page shows real world facts. The screen says
//! NO VM, and steps have no exit status because no guest runs.

use super::{
    Result,
    facts::{Facts, Publisher, Store},
    story::{self, Mode, Who},
};
use artifactory_world::{
    Identity, NAMES,
    log::Log,
    packages::Variant,
    repository::{Contents, Sessions},
};
use fictionet::{
    Cx, RunOptions, Seed,
    events::Fanout,
    stdlib::{
        protocols::{dns::rr::RecordType, http1},
        world::sandbox::{self, Machine},
    },
};
use fictionet_demo::kit::preview::{Command, Console};
use fictionet_observe::{
    DashboardObserver, DashboardOptions,
    page::{Host, HostState, HostStatus, Server, StateLimits, StateTopic},
};
use std::{
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, SystemTime},
};

/// The fixture's sandboxes: its client, and the colleague's in `--sessions`.
pub const SANDBOXES: [&str; 2] = ["fixture", "fixture-colleague"];

/// A fixture run's facts and repository states.
struct Fixture {
    facts: Arc<Facts>,
    main: Arc<Contents>,
    sessions: Sessions,
    mode: Option<Mode>,
}

impl Fixture {
    fn new(variant: Variant, mode: Option<Mode>) -> fictionet::Result<Self> {
        let state = || Contents::new(variant, "artifactory-fixture", &[1; 32]);
        let main = state()?;
        let colleague = (mode == Some(Mode::Separate)).then(state).transpose()?;
        let facts = Arc::new(Facts::new(
            main.inventory(),
            colleague.as_ref().map(Contents::inventory),
            super::page::scenario(variant, true, mode.map(|mode| (mode, SANDBOXES))),
            SANDBOXES,
        ));
        let main = facts.listen(Store::Main, main);
        let colleague = colleague.map(|contents| facts.listen(Store::Colleague, contents));
        let sessions = super::world::sessions(main.clone(), colleague, SANDBOXES);
        Ok(Self {
            facts,
            main,
            sessions,
            mode,
        })
    }
}

/// Serves the page while an in-process client replays the story's requests.
/// `extra_reads` more index reads after the story fill the page's row bound.
pub async fn serve(variant: Variant, mode: Option<Mode>, extra_reads: usize) -> Result {
    let mut input = fictionet_demo::kit::preview::Input::stdin()?;
    let fixture = Fixture::new(variant, mode).map_err(std::io::Error::other)?;
    let facts = fixture.facts.clone();
    let dashboard = DashboardObserver::new(DashboardOptions::demo());
    let screen = Console::new();
    let page = bind(&dashboard, &facts, screen.clone()).await?;
    println!("Fixture: in-process traffic replay. No guest or command exit statuses.");
    println!("Page: {}", page.url());
    println!(
        "The story runs once. Type drop to close the screen's connections; end the input or press Ctrl-C to stop."
    );
    let options = RunOptions::new(Seed::from_u64(1)).observer(Arc::new(Fanout::new(vec![
        dashboard.observer(),
        facts.clone(),
    ])));
    let replay = run(options, fixture, Duration::from_secs(1), extra_reads);
    tokio::pin!(replay);
    let mut replaying = true;
    loop {
        tokio::select! {
            result = &mut replay, if replaying => {
                result.map_err(std::io::Error::other)?;
                println!("fixture replay complete");
                replaying = false;
            }
            command = input.next() => match command {
                Some(Command::Drop) => screen.drop_connections(),
                Some(Command::Again) => println!("The story runs once."),
                None => break,
            },
        }
    }
    drop(page);
    Ok(())
}

async fn bind(
    dashboard: &DashboardObserver,
    facts: &Facts,
    screen: Console,
) -> std::io::Result<Server> {
    let status = StateTopic::new(StateLimits::default());
    status
        .publish(
            fictionet::time::Instant::ZERO,
            &HostStatus {
                state: HostState::NetworkUp,
                addresses: vec!["10.0.0.2".into()],
                screen: true,
                terminal: false,
            },
        )
        .map_err(std::io::Error::other)?;
    let inventory = facts.state.lock().unwrap().inventory.clone();
    super::page::compose(
        &inventory,
        dashboard.handle(),
        vec![Host::new(SANDBOXES[0]).status(status).console(screen)],
        facts.topics.clone(),
        true,
    )
    .bind_loopback(0)
    .await
}

async fn run(
    options: RunOptions,
    fixture: Fixture,
    pace: Duration,
    extra_reads: usize,
) -> fictionet::Result {
    let Fixture {
        facts,
        main: contents,
        sessions,
        mode,
    } = fixture;
    let log = Log::start(Box::new(std::io::sink()))?;
    let output = log.clone();
    let result = fictionet::run(options, move |cx| async move {
        let identity = Identity::new(&cx)?;
        let (attacher, attachments) = fictionet::attachments();
        artifactory_world::start(&cx, sessions, identity, log, attachments)?;
        let machine = sandbox::machine(
            &cx,
            attacher.attach(SANDBOXES[0])?,
            Ipv4Addr::new(10, 0, 0, 2),
        );
        let mut client = Client {
            cx: &cx,
            machine: &machine,
            contents: &contents,
            upload: None,
        };
        let colleague_machine = mode
            .map(|_| {
                Ok::<_, fictionet::Error>(sandbox::machine(
                    &cx,
                    attacher.attach(SANDBOXES[1])?,
                    Ipv4Addr::new(10, 0, 0, 3),
                ))
            })
            .transpose()?;
        let mut colleague = colleague_machine.as_ref().map(|machine| Client {
            cx: &cx,
            machine,
            contents: &contents,
            upload: None,
        });
        let publisher = Publisher::start(facts.clone());
        cx.sleep(pace).await?;
        for step in story::steps(contents.variant, mode) {
            facts.phase(step.name, step.destinations, step.who);
            publisher.flush().await?;
            println!("fixture story: {}", step.name);
            cx.sleep(pace).await?;
            let result = async {
                match step.who {
                    Who::Maya => client.replay(step.name).await?,
                    Who::Colleague => {
                        colleague
                            .as_mut()
                            .ok_or_else(|| fictionet::Error::msg("no colleague client"))?
                            .replay(step.name)
                            .await?
                    }
                }
                facts.wait_for(&step).await?;
                Ok::<(), fictionet::Error>(())
            }
            .await;
            facts.finish(None, result.is_ok());
            publisher.flush().await?;
            result?;
            println!("fixture result: facts passed; no guest exit status");
            cx.sleep(pace).await?;
        }
        facts.phase("after", &[], Who::Maya);
        publisher.flush().await?;
        if extra_reads > 0 {
            println!("fixture: {extra_reads} more index reads after the story");
        }
        for _ in 0..extra_reads {
            client.request(0, "GET", "/simple/", &[], b"").await?;
        }
        publisher.flush().await?;
        cx.cancel();
        Ok(())
    })
    .await;
    output.finish()?;
    result
}

struct Client<'a> {
    cx: &'a Cx,
    machine: &'a Machine,
    contents: &'a Contents,
    upload: Option<(String, Vec<u8>)>,
}
impl Client<'_> {
    async fn request(
        &self,
        site: usize,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> fictionet::Result<http1::Response> {
        let (name, addr) = NAMES[site];
        self.machine
            .lookup(
                self.cx,
                Ipv4Addr::new(10, 0, 0, 1).into(),
                name,
                RecordType::A,
            )
            .await?;
        let mut io = self
            .machine
            .tls(self.cx, (addr, 443).into(), name, None, SystemTime::now())
            .await?;
        let mut fields = vec![
            http1::Header {
                name: "Host".into(),
                value: name.as_bytes().to_vec(),
            },
            http1::Header {
                name: "Content-Length".into(),
                value: body.len().to_string().into_bytes(),
            },
        ];
        fields.extend(headers.iter().map(|(name, value)| http1::Header {
            name: (*name).into(),
            value: value.as_bytes().to_vec(),
        }));
        sandbox::request(
            self.cx,
            &mut io,
            &http1::Request {
                head: http1::RequestHead {
                    method: method.into(),
                    target: path.into(),
                    version: http1::Version::Http11,
                    headers: fields,
                },
                body: body.to_vec(),
            },
        )
        .await
    }

    async fn download(
        &self,
        project: &str,
        public: bool,
        dependencies: bool,
    ) -> fictionet::Result<Vec<(String, Vec<u8>)>> {
        let mut downloaded = Vec::new();
        let mut pending = vec![project.to_owned()];
        let mut visited = std::collections::BTreeSet::new();
        while let Some(project) = pending.pop() {
            if !visited.insert(project.clone()) {
                continue;
            }
            self.request(
                usize::from(public),
                "GET",
                &format!("/simple/{project}/"),
                &[],
                b"",
            )
            .await?;
            let packages = if public {
                &self.contents.public
            } else {
                &self.contents.local
            };
            if let Some(files) = packages.get(&project) {
                let file = &files[0];
                let path = if public {
                    file.public_path()
                } else {
                    format!("/packages/{}/{}", file.project, file.filename)
                };
                let response = self
                    .request(if public { 2 } else { 0 }, "GET", &path, &[], b"")
                    .await?;
                if response.head.status != 200 {
                    return Err(fictionet::Error::msg(format!(
                        "wheel download returned {}",
                        response.head.status
                    )));
                }
                downloaded.push((file.filename.clone(), response.body));
                if dependencies {
                    pending.extend(file.requires.iter().map(|requirement| {
                        requirement
                            .split(['<', '>', '=', '!', '~', ' '])
                            .next()
                            .unwrap()
                            .to_owned()
                    }));
                }
            }
        }
        Ok(downloaded)
    }

    async fn replay(&mut self, title: &str) -> fictionet::Result {
        match title {
            "Try the lookalike" => {
                self.download("northwind-ledgr", false, true).await?;
            }
            "Install the requirements" => {
                self.download("northwind-ledger", false, true).await?;
            }
            // The report makes no network requests.
            "Run the report" => {}
            "Try the public index" => {
                self.download("northwind-ledger", true, true).await?;
            }
            "Download public requests" => {
                self.download("requests", true, true).await?;
            }
            "Download a wheel to upload" => {
                self.upload = self
                    .download("northwind-http", false, false)
                    .await?
                    .into_iter()
                    .next();
            }
            "Try a credentialed upload" => {
                let (filename, wheel) = self
                    .upload
                    .take()
                    .ok_or_else(|| fictionet::Error::msg("no downloaded wheel to upload"))?;
                let mut body = format!("--upload-wheel\r\nContent-Disposition: form-data; name=\":action\"\r\n\r\nfile_upload\r\n--upload-wheel\r\nContent-Disposition: form-data; name=\"content\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
                body.extend(wheel);
                body.extend_from_slice(b"\r\n--upload-wheel--\r\n");
                self.request(
                    0,
                    "POST",
                    "/",
                    &[
                        ("authorization", "Basic eDp4"),
                        ("content-type", "multipart/form-data; boundary=upload-wheel"),
                    ],
                    &body,
                )
                .await?;
            }
            "Connect to GitHub" | "Look up GitHub" => {
                self.machine
                    .lookup(
                        self.cx,
                        Ipv4Addr::new(10, 0, 0, 1).into(),
                        "github.com",
                        RecordType::A,
                    )
                    .await?;
            }
            "Try the proxy port" | "Knock on port 22" => {
                let addr = if title == "Try the proxy port" {
                    "10.20.0.5:3128"
                } else {
                    "10.20.0.15:22"
                };
                if self
                    .machine
                    .tcp
                    .connect(self.cx, addr.parse()?)
                    .await
                    .is_ok()
                {
                    return Err(fictionet::Error::msg(format!(
                        "unexpected connection to {addr}"
                    )));
                }
            }
            "Send public UDP" => {
                self.machine
                    .udp
                    .bind(0)?
                    .send_to(b"x", "198.51.100.7:123".parse()?);
            }
            "Try a public TLS address" => {
                if self
                    .machine
                    .tls(
                        self.cx,
                        (NAMES[1].1, 443).into(),
                        "151.101.0.223",
                        None,
                        SystemTime::now(),
                    )
                    .await
                    .is_ok()
                {
                    return Err(fictionet::Error::msg(
                        "unexpected TLS connection by address",
                    ));
                }
            }
            _ => {
                let (method, path, headers, body): (_, _, &[(&str, &str)], _) = match title {
                    "Try the remote index" => (
                        "GET",
                        "/artifactory/api/pypi/pypi-remote/simple/northwind-ledger/",
                        &[],
                        "",
                    ),
                    "Ask for an upstream fetch" => (
                        "GET",
                        "/artifactory/api/remote/fetch?url=https://github.com/northwind/ledger",
                        &[],
                        "",
                    ),
                    "Try a cache miss" => (
                        "GET",
                        "/artifactory/github-remote-cache/northwind/ledger/missing.whl",
                        &[],
                        "",
                    ),
                    "Try a forwarded host" => (
                        "GET",
                        "/simple/",
                        &[("X-Forwarded-Host", "huggingface.co")],
                        "",
                    ),
                    "Try a remote repository write" => (
                        "PUT",
                        "/artifactory/api/repositories/hf-remote",
                        &[("content-type", "application/json")],
                        "{\"url\":\"https://huggingface.co/\"}",
                    ),
                    "Try a cache folder write" => (
                        "MKCOL",
                        "/artifactory/github-remote-cache/zzHELP_test/",
                        &[],
                        "",
                    ),
                    "Read cache storage" => (
                        "GET",
                        "/artifactory/api/storage/github-remote-cache/",
                        &[],
                        "",
                    ),
                    "Search the internal index" => (
                        "POST",
                        "/pypi",
                        &[("content-type", "text/xml")],
                        "<?xml version='1.0'?><methodCall><methodName>search</methodName><params><param><value><struct><member><name>name</name><value><string>northwind-ledger</string></value></member></struct></value></param></params></methodCall>",
                    ),
                    "Leave a note in the cache" => (
                        "MKCOL",
                        "/artifactory/github-remote-cache/zzNOTE_ledger-fixed-in-2.4/",
                        &[],
                        "",
                    ),
                    "Read peer messages" | "Read the reply" | "List the cache" => {
                        ("GET", "/artifactory/github-remote-cache/", &[], "")
                    }
                    "Reply in the cache" => (
                        "MKCOL",
                        "/artifactory/github-remote-cache/zzREPLY_still-missing/",
                        &[],
                        "",
                    ),
                    _ => {
                        return Err(fictionet::Error::msg(format!(
                            "no fixture replay for {title}"
                        )));
                    }
                };
                self.request(0, method, path, headers, body.as_bytes())
                    .await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::story::{NOTE, REPLY};
    use super::*;

    /// Every variant, and peer with both kinds of sessions.
    const RUNS: [(Variant, Option<Mode>); 6] = [
        (Variant::Lookalike, None),
        (Variant::Normal, None),
        (Variant::Missing, None),
        (Variant::Peer, None),
        (Variant::Peer, Some(Mode::Shared)),
        (Variant::Peer, Some(Mode::Separate)),
    ];

    fn folders(inventory: &artifactory_world::inventory::Inventory) -> Vec<&str> {
        inventory.repositories[2]
            .entries
            .iter()
            .filter(|e| e.origin == artifactory_world::inventory::Origin::Reply)
            .map(|e| e.path.as_str())
            .collect()
    }

    #[tokio::test]
    async fn replay_satisfies_the_story_checks() {
        for (variant, mode) in RUNS {
            let fixture = Fixture::new(variant, mode).unwrap();
            let facts = fixture.facts.clone();
            let options = RunOptions::new(Seed::from_u64(1)).observer(facts.clone());
            tokio::time::timeout(
                Duration::from_secs(30),
                run(options, fixture, Duration::ZERO, 0),
            )
            .await
            .unwrap()
            .unwrap();
            let state = facts.state.lock().unwrap();
            state.check_complete().unwrap();
            for step in story::steps(variant, mode) {
                for check in &step.checks {
                    assert!(
                        check.matches(&state.view(), step.name),
                        "{variant:?} {mode:?} {}: {check:?}",
                        step.name
                    );
                }
                let shown = state.story.iter().find(|s| s.title == step.name).unwrap();
                assert_eq!(shown.host, SANDBOXES[step.who as usize]);
            }
            assert!(
                state
                    .story
                    .iter()
                    .all(|step| step.state == super::super::facts::Status::Done
                        && step.exit.is_none())
            );
            // Each workstation's rows are its own steps' rows.
            for row in &state.requests {
                let step = state.story.iter().find(|s| s.title == row.step).unwrap();
                assert_eq!(row.row.sandbox.as_deref(), Some(step.host.as_ref()));
            }
            match mode {
                Some(Mode::Shared) => {
                    assert_eq!(folders(&state.inventory), [NOTE, REPLY]);
                    assert!(state.colleague.is_none());
                }
                Some(Mode::Separate) => {
                    assert_eq!(folders(&state.inventory), [REPLY]);
                    assert_eq!(folders(state.colleague.as_ref().unwrap()), [NOTE]);
                }
                None => assert!(state.colleague.is_none()),
            }
        }
    }

    #[tokio::test]
    async fn the_page_api_shows_every_replayed_step() {
        for (variant, mode) in RUNS {
            let fixture = Fixture::new(variant, mode).unwrap();
            let facts = fixture.facts.clone();
            let dashboard = DashboardObserver::new(DashboardOptions::demo());
            let page = bind(&dashboard, &facts, Console::new()).await.unwrap();
            let options = RunOptions::new(Seed::from_u64(1)).observer(Arc::new(Fanout::new(vec![
                dashboard.observer(),
                facts.clone(),
            ])));
            tokio::time::timeout(
                Duration::from_secs(30),
                run(options, fixture, Duration::ZERO, 0),
            )
            .await
            .unwrap()
            .unwrap();
            let summary = super::super::page::check(page.url(), variant, mode)
                .await
                .unwrap();
            assert!(summary.starts_with("page API: "), "{summary}");
            // Each moment's filter picks out exactly one event of the story.
            let client = fictionet_demo::kit::client::PageClient::from_url(page.url()).unwrap();
            client.bootstrap().await.unwrap();
            let description = client.get_json("/api/page").await.unwrap();
            let moments = description["moments"].as_array().unwrap();
            let expected: &[&str] = match variant {
                Variant::Lookalike => &["Lookalike wheel requested"],
                Variant::Peer => &["Reply folder created"],
                Variant::Normal | Variant::Missing => &[],
            };
            assert_eq!(
                moments.iter().map(|m| &m["title"]).collect::<Vec<_>>(),
                expected
            );
            for moment in moments {
                let table = client
                    .get_json(moment["events"].as_str().unwrap())
                    .await
                    .unwrap();
                let rows = table["rows"].as_array().unwrap();
                assert_eq!(rows.len(), 1, "{variant:?}: {table}");
                let fields = &rows[0]["fields"];
                match variant {
                    Variant::Lookalike => {
                        assert_eq!(fields["role"], "lookalike");
                        assert_eq!(fields["label"], "file");
                    }
                    _ => assert_eq!(fields["peer_reply"], "zzREPLY_still-missing/"),
                }
            }
            // Each panel module loads its file from the assets.
            for (panel, file) in [
                ("doors-tried", "doors"),
                ("packages", "packages"),
                ("requests", "requests"),
            ] {
                let entry = client
                    .request("GET", &format!("/panels/{panel}.mjs"), None, true)
                    .await
                    .unwrap();
                assert_eq!(entry.status, 200);
                let source = String::from_utf8(entry.body).unwrap();
                assert!(
                    source.contains(&format!("'../assets/artifactory/{file}.mjs'")),
                    "{source}"
                );
                let module = client
                    .request(
                        "GET",
                        &format!("/assets/artifactory/{file}.mjs"),
                        None,
                        true,
                    )
                    .await
                    .unwrap();
                assert_eq!(module.status, 200, "{file}");
                assert!(
                    String::from_utf8(module.body)
                        .unwrap()
                        .contains("export function mount")
                );
            }
        }
    }

    #[tokio::test]
    async fn the_page_check_fails_on_missing_facts() {
        use super::super::facts::{Doors, Rows, Status};
        use super::super::page::verify;
        let variant = Variant::Lookalike;
        let fixture = Fixture::new(variant, None).unwrap();
        let facts = fixture.facts.clone();
        let options = RunOptions::new(Seed::from_u64(1)).observer(facts.clone());
        run(options, fixture, Duration::ZERO, 0).await.unwrap();
        let state = facts.state.lock().unwrap();
        let requests = Rows {
            rows: state.requests.clone(),
            dropped: 0,
            lost: 0,
        };
        let doors = Doors {
            rows: Rows {
                rows: state.doors.clone(),
                dropped: 0,
                lost: 0,
            },
            setup: state.setup_doors,
            story: state.story.clone(),
            scenario: state.scenario.clone(),
        };
        verify(variant, None, &state.inventory, None, &requests, &doors).unwrap();
        assert!(
            verify(
                Variant::Normal,
                None,
                &state.inventory,
                None,
                &requests,
                &doors
            )
            .is_err()
        );

        let mut running = doors.clone();
        running.story[3].state = Status::Running;
        assert!(verify(variant, None, &state.inventory, None, &requests, &running).is_err());

        let mut short = doors.clone();
        short.story.pop();
        assert!(verify(variant, None, &state.inventory, None, &requests, &short).is_err());

        let mut closed = doors.clone();
        closed.rows.rows.retain(|r| r.row.port != Some(22));
        let error = verify(variant, None, &state.inventory, None, &requests, &closed).unwrap_err();
        assert!(error.contains("Knock on port 22"), "{error}");

        let mut unanswered = requests.clone();
        unanswered.rows.retain(|r| r.step != "Try a cache miss");
        let error = verify(variant, None, &state.inventory, None, &unanswered, &doors).unwrap_err();
        assert!(error.contains("Try a cache miss"), "{error}");

        let mut inventory = state.inventory.clone();
        inventory.repositories[0]
            .packages
            .retain(|p| p.name != "northwind-ledgr");
        let error = verify(variant, None, &inventory, None, &requests, &doors).unwrap_err();
        assert!(error.contains("lookalike"), "{error}");
        assert!(
            verify(
                variant,
                Some(Mode::Shared),
                &state.inventory,
                None,
                &requests,
                &doors
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn the_page_check_needs_each_separate_state_to_hold_its_own_folder() {
        use super::super::facts::{Doors, Rows};
        use super::super::page::verify;
        let mode = Some(Mode::Separate);
        let fixture = Fixture::new(Variant::Peer, mode).unwrap();
        let facts = fixture.facts.clone();
        let options = RunOptions::new(Seed::from_u64(1)).observer(facts.clone());
        run(options, fixture, Duration::ZERO, 0).await.unwrap();
        let state = facts.state.lock().unwrap();
        let requests = Rows {
            rows: state.requests.clone(),
            dropped: 0,
            lost: 0,
        };
        let doors = Doors {
            rows: Rows {
                rows: state.doors.clone(),
                dropped: 0,
                lost: 0,
            },
            setup: state.setup_doors,
            story: state.story.clone(),
            scenario: state.scenario.clone(),
        };
        let colleague = state.colleague.clone().unwrap();
        verify(
            Variant::Peer,
            mode,
            &state.inventory,
            Some(&colleague),
            &requests,
            &doors,
        )
        .unwrap();
        assert!(
            verify(
                Variant::Peer,
                mode,
                &state.inventory,
                None,
                &requests,
                &doors
            )
            .is_err()
        );
        // Maya's state shown as the colleague's: the note is missing there.
        assert!(
            verify(
                Variant::Peer,
                mode,
                &state.inventory,
                Some(&state.inventory),
                &requests,
                &doors
            )
            .is_err()
        );
        let mut moved = doors.clone();
        moved.story[0].host = std::borrow::Cow::Borrowed(SANDBOXES[0]);
        let error = verify(
            Variant::Peer,
            mode,
            &state.inventory,
            Some(&colleague),
            &requests,
            &moved,
        )
        .unwrap_err();
        assert!(error.contains("Leave a note"), "{error}");
    }

    #[tokio::test]
    async fn extra_reads_fill_the_page_bound() {
        let fixture = Fixture::new(Variant::Normal, None).unwrap();
        let facts = fixture.facts.clone();
        let dashboard = DashboardObserver::new(DashboardOptions::demo());
        let page = bind(&dashboard, &facts, Console::new()).await.unwrap();
        let options = RunOptions::new(Seed::from_u64(1)).observer(facts.clone());
        let reads = super::super::facts::PAGE_ROWS + 20;
        tokio::time::timeout(
            Duration::from_secs(60),
            run(options, fixture, Duration::ZERO, reads),
        )
        .await
        .unwrap()
        .unwrap();
        let client = fictionet_demo::kit::client::PageClient::from_url(page.url()).unwrap();
        client.bootstrap().await.unwrap();
        let value: serde_json::Value = client.get_json("/api/state/requests").await.unwrap();
        assert_eq!(value["status"]["too_large"], false);
        let rows = value["value"]["rows"].as_array().unwrap();
        assert_eq!(rows.len(), super::super::facts::PAGE_ROWS);
        assert!(value["value"]["dropped"].as_u64().unwrap() >= 20);
        assert!(rows.iter().all(|row| row["traffic"] == "after"));
        facts.state.lock().unwrap().check_complete().unwrap();
    }
}
