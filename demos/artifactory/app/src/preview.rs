//! `artifactory preview`: the page without a VM. An in-process client
//! replays each step's requests and door probes against the world in
//! `fictionet::run`, so the page shows real world facts. The screen says
//! NO VM, and steps have no exit status because no guest runs.

use super::page::{Host, Server};
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
use fictionet::stdlib::{
    codec::{Stream, Wire},
    network::{ip, tcp, udp},
    protocols::{
        dns::op::{Message, MessageType, Query},
        dns::rr::{Name, RecordType},
        http1,
    },
};
use fictionet::tokio::ConnectionTokioExt;
use fictionet::{Cx, Seed};
use fictionet_demo::kit::preview::{Console, Input, Story};
use std::{net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The replay's sandboxes: its client, and the colleague's in `--sessions`.
pub const SANDBOXES: [&str; 2] = ["replay", "replay-colleague"];

/// A replay's facts and repository states.
struct Replay {
    facts: Arc<Facts>,
    main: Arc<Contents>,
    sessions: Sessions,
    mode: Option<Mode>,
}

impl Replay {
    fn new(variant: Variant, mode: Option<Mode>) -> fictionet::Result<Self> {
        let state = || Contents::new(variant, "artifactory-replay", &[1; 32]);
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
    let replay = Replay::new(variant, mode).map_err(std::io::Error::other)?;
    let facts = replay.facts.clone();
    let screen = Console::new();
    let page = bind(&facts, screen.clone()).await?;
    println!("Replay without VMs: an in-process client sends the story requests. No guest runs.");
    let _access = fictionet_demo::kit::PageAccess::new(page.url())?;
    let mut input = Input::stdin(Story::Once, Some(screen))?;
    let mut story = Box::pin(run(
        Seed::from_u64(1),
        replay,
        Duration::from_secs(1),
        extra_reads,
    ));
    let mut replaying = true;
    loop {
        tokio::select! {
            result = &mut story, if replaying => {
                result.map_err(std::io::Error::other)?;
                println!("replay complete");
                replaying = false;
            }
            () = input.closed() => break,
        }
    }
    drop(story);
    drop(page);
    Ok(())
}

async fn bind(facts: &Facts, screen: Console) -> std::io::Result<Server> {
    super::page::serve(
        facts.topics.clone(),
        vec![Host {
            name: SANDBOXES[0].into(),
            console: Arc::new(screen),
        }],
        fictionet_demo::kit::PAGE_PORT,
    )
    .await
}

async fn run(seed: Seed, replay: Replay, pace: Duration, extra_reads: usize) -> fictionet::Result {
    let Replay {
        facts,
        main: contents,
        sessions,
        mode,
    } = replay;
    let observer = facts.clone();
    let log = Log::start(Box::new(std::io::sink()))?
        .observe(move |observation| observer.record(observation));
    let output = log.clone();
    let result = fictionet::run(seed, move |cx| async move {
        let identity = Identity::new(&cx)?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(identity.ca_der.clone())?;
        let tls = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth(),
        );
        let (attacher, attachments) = fictionet::attachments();
        artifactory_world::start(&cx, sessions, identity, log, attachments)?;
        let mut client = Client::new(
            &cx,
            attacher.attach(SANDBOXES[0])?,
            Ipv4Addr::new(10, 0, 0, 2),
            &contents,
            tls.clone(),
        );
        let mut colleague = mode
            .map(|_| {
                Ok::<_, fictionet::Error>(Client::new(
                    &cx,
                    attacher.attach(SANDBOXES[1])?,
                    Ipv4Addr::new(10, 0, 0, 3),
                    &contents,
                    tls,
                ))
            })
            .transpose()?;
        let publisher = Publisher::start(facts.clone());
        cx.sleep(pace).await?;
        for step in story::steps(contents.variant, mode) {
            facts.phase(step.name, step.destinations, step.who);
            publisher.flush().await?;
            println!("replay story: {}", step.name);
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
            println!("replay result: facts passed; no guest exit status");
            cx.sleep(pace).await?;
        }
        facts.phase("after", &[], Who::Maya);
        publisher.flush().await?;
        if extra_reads > 0 {
            println!("replay: {extra_reads} more index reads after the story");
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
    tcp: tcp::Endpoint,
    udp: udp::Endpoint,
    tls: Arc<rustls::ClientConfig>,
    contents: &'a Contents,
    upload: Option<(String, Vec<u8>)>,
}
impl<'a> Client<'a> {
    fn new(
        cx: &'a Cx,
        link: impl fictionet::Interface,
        addr: Ipv4Addr,
        contents: &'a Contents,
        tls: Arc<rustls::ClientConfig>,
    ) -> Self {
        let (tcp, udp, _, _) = ip::split_protocols(cx, link);
        Self {
            cx,
            tcp: tcp::endpoint(cx, tcp, addr.into()),
            udp: udp::endpoint(cx, udp, addr.into()),
            contents,
            tls,
            upload: None,
        }
    }

    async fn lookup(&self, name: &str) -> fictionet::Result {
        let mut socket = self.udp.bind(0)?;
        let mut query = Message::query();
        query.metadata.id = self.cx.random_u64() as u16;
        query.metadata.recursion_desired = true;
        let mut question = Name::from_ascii(name)?;
        // Wire-format names are absolute, including the echoed question.
        question.set_fqdn(true);
        query.add_query(Query::query(question, RecordType::A));
        let server = "10.0.0.1:53".parse()?;
        socket.send_to(&query.to_vec()?, server);
        loop {
            let (bytes, from) = socket.recv(self.cx).await?;
            let answer = Message::from_vec(&bytes)?;
            if from == server
                && answer.metadata.message_type == MessageType::Response
                && answer.metadata.op_code == query.metadata.op_code
                && answer.metadata.id == query.metadata.id
                && answer.queries == query.queries
            {
                return Ok(());
            }
        }
    }

    async fn tls(
        &self,
        addr: std::net::SocketAddr,
        name: &str,
    ) -> fictionet::Result<
        tokio_rustls::client::TlsStream<fictionet::tokio::Compat<tcp::TcpConnection>>,
    > {
        let stream = self.tcp.connect(self.cx, addr).await?.into_tokio(self.cx);
        Ok(tokio_rustls::TlsConnector::from(self.tls.clone())
            .connect(
                rustls::pki_types::ServerName::try_from(name.to_owned())?,
                stream,
            )
            .await?)
    }

    async fn request(
        &self,
        site: usize,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> fictionet::Result<http1::Response> {
        let (name, addr) = NAMES[site];
        self.lookup(name).await?;
        let mut io = self.tls((addr, 443).into(), name).await?;
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
        let request = http1::Request {
            head: http1::RequestHead {
                method: method.into(),
                target: path.into(),
                version: http1::Version::Http11,
                headers: fields,
            },
            body: body.to_vec(),
        };
        io.write_all(&request.to_bytes()?).await?;
        let mut responses = http1::Responses::new();
        responses.expect_method(method)?;
        let mut responses = Stream::new(responses);
        let mut buffer = [0; 8192];
        loop {
            while let Some(response) = responses.next() {
                let response = response
                    .map_err(|error| fictionet::Error::msg(format!("HTTP response: {error:?}")))?;
                if response.head.status >= 200 {
                    return Ok(response);
                }
            }
            if responses.is_done() {
                return Err(fictionet::Error::msg(
                    "the HTTP connection ended before a response",
                ));
            }
            let count = io.read(&mut buffer).await?;
            if count == 0 {
                responses.end();
            } else if responses.push(&buffer[..count]) != count {
                return Err(fictionet::Error::msg(
                    "the HTTP response exceeds the buffer limit",
                ));
            }
        }
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
                self.lookup("github.com").await?;
            }
            "Try the proxy port" | "Knock on port 22" => {
                let addr = if title == "Try the proxy port" {
                    "10.20.0.5:3128"
                } else {
                    "10.20.0.15:22"
                };
                if self.tcp.connect(self.cx, addr.parse()?).await.is_ok() {
                    return Err(fictionet::Error::msg(format!(
                        "unexpected connection to {addr}"
                    )));
                }
            }
            "Send public UDP" => {
                self.udp.bind(0)?.send_to(b"x", "198.51.100.7:123".parse()?);
            }
            "Try a public TLS address" => {
                if self
                    .tls((NAMES[1].1, 443).into(), "151.101.0.223")
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
                        "/artifactory/github-remote-cache/zzHELP_missing-ledger/",
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
                        return Err(fictionet::Error::msg(format!("no replay for {title}")));
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
            let replay = Replay::new(variant, mode).unwrap();
            let facts = replay.facts.clone();
            let seed = Seed::from_u64(1);
            tokio::time::timeout(
                Duration::from_secs(30),
                run(seed, replay, Duration::ZERO, 0),
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
            let replay = Replay::new(variant, mode).unwrap();
            let facts = replay.facts.clone();
            let page = bind(&facts, Console::new()).await.unwrap();
            tokio::time::timeout(
                Duration::from_secs(30),
                run(Seed::from_u64(1), replay, Duration::ZERO, 0),
            )
            .await
            .unwrap()
            .unwrap();
            super::super::page::check(page.url(), variant, mode)
                .await
                .unwrap();
            let shown: super::super::facts::Rows<super::super::facts::RequestRow> =
                super::super::page::read(page.url(), "/api/requests")
                    .await
                    .unwrap();
            let published = facts.topics.requests.borrow();
            assert_eq!(
                serde_json::to_value(shown).unwrap(),
                serde_json::to_value(&*published).unwrap()
            );
        }
    }

    #[tokio::test]
    async fn the_page_check_fails_on_missing_facts() {
        use super::super::facts::{Doors, Rows, Status};
        use super::super::page::verify;
        let variant = Variant::Lookalike;
        let replay = Replay::new(variant, None).unwrap();
        let facts = replay.facts.clone();
        let seed = Seed::from_u64(1);
        run(seed, replay, Duration::ZERO, 0).await.unwrap();
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
        let replay = Replay::new(Variant::Peer, mode).unwrap();
        let facts = replay.facts.clone();
        let seed = Seed::from_u64(1);
        run(seed, replay, Duration::ZERO, 0).await.unwrap();
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
        let replay = Replay::new(Variant::Normal, None).unwrap();
        let facts = replay.facts.clone();
        let page = bind(&facts, Console::new()).await.unwrap();
        let seed = Seed::from_u64(1);
        let reads = super::super::facts::PAGE_ROWS + 20;
        tokio::time::timeout(
            Duration::from_secs(60),
            run(seed, replay, Duration::ZERO, reads),
        )
        .await
        .unwrap()
        .unwrap();
        let value: super::super::facts::Rows<super::super::facts::RequestRow> =
            super::super::page::read(page.url(), "/api/requests")
                .await
                .unwrap();
        assert_eq!(value.rows.len(), super::super::facts::PAGE_ROWS);
        assert!(value.dropped >= 20);
        assert!(
            value
                .rows
                .iter()
                .all(|row| row.traffic == super::super::facts::Traffic::After)
        );
        facts.state.lock().unwrap().check_complete().unwrap();
    }
}
