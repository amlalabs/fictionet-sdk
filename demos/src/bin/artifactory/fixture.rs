use super::{
    Result,
    facts::{Facts, Publisher},
    story,
};
use artifactory_world::{Identity, NAMES, log::Log, packages::Variant, repository::Contents};
use fictionet::{
    Cx, RunOptions, Seed,
    events::Fanout,
    stdlib::{
        protocols::{dns::rr::RecordType, http1},
        world::sandbox::{self, Machine},
    },
};
use fictionet_observe::{
    DashboardObserver, DashboardOptions,
    page::{Host, HostState, HostStatus, StateLimits, StateTopic},
};
use std::{
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, SystemTime},
};

pub async fn serve(variant: Variant) -> Result {
    let contents =
        Contents::new(variant, "artifactory-fixture", &[1; 32]).map_err(std::io::Error::other)?;
    let facts = Arc::new(Facts::new(contents.inventory()));
    let dashboard = DashboardObserver::new(DashboardOptions::demo());
    let status = StateTopic::new(StateLimits::default());
    status.publish(
        fictionet::time::Instant::ZERO,
        &HostStatus {
            state: HostState::NetworkUp,
            addresses: vec!["10.0.0.2".into()],
            screen: false,
            terminal: false,
        },
    )?;
    let page = super::page(
        variant,
        dashboard.handle(),
        Host::new("fixture").status(status),
        facts.topics.clone(),
        true,
    )
    .bind_loopback(0)
    .await?;
    println!("Fixture: in-process traffic replay. No guest or command exit statuses.");
    println!("Page: {}", page.url());
    let options = RunOptions::new(Seed::from_u64(1)).observer(Arc::new(Fanout::new(vec![
        dashboard.observer(),
        facts.clone(),
    ])));
    let replay = run(options, contents, facts.clone(), Duration::from_secs(1));
    tokio::pin!(replay);
    tokio::select! {
        result = &mut replay => {
            result.map_err(std::io::Error::other)?;
            println!("fixture replay complete; page stays open until Ctrl-C");
            super::wait_for_interrupt().await?;
        }
        result = super::wait_for_interrupt() => { result?; }
    }
    drop(page);
    Ok(())
}

async fn run(
    options: RunOptions,
    contents: Contents,
    facts: Arc<Facts>,
    pace: Duration,
) -> fictionet::Result {
    let listener = facts.clone();
    let contents =
        Arc::new(contents.on_change(move |at, change, inventory| {
            listener.inventory_changed(at, change, inventory)
        }));
    let log = Log::start(Box::new(std::io::sink()))?;
    let output = log.clone();
    let result = fictionet::run(options, move |cx| async move {
        let identity = Identity::new(&cx)?;
        let (attacher, attachments) = fictionet::attachments();
        artifactory_world::start(&cx, contents.clone(), identity, log, attachments)?;
        let machine =
            sandbox::machine(&cx, attacher.attach("fixture")?, Ipv4Addr::new(10, 0, 0, 2));
        let mut client = Client {
            cx: &cx,
            machine: &machine,
            contents: &contents,
            upload: None,
        };
        let publisher = Publisher::start(facts.clone());
        cx.sleep(pace).await?;
        for step in story::steps(contents.variant) {
            facts.phase(step.name, step.destinations);
            publisher.flush().await?;
            println!("fixture story: {}", step.name);
            cx.sleep(pace).await?;
            let result = async {
                client.replay(step.name).await?;
                tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        let changed = facts.changed.notified();
                        {
                            let state = facts.state.lock().unwrap();
                            state.check_complete()?;
                            if step
                                .checks
                                .iter()
                                .all(|check| check.matches(&state, step.name))
                            {
                                return Ok::<(), fictionet::Error>(());
                            }
                        }
                        changed.await;
                    }
                })
                .await
                .map_err(|_| {
                    fictionet::Error::msg(format!("{}: fixture facts did not arrive", step.name))
                })??;
                Ok::<(), fictionet::Error>(())
            }
            .await;
            facts.finish(None, result.is_ok());
            publisher.flush().await?;
            result?;
            println!("fixture result: facts passed; no guest exit status");
            cx.sleep(pace).await?;
        }
        facts.phase("after", &[]);
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
                    "Read peer messages" | "Read the reply" => {
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
    use super::*;
    #[tokio::test]
    async fn replay_satisfies_the_story_checks() {
        for variant in [
            Variant::Lookalike,
            Variant::Normal,
            Variant::Missing,
            Variant::Peer,
        ] {
            let contents = Contents::new(variant, "artifactory-fixture", &[1; 32]).unwrap();
            let facts = Arc::new(Facts::new(contents.inventory()));
            let options = RunOptions::new(Seed::from_u64(1)).observer(facts.clone());
            tokio::time::timeout(
                Duration::from_secs(30),
                run(options, contents, facts.clone(), Duration::ZERO),
            )
            .await
            .unwrap()
            .unwrap();
            let state = facts.state.lock().unwrap();
            state.check_complete().unwrap();
            for step in story::steps(variant) {
                for check in step.checks {
                    assert!(check.matches(&state, step.name), "{}: {check:?}", step.name);
                }
            }
            assert!(
                state
                    .story
                    .iter()
                    .all(|step| step.state == super::super::facts::Status::Done
                        && step.exit.is_none())
            );
        }
    }
}
